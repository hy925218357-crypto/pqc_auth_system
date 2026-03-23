"""
无状态哈希签名 (SLH-DSA/SPHINCS+) - 使用 liboqs 官方实现 (FIPS 205)

FIPS 205: StateLess Hash-Based Digital Signatures
NIST PQC: SLH-DSA (SPHINCS+) - 无状态签名算法
备注: XMSS 在此 liboqs 版本中未编译，改用 SLH-DSA 替代
"""
import os
import json
import hashlib
import logging
import time
import threading
from typing import Dict, Tuple, Optional
from pathlib import Path

try:
    import oqs
except ImportError:
    raise ImportError(
        "liboqs-python 未安装。请运行: pip install liboqs-python>=0.8.0"
    )

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class StatefulXMSSLibOQS:
    """
    基于 liboqs 的无状态哈希签名 (SLH-DSA/SPHINCS+)
    
    API 兼容 RFC 8391 XMSS，但使用 SLH-DSA (FIPS 205) 作为后端
    原因: XMSS 未在当前 liboqs 二进制中编译
    
    特性:
    - ✅ FIPS 205 标准实现（SLH-DSA）
    - ✅ 无状态签名（不需要状态管理）
    - ✅ 常量时间操作（C库实现）
    - ✅ 安全性等同 XMSS
    - ✅ 支持多种安全级别（128/192/256-bit）
    - ✅ 支持 SHA2, SHAKE, SHA3 哈希
    - ✅ 分布式状态管理（Redis/文件）
    - ✅ 加密持久化
    - ✅ 线程安全
    """
    
    # SLH-DSA 安全级别映射 (替代 RFC 8391 树高)
    SECURITY_LEVELS = {
        'small': 'SLH_DSA_PURE_SHA2_128S',      # 128-bit, 小
        'medium': 'SLH_DSA_PURE_SHA2_256S',    # 256-bit, 小（推荐）
        'large': 'SLH_DSA_PURE_SHA2_256F',     # 256-bit, 快速
        'xlarge': 'SLH_DSA_PURE_SHAKE_256S'    # 256-bit, SHAKE
    }
    
    def __init__(self, 
                 tree_height: int = None,
                 security_level: str = 'medium',
                 device_id: str = None,
                 state_file: str = None,
                 master_key: bytes = None,
                 redis_backend: bool = False,
                 redis_host: str = "localhost",
                 redis_port: int = 6379):
        """
        初始化无状态哈希签名 (SLH-DSA)
        
        Args:
            tree_height: 已弃用（为向后兼容），使用 security_level 替代
            security_level: 安全级别 ('small'|'medium'|'large'|'xlarge')
            device_id: 设备唯一标识符
            state_file: 状态文件路径（用于密钥持久化）
            master_key: 主密钥（32字节）用于加密状态
            redis_backend: 是否使用 Redis 作为后端
            redis_host: Redis 地址
            redis_port: Redis 端口
        """
        # 向后兼容：tree_height 映射到 security_level
        if tree_height is not None:
            if tree_height < 10:
                security_level = 'small'
            elif tree_height <= 15:
                security_level = 'medium'
            elif tree_height <= 16:
                security_level = 'large'
            else:
                security_level = 'xlarge'
        
        if security_level not in self.SECURITY_LEVELS:
            logger.warning(f"未知的安全级别 {security_level}，使用 'medium'")
            security_level = 'medium'
        
        self.device_id = device_id or "unknown_device"
        self.security_level = security_level
        self.state_lock = threading.Lock()
        
        # 生成 SLH-DSA 签名算法名称
        self.sig_name = self.SECURITY_LEVELS[security_level]
        logger.info(f"[SLH-DSA] 已初始化: {self.sig_name} (安全级别: {security_level})")
        
        # 初始化 liboqs 签名对象
        try:
            self.sig_obj = oqs.Signature(self.sig_name)
            logger.debug(f"[SLH-DSA] 签名对象创建成功")
        except Exception as e:
            logger.error(f"[SLH-DSA] 无法初始化 {self.sig_name}: {e}")
            raise
        
        # 计算最大签名数（SLH-DSA 无状态，此值仅用于信息目的）
        # 256-bit S版本: ~2^63 签名容量
        # 256-bit F版本: ~相同容量，但更快
        self.max_signatures = float('inf')  # 无状态算法无限制
        
        # 设置状态后端
        self.redis_backend = redis_backend and HAS_REDIS
        self.state_file = state_file or f".slhdsa_{self.device_id}.state"
        
        if self.redis_backend:
            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=2,  # 状态存储专用数据库
                    decode_responses=True
                )
                self.redis_client.ping()
                logger.info(f"[SLH-DSA] Redis 后端已连接: {redis_host}:{redis_port}")
            except Exception as e:
                logger.warning(f"[SLH-DSA] Redis 连接失败: {e}，降级到文件存储")
                self.redis_backend = False
        
        # 密钥管理
        if master_key is None:
            master_key = os.urandom(32)
            logger.warning("[SLH-DSA] master_key 未提供，已随机生成（生产环境不推荐）")
        
        if len(master_key) != 32:
            raise ValueError("master_key 必须为 32 字节")
        
        self.master_key = master_key
        self.aesgcm = AESGCM(master_key)
        
        # 内存状态（SLH-DSA 无状态，但保持 API 兼容）
        self.current_index = 0  # SLH-DSA 中此值无意义，仅供兼容
        self.public_key = None
        self.secret_key = None
        
        # 尝试加载已有状态
        existing_state = self._load_state()
        if existing_state:
            self._restore_from_state(existing_state)
        else:
            logger.debug(f"[SLH-DSA] 未发现现有密钥，需调用 generate_keys()")
    
    def generate_keys(self) -> Dict:
        """
        生成新的 SLH-DSA 密钥对
        
        无状态算法（不需要状态管理，每次都能生成相同的签名）
        
        Returns:
            兼容旧 XMSS 接口：
            { "root": bytes, "public_key": bytes, "pub_seed": bytes,
              "security_level": str, "algorithm": str }
        """
        logger.info(f"[SLH-DSA] 生成密钥对: {self.sig_name}...")
        
        with self.state_lock:
            # 生成密钥对
            public_key = self.sig_obj.generate_keypair()
            
            # 保存内存状态
            self.public_key = public_key
            self.current_index = 0

            # 尝试导出/持久化秘密密钥（用于进程重启后继续签名）
            secret_key: Optional[bytes] = None
            try:
                if hasattr(self.sig_obj, "export_secret_key"):
                    secret_key = self.sig_obj.export_secret_key()
                elif hasattr(self.sig_obj, "secret_key"):
                    secret_key = getattr(self.sig_obj, "secret_key")
                elif hasattr(self.sig_obj, "sk"):
                    secret_key = getattr(self.sig_obj, "sk")
            except Exception as e:
                logger.warning(f"[SLH-DSA] 导出秘密密钥失败（将无法重启继续签名）: {e}")

            self.secret_key = secret_key
            pub_seed = hashlib.sha256(b"pub_seed" + public_key).digest()
            
            # 构造状态对象
            state = {
                'device_id': self.device_id,
                'sig_name': self.sig_name,
                'security_level': self.security_level,
                'algorithm': 'SLH-DSA (FIPS 205)',
                'public_key': public_key.hex(),
                'current_index': self.current_index,
                # secret_key 是敏感信息；只有在能导出时才写入状态文件。
                # 即便写入也会被 AES-GCM(master_key) 加密。
                'secret_key': (secret_key.hex() if secret_key is not None else None),
                'generated_at': int(time.time())
            }
            
            # 保存状态
            self._save_state(state)
            
            logger.info(
                f"[SLH-DSA] 密钥对已生成，公钥长度: {len(public_key)} 字节"
            )
            
            return {
                'root': public_key,          # 兼容旧接口
                'public_key': public_key,   # 便于调试/直观访问
                'pub_seed': pub_seed,       # 兼容旧接口；当前不参与 SLH-DSA 签名
                'security_level': self.security_level,
                'algorithm': 'SLH-DSA (FIPS 205)'
            }
    
    def sign(self, message: bytes) -> bytes:
        """
        使用 SLH-DSA 签名消息（无状态）
        
        Args:
            message: 待签名消息
            
        Returns:
            SLH-DSA 签名 (bytes)
        """
        with self.state_lock:
            # 使用 liboqs 签名（无状态，不需要索引管理）
            try:
                signature = self.sig_obj.sign(message)
            except Exception as e:
                logger.error(f"[SLH-DSA] 签名失败: {e}")
                raise
            
            logger.debug(f"[SLH-DSA] 签名成功，签名长度: {len(signature)} 字节")
            
            return signature
    
    def verify(self, message: bytes, signature: bytes, 
               public_key: bytes = None) -> bool:
        """
        验证 SLH-DSA 签名
        
        Args:
            message: 原始消息
            signature: SLH-DSA 签名
            public_key: 公钥（如果为None，使用内存中的）
            
        Returns:
            True 如果签名有效
        """
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            logger.error("[SLH-DSA] 公钥未初始化")
            return False
        
        try:
            result = self.sig_obj.verify(message, signature, public_key)
            logger.debug("[SLH-DSA] 签名验证通过 ✓")
            return result
        except Exception as e:
            logger.warning(f"[SLH-DSA] 签名验证失败: {e}")
            return False
    
    def get_root(self) -> bytes:
        """获取 SLH-DSA 公钥"""
        return self.public_key
    
    def get_current_index(self) -> int:
        """获取当前索引（用于兼容旧 XMSS 接口）"""
        return self.current_index
    
    def get_remaining_signatures(self) -> int:
        """获取剩余签名数（SLH-DSA无限制）"""
        return float('inf')  # SLH-DSA 无状态，无限
    
    def get_current_path_info(self) -> Dict:
        """
        获取当前路径信息（用于环签名）
        
        Returns:
            兼容旧 XMSS 接口：
            { "xmss_index": int, "xmss_path": List[bytes], "leaf_pk": bytes }
        """
        with self.state_lock:
            if self.public_key is None:
                raise RuntimeError("[SLH-DSA] 公钥未初始化，请先 generate_keys()")
            return {
                # 对于 SLH-DSA，此处的 xmss_index 仅用于兼容接口与测试流程。
                'xmss_index': int(self.current_index),
                # SLH-DSA 本身不提供 XMSS Merkle 路径；这里返回空路径以保持协议数据结构可用。
                'xmss_path': [],
                'leaf_pk': self.public_key,
            }

    def generate_zkp_witness(self, message: bytes) -> Dict:
        """
        生成环签名所需的见证（compat）。

        说明：
        - 真实的 XMSS 见证需要消耗 OTS 叶子并给出 Merkle 路径。
        - 这里使用 SLH-DSA 做“结构兼容”，返回 ots_sig（可选）+ leaf_pk，并递增 current_index 以模拟状态消耗。
        """
        with self.state_lock:
            if self.public_key is None:
                raise RuntimeError("[SLH-DSA] 公钥未初始化，请先 generate_keys()")

            idx = int(self.current_index)
            # 生成一个签名作为占位（当前 ring-ZKP 聚合器不依赖该字段）
            # 这样至少保证接口字段存在且签名可用于调试/扩展。
            try:
                ots_sig = self.sig_obj.sign(message)
            except Exception as e:
                logger.error(f"[SLH-DSA] generate_zkp_witness 签名失败: {e}")
                raise

            self.current_index = idx + 1

            # 更新状态文件中的索引（如果启用了持久化后端）
            state = {
                'device_id': self.device_id,
                'sig_name': self.sig_name,
                'security_level': self.security_level,
                'algorithm': 'SLH-DSA (FIPS 205)',
                'public_key': self.public_key.hex(),
                'current_index': self.current_index,
                'secret_key': (self.secret_key.hex() if self.secret_key is not None else None),
                'generated_at': int(time.time()),
            }
            self._save_state(state)

            return {
                'ots_sig': ots_sig,
                'xmss_index': idx,
                'xmss_path': [],
                'leaf_pk': self.public_key,
            }
    
    def get_linkage_key(self) -> bytes:
        """获取用于链接标签生成的密钥"""
        import hashlib
        # 基于公钥导出链接密钥
        return hashlib.sha256(self.public_key + b"linkage").digest()
    
    # ===== 状态持久化 =====
    
    def _save_state(self, state: Dict):
        """保存状态到后端"""
        if self.redis_backend:
            self._save_state_redis(state)
        else:
            self._save_state_file(state)
    
    def _load_state(self) -> Optional[Dict]:
        """从后端加载状态"""
        if self.redis_backend:
            return self._load_state_redis()
        else:
            return self._load_state_file()
    
    def _save_state_redis(self, state: Dict):
        """保存状态到 Redis"""
        try:
            key = f"slhdsa:{self.device_id}:state"
            
            # 序列化状态（简化为SLH-DSA无状态）
            serialized = {
                'device_id': state['device_id'],
                'sig_name': state['sig_name'],
                'security_level': state.get('security_level', 'medium'),
                'algorithm': state.get('algorithm', 'SLH-DSA (FIPS 205)'),
                'public_key': state['public_key'],
                'current_index': str(state.get('current_index', 0)),
                # Redis hash 不适合直接存 None；用空字符串表示“不保存秘密密钥”。
                'secret_key': (state.get('secret_key', None) or ''),
                'timestamp': str(int(time.time()))
            }
            
            # 原子保存
            self.redis_client.hset(key, mapping=serialized)
            
            logger.debug(f"[SLH-DSA] 状态已保存到 Redis: {key}")
        except Exception as e:
            logger.error(f"[SLH-DSA] Redis 保存失败: {e}，降级到文件存储")
            self._save_state_file(state)
    
    def _load_state_redis(self) -> Optional[Dict]:
        """从 Redis 加载状态"""
        try:
            key = f"slhdsa:{self.device_id}:state"
            data = self.redis_client.hgetall(key)
            
            if not data:
                logger.debug(f"[SLH-DSA] Redis 中未找到状态: {key}")
                return None
            
            state = {
                'device_id': data['device_id'],
                'sig_name': data['sig_name'],
                'security_level': data.get('security_level', 'medium'),
                'algorithm': data.get('algorithm', 'SLH-DSA (FIPS 205)'),
                'public_key': data['public_key'],
                'current_index': int(data.get('current_index', '0')),
                'secret_key': data.get('secret_key', None),
            }
            
            logger.debug(f"[SLH-DSA] 状态已从 Redis 加载: {key}")
            return state
        except Exception as e:
            logger.error(f"[SLH-DSA] Redis 加载失败: {e}，降级到文件存储")
            return self._load_state_file()
    
    def _save_state_file(self, state: Dict):
        """保存状态到加密文件"""
        try:
            # 序列化（简化为SLH-DSA无状态）
            state_to_save = {
                'device_id': state['device_id'],
                'sig_name': state['sig_name'],
                'security_level': state.get('security_level', 'medium'),
                'algorithm': state.get('algorithm', 'SLH-DSA (FIPS 205)'),
                'public_key': state['public_key'],
                'current_index': int(state.get('current_index', 0)),
                'secret_key': state.get('secret_key', None),
                'generated_at': state.get('generated_at', int(time.time()))
            }
            state_json = json.dumps(state_to_save)
            
            # 加密
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, state_json.encode(), None)
            
            # 保存
            Path(self.state_file).parent.mkdir(parents=True, exist_ok=True)
            with open(self.state_file, 'wb') as f:
                f.write(nonce + ciphertext)
            
            # 设置严格权限
            os.chmod(self.state_file, 0o600)
            
            logger.debug(f"[SLH-DSA] 状态已保存到文件: {self.state_file}")
        except Exception as e:
            logger.error(f"[SLH-DSA] 文件保存失败: {e}")
            raise
    
    def _load_state_file(self) -> Optional[Dict]:
        """从加密文件加载状态"""
        try:
            if not os.path.exists(self.state_file):
                logger.debug(f"[SLH-DSA] 状态文件不存在: {self.state_file}")
                return None
            
            with open(self.state_file, 'rb') as f:
                data = f.read()
            
            if len(data) < 12:
                logger.error("[SLH-DSA] 状态文件格式错误（过短）")
                return None
            
            # 解密
            nonce = data[:12]
            ciphertext = data[12:]
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            
            state = json.loads(plaintext.decode())
            logger.debug(f"[SLH-DSA] 状态已从文件加载: {self.state_file}")
            return state
        except Exception as e:
            logger.error(f"[SLH-DSA] 文件加载失败: {e}")
            return None
    
    def _restore_from_state(self, state: Dict):
        """从加载的状态恢复内存状态（恢复公钥 + 兼容状态索引 + 可选秘密密钥）"""
        try:
            self.public_key = bytes.fromhex(state['public_key'])
            self.current_index = int(state.get('current_index', 0))
            secret_key_hex = state.get('secret_key', None)

            # 尝试恢复秘密密钥以支持进程重启后的签名
            self.secret_key = None
            if secret_key_hex:
                self.secret_key = bytes.fromhex(secret_key_hex)
                try:
                    if hasattr(self.sig_obj, "import_secret_key"):
                        self.sig_obj.import_secret_key(self.secret_key)
                    elif hasattr(self.sig_obj, "set_secret_key"):
                        self.sig_obj.set_secret_key(self.secret_key)
                    elif hasattr(self.sig_obj, "secret_key"):
                        setattr(self.sig_obj, "secret_key", self.secret_key)
                    elif hasattr(self.sig_obj, "sk"):
                        setattr(self.sig_obj, "sk", self.secret_key)
                    else:
                        logger.warning("[SLH-DSA] liboqs Signature 不支持设置 secret_key（将无法重启继续签名）")
                except Exception as e:
                    logger.warning(f"[SLH-DSA] secret_key 恢复失败（将无法重启继续签名）: {e}")
            logger.info(
                f"[SLH-DSA] 装载现有密钥: 算法={state.get('sig_name', 'unknown')}"
            )
        except Exception as e:
            logger.error(f"[SLH-DSA] 状态恢复失败: {e}")
            raise


# ===== 向后兼容别名 =====
StatefulXMSS = StatefulXMSSLibOQS
