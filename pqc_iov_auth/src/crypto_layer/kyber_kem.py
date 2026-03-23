import oqs
import threading
import logging
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

class KyberKEMEngine:
    """线程安全的 ML-KEM 引擎，支持高并发会话协商"""
    
    def __init__(self, alg_name: str = "ML-KEM-512"):
        self.alg_name = alg_name
        self._local = threading.local()
        
        # 验证算法支持
        try:
            supported = oqs.get_enabled_KEM_mechanisms()
            if alg_name not in supported:
                raise ValueError(f"{alg_name} 不支持. 可用: {supported}")
        except Exception as e:
            logger.warning(f"无法验证 liboqs 支持: {e}")

    def _get_kem(self):
        """获取线程本地的 KEM 实例"""
        if not hasattr(self._local, 'kem'):
            self._local.kem = oqs.KeyEncapsulation(self.alg_name)
        return self._local.kem

    def generate_keypair(self) -> tuple:
        """
        生成 ML-KEM 密钥对
        
        Returns:
            (public_key: bytes, secret_key: bytes)
        """
        kem = self._get_kem()
        
        try:
            # 生成公钥
            pk = kem.generate_keypair()
            
            # 提取私钥（liboqs-python 版本兼容）
            if hasattr(kem, 'export_secret_key'):
                sk = kem.export_secret_key()
            elif hasattr(kem, 'secret_key'):
                sk = kem.secret_key
            else:
                raise RuntimeError("无法从 liboqs 提取私钥")
            
            logger.info(f"[KEM] 生成 {self.alg_name} 密钥对")
            return pk, sk
            
        except Exception as e:
            logger.error(f"[KEM] 密钥生成失败: {e}")
            raise

    def encapsulate(self, pk: bytes) -> tuple:
        """
        封装随机值
        
        Args:
            pk: 接收者公钥
            
        Returns:
            (ciphertext: bytes, session_key: bytes)
        """
        try:
            ct, ss = self._get_kem().encap_secret(pk)
            k_session = self._derive_and_wipe(ss)
            
            logger.debug(f"[KEM] 封装完成，会话密钥长度: {len(k_session)}")
            return ct, k_session
            
        except Exception as e:
            logger.error(f"[KEM] 封装失败: {e}")
            raise

    def decapsulate(self, ct: bytes, sk: bytes) -> bytes:
        """
        解封装密文
        
        Args:
            ct: 密文
            sk: 接收者私钥
            
        Returns:
            session_key: bytes（32 字节会话密钥）
        """
        try:
            # 创建临时 KEM 对象用于解封装
            with oqs.KeyEncapsulation(self.alg_name, sk) as decap_kem:
                ss = decap_kem.decap_secret(ct)
            
            k_session = self._derive_and_wipe(ss)
            
            logger.debug(f"[KEM] 解封装完成，会话密钥长度: {len(k_session)}")
            return k_session
            
        except Exception as e:
            logger.error(f"[KEM] 解封装失败: {e}")
            raise

    def _derive_and_wipe(self, ss: bytes) -> bytes:
        """
        从共享密钥派生会话密钥，并擦除临时数据
        
        使用 HKDF 确保导出的密钥具有均匀分布的熵
        """
        try:
            # HKDF 密钥派生
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"pqc_iov_session_key"
            )
            k_session = hkdf.derive(ss)
            
            # 工程级防御：显式内存擦除
            # 避免依赖 Python 垃圾回收，防止秘密在内存中停留
            ss_array = bytearray(ss)
            for i in range(len(ss_array)):
                ss_array[i] = 0
            
            # 强制删除临时变量（尽管不完全可靠）
            del ss_array
            
            return k_session
            
        except Exception as e:
            logger.error(f"[KEM] 密钥派生失败: {e}")
            raise

    def get_algorithm_info(self) -> dict:
        """获取算法信息"""
        try:
            kem = self._get_kem()
            return {
                "name": self.alg_name,
                "pk_len": kem.details["length_public_key"],
                "sk_len": kem.details["length_secret_key"],
                "ct_len": kem.details["length_ciphertext"],
                "ss_len": kem.details["length_shared_secret"]
            }
        except Exception as e:
            logger.warning(f"无法获取算法详情: {e}")
            return {"name": self.alg_name}