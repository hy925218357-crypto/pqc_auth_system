import os
import json
import struct
import hashlib
import threading
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ADRS:
    """严格遵守 RFC 8391 的 32 字节地址结构"""
    WOTS_HASH_ADDRESS = 0
    WOTS_PK_ADDRESS = 1
    TREE_NODE_ADDRESS = 2

    def __init__(self):
        self.layer = 0
        self.tree_address = 0
        self.type = 0
        self.ots_address = 0
        self.chain_address = 0
        self.hash_address = 0
        self.key_and_mask = 0

    def set_type(self, type_val: int):
        self.type = type_val
        self.chain_address = 0
        self.hash_address = 0
        self.key_and_mask = 0

    def serialize(self) -> bytes:
        return struct.pack('>I Q I I I I I', 
            self.layer, self.tree_address, self.type, 
            self.ots_address, self.chain_address, self.hash_address, self.key_and_mask)

class RFC8391WOTSPlus:
    """RFC 8391 标准 WOTS+ 实现"""
    
    def __init__(self, w=16):
        self.w = w
        self.hash_len = 32
        self.len_1 = 64
        self.len_2 = 3
        self.length = self.len_1 + self.len_2

    def _prf(self, key: bytes, data: bytes) -> bytes:
        """伪随机函数"""
        return hashlib.sha256(key + data).digest()

    def _chain(self, x: bytes, start_step: int, steps: int, pub_seed: bytes, adrs: ADRS) -> bytes:
        """WOTS+ 链操作"""
        val = x
        for i in range(start_step, start_step + steps):
            adrs.hash_address = i
            adrs.key_and_mask = 0
            key = self._prf(pub_seed, adrs.serialize())
            adrs.key_and_mask = 1
            mask = self._prf(pub_seed, adrs.serialize())
            val = hashlib.sha256(key + bytes(v ^ m for v, m in zip(val, mask))).digest()
        return val

    def pk_gen(self, sk: list, pub_seed: bytes, adrs: ADRS) -> list:
        """从私钥生成公钥"""
        pk = []
        for i in range(self.length):
            adrs.chain_address = i
            pk.append(self._chain(sk[i], 0, self.w - 1, pub_seed, adrs))
        return pk

    def sign(self, msg_hash: bytes, sk: list, pub_seed: bytes, adrs: ADRS) -> list:
        """WOTS+ 签名生成"""
        msg_base_w = self._base_w(msg_hash, self.len_1)
        csum = sum(self.w - 1 - val for val in msg_base_w)
        msg_base_w += self._base_w(csum.to_bytes(2, 'big'), self.len_2)
        
        sig = []
        for i in range(self.length):
            adrs.chain_address = i
            sig.append(self._chain(sk[i], 0, msg_base_w[i], pub_seed, adrs))
        return sig

    def _base_w(self, data: bytes, out_len: int) -> list:
        """将字节转换为 base-w 表示"""
        res = []
        for b in data:
            res.extend([(b >> 4) & 0x0F, b & 0x0F])
        return res[:out_len]

class StatefulXMSS:
    """线程安全的有状态 XMSS 实现"""
    
    def __init__(self, tree_height: int = 4, state_file: str = "xmss_state.enc", 
                 master_key: bytes = None):
        self.h = tree_height
        self.num_leaves = 2 ** self.h
        self.state_file = state_file
        self.wots = RFC8391WOTSPlus()
        self.lock = threading.Lock()
        
        if not master_key:
            raise ValueError("生产环境必须提供随机 master_key")
        if len(master_key) != 32:
            raise ValueError("master_key 必须为 32 字节")
            
        self.aesgcm = AESGCM(master_key)

    def _derive_sk_leaf(self, master_seed: bytes, idx: int) -> list:
        """动态派生 WOTS+ 私钥：不存储 SK 列表"""
        return [
            hashlib.sha256(master_seed + struct.pack('>I I', idx, i)).digest() 
            for i in range(self.wots.length)
        ]

    def generate_keys(self) -> dict:
        """生成 XMSS 树并初始化加密状态"""
        
        logger.info(f"[XMSS] 开始生成树（高度={self.h}）...")
        pub_seed, master_seed = os.urandom(32), os.urandom(32)
        leaves = []
        
        adrs = ADRS()
        for i in range(self.num_leaves):
            adrs.ots_address = i
            sk = self._derive_sk_leaf(master_seed, i)
            pk = self.wots.pk_gen(sk, pub_seed, adrs)
            leaves.append(hashlib.sha256(b''.join(pk)).digest())
            
            if (i + 1) % max(1, self.num_leaves // 4) == 0:
                logger.info(f"[XMSS] 已生成 {i+1}/{self.num_leaves} 个叶子")

        # 自底向上构建树
        tree = [leaves]
        for level in range(self.h):
            last = tree[-1]
            next_level = []
            for i in range(0, len(last), 2):
                next_level.append(hashlib.sha256(last[i] + last[i+1]).digest())
            tree.append(next_level)

        state = {
            "index": 0,
            "pub_seed": pub_seed.hex(),
            "master_seed": master_seed.hex(),
            "tree": [[n.hex() for n in level] for level in tree],
            "tree_height": self.h
        }
        
        self._encrypt_save(state)
        logger.info(f"[XMSS] 树生成完毕，根: {state['tree'][-1][0][:16]}...")
        
        return {
            "root": bytes.fromhex(state["tree"][-1][0]),
            "pub_seed": pub_seed
        }

    def _encrypt_save(self, data: dict):
        """加密并保存状态"""
        nonce = os.urandom(12)
        ct = self.aesgcm.encrypt(nonce, json.dumps(data).encode(), None)
        
        with open(self.state_file, "wb") as f:
            f.write(nonce + ct)
        
        logger.debug(f"[XMSS] 状态已加密保存到 {self.state_file}")

    def _decrypt_load(self) -> dict:
        """解密并加载状态"""
        try:
            with open(self.state_file, "rb") as f:
                d = f.read()
            
            if len(d) < 12:
                raise ValueError("状态文件格式错误")
            
            plaintext = self.aesgcm.decrypt(d[:12], d[12:], None)
            return json.loads(plaintext.decode())
        except Exception as e:
            logger.error(f"[XMSS] 状态加载失败: {e}")
            raise

    def get_current_path_info(self) -> dict:
        """
        【防 DoS 预检接口】
        只读取公开路径和索引，绝不消耗宝贵的私钥状态
        """
        with self.lock:
            state = self._decrypt_load()
            leaf_idx = state["index"]
            
            if leaf_idx >= self.num_leaves:
                raise RuntimeError(f"私钥已耗尽 (索引: {leaf_idx}/{self.num_leaves})")
            
            # 从树中提取 Merkle 路径
            merkle_path = []
            for lvl in range(self.h):
                sibling_idx = (leaf_idx >> lvl) ^ 1
                sibling = bytes.fromhex(state["tree"][lvl][sibling_idx])
                merkle_path.append(sibling)
            
            # 返回当前叶子和路径信息
            leaf_pk = bytes.fromhex(state["tree"][0][leaf_idx])
            
            return {
                "xmss_index": leaf_idx,
                "xmss_path": merkle_path,
                "leaf_pk": leaf_pk
            }

    def generate_zkp_witness(self, message: bytes) -> dict:
        """
        【受保护接口】
        真正动用私钥签名，消耗叶子状态
        调用此方法会递增状态计数器
        """
        with self.lock:
            state = self._decrypt_load()
            idx = state["index"]
            
            if idx >= self.num_leaves:
                raise RuntimeError(f"私钥已耗尽 (当前索引: {idx})")
            
            # 加载种子
            pub_seed = bytes.fromhex(state["pub_seed"])
            master_seed = bytes.fromhex(state["master_seed"])
            
            # 派生当前叶子的私钥
            sk = self._derive_sk_leaf(master_seed, idx)
            
            # 生成 WOTS+ 签名
            adrs = ADRS()
            adrs.ots_address = idx
            sig = self.wots.sign(hashlib.sha256(message).digest(), sk, pub_seed, adrs)
            
            # 提取 Merkle 路径
            path = []
            for lvl in range(self.h):
                sibling_idx = (idx >> lvl) ^ 1
                sibling = bytes.fromhex(state["tree"][lvl][sibling_idx])
                path.append(sibling)
            
            # 状态滚动并落盘加密
            state["index"] += 1
            self._encrypt_save(state)
            
            logger.info(f"[XMSS] 已使用叶子 {idx}/{self.num_leaves}")
            
            return {
                "ots_sig": sig,
                "xmss_index": idx,
                "xmss_path": path,
                "pub_seed": pub_seed,
                "leaf_pk": bytes.fromhex(state["tree"][0][idx])
            }

    def get_state_info(self) -> dict:
        """获取状态信息（诊断用）"""
        with self.lock:
            state = self._decrypt_load()
            return {
                "current_index": state["index"],
                "total_leaves": self.num_leaves,
                "remaining": self.num_leaves - state["index"],
                "exhausted": state["index"] >= self.num_leaves
            }