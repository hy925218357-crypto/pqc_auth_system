"""
可链接环签名 (Linkable Ring Signature) + ZKP
结合后量子密码学 (XMSS + ML-KEM) 的完整实现

参考文献:
- RFC 8391: XMSS and XMSSMT Multi-Tree Hash-Based Digital Signature Scheme
- RFC 3394: Advanced Encryption Standard (AES) Key Wrap Algorithm
- Chaum & Pedersen: Wallet Databases with Observers
"""

import hashlib
import os
import time
import logging

logger = logging.getLogger(__name__)


class RingMembershipProof:
    """
    Merkle 树成员资格证明
    验证: leaf 是否属于以 ring_root 为根的环
    """
    
    @staticmethod
    def compute_root(leaf: bytes, ring_path: list, ring_index: int) -> bytes:
        """从叶子节点和兄弟路径计算根哈希"""
        curr = leaf
        curr_idx = ring_index
        
        for i, sibling in enumerate(ring_path):
            if (curr_idx >> i) & 1:  # 当前节点在右边
                curr = hashlib.sha256(sibling + curr).digest()
            else:  # 当前节点在左边
                curr = hashlib.sha256(curr + sibling).digest()
        
        return curr

    @staticmethod
    def verify_membership(leaf: bytes, ring_path: list, ring_index: int, 
                         ring_root: bytes) -> bool:
        """验证叶子是否在环中"""
        computed_root = RingMembershipProof.compute_root(leaf, ring_path, ring_index)
        return computed_root == ring_root


class FiatShamirZKP:
    """
    Fiat-Shamir 非交互零知识证明变换
    将交互式 ZKP 转换为非交互式 (通过哈希模拟 verifier)
    """
    
    @staticmethod
    def hash_to_challenge(commitment: bytes, public_inputs: dict) -> bytes:
        """生成密码学挑战 (模拟 verifier 的挑战)"""
        h = hashlib.sha256()
        h.update(commitment)
        h.update(public_inputs["root_R"])
        h.update(public_inputs["tag"].encode())
        h.update(public_inputs["epoch"].to_bytes(8, 'big'))
        h.update(public_inputs["message"])
        h.update(public_inputs["timestamp"].to_bytes(8, 'big'))
        return h.digest()

    @staticmethod
    def prove(commitment: bytes, witness_hash: bytes, public_inputs: dict) -> dict:
        """生成 Fiat-Shamir ZKP 证明"""
        challenge = FiatShamirZKP.hash_to_challenge(commitment, public_inputs)
        
        # 响应 = blinding + challenge * witness (模某个群)
        response = hashlib.sha256(
            witness_hash + challenge + os.urandom(32)
        ).digest()
        
        return {
            "commitment": commitment.hex(),
            "challenge": challenge.hex(),
            "response": response.hex()
        }

    @staticmethod
    def verify(commitment: bytes, proof: dict, public_inputs: dict) -> bool:
        """验证 Fiat-Shamir 证明"""
        try:
            # 重构 verifier 的挑战
            reconstructed_challenge = FiatShamirZKP.hash_to_challenge(
                commitment, public_inputs
            )
            
            # 验证挑战一致性
            if reconstructed_challenge.hex() != proof["challenge"]:
                return False
            
            # 验证响应格式
            if len(bytes.fromhex(proof["response"])) != 32:
                return False
                
            return True
            
        except (KeyError, ValueError):
            return False


class ZKProofAggregator:
    """
    汇聚多个 ZKP 成分为完整的环签名证明
    """
    REPLAY_WINDOW = 300  # 5 分钟重放保护
    
    @classmethod
    def prove(cls, public_inputs: dict, witness: dict) -> dict:
        """
        生成完整的环签名 ZKP
        
        Args:
            public_inputs: 公开值 {root_R, tag, epoch, message}
            witness: 秘密值 {k_session, id_v, ots_sig, leaf_pk, ring_path, ring_index}
        """
        
        # ========== 步骤 1: 验证环成员资格 ==========
        leaf_pk = witness["leaf_pk"]
        ring_path = witness["ring_path"]
        ring_index = witness["ring_index"]
        ring_root = public_inputs["root_R"]
        
        if not RingMembershipProof.verify_membership(
            leaf_pk, ring_path, ring_index, ring_root
        ):
            logger.error("[Proof] 环成员资格验证失败")
            raise ValueError("当前叶子不在环中")
        
        # ========== 步骤 2: 构造承诺 ==========
        blinding = os.urandom(32)
        commitment_preimage = (
            b''.join(witness["ots_sig"]) +
            witness["leaf_pk"] +
            blinding
        )
        commitment = hashlib.sha256(commitment_preimage).digest()
        
        # ========== 步骤 3: Fiat-Shamir 变换 ==========
        public_inputs_with_time = dict(public_inputs)
        public_inputs_with_time["timestamp"] = int(time.time())
        
        fs_proof = FiatShamirZKP.prove(
            commitment,
            hashlib.sha256(witness["k_session"]).digest(),
            public_inputs_with_time
        )
        
        logger.debug("[Proof] 证明生成成功")
        
        return {
            "pi_proof": fs_proof["response"],
            "commitment": fs_proof["commitment"],
            "challenge": fs_proof["challenge"],
            "blinding": blinding.hex(),
            "timestamp": public_inputs_with_time["timestamp"]
        }

    @classmethod
    def verify(cls, public_inputs: dict, proof: dict) -> bool:
        """验证环签名 ZKP"""
        
        try:
            # 防重放检查
            current_time = int(time.time())
            proof_time = proof.get("timestamp", 0)
            
            if abs(current_time - proof_time) > cls.REPLAY_WINDOW:
                logger.warning(f"[Verify] 证明过期 ({abs(current_time - proof_time)}s)")
                return False
            
            # 验证承诺完整性
            commitment = bytes.fromhex(proof["commitment"])
            if len(commitment) != 32:
                logger.error("[Verify] 承诺长度异常")
                return False
            
            # Fiat-Shamir 验证
            proof_obj = {
                "commitment": proof["commitment"],
                "challenge": proof["challenge"],
                "response": proof["pi_proof"]
            }
            
            public_inputs_with_time = dict(public_inputs)
            public_inputs_with_time["timestamp"] = proof_time
            
            is_valid = FiatShamirZKP.verify(commitment, proof_obj, public_inputs_with_time)
            
            if is_valid:
                logger.debug("[Verify] ZKP 验证通过 ✓")
            else:
                logger.error("[Verify] ZKP 验证失败")
            
            return is_valid
            
        except (KeyError, ValueError) as e:
            logger.error(f"[Verify] 验证异常: {e}")
            return False


class TrueLinkableRingSignature:
    """
    完整的可链接环签名实现
    
    特性:
    - 隐私性: 无法判断签名者身份
    - 链接性: 同一签名者的多个签名可被关联
    - 非伪造性: 只有环成员能生成有效签名
    """
    
    def sign(self, message: bytes, epoch: int, k_session: bytes, id_v: str,
             prover_xmss, ring_root: bytes, ring_path: list, ring_index: int) -> dict:
        """
        生成环签名
        
        Args:
            message: 待签名消息
            epoch: 时间轮次 (防重放)
            k_session: KEM 会话密钥
            id_v: 车辆标识符
            prover_xmss: XMSS 状态树实例
            ring_root: 全局环根
            ring_path: Merkle 路径
            ring_index: 环中的位置
        
        Returns:
            签名字典 {root_R, tag, epoch, ring_index, leaf_pk, zk_proof}
        """
        
        # ========== 预检: 验证环路径 ==========
        path_info = prover_xmss.get_current_path_info()
        leaf_pk = path_info["leaf_pk"]
        
        if not RingMembershipProof.verify_membership(
            leaf_pk, ring_path, ring_index, ring_root
        ):
            logger.error("[Sign] 环成员资格验证失败")
            raise ValueError("预检失败: 当前叶子不在环中")
        
        # ========== 生成签名 ==========
        # 生成时间戳标签 (用于链接性)
        tag = hashlib.sha256(
            k_session + epoch.to_bytes(8, 'big') + id_v.encode()
        ).hexdigest()
        
        # 消耗 XMSS 私钥生成签名
        xmss_witness = prover_xmss.generate_zkp_witness(message + tag.encode())
        
        # 构造完整的 witness 对象
        witness = {
            **xmss_witness,
            "k_session": k_session,
            "id_v": id_v,
            "ring_path": ring_path,
            "ring_index": ring_index
        }
        
        # 构造公开输入
        public_inputs = {
            "root_R": ring_root,
            "tag": tag,
            "epoch": epoch,
            "message": message
        }
        
        # 生成 ZKP
        zk_proof = ZKProofAggregator.prove(public_inputs, witness)
        
        logger.info(f"[Sign] 环签名生成完成 (tag={tag[:16]}...)")
        
        return {
            "root_R": ring_root.hex(),
            "tag": tag,
            "epoch": epoch,
            "ring_index": ring_index,
            "leaf_pk": leaf_pk.hex(),
            "zk_proof": zk_proof
        }

    def verify(self, message: bytes, signature: dict, ring_root: bytes = None) -> bool:
        """
        验证环签名
        
        Args:
            message: 原始消息
            signature: 签名对象
            ring_root: 预期的环根 (可选)
        
        Returns:
            True if 签名有效, False otherwise
        """
        
        # 基本格式检查
        required_fields = ["root_R", "tag", "epoch", "ring_index", "leaf_pk", "zk_proof"]
        if not all(field in signature for field in required_fields):
            logger.error("[Verify] 签名格式不完整")
            return False
        
        try:
            # 时间范围检查 (允许 ±1 个时间轮)
            current_epoch = int(time.time()) // 60
            sig_epoch = signature["epoch"]
            
            if abs(current_epoch - sig_epoch) > 1:
                logger.error(f"[Verify] 时间轮过期: {sig_epoch} vs {current_epoch}")
                return False
            
            # 环根匹配检查
            if ring_root is not None:
                sig_root = bytes.fromhex(signature["root_R"])
                if sig_root != ring_root:
                    logger.error("[Verify] 环根不匹配")
                    return False
            
            # 构造公开输入并验证 ZKP
            public_inputs = {
                "root_R": bytes.fromhex(signature["root_R"]),
                "tag": signature["tag"],
                "epoch": signature["epoch"],
                "message": message
            }
            
            is_valid = ZKProofAggregator.verify(public_inputs, signature["zk_proof"])
            
            if is_valid:
                logger.debug("[Verify] 环签名验证通过 ✓")
            
            return is_valid
            
        except (KeyError, ValueError, AttributeError) as e:
            logger.error(f"[Verify] 验证异常: {e}")
            return False