"""双层混合认证协议交互 [cite: 18]"""
import logging
import redis
from typing import Dict, Any

from crypto_layer.lrs_zkp import TrueLinkableRingSignature
from crypto_layer.kyber_kem import KyberKEMEngine
from crypto_layer.xmss_stateful import StatefulXMSS

logger = logging.getLogger(__name__)

class AuthGateway:
    """边缘节点认证网关：处理终端注册与匿名认证请求"""

    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379):
        self.redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        self.kem_engine = KyberKEMEngine()
        self.lrs_engine = TrueLinkableRingSignature()

    def register_device(self, device_id: str, xmss_master_key: bytes) -> Dict[str, Any]:
        """
        设备注册：生成 XMSS 密钥树并存储环根到区块链

        Args:
            device_id: 设备标识符
            xmss_master_key: XMSS 主密钥

        Returns:
            注册响应
        """
        xmss = StatefulXMSS(tree_height=4, state_file=f"xmss_{device_id}.state", master_key=xmss_master_key)
        root_info = xmss.generate_keys()

        # 存储到 Redis 缓存
        self.redis.hset(f"device:{device_id}", "ring_root", root_info["root"].hex())

        logger.info(f"设备 {device_id} 注册成功，环根: {root_info['root'].hex()[:16]}...")

        return {
            "status": "registered",
            "ring_root": root_info["root"].hex(),
            "device_id": device_id
        }

    def authenticate_device(self, auth_request: Dict[str, Any]) -> Dict[str, Any]:
        """
        匿名认证：验证环签名并检查 tag 关联性

        Args:
            auth_request: 认证请求 {device_id, signature, message, epoch}

        Returns:
            认证响应
        """
        device_id = auth_request["device_id"]
        signature = auth_request["signature"]
        message = auth_request["message"]
        epoch = auth_request["epoch"]

        # 从缓存获取环根
        ring_root_hex = self.redis.hget(f"device:{device_id}", "ring_root")
        if not ring_root_hex:
            return {"status": "failed", "reason": "device_not_registered"}

        ring_root = bytes.fromhex(ring_root_hex)

        # 验证签名
        is_valid = self.lrs_engine.verify(message, signature, ring_root)

        if is_valid:
            # 检查 tag 是否已使用（防重放）
            linkage_tag = signature["linkage_tag"]
            if self.redis.sismember(f"used_tags:{epoch}", linkage_tag):
                return {"status": "failed", "reason": "tag_replayed"}

            self.redis.sadd(f"used_tags:{epoch}", linkage_tag)
            logger.info(f"设备 {device_id} 认证成功，tag: {linkage_tag[:16]}...")
            return {"status": "authenticated", "device_id": device_id}

        return {"status": "failed", "reason": "invalid_signature"}