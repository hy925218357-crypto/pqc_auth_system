"""
车辆/物联网终端客户端
发起认证请求的主要接口
"""
import os
import time
import logging
from typing import Dict

logger = logging.getLogger(__name__)

class IoVClient:
    """物联网车辆客户端"""
    
    def __init__(self, device_id: str, xmss_tree_height: int = 6,
                 state_file: str = None):
        """
        初始化客户端
        
        Args:
            device_id: 设备唯一标识符
            xmss_tree_height: XMSS 树高
            state_file: 状态文件路径
        """
        self.device_id = device_id
        self.tree_height = xmss_tree_height
        
        # 导入密码学模块
        from src.crypto_layer.kyber_kem import KyberKEMEngine
        from src.crypto_layer.xmss_stateful import StatefulXMSS
        from src.crypto_layer.lrs_zkp import TrueLinkableRingSignature
        
        # 初始化密码学引擎
        self.kem_engine = KyberKEMEngine("ML-KEM-512")
        
        if state_file is None:
            state_file = f"/tmp/{device_id}_xmss_state.enc"
        
        self.xmss = StatefulXMSS(
            tree_height=tree_height,
            state_file=state_file,
            master_key=os.urandom(32)
        )
        
        self.lrs_engine = TrueLinkableRingSignature()
        
        logger.info(f"[Client] 设备 {device_id} 已初始化")
    
    def authenticate(self, server_pk: bytes, ring_root: bytes, 
                    ring_path: list, ring_index: int) -> Dict:
        """
        执行认证流程
        
        Args:
            server_pk: 服务端公钥
            ring_root: 环根
            ring_path: Merkle 路径
            ring_index: 环中位置
        
        Returns:
            认证请求 {ct, signature, ...}
        """
        message = f"auth_request_{int(time.time())}".encode()
        epoch = int(time.time()) // 60
        
        # 1. KEM 封装
        ct, k_session = self.kem_engine.encapsulate(server_pk)
        
        # 2. 生成环签名
        sig = self.lrs_engine.sign(
            message=message,
            epoch=epoch,
            k_session=k_session,
            id_v=self.device_id,
            prover_xmss=self.xmss,
            ring_root=ring_root,
            ring_path=ring_path,
            ring_index=ring_index
        )
        
        logger.info(f"[Client] 认证请求已生成 (epoch={epoch})")
        
        return {
            "device_id": self.device_id,
            "message": message.hex(),
            "ciphertext": ct.hex(),
            "signature": sig,
            "timestamp": int(time.time())
        }