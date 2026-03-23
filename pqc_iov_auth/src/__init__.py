"""
PQC IoV Authentication System
Post-Quantum Cryptography for Internet of Vehicles
"""

__version__ = "1.0.0"
__author__ = "Your Name"

# PQC 组件是可选依赖（需要 liboqs-python / oqs）。
# 为了让不相关模块/测试在缺少 oqs 时也能被收集执行，这里使用懒加载/可选导入。
try:
    from src.crypto_layer.kyber_kem import KyberKEMEngine
    from src.crypto_layer.xmss_stateful import StatefulXMSS
    from src.crypto_layer.lrs_zkp import TrueLinkableRingSignature

    __all__ = [
        "KyberKEMEngine",
        "StatefulXMSS",
        "TrueLinkableRingSignature",
    ]
except Exception:  # pragma: no cover
    KyberKEMEngine = None
    StatefulXMSS = None
    TrueLinkableRingSignature = None
    __all__ = []