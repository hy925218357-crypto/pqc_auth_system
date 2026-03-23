"""密码学基础层

使用 NIST 标准的后量子密码学库:
- XMSS: liboqs-python (RFC 8391)
- Kyber KEM: liboqs (ML-KEM)
- 环签名 + ZKP: 待升级至 Dilithium
"""

try:
    from src.crypto_layer.kyber_kem import KyberKEMEngine
    from src.crypto_layer.xmss_stateful import StatefulXMSS
    from src.crypto_layer.lrs_zkp import (
        TrueLinkableRingSignature,
        RingMembershipProof,
        SchnorrZKP,
        ZKProofAggregator,
    )

    __all__ = [
        "KyberKEMEngine",
        "StatefulXMSS",
        "TrueLinkableRingSignature",
        "RingMembershipProof",
        "SchnorrZKP",
        "ZKProofAggregator",
    ]
except Exception:  # pragma: no cover
    # 缺少 oqs/liboqs-python 时，允许 crypto_layer 被导入但不导出 PQC 组件。
    KyberKEMEngine = None
    StatefulXMSS = None
    TrueLinkableRingSignature = None
    RingMembershipProof = None
    SchnorrZKP = None
    ZKProofAggregator = None
    __all__ = []