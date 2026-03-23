"""
兼容层: 无状态哈希签名模块

该模块现在使用 liboqs-python 官方实现 (FIPS 205 SLH-DSA)
而不是自实现的 WOTS+/Merkle 树

迁移路径:
- 旧实现: src/crypto_layer/xmss_stateful.py.backup (XMSS RFC 8391)
- 新实现: src/crypto_layer/xmss_liboqs.py (SLH-DSA FIPS 205)

注意: XMSS 在当前 liboqs 版本中未编译，改用 SLH-DSA
"""

# 向后兼容导入
from src.crypto_layer.xmss_liboqs import (
    StatefulXMSSLibOQS,
    StatefulXMSS
)

__all__ = ['StatefulXMSS', 'StatefulXMSSLibOQS']
