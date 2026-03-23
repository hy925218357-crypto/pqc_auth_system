import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    # 让 tests 里能直接 `import src...`
    sys.path.insert(0, str(REPO_ROOT))


@pytest.fixture
def kem_engine():
    """ML-KEM 引擎（需要 liboqs-python）"""
    pytest.importorskip("oqs")
    from src.crypto_layer.kyber_kem import KyberKEMEngine

    return KyberKEMEngine("ML-KEM-512")


@pytest.fixture
def lrs_engine():
    """Linkable Ring Signature 引擎（需要 liboqs-python）"""
    pytest.importorskip("oqs")
    from src.crypto_layer.lrs_zkp import TrueLinkableRingSignature

    return TrueLinkableRingSignature()


@pytest.fixture
def xmss_tree(tmp_path):
    """用于测试的 XMSS/SLH-DSA 兼容对象（需要 liboqs-python）"""
    pytest.importorskip("oqs")
    from src.crypto_layer.xmss_stateful import StatefulXMSS

    state_file = os.path.join(str(tmp_path), "test_xmss.state")
    # 使用固定 master_key 以便测试可重复；状态会被加密保存到 state_file
    return StatefulXMSS(tree_height=2, state_file=state_file, master_key=b"\x01" * 32)

