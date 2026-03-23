"""环签名与 ZKP 测试"""
import os
import sys
import time
import hashlib

# 本地测试时把 src 目录加入 sys.path
src_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
sys.path.insert(0, src_root)

# 直接加载模块，避免触发 crypto_layer/__init__.py 中依赖 oqs 的导入
import importlib.util

def _load_module(name, relative_path):
    path = os.path.join(src_root, relative_path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

lrs_zkp_mod = _load_module('lrs_zkp', 'crypto_layer/lrs_zkp.py')
xmss_mod = _load_module('xmss_stateful', 'crypto_layer/xmss_stateful.py')

TrueLinkableRingSignature = lrs_zkp_mod.TrueLinkableRingSignature
RingMembershipProof = lrs_zkp_mod.RingMembershipProof
SchnorrZKP = lrs_zkp_mod.SchnorrZKP
ZKProofAggregator = lrs_zkp_mod.ZKProofAggregator
StatefulXMSS = xmss_mod.StatefulXMSS


def build_test_ring(leaf: bytes, ring_size: int = 8) -> tuple:
    """构建测试环"""
    leaves = [leaf]
    for i in range(1, ring_size):
        leaves.append(hashlib.sha256(f"ring_member_{i}".encode()).digest())
    
    # 补齐为 2 的幂次
    while len(leaves) & (len(leaves) - 1) != 0:
        leaves.append(hashlib.sha256(b"padding").digest())
    
    # 构建 Merkle 树
    tree = [leaves[:]]
    while len(tree[-1]) > 1:
        next_level = []
        for i in range(0, len(tree[-1]), 2):
            parent = hashlib.sha256(tree[-1][i] + tree[-1][i+1]).digest()
            next_level.append(parent)
        tree.append(next_level)
    
    # 提取路径
    path = []
    idx = 0
    for level in range(len(tree) - 1):
        sibling_idx = (idx >> level) ^ 1
        if sibling_idx < len(tree[level]):
            path.append(tree[level][sibling_idx])
    
    return tree[-1][0], path

def test_ring_membership_proof_validity():
    leaf = hashlib.sha256(b"leaf").digest()
    root, path = build_test_ring(leaf, ring_size=4)

    # 给定正确的路径、索引验证成功
    assert RingMembershipProof.verify_membership(leaf, path, 0, root) is True

    # 错误 leaf 失败
    assert RingMembershipProof.verify_membership(hashlib.sha256(b"wrong").digest(), path, 0, root) is False


def test_schnorr_zkp_roundtrip():
    secret = hashlib.sha256(b"my_secret").digest()
    public_data = {
        "leaf_pk": b"leaf_pk",
        "ring_root": b"root",
        "message": b"hello",
        "timestamp": int(time.time())
    }

    proof = SchnorrZKP.prove(secret, public_data, additional_info=b"tag")
    assert "public_key" in proof
    assert "signature" in proof

    assert SchnorrZKP.verify(proof, public_data, additional_info=b"tag") is True

    # 被篡改消息验证失败
    bad_data = dict(public_data)
    bad_data["message"] = b"changed"
    assert SchnorrZKP.verify(proof, bad_data, additional_info=b"tag") is False


def test_zkp_aggregator_and_true_linkable_end_to_end():
    xmss = StatefulXMSS(tree_height=2, state_file="tmp_xmss.state", master_key=b"\x01" * 32)
    root_info = xmss.generate_keys()
    path_info = xmss.get_current_path_info()
    ring_root = root_info["root"]
    ring_path = path_info["xmss_path"]
    ring_index = path_info["xmss_index"]

    signer = TrueLinkableRingSignature()
    msg = b"message"
    epoch = int(time.time()) // 60
    k_session = os.urandom(32)

    sig = signer.sign(
        message=msg,
        epoch=epoch,
        k_session=k_session,
        id_v="device123",
        prover_xmss=xmss,
        ring_root=ring_root,
        ring_path=ring_path,
        ring_index=ring_index
    )

    assert signer.verify(msg, sig, ring_root=ring_root) is True

    # 重放数据失败（nonce 重复）
    assert signer.verify(msg, sig, ring_root=ring_root) is False

    # 信息篡改失败
    bad_sig = dict(sig)
    bad_sig["root_R"] = hashlib.sha256(b"bad_root").hexdigest()
    assert signer.verify(msg, bad_sig, ring_root=ring_root) is False


def test_linkage_tag_different_devices():
    xmss = StatefulXMSS(tree_height=2, state_file="tmp_xmss2.state", master_key=b"\x02" * 32)
    root_info = xmss.generate_keys()
    path_info = xmss.get_current_path_info()

    signer = TrueLinkableRingSignature()
    epoch = 5555
    k_session = os.urandom(32)

    sig1 = signer.sign(
        message=b"m1",
        epoch=epoch,
        k_session=k_session,
        id_v="vehicle_A",
        prover_xmss=xmss,
        ring_root=root_info["root"],
        ring_path=path_info["xmss_path"],
        ring_index=path_info["xmss_index"]
    )

    # 重新初始化一个新 XMSS 代表不同设备
    xmss2 = StatefulXMSS(tree_height=2, state_file="tmp_xmss3.state", master_key=b"\x03" * 32)
    root_info2 = xmss2.generate_keys()
    path_info2 = xmss2.get_current_path_info()

    sig2 = signer.sign(
        message=b"m2",
        epoch=epoch,
        k_session=os.urandom(32),
        id_v="vehicle_B",
        prover_xmss=xmss2,
        ring_root=root_info2["root"],
        ring_path=path_info2["xmss_path"],
        ring_index=path_info2["xmss_index"]
    )

    assert sig1["linkage_tag"] != sig2["linkage_tag"]
