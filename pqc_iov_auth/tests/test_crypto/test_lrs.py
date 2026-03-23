"""
环签名修复验证测试
验证：
1. ZKP 验证逻辑正确性
2. 可链接性（同一设备相同 tag）
3. 防伪造（随机证明无法通过）
"""
import pytest
import hashlib
import os

def build_test_ring(leaf: bytes, ring_size: int = 8) -> tuple:
    """构建 8 元素的测试环"""
    leaves = [leaf]
    for i in range(1, ring_size):
        leaves.append(hashlib.sha256(f"ring_member_{i}".encode()).digest())
    
    # 补齐 2 的幂次
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

def test_zkp_verification_correctness(xmss_tree, lrs_engine, kem_engine):
    """测试 ZKP 验证逻辑的正确性"""
    xmss_tree.generate_keys()
    kem_pk, kem_sk = kem_engine.generate_keypair()
    
    message = b"test_message_correctness"
    epoch = 1000
    
    ct, k_session = kem_engine.encapsulate(kem_pk)
    path_info = xmss_tree.get_current_path_info()
    ring_root, ring_path = build_test_ring(path_info["leaf_pk"])
    
    # 生成签名
    sig = lrs_engine.sign(
        message=message,
        epoch=epoch,
        k_session=k_session,
        id_v="device_123",
        prover_xmss=xmss_tree,
        ring_root=ring_root,
        ring_path=ring_path,
        ring_index=0
    )
    
    # 验证正确性：有效签名应该通过验证
    assert lrs_engine.verify(message, sig, ring_root) is True
    
    # 验证完整性：修改消息后应该失败
    assert lrs_engine.verify(b"modified_message", sig, ring_root) is False
    
    # 验证完整性：修改 tag 后应该失败
    bad_sig = dict(sig)
    bad_sig["linkage_tag"] = "0" * 64
    assert lrs_engine.verify(message, bad_sig, ring_root) is False

def test_linkability_same_device(xmss_tree, lrs_engine, kem_engine):
    """测试可链接性：同一设备在同一 epoch 应产生相同的 tag"""
    xmss_tree.generate_keys()
    kem_pk, kem_sk = kem_engine.generate_keypair()
    
    epoch = 2000
    device_id = "vehicle_ABC"
    
    # 生成两个不同的消息但在同一 epoch
    ct1, k1 = kem_engine.encapsulate(kem_pk)
    path_info1 = xmss_tree.get_current_path_info()
    ring_root1, ring_path1 = build_test_ring(path_info1["leaf_pk"])
    
    sig1 = lrs_engine.sign(
        message=b"msg_1",
        epoch=epoch,
        k_session=k1,
        id_v=device_id,
        prover_xmss=xmss_tree,
        ring_root=ring_root1,
        ring_path=ring_path1,
        ring_index=0
    )
    
    # 第二个签名
    ct2, k2 = kem_engine.encapsulate(kem_pk)
    path_info2 = xmss_tree.get_current_path_info()
    ring_root2, ring_path2 = build_test_ring(path_info2["leaf_pk"])
    
    sig2 = lrs_engine.sign(
        message=b"msg_2",
        epoch=epoch,
        k_session=k2,
        id_v=device_id,
        prover_xmss=xmss_tree,
        ring_root=ring_root2,
        ring_path=ring_path2,
        ring_index=0
    )
    
    # 同一设备在同一 epoch，tag 应相同
    assert sig1["linkage_tag"] == sig2["linkage_tag"], \
        "同一设备同一 epoch 的 tag 应相同（可链接性）"

def test_no_forgery_random_proof(lrs_engine):
    """测试防伪造：随机 ZKP 数据无法通过验证"""
    # 构造伪造的签名（完全随机数据）
    fake_sig = {
        "root_R": hashlib.sha256(b"fake_root").digest().hex(),
        "linkage_tag": hashlib.sha256(b"fake_tag").digest().hexdigest(),
        "epoch": 3000,
        "ring_index": 0,
        "leaf_pk": hashlib.sha256(b"fake_leaf").digest().hex(),
        "zk_proof": {
            "ring_proof": {
                "leaf": hashlib.sha256(b"fake").digest().hex(),
                "path_length": 4,
                "index": 0,
                "root": hashlib.sha256(b"fake_root").digest().hex()
            },
            "schnorr_proof": {
                "commitment": os.urandom(32).hex(),
                "challenge": hex(os.urandom(8)[0]),
                "response": os.urandom(32).hex(),
                "timestamp": 0
            },
            "nonce": os.urandom(32).hex(),
            "timestamp": 0
        },
        "timestamp": 0
    }
    
    # 随机伪造的证明应该无法通过验证
    assert lrs_engine.verify(b"any_message", fake_sig) is False, \
        "伪造的 ZKP 应该被检测"