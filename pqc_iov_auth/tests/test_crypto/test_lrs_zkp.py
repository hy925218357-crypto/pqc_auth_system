"""环签名与 ZKP 测试"""
import pytest
import hashlib
import os

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

def test_ring_signature_generation(xmss_tree, lrs_engine, kem_engine):
    """测试环签名生成"""
    xmss_tree.generate_keys()
    kem_pk, kem_sk = kem_engine.generate_keypair()
    
    message = b"test_message"
    epoch = 0
    ct, k_session = kem_engine.encapsulate(kem_pk)
    
    path_info = xmss_tree.get_current_path_info()
    ring_root, ring_path = build_test_ring(path_info["leaf_pk"])
    
    sig = lrs_engine.sign(
        message=message,
        epoch=epoch,
        k_session=k_session,
        id_v="test_device",
        prover_xmss=xmss_tree,
        ring_root=ring_root,
        ring_path=ring_path,
        ring_index=0
    )
    
    assert "root_R" in sig
    assert "tag" in sig
    assert "zk_proof" in sig

def test_ring_signature_verification(xmss_tree, lrs_engine, kem_engine):
    """测试环签名验证"""
    xmss_tree.generate_keys()
    kem_pk, kem_sk = kem_engine.generate_keypair()
    
    message = b"test_message"
    epoch = 0
    ct, k_session = kem_engine.encapsulate(kem_pk)
    
    path_info = xmss_tree.get_current_path_info()
    ring_root, ring_path = build_test_ring(path_info["leaf_pk"])
    
    sig = lrs_engine.sign(
        message=message,
        epoch=epoch,
        k_session=k_session,
        id_v="test_device",
        prover_xmss=xmss_tree,
        ring_root=ring_root,
        ring_path=ring_path,
        ring_index=0
    )
    
    is_valid = lrs_engine.verify(message, sig, ring_root)
    assert is_valid is True