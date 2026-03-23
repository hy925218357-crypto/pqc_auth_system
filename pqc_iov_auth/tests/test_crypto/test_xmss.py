"""XMSS 数字签名测试"""
import pytest
import os

def test_tree_generation(xmss_tree):
    """测试 XMSS 树生成"""
    result = xmss_tree.generate_keys()
    
    assert "root" in result
    assert "pub_seed" in result
    assert isinstance(result["root"], bytes)
    assert len(result["root"]) == 32

def test_get_path_info(xmss_tree):
    """测试获取路径信息"""
    xmss_tree.generate_keys()
    path_info = xmss_tree.get_current_path_info()
    
    assert "xmss_index" in path_info
    assert "xmss_path" in path_info
    assert "leaf_pk" in path_info
    assert path_info["xmss_index"] == 0
    assert len(path_info["xmss_path"]) == 4  # tree_height=4

def test_zkp_witness_generation(xmss_tree):
    """测试 ZKP witness 生成"""
    xmss_tree.generate_keys()
    message = b"test_message"
    
    witness = xmss_tree.generate_zkp_witness(message)
    
    assert "ots_sig" in witness
    assert "xmss_index" in witness
    assert witness["xmss_index"] == 0
    
    # 第二次应该递增
    witness2 = xmss_tree.generate_zkp_witness(message)
    assert witness2["xmss_index"] == 1

def test_state_exhaustion(xmss_tree):
    """测试私钥耗尽"""
    xmss_tree.generate_keys()
    
    # 消耗所有 2^4=16 个叶子
    for i in range(16):
        witness = xmss_tree.generate_zkp_witness(b"msg")
    
    # 第 17 次应该抛出异常
    with pytest.raises(RuntimeError, match="私钥已耗尽"):
        xmss_tree.generate_zkp_witness(b"msg")