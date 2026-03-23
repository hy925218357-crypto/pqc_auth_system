"""KEM 密钥封装机制测试"""
import pytest

def test_keypair_generation(kem_engine):
    """测试密钥对生成"""
    pk, sk = kem_engine.generate_keypair()
    
    assert isinstance(pk, bytes)
    assert isinstance(sk, bytes)
    assert len(pk) > 0
    assert len(sk) > 0

def test_encapsulate_decapsulate(kem_engine):
    """测试封装与解封装"""
    pk, sk = kem_engine.generate_keypair()
    
    ct, k_enc = kem_engine.encapsulate(pk)
    k_dec = kem_engine.decapsulate(ct, sk)
    
    assert isinstance(ct, bytes)
    assert isinstance(k_enc, bytes)
    assert isinstance(k_dec, bytes)
    assert len(k_enc) == 32
    assert len(k_dec) == 32
    assert k_enc == k_dec  # 一致性检查

def test_get_algorithm_info(kem_engine):
    """测试算法信息获取"""
    info = kem_engine.get_algorithm_info()
    
    assert "name" in info
    assert "ML-KEM-512" in info["name"]