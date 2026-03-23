"""
SLH-DSA 迁移测试: 验证 liboqs 实现

注意: 由于 XMSS 在当前 liboqs 版本中未编译，改用 SLH-DSA (FIPS 205)
"""
import pytest
import os
import tempfile
import shutil

# SLH-DSA/迁移测试需要 liboqs-python
pytest.importorskip("oqs")

from src.crypto_layer.xmss_stateful import StatefulXMSS


class TestXMSSLibOQSMigration:
    """验证从自实现到 liboqs 的迁移 (SLH-DSA)"""
    
    def test_initialization(self):
        """测试: SLH-DSA 初始化"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            xmss = StatefulXMSS(
                tree_height=10,  # 向后兼容参数，自动映射到安全级别
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x01' * 32
            )
            assert xmss.device_id == "test_device"
            assert xmss.security_level == 'medium'  # tree_height 10 映射到 medium
            # SLH-DSA 无状态，所以没有 tree_height 和 max_signatures
    
    def test_generate_keys(self):
        """测试: 密钥生成"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            xmss = StatefulXMSS(
                security_level='medium',
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x02' * 32
            )
            
            result = xmss.generate_keys()
            
            assert 'public_key' in result
            assert isinstance(result['public_key'], bytes)
            assert len(result['public_key']) == 64  # SLH-DSA 公钥大小
            assert result['security_level'] == 'medium'
            assert result['algorithm'] == 'SLH-DSA (FIPS 205)'
    
    def test_sign_and_verify(self):
        """测试: 签名和验证"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            xmss = StatefulXMSS(
                security_level='medium',
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x03' * 32
            )
            
            # 生成密钥对
            xmss.generate_keys()
            
            # 签名
            message = b"Test message for SLH-DSA"
            signature = xmss.sign(message)
            
            assert isinstance(signature, bytes)
            assert len(signature) > 0
            # SLH-DSA 签名通常很大 (~29KB for 256-bit)
            assert len(signature) > 1000
            
            # 验证
            is_valid = xmss.verify(message, signature)
            assert is_valid is True
    
    def test_stateless_signing(self):
        """测试: 无状态签名（SLH-DSA 不受签名数量限制）"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            xmss = StatefulXMSS(
                security_level='medium',
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x04' * 32
            )
            
            xmss.generate_keys()
            
            # 签名多条消息（SLH-DSA 无限制）
            for i in range(5):
                message = f"Message {i}".encode()
                signature = xmss.sign(message)
                assert isinstance(signature, bytes)
                
                # SLH-DSA 无状态，索引始终为 0
                assert xmss.get_current_index() == 0
    
    def test_remaining_signatures(self):
        """测试: 剩余签名数计算"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            xmss = StatefulXMSS(
                security_level='medium',
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x05' * 32
            )
            
            xmss.generate_keys()
            
            # SLH-DSA 无限制
            remaining = xmss.get_remaining_signatures()
            assert remaining == float('inf')
            
            # 签名后仍为无限
            xmss.sign(b"test")
            remaining = xmss.get_remaining_signatures()
            assert remaining == float('inf')
    
    def test_state_persistence(self):
        """测试: 状态持久化和恢复"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            
            # 第一个实例: 签名后保存
            xmss1 = StatefulXMSS(
                tree_height=10,
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x06' * 32
            )
            xmss1.generate_keys()
            pubkey1 = xmss1.get_root()
            
            for i in range(3):
                xmss1.sign(f"Message {i}".encode())
            
            # SLH-DSA 无状态，索引始终为 0
            index_after_signing = xmss1.get_current_index()
            assert index_after_signing == 0
            
            # 第二个实例: 加载状态
            xmss2 = StatefulXMSS(
                tree_height=10,
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x06' * 32  # 相同密钥
            )
            
            # 验证恢复的状态（SLH-DSA 无状态，只需验证公钥）
            pubkey2 = xmss2.get_root()
            assert pubkey1 == pubkey2
            
            # SLH-DSA 索引始终为 0（无状态）
            index_restored = xmss2.get_current_index()
            assert index_restored == 0
    
    def test_security_level_mapping(self):
        """测试: 安全级别映射"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # tree_height 向后兼容地映射到 security_level
            # h < 10: small, h = 10-15: medium, h = 16: large, h > 16: xlarge
            mapping = {
                9: 'small',
                10: 'medium',  # 改变：h=10现在映射到 medium
                15: 'medium',
                16: 'large',
                20: 'xlarge'
            }
            
            for height, expected_level in mapping.items():
                state_file = os.path.join(tmpdir, f"slhdsa_h{height}.state")
                xmss = StatefulXMSS(
                    tree_height=height,
                    device_id=f"test_h{height}",
                    state_file=state_file,
                    master_key=os.urandom(32)
                )
                assert xmss.security_level == expected_level, \
                    f"h={height}: 期望 {expected_level}，得到 {xmss.security_level}"
                assert xmss.sig_name.startswith('SLH_DSA')  # SLH-DSA 算法
    
    def test_multiple_signatures_no_exhaustion(self):
        """测试: SLH-DSA 无耗尽保护（任意数量签名）"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            xmss = StatefulXMSS(
                security_level='medium',
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x07' * 32
            )
            
            xmss.generate_keys()
            
            # SLH-DSA 可以签名任意数量的消息
            for i in range(10):
                sig = xmss.sign(f"Message {i}".encode())
                assert isinstance(sig, bytes)
            
            # 应该没有错误或耗尽异常
    
    def test_get_linkage_key(self):
        """测试: 链接密钥生成"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "test_slhdsa.state")
            xmss = StatefulXMSS(
                security_level='medium',
                device_id="test_device",
                state_file=state_file,
                master_key=b'\x08' * 32
            )
            
            xmss.generate_keys()
            linkage_key = xmss.get_linkage_key()
            
            assert isinstance(linkage_key, bytes)
            assert len(linkage_key) == 32  # SHA256 输出大小
    
    def test_multiple_devices(self):
        """测试: 多设备隔离"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # 设备 1
            state_file1 = os.path.join(tmpdir, "device1.state")
            xmss1 = StatefulXMSS(
                tree_height=10,
                device_id="device_1",
                state_file=state_file1,
                master_key=b'\x09' * 32
            )
            xmss1.generate_keys()
            pubkey1 = xmss1.get_root()
            
            # 设备 2
            state_file2 = os.path.join(tmpdir, "device2.state")
            xmss2 = StatefulXMSS(
                tree_height=10,
                device_id="device_2",
                state_file=state_file2,
                master_key=b'\x0A' * 32
            )
            xmss2.generate_keys()
            pubkey2 = xmss2.get_root()
            
            # 公钥不同（不同主密钥）
            assert pubkey1 != pubkey2


class TestXMSSLibOQSPerformance:
    """性能测试"""
    
    def test_signing_performance(self, benchmark):
        """基准测试: 签名性能"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "bench.state")
            xmss = StatefulXMSS(
                tree_height=10,
                device_id="bench_device",
                state_file=state_file,
                master_key=b'\x0F' * 32
            )
            xmss.generate_keys()
            message = b"Benchmark message"
            
            def sign_once():
                return xmss.sign(message)
            
            benchmark(sign_once)
    
    def test_verification_performance(self, benchmark):
        """基准测试: 验证性能"""
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = os.path.join(tmpdir, "bench.state")
            xmss = StatefulXMSS(
                tree_height=10,
                device_id="bench_device",
                state_file=state_file,
                master_key=b'\x10' * 32
            )
            xmss.generate_keys()
            message = b"Benchmark message"
            signature = xmss.sign(message)
            
            def verify_once():
                return xmss.verify(message, signature)
            
            benchmark(verify_once)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
