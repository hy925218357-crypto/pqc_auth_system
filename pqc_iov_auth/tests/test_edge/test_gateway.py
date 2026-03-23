"""Mock Redis 测试防重放与 epoch 窗口限制"""
import pytest
pytest.importorskip("redis")
pytest.importorskip("oqs")
from unittest.mock import Mock, patch
import os
import sys

# 添加 src 到路径
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'src')))

from edge_node.auth_gateway import AuthGateway

def test_register_device():
    """测试设备注册"""
    with patch('redis.Redis') as mock_redis:
        mock_redis_instance = Mock()
        mock_redis.return_value = mock_redis_instance

        gateway = AuthGateway()
        result = gateway.register_device("test_device", b"\x01" * 32)

        assert result["status"] == "registered"
        assert result["device_id"] == "test_device"
        mock_redis_instance.hset.assert_called_once()

def test_authenticate_device_success():
    """测试认证成功"""
    with patch('redis.Redis') as mock_redis:
        mock_redis_instance = Mock()
        mock_redis_instance.hget.return_value = "00" * 32  # 模拟环根
        mock_redis_instance.sismember.return_value = False  # tag 未使用
        mock_redis.return_value = mock_redis_instance

        gateway = AuthGateway()

        # Mock 签名验证通过
        with patch.object(gateway.lrs_engine, 'verify', return_value=True):
            auth_request = {
                "device_id": "test_device",
                "signature": {"linkage_tag": "test_tag"},
                "message": b"test",
                "epoch": 1000
            }
            result = gateway.authenticate_device(auth_request)

            assert result["status"] == "authenticated"
            mock_redis_instance.sadd.assert_called_once()

def test_authenticate_device_replay():
    """测试防重放攻击"""
    with patch('redis.Redis') as mock_redis:
        mock_redis_instance = Mock()
        mock_redis_instance.hget.return_value = "00" * 32
        mock_redis_instance.sismember.return_value = True  # tag 已使用
        mock_redis.return_value = mock_redis_instance

        gateway = AuthGateway()

        with patch.object(gateway.lrs_engine, 'verify', return_value=True):
            auth_request = {
                "device_id": "test_device",
                "signature": {"linkage_tag": "test_tag"},
                "message": b"test",
                "epoch": 1000
            }
            result = gateway.authenticate_device(auth_request)

            assert result["status"] == "failed"
            assert result["reason"] == "tag_replayed"


def test_authenticate_device_not_registered():
    """测试设备未注册时认证失败"""
    with patch('redis.Redis') as mock_redis:
        mock_redis_instance = Mock()
        mock_redis_instance.hget.return_value = None
        mock_redis.return_value = mock_redis_instance

        gateway = AuthGateway()
        auth_request = {
            "device_id": "unknown_device",
            "signature": {"linkage_tag": "test_tag"},
            "message": b"test",
            "epoch": 1000
        }
        result = gateway.authenticate_device(auth_request)

        assert result["status"] == "failed"
        assert result["reason"] == "device_not_registered"


def test_authenticate_device_epoch_mismatch():
    """测试签名epoch与请求epoch不一致"""
    with patch('redis.Redis') as mock_redis:
        mock_redis_instance = Mock()
        mock_redis_instance.hget.return_value = "00" * 32
        mock_redis.return_value = mock_redis_instance

        gateway = AuthGateway()
        with patch.object(gateway.lrs_engine, 'verify', return_value=True):
            auth_request = {
                "device_id": "test_device",
                "signature": {"linkage_tag": "test_tag", "epoch": 1001},
                "message": b"test",
                "epoch": 1000
            }
            result = gateway.authenticate_device(auth_request)

            assert result["status"] == "failed"
            assert result["reason"] == "epoch_mismatch"