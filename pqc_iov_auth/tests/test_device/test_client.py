"""测试终端完整的注册与认证流程发起"""
import pytest
import os
import sys
from unittest.mock import Mock, patch

pytest.importorskip("requests")

# 为了兼容历史测试：让 `device_node` 可被正确导入
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from src.device_node.client import DeviceClient

def test_device_registration():
    """测试设备注册流程"""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {"status": "registered"}
        mock_post.return_value = mock_response

        client = DeviceClient("test_device", b"\x01" * 32)
        result = client.register()

        assert result["status"] == "registered"
        mock_post.assert_called_once()

def test_device_authentication():
    """测试设备认证流程"""
    with patch('requests.post') as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {"status": "authenticated"}
        mock_post.return_value = mock_response

        client = DeviceClient("test_device", b"\x01" * 32)
        result = client.authenticate(b"test_message", 1000)

        assert result["status"] == "authenticated"
        mock_post.assert_called_once()