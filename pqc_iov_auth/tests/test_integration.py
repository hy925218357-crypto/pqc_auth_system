"""端到端集成测试：模拟完整认证流程"""
import os
import sys
import time
import tempfile
import shutil
from unittest.mock import Mock, patch

# 动态加载模块避免 oqs 依赖
import importlib.util

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# 直接加载核心模块
lrs_zkp_mod = load_module('lrs_zkp', 'src/crypto_layer/lrs_zkp.py')
xmss_mod = load_module('xmss_stateful', 'src/crypto_layer/xmss_stateful.py')

TrueLinkableRingSignature = lrs_zkp_mod.TrueLinkableRingSignature
StatefulXMSS = xmss_mod.StatefulXMSS

def test_end_to_end_authentication():
    """端到端认证流程测试"""
    # 创建临时目录
    temp_dir = tempfile.mkdtemp()

    try:
        # 1. 初始化 XMSS 树
        master_key = b'\x01' * 32
        xmss_file = os.path.join(temp_dir, 'test_xmss.state')
        xmss = StatefulXMSS(tree_height=2, state_file=xmss_file, master_key=master_key)
        root_info = xmss.generate_keys()

        # 2. 获取路径信息
        path_info = xmss.get_current_path_info()

        # 3. 创建环签名引擎
        lrs_engine = TrueLinkableRingSignature()

        # 4. 生成签名
        message = b"authentication_request"
        epoch = int(time.time()) // 60  # 使用当前分钟作为epoch
        k_session = os.urandom(32)

        signature = lrs_engine.sign(
            message=message,
            epoch=epoch,
            k_session=k_session,
            id_v="test_vehicle_123",
            prover_xmss=xmss,
            ring_root=root_info["root"],
            ring_path=path_info["xmss_path"],
            ring_index=path_info["xmss_index"]
        )

        # 5. 验证签名
        is_valid = lrs_engine.verify(message, signature, ring_root=root_info["root"])

        assert is_valid, "签名验证失败"
        print("✓ 签名生成和验证成功")

        # 6. 测试重放保护（第二次验证应失败）
        is_valid_second = lrs_engine.verify(message, signature, ring_root=root_info["root"])
        assert not is_valid_second, "重放保护失败"
        print("✓ 重放保护工作正常")

        # 7. 测试消息篡改检测
        tampered_sig = signature.copy()
        tampered_sig["root_R"] = os.urandom(32).hex()
        is_valid_tampered = lrs_engine.verify(message, tampered_sig, ring_root=root_info["root"])
        assert not is_valid_tampered, "篡改检测失败"
        print("✓ 篡改检测工作正常")

        print("🎉 端到端集成测试通过！")

    finally:
        # 清理临时文件
        shutil.rmtree(temp_dir)

def test_multiple_devices_linkability():
    """测试多设备可链接性"""
    temp_dir = tempfile.mkdtemp()

    try:
        lrs_engine = TrueLinkableRingSignature()
        epoch = int(time.time()) // 60  # 使用当前分钟

        # 设备 A
        xmss_a = StatefulXMSS(tree_height=2, state_file=os.path.join(temp_dir, 'a.state'), master_key=b'A' * 32)
        root_a = xmss_a.generate_keys()
        path_a = xmss_a.get_current_path_info()

        sig_a1 = lrs_engine.sign(b"msg1", epoch, os.urandom(32), "device_A", xmss_a, root_a["root"], path_a["xmss_path"], path_a["xmss_index"])

        # 为第二个签名重新获取路径（因为第一个签名消耗了一个叶子）
        path_a2 = xmss_a.get_current_path_info()
        sig_a2 = lrs_engine.sign(b"msg2", epoch, os.urandom(32), "device_A", xmss_a, root_a["root"], path_a2["xmss_path"], path_a2["xmss_index"])

        # 设备 B
        xmss_b = StatefulXMSS(tree_height=2, state_file=os.path.join(temp_dir, 'b.state'), master_key=b'B' * 32)
        root_b = xmss_b.generate_keys()
        path_b = xmss_b.get_current_path_info()

        sig_b = lrs_engine.sign(b"msg", epoch, os.urandom(32), "device_B", xmss_b, root_b["root"], path_b["xmss_path"], path_b["xmss_index"])

        # 验证可链接性：同一设备相同 epoch 的 tag 相同
        assert sig_a1["linkage_tag"] == sig_a2["linkage_tag"], "可链接性失败：同一设备不同签名 tag 不一致"

        # 验证匿名性：不同设备 tag 不同
        assert sig_a1["linkage_tag"] != sig_b["linkage_tag"], "匿名性失败：不同设备 tag 相同"

        print("✓ 多设备可链接性测试通过")

    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    test_end_to_end_authentication()
    test_multiple_devices_linkability()
    print("所有集成测试完成！")