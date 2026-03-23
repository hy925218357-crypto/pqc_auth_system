"""性能基准测试"""
import time
import os
import sys
import tempfile
import shutil

# 动态加载模块
import importlib.util

def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

lrs_zkp_mod = load_module('lrs_zkp', 'src/crypto_layer/lrs_zkp.py')
xmss_mod = load_module('xmss_stateful', 'src/crypto_layer/xmss_stateful.py')

TrueLinkableRingSignature = lrs_zkp_mod.TrueLinkableRingSignature
StatefulXMSS = xmss_mod.StatefulXMSS

def benchmark_signing():
    """签名性能基准测试"""
    temp_dir = tempfile.mkdtemp()

    try:
        xmss = StatefulXMSS(tree_height=4, state_file=os.path.join(temp_dir, 'bench.state'), master_key=b'\x01' * 32)
        root_info = xmss.generate_keys()
        lrs_engine = TrueLinkableRingSignature()

        message = b"Benchmark message for PQC IoV authentication"
        epoch = int(time.time()) // 60

        # 预热
        path_info = xmss.get_current_path_info()
        sig = lrs_engine.sign(message, epoch, os.urandom(32), "bench_device", xmss, root_info["root"], path_info["xmss_path"], path_info["xmss_index"])

        # 正式测试
        times = []
        for i in range(10):
            start_time = time.time()
            path_info = xmss.get_current_path_info()
            sig = lrs_engine.sign(message, epoch, os.urandom(32), "bench_device", xmss, root_info["root"], path_info["xmss_path"], path_info["xmss_index"])
            end_time = time.time()
            times.append(end_time - start_time)

        avg_time = sum(times) / len(times)
        print(f"平均签名时间: {avg_time:.3f} 秒")
        return avg_time

    finally:
        shutil.rmtree(temp_dir)

def benchmark_verification():
    """验证性能基准测试"""
    temp_dir = tempfile.mkdtemp()

    try:
        xmss = StatefulXMSS(tree_height=6, state_file=os.path.join(temp_dir, 'bench.state'), master_key=b'\x02' * 32)  # 更大的树
        root_info = xmss.generate_keys()
        lrs_engine = TrueLinkableRingSignature()

        message = b"Benchmark message for verification"
        epoch = int(time.time()) // 60

        # 先生成一批签名
        signatures = []
        for i in range(50):
            path_info = xmss.get_current_path_info()
            sig = lrs_engine.sign(message, epoch, os.urandom(32), f"bench_device_{i}", xmss, root_info["root"], path_info["xmss_path"], path_info["xmss_index"])
            signatures.append(sig)

        # 验证性能测试
        times = []
        for i, sig in enumerate(signatures):
            start_time = time.time()
            is_valid = lrs_engine.verify(message, sig, ring_root=root_info["root"])
            end_time = time.time()
            times.append(end_time - start_time)
            assert is_valid, f"验证失败在第 {i+1} 次"

        avg_time = sum(times) / len(times)
        print(f"平均验证时间: {avg_time:.3f} 秒")
        return avg_time

    finally:
        shutil.rmtree(temp_dir)

def benchmark_key_generation():
    """密钥生成性能基准测试"""
    temp_dir = tempfile.mkdtemp()

    try:
        times = []
        for height in [2, 3, 4]:
            start_time = time.time()
            xmss = StatefulXMSS(tree_height=height, state_file=os.path.join(temp_dir, f'keygen_{height}.state'), master_key=os.urandom(32))
            root_info = xmss.generate_keys()
            end_time = time.time()
            times.append((height, end_time - start_time))
            print(f"XMSS 高度 {height} 密钥生成时间: {end_time - start_time:.3f} 秒")
        return times

    finally:
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    print("🚀 PQC IoV 认证系统性能基准测试")
    print("=" * 50)

    print("\n📊 密钥生成性能:")
    keygen_times = benchmark_key_generation()

    print("\n⚡ 签名性能:")
    sign_time = benchmark_signing()

    print("\n🔍 验证性能:")
    verify_time = benchmark_verification()

    print("\n📈 性能总结:")
    print(f"签名/验证性能比: {sign_time/verify_time:.1f}x (签名较慢)")
    print(f"密钥生成 vs 签名: {keygen_times[-1][1]/sign_time:.1f}x (密钥生成较慢)")

    print("\n✅ 基准测试完成")