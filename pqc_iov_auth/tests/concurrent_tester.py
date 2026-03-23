import time
import os
import hashlib
import concurrent.futures
import statistics
import logging
import sys
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../')))

from src.crypto_layer.kyber_kem import KyberKEMEngine
from src.crypto_layer.xmss_stateful import StatefulXMSS
from src.crypto_layer.lrs_zkp import TrueLinkableRingSignature

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

def build_merkle_tree(leaves: list) -> tuple:
    """
    【修复】构建真正的 Merkle 树，而不是平面哈希
    
    Args:
        leaves: 叶子节点列表
        
    Returns:
        (tree: list[list], root: bytes)
        tree[0] = leaves
        tree[1] = 第一层内部节点
        tree[n] = 根节点（单元素列表）
    """
    tree = [leaves[:]]
    
    while len(tree[-1]) > 1:
        current_level = tree[-1]
        next_level = []
        
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                left = current_level[i]
                right = current_level[i + 1]
            else:
                # 奇数个节点，右节点为左节点
                left = current_level[i]
                right = left
            
            parent = hashlib.sha256(left + right).digest()
            next_level.append(parent)
        
        tree.append(next_level)
    
    root = tree[-1][0]
    return tree, root

def extract_merkle_path(tree: list, leaf_index: int) -> list:
    """
    【修复】从 Merkle 树中提取验证路径
    
    Args:
        tree: Merkle 树结构
        leaf_index: 叶子在第 0 层的索引
        
    Returns:
        path: 从叶子到根的兄弟节点列表
    """
    path = []
    curr_index = leaf_index
    
    for level in range(len(tree) - 1):
        level_nodes = tree[level]
        
        # 计算兄弟索引
        if curr_index % 2 == 0:
            # 当前在左边，兄弟在右边
            sibling_index = curr_index + 1
        else:
            # 当前在右边，兄弟在左边
            sibling_index = curr_index - 1
        
        # 如果兄弟存在，添加到路径
        if sibling_index < len(level_nodes):
            path.append(level_nodes[sibling_index])
        else:
            # 奇数层的最后一个节点，兄弟是自己
            path.append(level_nodes[curr_index])
        
        # 上升一层
        curr_index //= 2
    
    return path

def build_dynamic_ring(client_leaf: bytes, client_index: int, num_members: int = 8) -> tuple:
    """
    为特定的客户端叶子构建环
    
    Returns:
        (ring_root: bytes, ring_path: list)
    """
    # 生成其他环成员
    ring_leaves = [client_leaf]
    
    for i in range(1, num_members):
        fake_leaf = hashlib.sha256(
            f"vehicle_public_key_{i}".encode() + os.urandom(16)
        ).digest()
        ring_leaves.append(fake_leaf)
    
    # 补齐为 2 的幂次
    while len(ring_leaves) & (len(ring_leaves) - 1) != 0:
        ring_leaves.append(hashlib.sha256(b"padding").digest())
    
    tree, ring_root = build_merkle_tree(ring_leaves)
    ring_path = extract_merkle_path(tree, client_index)
    
    return ring_root, ring_path

def setup_global_ring(client_xmss, num_members: int = 8) -> tuple:
    """
    构建全局环：模拟 num_members 个环成员
    
    Returns:
        (ring_root: bytes, ring_members: list[dict])
    """
    logger.info(f"[Ring] 构建全局环（成员数: {num_members}）...")
    
    # 获取客户端的叶子
    path_info = client_xmss.get_current_path_info()
    client_leaf = path_info["leaf_pk"]
    client_index = 0
    
    logger.info(f"[Ring] 客户端叶子: {client_leaf.hex()[:16]}...")
    
    # 生成其他环成员
    ring_leaves = [client_leaf]
    
    for i in range(1, num_members):
        fake_leaf = hashlib.sha256(
            f"vehicle_public_key_{i}".encode() + os.urandom(16)
        ).digest()
        ring_leaves.append(fake_leaf)
    
    # 补齐为 2 的幂次
    original_count = len(ring_leaves)
    while len(ring_leaves) & (len(ring_leaves) - 1) != 0:
        ring_leaves.append(hashlib.sha256(b"padding").digest())
    
    tree, ring_root = build_merkle_tree(ring_leaves)
    logger.info(f"[Ring] 环根: {ring_root.hex()[:16]}...")
    logger.info(f"[Ring] 环大小: {len(ring_leaves)} (原始: {original_count})")
    
    # 提取每个成员的验证路径
    ring_members = []
    
    for i in range(original_count):
        member_path = extract_merkle_path(tree, i)
        
        ring_members.append({
            "leaf": ring_leaves[i],
            "index": i,
            "path": member_path
        })
        
        logger.debug(f"[Ring] 成员 {i}: 路径长度={len(member_path)}")
    
    return ring_root, ring_members


def main():
    print("="*60)
    print("  PQC IoV Authentication System - Concurrent Benchmark")
    print("  （后量子密码学 + 环签名 + ZKP）")
    print("="*60)
    
    # ========== 配置参数 ==========
    NUM_REQUESTS = 16  # 请求总数
    WORKERS = min(4, os.cpu_count() or 4)  # 并发线程数
    TREE_HEIGHT = 6  # XMSS 树高度 (2^6 = 64 叶子)
    RING_SIZE = 8  # 环大小
    
    logger.info(f"配置: {NUM_REQUESTS} 请求，{WORKERS} 线程，树高={TREE_HEIGHT}")
    
    # ========== 阶段 1: 初始化密码学引擎 ==========
    logger.info("\n[Phase 1] 初始化密码学引擎...")
    
    kem_engine = KyberKEMEngine("ML-KEM-512")
    kem_info = kem_engine.get_algorithm_info()
    logger.info(f"[KEM] 使用 {kem_info.get('name', 'ML-KEM-512')}")
    
    # 生成服务端密钥对
    server_pk, server_sk = kem_engine.generate_keypair()
    logger.info(f"[KEM] 服务端公钥长度: {len(server_pk)} 字节")
    
    lrs_engine = TrueLinkableRingSignature()
    logger.info("[LRS] 环签名引擎已初始化")
    
    # ========== 阶段 2: 初始化客户端 XMSS 树 ==========
    logger.info(f"\n[Phase 2] 初始化客户端 XMSS 树 (高度={TREE_HEIGHT})...")
    
    temp_dir = tempfile.gettempdir()
    state_file = os.path.join(temp_dir, f"test_xmss_{os.getpid()}.enc")
    
    try:
        master_key = os.urandom(32)
        client_xmss = StatefulXMSS(
            tree_height=TREE_HEIGHT,
            state_file=state_file,
            master_key=master_key
        )
        
        xmss_start = time.perf_counter()
        xmss_info = client_xmss.generate_keys()
        xmss_time = time.perf_counter() - xmss_start
        
        logger.info(f"[XMSS] 树生成耗时: {xmss_time:.2f} 秒")
        logger.info(f"[XMSS] XMSS 根: {xmss_info['root'].hex()[:16]}...")
        
        # ========== 阶段 3: 构建全局环 ==========
        ring_root, ring_members = setup_global_ring(client_xmss, RING_SIZE)
        
        # ========== 验证环的正确性 ==========
        logger.info(f"\n[Verify] 验证环的正确性...")
        for i in range(len(ring_members)):
            from src.crypto_layer.lrs_zkp import RingMembershipProof
            is_in_ring = RingMembershipProof.verify_membership(
                ring_members[i]["leaf"],
                ring_members[i]["path"],
                ring_members[i]["index"],
                ring_root
            )
            if not is_in_ring:
                logger.error(f"[Verify] 成员 {i} 环成员验证失败！")
                return
        logger.info(f"[Verify] 所有成员的环路径验证正确 ✓")
        
        # ========== 阶段 4: 生成请求负载 ==========
        logger.info(f"\n[Phase 3] 生成 {NUM_REQUESTS} 个请求...")
        
        requests = []
        setup_start = time.perf_counter()
        
        for i in range(NUM_REQUESTS):
            msg = f"auth_request_{i:04d}".encode('utf-8')
            epoch = int(time.time()) // 60
            
            try:
                # 客户端：KEM 封装
                ct, k_session = kem_engine.encapsulate(server_pk)
                
                # 【关键修复】：每次都为当前叶子构建动态环
                # 获取当前叶子信息（代表当前状态）
                current_path_info = client_xmss.get_current_path_info()
                current_leaf = current_path_info["leaf_pk"]
                current_index = current_path_info["xmss_index"]
                
                # 为这个特定的叶子构建环
                # 在实际系统中，应该使用全局维护的环
                dyn_ring_root, dyn_ring_path = build_dynamic_ring(
                    current_leaf, 0, RING_SIZE
                )
                
                logger.debug(f"[Load] 请求 {i}: 叶子索引={current_index}, "
                           f"动态环根={dyn_ring_root.hex()[:8]}...")
                
                # 客户端：生成环签名
                sig = lrs_engine.sign(
                    message=msg,
                    epoch=epoch,
                    k_session=k_session,
                    id_v=f"vehicle_{i:04d}",
                    prover_xmss=client_xmss,
                    ring_root=dyn_ring_root,
                    ring_path=dyn_ring_path,
                    ring_index=0  # 当前叶子总是在索引 0
                )
                
                requests.append((msg, ct, sig, dyn_ring_root))
                
                if (i + 1) % 4 == 0:
                    logger.info(f"[Load] 已生成 {i+1}/{NUM_REQUESTS} 个请求")
                    
            except ValueError as e:
                if "私钥已耗尽" in str(e):
                    logger.warning(f"[Load] XMSS 私钥已耗尽，仅生成了 {i} 个请求")
                    break
                else:
                    logger.error(f"[Load] 请求 {i} 生成失败: {e}")
                    raise
        
        setup_time = time.perf_counter() - setup_start
        logger.info(f"[Load] 负载生成耗时: {setup_time:.2f} 秒，实际请求数: {len(requests)}")
        
        if len(requests) == 0:
            logger.error("[Load] 无有效请求，测试中止")
            return
        
        # ========== 阶段 5: 并发压力测试 ==========
        logger.info(f"\n[Phase 4] 启动服务端压力测试 ({WORKERS} 线程)...")
        
        def server_worker(req_data):
            """模拟服务端处理逻辑"""
            msg, ct, sig, expected_root = req_data
            start_t = time.perf_counter()
            
            try:
                # 1. KEM 解封装
                k_session_recovered = kem_engine.decapsulate(ct, server_sk)
                
                # 2. 验证环签名与 ZKP
                is_valid = lrs_engine.verify(msg, sig, expected_root)
                
                if not is_valid:
                    raise ValueError("签名验证失败")
                
                end_t = time.perf_counter()
                return end_t - start_t, "OK"
                
            except Exception as e:
                end_t = time.perf_counter()
                return end_t - start_t, str(e)

        latencies = []
        success_count = 0
        error_count = 0
        error_log = []
        
        test_start = time.perf_counter()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
            futures = [executor.submit(server_worker, req) for req in requests]
            
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                try:
                    lat, status = future.result()
                    latencies.append(lat)
                    
                    if status == "OK":
                        success_count += 1
                    else:
                        error_count += 1
                        error_log.append(f"Request {i}: {status}")
                        
                except Exception as e:
                    error_count += 1
                    error_log.append(f"Request {i}: {str(e)}")
        
        test_total = time.perf_counter() - test_start
        
        # ========== 输出基准测试结果 ==========
        print("\n" + "="*60)
        print("  Benchmark Results")
        print("="*60)
        
        print(f"\n【基本指标】")
        print(f"  总请求数         : {len(requests)}")
        print(f"  成功处理         : {success_count}")
        print(f"  失败             : {error_count}")
        print(f"  成功率           : {100*success_count/len(requests):.1f}%")
        print(f"  并发线程数       : {WORKERS}")
        print(f"  总耗时           : {test_total:.4f} 秒")
        print(f"  环大小           : {RING_SIZE}")
        
        if latencies:
            qps = success_count / test_total if test_total > 0 else 0
            avg_lat = statistics.mean(latencies) * 1000
            min_lat = min(latencies) * 1000
            max_lat = max(latencies) * 1000
            
            print(f"\n【性能指标】")
            print(f"  吞吐量 (QPS)     : {qps:.2f} req/s")
            print(f"  平均延迟        : {avg_lat:.2f} ms")
            print(f"  最小延迟        : {min_lat:.2f} ms")
            print(f"  最大延迟        : {max_lat:.2f} ms")
            
            if len(latencies) >= 2:
                stddev = statistics.stdev(latencies) * 1000
                print(f"  标准差          : {stddev:.2f} ms")
            
            if len(latencies) >= 20:
                q95 = statistics.quantiles(latencies, n=100)[94] * 1000
                q99 = statistics.quantiles(latencies, n=100)[98] * 1000
                print(f"  P95 延迟        : {q95:.2f} ms")
                print(f"  P99 延迟        : {q99:.2f} ms")
        
        if error_log:
            print(f"\n【错误日志】 (前 5 条)")
            for err in error_log[:5]:
                print(f"  ! {err}")
        else:
            print(f"\n✅ 所有请求验证通过！")
        
        print("="*60)
        
    finally:
        # 清理临时文件
        if os.path.exists(state_file):
            os.remove(state_file)
            logger.info(f"[Cleanup] 已删除临时状态文件")

if __name__ == "__main__":
    main()