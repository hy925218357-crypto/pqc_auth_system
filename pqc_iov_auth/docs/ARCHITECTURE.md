# PQC IoV 系统架构设计文档

## 1. 系统整体架构

### 1.1 四层架构模型

```
┌─────────────────────────────────────────────────────────────┐
│                    应用层 (Application)                      │
│              V2V通信 / 位置服务 / 数据共享                   │
└────────────────────────┬────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────────┐
│               3️⃣ 设备节点层 (Device Node)                   │
│  ┌──────────────┐              ┌──────────────────────────┐ │
│  │   客户端     │◄────────────►│  服务端 (V2V Server)    │ │
│  │ (Initiator)  │  RSA/ECDH可  │                          │ │
│  └──────────────┘              └──────────────────────────┘ │
│          │                              │                    │
│          └──────────────┬───────────────┘                    │
│                         │                                    │
└─────────────────────────┼────────────────────────────────────┘
                          │ HTTP/TLS
                          │
┌─────────────────────────▼────────────────────────────────────┐
│          2️⃣ 边缘节点层 (Edge Node / 认证网关)              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │            AuthGateway (认证处理)                      │ │
│  │  • 接收认证请求                                       │ │
│  │  • 验证签名 + ZKP                                     │ │
│  │  • 防重放检查                                         │ │
│  │  • 返回认证结果                                       │ │
│  └────────────────────────────────────────────────────────┘ │
│          │                    │              │               │
│   (Redis │防重放)    (密码学验证)       (区块链)            │
│          │                    │              │               │
└──────────┼────────────────────┼──────────────┼───────────────┘
           │                    │              │
           ▼                    ▼              ▼
┌──────────────┐    ┌───────────────────────────────────────┐
│    Redis     │    │  1️⃣ 密码学层 (Crypto Layer)         │
│ (Tag Store)  │    │  ┌─────────────────────────────────┐ │
└──────────────┘    │  │  ML-KEM-512  │  SLH-DSA        │ │
                    │  │  (KEM)       │  (Signature)    │ │
                    │  │              │                │ │
                    │  │  ┌──────────────────────────┐ │ │
                    │  │  │  LRS + ZKP (匿名认证)   │ │ │
                    │  │  │  • 环成员验证           │ │ │
                    │  │  │  • 可链接性验证         │ │ │
                    │  │  └──────────────────────────┘ │ │
                    │  └─────────────────────────────────┘ │
                    └───────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────┐
│        4️⃣ 区块链层 (Blockchain / Hyperledger Fabric)      │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  • 身份注册 (Identity Registration)                   │ │
│  │  • 环根管理 (Ring Root Management)                    │ │
│  │  • 认证审计 (Authentication Audit Trail)             │ │
│  │  • 密钥吊销 (Key Revocation)                         │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 数据流图

#### 注册流程

```
设备端                        边缘节点                    区块链
  │                            │                         │
  │─── register(device_id) ───►│                        │
  │                            │                        │
  │                            │── 生成XMSS密钥树        │
  │                            │── hset XMSS环根        │
  │                            │                        │
  │                            │─── putIdentity ───────►│
  │                            │                        │
  │                            │◄─── 确认提交 ──────────│
  │                            │                        │
  │◄─── 注册成功 ──────────────│                        │
  │
```

#### 认证流程 (完整交握)

```
设备端                    边缘节点                Redis        区块链
  │                        │                    │             │
  │─ generate_witness ─►   │                    │             │
  │  (携带设备ID,签名)     │                    │             │
  │                        │                    │             │
  │◄─ authenticate ◄───────│                    │             │
  │                        │                    │             │
  │                        │─ verify signature  │             │
  │                        │─ verify ZKP       │             │
  │                        │                    │             │
  │                        │── check_nonce ───►│:            │
  │                        │                    │             │
  │                        │◄── True/False ─────│             │
  │                        │                    │             │
  │                        │ (if ok, sadd tag) │             │
  │                        │                    │             │
  │                        │── putAuditLog ────────────────►│
  │                        │                                 │
  │                        │◄─────────── 审计记录 ──────────│
  │                        │                                 │
  │◄─── session_key ───────│                                 │
  │
```

---

## 2. 密码学层设计

### 2.1 ML-KEM-512 (密钥封装机制)

**文件**: `src/crypto_layer/kyber_kem.py`

```python
状态:
  - _local: threading.local()  # 线程本地存储KEM实例
  - alg_name: "ML-KEM-512"     # NIST标准KEM

方法:
  generate_keypair() -> (pk, sk)
    - 生成ML-KEM-512密钥对
    - 返回: (public_key: bytes, secret_key: bytes)

  encapsulate(pk: bytes) -> (ct, ss)
    - 生成会话密钥
    - 返回: (ciphertext: bytes, shared_secret: bytes)
    - 用于密钥导出

  decapsulate(ct: bytes, sk: bytes) -> ss
    - 恢复会话密钥
    - 返回: shared_secret: bytes
    - 多进程安全(TLS)

  _derive_and_wipe(ss: bytes) -> k_session
    - HKDF密钥导出
    - 尝试内存擦除(注:Python不保证)
```

**关键点**:
- 使用 `liboqs-python` 绑定 liboqs C库
- 单个进程中使用线程本地存储避免状态污染
- 密钥导出使用 HKDF-SHA256

### 2.2 SLH-DSA 无状态签名

**文件**: `src/crypto_layer/xmss_liboqs.py`

```python
类: SLHDSASignature

初始化参数:
  - device_id: str          # 设备唯一标识
  - sig_name: str = "SLH-DSA-SHA2-128s"
  - redis_backend: Redis    # (可选)后端存储
  - state_file: str         # 本地文件路径

状态持久化:
  _save_state_redis()       # 加密后存储到Redis
  _save_state_file()        # 加密后存储到本地文件
  _load_state_redis()       # 从Redis恢复
  _load_state_file()        # 从文件恢复

签名方法:
  sign(message: bytes) -> bytes
    - 生成SLH-DSA签名
    - 更新public_key
    - 持久化状态

  verify(message: bytes, signature: bytes) -> bool
    - 验证签名有效性
```

**加密方案**:
```
明文状态 ─┬─► AES-256-GCM ──► 密文             (Redis/File)
          │
          └─► Key = HKDF(master_key, "state")
              IV = 12字节随机数
              AAD = "state_" + device_id
```

### 2.3 可链接环签名 (LRS) + 零知识证明 (ZKP)

**文件**: `src/crypto_layer/lrs_zkp.py`

```python
类: TrueLinkableRingSignature

核心操作:
  generate_zkp_witness(
    ring_members: List[bytes],      # 环成员公钥
    signer_index: int,              # 签名者在环中位置
    message: bytes
  ) -> Dict

  返回结构:
  {
    "ring_root": bytes,              # Merkle根
    "linkage_tag": bytes,            # 防重放标记(确定性)
    "xmss_index": int,               # XMSS叶子索引
    "xmss_path": List[bytes],        # Merkle证明路径
    "leaf_pk": bytes,                # 当前叶子公钥
    "zk_proof": Dict                 # ZKP证明数据
  }

  verify(
    message: bytes,
    witness: Dict,
    ring_root: bytes,
    replay_backend: Redis
  ) -> bool
```

**防重放机制**:
```
linkage_tag = HMAC-SHA256(
  key=signer_private_key,
  message=ring_members_concatenated
)

特性:
  • 不同环成员 → 不同tag (可链接性)
  • 相同环 & 相同消息 → 相同tag (检测重放)
  • tag存储在Redis中，TTL=600秒
```

**ZKP 验证流程**:
```
证明者需证明:
  1. 知道某个ring_member对应的私钥
  2. 但不暴露是哪个成员
  
验证步骤:
  1. 验证Merkle路径: leaf_pk → ring_root
  2. 验证环签名完整性
  3. 验证ZKP有效性
  4. 检查linkage_tag是否已使用 (Redis)
```

---

## 3. 边缘节点设计

### 3.1 认证网关 (AuthGateway)

**文件**: `src/edge_node/auth_gateway.py`

```python
类: AuthGateway

初始化:
  __init__(
    redis_host: str = "localhost",
    redis_port: int = 6379
  )

关键属性:
  - redis: Redis连接              # 防重放存储
  - kem_engine: KyberKEMEngine     # ML-KEM实例
  - server_pk, server_sk: bytes    # 网关自身KEM密钥对
  - lrs_engine: 环签名引擎
  - replay_manager: 防重放管理器

核心方法:

  register_device(device_id: str, xmss_master_key: bytes)
    ├─ 生成XMSS密钥树 (tree_height=4)
    ├─ 提取环根 (ring_root)
    ├─ Redis缓存: hset device:{device_id} ring_root
    └─ 返回: {status, ring_root, device_id}

  authenticate_device(auth_request: Dict)
    ├─ 验证设备已注册
    ├─ 统一消息格式 (str → bytes)
    ├─ 可选KEM绑定 (decapsulate)
    ├─ LRS验证 (签名 + ZKP)
    ├─ 防重放检查 (nonce/tag)
    ├─ 区块链审计记录
    └─ 返回: {status, session_key?, epoch_window}
```

### 3.2 防重放管理 (AntiReplayManager)

**文件**: `src/edge_node/anti_replay.py`

```python
类: AntiReplayManager

机制:
  1. 基于Tag的防重放
     - Redis Set存储已使用的tag
     - TTL = 600秒 (10分钟)
  
  2. 基于Epoch的时间窗口
     - 接受 epoch ∈ [当前-window, 当前+window]
     - 默认window=1 (±60秒)
  
  3. 统计与限流
     - 记录每设备认证次数
     - 超过阈值返回"rate_limited"

方法:
  check_nonce(nonce: str, tag: str) -> bool
    - 检查nonce是否已使用
    - 若未使用，记录并返回True
  
  check_epoch_window(epoch: int, current_epoch: int) -> bool
    - 验证epoch在可接受范围
  
  check_rate_limit(device_id: str) -> bool
    - 检查设备是否超限
```

---

## 4. 设备节点设计

### 4.1 客户端 (DeviceClient)

**文件**: `src/device_node/client.py`

```python
类: DeviceClient

初始化:
  __init__(
    device_id: str,           # 车辆ID
    master_key: bytes,        # XMSS主密钥
    gateway_url: str,         # 网关地址
    gateway_port: int = 5000
  )

生命周期:

  register()
    ├─ 向网关发送设备ID和master_key
    ├─ 等待注册确认
    ├─ 保存ring_root本地缓存
    └─ 返回: {status: "registered"}

  authenticate(message: bytes, epoch: int)
    ├─ 生成witness (包含ZKP)
    ├─ 构造认证请求
    │  {
    │    "device_id": "vehicle_001",
    │    "signature": witness,
    │    "message": message_hex,
    │    "epoch": epoch
    │  }
    ├─ POST到网关/authenticate
    ├─ 若成功获得session_key
    └─ 返回: {status: "authenticated", session_key?}

  discover_vehicles() -> List[DeviceInfo]
    └─ 查询同环境其他车辆 (可选)
```

### 4.2 服务端 (DeviceServer)

**文件**: `src/device_node/server.py`

```python
类: DeviceServer

用途: V2V通信中的被动端

功能:
  1. 接收来自其他设备的认证请求
  2. 验证对端设备身份
  3. 建立安全会话
  4. 交换业务数据

示例流程:
  server_side_v2v_comm = DeviceServer(
    device_id="vehicle_002",
    listen_port=5001
  )
  
  # 接收对端认证
  peer_auth_result = server_side_v2v_comm.authenticate_peer(
    peer_device_id="vehicle_001",
    peer_witness=witness
  )
  
  if peer_auth_result["authenticated"]:
      # 建立会话
      session = server_side_v2v_comm.create_session(
          peer_device_id="vehicle_001",
          session_key=peer_auth_result["session_key"]
      )
```

---

## 5. 数据存储设计

### 5.1 Redis Key 命名规范

```
设备相关:
  device:{device_id}              # 设备信息Hash
    - ring_root: Hex String       # 环根
    - public_key: Hex String      # 设备公钥
    - registration_time: Unix时间戳

签名状态:
  slhdsa:{device_id}:state        # SLH-DSA状态
    - device_id, sig_name, public_key, secret_key, ...

防重放:
  auth:nonce:{device_id}          # Nonce使用集合
    - 成员: 已使用的tag/nonce
    - TTL: 600秒

  auth:rate_limit:{device_id}     # 认证频率限制
    - 计数器
    - TTL: 60秒

  device:epoch:{device_id}        # 时间轮
    - 最后认证epoch
    - TTL: 120秒
```

### 5.2 静态文件存储

```
本地文件系统:
  xmss_{device_id}.state          # 加密状态文件
  ├─ 格式: AES-256-GCM加密
  ├─ IV: 12字节
  └─ Tag: 16字节

  configs/
  ├─ device_config.json           # 设备配置
  └─ network_config.yml           # 网络配置
```

---

## 6. 安全特性

### 6.1 端到端认证流程

```
1️⃣ 密钥交换 (ML-KEM)
   设备 ──encapsulate(server_pk)──► 网关
   设备 ◄─decapsulate(ct, sk_device)─ 网关
   共享会话密钥: k_session

2️⃣ 身份验证 (SLH-DSA)
   设备 ──sign(message)──► 网关
   网关 验证数字签名和有效期

3️⃣ 匿名性可选 (LRS + ZKP)
   设备可选在环中签名 (4-10成员)
   网关验证: 设备既不知道是哪个成员签名
            但可确认来自合法环成员

4️⃣ 重放防护
   使用确定性tag = HMAC(sk, ring)
   存储在Redis中28重复检查
```

### 6.2 威胁防护矩阵

| 威胁 | 防护层 | 机制 |
|------|--------|------|
| 后量子攻击 | 密码学 | ML-KEM + SLH-DSA |
| 中间人攻击 | 认证 | 数学绑定 (不可伪造) |
| 重放攻击 | 协议 | tag + epoch窗口 |
| 身份冒充 | 区块链 | 公钥基础设施 |
| DDoS | 网关 | 限流 + 黑名单 |
| 侧通道 | 实现 | 恒定时间操作 |

---

## 7. 扩展性与部署

### 7.1 水平扩展

```
多网关部署:
  设备 ┐
      ├─► 网关1 (Redis Cluster)
  设备 ┤   │
      ├─► 网关2 ◄─────┐
  设备 ┘   │         Redis
           └─────────Cluster
           
关键: Redis正确配置主从+哨兵自动故障恢复
```

### 7.2 性能优化

```
缓存策略:
  ✓ ML-KEM keypair缓存 (per thread)
  ✓ 签名结果缓存 (TTL: 60s)
  ✓ 环根缓存 (本地)
  
异步持久化:
  ✓ 署名后异步保存状态
  ✓ 批量提交区块链审计
  
连接池:
  ✓ Redis连接池 (size: 10-20)
  ✓ HTTP连接复用
```

---

## 8. 故障处理

### 8.1 Redis 不可用

```python
网关行为:
  Redis连接失败 → 降级到内存存储
  风险: 多进程环境下无防重放保证
  建议: 仅在临时故障时使用
```

### 8.2 签名操作失败

```python
异常处理:
  try:
    sig.sign(msg)
  except Exception:
    → 返回认证失败
    → 记录日志并通知管理员
    → 不自动重试 (避免延放)
```

---

## 9. 参考架构图

```
端到端通信流程:

[车辆A]                                    [车辆B]
  │                                         │
  │ 1. register()                          │
  ├──────────────────────────────────────► 网关
  │                                        │
  │ 2. authenticate()                      │
  ├──────────────────────────────────────► 网关
  │                                        │
  │ 3. 接收 {status, session_key}          │
  │◄──────────────────────────────────────┤
  │                                        │
  │ 4. V2V 安全通信 with session_key      │
  ├──────────────────────────────────────►│
  │◄──────────────────────────────────────┤
  │                                        │
  └─────────────────────────────────────────┘
```

---

**更新时间**: 2026年3月23日
