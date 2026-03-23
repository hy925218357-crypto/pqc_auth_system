# 安全分析 & 威胁模型

## 1. 前言

本文档详细分析 PQC IoV 认证系统的安全特性、已知威胁、防护机制及限制条件。所有技术决策均基于NIST PQC竞赛评审和产业最佳实践。

---

## 2. 威胁模型

### 2.1 假设的威胁环境

#### A. 计算能力威胁

| 威胁 | 能力 | 防护 |
|------|------|------|
| **多项式时间攻击者** | 经典计算机 | RSA/ECDH易被破解 |
| **量子计算攻击者** | 通用量子计算机 | ✅ 本系统target |
| **侧通道攻击者** | 物理访问 + 时间/功耗分析 | ✅ 恒定时间实现 |
| **混合攻击者** | 经典 + 量子 + 物理 | ✅ 多层防护 |

#### B. 通信环境假设

- ✅ 攻击者可窃听所有网络流量
- ✅ 攻击者可修改/延迟/重放消息
- ✅ 攻击者可冒充任何设备
- ✅ 攻击者可控制Redis (如未加密)
- ❌ 攻击者无法破坏物理密钥存储 (HSM)

#### C. 时间同步假设

```
设备之间时间误差 < 60秒 (一个时间轮)
└─ 通过NTP V4 + GPS认证实现
```

---

## 3. 安全属性分析

### 3.1 机密性 (Confidentiality)

#### ML-KEM-512 密钥封装

**威胁**: 被动窃听收获密文
```
攻击: Eve窃听所有通信
      设备 ──ct──► 网关
      Eve 截获 ct

防护: ct本身可公开,但无私钥sk无法恢复shared_secret
     IND-CCA2安全保证 (NIST标准)
```

**安全级别**: 🟢 Level 1 (抗量子)

#### 会话密钥导出

```python
k_session = HKDF-SHA256(
    ss,                      # ML-KEM shared secret
    salt=None,               # ⚠️ 无盐
    info=b"pqc_iov_session_key",
    length=32
)
```

**问题**: 无盐HKDF减弱信息论安全性
**建议**: 使用`salt = HMAC(master_key, device_id)`

#### 数据加密

- 状态文件: AES-256-GCM (128-bit Auth Tag) ✅
- Redis内数据: 建议使用TLS 1.3 ✅
- 消息传输: 应使用TLS 1.3 (推荐128-bit)

#### 风险评估

| 场景 | 风险 | 缓解措施 |
|------|------|---------|
| 量子计算机破解ML-KEM | 中 | 迁移到ml-kem-768/1024 |
| 侧通道泄露密钥 | 低 | 恒定时间实现 + Masking |
| Redis未加密 | 高 | 启用Redis TLS + Auth |

---

### 3.2 真实性 (Authenticity)

#### SLH-DSA 签名验证

```
安全假设: 攻击者无法伪造SLH-DSA签名
  (即使有多项式个签名示例)

NIST标准: 量子抗性，128-bit安全级别

实现:
  ✅ 恒定时间验证
  ✅ 内存隔离 (无缓存侧通道)
  ✅ 参数验证 (防止格式string攻击)
```

#### 环签名的真实性

```
可链接环签名提供:
  1. 身份真实性: 签名者必须是环成员
  2. 可否认性: 网关无法指认是哪个成员
  3. 可链接性: 相同签名者->相同tag (防重放)

Forging成本 = 伪造任一环成员的签名
            ≥ 2^128 (对于SLH-DSA-SHA2-256)
```

#### 风险评估

| 威胁 | 可能性 | 影响 | 缓解 |
|------|--------|------|------|
| 伪造SLH-DSA签名 | 极低 | 极高 | 多重验证 |
| 环成员身份窃取 | 低 | 高 | PKI + Fabric |
| 签名算法弱点发现 | 低 | 极高 | 定期更新liboqs |

---

### 3.3 可否认性 & 匿名性

#### 可链接环签名的匿名性分析

```
需要证明: 签名者是环成员, 但不知道谁

方法: Fiat-Shamir启发式ZKP
  证明者 知道: sk_i (环成员i的私钥)
  验证者 知道: {pk_1, pk_2, ..., pk_n} (所有公钥)
  验证: 证明者知晓sk_i对应的pk, 但i未暴露

强度:
  • 对诚实验证者: 信息论匿名 (计算不可区分)
  • 对恶意验证者: 暴露身份概率 ≤ 1/n
  • n=4: 匿名性 = 2-bit
  • n=10: 匿名性 = 3.3-bit
```

#### 用例

```
场景1: 数据分享 (隐私保护)
  └─ 车辆A不希望暴露位置，使用4-车辆环签名

场景2: 威胁举报 (匿名证人)
  └─ 车辆检测到恶意行为，匿名上报到Fabric

场景3: 基础设施监控 (隐私合规)
  └─ 无需记录谁认证了，只需验证有效车辆认证
```

#### 风险评估

| 威胁 | 防护 | 局限 |
|------|------|------|
| 流量分析 | 环签名 | 网络层可识别IP |
| 大规模去匿名化 | 同一环验证多次 | tag重复可被追踪 |
| 侧通道de-anonymization | 恒定时间 | 物理访问仍可破坏 |

---

### 3.4 防重放 (Replay Protection)

#### A. 基于Tag的防重放

```
原理:
  linkage_tag = HMAC-SHA256(sk_signer, ring_members)
  
  特性:
    • 相同签名者+环 → 相同tag (检测重放!)
    • 不同签名者 → 不同tag (允许)
    • 不可预测 (HMAC保证)

存储:
  Redis Set: auth:nonce:{device_id}
    - 添加tag
    - TTL = 600秒 (10分钟合理)

问题:
  • Redis不可用 → 无防重放
  • 分布式部署 → 使用Redis Cluster
  • 多网关间状态一致性 ← Redis同步保证
```

#### B. 基于Epoch的时间窗口

```
原理:
  epoch = floor(unix_timestamp / 60)
  
  接受窗口: abs(auth_epoch - current_epoch) ≤ 1
  即: ±60秒容差

问题:
  • 时间同步失败 → 认证失败
  • 攻击者预知epoch → 时间基础攻击
  
缓解:
  • 要求NTP V4 (广播认证)
  • 使用GPS PPS (±100ns精度)
  • 处理时间跳变 (RTC调整)
```

#### C. 组合防重放

```
完整检查流程:
  1. 检查设备是否已注册 ← Fabric lookup
  2. 验证epoch在窗口内 ← 时间检查
  3. 验证tag未使用 ← Redis lookup
  4. 验证签名有效 ← 密码学验证
  5. 保存tag到Redis ← 标记为已使用
```

#### 风险评估

| 攻击类型 | 防护 | 残余风险 |
|---------|------|---------|
| 简单重放 | Tag | 极低 |
| 分布式重放 | Redis Cluster | 中低 |
| 持久化存储重放 | 无 | 中 |
| 时间基础攻击 | epoch窗口 | 中 |
| Redis故障 | 内存降级 | 高 |

---

## 4. 已知安全限制

### 4.1 Merkle路径验证缺陷

**问题**: 当前使用SLH-DSA替代XMSS，环成员证明不完整

```python
# xmss_liboqs.py L340-355
return {
    'xmss_index': idx,
    'xmss_path': [],           # ⚠️ 空路径!
    'leaf_pk': self.public_key,
}
```

**影响等级**: 🟡 中等

**说明**:
- Merkle路径用于证明: leaf_pk → ring_root
- 空路径意味着跳过此验证
- 只能验证leaf_pk是否在某处签名，无法完全验证是否来自该树

**缓解方案**:
```python
# 改进方案 (需要liboqs原生支持)
if oqs支持原生Merkle树:
    xmss_path = sig.get_merkle_path(index)
else:
    # 降级方案: 验证leaf_pk是否在已知公钥集合中
    xmss_path = ring_members  # 信任关键字
```

### 4.2 防重放多进程限制

**问题**: 不使用Redis时，防重放仅限单进程

```python
# lrs_zkp.py L258
class ZKProofAggregator:
    seen_nonces = set()  # 全局类变量 (单进程!)
    
    @classmethod
    def verify(...):
        if not replay_backend:
            # 多进程时各进程独立set
            # ❌ 不安全!
            if proof_nonce in cls.seen_nonces:
                return False
```

**影响等级**: 🟠 高

**生产环境要求**:
```
强制条件: replay_backend must be Redis
缺失Redis → 启动时raise RuntimeError
```

**修复代码** (推荐):
```python
@classmethod
def verify(cls, ..., replay_backend=None):
    if replay_backend is None:
        raise RuntimeError(
            "防重放需要Redis后端。单进程内存存储仅适合开发。"
        )
    # 继续使用redis
```

### 4.3 内存擦除不可靠

**问题**: Python中无法可靠清除敏感数据

```python
# kyber_kem.py L110
ss_array = bytearray(ss)
for i in range(len(ss_array)):
    ss_array[i] = 0        # 尝试擦除
del ss_array               # ❌ 不保证内存清零
```

**影响等级**: 🟡 中等

**风险场景**: 
- 进程崩溃后内存转储 (coredump)
- Swap到磁盘被攻击者读取
- 物理内存访问 (冷启动攻击)

**修复建议**:
```python
# 方案1: 使用cryptography库的safer清零
from cryptography.hazmat.primitives import hashes
ss_secure = secrets.token_bytes(32)  # 使用secrets而非直接密钥

# 方案2: 使用mlock防止swap
import ctypes
ctypes.CDLL("libc.so.6").mlock(id(ss), len(ss))

# 方案3: 使用密钥管理服务(推荐)
# 密钥不落地，只在HSM中运算
```

### 4.4 时间窗口容差

**当前设置**: ±60秒 (window_size=1)

```python
def check_epoch_window(self, epoch: int, current_epoch: int, window_size: int = 1):
    if abs(current_epoch - epoch) > window_size:
        return False  # 拒绝 ±60秒外的请求
```

**风险**:
- 时间同步不佳 → 频繁认证失败
- 时间窗口太宽 → 增加重放攻击窗口
- 时间攻击 → 虚假timestamp

**优化建议**:
```python
# 根据NTP质量动态调整
if ntp_stratum ≤ 2:
    window_size = 1    # ±60秒 (精准NTP)
elif ntp_stratum ≤ 5:
    window_size = 2    # ±120秒 (一般NTP)
else:
    raise CriticalError("时间同步不可信")
```

### 4.5 Redis连接缺乏加密

**现状**:
```python
# auth_gateway.py L15-17
self.redis = redis.Redis(
    host=redis_host, 
    port=redis_port,
    decode_responses=True
    # ❌ 无password, ssl, ssl_cert_reqs
)
```

**影响等级**: 🟠 高

**威胁**:
- Tag窃听 → 重放攻击
- 状态修改 → 认证绕过
- MITM攻击 → 完全破坏防重放

**修复代码**:
```python
self.redis = redis.Redis(
    host=redis_host,
    port=redis_port,
    password=os.environ.get('REDIS_PASSWORD'),
    ssl=True,
    ssl_cert_reqs='required',
    ssl_ca_certs='/path/to/ca.pem',
    decode_responses=True
)
```

---

## 5. 密钥管理安全

### 5.1 主密钥(Master Key)生命周期

#### 生成

```python
❌ 不安全: master_key = os.urandom(32)

✅ 安全方案:
  • HSM生成密钥
  • 或使用KMS (AWS KMS, HashiCorp Vault)
  • 多方计算(MPC)分享密钥
```

#### 存储

```python
❌ 不安全:
  master_key = open("keys/master.key").read()

✅ 安全方案:
  • Hardware Security Module (HSM)
  • Trusted Execution Environment (TEE)
  • 密钥管理系统 (HashiCorp Vault, AWS Secrets Manager)
  • 环境变量 (仅开发环境)
```

#### 销毁

```python
❌ 不安全:
  del master_key  # Python 不保证清零

✅ 安全方案:
  • 在HSM中销毁 (无法导出)
  • 使用cryptography库的safety API
  • 操作系统级别保管销毁证书
```

### 5.2 密钥轮换

**当前**:  没有实现

**建议**:
```
轮换策略:
  • Master Key: 每年一次
  • SLH-DSA Keypair: 每10万个签名
  • KEM Keypair: 每个会话

实现:
  # Fabric上记录密钥版本
  events = blockchain.queryEvents(device_id)
  if len(events) > 100000:
    new_key, new_root = rotate_keys()
    blockchain.registerNewIdentity(device_id, new_root)
```

### 5.3 密钥阶梯(Key Hierarchy)

```
                ┌─────────────────────┐
                │  主密钥 (Master Key) │ (HSM保管)
                └──────────┬──────────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
        签名密钥      加密密钥      认证密钥
      (SLH-DSA)    (AES-GCM)     (HMAC-SHA256)
        (≤10y)       (≤1y)         (≤1m)
```

---

## 6. 协议级别安全分析

### 6.1 注册协议

```
设备 ──register(device_id, master_key)──► 网关 ──putIdentity──► Fabric

威胁分析:
  1. 网关不验证master_key真实性
     → 风险: 设备声称身份但未真正持有密钥
     → 缓解: 在注册时要求设备签名证明
     
  2. Master Key在网络中传输
     → 风险: 中间人窃听
     → 缓解: 使用TLS 1.3 + 证书固定
     
  3. Fabric上明文存储ring_root
     → 风险: off-chain泄露
     → 缓解: 接受 (ring_root本应公开)
```

### 6.2 认证协议

```
设备 ──authenticate(witness, message, epoch)──► 网关 ──verify──► Fabric

完整性验证流程:
  ✓ 消息完整性: 签名验证 (SLH-DSA)
  ✓ 消息真实性: 环成员验证 (LRS)
  ✓ 消息新鲜性: epoch验证 + tag检查
  ✓ 消息绑定: message在签名中
  
完全前向保密(Forward Secrecy):
  ❌ 不支持 (ML-KEM一次性不可更新)
  缓解: 每个会话用新KEM密钥对
```

### 6.3 协议安全属性总结

| 属性 | 本协议 | 说明 |
|------|--------|------|
| 真实性 | ✅ | SLH-DSA签名 + 公钥基础设施 |
| 机密性 | ✅ | ML-KEM (抗量子) + TLS |
| 前向保密 | ❌ | 无会话密钥更新 |
| 匿名性 | ⚠️ | 可选 (环签名需>=4成员) |
| 防重放 | ✅ | 基于tag + epoch |
| 否认性 | ⚠️ | 有条件 (取决于环大小) |

---

## 7. 合规性与标准

### 7.1 遵循的标准

- **NIST FIPS 203**: ML-KEM (Kyber标准化)
- **NIST FIPS 204**: ML-DSA (CRYSTALS-Dilithium)
- **NIST FIPS 205**: SLH-DSA (SPHINCS+标准化)
- **IETF RFC 9090**: Post-Quantum Cryptography
- **NIST SP 800-56C**: Key Derivation

### 7.2 不遵循的标准

- ❌ **FIPS 140-2**: 需要CMVP认证的HSM
- ❌ **ECC规范**: 使用PQC替代
- ❌ **PKI X.509**: 使用Hyperledger Fabric CA

---

## 8. 安全审计与测试

### 8.1 推荐的审计项目

```
自动化:
  ☐ 单元测试 (密码学运算)
  ☐ 集成测试 (协议流程)
  ☐ 模糊测试 (输入边界)
  ☐ 内存泄露检查 (Valgrind)

手动审计:
  ☐ 密码学评审 (第三方)
  ☐ 代码审查 (安全焦点)
  ☐ 渗透测试 (网关攻击)
  ☐ 侧通道分析 (时间/功耗)
```

### 8.2 漏洞报告流程

```
发现漏洞:
  1. 勿公开讨论
  2. 发送至 security@example.com
  3. 提供细节& PoC
  4. 等待90天披露期
```

---

## 9. 结论 & 建议

### 优势

✅ **量子安全**: NIST标准化算法
✅ **匿名性**: 可链接环签名
✅ **防重放**: 多层机制
✅ **可扩展**: 区块链底层

### 改进项

⚠️ **Priority 1** (立即):
- 修复Merkle路径验证 (重要)
- 强制Redis防重放 (安全)
- 启用Redis TLS (关键)

⚠️ **Priority 2** (本月):
- 实现密钥轮换
- 添加侧通道防护
- 进行第三方审计

⚠️ **Priority 3** (将来):
- 完全前向保密 (PFS)
- 后量子密钥交换升级 (ML-KEM-768)
- 中文 GDPR/GB/T 合规

---

**安全审查日期**: 2026-03-23
**下次审查**: 2026-09-23 (6个月)
**维护人**: Security Team
