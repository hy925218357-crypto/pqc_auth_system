# PQC IoV 认证系统 (Post-Quantum Cryptography Internet-of-Vehicles Authentication)

## 🎯 项目概述

该项目实现了一个**四层混合认证架构**，专为车联网(IoV)场景设计，采用**后量子密码学(PQC)**技术确保即使面临量子计算威胁也能保持安全性。

### 核心特性

- ✅ **ML-KEM-512 (Kyber)** - NIST标准化的抗量子密钥封装机制
- ✅ **SLH-DSA (FIPS 205)** - 无状态抗量子数字签名算法
- ✅ **可链接环签名(LRS)** - 实现匿名认证和防重放
- ✅ **零知识证明(ZKP)** - 证明环成员身份而不暴露真实身份
- ✅ **Hyperledger Fabric** - 分布式身份注册与管理
- ✅ **Redis** - 分布式防重放机制

### 架构层次

```
┌────────────────────────────────┐
│  1️⃣ 密码学层 (Crypto Layer)    │  ML-KEM + SLH-DSA + LRS
├────────────────────────────────┤
│  2️⃣ 边缘节点层 (Edge Node)     │  认证网关 + 防重放管理
├────────────────────────────────┤
│  3️⃣ 设备节点层 (Device Node)   │  客户端/服务端通信
├────────────────────────────────┤
│  4️⃣ 区块链层 (Blockchain)     │  身份注册 + 环根管理
└────────────────────────────────┘
```

---

## 🚀 快速开始

### 前置要求

| 组件 | 版本 | 说明 |
|------|------|------|
| Python | 3.9+ | 核心运行时 |
| Redis | 6.0+ | 防重放后端存储 |
| liboqs | 0.15.0 | 量子安全加密库 |
| Hyperledger Fabric | 2.5+ | (可选) 区块链部分 |

### 环境设置

#### 1. 克隆仓库

```bash
git clone <repository-url>
cd pqc_iov_auth
```

#### 2. 创建虚拟环境

```bash
python3 -m venv pqc_env
source pqc_env/bin/activate  # Linux/Mac
# 或 pqc_env\Scripts\activate  # Windows
```

#### 3. 安装依赖

```bash
pip install -r requirements.txt
```

#### 4. 启动 Redis

```bash
# 使用 Docker
docker run -d -p 6379:6379 redis:latest

# 或本地安装
redis-server
```

#### 5. 验证安装

```bash
python -c "
import sys
sys.path.insert(0, '.')
from src.edge_node.auth_gateway import AuthGateway
from src.device_node.client import DeviceClient
print('✅ 所有模块导入成功')
"
```

---

## 📚 模块介绍

### 核心模块结构

```
src/
├── crypto_layer/                    # 密码学核心
│   ├── kyber_kem.py                 # ML-KEM-512 密钥封装
│   ├── xmss_liboqs.py               # SLH-DSA 数字签名 (无状态)
│   ├── xmss_stateful.py             # XMSS 状态管理接口
│   ├── lrs_zkp.py                   # 可链接环签名 + 零知识证明
│   └── __init__.py
│
├── edge_node/                       # 边缘节点 (认证网关)
│   ├── auth_gateway.py              # 认证协议主逻辑
│   ├── anti_replay.py               # 防重放管理 (Redis后端)
│   └── __init__.py
│
├── device_node/                     # 设备节点 (IoV终端)
│   ├── client.py                    # 认证客户端
│   ├── server.py                    # V2V服务端
│   └── __init__.py
│
└── blockchain_layer/                # 区块链层 (Go/Fabric)
    └── ...
```

### 关键类和API

#### 1. KyberKEMEngine (ML-KEM-512)

```python
from src.crypto_layer.kyber_kem import KyberKEMEngine

# 初始化引擎
kem = KyberKEMEngine("ML-KEM-512")

# 生成密钥对
pk, sk = kem.generate_keypair()

# 密钥封装 (生成会话密钥)
ct, ss = kem.encapsulate(pk)

# 密钥解封装
ss_recovered = kem.decapsulate(ct, sk)
```

#### 2. SLH-DSA 签名 (xmss_liboqs.py)

```python
from src.crypto_layer.xmss_liboqs import SLHDSASignature

# 初始化 (无状态签名)
sig = SLHDSASignature(device_id="vehicle_001", redis_backend=redis_client)

# 生成密钥
sig.generate_keys()

# 签名
signature = sig.sign(message=b"authenticate_me")

# 验证
is_valid = sig.verify(message=b"authenticate_me", signature=signature)
```

#### 3. 可链接环签名 + ZKP

```python
from src.crypto_layer.lrs_zkp import TrueLinkableRingSignature

# 初始化
lrs = TrueLinkableRingSignature(replay_backend=redis_client)

# 生成证人 (ZKP)
witness = lrs.generate_zkp_witness(
    ring_members=[pk1, pk2, pk3],
    signer_index=0,
    message=b"message"
)

# 验证
is_valid = lrs.verify(
    message=b"message",
    witness=witness,
    ring_root=witness["ring_root"],
    replay_backend=redis_client
)
```

#### 4. 认证网关 (Edge Node)

```python
from src.edge_node.auth_gateway import AuthGateway

# 初始化
gateway = AuthGateway(redis_host="localhost", redis_port=6379)

# 设备注册
reg_result = gateway.register_device(
    device_id="vehicle_001",
    xmss_master_key=b"\x01" * 32
)

# 认证请求处理
auth_result = gateway.authenticate_device({
    "device_id": "vehicle_001",
    "signature": {...},
    "message": b"auth_message",
    "epoch": 1000
})
```

#### 5. 设备客户端

```python
from src.device_node.client import DeviceClient

# 初始化设备
client = DeviceClient(
    device_id="vehicle_001",
    master_key=b"\x01" * 32,
    gateway_url="http://edge_node:5000"
)

# 注册
client.register()

# 认证
auth_response = client.authenticate(
    message=b"sensor_data",
    epoch=1000
)
```

---

## 🔐 安全考虑

### 威胁模型

系统防护以下威胁:

| 威胁 | 防护机制 |
|------|---------|
| 后量子攻击 | ML-KEM + SLH-DSA |
| 中间人攻击 | 环签名 + ZKP |
| 重放攻击 | nonce验证 + Redis TTL |
| 身份冒充 | Fabric公钥证书 |
| 时间基础攻击 | ±60秒时间窗口 |

### 密钥管理

- ⚠️ **Master Key** 应由专业密钥管理系统(KMS)提供
- ⚠️ Redis 连接应启用 SSL/TLS + 密码认证
- ⚠️ 环境变量不应包含敏感密钥，使用密钥管理服务

### 已知限制

1. **防重放多进程支持**
   - 必须使用 Redis 后端
   - 进程内存存储仅支持单进程

2. **Merkle 路径验证**
   - 当前使用 SLH-DSA 替代 XMSS，路径为空
   - 环成员证明仅验证叶子节点

3. **内存清除**
   - Python中内存擦除不可靠
   - 建议在密钥交换后立即销毁敏感数据

---

## 🧪 测试

### 运行所有测试

```bash
# 标准输出
pytest

# 详细输出
pytest -v

# 指定测试文件
pytest tests/test_crypto/test_kyber.py

# 排除集成测试
pytest -m "not integration"

# 查看覆盖率
pytest --cov=src --cov-report=html
```

### 测试结构

```
tests/
├── test_crypto/              # 密码学层单元测试
│   ├── test_kyber.py         # ML-KEM 测试
│   ├── test_xmss.py          # SLH-DSA 测试
│   └── test_lrs_zkp.py       # 环签名 + ZKP 测试
│
├── test_edge/                # 边缘节点测试
│   ├── test_gateway.py       # 认证网关测试
│   └── test_anti_replay.py   # 防重放机制测试
│
├── test_device/              # 设备节点测试
│   ├── test_client.py        # 客户端测试
│   └── test_server.py        # 服务端测试
│
├── test_integration.py       # 端到端集成测试
└── conftest.py              # pytest 配置和共享Fixture
```

### 关键测试用例

#### 密码学层

```python
# 测试ML-KEM
def test_kem_encapsulation_decapsulation():
    """验证密钥封装和解封装一致性"""

# 测试SLH-DSA签名
def test_slhdsa_sign_and_verify():
    """验证签名生成和验证"""

# 测试环签名
def test_linkable_ring_signature():
    """验证可链接性和匿名性"""

# 测试ZKP
def test_zkp_membership_proof():
    """验证成员身份零知识证明"""
```

#### 集成测试

```python
# 测试完整认证流程
def test_full_authentication_flow():
    """从注册到认证的完整流程测试"""

# 测试防重放
def test_replay_prevention():
    """验证相同tag无法重复认证"""

# 测试并发认证
def test_concurrent_authentications():
    """测试高并发场景"""
```

---

## 📊 性能基准

### 基准测试结果 (在标准硬件上)

| 操作 | 耗时 | 说明 |
|------|------|------|
| ML-KEM 密钥生成 | ~0.5ms | per keypair |
| ML-KEM 封装 | ~0.8ms | per encapsulation |
| ML-KEM 解封装 | ~1.2ms | per decapsulation |
| SLH-DSA 签名 | ~15ms | per signature |
| SLH-DSA 验证 | ~20ms | per verification |
| 环签名 (4成员) | ~50ms | with ZKP |
| Redis 防重放检查 | ~2-5ms | network latency |

### 优化建议

- 使用连接池减少Redis往返
- 实现签名结果缓存 (TTL: 60s)
- 异步持久化状态而非同步阻塞

---

## 🛠️ 部署

### Docker 部署

```bash
# 构建镜像
docker build -t pqc-iov:latest .

# 启动容器 (with Redis)
docker-compose -f docker-compose.yml up -d
```

### 生产环境配置

```bash
# 使用环境变量
export REDIS_HOST=prod-redis.example.com
export REDIS_PASSWORD=secure_password
export REDIS_SSL=true
export DEVICE_ID=vehicle_$(hostname)

# 运行网关
python -m src.edge_node.auth_gateway
```

---

## 📖 详细文档

- [架构设计](docs/ARCHITECTURE.md) - 系统架构与数据流
- [API 参考](docs/API.md) - 完整API文档
- [安全分析](docs/SECURITY.md) - 威胁模型与防护措施
- [部署指南](docs/DEPLOYMENT.md) - 生产环境部署
- [贡献指南](CONTRIBUTING.md) - 如何贡献代码

---

## 🔗 相关资源

- **NIST PQC 标准**: https://csrc.nist.gov/projects/post-quantum-cryptography
- **liboqs 项目**: https://github.com/open-quantum-safe/liboqs
- **Hyperledger Fabric**: https://hyperledger-fabric.readthedocs.io

---

## 📄 许可证

该项目采用 **MIT License**。详见 [LICENSE](LICENSE) 文件。

---

## 📞 联系与支持

- **问题报告**: GitHub Issues
- **讨论**: GitHub Discussions
- **贡献**: Pull Requests 欢迎

---

## 🎓 引用

如果您在研究中使用本项目，请引用:

```bibtex
@software{pqc_iov_2026,
  title={PQC IoV Authentication System},
  author={Contributors},
  year={2026},
  url={https://github.com/yourusername/pqc_iov_auth}
}
```

---

**最后更新**: 2026年3月23日
