# PQC IoV Authentication System

基于后量子密码学的物联网车辆身份认证系统，实现环签名、可链接性与防重放保护。

## 特性

- **后量子安全**: 使用 XMSS (RFC 8391) 和 ML-KEM (Kyber) 提供量子计算抵抗力
- **匿名认证**: 基于可链接环签名 (Linkable Ring Signature) 实现隐私保护
- **防重放**: 时间纪元 (epoch) + nonce 机制
- **分布式架构**: 边缘节点 + 区块链信任层

## 架构

```
终端设备 (device_node) -> 边缘网关 (edge_node) -> 区块链 (blockchain_layer)
```

## 安装

1. 安装依赖:
```bash
pip install -r requirements.txt
```

2. 启动基础设施:
```bash
cd scripts
docker-compose up -d
```

3. 运行测试:
```bash
pytest
```

## 使用

### 设备注册

```python
from src.device_node.client import DeviceClient

client = DeviceClient("vehicle_123", b"your_master_key")
result = client.register()
```

### 认证请求

```python
result = client.authenticate(b"auth_message", current_epoch)
```

## 引用

[18] 本项目实现基于相关论文的协议设计。

## 许可证

MIT License