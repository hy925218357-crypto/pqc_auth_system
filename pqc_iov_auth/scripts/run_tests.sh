#!/bin/bash
# 运行所有测试

set -e

echo "🧪 运行 PQC IoV 自动化测试..."
echo ""

# 基础测试
echo "【密码学基础测试】"
pytest tests/test_crypto/ -v --cov=src/crypto_layer

echo ""
echo "【边缘节点测试】"
pytest tests/test_edge/ -v --cov=src/edge_node

echo ""
echo "【设备节点测试】"
pytest tests/test_device/ -v --cov=src/device_node

echo ""
echo "【集成测试】"
pytest tests/test_integration/ -v

echo ""
echo "✅ 所有测试通过！"