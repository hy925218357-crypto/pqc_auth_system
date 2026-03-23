#!/bin/bash
# 环境初始化脚本

set -e

echo "🚀 初始化 PQC IoV 开发环境..."

# 检查 Python 版本
python3 --version

# 创建虚拟环境
if [ ! -d "venv" ]; then
    echo "📦 创建 Python 虚拟环境..."
    python3 -m venv venv
fi

# 激活虚拟环境
source venv/bin/activate

# 安装依赖
echo "📚 安装依赖..."
pip install -q --upgrade pip setuptools wheel
pip install -q -r requirements.txt
pip install -q -r requirements-dev.txt

# 安装本地包
pip install -q -e .

echo "✅ 环境初始化完成！"
echo ""
echo "💡 后续使用："
echo "   source venv/bin/activate  # 激活虚拟环境"
echo "   pytest tests/              # 运行测试"
echo "   python scripts/benchmark.py # 性能测试"