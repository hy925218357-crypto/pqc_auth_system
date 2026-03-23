#!/usr/bin/env python3
"""
性能基准测试脚本
测试并发签名与验证性能
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.concurrent_tester import main

if __name__ == "__main__":
    main()