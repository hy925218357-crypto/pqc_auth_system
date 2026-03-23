"""
车辆/物联网终端服务端
处理来自其他设备或基础设施的请求
支持 V2V 通信和基础设施响应
"""
import socket
import threading
import json
import logging
from typing import Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class IoVServer:
    """物联网车辆服务端"""

    def __init__(self, device_id: str, host: str = "0.0.0.0", port: int = 8888,
                 max_workers: int = 4):
        """
        初始化服务端

        Args:
            device_id: 设备唯一标识符
            host: 监听地址
            port: 监听端口
            max_workers: 最大并发处理数
        """
        self.device_id = device_id
        self.host = host
        self.port = port
        self.max_workers = max_workers

        # 请求处理器映射
        self.request_handlers: Dict[str, Callable] = {}

        # 线程池
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

        # 服务器套接字
        self.server_socket = None
        self.running = False

        logger.info(f"[Server] 设备 {device_id} 服务端初始化完成")

    def register_handler(self, request_type: str, handler: Callable):
        """
        注册请求处理器

        Args:
            request_type: 请求类型
            handler: 处理函数，签名: handler(request_data: Dict) -> Dict
        """
        self.request_handlers[request_type] = handler
        logger.info(f"[Server] 已注册处理器: {request_type}")

    def start(self):
        """启动服务端"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        self.running = True

        logger.info(f"[Server] 服务启动在 {self.host}:{self.port}")

        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                logger.info(f"[Server] 新连接: {addr}")
                self.executor.submit(self._handle_client, client_socket, addr)
        except KeyboardInterrupt:
            logger.info("[Server] 收到停止信号")
        finally:
            self.stop()

    def stop(self):
        """停止服务端"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        self.executor.shutdown(wait=True)
        logger.info("[Server] 服务已停止")

    def _handle_client(self, client_socket: socket.socket, addr: tuple):
        """处理客户端连接"""
        try:
            # 接收数据
            data = client_socket.recv(4096)
            if not data:
                return

            # 解析请求
            request = json.loads(data.decode('utf-8'))
            request_type = request.get('type', 'unknown')
            request_data = request.get('data', {})

            logger.debug(f"[Server] 收到请求: {request_type} from {addr}")

            # 查找处理器
            handler = self.request_handlers.get(request_type)
            if not handler:
                response = {
                    'status': 'error',
                    'message': f'未知请求类型: {request_type}'
                }
            else:
                # 执行处理器
                try:
                    response = handler(request_data)
                    response['status'] = 'success'
                except Exception as e:
                    logger.error(f"[Server] 处理请求失败: {e}")
                    response = {
                        'status': 'error',
                        'message': str(e)
                    }

            # 发送响应
            response_json = json.dumps(response)
            client_socket.sendall(response_json.encode('utf-8'))

        except json.JSONDecodeError:
            logger.warning(f"[Server] 无效JSON from {addr}")
            error_response = {'status': 'error', 'message': '无效JSON格式'}
            client_socket.sendall(json.dumps(error_response).encode('utf-8'))
        except Exception as e:
            logger.error(f"[Server] 处理连接异常: {e}")
        finally:
            client_socket.close()

    # ===== 内置处理器 =====

    def handle_v2v_auth_request(self, request_data: Dict) -> Dict:
        """
        处理来自其他车辆的认证请求 (V2V)

        Args:
            request_data: 认证请求数据

        Returns:
            认证响应
        """
        # 这里应该集成认证逻辑
        # 目前返回模拟响应
        logger.info(f"[V2V] 收到认证请求: {request_data.get('device_id', 'unknown')}")

        return {
            'authenticated': True,
            'device_id': request_data.get('device_id'),
            'timestamp': request_data.get('timestamp')
        }

    def handle_infrastructure_message(self, request_data: Dict) -> Dict:
        """
        处理来自基础设施的消息 (I2V)

        Args:
            request_data: 消息数据

        Returns:
            处理确认
        """
        logger.info(f"[I2V] 收到基础设施消息: {request_data.get('message_type', 'unknown')}")

        return {
            'received': True,
            'message_id': request_data.get('message_id'),
            'processed_at': request_data.get('timestamp')
        }

    def handle_status_query(self, request_data: Dict) -> Dict:
        """
        处理状态查询请求

        Args:
            request_data: 查询数据

        Returns:
            状态信息
        """
        return {
            'device_id': self.device_id,
            'status': 'active',
            'uptime': 0,  # 可以集成实际运行时间
            'version': '1.0.0'
        }


def create_default_server(device_id: str, port: int = 8888) -> IoVServer:
    """
    创建默认配置的服务端

    Args:
        device_id: 设备ID
        port: 端口

    Returns:
        配置好的服务端实例
    """
    server = IoVServer(device_id, port=port)

    # 注册默认处理器
    server.register_handler('v2v_auth', server.handle_v2v_auth_request)
    server.register_handler('i2v_message', server.handle_infrastructure_message)
    server.register_handler('status_query', server.handle_status_query)

    return server


if __name__ == "__main__":
    # 示例用法
    import sys

    device_id = sys.argv[1] if len(sys.argv) > 1 else "vehicle_001"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8888

    server = create_default_server(device_id, port)
    logger.info(f"启动设备服务端: {device_id} 端口 {port}")

    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("服务被用户停止")