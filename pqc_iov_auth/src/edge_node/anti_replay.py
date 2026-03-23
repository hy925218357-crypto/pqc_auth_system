"""
基于 Redis 的防重放机制
防止重放攻击与签名链接追踪
"""
import redis
import logging
import hashlib
from typing import Dict, Tuple, Optional

logger = logging.getLogger(__name__)

class AntiReplayManager:
    """防重放管理器 - 基于 Redis 存储"""
    
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379,
                 db: int = 0, ttl: int = 600):
        """
        Args:
            redis_host: Redis 服务器地址
            redis_port: Redis 端口
            db: Redis 数据库号
            ttl: 时间戳有效期（秒）
        """
        self.redis_client = redis.Redis(
            host=redis_host, 
            port=redis_port, 
            db=db, 
            decode_responses=True
        )
        self.ttl = ttl
    
    def check_nonce(self, nonce: str, tag: str) -> bool:
        """
        检查 nonce 是否已被使用
        
        Args:
            nonce: 一次性数值
            tag: 链接标签（用于追踪同一签名者）
        
        Returns:
            True if 新鲜, False if 重放
        """
        key = f"nonce:{nonce}:{tag}"
        # 原子记录：使用 SET NX，避免竞态（多实例/并发签名场景）
        was_set = self.redis_client.set(key, "1", ex=self.ttl, nx=True)
        if not was_set:
            logger.warning(f"[Anti-Replay] 检测到重放攻击: {tag[:16]}...")
            return False
        logger.debug(f"[Anti-Replay] Nonce 已记录: {nonce[:8]}...")
        return True
    
    def track_linkage_tag(self, tag: str, device_id: str) -> Tuple[bool, Optional[str]]:
        """
        追踪链接标签（检测同一设备的多次签名）
        
        Args:
            tag: 链接标签
            device_id: 设备标识符
        
        Returns:
            (is_new, previous_device_id)
        """
        key = f"linkage_tag:{tag}"
        
        previous = self.redis_client.get(key)
        
        if previous and previous != device_id:
            logger.warning(f"[Anti-Replay] 链接标签冲突: {tag[:16]}...")
            return False, previous
        
        # 记录标签
        self.redis_client.setex(key, self.ttl * 2, device_id)
        logger.info(f"[Anti-Replay] 链接标签已记录: {tag[:16]}...")
        
        return True, previous
    
    def check_epoch_window(self, epoch: int, current_epoch: int, window_size: int = 1) -> bool:
        """
        检查时间轮是否在接受窗口内
        
        Args:
            epoch: 签名中的时间轮
            current_epoch: 当前时间轮
            window_size: 允许的偏差（时间轮数）
        
        Returns:
            True if 有效, False if 过期
        """
        if abs(current_epoch - epoch) > window_size:
            logger.warning(f"[Anti-Replay] 时间轮过期: {epoch} vs {current_epoch}")
            return False
        
        return True
    
    def cleanup_expired(self):
        """清理过期的缓存（应定期调用）"""
        # Redis 会自动清理过期键，无需手动干预
        logger.debug("[Anti-Replay] Redis 自动清理已过期的键")