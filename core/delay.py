"""
延迟生成模块
"""
import random
import logging
from .config import ScanConfig


class DelayGenerator:
    """延迟生成器，负责生成随机延迟时间"""

    def __init__(self, config: ScanConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger

    def generate_random_delay(self) -> float:
        """生成随机延迟时间：基础时间 + 随机抖动"""
        jitter = random.uniform(self.config.jitter_min, self.config.jitter_max)
        total_delay = self.config.base_delay + jitter
        self.logger.info(
            f"Sleep {self.config.base_delay} + {jitter:.2f} = {total_delay:.2f} seconds"
        )
        return total_delay
