"""
IP地址生成模块
"""
import ipaddress
import random
from typing import List


class IPGenerator:
    """IP地址生成器，负责根据CIDR生成IP列表"""

    @staticmethod
    def generate_ip_list(cidr: str) -> List[str]:
        """根据CIDR生成IP地址列表并随机打乱"""
        network = ipaddress.ip_network(cidr, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        random.shuffle(ip_list)
        return ip_list
    
    @staticmethod
    def generate_ip_stream(cidr: str):
        """根据CIDR生成IP地址流（生成器），节省内存"""
        network = ipaddress.ip_network(cidr, strict=False)
        for ip in network.hosts():
            yield str(ip)
    
    @staticmethod
    def get_ip_count(cidr: str) -> int:
        """获取CIDR范围内的IP数量（不生成实际IP）"""
        network = ipaddress.ip_network(cidr, strict=False)
        return network.num_addresses - 2  # 减去网络地址和广播地址
