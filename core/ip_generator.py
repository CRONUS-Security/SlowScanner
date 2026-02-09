"""
IP地址生成模块
"""
import ipaddress
import random
from typing import List
from pathlib import Path


class IPGenerator:
    """IP地址生成器，负责根据CIDR或文件生成IP列表"""

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
    
    @staticmethod
    def load_ips_from_file(file_path: str) -> List[str]:
        """从文件读取IP列表，每一行代表一个IP地址
        
        Args:
            file_path: 文件路径
            
        Returns:
            IP地址列表（已随机打乱）
            
        Raises:
            FileNotFoundError: 文件不存在时抛出
            ValueError: IP格式不正确时抛出
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"IP文件不存在: {file_path}")
        
        ip_list = []
        with open(path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                # 去除空白符和注释
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 验证IP地址格式
                try:
                    ipaddress.ip_address(line)
                    ip_list.append(line)
                except ValueError:
                    raise ValueError(f"第 {line_num} 行IP格式不正确: {line}")
        
        if not ip_list:
            raise ValueError(f"文件中没有找到有效的IP地址: {file_path}")
        
        random.shuffle(ip_list)
        return ip_list
    
    @staticmethod
    def load_ips_from_file_stream(file_path: str):
        """从文件读取IP列表的生成器版本（节省内存）
        
        Args:
            file_path: 文件路径
            
        Yields:
            IP地址字符串
            
        Raises:
            FileNotFoundError: 文件不存在时抛出
            ValueError: IP格式不正确时抛出
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"IP文件不存在: {file_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                # 去除空白符和注释
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 验证IP地址格式
                try:
                    ipaddress.ip_address(line)
                    yield line
                except ValueError:
                    raise ValueError(f"第 {line_num} 行IP格式不正确: {line}")
    
    @staticmethod
    def get_ip_count_from_file(file_path: str) -> int:
        """获取文件中有效的IP地址数量
        
        Args:
            file_path: 文件路径
            
        Returns:
            有效的IP地址数量
        """
        count = 0
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"IP文件不存在: {file_path}")
        
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        ipaddress.ip_address(line)
                        count += 1
                    except ValueError:
                        pass
        
        return count
