#!/usr/bin/env python3
"""
IP地址排序工具
读取扫描结果文件中的IP地址，进行排序后写回原文件
支持IPv4地址的自然排序（按数字大小而非字符串排序）
"""

import argparse
import ipaddress
from pathlib import Path
from typing import List, Dict, Optional
from main import ScanConfig


class IPSorter:
    """IP地址排序器，负责读取、排序和保存IP地址列表"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.result_files = {
            "response": self.config.response_file,
            "connection_refused": self.config.connection_refused_file,
            "timeout": self.config.timeout_file,
            "other_errors": self.config.other_errors_file
        }
    
    def read_ips_from_file(self, file_path: str) -> List[str]:
        """从文件中读取IP地址列表"""
        try:
            if not Path(file_path).exists():
                print(f"文件不存在: {file_path}")
                return []
            
            with open(file_path, 'r', encoding='utf-8') as f:
                # 读取所有行，去除空白字符和空行
                ips = [line.strip() for line in f.readlines() if line.strip()]
            
            print(f"从 {file_path} 读取到 {len(ips)} 个IP地址")
            return ips
            
        except Exception as e:
            print(f"读取文件 {file_path} 时出错: {e}")
            return []
    
    def sort_ips(self, ip_list: List[str]) -> List[str]:
        """对IP地址列表进行自然排序（按IP地址数值大小排序）"""
        if not ip_list:
            return []
        
        try:
            # 将字符串IP转换为ipaddress对象进行排序
            ip_objects = []
            invalid_ips = []
            
            for ip_str in ip_list:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    ip_objects.append((ip_obj, ip_str))
                except ValueError:
                    # 如果不是有效的IP地址，单独记录
                    invalid_ips.append(ip_str)
                    print(f"警告: 无效的IP地址格式: {ip_str}")
            
            # 按IP地址对象排序
            ip_objects.sort(key=lambda x: x[0])
            
            # 提取排序后的IP字符串
            sorted_ips = [ip_str for _, ip_str in ip_objects]
            
            # 将无效IP添加到末尾
            sorted_ips.extend(invalid_ips)
            
            print(f"成功排序 {len(sorted_ips)} 个IP地址")
            return sorted_ips
            
        except Exception as e:
            print(f"排序IP地址时出错: {e}")
            # 如果排序失败，返回原始列表的字符串排序
            return sorted(ip_list)
    
    def write_ips_to_file(self, file_path: str, ip_list: List[str]) -> bool:
        """将IP地址列表写入文件"""
        try:
            if not ip_list:
                print(f"没有IP地址需要写入 {file_path}")
                return True
            
            # 确保目录存在
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                for ip in ip_list:
                    f.write(f"{ip}\n")
            
            print(f"成功将 {len(ip_list)} 个IP地址写入 {file_path}")
            return True
            
        except Exception as e:
            print(f"写入文件 {file_path} 时出错: {e}")
            return False
    
    def sort_single_file(self, file_type: str) -> bool:
        """排序单个结果文件"""
        if file_type not in self.result_files:
            print(f"错误: 未知的文件类型 '{file_type}'")
            print(f"支持的文件类型: {list(self.result_files.keys())}")
            return False
        
        file_path = self.result_files[file_type]
        print(f"\n处理 {file_type} 文件: {file_path}")
        
        # 读取IP地址
        ips = self.read_ips_from_file(file_path)
        if not ips:
            print(f"文件 {file_path} 中没有IP地址需要排序")
            return True
        
        # 排序IP地址
        sorted_ips = self.sort_ips(ips)
        
        # 检查是否需要更新文件
        if ips == sorted_ips:
            print(f"文件 {file_path} 中的IP地址已经是有序的，无需更新")
            return True
        
        # 写回文件
        success = self.write_ips_to_file(file_path, sorted_ips)
        if success:
            print(f"文件 {file_path} 排序完成")
        
        return success
    
    def sort_all_files(self) -> Dict[str, bool]:
        """排序所有结果文件"""
        print(f"开始排序 CIDR {self.config.cidr_range} 端口 {self.config.port} 的所有结果文件...")
        print(f"结果目录: {self.config.result_dir}")
        
        results = {}
        
        for file_type in self.result_files.keys():
            results[file_type] = self.sort_single_file(file_type)
        
        # 输出总结
        print(f"\n排序总结:")
        success_count = sum(1 for success in results.values() if success)
        total_count = len(results)
        
        print(f"成功处理: {success_count}/{total_count} 个文件")
        
        for file_type, success in results.items():
            status = "✓" if success else "✗"
            print(f"  {status} {file_type}: {self.result_files[file_type]}")
        
        return results
    
    def preview_sorting(self, file_type: str, limit: int = 10) -> None:
        """预览排序效果，不实际修改文件"""
        if file_type not in self.result_files:
            print(f"错误: 未知的文件类型 '{file_type}'")
            return
        
        file_path = self.result_files[file_type]
        print(f"\n预览 {file_type} 文件排序效果: {file_path}")
        
        # 读取IP地址
        ips = self.read_ips_from_file(file_path)
        if not ips:
            print("文件中没有IP地址")
            return
        
        # 排序IP地址
        sorted_ips = self.sort_ips(ips)
        
        print(f"\n原始顺序 (前{min(limit, len(ips))}个):")
        for i, ip in enumerate(ips[:limit]):
            print(f"  {i+1:2d}. {ip}")
        
        if len(ips) > limit:
            print(f"  ... 还有 {len(ips) - limit} 个IP地址")
        
        print(f"\n排序后 (前{min(limit, len(sorted_ips))}个):")
        for i, ip in enumerate(sorted_ips[:limit]):
            print(f"  {i+1:2d}. {ip}")
        
        if len(sorted_ips) > limit:
            print(f"  ... 还有 {len(sorted_ips) - limit} 个IP地址")
        
        if ips == sorted_ips:
            print("\n文件中的IP地址已经是有序的")
        else:
            print(f"\n排序将改变 IP 地址的顺序")


def create_sorter_from_default_config() -> IPSorter:
    """从默认的ScanConfig配置创建IP排序器"""
    config = ScanConfig()  # 使用默认配置
    return IPSorter(config)


def main():
    """主函数 - 自动使用ScanConfig的默认配置"""
    parser = argparse.ArgumentParser(
        description="IP地址排序工具 - 使用ScanConfig默认配置对扫描结果文件中的IP地址进行排序",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 排序所有结果文件（使用ScanConfig默认配置）
  python ip_sorter.py
  
  # 只排序响应文件
  python ip_sorter.py --file-type response
  
  # 预览排序效果不实际修改
  python ip_sorter.py --preview --file-type timeout
  
支持的文件类型:
  - response: 有响应的IP地址
  - connection_refused: 连接被拒绝的IP地址  
  - timeout: 超时的IP地址
  - other_errors: 其他错误的IP地址
  
注意: 此工具自动使用ScanConfig中的默认CIDR、端口和协议配置
        """
    )
    
    parser.add_argument(
        "--file-type", 
        choices=["response", "connection_refused", "timeout", "other_errors"],
        help="只处理指定类型的文件，不指定则处理所有文件"
    )
    
    parser.add_argument(
        "--preview", 
        action="store_true",
        help="预览排序效果，不实际修改文件"
    )
    
    parser.add_argument(
        "--preview-limit", 
        type=int, 
        default=10,
        help="预览模式下显示的IP地址数量 (默认: 10)"
    )
    
    args = parser.parse_args()
    
    # 创建IP排序器（使用默认配置）
    try:
        sorter = create_sorter_from_default_config()
        print(f"使用ScanConfig默认配置:")
        print(f"  CIDR: {sorter.config.cidr_range}")
        print(f"  Port: {sorter.config.port}")
        print(f"  Protocol: {sorter.config.protocol}")
        print(f"  结果目录: {sorter.config.result_dir}")
        
    except Exception as e:
        print(f"创建配置时出错: {e}")
        return 1
    
    # 执行操作
    try:
        if args.preview:
            # 预览模式
            if args.file_type:
                sorter.preview_sorting(args.file_type, args.preview_limit)
            else:
                print("预览模式需要指定 --file-type 参数")
                return 1
        elif args.file_type:
            # 排序单个文件
            success = sorter.sort_single_file(args.file_type)
            return 0 if success else 1
        else:
            # 排序所有文件
            results = sorter.sort_all_files()
            success_count = sum(1 for success in results.values() if success)
            total_count = len(results)
            
            if success_count == total_count:
                print(f"\n所有 {total_count} 个文件排序成功！")
                return 0
            else:
                print(f"\n警告: 只有 {success_count}/{total_count} 个文件排序成功")
                return 1
                
    except KeyboardInterrupt:
        print("\n操作被用户取消")
        return 1
    except Exception as e:
        print(f"执行过程中出错: {e}")
        return 1


if __name__ == "__main__":
    exit(main())