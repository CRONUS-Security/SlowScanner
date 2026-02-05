#!/usr/bin/env python3
"""
HTML Title 提取器

从扫描结果的HTML文件中提取所有<title>标签内容，
使用URL解码后在终端显示结果。

使用方法:
    python extract_titles.py

作者: GitHub Copilot
版本: 1.0
"""

import os
import re
import urllib.parse
from pathlib import Path
from typing import List, Dict, Tuple
import argparse
import html
from bs4 import BeautifulSoup

# 导入主模块的配置
try:
    from main import ScanConfig
except ImportError:
    print("错误: 无法导入 SlowHTTPScanner 模块")
    print("请确保 SlowHTTPScanner.py 在同一目录下")
    exit(1)


class TitleExtractor:
    """HTML标题提取器"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.html_dir = config.html_responses_dir
        
    def find_html_files(self) -> List[Path]:
        """查找所有HTML响应文件"""
        html_dir = Path(self.html_dir)
        
        if not html_dir.exists():
            print(f"警告: HTML响应目录不存在: {html_dir}")
            return []
            
        html_files = list(html_dir.glob("*.html"))
        print(f"找到 {len(html_files)} 个HTML文件")
        return html_files
    
    def extract_title_from_file(self, file_path: Path) -> Tuple[str, str, str]:
        """从单个HTML文件中提取title
        
        返回: (文件名, IP地址, 解码后的title)
        """
        try:
            # 从文件名解析IP地址信息 (格式: protocol_ip_port_response.html)
            filename = file_path.stem  # 去掉.html扩展名
            parts = filename.split('_')
            
            if len(parts) >= 3:
                protocol = parts[0]
                ip = parts[1]
                port = parts[2]
                ip_info = f"{protocol}://{ip}:{port}"
            else:
                ip_info = filename
            
            # 读取HTML文件内容
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 使用BeautifulSoup解析HTML (更可靠和强大)
            soup = BeautifulSoup(content, 'html.parser')
            title_tag = soup.find('title')
            
            if title_tag:
                # 获取title内容，BeautifulSoup会自动处理HTML实体
                raw_title = title_tag.get_text().strip()
                
                # 清理多余的空白字符
                cleaned_title = re.sub(r'\s+', ' ', raw_title)
                
                # 进行URL解码
                decoded_title = urllib.parse.unquote(cleaned_title)
                
                return ip_info, raw_title, decoded_title
            else:
                # 如果BeautifulSoup没找到，作为备用尝试正则表达式
                title_match = re.search(r'<title[^>]*?>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                if title_match:
                    raw_title = html.unescape(title_match.group(1).strip())
                    cleaned_title = re.sub(r'\s+', ' ', raw_title)
                    decoded_title = urllib.parse.unquote(cleaned_title)
                    return ip_info, raw_title, decoded_title
                else:
                    return ip_info, "", "[无标题]"
                    
        except Exception as e:
            print(f"处理文件 {file_path} 时出错: {e}")
            return str(file_path), "", f"[错误: {e}]"
    
    def extract_all_titles(self) -> List[Tuple[str, str, str]]:
        """从所有HTML文件中提取标题"""
        html_files = self.find_html_files()
        
        if not html_files:
            print("没有找到HTML文件")
            return []
        
        results = []
        print(f"\n开始处理 {len(html_files)} 个文件...")
        
        for file_path in html_files:
            ip_info, raw_title, decoded_title = self.extract_title_from_file(file_path)
            results.append((ip_info, raw_title, decoded_title))
        
        return results
    
    def display_results(self, results: List[Tuple[str, str, str]], show_raw: bool = False):
        """在终端显示提取结果"""
        if not results:
            print("没有提取到任何标题")
            return
        
        print(f"\n{'='*80}")
        print(f"HTML 标题提取结果 (共 {len(results)} 个)")
        print(f"{'='*80}")
        
        # 按IP地址排序
        results.sort(key=lambda x: x[0])
        
        for i, (ip_info, raw_title, decoded_title) in enumerate(results, 1):
            print(f"\n[{i:3d}] {ip_info}")
            
            if decoded_title == "[无标题]":
                print(f"      标题: {decoded_title}")
            elif decoded_title.startswith("[错误"):
                print(f"      状态: {decoded_title}")
            else:
                print(f"      标题: {decoded_title}")
                if show_raw and raw_title != decoded_title:
                    print(f"      原始: {raw_title}")
        
        print(f"\n{'='*80}")
        
        # 统计信息
        valid_titles = [r for r in results if not r[2].startswith("[")]
        print(f"统计: 总文件数={len(results)}, 有效标题={len(valid_titles)}, 无标题/错误={len(results)-len(valid_titles)}")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='从扫描结果的HTML文件中提取标题')
    parser.add_argument('--cidr', type=str, help='指定CIDR范围 (默认使用配置文件中的值)')
    parser.add_argument('--port', type=int, help='指定端口 (默认使用配置文件中的值)')
    parser.add_argument('--show-raw', action='store_true', help='显示原始标题内容')
    parser.add_argument('--output', type=str, help='将结果保存到文件')
    
    args = parser.parse_args()
    
    try:
        # 创建配置
        if args.cidr or args.port:
            config = ScanConfig(
                cidr_range=args.cidr or "10.69.10.0/24",
                port=args.port or 80
            )
        else:
            config = ScanConfig()
        
        print(f"使用配置:")
        print(f"  CIDR范围: {config.cidr_range}")
        print(f"  端口: {config.port}")
        print(f"  HTML目录: {config.html_responses_dir}")
        
        # 创建提取器并执行
        extractor = TitleExtractor(config)
        results = extractor.extract_all_titles()
        
        # 显示结果
        extractor.display_results(results, show_raw=args.show_raw)
        
        # 保存到文件(如果指定)
        if args.output:
            save_results_to_file(results, args.output)
            print(f"\n结果已保存到: {args.output}")
            
    except KeyboardInterrupt:
        print("\n\n用户中断操作")
    except Exception as e:
        print(f"执行过程中出现错误: {e}")


def save_results_to_file(results: List[Tuple[str, str, str]], output_file: str):
    """将结果保存到文件"""
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("HTML标题提取结果\n")
        f.write("="*80 + "\n\n")
        
        for i, (ip_info, raw_title, decoded_title) in enumerate(results, 1):
            f.write(f"[{i:3d}] {ip_info}\n")
            f.write(f"      标题: {decoded_title}\n")
            if raw_title != decoded_title and not decoded_title.startswith("["):
                f.write(f"      原始: {raw_title}\n")
            f.write("\n")
        
        valid_titles = [r for r in results if not r[2].startswith("[")]
        f.write("="*80 + "\n")
        f.write(f"统计: 总文件数={len(results)}, 有效标题={len(valid_titles)}, 无标题/错误={len(results)-len(valid_titles)}\n")


if __name__ == "__main__":
    main()