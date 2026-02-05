#!/usr/bin/env python3
"""
从logs文件夹的日志文件重建scan_progress.csv进度缓存文件
"""

import csv
import re
import os
from pathlib import Path
import ipaddress
import random

TARGET_CIDR = "10.0.0.0/8"
TARGET_PORT = 80
output_dir = f"./{TARGET_CIDR.replace('/', '_')}_{TARGET_PORT}"


def parse_ip_from_url(url):
    """从URL中提取IP地址和端口"""
    match = re.search(r"http://(\d+\.\d+\.\d+\.\d+):(\d+)", url)
    if match:
        return match.group(1), match.group(2)
    return None, None


def parse_html_responses_dir(html_dir):
    """解析html_responses目录，返回成功访问的记录"""
    records = {}

    if not os.path.exists(html_dir):
        print(f"警告: {html_dir} 不存在")
        return records

    html_files = list(Path(html_dir).glob("http_*_response.html"))
    print(f"  找到 {len(html_files)} 个HTML响应文件")

    for html_file in html_files:
        # 格式: http_192.168.111.106_80_response.html
        filename = html_file.name
        match = re.search(
            r"http_(\d+)_(\d+)_(\d+)_(\d+)_(\d+)_response\.html", filename
        )
        if match:
            ip = f"{match.group(1)}.{match.group(2)}.{match.group(3)}.{match.group(4)}"
            port = match.group(5)

            records[f"{ip}:{port}"] = {
                "ip": ip,
                "port": port,
                "status": "200",  # HTML响应文件通常是200状态
                "title": "",
                "ssl_cert": "",
                "fingerprint": "",
            }

    return records


def parse_success_log(log_file):
    """解析success.log文件，返回成功访问的记录"""
    records = {}

    if not os.path.exists(log_file):
        print(f"警告: {log_file} 不存在")
        return records

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            # 格式: 2026-02-02 10:37:56,542 - http://192.168.17.162:80 - Status 200 - HTML saved to ...
            match = re.search(r"(http://[\d.:]+) - Status (\d+)", line)
            if match:
                url = match.group(1)
                status = match.group(2)
                ip, port = parse_ip_from_url(url)

                if ip and port:
                    records[f"{ip}:{port}"] = {
                        "ip": ip,
                        "port": port,
                        "status": status,
                        "title": "",
                        "ssl_cert": "",
                        "fingerprint": "",
                    }

    return records


def parse_raw_responses_dir(raw_dir):
    """解析raw_responses目录，返回非200状态的记录"""
    records = {}

    if not os.path.exists(raw_dir):
        print(f"警告: {raw_dir} 不存在")
        return records

    raw_files = list(Path(raw_dir).glob("http_*_status_*.txt"))
    print(f"  找到 {len(raw_files)} 个原始响应文件")

    for raw_file in raw_files:
        # 格式: http_192.168.10.112_80_status_403.txt
        filename = raw_file.name
        match = re.search(
            r"http_(\d+)_(\d+)_(\d+)_(\d+)_(\d+)_status_(\d+)\.txt", filename
        )
        if match:
            ip = f"{match.group(1)}.{match.group(2)}.{match.group(3)}.{match.group(4)}"
            port = match.group(5)
            status = match.group(6)

            records[f"{ip}:{port}"] = {
                "ip": ip,
                "port": port,
                "status": status,
                "title": "",
                "ssl_cert": "",
                "fingerprint": "",
            }

    return records


def parse_failure_log(log_file):
    """解析failure.log文件，返回超时或失败的记录"""
    records = {}

    if not os.path.exists(log_file):
        print(f"警告: {log_file} 不存在")
        return records

    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            # 格式: 2026-02-02 09:44:50,749 - http://192.168.183.30:80 - Timeout: ...
            match = re.search(r"(http://[\d.:]+) - (Timeout|Error)", line)
            if match:
                url = match.group(1)
                error_type = match.group(2).lower()
                ip, port = parse_ip_from_url(url)

                if ip and port:
                    records[f"{ip}:{port}"] = {
                        "ip": ip,
                        "port": port,
                        "status": "timeout" if error_type == "timeout" else "error",
                        "title": "",
                        "ssl_cert": "",
                        "fingerprint": "",
                    }

    return records


def generate_all_ips(TARGET_CIDR: str, prefix=16, port=80):
    """生成所有IP地址（192.168.0.0/16，端口80）"""
    all_records = {}

    # 生成192.168.0.0/16的所有IP (192.168.0.0 到 192.168.255.255)
    network = ipaddress.ip_network(TARGET_CIDR, strict=False)
    ip_list = [str(ip) for ip in network.hosts()]
    # random.shuffle(ip_list)
    for ip in ip_list:
        key = f"{ip}:{port}"
        all_records[key] = {
            "ip": ip,
            "port": str(port),
            "status": "",
            "title": "",
            "ssl_cert": "",
            "fingerprint": "",
        }

    return all_records


def rebuild_progress_csv(output_dir, output_file):
    """重建progress.csv文件"""
    output_path = Path(output_dir)

    # 定义各个子目录
    html_dir = output_path / "html_responses"
    raw_dir = output_path / "raw_responses"
    logs_dir = output_path / "logs"
    success_log = logs_dir / "success.log"
    failure_log = logs_dir / "failure.log"

    print("正在生成所有IP地址...")
    all_records = generate_all_ips(TARGET_CIDR)
    print(f"生成了 {len(all_records)} 个IP地址记录")

    # 从html_responses目录解析成功记录
    print("\n正在解析html_responses目录...")
    html_records = parse_html_responses_dir(html_dir)
    print(f"  找到 {len(html_records)} 条成功记录")

    # 从raw_responses目录解析非200状态记录
    print("\n正在解析raw_responses目录...")
    raw_records = parse_raw_responses_dir(raw_dir)
    print(f"  找到 {len(raw_records)} 条非200状态记录")

    # 从logs解析（如果存在）
    print("\n正在解析logs目录...")
    success_records = parse_success_log(success_log)
    print(f"  从success.log找到 {len(success_records)} 条记录")

    failure_records = parse_failure_log(failure_log)
    print(f"  从failure.log找到 {len(failure_records)} 条记录")

    # 更新记录：优先级从低到高
    # 1. 失败记录（timeout/error）
    # 2. 非200状态记录（来自raw_responses）
    # 3. 成功记录（来自html_responses和success.log）
    print("\n正在合并记录...")
    all_records.update(failure_records)
    all_records.update(raw_records)
    all_records.update(html_records)
    all_records.update(success_records)

    # 写入CSV文件
    print(f"\n正在写入 {output_file}...")
    with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["IP", "Port", "Status", "Title", "SSL Cert", "Fingerprint"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        # 按IP地址排序
        sorted_keys = sorted(
            all_records.keys(),
            key=lambda x: tuple(map(int, x.split(":")[0].split("."))),
        )

        for key in sorted_keys:
            record = all_records[key]
            writer.writerow(
                {
                    "IP": record["ip"],
                    "Port": record["port"],
                    "Status": record["status"],
                    "Title": record["title"],
                    "SSL Cert": record["ssl_cert"],
                    "Fingerprint": record["fingerprint"],
                }
            )

    # 统计各种状态
    scanned_count = sum(1 for r in all_records.values() if r["status"])
    success_count = sum(
        1
        for r in all_records.values()
        if r["status"] and r["status"].isdigit() and 200 <= int(r["status"]) < 300
    )

    print(f"\n✓ 成功重建 {output_file}")
    print(f"  总记录数: {len(all_records)}")
    print(f"  已扫描: {scanned_count}")
    print(f"  成功(2xx): {success_count}")
    print(f"  未扫描: {len(all_records) - scanned_count}")


if __name__ == "__main__":
    # 获取脚本所在目录
    script_dir = Path(__file__).parent
    output_dir_path = script_dir / output_dir
    output_file = output_dir_path / "scan_progress.csv"

    print("=" * 60)
    print("重建scan_progress.csv进度缓存文件")
    print(f"目标目录: {output_dir}")
    print("=" * 60)

    rebuild_progress_csv(output_dir_path, output_file)

    print("\n" + "=" * 60)
    print("完成！")
    print("=" * 60)
