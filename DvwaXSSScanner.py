import sys
import os
import requests
import urllib.parse
import time
import json
import urllib3
import re
import html
from typing import Dict, List, Tuple, Any,Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from datetime import datetime

# ========== 配置区域 (相对路径版) ==========
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_FILE = os.path.join(BASE_DIR, 'config', 'xss_payload.txt')
REPORT_DIR = os.path.join(BASE_DIR, 'scan_result', 'DvwaXSSScanner')
MAX_WORKERS = 10  # 并发线程数
# ==============================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

try:
    from DVWAlogin import DvwaLogin
except ImportError as e:
    print(f"{Fore.RED}[ERROR] DVWA登录模块导入失败: {e}")
    sys.exit(1)

# 导入爬虫模块
try:
    from crawler import VulnerabilityCrawler
except ImportError:
    print(f"{Fore.RED}[ERROR] 无法导入爬虫模块 crawler.py")
    sys.exit(1)


# ========================================
# 新增：XSS上下文检测函数（供NormalXSSScanner使用）
# 不修改任何DVWA类代码，抽取为独立函数
# ========================================
def detect_xss_context(response_text: str, payload: str) -> Dict[str, Any]:
    """
    智能上下文检测 - 看payload在哪，不是只看在不在
    返回值: vulnerable, context, confidence
    """
    # 先找payload位置
    pos = response_text.find(payload)
    if pos == -1:
        # 尝试解码后匹配
        decoded = urllib.parse.unquote(payload)
        pos = response_text.find(decoded)
        if pos == -1:
            return {'vulnerable': False}

    # 提取payload周围50字符看上下文
    context_start = max(0, pos - 50)
    context_end = min(len(response_text), pos + len(payload) + 50)
    context = response_text[context_start:context_end]

    # 1. 在HTML标签外（最危险）
    if re.search(rf'>[^<]*{re.escape(payload)}[^>]*<', context):
        return {'vulnerable': True, 'context': 'html_context', 'confidence': 'critical'}

    # 2. 在script标签内
    if re.search(rf'<script[^>]*>[^<]*{re.escape(payload)}', context, re.IGNORECASE):
        return {'vulnerable': True, 'context': 'javascript', 'confidence': 'critical'}

    # 3. 在HTML属性内（可闭合）
    if re.search(rf'=["\'][^"\']*{re.escape(payload)}[^"\']*["\']', context):
        if '"' in payload or "'" in payload or '>' in payload:
            return {'vulnerable': True, 'context': 'attribute', 'confidence': 'high'}

    # 4. 在注释里（没用）
    if f'<!--{payload}-->' in context:
        return {'vulnerable': False, 'reason': 'in_html_comment'}

    # 5. 被编码了（安全）
    if html.escape(payload) in context:
        return {'vulnerable': False, 'reason': 'html_encoded_safe'}

    return {'vulnerable': False}


# ========================================
# DVWA XSS扫描器 - 完全不动
# ========================================
class DvwaXSSScanner:
    """XSS漏洞扫描器 - DVWA专用，完全不变"""
    # ... [此处所有DVWA类代码保持不变，省略以节省篇幅] ...
    # 请保留您原有的DvwaXSSScanner类完整代码


# ========================================
# 普通网站XSS扫描器 - 仅修改此类
# ========================================
class NormalXSSScanner:
    """普通网站XSS扫描器（集成自动爬取）- 已修复核心问题"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "XSSScanner/1.0"})

        # 新增：注入点去重集合，存储 (url, 注入点名称)
        self.tested_injection_points = set()

        self.results = {
            'target_url': '普通网站多页面',
            'vulnerabilities': [],
            'scan_time': None,
            'parameters_tested': 0,
            'xss_points_found': 0,
            'payloads_loaded': 0
        }

        # 加载基础payload（硬编码）
        self.payloads = []
        self.load_payloads()

        print(f"{Fore.GREEN}[✓] 加载 {self.results['payloads_loaded']} 个payload")

    def load_payloads(self):
        """加载payload - 简化版"""
        # 基础反射型XSS payload
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "'\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "\"><svg/onload=alert(1)>"
        ]
        self.results['payloads_loaded'] = len(self.payloads)

    def send_request(self, url: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Tuple[
        bool, requests.Response]:
        """发送请求"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, verify=False)
            return True, response
        except requests.exceptions.RequestException as e:
            # 修复：捕获具体异常而非所有异常
            print(f"{Fore.RED}[-] 请求失败: {e}")
            return False, None

    # ========================================
    # 新增：测试单个注入点，首次命中即停止
    # ========================================
    def test_injection_point_with_early_exit(self, url: str, method: str, injection_point: Dict) -> Optional[Dict]:
        """测试单个注入点，一旦找到漏洞立即停止，不再测试后续payload"""
        # 确定参数名
        param_name = injection_point.get('param') or injection_point.get('field')
        if not param_name:
            return None

        # 去重检查：跳过已测试的注入点
        point_key = (url, f"{injection_point['name']}:{param_name}")
        if point_key in self.tested_injection_points:
            print(f"{Fore.LIGHTBLACK_EX}[-] 跳过已测试注入点: {injection_point['name']}")
            return None
        self.tested_injection_points.add(point_key)

        print(f"{Fore.CYAN}[TEST] 测试注入点: {injection_point['name']} -> {param_name}")

        # 遍历payload，首次成功即返回
        for payload in self.payloads:
            # 构建测试数据
            if 'params' in injection_point:  # URL参数
                test_params = injection_point['params'].copy()
                test_params[param_name] = payload
                success, response = self.send_request(url, method, params=test_params)
            else:  # 表单
                test_data = injection_point['form_data'].copy()
                test_data[param_name] = payload
                success, response = self.send_request(url, method, data=test_data)

            if not success or not response:
                continue

            # 使用智能上下文检测（复用独立函数）
            context_result = detect_xss_context(response.text, payload)
            if context_result['vulnerable']:
                return {
                    'url': url,
                    'method': method,
                    'injection_point': injection_point['name'],
                    'payload': payload,
                    'type': 'reflected',
                    'context': context_result['context'],
                    'confidence': context_result['confidence']
                }

        # 所有payload都未触发漏洞
        print(f"{Fore.LIGHTBLACK_EX}[-] 安全: {param_name}")
        return None

    def crawl_and_scan(self, base_url: str, max_depth: int = 2) -> Dict[str, Any]:
        """自动爬取并扫描 - 修复版"""
        print(f"{Fore.YELLOW}[INFO] 开始自动爬取并扫描...")
        print(f"{Fore.CYAN}目标: {base_url}  |  深度: {max_depth}")
        print("-" * 50)

        # 1. 执行爬取
        crawler = VulnerabilityCrawler(base_url, max_depth=max_depth)
        crawler.crawl(base_url)
        results = crawler.get_results()

        # 保存爬取结果
        crawl_file = crawler.save_results()
        print(f"\n{Fore.GREEN}[✓] 爬取完成，结果已保存: {os.path.basename(crawl_file)}")

        # 2. 统计总注入点数量（用于进度显示）
        total_points = sum(len(item['params']) for item in results.get('url_params', [])) + \
                       sum(len(form['form_data']) for form in results.get('forms', []))
        print(f"{Fore.GREEN}[✓] 发现 {total_points} 个待测注入点")

        # 3. 开始扫描
        print(f"\n{Fore.YELLOW}[INFO] 开始XSS注入测试...")
        print("-" * 50)

        vulnerabilities = []
        completed = 0

        # 测试URL参数
        for item in results.get('url_params', []):
            url = item['url']
            method = item['method']
            params_template = {k: "test" for k in item['params']}

            for param_name in item['params']:
                completed += 1
                if completed % 5 == 0:  # 每5个显示一次进度
                    print(f"{Fore.YELLOW}[进度] {completed}/{total_points}")

                injection_point = {
                    'name': f"URL参数:{param_name}",
                    'param': param_name,
                    'params': params_template
                }

                result = self.test_injection_point_with_early_exit(url, method, injection_point)
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.GREEN}[✓] 漏洞: {param_name} -> {result['payload'][:50]}")

        # 测试表单
        for item in results.get('forms', []):
            form_url = item['url']
            method = item['method']
            form_data = item['form_data']

            for field_name in form_data.keys():
                completed += 1
                if completed % 5 == 0:
                    print(f"{Fore.YELLOW}[进度] {completed}/{total_points}")

                injection_point = {
                    'name': f"表单字段:{field_name}",
                    'field': field_name,
                    'form_data': form_data
                }

                result = self.test_injection_point_with_early_exit(form_url, method, injection_point)
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.GREEN}[✓] 漏洞: {field_name} -> {result['payload'][:50]}")

        # 4. 生成报告
        self.results['vulnerabilities'] = vulnerabilities
        self.results['xss_points_found'] = len(vulnerabilities)
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """生成报告"""
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        return {
            'scan_summary': {
                'target_url': self.results['target_url'],
                'scan_time': self.results['scan_time'],
                'parameters_tested': len(self.tested_injection_points),
                'xss_points_found': self.results['xss_points_found'],
                'payloads_loaded': self.results['payloads_loaded'],
                'total_vulnerabilities': len(self.results['vulnerabilities'])
            },
            'vulnerabilities': self.results['vulnerabilities'],
            'recommendations': [
                "实施Context-aware输出编码",
                "部署CSP内容安全策略",
                "使用HttpOnly + Secure Cookie标志",
                "定期扫描+手动验证",
                "开发安全编码规范"
            ]
        }

    def print_report(self, report: Dict[str, Any]):
        """打印报告"""
        summary = report['scan_summary']
        vulns = report['vulnerabilities']

        print(f"\n{Fore.YELLOW}{'=' * 70}")
        print(f"  {Fore.CYAN}普通网站XSS扫描报告 ")
        print(f"{Fore.YELLOW}{'=' * 70}")
        print(f"{Fore.GREEN}目标: {summary['target_url']}")
        print(f"{Fore.GREEN}时间: {summary['scan_time']}")
        print(f"{Fore.GREEN}测试注入点: {summary['parameters_tested']}个")
        print(f"{Fore.GREEN}发现漏洞: {summary['total_vulnerabilities']}个")
        print(f"{Fore.YELLOW}{'=' * 70}")

        if not vulns:
            print(f"{Fore.GREEN}\n[✓] 未发现XSS漏洞")
            return

        print(f"{Fore.RED}\n[!] 发现漏洞详情:")
        for i, vuln in enumerate(vulns, 1):
            print(f"\n{Fore.YELLOW}[#{i}] {vuln['injection_point']}")
            print(f"{Fore.CYAN}Payload: {vuln['payload'][:60]}...")
            print(f"{Fore.BLUE}URL: {vuln['url']}")
            if vuln.get('context'):
                print(f"{Fore.MAGENTA}Context: {vuln['context']}")

        print(f"\n{Fore.CYAN}修复建议:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")


# ========================================
# main函数 - 完全不动，包括其中的DVWA流程
# ========================================
def main():
    """主函数 - DVWA流程完全不变，新增普通网站自动爬取"""
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f" XSS漏洞扫描器 ")
    print(f"{Fore.CYAN}{'=' * 70}")

    # 选择扫描模式
    print("\n请选择扫描模式:")
    print("1. 扫描DVWA靶场 (完整功能)")
    print("2. 扫描普通网站 (自动爬取+简化测试)")
    choice = input("请输入选项 (1 或 2): ").strip()

    if choice == '1':
        # ==================== DVWA流程 - 完全不变 ====================
        # ... [此处保留您原有的DVWA流程完整代码] ...
        # 请粘贴回您原有的DVWA处理逻辑
        pass  # 占位符，实际应替换为您的DVWA代码

    elif choice == '2':
        # ==================== 普通网站流程 - 已修复 ====================
        print("\n--- 普通网站XSS扫描模式 ---")
        base_url = input("请输入目标网站首页URL: ").strip()
        if not base_url:
            print(f"{Fore.RED}[✗] URL不能为空")
            return

        depth_input = input("请输入爬取深度 (默认2): ").strip()
        max_depth = int(depth_input) if depth_input.isdigit() else 2

        # 开始自动爬取并扫描
        print(f"\n{Fore.CYAN}[1/2] 初始化扫描器...")
        scanner = NormalXSSScanner(timeout=10)

        print(f"{Fore.CYAN}[2/2] 自动爬取并扫描...")
        print("=" * 50)
        report = scanner.crawl_and_scan(base_url, max_depth)

        # 报告
        if report:
            scanner.print_report(report)

            # 保存报告
            report_dir = os.path.join(BASE_DIR, 'scan_result', 'NormalXSSScanner')
            os.makedirs(report_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"normal_xss_report_{timestamp}.json"
            filepath = os.path.join(report_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"\n{Fore.GREEN}[✓] 报告已保存: {filepath}")
        else:
            print(f"{Fore.RED}[✗] 扫描失败")

    else:
        print(f"{Fore.RED}[✗] 无效选项")
        return


if __name__ == "__main__":
    main()