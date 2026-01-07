import os
import sys
import json
import importlib
from datetime import datetime

# 确保工作目录正确
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

# ==================== 基础模块导入 ====================
try:
    from DVWAlogin import DvwaLogin
    from crawler import VulnerabilityCrawler
except Exception as e:
    print(f"基础模块导入失败: {e}")
    sys.exit(1)


# ==================== 扫描器模块管理 ====================
class ScannerManager:
    """统一管理扫描器模块的加载和调用"""

    def __init__(self):
        self.scanners = {}
        self._load_scanners()

    def _load_scanners(self):
        """加载所有扫描器模块"""
        modules = [
            "DvwaSql_scanner",
            "DvwaXSSScanner",
            "DvwaCSRFScanner",
            "DvwaCommandInjectionScanner",
            "DvwaFileUploadScanner",
        ]

        for name in modules:
            try:
                module = importlib.import_module(name)
                self.scanners[name] = module
                print(f"扫描器已加载: {name}")
            except Exception as e:
                print(f"扫描器加载失败 {name}: {e}")

    def get_scanner(self, name):
        return self.scanners.get(name)

    def list_available(self):
        return list(self.scanners.keys())


scanner_manager = ScannerManager()


# ==================== 报告管理 ====================
class ReportManager:
    """统一处理报告保存"""

    @staticmethod
    def save(report, scanner_name, filename):
        try:
            report_dir = os.path.join(BASE_DIR, "scan_result", scanner_name)
            os.makedirs(report_dir, exist_ok=True)
            filepath = os.path.join(report_dir, filename)
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"报告已保存: {filepath}")
        except Exception as e:
            print(f"保存报告失败: {e}")


# ==================== DVWA模式（完全保留原逻辑） ====================
class DVWAModeHandler:
    """处理DVWA靶场扫描"""

    def __init__(self, dvwa_url):
        self.dvwa_url = dvwa_url
        self.login_obj = None
        self.session_info = None

    def login(self):
        """登录DVWA"""
        print(f"\nDVWA登录: {self.dvwa_url}")
        dvwa_login = DvwaLogin()
        if not dvwa_login.login(self.dvwa_url):
            print("DVWA登录失败")
            return False

        self.login_obj = dvwa_login
        self.session_info = dvwa_login.get_session_info()
        if not self.session_info:
            print("无法获取会话信息")
            return False

        print("DVWA登录成功")
        return True

    def run_sql_scan(self):
        module = scanner_manager.get_scanner("DvwaSql_scanner")
        if not module:
            print("SQL扫描器不可用")
            return

        print("\nDVWA SQL注入扫描:")
        print("1. 错误注入")
        print("2. 布尔盲注")
        print("3. 全部执行")
        choice = input("请选择: ").strip()

        if choice == "1":
            scanner = module.IntegratedSQLScanner(timeout=15)
            scanner.setup_session(self.login_obj)
            report = scanner.scan_dvwa()
            if report:
                module.print_report(report, "错误注入")
                ReportManager.save(report, "sql_scanner",
                                   f"dvwa_sql_error_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        elif choice == "2":
            cookies = self.session_info["session"].cookies
            cookie_str = "; ".join([f"{name}={value}" for name, value in cookies.items()]) + "; security=low"
            scanner = module.BlindSQLInjector(
                self.session_info["session"], self.session_info["base_url"], cookie_str, timeout=15
            )
            report = scanner.scan()
            if report:
                module.print_report(report, "布尔盲注")
                ReportManager.save(report, "sql_scanner",
                                   f"dvwa_sql_blind_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

        elif choice == "3":
            print("\n阶段1/2: 错误注入")
            scanner = module.IntegratedSQLScanner(timeout=15)
            scanner.setup_session(self.login_obj)
            report = scanner.scan_dvwa()
            if report:
                module.print_report(report, "错误注入")
                ReportManager.save(report, "sql_scanner",
                                   f"dvwa_sql_error_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

            print("\n阶段2/2: 布尔盲注")
            cookies = self.session_info["session"].cookies
            cookie_str = "; ".join([f"{name}={value}" for name, value in cookies.items()]) + "; security=low"
            scanner = module.BlindSQLInjector(
                self.session_info["session"], self.session_info["base_url"], cookie_str, timeout=15
            )
            report = scanner.scan()
            if report:
                module.print_report(report, "布尔盲注")
                ReportManager.save(report, "sql_scanner",
                                   f"dvwa_sql_blind_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    def run_xss_scan(self):
        module = scanner_manager.get_scanner("DvwaXSSScanner")
        if not module:
            print("XSS扫描器不可用")
            return

        scanner = module.DvwaXSSScanner(timeout=10)
        payload_file = os.path.join(BASE_DIR, "config", "xss_payload.txt")

        if not scanner.load_xss_payloads(payload_file):
            return

        if not scanner.setup_session(self.login_obj):
            return

        report = scanner.scan_dvwa_xss()
        scanner.print_report(report)
        ReportManager.save(report, "DvwaXSSScanner", f"dvwa_xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    def run_csrf_scan(self):
        module = scanner_manager.get_scanner("DvwaCSRFScanner")
        if not module:
            print("CSRF扫描器不可用")
            return

        scanner = module.DvwaCSRFScanner(
            self.session_info["session"], mode="dvwa", base_url=self.session_info["base_url"]
        )
        if not scanner.setup_session(self.login_obj):
            return

        report = scanner.scan_dvwa_csrf()
        scanner.print_report(report)
        ReportManager.save(report, "DvwaCSRFScanner", f"dvwa_csrf_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    def run_command_scan(self):
        module = scanner_manager.get_scanner("DvwaCommandInjectionScanner")
        if not module:
            print("命令注入扫描器不可用")
            return

        scanner = module.DvwaCommandInjectionScanner(
            self.session_info["session"], mode="dvwa", base_url=self.session_info["base_url"], timeout=5
        )
        scanner.detect_dvwa()

    def run_upload_scan(self):
        module = scanner_manager.get_scanner("DvwaFileUploadScanner")
        if not module:
            print("文件上传扫描器不可用")
            return

        scanner = module.DvwaFileUploadScanner(
            self.session_info["session"], self.session_info["base_url"], mode="dvwa"
        )
        scanner.detect()

    def run_all(self):
        print("\n警告：即将执行全模块DVWA扫描")
        print("CSRF模块会修改密码并自动回滚")
        if input("输入 'yes' 确认执行: ").strip().lower() != "yes":
            print("已取消")
            return

        print("\n开始全模块扫描...")
        print("1/5: SQL注入")
        self.run_sql_scan()

        print("\n2/5: XSS")
        self.run_xss_scan()

        print("\n3/5: CSRF")
        self.run_csrf_scan()

        print("\n4/5: 命令注入")
        self.run_command_scan()

        print("\n5/5: 文件上传")
        self.run_upload_scan()

        print("\n全模块扫描完成!")


# ==================== 通用网站模式 ====================
class GenericModeHandler:
    """处理普通网站扫描"""

    def __init__(self):
        self.session = None
        self.crawl_results = None
        self.target_url = None

    def input_target(self):
        """获取目标URL"""
        while True:
            self.target_url = input("请输入目标网站URL: ").strip()
            if self.target_url.startswith(("http://", "https://")):
                break
            print("URL格式错误，必须以http://或https://开头")

        depth_input = input("请输入爬取深度 (默认2): ").strip()
        self.max_depth = int(depth_input) if depth_input.isdigit() else 2

    def crawl(self):
        """爬取目标网站"""
        print(f"\n开始爬取: {self.target_url}")
        print(f"最大深度: {self.max_depth}")

        crawler = VulnerabilityCrawler(self.target_url, max_depth=self.max_depth)
        crawler.crawl(self.target_url)
        self.crawl_results = crawler.get_results()
        self.session = crawler.session  # 获取爬虫的会话

        crawl_file = crawler.save_results()
        if crawl_file:
            print(f"爬取结果已保存: {os.path.basename(crawl_file)}")

        print(f"\n爬取完成！发现注入点:")
        print(f"  URL参数: {len(self.crawl_results.get('url_params', []))} 个")
        print(f"  普通表单: {len(self.crawl_results.get('forms', []))} 个")
        print(f"  上传表单: {len(self.crawl_results.get('upload_forms', []))} 个")

    def run_scanner(self, module_name):
        """运行指定扫描器"""
        module = scanner_manager.get_scanner(module_name)
        if not module:
            print(f"{module_name} 扫描器不可用")
            return

        print(f"\n运行 {module_name} 扫描...")

        try:
            if module_name == "DvwaSql_scanner":
                # SQL扫描器需要特殊处理，因为它有独立的NormalSQLScanner类
                ScannerClass = getattr(module, "NormalSQLScanner", None)
                if ScannerClass:
                    scanner = ScannerClass(timeout=10)
                    # 已爬取过，直接传入结果
                    scanner.session = self.session  # 复用爬虫会话
                    scanner.results = {
                        "target_url": self.target_url,
                        "vulnerabilities": [],
                        "scan_time": None,
                        "parameters_tested": 0,
                        "injection_points_found": 0,
                    }

                    vulnerabilities = []
                    # 测试URL参数
                    for item in self.crawl_results.get("url_params", []):
                        vulns = scanner.test_url_params(item["url"], item["params"])
                        vulnerabilities.extend(vulns)

                    # 测试表单
                    for item in self.crawl_results.get("forms", []):
                        vulns = scanner.test_form(item["url"], item["method"], item["form_data"])
                        vulnerabilities.extend(vulns)

                    scanner.results["vulnerabilities"] = vulnerabilities
                    scanner.results["parameters_tested"] = len(vulnerabilities)
                    scanner.results["injection_points_found"] = len(vulnerabilities)

                    report = scanner.generate_report()
                    if report.get("vulnerabilities"):
                        scanner.print_report(report)
                        ReportManager.save(report, "sql_scanner",
                                           f"generic_sql_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

            elif module_name == "DvwaXSSScanner":
                # **关键修改：避免XSS扫描器重复爬取**
                ScannerClass = getattr(module, "NormalXSSScanner", None)
                if ScannerClass:
                    scanner = ScannerClass(timeout=10)
                    scanner.session = self.session  # 复用爬虫会话

                    # **直接使用爬取结果，不再调用crawl_and_scan**
                    vulnerabilities = []
                    tested_points = 0

                    # 测试URL参数
                    for item in self.crawl_results.get("url_params", []):
                        url = item["url"]
                        method = item["method"]
                        params_template = {k: "test" for k in item["params"]}

                        for param_name in item["params"]:
                            tested_points += 1
                            injection_point = {
                                "name": f"URL参数:{param_name}",
                                "param": param_name,
                                "params": params_template
                            }
                            result = scanner.test_injection_point_with_early_exit(url, method, injection_point)
                            if result:
                                vulnerabilities.append(result)

                    # 测试表单
                    for item in self.crawl_results.get("forms", []):
                        form_url = item["url"]
                        method = item["method"]
                        form_data = item["form_data"]

                        for field_name in form_data.keys():
                            tested_points += 1
                            injection_point = {
                                "name": f"表单字段:{field_name}",
                                "field": field_name,
                                "form_data": form_data
                            }
                            result = scanner.test_injection_point_with_early_exit(form_url, method, injection_point)
                            if result:
                                vulnerabilities.append(result)

                    scanner.results["vulnerabilities"] = vulnerabilities
                    scanner.results["xss_points_found"] = len(vulnerabilities)
                    scanner.results["parameters_tested"] = tested_points

                    report = scanner.generate_report()
                    if report.get("vulnerabilities"):
                        scanner.print_report(report)
                        ReportManager.save(report, "DvwaXSSScanner",
                                           f"generic_xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

            elif module_name == "DvwaCSRFScanner":
                # CSRF扫描器
                ScannerClass = getattr(module, "DvwaCSRFScanner", None)
                if ScannerClass:
                    scanner = ScannerClass(session=self.session, mode="generic", base_url=self.target_url)
                    scanner.detect_generic(self.crawl_results)

            elif module_name == "DvwaFileUploadScanner":
                # 文件上传扫描器
                ScannerClass = getattr(module, "DvwaFileUploadScanner", None)
                if ScannerClass:
                    scanner = ScannerClass(self.session, self.target_url, mode="generic")
                    scanner.detect(self.crawl_results)  # 传入爬取结果

        except Exception as e:
            print(f"{module_name} 扫描出错: {e}")

    def select_and_run(self):
        """显示菜单并执行扫描"""
        while True:
            print("\n选择扫描类型:")
            print("  1. SQL注入")
            print("  2. XSS")
            print("  3. CSRF（需手动验证）")
            print("  4. 文件上传")
            print("  5. 全部扫描")
            print("  0. 返回主菜单")

            choice = input("请选择: ").strip()

            if choice == "0":
                break

            if choice == "5":
                print("\n开始全模块扫描...")
                # **移除命令注入扫描器**
                modules = [
                    "DvwaSql_scanner",
                    "DvwaXSSScanner",
                    "DvwaCSRFScanner",
                    "DvwaFileUploadScanner",
                ]
                for module in modules:
                    self.run_scanner(module)
                print("\n全模块扫描完成!")
                continue

            # **调整模块映射，移除命令注入**
            module_map = {
                "1": "DvwaSql_scanner",
                "2": "DvwaXSSScanner",
                "3": "DvwaCSRFScanner",
                "4": "DvwaFileUploadScanner",
            }

            if choice in module_map:
                self.run_scanner(module_map[choice])
            else:
                print("无效选项")

    def run(self):
        """主流程"""
        print("\n" + "=" * 60)
        print("      普通网站漏洞扫描模式")
        print("=" * 60)

        self.input_target()
        self.crawl()
        self.select_and_run()


# ==================== 主程序入口 ====================
def main():
    """主程序"""
    print("\n" + "=" * 60)
    print("      WEB漏洞扫描器 已启动")
    print("=" * 60)

    while True:
        print("\n选择模式:")
        print("  1. 扫描DVWA靶场")
        print("  2. 扫描普通网站")
        print("  0. 退出")

        mode = input("请选择: ").strip()

        if mode == "0":
            print("\n程序退出")
            break

        if mode == "1":
            dvwa_url = input("请输入DVWA URL: ").strip()
            handler = DVWAModeHandler(dvwa_url)
            if not handler.login():
                continue

            while True:
                print("\nDVWA扫描菜单:")
                print("  1. SQL注入")
                print("  2. XSS")
                print("  3. CSRF（修改密码）")
                print("  4. 命令注入")
                print("  5. 文件上传")
                print("  6. 全部扫描")
                print("  0. 返回主菜单")

                choice = input("请选择: ").strip()
                if choice == "0":
                    break

                if choice == "1":
                    handler.run_sql_scan()
                elif choice == "2":
                    handler.run_xss_scan()
                elif choice == "3":
                    handler.run_csrf_scan()
                elif choice == "4":
                    handler.run_command_scan()
                elif choice == "5":
                    handler.run_upload_scan()
                elif choice == "6":
                    handler.run_all()
                else:
                    print("无效选项")

        elif mode == "2":
            handler = GenericModeHandler()
            handler.run()

        else:
            print("无效选项")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n检测到Ctrl+C，程序退出")
        sys.exit(0)
    except Exception as e:
        print(f"\n程序异常: {e}")
        sys.exit(1)