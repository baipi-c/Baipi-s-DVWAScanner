import os
import sys
import json
import time
from time import sleep
from typing import Optional, Dict, Any
from colorama import Fore, init
import contextlib
from datetime import datetime

# 初始化 colorama
init(autoreset=True)

# 确保当前工作目录为脚本所在目录
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

# 导入 DVWAlogin
try:
    from DVWAlogin import DvwaLogin
except Exception as e:
    print(f"{Fore.RED}[ERROR] 无法导入DVWA登录模块: {e}")
    sys.exit(1)

# 将当前目录加入 sys.path
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# 导入扫描器模块
_AVAILABLE = {}


def try_import(name):
    """导入模块并抑制其内部打印"""
    try:
        with contextlib.redirect_stdout(None), contextlib.redirect_stderr(None):
            module = __import__(name)
        _AVAILABLE[name] = module
        print(f"{Fore.GREEN}[INFO] 已载入模块: {name}")
        return module
    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] 无法载入模块 {name}: {e}")
        return None


sql_mod = try_import("DvwaSql_scanner")
xss_mod = try_import("DvwaXSSScanner")
csrf_mod = try_import("DvwaCSRFScanner")
cmdi_mod = try_import("DvwaCommandInjectionScanner")
upload_mod = try_import("DvwaFileUploadScanner")

print(f"{Fore.CYAN}[INFO] 所有模块加载完成，共 {len(_AVAILABLE)} 个扫描器可用")

# 配置文件
CONFIG_DIR = os.path.join(BASE_DIR, "config")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")


def load_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            print(f"{Fore.CYAN}[INFO] 已加载配置: {CONFIG_FILE}")
        except Exception as e:
            print(f"{Fore.YELLOW}[WARN] 读取配置失败: {e}")
    return cfg


config = load_config()


def ask_dvwa_url() -> str:
    if config.get("dvwa_url"):
        print(f"{Fore.CYAN}[INFO] 使用 config 中的 dvwa_url: {config['dvwa_url']}")
        return config['dvwa_url'].rstrip('/')
    url = input(f"{Fore.YELLOW}请输入 DVWA 的 URL (例如: http://127.0.0.1:8080/dvwa): ").strip()
    return url.rstrip('/')


def login_once(dvwa_url: str, username: Optional[str] = None, password: Optional[str] = None) -> Optional[dict]:
    dvwa_login = DvwaLogin()
    if username is None:
        username = config.get("username")
    if password is None:
        password = config.get("password")

    print(f"{Fore.CYAN}[STEP] 连接并登录 DVWA: {dvwa_url}")
    ok = dvwa_login.login(dvwa_url) if (username is None and password is None) else dvwa_login.login(dvwa_url,
                                                                                                     username=username,
                                                                                                     password=password)
    if not ok:
        print(f"{Fore.RED}[ERROR] 登录失败")
        return None

    try:
        dvwa_login.test_connection()
    except Exception:
        pass

    session_info = dvwa_login.get_session_info()
    if not session_info:
        print(f"{Fore.RED}[ERROR] 无法获取会话信息")
        return None

    return {"login_obj": dvwa_login, "session_info": session_info}


def _save_report(report: Dict[str, Any], scan_dir: str, filename: str):
    """保存报告到文件的辅助函数"""
    try:
        report_dir = os.path.join(BASE_DIR, "scan_result", scan_dir)
        os.makedirs(report_dir, exist_ok=True)
        filepath = os.path.join(report_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"{Fore.GREEN}[✓] 报告已保存到: {filepath}")
    except Exception as e:
        print(f"{Fore.YELLOW}[WARN] 无法保存报告: {e}")


def run_sql(scanner_module, session_info, dvwa_login, scan_mode='menu'):
    """运行SQL注入扫描，支持模式选择

    scan_mode: 'menu' - 显示子菜单让用户选择
               'error' - 仅错误注入
               'blind' - 仅盲注
               'both' - 执行两种注入
    """
    try:
        # 获取两个扫描器类
        ErrorScannerClass = getattr(scanner_module, "IntegratedSQLScanner", None)
        BlindScannerClass = getattr(scanner_module, "BlindSQLInjector", None)

        if ErrorScannerClass is None and BlindScannerClass is None:
            print(f"{Fore.RED}[ERROR] SQL扫描模块中未找到任何扫描器类")
            return

        # 根据模式决定执行哪些扫描
        scan_tasks = []

        if scan_mode == 'menu':
            # 显示子菜单
            print(f"\n{Fore.CYAN}{'=' * 40}")
            print(f"{Fore.CYAN}SQL注入扫描类型选择")
            print(f"{Fore.CYAN}{'=' * 40}")
            print("1. 错误注入 (Error-based)--快速发现漏洞")
            print("2. 布尔盲注 (Boolean Blind)--深度数据提取")
            print("3. 全部执行")
            sub_choice = input(f"{Fore.YELLOW}请选择 (1-3): ").strip()

            if sub_choice == '1':
                scan_tasks = [('error', ErrorScannerClass)]
            elif sub_choice == '2':
                scan_tasks = [('blind', BlindScannerClass)]
            elif sub_choice == '3':
                scan_tasks = [('error', ErrorScannerClass), ('blind', BlindScannerClass)]
            else:
                print(f"{Fore.YELLOW}无效选择")
                return

        elif scan_mode == 'error':
            scan_tasks = [('error', ErrorScannerClass)]
        elif scan_mode == 'blind':
            scan_tasks = [('blind', BlindScannerClass)]
        elif scan_mode == 'both':
            scan_tasks = [('error', ErrorScannerClass), ('blind', BlindScannerClass)]
        else:
            print(f"{Fore.RED}[ERROR] 未知的scan_mode: {scan_mode}")
            return

        # 执行扫描任务
        for scan_type, ScannerClass in scan_tasks:
            if ScannerClass is None:
                print(f"{Fore.YELLOW}[WARN] {scan_type}扫描器类不可用")
                continue

            print(f"\n{Fore.CYAN}{'=' * 50}")
            print(f"{Fore.CYAN}开始{scan_type}扫描...")
            print(f"{Fore.CYAN}{'=' * 50}")

            if scan_type == 'error':
                scanner = ScannerClass(timeout=15)
                if not scanner.setup_session(dvwa_login):
                    print(f"{Fore.RED}[ERROR] 错误注入扫描器初始化失败")
                    continue
                report = scanner.scan_dvwa()
                if report:
                    scanner.print_report(report)
                    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    _save_report(report, 'sql_scanner', f"dvwa_error_scan_report_{timestamp}.json")

            elif scan_type == 'blind':
                # 构建cookie字符串
                session_cookies = session_info['session'].cookies
                cookie_parts = [f"{name}={value}" for name, value in session_cookies.items()]

                # 从dvwa_login获取security cookie
                security_cookie = getattr(dvwa_login, 'security_cookie', 'security=low')
                if 'security=' not in security_cookie:
                    security_cookie = 'security=low'

                full_cookie = f"{'; '.join(cookie_parts)}; {security_cookie}"

                injector = ScannerClass(
                    session=session_info['session'],
                    base_url=session_info['base_url'],
                    cookie=full_cookie,
                    timeout=15
                )
                report = injector.scan()
                if report:
                    # 使用SQL模块的报告打印函数
                    print_report_func = getattr(scanner_module, "print_report", None)
                    if print_report_func:
                        print_report_func(report, "布尔盲注")
                    else:
                        print(f"{Fore.YELLOW}[WARN] 未找到报告打印函数")

                    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                    _save_report(report, 'sql_scanner', f"dvwa_blind_scan_report_{timestamp}.json")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] 运行SQL扫描时出错: {e}")


def run_xss(scanner_module, session_info, dvwa_login):
    try:
        ScannerClass = getattr(scanner_module, "DvwaXSSScanner", None)
        if ScannerClass is None:
            print(f"{Fore.RED}[ERROR] XSS 扫描模块中未找到 DvwaXSSScanner")
            return
        scanner = ScannerClass(timeout=10)
        payload_file = os.path.join(BASE_DIR, "config", "xss_payload.txt")
        if not os.path.exists(payload_file):
            print(f"{Fore.YELLOW}[WARN] XSS payload 文件不存在: {payload_file}")
            return
        loaded = scanner.load_xss_payloads(payload_file)
        if not loaded:
            print(f"{Fore.RED}[ERROR] XSS payload 加载失败")
            return
        if not scanner.setup_session(dvwa_login):
            print(f"{Fore.RED}[ERROR] XSS 扫描器 setup_session 失败")
            return
        report = scanner.scan_dvwa_xss()
        scanner.print_report(report)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        _save_report(report, 'DvwaXSSScanner', f"dvwa_xss_report_{timestamp}.json")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] 运行 XSS 扫描时出错: {e}")


def run_csrf(scanner_module, session_info, dvwa_login, force_rollback=False):
    try:
        ScannerClass = getattr(scanner_module, "DvwaCSRFScanner", None)
        if ScannerClass is None:
            print(f"{Fore.RED}[ERROR] CSRF 模块中未找到 DvwaCSRFScanner")
            return
        scanner = ScannerClass(timeout=15, force_rollback=force_rollback)
        if not scanner.setup_session(dvwa_login):
            print(f"{Fore.RED}[ERROR] CSRF setup_session 失败")
            return
        report = scanner.scan_dvwa_csrf()
        scanner.print_report(report)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        _save_report(report, 'DvwaCSRFScanner', f"dvwa_csrf_report_{timestamp}.json")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] 运行 CSRF 扫描时出错: {e}")


def run_cmdi(scanner_module, session_info, dvwa_login):
    try:
        ScannerClass = getattr(scanner_module, "DvwaCommandInjectionScanner", None)
        if ScannerClass is None:
            print(f"{Fore.RED}[ERROR] 命令注入模块中未找到 DvwaCommandInjectionScanner")
            return
        args_conf = config.get("command_injection", {}) or {}
        scanner = ScannerClass(
            timeout=args_conf.get("timeout", 10),
            delay_between_requests=args_conf.get("delay_between_requests", 10.0),
            time_threshold=args_conf.get("time_threshold", 3.0),
            max_payloads=args_conf.get("max_payloads", None),
            auto_detect_fields=args_conf.get("auto_detect_fields", False),
            skip_dangerous=args_conf.get("skip_dangerous", True)
        )
        if not scanner.setup_session(dvwa_login):
            print(f"{Fore.RED}[ERROR] 命令注入 setup_session 失败")
            return
        report = scanner.scan_command_injection()
        if report:
            scanner.print_report(report)
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            _save_report(report, 'DvwaCommandInjectionScanner', f"command_injection_report_{timestamp}.json")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] 运行命令注入扫描时出错: {e}")


def run_upload(scanner_module, session_info, dvwa_login):
    try:
        ScannerClass = getattr(scanner_module, "DvwaFileUploadScanner", None)
        if ScannerClass is None:
            print(f"{Fore.RED}[ERROR] 文件上传模块中未找到 DvwaFileUploadScanner")
            return
        sess = session_info.get("session")
        base_url = session_info.get("base_url")
        shell_path = os.path.join(BASE_DIR, "config", "backdoor.php")
        if not os.path.exists(shell_path):
            print(f"{Fore.YELLOW}[WARN] 上传测试文件缺失: {shell_path}")
            return
        scanner = ScannerClass(sess, base_url)
        scanner.detect()
    except Exception as e:
        print(f"{Fore.RED}[ERROR] 运行文件上传扫描时出错: {e}")


def run_all(session_info, dvwa_login):
    """按顺序运行全部扫描"""
    print(f"{Fore.CYAN}\n[ALL] 从 1 到 5 顺序执行全部模块，开始时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Fore.YELLOW}[!] 注意：CSRF 模块会修改密码，将强制自动回滚密码")

    # SQL - 执行两种注入
    if sql_mod:
        run_sql(sql_mod, session_info, dvwa_login, scan_mode='both')
    else:
        print(f"{Fore.YELLOW}[SKIP] SQL 模块不可用，跳过")

    # XSS
    if xss_mod:
        run_xss(xss_mod, session_info, dvwa_login)
    else:
        print(f"{Fore.YELLOW}[SKIP] XSS 模块不可用，跳过")

    # CSRF
    if csrf_mod:
        run_csrf(csrf_mod, session_info, dvwa_login, force_rollback=True)
    else:
        print(f"{Fore.YELLOW}[SKIP] CSRF 模块不可用，跳过")

    # Command Injection
    if cmdi_mod:
        run_cmdi(cmdi_mod, session_info, dvwa_login)
    else:
        print(f"{Fore.YELLOW}[SKIP] 命令注入模块不可用，跳过")

    # Upload
    if upload_mod:
        run_upload(upload_mod, session_info, dvwa_login)
    else:
        print(f"{Fore.YELLOW}[SKIP] 文件上传模块不可用，跳过")

    print(f"{Fore.CYAN}[ALL] 全部扫描结束，结束时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")


def menu():
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"{Fore.CYAN}      web漏洞扫描器 主程序")
    print(f"{Fore.CYAN}{'=' * 60}")
    print("  1. SQL 注入扫描")
    print("  2. XSS 反射型扫描")
    print("  3. CSRF 扫描（会尝试修改密码并可回滚）")
    print("  4. 命令注入扫描")
    print("  5. 文件上传扫描")
    print("  6. 全部扫描（按顺序执行）")
    print("  0. 退出")
    print(f"{Fore.CYAN}{'=' * 60}")


def main():
    cfg = config
    dvwa_url = cfg.get("dvwa_url") or ask_dvwa_url()
    if not dvwa_url:
        print(f"{Fore.RED}未提供 DVWA URL，退出")
        return

    auth = login_once(dvwa_url)
    if not auth:
        return

    dvwa_login = auth["login_obj"]
    session_info = auth["session_info"]

    # 主循环
    while True:
        menu()
        choice = input(f"{Fore.YELLOW}请选择扫描项目 (0-6): ").strip()
        if not choice:
            continue

        if choice == "0":
            print(f"{Fore.CYAN}退出，加纳 ")
            break

        elif choice == "1":
            if sql_mod:
                run_sql(sql_mod, session_info, dvwa_login, scan_mode='menu')
            else:
                print(f"{Fore.RED}SQL 模块不可用")

        elif choice == "2":
            if xss_mod:
                run_xss(xss_mod, session_info, dvwa_login)
            else:
                print(f"{Fore.RED}XSS 模块不可用")

        elif choice == "3":
            if csrf_mod:
                run_csrf(csrf_mod, session_info, dvwa_login)
            else:
                print(f"{Fore.RED}CSRF 模块不可用")

        elif choice == "4":
            if cmdi_mod:
                run_cmdi(cmdi_mod, session_info, dvwa_login)
            else:
                print(f"{Fore.RED}命令注入模块不可用")

        elif choice == "5":
            if upload_mod:
                run_upload(upload_mod, session_info, dvwa_login)
            else:
                print(f"{Fore.RED}文件上传模块不可用")

        elif choice == "6":
            print(f"\n{Fore.RED}{'=' * 60}")
            print(f"{Fore.RED} 重要警告：即将执行全模块扫描")
            print(f"{Fore.RED}{'=' * 60}")
            print(f"{Fore.YELLOW}CSRF 模块会临时修改 DVWA 登录密码为 'baipi666'")
            print(f"{Fore.YELLOW}为确保后续扫描正常，密码将**自动回滚**到 'password'")
            print(f"{Fore.YELLOW}此过程无需手动干预，但请确保您了解该操作")
            print(f"{Fore.RED}{'=' * 60}")

            confirm = input(f"\n{Fore.CYAN}请输入 'yes' 确认已知晓并继续执行: ").strip().lower()

            if confirm == 'yes':
                print(f"{Fore.GREEN}[✓] 确认成功，开始执行全模块扫描")
                run_all(session_info, dvwa_login)
            else:
                print(f"{Fore.YELLOW}[!] 已取消全模块扫描，返回主菜单")
                continue

        else:
            print(f"{Fore.YELLOW}无效选项，请输入 0-6")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}检测到键盘中断，退出")