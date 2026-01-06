import os
import re
import json
import sys
from urllib.parse import urljoin
from colorama import Fore, Style
from datetime import datetime

try:
    from DVWAlogin import DvwaLogin

    print(f"{Fore.GREEN}[✓] DVWA登录模块加载成功")
except Exception as e:
    print(f"{Fore.RED}[✗] DVWA登录模块加载失败: {e}")
    sys.exit(1)


class DvwaFileUploadScanner:
    def __init__(self, session, base_url, mode="dvwa"):
        """
        文件上传漏洞扫描器
        :param session: requests会话对象
        :param base_url: 目标网站基础URL
        :param mode: 扫描模式 - "dvwa" 或 "generic"
        """
        self.session = session
        self.base_url = base_url.rstrip("/ ")
        self.mode = mode

        # 根据模式设置默认上传路径
        if mode == "dvwa":
            self.upload_url = urljoin(self.base_url, "vulnerabilities/upload/")
            self.upload_dir = urljoin(self.base_url, "hackable/uploads/")
        else:
            self.upload_url = None
            self.upload_dir = None

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

        print(f"{Fore.CYAN}[→] 准备上传测试文件: {shell_path}")
        files = {
            file_field_name: ("backdoor.php", open(shell_path, "rb"), "application/octet-stream")
        }

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

            # 推断上传目录
            if self.mode == "generic":
                parsed_url = upload_url.split('?')[0]
                self.upload_dir = urljoin(parsed_url.rsplit('/', 1)[0] + '/', "uploads/")

            file_url = urljoin(self.upload_dir, uploaded_name)
            print(f"{Fore.CYAN}[→] 推断上传文件访问地址: {file_url}")

            # 验证文件是否可访问
            print(f"{Fore.CYAN}[→] 正在验证上传文件是否可访问...")
            verify = self.session.get(file_url)

            if verify.status_code == 200:
                print(f"{Fore.GREEN}[✓] 文件可访问！状态码: {verify.status_code}")
                print(f"{Fore.GREEN}[✓] {Fore.MAGENTA}{Style.BRIGHT}** 发现文件上传漏洞！ **{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[✓] 上传的文件可以直接访问，可能被利用")
                return True, file_url, "文件上传漏洞存在，可访问上传文件"
            else:
                print(f"{Fore.YELLOW}[!] 文件访问失败，状态码: {verify.status_code}")
                print(f"{Fore.YELLOW}[!] 可能原因: 1) 文件未上传成功 2) 路径推断错误 3) 权限限制")
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
            print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] 漏洞状态: {Fore.RED}存在漏洞{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[i] 漏洞状态: {Fore.GREEN}未发现问题{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] 详细报告已保存: {report_path}")
        print(f"{Fore.BLUE}{'=' * 60}\n")

    def detect(self, crawl_results=None):
        """
        主检测方法
        :param crawl_results: 爬虫结果（通用模式需要）
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
            if not crawl_results:
                print(f"{Fore.RED}[✗] 错误: 通用模式需要提供爬虫发现的上传表单数据")
                print(f"{Fore.YELLOW}[!] 请先运行爬虫模块获取上传点信息")
                return

            print(f"{Fore.GREEN}[✓] 爬虫共发现 {len(crawl_results)} 个上传表单")

            for idx, upload_form in enumerate(crawl_results, 1):
                print(f"\n{Fore.CYAN}[i] 正在处理第 {idx}/{len(crawl_results)} 个上传点")

                vulnerable, file_url, message = self.scan_upload_point(
                    upload_form['url'],
                    upload_form.get('form_data', {}),
                    upload_form.get('file_field', 'uploaded')
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
    print("=" * 50)
    print("    文件上传漏洞扫描程序")
    print("=" * 50)

    print("\n选择目标类型:")
    print("1. DVWA (内置固定路径)")
    print("2. 其他网站 (需要配合爬虫)")

    choice = input("\n请输入选项 (1/2): ").strip()

    if choice == "1":
        url = input("请输入 DVWA 首页 URL (如 http://localhost/dvwa): ").strip()
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
        print(f"{Fore.YELLOW}[!] 通用模式需要先运行爬虫获取上传表单信息")
        url = input("请输入目标网站 URL: ").strip()

        import requests
        session = requests.Session()

        scanner = DvwaFileUploadScanner(session, url, mode="generic")
        print(f"{Fore.YELLOW}[!] 请确保已运行爬虫并提供 crawl_results 参数")
        print(f"{Fore.CYAN}[i] 示例: scanner.detect(crawl_results=your_crawl_data)")

    else:
        print(f"{Fore.RED}[✗] 无效选项")


if __name__ == "__main__":
    main()