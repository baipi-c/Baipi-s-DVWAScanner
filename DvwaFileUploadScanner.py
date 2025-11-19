import os
import re
import json
import sys
from urllib.parse import urljoin
from colorama import Fore
from datetime import datetime

try:
    from DVWAlogin import DvwaLogin

    print(f"{Fore.GREEN}[INFO] 成功导入DVWA登录模块")
except Exception as e:
    print(f"{Fore.RED}[ERROR] 无法导入DVWA登录模块: {e}")
    sys.exit(1)


class DvwaFileUploadScanner:
    def __init__(self, session, base_url):
        self.session = session
        self.base_url = base_url.rstrip("/ ")
        self.upload_url = urljoin(self.base_url, "vulnerabilities/upload/")
        self.upload_dir = urljoin(self.base_url, "hackable/uploads/")
        self.report_dir = os.path.join("scan_result", "DvwaFileUploadScanner")
        os.makedirs(self.report_dir, exist_ok=True)

    def extract_filename(self, html):
        """
        从响应中提取上传后的文件名
        """
        patterns = [
            r"\.\./\.\./hackable/uploads/([^\s'\"<]+)",
            r"hackable/uploads/([^\s'\"<]+)",
            r'<pre>.*?(hackable/uploads/([^<]+?))\s+succ?esfully',  # succ?esfully 匹配两种拼写
        ]
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                filename = os.path.basename(match.group(1))
                return filename
        print("提取文件名失败，使用默认文件名 backdoor.php")
        return "backdoor.php"

    def save_report(self, vulnerable, file_url, message):
        # 获取当前时间并格式化（文件名使用安全格式）
        current_time = datetime.now()
        report_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        file_time = current_time.strftime("%Y-%m-%d_%H-%M-%S")  # 文件名中不能包含冒号

        report = {
            "target": self.base_url,
            "vulnerable": vulnerable,
            "uploaded_file": file_url,
            "message": message,
            "report_time": report_time  # 报告中显示可读时间
        }

        # 生成带时间戳的文件名
        report_filename = f"report_{file_time}.json"
        report_path = os.path.join(self.report_dir, report_filename)

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        print(f"✓ 扫描报告已生成: {report_path}")

    def detect(self):
        print(f"开始扫描 DVWA 文件上传漏洞: {self.base_url}")
        shell_path = os.path.join("config", "backdoor.php")
        if not os.path.isfile(shell_path):
            print(f"测试文件不存在: {shell_path}")
            return

        files = {
            "uploaded": ("backdoor.php", open(shell_path, "rb"), "application/octet-stream")
        }
        data = {
            "Upload": "Upload"
        }

        try:
            res = self.session.post(self.upload_url, files=files, data=data)
            if res.status_code != 200:
                self.save_report(False, "", f"HTTP请求失败，状态码: {res.status_code}")
                return

            # 检测成功提示
            success_indicators = [
                "successfully uploaded",
                "succesfully uploaded",
                "has been uploaded",
                "file uploaded",
                "uploaded"
            ]
            if not any(indicator in res.text.lower() for indicator in success_indicators):
                uploaded_name = self.extract_filename(res.text)
                file_url = urljoin(self.upload_dir, uploaded_name)

                verify = self.session.get(file_url)
                if verify.status_code == 200:
                    self.save_report(True, file_url, "文件上传成功（无成功提示但可访问）")
                else:
                    self.save_report(False, "", "上传失败，响应中无成功提示，且文件不存在")
                return

            # 提取文件名
            uploaded_name = self.extract_filename(res.text)
            file_url = urljoin(self.upload_dir, uploaded_name)

            # 验证文件访问
            verify = self.session.get(file_url)
            if verify.status_code == 200:
                self.save_report(True, file_url, "文件上传漏洞存在，可访问上传文件")
            else:
                self.save_report(False, file_url, "文件上传成功，但无法访问上传文件")

        except Exception as e:
            self.save_report(False, "", f"扫描过程中发生异常: {e}")


def main():
    print("=" * 50)
    print("    DVWA 文件上传漏洞扫描程序")
    print("=" * 50)
    url = input("请输入 DVWA URL (例如 http://localhost/dvwa): ").strip()
    if not url:
        print("URL不能为空")
        return

    dvwa = DvwaLogin()
    if not dvwa.login(url):
        print("登录失败")
        return

    session_info = dvwa.get_session_info()
    if not session_info:
        print("无法获取登录会话信息")
        return

    scanner = DvwaFileUploadScanner(session_info['session'], session_info['base_url'])
    scanner.detect()


if __name__ == "__main__":
    main()