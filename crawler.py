import time
import os
import json
import re
import sys
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("请先安装BeautifulSoup: pip install beautifulsoup4")
    sys.exit(1)

import requests
from colorama import Fore, init

init(autoreset=True)


class VulnerabilityCrawler:
    def __init__(self, base_url, max_depth=2):
        """
        漏洞扫描专用爬虫
        :param base_url: 起始URL
        :param max_depth: 最大爬取深度，默认2
        """
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.visited = set()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "VulnerabilityCrawler/1.0"
        })
        self.injection_points = {
            'url_params': [],  # URL参数注入点
            'forms': [],  # 普通表单
            'upload_forms': [],  # 文件上传表单
        }

    def is_same_domain(self, url):
        """检查是否为同一域名"""
        return urlparse(url).netloc == self.domain

    def is_valid_url(self, url):
        """过滤无效URL"""
        invalid_ext = ('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.rar', '.exe', '.mp4', '.mp3')
        return not url.lower().endswith(invalid_ext)

    def extract_url_params(self, url):
        """提取URL参数注入点"""
        parsed = urlparse(url)
        if parsed.query:
            params = list(parse_qs(parsed.query).keys())
            if params:
                self.injection_points['url_params'].append({
                    'url': url,
                    'params': params,
                    'method': 'GET'
                })
                print(f"{Fore.CYAN}[→] 发现URL参数: {params} (URL: {url})")

    def extract_forms(self, soup, current_url):
        """提取表单注入点"""
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(current_url, action)

            # 检查文件上传
            file_inputs = form.find_all('input', type='file')
            is_upload = len(file_inputs) > 0

            # 提取表单字段
            inputs = form.find_all(['input', 'textarea', 'select'])
            form_data = {}
            file_field = None

            for inp in inputs:
                name = inp.get('name')
                if not name:
                    continue

                if inp.get('type') == 'file':
                    file_field = name
                else:
                    form_data[name] = inp.get('value', '')

            form_info = {
                'url': form_url,
                'method': method,
                'form_data': form_data,
            }

            if is_upload:
                form_info['file_field'] = file_field or 'uploaded'
                self.injection_points['upload_forms'].append(form_info)
                print(f"{Fore.GREEN}[+] 发现文件上传表单: {form_url}")
            else:
                self.injection_points['forms'].append(form_info)
                print(f"{Fore.CYAN}[→] 发现普通表单: {form_url} (字段: {list(form_data.keys())})")

    def crawl(self, url, depth=0):
        """深度优先爬取"""
        if depth > self.max_depth or url in self.visited:
            return

        print(f"{'  ' * depth}[+] 正在爬取: {url}")
        self.visited.add(url)

        try:
            time.sleep(0.3)

            response = self.session.get(
                url,
                timeout=5,
                allow_redirects=True
            )
            if response.status_code != 200:
                print(f"{'  ' * depth}[-] 访问失败: {response.status_code}")
                return

            soup = BeautifulSoup(response.text, 'html.parser')

            # 提取当前页面的注入点
            self.extract_url_params(url)
            self.extract_forms(soup, url)

            # DVWA特殊处理
            is_dvwa = 'dvwa' in self.domain.lower()
            if is_dvwa:
                links = soup.find_all('a', href=re.compile(r'vulnerabilities/'))
            else:
                links = soup.find_all('a', href=True)

            # 递归爬取
            for link in links:
                href = link['href']
                full_url = urljoin(url, href)

                if (full_url not in self.visited and
                        self.is_same_domain(full_url) and
                        self.is_valid_url(full_url)):
                    self.crawl(full_url, depth + 1)

        except Exception as e:
            print(f"{'  ' * depth}{Fore.YELLOW}[-] 错误: {e}")

    def get_results(self):
        """获取爬取结果"""
        print(f"\n{Fore.BLUE}{'=' * 60}")
        print(f"{Fore.BLUE}爬虫统计信息")
        print(f"{Fore.BLUE}{'=' * 60}")
        print(f"访问页面数: {len(self.visited)}")
        print(f"URL参数注入点: {len(self.injection_points['url_params'])}")
        print(f"普通表单: {len(self.injection_points['forms'])}")
        print(f"文件上传表单: {len(self.injection_points['upload_forms'])}")
        print(f"{Fore.BLUE}{'=' * 60}\n")

        return self.injection_points

    def save_results(self, filename=None):
        """保存结果到JSON文件"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crawl_results_{timestamp}.json"

        filepath = os.path.join("scan_result", filename)
        os.makedirs("scan_result", exist_ok=True)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.injection_points, f, indent=4, ensure_ascii=False)

        print(f"{Fore.GREEN}[✓] 爬取结果已保存: {filepath}")
        return filepath


def main():
    print("=" * 60)
    print("    漏洞扫描爬虫程序")
    print("=" * 60)

    url = input("\n请输入目标网站URL: ").strip()
    while not url.startswith('http'):
        print(f"{Fore.RED}[✗] URL格式错误，必须以http://或https://开头")
        url = input("请重新输入: ").strip()

    depth_input = input("请输入爬取深度 (默认2): ").strip()
    max_depth = int(depth_input) if depth_input.isdigit() else 2

    print(f"\n{Fore.CYAN}[i] 开始爬取，最大深度: {max_depth}")
    print(f"{Fore.CYAN}[i] 目标: {url}\n")

    crawler = VulnerabilityCrawler(url, max_depth=max_depth)
    crawler.crawl(url)
    results = crawler.get_results()

    # 保存结果
    crawler.save_results()

    # 简要总结
    if results['upload_forms']:
        print(f"\n{Fore.GREEN}[!] 发现文件上传表单 - 可使用文件上传扫描器")

    if results['forms']:
        print(f"{Fore.GREEN}[!] 发现普通表单 - 可使用SQLi/XSS/CSRF扫描器")

    if results['url_params']:
        print(f"{Fore.GREEN}[!] 发现URL参数 - 可使用SQLi/XSS扫描器")


if __name__ == "__main__":
    main()