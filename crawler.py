# crawler.py - 增强版（带重试、延迟、精确计数）
import os
import json
import re
import sys
import time
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("请先安装BeautifulSoup: pip install beautifulsoup4")
    sys.exit(1)

import requests
from colorama import Fore, Style, init

init(autoreset=True)


class VulnerabilityCrawler:
    def __init__(self, base_url, max_depth=2, delay=0.5, timeout=15, retries=2):
        """
        漏洞扫描专用爬虫 - 增强版
        :param base_url: 起始URL
        :param max_depth: 最大爬取深度，默认2
        :param delay: 请求延迟(秒)，默认0.5
        :param timeout: 超时时间(秒)，默认15
        :param retries: 失败重试次数，默认2
        """
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        self.retries = retries

        # 精确计数：只统计成功访问的页面
        self.visited_success = set()
        self.visited_attempted = set()
        self.injection_points = {
            'url_params': [],
            'forms': [],
            'upload_forms': [],
        }

    def is_same_domain(self, url):
        """检查是否为同一域名"""
        try:
            return urlparse(url).netloc == self.domain
        except:
            return False

    def is_valid_url(self, url):
        """过滤无效URL和资源文件"""
        try:
            invalid_ext = ('.pdf', '.jpg', '.jpeg', '.png', '.gif', '.zip', '.rar',
                           '.exe', '.mp4', '.mp3', '.css', '.js', '.ico', '.svg', '.woff', '.woff2')
            return not url.lower().endswith(invalid_ext)
        except:
            return False

    def fetch_with_retry(self, url):
        """带重试的请求"""
        for attempt in range(self.retries + 1):
            try:
                if attempt > 0:
                    print(f"    {Fore.YELLOW}[-] 第{attempt}次重试...")
                    time.sleep(self.delay * 2)

                response = requests.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                return response, None
            except requests.exceptions.Timeout:
                error = f"请求超时 ({self.timeout}秒)"
            except requests.exceptions.ConnectionError:
                error = "连接失败"
            except Exception as e:
                error = str(e)

        return None, error

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
                print(f"{Fore.CYAN}[→] 发现URL参数: {params}")
                print(f"    {Fore.LIGHTBLACK_EX}└─ URL: {url}")

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
                print(f"{Fore.GREEN}[+] 发现文件上传表单")
                print(f"    {Fore.LIGHTBLACK_EX}└─ URL: {form_url}")
                print(f"    {Fore.LIGHTBLACK_EX}└─ 文件字段: {file_field}")
            else:
                self.injection_points['forms'].append(form_info)
                print(f"{Fore.CYAN}[→] 发现普通表单")
                print(f"    {Fore.LIGHTBLACK_EX}└─ URL: {form_url}")
                print(f"    {Fore.LIGHTBLACK_EX}└─ 字段: {list(form_data.keys())}")

    def crawl(self, url, depth=0):
        """深度优先爬取 - 精确计数版"""
        # 避免重复尝试
        if url in self.visited_attempted:
            return

        # 标记为已尝试
        self.visited_attempted.add(url)

        # 深度检查
        if depth > self.max_depth:
            return

        # 域名和URL有效性检查
        if not self.is_same_domain(url) or not self.is_valid_url(url):
            return

        print(f"{'  ' * depth}[+] 深度{depth}: {url}")

        # 请求页面
        response, error = self.fetch_with_retry(url)
        if error:
            print(f"{'  ' * (depth + 1)}{Fore.RED}[✗] 访问失败: {error}")
            return

        # 成功访问，加入成功集合
        self.visited_success.add(url)

        try:
            soup = BeautifulSoup(response.text, 'html.parser')

            # 提取注入点
            self.extract_url_params(response.url)
            self.extract_forms(soup, response.url)

            # 查找所有链接
            links = soup.find_all('a', href=True)

            # 递归爬取
            for link in links:
                href = link['href']
                full_url = urljoin(response.url, href)

                # 延迟，避免请求过快
                if self.delay > 0:
                    time.sleep(self.delay)

                self.crawl(full_url, depth + 1)

        except Exception as e:
            print(f"{'  ' * (depth + 1)}{Fore.YELLOW}[-] 解析错误: {e}")

    def get_results(self):
        """获取爬取结果统计"""
        print(f"\n{Fore.BLUE}{'=' * 60}")
        print(f"{Fore.BLUE}爬虫统计信息")
        print(f"{Fore.BLUE}{'=' * 60}")
        print(f"尝试访问页面: {len(self.visited_attempted)}")
        print(f"{Fore.GREEN}成功访问页面: {len(self.visited_success)}")
        print(f"{Fore.CYAN}URL参数注入点: {len(self.injection_points['url_params'])}")
        print(f"{Fore.CYAN}普通表单: {len(self.injection_points['forms'])}")
        print(f"{Fore.CYAN}文件上传表单: {len(self.injection_points['upload_forms'])}")
        print(f"{Fore.BLUE}{'=' * 60}\n")

        return self.injection_points

    def save_results(self, filename=None):
        """保存结果到JSON文件"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"crawl_results_{timestamp}.json"

        filepath = os.path.join("scan_result", filename)
        os.makedirs("scan_result", exist_ok=True)

        data = {
            "scan_info": {
                "base_url": self.base_url,
                "max_depth": self.max_depth,
                "success_pages": len(self.visited_success),
                "attempted_pages": len(self.visited_attempted),
            },
            "injection_points": self.injection_points
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

        print(f"{Fore.GREEN}[✓] 爬取结果已保存: {filepath}")
        return filepath


def main():
    """交互式主函数"""
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
    print(f"{Fore.CYAN}[i] 目标: {url}")
    print(f"{Fore.CYAN}[i] 请求延迟: 0.5秒 | 超时: 15秒 | 重试: 2次\n")

    crawler = VulnerabilityCrawler(url, max_depth=max_depth, delay=0.5, timeout=15)
    crawler.crawl(url)
    results = crawler.get_results()
    crawler.save_results()

    # 后续扫描建议
    print(f"\n{Fore.GREEN}[!] 爬取完成！建议执行:")
    has_forms = False

    if results['upload_forms']:
        print(f"      {Fore.MAGENTA}⇢ 文件上传扫描器 ({len(results['upload_forms'])}个表单)")
        has_forms = True

    if results['forms']:
        print(f"      {Fore.MAGENTA}⇢ SQLi/XSS/CSRF扫描器 ({len(results['forms'])}个表单)")
        has_forms = True

    if results['url_params']:
        print(f"      {Fore.MAGENTA}⇢ URL参数扫描器 ({len(results['url_params'])}个链接)")
        has_forms = True

    if not has_forms:
        print(f"      {Fore.YELLOW}未发现任何注入点，目标可能是API或纯静态站")


if __name__ == "__main__":
    main()