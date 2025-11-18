import requests
import sys
import urllib3
from bs4 import BeautifulSoup

# 禁用SSL警告（用于自签名证书）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class DvwaLogin:
    def __init__(self):
        self.session = requests.Session()
        # 设置请求头，模拟真实浏览器
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.base_url = None
        self.logged_in = False

    def get_csrf_token(self, login_page_content):
        """从登录页面提取CSRF token"""
        soup = BeautifulSoup(login_page_content, 'html.parser')
        csrf_token_input = soup.find('input', {'name': 'user_token'})
        if csrf_token_input:
            return csrf_token_input.get('value')
        return None

    def login(self, url, username='admin', password='password'):
        """登录DVWA"""
        try:
            # 确保URL格式正确
            if not url.startswith('http'):
                url = 'http://' + url

            # 移除末尾的斜杠
            self.base_url = url.rstrip('/')

            print(f"尝试连接到: {self.base_url}")

            # 首先访问登录页面获取CSRF token
            login_url = f"{self.base_url}/login.php"

            try:
                response = self.session.get(login_url, verify=False, timeout=10)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f" 无法连接到DVWA: {e}")
                return False

            # 检查是否是DVWA页面
            if 'Damn Vulnerable Web Application' not in response.text:
                print(" 这不是一个有效的DVWA页面")
                return False

            # 获取CSRF token
            csrf_token = self.get_csrf_token(response.text)
            if not csrf_token:
                print(" 无法获取CSRF token，可能页面结构不匹配")
                return False

            print("✓ 成功获取CSRF token")

            # 准备登录数据
            login_data = {
                'username': username,
                'password': password,
                'user_token': csrf_token,
                'Login': 'Login'
            }

            # 发送登录请求
            print("正在尝试登录...")
            login_response = self.session.post(
                login_url,
                data=login_data,
                verify=False,
                allow_redirects=True,
                timeout=10
            )

            # 检查登录是否成功
            if 'Login failed' in login_response.text:
                print(" 登录失败：用户名或密码错误")
                return False
            elif 'PHPSESSID' in self.session.cookies and 'index.php' in login_response.url:
                print("✓ 登录成功！")
                self.logged_in = True

                # 登录成功后自动设置安全等级为low
                if self.set_security_level('low'):
                    print("✓ 安全等级已设置为low")
                else:
                    print("⚠ 无法设置安全等级，请手动设置")

                return True
            else:
                print(" 登录状态不确定，请检查响应")
                return False

        except Exception as e:
            print(f" 登录过程中发生错误: {e}")
            return False

    def set_security_level(self, level='low'):
        """设置DVWA安全等级"""
        if not self.logged_in:
            print(" 未登录，无法设置安全等级")
            return False

        try:
            # 访问安全设置页面
            security_url = f"{self.base_url}/security.php"
            response = self.session.get(security_url, verify=False, timeout=10)

            if response.status_code != 200:
                print(f" 无法访问安全设置页面，状态码: {response.status_code}")
                return False

            # 获取CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token_input = soup.find('input', {'name': 'user_token'})
            if not csrf_token_input:
                print(" 无法获取安全页面的CSRF token")
                return False

            csrf_token = csrf_token_input.get('value')
            print(f"✓ 获取安全页面CSRF token: {csrf_token}")

            # 准备安全等级设置数据
            security_data = {
                'security': level,
                'seclev_submit': 'Submit',
                'user_token': csrf_token
            }

            # 发送安全等级设置请求
            set_response = self.session.post(
                security_url,
                data=security_data,
                verify=False,
                timeout=10
            )

            # 检查设置是否成功
            if set_response.status_code == 200:
                # 验证安全等级是否真的被设置
                verify_response = self.session.get(security_url, verify=False, timeout=10)
                if f'value="{level}"' in verify_response.text:
                    return True
                else:
                    print(" 安全等级设置验证失败")
                    return False
            else:
                print(f" 安全等级设置失败，状态码: {set_response.status_code}")
                return False

        except Exception as e:
            print(f" 设置安全等级过程中发生错误: {e}")
            return False

    def get_security_level(self):
        """获取当前安全等级"""
        if not self.logged_in:
            print(" 未登录，无法获取安全等级")
            return None

        try:
            security_url = f"{self.base_url}/security.php"
            response = self.session.get(security_url, verify=False, timeout=10)

            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                # 查找被选中的安全等级
                selected_option = soup.find('select', {'name': 'security'}).find('option', selected=True)
                if selected_option:
                    return selected_option.get('value')
            return None
        except Exception as e:
            print(f" 获取安全等级失败: {e}")
            return None

    def test_connection(self):
        """测试连接是否有效"""
        if not self.logged_in:
            print(" 未登录，无法测试连接")
            return False

        try:
            response = self.session.get(f"{self.base_url}/index.php", verify=False, timeout=10)
            if response.status_code == 200:
                print("✓ 连接测试成功")
                return True
            else:
                print(f" 连接测试失败，状态码: {response.status_code}")
                return False
        except Exception as e:
            print(f" 连接测试失败: {e}")
            return False

    def get_session_info(self):
        """获取会话信息"""
        if self.logged_in:
            return {
                'session': self.session,
                'base_url': self.base_url,
                'cookies': dict(self.session.cookies)
            }
        else:
            return None


def main():
    """主函数"""
    print("=" * 50)
    print("        DVWA 登录程序")
    print("=" * 50)

    # 获取用户输入的URL
    url = input("请输入DVWA的URL (例如: http://localhost/dvwa): ").strip()

    if not url:
        print(" URL不能为空")
        sys.exit(1)

    # 创建登录实例
    dvwa = DvwaLogin()

    # 尝试登录
    if dvwa.login(url):
        # 测试连接
        dvwa.test_connection()

        # 显示当前安全等级
        current_level = dvwa.get_security_level()
        if current_level:
            print(f"当前安全等级: {current_level}")

        # 获取会话信息（可用于后续操作）
        session_info = dvwa.get_session_info()
        if session_info:
            print("\n✓ 登录信息已保存，可用于后续漏洞检测操作")
            print(f"Session Cookies: {session_info['cookies']}")
    else:
        print("\n 登录失败，请检查URL、用户名和密码")
        sys.exit(1)


if __name__ == "__main__":
    main()