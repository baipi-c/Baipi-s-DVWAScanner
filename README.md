# WebScanner
🔍 一个基于 Python 的DVWA专用漏洞扫描工具，支持 SQL 注入、XSS 检测、CSRF检测、文件上传、命令注入检测

## 环境要求
- Python 3.10（不知道其他版本可不可以，没测过）
- Window11系统

## 安装

### 克隆项目
git clone https://github.com/baipi-c/Baipi-s-DVWAScanner

### 安装依赖
pip install -r requirements.txt

### 后续更新
先添加该项目为上游仓库：
git remote add upstream https://github.com/baipi-c/Baipi-s-DVWAScanner

获取最新信息：
git fetch upstream

## 运行
在终端运行app.py，得到一个网址，访问，然后在网页上进行扫描操作（这是一个本地网页）
#### 或
在终端运行main.py，然后在控制台进行扫描操作

## 温馨提示
该程序有很多问题，如果遇到了请私信我，不保证解决

## 项目架构
```
DVWA_Scanner/
├── app.py                             # 生成本地网页
├── crawler.py                         # 爬虫模块 
├── DvwaCommandInjectionScanner.py     # 命令注入扫描器 
├── DvwaCSRFScanner.py                 # CSRF扫描器 
├── DvwaFileUploadScanner.py           # 文件上传扫描器 
├── DVWAlogin.py                       # DVWA登录程序 
├── DvwaSql_scanner.py                 # SQL注入扫描器 
├── DvwaXSSScanner.py                  # XSS注入扫描器 
├── main.py                            # 集成了所有扫描器的主程序 
├── config/
    ├── xss_payload.txt                # XSS扫描器用到的payload 
    ├── backdoor.php                   # 文件上传扫描器后门文件 
├── scan_result
    ├── DvwaCommandInjectionScanner/   # 命令注入扫描器扫描报告储存文件夹
    ├── DvwaCSRFScanner/               # CSRF扫描器扫描报告储存文件夹
    ├── DvwaFileUploadScanner/         # 文件上传扫描器扫描报告储存文件夹
    ├── DvwaXSSScanner/                # XSS注入扫描器扫描报告储存文件夹
    ├── sql_scanner/                   # SQL注入扫描器扫描报告储存文件夹
    └── crawl_results_YYYYMMDD_HHMMSS.json  # 爬虫结果
```