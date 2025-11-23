# app.py - 支持多选 + 路径安全 + 多报告精准返回（最终可用版）
import os
import sys
import subprocess
import threading
import queue
import json
import glob
import re
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, Response

app = Flask(__name__, static_folder='static')
ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
task_queues = {}
scan_history = []

def generate_scan_id():
    return str(int(datetime.now().timestamp() * 1000))

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    dvwa_url = data.get('url', '').strip()
    scan_types = data.get('scan_types', [])
    if not dvwa_url or not dvwa_url.endswith('/'):
        return jsonify({'error': 'DVWA URL 必须以 / 结尾'}), 400
    if not scan_types:
        return jsonify({'error': '请至少选择一种扫描类型'}), 400

    # 类型映射
    type_map = {
        "SQL 注入": "1",
        "XSS 反射型": "2",
        "CSRF": "3",
        "命令注入": "4",
        "文件上传": "5"
    }
    report_key_map = {
        "SQL 注入": "sql_injection",
        "XSS 反射型": "xss",               # ✅ 关键：使用 "xss" 与前端一致
        "CSRF": "csrf",
        "命令注入": "command_injection",
        "文件上传": "file_upload"
    }

    # 输入序列构造
    if "全部扫描" in scan_types:
        if len(scan_types) > 1:
            return jsonify({'error': '“全部扫描”不能与其他类型同时选择'}), 400
        input_sequence = ["6", "yes", "0"]
        expected_keys = set(report_key_map.values())
    else:
        input_sequence = []
        expected_keys = set()
        for t in scan_types:
            if t == "全部扫描":
                continue
            if t not in type_map:
                return jsonify({'error': f'未知类型: {t}'}), 400
            input_sequence.append(type_map[t])
            expected_keys.add(report_key_map[t])
        input_sequence.append("0")

    task_id = generate_scan_id()
    msg_queue = queue.Queue()
    task_queues[task_id] = msg_queue

    def run_main_py():
        full_log = []
        try:
            input_str = dvwa_url + '\n' + '\n'.join(input_sequence) + '\n\n\n'
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            env['COLORAMA_DISABLE'] = '1'
            proc = subprocess.Popen(
                [sys.executable, 'main.py'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                cwd=os.path.dirname(__file__),
                env=env
            )
            proc.stdin.write(input_str)
            proc.stdin.close()

            for line in iter(proc.stdout.readline, ''):
                if line:
                    clean_line = ansi_escape.sub('', line).rstrip()
                    full_log.append(clean_line)
                    msg_queue.put(clean_line)

            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                msg_queue.put("[WARN] 主程序超时，已终止")

            # === 报告路径 ===
            BASE_DIR = os.path.dirname(os.path.abspath(__file__))
            report_patterns = {
                "sql_injection": os.path.join(BASE_DIR, "scan_result", "sql_scanner", "dvwa_sql_scan_report_*.json"),
                "xss": os.path.join(BASE_DIR, "scan_result", "DvwaXSSScanner", "dvwa_xss_report_*.json"),          # ✅ xss
                "csrf": os.path.join(BASE_DIR, "scan_result", "DvwaCSRFScanner", "dvwa_csrf_report_*.json"),
                "command_injection": os.path.join(BASE_DIR, "scan_result", "DvwaCommandInjectionScanner", "command_injection_report_*.json"),
                "file_upload": os.path.join(BASE_DIR, "scan_result", "DvwaFileUploadScanner", "report_*.json")
            }

            all_reports = {}
            for key in expected_keys:
                pattern = report_patterns.get(key)
                if not pattern:
                    all_reports[key] = {"error": "内部错误：未知报告类型"}
                    continue
                report_files = glob.glob(pattern)
                if report_files:
                    latest_file = max(report_files, key=os.path.getmtime)
                    try:
                        with open(latest_file, 'r', encoding='utf-8') as f:
                            content = json.load(f)
                        all_reports[key] = content
                    except Exception as e:
                        all_reports[key] = {"error": f"读取失败: {str(e)}"}
                else:
                    all_reports[key] = {"error": "未生成报告文件"}

            report_json_str = json.dumps(all_reports, ensure_ascii=False, indent=2)
            record = {
                "id": task_id,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": dvwa_url,
                "scan_types": scan_types,
                "log": '\n'.join(full_log),
                "report": report_json_str
            }
            scan_history.insert(0, record)

            msg_queue.put("[INFO] 扫描已完成！")
            msg_queue.put("[END]")

        except Exception as e:
            msg_queue.put(f"[ERROR] 异常: {str(e)}")
            msg_queue.put("[END]")

    threading.Thread(target=run_main_py, daemon=True).start()
    return jsonify({'task_id': task_id})

# ===== SSE 流 =====
@app.route('/stream/<task_id>')
def stream(task_id):
    def generate():
        q = task_queues.get(task_id)
        if not q:
            yield "data: {\"error\": \"任务不存在\"}\n\n"
            return
        while True:
            try:
                line = q.get(timeout=30)
                if line == "[END]":
                    yield "data: {\"end\": true}\n\n"
                    break
                else:
                    yield f"data: {{\"line\": {json.dumps(line)}}}\n\n"
            except queue.Empty:
                yield "data: {\"timeout\": true}\n\n"
                break
    return Response(generate(), mimetype='text/event-stream')

# ===== 历史记录列表 =====
@app.route('/history')
def get_history():
    return jsonify(scan_history[:30])

# ===== 历史详情（增强健壮性）=====
@app.route('/history/<scan_id>')
def get_history_detail(scan_id):
    # 清理输入，防止前后空格导致匹配失败
    scan_id_clean = str(scan_id).strip()
    for rec in scan_history:
        if str(rec["id"]).strip() == scan_id_clean:
            return jsonify({
                "id": rec["id"],
                "time": rec["time"],
                "target_url": rec["target_url"],
                "scan_types": rec["scan_types"],
                "log": rec["log"],
                "report": rec["report"]  # 注意：这是 JSON 字符串
            })

    return jsonify({"error": "记录未找到"}), 404

if __name__ == '__main__':
    import logging
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    print("服务已启动：http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, threaded=True)

