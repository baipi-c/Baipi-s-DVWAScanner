# app.py - 融合 SSE 实时流 + 扫描历史记录（已适配 scan_result 报告路径）
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
scan_history = []  # 内存中的历史记录

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

    task_id = generate_scan_id()
    msg_queue = queue.Queue()
    task_queues[task_id] = msg_queue

    def run_main_py():
        full_log = []
        try:
            # 构建输入序列（模拟交互）
            inputs = [dvwa_url]
            if "全部扫描" in scan_types:
                inputs.extend(["6", "yes", "0"])
            else:
                # 映射中文到数字选项
                type_map = {
                    "SQL 注入": "1",
                    "XSS 反射型": "2",
                    "CSRF": "3",
                    "命令注入": "4",
                    "文件上传": "5"
                }
                for st in scan_types:
                    if st in type_map:
                        inputs.append(type_map[st])
                inputs.append("0")  # 退出

            input_str = '\n'.join(inputs) + '\n'

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

            proc.wait()

            # === 查找最新报告（关键修改：适配 scan_result 目录结构）===
            report_content = json.dumps({"error": "未找到报告文件"}, ensure_ascii=False, indent=2)
            latest_report = None
            latest_time = 0

            # 更新为实际的报告路径模式
            patterns = [
                os.path.join("scan_result", "sql_scanner", "dvwa_sql_scan_report_*.json"),
                os.path.join("scan_result", "DvwaXSSScanner", "dvwa_xss_report_*.json"),
                os.path.join("scan_result", "DvwaCSRFScanner", "dvwa_csrf_report_*.json"),
                os.path.join("scan_result", "DvwaCommandInjectionScanner", "command_injection_report_*.json"),
                os.path.join("scan_result", "DvwaFileUploadScanner", "report_*.json")
            ]

            for pattern in patterns:
                for report in glob.glob(pattern):
                    try:
                        mtime = os.path.getmtime(report)
                        if mtime > latest_time:
                            latest_time = mtime
                            latest_report = report
                    except OSError:
                        continue

            if latest_report:
                try:
                    with open(latest_report, 'r', encoding='utf-8') as f:
                        report_content = f.read()
                except Exception as e:
                    report_content = json.dumps({"error": f"读取报告失败: {str(e)}"}, ensure_ascii=False, indent=2)

            # === 保存到历史记录 ===
            record = {
                "id": task_id,
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target_url": dvwa_url,
                "scan_types": scan_types,
                "log": '\n'.join(full_log),
                "report": report_content
            }
            scan_history.insert(0, record)

            msg_queue.put("[INFO] 扫描已完成！")
            msg_queue.put(f"[REPORT]{report_content}")
            msg_queue.put("[END]")

        except Exception as e:
            error_msg = f"[ERROR] 扫描异常: {str(e)}"
            msg_queue.put(error_msg)
            msg_queue.put("[END]")

    thread = threading.Thread(target=run_main_py, daemon=True)
    thread.start()

    return jsonify({'task_id': task_id})

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
                elif line.startswith("[REPORT]"):
                    report_json = line[len("[REPORT]"):]
                    yield f"data: {{\"report\": {json.dumps(report_json)}}}\n\n"
                else:
                    yield f"data: {{\"line\": {json.dumps(line)}}}\n\n"
            except queue.Empty:
                yield "data: {\"timeout\": true}\n\n"
                break

    return Response(generate(), mimetype='text/event-stream')

# ===== 历史记录 API =====
@app.route('/history')
def get_history():
    brief = []
    for rec in scan_history[:30]:
        brief.append({
            "id": rec["id"],
            "time": rec["time"],
            "target_url": rec["target_url"],
            "scan_types": rec["scan_types"]
        })
    return jsonify(brief)

@app.route('/history/<scan_id>')
def get_history_detail(scan_id):
    for rec in scan_history:
        if rec["id"] == scan_id:
            return jsonify({
                "log": rec["log"],
                "report": rec["report"]
            })
    return jsonify({"error": "记录未找到"}), 404

if __name__ == '__main__':
    import logging
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    print("服务已启动：http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, threaded=True)