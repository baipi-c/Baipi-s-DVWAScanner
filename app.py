# app.py
import os
import sys
import subprocess
import threading
import queue
import json
import glob
import re
from flask import Flask, request, jsonify, send_from_directory, Response

app = Flask(__name__, static_folder='static')
ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
task_queues = {}


@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    dvwa_url = data.get('url', '').strip()
    scanner_choice = data.get('scanner')

    if not dvwa_url or not dvwa_url.endswith('/'):
        return jsonify({'error': 'DVWA URL 必须以 / 结尾'}), 400
    if scanner_choice not in {"1", "2", "3", "4", "5", "6"}:
        return jsonify({'error': '无效的扫描选项'}), 400

    task_id = "scan_1"
    msg_queue = queue.Queue()
    task_queues[task_id] = msg_queue

    def run_main_py():
        try:
            # ✅ 不再处理 cookie，统一走 URL + 交互式输入
            if scanner_choice == "6":
                inputs = [dvwa_url, "6", "yes", "0"]
            else:
                inputs = [dvwa_url, scanner_choice, "0"]

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
                    msg_queue.put(clean_line)

            proc.wait()

            report_links = []
            base_dir = os.path.dirname(__file__)
            patterns = [
                os.path.join(base_dir, "sql_scanner", "reports", "*.json"),
                os.path.join(base_dir, "xss_scanner", "reports", "*.json"),
                os.path.join(base_dir, "csrf_scanner", "reports", "*.json"),
                os.path.join(base_dir, "command_injection_report_*.json"),
                os.path.join(base_dir, "file_upload_report_*.json")
            ]

            for pattern in patterns:
                for report in sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)[:2]:
                    rel_path = os.path.relpath(report, base_dir).replace("\\", "/")
                    report_links.append(rel_path)

            msg_queue.put("[INFO] 扫描已完成！")
            if report_links:
                msg_queue.put(f"[REPORTS]{json.dumps(report_links)}")
            msg_queue.put("[END]")

        except Exception as e:
            msg_queue.put(f"[ERROR] {str(e)}")
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
                yield f"data: {json.dumps({'line': line})}\n\n"
            except queue.Empty:
                yield "data: {\"timeout\": true}\n\n"
                break

    return Response(generate(), mimetype='text/event-stream')


if __name__ == '__main__':
    print("🚀 Web 漏洞扫描器已启动（无 Cookie + 无 ANSI + 无进度条）")
    print("🌐 访问 http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, threaded=True)