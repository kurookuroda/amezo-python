#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# amezo.py / dai.py を CGI として動かす簡易サーバー + Cloudflare Tunnel (Colab 用)
#
#   - /amezo.cgi と /amezo.py はどちらも amezo.py を実行する
#     (フォームの action="../amezo.cgi" のまま動く。古い Perl 版 .cgi は実行されない)
#   - 静的ファイルは「許可リスト方式」で配信する。許可するのは次のものだけ:
#       /  /index.html  /style.css
#       blist.txt に載っている板フォルダの index.html / index2.html / 数字.html
#     delpass.txt, global.mem, ng.txt, x〜.html (非表示スレッド), ソースなどは 404 になる

import os
import shutil
import time
import subprocess
import threading
import sys
import re
import socket
import urllib.parse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

PORT = 8000

# POST ボディの上限 (amezo.py 側の上限は 7500 バイト)
MAX_POST_BYTES = 64 * 1024

# CGI として実行するスクリプト名 (拡張子なし)。None なら ./ 内の .cgi/.py を全て実行する
# (None だと /server.py のような URL でサーバー自身が再起動されるので注意)
ALLOWED_CGI = {"amezo", "dai", "admin"}

# 板フォルダの外で配信を許可するパス
STATIC_ROOT_FILES = {"/", "/index.html", "/style.css"}

# 板フォルダの中で配信を許可するファイル名 (x〜.html / o〜.html は含まない)
BOARD_FILE_RE = r'(?:index2?|\d+)\.html'

DEFAULT_BOARDS = ["main", "zatsu", "test"]


def load_boards():
    """blist.txt に載っている板フォルダ名の集合を返す (毎回読む。小さいファイルなので十分速い)"""
    boards = set()
    try:
        with open("blist.txt", "r", encoding="utf-8") as f:
            for line in f:
                name = line.strip().split(",")[0]
                if name and not name.startswith(".") and "/" not in name and "\\" not in name:
                    boards.add(name)
    except OSError:
        pass
    return boards


# 1. BBSの初期ディレクトリ・パーミッション設定
def setup_bbs_directories():
    print("📂 BBS用のディレクトリとパーミッションを設定しています...")

    for cgi_script in ["amezo.py", "dai.py", "admin.py"]:
        if os.path.exists(cgi_script):
            os.chmod(cgi_script, 0o755)
            print(f"  - 実行権限付与: {cgi_script}")
        else:
            print(f"  ⚠️ {cgi_script} が見つかりません")

    # フレーム構成に必要なファイルの確認
    for needed in ["index.html", "style.css", "header.html", "blist.txt"]:
        if not os.path.exists(needed):
            print(f"  ⚠️ {needed} が見つかりません")

    # 古い Perl 版が残っていると紛らわしいので知らせる (削除はしない)
    for old in ["amezo.cgi", "dai.cgi"]:
        if os.path.exists(old):
            print(f"  ⚠️ {old} が残っています。Python版では使われません (削除か退避を推奨)")

    if not os.path.exists("delpass.txt"):
        print("  ℹ️ delpass.txt がありません。削除機能を使うなら次で作成してください:")
        print("     !python3 amezo.py --make-hash 合言葉 > delpass.txt")

    # blist.txt に定義されている板用フォルダを作成
    boards = sorted(load_boards()) if os.path.exists("blist.txt") else DEFAULT_BOARDS

    for board in boards:
        if not os.path.exists(board):
            os.makedirs(board, exist_ok=True)
            print(f"  - フォルダ作成: {board}/")
        os.chmod(board, 0o777)

        # index.html が無い(または極端に小さい)場合は、再生成を促す転送ページを置く
        index_path = os.path.join(board, "index.html")
        if not os.path.exists(index_path) or os.path.getsize(index_path) < 100:
            with open(index_path, "w", encoding="utf-8") as f:
                f.write(
                    f'<html><head>'
                    f'<meta http-equiv="refresh" content="0;url=../amezo.cgi?folder={board}">'
                    f'</head><body>Redirecting to BBS...</body></html>'
                )
            # 更新日時を古くして、amezo.py の「直近に更新済みなら再生成しない」判定を避ける
            old = time.time() - 3600
            os.utime(index_path, (old, old))
            print(f"  - 初期リダイレクト用ファイルを配置: {index_path}")


def cleanup_old_processes(port=PORT):
    """以前の古いプロセスをクリーンアップ"""
    print("🧹 古いWebサーバーやトンネルプロセスをクリーンアップしています...")
    os.system("pkill -f 'cloudflared' 2>/dev/null")
    os.system(f"fuser -k {port}/tcp 2>/dev/null")
    time.sleep(2)


# 2. PythonによるCGI対応Webサーバー
class MyCGIHandler(SimpleHTTPRequestHandler):

    # ---- ルーティング ----
    def do_GET(self):
        if self.is_cgi_request():
            self.run_custom_python_cgi()
        else:
            super().do_GET()          # 静的ファイル (send_head で許可リスト判定)

    def do_POST(self):
        if self.is_cgi_request():
            self.run_custom_python_cgi()
        else:
            self.send_error(501, "Can only POST to CGI scripts")

    def is_cgi_request(self):
        """/xxx.cgi /xxx.py をCGIとして扱う (ALLOWED_CGI で対象を制限)"""
        path = urllib.parse.urlparse(self.path).path
        m = re.fullmatch(r'/([A-Za-z0-9_]+)\.(cgi|py)', path)
        if not m:
            return False
        return ALLOWED_CGI is None or m.group(1) in ALLOWED_CGI

    # ---- 静的ファイル: 許可リスト方式 ----
    def is_static_allowed(self):
        path = urllib.parse.unquote(urllib.parse.urlparse(self.path).path)

        if path in STATIC_ROOT_FILES:
            return True

        # /板名  /板名/  /板名/index.html  /板名/index2.html  /板名/数字.html
        m = re.fullmatch(r'/([^/\\]+)(?:/(?:' + BOARD_FILE_RE + r')?)?', path)
        if not m:
            return False
        return m.group(1) in load_boards()

    def send_head(self):
        # GET / HEAD の両方がここを通る
        if not self.is_static_allowed():
            self.send_error(404, "Not Found")
            return None
        return super().send_head()

    def list_directory(self, path):
        # index.html が無いフォルダの中身を一覧表示しない
        self.send_error(404, "Not Found")
        return None

    # ---- CGI 実行 ----
    def run_custom_python_cgi(self):
        parsed_url = urllib.parse.urlparse(self.path)
        script_name = os.path.basename(parsed_url.path)      # 例: amezo.cgi

        # amezo.cgi / amezo.py のどちらで来ても、実体は amezo.py
        base = re.sub(r'\.(cgi|py)$', '', script_name)
        script_path = base + ".py"
        if not os.path.exists(script_path):
            self.send_error(404, f"Script not found: {script_name}")
            return

        abs_script_path = os.path.abspath(script_path)
        script_dir = os.path.dirname(abs_script_path)

        # POSTデータ読み込み (上限を超えるものは読まずに拒否)
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0
        if content_length < 0:
            content_length = 0
        if content_length > MAX_POST_BYTES:
            self.send_error(413, "Payload Too Large")
            return

        print(f"⚡ Python CGIを実行中: {script_path} (要求: {script_name}, Method: {self.command})")

        # 環境変数の準備 (CGI/1.1 に近づける)
        env = os.environ.copy()
        env["SERVER_SOFTWARE"] = "SimplePythonCGI/1.1"
        env["SERVER_NAME"] = socket.gethostname()
        env["GATEWAY_INTERFACE"] = "CGI/1.1"
        env["SERVER_PROTOCOL"] = "HTTP/1.1"
        env["SERVER_PORT"] = str(self.server.server_port)
        env["REQUEST_METHOD"] = self.command
        env["QUERY_STRING"] = parsed_url.query or ""
        env["CONTENT_TYPE"] = self.headers.get("Content-Type", "")
        env["SCRIPT_NAME"] = "/" + script_name
        # 要求された名前(amezo.cgi)で渡す: フォームの action="../amezo.cgi" をそのまま保つため
        env["SCRIPT_FILENAME"] = os.path.join(script_dir, script_name)
        env["REMOTE_ADDR"] = self.client_address[0]
        env["REMOTE_HOST"] = self.client_address[0]
        env["HTTP_REFERER"] = self.headers.get("Referer", "")
        env["HTTP_ORIGIN"] = self.headers.get("Origin", "")
        env["HTTP_USER_AGENT"] = self.headers.get("User-Agent", "")
        env["HTTP_HOST"] = self.headers.get("Host", f"127.0.0.1:{self.server.server_port}")
        env["HTTPS"] = "OFF"

        # その他のHTTPヘッダーを HTTP_* として渡す
        for header, value in self.headers.items():
            key = f"HTTP_{header.upper().replace('-', '_')}"
            if key not in env:
                env[key] = value

        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        env["CONTENT_LENGTH"] = str(len(post_data))

        proc = None
        try:
            proc = subprocess.Popen(
                [sys.executable, abs_script_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=script_dir
            )
            stdout, stderr = proc.communicate(input=post_data, timeout=30)

            if stderr:
                for line in stderr.decode('utf-8', errors='ignore').strip().splitlines():
                    print(f"  ⚠️ {line}")

            # ヘッダーとボディを分離 (\r\n\r\n と \n\n の両方に対応)
            if b"\r\n\r\n" in stdout:
                header_bytes, body_bytes = stdout.split(b"\r\n\r\n", 1)
            elif b"\n\n" in stdout:
                header_bytes, body_bytes = stdout.split(b"\n\n", 1)
            else:
                header_bytes, body_bytes = b"", stdout

            # ヘッダー解析
            status_code = 200
            headers = []
            for line in header_bytes.split(b"\n"):
                h_str = line.decode("utf-8", errors="ignore").strip()
                if not h_str or ":" not in h_str:
                    continue
                key, val = h_str.split(":", 1)
                key, val = key.strip(), val.strip()
                if key.lower() == "status":
                    parts = val.split(None, 1)
                    if parts:
                        try:
                            status_code = int(parts[0])
                        except ValueError:
                            pass
                else:
                    headers.append((key, val))

            # Status が無く Location だけの場合は 302 (CGI の仕様)
            if status_code == 200 and any(k.lower() == "location" for k, _ in headers):
                status_code = 302

            self.send_response(status_code)
            for key, val in headers:
                self.send_header(key, val)
            if not any(k.lower() == "content-length" for k, _ in headers):
                self.send_header("Content-Length", str(len(body_bytes)))
            self.end_headers()
            self.wfile.write(body_bytes)

        except subprocess.TimeoutExpired:
            if proc:
                proc.kill()
                proc.communicate()
            self.send_error(504, "CGI Timeout")
        except Exception as e:
            self.send_error(500, f"CGI Execution Failed: {e}")


def run_cgi_server(port=PORT):
    print(f"🚀 CGI Webサーバーを起動しています (ポート {port})...")
    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer(('127.0.0.1', port), MyCGIHandler)
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    return server


def wait_for_server(port=PORT, timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                print(f"✅ Webサーバーがポート {port} で正常に応答しました。")
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            pass
        time.sleep(1)
    return False


# 3. トンネルによる外部公開
def start_tunnel(port=PORT):
    print("☁️ Cloudflare Tunnel をセットアップしています...")
    if not shutil.which("cloudflared"):
        print("cloudflared をダウンロード中...")
        os.system(
            'curl -sL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o cloudflared'
        )
        os.system('chmod +x cloudflared')
        cloudflared_bin = "./cloudflared"
    else:
        cloudflared_bin = "cloudflared"

    tunnel_process = subprocess.Popen(
        [cloudflared_bin, 'tunnel', '--url', f'http://127.0.0.1:{port}'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )

    url_event = threading.Event()
    public_url = [""]

    def read_output():
        for line in iter(tunnel_process.stdout.readline, ""):
            if "[CF_OUT]" not in line:
                print(f"[CF_OUT] {line.strip()}")
            match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
            if match:
                public_url[0] = match.group(0)
                url_event.set()

    t = threading.Thread(target=read_output)
    t.daemon = True
    t.start()

    print("⏳ トンネルの公開URLを取得しています...")
    if url_event.wait(timeout=20):
        print(f"\n🎉 【BBSアクセス先URL】: {public_url[0]}/ \n")
    else:
        print("❌ 公開URLの取得に失敗しました。トンネルプロセスの出力を確認してください。")

    return tunnel_process


if __name__ == "__main__":
    # __file__ が無い環境 (Jupyter/Colab) では os.getcwd() を使う
    try:
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        BASE_DIR = os.getcwd()

    os.chdir(BASE_DIR)

    cleanup_old_processes()
    setup_bbs_directories()

    server = run_cgi_server(port=PORT)

    if wait_for_server(port=PORT):
        tunnel_proc = start_tunnel(port=PORT)

        try:
            print("\n⏳ サーバー稼働中... 停止するには Ctrl+C を押してください。")
            while True:
                if tunnel_proc.poll() is not None:
                    print("⚠️ トンネルプロセスが終了しました。")
                    break
                time.sleep(5)
        except KeyboardInterrupt:
            print("\n🛑 終了シグナルを検知しました。プロセスを停止します...")
        finally:
            tunnel_proc.terminate()
            server.shutdown()
            print("✅ プロセスを安全に停止しました。")
    else:
        print("❌ Webサーバーが起動しませんでした。")
        server.shutdown()
