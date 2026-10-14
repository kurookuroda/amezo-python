# -*- coding: utf-8 -*-
#
# amezo.py - Python 版あめぞう風掲示板
#

import sys
import os
import re
import time
import fcntl
import hmac
import urllib.parse
import html
import hashlib
from datetime import datetime

# スクリプトのあるディレクトリに固定
try:
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
except Exception:
    pass

try:
    sys.stdout.reconfigure(encoding='utf-8', newline='')
except AttributeError:
    pass

# =========================================================================
# 設定
# =========================================================================
COPYRIGHT = """<!--
    Script for amezo-like BBS (Python Version)
    Original Copyright (C) 1999-2003 amezo_
    http://www17.big.or.jp/~amezo_/
    http://ame.x0.com/
-->
"""

AMEZO = '＠あめぞう'
URLBASE = 'http://ame.x0.com/'
ADMIN = 'サポート'

POST_INTERVAL = 5
MAX_THREADS = 0
PAGE_CACHE = 10
TRUSTED_PROXIES = ['127.0.0.1', '::1']
DELCRYPTFILE = 'delpass.txt'

HASH_SCHEME = 'pbkdf2_sha256'
HASH_ITERATIONS = 100000

HEADER = "Content-type: text/html; charset=UTF-8\r\n\r\n"

_ENTITY_TOKEN = re.compile(r'&(?:amp|quot|lt|gt|#39);|[\s\S]')
_INVISIBLE = re.compile(
    '[\u0080-\u009F\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5'
    '\u180B-\u180E\u200B\u200C\u200E\u200F\u2028-\u202E\u2060-\u206F'
    '\u3164\uFEFF\uFFA0\uFFF9-\uFFFB]'
)

# =========================================================================
# ユーティリティ関数
# =========================================================================

def error(msg):
    sys.stdout.write(HEADER)
    sys.stdout.write(
        "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\">"
        f"</head><body><h2>{html.escape(msg)}</h2></body></html>"
    )
    sys.exit(0)


def to_utf8(b):
    if not b:
        return ""
    for enc in ('utf-8', 'cp932'):
        try:
            return b.decode(enc)
        except UnicodeDecodeError:
            pass
    return b.decode('ascii', errors='ignore')


def strip_invisible(s):
    return _INVISIBLE.sub('', s)


def html_escape(s):
    return (s.replace('&', '&amp;')
             .replace('"', '&quot;')
             .replace('<', '&lt;')
             .replace('>', '&gt;')
             .replace("'", '&#39;'))


def html_chars_len(s):
    return len(_ENTITY_TOKEN.findall(s))


def ccut(s, max_len):
    return ''.join(_ENTITY_TOKEN.findall(s)[:max_len])


def url_decode(s):
    if isinstance(s, str):
        s = s.encode('latin1', errors='ignore')
    return to_utf8(urllib.parse.unquote_to_bytes(s.replace(b'+', b' ')))


def client_ip():
    addr = os.environ.get('REMOTE_ADDR', '')
    if addr not in TRUSTED_PROXIES:
        return addr
    ip_re = re.compile(r'^[0-9A-Fa-f:.]{2,45}$')
    cf = os.environ.get('HTTP_CF_CONNECTING_IP', '')
    if cf and ip_re.match(cf):
        return cf
    xff = [p.strip() for p in os.environ.get('HTTP_X_FORWARDED_FOR', '').split(',')]
    if xff and ip_re.match(xff[-1]):
        return xff[-1]
    return addr

# ---- パスワードハッシュ (admin.py からも使う) ---------------------------------

def make_hash(password, iterations=HASH_ITERATIONS, salt=None):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return f"{HASH_SCHEME}${iterations}${salt.hex()}${dk.hex()}"


def verify_hash(password, stored):
    try:
        scheme, iters, salt_hex, hash_hex = stored.strip().split('$')
        if scheme != HASH_SCHEME:
            return False
        iters = int(iters)
        if not (1 <= iters <= 5000000):
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
    return hmac.compare_digest(dk, expected)


def load_delcrypt():
    try:
        with open(DELCRYPTFILE, 'r', encoding='utf-8') as f:
            return f.read().strip()
    except FileNotFoundError:
        return ""

# ---- 板処理・制限 -----------------------------------------------------

def is_board(folder):
    try:
        with open('./blist.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.rstrip('\r\n')
                if line and line.split(',')[0] == folder:
                    return True
    except FileNotFoundError:
        pass
    return False


def post_interval_left(folder):
    if POST_INTERVAL <= 0:
        return 0
    last = 0
    try:
        with open(f'./{folder}/lasttime.txt', 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if content.isdigit():
                last = int(content)
    except FileNotFoundError:
        pass
    left = POST_INTERVAL - (int(time.time()) - last)
    return left if left > 0 else 0


def touch_lasttime(folder):
    if POST_INTERVAL <= 0:
        return
    try:
        with open(f'./{folder}/lasttime.txt', 'w', encoding='utf-8') as f:
            f.write(str(int(time.time())))
    except OSError:
        pass


def check_global_ip(ip):
    try:
        fd = os.open('global.mem', os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return
    with os.fdopen(fd, 'r+', encoding='utf-8') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        now = int(time.time())
        iplist = {}
        for line in f:
            parts = line.split()
            if len(parts) == 2 and parts[1].isdigit() and now - int(parts[1]) < 180:
                iplist[parts[0]] = int(parts[1])
        if ip in iplist:
            remain = 180 - (now - iplist[ip])
            error(f"あと {remain} 秒たってから投稿してください")
        iplist[ip] = now
        f.seek(0)
        f.truncate()
        for k, v in iplist.items():
            f.write(f"{k} {v}\n")


def redirect(folder, index_name):
    target = html.escape(f"{folder}/{index_name}", quote=True)
    sys.stdout.write("Status: 303 See Other\r\n")
    sys.stdout.write(f"Location: ../{target}\r\n")
    sys.stdout.write(HEADER)
    sys.stdout.write(
        f"<html><head><meta http-equiv=\"refresh\" content=\"0;url=../{target}\"></head>"
        f"<body>Redirecting to <a href=\"../{target}\">{target}</a>...</body></html>"
    )
    sys.exit(0)


def url_link(m):
    url = dsp = m.group(1)
    url = url.replace('&amp;', '&')
    return f'<a href="{url}" target="_blank" rel="noopener noreferrer nofollow">{dsp}</a>'


def reply_form(res, links=''):
    """レス用フォーム(1行で返す。スレッドファイルのパーサが行単位のため)"""
    return (
        '<form method=post action="../amezo.cgi" class="post">'
        f'<input type=hidden name="res" value="{res}">'
        '<div class="row">投稿者 <input type=text name="name" size=20> '
        'メール <input type=text name="mail" size=20></div>'
        '<textarea name="comm" rows=4 cols=70></textarea>'
        '<div class="row"><input type=submit value="↑へのレスカキコ"></div>'
        f'{links}'
        '</form>'
    )

# ---- 表示処理 -----------------------------------------------------

def res_view(folder, form):
    """レス表示 (Perl の res サブルーチン相当)"""
    res = form.get('res', '')
    if not re.match(r'^\d+$', res):
        error('不正なスレッド指定です')
    try:
        from_idx = int(form.get('from', '1'))
    except ValueError:
        from_idx = 1
    if from_idx < 1:
        from_idx = 1

    file_path = f"./{folder}/{res}.html"
    if not os.path.exists(file_path):
        error('スレッドがありません.')

    sys.stdout.write("Content-type: text/html; charset=UTF-8\r\n\r\n")
    with open(file_path, 'r', encoding='utf-8') as rf:
        for line in rf:
            line = line.replace('href="../style.css"', 'href="style.css"')
            sys.stdout.write(line)
            if '<dl>' in line or '<dt>' in line:
                break

        for line in rf:
            m = re.search(r'<dt>(\d+)', line)
            if m and int(m.group(1)) >= from_idx:
                sys.stdout.write(line)
                break

        fol_tag = f'<input type="hidden" name="folder" value="{html.escape(folder, quote=True)}">'
        for line in rf:
            if '</form>' in line:
                line = line.replace('action="../', 'action="')
                line = line.replace('</form>', f'{fol_tag}</form>')
            sys.stdout.write(line)
    sys.exit(0)

# ---- インデックス再生成 (amezo.py の投稿処理と admin.py の両方から使う) -------------

def regen_index(folder, next_int=21, reload_flag=False, use_cache=True):
    """板の index.html (next_int != 21 のときは index2.html) を再生成する。
    戻り値: (index_name, status)
      status: 'done'   再生成した
              'cached' 直近に更新済みのため再生成しなかった (use_cache=True のときのみ)
              'busy'   他のプロセスが再生成中でロックを取れなかった
    """
    # blist.txt から板の背景色とタイトル取得
    color = ""
    title = ""
    try:
        with open('./blist.txt', 'r', encoding='utf-8') as rf:
            for line in rf:
                line = line.rstrip('\r\n')
                if not line:
                    continue
                parts = line.split(',')
                if parts[0] == folder:
                    color = parts[1] if len(parts) > 1 else ''
                    title = parts[2] if len(parts) > 2 else ''
                    break
    except FileNotFoundError:
        pass

    page_suffix = '2' if next_int != 21 else ''
    index_name = f"index{page_suffix}.html"
    index_path = f"./{folder}/{index_name}"
    main_title_suffix = "(メイン)" if folder == 'main' else ''

    bg_attr = ""
    color_parts = color.split('!')
    color = color_parts[0]
    if len(color_parts) > 1:
        bg_attr = f' background="{color_parts[1]}"'

    text_attr = ""
    if color.endswith('*'):
        text_attr = ' text="#ffffff" link="red" vlink="orange"'
        color = color[:-1]

    title = title.replace('#c#', ',')
    title0 = title
    amezo_name = AMEZO
    m_title = re.search(r'alt="([^"]+)', title0)
    if m_title:
        title0 = m_title.group(1)
        amezo_name = ""

    # キャッシュチェック
    if use_cache:
        if next_int == 21 and reload_flag and POST_INTERVAL > 0:
            try:
                mtime = os.path.getmtime(index_path)
                if time.time() - mtime < POST_INTERVAL:
                    return index_name, 'cached'
            except OSError:
                pass

        if next_int != 21 and PAGE_CACHE > 0:
            try:
                with open(index_path, 'r', encoding='utf-8') as pf:
                    head = pf.read(4096)
                m_next = re.search(r'<!-- AMEZO-NEXT (\d+) -->', head)
                if m_next and int(m_next.group(1)) == next_int:
                    mtime = os.path.getmtime(index_path)
                    if time.time() - mtime < PAGE_CACHE:
                        return index_name, 'cached'
            except OSError:
                pass

    # ロック獲得とインデックス再生成
    lock_path = f"./{folder}/regen.lock"
    try:
        lk_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o644)
        LK = os.fdopen(lk_fd, 'w')
    except OSError:
        error("ロックファイルを作成できません.")

    locked = False
    if next_int == 21 and not reload_flag:
        # ブロッキングロック (CGIタイムアウトを考慮し最大10秒)
        for _ in range(100):
            try:
                fcntl.flock(LK, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except BlockingIOError:
                time.sleep(0.1)
    else:
        try:
            fcntl.flock(LK, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError:
            pass

    if not locked:
        LK.close()
        return index_name, 'busy'

    tmp_path = f"{index_path}.tmp{os.getpid()}"
    try:
        W = open(tmp_path, 'w', encoding='utf-8')
    except OSError:
        LK.close()
        error("indexを書き込めません.")

    W.write(
        f'<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8">\n'
        f'<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        f'<link rel="stylesheet" href="../style.css">\n'
        f'<title>{title0}{amezo_name}{main_title_suffix}</title></head>\n'
        f'{COPYRIGHT}\n'
        f'<!-- AMEZO-NEXT {next_int} -->\n'
        f'<body{bg_attr} bgcolor="{color}"{text_attr}>\n'
        f'<font size=+2>{title}{amezo_name}{main_title_suffix}</font>\n'
    )

    if os.path.exists('./header.html'):
        try:
            with open('./header.html', 'r', encoding='utf-8') as hf:
                W.write(hf.read())
        except OSError:
            pass

    W.write(
        f'<form method=post action="../amezo.cgi">\n'
        f'<input type=submit value="次のページ">\n'
        f'<input type=text name="next" value="{next_int}" size="3">〜</form>\n'
        f'<font size=2>\n<!-- HEAD LINE -->\n'
    )

    # ディレクトリ走査してヘッドラインをソート生成
    files = []
    try:
        for f_name in os.listdir(f"./{folder}"):
            if re.match(r'^\d+\.html$', f_name):
                try:
                    mtime = int(os.path.getmtime(f"./{folder}/{f_name}"))
                except OSError:
                    mtime = 0
                files.append((f"{mtime:011d}", f_name))
    except OSError:
        pass

    files.sort(key=lambda x: x[0], reverse=True)

    # 古いスレッドを退避 (oスレッドID.html)
    if MAX_THREADS > 0:
        n_thr = 0
        filtered_files = []
        for ts, f_name in files:
            n_thr += 1
            if n_thr > MAX_THREADS:
                if not os.path.exists(f"./{folder}/o{f_name}"):
                    try:
                        os.rename(f"./{folder}/{f_name}", f"./{folder}/o{f_name}")
                    except OSError:
                        pass
            else:
                filtered_files.append((ts, f_name))
        files = filtered_files

    start_idx = next_int - 21
    for i in range(start_idx, start_idx + 100):
        if i >= len(files):
            break
        ts, f_name = files[i]
        ttl = ""
        try:
            with open(f"./{folder}/{f_name}", 'r', encoding='utf-8') as rf:
                first_line = rf.readline()
                m_ttl = re.search(r'<b>([^<]*)</b>', first_line)
                if m_ttl:
                    ttl = m_ttl.group(1)
        except OSError:
            pass
        W.write(f' {i+1}<a href="{f_name}">{ttl}</a>\n')

    W.write("<!-- HEAD LINE END -->\n</font>\n")

    # 各スレッドの内容表示
    for i in range(start_idx, next_int - 1):
        if i >= len(files):
            break
        ts, f_name = files[i]
        W.write('<table border=1 cellspacing=1 cellpadding=2 width=100% bgcolor="#efefef"><tr><td><font color="#000000">\n')

        lines = []
        try:
            with open(f"./{folder}/{f_name}", 'r', encoding='utf-8') as rf:
                first_line = rf.readline()
                # スレッドの先頭行から html/head/body/meta/title/link を削って出力
                first_line = re.sub(r'</?(?:html|head|body)[^>]*>', '', first_line)
                first_line = re.sub(r'<(?:meta|link)[^>]*>', '', first_line)
                first_line = re.sub(r'<title>.*?</title>', '', first_line)
                W.write(first_line)

                for line in rf:
                    if line.startswith('<form'):
                        break
                    lines.append(line)
        except OSError:
            pass

        # 最初の1レスと最後の7レスのみを抜粋して表示
        k = len(lines) - 7
        if k < 0:
            k = 0
        for m in range(k, len(lines)):
            W.write(lines[m])

        res_id = f_name.replace('.html', '')
        sub_tag = ""
        if len(lines) > 200:
            k_idx = len(lines) - 98
            sub_tag = (f'<input type=text name="from" value="{k_idx}" size="4">'
                       '<input type=submit name="sub" value="〜"> ')

        links = (f'<div class="row links"><a href="{res_id}.html">レス全部を見る</a> '
                 f'{sub_tag}<a href="#top">上へ</a> <a href="./">リロード</a></div>')

        W.write('</font></td></tr></table>\n' + reply_form(res_id, links) + '<hr>\n')

    W.write(
        f'<form method=post action="../amezo.cgi">\n'
        f'<input type=submit value="次のページ">\n'
        f'<input type=text name="next" value="{next_int}" size="3">〜</form>\n'
        f'<hr></body></html>\n'
    )
    W.close()

    # 元の index ファイルに置き換え
    try:
        if os.path.exists(index_path):
            orig_mode = os.stat(index_path).st_mode & 0o7777
        else:
            orig_mode = 0o644
        os.chmod(tmp_path, orig_mode)
        os.replace(tmp_path, index_path)
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        error("indexを更新できません.")

    try:
        fcntl.flock(LK, fcntl.LOCK_UN)
        LK.close()
    except OSError:
        pass

    return index_name, 'done'

# =========================================================================
# メインロジック
# =========================================================================

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--make-hash':
        if len(sys.argv) < 3:
            print("Usage: python3 amezo.py --make-hash PASSWORD", file=sys.stderr)
            sys.exit(1)
        print(make_hash(sys.argv[2]))
        sys.exit(0)

    content_len = 0
    try:
        content_len = int(os.environ.get('CONTENT_LENGTH', '0'))
    except ValueError:
        pass

    if content_len > 7500:
        error('投稿内容が大きすぎます')

    try:
        buffer = sys.stdin.buffer.read(content_len)
    except Exception:
        buffer = b''

    if len(buffer) > 7500:
        error('投稿内容が大きすぎます')

    query_params = {}
    query_string = os.environ.get('QUERY_STRING', '')
    if query_string:
        for pair in query_string.split('&'):
            if '=' in pair:
                k, v = pair.split('=', 1)
                query_params[k] = url_decode(v)

    form = {}
    if buffer:
        for pair in buffer.split(b'&'):
            if b'=' in pair:
                k_b, v_b = pair.split(b'=', 1)
                key = to_utf8(k_b)
                value = url_decode(v_b)
                value = strip_invisible(value)
                value = html_escape(value)
                value = value.replace('\r\n', '\r').replace('\n', '\r')
                if key == 'comm':
                    value = value.replace('\r', '<br>')
                value = re.sub(r'[\x00-\x1f]', '', value)
                form[key] = value

    folder = form.get('folder', query_params.get('folder', ''))
    if not folder:
        referer = os.environ.get('HTTP_REFERER', '')
        referer = url_decode(referer)
        referer = re.sub(r'^(https?://)www\.', r'\1', referer)
        m = re.search(r'https?://[^/]+/([^/]+)/', referer)
        if m:
            folder = m.group(1)

    if not folder:
        error('板名が判定できません。')
    if '/' in folder or '..' in folder or not is_board(folder):
        error('板名が不正です')
    
    
    # CORS/Origin 検証 (一時的に無効化)
    # origin = os.environ.get('HTTP_ORIGIN', '')
    # referer = os.environ.get('HTTP_REFERER', '')
    # http_host = os.environ.get('HTTP_HOST', '')
    # if origin:
    #     url_cmp = re.sub(r'^(https?://)www\.', r'\1', URLBASE)
    #     ori_cmp = re.sub(r'^(https?://)www\.', r'\1', origin)
    #     if not url_cmp.startswith(ori_cmp + '/'):
    #         if http_host:
    #             clean_host = http_host.split(':')[0]
    #             if clean_host not in ori_cmp:
    #                 error('不正なリクエストです(Origin不一致)')
    #         elif referer:
    #             clean_host = http_host.split(':')[0]
    #             if clean_host not in referer and URLBASE not in referer:
    #                 error('不正なリクエストです(Origin判定不可/Referer不一致)')
    # elif referer and http_host:
    #     clean_host = http_host.split(':')[0]
    #     if clean_host not in referer and URLBASE not in referer:
    #         error('不正なリクエストです(Referer不一致)')
    
    name = form.get('name', '')
    mail = form.get('mail', '')
    comm = form.get('comm', '')
    subj = form.get('subj', '')
    res = form.get('res', '')

    if res and not re.match(r'^\d*$', res):
        error('不正なスレッド指定です')

    if 'sub' in form and len(form['sub']):
        res_view(folder, form)

    next_val = form.get('next', '1')
    if not re.match(r'^\d{1,6}$', next_val):
        next_val = '1'
    next_int = int(next_val)
    if next_int <= 0:
        next_int = 1
    next_int += 20

    reload_flag = False
    if name == subj and name == comm:
        reload_flag = True
    if not name and not subj and not comm:
        reload_flag = True

    if comm.count('<br>') > 20:
        error('改行が多すぎます')
    if html_chars_len(subj) > 20:
        error('題名が長すぎます')

    name = re.sub(r' |　|\u200D', '', name)
    name = ccut(name, 30)
    comm = re.sub(r'&gt;(&gt;)+', '&gt;', comm)
    subj = re.sub(r' |　|＿', '', subj)

    # NGワードチェック用の元メッセージデコード
    comm2 = comm
    if os.path.exists('./ng.txt'):
        try:
            with open('./ng.txt', 'r', encoding='utf-8') as rf:
                for line in rf:
                    line = line.rstrip('\r\n')
                    if not line:
                        continue
                    parts = line.split(',')
                    ng = parts[0]
                    opt = parts[1] if len(parts) > 1 else ''
                    if not ng:
                        continue
                    ng_esc = re.escape(ng)
                    if opt == 'n':
                        if re.search(ng_esc, name):
                            reload_flag = True
                    elif opt == 'c':
                        if re.search(ng_esc, comm2):
                            reload_flag = True
                    else:
                        name = re.sub(ng_esc, '', name)
                        comm = re.sub(ng_esc, '', comm)
                        mail = re.sub(ng_esc, '', mail)
                        subj = re.sub(ng_esc, '', subj)
        except OSError:
            pass

    if next_int == 21 and not reload_flag:
        # 管理者名偽装防止
        admin_pat = re.escape(ADMIN)
        name = re.sub(admin_pat, f"＃{ADMIN}", name)

        if res:
            subj = ''

        if not name:
            error('投稿者を記入してください')
        if not comm:
            error('コメントが入力されていません')
        if not res and not subj:
            error('題名が入力されていません')

        left_sec = post_interval_left(folder)
        if left_sec > 0:
            error(f"連投を検知しました。あと {left_sec} 秒ほど待ってから投稿してください")

        if subj:
            check_global_ip(client_ip())

        comm = re.sub(r'(https?\:[\w\.\~\-\/\?\+\=\:\@\%\;\#\&]+)', url_link, comm)
        if mail:
            name = f'<a href="mailto:{mail} ">{name} </a>'

        now = datetime.now()
        wdays = ["月", "火", "水", "木", "金", "土", "日"]
        wday = wdays[now.weekday()]
        date_str = now.strftime(f"20%y年%m月%d日({wday})%H時%M分%S秒")

        if not res:
            res = now.strftime("%y%m%d%H%M%S")

        file_path = f"./{folder}/{res}.html"
        if subj:
            for try_cnt in range(31):
                file_path = f"./{folder}/{res}.html"
                if not os.path.exists(f"./{folder}/x{res}.html") and not os.path.exists(f"./{folder}/o{res}.html"):
                    try:
                        fd = os.open(file_path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o644)
                        W = os.fdopen(fd, 'r+', encoding='utf-8')
                        break
                    except FileExistsError:
                        pass
                if try_cnt >= 30:
                    error('スレッドを作成できません.')
                res = str(int(res) + 1)
        else:
            try:
                W = open(file_path, 'r+', encoding='utf-8')
            except FileNotFoundError:
                error('スレッドがありません.')

        fcntl.flock(W, fcntl.LOCK_EX)
        cnt = 0
        pos = 0
        prev = ""
        # for line in W だと途中の tell() が OSError になるため readline() で読む
        while True:
            line = W.readline()
            if not line:
                break
            m = re.search(r'<dt>(\d+)', line)
            if not m:
                break
            cnt = int(m.group(1))
            prev = line
            pos = W.tell()

        W.seek(pos, 0)
        cnt += 1

        prev_m = re.search(r'<b>(.+?) </b>.+<dd>(.+?) </dl>', prev)
        if prev_m and name == prev_m.group(1) and comm == prev_m.group(2):
            W.close()
            error('二重カキコです.')

        subj1 = ""
        subj2 = ""
        if subj:
            subj1 = ('<html><head><meta charset="UTF-8">'
                     '<meta name="viewport" content="width=device-width, initial-scale=1">'
                     f'<title>{subj} </title>'
                     '<link rel="stylesheet" href="../style.css">'
                     '</head><body>')
            subj2 = f'<font size=+2 color=red><b>{subj} </b></font>'

        new_line = (f"{subj1}<dl><dt>{cnt}{subj2}投稿者：<font color=forestgreen><b>{name} </b></font>"
                    f"<font size=-1>　投稿日：{date_str}</font><br><dd>{comm} </dl>\n")
        W.write(new_line)
        W.write(reply_form(res) + '</body></html>\n')
        W.truncate()
        W.flush()
        W.close()
        touch_lasttime(folder)

    index_name, _ = regen_index(folder, next_int, reload_flag)
    redirect(folder, index_name)


if __name__ == '__main__':
    main()
