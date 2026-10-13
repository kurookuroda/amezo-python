%%writefile admin.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# admin.py - あめぞう風掲示板の管理画面 (CGI)
#
#   板 → スレッド → レス の順にたどり、レスの削除・スレッドの非表示/復元を行う。
#   認証は各画面のフォームにパスワードを持たせ、送信のたびに delpass.txt と照合する
#   (セッション/クッキーは使わない)。失敗が続いたら一定時間は照合せずに拒否する。

import sys
import os
import re
import time
import fcntl
import html
import urllib.parse
from datetime import datetime

import amezo   # verify_hash / load_delcrypt / is_board / client_ip / regen_index を共用

MAX_BODY = 64 * 1024        # POST の上限
MAX_FAILS = 5               # この回数失敗したら
LOCK_SEC = 15 * 60          # この時間 (秒) 受け付けない
FAIL_FILE = 'admin_fail.mem'
LIST_LIMIT = 100            # スレッド一覧に出す最大件数 (新しい順)
BODY_PREVIEW = 60           # レス一覧に出す本文の文字数

DATE_RE = r'(\d{4})年(\d{2})月(\d{2})日\([^)]+\)(\d{2})時(\d{2})分(\d{2})秒'

STYLE = """<style>
body { font-family: sans-serif; margin: 12px; }
table { border-collapse: collapse; }
th, td { border: 1px solid #999; padding: 4px 8px; vertical-align: top; }
td.body { max-width: 32em; word-break: break-all; }
form.inline { display: inline; }
.msg { padding: 6px 10px; border: 1px solid #c33; margin: 8px 0; }
.msg.ok { border-color: #393; }
button { padding: 4px 12px; }
</style>"""


def E(s):
    return html.escape(str(s), quote=True)


# ---- 出力 ---------------------------------------------------------------

def page(title, body):
    sys.stdout.write(
        "Content-type: text/html; charset=UTF-8\r\n"
        "Cache-Control: no-store\r\n"
        "X-Robots-Tag: noindex\r\n\r\n"
    )
    sys.stdout.write(
        '<!DOCTYPE html>\n<html lang="ja"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="robots" content="noindex">'
        f'<title>{E(title)}</title>{STYLE}</head><body>\n'
        f'<h2>{E(title)}</h2>\n{body}\n</body></html>\n'
    )
    sys.exit(0)


def msg_html(message, ok=True):
    if not message:
        return ''
    cls = 'msg ok' if ok else 'msg'
    return f'<div class="{cls}">{E(message)}</div>'


def hidden(pw, **fields):
    parts = [f'<input type="hidden" name="adminpass" value="{E(pw)}">']
    for k, v in fields.items():
        parts.append(f'<input type="hidden" name="{E(k)}" value="{E(v)}">')
    return ''.join(parts)


def btn(pw, label, confirm=None, **fields):
    onclick = ''
    if confirm:
        onclick = ' onclick="return confirm(\'' + E(confirm) + '\')"'
    return (f'<form method="post" action="admin.cgi" class="inline">{hidden(pw, **fields)}'
            f'<button type="submit"{onclick}>{E(label)}</button></form>')


def nav(pw, folder=None):
    s = btn(pw, '板一覧', act='boards')
    if folder:
        s += ' ' + btn(pw, f'「{folder}」のスレッド一覧', act='threads', folder=folder)
    return f'<p>{s}</p>'


def fatal(pw, message):
    page('エラー', msg_html(message, ok=False) + nav(pw))


def login_page(message=''):
    page('管理画面', msg_html(message, ok=False) +
         '<form method="post" action="admin.cgi">'
         '<input type="hidden" name="act" value="boards">'
         '管理用パスワード <input type="password" name="adminpass" autocomplete="current-password"> '
         '<button type="submit">ログイン</button></form>')


# ---- 認証 (失敗回数の制限つき) -----------------------------------------------

def fail_store(update):
    """admin_fail.mem を排他ロックして update(fails, now) を実行し、書き戻す。
    fails: {ip: (失敗回数, 最終失敗時刻)}。ファイルを開けなければ None (呼び出し側は拒否する)"""
    try:
        fd = os.open(FAIL_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        return None
    with os.fdopen(fd, 'r+', encoding='utf-8') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        now = int(time.time())
        fails = {}
        for line in f:
            p = line.split()
            if len(p) == 3 and p[1].isdigit() and p[2].isdigit() and now - int(p[2]) < LOCK_SEC:
                fails[p[0]] = (int(p[1]), int(p[2]))
        result = update(fails, now)
        f.seek(0)
        f.truncate()
        for k, (c, t) in fails.items():
            f.write(f"{k} {c} {t}\n")
        return result


def authenticate(pw):
    ip = amezo.client_ip() or 'unknown'

    blocked = fail_store(lambda fails, now: fails.get(ip, (0, 0))[0] >= MAX_FAILS)
    if blocked is None:
        page('管理画面', msg_html('状態ファイル (admin_fail.mem) を開けないため、受け付けられません。', ok=False))
    if blocked:
        page('管理画面', msg_html('失敗が続いたため、しばらく受け付けません。時間をおいてやり直してください。', ok=False))

    delcrypt = amezo.load_delcrypt()
    if not delcrypt:
        page('管理画面', msg_html('管理用パスワード (delpass.txt) が設定されていません。', ok=False))

    ok = bool(pw) and amezo.verify_hash(pw, delcrypt)

    def record(fails, now):
        if ok:
            fails.pop(ip, None)
        else:
            fails[ip] = (fails.get(ip, (0, 0))[0] + 1, now)

    fail_store(record)
    return ok


# ---- 板・スレッドの読み取り ------------------------------------------------------

def read_boards():
    boards = []
    try:
        with open('./blist.txt', 'r', encoding='utf-8') as f:
            for line in f:
                p = line.rstrip('\r\n').split(',')
                name = p[0]
                if not name or name.startswith('.') or '/' in name or '\\' in name:
                    continue
                title = p[2].replace('#c#', ',') if len(p) > 2 else ''
                m = re.search(r'alt="([^"]+)', title)
                plain = m.group(1) if m else re.sub(r'<[^>]*>', '', title)
                boards.append((name, plain))
    except FileNotFoundError:
        pass
    return boards


def list_threads(folder):
    """(表示中, 非表示中) のスレッドを更新の新しい順に返す。要素は (mtime, 番号, パス)"""
    active, hidden_list = [], []
    try:
        names = os.listdir(f'./{folder}')
    except OSError:
        names = []
    for n in names:
        m = re.fullmatch(r'(x?)(\d+)\.html', n)
        if not m:
            continue
        path = f'./{folder}/{n}'
        try:
            mt = os.path.getmtime(path)
        except OSError:
            continue
        (hidden_list if m.group(1) else active).append((mt, m.group(2), path))
    active.sort(reverse=True)
    hidden_list.sort(reverse=True)
    return active, hidden_list


def thread_summary(path):
    """(題名, レス数)"""
    title = ''
    count = 0
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i == 0:
                    m = re.search(r'<b>([^<]*)</b>', line)
                    if m:
                        title = html.unescape(m.group(1)).strip()
                if re.search(r'<dt>\d+', line):
                    count += 1
    except (OSError, UnicodeDecodeError):
        pass
    return title, count


def parse_thread(path):
    """(題名, [(番号, 名前, 日時, 本文), ...])"""
    title = ''
    rows = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i == 0:
                    m = re.search(r'<b>([^<]*)</b>', line)
                    if m:
                        title = html.unescape(m.group(1)).strip()
                m = re.search(r'<dt>(\d+)', line)
                if not m:
                    continue
                num = int(m.group(1))
                nm = re.search(r'投稿者：<font[^>]*><b>(.*?) </b>', line)
                name = html.unescape(re.sub(r'<[^>]*>', '', nm.group(1))).strip() if nm else ''
                dm = re.search(r'投稿日：([^<]*)</font>', line)
                date = dm.group(1).strip() if dm else ''
                bm = re.search(r'<dd>(.*?) </dl>', line)
                body = bm.group(1) if bm else ''
                body = body.replace('<br>', ' ')
                body = html.unescape(re.sub(r'<[^>]*>', '', body))
                rows.append((num, name, date, body))
    except (OSError, UnicodeDecodeError):
        pass
    return title, rows


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')


# ---- 画面 ------------------------------------------------------------------

def show_boards(pw):
    rows = ''
    for name, plain in read_boards():
        rows += (f'<tr><td>{E(name)}</td><td>{E(plain)}</td><td>'
                 + btn(pw, '開く', act='threads', folder=name) + '</td></tr>')
    if rows:
        body = '<table><tr><th>板</th><th>名称</th><th></th></tr>' + rows + '</table>'
    else:
        body = '<p>板がありません。</p>'
    page('板の一覧', body)


def show_threads(pw, folder, message='', ok=True):
    active, hidden_list = list_threads(folder)

    rows = ''
    for mt, res, path in active[:LIST_LIMIT]:
        title, count = thread_summary(path)
        rows += (f'<tr><td>{E(title) or "(題名なし)"}</td><td>{count}</td><td>{fmt_time(mt)}</td><td>'
                 + btn(pw, 'レスを見る', act='replies', folder=folder, res=res) + ' '
                 + btn(pw, '非表示', confirm='このスレッドを非表示にします。よろしいですか?',
                       act='hide', folder=folder, res=res)
                 + '</td></tr>')
    body = msg_html(message, ok) + nav(pw)
    if rows:
        body += '<table><tr><th>題名</th><th>レス数</th><th>更新</th><th></th></tr>' + rows + '</table>'
        if len(active) > LIST_LIMIT:
            body += f'<p>新しい順に {LIST_LIMIT} 件だけ表示しています (全 {len(active)} 件)。</p>'
    else:
        body += '<p>表示中のスレッドはありません。</p>'

    hrows = ''
    for mt, res, path in hidden_list[:LIST_LIMIT]:
        title, count = thread_summary(path)
        hrows += (f'<tr><td>{E(title) or "(題名なし)"}</td><td>{count}</td><td>{fmt_time(mt)}</td><td>'
                  + btn(pw, '復元', act='restore', folder=folder, res=res) + '</td></tr>')
    if hrows:
        body += ('<h3>非表示中のスレッド</h3>'
                 '<table><tr><th>題名</th><th>レス数</th><th>更新</th><th></th></tr>' + hrows + '</table>')

    page(f'「{folder}」のスレッド', body)


def show_replies(pw, folder, res, message='', ok=True):
    path = f'./{folder}/{res}.html'
    if not os.path.exists(path):
        fatal(pw, 'スレッドがありません。(非表示中の場合は、スレッド一覧から復元してください)')
    title, rows = parse_thread(path)

    trs = ''
    for num, name, date, body in rows:
        cb = '—' if num == 1 else f'<input type="checkbox" name="del" value="{num}">'
        short = body[:BODY_PREVIEW] + ('…' if len(body) > BODY_PREVIEW else '')
        trs += (f'<tr><td>{cb}</td><td>{num}</td><td>{E(name)}</td>'
                f'<td>{E(date)}</td><td class="body">{E(short)}</td></tr>')

    form = (f'<form method="post" action="admin.cgi">{hidden(pw, act="delete", folder=folder, res=res)}'
            '<table><tr><th>削除</th><th>No</th><th>名前</th><th>日時</th><th>本文</th></tr>'
            + trs + '</table>'
            '<p><button type="submit" onclick="return confirm(\'選択したレスを削除します。よろしいですか?\')">'
            '選択したレスを削除</button></p></form>')

    body = (msg_html(message, ok) + nav(pw, folder) + form
            + '<p>1番は削除できません。スレッドごと消す場合は「非表示」を使ってください。</p>'
            + '<p>' + btn(pw, 'このスレッドを非表示にする',
                          confirm='このスレッドを非表示にします。よろしいですか?',
                          act='hide', folder=folder, res=res) + '</p>')
    page(f'{title or "(題名なし)"} ({folder}/{res})', body)


# ---- 操作 ------------------------------------------------------------------

def do_delete(folder, res, nums):
    path = f'./{folder}/{res}.html'
    nums = {n for n in nums if n != 1}
    if not nums:
        return False, '削除するレスが選ばれていません。(1番は削除できません)'
    if not os.path.exists(path):
        return False, 'スレッドがありません。'

    removed = 0
    stamp = None
    try:
        with open(path, 'r+', encoding='utf-8') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            orig_mtime = os.fstat(f.fileno()).st_mtime
            keep = []
            for line in f.readlines():
                m = re.search(r'<dt>(\d+)', line)
                if m and int(m.group(1)) in nums:
                    removed += 1
                    continue
                d = re.search(DATE_RE, line)
                if d:
                    stamp = [int(x) for x in d.groups()]
                keep.append(line)
            f.seek(0)
            f.truncate()
            f.writelines(keep)
    except (OSError, UnicodeDecodeError):
        return False, '削除中にファイルエラーが発生しました。'

    # 更新日時を「残った最後のレスの日時」に戻す (一覧の順位が変わらないように)
    ts = orig_mtime
    if stamp:
        try:
            ts = datetime(*stamp).timestamp()
        except ValueError:
            pass
    try:
        os.utime(path, (ts + 1, ts + 1))
    except OSError:
        pass
    return True, f'{removed}件のレスを削除しました。'


def do_hide(folder, res):
    src = f'./{folder}/{res}.html'
    dst = f'./{folder}/x{res}.html'
    if not os.path.exists(src):
        return False, 'スレッドがありません。'
    if os.path.exists(dst):
        return False, '同じ番号の非表示スレッドが既にあるため、処理できません。'
    try:
        os.rename(src, dst)
        os.chmod(dst, 0o600)
    except OSError:
        return False, 'スレッドの非表示化に失敗しました。'
    return True, f'スレッド {res} を非表示にしました。'


def do_restore(folder, res):
    src = f'./{folder}/x{res}.html'
    dst = f'./{folder}/{res}.html'
    if not os.path.exists(src):
        return False, '非表示のスレッドがありません。'
    if os.path.exists(dst):
        return False, '同じ番号の表示中スレッドが既にあるため、復元できません。'
    try:
        os.rename(src, dst)
        os.chmod(dst, 0o644)
    except OSError:
        return False, 'スレッドの復元に失敗しました。'
    return True, f'スレッド {res} を復元しました。'


def regen(folder):
    """板の index を作り直す。戻り値は補足メッセージ (問題なければ空)"""
    _, status = amezo.regen_index(folder, use_cache=False)
    if status != 'done':
        return ' (他の処理が再生成中のため、板の一覧の更新は省略されました)'
    return ''


# ---- メイン ----------------------------------------------------------------

def main():
    method = os.environ.get('REQUEST_METHOD', 'GET')
    params = {}
    if method == 'POST':
        try:
            n = int(os.environ.get('CONTENT_LENGTH', '0'))
        except ValueError:
            n = 0
        if n < 0 or n > MAX_BODY:
            page('エラー', msg_html('送信内容が大きすぎます。', ok=False))
        body = sys.stdin.buffer.read(n).decode('utf-8', 'replace')
        params = urllib.parse.parse_qs(body, keep_blank_values=True)

    def get(key):
        return params.get(key, [''])[0]

    pw = get('adminpass')
    if method != 'POST' or not pw:
        login_page()
    if not authenticate(pw):
        login_page('パスワードが違います。')

    act = get('act') or 'boards'
    if act == 'boards':
        show_boards(pw)

    folder = get('folder')
    if (not folder or '/' in folder or '\\' in folder or '..' in folder
            or not amezo.is_board(folder)):
        fatal(pw, '板名が不正です。')
    if act == 'threads':
        show_threads(pw, folder)

    res = get('res')
    if not re.fullmatch(r'\d{1,20}', res):
        fatal(pw, 'スレッド番号が不正です。')

    if act == 'replies':
        show_replies(pw, folder, res)
    elif act == 'delete':
        nums = [int(x) for x in params.get('del', []) if re.fullmatch(r'[0-9]{1,6}', x)]
        ok, message = do_delete(folder, res, nums)
        if ok:
            message += regen(folder)
        show_replies(pw, folder, res, message, ok)
    elif act == 'hide':
        ok, message = do_hide(folder, res)
        if ok:
            message += regen(folder)
        show_threads(pw, folder, message, ok)
    elif act == 'restore':
        ok, message = do_restore(folder, res)
        if ok:
            message += regen(folder)
        show_threads(pw, folder, message, ok)
    else:
        fatal(pw, '不明な操作です。')


if __name__ == '__main__':
    main()
