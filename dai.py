%%writefile dai.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# dai.cgi の Python 版 (板一覧 + 各板の HEAD LINE 表示)
#
#     Script for amezo-like BBS HEAD LINE (Python Version)
#     Original Copyright (C) 2000 amezo_
#     http://www17.big.or.jp/~amezo_/
#
# GETパラメータによるソースコード公開はセキュリティリスクのため実装しない。

import sys
import re
import html as html_module

# CGI 環境(LANG=C 等)でも日本語を UTF-8 で出力する
try:
    sys.stdout.reconfigure(encoding='utf-8', newline='')
except AttributeError:
    pass

HEADLINE_MAX = 20

PAGE_HEAD = (
    '<!DOCTYPE html>\n'
    '<html lang="ja"><head>\n'
    '<meta charset="UTF-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    '<base target="naka">\n'
    '<link rel="stylesheet" href="style.css">\n'
    '<title>板一覧</title>\n'
    '</head><body>\n'
)
PAGE_FOOT = '</body></html>\n'


def read_headline(folder, folder_escaped):
    """./<folder>/index.html の HEAD LINE 部分(最大20行)を返す"""
    out = []
    try:
        with open(f'./{folder}/index.html', 'r', encoding='utf-8') as rf:
            for line in rf:
                if '<!-- HEAD LINE -->' in line:
                    break
            else:
                return out   # HEAD LINE が無い

            for line in rf:
                if len(out) >= HEADLINE_MAX or '<!-- HEAD LINE END -->' in line:
                    break
                # 最初の1箇所だけ 1234.html -> folder/1234.html (Perl の s/// と同じ)
                out.append(re.sub(r'(\d+\.html)',
                                  lambda m: f"{folder_escaped}/{m.group(1)}",
                                  line, count=1))
    except (OSError, UnicodeDecodeError):
        pass   # index がまだ無い板でも落ちない
    return out


def main():
    sys.stdout.write("Content-type: text/html; charset=UTF-8\r\n\r\n")
    sys.stdout.write(PAGE_HEAD)

    try:
        bf = open('./blist.txt', 'r', encoding='utf-8')
    except FileNotFoundError:
        sys.stdout.write(PAGE_FOOT)
        sys.exit(0)

    with bf:
        for line in bf:
            line = line.rstrip('\r\n')
            if not line:
                continue

            parts = line.split(',')
            folder = parts[0]
            color = parts[1] if len(parts) > 1 else ''
            title = parts[2] if len(parts) > 2 else ''

            if not folder or folder.startswith('.') or '/' in folder or '..' in folder:
                continue

            color = re.sub(r'!.*', '', color)    # 背景画像の指定は使わない
            color = re.sub(r'\*$', '', color)    # 白文字指定の * は色ではない
            title = title.replace('#c#', ',')    # #c# をカンマに戻す

            # title は blist.txt(管理者のみ編集)の値をそのまま出す
            # (title には <img alt=...> などの HTML が入りうる)
            # color は属性値なのでエスケープする
            folder_escaped = html_module.escape(folder, quote=True)
            color_escaped = html_module.escape(color, quote=True)

            # target は <base target="naka"> で一括指定している
            sys.stdout.write(
                f'<table border=0 cellspacing=1 cellpadding=2 width=100% bgcolor="{color_escaped}"><tr><td>\n'
                f'<a href="{folder_escaped}/"><b><font size="3" color="#F92500">{title}</font></b></a>\n'
            )
            for hl in read_headline(folder, folder_escaped):
                sys.stdout.write(hl)
            sys.stdout.write("</td></tr></table>\n")

    sys.stdout.write(PAGE_FOOT)


if __name__ == '__main__':
    main()
