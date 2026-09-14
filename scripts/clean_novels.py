from __future__ import annotations

import re
import sys
import json
import argparse
import bisect
import shutil
from datetime import datetime
from pathlib import Path
from itertools import zip_longest
from typing import Callable


def detect_decode(raw: bytes) -> tuple[str, str]:
    """Sniff BOM, then try utf-8, then fall back to gb18030."""
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw[3:].decode('utf-8', errors='replace'), 'utf-8-bom'
    if raw.startswith(b'\xff\xfe\x00\x00'):
        return raw[4:].decode('utf-32-le', errors='replace'), 'utf-32-le'
    if raw.startswith(b'\x00\x00\xfe\xff'):
        return raw[4:].decode('utf-32-be', errors='replace'), 'utf-32-be'
    if raw.startswith(b'\xff\xfe'):
        return raw[2:].decode('utf-16-le', errors='replace'), 'utf-16-le'
    if raw.startswith(b'\xfe\xff'):
        return raw[2:].decode('utf-16-be', errors='replace'), 'utf-16-be'
    try:
        return raw.decode('utf-8'), 'utf-8'
    except UnicodeDecodeError:
        pass
    return raw.decode('gb18030', errors='replace'), 'gb18030'


RULES: dict = {}


def rule(key: str, label: str, fn: Callable) -> None:
    RULES[key] = (label, fn)



def _a():
    return [
        re.compile(r'^[ 　\t]*采墨阁[^\n]*?(?:为您搜集整理|提供)[^\n]*?(?:TXT下载|全文|看完整章节)[^\n\r]*[ 　\t]*\r?\n?', re.MULTILINE),
        re.compile(r'^[ 　\t]*[\[【\(（][^\]\)】）\n\r]*[\]】\)）][^\n]{0,60}?(?:为您搜集整理|看完整章节|TXT下载|永久更新|无广告阅读|最\s*新\s*章\s*节)[^\n]*[ 　\t]*\r?\n?', re.MULTILINE),
        re.compile(r'^[ 　\t]*本书网址[ 　]*[:：][^\n]{0,200}[ 　\t]*\r?\n?', re.MULTILINE),
        re.compile(r'^[ 　\t]*本书(?:来自|源)[^\n]{0,80}[裙群君羊]{1,3}[^\n]{0,30}[ 　\t]*\r?\n?', re.MULTILINE),
    ]


rule('A', '头部/独立行 网站水印', _a)


def _b():
    return [
        re.compile(
            r'(?<=\n)([ 　\t]*)(?:[qQ][qQ][ 　][\d零洞令玲磷铃拎另领冷oO⓪-⓿⓪-⓿②]{6,18}/[ 　]?整理[\d\s\-:ɞ\u4e00-\u9fff]{0,40})\s*\r?\n?',
            re.MULTILINE,
        ),
    ]


rule('B', '章节末尾 qq 整理 时间戳', _b)


_C_NUMCH = r"[\dA-Za-z\u2460-\u249b⓪-⓿零洞令玲磷铃拎另领冷oO]"
_C_NUM = (r"(?:" + _C_NUMCH + r"[\s./\\~·\-]{0,2}){2,15}" + _C_NUMCH)
_C_JUNK = (r"(?:[\s./\\~·\-A-Za-z]{0,3}"
           r"(?:梦[\s./\\~·\-]{0,2}中[\s./\\~·\-]{0,2}[A-Za-z]?[\s./\\~·\-]{0,2}星[\s./\\~·\-]{0,2}推[\s./\\~·\-]{0,2}文"
           r"|独[\s./\\~·\-]{0,2}家[\s./\\~·\-]{0,2}整[\s./\\~·\-]{0,2}理"
           r"|整[\s./\\~·\-]{0,2}理"
           r"|[\s./\\~·\-]{1,2}星"
           r")){0,3}")


def _c():
    return [
        re.compile(
            r'(?:^|(?<=\n))[ \t　]*(?:(?:[qQ][qQ]\s*[:：]\s*)|((?:本文|本\s*文)[^\u4e00-\u9fff]{0,2}唯一[^\u4e00-\u9fff]{0,2}更[^\u4e00-\u9fff]{0,2}新\s*[qQ]?\s*[:：]\s*))'
            + _C_NUM + _C_JUNK,
            re.MULTILINE,
        ),
        re.compile(r'(?:^|(?<=\n))[ \t　]*[qQ][qQ]\s*[:：]\s*[\d零洞令玲磷铃拎另领冷oO⓪-⓿]{6,14}[^\n]{0,6}?(?:[\(（][^\(（\)）]{1,60}[\)）])[^\n]*', re.MULTILINE),
    ]


rule('C', '章节前置广告 QQ:xxx', _c)


def _d():
    return [
        re.compile(r'^[ 　\t]*防失[\u4e00-\u9fffA-Za-z]{0,2}联[ 　]?[qQ]{1,2}[ 　]?[qQ群裙]?[ 　]?[:：][ 　]?[^\n\r]{0,60}[ 　\t]*\r?\n?', re.MULTILINE),
        re.compile(r'\[[ 　\t]*防失[\u4e00-\u9fffA-Za-z]{0,2}联[ 　]?[qQ]{1,2}[ 　]?[qQ群裙]?[ 　]?[:：][ 　]?[^\]]{0,80}\]', re.MULTILINE),
    ]


rule('D', '防失联QQ群', _d)


def _e():
    return [
        re.compile(r'本文件源自[\d零洞令玲磷铃拎另领冷oO⓪-⓿]{6,12}群[^\n]{0,8}(?:還|还)?[ 　]?追[^\n]{0,4}', re.MULTILINE),
        re.compile(r'(?:QQ|扣扣|扣扣群|裙内)[ 　]?[：:][ 　]*[\d零洞令玲磷铃拎另领冷oO⓪-⓿]{6,12}[，,]?[ 　]?(?:還|还|来)?[ 　]?追?(?:更|新|章|看|更章)[^\n]{0,4}', re.MULTILINE),
    ]


rule('E', '本文件源自xxx群 追章', _e)


def _f():
    _LAN = r"兰澜蘭籣笙昇声しぐゞ苼岚丶曻"
    _cn_digits = r"零〇一壹二贰貳參弎三叁仨四肆五伍忢忤舞武六陆七柒妻漆八捌九玖久酒灸十百千"
    _F2 = re.compile(
        r"(?:[,，])?"
        + r"日\s*更"
        + r"[" + _cn_digits + r"\d" + _M_NAD_BODY + _N_WEIRD + r" ，,\.]{2,40}"
        + r"[" + _LAN + r"\d ,，.」L\w]{0,80}"
        + r"公众[号浩]"
        + r"[^\u4e00-\u9fff\n]{0,30}"
        + r"(?:[\u4e00-\u9fff]{0,4}推文\s?\d{8}(?:[ ]\d{4,6})?整?)?",
        re.UNICODE,
    )
    return [
        re.compile(
            r'(?<![\d\u4e00-\u9fff])'
            r'(?:'
            r'(?:企[^\u4e00-\u9fff]{0,2}鹅[^\u4e00-\u9fff]{0,2}群|海[ ]?棠[ ]?群[ ]?主[ ]?扣[ ]?)'
            r'(?:[扣釦叩口][.．﹒]{0,2})?'
            r'|'
            r'(?:[扣釦叩口][.．﹒]{0,2})?[0-9０-９]'
            r')'
            r'(?:[ ]?[^\u4e00-\u9fff\s”’"「」『』]){5,29}'
            r'日'
            r'[^\u4e00-\u9fff\s]{0,3}'
            r'[更近]'
            r'(?:[＜﹤<~～]?[，,]?\s*(?:日更)?(?:[海嗨][棠堂][群裙]~?)?)?'
            r'(?:[Hh][^\u4e00-\u9fff]{0,2}[文])?'
            r'[、,，]?',
            re.UNICODE,
        ),
        _F2,
    ]


rule('F', '数字-分隔符-日更 群号乱码', _f)


def _g():
    return [
        re.compile(r'^[ 　\t]*裙内示例文本[^\n]{0,80}[ 　\t]*\r?\n?', re.MULTILINE),
        re.compile(r'^[ 　\t]*裙内日[\._\.．][ 　]?更[^\n]{0,60}[ 　\t]*\r?\n?', re.MULTILINE),
        re.compile(r'^[ 　\t]*[裙群][内中里][^\n]{0,30}?(?:日\.?更|更精彩|支持求文催更|史上万本|H文更多更全|戳我主页|来呀|求收|裙内|免\s*费|更多小说|看更多|番\s*外|看小?說|机器人秒出|找文|秒出)[^\n]*[ 　\t]*\r?\n?', re.MULTILINE),
        re.compile(r'^[^\n]{0,30}?追更[群裙][^\n]{0,40}?(?:求文[/／]?催更|催更|配找文|找文AI|找文机器人)[^\n]*\r?\n?', re.MULTILINE),
    ]


rule('G', '裙内/群内 行级推广', _g)


_H2_ANCHOR = re.compile(
    r'长[^\u4e00-\u9fff]{0,2}腿?[^\u4e00-\u9fff]{0,2}'
    r'[老佬姥咾唠耂铑劳牢捞][^\u4e00-\u9fff]{0,2}'
    r'[阿呵锕啊吖aA][^\u4e00-\u9fff]{0,2}'
    r'[姨咦胰疑移怡仪夷]', re.UNICODE)
_H2_STRONG = re.compile(
    r'[整正證证][^\u4e00-\u9fff]{0,2}[理里裡]'
    r'|[追][^\u4e00-\u9fff]{0,2}[更哽噎梗綆耕庚浭]'
    r'|[Hh][^\u4e00-\u9fff]{0,2}[文]'
    r'|[找][^\u4e00-\u9fff]{0,2}[文]'
    r'|[机機][器]?[^\u4e00-\u9fff]{0,2}[人]'
    r'|[等][你][来來][撩]')
_H2_NUM = re.compile(
    r'[\d０-９⓪-⓿①-⑨㊀-㊉⒈-⒛零〇一二三四五六七八九十百千壹贰叁肆伍陆柒捌玖]{2,}')
_H2_QUN = re.compile(r'[群裙君羊]')
_H2_TAIL_HANZI = frozenset(
    '整正證证政理里裡裏李礼追更更新新多好文紋雯蚊玟资資源源福福利看後后續续撩来來'
    '欢迎迎進进加入入群裙羣圈求催配有人人工找找机機器器日每時时请請联连係系招招聘坡等在你')


def _h2_seg(text: str):
    """长腿老阿姨超长广告形态：锚点+广告段，精准子串删（保留行首正文与句读）。
    v2.11：① _lex_left 左扩口号前缀（本文由长腿老阿姨… 的「本文由」残留 ×3）；
    ② 句读后剩余行若仍是广告段（另有…群…欢迎来撩）则并入到行尾；
    ③ 左侧装饰符串（┉✧┉）并入（synthetic-case 整行是 ┉✧ 长腿老阿姨整理 ┉✧ 装饰行）。"""
    res = []
    for m in _H2_ANCHOR.finditer(text):
        s, e = m.start(), m.end()
        ls = text.rfind('\n', 0, s) + 1
        le = text.find('\n', s)
        if le == -1:
            le = len(text)
        tail = text[e:le]
        if not _H2_STRONG.search(tail):
            qm = _H2_QUN.search(tail)
            if not qm or (not _H2_NUM.search(tail[qm.end():])
                          and not _H2_STRONG.search(tail[qm.end():])):
                continue
        end = le
        for i in range(e, le):
            if text[i] in '。！？…':
                if text[i] in '？?':
                    prev = text[i - 1] if i > 0 else ''
                    nxt = text[i + 1] if i + 1 < len(text) else ''
                    if prev in '┉？?' and nxt in '┉？?':
                        continue
                end = i
                break
            if ('\u4e00' <= text[i] <= '\u9fff'
                    and not (_V22_DIG_RE.match(text[i]) or _V22_HOMO_RE.match(text[i])
                             or text[i] in _H2_TAIL_HANZI)):
                end = i
                break
        if end < le:
            rest = text[end + 1:le]
            if re.search(r'[群裙羣君羊]', rest) and re.search(r'[0-9０-９撩]|加', rest):
                end = le
        s2 = _lex_left(text, s, ls)
        _h2_deco = '┉✧～~＝=－—·・*＊﹏ˊ'
        while s2 > ls:
            c = text[s2 - 1]
            if c in _h2_deco:
                s2 -= 1
            elif c in '？?﹖' and s2 - 2 >= ls and (text[s2 - 2] in _h2_deco or text[s2 - 2] in '？?﹖'):
                s2 -= 1
            else:
                break
        if end > s2 and text[s2:end].strip():
            res.append((s2, end))
    return res


_H3_ANCHOR = re.compile(
    r'[老佬姥咾唠耂铑劳牢捞][^\u4e00-\u9fff]{0,1}'
    r'[阿呵锕啊吖aA錒][^\u4e00-\u9fff]{0,1}'
    r'[姨咦胰疑移怡仪夷銕][^\u4e00-\u9fff]{0,1}[裙群君羊]', re.UNICODE)



_H4_ANCHOR = re.compile(
    r'[老佬姥咾唠耂铑劳牢捞锕][^\u4e00-\u9fff]{0,1}'
    r'[阿呵锕啊吖aA錒][^\u4e00-\u9fff]{0,1}'
    r'[姨咦胰疑移怡仪夷銕][^\u4e00-\u9fff]{0,1}'
    r'(?:[政整拯证正挣症征][礼李哩里锂理裡裏][\'\u2019]?'
    r'|[更哽缒耕梗庚][^\u4e00-\u9fff]{0,2}[新薪更]?)', re.UNICODE)

def _h3_seg(text: str):
    res = []
    for m in _H3_ANCHOR.finditer(text):
        ls = text.rfind('\n', 0, m.start()) + 1
        le = text.find('\n', m.end())
        if le == -1:
            le = len(text)
        e = m.end()
        run_ok = False
        anchor_evid = True
        for k in range(0, 9):
            if m.end() + k > le:
                break
            seg_head = text[m.end():m.end() + k]
            if seg_head and not re.fullmatch(r'[\u4e00-\u9fff；;“”"‘’\'，,·・~～*]{1,8}', seg_head):
                break
            e2 = _scan_obf_run(text, m.end() + k)
            run = text[m.end() + k:e2]
            if _v22_gate(run) or (anchor_evid and len(_V22_DIG_RE.findall(run)) >= 2
                                  and not _plain_cjk_run(run)):
                e = _trim_run_tail(text, m.end() + k, e2)
                run_ok = True
                break
            rest = text[m.end() + k:le]
            nd = (len(_V22_DIG_RE.findall(rest))
                  + len(_V22_HOMO_RE.findall(rest)))
            if nd >= 1 and not _plain_cjk_run(rest) and len(rest) <= 8:
                e = le
                run_ok = True
                break
        if run_ok:
            _verb_done = False
            e = _cross_punct_extend(text, e, le)
            s = _lex_left(text, m.start(), ls)
            e = _lex_right(text, e, le)
            _qcloser = {'“': '”', '「': '」', '『': '』'}
            while s > ls:
                c = text[s - 1]
                if c in _V22_WS or (_V22_SEP_RE.match(c) and c not in _V22_SENT):
                    s -= 1
                    continue
                if c in '入加' and (s - 1 == ls or text[s - 2] in _V22_SENT
                                   or text[s - 2] in _V22_HARD):
                    s -= 1
                    continue
                if c in '。．' and s - 2 > ls and text[s - 2] in '入加来來' and not _verb_done:
                    _verb_done = True
                    s -= 2
                    continue
                if c in _qcloser and text[ls:le].count(c) > text[ls:le].count(_qcloser[c]):
                    s -= 1
                    continue
                break
        else:
            s = _lex_left(text, m.start(), ls)
            e = _lex_right(text, m.end(), le)
        if e > s:
            res.append((s, e))
    return res


def _h4_seg(text: str):
    """v2.12 H4：老阿姨+整理+号段（政李'起凌韭四流山起三灵——号段为纯谐音汉字链，无「群」字）。"""
    res = []
    for m in _H4_ANCHOR.finditer(text):
        ls = text.rfind('\n', 0, m.start()) + 1
        le = text.find('\n', m.end())
        if le == -1:
            le = len(text)
        e = _scan_obf_run(text, m.end())
        run = text[m.end():e]
        anchor_evid = True
        nd = (len(_V22_DIG_RE.findall(run)) + len(_V22_HOMO_RE.findall(run)))
        if not (_v22_gate(run) or (anchor_evid and nd >= 2 and not _plain_cjk_run(run))):
            rest = text[m.end():le]
            ndr = (len(_V22_DIG_RE.findall(rest)) + len(_V22_HOMO_RE.findall(rest)))
            if anchor_evid and ndr >= 3 and not _plain_cjk_run(rest):
                run = rest
                e = le
        if _v22_gate(run) or (anchor_evid and nd >= 2 and not _plain_cjk_run(run)):
            e = _trim_run_tail(text, m.end(), e)
            if e < le and text[e] in 'oO' and e > m.end() and _V22_DIG_RE.match(text[e - 1]):
                e += 1
            e = _cross_punct_extend(text, e, le)
            s = _lex_left(text, m.start(), ls)
            while s < m.start() and text[s] in '—－-':
                s += 1
            e = _lex_right(text, e, le)
            if e > s:
                res.append((s, e))
    return res


def _h():
    return [
        _h2_seg,
        _h3_seg,
        _h4_seg,
        re.compile(r'[老佬姥咾唠耂铑劳牢捞][阿呵锕啊吖aA][姨咦胰疑移怡仪夷][整症拯征争政正挣][理李哩里礼丽锂][\'’]?', re.UNICODE),
    ]


rule('H', '老阿姨群/老阿姨整理 变形', _h)


def _i():
    fancy = r'[^\u4e00-\u9fff]'
    mid = r'(?:' + fancy + r'){0,4}'
    chain = (
        r'(?:' + mid + r'整(?:' + mid + r'[理里])?'
        r'|' + mid + r'[ＱQq]' + mid + r'[群裙羣](?![·°.．\-~]?[0-9０-９①-⑨⑴-⒛])'
        r'|' + mid + r'更(?:' + mid + r'[新妏])?'
        r'|' + mid + r'新'
        r'|' + mid + r'制(?:' + mid + r'作)?'
        r'|' + mid + r'作'
        r'|' + mid + r'理)'
    )
    return [
        re.compile(
            r'(?:[0-9A-Za-z]{4,16})?'
            + r'(?:更多[^一-鿿]{0,2}好[^一-鿿]{0,2}文[^一-鿿]{0,2}关注'
               r'|本' + fancy + r'?书' + fancy + r'?由' + fancy + r'?'
               r'|本' + fancy + r'?文' + fancy + r'?为' + fancy + r'?'
               r'|小' + fancy + r'?说' + fancy + r'?由' + fancy + r'?'
               r'|═*➣?企═*➣?鹅═*➣?裙'
               r'|[♡♥✧★☆°·\-]{1,4})?'
            + r'(?:本' + fancy + r'?书' + fancy + r'?为' + fancy + r'?)?'
            + r'(?:(?<![0-9０-９A-Za-z澜蘭笙昇声しぐゞ苼岚丶曻」』】）)])公' + fancy + r'?众' + fancy + r'?[0-9０-９]?[号浩][：:]?)?'
            + r'兰' + mid + r'生' + mid +
            r'(?:' + r'(?:柠' + mid + r'檬)' + r'(?:' + chain + r')*'
            + r'|' + r'(?:' + chain + r')+' + r')'
            + r'(?:[ 　\t]*[A-Za-zÀ-ÿ\ue000-\uf8ff]{1,6}[ 　\t]*(?![qQＱ]?[群羣裙君羊]))?'
            + r'(?:[，,]\s*进[^\u4e00-\u9fff]{0,2}群看更多文[0-9０-９\.·﹒]{6,40})?'
            + r'(?:' + fancy + r'{0,2}(?:公' + fancy + r'?众' + fancy + r'?[0-9０-９]?[号浩]|为您' + fancy + r'{0,2}更新|为您整理|整理))?'
            + r'(?:[\-~]?[♡♥✧★☆°]){0,3}'
            , re.UNICODE,
        ),
    ]


rule('I', '兰×生×柠檬×更新×制作 嵌入水印', _i)


def _j():
    return [
        re.compile(r'[兰蓝篮岚拦栏][生升声笙甥][独读牍犊毒][家佳嘉夹甲][整拯症征争][理李里礼丽][\'’，]?', re.UNICODE),
    ]


rule('J', '兰生独家整理 变形', _j)


def _k():
    return [
        (re.compile(r"['‘’]", re.UNICODE), '"'),
    ]


rule('K', '引号污染 \'→\"', _k)


def _l():
    return [
        re.compile(r'(?:[^\u4e00-\u9fa5，。？……\n]\s*){1,12}来[^\n]{0,120}完整章节[^\n]{0,80}', re.UNICODE),
        re.compile(r'(?:[^\u4e00-\u9fa5，。？……\n]\s*){1,8}(?:看)?[^\n]{0,60}?(?:提醒|想看|的作品)[^\n]{0,80}完整章节[^\n]{0,80}?(?:[\(（][^\(（\)）]{1,30}[\)）][·•．][\(（]?com[\)）])?', re.UNICODE),
        re.compile(
            r'(?<![\d\u4e00-\u9fff])'
            r'来(?:[^\u4e00-\u9fa5，。？……\s]){4,30}'
            r'(?:追更|追[更]?更|更\s*新|追\s*更)[^\n]{0,15}'
            r'(?:本_?小[说說]|本\s*小[说說]|小[说說]|小\s*[说說])'
            r'[^\n]{0,80}',
            re.UNICODE,
        ),
        re.compile(r'来[^\n。！？]{0,40}?(?:追更|更\s*新|追\s*更)[^\n。！？]{0,30}?(?:找文|机器人|秒出)[^\n]{0,40}?秒出文件[^\n]*', re.UNICODE),
    ]


rule('L', '段尾 来xx%学网%看完整章节 + 变体', _l)


_M_DIGITS = r"0-9０-９①-⑨⑩⓪-⓿⒈-⒙㊀-㊉零〇洞令玲磷铃拎另领冷灵一三四五六七八九十百千万"
_M_SEP = (r"；﹔：︰﹕:；,，.．。％%＿_\-|〉》>』】〕〙〘︿^ˇ﹀﹑﹐~～－—・·•※○（()）"
          r"\[\]『「〆﹁﹂￥$#@&＊*＋+＝=／/ \t⁅⁆«»“”】〖〗︵︶;\\")
_M_GARB = "[" + _M_DIGITS + _M_SEP + "]"
_M_WEIRD = r"[﹔︰﹕〉》』】〕〙〘︿^ˇ﹀﹑﹐~～—・·•※○（『「〆﹁﹂￥＄＃＠＆＊＋＝％«；;﹥︶︵⁅⁆﹍＞＜≫≪´∠∧\ufe50-\ufe6b]"
_M_NAD_BODY = r"０-９①-⑨⑩⓪-⓿⒈-⒙㊀-㊉零〇洞令玲磷铃拎另领冷灵一三四五六七八九十百千万"
_M_NAD = r"[" + _M_NAD_BODY + r"]"
_M_G = r"[" + _M_SEP + r"]{0,3}"

_M_QQ_VARIANTS = r"(?:QQ|扣扣|釦釦|叩叩|叩)"
_M_QUN_VARIANTS = r"(?:群|裙|君羊|扣扣群|叩叩群|👗💃|💃👗|👗|💃)"
_M_LIANXI_VARIANTS = r"(?:[请請綪][联连連蓮莲蠊镰][系係细])"

_M_ANCHOR = (r"(?:" + _M_QQ_VARIANTS + r"|本" + _M_G + r"文" + _M_G + r"档|来" + _M_G + r"自" + _M_G + r"群"
             r"|自" + _M_G + r"群|吃" + _M_G + r"肉|R" + _M_G + r"雯|链|"
             + _M_LIANXI_VARIANTS + r")")
_M_KW = (r"(?:追" + _M_G + r"更|看" + _M_G + r"后" + _M_G + r"续|后" + _M_G + r"续|催" + _M_G + r"更"
         r"|新" + _M_G + r"章|看" + _M_G + r"新" + _M_G + r"章|看" + _M_G + r"后" + _M_G + r"文|后" + _M_G + r"文"
         r"|全" + _M_G + r"篇|来" + _M_G + r"自" + _M_G + r"群|链" + _M_G + r"接|追" + _M_G + r"新"
         r"|本" + _M_G + r"小" + _M_G + r"[说說]|更" + _M_G + r"本|追" + _M_G + r"本)")
_M_MAIN = re.compile(
    r"^(?=.*(?:" + _M_ANCHOR + r"|" + _M_KW + r"))"
    r".*?"
    r"(?=" + _M_GARB + r"*" + _M_WEIRD + r")" + _M_GARB + r"{5,}"
    r".*\r?\n?",
    re.MULTILINE,
)
_M_SPECIAL = re.compile(
    r"^(?=.*(?:全" + _M_G + r"篇|R" + _M_G + r"雯))"
    r".*?"
    r"(?=" + _M_GARB + r"*" + _M_NAD + r")" + _M_GARB + r"{6,}"
    r".*\r?\n?",
    re.MULTILINE,
)

_N_STRONG = r"①-⑨⑩⓪-⓿⑴-⒛❶-❿㊀-㊉Ϭ㈠-㈩㊊-㊏𝟎-𝟿Ⅰ-Ⅻⅰ-ⅹ"
_N_FOREIGN = (r"\u0531-\u0587\u13a0-\u13ff\u1400-\u167f\u0400-\u052f\u0370-\u03ff\u01c0-\u024f\u10a0-\u10ff"
              + r"\u25a2-\u25ff\u2af0-\u2aff\u301f\u302a-\u302f\ue000-\uf8ff\u231c-\u231f"
              + r"\u24b6-\u24e9\u2713-\u2793"
              + r"\u0100-\u024f\u00c0-\u00ff\u0a66-\u0a6f\u2ae0-\u2aff\u3021-\u3029")
_N_STRONG = _N_STRONG + _N_FOREIGN
_M_LIANXI = re.compile(
    r"(?:" + _M_LIANXI_VARIANTS + r"|" + _M_QUN_VARIANTS + r"{2,})"
    + r"(?=[^|\n]*[" + _N_STRONG + r"])"
    + r"[^|\n]*(?:\|[^|\n]*)*",
)


_V22_DIG_RE = re.compile('[' + _N_STRONG + _N_FOREIGN + _M_NAD_BODY
                         + r'0-9０-９₀-₉零〇一二三四五六七八九十百千万两壹贰貳參叄弎叁仨肆伍陆柒捌玖]')
_V22_HOMO_STR = ("鸠䫩嗣尓蕶㒃葻罒伶焐午思令玲磷铃拎另领冷灵澪靈潁依溜浏妻亿伊"
                 "柩似迩妩氿彡嘁菱沏汣貮武悟晤梧驷弐泠寺樲杦期祀尔仵龄栖欺砌泗凄戚毿勼司捂陵镹参䀐忢徰撜舞忤"
                 "邇㪊崃唍袺璉穫朂輐拮嗹載蕞噺峮奺扒吧ぺ"
                 "久鹉伞咿徕呤起铱韭韮流留山衫姗散聆淋似思泗临拎领灵馏酒玟駟雁伍珥妏疤凌柶輑纹绫旧鎏舅骑医醫")
_V22_HOMO_RE = re.compile('[' + _V22_HOMO_STR + ']')
_V22_HOMO_RARE_STR = ("鸠䫩嗣尓蕶㒃葻罒澪靈潁氿汣貮弐樲杦毿勼䀐忢徰撜"
                      "邇㪊崃唍袺璉穫朂輐拮嗹載蕞噺峮奺镹铱韭韮")
_V22_RARE_SET = set(_V22_HOMO_RARE_STR)
_V22_LEAD_SET = _V22_RARE_SET | set('QqＱ衤扌亻钅讠忄纟釦鹅衣久群柶圈君羊星联请系伽切丘藤医')
_V22_EVID_RE = re.compile('[' + _N_STRONG + _N_FOREIGN + _V22_HOMO_RARE_STR
                          + _M_WEIRD[1:-1] + '壹贰貳參叄弎叁仨肆伍陆柒捌玖₀-₉' + ']')
_V22_SEP_RE = re.compile('[' + _M_SEP + '、﹒〝〞〻◆◇★☆♠♣♥♦♪♫§∕〃∠∧▽△▲▼―"\'\u3105-\u312f\\\ufe30-\ufe4f\ufe50-\ufe6b]')
_V22_SENT = set('，,。．.!！?？;；…“”‘’«»：')
_V22_BASIC_NUM_RE = re.compile(r'[0-9０-９零一二三四五六七八九十百千万两]')
_V22_POST_OK = set('鲤哩梩理里久ぺ群裙羣〻{巴漆续')
_V22_OBF_RE = re.compile('[' + _N_STRONG + _N_FOREIGN + _V22_HOMO_STR + _M_WEIRD[1:-1]
                         + '壹贰貳參叄弎叁仨肆伍陆柒捌玖₀-₉' + ']')
_V22_HARD = set('。！？…\n\r')
_V22_WS = set(' 　\t')
_V22_LATIN = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ')
_M_SEP_V22 = _M_SEP + '﹒〝〞〻＜＞' + '\\﹛﹜﹝﹞'
_V22_TAIL_WORDS = {'午睡', '灵敏', '焐阑'}


def _scan_obf_run(text: str, start: int) -> int:
    """从 start 向后扫描混淆号段，返回段尾位置（不含）。

    边界：3 连续正文汉字/句读标点（回退到该段起点）、硬标点（。！？…换行）、行尾。
    基础数字出现在连续正文段内视为正文（防「愣了一下」的「一」跨段）。
    段尾的普通字（非数字/谐音/分隔符）会被修剪，仅保留「整理」后缀字族（徰鲤/撜哩…）。
    """
    n = len(text)
    i = start
    plain_cnt = 0
    plain_start = -1
    sep_run = 0
    while i < n:
        c = text[i]
        if c in _V22_HARD:
            break
        if _V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c):
            if (plain_cnt in (1, 2) and _V22_HOMO_RE.match(c)
                    and c not in _V22_RARE_SET and i + 1 < n):
                nc = text[i + 1]
                if not (_V22_DIG_RE.match(nc) or _V22_HOMO_RE.match(nc)
                        or (_V22_SEP_RE.match(nc) and nc not in _V22_SENT)
                        or nc in _V22_WS or nc in _V22_HARD):
                    plain_cnt += 1
                    if plain_cnt >= 3:
                        i = plain_start
                        break
                    i += 1
                    continue
            if not (plain_cnt >= 2 and _V22_BASIC_NUM_RE.match(c)
                    and not _V22_HOMO_RE.match(c)):
                plain_cnt = 0
                sep_run = 0
                i += 1
                continue
        if c in '"\'':
            if plain_cnt >= 1:
                plain_cnt += 1
                sep_run = 0
                if plain_cnt >= 3:
                    i = plain_start
                    break
                i += 1
                continue
            i += 1
            continue
        if _V22_SEP_RE.match(c) and c not in _V22_SENT:
            if sep_run >= 2:
                break
            sep_run += 1
            plain_cnt = 0
            i += 1
            continue
        if _V22_EVID_RE.match(c) and not ('\u4e00' <= c <= '\u9fff'):
            plain_cnt = 0
            i += 1
            continue
        if plain_cnt == 0 and re.match(r'[A-Za-z]', c):
            i += 1
            continue
        if c in _V22_WS:
            i += 1
            continue
        plain_cnt += 1
        sep_run = 0
        if plain_cnt == 1:
            plain_start = i
        elif plain_cnt >= 3:
            i = plain_start
            break
        i += 1
    while i > start:
        c = text[i - 1]
        if (_V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c)
                or (_V22_SEP_RE.match(c) and c not in _V22_SENT) or c in _V22_WS):
            break
        if c in _V22_POST_OK:
            break
        i -= 1
    return i


def _trim_run_tail(text: str, start: int, i: int) -> int:
    """v2.9：数字尾巴修剪（句读+基础数字孤儿对 / 「一/两」成词回退）。
    在 _scan_obf_run 主修剪之后、_v22_gate 门控**之后**调用——若在门控前剪，
    会把段内数字密度剪到门控以下导致整段漏删（球裙勼零…捂两 的「两」被剪后
    只剩 1 个数字类字符，gate 拒收，R5 全盲）。
    - 孤儿对：段尾「，一」类（句读+单个基础数字）且其后是正文汉字/行尾 → 成对回退
      （…妻一⒋，一副… 的「一」属下一句）；其后若为硬标点/数字（.九…零 的「.九」
      属混淆号本身）则不剪。
    - 一/两回退：段尾单个 一/两 后跟正文汉字（完全没两样/一辈子）→ 回退；
      四/五/三 等常为群号尾数（…玖思⒉五在胸腔）不剪（人工审核两向判例，按多数判决）。"""
    while i - start >= 2 and i <= len(text):
        c, c2 = text[i - 1], text[i - 2]
        nc = text[i] if i < len(text) else '\n'
        if (_V22_BASIC_NUM_RE.match(c) and not _V22_HOMO_RE.match(c)
                and c not in '零〇' and c2 in _V22_SENT
                and (nc == '\n' or ('\u4e00' <= nc <= '\u9fff'
                                    and not (_V22_DIG_RE.match(nc) or _V22_HOMO_RE.match(nc))))):
            i -= 2
            continue
        break
    while i > start and i < len(text):
        c, nc = text[i - 1], text[i]
        if (c in '一两' and not _V22_HOMO_RE.match(c)
                and '\u4e00' <= nc <= '\u9fff'
                and not (_V22_DIG_RE.match(nc) or _V22_HOMO_RE.match(nc))
                and not any(p.match(text, i) for p in _SL_POST_RES)):
            i -= 1
            continue
        break
    while i > start and i < len(text) and text[i - 1] == '*' \
            and (i >= len(text) or text[i] in _V22_WS or text[i] == '\n'
                 or '\u4e00' <= text[i] <= '\u9fff'):
        i -= 1
        break
    while i > start and i < len(text):
        c, nc = text[i - 1], text[i]
        if _V22_HOMO_RE.match(c) and (c + nc) in _V22_TAIL_WORDS:
            i -= 1
            continue
        break
    return i


def _cross_punct_extend(text: str, e: int, le: int) -> int:
    """v2.11：广告把全角句读当数字分隔符（synthetic-case 裙６8*5；０；5。7，９。６九,——
    _scan_obf_run 在「。」处停步，号段后半被当成正文残留）。
    门控后调用：切割点起的句读串之后，若到行尾全是「数字/谐音/分隔符/句读」且数字类 ≥2
    → 扩到行尾。正文（含 ≥1 个非数字普通汉字）立即停。"""
    j = e
    while j < le and text[j] in _V22_SENT:
        j += 1
    if j >= le or j == e:
        return e
    k = j
    ndig = 0
    while k < le:
        c = text[k]
        if _V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c):
            ndig += 1
            k += 1
            continue
        if (_V22_SEP_RE.match(c) or c in _V22_SENT) and True:
            k += 1
            continue
        if c in _V22_WS:
            k += 1
            continue
        return e
    if k >= le and ndig >= 2:
        return le
    return e


def _v22_gate(run: str) -> bool:
    """数字密度门控：≥2 数字类字符 且 ≥1 混淆证据字符 且 段长 ≥3。
    v2.3 证据分级：证据=强怪异/异国字母/生僻谐音字/小形式标点/大写数字；
    常用字谐音（另一思妻期寺…）只计数字，防正文「链的另一」凑门控。
    v2.13：纯谐音号段（镹o❸期期酒祀尔仵——synthetic-case 数字全用谐音字拼写）DIG<2 被拒；
    放宽为 DIG≥2 或 (DIG+HOMO≥3 且 EVID≥1)。"""
    if len(run) < 3:
        return False
    nd = len(_V22_DIG_RE.findall(run))
    if nd >= 2:
        return len(_V22_EVID_RE.findall(run)) >= 1
    if nd + len(_V22_HOMO_RE.findall(run)) >= 3:
        return len(_V22_EVID_RE.findall(run)) >= 1
    return False


_SL_PRE_RES = [re.compile(p) for p in (
    r'[每梅苺莓浗鋂毎][日鈤馹][更哽噎梗綆耕庚浭膇缒追]{1,2}[新薪心]?[A-Za-z\u00c0-\u024f\u1400-\u167f]{0,3}[海嗨]?[棠堂䉎]?',
    r'[更哽噎梗綆耕庚浭][新薪心][oOō]?',
    r'[每梅苺莓浗鋂毎][日鈤馹][大][量]',
    r'[稳穏订][定订][更哽噎梗綆耕庚浭][新薪]?',
    r'[小䒕暁晓]?[说說暁説說][㪊]?',
    r'[婆][海][棠废费文FWfw]{0,4}',
    r'[滕腾][訊讯迅]',
    r'[笨苯泍本][纹玟文蚊汶雯][档裆]?[邮铀由油]?',
    r'[乞企岂][额蛾鹅]',
    r'[更哽浭綆][多哆茤陊][好恏来徕䒵]?[纹雯蚊汶玟芠炆文]?[请請綪錆]?[联连連蓮莲蠊镰鎴]?[系係细喺鎴]?[群裙羣]?',
    r'[海嗨][棠堂]?',
    r'[Hh]?[〉》]?[文][追][〃﹒ˇ^]{0,2}[新]',
    r'[追][^\u4e00-\u9fff]{0,2}[更][^\u4e00-\u9fff]{0,2}(?:[整正證][^\u4e00-\u9fff]{0,2}[理里裡裏李][^\u4e00-\u9fff]{0,2})?[本][^\u4e00-\u9fff]{0,2}[文]',
    r'[整正證][理里裡裏李][自]?[老佬姥咾唠][阿呵锕啊吖aA]?[姨咦胰疑移怡仪夷]?',
    r'[入]?[老佬姥咾唠耂铑劳牢捞][^\u4e00-\u9fff]{0,2}[阿呵锕啊吖aA錒][^\u4e00-\u9fff]{0,2}[姨咦胰疑移怡仪夷]',
    r'[补][番帆][追][更]?[徕来]?',
    r'[全][天]?[出][文][机機][器]?[^\u4e00-\u9fff]{0,2}[人]?',
    r'[肉][、.,~～\s]{0,2}[纹文雯][档]?',
    r'[追][^\u4e00-\u9fff]{0,3}[文][呤]?',
    r'[文紋彣雯纹][件建曲][^\u4e00-\u9fff]{0,2}[来來]?[^\u4e00-\u9fff]{0,2}[取曲娶]?[^\u4e00-\u9fff]{0,2}自[自]?',
    r'[滕腾騰駦][訊讯迅訙训]',
    r'[搜][企乞][额蛾鹅][号號]?',
    r'[pP][oO][1lI]?[8Bb]?[资資][源]?',
    r'[pP][oO][pP][oO]',
    r'[sS][tT][aA][rR][pP][oO]',
    r'星星?[(（][▽△●xXw＊]{1,3}[)）]',
    r'[欢歡懽][迎]',
    r'加[管][理]',
    r'[本][书][由]|[本][文][为為]|小[说說][由]',
    r'[更哽浭綆][多哆茤陊][好恏䒵]?[纹雯蚊汶玟芠炆文]?[关][注]',
    r'[陂婆媻泼嘙][^\u4e00-\u9fff]{0,2}[海嗨]?[^\u4e00-\u9fff]{0,2}[Hh][Tt]?[癈废费][文]?',
    r'[連连莲蓮鏈链傤栽載载溨][^\u4e00-\u9fff]{0,2}(?:[載载栽溨傤栽][^\u4e00-\u9fff]{0,2}[追缒膇更]?[新薪心]?|[追缒膇更][^\u4e00-\u9fff]{0,2}[新薪心]?|[新薪心])',
    r'[稳穏穩吻][定订锭腚][更耕梗庚哽][新薪]?',
    r'(?:[zZ2]|[整正證证政拯])[理里裡裏李礼][自]',
    r'[野][熳][生][长]',
    r'[(（][ㄒxX][oO][ㄒxX][)）][进]?[群]?[找]?',
    r'[Pp][.．]?[Oo][文]?[企乞][额蛾鹅][hH][aA][oO]?[码碼]?[、.．]?',
    r'[更][多]?[文]?[请請][进]',
    r'[本][^\u4e00-\u9fff]{0,2}[文][^\u4e00-\u9fff]{0,3}[来][^\u4e00-\u9fff]{0,2}[自]',
    r'[群][号號]',
    r'[哽更][快][哦噢]',
    r'[请請綪錆][联连連蓮莲蠊镰鎴][系係细喺鎴]?[群裙羣]?',
    r'[兰蓝][^\u4e00-\u9fff]{0,1}[生][为為][您]?[整拯]?[理李]?',
    r'[看]?[泼媻波][媻婆泼]?[海嗨塰][癈棠堂]?[废费]?',
    r'[补][番帆翻幡][追][更]?[徕来]?',
    r'[a-zA-Z]?(?:[野吔聲声枽][蠻熳嫚蛮漫]{0,1}[生泩升笙]?[长長張涨]|[蠻熳嫚蛮漫][生泩升笙]?[长長張涨]|[生泩升笙][长長張涨])',
    r'[每梅苺莓浗鋂毎][日鈤馹]',
    r'[小䒕暁晓膮]?[说說暁説說膮哓][㪊]?',
    r'[笨苯泍本][纹玟文蚊汶雯芠炆][档裆]?[邮铀由油甴]?',
    r'[日][日]?[有][荤葷]',
    r'[肉][纹文雯][日]?[更]?',
    r"[求][;；'\"\s]{0,2}[文][;；'\"\s]{0,2}[催][;；'\"\s]{0,2}[更]",
    r'[裙群][主]',
    r'[Hh][;；。]?.[文][追][〃﹒ˇ^~～]{0,2}[新]',
    r'[笨苯泍本][^\u4e00-\u9fff]{0,2}[纹玟文蚊汶雯芠炆][^\u4e00-\u9fff]{0,2}[档裆][^\u4e00-\u9fff]{0,2}',
    r'[群裙羣君羊][整正證证政拯症征挣][理里裡裏李]',
    r'[稳穏穩][定订][追][更]',
    r'[荤葷Hh][纹文雯][来來]?',
    r'[兰蓝][°·.．\-~～\s]{1,3}[生]',
    r'[婆媻嘙泼][海嗨塰][癈棠堂废费文FWfw]{0,4}',
    r'[海][癈废费][婆媻][崃来來徕俄峨]?',
    r'[看]?[泼][媻婆]?[海][癈棠堂]?[废费]?',
    r'[Hh][Tt]?[癈废费][婆媻][崃来徕]?',
    r'[海][癈废费][文]?[陂]?[崃来徕]?',
    r'[陂][Hh][Tt][癈废费][文]?',
    r'[稳穏穩][^\u4e00-\u9fff]{0,2}[定订][吃][肉]',
    r'[日][更][A-Za-zａ-ｚＡ-Ｚ]{0,2}',
    r'[Hh][^\u4e00-\u9fff]{0,2}[文][^\u4e00-\u9fff]{0,2}[追][^\u4e00-\u9fff]{0,2}[新]',
    r'[力][口]',
    r'[医][醫]',
    r'[，,]?[汁][源]',
    r'[管][^\u4e00-\u9fff]{0,2}[理][^\u4e00-\u9fff]{0,2}[号號]',
    r'[QqＱ][uUＵ][nNＮ]',
    r'[Gg][Rr][Oo][Uu][Pp][ ]?',
    r'[兰蓝][//／]{1,2}[生][看][书]',
    r'[追][庚]?[qQ][uU][nN]',
    r'[一]?[肉][雯][日][^\u4e00-\u9fff]{0,2}[更]',
    r'[全整][天][^\u4e00-\u9fff]{0,2}[出][文][^\u4e00-\u9fff]{0,2}[机機][器]?[^\u4e00-\u9fff]{0,2}[人]?',
    r'[更][快][更][：:]',
    r'[看][后][续]',
    r'[海][棠][废][文][日]?[更]?',
    r'[兰蓝][°·.．\-~～\s]{0,3}[生][°·.．\-~～\s]{0,3}[ＱQq]?[°·.．\-~～\s]{0,3}',
    r'[切]',
    r'[丘]',
    r'[伽]',
    r'[小][说][月][群][：:]',
    r'[小][说][永][久][群][：:]',
    r'[视][频][永][久][群][：:]',
    r'[老][aA]?[ 　]?[姨][^\u4e00-\u9fff]{0,2}[扣]?[裙]?',
    r'[QqＱ][^\u4e00-\u9fff]{0,1}[uUＵ][^\u4e00-\u9fff]{0,1}[nNＮ]',
    r'[群][浩号]',
    r'[耽][美]',
    r'[联连連蓮莲蠊镰鎴][系係细喺鎴]',
    r'[资資][源]',
    r'[机機][器]?[人][0-9０-９hH]{1,4}[文][件]',
    r'[2２][4４][小]?[，,]?[时時][A-Za-zＡ-Ｚａ-ｚ]{0,3}[机機][器]?[人]',
    r'[这][^\u4e00-\u9fff]{0,2}[儿兒]',
    r'[扣釦叩抠][^\u4e00-\u9fff]{0,2}',
)]
_SL_POST_RES = [re.compile(p) for p in (
    r'[裙羣]?[整正證][理里裡裏李][追]?[更]?',
    r'[徰撜整證征][鲤哩梩理里裡]',
    r'[稳穏][^\u4e00-\u9fff]{0,2}[定订][^\u4e00-\u9fff]{0,2}[更耕梗庚][^\u4e00-\u9fff]{0,2}[新薪]?[肉]?[闻雯文]?',
    r'[穫获][耳又][朂最][亲薪新斤](?:[斤]?[唍完輐]?[袺结拮]?[璉连嗹]?[載载]?)?',
    r'[蕞最][噺新]?[唍完][結结][嗹连][載载]',
    r'[上][万萬]',
    r'[婆][海][棠废费文FWfw]{0,4}',
    r'[更浭哽][︿﹀〈<~～〻]?\s?[多哆茤恏]?[^\u4e00-\u9fff]{0,2}[好恏肉]?[﹂〻]?[^\u4e00-\u9fff]{0,2}\s?[文雯纹玟蚊][章節]?',
    r'[本][︰:﹤<﹑﹐~～∠∧»≪≫]{0,2}[文][︰:﹤<]?',
    r'[看][\s﹑﹒.．，,﹝（(︰﹕:]{0,2}[后][\s〉》﹑﹒，,︰﹕:]{0,2}[文续章][〃，,]{0,2}',
    r'[しlⓁ][oⓄ〇0][vⓋ][eёⒺ]',
    r'弍[唔悟]',
    r'[qQ][uU][nN]内求[雯文]催更',
    r'[群裙羣]?[每][日]?[吃][肉]',
    r'[天][.．﹒]?[天][.．]?[文]',
    r'[老佬][阿呵]?[姨咦]?[群裙羣]?',
    r'[欢歡][迎][加][入]',
    r'[本][篇]',
    r"[追][﹜﹞)）〉》﹐〃―'\s]{0,2}[更][ˇ^﹀︿~～―﹐﹑＜<]{0,2}[本][＜<﹤︰:﹐，,]{0,2}[文][〻﹒﹒]?",
    r'[追][更]',
    r'[每梅苺莓浗鋂毎][日鈤馹][^\u4e00-\u9fff]{0,2}[更哽噎梗綆耕庚浭膇缒追]{1,2}[新薪心]?[^\u4e00-\u9fff]{0,2}[#＃]?',
    r'[日][更]',
    r'[制][作][。．.]?',
    r'[群裙羣]?[整拯][理里裡裏李][锥追][庚耕更哽]?[。．.]?',
    r'[持][續续][更][新心]?',
    r'[欢歡][迎][瞰看]?[更][多]?[。．.]?',
    r'[出][文][机機][器]?[人][全]?[天]?',
    r'[pP][oO][海嗨]?[棠堂]?[废费][文]?[追]?[更]?[ＱQqｑ]{0,2}[群裙羣]?',
    r'[于]?[0-9０-９]{1,2}[月][0-9０-９]{1,2}[~～]?[日]',
    r'[制][作柞][。．.]?',
    r'[政拯証证][礼李里裡][。．.]?',
    r'[吻稳穏穩][定订锭腚][哽更耕梗庚][新薪心]?',
    r'[群羣裙]?[整正証证政][礼理里裡][追]?[梗更庚]?[。．.]?',
    r'[欢歡懽][迎贏盈]?[看瞰刊]?[更庚哽耕][哆多跢][。．.]?',
    r'[群羣][員员]?[求][文]?[催][更]?[正整][理礼]?',
    r"[求][;；'\"\s]{0,2}[文][;；'\"\s]{0,2}[催][;；'\"\s]{0,2}[更]",
    r'[.．]{0,2}[群裙羣]?[.．]{0,2}[內内][求][心文雯]?[.．]{0,2}[催][.．]{0,2}[更]',
    r'[于]?[0-9０-９]{1,2}[.．]{0,1}[月][0-9０-９]{1,2}[.．]{0,1}[~～]?[日]',
    r'[圈群羣裙]?[整正証证政][礼理里裡裏][追]?[梗更庚]?[。．.]?',
    r'[意]?[看][，,﹑﹒﹐]?[后][.．〃]{0,1}[文续张章][﹔;；]{0,1}',
    r'[群羣裙]?[催][更][\s看]?[»＞>]{0,2}[新]?[»＞>]{0,2}[章]?',
    r"[qQ][^a-zA-Z\u4e00-\u9fff]{0,1}[uU][^a-zA-Z\u4e00-\u9fff]{0,1}[nN][^a-zA-Z\u4e00-\u9fff]{0,1}内[点求][≪‵'\"\s]{0,2}[文雯]?[催][‵'\"\s≪]{0,2}[更]",
    r'[看][»＞>]{0,2}[新][»＞>]{0,2}[章]',
    r'[追][!！]?[更][于]?[0-9０-９:：.．月日~～]{0,12}',
    r'[更哽浭綆][^\u4e00-\u9fff]{0,2}[多哆茤][^\u4e00-\u9fff]{0,2}(?:[好恏肉][^\u4e00-\u9fff]{0,2}(?:[文雯纹玟蚊][篇章節章节]{0,2}|[篇章節章节]{1,2}|[看][小]?[说說]?[篇章節章节]{0,2}|[文雯纹玟蚊]|[看])|[小][说說][好]?[看]?|[篇章節章节])',
    r'[更哽耕梗庚][薪新心]',
    r'[内內][崔催][更][拯][李理]?',
    r'[求][文]?[催][更]?[正整][理礼李]?(?:[本][小][说說])?',
    r'[全][天][自][动動][找][小][说說]',
    r'[看刊瞰][梗耕庚哽更][哆多跢][。．.]?',
    r'[制製][作做柞][。．.]?',
    r'[獲获][耳又]{0,2}[樶最朂][薪新][唍完][纟吉结拮]{0,2}[璉连嗹]{0,2}[載载]?',
    r'[许][多][故][，,]?[事]',
    r'[天][.．﹒]?[天][.．]?[文НN]',
    r'[婆媻嘙泼][海嗨塰][癈棠堂废费文FWfw]{0,4}',
    r'[海][癈废费][婆媻][崃来徕俄峨]?',
    r'[看]?[泼][媻婆]?[海][癈棠堂]?[废费]?',
    r'[上尚][万萬腕]?',
    r'[＜<]{0,2}[看]?[后][文续章]',
    r'[新][»＞>]{0,2}[章]',
    r'[看][庚耕哽更][哆多跢][。．.]?',
    r'[.．、~～\-]{0,2}[整正證][^\u4e00-\u9fff]{0,1}[理里裡裏李]',
    r'[凌綆哽]?[薪新]',
    r'[更哽耕梗庚][快][哦噢][。．.]?',
    r'ヽ?[（(]?[▽△]?[)）]?ノ?[祝][你][平][安][!！]?[εe]{0,4}[()（）]{0,3}',
    r'[每][日]?[<＜\[\[]?[稳穏][>＞\]\]]?[定订][·﹒.]{0,2}[更耕梗庚][·﹒.]{0,2}[肉][闻雯文]?',
    r'[更][^\u4e00-\u9fff]{0,2}[多][^\u4e00-\u9fff]{0,2}[资資][^\u4e00-\u9fff]{0,2}[源][^\u4e00-\u9fff]{0,3}',
    r'[每][日][好][资資][源][^\u4e00-\u9fff]{0,2}',
    r'[资資][源][^\u4e00-\u9fff]{0,2}',
    r'[意][有][後后][绪續]?',
    r'[还][^\u4e00-\u9fff]{0,3}[有][^\u4e00-\u9fff]{0,3}[福][^\u4e00-\u9fff]{0,3}[利][^\u4e00-\u9fff]{0,2}',
    r'[追][全][本]',
    r'[巴][伍][衣][久][，,]?',
    r'[群羣][員员]?[求][文]?[催][更]?[新]?[章]?',
    r'[看][侯后][文]',
    r'[儿][捂]',
    r'[巴]?[整][鲤哩]',
    r'[每][日][^\u4e00-\u9fff]{0,2}[稳穏][^\u4e00-\u9fff]{0,2}[定订][^\u4e00-\u9fff]{0,2}[更][^\u4e00-\u9fff]{0,2}[肉][闻文雯]?',
    r'[∗＊]?[每][日][吃][肉][´\u00b4]?',
    r'[追][，,]?[更]',
    r'[进][入][资資][源][群][，,]?',
    r'[裙群][，,][还][有][其][他][hH]?[篇]?',
    r'[，,]?[群][，,]?[稳][定][埂梗更庚][Hh]',
    r'[更][^\u4e00-\u9fff]{0,2}[多][^\u4e00-\u9fff]{0,2}[好]?[^\u4e00-\u9fff]{0,2}[文]?[，,]?[等]?[你]?[ 　]?[来來]?[ 　]?[撩][~～]?',
    r'[追][更][·﹒.]{0,2}=[0-9０-９]{1,4}[每][\\]?[日][更]?[新]?[}]?',
    r'[=][0-9０-９]{2,6}[每][\\]?[日][更]?[新]?[}]?',
)]


_R2_DATE_RE = re.compile(
    r'[0-9０-９]{1,4}[-/－／.．年月][0-9０-９]{1,3}[-/－／.．年月日]{1,2}[0-9０-９]{0,3}')

_R2_WATERMARK_CJK = set('兰澜蘭籣笙昇声苼岚曻しぐゞ丶呏阑生')
_R2_HOMO_CJK = set(_V22_HOMO_STR) | set(
    '零〇一二三四五六七八九十百千万两壹贰貳參弎叁仨肆伍陆柒捌玖久酒灸') | _R2_WATERMARK_CJK
_R2_KAOMO_RE = re.compile(r'[（(][^）)\n]{0,12}[)）]')
_R2_KAOMO_SYM = re.compile(r'[=·ω°△▽*╯╰Σ∩︴|／^_－—○｀′≡▽]')


def _r2_content_skip(inner: str) -> bool:
    """R2【】内容是否应跳过（颜文字/非谐音CJK/纯符号）。"""
    if _R2_KAOMO_RE.search(inner):
        return True
    if len(_R2_KAOMO_SYM.findall(inner)) >= 2:
        return True
    for ch in inner:
        if '\u4e00' <= ch <= '\u9fff' and ch not in _R2_HOMO_CJK:
            return True
    if not re.search(r'[0-9０-９零〇一二三四五六七八九十百千壹贰參弎叁仨肆伍陆柒捌玖'
                     r'①-⑨⑴-⒛❶-❿㊀-㊉⓪-⓿]', inner):
        return True
    return False


def _plain_cjk_run(seg: str) -> bool:
    """v2.12：段内是否含 ≥4 连续「普通」汉字（非数字/非谐音字）——正文判别。
    数字汉字（二三六九…）与谐音字（灵铃期…）不算普通字，纯广告行（筘扣裙二三；翎+六九《三九六）
    无 4 连普通汉字 → 行尾句读归广告；正文行（…插入了小瓷的穴内）有 → 句读归正文。"""
    run = 0
    for ch in seg:
        if ('\u4e00' <= ch <= '\u9fff'
                and not _V22_DIG_RE.match(ch) and not _V22_HOMO_RE.match(ch)):
            run += 1
            if run >= 4:
                return True
        else:
            run = 0
    return False


def _lex_left(text: str, s: int, ls: int) -> int:
    """向左扩展口号词族：从混淆段/锚点起点 s 起，越过分隔符后逐短语 fullmatch 回退。
    ls = 行首。分隔符不含句读（。，。！？不跨越），防把正文句吃进。
    v2.3.1：单个前导字符跳过集 = 生僻证据字 + 混淆证据字符（ǬɊԚ…）+ Q/q/Ｑ + 广告自带
    左侧符号（《【〈『\\￥$｛{——人工审核公开测试 6 条含这些前导符）。
    闭合符（」』】）按行内配对判断：无配对 opener（广告自带）才并入，
    与正文【】/「」配对的是正文结构，保留（示例 sample-line vs sample-line 人工审核两向判例）。"""
    _skip1 = _V22_RARE_SET | set('QqＱ《【〈『\\￥$｛{入鹅球兰笙肉抠进搜筘咾錒騰駦绮乞企訊训扣叩釦星()（）←]|?伽切丘藤医')
    _closer_opener = {'」': '「', '』': '『', '】': '【', '》': '《'}
    s0 = s
    while True:
        j = s
        j_orig = s
        while j > ls and text[j - 1] != '\n' and (
                (_V22_SEP_RE.match(text[j - 1]) and text[j - 1] not in _V22_SENT
                 and not (text[j - 1] == '—' and j - 2 >= ls and text[j - 2] == '—'))
                or (_V22_EVID_RE.match(text[j - 1])
                    and not ('\u4e00' <= text[j - 1] <= '\u9fff'))):
            j -= 1
        moved = False
        _jj = [j, j_orig, s + 1]
        for jj in _jj:
            for span in range(16, 1, -1):
                k = jj - span
                if k < ls:
                    continue
                for pat in _SL_PRE_RES:
                    m = pat.match(text, k, jj)
                    if m and m.end() == jj:
                        s = k
                        moved = True
                        break
                if moved:
                    break
            if moved:
                break
        if moved:
            continue
        if s > ls:
            c = text[s - 1]
            if c in ')）':
                k3 = s - 1
                depth = 0
                moved_km = False
                while k3 > ls and s - k3 <= 10:
                    if text[k3] in ')）':
                        depth += 1
                    elif text[k3] in '(（':
                        depth -= 1
                        if depth == 0:
                            inner = text[k3 + 1:s - 1]
                            if len(inner) <= 6 and not re.search(r'[\u4e00-\u9fff]{2}', inner):
                                s = k3
                                moved_km = True
                            break
                    k3 -= 1
                if moved_km:
                    continue
            if c in '，,:：':
                hit_c = False
                for span in range(16, 1, -1):
                    k2 = s - 1 - span
                    if k2 < ls:
                        continue
                    for pat in _SL_PRE_RES:
                        m2 = pat.match(text, k2, s - 1)
                        if m2 and m2.end() == s - 1:
                            s = k2
                            hit_c = True
                            break
                    if hit_c:
                        break
                if hit_c:
                    continue
            if (_V22_SEP_RE.match(c) and c not in _V22_SENT and c not in _V22_WS
                    and c not in '】》』」）)' and s - 1 > ls):
                k4 = s - 1
                while k4 > ls and (_V22_DIG_RE.match(text[k4 - 1])
                                   or _V22_HOMO_RE.match(text[k4 - 1])
                                   or (_V22_SEP_RE.match(text[k4 - 1])
                                       and text[k4 - 1] not in _V22_SENT)):
                    k4 -= 1
                if k4 < s - 1 and (k4 == ls or text[k4 - 1] in _V22_SENT
                                   or text[k4 - 1] in _V22_HARD):
                    s = k4
                    continue
            if c in '，,' and s - 2 > ls:
                c2 = text[s - 2]
                if _V22_DIG_RE.match(c2) or _V22_HOMO_RE.match(c2):
                    c3 = text[s - 3] if s - 3 >= ls else '\n'
                    if (_V22_DIG_RE.match(c3) or _V22_HOMO_RE.match(c3)
                            or c3 in _V22_SENT or c3 in _V22_HARD or s - 3 < ls):
                        s -= 1
                        continue
            if c in _V22_WS:
                k2 = s - 1
                while k2 > ls and text[k2 - 1] in _V22_WS:
                    k2 -= 1
                if k2 > ls and text[k2 - 1] in _skip1:
                    s = k2 - 1
                    continue
                if k2 > ls and (_V22_DIG_RE.match(text[k2 - 1])
                                or _V22_HOMO_RE.match(text[k2 - 1])):
                    k3 = k2
                    while k3 > ls and (_V22_DIG_RE.match(text[k3 - 1])
                                       or _V22_HOMO_RE.match(text[k3 - 1])
                                       or text[k3 - 1] in _V22_WS
                                       or (_V22_SEP_RE.match(text[k3 - 1])
                                           and text[k3 - 1] not in _V22_SENT)):
                        k3 -= 1
                    if k3 == ls or text[k3 - 1] in _V22_SENT or text[k3 - 1] in _V22_HARD \
                            or not ('\u4e00' <= text[k3 - 1] <= '\u9fff'):
                        s = k3
                        continue
            ok = c in _skip1 or _V22_EVID_RE.match(c)
            if ok and c == '—' and s - 2 >= ls and text[s - 2] == '—':
                ok = False
            if not ok and (_V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c)):
                k2 = s - 1
                while k2 > ls and (_V22_DIG_RE.match(text[k2 - 1])
                                   or _V22_HOMO_RE.match(text[k2 - 1])
                                   or (_V22_SEP_RE.match(text[k2 - 1])
                                       and text[k2 - 1] not in _V22_SENT)
                                   or text[k2 - 1] in _V22_WS):
                    k2 -= 1
                if k2 == ls or text[k2 - 1] in _V22_SENT or text[k2 - 1] in _V22_HARD \
                        or not ('\u4e00' <= text[k2 - 1] <= '\u9fff'):
                    ok = True
            if c in _closer_opener:
                le = text.find('\n', s)
                if le == -1:
                    le = len(text)
                if text[ls:le].count(_closer_opener[c]) >= text[ls:le].count(c):
                    ok = False
            if ok:
                s -= 1
                continue
        if s0 != s and s > ls:
            j = s
            while j > ls and text[j - 1] != '\n' and (
                    (_V22_SEP_RE.match(text[j - 1]) and text[j - 1] not in _V22_SENT
                     and text[j - 1] not in _V22_WS
                     and not (text[j - 1] == '—' and j - 2 >= ls and text[j - 2] == '—'))
                    or (text[j - 1] == '.' and (j - 1 == ls
                                                or (text[j - 2] in _V22_SENT and text[j - 2] != '.')
                                                or text[j - 2] in _V22_HARD))):
                j -= 1
            if j < s and (j == ls or text[j - 1] in _V22_SENT or text[j - 1] in _V22_HARD):
                s = j
        return s


def _lex_right(text: str, e: int, le: int) -> int:
    """向右扩展口号词族（含尾随终止句读——仅当其后到行尾只剩空白）。le = 行尾。
    v2.3.1：终止句读只在「本调用确实吃到口号词族」时才并入（整理。/婆海棠费。）；
    半角句点 '.' 例外（人工审核公开测试：稳定更扣扣圈…寺二. 的 '.' 属广告自带）。
    纯数字串行尾的 。！？（Q群…⑸。）不并入——人工审核多数保留其作正文句读。"""
    phrase_hit = False
    for span in range(10, 1, -1):
        k = e - span
        if k < 0:
            continue
        hit = False
        for pat in _SL_POST_RES:
            m = pat.match(text, k, le)
            if m and m.end() > e:
                e = m.end()
                phrase_hit = True
                hit = True
                break
        if hit:
            break
    while e < le:
        best = 0
        for pat in _SL_POST_RES:
            m = pat.match(text, e, le)
            if m and m.end() - e >= 2 and m.end() > e + best:
                best = m.end() - e
        if best:
            e += best
            phrase_hit = True
            continue
        if _V22_EVID_RE.match(text[e]) and not ('\u4e00' <= text[e] <= '\u9fff'):
            j4 = e
            while j4 < le and (_V22_EVID_RE.match(text[j4])
                               and not ('\u4e00' <= text[j4] <= '\u9fff')):
                j4 += 1
            best4 = 0
            for pat in _SL_POST_RES:
                m4 = pat.match(text, j4, le)
                if m4 and m4.end() - j4 >= 2 and m4.end() > j4 + best4:
                    best4 = m4.end() - j4
            if best4:
                e = j4 + best4
                phrase_hit = True
                continue
        if text[e] in _V22_WS:
            j = e
            while j < le and text[j] in _V22_WS:
                j += 1
            best2 = 0
            for pat in _SL_POST_RES:
                m = pat.match(text, j, le)
                if m and m.end() - j >= 2 and m.end() > j + best2:
                    best2 = m.end() - j
            if best2:
                e = j + best2
                phrase_hit = True
                continue
        if text[e] in '…！？' and e + 1 < le:
            k2 = e + 1
            ok2 = True
            while k2 < le:
                c = text[k2]
                if (_V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c)
                        or (_V22_SEP_RE.match(c) and c not in _V22_SENT)):
                    k2 += 1
                else:
                    ok2 = False
                    break
            if ok2:
                e = le
                phrase_hit = True
                continue
        if _V22_SEP_RE.match(text[e]) and text[e] not in _V22_SENT:
            j = e
            while j < le and _V22_SEP_RE.match(text[j]) and text[j] not in _V22_SENT:
                j += 1
            hit = False
            for pat in _SL_POST_RES:
                m = pat.match(text, j, le)
                if m and m.end() - j >= 2:
                    e = m.end()
                    hit = True
                    phrase_hit = True
                    break
            if hit:
                continue
        if text[e] in '，,':
            j2 = e + 1
            while j2 < le and text[j2] in _V22_WS:
                j2 += 1
            hit = False
            for pat in _SL_POST_RES:
                m2 = pat.match(text, j2, le)
                if m2 and m2.end() - j2 >= 2 and (
                        re.search(r'[A-Za-z]', m2.group())
                        or m2.group()[:1] in '欢歡'
                        or m2.group()[:2] in ('全天', '稳定', '更多', '歡迎', '许多')):
                    e = m2.end()
                    hit = True
                    phrase_hit = True
                    break
            if hit:
                continue
            if e + 2 == le and _V22_DIG_RE.match(text[e + 1]):
                e = le
                phrase_hit = True
                continue
            if e + 1 < le and _V22_DIG_RE.match(text[e + 1]):
                k3 = e + 1
                while k3 < le and (_V22_DIG_RE.match(text[k3])
                                   or _V22_HOMO_RE.match(text[k3])
                                   or (_V22_SEP_RE.match(text[k3])
                                       and text[k3] not in _V22_SENT)):
                    k3 += 1
                if k3 < le and any(p.match(text, k3, le) and p.match(text, k3, le).end() >= le - 1
                                   for p in _SL_POST_RES):
                    e = le
                    phrase_hit = True
                    continue
        if text[e] in _V22_LATIN:
            bestL = 0
            for pat in _SL_POST_RES:
                mL = pat.match(text, e + 1, le)
                if mL and mL.end() - (e + 1) >= 2 and mL.end() > (e + 1) + bestL:
                    bestL = mL.end() - (e + 1)
            if bestL:
                e = (e + 1) + bestL
                phrase_hit = True
                continue
        break
    if not phrase_hit:
        for span in range(10, 1, -1):
            k = e - span
            if k < 0:
                continue
            if any(p.match(text, k, e) and p.match(text, k, e).end() == e
                   for p in _SL_POST_RES):
                phrase_hit = True
                break
    if e < le and text[e] == '…':
        rest = text[e + 1:le]
        nd5 = (len(_V22_DIG_RE.findall(rest)) + len(_V22_HOMO_RE.findall(rest)))
        if (nd5 >= 2 or (nd5 >= 1 and re.search(r'[群裙羣催更看新]', rest))) \
                and not _plain_cjk_run(rest):
            return le
    if e < le and (_V22_EVID_RE.match(text[e]) or text[e] in '￣〻﹏✧') and not ('\u4e00' <= text[e] <= '\u9fff'):
        k3 = e
        n3 = 0
        while k3 < le and n3 < 4 and (_V22_EVID_RE.match(text[k3])
                                       or text[k3] in '«»‵≪≫＜￣〻﹏✧'):
            k3 += 1
            n3 += 1
        while k3 < le and text[k3] in _V22_WS:
            k3 += 1
        if k3 >= le:
            return k3
    if e < le and text[e] == '…':
        rest = text[e + 1:le]
        nd5 = (len(_V22_DIG_RE.findall(rest)) + len(_V22_HOMO_RE.findall(rest)))
        if (nd5 >= 2 or (nd5 >= 1 and re.search(r'[群裙羣催更看新]', rest))) \
                and not _plain_cjk_run(rest):
            return le
    if e < le and (_V22_EVID_RE.match(text[e]) or text[e] in '￣〻﹏✧') and not ('\u4e00' <= text[e] <= '\u9fff'):
        k3 = e
        n3 = 0
        while k3 < le and n3 < 4 and (_V22_EVID_RE.match(text[k3])
                                       or text[k3] in '«»‵≪≫＜￣〻﹏✧'):
            k3 += 1
            n3 += 1
        while k3 < le and text[k3] in _V22_WS:
            k3 += 1
        if k3 >= le:
            return k3
    if e < le and text[e] in '。．.!！?？':
        k2 = e + 1
        while k2 < le and text[k2] in _V22_WS:
            k2 += 1
        if k2 >= le:
            j3 = e - 1
            while j3 >= 0 and j3 > e - 60 and text[j3] not in _V22_SENT \
                    and text[j3] not in _V22_HARD and text[j3] != '\n':
                j3 -= 1
            if phrase_hit or not _plain_cjk_run(text[j3 + 1:e]):
                return e + 1
    if not phrase_hit:
        k = e
        while k < le and text[k] in _V22_WS:
            k += 1
        if k < le and text[k] == '.' and k + 1 >= le:
            return k + 1
        if (k < le and text[k] == '.' and k + 2 >= le
                and (_V22_DIG_RE.match(text[k + 1]) or _V22_HOMO_RE.match(text[k + 1]))):
            return k + 2
        if k < le and text[k] in '、＜【{←"?？':
            k2 = k + 1
            while k2 < le and text[k2] in _V22_WS:
                k2 += 1
            if k2 >= le:
                return k + 1
        if k < le and text[k] in '。．.!！?？':
            j3 = k - 1
            while j3 >= 0 and j3 > k - 60 and text[j3] not in _V22_SENT \
                    and text[j3] not in _V22_HARD and text[j3] != '\n':
                j3 -= 1
            if not _plain_cjk_run(text[j3 + 1:k]):
                k2 = k + 1
                while k2 < le and text[k2] in _V22_WS:
                    k2 += 1
                if k2 >= le:
                    return k + 1
        if k < le and text[k] in '新文章節更':
            k2 = k + 1
            while k2 < le and text[k2] in _V22_WS:
                k2 += 1
            if k2 >= le:
                return k + 1
        return e
    k = e
    while k < le and text[k] in _V22_WS:
        k += 1
    if k < le and text[k] in '。．.!！?？、':
        k2 = k + 1
        while k2 < le and text[k2] in _V22_WS:
            k2 += 1
        if k2 >= le:
            return k + 1
    return e


_V22_SLOGAN_RE = re.compile(
    r"(?:[追看全催日来][﹒〝〞〻~～－—・·]*)?"
    r"[更篇新][^，。！？\n]{0,2}?"
    r"(?:本[^，。！？\n]{0,2}文[^，。！？\n]{0,2}档?[﹒〝〞〻~～）)】」』]?)?"
)


def _slogan_extend(text: str, e: int) -> int:
    """段尾若紧跟「追更/本文」类广告口号（含混淆分隔符），并入删除。"""
    m = _V22_SLOGAN_RE.match(text, e)
    if m and m.end() - e <= 12:
        seg = m.group()
        if (_V22_SEP_RE.search(seg) or _V22_OBF_RE.search(seg)
                or re.search(r'本[^，。！？\n]{0,2}文', seg)):
            return m.end()
    return e


_M2_ANCHOR = re.compile(
    r"(?:(?:QQ|扣[" + _M_SEP_V22 + r"]{0,2}扣|叩叩|叩|[扣釦叩抠][扣釦叩抠])[" + _M_SEP_V22 + r"]{0,2}[a-zA-Z_＇']{0,2}[群圈👗💃]"
    r"|[ＱQq][" + _M_SEP_V22 + r"]{0,2}[ＱQq]?[" + _M_SEP_V22 + r"]{0,2}[群羣圈]"
    r"|[ＱQq][君羊]"
    r"|小说[群君羊]"
    r"|全天出文機器人|全天出文机器人"
    r"|[滕腾騰駦藤][訊讯迅訙训][" + _M_SEP_V22 + r"]{0,2}[群羣]"
    r"|(?<![R肉纹文雯])[扣釦叩抠口][" + _M_SEP_V22 + r"]{0,2}[叩]?[" + _M_SEP_V22 + r"]{0,2}[群圈裙羣]"
    r"|本[" + _M_SEP_V22 + r"]{0,3}文[" + _M_SEP_V22 + r"]{0,3}档[" + _M_SEP_V22 + r"]{0,3}来[" + _M_SEP_V22 + r"]{0,3}自[" + _M_SEP_V22 + r"]{0,3}群"
    r"|本[" + _M_SEP_V22 + r"]{0,3}文[" + _M_SEP_V22 + r"]{0,3}档"
    r"|来[" + _M_SEP_V22 + r"]{0,3}自[" + _M_SEP_V22 + r"]{0,3}群"
    r"|自[" + _M_SEP_V22 + r"]{0,3}群"
    r"|吃[" + _M_SEP_V22 + r"]{0,2}肉(?:[qQ][uU][nN]|群)?"
    r"|全[" + _M_SEP_V22 + r"]{0,3}篇"
    r"|(?<![鹅球兰笙肉文说訊讯扣釦叩ＱQq自群n])[群羣][" + _M_SEP_V22 + r"]{0,2}[0-9０-９①-⑨⑴-⒛㊀-㊉]"
    r"|R[" + _M_SEP_V22 + r"]{0,2}雯|链)"
    + r"|[文紋彣雯纹][" + _M_SEP_V22 + r"]{0,2}[件建曲娶][" + _M_SEP_V22 + r"]{0,2}[取曲][" + _M_SEP_V22 + r"]{0,2}自[自]?"
    r"|群[号號]"
    r"|叩[叩]?[君羊]"
    r"|[ⓠⓆ][" + _M_SEP_V22 + r"]{0,2}[ⓤⓊ][" + _M_SEP_V22 + r"]{0,2}[:：]?[" + _M_SEP_V22 + r"]{0,2}[ⓝⓃ]"
    r"|popo[群裙]"
    r"|po18资源[群裙]"
    r"|starpopo[群裙]"
)


def _m2_seg(text: str):
    """M v2.2：锚点（QQ群/扣扣群/本文档/来自群/吃肉[qun]/全篇/R雯/链）+ 混淆号段。
    v2.3：命中后左右扩展口号词族（每日大量婆海FW：/稳定更/整理。…）。
    v2.11：① 门控后跨句读扩段（_cross_punct_extend，广告把全角句读当数字分隔符）；
    ② 锚点前单字 叩/扣/抠 并入（synthetic-case 抠\叩群、synthetic-case 叩〉叩群）。"""
    res = []
    for m in _M2_ANCHOR.finditer(text):
        k2_chain = None
        e = _scan_obf_run(text, m.end())
        run = text[m.end():e]
        if _v22_gate(run):
            e = _trim_run_tail(text, m.end(), e)
            e = _slogan_extend(text, e)
            if '（' in run and '）' not in run:
                k = text.find('）', e)
                if k != -1 and k - e <= 12:
                    e = k + 1
                    if e < len(text) and text[e] in '。．':
                        e += 1
            ls = text.rfind('\n', 0, m.start()) + 1
            le = text.find('\n', e)
            if le == -1:
                le = len(text)
            s = _lex_left(text, m.start(), ls)
            grp = m.group()
            if len(grp) >= 3 and s >= 3 and text[s - 3:s] == grp[:3] == grp[:3]:
                s -= 3
            if re.match(r'(?:QQ|扣|釦|叩|Ｑ|Q|q)', m.group()):
                while s > ls and text[s - 1] in '加来來入去快':
                    s -= 1
            if m.group().startswith('吃'):
                k = m.start()
                while k > ls and (_V22_SEP_RE.match(text[k - 1])
                                  and text[k - 1] not in _V22_SENT):
                    k -= 1
                if k - 2 >= ls and re.fullmatch(r'[稳穏穩][定订]', text[k - 2:k]):
                    s = min(s, k - 2)
            if m.group() == '链':
                k2 = m.end()
                while k2 < e and (text[k2] in _V22_SENT or text[k2] in _V22_WS):
                    k2 += 1
                k2_chain = k2
                if re.fullmatch(r'[0-9０-９\s（）()，,。.：:；;…\-—–%~%/，、！？…]*', text[k2:e]):
                    continue
                if k2 > m.end():
                    s = max(s, k2)
            s = _lex_left(text, s, ls)
            while s > ls and text[s - 1] in '叩扣抠' and (
                    s - 1 == ls or text[s - 2] in _V22_SENT or text[s - 2] in _V22_WS
                    or (_V22_SEP_RE.match(text[s - 2]) and text[s - 2] not in _V22_SENT)):
                s -= 1
            e = _cross_punct_extend(text, e, le)
            e = _lex_right(text, e, le)
            if k2_chain is not None:
                s = max(s, k2_chain)
            res.append((s, e))
    return res


def _m():
    return [_m2_seg]


rule('M', '混淆群号广告 QQ群/扣扣群/本文档来自群/吃肉qun[混淆数字] (锚点起子串删保留正文)', _m)


def _q_seg(text: str):
    res = []
    for m in _M_LIANXI.finditer(text):
        ls = text.rfind('\n', 0, m.start()) + 1
        s = _lex_left(text, m.start(), ls)
        if s < m.start():
            res.append((s, m.end()))
        else:
            res.append((m.start(), m.end()))
    return res


def _q():
    return [_q_seg]


rule('Q', '请联系/群emoji 弱信号 (仅候选不自动删)', _q)


_N_WEIRD = r"①-⑨⑩⓪-⓿⑴-⒂⒈-⒛❶-❿㊀-㊉Ϭ㈠-㈩㊊-㊏𝟎-𝟿Ⅰ-Ⅻⅰ-ⅹ\u24b6-\u24e9\u2713-\u2793"


def _n_seg(text: str):
    """N v2.2：返回最小怪异簇子串 [(s,e), …]（collect-only，供人工勾选）。
    v2.3：左扫字符类扩 Q/q/Ｑ/生僻证据字/部首字（q衤君…拆字）；命中后词族左右扩展
    （鋂日哽薪小说㪊/每日大量婆海FW：…——示例公开测试 14 条前缀口号漏删）。"""
    res = []
    strongs = list(re.finditer('[' + _N_WEIRD + ']', text))
    if len(strongs) < 1:
        return res
    for m in strongs:
        ls = text.rfind('\n', 0, m.start()) + 1
        le = text.find('\n', m.start())
        if le == -1:
            le = len(text)
        line = text[ls:le]
        if not re.search(r'[\u4e00-\u9fff](?:[^\u4e00-\u9fff]?[\u4e00-\u9fff]){3}', line):
            continue
        s = m.start()
        while s > ls and text[s - 1] != '\n' and text[s - 1] not in '。！？…“「『”』」' and (
                _V22_DIG_RE.match(text[s - 1]) or _V22_HOMO_RE.match(text[s - 1])
                or _V22_SEP_RE.match(text[s - 1])
                or text[s - 1] in _V22_LEAD_SET):
            if text[s - 1] == '—' and s - 2 >= ls and text[s - 2] == '—':
                break
            s -= 1
        e = _scan_obf_run(text, m.start())
        e = _trim_run_tail(text, m.start(), e)
        for _ in range(2):
            e = _lex_right(text, e, le)
            e2 = _scan_obf_run(text, e)
            if e2 > e and (len(_V22_DIG_RE.findall(text[e:e2]))
                           + len(_V22_HOMO_RE.findall(text[e:e2]))) >= 2:
                e = _trim_run_tail(text, e, e2)
            else:
                break
        if e > s:
            s = _lex_left(text, s, ls)
            e = _lex_right(text, e, le)
            while s > ls and text[s - 1] in '来加进搜' and (
                    s - 1 == ls or text[s - 2] in _V22_SENT or text[s - 2] in _V22_HARD):
                s -= 1
            if e > s:
                if (s > ls and e > s
                        and _V22_HOMO_RE.match(text[s]) and text[s] not in _V22_RARE_SET
                        and '\u4e00' <= text[s - 1] <= '\u9fff'
                        and not (_V22_DIG_RE.match(text[s - 1]) or _V22_HOMO_RE.match(text[s - 1])
                                 or _V22_SEP_RE.match(text[s - 1])
                                 or text[s - 1] in _V22_LEAD_SET)):
                    s += 1
                cluster = text[s:e]
                if not re.search(r'[\u4e00-\u9fff]', cluster) \
                        and not _V22_DIG_RE.search(cluster) \
                        and not _V22_HOMO_RE.search(cluster):
                    continue
                n_strong = len(re.findall('[' + _N_WEIRD + ']', cluster))
                if n_strong >= 2 or len(cluster) >= 4 or (
                        len(cluster) == 1 and cluster in '①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳'
                        and s == ls):
                    res.append((s, e))
    return res


def _n():
    return [_n_seg]


rule('N', '强怪异字符密度门控 (最小怪异簇子串提案，仅候选不自动删)', _n)


_V_PAT = re.compile(
    r"^[ 　\t]*"
    r"(?=[ 　\t]*[" + _N_WEIRD + _M_NAD_BODY + r"0-9])"
    r"(?=[^\n]*[" + _N_WEIRD + r"])"
    r"(?![^\n]*[\u4e00-\u9fff]{4})"
    r"(?![^\n]*(?:[①-⑨⑴-⒛㊀-㊉]\s*[\u4e00-\u9fff]{1,4}[,，、]\s*){1,}[①-⑨⑴-⒛㊀-㊉])"
    r"(?=(?:[^\n]*[" + _N_WEIRD + r"]){3,})"
    r"(?=[^\n]{8,})"
    r"[ 　\t]*[^\n【]*"
    r"(?=[【\n]|$)",
    re.MULTILINE,
)


def _v():
    return [_V_PAT]


rule('V', '行级强怪异密度无汉字版本 (纯广告水印整段删)', _v)


_W_KW = re.compile(
    r'[追][^\u4e00-\u9fff]{0,3}[更新文]'
    r'|每日|日更|更[^\u4e00-\u9fff]{0,2}[新]|求文|催更|福利|资源'
    r'|[整正證证][^\u4e00-\u9fff]{0,2}[理里裡裏李]'
    r'|关注|联系|公众号'
    r'|海棠|废文|po18|popo|starpopo|群号|群主|裙|群|羣|君羊|叩叩|扣扣'
    r'|QQ|ＱＱ|[qQ][^\u4e00-\u9fff]{0,2}[uUＵ][^\u4e00-\u9fff]{0,2}[nNＮ]')
_W_EVID_HARD = re.compile(
    r'[\u0530-\u058f\u0400-\u052f\u0370-\u03ff\u13a0-\u13ff\u1400-\u167f'
    r'\u0100-\u024f\u249c-\u24e9\ue000-\uf8ff]')
_W_SIGN = re.compile(r'[整正證证][^\u4e00-\u9fff]{0,2}[理里裡裏李]|更新|追更|追新|日更|[0-9０-９]{1,2}[月][0-9０-９]{1,2}[日]')
_W_DATE_HANZI = set('年月日时分秒号点')

_RISK_PROFILE = 'conservative'
_W_LIB_CLASS = ''

_W_STRONG_KW = re.compile(
    r'[追][^\u4e00-\u9fff]{0,3}[更新文]|每日|日更|更[^\u4e00-\u9fff]{0,2}[新]|求文|催更|福利|资源'
    r'|[整正證证][^\u4e00-\u9fff]{0,2}[理里裡裏李]|关注|联系|公众号'
    r'|海棠|废文|po18|popo|starpopo|群号|群主|叩叩|扣扣|QQ|ＱＱ|[qQ][^\u4e00-\u9fff]{0,2}[uUＵ][^\u4e00-\u9fff]{0,2}[nNＮ]')

_W_NUMCLASS = r'[0-9０-９〇零一二三四五六七八九十百千万两壹贰叁肆伍陆柒捌玖]{1,12}'
_W_PORN_TAG = re.compile(r'群交|[3三][Pp]|[nN][Pp]|双性|扶她|扶他|[高全][HhＨ]|肉文|无码|18禁')
_W_CHAPTER_TITLE = re.compile(r'^第?' + _W_NUMCLASS + r'\s*[章回节卷幕部]')
_W_CHAPTER_HDR = re.compile(
    r'^\d{1,4}(?:\s+\d{1,3})?\s*[^\w\s]{0,2}\s*'
    r'[\u4e00-\u9fff…]{1,8}\d{0,3}\s*'
    r'(?:[（(][^（）()\n]{0,8}[)）])?'
    r'(?:\s*[【\[][^\]【\[]{0,12}[\]】])?\s*$')
_W_NUM_PREFIX_HDR = re.compile(
    r'^\d{1,4}\s+[^\d\n]{0,3}[\u4e00-\u9fff]'
    r'.{0,20}?(?:[（(][^（）()\n]{0,8}[)）]|[【\[][^\]【\[]{0,12}[\]】])\s*$')
_W_PIPE_NUM = re.compile(r'^\d{1,6}｜\d{1,6}[.、]\s*[\u4e00-\u9fff]')
_W_RANGE_LEAD = re.compile(r'^\d{1,5}\s*[-–~～]\s*\d{1,5}\b')
_W_CYR_PROSE = re.compile(r'[А-Яа-яЁё]{4,}')
_W_CJK_TAIL = set('。！？…，、；：”』」》）)】')
_W_TIMETABLE = re.compile(r'\d{1,2}[:：]\d{2}\s*(?:[ap]\.?\s*m|a\.m|p\.m|AM|PM)', re.IGNORECASE)
_W_TIMETABLE_RANGE = re.compile(r'^\d{1,2}[:：]\d{2}\s*[～~\-–]+\s*\d{1,2}[:：]\d{2}')
_W_BRACKET_REPEAT = re.compile(r'^[［【\[]\s*\d{2,}\s*[。！？啊哈呜嘛呢]?.{0,4}\s*[］】\]]\s*$')
_W_TRUE_NUM = set('0123456789０-９零〇一二三四五六七八九十百千万两亿')
_W_ENUM_ALLOWED_PUNCT = set('，、。！？…：；“”‘’「」『』（）《》〈〉﹔｜%\u3000 ')
_W_PURE_ENUM_RE = re.compile(r'[0-9０-９零〇一二三四五六七八九十百千万两]{1,12}')


def _w_pure_enum(stripped: str) -> bool:
    """v2.25③/v2.26：全行为真数字列举（倒数/计数/数列/百分数递进）→ 正文。
    结构：≥2 组数字由 ，、 或 …… 分隔（组内允许 ≤2 个普通汉字，如 五十二，是五十二万。）；
    全行不得含 形式数字/谐音字/ASCII 分隔符/异国字母/广告关键词。"""
    if not (re.search(r'[0-9０-９零〇一二三四五六七八九十百千万两]{1,12}[，、]', stripped)
            or re.search(r'[0-9０-９零〇一二三四五六七八九十百千万两%]+[…]', stripped)):
        return False
    if _W_KW.search(stripped):
        return False
    ordinary = 0
    for ch in stripped:
        if ch in _W_TRUE_NUM or ch in _W_ENUM_ALLOWED_PUNCT:
            continue
        if '\u4e00' <= ch <= '\u9fff':
            if _V22_DIG_RE.match(ch) or _V22_HOMO_RE.match(ch):
                return False
            ordinary += 1
            if ordinary > 2:
                return False
            continue
        return False
    return True


def _w_ordinary_run_ge(text: str, n: int) -> bool:
    """普通汉字（非数字类/非谐音类）连续 ≥n（容忍字间 ≤1 个非普通字）。"""
    cnt = 0
    gap = 0
    for ch in text:
        if ('\u4e00' <= ch <= '\u9fff'
                and not _V22_DIG_RE.match(ch) and not _V22_HOMO_RE.match(ch)):
            cnt += 1
            gap = 0
        else:
            gap += 1
            if gap > 1:
                cnt = 0
                gap = 0
        if cnt >= n:
            return True
    return False


def _w_is_ad_line(stripped: str) -> bool:
    """v2.23 W 行判定（v2.25 加 6 类护栏）。stripped 为去首尾空白后的行内容。"""
    if stripped[:1] in '“"‘':
        return False
    if _W_CHAPTER_TITLE.match(stripped) and not re.search(r'群交|双性|扶她|扶他', stripped):
        return False
    if _W_CHAPTER_HDR.match(stripped) and not re.search(r'群交|双性|扶她|扶他', stripped):
        return False
    if _W_NUM_PREFIX_HDR.match(stripped) and not re.search(r'群交|双性|扶她|扶他', stripped):
        return False
    if _W_PIPE_NUM.match(stripped):
        return False
    if _w_pure_enum(stripped):
        return False
    if _W_RANGE_LEAD.match(stripped):
        return False
    if _W_TIMETABLE.search(stripped) or _W_TIMETABLE_RANGE.match(stripped):
        return False
    if _W_BRACKET_REPEAT.match(stripped):
        return False
    if _W_CYR_PROSE.search(stripped) and not re.search(r'[0-9]', stripped):
        return False
    dig_n = len(_V22_DIG_RE.findall(stripped))
    homo_n = len(_V22_HOMO_RE.findall(stripped))
    if len(stripped) < 6 or (dig_n + homo_n) < 4:
        return False
    ordinary = [ch for ch in stripped
                if '\u4e00' <= ch <= '\u9fff'
                and not _V22_DIG_RE.match(ch) and not _V22_HOMO_RE.match(ch)]
    if len(ordinary) > 8:
        return False
    if not re.search(r'[^\x00-\x7f]', stripped):
        return False
    if stripped.startswith('【') and stripped.endswith('】'):
        return False
    _strong_pat = re.compile(r'[0-9０-９①-⑨⑩⓪-⓿⑴-⒛❶-❿㊀-㊉𝟎-𝟿ⅡⅠ-Ⅻ]|[^\w\u4e00-\u9fff\s]')
    last_strong = 0
    for m in _strong_pat.finditer(stripped):
        last_strong = max(last_strong, m.end())
    trailing = stripped[last_strong:].strip()
    trailing_ordinary = [ch for ch in trailing
                         if '\u4e00' <= ch <= '\u9fff'
                         and not _V22_DIG_RE.match(ch) and not _V22_HOMO_RE.match(ch)]
    if any(ch in '的了吗呢吧着啊呀哦嘛么' for ch in trailing_ordinary):
        return False
    if _w_ordinary_run_ge(trailing, 4) and not (len(trailing) <= 6 and _W_KW.search(trailing)):
        return False
    first_obf = len(stripped)
    for scanner in (_V22_DIG_RE, _V22_HOMO_RE, _V22_EVID_RE, _W_EVID_HARD):
        for m in scanner.finditer(stripped):
            first_obf = min(first_obf, m.start())
    lead = stripped[:first_obf]
    if any(len(r) >= 4 for r in re.findall(r'[\u4e00-\u9fff]+', lead)) \
            and not _W_KW.search(lead):
        return False
    ev_strong = sum(1 for m in _V22_EVID_RE.finditer(stripped)
                    if not _V22_DIG_RE.match(m.group()))
    hard = len(_W_EVID_HARD.findall(stripped))
    kw = bool(_W_KW.search(stripped))
    if _RISK_PROFILE == 'conservative' and not kw \
            and not (hard >= 3 or (hard >= 2 and dig_n + homo_n >= 6)):
        return False
    if not kw and ev_strong == 0 and hard == 0 and _w_ordinary_run_ge(stripped, 4):
        return False
    if kw:
        digits_pure_ascii = (homo_n == 0
                             and not re.search(r'[０-９①-⑨⑩⓪-⓿⑴-⒛⒈-⒛❶-❿㊀-㊉Ⅰ-Ⅻ𝟎-𝟿]', stripped))
        if digits_pure_ascii and ev_strong == 0 and hard == 0 \
                and not _W_SIGN.search(stripped):
            return False
        return True
    if (kw and ev_strong >= 2) or (hard >= 2 and dig_n + homo_n >= 4):
        return True
    sym_n = len(re.findall(r'[^\w\u4e00-\u9fff\s]', stripped))
    if (dig_n + homo_n) >= 6 and len(ordinary) <= 2 and sym_n >= 2 and (
            not ordinary or all(ch not in _W_DATE_HANZI for ch in ordinary)):
        return True
    return False


def _w_seg(text: str):
    res = []
    off = 0
    for line in text.split('\n'):
        stripped = line.strip()
        if _w_is_ad_line(stripped):
            s = off + (len(line) - len(line.lstrip()))
            e = off + len(line)
            if text[e:e + 1] == '\r':
                e += 1
            if text[e:e + 1] == '\n':
                e += 1
            res.append((s, e))
        off += len(line) + 1
    return res


def _w():
    return [_w_seg]


rule('W', '行级混淆号段广告整行删 (追文/圈号链+亚美尼亚/西里尔/圈拉丁冒充数字)', _w)


_WT_END = set('。！？…')
_WT_CJK_NUM = set('零〇一二三四五六七八九十百千万两')

def _wt_seg(text: str):
    res = []
    off = 0
    for line in text.split('\n'):
        rline = line.rstrip()
        cuts = [i for i, c in enumerate(rline) if c in _WT_END]
        for p in reversed(cuts):
            s0 = p + 1
            if s0 >= len(rline) - 3:
                break
            tail = rline[s0:]
            if tail and tail[0] in '”』」】）' and len(tail) > 1:
                opener = {'”': '“', '』': '『', '」': '「', '】': '【', '）': '('}.get(tail[0])
                if opener and line.count(opener) >= line.count(tail[0]):
                    tail = tail[1:]
                    s0 += 1
                elif not opener:
                    tail = tail[1:]
                    s0 += 1
            ordinary = [ch for ch in tail
                        if '\u4e00' <= ch <= '\u9fff'
                        and not _V22_DIG_RE.match(ch) and not _V22_HOMO_RE.match(ch)]
            if ordinary:
                break
            tail_groups = re.findall(r'[0-9０-９零〇一二三四五六七八九十百千万两]{1,4}', tail)
            if len(tail_groups) >= 3 and re.search(r'[，、]', tail):
                if _RISK_PROFILE != 'aggressive' or re.fullmatch(
                        r'[零〇一二三四五六七八九十百千万两，、…\s]+', tail):
                    break
            if re.search(r'[（(]\s*\d', tail) and re.search(r'\d\s*[)）]', tail):
                break
            if tail.rstrip().endswith(('】', '〕')):
                break
            if tail.startswith(']') or (tail.startswith('[') and re.match(r'\[\d', tail)):
                break
            if re.fullmatch(r'\s*\d{1,2}\s*[/／]\s*\d{1,2}\s*',
                             tail.strip('”』」】）) ')):
                break
            if re.search(r'\d{4}[/／]\d{1,2}[/／]\d{1,2}', tail):
                break
            if re.search(r'\d{1,2}[:：]\d{2}[:：]\d{2}', tail):
                break
            if re.search(r'——\s*[”』」】）)]?\s*$', tail) and re.search(r'\d', tail):
                break
            if re.fullmatch(r'\d{1,2}[:：]\d{2}', tail.strip()) and not _W_EVID_HARD.search(tail):
                break
            if len(tail) < 6 and not _W_EVID_HARD.search(tail):
                break
            if re.search(r'[A-Za-z]{3,}', tail) and re.search(r'[(]', tail):
                break
            _wt_dig = len(_V22_DIG_RE.findall(tail))
            if _RISK_PROFILE == 'aggressive':
                _wt_dig += len(_V22_HOMO_RE.findall(tail))
            if len(tail) >= 4 and _wt_dig >= 3 \
                    and re.search(r'[^\w\u4e00-\u9fff\s]', tail):
                res.append((off + s0, off + len(rline)))
            break
        off += len(line) + 1
    return res


def _wt():
    return [_wt_seg]


rule('WT', '正文行尾纯混淆尾巴 (无普通汉字+≥3数字+符号分隔——“吃饭！”92\'4|1?5!76#5@4)', _wt)


_WE_TERM = set('。！？…」』）)】”')
_WE_FOREIGN = re.compile(
    r'[\u0530-\u058f\u0400-\u052f\u0370-\u03ff\u13a0-\u13ff\u1400-\u167f'
    r'\u0100-\u024f\u249c-\u24e9\ue000-\uf8ff\u1d00-\u1d7f\u0500-\u052f]')


def _we_seg(text: str):
    res = []
    off = 0
    for line in text.split('\n'):
        rline = line.rstrip()
        last = -1
        for i, c in enumerate(rline):
            if c in _WE_TERM:
                last = i
        if last < 0 or last >= len(rline) - 1:
            off += len(line) + 1
            continue
        s0 = last + 1
        tail = rline[s0:]
        if tail and tail[0] in '”』」】）' and len(tail) > 1:
            tail = tail[1:]
            s0 += 1
        ordinary = [ch for ch in tail
                    if '\u4e00' <= ch <= '\u9fff'
                    and not _V22_DIG_RE.match(ch) and not _V22_HOMO_RE.match(ch)]
        if ordinary:
            off += len(line) + 1
            continue
        if len(_WE_FOREIGN.findall(tail)) >= 2 and len(tail) >= 2:
            res.append((off + s0, off + len(rline)))
        off += len(line) + 1
    return res


def _we():
    return [_we_seg]


rule('WE', '正文行末异国字母水印尾 (宋霁雪…Ꮵᒝs影 / 里面一片肃然。ŸČχĜ)', _we)


_ST_MHT_RE = re.compile(r'[\[（(]?棉花糖小说网[^\n）)\]]{0,40}[\]）)]?')
_ST_TXT_RE = re.compile(r'\d{0,2};?\s*提供\s*Txt\s*免费下载[）)]?')


def _st():
    return [_ST_MHT_RE, _ST_TXT_RE]


rule('ST', '站点水印片段 (棉花糖小说网/提供Txt免费下载)', _st)


_P_MORE    = r"[綆哽更浭][哆茤多]"
_P_HAOWEN  = r"(?:[恏好][纹雯蚊汶玟]|䒵[芠汶])"
_P_LIANZAI = r"[連连鏈蓮链][載傤载载](?:膇[薪新]|追新)"
_P_QING    = r"[请請綪]"
_P_LIANXI  = r"[联连連蓮莲蠊镰鎴][系係细鎴]"
_P_TAIL = re.compile(
    r"(?:" + _P_MORE + _P_HAOWEN + r"|" + _P_LIANZAI + r")"
    + _P_QING + _P_LIANXI
    + r"(?=[^|\n]*[" + _N_STRONG + _M_NAD_BODY + r"])"
    + r"[^|\n]*(?:\|[^|\n]*)*",
)


def _p():
    return [_P_TAIL]


rule('P', '行末广告尾巴 更多好文/连载追新+请联系[群]混淆号 (只删尾巴保留正文)', _p)


_R_OBF_BODY = (
    _N_STRONG
    + r"0-9"
    + r"零〇一壹二贰貳參弎三叁仨四肆五伍忢忤舞武六陆七柒妻漆八捌九玖久酒灸十百千"
    + r"鸠䫩嗣尓蕶㒃葻罒伶焐午思令玲磷铃拎另领冷灵澪靈潁依溜浏"
    + r"\u0220-\u022f"
    + r"Qq裙球群"
)
_R_PUNCT = r"，。！？、；：…\n\r\"'”’）)】」』〕"
_R_PRE = r"(?:[乞企岂][额蛾鹅]|[笨苯泍本][纹玟文蚊汶雯][邮铀由油][qQǪɊǬԚ]{0,3}|本文[油由邮][qQǪɊǬԚ]{0,3})?"
_R_POST = r"(?:[徰撜整證][鲤哩梩理里])?"
_R1 = re.compile(
    _R_PRE
    + r"(?:Q[qQ]?群|裙)"
    + r"(?=[" + _R_OBF_BODY + r"]*[" + _N_STRONG + r"])"
    + r"(?=[" + _R_OBF_BODY + r"]{2,})"
    + r"[" + _R_OBF_BODY + r"]*?"
    + _R_POST
    + r"(?=[" + _R_PUNCT + r"]|[^" + _R_OBF_BODY + r"\n]{2}|$)",
)
_R2 = re.compile(
    r"【(?=[^】]*[0-9" + _N_STRONG + r"])"
    + r"(?![^】]*[\u4e00-\u9fff]{2})"
    + r"(?![^】]*[0-9０-９]{1,3}\s*[：:．]\s*[0-9０-９]{1,3})"
    + r"(?![^】]*[0-9]+\s*月[^】]*[0-9]+\s*日)"
    + r"(?!(?=[^】]*[A-PR-Za-pr-z])(?![^】]*[澜蘭兰][^】]*[生笙昇声]))"
    + r"(?![0-9０-９\s.\-—–%~%/，、！？………。．]*[0-9０-９][0-9０-９\s.\-—–%/，、！？………。．]*】)"
    + r"(?![0-9０-９\s\-—–~～%,，、]*[章节卷话回番册部]】)"
    + r"(?=[^】]*[0-9]+[^】0-9]+[^】]*[0-9]+|[^】]*[" + _N_STRONG + r"])"
    + r"[^】]+?】",
)


_R4 = re.compile(
    r"球裙"
    r"(?=[^\n]{0,40}(?:更精彩|更多好文|更多小说|连载追新|看新章|追更|催更|日更|全篇|更章|看后续|"
    + r"[\d⓪-⓿①-⑨㊀-㊉⒈-⒛零洞令玲磷铃拎另领冷灵一二三四五六七八九十壹贰叁肆伍陆柒捌玖〇]{4,}))"
    + r"[^\n，。！？；：…""]{0,80}",
    re.UNICODE,
)


_R5_ANCHOR = re.compile(
    _R_PRE
    + r"(?:企鹅[小]?[裙峮群]|鹅[" + _M_SEP_V22 + r"]{0,1}[裙羣]|球裙|兰[笙生]裙|[ＱQq][qQＱ]?[群羣]"
    + r"|[ＱQq][君羊]|小说[群君羊]|[滕腾騰駦藤][訊讯迅訙训][" + _M_SEP_V22 + r"]{0,2}[群羣]"
    + r"|吃肉[qQ][uU][nN]|[扣釦][" + _M_SEP_V22 + r"]{0,2}[扣釦][群圈]"
    + r"|[裙群][紸主]?[号號]|[Qq][0-9₀-₉]|[裙群羣]"
    + r"|肉[纹文][群]"
    + r"|[R肉][纹文雯][釦扣][群裙羣]"
    + r"|[兰蓝篮岚拦栏][生升声笙甥][独读牍犊毒度][家佳嘉夹甲][整拯症征争][理李里礼丽荔]"
    + r"|[乞企绮岂起啟騰腾駦启][额蛾鹅峨俄䳘][裙群羣峮👗]"
    + r"|[口][ＱQq叩][裙群羣圈]|🐧[👗]?"
    + r"|[裙群紸][号號]|[ＱQq][裙]|[额蛾鹅峨俄䳘][：:﹕]"
    + r"|(?<![群羣裙])[圈][" + _M_SEP_V22 + r"]{0,2}[0-9０-９①-⑨⑴-⒛㊀-㊉]"
    + r"|[筘][扣][裙群羣]"
    + r"|popo[群裙]|po18资源[群裙]|starpopo[群裙]"
    + r"|[ＱQq][uUＵ][nNＮ]|[Gg][Rr][Oo][Uu][Pp]"
    + r")"
)




def _ad_num_chain_after(text: str, k0: int) -> bool:
    """裸裙锚点后的句读是否起一个纯混淆号段链（≥2 数字/谐音，且非正文长句）。
    裙.七﹒衣龄﹑伍吧吧五.九…零 → True（真广告，衣 虽非 HOMO 但前后皆混淆）；
    裙，一个长；一个白猫… → False（正文，连续正文汉字 个长 即断）。"""
    j = k0 + 1
    d = 0
    while j < len(text):
        c = text[j]
        if c in _V22_WS:
            j += 1
        elif _V22_DIG_RE.match(c):
            d += 1
            j += 1
        elif _V22_HOMO_RE.match(c) or _V22_SEP_RE.match(c):
            j += 1
        elif '\u4e00' <= c <= '\u9fff':
            if j + 1 < len(text) and (
                    _V22_DIG_RE.match(text[j + 1]) or _V22_HOMO_RE.match(text[j + 1])
                    or _V22_SEP_RE.match(text[j + 1]) or text[j + 1] in _V22_WS):
                j += 1
            else:
                break
        else:
            break
    return d >= 2


def _r5_seg(text: str):
    res = []
    for m in _R5_ANCHOR.finditer(text):
        if m.group() in ('裙', '羣', '群'):
            k0 = m.end()
            while k0 < len(text) and text[k0] in _V22_WS:
                k0 += 1
            if k0 < len(text) and ('\u4e00' <= text[k0] <= '\u9fff'
                                   and not (_V22_DIG_RE.match(text[k0]) or _V22_HOMO_RE.match(text[k0]))
                                   or (text[k0] in _V22_SENT and not _ad_num_chain_after(text, k0))):
                continue
            if m.group() == '群':
                if not (k0 < len(text)
                        and (_V22_EVID_RE.match(text[k0])
                             and not ('\u4e00' <= text[k0] <= '\u9fff'))):
                    continue
        if re.fullmatch(r'[额蛾鹅峨俄䳘][：:﹕]', m.group()):
            run_probe = text[m.end():_scan_obf_run(text, m.end())]
            if re.fullmatch(r'[0-9０-９\s（）()，,。.：:；;…\-—–%~%/，、！？…]*',
                            run_probe):
                continue
        e = _scan_obf_run(text, m.end())
        run = text[m.end():e]
        if _v22_gate(run):
            e = _trim_run_tail(text, m.end(), e)
            e = _slogan_extend(text, e)
            ls = text.rfind('\n', 0, m.start()) + 1
            le = text.find('\n', e)
            if le == -1:
                le = len(text)
            s = _lex_left(text, m.start(), ls)
            if s > ls and text[s - 1] in '加来來入去快':
                s2 = _lex_left(text, s - 1, ls)
                if s2 < s - 1:
                    s = s2
            e = _cross_punct_extend(text, e, le)
            e = _lex_right(text, e, le)
            deleted_seg = text[s:e]
            if m.group() in ('群', '裙') and re.fullmatch(
                    r'[群裙][（(][0-9０-９一二三四五六七八九十]{1,3}[)）]', deleted_seg) \
                    and m.start() > 0 and '\u4e00' <= text[m.start() - 1] <= '\u9fff':
                continue
            res.append((s, e))
    _BACKSCAN_SEP = set(',.．/／\\、-－—~～·・:：;；')
    _R2_PRE_RES = [re.compile(p) for p in (
        r'肉[、.,~～\s]{0,2}[纹文雯][档]?',
        r'球[、.,~～\s]{0,2}裙',
        r'[ＱQq][、.,~～\s]{0,2}群',
    )]
    for m in _R2.finditer(text):
        if _R2_DATE_RE.fullmatch(m.group().strip('【】………')):
            continue
        if _r2_content_skip(m.group()[1:-1]):
            continue
        s = m.start()
        j = s
        sep_run = 0
        while j > 0 and text[j - 1] != '\n':
            c = text[j - 1]
            if _V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c):
                sep_run = 0
                j -= 1
            elif c in _V22_WS or (c in _BACKSCAN_SEP and sep_run < 2):
                sep_run += 1
                j -= 1
            elif (_V22_SEP_RE.match(c) and c not in _V22_SENT
                  and sep_run < 2):
                sep_run += 1
                j -= 1
            else:
                break
        if j < s and len(_V22_DIG_RE.findall(text[j:s])) >= 2:
            s = j
        moved = True
        while moved and s > 0:
            moved = False
            for span in (2, 3, 4):
                if s - span < 0:
                    continue
                if any(p.fullmatch(text[s - span:s]) for p in _R2_PRE_RES):
                    s -= span
                    moved = True
                    break
            if not moved:
                k = s
                while k > 0 and text[k - 1] != '\n' and (
                        _V22_SEP_RE.match(text[k - 1]) and text[k - 1] not in _V22_SENT):
                    k -= 1
                if k < s and any(p.fullmatch(text[k:s]) for p in _R2_PRE_RES):
                    s = k
                    moved = True
        res.append((s, m.end()))
    return res


def _r2_seg(text: str):
    """v2.12：R2 独立提案 + 日期门控（【1191-7-01……】正文日期跳过——synthetic-case）。
    v2.14：+ 颜文字/非谐音CJK 门控（synthetic-case）。"""
    res = []
    for m in _R2.finditer(text):
        if _R2_DATE_RE.fullmatch(m.group().strip('【】………')):
            continue
        if _r2_content_skip(m.group()[1:-1]):
            continue
        res.append((m.start(), m.end()))
    return res


def _r():
    return [_r5_seg, _R1, _r2_seg, _R4]


rule('R', '中间夹广告 Q群/球裙/【数字串】锚点+混淆段 (子串删除保留前后正文)', _r)


_ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060-\u2064\ufeff]")
_COMBINING_MARK = re.compile(r"[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b]")
_STEGO_COMBINING = re.compile(
    r"[༓]*[鎖锁](?:[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b])+"
    r"春(?:[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b])+"
    r"宵(?:[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b])+[༓]*"
    r"|[༓]*禁(?:[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b])+"
    r"忌(?:[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b])+"
    r"引(?:[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b])+"
    r"力(?:[\u0300-\u036f\u0483-\u0489\u0d62\u0f7c\u1ab0-\u1aff\u20d0-\u20ff\u2de0-\u2dff\ua67b])+[༓]*")
_STEGO_LINE = re.compile(r"^[ \t　]*(?:管理QQ?[：:]\s*\d{8,}|豆丁推文更新整理|甛饣并甲鸟)[ \t　]*(?:\r?\n|$)", re.MULTILINE)


def _z():
    return [
        (_ZERO_WIDTH, ''),
    ]


rule('Z', '零宽字符隐写水印清除 (ZWSP/ZWNJ/ZWJ/LRM/RLM 等不可见溯源水印)', _z)


_T_END_PUNCT = '。”’」』】）)？！…—－~～'
_T_CLOSE_PUNCT = ''
_T_STRONG_SET = None
_T_DIGIT_RE = None


def _t_init():
    global _T_STRONG_SET, _T_DIGIT_RE
    if _T_STRONG_SET is None:
        import re as _re
        _T_STRONG_RE = _re.compile('[' + _N_STRONG + r']')
        _T_STRONG_CNT = _T_STRONG_RE.findall
        _T_DIGIT_RE = _re.compile(r'[0-9０-９' + _N_STRONG + _M_NAD_BODY + r']')
        globals()['_T_STRONG_CNT'] = _T_STRONG_CNT
        globals()['_T_DIGIT_RE'] = _T_DIGIT_RE
        _T_STRONG_SET = True


def _t_func(text: str):
    """删除每行「最后一个终止标点之后、满足广告门控的段」。返回 (新文本, 命中数)。"""
    _t_init()
    out_lines = []
    hits = 0
    for line in text.split('\n'):
        rline = line.rstrip()
        last_p = -1
        for i in range(len(rline) - 1, -1, -1):
            if rline[i] in _T_END_PUNCT:
                last_p = i
                break
        if last_p >= 0 and last_p < len(rline) - 1:
            seg = rline[last_p + 1:]
            if (len(seg) >= 4
                    and (len(_T_DIGIT_RE.findall(seg)) >= 2 and len(_T_STRONG_CNT(seg)) >= 2
                         or len(_T_DIGIT_RE.findall(seg)) >= 4 and len(_T_STRONG_CNT(seg)) >= 1)):
                out_lines.append(rline[:last_p + 1])
                hits += 1
                continue
        out_lines.append(line)
    return '\n'.join(out_lines), hits


def _t_collect(text: str):
    """collect 模式：返回 [(行号1based, 该行原文, 删除段, 段在行内的起始偏移)]，供 dry-run 报告使用。"""
    _t_init()
    res = []
    for ln, line in enumerate(text.split('\n'), 1):
        rline = line.rstrip()
        last_p = -1
        for i in range(len(rline) - 1, -1, -1):
            if rline[i] in _T_END_PUNCT:
                last_p = i
                break
        if last_p >= 0 and last_p < len(rline) - 1:
            seg = rline[last_p + 1:]
            if (len(seg) >= 4
                    and (len(_T_DIGIT_RE.findall(seg)) >= 2 and len(_T_STRONG_CNT(seg)) >= 2
                         or len(_T_DIGIT_RE.findall(seg)) >= 4 and len(_T_STRONG_CNT(seg)) >= 1)):
                res.append((ln, line, seg, last_p + 1))
    return res


def _t():
    return [_t_func]


rule('T', '终止标点后行末广告段 (企鹅/本文由拼音级随机变体兜底，只删标点后的广告段)', _t)


_THANKS_RE = re.compile(
    r'^[ 　\t]*(?:感谢(?:投出|灌溉|成为|贡献|打出)[^\n：:]{0,20}[：:]'
    r'|感谢[^\n，、]{0,24}[（(][0-9０-９]{1,4}[）)][、，]'
    r'|感谢[^\n。！？]{0,30}[、，](?=[^\n]*[、，]))'
    r'[^\n]*\r?\n?',
    re.MULTILINE)


def _th():
    return [_THANKS_RE]


rule('TH', '感谢打赏名单整行 (感谢投出地雷/灌溉营养液的小天使：…)', _th)


_TH_AUTHOR_SIGNAL_RE = re.compile(
    r'地雷|营养液|礼物|宝石钻戒|草莓(?:派|蛋糕)|牛排全餐|杯子蛋糕|玫瑰花|别墅'
    r'|打赏|投雷|灌溉|送出|送给|赠送|投票|票票|订阅|收藏|评论|支持|追更|追连载'
    r'|小天使|小可爱|读者|宝宝们|宝贝们|姐妹们|姑娘们|老婆们|亲亲|啵|比心'
    r'|火箭炮|手榴弹|深水(?:鱼雷|炸弹)|浅水炸弹|五星好评|小说封面|点亮星星'
    r'|投喂|珠珠|红包|名单|催更|土豪|app'
    r'|长评|短评|书评|番外|小汽车|道具|彩蛋|看到这里|等到现在|为小生|烂作者|某颓',
    re.IGNORECASE)
_TH_NARRATIVE_PREFIX_RE = re.compile(
    r'^感谢(?:完|过|了|的话|和不用谢|这|那|有你|它的礼物，感谢它|上苍|纯黑兜帽)')
_TH_NARRATIVE_MARKS_RE = re.compile(
    r'如果|因为|所以|之后|时候|让他|让她|让它|成功|存在|发展|技能|天气|身体|科技|教育'
    r'|虽然|但是|却|至少|于是|然后|当|可以|不会|没有|知道|觉得|开始'
    r'|他们|她们|它们|依然|依旧|越发|更加|缓缓|轻轻|猛地|顿时|随即|接着|随后|这时|此时|那晚|当年|此刻'
    r'|屁股|鸡巴|穴肉|高潮|操|艹|射了|抽插|乳|阴蒂|精液'
    r'|已经|一直|正|便|才|只|又|也|还|都|就'
    r'|盯着|稳住|交叠|放于|智能机|胡言|相恋|相伴|相念|相知|相见|相随')
_TH_AGGRESSIVE_AUTHORNOTE_RE = re.compile(
    r'学业|弃文|弃坑|跑路|辜负|放弃|间隔了|这么长的时间|两本书|断更|停更|请假'
    r'|完结感言|后记|致谢|作者的话|碎碎念|看到这里|等到现在|烂作者|某颓|不会让大家'
    r'|不会弃|不会辜负|没有放弃|更新计划|连载中|专栏|微博|公众号|围脖|lofter'
    r'|留言|评论回复|回复大家|抱歉|对不起|谢谢大家|感谢大家(?:对于|一路|看到|支持)')


def _legacy_route(context) -> str:
    """Compatibility shim: public builds never route by private categories."""
    return ''


def _risk_profile(context) -> str:
    value = context.get('risk_profile', '') if isinstance(context, dict) else ''
    return value if value in ('conservative', 'balanced', 'aggressive') else 'conservative'


def _th_context_is_ad(line: str, context) -> bool:
    """分类已知时判定 TH 是否为作者互动行；不读取书名/file_key/答案。
    v2.28 类差异化：aggressive-profile 更激进（作者话标记 override 叙事），conservative-profile更保守（叙事标记留）。"""
    cls = _legacy_route(context)
    if not cls:
        return True
    line = line.strip()
    if not line.startswith('感谢') or _TH_NARRATIVE_PREFIX_RE.search(line):
        return False
    separators = len(re.findall(r'[、，,]', line))
    repeated_thanks = line.count('感谢') > 1
    narrative_marks = _TH_NARRATIVE_MARKS_RE.search(line)
    if _TH_AUTHOR_SIGNAL_RE.search(line):
        if narrative_marks and separators < 2 and len(line) >= 42:
            return False
        return True
    if cls == 'aggressive-profile' and _TH_AGGRESSIVE_AUTHORNOTE_RE.search(line):
        return True
    if narrative_marks and separators >= 3:
        seg_lens = [len(s) for s in re.split(r'[、，,]', line)]
        if any(length >= 8 for length in seg_lens):
            return False
    return separators >= 4 and len(line) >= 24 and not repeated_thanks and not narrative_marks


def _th_context_segments(text: str, context):
    """补出 v2.23 窄正则漏掉的作者互动感谢行，返回含换行的整行范围。"""
    if not _legacy_route(context):
        return []
    result = []
    offset = 0
    for line in text.splitlines(keepends=True):
        if _th_context_is_ad(line, context):
            result.append((offset, offset + len(line)))
        offset += len(line)
    if offset < len(text):
        line = text[offset:]
        if _th_context_is_ad(line, context):
            result.append((offset, len(text)))
    return result


_SITE_SLOGAN_RE = re.compile(
    r'(?:[①②③④⑤⑥⑦⑧⑨⑩][ 　\t]?)?(?:小说月群|小说永久群|视频永久群)[:：][^\n]{0,45}')


def _sl():
    return [_SITE_SLOGAN_RE]


rule('SL', '站点口号行中段 (小说月群:/小说永久群:/视频永久群:…)', _sl)


_SS_SEP = ' 　\t:：;；' + "'" + '"' + '，。、·﹒〃' + '“”‘’'
_SS_CHUNK = re.compile(
    r'(?:[\u4e00-\u9fffA-Za-z0-9]{1,4}[' + re.escape(_SS_SEP) + r']+){5,}'
    r'[\u4e00-\u9fffA-Za-z0-9]{1,4}?',
    re.UNICODE)
_SS_KEYWORDS = re.compile(r'免费分享|公众浩|公众号|更多好文|请联系|看完整|更新章|追更|日更|婆海棠|整理本文|独家整理|更新最快|整理于|整理制作|汪汪.{0,8}雪糕|雪糕.{0,8}(?:分享|整理|免费)')
_SS_WEAK_KW = re.compile(r'整理|免费|分享|公众|糖果|海棠|婆|波|汪|糖|更|追|日')
_SS_LIST_ONLY_SEP = set('，、')
_SS_RADICALS = set('氵亻扌纟艹钅讠忄辶阝饣牜犭耂髟阝')
_SS_ADLEAD = set('更多免分享公众衆號糖更追整理微波汪雪糕维薄氵王联系看求欢欢请资資源福利等撩欢迎')
_SS_MIXU = re.compile(r'米需[ \t　:：;；，,。]*米[ \t　:：;；，,。]*整[ \t　:：;；，,。]*理[ \t　:：;；，,。]*制[ \t　:：;；，,。]*作')
_SS_BSTATION = re.compile(
    r'B\s*站\s*一\s*颗\s*柠\s*檬\s*怪\s*免\s*费\s*日更\s*小\s*说\s*广\s*播\s*漫\s*画\s*游\s*戏'
    r'[，,。]?[ \t　]*本作品来自互\s*联网[，,。]?[ \t　]*本人不做任何负\s*责[，,。]?[ \t　]*内容版\s*权归作\s*者所有')


def _ss_strict_run4(seg: str) -> bool:
    """严格无分隔的 ≥4 连续普通汉字（拆字广告字字≤2 且有分隔；正文「鼻尖一酸」4 连无分隔）。"""
    cnt = 0
    for ch in seg:
        if ('\u4e00' <= ch <= '\u9fff'
                and not _V22_DIG_RE.match(ch) and not _V22_HOMO_RE.match(ch)
                and ch not in _SS_SEP):
            cnt += 1
            if cnt >= 4:
                return True
        else:
            cnt = 0
    return False


def _ss_seg(text: str):
    res = []
    res.extend((m.start(), m.end()) for m in _SS_MIXU.finditer(text))
    res.extend((m.start(), m.end()) for m in _SS_BSTATION.finditer(text))
    for m in _SS_CHUNK.finditer(text):
        seg = m.group()
        dense = re.sub('[' + re.escape(_SS_SEP) + r']', '', seg)
        if len(dense) < 6:
            continue
        hit_kw = bool(_SS_KEYWORDS.search(dense))
        hit_rad = any(ch in _SS_RADICALS for ch in seg)
        non_list_seps = 0
        if _SS_WEAK_KW.search(dense):
            sep_density = sum(1 for c in seg if c in _SS_SEP) / max(1, len(seg))
            hit_weak = sep_density >= 0.4 and not _ss_strict_run4(seg)
        else:
            hit_weak = False
        if not (hit_kw or hit_rad or hit_weak):
            continue
        s, e = m.start(), m.end()
        first_sep = -1
        for _k, _ch in enumerate(seg):
            if _ch in _SS_SEP:
                first_sep = _k
                break
        lead_trimmed = False
        if first_sep > 0:
            lead = seg[:first_sep]
            if len(lead) >= 3 and not any(ch in _SS_ADLEAD for ch in lead):
                s = m.start() + first_sep + 1
                lead_trimmed = True
        if not lead_trimmed:
            while s > 0 and text[s - 1] in _SS_SEP:
                s -= 1
        while e < len(text) and text[e] in _SS_SEP:
            e += 1
        res.append((s, e))
    return res


def _ss():
    return [_ss_seg]


rule('SS', '分隔符铺开口号/拆字广告 (维 薄 氵王氵王…/微：波：汪：雪：糕…)', _ss)



COLLECT_ONLY = {'N', 'Q'}

_BASE_CACHE = {}

_K_FINDER = re.compile(r"['‘’]")
_K_REPL = '"'

_FOREIGN_SCAN = re.compile(r"[\u0531-\u0587\u13a0-\u13ff\u1400-\u167f\u0400-\u052f\u0370-\u03ff\u01c0-\u024f]")
_STRONG_SCAN = None


def scan_text(text: str) -> dict:
    """独立信号扫描：零宽字符 / 异国字母 / 强怪异字符计数。

    双向使用：dry-run 报告总览（输入侧，防止「规则零命中=干净」的漏判）；
    执行结果验证（产物侧，零宽残留必须为 0，foreign/strong 残留应趋近 0）。
    """
    global _STRONG_SCAN
    if _STRONG_SCAN is None:
        _STRONG_SCAN = re.compile('[' + _N_STRONG + ']')
    return {
        'zero_width': len(_ZERO_WIDTH.findall(text)),
        'foreign': len(_FOREIGN_SCAN.findall(text)),
        'strong': len(_STRONG_SCAN.findall(text)),
    }


def _nested_quote_ratio(text: str):
    """配对单引号中位于双引号内部的比例（合法嵌套引用占比）。无配对返回 None。"""
    pairs = list(re.finditer(r'‘[^’]{0,40}’', text))
    if not pairs:
        return None
    inside = 0
    for m in pairs:
        before = text[:m.start()]
        if before.rfind('“') > before.rfind('”'):
            inside += 1
    return inside / len(pairs)


def _t_gate(seg: str) -> bool:
    """T 段门控（v1.5.2）：段长≥4 且 [(强≥2且数字≥2) 或 (强≥1且数字≥4)]。
    v2.5：段内出现 ≥5 连续汉字且其中普通字（非数字/谐音）≥3 → 判为正文
    （俄语对白后中文旁白、作者的话、遮字正文），不删。广告长汉字串全是数字谐音
    （壹妻九貳六=17926，普通字 0）或短口号（追更本文≤4字），不误杀。
    v2.11：段内须含 ≥1 个基础数字（ASCII/全角/汉字小写数字）——颜文字 (●w●)
    的 ● 属几何图形类强怪异字符，旧门控把它当数字凑密度致误删（synthetic-case）。
    v2.22：4 连汉字的正文防线加口号双字守卫——「催更看新」等纯口号串含
    口号双字组合（催更/看新/追更/更新…），不判正文（v2.1 样本回归修复；
    5 连及以上沿用 v2.5/v2.7 原逻辑，正文「作者今天不更新」不误伤）。"""
    _t_init()
    if len(seg) < 4:
        return False
    if not re.search(r'[0-9０-９〇零一二三四五六七八九十两壹贰貳參叄弎叁仨肆伍陆柒捌玖Ⅰ-Ⅻⅰ-ⅹ]', seg):
        return False
    for m in re.finditer(r'[\u4e00-\u9fff]{4,}', seg):
        run = m.group()
        ordinary = sum(1 for c in run
                       if not _V22_DIG_RE.match(c) and not _V22_HOMO_RE.match(c))
        if ordinary >= 3:
            if len(run) == 4 and _T_SLOGAN_BIGRAM.search(run):
                continue
            if any(p.match(run[:i]) and p.match(run[:i]).end() == i
                   for p in _SL_PRE_RES for i in range(2, min(len(run), 6) + 1)):
                continue
            return False
    n_d = len(_T_DIGIT_RE.findall(seg))
    n_s = len(_T_STRONG_CNT(seg))
    return (n_d >= 2 and n_s >= 2) or (n_d >= 4 and n_s >= 1)


_T_SLOGAN_BIGRAM = re.compile(
    r'催更|看新|追更|求文|找文|好文|整理|连载|完结|福利|资源|免费|分享'
    r'|公众|海棠|婆海|上万|更新|更薪|群发|进群|加群|群主')


_T_BETWEEN_PUNCT = r'。，！？；：、…—－~～()（）\[\]【】「」『』“”‘”\'"《》〈〉\/\\．.·・{}｛｝'\
                   + '﹔﹕﹑﹐﹒〃〻'

_T_BETWEEN_STRIP = re.compile(
    r'[A-Za-z' + _N_STRONG + _N_FOREIGN + _M_NAD_BODY
    + r'0-9０-９₀-₉零〇一二三四五六七八九十百千万两壹贰貳參叄弎叁仨肆伍陆柒捌玖Ⅰ-Ⅻⅰ-ⅹ'
    + _V22_HOMO_STR + _M_WEIRD[1:-1] + _T_BETWEEN_PUNCT + r'\s]')


def _t_between_pure(between: str) -> bool:
    """v2.11：T 左向扩段的间隔纯度判定——两切割点之间的文本须为纯混淆串。
    判定：剥离所有「数字/谐音/分隔符/句读/空白/强怪异」字符后，剩余串为空，
    或其中的每个连续汉字段都能被前缀口号词族 fullmatch（全天出文机器 / 人）。"""
    stripped = _T_BETWEEN_STRIP.sub('', between)
    if not stripped:
        return True
    if any(p.fullmatch(stripped) for p in _SL_PRE_RES):
        return True
    for seg in re.findall(r'[\u4e00-\u9fff]+', between):
        if not any(p.fullmatch(seg) for p in _SL_PRE_RES):
            if len(seg) == 1 and seg in '扣釦叩口佬老咾来加':
                continue
            if seg in ('追更', '更多'):
                continue
            return False
    return True


def _t_segments(text: str) -> list:
    """T 段列表 [(start, end)]（基于传入文本的绝对 offset，含段尾空白剥离）。
    v2.3：终止符加闭合括号「」』】）并把「】」纳入；从最后一个终止符**向前迭代**，
    取第一个满足门控的尾巴——修 regression-02 两例正文误吞：
      「…做爱邀请】小说群1壹…」旧算法从「？」切，把正文句「感觉…邀请】」并入删除；
      新算法从「】」切，只删广告「小说群1壹…」。
    v2.11：左向扩段——选定切割点后，若更左侧还有终止符、且两切割点之间为纯混淆串
    （_t_between_pure），扩到更左切割点（修 synthetic-case/072/073/068：广告段内部含
    终止标点「）」「。」被当切割点，只删了尾巴一小截）。"""
    segs = []
    off = 0
    _closer_opener = {'」': '「', '』': '『', '】': '【', '》': '《'}
    for line in text.split('\n'):
        rline = line.rstrip()
        cuts = [i for i, c in enumerate(rline) if c in _T_END_PUNCT or c in _T_CLOSE_PUNCT]
        for p in reversed(cuts):
            if p >= len(rline) - 1:
                continue
            seg = rline[p + 1:]
            if _t_gate(seg):
                s = off + p + 1
                idx = cuts.index(p)
                _t_pairs = {'」': '「', '』': '『', '】': '【', '”': '“', '’': '‘'}
                for q in reversed(cuts[:idx]):
                    if q >= p:
                        continue
                    between = rline[q + 1:p + 1]
                    if not re.sub(r'[' + _T_BETWEEN_PUNCT + r'\s]', '', between):
                        break
                    c0 = between[:1]
                    if c0 in _t_pairs and rline.count(_t_pairs[c0]) >= rline.count(c0):
                        break
                    if _t_between_pure(between):
                        s = off + q + 1
                        p = q
                    else:
                        break
                if s > off and _t_between_pure(rline[:s - off]) and not _plain_cjk_run(rline[:s - off]):
                    s = off
                c = rline[p]
                if c in _closer_opener and line.count(_closer_opener[c]) < line.count(c):
                    s = off + p
                segs.append((s, off + len(rline)))
                break
        off += len(line) + 1
    return segs


def build_plan(text: str, enabled: set, context=None):
    """v2.0 计划引擎：计算完整编辑计划。执行与报告均消费此计划——单一事实源。

    流程（顺序即 v1.5.2 修复后的执行顺序）：
      1. Z 零宽剥离（计数入 plan['zw']，基准文本随之变化）
      2. K 引号替换（v2.0 自动门控：嵌套占比≥80% 判定合法引用自动跳过）
      3. T 段切割（终止标点→行尾，先于锚点规则，坐标记录在基准文本上）
      4. 锚点自动删规则 A~R（在 T 删除后的工作文本上匹配，坐标经映射表映射回基准）
      5. collect-only（N/Q）：仅候选，auto=False，默认不勾选

    返回 (plan, base)。base = 后 Z 后 K 的基准文本，所有 edit 坐标基于 base。
    plan = {'zw', 'k', 'k_note', 'edits': [{id, rule, label, start, end, line, deleted, auto}]}
    """
    plan = {'zw': 0, 'k': 0, 'k_note': '', 'edits': []}
    if 'Z' in enabled:
        text, stego_n = _STEGO_COMBINING.subn('', text)
        text, line_n = _STEGO_LINE.subn('', text)
        text, zw_n = _ZERO_WIDTH.subn('', text)
        plan['zw'] = stego_n + line_n + zw_n
    if 'K' in enabled:
        ratio = _nested_quote_ratio(text)
        if ratio is not None and ratio >= 0.8:
            plan['k_note'] = f'嵌套单引号占比 {ratio:.0%} ≥ 80%，判定为合法引用，K 自动跳过'
        else:
            text, plan['k'] = _K_FINDER.subn(_K_REPL, text)
    base = text

    global _RISK_PROFILE, _W_LIB_CLASS
    _RISK_PROFILE = _risk_profile(context)
    _W_LIB_CLASS = ''

    line_starts = [0]
    for i, c in enumerate(base):
        if c == '\n':
            line_starts.append(i + 1)

    edits = []
    taken = []

    def add_edit(rule, label, s, e, auto=True):
        if s >= e:
            return False
        for ts, te in taken:
            if s < te and ts < e:
                return False
        while s < e and base[s] in _V22_WS:
            s += 1
        while e > s and base[e - 1] in _V22_WS:
            e -= 1
        if s >= e:
            return False
        deleted = base[s:e]
        if not deleted.strip():
            return False
        taken.append((s, e))
        edits.append({
            'rule': rule, 'label': label, 'start': s, 'end': e,
            'line': bisect.bisect_right(line_starts, s),
            'deleted': deleted, 'auto': auto,
        })
        return True

    anchor_props = []
    scanner_props = []
    for key in RULES:
        if key not in enabled or key in ('K', 'Z', 'T') or key in COLLECT_ONLY:
            continue
        label = RULES[key][0]
        for pat in RULES[key][1]():
            if key == 'TH' and _legacy_route(context):
                continue
            if isinstance(pat, tuple):
                continue
            if callable(pat):
                for s, e in pat(base):
                    anchor_props.append((key, label, s, e))
                    scanner_props.append((key, label, s, e))
                continue
            for m in pat.finditer(base):
                anchor_props.append((key, label, m.start(), m.end()))

    _anchor_priority = {'WE': 0}

    if 'TH' in enabled and _legacy_route(context):
        th_label = RULES['TH'][0]
        for s, e in _th_context_segments(base, context):
            anchor_props.append(('TH', th_label, s, e))

    _I_TAIL_PAT = re.compile(r'[兰蓝澜][^\u4e00-\u9fff]{0,3}[生][^\u4e00-\u9fff]{0,3}(?:柠[^\u4e00-\u9fff]{0,3}檬)?')
    if 'T' in enabled:
        t_label = RULES['T'][0]
        for s, e in _t_segments(base):
            if any(ps < e and pe > s for _, _, ps, pe in scanner_props):
                continue
            if 'I' in enabled and _I_TAIL_PAT.search(base[s:e]):
                continue
            add_edit('T', t_label, s, e, auto=True)

    _scanner_set = set(scanner_props)
    _anchor_edits_from = len(edits)
    for key, label, s, e in anchor_props:
        if (key, label, s, e) in _scanner_set:
            for i in range(_anchor_edits_from, len(edits)):
                ed = edits[i]
                if (ed['auto'] and ed['rule'] != 'T'
                        and ((s <= ed['start'] and e >= ed['end'])
                             or (key == 'WE' and ed['rule'] == 'W'
                                 and s < ed['end'] and ed['start'] < e))
                        and (s, e) != (ed['start'], ed['end'])
                        and _anchor_priority.get(key, 1) <= _anchor_priority.get(ed['rule'], 1)):
                    if (ed['start'], ed['end']) in taken:
                        taken.remove((ed['start'], ed['end']))
                    edits.pop(i)
                    break
        ok = add_edit(key, label, s, e, auto=True)
        if ok and (key, label, s, e) in _scanner_set:
            edits[-1]['scanner'] = True

    def _absorb_n(s, e):
        while s < e and base[s] in _V22_WS:
            s += 1
        while e > s and base[e - 1] in _V22_WS:
            e -= 1
        if s >= e:
            return False
        near = [ed for ed in edits
                if ed['auto'] and ed['start'] < e + 3 and ed['end'] + 3 > s]
        if not near:
            return False
        if len(near) == 1 and near[0]['start'] <= s and e <= near[0]['end']:
            return True
        ns = min([s] + [ed['start'] for ed in near])
        ne = max([e] + [ed['end'] for ed in near])
        cov_s = min(ed['start'] for ed in near)
        cov_e = max(ed['end'] for ed in near)
        while ns < cov_s and (base[ns] in _V22_SENT or base[ns] == '—'):
            ns += 1
        while ne > cov_e and (base[ne - 1] in _V22_SENT or base[ne - 1] == '—'):
            ne -= 1
        while ns < cov_s and base[ns] in _V22_WS:
            ns += 1
        while ne > cov_e and base[ne - 1] in _V22_WS:
            ne -= 1
        if ns >= cov_s and ne <= cov_e:
            return True
        if re.search(r'[\u4e00-\u9fff]{4}', base[ns:ne]):
            return False
        if len(_V22_DIG_RE.findall(base[ns:ne])) < 2 or not _V22_EVID_RE.search(base[ns:ne]):
            return False
        for ed in near:
            if ed['end'] <= s:
                gap = base[ed['end']:s]
            elif ed['start'] >= e:
                gap = base[e:ed['start']]
            else:
                gap = ''
            if not gap:
                continue
            if len(gap) > 2 or '\n' in gap:
                return False
            for c in gap:
                if c in _V22_SENT or not (
                        _V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c)
                        or (_V22_SEP_RE.match(c) and c not in _V22_SENT)
                        or c in _V22_WS):
                    return False
        old_bounds = {(ed['start'], ed['end']) for ed in near}
        for ts, te in taken:
            if (ts, te) in old_bounds:
                continue
            if ns < te and ts < ne:
                return False
        for ed in near[1:]:
            edits.remove(ed)
        taken[:] = [t for t in taken if t not in old_bounds]
        taken.append((ns, ne))
        first = near[0]
        first.update({'start': ns, 'end': ne, 'deleted': base[ns:ne],
                      'line': bisect.bisect_right(line_starts, ns)})
        if 'N' not in first['rule'].split('+'):
            first['rule'] += '+N'
            first['label'] += ' + 吸收N混淆簇'
        return True

    for key in ('Q', 'N'):
        if key not in enabled or key not in COLLECT_ONLY:
            continue
        label = RULES[key][0]
        for pat in RULES[key][1]():
            if callable(pat):
                for s, e in pat(base):
                    if key == 'N' and _absorb_n(s, e):
                        continue
                    add_edit(key, label, s, e, auto=False)
                continue
            for m in pat.finditer(base):
                if key == 'N' and _absorb_n(m.start(), m.end()):
                    continue
                add_edit(key, label, m.start(), m.end(), auto=False)

    edits.sort(key=lambda x: (x['start'], x['rule']))
    merged = []
    for e_ in edits:
        if merged:
            prev = merged[-1]
            gap = base[prev['end']:e_['start']]
            newline_adjacent = (not gap and prev['end'] > prev['start']
                                and base[prev['end'] - 1] == '\n')
            obf_gap = (not prev['auto'] and not e_['auto'] and 0 < len(gap) <= 6
                       and all((_V22_DIG_RE.match(c) or _V22_HOMO_RE.match(c)
                                or (_V22_SEP_RE.match(c) and c not in _V22_HARD)) for c in gap))
            separate_th_lines = (prev['rule'] == 'TH' and e_['rule'] == 'TH'
                                 and prev['end'] > 0 and base[prev['end'] - 1] == '\n')
            if (not newline_adjacent and not separate_th_lines
                    and prev['auto'] == e_['auto']
                    and (not gap or obf_gap
                         or (len(gap) <= 3 and all(c in '，,、;；: 　\t' for c in gap)))):
                prev['end'] = e_['end']
                while prev['start'] < prev['end'] and base[prev['start']] in _V22_WS:
                    prev['start'] += 1
                while prev['end'] > prev['start'] and base[prev['end'] - 1] in _V22_WS:
                    prev['end'] -= 1
                prev['deleted'] = base[prev['start']:prev['end']]
                if e_['rule'] != prev['rule']:
                    prev['rule'] = f"{prev['rule']}+{e_['rule']}"
                    prev['label'] = f"{prev['label']} + {e_['label']}"
                continue
        merged.append(e_)
    edits = merged
    for i, e_ in enumerate(edits, 1):
        e_['id'] = i
    plan['edits'] = edits
    return plan, base


def apply_plan(base: str, plan: dict, confirmed=None, keep_map=None, replace_map=None):
    """按计划应用删除。返回 (new_text, stats)。

    confirmed=None → 删除全部 auto=True 编辑（默认执行模式，等同 v1.5.2 行为）；
    confirmed=set(ids) → 仅删除指定 id（confirmed-from 真勾选语义），
                         collect-only 候选被使用者勾选后在此一并生效。
    keep_map={id: keep_str} → 部分保留：从删除段中挖掉 keep 子串（保留原文其余删除）。
    replace_map={id: new_str} → v2.2 改删：删除 new_str（就近定位）替代引擎原匹配。
                         审核人在报告「其他」写「删除：<子串>」即此语义；定位不到时
                         跳过该条并计入 stats['改删未定位']（宁可不删也不误删正文）。
    """
    if confirmed is None:
        sel = [e for e in plan['edits'] if e['auto']]
    else:
        sel = [e for e in plan['edits'] if e['id'] in confirmed]
    deletions = []
    stats = {'Z': plan['zw'], 'K': plan['k']}
    for e in sel:
        s, en, d = e['start'], e['end'], e['deleted']
        rep = (replace_map or {}).get(e['id'])
        if rep:
            if rep in base:
                idx = base.find(rep, max(0, s - 60), en + 60)
                if idx == -1:
                    idx = base.find(rep)
                if idx >= 0:
                    deletions.append((idx, idx + len(rep)))
                    stats['改删'] = stats.get('改删', 0) + 1
                    continue
            stats['改删未定位'] = stats.get('改删未定位', 0) + 1
            continue
        keep = (keep_map or {}).get(e['id'], '')
        if keep and keep in d:
            idx = d.find(keep)
            s2, e2 = s + idx, s + idx + len(keep)
            if s < s2:
                deletions.append((s, s2))
            if e2 < en:
                deletions.append((e2, en))
        else:
            deletions.append((s, en))
        stats[e['rule']] = stats.get(e['rule'], 0) + 1
    deletions.sort()
    parts, pos = [], 0
    for s, en in deletions:
        if s < pos:
            continue
        parts.append(base[pos:s])
        pos = en
    parts.append(base[pos:])
    return ''.join(parts), stats


def collapsed_blanks(text: str) -> str:
    """CRLF→LF；4+ 连续空行折叠为 3。"""
    text = text.replace('\r\n', '\n')
    text = re.sub(r'\n{4,}', '\n\n\n', text)
    return text



def process_one(src: Path, dst: Path | None, enabled: set, confirmed=None, keep_map=None,
                replace_map=None, context=None) -> dict:
    raw = src.read_bytes()
    text, encoding = detect_decode(raw)
    text = collapsed_blanks(text).lstrip('\ufeff')
    plan, base = build_plan(text, enabled, context=context)
    _BASE_CACHE[str(src)] = base

    if dst is not None:
        cleaned, stats = apply_plan(base, plan, confirmed=confirmed, keep_map=keep_map,
                                    replace_map=replace_map)
        cleaned = collapsed_blanks(cleaned)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(cleaned.encode('utf-8'))
        product_scan = scan_text(cleaned)
        zw_left = product_scan['zero_width']
        visible_removed = len(base) - len(cleaned)
    else:
        preview, stats = apply_plan(base, plan)
        preview = collapsed_blanks(preview)
        product_scan = None
        zw_left = None
        visible_removed = len(base) - len(preview)

    info = {
        'file': str(src),
        'dst': str(dst) if dst else None,
        'encoding_in': encoding,
        'bytes_before': len(raw),
        'bytes_after': len(preview.encode('utf-8')) if dst is None else len(cleaned.encode('utf-8')),
        'lines_before': text.count('\n'),
        'lines_after': (preview if dst is None else cleaned).count('\n'),
        'rules_hit': stats,
        'plan': plan,
        'input_scan': scan_text(base),
        'product_scan': product_scan,
        'zw_left': zw_left,
        'visible_chars_removed': visible_removed,
        'confirmed_mode': confirmed is not None,
        '_base': base,
    }
    return info


def write_markdown_report(report: list, md_path: Path, enabled: set) -> None:
    """v2.12 格式候选报告（无勾选框纯文本三段）：章节头一次 + 命中总览 + 输入信号扫描；机器审核样本默认照删。"""
    md_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ['# 小说 txt 清洗 - 删除候选报告', '']
    lines.append(f'启用规则: {", ".join(sorted(enabled))}')
    lines.append(f'文件数: {len(report)}')
    total_hits = sum(len(f['plan']['edits']) for f in report)
    lines.append(f'候选总数: {total_hits}')
    lines.append('')
    lines.append('> 人工门禁审查（v2.12 起**无勾选框**，纯文本填写，便于后续精确读取）：')
    lines.append('> - **机器审核样本**：机器建议删除的内容（默认照删）。')
    lines.append('> - **人工复核删除样本**：你确认要删的内容。留空 = 照机器样本删；写入即以此为准（改删/部分保留：只写实际要删的那段）。')
    lines.append('> - **其他**：其他说明。`删除：X` / `改删：X` = 以 X 为删除范围（改删）；`保留` / `不删` = 整条不删。')
    lines.append('> 审核 = 逐条确认：默认照删机器样本；要改删就在「人工复核删除样本」或「其他」写实际范围；要保留就写「保留」。审完给出明确指令后执行。')
    lines.append('> 执行用 `--confirmed-from <本报告>` 时：删「人工复核删除样本」有内容或「其他」含 `删除：/改删：` 的条目；其余默认照删机器样本；「其他」写「保留」则不删（N/Q 仅候选全空默认不删）。')
    lines.append('')
    lines.append('---')
    lines.append('')
    for f in report:
        plan = f['plan']
        book_name = Path(f['file']).stem
        lines.append(f'## {book_name}')
        lines.append('')
        lines.append(f'- 文件: `{f["file"]}`')
        lines.append(f'- 编码: {f["encoding_in"]}  字节差: {f["bytes_after"]-f["bytes_before"]:+d}  行数差: {f["lines_after"]-f["lines_before"]:+d}')
        ins = f['input_scan']
        lines.append(f'- 输入信号扫描: 零宽 {ins["zero_width"]:,} / 异国字母 {ins["foreign"]:,} / 强怪异 {ins["strong"]:,}')
        zw_n, k_n = plan['zw'], plan['k']
        auto_edits = [e for e in plan['edits'] if e['auto']]
        coll_edits = [e for e in plan['edits'] if not e['auto']]
        lines.append('- 命中总览:')
        if zw_n:
            lines.append(f'  - 零宽字符（Z 隐写水印）: **{zw_n:,} 个**不可见字符，将全部删除（可见文本不变）')
        if k_n:
            lines.append(f'  - 引号替换（K）: **{k_n:,} 处**（自动应用，未经勾选；若嵌套单引号为合法引用请 `--skip K`）')
        if plan['k_note']:
            lines.append(f'  - 引号替换（K）: 0 处——{plan["k_note"]}')
        if auto_edits:
            by_rule = {}
            for e in auto_edits:
                by_rule[e['rule']] = by_rule.get(e['rule'], 0) + 1
            detail = '、'.join(f'{k}×{v}' for k, v in sorted(by_rule.items()))
            lines.append(f'  - 可见广告: **{len(auto_edits):,} 处**（{detail}），逐条列于下方，机器审核样本默认照删')
        if coll_edits:
            by_rule = {}
            for e in coll_edits:
                by_rule[e['rule']] = by_rule.get(e['rule'], 0) + 1
            detail = '、'.join(f'{k}×{v}' for k, v in sorted(by_rule.items()))
            lines.append(f'  - 仅候选（N/Q 弱信号）: **{len(coll_edits):,} 条**（{detail}），默认不删；确认后在“人工复核删除样本”或“其他”填写删除范围')
        if not (zw_n or k_n or auto_edits or coll_edits):
            lines.append('  - 无命中（本书无广告/水印）')
        if not plan['edits']:
            lines.append('')
            lines.append('---')
            lines.append('')
            continue
        for e in plan['edits']:
            mode_tag = '(整行)' if e['deleted'] == _line_text(base_of(f), e) else '(片段)'
            lines.append(f"- #{e['id']:03d} [{e['rule']} {e['label']}{mode_tag}·第 {e['line']} 行]")
            lines.append(f'  - 机器审核样本：{e["deleted"]}')
            lines.append(f'  - 人工审核意见：')
            lines.append(f'    - 人工复核删除样本：')
            lines.append(f'    - 其他：')
            lines.append(f'  - 原文：{_line_text(base_of(f), e)}')
            lines.append('')
        lines.append('---')
        lines.append('')
    md_path.write_text('\n'.join(lines), encoding='utf-8')


def base_of(f: dict) -> str:
    """报告条目需要整行原文——从缓存取 base 文本（process_one 存入）。"""
    return f['_base']


def _line_text(base: str, e: dict) -> str:
    ls = base.rfind('\n', 0, e['start']) + 1
    le = base.find('\n', e['end'])
    if le == -1:
        le = len(base)
    return base[ls:le]


def write_result_report(report: list, md_path: Path) -> None:
    """执行结果报告：规则命中数（K/Z 计数）+ 验证断言（含产物信号扫描）。"""
    md_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ['# 小说 txt 清洗 - 执行结果报告', '']
    lines.append('> 实际执行后的结果对账单：规则命中数、体积/行数变化、验证断言（含产物信号扫描）。')
    lines.append('')
    lines.append('---')
    lines.append('')
    for f in report:
        book = Path(f['file']).stem
        lines.append(f'## {book}')
        lines.append('')
        lines.append(f'- 文件: `{f["file"]}`')
        lines.append(f'- 编码: {f["encoding_in"]} → utf-8')
        lines.append(f'- 体积: {f["bytes_before"]:,} → {f["bytes_after"]:,} bytes（{f["bytes_after"]-f["bytes_before"]:+,}）')
        lines.append(f'- 行数: {f["lines_before"]:,} → {f["lines_after"]:,}（{f["lines_after"]-f["lines_before"]:+d}）')
        lines.append(f'- 执行模式: {"按人工审核报告授权执行（--confirmed-from）" if f["confirmed_mode"] else "自动删（全部 auto 候选）"}')
        rules = {k: v for k, v in f['rules_hit'].items() if v}
        if rules:
            lines.append('- 规则命中与执行:')
            for k in sorted(rules):
                label = RULES[k][0] if k in RULES else ''
                if k in ('K', 'Z'):
                    lines.append(f'  - {k} {label}: 识别到 **{rules[k]:,} 个字符**，已全部'
                                 + ('替换' if k == 'K' else '删除'))
                else:
                    lines.append(f'  - {k} {label}: {rules[k]:,} 处，已删除')
        else:
            lines.append('- 规则命中: 无')
        ps = f.get('product_scan')
        zw_left = f.get('zw_left')
        if ps is not None:
            lines.append('- 验证断言（产物信号扫描）:')
            lines.append(f'  - 零宽字符残留: **{zw_left} 个**（应为 0）' + (' ✓' if zw_left == 0 else ' ✗ 异常！'))
            lines.append(f'  - 异国字母残留: {ps["foreign"]:,} 个（广告混淆字母，清洗后应趋近 0）')
            lines.append(f'  - 强怪异字符残留: {ps["strong"]:,} 个')
            lines.append(f'  - 可见字符净删除: **{f["visible_chars_removed"]:,} 个**（应与可见删除候选字符数对账）')
            lines.append(f'  - 行数变化: {f["lines_after"]-f["lines_before"]:+d}（无整行删除时应为 0）')
        lines.append('')
        lines.append('---')
        lines.append('')
    md_path.write_text('\n'.join(lines), encoding='utf-8')


def parse_confirmed_report(md_path: Path) -> dict:
    """解析人工审核后的 v2.12 报告（无勾选框，纯文本三段结构）。返回 {书名stem: [entry, ...]}。

    entry = {'id': int, 'delete': bool, 'partial': str, 'replace': str, 'human_del': str}

    报告每条形如：
      -
        - 机器审核样本：<机器建议删除内容>        ← 默认照删范围
        - 人工审核意见：
          - 人工复核删除样本：<人工确认删除内容>   ← 非空 = 以此为准删除
          - 其他：<说明>                         ← 删除：X/改删：X=改删；保留/不删=不删
        - 原文：<整行原文>

    语义（v2.12，无勾选框，纯文本）：
      - 人工复核删除样本 非空（且非保留标记）→ 删除该内容（replace=该内容，delete=True）。
      - 其他 含「删除：X / 改删：X」→ 改删：replace=X，delete=True（不依赖勾选）。
      - 其他 含保留类标记（保留/不删/keep/整行保留）→ delete=False。
      - 其他 为非前缀纯文本且包含机器样本且更长 → 视为改删（legacy 自然写法），replace=该文本。
      - 其余（全空）：auto 提案默认照删机器样本；N/Q 仅候选默认不删。
    """
    import html as _html

    KEEP_MARKS = ('保留', '不删', 'keep', '整行保留', '整条保留')

    def _md_clean(s: str) -> str:
        """剥离 markdown 编辑器自动添加的格式：**加粗**、HTML实体、反斜杠转义。"""
        s = _html.unescape(s)
        s = s.replace('**', '')
        s = re.sub(r'\\([\\`*_{}\[\]()#+\-.!~^|>])', r'\1', s)
        return s.strip()

    def _is_keep(s: str) -> bool:
        return any(k in s for k in KEEP_MARKS)

    def _field(blk: str, label: str) -> str:
        """取 `- 标签：内容`（兼容前导空格/加粗/转义）的首个值。"""
        m = re.search(r'^[ \t]*-[ \t]*' + label + r'[：:][^\S\n]*(.*)$', blk, re.M)
        return _md_clean(m.group(1)) if m else ''

    text = md_path.read_text(encoding='utf-8')
    result: dict = {}
    headers = [(m.start(), m.group(1).strip()) for m in re.finditer(r'^## (.+)$', text, re.M)]
    for _, hn in headers:
        result.setdefault(hn, [])
    blocks = re.split(r'(?=^- \\?#\d{3} \[)', text, flags=re.MULTILINE)
    for blk in blocks:
        if not re.match(r'^- \\?#\d{3} \[', blk):
            continue
        entry_id = int(re.match(r'^- \\?#(\d{3}) \[', blk).group(1))
        pos = text.find(blk)
        blk = _html.unescape(blk)
        cur = None
        for hp, hn in headers:
            if hp < pos:
                cur = hn
            else:
                break
        if cur is None:
            continue
        hm = re.search(r'^- \\?#\d{3} \[([A-Z])', blk)
        rule_key = hm.group(1) if hm else ''
        machine_del = _field(blk, '机器审核样本')
        human_del = _field(blk, '人工复核删除样本')
        other_text = _field(blk, '其他')
        replace = ''
        partial = ''
        explicit_keep = _is_keep(human_del) or _is_keep(other_text)
        m_rep = re.match(r'^(?:删除|改删)[：:]\s*(.+)$', other_text) if other_text else None
        if m_rep:
            replace = m_rep.group(1).strip()
        elif other_text and not _is_keep(other_text):
            if machine_del and machine_del in other_text and len(other_text) > len(machine_del):
                replace = other_text
        human_override = bool(human_del) and not _is_keep(human_del)
        if human_override and not replace:
            replace = human_del
        if explicit_keep:
            delete = False
        elif replace:
            delete = True
        else:
            delete = (rule_key not in ('N', 'Q')) and bool(machine_del)
        result[cur].append({
            'id': entry_id,
            'delete': delete,
            'partial': partial,
            'replace': replace,
            'human_del': human_del,
        })
    return result


def collect_files(input_path: Path, pattern: str = '*.txt') -> list:
    if input_path.is_file():
        return [input_path]
    return sorted(input_path.rglob(pattern))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', help='输入文件/目录（--selftest 时可省）')
    ap.add_argument('--output', help='输出目录（执行模式必填；保留输入目录树）')
    ap.add_argument('--dry-run', action='store_true', help='不写文件，仅生成候选报告（默认模式）')
    ap.add_argument('--only', help='仅启用这些 key (逗号分隔)')
    ap.add_argument('--skip', help='跳过这些 key')
    ap.add_argument('--limit', type=int, default=None)
    ap.add_argument('--report', help='汇总报告 JSON')
    ap.add_argument('--report-md', help='dry-run 候选报告 Markdown（v1.6 格式 + 输入信号扫描）')
    ap.add_argument('--result-md', help='执行后结果报告 Markdown（含产物信号扫描验证）')
    ap.add_argument('--confirmed-from', help='人工审核后的文本报告：按保留/删除范围语义执行（N/Q 默认不删）')
    ap.add_argument('--scan', action='store_true', help='仅做独立信号扫描（零宽/异国字母/强怪异），不清洗')
    ap.add_argument('--selftest', action='store_true', help='运行回归测试套件（scripts/selftest.py）')
    ap.add_argument('--risk-profile', choices=['conservative', 'balanced', 'aggressive'],
                    default='conservative', help='通用歧义规则强度（默认 conservative）')
    ap.add_argument('--in-place', action='store_true',
                    help='允许原地执行；必须同时提供 --confirm-in-place')
    ap.add_argument('--confirm-in-place', action='store_true',
                    help='确认原地写入并接受输入文件会被替换')
    ap.add_argument('--backup-dir', help='原地执行前的备份目录（默认自动创建）')
    ap.add_argument('--no-backup', action='store_true',
                    help='明确关闭原地执行前备份（不推荐）')
    args = ap.parse_args()

    if args.selftest:
        import runpy
        runpy.run_path(str(Path(__file__).parent / 'selftest.py'), run_name='__main__')
        return 0

    if not args.input:
        ap.error('--input 必填（除非 --selftest）')

    if not args.confirmed_from and not args.dry_run:
        args.dry_run = True
        print('[cleaner] no --confirmed-from supplied; switching to safe dry-run mode')
    if args.dry_run and (args.in_place or args.confirm_in_place):
        ap.error('--dry-run cannot be combined with --in-place/--confirm-in-place')
    if args.in_place and not args.confirm_in_place:
        ap.error('--in-place requires --confirm-in-place')
    if args.confirm_in_place and not args.in_place:
        ap.error('--confirm-in-place requires --in-place')
    if args.no_backup and not args.in_place:
        ap.error('--no-backup is only valid with --in-place')
    if args.confirmed_from and not args.output and not args.in_place:
        ap.error('execution requires --output DIR; use --in-place --confirm-in-place for replacement')

    enabled = set(RULES)
    if args.only:
        enabled = enabled & set(s.strip() for s in args.only.split(','))
    if args.skip:
        enabled -= set(s.strip() for s in args.skip.split(','))

    print(f'[cleaner] enabled rules: {sorted(enabled)}')

    src = Path(args.input)
    if not src.exists():
        print(f'[cleaner] input not found: {src}', file=sys.stderr)
        return 2

    output_dir: Path | None = None
    if args.output:
        output_dir = Path(args.output)
        if src.is_dir() and output_dir.resolve() == src.resolve():
            ap.error('--output must be different from --input; use --in-place for replacement')
        output_dir.mkdir(parents=True, exist_ok=True)

    if args.in_place and not args.no_backup:
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        backup_root = Path(args.backup_dir) if args.backup_dir else src.parent / (
            src.name + '-backup-' + stamp)
        src_abs, backup_abs = src.resolve(), backup_root.resolve()
        if backup_abs == src_abs or src_abs in backup_abs.parents:
            ap.error('--backup-dir must be outside --input')
        if src.is_file():
            backup_root.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, backup_root / src.name)
        else:
            shutil.copytree(src, backup_root, dirs_exist_ok=False)
        print(f'[cleaner] backup created: {backup_root}')

    files = collect_files(src)
    if args.limit:
        files = files[: args.limit]
    print(f'[cleaner] files to process: {len(files)}')

    if args.scan:
        for i, f in enumerate(files, 1):
            raw = f.read_bytes()
            text, enc = detect_decode(raw)
            s = scan_text(text)
            flag = ' ⚠ 有信号' if (s['zero_width'] or s['foreign']) else ' 干净'
            print(f'[{i:>4}/{len(files)}] {f.name[:60]:<60} enc={enc:<12} '
                  f'zw={s["zero_width"]:,} foreign={s["foreign"]:,} strong={s["strong"]:,}{flag}')
        return 0

    confirmed_map = None
    if args.confirmed_from:
        parsed = parse_confirmed_report(Path(args.confirmed_from))
        confirmed_map = {}
        for book, entries in parsed.items():
            ids = {e['id'] for e in entries if e['delete'] or e['partial'] or e['replace']}
            keeps = {e['id']: e['partial'] for e in entries if e['partial']}
            replaces = {e['id']: e['replace'] for e in entries if e['replace']}
            confirmed_map[book] = {'ids': ids, 'keeps': keeps, 'replaces': replaces}
        n_conf = sum(len(v['ids']) for v in confirmed_map.values())
        n_rep = sum(len(v['replaces']) for v in confirmed_map.values())
        print(f'[cleaner] confirmed-from: {args.confirmed_from} → {n_conf} 条删除授权（含改删 {n_rep} 条）')
        if args.dry_run:
            print('[cleaner] --confirmed-from 与 --dry-run 不兼容（dry-run 无需勾选）', file=sys.stderr)
            return 2

    report = []
    for i, f in enumerate(files, 1):
        if args.in_place and not args.dry_run:
            dst = f
        elif output_dir and not args.dry_run:
            rel = f.relative_to(src) if src.is_dir() and f.is_relative_to(src) else Path(f.name)
            dst = output_dir / rel
        else:
            dst = f
        if args.dry_run:
            dst = None
        confirmed = keep_map = replace_map = None
        if confirmed_map is not None:
            stem = f.stem
            if stem not in confirmed_map:
                print(f'[cleaner] ⚠ {f.name} 不在审核报告中——跳过（未获删除授权）')
                continue
            confirmed = confirmed_map[stem]['ids']
            keep_map = confirmed_map[stem]['keeps']
            replace_map = confirmed_map[stem]['replaces']
        info = process_one(f, dst, enabled, confirmed=confirmed, keep_map=keep_map,
                           replace_map=replace_map,
                           context={'risk_profile': args.risk_profile})
        report.append(info)
        print(f'[{i:>4}/{len(files)}] {f.name[:60]:<60} '
              f'enc={info["encoding_in"]:<12} '
              f'rules={ {k: v for k, v in info["rules_hit"].items() if v} } '
              f'Δbytes={info["bytes_after"]-info["bytes_before"]:+d} '
              f'Δlines={info["lines_after"]-info["lines_before"]:+d}')

    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        json_report = []
        for r in report:
            plan = r.get('plan', {})
            json_report.append({
                **{k: v for k, v in r.items() if k not in ('plan', '_base')},
                'edits_total': len(plan.get('edits', [])),
                'auto_edits': sum(1 for e in plan.get('edits', []) if e['auto']),
                'collect_only_edits': sum(1 for e in plan.get('edits', []) if not e['auto']),
            })
        Path(args.report).write_text(
            json.dumps({'enabled': sorted(enabled), 'files': json_report}, ensure_ascii=False, indent=2),
            encoding='utf-8')
        print(f'[cleaner] report -> {args.report}')

    if args.report_md:
        md_path = Path(args.report_md)
        for r in report:
            r['_base'] = _BASE_CACHE.get(r['file'], '')
        write_markdown_report(report, md_path, enabled)
        print(f'[cleaner] markdown report -> {md_path}')
        print(f'[cleaner] 候选总数: {sum(len(f["plan"]["edits"]) for f in report)}')
        print(f'[cleaner] 请人工审阅报告（机器审核样本默认照删；要保留/改删在「人工复核删除样本」或「其他」填写），审完用 --confirmed-from 执行')

    if args.result_md and not args.dry_run:
        result_path = Path(args.result_md)
        write_result_report(report, result_path)
        print(f'[cleaner] result report -> {result_path}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
