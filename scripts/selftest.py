#!/usr/bin/env python3
"""Small, public, synthetic regression suite for novel-txt-cleaner."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("clean_novels", ROOT / "clean_novels.py")
mod = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(mod)

passed = 0
failed = 0


def check(name: str, condition: bool) -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"PASS {name}")
    else:
        failed += 1
        print(f"FAIL {name}")


def cleaned(text: str, *, profile: str = "conservative") -> tuple[str, dict]:
    plan, base = mod.build_plan(text, set(mod.RULES), {"risk_profile": profile})
    return mod.apply_plan(base, plan)


def main() -> int:
    out, stats = cleaned("正文。\u200b\u200c广告")
    check("zero-width characters are removed", "\u200b" not in out and "\u200c" not in out)
    check("visible text is preserved", out == "正文。广告")
    out, _ = cleaned("他说‘你好’。")
    check("quote replacement remains available", "‘" not in out and '"' in out)
    out, _ = cleaned("采墨阁为您搜集整理TXT下载\n")
    check("site watermark line is detected", "采墨阁" not in out)
    out, _ = cleaned("他说：‘这是正文。’92'4|1?5!76#5@4")
    check("mixed tail keeps the sentence", "这是正文" in out and "92'4" not in out)
    out, _ = cleaned("正文。更多好文请联系群⑨⓪⑧")
    check("anchored ad is detected", "更多好文" not in out)
    out, _ = cleaned("普通段落：今年45岁，身高180cm。")
    check("ordinary numeric prose is retained", out == "普通段落：今年45岁，身高180cm。")
    out, _ = cleaned("[1] 第一项\n[2] 第二项\n[3] 第三项")
    check("numbered list is retained", out == "[1] 第一项\n[2] 第二项\n[3] 第三项")
    for profile in ("conservative", "balanced", "aggressive"):
        mod.build_plan("普通文本", set(mod.RULES), {"risk_profile": profile})
        check(f"risk profile {profile} is accepted", mod._RISK_PROFILE == profile)
    text, enc = mod.detect_decode("\ufeff正文".encode("utf-8"))
    check("UTF-8 BOM is detected and stripped", enc == "utf-8-bom" and text == "正文")
    text, enc = mod.detect_decode("正文".encode("gb18030"))
    check("GB18030 is decoded", enc == "gb18030" and text == "正文")
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "input.txt"
        src.write_bytes("\ufeff正文。\r\n".encode("utf-8"))
        info = mod.process_one(src, None, set(mod.RULES), context={"risk_profile": "conservative"})
        check("dry-run does not write", src.read_bytes() == "\ufeff正文。\r\n".encode("utf-8"))
        check("dry-run reports input signals", "input_scan" in info and info["product_scan"] is None)
    print(f"selftest: {passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
