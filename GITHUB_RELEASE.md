# novel-txt-cleaner 公开版1.0

这是一个面向公开分享的中文 TXT 文本清洗工具包，用于识别并清理常见的水印、广告尾巴、群号签名、混淆文本和隐写字符。

## 本版亮点

- 默认 dry-run，只生成报告，不直接修改原文件
- 执行前要求明确指定确认报告和输出目录
- 原地修改需要显式确认，并自动创建备份
- 支持 UTF-8、UTF-8-BOM、GB18030、UTF-16LE 等常见编码
- 保留人工逐条复核、原文命中校验和结果验证流程
- 测试样本全部为合成文本，不包含真实作品或私人数据

## 快速开始

```bash
python3 scripts/clean_novels.py --help
python3 scripts/clean_novels.py --input ./samples --report ./reports/dry-run.md
python3 scripts/clean_novels.py --input ./samples \
  --confirmed-from ./reports/reviewed.md \
  --output ./cleaned
```

请先阅读 `README.md`、`SKILL.md` 和 `docs/privacy-and-safety.md`，再处理真实文本。

## 安全边界

报告可能包含输入文件名、路径和原文片段。分享报告前，请检查并删除其中的敏感信息。不要将真实文本、账号信息或私人台账提交到公开仓库。

## 兼容性

- Python 3.9+
- macOS、Linux、Windows（使用对应 Python 环境）

## 校验

```bash
python3 scripts/check_public_release.py
python3 scripts/selftest.py
```

