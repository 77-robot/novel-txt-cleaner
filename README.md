# novel-txt-cleaner 公开版1.0

一个面向中文 TXT 的广告与水印候选清理工具。它识别常见的整行/行尾/行中推广文本、混淆数字号段、零宽字符和编码问题，并把每个可见删除范围交给人审。

## 安全模型

- 默认是 dry-run，不写入输入文件。
- 执行必须使用人工审核后的 `--confirmed-from` 报告和显式 `--output` 目录。
- 原地执行必须同时使用 `--in-place --confirm-in-place`；默认先创建可恢复备份。
- 弱信号候选默认保留。无法定位人工指定片段时跳过删除并记录。
- 输出统一为 UTF-8、LF、无 BOM；输入目录树和文件名保持不变。

## 快速使用

```bash
# 1. 生成候选报告（不改原文件）
python3 scripts/clean_novels.py --input ./books --dry-run \
  --report-md ./reports/clean-report.md

# 2. 人工编辑报告中的“人工复核删除样本”或“其他”栏

# 3. 输出到新目录并生成结果报告
python3 scripts/clean_novels.py --input ./books \
  --output ./books-cleaned --confirmed-from ./reports/clean-report.md \
  --result-md ./reports/clean-result.md

# 只做独立信号扫描
python3 scripts/clean_novels.py --input ./books --scan

# 运行公开合成回归集
python3 scripts/clean_novels.py --selftest
```

`--risk-profile` 可选 `conservative`（默认）、`balanced`、`aggressive`，只影响歧义的整行/尾部启发式规则；它不代表任何内容类别。

## 人工裁决协议

报告的每条可见候选包含文件、1-based 物理行号、规则、机器样本和原文。空白表示接受机器建议；写“保留”或“不删”表示保留；写 `删除：文本`、`改删：文本` 或在人工复核栏填写文本表示只删除指定范围。引号替换和零宽字符以汇总方式记录，不把不可见字符铺进报告。

## 边界

本工具只处理广告/水印和文本编码清理，不负责章节整理、简介生成、内容审查或版权判断。任何规则都可能遇到新变体；发布前应运行 dry-run，并人工核对候选及结果报告。

## 隐私

工具不联网、不上传输入内容，不要求书名、账号、台账或外部服务。报告可能包含输入文件名、路径和原文片段，请在分享前自行检查并删除敏感内容。公开测试只使用合成样本。

详见 [docs/workflow.md](docs/workflow.md)、[docs/privacy-and-safety.md](docs/privacy-and-safety.md) 和 [MIGRATION.md](MIGRATION.md)。
