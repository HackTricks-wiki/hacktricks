# Crypto CTF 杂项

{{#include ../../banners/hacktricks-training.md}}

本节汇总了密码学挑战中会出现、但无法很好地归入其他类别的技术。

## Esoteric languages

### 技术

当挑战要求运行 Esoteric language 程序并解码其输出时，可以使用以下流程。

如果挑战提供的代码看起来不像标准语言：

- 通过搜索具有独特特征的 token 或指令序列来识别该语言。
- 使用在线解释器或 Docker image。
- 如果输出内容很奇怪，请在执行后检查是否存在分层编码或压缩。

一个实用的语言索引是 Esolang wiki。<sup>[[1]](#references)</sup>

## References

- [1] [Esolang，Esoteric programming languages wiki](https://esolangs.org/wiki/Main_Page)
{{#include ../../banners/hacktricks-training.md}}
