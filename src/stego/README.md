# Stego

{{#include ../banners/hacktricks-training.md}}

本节重点介绍如何从图像、音频、视频、文档、存档和文本中**发现并提取隐藏数据**。Steganography 通过将数据嵌入其他数据中来隐藏通信的存在。<sup>[[1]](#references)</sup>

如果你是来了解 cryptographic attacks 的，请前往 **Crypto** 部分。

## Entry Point

将 steganography 视为一个取证问题：识别真实容器，枚举高信号位置（metadata、追加数据、嵌入文件），然后再应用内容级提取技术。

### Workflow & triage

一种结构化 workflow，优先进行容器识别、metadata/string 检查、carving，以及特定格式的分支处理。

{{#ref}}
workflow/README.md
{{#endref}}

### Images

大多数 CTF stego 都发生在这里：LSB/bit-planes（PNG/BMP）、chunk/file-format 异常、JPEG 工具，以及多帧 GIF 技巧。

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram 消息、sample LSB embedding，以及电话键盘音调（DTMF）都是常见模式。

{{#ref}}
audio/README.md
{{#endref}}

### Text

如果文本正常渲染但行为异常，请考虑 Unicode homoglyphs、zero-width characters 或基于空白的编码。

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDF 和 Office 文件首先是容器；攻击通常围绕嵌入文件/streams、对象/relationship 图以及 ZIP 提取展开。

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery 可以使用看似有效的文件，例如 GIF 或 PNG 图像；这些文件携带由标记分隔的文本 payload，而不是将数据隐藏在像素中。

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC 术语表 - Steganography](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
