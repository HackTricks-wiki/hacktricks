# Stego

{{#include ../banners/hacktricks-training.md}}

本节重点介绍从文件（图像/音频/视频/文档/压缩包）以及基于文本的 steganography 中**查找和提取隐藏数据**。

如果你要进行 cryptographic attacks，请前往 **Crypto** 部分。

## Entry Point

将 steganography 作为取证问题处理：识别真实容器，枚举高信号位置（metadata、追加数据、嵌入文件），然后再应用内容级提取技术。

### Workflow & triage

一种结构化 workflow，优先进行容器识别、metadata/string 检查、carving，以及根据格式进行分支处理。

{{#ref}}
workflow/README.md
{{#endref}}

### Images

大多数 CTF stego 内容所在的领域：LSB/bit-planes（PNG/BMP）、chunk/文件格式异常、JPEG tooling，以及多帧 GIF 技巧。

{{#ref}}
images/README.md
{{#endref}}

### Audio

Spectrogram 消息、sample LSB embedding，以及电话键盘音调（DTMF）都是常见模式。

{{#ref}}
audio/README.md
{{#endref}}

### Text

如果文本正常渲染但行为异常，请考虑 Unicode homoglyphs、zero-width characters 或基于 whitespace 的 encoding。

{{#ref}}
text/README.md
{{#endref}}

### Documents

PDF 和 Office 文件首先是容器；攻击通常围绕嵌入文件/streams、object/relationship graphs 以及 ZIP extraction 展开。

{{#ref}}
documents/README.md
{{#endref}}

### Malware and delivery-style steganography

Payload delivery 经常使用看似有效的文件（例如 GIF/PNG）来携带由 marker 分隔的文本 payload，而不是进行像素级隐藏。

{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
