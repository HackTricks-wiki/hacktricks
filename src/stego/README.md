# Stego

{{#include ../banners/hacktricks-training.md}}

本节侧重于**从文件（图像/音频/视频/文档/归档）和基于文本的 steganography 中发现并提取隐藏数据**。

如果你是来研究密码学攻击的，请移步 **Crypto** 部分。

## 入口点

把 steganography 当作取证问题来处理：先识别真实容器，枚举高信号位置（metadata、appended data、embedded files），然后再应用内容级的提取技术。

### 工作流与分诊

一个结构化的工作流程，优先进行容器识别、metadata/字符串检查、carving，以及针对格式的分支处理。
{{#ref}}
workflow/README.md
{{#endref}}

### 图像

大多数 CTF stego 都在这里：LSB/bit-planes（PNG/BMP）、chunk/file-format weirdness、JPEG tooling，以及多帧 GIF 技巧。
{{#ref}}
images/README.md
{{#endref}}

### 音频

频谱图消息、样本 LSB 嵌入，以及电话按键音（DTMF）是常见模式。
{{#ref}}
audio/README.md
{{#endref}}

### 文本

如果文本显示正常但行为异常，考虑 Unicode homoglyphs、zero-width characters，或基于空白的编码。
{{#ref}}
text/README.md
{{#endref}}

### 文档

PDFs 和 Office 文件首先是容器；攻击通常围绕 embedded files/streams、object/relationship graphs，以及 ZIP 提取展开。
{{#ref}}
documents/README.md
{{#endref}}

### Malware 和 delivery-style steganography

Payload delivery 经常使用看起来合法的文件（例如 GIF/PNG），这些文件携带标记分隔的文本 payloads，而不是像素级隐藏。
{{#ref}}
malware-and-network/README.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
