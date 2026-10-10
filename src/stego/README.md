# Stego

{{#include ../banners/hacktricks-training.md}}

本节重点介绍如何从图像、音频、视频、文档、归档文件和文本中**发现并提取隐藏数据**。隐写术通过将数据嵌入其他数据中，隐藏通信的存在。<sup>[[1]](#references)</sup>

如果你要查找的是密码学攻击，请前往 **Crypto** 章节。

## Entry Point

将隐写术视为取证问题：识别真实容器，枚举高价值位置（元数据、附加数据、嵌入文件），然后再应用内容级提取技术。

### 工作流程与初步筛查

采用结构化工作流程，优先识别容器、检查元数据和字符串、雕刻数据，并根据格式采取相应的分析方法。

{{#ref}}
workflow/README.md
{{#endref}}

### 图像

大多数 CTF 隐写都出现在这里：LSB/位平面（PNG/BMP）、数据块/文件格式异常、JPEG 工具，以及多帧 GIF 技巧。

{{#ref}}
images/README.md
{{#endref}}

### 音频

频谱图消息、样本 LSB 嵌入，以及电话键盘音调（DTMF）都是常见模式。

{{#ref}}
audio/README.md
{{#endref}}

### 文本

如果文本显示正常但表现异常，请考虑 Unicode 同形异义字符、零宽字符或基于空白字符的编码。

{{#ref}}
text/README.md
{{#endref}}

### 文档

PDF 和 Office 文件首先是容器；攻击通常围绕嵌入文件/数据流、对象/关系图以及 ZIP 提取展开。

{{#ref}}
documents/README.md
{{#endref}}

### 恶意软件与投递式隐写

Payload 投递可以使用看似有效的文件，例如 GIF 或 PNG 图像，其中包含由标记分隔的文本 payload，而不是将数据隐藏在像素中。

{{#ref}}
malware-and-network/README.md
{{#endref}}

## References

- [1] [NIST CSRC 术语表 - 隐写术](https://csrc.nist.gov/glossary/term/steganography)
{{#include ../banners/hacktricks-training.md}}
