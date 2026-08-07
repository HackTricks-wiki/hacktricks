# 克隆网站

{{#include ../../banners/hacktricks-training.md}}


在进行 phishing assessment 时，有时完全**克隆/转储网站**可能会很有用。

请注意，你还可以向克隆的网站添加一些 payload，例如 BeEF hook，以便“控制”用户的标签页。

你可以使用不同的工具来实现这一目的：

## wget
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## 社会工程学工具包
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
