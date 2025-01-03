{{#include ../../banners/hacktricks-training.md}}

在钓鱼评估中，有时完全**克隆一个网站**可能会很有用。

请注意，您还可以向克隆的网站添加一些有效载荷，例如 BeEF hook，以“控制”用户的标签。

您可以使用不同的工具来实现此目的：

## wget
```text
wget -mk -nH
```
## goclone
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## 社会工程工具箱
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
{{#include ../../banners/hacktricks-training.md}}
