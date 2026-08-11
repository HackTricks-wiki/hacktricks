# Cloning a Website

{{#include ../../banners/hacktricks-training.md}}

在 phishing assessment 中，有时完全 **clone/dump a website** 可能会很有用。

请注意，你还可以向 cloned website 添加一些 payload，例如 BeEF hook，以“控制”用户的选项卡。

你可以使用不同的工具来实现这一目的：

## wget

以下命令使用 Wget 的镜像、页面所需资源、链接转换和扩展名调整模式，然后通过 Python 的 `http.server` 模块，在端口 8000 上从当前目录提供下载的文件。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
wget --mirror --page-requisites --convert-links --adjust-extension <URL>
cd <URL>
python3 -m http.server 8000
```
## goclone

goclone repository 将该 utility 描述为：将网站下载到本地目录，同时保留其相对链接结构，并记录了 `goclone <url>` 的调用方式。<sup>[[3]](#references)</sup>
```bash
#https://github.com/imthaghost/goclone
goclone <url>
```
## 社会工程学工具包

Social-Engineer Toolkit（SET）仓库将 SET 定义为一个开源的 penetration-testing framework，用于经授权的社会工程学评估。<sup>[[4]](#references)</sup>
```bash
#https://github.com/trustedsec/social-engineer-toolkit
```
## References

- [1] [GNU Wget 手册](https://www.gnu.org/software/wget/manual/wget.html)
- [2] [Python `http.server` 文档](https://docs.python.org/3/library/http.server.html)
- [3] [goclone 仓库](https://github.com/imthaghost/goclone)
- [4] [Social-Engineer Toolkit 仓库](https://github.com/trustedsec/social-engineer-toolkit)
{{#include ../../banners/hacktricks-training.md}}
