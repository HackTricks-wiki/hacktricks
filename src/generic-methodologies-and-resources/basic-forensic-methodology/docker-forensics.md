# Docker 取证

{{#include ../../banners/hacktricks-training.md}}

## 容器修改

有人怀疑某个 Docker 容器已遭入侵：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
你可以轻松地通过以下方式**找出此 container 相对于 image 所做的修改**：
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
在上一条命令中，**C** 表示 **Changed**，**A** 表示 **Added**。\
如果你发现某个有趣的文件（例如 `/etc/shadow`）被修改，可以将其从 container 下载出来，以检查是否存在恶意活动：
```bash
docker cp wordpress:/etc/shadow.
```
你也可以**通过运行一个新容器并从中提取文件，将其与原始文件进行比较**：
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
如果发现**添加了某个可疑文件**，可以访问该 container 并对其进行检查：
```bash
docker exec -it wordpress bash
```
## 镜像修改

当你获得一个导出的 docker image（通常为 `.tar` 格式）时，可以使用 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) 来**提取修改内容摘要**：
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
然后，你可以**解压缩**该镜像并**访问 blobs**，以搜索你可能在变更历史中发现的可疑文件：
```bash
tar -xf image.tar
```
### 基础分析

你可以通过运行以下命令从镜像中获取**基本信息**：
```bash
docker inspect <image>
```
你还可以使用以下命令获取**更改历史摘要**：
```bash
docker history --no-trunc <image>
```
你还可以使用以下命令从镜像生成 **dockerfile**：
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Dive

为了在 Docker 镜像中查找新增/修改的文件，你还可以使用 [**dive**](https://github.com/wagoodman/dive) 工具（从 [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) 下载）：
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
这允许你**浏览 Docker 镜像的不同 blob**，并检查哪些文件被修改或添加。**红色**表示已添加，**黄色**表示已修改。使用 **tab** 切换到另一个视图，使用 **space** 折叠/展开文件夹。

使用 die 无法访问镜像不同阶段的内容。为此，你需要**解压每一层并访问它**。\
你可以在镜像解压后的目录中执行以下命令来解压镜像的所有层：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 从内存中获取 Credentials

请注意，当你在 host 内运行 docker container 时，**你可以从 host 上查看 container 中运行的进程**，只需运行 `ps -ef`。

因此，作为 root，你可以从 host 上**转储进程的内存**，并搜索 **Credentials**，正如[**以下示例所示**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory)。

{{#include ../../banners/hacktricks-training.md}}
