# Docker 取证

## 容器修改

有迹象表明某个 Docker 容器可能已被入侵：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
你可以轻松**查找自此容器创建以来对其文件系统所做的更改**：<sup>[[1]](#references)</sup>
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
在前一个命令中，**C** 表示 **Changed**，**A** 表示 **Added**。<sup>[[1]](#references)</sup>\
如果你发现类似 `/etc/shadow` 这样的有趣文件被修改，可以使用以下命令将其从 container 下载下来，以检查是否存在恶意活动：<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
你还可以**将其与原始文件进行比较**，方法是运行一个新的 container 并从中提取该文件：<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
如果发现**添加了某个可疑文件**，可以访问该 container 并检查它：<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## 镜像修改

当你获得一个导出的 docker image（可能为 `.tar` 格式）时，可以使用 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) 来**提取修改内容摘要**：<sup>[[5]](#references)[[6]](#references)</sup>
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
然后，你可以**解压缩**该镜像并**访问 blobs**，以搜索你可能在变更历史中发现的可疑文件：<sup>[[7]](#references)</sup>
```bash
tar -xf image.tar
```
### 基础分析

你可以通过运行以下命令从镜像中获取**基本信息**：<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
你还可以通过以下方式获取**更改历史摘要**：<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
你还可以从一个 **image** 生成 **dockerfile**：<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

为了查找 docker images 中新增或修改的文件，你还可以使用 [**dive**](https://github.com/wagoodman/dive) 工具（从 [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) 下载）：<sup>[[11]](#references)[[12]](#references)</sup>

在使用 dive 打开其 image tag 之前，先将保存的 archive 加载到 Docker 中：<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
这允许你**浏览 docker images 的不同 blobs**，并检查哪些文件被修改/添加/删除。使用 **tab** 移动到其他视图，使用 **space** 折叠/展开文件夹。<sup>[[11]](#references)</sup>

使用 dive，你无法访问 image 的不同 stages 的内容。为此，你需要**解压每个 layer 并访问它**。\
你可以在 image 已解压的目录中执行以下命令，解压 image 的所有 layers：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 内存中的凭据

在 Linux 上，主机的祖先进程 PID namespace 可以查看容器的子 PID namespace 中的进程，因此主机上的进程列表命令（例如 `ps -ef`）可以显示这些进程。<sup>[[14]](#references)</sup>

当主机凭据、capabilities 以及 LSM/ptrace 策略允许时，具备适当权限的主机调查人员可以**dump 进程内存**，并搜索**凭据**，正如[**以下示例所示**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory)。<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff analyzer 定义](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 发布](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
