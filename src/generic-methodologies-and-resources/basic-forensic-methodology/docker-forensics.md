# Docker Forensics

{{#include ../../banners/hacktricks-training.md}}

## 容器修改

有人怀疑某个 Docker 容器遭到入侵：
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
你可以轻松**查找自此 container 创建以来对其文件系统所做的更改**：<sup>[[1]](#references)</sup>
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
在之前的命令中，**C** 表示 **Changed**，**A** 表示 **Added**。<sup>[[1]](#references)</sup>\
如果发现某个有趣的文件（例如 `/etc/shadow`）被修改，可以使用以下命令将其从 container 中下载下来，以检查是否存在恶意活动：<sup>[[2]](#references)</sup>
```bash
docker cp wordpress:/etc/shadow shadow
```
你还可以通过运行一个新的 container 并从中提取文件，将其与**原始文件**进行比较：<sup>[[2]](#references)[[3]](#references)</sup>
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
如果发现**添加了某个可疑文件**，你可以访问该容器并进行检查：<sup>[[4]](#references)</sup>
```bash
docker exec -it wordpress bash
```
## 镜像修改

当你获得一个导出的 docker image（可能为 `.tar` 格式）时，可以使用 [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) 来**提取修改摘要**：<sup>[[5]](#references)[[6]](#references)</sup>
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

运行以下命令可以从镜像中获取**基本信息**：<sup>[[8]](#references)</sup>
```bash
docker inspect <image>
```
你还可以通过以下方式获取**变更历史摘要**：<sup>[[9]](#references)</sup>
```bash
docker history --no-trunc <image>
```
你还可以使用以下命令从 **image** 生成 **dockerfile**：<sup>[[10]](#references)</sup>
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers
```
### Dive

为了在 Docker images 中查找新增/修改的文件，你也可以使用 [**dive**](https://github.com/wagoodman/dive)（从 [**releases**](https://github.com/wagoodman/dive/releases/tag/v0.10.0) 下载）工具：<sup>[[11]](#references)[[12]](#references)</sup>

在使用 dive 打开其 image tag 之前，先将保存的 archive 加载到 Docker 中：<sup>[[11]](#references)[[13]](#references)</sup>
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
这允许你**浏览 docker images 的不同 blobs**，并检查哪些文件被修改/添加/删除。使用 **tab** 移动到其他视图，并使用 **space** 折叠/展开文件夹。<sup>[[11]](#references)</sup>

使用 dive 无法访问 image 的不同 stages 的内容。为此，你需要**解压每个 layer 并访问它**。\
你可以在 image 已解压的目录中执行以下命令来解压 image 的所有 layers：
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## 从内存中获取 Credentials

在 Linux 上，主机的祖先进程 PID namespace 可以查看容器的子进程 PID namespace 中的进程，因此主机上的 `ps -ef` 等进程列表命令可以显示这些进程。<sup>[[14]](#references)</sup>

当主机的 credentials、capabilities 以及 LSM/ptrace policy 允许时，拥有适当权限的主机调查人员可以**转储进程内存**并搜索 **credentials**，具体[**如以下示例所示**](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#process-memory)。<sup>[[15]](#references)</sup>

## References

- [1] [Docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- [2] [Docker container cp](https://docs.docker.com/reference/cli/docker/container/cp/)
- [3] [Docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [4] [Docker container exec](https://docs.docker.com/reference/cli/docker/container/exec)
- [5] [GoogleContainerTools/container-diff](https://github.com/GoogleContainerTools/container-diff)
- [6] [container-diff analyzer definitions](https://github.com/GoogleContainerTools/container-diff/blob/master/differs/differs.go)
- [7] [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/)
- [8] [Docker image inspect](https://docs.docker.com/reference/cli/docker/image/inspect/)
- [9] [Docker image history](https://docs.docker.com/reference/cli/docker/image/history/)
- [10] [alpine-docker/dfimage](https://github.com/alpine-docker/dfimage)
- [11] [Dive v0.10.0 README](https://github.com/wagoodman/dive/blob/v0.10.0/README.md)
- [12] [Dive v0.10.0 release](https://github.com/wagoodman/dive/releases/tag/v0.10.0)
- [13] [Docker image load](https://docs.docker.com/reference/cli/docker/image/load/)
- [14] [pid_namespaces(7)](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)
- [15] [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html)
{{#include ../../banners/hacktricks-training.md}}
