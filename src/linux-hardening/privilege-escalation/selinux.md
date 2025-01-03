{{#include ../../banners/hacktricks-training.md}}

# コンテナにおけるSELinux

[Red Hatのドキュメントからの紹介と例](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) は **ラベリング** **システム** です。すべての **プロセス** とすべての **ファイル** システムオブジェクトには **ラベル** があります。SELinuxポリシーは、**プロセスラベルがシステム上の他のすべてのラベルに対して何をすることが許可されているか** に関するルールを定義します。

コンテナエンジンは、通常 `container_t` の単一の制限されたSELinuxラベルを持つ **コンテナプロセス** を起動し、その後コンテナ内のコンテナを `container_file_t` とラベル付けします。SELinuxポリシールールは基本的に、**`container_t` プロセスは `container_file_t` とラベル付けされたファイルのみを読み書き/実行できる** と述べています。コンテナプロセスがコンテナから脱出し、ホスト上のコンテンツに書き込もうとすると、Linuxカーネルはアクセスを拒否し、コンテナプロセスが `container_file_t` とラベル付けされたコンテンツにのみ書き込むことを許可します。
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinux ユーザー

通常の Linux ユーザーに加えて、SELinux ユーザーも存在します。SELinux ユーザーは SELinux ポリシーの一部です。各 Linux ユーザーはポリシーの一部として SELinux ユーザーにマッピングされます。これにより、Linux ユーザーは SELinux ユーザーに課せられた制限やセキュリティルール、メカニズムを継承することができます。

{{#include ../../banners/hacktricks-training.md}}
