<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>でAWSハッキングをゼロからヒーローまで学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**か**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする：[**@carlospolopm**](https://twitter.com/carlospolopm)。
- **ハッキングテクニックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>


# コンテナ内のSELinux

[Red Hatのドキュメントからの紹介と例](https://www.redhat.com/sysadmin/privileged-flag-container-engines)

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux)は**ラベリングシステム**です。すべての**プロセス**と**ファイル**システムオブジェクトには**ラベル**があります。SELinuxポリシーは、システム上の他のすべてのラベルと何を**プロセスラベルが許可されているか**についてのルールを定義します。

コンテナエンジンは、通常`container_t`という1つの制限付きSELinuxラベルで**コンテナプロセスを起動**し、その後コンテナ内のコンテナを`container_file_t`としてラベル付けします。SELinuxポリシールールは基本的に、**`container_t`プロセスが`container_file_t`とラベル付けされたファイルを読み取り/書き込み/実行できる**と言っています。コンテナプロセスがコンテナを脱出してホスト上のコンテンツに書き込もうとすると、Linuxカーネルはアクセスを拒否し、コンテナプロセスが`container_file_t`とラベル付けされたコンテンツにのみ書き込むことを許可します。
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
# SELinuxユーザー

通常のLinuxユーザーに加えて、SELinuxユーザーが存在します。SELinuxユーザーはSELinuxポリシーの一部です。各Linuxユーザーはポリシーの一部としてSELinuxユーザーにマッピングされます。これにより、LinuxユーザーはSELinuxユーザーに配置された制限やセキュリティルール、メカニズムを継承することができます。
