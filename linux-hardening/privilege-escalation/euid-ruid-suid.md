# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**最新のPEASSバージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。これは私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**にフォローしてください。**
* **[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。**

</details>

### ユーザー識別変数

- **`ruid`**: **実ユーザーID**は、プロセスを開始したユーザーを示します。
- **`euid`**: **有効ユーザーID**として知られ、システムがプロセスの権限を判断するために使用するユーザーのアイデンティティを表します。通常、`euid`は`ruid`を反映していますが、SetUIDバイナリの実行のような場合には、`euid`はファイル所有者のアイデンティティを引き継ぎ、特定の操作権限を付与します。
- **`suid`**: **保存されたユーザーID**は、高権限プロセス（通常はrootとして実行される）が一時的に権限を放棄して特定のタスクを実行し、後で元の高いステータスを再取得する必要がある場合に重要です。

#### 重要な注意
root以外で動作するプロセスは、`euid`を現在の`ruid`、`euid`、または`suid`に一致させることしかできません。

### set*uid関数の理解

- **`setuid`**: 最初の仮定とは異なり、`setuid`は主に`ruid`ではなく`euid`を変更します。特に、特権プロセスの場合、指定されたユーザー（通常はroot）に`ruid`、`euid`、`suid`を合わせ、`suid`の上書きによりこれらのIDを固定します。詳細は[setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)で見ることができます。
- **`setreuid`** と **`setresuid`**: これらの関数は、`ruid`、`euid`、`suid`の微調整を可能にします。ただし、その機能はプロセスの権限レベルに依存しています。非rootプロセスの場合、変更は現在の`ruid`、`euid`、`suid`の値に制限されます。対照的に、rootプロセスまたは`CAP_SETUID`機能を持つプロセスは、これらのIDに任意の値を割り当てることができます。詳細は[setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)と[setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)で得られます。

これらの機能はセキュリティメカニズムとしてではなく、プログラムがその有効ユーザーIDを変更して別のユーザーのアイデンティティを採用するなど、意図した操作フローを容易にするために設計されています。

特に、`setuid`はすべてのIDをrootに合わせるため、rootへの権限昇格によく使用されますが、さまざまなシナリオでユーザーIDの動作を理解し操作するためには、これらの関数の違いを区別することが重要です。

### Linuxでのプログラム実行メカニズム

#### **`execve` システムコール**
- **機能**: `execve`は、最初の引数で指定されたプログラムを開始します。引数用の`argv`配列と環境用の`envp`配列の2つの配列引数を取ります。
- **動作**: 呼び出し元のメモリ空間を保持しますが、スタック、ヒープ、データセグメントを新しくします。プログラムのコードは新しいプログラムに置き換えられます。
- **ユーザーIDの保持**:
- `ruid`、`euid`、および補助グループIDは変更されません。
- 新しいプログラムにSetUIDビットが設定されている場合、`euid`に微妙な変更があるかもしれません。
- 実行後、`suid`は`euid`から更新されます。
- **ドキュメント**: 詳細は[`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)で見ることができます。

#### **`system` 関数**
- **機能**: `execve`とは異なり、`system`は`fork`を使用して子プロセスを作成し、その子プロセス内で`execl`を使用してコマンドを実行します。
- **コマンド実行**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`を使用して`sh`経由でコマンドを実行します。
- **動作**: `execl`は`execve`の一形態であるため、新しい子プロセスのコンテキストで同様に動作します。
- **ドキュメント**: さらなる洞察は[`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)から得られます。

#### **SUIDを持つ`bash`と`sh`の動作**
- **`bash`**:
- `euid`と`ruid`の扱いに影響を与える`-p`オプションがあります。
- `-p`なしでは、初期に`euid`と`ruid`が異なる場合、`bash`は`euid`を`ruid`に設定します。
- `-p`ありでは、初期の`euid`が保持されます。
- 詳細は[`bash` man page](https://linux.die.net/man/1/bash)で見ることができます。
- **`sh`**:
- `bash`の`-p`に類似したメカニズムは持っていません。
- ユーザーIDに関する動作は、`euid`と`ruid`の等価性の保持を強調する`-i`オプションの下でのみ明示的に言及されています。
- 追加情報は[`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)で利用可能です。

これらのメカニズムは、それぞれが異なる操作を提供し、プログラム間の実行と移行のための多様な選択肢を提供し、ユーザーIDがどのように管理され、保持されるかに特定のニュアンスがあります。

### 実行におけるユーザーIDの動作のテスト

以下の例はhttps://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jailから取られており、さらなる情報についてはそちらをチェックしてください。

#### ケース1: `setuid`を`system`と組み合わせて使用する

**目的**: `setuid`を`system`および`sh`としての`bash`と組み合わせた場合の効果を理解する。

**Cコード**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
system("id");
return 0;
}
```
**コンパイルと権限:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `ruid` と `euid` はそれぞれ99（nobody）と1000（frank）から始まります。
* `setuid` は両方を1000に合わせます。
* `system` はshからbashへのシンボリックリンクのため、`/bin/bash -c id` を実行します。
* `-p` なしの `bash` は `euid` を `ruid` に合わせるため、両方とも99（nobody）になります。

#### ケース2: setreuid と system を使用する

**C コード**:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setreuid(1000, 1000);
system("id");
return 0;
}
```
**コンパイルと権限:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**実行と結果：**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `setreuid` は ruid と euid の両方を 1000 に設定します。
* `system` は bash を呼び出し、ユーザー ID が等しいため、frank として効果的に操作します。

#### ケース 3: execve での setuid の使用
目的: setuid と execve の相互作用を探る。
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**実行と結果：**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `ruid` は99のままですが、euidはsetuidの効果に従って1000に設定されます。

**C言語の例 2 (Bashの呼び出し):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**実行と結果：**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `setuid`によって`euid`は1000に設定されますが、`-p`がないため、`bash`は`euid`を`ruid`(99)にリセットします。

**Cのコード例 3 (`bash -p`を使用する場合):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
setuid(1000);
execve(paramList[0], paramList, NULL);
return 0;
}
```
**実行と結果：**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
# 参考文献
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**に**フォローしてください。**
* **[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。**

</details>
