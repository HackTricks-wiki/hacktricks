# euid、ruid、suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>

**この投稿は、**[**https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail**](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)**からコピーされました**

## **`*uid`**

* **`ruid`**: これはプロセスを開始したユーザーの**実ユーザーID**です。
* **`euid`**: これは**有効なユーザーID**であり、システムは**プロセスがどの特権を持つかを決定する**際に参照します。ほとんどの場合、`euid`は`ruid`と同じになりますが、SetUIDバイナリはこの場合と異なる例です。SetUIDバイナリが起動すると、**`euid`はファイルの所有者に設定され**、これによりこれらのバイナリが機能することができます。
* `suid`: これは**保存されたユーザーID**であり、特権プロセス（ほとんどの場合はrootとして実行される）が一部の動作を行うために**特権を降下**する必要があるが、その後**特権状態に戻る**必要がある場合に使用されます。

{% hint style="info" %}
**非ルートプロセス**が**`euid`を変更**したい場合、**現在の`ruid`**、**`euid`**、または**`suid`**の値に**設定**することしかできません。
{% endhint %}

## set\*uid

最初に見ると、**`setuid`**システムコールは`ruid`を設定すると思われるかもしれません。実際には、特権プロセスの場合はそうです。しかし、一般的な場合では、実際には**`euid`を設定**します。[manページ](https://man7.org/linux/man-pages/man2/setuid.2.html)から：

> setuid()は、**呼び出し元プロセスの有効なユーザーIDを設定**します。呼び出し元プロセスが特権を持っている場合（より正確には、プロセスがユーザーネームスペースのCAP\_SETUID機能を持っている場合）、実ユーザーIDと保存された設定ユーザーIDも設定されます。

したがって、rootとして`setuid(0)`を実行している場合、これはすべてのIDをrootに設定し、基本的にそれらをロックします（`suid`が0であるため、以前のユーザーの情報は失われます - もちろん、rootプロセスは任意のユーザーに変更できます）。

2つの一般的でないシステムコール、**`setreuid`**（`re`は実ユーザーIDと有効ユーザーIDを表す）と**`setresuid`**（`res`には保存されたユーザーIDも含まれる）は、特定のIDを設定します。特権のないプロセスでは、これらの呼び出しは制限されます（`setresuid`の[manページ](https://man7.org/linux/man-pages/man2/setresuid.2.html)に記載されていますが、`setreuid`の[ページ](https://man7.org/linux/man-pages/man2/setreuid.2.html)にも似たような言語があります）：

> 特権のないプロセス（Linuxでは、CAP\_SETUID機能を持つプロセス）は、実ユーザーID、有効ユーザーID、保存された設定ユーザーIDを、現在の実ユーザーID、現在の有効ユーザーID、または現在の保存された設定ユーザーIDのいずれかに変更できます。

これらはセキュリティ機能としてではなく、意図したワークフローを反映するために存在していることを覚えておくことが重要です。プログラムが別のユーザーに変更する場合、有効なユーザーIDを変更してそのユーザーとして動作できるようにします。

攻撃者としては、最も一般的なケースがrootに移動することなので、`setuid`を呼び出すだけの悪い習慣に陥りやすいです。その場合、`setuid`は事実上`setresuid`と同じです。

## 実行

### **execve（および他のexecs）**

`execve`システムコールは、最初の引数で指定されたプログラムを実行します。2番目と3番目の引数は配列であり、引数（`argv`）と環境（`envp`）です。`execve`に基づいていくつかの他のシステムコールがあり、`exec`（[manページ](https://man7.org/linux/man-pages/man3/exec.3.html)）と呼ばれます。これらはすべて、`execve`を呼び出すための略記法を提供するためのラッパーです。

[manページ](https://man7.org/linux/man-pages/man2/execve.2.html)には、その動作に関する詳細がたくさんあります。要するに、**`execve`がプログラムを開始すると、呼び出し元プログラムと同じメモリスペースを使用**し、その
### **system**

`system`は、新しいプロセスを開始するための[完全に異なるアプローチ](https://man7.org/linux/man-pages/man3/system.3.html)です。`execve`が同じプロセス内でプロセスレベルで動作するのに対して、**`system`は`fork`を使用して子プロセスを作成し、その子プロセスで`execl`を使用して実行します**：

> ```
> execl("/bin/sh", "sh", "-c", command, (char *) NULL);
> ```

`execl`は、文字列引数を`argv`配列に変換し、`execve`を呼び出すラッパーです。重要な点は、**`system`がコマンドを呼び出すために`sh`を使用する**ということです。

### shとbashのSUID <a href="#sh-and-bash-suid" id="sh-and-bash-suid"></a>

**`bash`**には**`-p`オプション**があり、[manページ](https://linux.die.net/man/1/bash)では次のように説明されています：

> 特権モードをオンにします。このモードでは、**$ENV**と**$BASH\_ENV**ファイルは処理されず、シェル関数は環境から継承されず、環境に**SHELLOPTS**、**BASHOPTS**、**CDPATH**、**GLOBIGNORE**変数が含まれている場合は無視されます。シェルが実効ユーザー（グループ）IDが実ユーザー（グループ）IDと等しくない場合、かつ**-pオプションが指定されていない**場合、これらの操作が実行され、**実効ユーザーIDが実ユーザーIDに設定されます**。起動時に**-p**オプション**が指定された場合、実効ユーザーIDはリセットされません**。このオプションをオフにすると、実効ユーザーIDとグループIDが実ユーザーIDとグループIDに設定されます。

要するに、`-p`を指定しない場合、Bashが実行されると`euid`は`ruid`に設定されます。**`-p`はこれを防ぎます**。

**`sh`**シェルにはこのような機能はありません。[manページ](https://man7.org/linux/man-pages/man1/sh.1p.html)では、「ユーザーID」という言葉は言及されておらず、`-i`オプションのみが以下のように述べています：

> \-i シェルが対話的であることを指定します。以下を参照してください。呼び出し元のプロセスの実ユーザーIDが実効ユーザーIDと等しくない場合、または実グループIDが実効グループIDと等しくない場合、実装は-iオプションの指定をエラーとして扱う場合があります。

## テスト

### setuid / system <a href="#setuid--system" id="setuid--system"></a>

この背景を踏まえて、Jail（HTB）でこのコードを実行し、何が起こるかを説明します：
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
このプログラムは、NFS上のJailでコンパイルされ、SetUIDとして設定されています。
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
...[snip]...
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```
As root, I can see this file:
```
[root@localhost nfsshare]# ls -l a
-rwsr-xr-x. 1 frank frank 16736 May 30 04:58 a
```
以下のコマンドを nobody として実行すると、`id` コマンドも nobody として実行されます:

```bash
$ sudo -u nobody id
```
```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
プログラムは、`ruid`が99（nobody）であり、`euid`が1000（frank）で開始されます。`setuid`呼び出しに到達すると、同じ値が設定されます。

その後、`system`が呼び出され、`uid`が99であることを期待していますが、`euid`も1000であるはずです。なぜそうならないのでしょうか？このディストリビューションでは、**`sh`が`bash`にシンボリックリンクされている**ため、そのような結果になります。
```
$ ls -l /bin/sh
lrwxrwxrwx. 1 root root 4 Jun 25  2017 /bin/sh -> bash
```
したがって、`system`は`/bin/sh sh -c id`を呼び出し、実質的には`/bin/bash bash -c id`となります。`bash`が呼び出されると、`-p`オプションがないため、`ruid`が99で`euid`が1000であることがわかり、`euid`が99に設定されます。

### setreuid / system <a href="#setreuid--system" id="setreuid--system"></a>

この理論をテストするために、`setuid`を`setreuid`で置き換えてみます:
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
コンパイルとパーミッション:
```
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
現在、Jail内にいるため、`id`コマンドを実行すると、uidが1000と返されます。
```
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
`setreuid`呼び出しは、`ruid`と`euid`の両方を1000に設定します。したがって、`system`が`bash`を呼び出したとき、それらは一致し、事はfrankのまま続きます。

### setuid / execve <a href="#setuid--execve" id="setuid--execve"></a>

上記の理解が正しい場合、uidをいじることを心配する必要はなく、代わりに`execve`を呼び出すこともできます。これにより、既存のIDが引き継がれます。これは機能しますが、トラップもあります。たとえば、一般的なコードは次のようになります：
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
環境変数は使用しないため（単純化のためにNULLを渡しています）、`id`には完全なパスが必要です。これは動作し、期待どおりの結果を返します。
```
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
`[r]uid`は99ですが、`euid`は1000です。

これからシェルを取得しようとする場合、注意が必要です。例えば、単に`bash`を呼び出すだけでは:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
私はそれをコンパイルし、SetUIDを設定します。
```
oxdf@hacky$ gcc d.c -o /mnt/nfsshare/d
oxdf@hacky$ chmod 4755 /mnt/nfsshare/d
```
まだ、これはすべてのnobodyを返します：
```
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
もし `setuid(0)` だったら、（プロセスがそれを行う権限を持っていると仮定すれば）問題なく動作するでしょう。その場合、すべての3つのIDが0に変更されます。しかし、非ルートユーザーの場合、これは単に `euid` を1000に設定し（既にそうであった場合）、`sh` を呼び出します。しかし、Jailでは `sh` は `bash` です。そして、`bash` が `ruid` が99で `euid` が1000で起動すると、`euid` は99に戻されます。

これを修正するために、`bash -p` を呼び出します：
```c
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
今回は、`euid` が存在します:
```
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
または、`setuid`の代わりに`setreuid`または`setresuid`を呼び出すこともできます。
