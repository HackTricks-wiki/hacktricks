# euid, ruid, suid

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を使って、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

- **サイバーセキュリティ企業**で働いていますか？**HackTricksで会社を宣伝**してみたいですか？または**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションです。
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう。
- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)。
- **ハッキングトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

### ユーザー識別変数

- **`ruid`**: **実ユーザーID**はプロセスを開始したユーザーを示します。
- **`euid`**: **有効ユーザーID**として知られ、システムがプロセス特権を確定するために使用するユーザーIDを表します。一般的に、`euid`は`ruid`と同じであり、SetUIDバイナリの実行などの場合を除いて、`euid`はファイル所有者のIDを取り、特定の操作権限を付与します。
- **`suid`**: この**保存されたユーザーID**は、一時的に特定のタスクを実行するために高特権プロセス（通常はrootとして実行）が特権を一時的に放棄する必要がある場合に重要です。後で元の昇格された状態を取り戻します。

#### 重要な注意事項
rootで動作していないプロセスは、現在の`ruid`、`euid`、または`suid`に一致するように`euid`を変更できます。

### set*uid関数の理解

- **`setuid`**: 最初の仮定とは異なり、`setuid`は主に`ruid`ではなく`euid`を変更します。特権プロセスの場合、`setuid`は`ruid`、`euid`、および`suid`を指定されたユーザー（通常はroot）と一致させ、これらのIDを効果的に固定します。詳細な情報は[setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)にあります。
- **`setreuid`**および**`setresuid`**: これらの関数は`ruid`、`euid`、および`suid`を微調整することを可能にします。ただし、その機能はプロセスの特権レベルに依存します。rootプロセスまたは`CAP_SETUID`機能を持つプロセスは、これらのIDに任意の値を割り当てることができます。詳細は[setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)および[setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)から得ることができます。

これらの機能はセキュリティメカニズムではなく、プログラムが他のユーザーのIDを採用する際など、意図した操作フローを容易にするために設計されています。

`setuid`はrootへの特権昇格に一般的に使用されるかもしれませんが、これらの関数の違いを区別することは、さまざまなシナリオでユーザーIDの動作を理解し操作するために重要です。

### Linuxでのプログラム実行メカニズム

#### **`execve`システムコール**
- **機能**: `execve`は最初の引数で決定されたプログラムを開始します。`argv`は引数用、`envp`は環境用の2つの配列引数を取ります。
- **動作**: 呼び出し元のメモリ空間を保持しますが、スタック、ヒープ、およびデータセグメントをリフレッシュします。プログラムのコードは新しいプログラムに置き換えられます。
- **ユーザーIDの保持**:
- `ruid`、`euid`、および補助グループIDは変更されません。
- 新しいプログラムがSetUIDビットを設定している場合、`euid`に微妙な変更が加えられる可能性があります。
- 実行後、`suid`は`euid`から更新されます。
- **ドキュメント**: 詳細な情報は[`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)にあります。

#### **`system`関数**
- **機能**: `execve`とは異なり、`system`は`fork`を使用して子プロセスを作成し、その子プロセス内で`execl`を使用してコマンドを実行します。
- **コマンドの実行**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`を使用して`sh`を介してコマンドを実行します。
- **動作**: `execl`は`execve`の形式であるため、新しい子プロセスのコンテキストで同様に動作します。
- **ドキュメント**: [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)からさらなる洞察を得ることができます。

#### **SUIDを持つ`bash`および`sh`の動作**
- **`bash`**:
- `-p`オプションが`euid`と`ruid`の扱いに影響を与えます。
- `-p`なしでは、`bash`は最初に異なる場合に`euid`を`ruid`に設定します。
- `-p`を使用すると、初期の`euid`が保持されます。
- 詳細は[`bash` man page](https://linux.die.net/man/1/bash)で確認できます。
- **`sh`**:
- `bash`の`-p`に類似したメカニズムを持っていません。
- ユーザーIDに関する動作は明示的に述べられておらず、`-i`オプションの下でのみ`euid`と`ruid`の等しさの保持が強調されています。
- 追加情報は[`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)で入手できます。

これらの操作方法は、操作とプログラム間の移行を可能にし、ユーザーIDがどのように管理および保持されるかに特定の微妙な違いがある、多様なオプションを提供します。

### 実行中のユーザーIDの動作をテストする

詳細については、https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail から取得した例を確認してください。

#### ケース1: `system`と`bash`を`sh`と組み合わせて`setuid`を使用する

**目的**: `setuid`を`system`および`bash`として`sh`と組み合わせて使用した場合の効果を理解する。

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

* `ruid` と `euid` は最初にそれぞれ99（nobody）と1000（frank）から始まります。
* `setuid` は両方を1000に揃えます。
* `system` は `/bin/bash -c id` を実行します。これはshからbashへのシンボリックリンクによるものです。
* `-p` を付けずに実行される `bash` は、`euid` を `ruid` に合わせ、結果として両方が99（nobody）になります。

#### ケース2: setreuidをsystemと一緒に使用する

**Cコード**:
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
**実行と結果:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `setreuid` は ruid と euid を両方とも 1000 に設定します。
* `system` は bash を呼び出し、ユーザー ID を等しく保持するため、実質的に frank として動作します。

#### ケース 3: execve と setuid の相互作用の探索
目的: setuid と execve の相互作用を探る
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
**実行と結果:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `ruid` は99のままですが、euid は1000に設定され、setuid の効果と一致しています。

**Cコード例2（Bashの呼び出し）:**
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
**実行と結果:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

* `euid` は `setuid` によって1000に設定されていますが、`-p` がないため、`bash` は `ruid` (99) に euid をリセットします。

**Cコード例3 (bash -p を使用):**
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
**実行と結果:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## 参考文献
* [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* **[💬](https://emojipedia.org/speech-balloon/) [Discordグループ](https://discord.gg/hRep4RUj7f)に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**私をフォロー**してください 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングトリックを共有するために、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
