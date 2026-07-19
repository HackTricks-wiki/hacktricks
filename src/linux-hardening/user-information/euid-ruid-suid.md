# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### User Identification Variables

- **`ruid`**: **real user ID**は、プロセスを開始したユーザーを示します。
- **`euid`**: **effective user ID**とも呼ばれ、プロセスの権限を判断するためにシステムが使用するユーザー識別情報を表します。通常、`euid`は`ruid`と同じですが、SetUID binaryを実行する場合などは例外です。この場合、`euid`はファイル所有者の識別情報となり、特定の操作権限が付与されます。
- **`suid`**: **saved user ID**は、高い権限を持つプロセス（通常はrootとして実行されるプロセス）が、特定のタスクを実行するために一時的に権限を放棄し、その後、元の高い権限を再取得する必要がある場合に重要となります。

#### Important Note

rootで実行されていないプロセスは、`euid`を現在の`ruid`、`euid`、または`suid`と同じ値に変更することしかできません。

### Understanding set\*uid Functions

- **`setuid`**: 当初の想定とは異なり、`setuid`は主に`ruid`ではなく`euid`を変更します。具体的には、privileged processの場合、`ruid`、`euid`、`suid`を指定されたユーザー（多くの場合はroot）に揃えます。これにより、`suid`による上書きの影響で、これらのIDが実質的に固定されます。詳しい情報は[setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)にあります。
- **`setreuid`**および**`setresuid`**: これらの関数を使用すると、`ruid`、`euid`、`suid`を細かく調整できます。ただし、その機能はプロセスの権限レベルに依存します。rootではないプロセスの場合、変更できるのは現在の`ruid`、`euid`、`suid`の値に限られます。一方、root process、または`CAP_SETUID` capabilityを持つプロセスは、これらのIDに任意の値を設定できます。詳しい情報は[setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)および[setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)で確認できます。

これらの機能はsecurity mechanismとして設計されたものではなく、プログラムがeffective user IDを変更して別のユーザーのidentityを採用する場合など、想定された処理フローを実現するためのものです。

特に、`setuid`はすべてのIDをrootに揃えるため、rootへのprivilege elevationに一般的に使用されます。しかし、さまざまな状況でのuser IDの動作を理解し、操作するには、これらの関数の違いを把握することが重要です。

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve`は、最初の引数で指定されたプログラムを開始します。引数用の`argv`と環境用の`envp`という2つのarray引数を受け取ります。
- **Behavior**: callerのmemory spaceを保持しながら、stack、heap、data segmentを更新します。プログラムのcodeは新しいプログラムに置き換えられます。
- **User ID Preservation**:
- `ruid`、`euid`、およびsupplementary group IDは変更されません。
- 新しいプログラムにSetUID bitが設定されている場合、`euid`が細かく変更される可能性があります。
- 実行後、`suid`は`euid`から更新されます。
- **Documentation**: 詳細な情報は[`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)で確認できます。

#### **`system` Function**

- **Functionality**: `execve`とは異なり、`system`は`fork`を使用してchild processを作成し、そのchild process内で`execl`を使用してcommandを実行します。
- **Command Execution**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`を使用して、`sh`経由でcommandを実行します。
- **Behavior**: `execl`は`execve`の一種であるため、新しいchild processのコンテキストで同様に動作します。
- **Documentation**: 詳細については[`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)を参照してください。

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
- `euid`と`ruid`の扱いに影響する`-p` optionがあります。
- `-p`を指定しない場合、起動時に両者が異なっていると、`bash`は`euid`を`ruid`に設定します。
- `-p`を指定すると、起動時の`euid`が保持されます。
- 詳細は[`bash` man page](https://linux.die.net/man/1/bash)で確認できます。
- **`sh`**:
- `bash`の`-p`に相当するmechanismはありません。
- user IDに関する動作は明示的に記載されていませんが、`-i` optionでは`euid`と`ruid`が等しい状態の保持が強調されています。
- 詳細な情報は[`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)で確認できます。

これらのmechanismは、それぞれ異なる動作をしますが、プログラムの実行や切り替えに関する多様な選択肢を提供します。また、user IDの管理と保持方法には、それぞれ固有の注意点があります。

### Testing User ID Behaviors in Executions

Examples taken from https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, さらなる情報についてはこのページを確認してください

#### Case 1: Using `setuid` with `system`

**Objective**: `setuid`を`system`および`sh`としての`bash`と組み合わせた場合の影響を理解すること。

**C Code**:
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

- `ruid` と `euid` は、それぞれ 99 (nobody) と 1000 (frank) として開始します。
- `setuid` によって、両方が 1000 に設定されます。
- `sh` から `bash` への symlink により、`system` は `/bin/bash -c id` を実行します。
- `bash` は `-p` なしで実行されると、`euid` を `ruid` に合わせて調整するため、両方が 99 (nobody) になります。

#### Case 2: system で setreuid を使用

**C Code**:
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

- `setreuid` は ruid と euid の両方を 1000 に設定します。
- `system` は bash を呼び出します。ruid と euid が等しいため、bash はユーザー ID を維持し、実質的に frank として動作します。

#### ケース 3: setuid と execve の使用

目的: setuid と execve の相互作用を確認する。
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

- `ruid` は 99 のままですが、setuid の効果により euid は 1000 に設定されています。

**C Code Example 2 (Calling Bash):**
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

- `setuid` によって `euid` は 1000 に設定されていますが、`-p` がないため、`bash` は `euid` を `ruid`（99）にリセットします。

**C Code Example 3（bash -p の使用）:**
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
## 参照

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
