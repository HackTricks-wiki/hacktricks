# euid、ruid、suid

{{#include ../../banners/hacktricks-training.md}}

### User Identification Variables

- **`ruid`**: **real user ID**は、プロセスを開始したユーザーを示します。
- **`euid`**: **effective user ID**とも呼ばれ、プロセスの権限を判定するためにシステムが使用するユーザー ID を表します。通常、`euid`は`ruid`と同じですが、SetUID binaryの実行時などは例外です。この場合、`euid`はファイル所有者の identity となり、特定の操作権限が付与されます。
- **`suid`**: **saved user ID**は、高権限プロセス（通常はrootとして実行されるプロセス）が特定のタスクを実行するために一時的に権限を放棄し、その後、元の高い権限を再取得する必要がある場合に重要です。

#### Important Note

rootとして動作していないプロセスは、`euid`を現在の`ruid`、`euid`、または`suid`と同じ値に変更することしかできません。

### set\*uid Functionsの理解

- **`setuid`**: 初期の想定とは異なり、`setuid`は主に`ruid`ではなく`euid`を変更します。具体的には、privileged processの場合、`ruid`、`euid`、`suid`を指定されたユーザー（多くの場合root）に合わせます。これにより、上書きに使われる`suid`によって、これらの ID は実質的に固定されます。詳細は[setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)を参照してください。<sup>[[2]](#references)</sup>
- **`setreuid`**および**`setresuid`**: これらの関数では、`ruid`、`euid`、`suid`を柔軟に調整できます。ただし、その機能はプロセスの権限レベルに依存します。non-root processでは、変更できる値は現在の`ruid`、`euid`、`suid`に限定されます。一方、root processまたは`CAP_SETUID` capabilityを持つプロセスは、これらの ID に任意の値を設定できます。詳細は[setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)および[setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)を参照してください。<sup>[[3]](#references)[[4]](#references)</sup>

これらの機能はsecurity mechanismとして設計されたものではなく、effective user IDを変更してプログラムが別のユーザーの identity を採用する場合など、想定された操作フローを実現するためのものです。

特に、`setuid`はすべての ID をrootに合わせるため、rootへのprivilege elevationで一般的に使用されますが、さまざまな状況における user ID の動作を理解および操作するには、これらの関数の違いを区別することが重要です。

### LinuxにおけるProgram Execution Mechanisms

#### **`execve` System Call**

- **Functionality**: `execve`は、最初の引数で指定されたプログラムを開始します。引数用の`argv`と環境用の`envp`という2つの配列引数を受け取ります。
- **Behavior**: 呼び出し元のmemory spaceを保持しますが、stack、heap、data segmentを更新します。プログラムのcodeは新しいプログラムに置き換えられます。
- **User ID Preservation**:
- `ruid`、`euid`、およびsupplementary group IDsは変更されません。
- 新しいプログラムにSetUID bitが設定されている場合、`euid`が細かく変更される可能性があります。
- 実行後、`suid`は`euid`から更新されます。
- **Documentation**: 詳細は[`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)を参照してください。<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Functionality**: `execve`とは異なり、`system`は`fork`を使用してchild processを作成し、そのchild process内で`execl`を使用してcommandを実行します。
- **Command Execution**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`を使用して、`sh`経由でcommandを実行します。
- **Behavior**: `execl`は`execve`の一種であるため、新しいchild processのコンテキストで同様に動作します。
- **Documentation**: 詳細は[`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)を参照してください。

#### **SUIDを使用した`bash`と`sh`のBehavior**

- **`bash`**:
- `euid`と`ruid`の扱いに影響する`-p` optionがあります。
- `-p`なしでは、初期状態で両者が異なる場合、`bash`は`euid`を`ruid`に設定します。
- `-p`を付けると、初期状態の`euid`が保持されます。
- 詳細は[`bash` man page](https://linux.die.net/man/1/bash)を参照してください。
- **`sh`**:
- `bash`の`-p`に相当するmechanismはありません。
- user IDsに関する動作は明示的に記載されていませんが、`-i` optionでは`euid`と`ruid`の equality の保持が強調されています。
- 詳細は[`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)を参照してください。

これらのmechanismsはそれぞれ異なる動作をし、プログラムの実行やプログラム間のtransitionに関して多様な options を提供します。また、user IDsの管理および保持方法には、それぞれ固有のニュアンスがあります。

### ExecutionにおけるUser ID BehaviorsのTesting

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jailから取得したExamplesです。詳細についてはこのページを確認してください<sup>[[1]](#references)</sup>

#### Case 1: `system`で`setuid`を使用する場合

**Objective**: `system`と、`sh`としての`bash`を組み合わせた場合の`setuid`の影響を理解すること。

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

- `ruid` と `euid` はそれぞれ 99（nobody）と 1000（frank）として開始します。
- `setuid` により、両方が 1000 に揃えられます。
- `sh` から `bash` への symlink により、`system` は `/bin/bash -c id` を実行します。
- `bash` は `-p` なしで実行されると、`euid` を `ruid` に合わせて調整するため、両方が 99（nobody）になります。

#### Case 2: `system` で `setreuid` を使用

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
- `system` は bash を呼び出します。bash はこれらのユーザー ID が同一であるため、その状態を維持し、実質的に frank として動作します。

#### Case 3: setuid と execve の使用

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
**実行と結果:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

- `ruid` は 99 のままですが、euid は 1000 に設定されており、setuid の効果と一致します。

**C コード例 2 (Bash の呼び出し):**
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

- `setuid` によって `euid` は 1000 に設定されますが、`-p` がないため、`bash` は euid を `ruid`（99）にリセットします。

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
## 参考資料

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man page](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}
