# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### User Identification Variables

- **`ruid`**: **real user ID**は、プロセスを開始したユーザーを示します。<sup>[[1]](#references)</sup>
- **`euid`**: **effective user ID**とも呼ばれ、プロセスの権限を確認するためにシステムが使用するユーザーIDを示します。通常、`euid`は`ruid`と同じですが、SetUID binaryの実行など（set-user-ID transitionが適用される場合）では、`euid`はファイル所有者のIDとなり、特定の操作権限が付与されます。<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: **saved user ID**は、高権限プロセス（通常はrootとして実行されるプロセス）が、特定のタスクを実行するために一時的に権限を放棄し、その後、元の昇格された権限を再取得する必要がある場合に重要となります。<sup>[[1]](#references)</sup>

#### Important Note

権限のないプロセスは、現在の`ruid`、`euid`、または`suid`と同じ値にのみ`euid`を変更できます。<sup>[[3]](#references)</sup>

### Understanding set\*uid Functions

- **`setuid`**: 当初の想定とは異なり、`setuid`は呼び出し元プロセスの`euid`を設定します。特権プロセスの場合は、`ruid`と`suid`も指定されたユーザーに設定します。すべてのIDをrootに設定した後、プロセスは`setuid`を使用して以前のidentityを再取得できません。詳細は[setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)で確認できます。<sup>[[2]](#references)</sup>
- **`setreuid`**および**`setresuid`**: `setreuid`は`ruid`と`euid`を変更し、`setresuid`は3つすべてのIDを変更します。権限のないプロセスの場合、`setresuid`は各変更先を現在の`ruid`、`euid`、または`suid`に制限します。`setreuid`は、`euid`をこれらの値に制限し、`ruid`を現在の`ruid`または`euid`に制限します。`CAP_SETUID`を持つプロセスは、各callでサポートされるIDに任意の値を割り当てることができます。詳細は[setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html)および[setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)で確認できます。<sup>[[3]](#references)[[4]](#references)</sup>

これらの機能はsecurity mechanismとして設計されたものではなく、プログラムがeffective user IDを変更して別のユーザーのidentityを採用する場合など、想定されたoperation flowを実現するためのものです。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

特権を持つ`setuid` callでは3つすべてのIDを割り当てられますが、`setreuid`と`setresuid`では異なる制御が提供されます。user-ID transitionを理解するには、これらのfunctionを区別することが重要です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Program Execution Mechanisms in Linux

#### **`execve` System Call**

- **Functionality**: `execve`は、最初のargumentで指定されたプログラムを開始します。引数用の`argv`と環境用の`envp`という2つのarray argumentを受け取ります。<sup>[[5]](#references)</sup>
- **Behavior**: callerのmemory spaceを保持しますが、stack、heap、data segmentを更新します。プログラムのcodeは新しいプログラムに置き換えられます。<sup>[[5]](#references)</sup>
- **User ID Preservation**:
- `ruid`とsupplementary group IDは変更されません。<sup>[[5]](#references)</sup>
- `euid`は通常変更されませんが、新しいプログラムにSetUID bitが設定されている場合は変更されることがあります。<sup>[[5]](#references)</sup>
- `suid`は実行後に`euid`から更新されます。<sup>[[5]](#references)</sup>
- **Documentation**: 詳細は[`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)で確認できます。<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Functionality**: `execve`とは異なり、`system`は`fork`を使用してchild processを作成し、そのchild process内で`execl`を使用してcommandを実行するように動作します。<sup>[[6]](#references)</sup>
- **Command Execution**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`を使用して`sh`経由でcommandを実行します。<sup>[[6]](#references)</sup>
- **Behavior**: `execl`は`exec`-family callであるため、新しいchild processのcontextで`execve`と同様に動作します。<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentation**: 詳細は[`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)で確認できます。<sup>[[6]](#references)</sup>

#### **Behavior of `bash` and `sh` with SUID**

- **`bash`**:
- `euid`と`ruid`の扱いに影響する`-p` optionがあります。<sup>[[7]](#references)</sup>
- `-p`を指定しない場合、初期状態で両者が異なると、`bash`は`euid`を`ruid`に設定します。<sup>[[7]](#references)</sup>
- `-p`を指定すると、初期`euid`が保持されます。<sup>[[7]](#references)</sup>
- 詳細は[`bash` man page](https://linux.die.net/man/1/bash)で確認できます。<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh`では、Bash形式の`-p` privilege-preservation optionは定義されていません。<sup>[[8]](#references)</sup>
- POSIX option listにはinteractive modeを選択する`-i`が含まれており、real IDとeffective IDが異なる場合は拒否されることがあります。<sup>[[8]](#references)</sup>
- 詳細は[`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)で確認できます。<sup>[[8]](#references)</sup>

これらのmechanismはそれぞれ異なる動作をするため、プログラムの実行やprogram間のtransitionに幅広い選択肢を提供します。また、user IDの管理方法や保持方法には、それぞれ固有の注意点があります。

### Testing User ID Behaviors in Executions

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jailから引用したExamplesです。詳細については確認してください。<sup>[[1]](#references)</sup>

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

- `ruid` と `euid` は、それぞれ最初は 99 (nobody) と 1000 (frank) です。
- この非特権コンテキストでは、`setuid(1000)` を実行しても、`ruid` は 99 のままで、`euid` は 1000 のままです。<sup>[[1]](#references)</sup>
- `sh` から `bash` への symlink により、`system` は `/bin/bash -c id` を実行します。
- `bash` は `-p` なしで実行されると、`euid` を `ruid` に合わせて調整するため、両方とも 99 (nobody) になります。<sup>[[1]](#references)</sup>

#### Case 2: setreuid と system の使用

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
**実行と結果:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

- `setreuid` は ruid と euid の両方を 1000 に設定します。
- `system` は bash を呼び出します。bash はこれらのユーザー ID が等しいため、その状態を維持し、実質的に frank として動作します。<sup>[[1]](#references)</sup>

#### Case 3: setuid と execve の使用

目的: setuid と execve の相互作用を調査します。
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

- `ruid` は 99 のままですが、setuid の効果に従って euid は 1000 に設定されます。<sup>[[1]](#references)</sup>

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
**実行と結果：**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析:**

- `setuid` によって `euid` は 1000 に設定されますが、`-p` がないため、`bash` は `euid` を `ruid` (99) にリセットします。<sup>[[1]](#references)</sup>

**C Code Example 3 (bash -p の使用):**
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
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUIDの迷宮 - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuidのmanページ](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuidのmanページ](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuidのmanページ](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execveのmanページ](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - systemのmanページ](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bashのmanページ](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX shのmanページ](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
