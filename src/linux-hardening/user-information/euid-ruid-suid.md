# euid, ruid, suid

### ユーザー識別変数

- **`ruid`**: **real user ID** は、プロセスを開始したユーザーを示します。<sup>[[1]](#references)</sup>
- **`euid`**: **effective user ID** と呼ばれ、プロセスの権限を判断するためにシステムが使用するユーザー識別情報を表します。通常、`euid` は `ruid` と同じですが、SetUID binary の実行時（set-user-ID transition が適用される場合）などは例外です。この場合、`euid` はファイル所有者の identity となり、特定の操作権限が付与されます。<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: この **saved user ID** は、高い権限を持つプロセス（通常は root として実行されるプロセス）が、特定のタスクを実行するために一時的に権限を放棄し、その後、元の elevated status を回復する必要がある場合に重要です。<sup>[[1]](#references)</sup>

#### 重要な注意事項

unprivileged process は、現在の `ruid`、`euid`、または `suid` に一致するようにのみ、自身の `euid` を変更できます。<sup>[[3]](#references)</sup>

### set\*uid Functions の理解

- **`setuid`**: 当初の想定とは異なり、`setuid` は呼び出し元プロセスの `euid` を設定します。privileged process の場合は、`ruid` と `suid` も指定されたユーザーに設定します。すべての ID が root に設定された後は、プロセスは `setuid` を使用して以前の identity を取り戻すことができません。詳しい情報は [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) にあります。<sup>[[2]](#references)</sup>
- **`setreuid`** と **`setresuid`**: `setreuid` は `ruid` と `euid` を変更し、`setresuid` は3つすべての ID を変更します。unprivileged process の場合、`setresuid` は各 target を現在の `ruid`、`euid`、または `suid` に制限します。一方、`setreuid` は `euid` をこれらの値に制限し、`ruid` を現在の `ruid` または `euid` に制限します。`CAP_SETUID` を持つプロセスは、各 call がサポートする ID に任意の値を割り当てられます。詳細は [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) と [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) で確認できます。<sup>[[3]](#references)[[4]](#references)</sup>

これらの機能は security mechanism としてではなく、プログラムが effective user ID を変更して別のユーザーの identity を採用する場合など、想定された operational flow を実現するために設計されています。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

特に、privileged call である `setuid` は3つすべての ID を割り当てられますが、`setreuid` と `setresuid` は異なる control を提供します。user-ID transition を理解するには、これらの functions の違いを把握することが重要です。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Linux における Program Execution Mechanisms

#### **`execve` System Call**

- **Functionality**: `execve` は、第1引数によって指定された program を開始します。引数用の `argv` と environment 用の `envp` という2つの array arguments を受け取ります。<sup>[[5]](#references)</sup>
- **Behavior**: caller の memory space を保持しますが、stack、heap、data segments を更新します。program の code は新しい program に置き換えられます。<sup>[[5]](#references)</sup>
- **User ID Preservation**:
- `ruid` と supplementary group IDs は変更されません。<sup>[[5]](#references)</sup>
- `euid` は通常変更されませんが、新しい program に SetUID bit が設定されている場合は変更される可能性があります。<sup>[[5]](#references)</sup>
- `suid` は execution 後に `euid` から更新されます。<sup>[[5]](#references)</sup>
- **Documentation**: 詳細は [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) にあります。<sup>[[5]](#references)</sup>

#### **`system` Function**

- **Functionality**: `execve` とは異なり、`system` は `fork` を使用して child process を作成し、その child process 内で `execl` を使用して command を実行するかのように動作します。<sup>[[6]](#references)</sup>
- **Command Execution**: `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` により、`sh` を介して command を実行します。<sup>[[6]](#references)</sup>
- **Behavior**: `execl` は `exec`-family call であるため、新しい child process の context で `execve` と同様に動作します。<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentation**: 詳細は [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) で確認できます。<sup>[[6]](#references)</sup>

#### **SUID における `bash` と `sh` の Behavior**

- **`bash`**:
- `euid` と `ruid` の扱いに影響する `-p` option があります。<sup>[[7]](#references)</sup>
- `-p` がない場合、初期状態で両者が異なると、`bash` は `euid` を `ruid` に設定します。<sup>[[7]](#references)</sup>
- `-p` を指定すると、初期 `euid` が保持されます。<sup>[[7]](#references)</sup>
- 詳細は [`bash` man page](https://linux.die.net/man/1/bash) にあります。<sup>[[7]](#references)</sup>
- **`sh`**:
- POSIX `sh` は、Bash-style の `-p` privilege-preservation option を定義していません。<sup>[[8]](#references)</sup>
- POSIX option list には interactive mode を選択する `-i` が含まれています。この option は、real ID と effective ID が異なる場合に拒否されることがあります。<sup>[[8]](#references)</sup>
- 追加情報は [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) で確認できます。<sup>[[8]](#references)</sup>

これらの mechanisms は operation がそれぞれ異なり、program の実行や program 間の transition に関して柔軟な選択肢を提供します。また、user IDs の管理方法と保持方法には、それぞれ固有の nuances があります。

### Executions における User ID Behaviors の Testing

https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail から取得した examples です。詳細については、このページを確認してください。<sup>[[1]](#references)</sup>

#### Case 1: `setuid` と `system` の使用

**Objective**: `setuid` と `system`、および `sh` としての `bash` の組み合わせによる影響を理解すること。

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

- `ruid` と `euid` はそれぞれ 99 (nobody) と 1000 (frank) として開始します。
- この非特権コンテキストでは、`setuid(1000)` によって `ruid` は 99 のまま、`euid` は 1000 になります。<sup>[[1]](#references)</sup>
- sh から bash への symlink により、`system` は `/bin/bash -c id` を実行します。
- `-p` なしの `bash` は、`euid` を `ruid` に合わせて調整するため、両方とも 99 (nobody) になります。<sup>[[1]](#references)</sup>

#### ケース 2: system で setreuid を使用

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
- `system` は bash を呼び出します。ruid と euid が等しいため、bash は user ID を維持し、実質的に frank として動作します。<sup>[[1]](#references)</sup>

#### ケース 3: setuid と execve の使用

目的: setuid と execve の相互作用を調査する。
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

- `ruid` は 99 のままですが、setuid の効果に従って euid は 1000 に設定されています。<sup>[[1]](#references)</sup>

**C コード例 2（Bash の呼び出し）:**
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

- `euid` は `setuid` によって 1000 に設定されますが、`-p` がないため、`bash` は euid を `ruid` (99) にリセットします。<sup>[[1]](#references)</sup>

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
**実行と結果：**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid manページ](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid manページ](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid manページ](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve manページ](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system manページ](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash manページ](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh manページ](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
