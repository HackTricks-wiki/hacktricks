# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}


### 用户标识变量

- **`ruid`**：**真实用户 ID**表示启动该进程的用户。
- **`euid`**：称为**有效用户 ID**，表示系统用于确定进程权限的用户身份。通常，`euid` 与 `ruid` 相同，但在执行 SetUID binary 等情况下除外，此时 `euid` 会采用文件所有者的身份，从而获得特定的操作权限。
- **`suid`**：当高权限进程（通常以 root 身份运行）需要暂时放弃其权限以执行某些任务，并在之后恢复其初始提升状态时，这个**保存的用户 ID**至关重要。

#### 重要说明

非 root 进程只能将其 `euid` 修改为当前的 `ruid`、`euid` 或 `suid`。

### 理解 set\*uid 函数

- **`setuid`**：与最初的理解相反，`setuid` 主要修改的是 `euid`，而不是 `ruid`。具体来说，对于特权进程，它会将 `ruid`、`euid` 和 `suid` 设置为指定用户，通常是 root，从而由于 `suid` 的覆盖作用而有效固定这些 ID。详细信息请参阅 [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)。
- **`setreuid`** 和 **`setresuid`**：这些函数允许对 `ruid`、`euid` 和 `suid` 进行细致调整。不过，它们的能力取决于进程的权限级别。对于非 root 进程，修改范围仅限于当前的 `ruid`、`euid` 和 `suid` 值。相比之下，root 进程或具有 `CAP_SETUID` capability 的进程可以为这些 ID 指定任意值。更多信息请参阅 [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) 和 [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)。

这些功能的设计目的不是作为安全机制，而是为了支持预期的操作流程，例如程序通过修改其有效用户 ID 来采用另一个用户的身份。

值得注意的是，虽然 `setuid` 可能是提升到 root 的常用方法（因为它会将所有 ID 设置为 root），但区分这些函数对于理解和操纵不同场景下的用户 ID 行为至关重要。

### Linux 中的程序执行机制

#### **`execve` System Call**

- **功能**：`execve` 启动由第一个参数指定的程序。它接受两个数组参数：用于传递参数的 `argv` 和用于传递环境的 `envp`。
- **行为**：它保留调用者的内存空间，但会刷新 stack、heap 和 data segment。程序的代码会被新程序替换。
- **用户 ID 保留**：
- `ruid`、`euid` 和 supplementary group IDs 保持不变。
- 如果新程序设置了 SetUID bit，`euid` 可能会发生细微变化。
- 执行后，`suid` 会从 `euid` 更新。
- **文档**：详细信息请参阅 [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)。

#### **`system` Function**

- **功能**：与 `execve` 不同，`system` 使用 `fork` 创建 child process，并在该 child process 中使用 `execl` 执行命令。
- **命令执行**：通过 `sh` 使用 `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` 执行命令。
- **行为**：由于 `execl` 是 `execve` 的一种形式，因此它的操作方式类似，但运行在新的 child process 上下文中。
- **文档**：更多信息请参阅 [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)。

#### **`bash` 和 `sh` 使用 SUID 时的行为**

- **`bash`**：
- 具有会影响 `euid` 和 `ruid` 处理方式的 `-p` option。
- 如果最初二者不同，不使用 `-p` 时，`bash` 会将 `euid` 设置为 `ruid`。
- 使用 `-p` 时，会保留初始的 `euid`。
- 更多详细信息请参阅 [`bash` man page](https://linux.die.net/man/1/bash)。
- **`sh`**：
- 没有类似于 `bash` 中 `-p` 的机制。
- 除了 `-i` option 外，文档没有明确说明与用户 ID 相关的行为；该 option 强调保留 `euid` 和 `ruid` 相等。
- 更多信息请参阅 [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)。

这些机制的操作方式各不相同，为执行程序以及在程序之间进行转换提供了多种灵活选项，同时在用户 ID 的管理和保留方式上存在特定差异。

### 测试执行过程中的用户 ID 行为

示例取自 https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail，更多信息请参阅该页面

#### Case 1：将 `setuid` 与 `system` 结合使用

**目标**：理解 `setuid` 与 `system` 结合使用，并将 `bash` 作为 `sh` 时产生的影响。

**C Code**：
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
**编译和权限：**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- `ruid` 和 `euid` 的初始值分别为 99（nobody）和 1000（frank）。
- `setuid` 将两者都设置为 1000。
- 由于 sh 指向 bash 的 symlink，`system` 执行 `/bin/bash -c id`。
- 未使用 `-p` 的 `bash` 会调整 `euid` 以匹配 `ruid`，因此两者都变为 99（nobody）。

#### Case 2：使用 setreuid 和 system

**C Code**：
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
**编译与权限：**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**执行与结果：**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- `setreuid` 将 ruid 和 euid 都设置为 1000。
- `system` 调用 bash；由于两个用户 ID 相等，bash 会保留这些用户 ID，从而实际上以 frank 身份运行。

#### Case 3: 使用 setuid 与 execve

目标：探索 setuid 与 execve 之间的交互。
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
**执行与结果：**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- `ruid` 仍为 99，但 euid 被设置为 1000，这与 setuid 的效果一致。

**C 代码示例 2（调用 Bash）：**
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
**执行与结果：**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- 尽管 `euid` 通过 `setuid` 被设置为 1000，但由于缺少 `-p`，`bash` 会将 euid 重置为 `ruid`（99）。

**C 代码示例 3（使用 bash -p）：**
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
**执行与结果：**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## 参考资料

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
