# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### 用户标识变量

- **`ruid`**: **真实用户 ID** 表示发起进程的用户。
- **`euid`**: 被称为 **有效用户 ID**，它代表系统用来确定进程权限的用户身份。通常情况下，`euid` 与 `ruid` 相同，除非在执行 SetUID 二进制文件的情况下，`euid` 采用文件所有者的身份，从而授予特定的操作权限。
- **`suid`**: 这个 **保存的用户 ID** 在高权限进程（通常以 root 身份运行）需要暂时放弃其权限以执行某些任务时至关重要，之后再恢复其最初的提升状态。

#### 重要说明

非 root 进程只能将其 `euid` 修改为当前的 `ruid`、`euid` 或 `suid`。

### 理解 set\*uid 函数

- **`setuid`**: 与最初的假设相反，`setuid` 主要修改 `euid` 而不是 `ruid`。具体而言，对于特权进程，它将 `ruid`、`euid` 和 `suid` 与指定用户（通常是 root）对齐，有效地巩固这些 ID，因为 `suid` 的覆盖。详细信息可以在 [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html) 中找到。
- **`setreuid`** 和 **`setresuid`**: 这些函数允许对 `ruid`、`euid` 和 `suid` 进行细致的调整。然而，它们的能力取决于进程的权限级别。对于非 root 进程，修改仅限于当前的 `ruid`、`euid` 和 `suid` 值。相比之下，root 进程或具有 `CAP_SETUID` 能力的进程可以为这些 ID 分配任意值。更多信息可以从 [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) 和 [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html) 中获取。

这些功能并不是作为安全机制设计的，而是为了促进预期的操作流程，例如当程序通过更改其有效用户 ID 来采用另一个用户的身份时。

值得注意的是，虽然 `setuid` 可能是提升到 root 权限的常用方法（因为它将所有 ID 对齐到 root），但区分这些函数对于理解和操控不同场景下的用户 ID 行为至关重要。

### Linux 中的程序执行机制

#### **`execve` 系统调用**

- **功能**: `execve` 启动一个程序，由第一个参数决定。它接受两个数组参数，`argv` 用于参数，`envp` 用于环境。
- **行为**: 它保留调用者的内存空间，但刷新堆栈、堆和数据段。程序的代码被新程序替换。
- **用户 ID 保持**:
- `ruid`、`euid` 和附加的组 ID 保持不变。
- 如果新程序设置了 SetUID 位，`euid` 可能会有细微变化。
- `suid` 在执行后从 `euid` 更新。
- **文档**: 详细信息可以在 [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html) 中找到。

#### **`system` 函数**

- **功能**: 与 `execve` 不同，`system` 使用 `fork` 创建一个子进程，并在该子进程中执行命令，使用 `execl`。
- **命令执行**: 通过 `sh` 执行命令，使用 `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`。
- **行为**: 由于 `execl` 是 `execve` 的一种形式，它在新子进程的上下文中以类似方式操作。
- **文档**: 进一步的见解可以从 [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html) 中获取。

#### **带有 SUID 的 `bash` 和 `sh` 的行为**

- **`bash`**:
- 有一个 `-p` 选项影响 `euid` 和 `ruid` 的处理方式。
- 如果没有 `-p`，`bash` 会将 `euid` 设置为 `ruid`，如果它们最初不同。
- 如果有 `-p`，则保留初始的 `euid`。
- 更多细节可以在 [`bash` man page](https://linux.die.net/man/1/bash) 中找到。
- **`sh`**:
- 没有类似于 `bash` 中的 `-p` 的机制。
- 关于用户 ID 的行为没有明确提及，除了在 `-i` 选项下，强调保留 `euid` 和 `ruid` 的相等性。
- 额外信息可在 [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html) 中找到。

这些机制在操作上各不相同，为执行和程序之间的转换提供了多种选择，具体细节在用户 ID 的管理和保留方面有所不同。

### 测试执行中的用户 ID 行为

示例取自 https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail，查看以获取更多信息

#### 案例 1: 使用 `setuid` 和 `system`

**目标**: 理解 `setuid` 与 `system` 和 `bash` 作为 `sh` 结合的效果。

**C 代码**:
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

- `ruid` 和 `euid` 初始值分别为 99（nobody）和 1000（frank）。
- `setuid` 将两者对齐到 1000。
- `system` 执行 `/bin/bash -c id`，这是由于 sh 到 bash 的符号链接。
- `bash` 在没有 `-p` 的情况下，将 `euid` 调整为与 `ruid` 匹配，导致两者均为 99（nobody）。

#### 案例 2：使用 setreuid 和 system

**C 代码**：
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
**编译和权限：**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**执行和结果：**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- `setreuid` 将 ruid 和 euid 都设置为 1000。
- `system` 调用 bash，由于用户 ID 的相等性，保持用户 ID，有效地作为 frank 操作。

#### 案例 3：使用 setuid 和 execve

目标：探索 setuid 和 execve 之间的交互。
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
**执行和结果：**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- `ruid` 保持为 99，但 euid 设置为 1000，符合 setuid 的效果。

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
**执行和结果：**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- 尽管 `euid` 通过 `setuid` 设置为 1000，`bash` 由于缺少 `-p` 将 `euid` 重置为 `ruid` (99)。

**C 代码示例 3 (使用 bash -p)：**
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
**执行和结果：**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## 参考

- [https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)


{{#include ../../banners/hacktricks-training.md}}
