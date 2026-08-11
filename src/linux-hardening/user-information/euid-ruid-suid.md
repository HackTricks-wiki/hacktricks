# euid、ruid、suid

### 用户标识变量

- **`ruid`**：**real user ID** 表示发起该进程的用户。<sup>[[1]](#references)</sup>
- **`euid`**：称为 **effective user ID**，表示系统用于确定进程权限的用户身份。通常情况下，`euid` 与 `ruid` 相同；但在执行 SetUID binary 等情况下（即 set-user-ID transition 生效时），`euid` 会采用文件所有者的身份，从而获得特定的操作权限。<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**：**saved user ID** 在高权限进程（通常以 root 身份运行）需要暂时放弃权限以执行某些任务，并在之后恢复其初始提升状态时发挥关键作用。<sup>[[1]](#references)</sup>

#### 重要说明

非特权进程只能将其 `euid` 修改为当前的 `ruid`、`euid` 或 `suid`。<sup>[[3]](#references)</sup>

### 理解 set\*uid 函数

- **`setuid`**：与最初的理解相反，`setuid` 会设置调用进程的 `euid`。对于特权进程，它还会将 `ruid` 和 `suid` 设置为指定用户；当所有 ID 都被设置为 root 后，进程将无法再通过 `setuid` 恢复之前的身份。详细信息请参阅 [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)。<sup>[[2]](#references)</sup>
- **`setreuid`** 和 **`setresuid`**：`setreuid` 会修改 `ruid` 和 `euid`，而 `setresuid` 会修改全部三个 ID。对于非特权进程，`setresuid` 会将每个目标值限制为当前的 `ruid`、`euid` 或 `suid`；`setreuid` 会将 `euid` 限制为这些值，并将 `ruid` 限制为当前的 `ruid` 或 `euid`。拥有 `CAP_SETUID` 的进程可以为每个调用所支持的 ID 分配任意值。更多信息请参阅 [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) 和 [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)。<sup>[[3]](#references)[[4]](#references)</sup>

这些功能并非作为安全机制设计，而是用于实现预期的操作流程，例如程序通过修改其 effective user ID 来采用另一个用户的身份。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

值得注意的是，对特权进程调用 `setuid` 可以设置全部三个 ID，而 `setreuid` 和 `setresuid` 提供不同的控制方式；区分这些函数对于理解 user-ID transition 至关重要。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Linux 中的程序执行机制

#### **`execve` 系统调用**

- **功能**：`execve` 启动由第一个参数指定的程序。它接收两个数组参数：用于传递参数的 `argv` 和用于传递环境的 `envp`。<sup>[[5]](#references)</sup>
- **行为**：它保留调用者的内存空间，但会刷新 stack、heap 和 data segments。程序的代码会被新程序替换。<sup>[[5]](#references)</sup>
- **用户 ID 保留**：
- `ruid` 和 supplementary group IDs 保持不变。<sup>[[5]](#references)</sup>
- `euid` 通常不会改变，但如果新程序设置了 SetUID bit，则可能发生变化。<sup>[[5]](#references)</sup>
- 执行后，`suid` 会从 `euid` 更新。<sup>[[5]](#references)</sup>
- **文档**：详细信息请参阅 [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)。<sup>[[5]](#references)</sup>

#### **`system` 函数**

- **功能**：与 `execve` 不同，`system` 的行为类似于使用 `fork` 创建 child process，然后在该 child process 中使用 `execl` 执行命令。<sup>[[6]](#references)</sup>
- **命令执行**：通过 `sh` 使用 `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` 执行命令。<sup>[[6]](#references)</sup>
- **行为**：由于 `execl` 属于 `exec`-family call，它的运行方式类似于 `execve`，但上下文是新的 child process。<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **文档**：更多信息请参阅 [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)。<sup>[[6]](#references)</sup>

#### **`bash` 和 `sh` 在 SUID 下的行为**

- **`bash`**：
- 具有影响 `euid` 和 `ruid` 处理方式的 `-p` 选项。<sup>[[7]](#references)</sup>
- 不使用 `-p` 时，如果初始的 `euid` 与 `ruid` 不同，`bash` 会将 `euid` 设置为 `ruid`。<sup>[[7]](#references)</sup>
- 使用 `-p` 时，会保留初始的 `euid`。<sup>[[7]](#references)</sup>
- 更多细节请参阅 [`bash` man page](https://linux.die.net/man/1/bash)。<sup>[[7]](#references)</sup>
- **`sh`**：
- POSIX `sh` 没有定义 Bash 风格的 `-p` privilege-preservation 选项。<sup>[[8]](#references)</sup>
- 其 POSIX 选项列表包含 `-i`，用于选择 interactive mode；当 real ID 与 effective ID 不同时，该选项可能会被拒绝。<sup>[[8]](#references)</sup>
- 更多信息请参阅 [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)。<sup>[[8]](#references)</sup>

这些机制的运行方式各不相同，为程序执行以及程序之间的切换提供了多种灵活选项，同时在用户 ID 的管理和保留方式上具有特定差异。

### 测试执行过程中的用户 ID 行为

示例取自 https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail，请参阅该页面以获取更多信息。<sup>[[1]](#references)</sup>

#### 案例 1：将 `setuid` 与 `system` 配合使用

**目标**：理解 `setuid` 与 `system` 以及作为 `sh` 的 `bash` 结合使用时的效果。

**C 代码**：
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

- `ruid` 和 `euid` 分别以 99（nobody）和 1000（frank）开始。
- 在此非特权上下文中，`setuid(1000)` 会使 `ruid` 保持为 99，而 `euid` 为 1000。<sup>[[1]](#references)</sup>
- 由于 sh 到 bash 的符号链接，`system` 会执行 `/bin/bash -c id`。
- 未使用 `-p` 的 `bash` 会调整 `euid` 以匹配 `ruid`，最终二者都为 99（nobody）。<sup>[[1]](#references)</sup>

#### 案例 2：将 setreuid 与 system 配合使用

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
**执行与结果：**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**分析：**

- `setreuid` 将 ruid 和 euid 都设置为 1000。
- `system` 调用 bash，由于用户 ID 相等，bash 会保持这些用户 ID，实际以 frank 身份运行。<sup>[[1]](#references)</sup>

#### 案例 3：使用 setuid 与 execve

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

- `ruid` remains 99，但 euid is set to 1000，符合 setuid 的效果。<sup>[[1]](#references)</sup>

**C Code Example 2（调用 Bash）：**
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

- Although `euid` is set to 1000 by `setuid`, `bash` resets euid to `ruid` (99) due to the absence of `-p`.<sup>[[1]](#references)</sup>

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
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID 兔子洞 - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - setuid 手册页](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid 手册页](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid 手册页](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve 手册页](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system 手册页](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash 手册页](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh 手册页](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
