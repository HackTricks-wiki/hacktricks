# euid、ruid、suid

{{#include ../../banners/hacktricks-training.md}}

### 用户标识变量

- **`ruid`**：**真实用户 ID**，表示启动该进程的用户。<sup>[[1]](#references)</sup>
- **`euid`**：称为**有效用户 ID**，表示系统用来确定进程权限的用户身份。通常情况下，`euid` 与 `ruid` 相同，但在执行 SetUID binary 等情况下（当 set-user-ID 转换生效时），`euid` 会采用文件所有者的身份，从而获得特定的操作权限。<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**：此**保存的用户 ID** 在高权限进程（通常以 root 身份运行）需要暂时放弃权限来执行某些任务，并随后恢复其初始提升状态时起着关键作用。<sup>[[1]](#references)</sup>

#### 重要说明

非特权进程只能将其 `euid` 修改为当前的 `ruid`、`euid` 或 `suid`。<sup>[[3]](#references)</sup>

### 理解 set\*uid 函数

- **`setuid`**：与最初的理解相反，`setuid` 会设置调用进程的 `euid`。对于特权进程，它还会将 `ruid` 和 `suid` 设置为指定用户；当所有 ID 都被设置为 root 后，进程无法再使用 `setuid` 恢复之前的身份。详细信息请参阅 [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html)。<sup>[[2]](#references)</sup>
- **`setreuid`** 和 **`setresuid`**：`setreuid` 修改 `ruid` 和 `euid`，而 `setresuid` 修改全部三个 ID。对于非特权进程，`setresuid` 将每个目标值限制为当前的 `ruid`、`euid` 或 `suid`；`setreuid` 将 `euid` 限制为这些值，并将 `ruid` 限制为当前的 `ruid` 或 `euid`。拥有 `CAP_SETUID` 的进程可以为每个调用所支持的 ID 分配任意值。更多信息请参阅 [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) 和 [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html)。<sup>[[3]](#references)[[4]](#references)</sup>

这些功能的设计目的不是作为安全机制，而是为了实现预期的操作流程，例如程序通过更改其有效用户 ID 来采用其他用户的身份。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

值得注意的是，对特权进程而言，调用 `setuid` 可以分配全部三个 ID，而 `setreuid` 和 `setresuid` 提供不同的控制方式；区分这些函数对于理解用户 ID 转换至关重要。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Linux 中的程序执行机制

#### **`execve` 系统调用**

- **功能**：`execve` 根据第一个参数确定并启动程序。它接受两个数组参数：用于传递参数的 `argv` 和用于传递环境的 `envp`。<sup>[[5]](#references)</sup>
- **行为**：它保留调用者的内存空间，但会刷新栈、堆和数据段。程序的代码会被新程序替换。<sup>[[5]](#references)</sup>
- **用户 ID 保留**：
- `ruid` 和补充组 ID 保持不变。<sup>[[5]](#references)</sup>
- `euid` 通常不会改变，但如果新程序设置了 SetUID 位，则可能发生变化。<sup>[[5]](#references)</sup>
- 执行后，`suid` 会从 `euid` 更新。<sup>[[5]](#references)</sup>
- **文档**：详细信息请参阅 [`execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html)。<sup>[[5]](#references)</sup>

#### **`system` 函数**

- **功能**：与 `execve` 不同，`system` 的行为类似于使用 `fork` 创建子进程，并在该子进程中使用 `execl` 执行命令。<sup>[[6]](#references)</sup>
- **命令执行**：通过 `sh` 使用 `execl("/bin/sh", "sh", "-c", command, (char *) NULL);` 执行命令。<sup>[[6]](#references)</sup>
- **行为**：由于 `execl` 属于 `exec` 系列调用，它的运行方式与 `execve` 类似，但执行环境是新的子进程。<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **文档**：更多信息请参阅 [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html)。<sup>[[6]](#references)</sup>

#### **带有 SUID 的 `bash` 和 `sh` 的行为**

- **`bash`**：
- 具有 `-p` 选项，该选项会影响 `euid` 和 `ruid` 的处理方式。<sup>[[7]](#references)</sup>
- 如果初始状态下两者不同，不使用 `-p` 时，`bash` 会将 `euid` 设置为 `ruid`。<sup>[[7]](#references)</sup>
- 使用 `-p` 时，会保留初始的 `euid`。<sup>[[7]](#references)</sup>
- 更多详情请参阅 [`bash` man page](https://linux.die.net/man/1/bash)。<sup>[[7]](#references)</sup>
- **`sh`**：
- POSIX `sh` 没有定义类似 Bash 的 `-p` 权限保留选项。<sup>[[8]](#references)</sup>
- 其 POSIX 选项列表包含 `-i`，用于选择交互模式；当真实 ID 与有效 ID 不同时，该选项可能会被拒绝。<sup>[[8]](#references)</sup>
- 更多信息请参阅 [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html)。<sup>[[8]](#references)</sup>

这些机制在运行方式上各不相同，为执行程序以及在程序之间进行转换提供了灵活的选项，同时在用户 ID 的管理和保留方式上具有特定差异。

### 测试执行过程中的用户 ID 行为

示例取自 https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail，详情请进一步查看。<sup>[[1]](#references)</sup>

#### 情况 1：将 `setuid` 与 `system` 结合使用

**目标**：理解 `setuid` 与 `system` 结合使用，以及将 `bash` 作为 `sh` 使用时的影响。

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

- `ruid` 和 `euid` 分别从 99（nobody）和 1000（frank）开始。
- 在此非特权上下文中，`setuid(1000)` 会使 `ruid` 保持为 99，而 `euid` 为 1000。<sup>[[1]](#references)</sup>
- 由于 sh 到 bash 的 symlink，`system` 会执行 `/bin/bash -c id`。
- 不带 `-p` 的 `bash` 会调整 `euid` 以匹配 `ruid`，因此二者都变为 99（nobody）。<sup>[[1]](#references)</sup>

#### Case 2: 使用 setreuid 和 system

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
- `system` 调用 bash，由于用户 ID 相同，bash 会保留这些用户 ID，因此实际上以 frank 身份运行。<sup>[[1]](#references)</sup>

#### 案例 3：使用 setuid 和 execve

目标：探索 setuid 与 execve 的交互。
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

- `ruid` 保持为 99，但 euid 被设置为 1000，这与 setuid 的效果一致。<sup>[[1]](#references)</sup>

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

- 尽管 `euid` 通过 `setuid` 被设置为 1000，但由于缺少 `-p`，`bash` 会将 euid 重置为 `ruid`（99）。<sup>[[1]](#references)</sup>

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
- [2] [man7.org - setuid man 页面](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - setresuid man 页面](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - setreuid man 页面](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - execve man 页面](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - system man 页面](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - bash man 页面](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - POSIX sh man 页面](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}
