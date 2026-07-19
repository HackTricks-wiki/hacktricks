# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch、SKRoot、Magisk などの Rooting frameworks は、Linux/Android kernel に頻繁に patch を適用し、hook された syscall を介して、権限のない userspace の「manager」app に privileged functionality を公開します。manager authentication の手順に不備がある場合、あらゆる local app がこの channel にアクセスし、すでに root 化された device 上で privileges を昇格できます。

このページでは、公開 research（特に Zimperium による KernelSU v0.5.7 の analysis）で明らかになった techniques と pitfalls を抽象化し、red team と blue team の双方が attack surface、exploitation primitives、堅牢な mitigations を理解できるようにします。

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch が syscall（一般的には prctl）を hook し、userspace からの「commands」を受信します。
- Protocol は通常、magic_value、command_id、arg_ptr/len ... という形式です。
- userspace manager app が最初に authenticate します（例：CMD_BECOME_MANAGER）。kernel が caller を trusted manager として mark すると、privileged commands が受け入れられます。
- caller に root を grant（例：CMD_GRANT_ROOT）
- su の allowlists/deny-lists を manage
- SELinux policy を adjust（例：CMD_SET_SEPOLICY）
- version/configuration を query
- あらゆる app が syscalls を invoke できるため、manager authentication の正確性が critical です。

Example（KernelSU design）:
- Hooked syscall: prctl
- KernelSU handler に divert するための Magic value: 0xDEADBEEF
- Commands には CMD_BECOME_MANAGER、CMD_GET_VERSION、CMD_ALLOW_SU、CMD_SET_SEPOLICY、CMD_GRANT_ROOT などが含まれます。

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspace が prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) を call すると、KernelSU は以下を verify します。

1) Path prefix check
- 提供された path は caller UID に対応する expected prefix で始まる必要があります。例：/data/data/<pkg> または /data/user/<id>/<pkg>。
- Reference: core_hook.c (v0.5.7) path prefix logic.

2) Ownership check
- path は caller UID が own している必要があります。
- Reference: core_hook.c (v0.5.7) ownership logic.

3) FD table scan による APK signature check
- calling process の open file descriptors（FDs）を iterate します。
- path が /data/app/*/base.apk に match する最初の file を選択します。
- APK v2 signature を parse し、official manager certificate に対して verify します。
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).

すべての checks に pass すると、kernel は manager の UID を一時的に cache し、その UID からの privileged commands を reset されるまで受け入れます。

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

signature check が process の FD table 内で見つかった「最初の matching /data/app/*/base.apk」に bind されている場合、実際には caller 自身の package を verify していません。attacker は、正規に signed された APK（本物の manager のもの）を、攻撃者自身の base.apk より FD list の前方に現れるよう pre-position できます。

この trust-by-indirection により、unprivileged app は manager の signing key を own することなく manager を impersonate できます。

Key properties exploited:
- FD scan は caller の package identity に bind されず、path strings の pattern matching のみを行います。
- open() は最も小さい available FD を返します。先に lower-numbered FDs を close することで、attacker は ordering を control できます。
- filter は path が /data/app/*/base.apk に match することだけを check し、caller の installed package に対応しているかは check しません。

---
## Attack preconditions

- device がすでに vulnerable な Rooting framework（例：KernelSU v0.5.7）で root 化されている。
- attacker が local で任意の unprivileged code（Android app process）を実行できる。
- real manager がまだ authenticate していない（例：reboot 直後）。一部の frameworks は success 後に manager UID を cache するため、race に勝つ必要があります。

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:
1) prefix と ownership checks を満たすため、自分の app data directory への valid path を build します。
2) genuine KernelSU Manager base.apk が、自分の base.apk より lower-numbered FD で open されるようにします。
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) を invoke して checks に pass します。
4) CMD_GRANT_ROOT、CMD_ALLOW_SU、CMD_SET_SEPOLICY などの privileged commands を issue し、elevation を persist させます。

Practical notes on step 2 (FD ordering):
- /proc/self/fd symlinks を walk して、自分の /data/app/*/base.apk に対応する process の FD を identify します。
- low FD（例：stdin、fd 0）を close し、legitimate manager APK を先に open して fd 0（または自分の base.apk の FD より小さい index）を占有させます。
- legitimate manager APK を app に bundle し、path が kernel の naive filter を満たすようにします。例えば、/data/app/*/base.apk に match する subpath の下に配置します。

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
番号の小さい FD が正規の manager APK を指すよう強制する：
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
prctl hook による Manager 認証:
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
成功後の特権コマンド（例）:
- CMD_GRANT_ROOT: 現在のプロセスを root に昇格させる
- CMD_ALLOW_SU: 永続的な su 用の allowlist に自分の package/UID を追加する
- CMD_SET_SEPOLICY: framework がサポートする範囲で SELinux policy を調整する

Race/persistence のヒント:
- AndroidManifest に BOOT_COMPLETED receiver（RECEIVE_BOOT_COMPLETED）を登録し、reboot 後早期に起動して、正規の manager より前に authentication を試行する

---
## Detection と mitigation のガイダンス

framework 開発者向け:
- authentication を任意の FD ではなく、呼び出し元の package/UID に紐付ける:
- UID から呼び出し元の package を解決し、FD をスキャンするのではなく、PackageManager を介してインストール済み package の signature と照合する
- kernel-only の場合は、安定した呼び出し元 identity（task creds）を使用し、process FD ではなく、init/userspace helper が管理する安定した source of truth に対して検証する
- identity として path-prefix checks を使用しない。呼び出し元が簡単に条件を満たせるためである
- channel 上で nonce-based challenge–response を使用し、boot 時または重要な event 発生時にキャッシュされた manager identity を消去する
- 可能な場合は、generic syscalls を流用するのではなく、binder-based authenticated IPC の使用を検討する

defender/blue team 向け:
- rooting frameworks と manager processes の存在を検出する。kernel telemetry が利用できる場合は、疑わしい magic constants（例: 0xDEADBEEF）を伴う prctl calls を監視する
- managed fleet では、信頼されていない packages による boot receivers のうち、boot 後すぐに特権 manager commands を繰り返し試行するものを block または alert の対象にする
- devices が patched framework versions に更新されていることを確認し、update 時にキャッシュされた manager IDs を無効化する

attack の制限:
- 脆弱な framework によってすでに rooted になっている devices にのみ影響する
- 通常、正規の manager が authentication を行う前の reboot/race window が必要となる（一部の frameworks は reset まで manager UID を cache する）

---
## frameworks 全体にわたる関連 notes

- Password-based auth（例: 過去の APatch/SKRoot builds）は、password が推測または brute-force 可能である場合や、validation に bug がある場合、弱くなり得る
- Package/signature-based auth（例: KernelSU）は原理上より強固だが、FD scans のような間接的な artefacts ではなく、実際の呼び出し元に bind する必要がある
- Magisk: CVE-2024-48336（MagiskEoP）は、成熟した ecosystem であっても identity spoofing の影響を受け、manager context 内で root による code execution につながり得ることを示した

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
