# macOS Kernel 취약점

{{#include ../../../banners/hacktricks-training.md}}

최근 macOS kernel exploitation은 더 이상 "사소한 unsigned kext를 로드하고 ring-0을 얻는" 방식이 아니라, **Mach/MIG parsers**, **IOKit user clients**, **XNU 내부의 data-only race**, 그리고 kernel attack surface를 다시 열 수 있는 **특수 entitlement가 부여된 daemon**을 악용하는 방식에 가깝습니다. 구체적인 interface를 reversing하려면 [**IOKit**](macos-iokit.md) 및 [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md)에 관한 페이지도 확인하세요.

## 여전히 중요한 attack surface

- system daemon 및 kernel-facing service의 **Mach/MIG handler**: malformed descriptor, out-of-line (OOL) data, stateful multi-message flow.
- **IOKit user client**: selector별 parsing, entitlement로 제한된 method, 실제 call graph를 숨기는 wrapper library/daemon.
- **XNU data-only primitive**: credential, SMR-protected pointer, read-only zone 및 corruption이 먼저 RIP/PC control을 확보하지 않고도 policy를 변경하는 기타 영역 주변의 race.
- **Third-party / auxiliary kernel code**: legacy kext는 드물어졌지만, enterprise fleet, reduced-security Apple Silicon system, vendor `.fs` / helper bundle은 여전히 높은 가치의 kernel-adjacent path를 만듭니다.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**이 report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 여러 OTA/update-chain bug를 결합하여 software update pipeline과 rootless 관련 capability를 악용하고 kernel compromise에 도달합니다.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple의 [**2024년 3월 macOS security release**](https://support.apple.com/en-us/120895)는 **actively exploited**된 두 가지 issue를 수정했습니다.

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write 권한을 가진 attacker가 kernel memory protection을 우회할 수 있는 memory-corruption bug.
- **CVE-2024-23296 – RTKit**: 동일한 public impact statement를 가진 두 번째 memory-corruption bug.

공개된 root-cause detail은 여전히 부족하지만, 이 두 issue는 최신 Apple exploit chain이 "단순히" kernel R/W를 확보하는 것 이상을 필요로 하는 경우가 많다는 점을 잘 보여줍니다. memory protection, coprocessor-adjacent code 또는 secondary trust boundary를 대상으로 한 post-exploitation 작업이 실제 chain을 안정화하는 지점인 경우가 많습니다.

빠른 patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran의 [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/)은 전형적인 buffer overflow가 아니기 때문에 매우 훌륭한 최신 XNU 사례 연구입니다:

- `proc_ro.p_ucred`는 **read-only** `proc_ro` object에 저장된 **SMR-protected pointer**입니다.
- Writer는 해당 pointer를 **atomically** 업데이트해야 합니다.
- `kauth_cred_proc_update()`는 `zalloc_ro_mut(...)`을 사용해 `p_ucred`를 변경했습니다. x86_64에서 이 경로는 결국 `memcpy` / `rep movsb`에 도달하므로, 동시에 실행 중인 reader가 **torn pointer**를 관찰할 수 있습니다.
- 이 bug는 **data-only privilege escalation**으로 이어집니다. 손상된 credential pointer가 다른 유효한 credential object를 가리키면, 현재 thread는 먼저 명확한 control-flow hijack에 성공하지 않고도 더 높은 권한의 state를 상속할 수 있습니다.

Minimal trigger pattern:
```c
// writer thread: force frequent credential swaps
while (1) {
setgid(real_gid);
setgid(saved_or_effective_gid);
}

// reader thread: repeatedly dereference current credentials
while (1) {
(void)getgid();
}
```
유용한 audit heuristic: kernel 경로에서 **SMR readers**, **read-only zone mutation**, 그리고 **credential 또는 task metadata**가 함께 사용되는 경우, 업데이트에 copy-based helper가 아닌 atomic `zalloc_ro_mut_*` variants가 사용되는지 확인하세요.

---

## 2024-2025: kernel loading path를 다시 여는 SIP bypass (CVE-2024-44243)

Microsoft는 `storagekitd`가 **SIP를 bypass**하는 데 악용될 수 있으며, 그 결과 일반적으로 "post-kext"로 보이는 시스템에서도 third-party kernel code가 다시 유효해질 수 있음을 보여주었습니다. 핵심 아이디어는 다음과 같습니다.

1. `/Library/Filesystems` 아래에 악성 `.fs` bundle을 drop하거나 덮어씁니다.
2. Disk Utility 또는 `diskutil`을 통해 `storagekitd`를 trigger합니다.
3. 특별한 entitlement를 가진 daemon이 **privilege를 적절히 drop하거나 path를 검증하지 않은 채** bundle executable을 spawn하도록 합니다.
4. 그 결과 발생한 SIP bypass를 사용해 보호된 file-system state를 변경하고, Microsoft의 demonstration에서는 kernel extension exclusion list를 override합니다.

kernel researchers에게 중요한 교훈은, direct third-party kext loading이 강하게 제한된 경우에도 **userland management daemon에서 kernel attack surface가 다시 도입될 수 있다**는 점입니다.

유용한 triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing 및 research workflow

이 bug 유형을 적극적으로 hunting하고 있다면, 최근 public work는 같은 방향을 가리키고 있습니다:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)는 여전히 Apple-Silicon-era kernel research를 위한 최고의 reference 중 하나입니다. **static binary rewriting**을 사용해 coverage를 복구하고, testing 중 **entitlement-gated** 경로를 비활성화하며, userspace wrapper에서 interface structure를 추론합니다.
- Project Zero의 [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)는 parser-heavy code를 on-device에서 재현하기 전에 훨씬 빠른 속도로 fuzzing할 수 있도록 **kext / fileset을 userspace로 rebasing**하는 매우 실용적인 workflow를 보여줍니다.
- Mach-heavy target의 경우 단순한 single selector blob가 아니라 **real message layout과 multi-call state machine**을 기반으로 harness를 구축하세요. Project Zero의 최근 CoreAudio/Mach research와 **Fuzzing at Mach Speed** 같은 conference talk는 stateful message sequence가 계속 성과를 내는 이유를 보여줍니다.

실제로 자주 사용하게 될 간단한 local command:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## 빠른 열거 치트시트
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## 참고 자료

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “CVE-2024-44243 분석: kernel extensions를 통한 macOS System Integrity Protection 우회.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
