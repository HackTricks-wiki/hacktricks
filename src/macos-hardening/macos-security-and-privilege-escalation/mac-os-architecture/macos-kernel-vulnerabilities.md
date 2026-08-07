# macOS Kernel 취약점

{{#include ../../../banners/hacktricks-training.md}}

최근 macOS kernel exploitation은 "사소한 unsigned kext를 로드하고 ring-0를 획득하는 것"보다는 **Mach/MIG parser**, **IOKit user client**, **XNU 내부의 data-only race**, 그리고 여전히 kernel attack surface를 다시 열 수 있는 **특수 entitlement가 부여된 daemon**을 악용하는 방식에 가깝습니다. 구체적인 interface를 reversing하려면 [**IOKit**](macos-iokit.md) 및 [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md)에 관한 페이지도 확인하세요.

## 여전히 중요한 attack surface

- **시스템 daemon 및 kernel-facing service의 Mach/MIG handler**: malformed descriptor, out-of-line (OOL) data, stateful multi-message flow.
- **IOKit user client**: selector별 parsing, entitlement로 제한된 method, 실제 call graph를 숨기는 wrapper library/daemon.
- **XNU data-only primitive**: credential, SMR-protected pointer, read-only zone 및 corruption을 통해 먼저 RIP/PC control을 획득하지 않고도 policy를 변경할 수 있는 기타 영역에서 발생하는 race.
- **Third-party / auxiliary kernel code**: legacy kext는 드물어졌지만, enterprise fleet, reduced-security Apple Silicon system, vendor `.fs` / helper bundle은 여전히 가치가 높은 kernel-adjacent path를 만듭니다.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**이 보고서**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 여러 OTA/update-chain bug를 결합하고 software update pipeline과 rootless 관련 capability를 악용하여 kernel compromise에 도달합니다.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple의 [**March 2024 macOS security release**](https://support.apple.com/en-us/120895)는 **actively exploited**된 두 가지 issue를 수정했습니다:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write 권한을 가진 attacker가 kernel memory protection을 우회할 수 있는 memory-corruption bug.
- **CVE-2024-23296 – RTKit**: 동일한 public impact statement를 가진 두 번째 memory-corruption bug.

공개된 root-cause detail은 여전히 부족하지만, 이 두 issue는 최신 Apple exploit chain에 "단순히" kernel R/W만 필요한 것은 아니라는 점을 잘 보여줍니다. memory protection, coprocessor-adjacent code 또는 secondary trust boundary를 대상으로 하는 post-exploitation 작업이 실제 chain을 안정화하는 단계인 경우가 많습니다.

빠른 patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran의 [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/)은 고전적인 buffer overflow가 아니기 때문에 매우 좋은 최신 XNU case study입니다:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred`는 **read-only** `proc_ro` object에 저장된 **SMR-protected pointer**입니다.
- Writer는 해당 pointer를 **atomically** 업데이트해야 합니다.
- `kauth_cred_proc_update()`는 `zalloc_ro_mut(...)`을 사용해 `p_ucred`를 변경했습니다. x86_64에서 이 경로는 결국 `memcpy` / `rep movsb`에 도달하므로, concurrent reader가 **torn pointer**를 관찰할 수 있습니다.
- 이 bug는 **data-only privilege escalation**으로 이어집니다. 손상된 credential pointer가 다른 유효한 credential object를 가리키도록 되면, 현재 thread는 먼저 명백한 control-flow hijack에 성공하지 않고도 더 높은 권한의 state를 상속할 수 있습니다.

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
유용한 audit heuristic: kernel path에서 **SMR readers**, **read-only zone mutation**, **credential 또는 task metadata**가 함께 사용되는 경우, 업데이트에 copy-based helper가 아니라 atomic `zalloc_ro_mut_*` variants가 사용되는지 확인하세요.

---

## 2024-2025: kernel loading path를 다시 여는 SIP bypass (CVE-2024-44243)

Microsoft는 `storagekitd`를 악용하여 **SIP를 우회**한 다음, 원래라면 "post-kext" 환경으로 보이는 시스템에서 third-party kernel code를 다시 유효하게 만들 수 있음을 보여주었습니다. 핵심 아이디어는 다음과 같습니다:<sup>[[2]](#references)</sup>

1. `/Library/Filesystems` 아래에 악성 `.fs` bundle을 생성하거나 덮어씁니다.
2. Disk Utility 또는 `diskutil`을 통해 `storagekitd`를 트리거합니다.
3. 특별한 entitlement를 가진 daemon이 **privilege를 적절히 제거하거나 path를 검증하지 않은 채** bundle executables를 spawn하도록 합니다.
4. 그 결과 얻은 SIP bypass를 사용해 보호된 file-system state를 변경하고, Microsoft의 demonstration에서는 kernel extension exclusion list를 덮어씁니다.

Kernel researchers에게 중요한 교훈은, direct third-party kext loading이 강하게 제한된 경우에도 **userland management daemons를 통해 kernel attack surface가 다시 도입될 수 있다**는 점입니다.

유용한 triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing 및 research workflow

이 유형의 bug를 적극적으로 hunting하고 있다면, 최근 공개된 연구는 같은 방향을 가리키고 있습니다:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)는 여전히 Apple-Silicon-era kernel research를 위한 최고의 reference 중 하나입니다. **static binary rewriting**을 사용해 coverage를 복구하고, testing 중 **entitlement-gated** 경로를 비활성화하며, userspace wrapper에서 interface structure를 추론합니다.<sup>[[4]](#references)</sup>
- Project Zero의 [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)는 **kext / fileset을 userspace로 rebasing**하여 parser-heavy code를 device에서 재현하기 전에 훨씬 빠른 속도로 fuzzing하는 매우 실용적인 workflow를 보여줍니다.<sup>[[5]](#references)</sup>
- Mach-heavy target의 경우 단일 selector blob만이 아니라 **real message layout과 multi-call state machine**을 중심으로 harness를 구성하세요. Project Zero의 최근 CoreAudio/Mach research와 **Fuzzing at Mach Speed** 같은 conference talk는 stateful message sequence가 계속해서 효과를 발휘하는 이유를 보여줍니다.

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
## References

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - CVE-2024-44243 분석: kernel extensions를 통한 macOS System Integrity Protection 우회](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple OTA Update의 악몽: Signature Verification 우회 및 Kernel 장악](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Mitigations 악용을 통한 Apple Silicon용 macOS Kernel EXTensions Fuzzing (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDA와 TinyInst를 사용한 userspace에서의 간단한 macOS kernel extension fuzzing](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [macOS Sonoma 14.4의 security content 정보 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
