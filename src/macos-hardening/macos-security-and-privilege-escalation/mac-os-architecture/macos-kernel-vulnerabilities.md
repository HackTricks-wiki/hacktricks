# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

최근 macOS kernel exploitation은 "사소한 unsigned kext를 로드하고 ring-0를 획득하는" 방식보다는 **Mach/MIG parsers**, **IOKit user clients**, **XNU 내부의 data-only races**, 그리고 여전히 kernel attack surface를 다시 열 수 있는 **특정 entitlement가 부여된 daemons**를 악용하는 방식에 가깝습니다. 구체적인 interfaces를 reverse engineering하려면 [**IOKit**](macos-iokit.md) 및 [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md)에 관한 페이지도 확인하세요.

## 여전히 중요한 Attack surfaces

- **Mach/MIG handlers**: system daemons 및 kernel-facing services에 존재하며, malformed descriptors, out-of-line (OOL) data, stateful multi-message flows가 포함됩니다.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods, 그리고 실제 call graph를 숨기는 wrapper libraries/daemons입니다.
- **XNU data-only primitives**: credentials, SMR-protected pointers, read-only zones 및 corruption이 먼저 RIP/PC control을 확보하지 않고도 policy를 변경하는 기타 영역 주변의 races입니다.
- **Third-party / auxiliary kernel code**: legacy kexts는 드물어졌지만, enterprise fleets, reduced-security Apple Silicon systems, vendor `.fs` / helper bundles는 여전히 높은 가치의 kernel-adjacent paths를 생성합니다.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**이 보고서**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)에서는 여러 OTA/update-chain bugs를 결합하고 software update pipeline 및 rootless-related capabilities를 악용하여 kernel compromise에 도달합니다.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple의 [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895)는 **actively exploited**된 두 가지 문제를 수정했습니다:

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write 권한을 가진 attacker가 kernel memory protections를 우회할 수 있는 memory-corruption bug입니다.
- **CVE-2024-23296 – RTKit**: 동일한 public impact statement를 가진 두 번째 memory-corruption bug입니다.

공개된 root-cause details는 여전히 부족하지만, 이 두 취약점은 최신 Apple exploit chains에 "단순히" kernel R/W만 필요한 것이 아니라는 점을 잘 보여줍니다. memory protections, coprocessor-adjacent code 또는 secondary trust boundaries를 대상으로 하는 post-exploitation 작업이 실제 chain을 안정화하는 단계인 경우가 많습니다.

빠른 patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran의 [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/)은 전형적인 buffer overflow가 아니기 때문에 매우 좋은 최신 XNU case study입니다:<sup>[1]</sup>

- `proc_ro.p_ucred`는 **read-only** `proc_ro` object에 저장된 **SMR-protected pointer**입니다.
- Writer는 해당 pointer를 **atomically** update해야 합니다.
- `kauth_cred_proc_update()`는 `zalloc_ro_mut(...)`을 사용해 `p_ucred`를 mutate했으며, x86_64에서 해당 path는 최종적으로 `memcpy` / `rep movsb`에 도달하므로 concurrent reader가 **torn pointer**를 observe할 수 있습니다.
- 이 bug는 **data-only privilege escalation**으로 이어집니다. corrupted credential pointer가 다른 유효한 credential object를 가리키도록 resolve되면, 현재 thread는 먼저 명백한 control-flow hijack에 성공하지 않고도 더 높은 privilege state를 inherit할 수 있습니다.

최소 trigger 패턴:
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
유용한 audit heuristic: kernel 경로에서 **SMR readers**, **read-only zone mutation**, **credential 또는 task metadata**가 함께 사용되는 경우, 업데이트가 copy-based helper가 아니라 atomic `zalloc_ro_mut_*` variants를 사용하는지 확인하십시오.

---

## 2024-2025: kernel loading 경로를 다시 여는 SIP bypass (CVE-2024-44243)

Microsoft는 `storagekitd`를 악용하여 **SIP를 우회**한 다음, 그렇지 않으면 "post-kext" 상태로 보일 시스템에서 third-party kernel code를 다시 유효하게 만들 수 있음을 보여주었습니다. 핵심 아이디어는 다음과 같습니다:<sup>[2]</sup>

1. `/Library/Filesystems` 아래에 악성 `.fs` bundle을 배치하거나 기존 bundle을 덮어씁니다.
2. Disk Utility 또는 `diskutil`을 통해 `storagekitd`를 트리거합니다.
3. 특별한 entitlement를 가진 daemon이 **권한을 제대로 제거하지 않거나 / 경로를 검증하지 않은 채** bundle executable을 spawn하도록 합니다.
4. 그 결과 얻은 SIP bypass를 사용하여 보호된 file-system 상태를 변경하고, Microsoft의 시연에서는 kernel extension exclusion list를 덮어씁니다.

kernel researcher에게 중요한 교훈은, third-party kext loading이 강하게 제한된 경우에도 **userland management daemon에서 kernel attack surface가 다시 도입될 수 있다**는 점입니다.

유용한 triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing 및 research workflow

이 유형의 bug를 적극적으로 hunting하고 있다면, 최근 공개된 research는 같은 방향을 가리키고 있습니다:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)는 여전히 Apple-Silicon-era kernel research를 위한 최고의 references 중 하나입니다. **static binary rewriting**을 사용해 coverage를 복구하고, testing 중 **entitlement-gated** paths를 비활성화하며, userspace wrappers에서 interface structure를 추론합니다.<sup>[4]</sup>
- Project Zero의 [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)는 parser-heavy code를 on-device에서 재현하기 전에 훨씬 높은 speed로 fuzzing할 수 있도록 **kext / fileset을 userspace로 rebasing**하는 매우 실용적인 workflow를 보여줍니다.<sup>[5]</sup>
- Mach-heavy targets의 경우 단순한 single selector blobs가 아니라 **real message layouts와 multi-call state machines**를 중심으로 harnesses를 구축하세요. Project Zero의 최근 CoreAudio/Mach research와 **Fuzzing at Mach Speed** 같은 conference talks는 stateful message sequences가 계속해서 성과를 내는 이유를 보여줍니다.

실제로 자주 사용하게 될 빠른 local commands:
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - CVE-2024-44243 분석: kernel extensions를 통한 macOS System Integrity Protection 우회](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple OTA Update의 악몽: Signature Verification 우회 및 Kernel 장악](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Mitigations 악용을 통한 Apple Silicon의 macOS Kernel EXTensions Fuzzing (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDA와 TinyInst를 사용한 userspace의 간단한 macOS kernel extension fuzzing](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
