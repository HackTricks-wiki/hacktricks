# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

Recent macOS kernel exploitation is less about "load a trivial unsigned kext and get ring-0" and more about abusing **Mach/MIG parsers**, **IOKit user clients**, **data-only races inside XNU**, and **specially entitled daemons** that can still re-open kernel attack surface. For reversing the concrete interfaces, also check the pages about [**IOKit**](macos-iokit.md) and [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md).

## Attack surfaces that still matter

- **Mach/MIG handlers** in system daemons and kernel-facing services: malformed descriptors, out-of-line (OOL) data, and stateful multi-message flows.
- **IOKit user clients**: selector-specific parsing, entitlement-gated methods, and wrapper libraries/daemons that hide the real call graph.
- **XNU data-only primitives**: races around credentials, SMR-protected pointers, read-only zones, and other places where corruption changes policy without first winning RIP/PC control.
- **Third-party / auxiliary kernel code**: legacy kexts are rarer, but enterprise fleets, reduced-security Apple Silicon systems, and vendor `.fs` / helper bundles still create high-value kernel-adjacent paths.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

In [**this report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) several OTA/update-chain bugs are combined to reach kernel compromise by abusing the software update pipeline and rootless-related capabilities.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple's [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) fixed two issues that were **actively exploited**:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: a memory-corruption bug where an attacker with arbitrary kernel read/write could bypass kernel memory protections.
- **CVE-2024-23296 – RTKit**: a second memory-corruption bug with the same public impact statement.

Public root-cause details are still scarce, but the pair is a good reminder that modern Apple exploit chains often need **more than "just" kernel R/W**: post-exploitation work against memory protections, coprocessor-adjacent code, or secondary trust boundaries is frequently where the real chain gets stabilized.

Quick patch triage:

```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```

---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran's [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) is a very good modern XNU case study because it is **not** a classic buffer overflow:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` is an **SMR-protected pointer** stored in a **read-only** `proc_ro` object.
- Writers must update that pointer **atomically**.
- `kauth_cred_proc_update()` used `zalloc_ro_mut(...)` to mutate `p_ucred`; on x86_64 that path eventually hits `memcpy` / `rep movsb`, so a concurrent reader can observe a **torn pointer**.
- The bug turns into a **data-only privilege escalation**: if the corrupted credential pointer resolves to a different valid credential object, the current thread can inherit more privileged state without first winning an obvious control-flow hijack.

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

Useful audit heuristic: whenever a kernel path mixes **SMR readers**, **read-only zone mutation**, and **credential or task metadata**, verify that updates use the atomic `zalloc_ro_mut_*` variants rather than copy-based helpers.

---

## 2024-2025: SIP bypass that re-opens kernel loading paths (CVE-2024-44243)

Microsoft showed that `storagekitd` could be abused to **bypass SIP** and then make third-party kernel code relevant again on machines that would otherwise look "post-kext". The key idea is:<sup>[[2]](#references)</sup>

1. Drop or overwrite a malicious `.fs` bundle under `/Library/Filesystems`.
2. Trigger `storagekitd` via Disk Utility or `diskutil`.
3. Let the specially entitled daemon spawn bundle executables **without properly dropping privileges / validating the path**.
4. Use the resulting SIP bypass to alter protected file-system state and, in Microsoft's demonstration, override the kernel extension exclusion list.

For kernel researchers, the important lesson is that **kernel attack surface can be reintroduced from userland management daemons**, even when direct third-party kext loading is heavily restricted.

Useful triage:

```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```

---

## Fuzzing & research workflow

If you are actively hunting this class of bugs, the recent public work is pointing in the same direction:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) is still one of the best references for Apple-Silicon-era kernel research. It uses **static binary rewriting** to recover coverage, disables **entitlement-gated** paths during testing, and infers interface structure from userspace wrappers.<sup>[[4]](#references)</sup>
- Project Zero's [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) shows a very practical workflow for **rebasing a kext / fileset into userspace** so parser-heavy code can be fuzzed at much higher speed before reproducing on-device.<sup>[[5]](#references)</sup>
- For Mach-heavy targets, build harnesses around **real message layouts and multi-call state machines**, not just single selector blobs. Recent CoreAudio/Mach research from Project Zero and conference talks such as **Fuzzing at Mach Speed** show why stateful message sequences keep paying off.

Quick local commands you will actually use a lot:

```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```

## Quick Enumeration Cheatsheet

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
- [2] [Microsoft Security Blog - Analyzing CVE-2024-44243, a macOS System Integrity Protection bypass through kernel extensions](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - The Nightmare of Apple's OTA Update: Bypassing the Signature Verification and Pwning the Kernel](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Fuzzing macOS Kernel EXTensions on Apple Silicon via Exploiting Mitigations (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [About the security content of macOS Sonoma 14.4 - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
