# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

近年のmacOS kernel exploitationは、「単純な unsigned kext を load して ring-0 を取得する」というより、**Mach/MIG parsers**、**IOKit user clients**、XNU 内部の **data-only races**、そして **specially entitled daemons** を悪用し、kernel attack surface を再び開くことが中心です。具体的な interface を reverse engineering する場合は、[**IOKit**](macos-iokit.md) および [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) に関するページも確認してください。

## 現在も重要な Attack surface

- system daemons および kernel-facing services の **Mach/MIG handlers**: malformed descriptors、out-of-line (OOL) data、stateful な multi-message flow。
- **IOKit user clients**: selector-specific parsing、entitlement-gated methods、そして実際の call graph を隠す wrapper libraries/daemons。
- **XNU data-only primitives**: credentials、SMR-protected pointers、read-only zones、および corruption によって RIP/PC control を最初に取得せずとも policy を変更できるその他の箇所をめぐる race。
- **Third-party / auxiliary kernel code**: legacy kext は少なくなりましたが、enterprise fleet、reduced-security Apple Silicon system、vendor の `.fs` / helper bundle は、依然として価値の高い kernel-adjacent path を生み出します。

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、複数の OTA/update-chain bug を組み合わせ、software update pipeline と rootless-related capability を悪用して kernel compromise に到達しています。<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple の [**March 2024 macOS security release**](https://support.apple.com/en-us/120895) では、**actively exploited** だった2つの issue が修正されました。

- **CVE-2024-23225 – Kernel**: attacker が arbitrary kernel read/write を持つ場合に、kernel memory protection を bypass できる memory-corruption bug。
- **CVE-2024-23296 – RTKit**: 同じ public impact statement を持つ、2つ目の memory-corruption bug。

公開されている root cause の詳細はまだ少ないものの、この2つの組み合わせは、modern Apple exploit chain では「単に」kernel R/W を取得するだけでは不十分なことが多い、という点をよく示しています。memory protection、coprocessor-adjacent code、または二次的な trust boundary に対する post-exploitation が、実際の chain を安定化させる主要な段階になることがよくあります。

Quick patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran の [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) は、classic buffer overflow ではないため、現代の XNU の非常に優れたケーススタディです:<sup>[1]</sup>

- `proc_ro.p_ucred` は、**read-only** な `proc_ro` object に格納された **SMR-protected pointer** です。
- Writer は、その pointer を **atomically** 更新する必要があります。
- `kauth_cred_proc_update()` は `zalloc_ro_mut(...)` を使用して `p_ucred` を変更していました。この path は x86_64 では最終的に `memcpy` / `rep movsb` に到達するため、concurrent reader は **torn pointer** を観測できます。
- この bug は **data-only privilege escalation** に変わります。破損した credential pointer が別の有効な credential object を指す場合、current thread は、明らかな control-flow hijack に最初に成功しなくても、より privileged な state を継承できます。

最小限の trigger pattern:
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
有用な audit heuristic: **SMR readers**、**read-only zone mutation**、**credential または task metadata** が同じ kernel path 内で混在している場合は、更新に copy-based helpers ではなく、atomic な `zalloc_ro_mut_*` variants が使用されていることを確認する。

---

## 2024-2025: kernel loading paths を再び開く SIP bypass（CVE-2024-44243）

Microsoft は、`storagekitd` を悪用して **SIP を bypass** し、その後、通常であれば "post-kext" と見なされるマシン上でも、third-party kernel code を再び関係させられることを示した。主要な考え方は次のとおりである:<sup>[2]</sup>

1. `/Library/Filesystems` 配下に悪意のある `.fs` bundle を配置または上書きする。
2. Disk Utility または `diskutil` を介して `storagekitd` を trigger する。
3. 特別な entitlement を持つ daemon に、privileges を適切に drop したり path を検証したりせずに bundle executables を spawn させる。
4. 結果として得られた SIP bypass を使用して protected file-system state を変更し、Microsoft の demonstration では、kernel extension exclusion list を override する。

kernel researchers にとって重要な教訓は、direct third-party kext loading が厳しく制限されている場合でも、**kernel attack surface は userland management daemons から再び導入され得る** ということである。

有用な triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing と research workflow

このクラスの bug を積極的に hunting している場合、最近の public work は同じ方向性を示しています。

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) は、Apple Silicon 時代の kernel research における最良の reference の 1 つです。**static binary rewriting** を使用して coverage を復元し、testing 中は **entitlement-gated** な path を無効化し、userspace wrapper から interface の構造を推測します。<sup>[4]</sup>
- Project Zero の [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) では、parser-heavy な code を device 上で再現する前に、より高速に fuzzing できるよう **kext / fileset を userspace に rebase する**、非常に実用的な workflow が紹介されています。<sup>[5]</sup>
- Mach-heavy な target では、単一の selector blobs だけでなく、**real message layouts と multi-call state machines** を中心に harnesses を構築してください。Project Zero の最近の CoreAudio/Mach research や、**Fuzzing at Mach Speed** などの conference talks は、stateful な message sequences が有効であり続ける理由を示しています。

実際によく使用する quick local commands：
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## 簡易列挙チートシート
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## 参考文献

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - CVE-2024-44243 の分析：kernel extensions を通じた macOS System Integrity Protection bypass](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple の OTA Update の悪夢：Signature Verification の bypass と Kernel の Pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz：Mitigations の悪用による Apple Silicon 上の macOS Kernel EXTensions の Fuzzing (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDA と TinyInst を使用した userspace におけるシンプルな macOS kernel extension fuzzing](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
