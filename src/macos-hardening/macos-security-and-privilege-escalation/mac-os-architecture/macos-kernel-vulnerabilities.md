# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

最近のmacOS kernel exploitationは、「単純な unsigned kext を load して ring-0 を取得する」ことよりも、**Mach/MIG parsers**、**IOKit user clients**、**XNU 内部の data-only races**、そして kernel attack surface を再び開く可能性がある**特別な entitlement を持つ daemon**の悪用が中心になっています。具体的な interface を reversing する場合は、[**IOKit**](macos-iokit.md) および [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) に関するページも確認してください。

## 現在も重要な attack surface

- system daemon および kernel-facing service の **Mach/MIG handlers**: malformed descriptor、out-of-line (OOL) data、stateful な multi-message flow。
- **IOKit user clients**: selector 固有の parsing、entitlement で制限された method、そして実際の call graph を隠す wrapper library/daemon。
- **XNU data-only primitives**: credential、SMR で保護された pointer、read-only zone、および corruption によって RIP/PC の control を最初に奪取しなくても policy を変更できるその他の箇所をめぐる race。
- **Third-party / auxiliary kernel code**: legacy kext は少なくなっていますが、enterprise fleet、reduced-security の Apple Silicon system、vendor の `.fs` / helper bundle は、依然として価値の高い kernel-adjacent path を生み出します。

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) では、複数の OTA/update-chain bug を組み合わせ、software update pipeline と rootless 関連 capability を悪用して kernel compromise に到達しています。

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple の [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) では、**actively exploited** されていた2つの issue が修正されました。

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write を持つ attacker が kernel memory protection を bypass できる memory-corruption bug。
- **CVE-2024-23296 – RTKit**: 同じ public impact statement を持つ、2つ目の memory-corruption bug。

公開されている root-cause の詳細は依然として乏しいものの、この2つの組み合わせは、現代の Apple exploit chain では「単に」kernel R/W を得るだけでは不十分な場合が多いことを示しています。memory protection、coprocessor-adjacent code、または二次的な trust boundary に対する post-exploitation が、実際の chain を安定化させる重要な段階になることがよくあります。

Quick patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran の [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) は、典型的な buffer overflow **ではない**ため、現代の XNU を理解するうえで非常に優れたケーススタディです。

- `proc_ro.p_ucred` は、**read-only** な `proc_ro` オブジェクトに格納された **SMR-protected pointer** です。
- Writer はその pointer を **atomically** 更新する必要があります。
- `kauth_cred_proc_update()` は `zalloc_ro_mut(...)` を使用して `p_ucred` を変更していました。x86_64 では、この処理が最終的に `memcpy` / `rep movsb` に到達するため、同時実行中の reader は **torn pointer** を観測できます。
- この bug は **data-only privilege escalation** へと発展します。破損した credential pointer が別の有効な credential object を指す場合、現在の thread は、明らかな control-flow hijack を最初に成功させることなく、より privileged な state を引き継げます。

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
有用な audit heuristic: **SMR readers**、**read-only zone の変更**、および **credential または task metadata** が同じ kernel path に混在している場合は、更新にコピー方式の helper ではなく、atomic な `zalloc_ro_mut_*` variant が使用されていることを確認する。

---

## 2024-2025: kernel loading path を再び開く SIP bypass (CVE-2024-44243)

Microsoft は、`storagekitd` を悪用して **SIP を bypass** し、それによって、通常なら "post-kext" に見えるマシン上でも third-party kernel code を再び有効にできることを示した。主要な考え方は次のとおり。

1. `/Library/Filesystems` 配下に悪意のある `.fs` bundle を配置または上書きする。
2. Disk Utility または `diskutil` 経由で `storagekitd` を起動する。
3. 特別な entitlement を持つ daemon に、**適切に privilege を drop したり path を検証したりせずに** bundle executables を spawn させる。
4. 結果として得られた SIP bypass を使用して保護された file-system state を変更し、Microsoft の demonstration では kernel extension exclusion list を上書きする。

kernel researchers にとって重要な教訓は、direct third-party kext loading が厳しく制限されている場合でも、**userland management daemon から kernel attack surface が再導入される可能性がある**という点である。

Useful triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing と research workflow

この種類のバグを積極的に hunting している場合、最近の公開 research は同じ方向を示しています。

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) は、Apple Silicon 時代の kernel research における現在も有力な reference の 1 つです。**static binary rewriting** を使用して coverage を復元し、テスト中は **entitlement-gated** な path を無効化し、userspace wrapper から interface の構造を推測します。
- Project Zero の [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) では、**kext / fileset を userspace に rebasing** する非常に実用的な workflow が紹介されています。これにより、parser-heavy な code を on-device で再現する前に、はるかに高速に fuzzing できます。
- Mach-heavy な target では、単一の selector blob だけでなく、**実際の message layout と multi-call state machine** を中心に harness を構築してください。Project Zero の最近の CoreAudio/Mach research や、**Fuzzing at Mach Speed** などの conference talk は、stateful な message sequence が有効であり続ける理由を示しています。

実際に頻繁に使用することになる、ローカルでの簡単な command:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## クイック列挙チートシート
```bash
uname -a                          # Kernel build
sw_vers                           # ProductVersion / BuildVersion
kmutil showloaded                 # List loaded kernel extensions
kmutil showloaded --collection aux  # Auxiliary / 3rd party collections
kextstat 2>/dev/null | grep -v com.apple
csrutil status                    # Check SIP state
spctl --status                    # Confirm Gatekeeper state
```
## 参考資料

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “CVE-2024-44243の分析：kernel extensionsを介したmacOS System Integrity Protectionのバイパス。” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
