# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

近年のmacOS kernel exploitationは、「単純な unsigned kext を load して ring-0 を取得する」ことよりも、**Mach/MIG parsers**、**IOKit user clients**、XNU内部の**data-only races**、そして kernel attack surface を再び開く可能性がある、特別な entitlement を持つ daemon の悪用が中心になっています。具体的な interface の reversing については、[**IOKit**](macos-iokit.md)および[**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md)のページも確認してください。

## 現在も重要な攻撃対象

- system daemon および kernel-facing service の **Mach/MIG handlers**：malformed descriptors、out-of-line (OOL) data、stateful な multi-message flow。
- **IOKit user clients**：selector-specific parsing、entitlement-gated method、実際の call graph を隠す wrapper library/daemon。
- **XNU data-only primitives**：credential、SMR-protected pointer、read-only zone、その他の corruption によって、RIP/PC control を得る前に policy を変更できる箇所をめぐる race。
- **Third-party / auxiliary kernel code**：legacy kext は少なくなっていますが、enterprise fleet、reduced-security の Apple Silicon system、vendor の `.fs` / helper bundle は、依然として価値の高い kernel-adjacent path を生み出します。

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**この report**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)では、複数の OTA/update-chain bug を組み合わせ、software update pipeline と rootless 関連 capability を悪用して kernel compromise に到達しています。<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722)。

---

## 2024：実環境で悪用された kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple の[**2024年3月のmacOS security release**](https://support.apple.com/en-us/120895)では、**actively exploited**だった2つの問題が修正されました：<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**：arbitrary kernel read/write を持つ attacker が kernel memory protection を bypass できる memory-corruption bug。
- **CVE-2024-23296 – RTKit**：同じ public impact statement を持つ、2つ目の memory-corruption bug。

公開されている root-cause の詳細はまだ少ないものの、この2件は、現代の Apple exploit chain では「単に」kernel R/W を得るだけでは不十分なことが多い、という点をよく示しています。memory protection、coprocessor-adjacent code、または二次的な trust boundary に対する post-exploitation work が、実際の chain を安定化させる段階になることが頻繁にあります。

Quick patch triage：
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + read-only credential race (CVE-2025-24118)

Joseph Ravichandran の [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) は、典型的な buffer overflow ではないため、現代的な XNU のケーススタディとして非常に優れています:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred` は、**read-only** な `proc_ro` オブジェクトに格納された **SMR-protected pointer** です。
- Writer は、その pointer を **atomically** 更新する必要があります。
- `kauth_cred_proc_update()` は `zalloc_ro_mut(...)` を使用して `p_ucred` を変更していました。x86_64 では、この処理は最終的に `memcpy` / `rep movsb` に到達するため、同時実行中の reader は **torn pointer** を観測できます。
- この bug は **data-only privilege escalation** につながります。破損した credential pointer が別の有効な credential object を指す場合、現在の thread は、明らかな control-flow hijack に先に成功しなくても、より privileged な state を継承できます。

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
Useful audit heuristic: カーネルパスが **SMR readers**、**read-only zone mutation**、および **credential or task metadata** を混在させている場合は、更新にコピー方式のヘルパーではなく、アトミックな `zalloc_ro_mut_*` variants が使用されていることを確認する。

---

## 2024-2025: カーネル読み込みパスを再び開く SIP bypass（CVE-2024-44243）

Microsoft は、`storagekitd` を悪用して **SIP を bypass** し、それによって、通常であれば "post-kext" に見えるマシン上でも、サードパーティ製カーネルコードを再び関与させられることを示した。重要なアイデアは次のとおりである:<sup>[[2]](#references)</sup>

1. `/Library/Filesystems` 配下に悪意のある `.fs` bundle を配置または上書きする。
2. Disk Utility または `diskutil` を介して `storagekitd` をトリガーする。
3. 特別な entitlement を持つ daemon に、適切に privileges を drop したり path を検証したりせず、bundle executables を spawn させる。
4. 結果として得られる SIP bypass を使用して、保護された file-system state を変更し、Microsoft の demonstration では、kernel extension exclusion list を上書きする。

Kernel researchers にとって重要な教訓は、direct third-party kext loading が厳しく制限されている場合でも、**kernel attack surface は userland management daemons から再び導入され得る**ということである。

Useful triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzingとresearch workflow

この種類のbugを積極的に探しているなら、最近のpublic workは同じ方向を示しています。

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) は、Apple Silicon時代のkernel researchにおける最良のreferenceの1つです。**static binary rewriting**を使用してcoverageを復元し、testing中は**entitlement-gated**なpathを無効化し、userspace wrapperからinterfaceの構造を推測します。<sup>[[4]](#references)</sup>
- Project Zeroの[**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) は、**kext / filesetをuserspaceにrebase**して、device上で再現する前にparser-heavyなcodeをはるかに高速にfuzzingする、非常に実践的なworkflowを紹介しています。<sup>[[5]](#references)</sup>
- Mach-heavyなtargetでは、単一のselector blobだけでなく、**real message layout**と**multi-call state machine**を中心にharnessを構築します。Project Zeroによる最近のCoreAudio/Mach researchや、**Fuzzing at Mach Speed**などのconference talkは、statefulなmessage sequenceが有効であり続ける理由を示しています。

実際に何度も使用することになる、簡単なlocal command：
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Quick Enumerationチートシート
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
- [2] [Microsoft Security Blog - CVE-2024-44243の分析：kernel extensionsを介したmacOS System Integrity Protection bypass](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - AppleのOTA Updateの悪夢：Signature VerificationのbypassとKernelの掌握](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz：Mitigationsの悪用によるApple Silicon上のmacOS Kernel EXTensionsのFuzzing (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDAとTinyInstを使用したuserspaceでのシンプルなmacOS kernel extension fuzzing](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [macOS Sonoma 14.4のsecurity contentについて - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
