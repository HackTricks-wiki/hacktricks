# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

Yakın dönem macOS kernel exploitation, artık daha çok "trivial unsigned kext yükleyip ring-0 elde etmekten" ziyade **Mach/MIG parser'larını**, **IOKit user client'larını**, **XNU içindeki data-only race'leri** ve kernel attack surface'ini yeniden açabilen **özel yetkilere sahip daemon'ları** kötüye kullanmaya dayanıyor. Somut interface'leri reverse etmek için [**IOKit**](macos-iokit.md) ve [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) sayfalarına da bakın.

## Hâlâ önem taşıyan attack surface'leri

- Sistem daemon'larındaki ve kernel-facing service'lerdeki **Mach/MIG handler'ları**: hatalı descriptor'lar, out-of-line (OOL) data ve stateful multi-message akışları.
- **IOKit user client'ları**: selector'a özel parsing, entitlement-gated method'lar ve gerçek call graph'ı gizleyen wrapper library/daemon'ları.
- **XNU data-only primitive'leri**: credential'lar, SMR-protected pointer'lar, read-only zone'lar ve corruption'ın önce RIP/PC control elde etmeden policy'yi değiştirdiği diğer alanlar etrafındaki race'ler.
- **Third-party / auxiliary kernel code**: legacy kext'ler daha nadir olsa da enterprise fleet'leri, reduced-security Apple Silicon sistemleri ve vendor `.fs` / helper bundle'ları hâlâ yüksek değerli kernel-adjacent path'ler oluşturuyor.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) çeşitli OTA/update-chain bug'ları birleştirilerek software update pipeline'ı ve rootless-related capability'ler kötüye kullanılıp kernel compromise'a ulaşılıyor.

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple'ın [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) kapsamında **actively exploited** olan iki sorun düzeltildi:

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write yetkisine sahip bir attacker'ın kernel memory protection'larını bypass etmesini sağlayan memory-corruption bug'ı.
- **CVE-2024-23296 – RTKit**: aynı public impact statement'a sahip ikinci bir memory-corruption bug'ı.

Public root-cause detayları hâlâ sınırlı, ancak bu ikili modern Apple exploit chain'lerinin çoğu zaman **"sadece" kernel R/W'den fazlasına** ihtiyaç duyduğunu hatırlatıyor: memory protection'lara, coprocessor-adjacent code'a veya secondary trust boundary'lere yönelik post-exploitation çalışmaları, gerçek chain'in stabilize edildiği nokta oluyor.

Hızlı patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + salt okunur credential race (CVE-2025-24118)

Joseph Ravichandran'ın [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) yazısı, klasik bir buffer overflow olmadığı için oldukça iyi bir modern XNU vaka incelemesidir:

- `proc_ro.p_ucred`, salt okunur bir `proc_ro` nesnesinde depolanan **SMR-korumalı bir pointer**'dır.
- Yazıcılar bu pointer'ı **atomik olarak** güncellemelidir.
- `kauth_cred_proc_update()`, `p_ucred`'ı değiştirmek için `zalloc_ro_mut(...)` kullanıyordu; x86_64 üzerinde bu yol sonunda `memcpy` / `rep movsb`'ye ulaşır. Bu nedenle eşzamanlı bir okuyucu **torn pointer** gözlemleyebilir.
- Bug, **data-only privilege escalation**'a dönüşür: bozulmuş credential pointer'ı farklı bir geçerli credential nesnesine çözülürse, mevcut thread önce belirgin bir **control-flow hijack** gerçekleştirmeden daha yüksek ayrıcalıklı durumu devralabilir.

Minimal tetikleme deseni:
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
Yararlı audit heuristic: bir kernel path'i **SMR readers**, **read-only zone mutation** ve **credential veya task metadata** kavramlarını birlikte kullandığında, güncellemelerin copy-based helper'lar yerine atomic `zalloc_ro_mut_*` varyantlarını kullandığını doğrulayın.

---

## 2024-2025: Kernel loading path'lerini yeniden açan SIP bypass (CVE-2024-44243)

Microsoft, `storagekitd`'nin **SIP bypass** amacıyla abuse edilebildiğini ve bunun sonucunda, aksi hâlde "post-kext" olarak görünen makinelerde third-party kernel code'u yeniden relevant hâle getirebildiğini gösterdi. Temel fikir şudur:

1. `/Library/Filesystems` altında malicious bir `.fs` bundle bırakın veya mevcut bundle'ın üzerine yazın.
2. Disk Utility veya `diskutil` üzerinden `storagekitd`'yi trigger edin.
3. Özel entitlement'lara sahip daemon'ın, privilege'ları düzgün şekilde drop etmeden / path'i validate etmeden bundle executable'larını spawn etmesini sağlayın.
4. Elde edilen SIP bypass'ı protected file-system state'i değiştirmek ve Microsoft'un demonstration'ında kernel extension exclusion list'ini override etmek için kullanın.

Kernel researchers için önemli ders şudur: direct third-party kext loading ciddi şekilde kısıtlanmış olsa bile, **kernel attack surface userland management daemon'ları üzerinden yeniden devreye alınabilir**.

Yararlı triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing ve araştırma workflow'u

Bu bug sınıfını aktif olarak arıyorsanız, son dönemdeki public çalışmalar aynı yöne işaret ediyor:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin), Apple Silicon dönemindeki kernel araştırmaları için hâlâ en iyi referanslardan biri. Coverage elde etmek için **static binary rewriting** kullanır, test sırasında **entitlement-gated** yolları devre dışı bırakır ve userspace wrapper'larından interface yapısını çıkarır.
- Project Zero'nun [**IDA ve TinyInst ile userspace'te basit macOS kernel extension fuzzing**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) çalışması, parser ağırlıklı kodun cihaz üzerinde yeniden üretim yapılmadan önce çok daha yüksek hızda fuzz edilebilmesi için **bir kext / fileset'i userspace'e rebase etme** konusunda oldukça pratik bir workflow gösteriyor.
- Mach ağırlıklı hedefler için harness'leri yalnızca tek selector blob'ları etrafında değil, **gerçek message layout'ları ve multi-call state machine'leri** etrafında oluşturun. Project Zero'nun son CoreAudio/Mach araştırmaları ve **Fuzzing at Mach Speed** gibi konferans sunumları, stateful message sequence'larının neden sürekli sonuç verdiğini gösteriyor.

Yerelde sıkça gerçekten kullanacağınız hızlı komutlar:
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
## Referanslar

* Joseph Ravichandran. “TRAVERTINE: CVE-2025-24118.” https://jprx.io/cve-2025-24118/
* Microsoft Security Blog. “CVE-2024-44243 analizi: kernel extensions üzerinden bir macOS System Integrity Protection bypass.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}
