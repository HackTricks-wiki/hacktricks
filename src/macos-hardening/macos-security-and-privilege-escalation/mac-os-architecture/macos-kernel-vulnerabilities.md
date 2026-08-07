# macOS Kernel Zafiyetleri

{{#include ../../../banners/hacktricks-training.md}}

Güncel macOS kernel exploitation, "önemsiz bir unsigned kext yükleyip ring-0 elde etmekten" ziyade **Mach/MIG parser'larını**, **IOKit user client'larını**, **XNU içindeki yalnızca veri üzerinde çalışan yarış durumlarını** ve kernel attack surface'i yeniden açabilen **özel yetkilere sahip daemon'ları** kötüye kullanmaya dayanıyor. Somut arayüzleri reverse etmek için [**IOKit**](macos-iokit.md) ve [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) sayfalarına da bakın.

## Hâlâ önem taşıyan attack surface'ler

- Sistem daemon'larındaki ve kernel'e yönelik servislerdeki **Mach/MIG handler'ları**: hatalı descriptor'lar, out-of-line (OOL) veriler ve stateful çoklu mesaj akışları.
- **IOKit user client'ları**: selector'a özgü parsing, entitlement ile kısıtlanmış method'lar ve gerçek call graph'ı gizleyen wrapper library/daemon'lar.
- **XNU data-only primitive'leri**: credential'lar, SMR tarafından korunan pointer'lar, read-only zone'lar ve corruption'ın önce RIP/PC kontrolünü ele geçirmeden policy'yi değiştirdiği diğer alanlar etrafındaki race condition'lar.
- **Third-party / auxiliary kernel code**: legacy kext'ler daha nadir görülse de enterprise fleet'ler, reduced-security Apple Silicon sistemleri ve vendor `.fs` / helper bundle'ları hâlâ yüksek değerli kernel-adjacent yollar oluşturuyor.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) birkaç OTA/update-chain bug'ı birleştirilerek software update pipeline ve rootless ile ilgili yetenekler kötüye kullanılıp kernel compromise'a ulaşılıyor.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: Gerçek saldırılarda kernel korumasını bypass eden chain (CVE-2024-23225 & CVE-2024-23296)

Apple'ın [**March 2024 macOS security releases**](https://support.apple.com/en-us/120895) sayfasında, **aktif olarak exploit edilen** iki sorun düzeltildi:<sup>[[6]](#references)</sup>

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write yetkisine sahip bir attacker'ın kernel memory protection'larını bypass etmesini sağlayan bir memory-corruption bug'ı.
- **CVE-2024-23296 – RTKit**: aynı public impact statement'a sahip ikinci bir memory-corruption bug'ı.

Public root-cause ayrıntıları hâlâ sınırlı; ancak bu ikili, modern Apple exploit chain'lerinin çoğu zaman **"sadece" kernel R/W'den daha fazlasına** ihtiyaç duyduğunu hatırlatıyor: memory protection'lara, coprocessor-adjacent code'a veya ikincil trust boundary'lere yönelik post-exploitation çalışmaları, gerçek chain'in stabilize edildiği nokta oluyor.

Hızlı patch önceliklendirmesi:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + salt okunur credential race (CVE-2025-24118)

Joseph Ravichandran'ın [**TRAVERTINE incelemesi**](https://jprx.io/cve-2025-24118/) çok iyi bir modern XNU case study örneğidir; çünkü bu, **klasik bir buffer overflow** değildir:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred`, **salt okunur** bir `proc_ro` nesnesinde depolanan **SMR-korumalı bir pointer**'dır.
- Writer'lar bu pointer'ı **atomik olarak** güncellemelidir.
- `kauth_cred_proc_update()`, `p_ucred`'ı değiştirmek için `zalloc_ro_mut(...)` kullanıyordu; x86_64 üzerinde bu yol sonunda `memcpy` / `rep movsb`'ye ulaştığından, eşzamanlı bir reader **parçalanmış bir pointer** gözlemleyebilir.
- Bug, **data-only privilege escalation**'a dönüşür: bozulmuş credential pointer'ı farklı bir geçerli credential nesnesine çözülürse mevcut thread, önce belirgin bir control-flow hijack gerçekleştirmeden daha yüksek ayrıcalıklı durumu devralabilir.

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
Yararlı audit heuristic: bir kernel path'i **SMR readers**, **read-only zone mutation** ve **credential or task metadata** bileşenlerini birlikte kullandığında, güncellemelerin copy-based helper'lar yerine atomic `zalloc_ro_mut_*` varyantlarını kullandığını doğrulayın.

---

## 2024-2025: Kernel loading path'lerini yeniden açan SIP bypass (CVE-2024-44243)

Microsoft, `storagekitd`'nin **SIP'i bypass etmek** ve ardından normalde "post-kext" olarak görülecek makinelerde third-party kernel code'u yeniden ilgili hâle getirmek için abuse edilebileceğini gösterdi. Temel fikir şudur:<sup>[[2]](#references)</sup>

1. `/Library/Filesystems` altında kötü amaçlı bir `.fs` bundle drop edin veya mevcut bundle'ın üzerine yazın.
2. Disk Utility veya `diskutil` üzerinden `storagekitd`'yi trigger edin.
3. Özel yetkilere sahip daemon'ın, **privilege'ları düzgün şekilde drop etmeden / path'i doğrulamadan** bundle executable'larını spawn etmesine izin verin.
4. Ortaya çıkan SIP bypass'ı, protected file-system state'i değiştirmek ve Microsoft'un demonstration'ında kernel extension exclusion list'ini override etmek için kullanın.

Kernel araştırmacıları için önemli ders şudur: **kernel attack surface, userland management daemon'larından yeniden devreye sokulabilir**; direct third-party kext loading ciddi şekilde kısıtlanmış olsa bile.

Yararlı triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing ve araştırma iş akışı

Bu hata sınıfını aktif olarak arıyorsanız, yakın zamanda yayımlanan çalışmalar aynı yöne işaret ediyor:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin), Apple Silicon dönemi kernel araştırmaları için hâlâ en iyi referanslardan biri. **static binary rewriting** kullanarak coverage'ı geri kazanıyor, test sırasında **entitlement-gated** yolları devre dışı bırakıyor ve userspace wrapper'larından interface yapısını çıkarıyor.<sup>[[4]](#references)</sup>
- Project Zero'nun [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) çalışması, parser ağırlıklı kodun cihaz üzerinde yeniden üretilmeden önce çok daha yüksek hızda fuzz edilebilmesi için **kext / fileset'i userspace'e rebase etme** konusunda oldukça pratik bir workflow gösteriyor.<sup>[[5]](#references)</sup>
- Mach ağırlıklı hedefler için harness'leri yalnızca tek selector blob'ları etrafında değil, **gerçek message layout'ları ve çok çağrılı state machine'ler** etrafında oluşturun. Project Zero'nun yakın tarihli CoreAudio/Mach araştırmaları ve **Fuzzing at Mach Speed** gibi konferans sunumları, stateful message sequence'larının neden sürekli sonuç verdiğini gösteriyor.

Gerçekte sıkça kullanacağınız hızlı local komutlar:
```bash
# Loaded auxiliary / 3rd party kernel code
kmutil showloaded --collection aux

# Fileset entries in the boot kernel collection
kmutil inspect -B /System/Library/KernelCollections/BootKernelExtensions.kc --show-fileset-entries

# Diffable version info before matching a KDK / symbols pack
sw_vers
uname -a
```
## Hızlı Enumeration Cheatsheet
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

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - CVE-2024-44243 analizi: kernel extensions üzerinden bir macOS System Integrity Protection bypass'ı](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple's OTA Update kabusu: Signature Verification'ı bypass etmek ve Kernel'ı Pwn etmek](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin ve diğerleri - KextFuzz: Mitigations'ı exploit ederek Apple Silicon üzerinde macOS Kernel EXTensions fuzzing'i (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDA ve TinyInst ile userspace'te basit macOS kernel extension fuzzing'i](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)
- [6] [macOS Sonoma 14.4'ün güvenlik içeriği hakkında - Apple Support](https://support.apple.com/en-us/120895)

{{#include ../../../banners/hacktricks-training.md}}
