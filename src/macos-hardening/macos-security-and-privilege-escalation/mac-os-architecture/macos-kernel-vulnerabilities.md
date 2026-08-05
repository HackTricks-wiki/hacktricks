# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

Güncel macOS kernel exploitation, "önemsiz bir unsigned kext yükleyip ring-0 elde etmekten" ziyade **Mach/MIG parser'larını**, **IOKit user client'larını**, **XNU içindeki data-only race'leri** ve kernel attack surface'ini yeniden açabilen **özel yetkilere sahip daemon'ları** kötüye kullanmaya dayanır. Somut interface'leri reverse etmek için [**IOKit**](macos-iokit.md) ve [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) sayfalarına da bakın.

## Hâlâ önem taşıyan attack surface'leri

- Sistem daemon'larındaki ve kernel'e erişen servislerdeki **Mach/MIG handler'ları**: hatalı descriptor'lar, out-of-line (OOL) data ve stateful multi-message flow'lar.
- **IOKit user client'ları**: selector'a özgü parsing, entitlement ile kısıtlanan method'lar ve gerçek call graph'ı gizleyen wrapper library/daemon'lar.
- **XNU data-only primitive'leri**: credential'lar, SMR tarafından korunan pointer'lar, read-only zone'lar ve corruption'ın önce RIP/PC kontrolünü ele geçirmeden policy'yi değiştirdiği diğer alanlar etrafındaki race'ler.
- **Third-party / auxiliary kernel code**: legacy kext'ler daha nadir olsa da enterprise fleet'leri, reduced-security Apple Silicon sistemleri ve vendor `.fs` / helper bundle'ları hâlâ yüksek değerli kernel-adjacent yollar oluşturur.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) çeşitli OTA/update-chain bug'ları birleştirilerek software update pipeline'ı ve rootless ile ilgili capability'ler kötüye kullanılıp kernel compromise elde edilir.<sup>[[3]](#references)</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple'ın [**March 2024 macOS security release'leri**](https://support.apple.com/en-us/120895) **aktif olarak exploit edilen** iki sorunu düzeltti:

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write yetkisine sahip bir attacker'ın kernel memory protection'larını bypass etmesini sağlayan memory-corruption bug'ı.
- **CVE-2024-23296 – RTKit**: aynı public impact statement'a sahip ikinci bir memory-corruption bug'ı.

Public root-cause detayları hâlâ sınırlı olsa da bu ikili, modern Apple exploit chain'lerinin çoğu zaman **"sadece" kernel R/W'den fazlasına** ihtiyaç duyduğunu hatırlatır: memory protection'lara, coprocessor-adjacent code'a veya secondary trust boundary'lere yönelik post-exploitation çalışmaları, gerçek chain'in stabilize edildiği aşama olur.

Quick patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + salt okunur credential race (CVE-2025-24118)

Joseph Ravichandran'ın [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) çalışması, klasik bir **buffer overflow** olmadığı için modern bir XNU vaka çalışmasıdır:<sup>[[1]](#references)</sup>

- `proc_ro.p_ucred`, **salt okunur** bir `proc_ro` nesnesinde depolanan **SMR-korumalı bir pointer**'dır.
- Writer'lar bu pointer'ı **atomik olarak** güncellemelidir.
- `kauth_cred_proc_update()`, `p_ucred`'ı değiştirmek için `zalloc_ro_mut(...)` kullanıyordu; x86_64'te bu yol sonunda `memcpy` / `rep movsb`'ye ulaştığı için eşzamanlı bir reader **parçalanmış bir pointer** gözlemleyebilir.
- Bug, **data-only privilege escalation** durumuna dönüşür: bozulmuş credential pointer'ı farklı bir geçerli credential nesnesine çözülürse mevcut thread, bariz bir control-flow hijack gerçekleştirmeden daha ayrıcalıklı bir durumu devralabilir.

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
Yararlı audit sezgisi: bir kernel yolu **SMR readers**, **read-only zone mutation** ve **credential veya task metadata** kavramlarını birlikte kullandığında, güncellemelerin copy-based helper'lar yerine atomic `zalloc_ro_mut_*` varyantlarını kullandığını doğrulayın.

---

## 2024-2025: kernel loading path'lerini yeniden açan SIP bypass (CVE-2024-44243)

Microsoft, `storagekitd`'nin **SIP bypass** için kötüye kullanılabileceğini ve ardından, aksi hâlde "post-kext" olarak görülecek makinelerde üçüncü taraf kernel kodunu yeniden önemli hâle getirebileceğini gösterdi. Temel fikir:<sup>[[2]](#references)</sup>

1. `/Library/Filesystems` altında kötü amaçlı bir `.fs` bundle bırakın veya mevcut bundle'ın üzerine yazın.
2. Disk Utility veya `diskutil` aracılığıyla `storagekitd`'yi tetikleyin.
3. Özel yetkilere sahip daemon'ın, **privilege'ları düzgün şekilde düşürmeden / path'i doğrulamadan** bundle executable'larını başlatmasına izin verin.
4. Ortaya çıkan SIP bypass'ı, korunan file-system durumunu değiştirmek ve Microsoft'un gösteriminde kernel extension exclusion list'ini değiştirmek için kullanın.

Kernel araştırmacıları için önemli ders şudur: **doğrudan üçüncü taraf kext yükleme ciddi şekilde kısıtlanmış olsa bile, kernel attack surface userland yönetim daemon'larından yeniden ortaya çıkarılabilir.**

Yararlı triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing ve araştırma iş akışı

Bu hata sınıfını aktif olarak arıyorsanız, yakın zamanda yayımlanan çalışmalar aynı yönü gösteriyor:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin), Apple Silicon dönemi kernel araştırmaları için hâlâ en iyi referanslardan biri. **static binary rewriting** kullanarak coverage bilgisini geri kazanıyor, test sırasında **entitlement-gated** yolları devre dışı bırakıyor ve userspace wrapper'larından interface yapısını çıkarıyor.<sup>[[4]](#references)</sup>
- Project Zero'nun [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) çalışması, **kext / fileset'i userspace'e rebase etme** konusunda son derece pratik bir iş akışı gösteriyor. Böylece parser-heavy code, cihaz üzerinde yeniden üretilmeden önce çok daha yüksek hızda fuzz edilebiliyor.<sup>[[5]](#references)</sup>
- Mach ağırlıklı hedeflerde harness'leri yalnızca tek selector blob'ları etrafında değil, **gerçek message layout'ları ve multi-call state machine'leri** etrafında oluşturun. Project Zero'nun yakın tarihli CoreAudio/Mach araştırmaları ve **Fuzzing at Mach Speed** gibi konferans sunumları, stateful message sequence'lerinin neden sürekli işe yaradığını gösteriyor.

Pratikte sıkça kullanacağınız hızlı yerel komutlar:
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
## Kaynaklar

- [1] [Joseph Ravichandran - TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [2] [Microsoft Security Blog - CVE-2024-44243'ü analiz etme: kernel extensions aracılığıyla bir macOS System Integrity Protection bypass'ı](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple'ın OTA Güncellemesinin Kâbusu: Signature Verification'ı Bypass Etme ve Kernel'i Pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin ve diğerleri - KextFuzz: Mitigations'ı Exploit Etme Yoluyla Apple Silicon'da macOS Kernel EXTensions için Fuzzing (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDA ve TinyInst ile userspace'te basit macOS kernel extension fuzzing'i](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
