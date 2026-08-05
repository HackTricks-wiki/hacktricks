# macOS Kernel Zafiyetleri

{{#include ../../../banners/hacktricks-training.md}}

Recent macOS kernel exploitation artık "trivial unsigned kext yükleyip ring-0 elde etmekten" çok **Mach/MIG parser**'larını, **IOKit user client**'larını, XNU içindeki **data-only race**'leri ve kernel attack surface'i yeniden açabilen **specially entitled daemon**'ları abuse etmeye dayanıyor. Somut interface'leri reverse etmek için [**IOKit**](macos-iokit.md) ve [**kernel extensions / kernelcache extraction**](macos-kernel-extensions.md) sayfalarına da bakın.

## Hâlâ önem taşıyan attack surface'leri

- System daemon'larındaki ve kernel-facing service'lerdeki **Mach/MIG handler**'ları: malformed descriptor'lar, out-of-line (OOL) data ve stateful multi-message flow'lar.
- **IOKit user client**'ları: selector-specific parsing, entitlement-gated method'lar ve gerçek call graph'ı gizleyen wrapper library/daemon'ları.
- **XNU data-only primitive**'leri: credential'lar, SMR-protected pointer'lar, read-only zone'lar ve corruption'ın önce RIP/PC control elde etmeden policy'yi değiştirdiği diğer noktalar etrafındaki race'ler.
- **Third-party / auxiliary kernel code**: legacy kext'ler daha nadir olsa da enterprise fleet'leri, reduced-security Apple Silicon sistemleri ve vendor `.fs` / helper bundle'ları hâlâ yüksek değerli kernel-adjacent path'ler oluşturuyor.

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Bu raporda**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) birkaç OTA/update-chain bug'ı, software update pipeline'ını ve rootless-related capability'leri abuse ederek kernel compromise'a ulaşmak için birleştiriliyor.<sup>[3]</sup>

[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild kernel protection bypass chain (CVE-2024-23225 & CVE-2024-23296)

Apple'ın [**March 2024 macOS security release**](https://support.apple.com/en-us/120895)'leri **actively exploited** olan iki sorunu düzeltti:

- **CVE-2024-23225 – Kernel**: arbitrary kernel read/write yetkisine sahip bir attacker'ın kernel memory protection'larını bypass etmesini sağlayan bir memory-corruption bug'ı.
- **CVE-2024-23296 – RTKit**: aynı public impact statement'e sahip ikinci bir memory-corruption bug'ı.

Public root-cause detail'ları hâlâ sınırlı, ancak bu ikili modern Apple exploit chain'lerinin genellikle **"sadece" kernel R/W'den daha fazlasına** ihtiyaç duyduğunu hatırlatıyor: memory protection'lara, coprocessor-adjacent code'a veya secondary trust boundary'lere yönelik post-exploitation çalışmaları, gerçek chain'in stabilize edildiği nokta oluyor.

Hızlı patch triage:
```bash
sw_vers
uname -v
softwareupdate --history | tail -n 20
```
---

## 2025: SMR + salt okunur credential race (CVE-2025-24118)

Joseph Ravichandran'ın [**TRAVERTINE write-up**](https://jprx.io/cve-2025-24118/) yazısı, bunun klasik bir buffer overflow olmaması nedeniyle oldukça iyi bir modern XNU vaka çalışmasıdır:<sup>[1]</sup>

- `proc_ro.p_ucred`, salt okunur bir `proc_ro` nesnesinde depolanan **SMR-korumalı bir pointer**'dır.
- Writer'lar bu pointer'ı **atomik olarak** güncellemelidir.
- `kauth_cred_proc_update()`, `p_ucred`'ı değiştirmek için `zalloc_ro_mut(...)` kullanıyordu; x86_64 üzerinde bu yol sonunda `memcpy` / `rep movsb`'ye ulaştığından, eşzamanlı bir reader **bölünmüş bir pointer** gözlemleyebilir.
- Bug, **salt veri tabanlı bir privilege escalation**'a dönüşür: bozulmuş credential pointer'ı farklı bir geçerli credential nesnesine çözülürse, mevcut thread önce bariz bir control-flow hijack gerçekleştirmeye gerek kalmadan daha ayrıcalıklı durumu devralabilir.

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
Yararlı audit heuristic: kernel path'inde **SMR readers**, **read-only zone mutation** ve **credential veya task metadata** birlikte kullanıldığında, güncellemelerin copy-based helper'lar yerine atomic `zalloc_ro_mut_*` varyantlarını kullandığını doğrulayın.

---

## 2024-2025: SIP bypass that re-opens kernel loading paths (CVE-2024-44243)

Microsoft, `storagekitd`'nin **SIP bypass** gerçekleştirmek ve ardından normalde "post-kext" olarak görünen makinelerde üçüncü taraf kernel code'u yeniden ilgili hâle getirmek için kötüye kullanılabileceğini gösterdi. Temel fikir şudur:<sup>[2]</sup>

1. `/Library/Filesystems` altında kötü amaçlı bir `.fs` bundle bırakın veya mevcut bundle'ın üzerine yazın.
2. Disk Utility veya `diskutil` üzerinden `storagekitd`'yi tetikleyin.
3. Özel yetkilere sahip daemon'ın **privileges'ı düzgün şekilde düşürmeden / path'i doğrulamadan** bundle executable'larını spawn etmesini sağlayın.
4. Ortaya çıkan SIP bypass'ı, protected file-system state'i değiştirmek ve Microsoft'un gösteriminde kernel extension exclusion list'i override etmek için kullanın.

Kernel researchers için önemli ders şudur: doğrudan üçüncü taraf kext loading ciddi ölçüde kısıtlanmış olsa bile, **kernel attack surface userland management daemon'ları üzerinden yeniden ortaya çıkarılabilir**.

Yararlı triage:
```bash
ls -la /Library/Filesystems
find /Library/Filesystems -maxdepth 3 -type f \( -name 'mount_*' -o -name 'fsck_*' -o -name 'newfs_*' \) 2>/dev/null
log stream --style syslog --predicate 'process == "storagekitd" || process == "diskarbitrationd"'
kmutil showloaded --collection aux
```
---

## Fuzzing ve araştırma iş akışı

Bu bug sınıfını aktif olarak araştırıyorsanız, yakın tarihli kamuya açık çalışmalar aynı yönü işaret ediyor:

- [**KextFuzz**](https://www.usenix.org/conference/usenixsecurity23/presentation/yin), Apple Silicon dönemindeki kernel araştırmaları için hâlâ en iyi referanslardan biri. **Static binary rewriting** kullanarak coverage'ı geri kazanıyor, test sırasında **entitlement-gated** yolları devre dışı bırakıyor ve userspace wrapper'larından interface yapısını çıkarıyor.<sup>[4]</sup>
- Project Zero'nun [**Simple macOS kernel extension fuzzing in userspace with IDA and TinyInst**](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html) çalışması, parser ağırlıklı kodun cihaz üzerinde yeniden üretimden önce çok daha yüksek hızda fuzz edilebilmesi için **bir kext'i / fileset'i userspace'e rebase etme** konusunda oldukça pratik bir workflow gösteriyor.<sup>[5]</sup>
- Mach ağırlıklı hedefler için harness'leri yalnızca tek selector blob'ları etrafında değil, **gerçek message layout'ları ve çok çağrılı state machine'ler** etrafında oluşturun. Project Zero'nun yakın tarihli CoreAudio/Mach araştırmaları ve **Fuzzing at Mach Speed** gibi konferans sunumları, stateful message sequence'larının neden sürekli sonuç verdiğini gösteriyor.

Gerçekte sık sık kullanacağınız hızlı yerel komutlar:
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
- [2] [Microsoft Security Blog - CVE-2024-44243'ü analiz etme: kernel extensions aracılığıyla bir macOS System Integrity Protection bypass'ı](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [3] [Mickey Jin - Apple's OTA Update'inin Kabusu: Signature Verification'ı Bypass Etme ve Kernel'i Pwning](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)
- [4] [Tingting Yin et al. - KextFuzz: Mitigations'tan yararlanarak Apple Silicon üzerinde macOS Kernel EXTensions için Fuzzing (USENIX Security '23)](https://www.usenix.org/conference/usenixsecurity23/presentation/yin)
- [5] [Ivan Fratric (Project Zero) - IDA ve TinyInst ile userspace'te basit macOS kernel extension fuzzing'i](https://projectzero.google/2024/11/simple-macos-kernel-extension-fuzzing.html)

{{#include ../../../banners/hacktricks-training.md}}
