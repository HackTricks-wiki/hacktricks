# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, cihaz bootloader yapılandırması (seccfg) "unlocked" olduğunda doğrulama boşluğundan yararlanarak birden fazla MediaTek platformunda pratik bir secure-boot kırılmasını belgeler. Bu kusur, ARM EL3'te yama yapılmış bir bl2_ext çalıştırmaya izin vererek aşağı yönlü imza doğrulamayı devre dışı bırakır, güven zincirini çökerterek rastgele unsigned TEE/GZ/LK/Kernel yüklemeye olanak tanır.

> Uyarı: Erken-boot yaması, offset'ler yanlışsa cihazları kalıcı olarak tuğla haline getirebilir. Her zaman tam dump'ları ve güvenilir bir kurtarma yolunu saklayın.

## Etkilenen boot akışı (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Ana güven sınırı:
- bl2_ext EL3'te çalışır ve TEE, GenieZone, LK/AEE ve kernel'i doğrulamaktan sorumludur. Eğer bl2_ext'in kendisi doğrulanmamışsa, zincirin geri kalanı kolayca atlanır.

## Kök neden

Etkilenen cihazlarda, seccfg "unlocked" durumunu gösterdiğinde Preloader bl2_ext bölümünün kimlik doğrulamasını zorunlu kılmaz. Bu, EL3'te çalışan saldırgan kontrollü bir bl2_ext'in flashlenmesine izin verir.

bl2_ext içinde, doğrulama politika fonksiyonu şart koşulsuz olarak doğrulamanın gerekli olmadığını bildirecek şekilde yamalanabilir. Minimal kavramsal yama şudur:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Bu değişiklikle, EL3'te çalışan yamalı bl2_ext tarafından yüklendiklerinde sonraki tüm imajlar (TEE, GZ, LK/AEE, Kernel) kriptografik kontroller olmadan kabul edilir.

## Bir hedef nasıl triage edilir (expdb logları)

bl2_ext yüklemesi çevresindeki boot loglarını (ör. expdb gibi) dök/incele. Eğer img_auth_required = 0 ve sertifika doğrulama süresi ~0 ms ise, zorlamanın muhtemelen kapalı olduğu ve cihazın sömürülebilir olduğu anlaşılır.

Örnek log kesiti:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Not: Bazı cihazların bildirildiğine göre kilitli bir bootloader olsa bile bl2_ext doğrulamasını atladığı ve bunun etkinin artmasına neden olduğu.

## Pratik exploitation iş akışı (Fenrir PoC)

Fenrir, bu sınıftaki sorunlar için referans bir exploit/patching toolkit'tir. Nothing Phone (2a) (Pacman) modelini destekler ve CMF Phone 1 (Tetris) üzerinde (eksik destekle) çalıştığı bilinmektedir. Diğer modellere port etmek, cihaza özgü bl2_ext'in reverse engineering'ini gerektirir.

Yüksek seviyeli süreç:
- Hedef codename'iniz için cihazın bootloader imajını edinin ve bunu bin/<device>.bin olarak yerleştirin
- bl2_ext doğrulama politikasını devre dışı bırakan bir patched image oluşturun
- Ortaya çıkan payload'ı cihaza flash'layın (yardımcı script fastboot varsayımı yapar)

Komutlar:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot kullanılamıyorsa, platformunuz için uygun bir alternatif flashing yöntemi kullanmalısınız.

## Runtime payload capabilities (EL3)

Patched bl2_ext payload şunları yapabilir:
- Özel fastboot komutları kaydetmek
- Boot modunu kontrol/override etmek
- Çalışma zamanında yerleşik bootloader fonksiyonlarını dinamik olarak çağırmak
- Güçlü bütünlük kontrollerini geçmek için kilit durumunu kilitli gibi sahtelemek (bazı ortamlarda hâlâ vbmeta/AVB ayarlamaları gerekebilir)

Sınırlama: Mevcut PoC'lar, MMU kısıtlamaları nedeniyle çalışma zamanı bellek değişikliklerinin fault oluşturabileceğini not eder; payload'lar genelde bu çözülene kadar canlı bellek yazmalarından kaçınır.

## Porting tips

- Cihaza özgü bl2_ext'i tersine mühendislik yaparak doğrulama politika mantığını bulun (örn., sec_get_vfy_policy).
- Politika dönüş noktasını veya karar dalını tespit edin ve bunu “doğrulama gerekmez” olarak yama yapın (return 0 / koşulsuz izin).
- Ofsetlerin tamamen cihaza ve firmware'e özgü olmasını sağlayın; varyantlar arasında adresleri yeniden kullanmayın.
- Önce feda edilebilir bir ünite üzerinde doğrulayın. Flashlamadan önce bir kurtarma planı hazırlayın (örn., EDL/BootROM loader/SoC'e özgü download modu).

## Security impact

- Preloader'dan sonra EL3 kod yürütmesi ve geri kalan boot yolunda tüm güven zincirinin çöküşü.
- İmzalanmamış TEE/GZ/LK/Kernel boot etme yeteneği, secure/verified boot beklentilerini atlayarak kalıcı kompromis sağlanmasını mümkün kılar.

## Detection and hardening ideas

- Preloader'ın seccfg durumundan bağımsız olarak bl2_ext'i doğruladığından emin olun.
- Kimlik doğrulama sonuçlarını zorunlu kılın ve denetim kanıtı toplayın (timings > 0 ms, uyumsuzlukta katı hatalar).
- Lock-state sahtekarlığını attestation için etkisiz hale getirin (kilit durumunu AVB/vbmeta doğrulama kararlarına ve fuse-backed duruma bağlayın).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
