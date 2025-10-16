# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, cihaz bootloader yapılandırması (seccfg) "unlocked" olduğunda doğrulama boşluğundan yararlanarak birden fazla MediaTek platformunda pratik bir secure-boot açığını belgeliyor. Bu hata, ARM EL3'te yaması yapılmış bir bl2_ext'in çalıştırılmasına izin vererek sonraki imza doğrulamalarını devre dışı bırakır, güven zincirini çökertir ve unsigned TEE/GZ/LK/Kernel gibi bileşenlerin rastgele yüklenmesini mümkün kılar.

> Uyarı: Early-boot patching, offset'ler yanlışsa cihazları kalıcı olarak tuğla edebilir. Her zaman tam dump'ları ve güvenilir bir kurtarma yolunu saklayın.

## Etkilenen boot akışı (MediaTek)

- Normal yol: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Zayıf yol: seccfg "unlocked" olarak ayarlandığında, Preloader bl2_ext'in doğrulanmasını atlayabilir. Preloader yine de EL3'te bl2_ext'e atlar; bu yüzden hazırlanmış bir bl2_ext sonrasında doğrulanmamış bileşenleri yükleyebilir.

Ana güven sınırı:
- bl2_ext EL3'te çalışır ve TEE, GenieZone, LK/AEE ve kernel'i doğrulamaktan sorumludur. Eğer bl2_ext'in kendisi doğrulanmamışsa, zincirin geri kalanı kolayca atlanır.

## Kök neden

Etkilenen cihazlarda, seccfg "unlocked" durumunu gösterdiğinde Preloader bl2_ext partition'ının kimlik doğrulamasını zorlamaz. Bu, EL3'te çalışan saldırgan kontrollü bir bl2_ext'in flash'lenmesine izin verir.

bl2_ext içinde, doğrulama politika fonksiyonu koşulsuz olarak doğrulamanın gerekli olmadığını rapor edecek şekilde patch'lenebilir. Kavramsal olarak en az düzeyde bir patch şöyledir:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Bu değişiklikle, EL3'te çalışan patched bl2_ext tarafından yüklendiğinde, sonraki tüm imajlar (TEE, GZ, LK/AEE, Kernel) kriptografik kontroller olmadan kabul edilir.

## Bir hedef nasıl değerlendirilir (expdb logları)

Boot loglarını (ör. expdb) bl2_ext yüklemesi civarında dök/incele. Eğer img_auth_required = 0 ve certificate verification time ~0 ms ise, enforcement muhtemelen kapalıdır ve cihaz exploitable'dır.

Örnek log kesiti:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Not: Bazı cihazların kilitli bootloader olsa bile bl2_ext doğrulamasını atladığı bildirildi; bu etkinin şiddetini artırır.

## Pratik istismar iş akışı (Fenrir PoC)

Fenrir, bu sınıf sorunlar için referans bir exploit/patching toolkit'tir. Nothing Phone (2a) (Pacman) cihazlarını destekler ve CMF Phone 1 (Tetris) üzerinde çalıştığı (tam desteklenmiyor) bilinmektedir. Diğer modellere port etmek, cihaz-özgü bl2_ext'in reverse engineering'ini gerektirir.

Genel süreç:
- Hedef kodadınız için device bootloader imajını edinin ve bin/<device>.bin olarak yerleştirin
- bl2_ext doğrulama politikasını devre dışı bırakan bir patched image oluşturun
- Ortaya çıkan payload'ı cihaza flash edin (helper script tarafından fastboot varsayılır)

Komutlar:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Runtime payload capabilities (EL3)

Yaması uygulanmış bl2_ext payload şunları yapabilir:
- Özel fastboot komutları kaydedebilir
- Boot modunu kontrol edebilir/üstüne yazabilir
- Çalışma zamanında dahili bootloader fonksiyonlarını dinamik olarak çağırabilir
- Gerçekte kilidi açıkken “lock state”i kilitliymiş gibi sahteleyerek daha güçlü bütünlük kontrollerini geçebilir (bazı ortamlar yine de vbmeta/AVB ayarlamaları gerektirebilir)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Porting tips

- Cihaza özgü bl2_ext'i reverse engineer ederek doğrulama politika mantığını bulun (ör. sec_get_vfy_policy).
- Politika dönüş noktasını veya karar dalını belirleyin ve bunu “no verification required” olacak şekilde patch'leyin (return 0 / unconditional allow).
- Offsets'ları tamamen cihaza ve firmware'e özgü tutun; varyantlar arasında adresleri yeniden kullanmayın.
- Önce fedakâr bir cihazda doğrulayın. Flashlamadan önce bir kurtarma planı hazırlayın (ör. EDL/BootROM loader/SoC-specific download mode).

## Security impact

- Preloader'dan sonra EL3 kodu çalıştırma ve geri kalan boot yolunun chain-of-trust'inin tamamen çökmesi.
- Unsigned TEE/GZ/LK/Kernel boot etme yeteneği; secure/verified boot beklentilerini atlatır ve kalıcı compromise'a izin verir.

## Detection and hardening ideas

- Preloader'ın seccfg durumundan bağımsız olarak bl2_ext'i doğruladığından emin olun.
- Authentication sonuçlarını zorunlu kılın ve denetim kanıtı toplayın (timings > 0 ms, eşleşmeme durumunda katı hatalar).
- Lock-state spoofing attestation için etkisiz hale getirilmelidir (lock state'i AVB/vbmeta doğrulama kararlarına ve fuse-backed duruma bağlayın).

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}
