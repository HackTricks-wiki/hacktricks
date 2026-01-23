# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, cihaz bootloader yapılandırması (seccfg) "unlocked" olduğunda ortaya çıkan bir doğrulama boşluğundan yararlanarak birden fazla MediaTek platformunda pratik bir secure-boot kırılmasını belgeliyor. Hata, ARM EL3'te yama uygulanmış bir bl2_ext çalıştırmaya izin vererek aşağı yöndeki imza doğrulamasını devre dışı bırakır, güven zincirini çökertir ve rastgele unsigned TEE/GZ/LK/Kernel yüklemelerine olanak sağlar.

> Uyarı: Erken önyükleme yaması, offset'ler yanlışsa cihazları kalıcı olarak tuğlalaştırabilir. Her zaman tam dump'lar ve güvenilir bir kurtarma yolu bulundurun.

## Etkilenen önyükleme akışı (MediaTek)

- Normal yol: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Zafiyetli yol: seccfg "unlocked" olarak ayarlandığında, Preloader bl2_ext doğrulamasını atlayabilir. Preloader yine de EL3'te bl2_ext'e atlar, dolayısıyla hazırlanmış bir bl2_ext daha sonra doğrulanmamış bileşenleri yükleyebilir.

Ana güven sınırı:
- bl2_ext EL3'te çalışır ve TEE, GenieZone, LK/AEE ve kernel'i doğrulamaktan sorumludur. bl2_ext kendisi kimlik doğrulaması yapılmamışsa, zincirin geri kalanı kolayca atlanır.

## Temel neden

Etkilenen cihazlarda, seccfg "unlocked" durumunu gösterdiğinde Preloader bl2_ext bölümünün kimlik doğrulamasını zorunlu kılmaz. Bu, EL3'te çalışan saldırgan tarafından kontrol edilen bir bl2_ext'in flashlenmesine izin verir.

bl2_ext içinde, doğrulama politika fonksiyonu, doğrulamanın gerekli olmadığını koşulsuz olarak bildirecek şekilde yamanabilir. Minimal bir kavramsal yama şöyle olabilir:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Bu değişiklikle, EL3'te çalışan yamalı bl2_ext tarafından yüklendiğinde, sonraki tüm imajlar (TEE, GZ, LK/AEE, Kernel) kriptografik kontroller olmadan kabul edilir.

## Hedef nasıl triage edilir (expdb logs)

bl2_ext yüklemesi çevresindeki önyükleme loglarını (örn. expdb) döküp/inceleyin. Eğer img_auth_required = 0 ve certificate verification time is ~0 ms ise, enforcement muhtemelen kapalıdır ve cihaz istismar edilebilir.

Örnek log kesiti:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Not: Bazı cihazların, locked bootloader olmasına rağmen bl2_ext doğrulamasını atladığı bildirildi; bu, etkinin şiddetini artırır.

lk2 secondary bootloader ile gönderilen cihazlarda da aynı mantık boşluğu gözlemlendi; bu yüzden porting yapmadan önce bl2_ext ve lk2 partition'ları için expdb logs alın ve hangi yolun signatures uygulayıp uygulamadığını doğrulayın.

Eğer post-OTA Preloader artık seccfg unlocked olsa bile bl2_ext için img_auth_required = 1 kaydediyorsa, vendor muhtemelen boşluğu kapatmıştır — aşağıdaki OTA persistence notlarına bakın.

## Pratik exploitation workflow (Fenrir PoC)

Fenrir, bu sınıf sorun için referans bir exploit/patching toolkit'tir. Nothing Phone (2a) (Pacman)'ı destekler ve CMF Phone 1 (Tetris) üzerinde (tam desteklenmemekle birlikte) çalıştığı bilinmektedir. Diğer modellere porting yapmak, device-specific bl2_ext için reverse engineering gerektirir.

High-level process:
- Hedef codename için device bootloader image'ını edinin ve bunu `bin/<device>.bin` olarak yerleştirin
- bl2_ext verification policy'yi devre dışı bırakan patched image oluşturun
- Ortaya çıkan payload'u cihaza flash'layın (helper script'in fastboot varsaydığı kabul edilir)

Komutlar:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
fastboot mevcut değilse, platformunuz için uygun bir alternatif flashing yöntemi kullanmalısınız.

### OTA ile yamanmış firmware: bypass'ı canlı tutmak (NothingOS 4, 2025 sonları)

Nothing, Kasım 2025 NothingOS 4 stable OTA (build BP2A.250605.031.A3) içinde Preloader'ı, seccfg unlocked olsa bile bl2_ext verification'ı zorlamak için yamaladı. Fenrir `pacman-v2.0`, NOS 4 beta'daki vulnerable Preloader'ı stable LK payload ile karıştırarak tekrar çalışıyor:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Önemli:
- Sağlanan Preloader'ı **sadece** eşleşen device/slot'a yazın; yanlış bir preloader anında hard brick olur.
- Flash işleminden sonra expdb'yi kontrol edin; img_auth_required bl2_ext için tekrar 0'a düşmelidir, bu da zafiyetli Preloader'ın patched LK'den önce çalıştığını doğrular.
- Gelecekteki OTAs hem Preloader'ı hem de LK'yı yamalarsa, boşluğu yeniden açmak için zafiyetli bir Preloader'ın yerel bir kopyasını saklayın.

### Build automation & payload debugging

- `build.sh` artık ilk çalıştırdığınızda Arm GNU Toolchain 14.2 (aarch64-none-elf) paketini otomatik indirip export ediyor, böylece çapraz derleyicilerle manuel olarak uğraşmak zorunda kalmazsınız.
- `build.sh`'i çağırmadan önce `DEBUG=1`'i export ederek payload'ları ayrıntılı seri çıktılarla derleyebilirsiniz; bu, EL3 kod yollarını kör yamalarken büyük ölçüde yardımcı olur.
- Başarılı derlemeler hem `lk.patched` hem de `<device>-fenrir.bin` dosyalarını bırakır; ikincisi payload'ın zaten enjekte edildiği dosyadır ve bunu flash/boot-test etmelisiniz.

## Runtime payload capabilities (EL3)

Patchlenmiş bl2_ext payload şu yeteneklere sahip olabilir:
- Özel fastboot komutları kaydetmek
- Boot modunu kontrol etmek/geçersiz kılmak
- Çalışma zamanında yerleşik bootloader fonksiyonlarını dinamik olarak çağırmak
- Güçlü bütünlük kontrollerini geçmek için "lock state"i kilitli olarak taklit etmek; aslında kilitsizken çalışmak (bazı ortamlar yine de vbmeta/AVB ayarlamaları gerektirebilir)

Sınırlama: Mevcut PoC'lar çalışma zamanı bellek değişikliklerinin MMU kısıtlamaları nedeniyle hata verebileceğini not ediyor; bu çözülene kadar payload'lar genellikle canlı bellek yazmalarından kaçınır.

## Payload staging patterns (EL3)

Fenrir enstrümantasyonunu üç derleme-zamanı aşamasına ayırır: stage1 `platform_init()`'den önce, stage2 LK fastboot girişini sinyallemeden önce, ve stage3 LK Linux'u yüklemeden hemen önce çalışır. `payload/devices/` altındaki her device header bu hook'lar için adresleri ve fastboot yardımcı sembollerini sağlar; bu offset'leri hedef derlemenizle senkronize tutun.

Stage2, rastgele `fastboot oem` verb'lerini kaydetmek için uygun bir yerdir:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3, downstream kernel erişimi gerektirmeden, Android’in “Orange State” uyarısı gibi değiştirilemeyen dizeleri yamalamak için sayfa tablosu özniteliklerini geçici olarak nasıl tersine çevireceğini gösterir:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Çünkü stage1 platform bring-up'tan önce tetiklendiği için, OEM power/reset primitives'lerini çağırmak veya verified boot zinciri yıkılmadan önce ek bütünlük kaydı eklemek için doğru yerdir.

## Porting tips

- Cihaza özel bl2_ext'i tersine mühendislik yaparak doğrulama politika mantığını bulun (ör. sec_get_vfy_policy).
- Politikanın dönüş noktasını veya karar dalını tespit edin ve bunu “no verification required” (return 0 / unconditional allow) olacak şekilde yama yapın.
- Offset'ları tamamen cihaz- ve firmware-özgü tutun; adresleri varyantlar arasında yeniden kullanmayın.
- Önce feda edilebilir bir birimde doğrulayın. Flashlamadan önce bir kurtarma planı hazırlayın (ör. EDL/BootROM loader/SoC-specific download mode).
- lk2 secondary bootloader kullanan veya bl2_ext için kilitli olsalar bile “img_auth_required = 0” raporlayan cihazlar, bu hata sınıfının savunmasız kopyaları olarak değerlendirilmelidir; Vivo X80 Pro'nun rapor edilen kilit durumuna rağmen doğrulamayı atladığı zaten gözlemlenmiştir.
- Bir OTA, kilit açık durumda bl2_ext imzalarını (img_auth_required = 1) zorlamaya başladığında, daha eski bir Preloader'ın (çoğunlukla beta OTA'larda bulunan) flaşlanıp boşluğu yeniden açıp açamayacağını kontrol edin; ardından daha yeni LK için güncellenmiş offset'lerle fenrir'i yeniden çalıştırın.

## Security impact

- Preloader sonrası EL3 kod yürütme ve geri kalan önyükleme yolu için tam trust zinciri çöküşü.
- İmzalanmamış TEE/GZ/LK/Kernel'i boot etme yeteneği; secure/verified boot beklentilerini atlayarak kalıcı ele geçirme sağlar.

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) re-enabled bl2_ext verification; fenrir `pacman-v2.0` restores the bypass by flashing the beta Preloader plus patched LK as shown above
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## Referanslar

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}
