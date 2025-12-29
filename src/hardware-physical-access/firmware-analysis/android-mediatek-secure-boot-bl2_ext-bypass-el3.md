# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, cihaz bootloader yapılandırması (seccfg) "unlocked" olduğunda ortaya çıkan bir doğrulama boşluğunu kötüye kullanarak birden fazla MediaTek platformunda gerçekleştirilebilen pratik bir secure-boot kırılmasını belgeler. Bu kusur, ARM EL3'te yamalanmış bir bl2_ext çalıştırılmasına izin vererek sonraki imza doğrulamasını devre dışı bırakır, güven zincirini çökerterek rastgele unsigned TEE/GZ/LK/Kernel yüklemelerine olanak tanır.

> Uyarı: Early-boot patching, offsets yanlışsa cihazları kalıcı olarak kullanılmaz hale getirebilir. Her zaman full dumps ve güvenilir bir recovery path saklayın.

## Etkilenen boot akışı (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Zafiyetli yol: seccfg "unlocked" olarak ayarlandığında, Preloader bl2_ext doğrulamasını atlayabilir. Preloader yine de EL3'te bl2_ext'e atlar; bu yüzden hazırlanmış bir bl2_ext, sonrasında doğrulanmamış bileşenleri yükleyebilir.

Ana güven sınırı:
- bl2_ext EL3'te çalışır ve TEE, GenieZone, LK/AEE ve kernel'i doğrulamaktan sorumludur. bl2_ext'in kendisi kimlik doğrulaması yapılmamışsa, zincirin geri kalanı kolayca atlanır.

## Temel sebep

Etkilenen cihazlarda, seccfg "unlocked" durumunu gösterdiğinde Preloader bl2_ext bölümünün kimlik doğrulamasını zorlamaz. Bu, EL3'te çalışan saldırgan kontrollü bir bl2_ext'in flashlanmasına izin verir.

bl2_ext içinde, doğrulama politikası fonksiyonu, doğrulamanın gerekli olmadığını koşulsuz olarak bildirecek şekilde yamalanabilir. Minimal kavramsal bir yama şöyledir:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Bu değişiklikle, patched bl2_ext'in EL3'te çalışırken yüklediği tüm sonraki görüntüler (TEE, GZ, LK/AEE, Kernel) kriptografik kontroller olmadan kabul edilir.

## Bir hedef nasıl triage edilir (expdb logları)

Boot loglarını (ör. expdb) bl2_ext yüklemesinin etrafında dump/inspect edin. Eğer img_auth_required = 0 ve certificate verification time ~0 ms ise, enforcement muhtemelen kapalıdır ve cihaz exploitable'dır.

Örnek log kesiti:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Not: Bazı cihazların kilitli bootloader olsa bile bl2_ext verification'ı atladığı bildirildi; bu, etkinin şiddetini artırır.

Cihazların lk2 secondary bootloader ile gönderilenlerinde aynı mantık boşluğu gözlemlendi; bu yüzden port etmeye çalışmadan önce bl2_ext ve lk2 bölümleri için expdb logs alın, hangi yolun imzaları zorunlu kıldığını doğrulamak için.

## Pratik istismar iş akışı (Fenrir PoC)

Fenrir, bu sınıftaki sorunlar için referans bir exploit/patching toolkit'tir. Nothing Phone (2a) (Pacman)'ı destekler ve CMF Phone 1 (Tetris) üzerinde (tam desteklenmemekle birlikte) çalıştığı bilinmektedir. Diğer modellere port etmek, cihaz-özgü bl2_ext'in reverse engineering'ini gerektirir.

High-level process:
- Obtain the device bootloader image for your target codename and place it as `bin/<device>.bin`
- Build a patched image that disables the bl2_ext verification policy
- Flash the resulting payload to the device (fastboot assumed by the helper script)

Komutlar:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

### Build automation & payload debugging

- `build.sh` ilk çalıştırmanızda Arm GNU Toolchain 14.2 (aarch64-none-elf)'ü otomatik indirir ve export eder, böylece çapraz derleyicileri elle yönetmek zorunda kalmazsınız.
- `build.sh`'i çağırmadan önce `DEBUG=1` export edin; bu, payload'ları ayrıntılı seri çıktılarla derler ve EL3 kod yollarını görmeden yama yaparken büyük ölçüde yardımcı olur.
- Başarılı derlemeler hem `lk.patched` hem de `<device>-fenrir.bin` dosyalarını üretir; ikincisi payload'ın zaten enjekte edildiği dosyadır ve flash/boot-test için kullanmanız gereken dosyadır.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Register custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Payload staging patterns (EL3)

Fenrir splits its instrumentation into three compile-time stages: stage1 runs before `platform_init()`, stage2 runs before LK signals fastboot entry, and stage3 executes immediately before LK loads Linux. Each device header under `payload/devices/` provides the addresses for these hooks plus fastboot helper symbols, so keep those offsets synchronized with your target build.

Stage2 is a convenient location to register arbitrary `fastboot oem` verbs:
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
Stage3, page-table attributes'ı geçici olarak flipleyip Android’s “Orange State” warning gibi immutable strings'i patch etmeyi, downstream kernel access gerekmeksizin nasıl yapıldığını gösterir:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Çünkü stage1 platformun başlatılmasından önce tetiklendiğinden, doğrulanmış boot zinciri parçalanmadan önce OEM power/reset primitives'lerini çağırmak veya ek bütünlük loglaması eklemek için doğru yerdir.

## Porting tips

- Cihaza özel bl2_ext'i tersine mühendislik yaparak doğrulama politika mantığını bulun (örn. sec_get_vfy_policy).
- Politika dönüş noktasını veya karar dalını belirleyin ve bunu “no verification required” olarak patch'leyin (return 0 / unconditional allow).
- Offset'ları tamamen cihaza ve firmware'e özgü tutun; varyantlar arasında adresleri yeniden kullanmayın.
- Önce feda edilebilecek bir ünitede doğrulayın. Flashlamadan önce bir kurtarma planı hazırlayın (örn. EDL/BootROM loader/SoC-specific download mode).
- lk2 ikincil bootloader'ı kullanan veya bl2_ext için kilitli olsa bile “img_auth_required = 0” bildiren cihazlar bu hata sınıfının savunmasız kopyaları olarak değerlendirilmelidir; Vivo X80 Pro'nun bildirilen kilit durumuna rağmen doğrulamayı atladığı zaten gözlemlenmiştir.
- Kilitli ve kilitsiz durumların expdb log'larını karşılaştırın—sertifika zamanlaması tekrar kilitlediğinizde 0 ms'den sıfır olmayan bir değere atlıyorsa, muhtemelen doğru karar noktasını patch'lediniz fakat değişikliği gizlemek için kilit-durum taklitçiliğini sertleştirmeniz gerekir.

## Security impact

- Preloader sonrası EL3 kodu yürütülmesi ve boot yolunun geri kalanı için güven zincirinin (chain-of-trust) tamamen çökmesi.
- İmzalanmamış TEE/GZ/LK/Kernel boot edebilme yeteneği; secure/verified boot beklentilerini aşar ve kalıcı ele geçirme sağlar.

## Device notes

- Confirmed supported: Nothing Phone (2a) (Pacman)
- Known working (incomplete support): CMF Phone 1 (Tetris)
- Observed: Vivo X80 Pro reportedly did not verify bl2_ext even when locked
- Industry coverage highlights additional lk2-based vendors shipping the same logic flaw, so expect further overlap across 2024–2025 MTK releases.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}
