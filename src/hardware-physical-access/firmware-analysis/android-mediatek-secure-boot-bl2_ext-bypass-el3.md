# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, cihaz bootloader yapılandırması (seccfg) "unlocked" durumundayken bir verification gap'i kötüye kullanarak birden fazla MediaTek platformunda gerçekleştirilebilen pratik bir secure-boot kırma yöntemini belgeler. Bu flaw, ARM EL3 seviyesinde patched bir bl2_ext çalıştırarak sonraki signature verification işlemlerini devre dışı bırakmaya, trust chain'i çökertmeye ve imzasız TEE/GZ/LK/Kernel yüklemesini mümkün kılmaya izin verir.<sup>[[1]](#references)</sup>

> Dikkat: Early-boot patching, offset'ler yanlışsa cihazları kalıcı olarak brick edebilir. Her zaman full dump'ları ve güvenilir bir recovery yolunu hazır bulundurun.

## Affected boot flow (MediaTek)

- Normal yol: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable yol: seccfg unlocked olarak ayarlandığında Preloader, bl2_ext'i verify etmeyi atlayabilir. Preloader yine de bl2_ext'e EL3 seviyesinde geçiş yapar; bu nedenle crafted bir bl2_ext, bundan sonraki unverified bileşenleri yükleyebilir.

Temel trust boundary:
- bl2_ext, EL3 seviyesinde çalışır ve TEE, GenieZone, LK/AEE ile kernel'i verify etmekten sorumludur. bl2_ext'in kendisi authenticated değilse chain'in geri kalanı trivially bypass edilebilir.<sup>[[1]](#references)</sup>

## Root cause

Etkilenen cihazlarda Preloader, seccfg bir "unlocked" durumu belirttiğinde bl2_ext partition'ının authentication işlemini zorunlu kılmaz. Bu, attacker-controlled bir bl2_ext'in flash edilmesine ve EL3 seviyesinde çalıştırılmasına izin verir.

bl2_ext içinde verification policy function, verification'ın gerekli olmadığını koşulsuz olarak bildirecek (veya her zaman başarılı olacak) şekilde patched edilebilir; böylece boot chain, imzasız TEE/GZ/LK/Kernel image'larını kabul etmeye zorlanır. Bu patch EL3 seviyesinde çalıştığından, downstream bileşenler kendi kontrollerini uygulasa bile etkilidir.<sup>[[1]](#references)</sup>

## Practical exploit chain

1. Bootloader partition'larını (Preloader, bl2_ext, LK/AEE vb.) OTA/firmware package'ları, EDL/DA readback veya hardware dumping yoluyla elde edin.
2. bl2_ext verification routine'ini belirleyin ve verification'ı her zaman skip/accept edecek şekilde patch'leyin.
3. Modified bl2_ext'i, unlocked cihazlarda hâlâ izin verilen fastboot, DA veya benzer maintenance channel'larını kullanarak flash edin.
4. Reboot edin; Preloader, patched bl2_ext'e EL3 seviyesinde geçiş yapar. bl2_ext daha sonra imzasız downstream image'ları (patched TEE/GZ/LK/Kernel) yükler ve signature enforcement'ı devre dışı bırakır.<sup>[[1]](#references)</sup>

Cihaz locked olarak yapılandırılmışsa (seccfg locked), Preloader'ın bl2_ext'i verify etmesi beklenir. Bu yapılandırmada, başka bir vulnerability imzasız bir bl2_ext yüklenmesine izin vermediği sürece bu attack başarısız olur.

## Triage (expdb boot logs)

- bl2_ext yüklemesi çevresindeki boot/expdb log'larını dump edin. `img_auth_required = 0` ise ve certificate verification süresi yaklaşık 0 ms ise verification büyük olasılıkla skip edilmiştir.<sup>[[1]](#references)</sup>

Örnek log alıntısı:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Bazı cihazlar kilitli olsalar bile bl2_ext doğrulamasını atlar; lk2 secondary bootloader yollarında da aynı açık görülmüştür. OTA sonrası Preloader, cihaz kilidi açıkken bl2_ext için `img_auth_required = 1` kaydederse enforcement muhtemelen geri yüklenmiştir.<sup>[[1]](#references)[[2]](#references)</sup>

## Doğrulama mantığının konumları

- İlgili kontrol genellikle bl2_ext image içinde, `verify_img` veya `sec_img_auth` benzeri adlara sahip functions içinde bulunur.
- Patched version, function'ın success döndürmesini zorlar veya verification call'u tamamen bypass eder.<sup>[[1]](#references)</sup>

Örnek patch yaklaşımı (kavramsal):
- TEE, GZ, LK ve kernel images üzerinde `sec_img_auth` çağıran function'ı bulun.
- Body'sini hemen success döndüren bir stub ile değiştirin veya verification failure'ı işleyen conditional branch'i overwrite edin.

Patch'in stack/frame setup'ı koruduğundan ve caller'ların beklediği status code'ları döndürdüğünden emin olun.<sup>[[1]](#references)</sup>

## Fenrir PoC iş akışı (Nothing/CMF)

Fenrir, bu sorun için bir reference patching toolkit'tir (Nothing Phone (2a) tamamen desteklenir; CMF Phone 1 kısmen desteklenir).<sup>[[1]](#references)</sup> Genel hatlarıyla:
- Cihazın bootloader image'ını `bin/<device>.bin` olarak yerleştirin.
- bl2_ext verification policy'yi devre dışı bırakan patched image oluşturun.
- Ortaya çıkan payload'ı flash edin (fastboot helper sağlanmıştır).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use fastboot kullanılamıyorsa başka bir flashing channel kullanın.

## EL3 patching notları

- bl2_ext ARM EL3'te çalışır. Buradaki crash'ler, cihaz EDL/DA veya test points üzerinden yeniden flash edilene kadar cihazı brick edebilir.
- Execution path'i doğrulamak ve crash'leri teşhis etmek için board'a özel logging/UART kullanın.
- Değiştirilen tüm partition'ların backup'larını alın ve önce disposable hardware üzerinde test edin.<sup>[[1]](#references)</sup>

## Çıkarımlar

- Preloader'dan sonra EL3 code execution ve boot path'in geri kalanı için tüm chain-of-trust'un çökmesi.
- Unsigned TEE/GZ/LK/Kernel boot etme, secure/verified boot beklentilerini bypass etme ve persistent compromise sağlama yeteneği.<sup>[[1]](#references)</sup>

## Cihaz notları

- Desteklendiği doğrulanan: Nothing Phone (2a) (Pacman)
- Çalıştığı bilinen (incomplete support): CMF Phone 1 (Tetris)
- Gözlemlenen: Vivo X80 Pro'nun locked durumdayken bile bl2_ext'i doğrulamadığı bildirildi<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025), bl2_ext verification'ı yeniden etkinleştirdi; fenrir `pacman-v2.0`, beta Preloader'ı patched LK ile mix ederek bypass'ı geri getiriyor<sup>[[3]](#references)</sup>
- Industry coverage, aynı logic flaw'ı içeren ve lk2 tabanlı ek vendor'ların da bu yapıyı kullandığını vurguluyor; bu nedenle 2024–2025 MTK release'leri arasında daha fazla örtüşme bekleyin.<sup>[[2]](#references)[[4]](#references)</sup>

## Penumbra ile MTK DA readback ve seccfg manipulation

Penumbra, USB üzerinden MTK preloader/bootrom ile DA-mode operations etkileşimini otomatikleştiren bir Rust crate/CLI/TUI'dir. Vulnerable bir handset'e physical access ile (DA extensions allowed), MTK USB port'unu keşfedebilir, bir Download Agent (DA) blob'u yükleyebilir ve seccfg lock flipping ile partition readback gibi privileged command'lar gönderebilir.<sup>[[5]](#references)</sup>

- **Environment/driver setup**: Linux'ta `libudev` kurun, user'ı `dialout` group'una ekleyin ve udev rules oluşturun veya device node'a erişilemiyorsa `sudo` ile çalıştırın. Windows support güvenilir değildir; project guidance'a göre bazen MTK driver'ı Zadig kullanarak WinUSB ile değiştirdikten sonra çalışır.
- **Workflow**: Bir DA payload okuyun (ör. `std::fs::read("../DA_penangf.bin")`), `find_mtk_port()` ile MTK port'u poll edin ve `DeviceBuilder::with_mtk_port(...).with_da_data(...)` kullanarak bir session oluşturun. `init()` handshake'i tamamlayıp device info'yu topladıktan sonra `dev_info.target_config()` bitfield'leri üzerinden protections'ı kontrol edin (bit 0 set → SBC enabled). DA mode'a girin ve `set_seccfg_lock_state(LockFlag::Unlock)` işlemini deneyin—bu yalnızca device extensions'ı kabul ederse başarılı olur. Partition'lar, offline analysis veya patching için `read_partition("lk_a", &mut progress_cb, &mut writer)` ile dump edilebilir.
- **Security impact**: Başarılı seccfg unlocking, unsigned boot image'lar için flashing path'lerini yeniden açar ve yukarıda açıklanan bl2_ext EL3 patching gibi persistent compromise'ları mümkün kılar. Partition readback, reverse engineering ve modified image'lar hazırlamak için firmware artifact'ları sağlar.

<details>
<summary>Rust DA session + seccfg unlock + partition dump (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## Referanslar

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Nothing Phone Code Execution Vulnerability için PoC Exploit yayınlandı](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Fenrir pacman-v2.0 sürümü (NothingOS 4 bypass paketi)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – Fenrir PoC, Nothing Phone 2a/CMF1 üzerindeki secure boot'u kırıyor](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – MTK DA flash/readback ve seccfg araçları](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
