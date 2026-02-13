# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Bu sayfa, cihaz bootloader yapılandırması (seccfg) "unlocked" olduğunda doğrulama boşluğundan yararlanarak birden fazla MediaTek platformunda gerçekleştirilen pratik bir secure-boot kırılmasını belgeler. Hata, ARM EL3'te yama uygulanmış bir bl2_ext'in çalıştırılmasına izin vererek aşağı akıştaki imza doğrulamasını devre dışı bırakır, güven zincirini çökertir ve rastgele imzasız TEE/GZ/LK/Kernel yüklemeye imkan tanır.

> Uyarı: Early-boot patching offset'ler yanlışsa cihazları kalıcı olarak brickleyebilir. Her zaman full dumps ve güvenilir bir recovery path saklayın.

## Etkilenen boot akışı (MediaTek)

- Normal path: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Vulnerable path: seccfg "unlocked" olarak ayarlandığında, Preloader bl2_ext'in doğrulamasını atlayabilir. Preloader yine de EL3'te bl2_ext'e atlar; bu yüzden hazırlanmış bir bl2_ext sonrasında doğrulanmamış bileşenleri yükleyebilir.

Ana güven sınırı:
- bl2_ext EL3'te çalışır ve TEE, GenieZone, LK/AEE ve kernel'i doğrulamaktan sorumludur. Eğer bl2_ext'in kendisi authenticate edilmemişse, zincirin geri kalan kısmı kolayca bypass edilir.

## Temel neden

Etkilenen cihazlarda, seccfg "unlocked" durumunu gösterdiğinde Preloader bl2_ext bölümünün authentication'ını zorunlu kılmaz. Bu, saldırgan kontrollü bir bl2_ext'in flashlenmesine ve EL3'te çalıştırılmasına izin verir.

bl2_ext içinde, doğrulama politikası fonksiyonu koşulsuz olarak doğrulamanın gerekli olmadığını (veya her zaman başarılı olduğunu) raporlayacak şekilde patch'lenebilir; bu da boot zincirinin imzasız TEE/GZ/LK/Kernel görüntülerini kabul etmesine zorlar. Bu patch EL3'te çalıştığı için, aşağı akış bileşenleri kendi kontrollerini uygulasalar bile etkili olur.

## Pratik exploit zinciri

1. Bootloader partition'larını (Preloader, bl2_ext, LK/AEE, vb.) OTA/firmware paketleri, EDL/DA readback veya donanım dump'ları ile edinin.
2. bl2_ext doğrulama rutinini tespit edin ve doğrulamayı her zaman atlayacak/kabul edecek şekilde patch'leyin.
3. Değiştirilmiş bl2_ext'i fastboot, DA veya unlocked cihazlarda hâlâ izin verilen benzer bakım kanalları aracılığıyla flash'layın.
4. Yeniden başlatın; Preloader EL3'te patch'lenmiş bl2_ext'e atlar ve ardından imzasız downstream görüntüleri (patch'lenmiş TEE/GZ/LK/Kernel) yükleyip imza zorlamasını devre dışı bırakır.

Cihaz seccfg locked olarak yapılandırılmışsa (seccfg locked), Preloader'ın bl2_ext'i doğrulaması beklenir. Bu yapılandırmada, başka bir vulnerability unsigned bl2_ext yüklemeye izin vermedikçe bu attack başarısız olur.

## Triage (expdb boot logs)

- bl2_ext yüklemesi çevresindeki boot/expdb log'larını dump edin. Eğer `img_auth_required = 0` ve sertifika doğrulama süresi ~0 ms ise, doğrulamanın atlanmış olması muhtemeldir.

Örnek log alıntısı:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Bazı cihazlar kilitli olsa bile bl2_ext doğrulamasını atlıyor; lk2 ikincil bootloader yolları aynı açığı gösterdi. Eğer post-OTA Preloader, cihaz kilitsizken bl2_ext için `img_auth_required = 1` kaydı tutuyorsa, doğrulama zorlaması muhtemelen geri getirilmiştir.

## Doğrulama mantığının bulunduğu yerler

- İlgili kontrol genellikle bl2_ext imajı içinde, `verify_img` veya `sec_img_auth` gibi adlandırılmış fonksiyonlarda bulunur.
- Yamanmış sürüm, fonksiyonun başarı döndürmesini zorlar veya doğrulama çağrısını tamamen atlar.

Örnek yama yaklaşımı (kavramsal):
- TEE, GZ, LK ve kernel imajlarında `sec_img_auth` çağıran fonksiyonu bulun.
- Gövdesini hemen başarı döndüren bir stub ile değiştirin veya doğrulama hatasını işleyen koşullu dalı üzerine yazın.

Yamanın stack/frame kurulumunu koruduğundan ve çağıranlara beklenen durum kodlarını döndürdüğünden emin olun.

## Fenrir PoC iş akışı (Nothing/CMF)

Fenrir, bu sorun için referans bir yama araç takımıdır (Nothing Phone (2a) tam desteklenir; CMF Phone 1 kısmen). Yüksek düzey:
- Cihaz bootloader imajını `bin/<device>.bin` olarak yerleştirin.
- bl2_ext doğrulama politikasını devre dışı bırakan yamanmış bir imaj oluşturun.
- Oluşan payload'u flash'layın (fastboot helper sağlanmıştır).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Use another flashing channel if fastboot is unavailable.

## EL3 yama notları

- bl2_ext ARM EL3'te çalışır. Buradaki çöküşler cihazı EDL/DA veya test noktaları ile yeniden flash'lanana kadar tuğlalaştırabilir.
- Çalışma yolunu doğrulamak ve çöküşleri teşhis etmek için board'a özel logging/UART kullanın.
- Değiştirilen tüm partition'ların yedeklerini tutun ve önce harcanabilir bir donanımda test edin.

## Etkileri

- Preloader'dan sonra EL3 kodu yürütme ve geriye kalan önyükleme yolunun tam zincir-güveninin çökmesi.
- İmzalanmamış TEE/GZ/LK/Kernel'i boot etme yeteneği; secure/verified boot beklentilerini atlayarak kalıcı bir ele geçirilme sağlar.

## Cihaz notları

- Onaylı destek: Nothing Phone (2a) (Pacman)
- Çalıştığı biliniyor (tam destek değil): CMF Phone 1 (Tetris)
- Gözlemlendi: Vivo X80 Pro'nun bl2_ext'i kilitli olsa bile doğrulamadığı bildirildi
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) bl2_ext doğrulamayı yeniden etkinleştirdi; fenrir `pacman-v2.0` beta Preloader ile yamalanmış bir LK'yi karıştırarak bypass'ı geri getiriyor
- Sektör haberleri aynı mantık hatasını içeren ek lk2-tabanlı tedarikçilerin ürünler gönderdiğini vurguluyor; bu nedenle 2024–2025 MTK sürümleri arasında daha fazla örtüşme bekleyin.

## MTK DA readback and seccfg manipulation with Penumbra

Penumbra, Rust crate/CLI/TUI olup MTK preloader/bootrom ile USB üzerinden DA-modu işlemlerini otomatikleştirir. Fiziksel erişime sahip ve savunmasız bir cihaza (DA uzantıları izinliyse) MTK USB portunu keşfedebilir, bir Download Agent (DA) blob'u yükleyebilir ve seccfg kilidi çevirme ile partition okuma gibi ayrıcalıklı komutlar gönderebilir.

- **Environment/driver setup**: On Linux install `libudev`, add the user to the `dialout` group, and create udev rules or run with `sudo` if the device node is not accessible. Windows support is unreliable; it sometimes works only after replacing the MTK driver with WinUSB using Zadig (per project guidance).
- **Workflow**: Read a DA payload (e.g., `std::fs::read("../DA_penangf.bin")`), poll for the MTK port with `find_mtk_port()`, and build a session using `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. After `init()` completes the handshake and gathers device info, check protections via `dev_info.target_config()` bitfields (bit 0 set → SBC enabled). Enter DA mode and attempt `set_seccfg_lock_state(LockFlag::Unlock)`—this only succeeds if the device accepts extensions. Partitions can be dumped with `read_partition("lk_a", &mut progress_cb, &mut writer)` for offline analysis or patching.
- **Security impact**: Successful seccfg unlocking reopens flashing paths for unsigned boot images, enabling persistent compromises such as the bl2_ext EL3 patching described above. Partition readback provides firmware artifacts for reverse engineering and crafting modified images.

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

## Kaynaklar

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}
