# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok archive formatı (ZIP, RAR, TAR, 7-ZIP vb.), her girdinin kendi **internal path** bilgisini taşımasına izin verir. Bir extraction utility bu path bilgisini kontrol etmeden kullandığında, `..` veya **absolute path** (ör. `C:\Windows\System32\`) içeren hazırlanmış bir filename, kullanıcı tarafından seçilen directory'nin dışına yazılır.
Bu vulnerability sınıfı yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.<sup>[[6]](#references)</sup>

Sonuçlar arbitrary file'ların üzerine yazılmasından, Windows *Startup* folder gibi bir **auto-run** konumuna payload bırakarak doğrudan **remote code execution (RCE)** elde etmeye kadar uzanır.

## Root Cause

1. Attacker, bir veya daha fazla file header'ının şunları içerdiği bir archive oluşturur:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya target dir dışına çözümlenen hazırlanmış **symlinks** (*nix* üzerinde ZIP/TAR'da yaygındır).
2. Victim, embedded path'e güvenen (veya symlinks'i takip eden), bunu sanitise etmek ya da extraction işlemini seçilen directory altında zorlamak yerine vulnerable bir tool ile archive'ı extract eder.
3. File, attacker-controlled location'a yazılır ve system veya user bu path'i bir sonraki tetiklediğinde execute/load edilir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern, hedeflenen destination'ı **user-controlled** `ZipArchiveEntry.FullName` ile birleştirmek ve path normalisation yapmadan extract etmektir:<sup>[[4]](#references)[[8]](#references)</sup>
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
Bu ZIP dosyasının izlenen gelen kutusuna bırakılması `C:\samples\app\0xdf.txt` sonucunu doğurur; bu da `C:\samples\queue\` dışına traversal yapılabildiğini ve takip eden primitive'lerin (ör. DLL hijack'leri) etkinleştirilebildiğini kanıtlar.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ve Windows RAR/UnRAR bileşenleri, extraction sırasında dosya adlarını doğrulayamıyordu. Bu açık, seçilen extraction path'ini atlatmak ve dosyaları amaçlanmayan konumlara yazmak için NTFS alternate data streams (ADS) kullanıyordu.<sup>[[5]](#references)</sup>
Şu türde bir entry içeren kötü amaçlı bir RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
**dışına** çıkar ve kullanıcının *Startup* klasörünün içine yerleşirdi. ESET, kötü amaçlı LNK dosyalarının buraya çıkarıldığını ve kullanıcı oturum açtığında çalıştırıldığını gözlemledi; bu durum kalıcılık ve RCE için bir yol sağladı.<sup>[[5]](#references)</sup>

### PoC Archive Oluşturma (Linux/Mac)

CVE-2025-8088 bir ADS adında traversal path kullandığından, RAR dosyasını oluşturmak için amaca yönelik bir generator kullanın; ardından extraction işlemini yalnızca güvenlik açığı bulunan bir WinRAR build'iyle izole bir lab ortamında test edin.<sup>[[5]](#references)</sup>

### Gerçek Dünyada Gözlemlenen Exploitation

ESET, RomCom'un (Storm-0978/UNC2596) CVE-2025-8088'i kötüye kullanan RAR arşivlerini eklediği; özelleştirilmiş backdoor'lar dağıtmak ve ransomware operasyonlarını kolaylaştırmak için spear-phishing kampanyaları yürüttüğünü bildirdi.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Hata**: **symbolic link** olan ZIP girdilerinin extraction sırasında dereference edilmesi, saldırganların hedef dizinin dışına çıkmasına ve rastgele yolların üzerine yazmasına olanak sağladı. Kullanıcı etkileşimi yalnızca arşivi *açmak/çıkarmak*tır.<sup>[[1]](#references)</sup>
* **Etkilenen**: **25.00** öncesindeki 7-Zip build'leri. Symbolic-link işleme flaw'ı **25.00** (Temmuz 2025) ve sonraki sürümlerde düzeltildi.<sup>[[1]](#references)[[10]](#references)</sup>
* **Etki yolu**: `Start Menu/Programs/Startup` veya service-run konumlarının üzerine yazma → kod bir sonraki oturum açmada veya service restart sonrasında çalışır.
* **Hızlı symlink-handling fixture'ı (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Bu arşiv, extraction directory dışını gösteren bir symlink girdisi içerir; disposable bir target kullanın ve extractor'ın bunu takip etmediğini doğrulayın. Write-through testi ayrıca symlink'in altında normal bir file girdisi gerektirir.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Hata**: `archiver.Unarchive()` `../` ve symlink'li ZIP girdilerini takip ederek `outputDir` dışına yazıyor.<sup>[[2]](#references)</sup>
* **Etkilenen**: `github.com/mholt/archiver` ≤ 3.5.1 (project artık deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0 sürümüne geçin veya write öncesinde canonical-path kontrolleri uygulayın.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection İpuçları

* **Static inspection** – Archive girdilerini listeleyin ve `../`, `..\\`, *absolute paths* (`/`, `C:`) içeren adları veya hedefi extraction dir dışında olan *symlink* türündeki girdileri işaretleyin.
* **Canonicalisation** – `realpath(join(dest, name))` değerinin `realpath(dest)` içinde kaldığından emin olun (yalnızca ham string prefix'ini değil, path bileşenlerini karşılaştırın). Aksi durumda reddedin.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Bir extractor kullanarak disposable bir directory'ye decompress edin; path/symlink kontrollerinin etkin olduğundan emin olun (örneğin bsdtar'ın varsayılan güvenli kontrolleri veya 7-Zip ≥ 25.00), ardından oluşan path'lerin directory içinde kaldığını doğrulayın.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip vb. ile bir archive açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yazılan yeni executable'lar için alert oluşturun.

## Mitigation & Hardening

1. **Extractor'ı güncelleyin** – WinRAR 7.13+ ve 7-Zip 25.00+, belirtilen path/symlink sorunları için fix'ler içerir.<sup>[[1]](#references)[[5]](#references)</sup>
2. Mümkün olduğunda arşivleri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle extract edin.
3. Unix'te extraction öncesinde privilege'ları drop edin ve bir **chroot/namespace** mount edin; Windows'ta **AppContainer** veya bir sandbox kullanın.
4. Custom code yazıyorsanız, **create/write** öncesinde `realpath()`/`PathCanonicalize()` ile normalise edin ve destination dışına çıkan tüm girdileri reddedin.

## Etkilenen Diğer / Geçmiş Vakalar

* 2018 – Snyk tarafından yayınlanan ve birçok Java/Go/JS library'sini etkileyen kapsamlı *Zip-Slip* advisory'si.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) içindeki slug'larda TAR extraction traversal (v0.16.3 sürümünde düzeltildi).<sup>[[7]](#references)</sup>
* Write öncesinde `PathCanonicalize` / `realpath` çağırmayan tüm custom extraction logic'leri.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET'te Zip Slip'i Önleme](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR araçlarını şimdi güncelleyin: RomCom ve diğerleri zero-day açığını kötüye kullanıyor (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Kritik Arbitrary File Overwrite Açığının Public Disclosure'ı: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug Zip Slip Saldırısına Karşı Vulnerable (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip'te CVE-2025-11001 için Proof-of-Concept Exploit Raporlandı](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
