# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok arşiv formatı (ZIP, RAR, TAR, 7-ZIP vb.), her girdinin kendi **internal path** bilgisini taşımasına izin verir. Bir extraction utility bu yolu sorgulamadan kullandığında, `..` veya **absolute path** (ör. `C:\Windows\System32\`) içeren hazırlanmış bir dosya adı, kullanıcı tarafından seçilen dizinin dışına yazılır.
Bu vulnerability sınıfı, yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.<sup>[[6]](#references)</sup>

Sonuçlar, rastgele dosyaların üzerine yazılmasından, Windows *Startup* folder gibi bir **auto-run** konumuna payload bırakarak doğrudan **remote code execution (RCE)** elde edilmesine kadar uzanır.

## Temel Neden

1. Attacker, bir veya daha fazla file header'ın şunları içerdiği bir archive oluşturur:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya target dir dışına çözümlenen hazırlanmış **symlinks** (*nix üzerinde ZIP/TAR'da yaygındır).
2. Victim, embedded path'e güvenen (veya symlink'leri takip eden), path'i sanitize etmek ya da extraction'ı seçilen dizinin altında zorlamak yerine vulnerable bir tool ile archive'ı extract eder.
3. File, attacker-controlled location'a yazılır ve sistem veya user bu path'i bir sonraki tetiklediğinde çalıştırılır/yüklenir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern, amaçlanan destination'ı **user-controlled** `ZipArchiveEntry.FullName` ile birleştirmek ve path normalization yapmadan extract etmektir:<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` `..\\` ile başlıyorsa traversal gerçekleşir; bir **absolute path** ise sol taraftaki bileşen tamamen atılır ve extraction identity olarak **arbitrary file write** elde edilir.
- Zamanlanmış bir scanner tarafından izlenen kardeş `app` dizinine yazmak için Proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Bu ZIP dosyasının izlenen gelen kutusuna bırakılması `C:\samples\app\0xdf.txt` dosyasının oluşturulmasına neden olur; bu da `C:\samples\queue\` dışına traversal yapılabildiğini ve sonraki aşama primitive'lerinin (ör. DLL hijack'leri) etkinleştirilebildiğini kanıtlar.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ile Windows RAR/UnRAR bileşenleri, extraction sırasında dosya adlarını doğrulayamıyordu. Bu açık, seçilen extraction path'ini atlamak ve dosyaları istenmeyen konumlara yazmak için NTFS alternate data streams (ADS) kullandı.<sup>[[5]](#references)</sup>
Şu türde bir entry içeren kötü amaçlı bir RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
**dışında** ve kullanıcının *Startup* klasörünün içinde kalırdı. ESET, kötü amaçlı LNK dosyalarının buraya açıldığını ve kullanıcı oturum açtığında çalıştırıldığını gözlemledi; bu durum persistence ve RCE için bir yol sağladı.<sup>[[5]](#references)</sup>

### PoC Archive Oluşturma (Linux/Mac)

CVE-2025-8088, bir ADS name içinde traversal path kullandığından RAR'ı oluşturmak için amaca özel bir generator kullanın; ardından extraction işlemini yalnızca vulnerable WinRAR build'inin bulunduğu izole bir lab ortamında test edin.<sup>[[5]](#references)</sup>

### Gerçek Ortamda Gözlemlenen Exploitation

ESET, RomCom'un (Storm-0978/UNC2596) CVE-2025-8088'i abuse eden RAR arşivlerini eklediği spear-phishing kampanyaları bildirdi. Bu arşivler özelleştirilmiş backdoor'lar dağıtmak ve ransomware operasyonlarını kolaylaştırmak için kullanıldı.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: **symbolic link** olan ZIP entries extraction sırasında dereference ediliyordu. Bu, attacker'ların destination directory dışına çıkmasına ve arbitrary path'lerin üzerine yazmasına olanak sağladı. User interaction yalnızca arşivi *açmak/extract etmek* için gereklidir.<sup>[[1]](#references)</sup>
* **Affected**: **25.00** öncesindeki 7-Zip build'leri. Symbolic-link işleme flaw'ı **25.00** (Temmuz 2025) ve sonraki sürümlerde düzeltildi.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` veya service-run konumlarının üzerine yazma → code bir sonraki logon'da veya service restart sonrasında çalışır.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Bu archive, extraction directory dışını gösteren bir symlink entry içerir; disposable bir target kullanın ve extractor'ın bunu takip etmediğini doğrulayın. Write-through testi ayrıca symlink'in altında bir regular-file entry gerektirir.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` `../` ve symlink'li ZIP entries'lerini takip ederek `outputDir` dışına yazıyor.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project artık deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0 sürümüne geçin veya write işleminden önce canonical-path checks uygulayın.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Archive entries'lerini listeleyin ve `../`, `..\\`, *absolute paths* (`/`, `C:`) içeren adları veya target'ı extraction dir dışında olan *symlink* türündeki entries'leri işaretleyin.
* **Canonicalisation** – `realpath(join(dest, name))` değerinin `realpath(dest)` içinde kaldığından emin olun (yalnızca raw string prefix'i değil, path components'ı karşılaştırın). Aksi durumda reddedin.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Disposable bir directory'ye, path/symlink checks uygulayan bir extractor kullanarak decompress edin (örneğin bsdtar'ın default secure checks'i veya 7-Zip ≥ 25.00); ardından resulting paths'lerin directory içinde kaldığını doğrulayın.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip vb. ile bir archive açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yazılan yeni executable'lar için alert oluşturun.

## Mitigation & Hardening

1. **Extractor'ı update edin** – WinRAR 7.13+ ve 7-Zip 25.00+ d path/symlink sorunlarına yönelik fix'ler içerir.<sup>[[1]](#references)[[5]](#references)</sup>
2. Mümkün olduğunda arşivleri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle extract edin.
3. Unix'te extraction öncesinde privileges'ı düşürün ve bir **chroot/namespace** mount edin; Windows'ta **AppContainer** veya sandbox kullanın.
4. Custom code yazıyorsanız create/write işleminden **önce** `realpath()`/`PathCanonicalize()` ile normalise edin ve destination'dan çıkan tüm entries'leri reddedin.

## Additional Affected / Historical Cases

* 2018 – Snyk tarafından yayımlanan ve birçok Java/Go/JS library'sini etkileyen kapsamlı *Zip-Slip* advisory'si.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) içindeki slug'larda TAR extraction traversal (v0.16.3 sürümünde düzeltildi).<sup>[[7]](#references)</sup>
* Write işleminden önce `PathCanonicalize` / `realpath` çağırmayan tüm custom extraction logic'leri.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET'te Zip Slip'i Önleme](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR araçlarını şimdi update edin: RomCom ve diğerleri zero-day vulnerability'yi exploit ediyor (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability'nin Public Disclosure'ı: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug, Zip Slip Attack'e Vulnerable (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip'te CVE-2025-11001 için Proof-of-Concept Exploit Bildirildi](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
