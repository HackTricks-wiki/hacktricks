# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

## Genel Bakış

Birçok archive formatı (ZIP, RAR, TAR, 7-ZIP vb.), her entry'nin kendi **internal path** bilgisini taşımasına izin verir. Bir extraction utility bu path'i körü körüne dikkate aldığında, `..` veya **absolute path** (ör. `C:\Windows\System32\`) içeren hazırlanmış bir filename, kullanıcının seçtiği directory'nin dışına yazılır.
Bu vulnerability class'ı yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.<sup>[[6]](#references)</sup>

Sonuçlar, arbitrary file'ların üzerine yazılmasından, Windows *Startup* folder gibi bir **auto-run** konumuna payload bırakılarak doğrudan **remote code execution (RCE)** elde edilmesine kadar uzanır.

## Kök Neden

1. Saldırgan, bir veya daha fazla file header'ının şunları içerdiği bir archive oluşturur:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Ya da target dir'in dışına çözümlenen hazırlanmış **symlinks** (*nix* üzerinde ZIP/TAR'da yaygındır).
2. Mağdur, embedded path'e güvenen (veya symlink'leri takip eden), bunu sanitize etmek ya da extraction'ı seçilen directory'nin altına zorlamak yerine vulnerable bir tool ile archive'ı extract eder.
3. File, saldırganın kontrol ettiği konuma yazılır ve sistem veya user bu path'i bir sonraki kez tetiklediğinde execute/load edilir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern, hedeflenen destination'ı user-controlled `ZipArchiveEntry.FullName` ile birleştirmek ve path normalisation yapmadan extract etmektir:<sup>[[4]](#references)[[8]](#references)</sup>
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
Bu ZIP'i izlenen gelen kutusuna bırakmak, `C:\samples\app\0xdf.txt` yolunun oluşturulmasını sağlar; bu da `C:\samples\queue\` dışına traversal yapılabildiğini ve devam eden primitive'lerin (ör. DLL hijacks) kullanılabildiğini kanıtlar.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ve Windows RAR/UnRAR bileşenleri, extraction sırasında dosya adlarını doğrulayamıyordu. Bu açık, seçilen extraction path'ini atlamak ve dosyaları amaçlanmayan konumlara yazmak için NTFS alternate data streams (ADS) kullanıyordu.<sup>[[5]](#references)</sup>
Şuna benzer bir entry içeren malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET, kötü amaçlı LNK dosyalarının burada unpack edilip kullanıcı logon olduğunda çalıştırıldığını gözlemledi; bu durum persistence ve RCE için bir yol sağladı.<sup>[[5]](#references)</sup>

### PoC Archive Oluşturma (Linux/Mac)

CVE-2025-8088 bir ADS name içinde traversal path kullandığından, RAR oluşturmak için amaca özel bir generator kullanın; ardından extraction işlemini yalnızca vulnerable WinRAR build içeren izole bir lab ortamında test edin.<sup>[[5]](#references)</sup>

### Wild'da Gözlemlenen Exploitation

ESET, RomCom’un (Storm-0978/UNC2596) CVE-2025-8088’i abuse eden RAR arşivlerini eklediği spear-phishing campaign'lerini bildirdi; bu arşivler customised backdoor'lar deploy etmek ve ransomware operations gerçekleştirmek için kullanıldı.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Extraction sırasında **symbolic link** olan ZIP entries dereference ediliyordu; bu da attacker'ların destination directory dışına çıkmasına ve arbitrary paths üzerine yazmasına izin veriyordu. User interaction yalnızca arşivi *opening/extracting* işleminden ibarettir.<sup>[[1]](#references)</sup>
* **Affected**: **25.00** öncesindeki 7-Zip builds. Symbolic-link processing flaw, **25.00** (July 2025) ve sonraki sürümlerde fix edildi.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` veya service-run locations üzerine overwrite → code bir sonraki logon veya service restart sırasında çalışır.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Bu archive, extraction directory dışını gösteren bir symlink entry içerir; disposable bir target kullanın ve extractor'ın bu symlink'i takip etmediğini doğrulayın. Write-through testi için symlink altında regular-file entry de gerekir.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` `../` ve symlinked ZIP entries'i takip ederek `outputDir` dışına yazıyor.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project artık deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0 sürümüne geçin veya write işleminden önce canonical-path checks implement edin.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Archive entries'i listeleyin ve `../`, `..\\`, *absolute paths* (`/`, `C:`) içeren name'leri veya target'ı extraction dir dışında olan *symlink* türündeki entries'i flag'leyin.
* **Canonicalisation** – `realpath(join(dest, name))` değerinin `realpath(dest)` içinde kaldığından emin olun (yalnızca raw string prefix'i değil, path components'ı karşılaştırın). Aksi durumda reject edin.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Bir extractor'ın path/symlink checks özelliğini kullanarak disposable bir directory'ye decompress edin (örneğin bsdtar'ın default secure checks'i veya 7-Zip ≥ 25.00), ardından resulting paths'lerin directory içinde kaldığını doğrulayın.<sup>[[1]](#references)[[9]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip/etc. tarafından bir archive açıldıktan kısa süre sonra `Startup`/`Run`/`cron` locations'a yazılan yeni executables için alert oluşturun.

## Mitigation & Hardening

1. **Extractor'ı update edin** – WinRAR 7.13+ ve 7-Zip 25.00+, belirtilen path/symlink issues için fixes içerir.<sup>[[1]](#references)[[5]](#references)</sup>
2. Mümkün olduğunda archives'leri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle extract edin.
3. Unix'te extraction öncesinde privileges'ı drop edin ve bir **chroot/namespace** mount edin; Windows'ta **AppContainer** veya sandbox kullanın.
4. Custom code yazıyorsanız, **before** create/write işlemi için `realpath()`/`PathCanonicalize()` ile normalise edin ve destination'dan çıkan her entry'yi reject edin.

## Additional Affected / Historical Cases

* 2018 – Birçok Java/Go/JS library'sini etkileyen, Snyk tarafından yayımlanan kapsamlı *Zip-Slip* advisory.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) slugs içindeki TAR extraction traversal (v0.16.3 sürümünde fix edildi).<sup>[[7]](#references)</sup>
* Write işleminden önce `PathCanonicalize` / `realpath` çağırmayan tüm custom extraction logic'leri.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET'te Zip Slip'i Önleme](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR tools'larını şimdi update edin: RomCom ve diğerleri zero-day vulnerability'yi exploit ediyor (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability'nin Public Disclosure'ı: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug, Zip Slip Attack'e karşı Vulnerable (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip'te CVE-2025-11001 için Proof-of-Concept Exploit Report Edildi](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
{{#include ../banners/hacktricks-training.md}}
