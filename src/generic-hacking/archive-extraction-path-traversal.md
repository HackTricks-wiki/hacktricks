# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok archive formatı (ZIP, RAR, TAR, 7-ZIP vb.), her entry'nin kendi **internal path** bilgisini taşımasına izin verir. Bir extraction utility bu path bilgisini herhangi bir kontrol yapmadan kullandığında, `..` veya **absolute path** (ör. `C:\Windows\System32\`) içeren hazırlanmış bir filename, kullanıcı tarafından seçilen directory'nin dışına yazılır.
Bu vulnerability sınıfı yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.<sup>[[6]](#references)</sup>

Sonuçlar, arbitrary file'ların üzerine yazılmasından, Windows *Startup* folder gibi bir **auto-run** konumuna payload bırakarak doğrudan **remote code execution (RCE)** elde etmeye kadar uzanabilir.

## Kök Neden

1. Attacker, bir veya daha fazla file header'ının şunları içerdiği bir archive oluşturur:
* Relative traversal sequence'ları (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute path'ler (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya target dir'nin dışına çözümlenen hazırlanmış **symlink**'ler (*nix* üzerinde ZIP/TAR'da yaygındır).
2. Victim, embedded path'e güvenen (veya symlink'leri takip eden), path'i sanitize etmek ya da extraction işlemini seçilen directory altında zorlamak yerine vulnerable bir tool ile archive'ı extract eder.
3. File, attacker-controlled location'a yazılır ve system veya user bu path'i bir sonraki tetiklediğinde execute/load edilir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern, hedeflenen destination'ı user-controlled `ZipArchiveEntry.FullName` ile birleştirmek ve path normalisation yapmadan extraction gerçekleştirmektir:<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` `..\\` ile başlıyorsa traversal gerçekleştirir; **absolute path** ise sol taraftaki bileşen tamamen atılır ve çıkarma hedefi olarak **arbitrary file write** elde edilir.
- Scheduled scanner tarafından izlenen kardeş `app` dizinine yazmak için proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Bu ZIP dosyasının monitored inbox dizinine bırakılması `C:\samples\app\0xdf.txt` sonucunu doğurur; bu da `C:\samples\queue\` dışına traversal yapılabildiğini ve follow-on primitives (ör. DLL hijacks) kullanılabildiğini kanıtlar.

## Advanced Archive-Breakout Primitives

Extraction işlemini birbirinden bağımsız filename kontrolleri olarak değil, bir filesystem mutation dizisi olarak ele alın. Parse edildiğinde güvenli olan bir entry, daha önceki bir member bir link oluşturduğunda veya değiştirdiğinde güvensiz hale gelebilir; aynı sorun, bir extractor bir directory'yi güvenli olarak cache'lediğinde ve daha sonra bu directory'nin türü değiştiğinde de ortaya çıkar.<sup>[[11]](#references)</sup>

### Link pivots and entry collisions

* **Symlink write-through**: `pivot -> /tmp` oluşturun, ardından normal bir member'ı `pivot/PWNED.txt` olarak extract edin. Extractor ikinci member'ı materialise ederken ilk member'ı takip ederse write işlemi, ikinci adda `..` bulunmadan dışarıya taşar.
* **Directory-cache/TOCTOU collision**: `d/sub/` directory'sini oluşturun, `d/sub` öğesini `/tmp` konumuna işaret eden bir symlink ile değiştirin, ardından `d/sub/PWNED.txt` öğesini oluşturun. Bu, directory'yi bir kez validate veya cache eden ve final write işleminden önce tekrar kontrol etmeyen extractor'ları hedefler.
* **Hardlink read/overwrite**: TAR ve RAR hardlink'leri temsil edebilir. Mevcut bir host file'a verilen hardlink, daha sonraki bir component extracted name'i sunduğunda içeriğini açığa çıkarabilir; çakışan bir regular entry ise linked inode'un üzerine yazabilir. Bu durum aynı-filesystem ve OS hardlink-permission kurallarıyla sınırlıdır.
* **Pre-existing or cross-archive pivot**: Boş olmayan bir destination ile tekrar deneyin. Her archive stateless header-name check'i geçse bile, bir archive link yerleştirebilir ve sonraki bir extraction bu link üzerinden write gerçekleştirebilir.<sup>[[11]](#references)</sup>

### Filesystem-equivalence collisions

İsimleri, onları alacak filesystem'ın semantics kurallarını kullanarak karşılaştırın. Yararlı differential case'ler arasında case-insensitive filesystem'larda `LINK` ile `link`, NFC ile NFD Unicode yazımları, `ﬁle` ile `file` gibi compatibility-equivalent isimler, bir path'i directory'den symlink'e dönüştüren duplicate member'lar ve yalnızca Windows'ta separator olarak yorumlanan backslash'ler bulunur. NTFS üzerinde ADS içeren isimleri de test edin. Bu durumlar validator'ın iki path görmesine, filesystem'ın ise tek bir path çözümlemesine neden olabilir.<sup>[[5]](#references)[[11]](#references)</sup>

Bu nedenle compact bir corpus; **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, karışık `/` ve `\`, absolute/rooted isimler ve `.tar.gz` gibi compressed wrapper'ların sıralı kombinasyonlarını test etmelidir. Bunu yalnızca disposable bir VM/container içinde çalıştırın ve hem destination'ı hem de amaçlanan dış canary path'i izleyin.<sup>[[11]](#references)</sup>

## Real-World Example – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ve Windows RAR/UnRAR component'leri extraction sırasında filename'ları validate edemedi. Flaw, seçilen extraction path'i bypass etmek ve dosyaları amaçlanmayan konumlara yazmak için NTFS alternate data streams (ADS) kullandı.<sup>[[5]](#references)</sup>
Şu türde bir entry içeren malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
`...` would end up **outside** the selected output directory and inside the user’s *Startup* folder. ESET, kötü amaçlı LNK dosyalarının burada açıldığını ve kullanıcı oturum açtığında çalıştırıldığını gözlemledi; bu durum persistence ve RCE için bir yol sağladı.<sup>[[5]](#references)</sup>

### PoC Archive Oluşturma (Linux/Mac)

CVE-2025-8088 bir ADS name içinde traversal path kullandığından, RAR oluşturmak için amaca özel bir generator kullanın; ardından extraction işlemini yalnızca vulnerable bir WinRAR build'i bulunan izole bir lab ortamında test edin.<sup>[[5]](#references)</sup>

### Gerçek Ortamda Gözlemlenen Exploitation

ESET, RomCom’un (Storm-0978/UNC2596) CVE-2025-8088’i kötüye kullanan RAR arşivlerini eklediği spear-phishing campaign'leri raporladı. Bu arşivler customized backdoor'lar dağıtmak ve ransomware operasyonlarını kolaylaştırmak için kullanıldı.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: **Symbolic link** olan ZIP entries extraction sırasında dereference ediliyordu. Bu durum saldırganların destination directory dışına çıkmasına ve arbitrary path'lerin üzerine yazmasına izin veriyordu. User interaction yalnızca arşivi *açmak/extract etmekti*.<sup>[[1]](#references)</sup>
* **Affected**: **25.00** öncesindeki 7-Zip build'leri. Symbolic-link processing flaw, **25.00** sürümünde (Temmuz 2025) ve sonraki sürümlerde düzeltildi.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` veya service-run locations üzerine yazın → kod bir sonraki logon'da veya service restart sonrasında çalışır.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Bu arşiv, extraction directory dışını gösteren bir symlink entry içerir; disposable bir target kullanın ve extractor'ın bu symlink'i takip etmediğini doğrulayın. Write-through testi ayrıca symlink'in altında bir regular-file entry gerektirir.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`, bir ZIP symlink'ini extract ettikten sonra, daha sonraki bir regular member aynı ada sahip olduğunda symlink'i dereference edebilir. Bu durum, görünüşte in-root olan bir write işlemini out-of-root write'a dönüştürür.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project artık deprecated).<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0 kullanın veya link'leri reject edip her destination'ı açmadan hemen önce yeniden resolve edin.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (`archiver.Unarchive("exploit.zip", "/tmp/safe")` çağrısından sonra):<sup>[[2]](#references)</sup>
```python
import zipfile

with zipfile.ZipFile("exploit.zip", "w") as z:
link = zipfile.ZipInfo("./x")
link.create_system = 3
link.external_attr = 0o120777 << 16
z.writestr(link, "../../../tmp/PWNED")
z.writestr("./x", b"owned\n")
```

### CPython filtered TAR extraction bypass (CVE-2026-11940)

`tarfile.extractall(filter="data")` ve `filter="tar"` bile link-order bypass'larına maruz kalmıştır. Bu vakada bir hardlink, daha derin bir path'te arşivlenmiş bir symlink'e referans veriyordu; fallback extraction, relative symlink'i bu deep location'da validate ediyor ancak aynı symlink'i hardlink'in daha sığ location'ında yeniden oluşturuyordu. Burada aynı relative target dışarı çıkıyordu. Bu, genel bir test için kullanışlıdır: validation ile materialisation'ın base directory veya final member type konusunda farklı davranmasını sağlayın.<sup>[[12]](#references)</sup>

## Detection Tips

* **Static inspection** – Hem member name'leri hem de link target'larını listeleyin. `../`, `..\\`, absolute/rooted path'leri, symlink'leri, hardlink'leri, special file'ları, duplicate name'leri, type change'leri ve case/Unicode-equivalent collision'ları işaretleyin. İnceleme sırasında entry order'ını koruyun; çünkü exploit önceki member'lara bağlı olabilir.<sup>[[11]](#references)</sup>
* **Canonicalisation** – Resolved parent ile final basename'in resolved destination altında kaldığından emin olun (raw string prefix yerine path component'lerini karşılaştırın). Her preceding member'dan sonra yeniden kontrol edin; tek seferlik `realpath(join(dest, name))` testi, link replacement'a karşı vulnerable'dır ve henüz oluşturulmamış bir leaf için başarısız olabilir.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – Fresh ve disposable bir directory'ye, path/symlink check'leri kullanan bir extractor ile decompress edin (örneğin bsdtar'ın default secure check'leri veya 7-Zip ≥ 25.00); ardından ortaya çıkan tree'de outward link bulunmadığını doğrulayın. Isolation, daha önce tetiklenmiş bir escape'in host path'lerine ulaşmasını engellemelidir.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Extraction'ın kendisi outside file oluşturmamış olsa bile, hayatta kalan bir symlink veya hardlink; previewer, CDN, file browser ya da package pipeline daha sonra extract edilen name'i açtığında veya sunduğunda arbitrary-file-read primitive'ine dönüşebilir.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip vb. tarafından bir arşiv açıldıktan kısa süre sonra `Startup`/`Run`/`cron` locations'a yazılan yeni executable'lar için alert oluşturun.

## Mitigation & Hardening

1. **Extractor'ı güncelleyin** – WinRAR 7.13+ ve 7-Zip 25.00+, belirtilen path/symlink sorunlarına yönelik fix'leri içerir.<sup>[[1]](#references)[[5]](#references)</sup>
2. Mümkün olduğunda arşivleri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle extract edin. Untrusted input için, uygulamanın bunlara açıkça ihtiyaç duyduğu durumlar dışında symbolic link'leri, hardlink'leri, device'ları ve FIFO'ları reject edin.<sup>[[9]](#references)[[11]](#references)</sup>
3. Arşivleri **yeni ve boş bir directory**'ye extract edin. Untrusted member'ları attacker tarafından replace edilebilir path'ler içeren bir tree ile merge etmeyin ve önceki bir arşiv tarafından hazırlanmış bir directory'yi yeniden kullanmayın.<sup>[[11]](#references)</sup>
4. Unix'te privileges'ı düşürün ve destination'ı bir **chroot/mount namespace** içinde isolate edin; Windows'ta **AppContainer** veya bir sandbox kullanın. Yalnızca post-extraction scan yeterli değildir; çünkü escaped write scan'den önce gerçekleşir.<sup>[[11]](#references)</sup>
5. Custom code'da hedef OS'in separator/case/Unicode kurallarını uygulayın ve hem member'ı hem de link target'ını validate edin. Link'leri takip etmeden destination'ı resolve edip açın; containment check'i daha sonraki create/replace operation'ından ayırmayın. Validator, write path ile tamamen aynı base ve link-emulation semantics'lerini kullanmalıdır.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Snyk tarafından yayımlanan ve birçok Java/Go/JS library'sini etkileyen kapsamlı *Zip-Slip* advisory'si.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) içinde slugs için TAR extraction traversal (v0.16.3'te düzeltildi).<sup>[[7]](#references)</sup>
* Header string'lerini validate eden ancak link target'larını ve her write işlemi için kullanılan final filesystem path'ini validate etmeyen tüm custom extraction logic'leri.<sup>[[11]](#references)[[12]](#references)</sup>



## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET'te Zip Slip'i önleme](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR araçlarını şimdi güncelleyin: RomCom ve diğerleri zero-day vulnerability'yi exploit ediyor (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability'nin Public Disclosure'ı: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug, Zip Slip Attack'e karşı Vulnerable (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flags](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip'te CVE-2025-11001 için Proof-of-Concept Exploit raporlandı](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Zip-slip, tar-slip, symlink, hardlink, collision ve daha fazlasıyla hacking eğlencesi](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
{{#include ../banners/hacktricks-training.md}}
