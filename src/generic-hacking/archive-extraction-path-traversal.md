# Archive Extraction Path Traversal ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok archive formatı (ZIP, RAR, TAR, 7-ZIP vb.), her entry'nin kendi **internal path** bilgisini taşımasına izin verir. Bir extraction utility bu yolu herhangi bir doğrulama yapmadan kullandığında, `..` veya **absolute path** (ör. `C:\Windows\System32\`) içeren hazırlanmış bir filename, kullanıcı tarafından seçilen directory'nin dışına yazılır.
Bu vulnerability sınıfı, yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.<sup>[[6]](#references)</sup>

Sonuçlar arbitrary file'ların üzerine yazılmasından, Windows *Startup* folder gibi bir **auto-run** konumuna payload bırakılarak doğrudan **remote code execution (RCE)** elde edilmesine kadar uzanabilir.

## Root Cause

1. Attacker, bir veya daha fazla file header'ının şunları içerdiği bir archive oluşturur:
* Relative traversal sequence'ları (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute path'ler (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya target dir'in dışına çözümlenen hazırlanmış **symlink**'ler (*nix üzerinde ZIP/TAR'da yaygındır).
2. Victim, embedded path'e güvenen (veya symlink'leri takip eden), bunu sanitize etmek ya da extraction işlemini seçilen directory altında zorlamak yerine vulnerable bir tool ile archive'ı extract eder.
3. File, attacker-controlled location'a yazılır ve system veya user bu path'i bir sonraki kez tetiklediğinde execute edilir/load edilir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern'i, amaçlanan destination'ı **user-controlled** `ZipArchiveEntry.FullName` ile birleştirmek ve path normalization yapmadan extract etmektir:<sup>[[4]](#references)[[8]](#references)</sup>
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
- `entry.FullName` `..\\` ile başlıyorsa traversal gerçekleştirir; **absolute path** ise sol taraftaki bileşen tamamen atılır ve extraction identity olarak **keyfi dosya yazma** elde edilir.
- Zamanlanmış bir scanner tarafından izlenen kardeş `app` dizinine yazmak için proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Bu ZIP dosyasının izlenen gelen kutusuna bırakılması `C:\samples\app\0xdf.txt` dosyasının oluşturulmasına neden olur; bu da `C:\samples\queue\` dışına çıkıldığını ve takip eden primitive'lerin (ör. DLL hijack'leri) etkinleştirilebildiğini kanıtlar.

## Gelişmiş Archive-Breakout Primitive'leri

Extraction işlemini bağımsız filename kontrolleri olarak değil, bir filesystem mutation dizisi olarak ele alın. Parse edildiğinde güvenli olan bir entry, önceki bir member link oluşturduğunda veya değiştirdiğinde güvensiz hale gelebilir; aynı sorun, bir extractor bir directory'yi güvenli olarak cache'lediğinde ve daha sonra türü değiştiğinde de ortaya çıkar.<sup>[[11]](#references)</sup>

### Link pivot'ları ve entry çakışmaları

* **Symlink write-through**: `pivot -> /tmp` oluşturun, ardından normal bir member'ı `pivot/PWNED.txt` olarak extract edin. Extractor ikinci member'ı materialise ederken ilk member'ı takip ederse, ikinci add'de `..` bulunmasa bile yazma işlemi dışarı taşar.
* **Directory-cache/TOCTOU collision**: `d/sub/` directory'sini oluşturun, `d/sub` öğesini `/tmp` konumuna işaret eden bir symlink ile değiştirin, ardından `d/sub/PWNED.txt` öğesini oluşturun. Bu, directory'yi bir kez validate eden veya cache'leyen ve final write işleminden önce yeniden kontrol etmeyen extractor'ları hedefler.
* **Hardlink read/overwrite**: TAR ve RAR hardlink'leri temsil edebilir. Mevcut bir host file'a verilen hardlink, daha sonraki bir component extracted name'i sunduğunda içeriğini açığa çıkarabilir; çakışan bir regular entry ise bunun yerine linked inode'u overwrite edebilir. Bu durum aynı-filesystem ve işletim sistemi hardlink-permission kurallarıyla sınırlıdır.
* **Pre-existing veya cross-archive pivot**: Boş olmayan bir destination ile yeniden deneyin. Her archive stateless header-name check'inden geçse bile, bir archive link yerleştirebilir ve sonraki extraction işlemi bu link üzerinden yazabilir.<sup>[[11]](#references)</sup>

### Filesystem-equivalence çakışmaları

Name'leri, onları alacak filesystem'ın semantics kurallarını kullanarak karşılaştırın. Yararlı differential case'ler arasında case-insensitive filesystem'larda `LINK` ile `link`, NFC ile NFD Unicode yazımları, `ﬁle` ile `file` gibi compatibility-equivalent name'ler, bir path'i directory'den symlink'e dönüştüren duplicate member'lar ve yalnızca Windows'ta separator olarak yorumlanan backslash'ler bulunur. Ayrıca NTFS üzerinde ADS içeren name'leri de test edin. Bu case'ler validator'ın iki path görmesine, filesystem'ın ise tek bir path resolve etmesine neden olabilir.<sup>[[5]](#references)[[11]](#references)</sup>

Bu nedenle compact bir corpus; **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file**, karışık `/` ve `\`, absolute/rooted name'ler ve `.tar.gz` gibi compressed wrapper'ların sıralı kombinasyonlarını test etmelidir. Bunu yalnızca disposable bir VM/container içinde çalıştırın ve hem destination'ı hem de hedeflenen dış canary path'i izleyin.<sup>[[11]](#references)</sup>

ZIP'e özgü structural ambiguity, pre-scan ile gerçek extractor'ın farklı entry name'leri veya tree'ler görmesine neden olabilir. Yalnızca tek bir ZIP library'sinin çıktısına güvenmek yerine [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) bölümüne bakın.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ve Windows RAR/UnRAR component'leri extraction sırasında filename'leri validate edemiyordu. Flaw, seçilen extraction path'ini bypass etmek ve dosyaları amaçlanmayan konumlara yazmak için NTFS alternate data stream'lerini (ADS) kullandı.<sup>[[5]](#references)</sup>
Şu tür bir entry içeren kötü amaçlı bir RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```
seçilen çıktı dizininin **dışında** ve kullanıcının *Startup* klasörünün içinde yer alacaktı. ESET, kötü amaçlı LNK dosyalarının buraya unpack edilerek kullanıcı oturum açtığında çalıştırıldığını; bunun persistence ve RCE için bir yol sağladığını gözlemledi.<sup>[[5]](#references)</sup>

### PoC Archive Oluşturma (Linux/Mac)

CVE-2025-8088 bir ADS name içinde traversal path kullandığından, RAR'ı oluşturmak için amaca özel bir generator kullanın; ardından extraction işlemini yalnızca vulnerable bir WinRAR build'i içeren izole bir lab ortamında test edin.<sup>[[5]](#references)</sup>

### Gerçek Ortamda Gözlemlenen Exploitation

ESET, RomCom'un (Storm-0978/UNC2596) CVE-2025-8088'i abuse eden RAR archive'larını eklediği spear-phishing campaign'leri raporladı. Bu archive'lar customized backdoor'lar deploy etmek ve ransomware operation'larını kolaylaştırmak için kullanıldı.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: **symbolic link** olan ZIP entry'leri extraction sırasında dereference ediliyordu; bu da attacker'ların destination directory'den çıkıp arbitrary path'leri overwrite etmesine olanak sağlıyordu. User interaction yalnızca archive'ı *açmak/extract etmek*tir.<sup>[[1]](#references)</sup>
* **Affected**: **25.00** öncesindeki 7-Zip build'leri. Symbolic-link processing flaw **25.00** (Temmuz 2025) ve sonraki sürümlerde düzeltildi.<sup>[[1]](#references)[[10]](#references)</sup>
* **Impact path**: `Start Menu/Programs/Startup` veya service-run location'larını overwrite etmek → code bir sonraki logon'da veya service restart sonrasında çalışır.
* **Quick symlink-handling fixture (Linux)**:
```bash
mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
cd /tmp/archive-slip-test
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/archive-slip-target
```
Bu archive, extraction directory'sinin dışını gösteren bir symlink entry'si içerir; disposable bir target kullanın ve extractor'ın bu symlink'i takip etmediğini doğrulayın. Write-through testi için symlink'in altında bir regular-file entry'si de gerekir.

### Go mholt/archiver `Unarchive()` symlink collision (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()`, bir ZIP symlink'ini extract ettikten sonra, sonraki regular member aynı name'e sahip olduğunda bu symlink'i dereference edebilir; böylece görünüşte root içindeki bir write, root dışındaki bir write'a dönüşür.<sup>[[2]](#references)</sup>
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (project artık deprecated).<sup>[[2]](#references)</sup>
* **Fix**: `mholt/archives` ≥ 0.1.0'a geçin veya link'leri reject edip her destination'ı açmadan hemen önce yeniden resolve edin.<sup>[[2]](#references)</sup>
* **Minimal collision generator** (ardından `archiver.Unarchive("exploit.zip", "/tmp/safe")` çağırın):<sup>[[2]](#references)</sup>
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

`tarfile.extractall(filter="data")` ve `filter="tar"` kullanıldığında bile link-order bypass'ları görüldü. Bu vakada bir hardlink, daha derin bir path'te archive edilmiş bir symlink'e referans veriyordu; fallback extraction, relative symlink'i bu deep location'da validate etti ancak symlink'i hardlink'in daha shallow location'ında yeniden oluşturdu ve aynı relative target dışarı kaçtı. Bu, genel amaçlı faydalı bir testtir: validation ile materialisation'ın base directory veya final member type konusunda farklı sonuçlara ulaşmasını sağlayın.<sup>[[12]](#references)</sup>

### Node `tar` hardlink target escape through a symlink chain (GHSA-83g3-92jg-28cx)

Node.js `tar` package'ının `tar.extract()` fonksiyonu, target'ı lexical olarak extraction root içinde görünmesine rağmen iki önceki symlink üzerinden extraction root'un dışına resolve olan bir hardlink'i kabul ediyordu. Attack, default extraction options ile çalışır: destination-parent checks hardlink'in root içindeki name'ini kapsarken hardlink target'ı, containment için chain'in tamamı resolve edilmeden filesystem'a aktarılıyordu. `tar` ≤ 7.5.7 etkilenir; 7.5.8 bu issue'yu patch'ler.<sup>[[13]](#references)</sup>

Önemli test fixture'ı bu literal name'ler değil, member'lar arasındaki **ordered relationship**'tır:<sup>[[13]](#references)</sup>
```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```
Çıkarma başarılı olursa, `exfil` çıktı ağacının içinde görünür şekilde kalır ancak seçilen dış dosyayla aynı inode'u paylaşır; bu dosyanın okunması onu sızdırır ve yazılması orijinali değiştirir. Bu bypass, yalnızca son pathname'i kontrol etmenin, absolute prefix'leri kaldırmanın veya hardlink header'ında `..` kullanımını engellemenin neden yetersiz olduğunu gösterir: link target'larını, daha önce çıkarılmış tüm filesystem state uygulandıktan sonra doğrulayın.<sup>[[13]](#references)</sup>

## Detection Tips

* **Static inspection** – Hem member name'lerini hem de link target'larını listeleyin. `../`, `..\\`, absolute/rooted path'leri, symlink'leri, hardlink'leri, special file'ları, duplicate name'leri, type değişikliklerini ve case/Unicode-equivalent collision'ları işaretleyin. Exploit daha önceki member'lara bağlı olabileceğinden, inceleme sırasında entry sırasını koruyun.<sup>[[11]](#references)</sup>

```bash
bsdtar -tvf suspect.tar       # sıralı TAR member'ları, type'lar ve link target'ları
7z l -slt suspect.7z          # teknik metadata, satır başına bir field
zipinfo -v suspect.zip        # ZIP central-directory metadata'sı ve offset'leri
```

* **Canonicalisation** – Resolved parent ile final basename'in, resolved destination'ın altında kalmaya devam ettiğinden emin olun (raw string prefix yerine path component'lerini karşılaştırın). Önceki her member'dan sonra yeniden kontrol edin; tek seferlik `realpath(join(dest, name))` testi, link replacement'a karşı savunmasızdır ve henüz oluşturulmamış bir leaf için başarısız olabilir.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox extraction** – path/symlink kontrolleri yapan bir extractor kullanarak yeni ve disposable bir directory'ye decompress edin (örneğin bsdtar'ın varsayılan güvenli kontrolleri veya 7-Zip ≥ 25.00), ardından ortaya çıkan tree'de dışarı yönelen link'ler bulunmadığını doğrulayın. Isolation, önceden tetiklenmiş bir escape'in host path'lerine ulaşmasını engellemelidir.<sup>[[1]](#references)[[9]](#references)</sup>
* **Downstream reads matter** – Hayatta kalan bir symlink veya hardlink, extraction'ın kendisi dışarıda dosya oluşturmamış olsa bile, bir previewer, CDN, file browser veya package pipeline daha sonra çıkarılan name'i açtığında ya da sunduğunda arbitrary-file-read primitive'ine dönüşebilir.<sup>[[11]](#references)</sup>
* **Endpoint monitoring** – WinRAR/7-Zip/etc. ile bir archive açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yazılan yeni executable'lar için alert oluşturun.

## Mitigation & Hardening

1. **Extractor'ı güncelleyin** – WinRAR 7.13+, 7-Zip 25.00+ ve Node `tar` 7.5.8+, belirtilen path/symlink/link-target sorunları için fix'ler içerir.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Mümkün olduğunda archive'ları “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle extract edin. Untrusted input için, uygulamanın bunlara açıkça ihtiyaç duymadığı durumlarda symbolic link'leri, hardlink'leri, device'ları ve FIFO'ları reddedin.<sup>[[9]](#references)[[11]](#references)</sup>
3. Archive'ları **yeni ve boş bir directory**'ye extract edin. Untrusted member'ları attacker tarafından replace edilebilen path'ler içeren bir tree ile merge etmeyin ve önceki bir archive tarafından hazırlanmış bir directory'yi yeniden kullanmayın.<sup>[[11]](#references)</sup>
4. Unix'te privilege'ları düşürün ve destination'ı bir **chroot/mount namespace** içinde isolate edin; Windows'ta **AppContainer** veya bir sandbox kullanın. Yalnızca extraction sonrası yapılan bir scan yeterli değildir; çünkü escaped write scan'den önce gerçekleşir.<sup>[[11]](#references)</sup>
5. Custom code'da hedef OS'nin separator/case/Unicode kurallarını uygulayın ve hem member'ı hem de link target'ını doğrulayın. Link'leri takip etmeden destination'ı resolve edip açın; containment check'i sonraki create/replace işleminden ayırmayın. Validator, write path ile tamamen aynı base ve link-emulation semantics'ini kullanmalıdır.<sup>[[11]](#references)[[12]](#references)</sup>

## Additional Affected / Historical Cases

* 2018 – Snyk tarafından yayımlanan ve birçok Java/Go/JS library'sini etkileyen kapsamlı *Zip-Slip* advisory'si.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) slug'larda TAR extraction traversal (v0.16.3'te fix'lendi).<sup>[[7]](#references)</sup>
* Header string'lerini doğrulayan ancak link target'larını ve her write işlemi için kullanılan final filesystem path'ini doğrulamayan tüm custom extraction logic'leri.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET'te Zip Slip'i önleme](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain'i](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR araçlarını şimdi güncelleyin: RomCom ve diğerleri zero-day vulnerability'yi (CVE-2025-8088) exploit ediyor](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Critical Arbitrary File Overwrite Vulnerability'nin Public Disclosure'ı: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug, Zip Slip Attack'e karşı vulnerable (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Method'u](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar secure extraction flag'leri](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip'te CVE-2025-11001 için Proof-of-Concept Exploit bildirildi](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – zip-slip'ler, tar-slip'ler, symlink'ler, hardlink'ler, collision'lar ve daha fazlasıyla eğlenceli hacking](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile extraction filter bypass'ı](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar hardlink target escape through symlink chain](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
{{#include ../banners/hacktricks-training.md}}
