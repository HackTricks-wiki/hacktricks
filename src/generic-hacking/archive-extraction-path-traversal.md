# Arşiv Çıkarma Yol Geçişi ("Zip-Slip")

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok arşiv biçimi (ZIP, RAR, TAR, 7-ZIP vb.), her girdinin kendi **iç yolunu** taşımasına izin verir. Bir çıkarma aracı bu yolu sorgulamadan kullandığında, `..` veya **mutlak yol** (ör. `C:\Windows\System32\`) içeren özel hazırlanmış bir dosya adı, seçilen dizinin dışına yazılır.  
Bu güvenlik açığı sınıfı yaygın olarak *Zip-Slip* veya **arşiv çıkarma yol geçişi** olarak bilinir.<sup>[[6]](#references)</sup>

Sonuçlar, rastgele dosyaların üzerine yazılmasından, Windows *Startup* klasörü gibi bir **otomatik çalıştırma** konumuna payload bırakarak doğrudan **uzaktan kod yürütme (RCE)** sağlamaya kadar değişebilir.

## Kök Neden

1. Saldırgan, bir veya daha fazla dosya başlığında şunları içeren bir arşiv oluşturur:
   * Göreli geçiş dizileri (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
   * Mutlak yollar (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
   * Ya da hedef dizinin dışına çözümlenen özel hazırlanmış **sembolik bağlantılar** (Unix benzeri sistemlerde ZIP/TAR arşivlerinde yaygındır). 
2. Kurban, gömülü yola güvenen (veya sembolik bağlantıları izleyen), bu yolu temizlemeyen ya da çıkarma işlemini seçilen dizinin altına zorlamayan güvenlik açığı bulunan bir araçla arşivi çıkarır.
3. Dosya, saldırganın kontrol ettiği konuma yazılır ve sistem veya kullanıcı bu yolu bir sonraki kez kullandığında yürütülür/yüklenir.

### .NET `Path.Combine` + `ZipArchive` yol geçişi

Yaygın bir .NET anti-pattern’i, hedeflenen konumu **kullanıcı kontrollü** `ZipArchiveEntry.FullName` ile birleştirip yolu normalleştirmeden çıkarmaktır:<sup>[[4]](#references)[[8]](#references)</sup>

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

- `entry.FullName` `..\\` ile başlıyorsa dizinler arasında gezinir; **absolute path** ise sol taraftaki bileşen tamamen atılır ve böylece çıkarma hedefi **arbitrary file write** olur.
- Zamanlanmış bir tarayıcı tarafından izlenen kardeş `app` dizinine yazmak için proof-of-concept arşivi:

```python
import zipfile
with zipfile.ZipFile("slip.zip", "w") as z:
    z.writestr("../app/0xdf.txt", "ABCD")
```

Bu ZIP dosyasını izlenen gelen kutusuna bırakmak, `C:\samples\app\0xdf.txt` dosyasının oluşmasını sağlar; bu da `C:\samples\queue\` dışına traversal yapıldığını kanıtlar ve devamındaki saldırı adımlarına (ör. DLL hijacks) olanak tanır.

### Kullanıcı denetimindeki extraction root

Yalnızca arşiv üyesi adlarını değil, **extractor'a verilen dizini** de test edin. Bir uygulama bu dizini başlık, proje adı veya başka bir istek alanından türetebilir. `../../../../app/module` gibi bir değer, extractor üyeleri işlemeden önce extraction root'u upload alanının dışına taşıyabilir. Bu durumda yalnızca güvenli `api.py` basename'ini içeren bir arşiv bile uygulama kodunun üzerine yazabilir.<sup>[[14]](#references)[[15]](#references)</sup>

```python
# Vulnerable pattern: the ZIP entries themselves need no ../ components.
extract_root = os.path.join(site_root, "public", "files", user_title)
archive.extractall(extract_root)
```

Bu, klasik Zip-Slip'ten ayrı bir containment sınırıdır. Hem çözümlenmiş çıkarma kökünü hem de çözümlenmiş her üye yolunu doğrulayın. Kök denetiminde string prefix yerine yol bileşenleri kullanılabilir:<sup>[[14]](#references)</sup>

```python
base = Path(site_root, "public", "files").resolve()
dest = (base / user_title).resolve()
if not dest.is_relative_to(base):
    raise ValueError("extraction root escapes its base")
```

Güvenli bir test için, bir canary file içeren geçerli bir arşiv yükleyin ve çıkarma dizinini seçebilecek her alana path traversal dizileri yerleştirin. Hem hedef dizini hem de kullan-at bir dış yolu izleyin. Hedef, içe aktarılmış bir modüle ulaşabiliyorsa, üzerine yazmak worker'lar yeniden yüklendiğinde code execution'a yol açabilir; bu yeniden yükleme sırasında HTTP 500 veya bağlantının sıfırlanması, yazma işleminin başarısız olduğunu kanıtlamaz.<sup>[[14]](#references)[[15]](#references)</sup> Ayrıca daha kapsamlı [file upload methodology](../pentesting-web/file-upload/) sayfasına bakın.

## Gelişmiş Arşivden Kaçış Primitifleri

Çıkarmayı, birbirinden bağımsız dosya adı kontrolleri olarak değil, bir dosya sistemi değişiklikleri dizisi olarak ele alın. Ayrıştırıldığında güvenli olan bir kayıt, önceki bir üye bir bağlantı oluşturduktan veya değiştirdikten sonra güvensiz hâle gelebilir; aynı sorun, bir çıkarıcı dizini güvenli olarak önbelleğe alıp daha sonra türünü değiştirdiğinde de ortaya çıkar.<sup>[[11]](#references)</sup>

### Link pivots ve kayıt çakışmaları

* **Symlink write-through**: `pivot -> /tmp` oluşturun, ardından normal bir üyeyi `pivot/PWNED.txt` olarak çıkarın. Çıkarıcı ikinci üyeyi oluştururken ilk üyeyi izlerse, ikinci adında `..` olmadan yazma işlemi hedef dizinin dışına çıkar.
* **Directory-cache/TOCTOU collision**: `d/sub/` dizinini oluşturun, `d/sub` öğesini `/tmp` konumuna işaret eden bir symlink ile değiştirin, ardından `d/sub/PWNED.txt` öğesini çıkarın. Bu, dizini bir kez doğrulayan veya önbelleğe alan ve son yazma işleminden önce yeniden kontrol etmeyen çıkarıcıları hedefler.
* **Hardlink read/overwrite**: TAR ve RAR hardlink'leri temsil edebilir. Mevcut bir host dosyasına verilen hardlink, çıkarılan adı daha sonra bir bileşen tarafından sunulursa dosyanın içeriğini açığa çıkarabilir; çakışan normal bir kayıt ise bunun yerine bağlı inode'un üzerine yazabilir. Bu, aynı dosya sistemi ve OS hardlink izin kurallarıyla sınırlıdır.
* **Pre-existing or cross-archive pivot**: boş olmayan bir hedef dizinle yeniden deneyin. Her arşiv durumsuz bir başlık adı kontrolünden geçse bile, bir arşiv bağlantı yerleştirebilir ve sonraki bir çıkarma işlemi bu bağlantı üzerinden yazabilir.<sup>[[11]](#references)</sup>

### Dosya sistemi eşdeğerliği çakışmaları

Adları, onları alacak dosya sisteminin semantiğine göre karşılaştırın. İşe yarayan farklılık testleri arasında büyük/küçük harfe duyarsız dosya sistemlerinde `LINK` ile `link`, NFC ile NFD Unicode yazımları, `ﬁle` ile `file` gibi uyumluluk bakımından eşdeğer adlar, bir yolu dizinden symlink'e dönüştüren yinelenen üyeler ve yalnızca Windows'ta ayraç olarak yorumlanan ters eğik çizgiler bulunur. NTFS'te ADS içeren adları da test edin. Bu durumlar, doğrulayıcının iki yol gördüğü hâlde dosya sisteminin tek bir yolu çözümlemesine neden olabilir.<sup>[[5]](#references)[[11]](#references)</sup>

Bu nedenle, kısa bir test kümesi sıralı **directory → symlink → child**, **symlink → colliding regular file**, **hardlink → colliding regular file** kombinasyonlarını, karışık `/` ve `\` kullanımını, mutlak/kök dizinli adları ve `.tar.gz` gibi sıkıştırılmış sarmalayıcıları test etmelidir. Testleri yalnızca kullan-at bir VM/container içinde çalıştırın ve hem hedefi hem de amaçlanan dış canary yolunu izleyin.<sup>[[11]](#references)</sup>

ZIP'e özgü yapısal belirsizlikler, ön taramanın ve gerçek çıkarıcının farklı kayıt adları veya dizin ağaçları görmesine neden olabilir. Yalnızca tek bir ZIP kütüphanesinin çıktısına güvenmek yerine [Local-header vs central-directory parser confusion](../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md#local-header-vs-central-directory-parser-confusion) sayfasına bakın.

## Gerçek Dünyadan Örnek – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ve Windows RAR/UnRAR bileşenleri, çıkarma sırasında dosya adlarını doğrulayamadı. Güvenlik açığı, seçilen çıkarma yolunu atlatıp dosyaları istenmeyen konumlara yazmak için NTFS alternate data streams (ADS) kullandı.<sup>[[5]](#references)</sup>
Aşağıdaki gibi bir kayıt içeren kötü amaçlı bir RAR arşivi:

```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.lnk
```

seçilen çıktı dizininin **dışında** ve kullanıcının *Startup* klasörünün içinde kalırdı. ESET, kötü amaçlı LNK dosyalarının buraya çıkarıldığını ve kullanıcı oturum açtığında çalıştırılarak persistence sağladığını ve RCE'ye giden bir yol sunduğunu gözlemledi.<sup>[[5]](#references)</sup>

### PoC Arşivi Oluşturma (Linux/Mac)

CVE-2025-8088, bir ADS adında path traversal yolu kullandığından, RAR'ı oluşturmak için amaca özel bir generator kullanın ve çıkarma işlemini yalnızca savunmasız bir WinRAR sürümünün bulunduğu yalıtılmış bir laboratuvarda test edin.<sup>[[5]](#references)</sup>

### Sahada Gözlemlenen Exploitation

ESET, RomCom'un (Storm-0978/UNC2596) CVE-2025-8088'i kötüye kullanan RAR arşivleri eklediği; özelleştirilmiş backdoor'lar dağıtmayı ve ransomware operasyonlarını kolaylaştırmayı amaçlayan spear-phishing kampanyaları bildirdi.<sup>[[5]](#references)</sup>

## Daha Yeni Vakalar (2024–2026)

### 7-Zip ZIP symlink traversal → RCE (CVE-2025-11001 / ZDI-25-949)
* **Hata**: ZIP içindeki **symbolic link** girdileri çıkarma sırasında takip edilerek saldırganların hedef dizinin dışına çıkıp istedikleri yolların üzerine yazmasına olanak tanıyordu. Kullanıcının yalnızca arşivi *açması/çıkarması* yeterlidir.<sup>[[1]](#references)</sup>
* **Etkilenen sürümler**: **25.00** öncesindeki 7-Zip sürümleri. Symbolic link işleme hatası **25.00** sürümünde (Temmuz 2025) ve sonrasında düzeltildi.<sup>[[1]](#references)[[10]](#references)</sup>
* **Etki yolu**: `Start Menu/Programs/Startup` veya hizmetlerin çalıştırdığı konumların üzerine yazma → sonraki oturum açmada ya da hizmet yeniden başlatıldığında kod çalışır.
* **Hızlı symlink işleme fixture'ı (Linux)**:
  ```bash
  mkdir -p /tmp/archive-slip-test /tmp/archive-slip-outside
  ln -s /tmp/archive-slip-outside /tmp/archive-slip-test/evil
  cd /tmp/archive-slip-test
  zip -y exploit.zip evil   # -y preserves symlinks
  7z x exploit.zip -o/tmp/archive-slip-target
  ```
  Bu arşiv, çıkarma dizininin dışını gösteren bir symlink girdisi içerir; geçici bir hedef kullanın ve çıkarıcının bu symlink'i izlemediğini doğrulayın. Write-through testi için symlink'in altında normal dosya girdisi de gerekir.

### Go mholt/archiver `Unarchive()` symlink çakışması (CVE-2025-3445)
* **Hata**: `archiver.Unarchive()`, bir ZIP symlink'ini çıkarıp daha sonra aynı ada sahip normal bir üyeyle karşılaştığında symlink'i izleyebilir; böylece görünüşte dizin içinde olan bir yazma, dizin dışına yazmaya dönüşür.<sup>[[2]](#references)</sup>
* **Etkilenen sürümler**: `github.com/mholt/archiver` ≤ 3.5.1 (proje artık kullanımdan kaldırılmıştır).<sup>[[2]](#references)</sup>
* **Düzeltme**: `mholt/archives` ≥ 0.1.0 sürümüne geçin veya bağlantıları reddedip her hedefi açmadan hemen önce yeniden çözümleyin.<sup>[[2]](#references)</sup>
* **Minimal çakışma oluşturucu** (ardından `archiver.Unarchive("exploit.zip", "/tmp/safe")` çağırın):<sup>[[2]](#references)</sup>
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

`tarfile.extractall(filter="data")` ve `filter="tar"` bile bağlantı sırası bypass’larına maruz kaldı. Bu durumda bir hardlink, arşivde daha derin bir yolda bulunan symlink’e başvuruyordu; yedek çıkarma işlemi, derin konumdaki göreli symlink’i doğruluyor ancak onu hardlink’in daha sığ konumunda yeniden oluşturuyordu. Aynı göreli hedef bu konumdan kök dizinin dışına çıkıyordu. Bu, genel olarak faydalı bir testtir: doğrulama ile oluşturma işleminin temel dizin veya son üye türü konusunda farklı davranmasını sağlayın.<sup>[[12]](#references)</sup>

### Node `tar` hardlink hedefinin symlink zinciri üzerinden dışarı çıkması (GHSA-83g3-92jg-28cx)

Node.js `tar` paketi’nin `tar.extract()` işlevi, hedefi sözcüksel olarak içeride görünen ancak önceki iki symlink üzerinden çözümlendiğinde çıkarma kök dizininin dışına çıkan bir hardlink’i kabul ediyordu. Saldırı varsayılan çıkarma seçenekleriyle çalışır: hedef üst dizin denetimleri hardlink’in kök dizin içindeki adını kapsıyordu, ancak hardlink hedefi, zincirin tamamı içeride kalıyor mu diye çözümleme yapılmadan dosya sistemine iletiliyordu. `tar` ≤ 7.5.7 etkilenmiştir; 7.5.8 bu sorunu giderir.<sup>[[13]](#references)</sup>

Önemli test fikstürü, bu sabit adlar değil, üyeler arasındaki **sıralı ilişkidir**:<sup>[[13]](#references)</sup>

```text
a/b/c/up     -> ../..                          (symlink)
a/b/escape   -> c/up/../..                     (symlink)
exfil        => a/b/escape/<path-from-parent>  (hardlink)
```

Ayıklama başarılı olursa `exfil`, çıktı ağacında görünür biçimde kalır ancak seçilen dış dosyayla aynı inode'u paylaşır; dosyanın okunması bu dosyayı sızdırır, yazılmasıysa orijinal dosyayı değiştirir. Bu bypass, yalnızca son pathname'i kontrol etmenin, mutlak önekleri kaldırmanın veya hardlink başlığındaki `..` ifadelerini engellemenin neden yetersiz olduğunu gösterir: bağlantı hedeflerini, daha önce ayıklanan tüm dosya sistemi durumunu uyguladıktan sonra doğrulayın.<sup>[[13]](#references)</sup>

## Tespit İpuçları

* **Statik inceleme** – Hem üye adlarını hem de bağlantı hedeflerini listeleyin. `../`, `..\\`, mutlak/kök dizinli yolları, symlink'leri, hardlink'leri, özel dosyaları, yinelenen adları, tür değişikliklerini ve büyük/küçük harf veya Unicode eşdeğerliğinden kaynaklanan çakışmaları işaretleyin. İnceleme sırasında giriş sırasını koruyun; çünkü exploit daha önceki üyelere bağlı olabilir.<sup>[[11]](#references)</sup>

  ```bash
  bsdtar -tvf suspect.tar       # ordered TAR members, types and link targets
  7z l -slt suspect.7z          # technical metadata, one field per line
  zipinfo -v suspect.zip        # ZIP central-directory metadata and offsets
  ```

* **Kanonikleştirme** – Çözümlenmiş üst dizin ile son basename'in çözümlenmiş hedef dizinin altında kaldığından emin olun (ham bir dize öneki yerine yol bileşenlerini karşılaştırın). Önceki her üye işlendiğinde yeniden kontrol edin; bir defaya mahsus `realpath(join(dest, name))` kontrolü, linkin değiştirilmesine karşı savunmasızdır ve henüz oluşturulmamış bir leaf için başarısız olabilir.<sup>[[3]](#references)[[11]](#references)</sup>
* **Sandbox'ta çıkarma** – Arşivi, yol/symlink kontrolleri yapan bir extractor kullanarak yeni ve geçici bir dizine açın (örneğin, bsdtar'ın varsayılan güvenli kontrolleri veya 7-Zip ≥ 25.00); ardından oluşan ağaçta dışarıya yönelen link olmadığını doğrulayın. İzolasyon, tetiklenmiş bir kaçışın host yollarına erişmesini önlemelidir.<sup>[[1]](#references)[[9]](#references)</sup>
* **Sonraki okumalar önemlidir** – Arşiv çıkarma işlemi dışarıda dosya oluşturmamış olsa bile, geride kalan bir symlink veya hardlink; önizleyici, CDN, dosya tarayıcısı ya da paket hattı çıkarılan adı daha sonra açtığında veya sunucudan sağladığında arbitrary-file-read ilkel hâline gelebilir.<sup>[[11]](#references)</sup>
* **Uç nokta izleme** – WinRAR/7-Zip vb. bir program arşivi açtıktan kısa süre sonra `Startup`/`Run`/`cron` konumlarına yazılan yeni yürütülebilir dosyalar için uyarı oluşturun.

## Azaltma ve Sağlamlaştırma

1. **Extractor'ı güncelleyin** – WinRAR 7.13+, 7-Zip 25.00+ ve Node `tar` 7.5.8+, belirtilen path/symlink/link-target sorunlarına yönelik düzeltmeler içerir.<sup>[[1]](#references)[[5]](#references)[[13]](#references)</sup>
2. Mümkün olduğunda arşivleri “**Do not extract paths**” / “**Ignore paths**” seçenekleriyle çıkarın. Güvenilmeyen girdilerde, uygulamanın açıkça ihtiyaç duymadığı sürece symbolic link'leri, hardlink'leri, aygıtları ve FIFO'ları reddedin.<sup>[[9]](#references)[[11]](#references)</sup>
3. Arşivleri **yeni ve boş bir dizine** çıkarın. Güvenilmeyen üyeleri, saldırganın değiştirebileceği yollar içeren bir ağaçla birleştirmeyin ve önceki bir arşivin hazırladığı dizini yeniden kullanmayın.<sup>[[11]](#references)</sup>
4. Unix'te ayrıcalıkları düşürün ve hedefi bir **chroot/mount namespace** içinde yalıtın; Windows'ta **AppContainer** veya bir sandbox kullanın. Yalnızca çıkarma sonrası tarama yapmak yeterli değildir; çünkü kaçışa yol açan yazma taramadan önce gerçekleşir.<sup>[[11]](#references)</sup>
5. Özel kodda hedef işletim sisteminin ayraç/büyük-küçük harf/Unicode kurallarını uygulayın; hem üyeyi hem de link hedefini doğrulayın. Hedefi linkleri takip etmeden çözümleyip açın; containment kontrolünü daha sonraki oluşturma/değiştirme işleminden ayırmayın. Doğrulayıcı, yazma yoluyla aynı temel dizini ve link emülasyonu semantiğini kullanmalıdır.<sup>[[11]](#references)[[12]](#references)</sup>

## Etkilenen / Geçmişteki Diğer Vakalar

* 2018 – Snyk'in çok sayıda Java/Go/JS kütüphanesini etkileyen kapsamlı *Zip-Slip* uyarısı.<sup>[[6]](#references)</sup>
* 2025 – HashiCorp `go-slug` (CVE-2025-0377): slug'larda TAR çıkarma sırasında path traversal (v0.16.3'te düzeltildi).<sup>[[7]](#references)</sup>
* Link hedeflerini ve her yazma işlemi için kullanılan son dosya sistemi yolunu değil, yalnızca header dizelerini doğrulayan tüm özel çıkarma mantıkları.<sup>[[11]](#references)[[12]](#references)</sup>





## References

- [1] [Trend Micro ZDI-25-949 – 7-Zip symlink ZIP traversal (CVE-2025-11001)](https://www.zerodayinitiative.com/advisories/ZDI-25-949/)
- [2] [JFrog Research – mholt/archiver Zip-Slip (CVE-2025-3445)](https://research.jfrog.com/vulnerabilities/archiver-zip-slip/)
- [3] [Meziantou – .NET'te Zip Slip'i önleme](https://www.meziantou.net/prevent-zip-slip-in-dotnet.htm)
- [4] [0xdf – HTB Bruno ZipSlip → DLL hijack zinciri](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [ESET Research – WinRAR araçlarını hemen güncelleyin: RomCom ve diğerleri zero-day güvenlik açığından yararlanıyor (CVE-2025-8088)](https://www.welivesecurity.com/en/eset-research/update-winrar-tools-now-romcom-and-others-exploiting-zero-day-vulnerability/)
- [6] [Snyk – Kritik Bir Arbitrary File Overwrite Güvenlik Açığının Kamuya Açıklanması: Zip Slip](https://snyk.io/blog/zip-slip-vulnerability/)
- [7] [HashiCorp – HCSEC-2025-01: go-slug, Zip Slip Saldırısına Karşı Savunmasız (CVE-2025-0377)](https://discuss.hashicorp.com/t/hcsec-2025-01-hashicorp-go-slug-vulnerable-to-zip-slip-attack/72719)
- [8] [Microsoft Learn – Path.Combine Metodu](https://learn.microsoft.com/en-us/dotnet/api/system.io.path.combine?view=net-7.0)
- [9] [libarchive – bsdtar güvenli çıkarma seçenekleri](https://github.com/libarchive/libarchive/blob/master/tar/bsdtar.c)
- [10] [NHS England Digital – 7-Zip'teki CVE-2025-11001 için Proof-of-Concept Exploit bildirildi](https://digital.nhs.uk/cyber-alerts/2025/cc-4719)
- [11] [Joshua Rogers – Zip-slip, tar-slip, symlink, hardlink, çakışmalar ve daha fazlasıyla hacking eğlencesi](https://joshua.hu/tarslip-zipslip-symlink-hardlink-generator)
- [12] [Python Security Announce – CVE-2026-11940 tarfile çıkarma filtresi atlatması](https://mail.python.org/archives/list/security-announce@python.org/thread/LD6QIISNQFQYOIEPJNEUIPV7S3V76FZH/)
- [13] [GitHub Security Advisory – node-tar hardlink hedefinin symlink zinciri üzerinden dışarı kaçması](https://github.com/isaacs/node-tar/security/advisories/GHSA-83g3-92jg-28cx)
- [14] [Rhino Security Labs CVE PoC – kullanıcı denetimindeki SCORM çıkarma kök dizini](https://raw.githubusercontent.com/RhinoSecurityLabs/CVEs/master/CVE-2026-39405/README.md)
- [15] [Rhino Security Labs – Frappe LMS'te Uzaktan Kod Yürütmeye Yol Açan Birden Fazla Güvenlik Açığı](https://rhinosecuritylabs.com/research/multiple-vulnerabilities-in-frappe-lms-leading-to-remote-code-execution/)
{{#include ../banners/hacktricks-training.md}}
