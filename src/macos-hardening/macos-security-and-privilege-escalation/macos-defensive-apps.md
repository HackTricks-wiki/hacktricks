# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): यह प्रत्येक process द्वारा बनाए गए हर connection को monitor करेगा। mode के आधार पर (silent allow connections, silent deny connection और alert), हर बार नया connection stablished होने पर यह **आपको एक alert दिखाएगा**। इसमें यह सारी information देखने के लिए एक बहुत अच्छा GUI भी है।
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall। यह एक basic firewall है जो आपको suspicious connections के बारे में alert करेगा (इसमें GUI है, लेकिन यह Little Snitch जितना fancy नहीं है)।

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See application, जो कई locations में search करेगा जहाँ **malware persist कर सकता है** (यह one-shot tool है, monitoring service नहीं)।
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): KnockKnock की तरह, persistence generate करने वाले processes को monitor करता है।

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See application, जो keyboard "event taps" install करने वाले **keyloggers** को खोजने के लिए है।

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS के लिए binary authorization और monitoring system। यह code चलने से पहले **`exec`** events को authorize करने के लिए **Endpoint Security** client का उपयोग करता है, इसलिए यह केवल post-execution detection के बजाय **allowlisting/denylisting** पर केंद्रित enterprise fleets में सामान्य है।
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-जैसा macOS dynamic analysis tool। यह **Endpoint Security telemetry** (process, file, interprocess, login और XProtect-related events) को ingest करता है और यह समझने के लिए उपयोगी है कि एक mature ES-based sensor वास्तव में क्या observe कर सकता है।<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file** और **DNS** telemetry के लिए lightweight Objective-See tools। Modern macOS पर इनके लिए **root**, **Terminal Full Disk Access**, या **System/Network Extension approval** जैसी अतिरिक्त prerequisites होती हैं। अधिक instrumentation ideas के लिए [macOS app inspection/debugging के बारे में यह अन्य page](macos-apps-inspecting-debugging-and-fuzzing/README.md) देखें।

## Quick triage of defensive tooling

अधिकांश modern macOS security products **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, और **Full Disk Access** वाली applications के किसी combination के रूप में run होते हैं। एक quick operator checklist:
```bash
# System / network extensions (EDRs, DNS filters, firewalls, VPNs)
systemextensionsctl list

# Legacy kernel agents on older boxes / upgraded fleets
kmutil showloaded 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'
# Older releases:
kextstat 2>/dev/null | rg -i 'crowdstrike|carbon|sentinel|defender|sophos|eset|symantec|trellix|sentinelone'

# Userland agents / helpers
launchctl print system | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'
launchctl print gui/$UID | rg -i 'santa|lulu|little snitch|crowdstrike|sentinel|defender|jamf|sophos|eset|symantec'

# Inspect code-signing and entitlements of a defensive app
codesign -dvv --entitlements :- /Applications/SomeAgent.app

# Check common TCC grants used by sensors / telemetry tools
for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
[ -f "$db" ] || continue
echo "== $db =="
sqlite3 "$db" 'SELECT service,client,auth_value,last_modified FROM access WHERE service IN ("kTCCServiceSystemPolicyAllFiles","kTCCServiceEndpointSecurityClient") ORDER BY last_modified DESC;'
done
```
यदि `systemextensionsctl list` किसी sensor को **`[activated enabled]`** दिखाता है, तो यह आमतौर पर extension के वास्तव में live होने का सबसे तेज़ संकेत है। **macOS 15 Sequoia और उसके बाद के संस्करणों** पर MDM विशिष्ट security extensions को UI से **non-removable** भी चिह्नित कर सकता है, इसलिए "इसे System Settings से disable करें" अब सुरक्षित धारणा नहीं है। Internals के लिए [macOS System Extensions](mac-os-architecture/macos-system-extensions.md) देखें।

## Recent native telemetry जिसे defenders consume कर सकते हैं

हाल के macOS releases ने कुछ ऐसे user-driven bypasses को, जिन्हें पहले detect करना कठिन था, blue teams के लिए अधिक noisy बना दिया है:

- **macOS 15+**: Endpoint Security clients **`gatekeeper_user_override`** events प्राप्त कर सकते हैं, इसलिए manual Gatekeeper bypasses को centrally log किया जा सकता है।
- **Current macOS Endpoint Security tooling** **XProtect malware detection** events को भी ingest कर सकता है, जिससे यह confirm करना आसान हो जाता है कि Apple ने endpoint पर पहले से क्या detect किया है।
- **macOS 15.4+**: Endpoint Security में **`tcc_modify`** जोड़ा गया है, जिससे defenders को TCC grants/revokes को monitor करने का समर्थित तरीका मिल गया है, बजाय TCC debug logs को scrape करने के।<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
यह defenders और self-assessment करने वाले red teamers—दोनों के लिए उपयोगी है: यदि target के पास mature ES-based stack है, तो **user-approved Gatekeeper / TCC bypass chains शायद पहले की तुलना में कहीं अधिक visible हो सकती हैं**। इन protections की background के लिए [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) और [TCC](macos-security-protections/macos-tcc/README.md) देखें।

## संदर्भ

- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
