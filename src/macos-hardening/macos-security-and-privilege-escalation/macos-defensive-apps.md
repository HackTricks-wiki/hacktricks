# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): यह प्रत्येक process द्वारा बनाए गए हर connection को monitor करेगा। mode (silent allow connections, silent deny connection और alert) के आधार पर, हर बार नया connection स्थापित होने पर यह **आपको एक alert दिखाएगा**। इसमें यह सारी जानकारी देखने के लिए एक बहुत अच्छा GUI भी है।
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall। यह एक basic firewall है जो आपको suspicious connections के बारे में alert करेगा (इसमें GUI है, लेकिन यह Little Snitch जितना fancy नहीं है)।

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See application जो उन कई locations में search करेगा जहां **malware persist कर सकता है** (यह one-shot tool है, monitoring service नहीं)।
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): Persistence generate करने वाले processes को monitor करके KnockKnock की तरह काम करता है।

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): **keyloggers** को खोजने के लिए Objective-See application, जो keyboard "event taps" install करते हैं।

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS के लिए Binary authorization और monitoring system। यह code चलने से पहले **`exec`** events को authorize करने के लिए **Endpoint Security** client का उपयोग करता है, इसलिए यह केवल post-execution detection के बजाय **allowlisting/denylisting** पर केंद्रित enterprise fleets में आम है।
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon जैसा macOS dynamic analysis tool। यह **Endpoint Security telemetry** (process, file, interprocess, login और XProtect-related events) को ingest करता है और यह समझने में उपयोगी है कि एक mature ES-based sensor वास्तव में क्या observe कर सकता है।<sup>[[2]](#references)</sup>
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file** और **DNS** telemetry के लिए lightweight Objective-See tools। आधुनिक macOS पर इनके लिए **root**, **Terminal Full Disk Access**, या **System/Network Extension approval** जैसी अतिरिक्त prerequisites होती हैं। अधिक instrumentation ideas के लिए [macOS app inspection/debugging के बारे में यह अन्य page](macos-apps-inspecting-debugging-and-fuzzing/README.md) देखें।

## Defensive tooling की Quick triage

अधिकांश आधुनिक macOS security products **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, और **Full Disk Access** वाले applications के किसी संयोजन के रूप में run होते हैं। एक quick operator checklist:
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
यदि `systemextensionsctl list` में कोई sensor **`[activated enabled]`** दिखाता है, तो यह आमतौर पर सबसे तेज़ संकेत होता है कि extension वास्तव में live है। **macOS 15 Sequoia और बाद के संस्करणों** पर MDM विशिष्ट security extensions को UI से **non-removable** भी चिह्नित कर सकता है, इसलिए "System Settings से disable करें" अब सुरक्षित धारणा नहीं है। Internals के लिए [macOS System Extensions](mac-os-architecture/macos-system-extensions.md) देखें।

## हाल की native telemetry, जिसे defenders consume कर सकते हैं

हाल के macOS releases ने पहले detect करने में परेशान करने वाले कुछ user-driven bypasses को blue teams के लिए अधिक स्पष्ट बना दिया है:

- **macOS 15+**: Endpoint Security clients को **`gatekeeper_user_override`** events प्राप्त हो सकते हैं, इसलिए manual Gatekeeper bypasses को centrally log किया जा सकता है।
- **Current macOS Endpoint Security tooling** अब **XProtect malware detection** events भी ingest कर सकता है, जिससे यह confirm करना आसान हो जाता है कि Apple ने endpoint पर पहले से क्या detect किया है।
- **macOS 15.4+**: Endpoint Security में **`tcc_modify`** जोड़ा गया है, जो अंततः defenders को TCC debug logs को scrape करने के बजाय **TCC grants/revokes** monitor करने का supported तरीका देता है।<sup>[[1]](#references)</sup>
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
यह defenders और self-assessment करने वाले red teamers, दोनों के लिए उपयोगी है: यदि target के पास mature ES-based stack है, तो **user-approved Gatekeeper / TCC bypass chains पहले की तुलना में कहीं अधिक दिखाई दे सकती हैं**। इन protections की पृष्ठभूमि के लिए [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) और [TCC](macos-security-protections/macos-tcc/README.md) देखें।

## संदर्भ


- [1] [Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!](https://objective-see.org/blog/blog_0x7F.html)
- [2] [Red Canary - Introducing: Mac Monitor](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
