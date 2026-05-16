# macOS Defensive Apps

{{#include ../../banners/hacktricks-training.md}}

## Firewalls

- [**Little Snitch**](https://www.obdev.at/products/littlesnitch/index.html): यह हर process द्वारा की गई हर connection की monitoring करेगा। mode पर निर्भर करते हुए (silent allow connections, silent deny connection and alert) यह **हर बार जब कोई नई connection stablished होती है, आपको alert दिखाएगा**। इसमें यह सारी information देखने के लिए एक बहुत अच्छा GUI भी है।
- [**LuLu**](https://objective-see.org/products/lulu.html): Objective-See firewall. यह एक basic firewall है जो suspicious connections के लिए आपको alert करेगा (इसमें GUI है, लेकिन यह Little Snitch जितना fancy नहीं है)।

## Persistence detection

- [**KnockKnock**](https://objective-see.org/products/knockknock.html): Objective-See application जो कई locations में search करेगा जहाँ **malware could be persisting** (यह one-shot tool है, monitoring service नहीं)।
- [**BlockBlock**](https://objective-see.org/products/blockblock.html): KnockKnock की तरह, persistence generate करने वाले processes की monitoring करके।

## Keyloggers detection

- [**ReiKey**](https://objective-see.org/products/reikey.html): Objective-See application जो keyboard "event taps" install करने वाले **keyloggers** को ढूँढने के लिए है

## Endpoint telemetry / execution control

- [**Santa**](https://santa.dev/): macOS के लिए Binary authorization और monitoring system. यह code run होने से पहले **`exec`** events को authorize करने के लिए एक **Endpoint Security** client का उपयोग करता है, इसलिए enterprise fleets में यह आम है जो केवल post-execution detection की बजाय **allowlisting/denylisting** पर केंद्रित होते हैं।
- [**Mac Monitor**](https://github.com/redcanaryco/mac-monitor): Procmon-like macOS dynamic analysis tool. यह **Endpoint Security telemetry** (process, file, interprocess, login, और XProtect-related events) ingest करता है और यह समझने में उपयोगी है कि एक mature ES-based sensor वास्तव में क्या observe कर सकता है।
- [**ProcessMonitor / FileMonitor / DNSMonitor**](https://objective-see.org/products/utilities.html): **process**, **file**, और **DNS** telemetry के लिए lightweight Objective-See tools. Modern macOS पर इनके लिए extra prerequisites जैसे **root**, **Terminal Full Disk Access**, या **System/Network Extension approval** की आवश्यकता होती है। अधिक instrumentation ideas के लिए [macOS app inspection/debugging and fuzzing](macos-apps-inspecting-debugging-and-fuzzing/README.md) के बारे में यह दूसरा page देखें।

## Quick triage of defensive tooling

Most modern macOS security products run as some combination of **System Extensions / Endpoint Security clients**, **launchd agents/daemons**, and applications with **Full Disk Access**. A quick operator checklist:
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
If `systemextensionsctl list` दिखाता है कि कोई sensor **`[activated enabled]`** है, तो यह आमतौर पर सबसे तेज़ संकेत है कि extension वास्तव में live है। **macOS 15 Sequoia और बाद के versions** पर, MDM कुछ specific security extensions को **UI से non-removable** भी mark कर सकता है, इसलिए "इसे System Settings से disable कर दो" अब safe assumption नहीं है। Internals के लिए देखें [macOS System Extensions](mac-os-architecture/macos-system-extensions.md).

## Recent native telemetry defenders can consume

Recent macOS releases ने कुछ पहले से annoying-to-detect user-driven bypasses को blue teams के लिए और ज़्यादा noisy बना दिया है:

- **macOS 15+**: Endpoint Security clients **`gatekeeper_user_override`** events receive कर सकते हैं, इसलिए manual Gatekeeper bypasses centrally log किए जा सकते हैं।
- **Current macOS Endpoint Security tooling** अब **XProtect malware detection** events भी ingest कर सकती है, जिससे यह confirm करना आसान हो जाता है कि endpoint पर Apple ने already क्या detect किया था।
- **macOS 15.4+**: Endpoint Security **`tcc_modify`** जोड़ता है, जो आखिरकार defenders को **TCC grants/revokes** monitor करने का supported तरीका देता है, बजाय TCC debug logs scrape करने के।
```bash
# Gatekeeper user overrides
sudo eslogger gatekeeper_user_override

# XProtect detections
sudo eslogger xp_malware_detected

# macOS 15.4+
sudo eslogger tcc_modify
```
यह defenders और self-assessment करने वाले red teamers दोनों के लिए उपयोगी है: अगर target के पास mature ES-based stack है, तो **user-approved Gatekeeper / TCC bypass chains पहले की तुलना में कहीं अधिक visible हो सकती हैं**। इन protections के बारे में background के लिए, देखें [Gatekeeper / Quarantine / XProtect](macos-security-protections/macos-gatekeeper.md) और [TCC](macos-security-protections/macos-tcc/README.md)।

## References

- [**Objective-See - TCCing is Believing! Apple finally adds TCC events to Endpoint Security!**](https://objective-see.org/blog/blog_0x7F.html)
- [**Red Canary - Introducing: Mac Monitor**](https://redcanary.com/blog/threat-detection/mac-monitor/)

{{#include ../../banners/hacktricks-training.md}}
