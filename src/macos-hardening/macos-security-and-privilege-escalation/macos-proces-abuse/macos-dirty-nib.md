# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB bezeichnet den Missbrauch von Interface-Builder-Dateien (.xib/.nib) innerhalb eines signierten macOS-App-Bundles, um vom Angreifer kontrollierte Logik im Zielprozess auszuführen und dadurch dessen Entitlements und TCC-Berechtigungen zu übernehmen. Diese Technik wurde ursprünglich von xpn (MDSec) dokumentiert und später von Sector7 verallgemeinert und erheblich erweitert. Sector7 behandelte außerdem Apples Gegenmaßnahmen in macOS 13 Ventura und macOS 14 Sonoma.<sup>[[1]](#references)[[2]](#references)</sup> Hintergrundinformationen und ausführliche Analysen finden sich in den Referenzen am Ende.

> TL;DR
> • Vor macOS 13 Ventura: Das Ersetzen der MainMenu.nib eines Bundles (oder eines anderen beim Start geladenen NIB) konnte zuverlässig process injection und häufig auch eine privilege escalation erreichen.
> • Seit macOS 13 (Ventura) und weiter verbessert in macOS 14 (Sonoma): Eine gründliche Verifizierung beim ersten Start, Bundle-Schutz, Launch Constraints und die neue TCC-Berechtigung „App Management“ verhindern weitgehend das nachträgliche Manipulieren von NIBs durch nicht verbundene Apps. Angriffe können in speziellen Fällen weiterhin möglich sein (z. B. bei Tooling desselben Entwicklers, das eigene Apps verändert, oder bei Terminals, denen der Benutzer App Management/Full Disk Access gewährt hat).

## Was sind NIB/XIB-Dateien?

Nib-Dateien (kurz für NeXT Interface Builder) sind serialisierte UI-Objektgraphen, die von AppKit-Apps verwendet werden. Modernes Xcode speichert bearbeitbare XML-.xib-Dateien, die beim Build in .nib-Dateien kompiliert werden. Eine typische App lädt ihre Haupt-UI über `NSApplicationMain()`, das den Schlüssel `NSMainNibFile` aus der `Info.plist` der App liest und den Objektgraphen zur Laufzeit instanziiert.

Wichtige Punkte, die den Angriff ermöglichen:
- Das Laden von NIBs instanziiert beliebige Objective-C-Klassen, ohne dass diese NSSecureCoding implementieren müssen (Apples NIB-Loader greift auf `init`/`initWithFrame:` zurück, wenn `initWithCoder:` nicht verfügbar ist).
- Cocoa Bindings können missbraucht werden, um Methoden aufzurufen, während NIBs instanziiert werden, einschließlich verketteter Aufrufe, die keine Benutzerinteraktion erfordern.


## Dirty-NIB-Injection-Prozess (Angreiferperspektive)

Der klassische Ablauf vor Ventura:
1) Eine bösartige .xib-Datei erstellen
- Ein `NSAppleScript`-Objekt (oder andere „Gadget“-Klassen wie `NSTask`) hinzufügen.
- Ein `NSTextField` hinzufügen, dessen Titel den Payload enthält (z. B. AppleScript oder Befehlsargumente).
- Ein oder mehrere `NSMenuItem`-Objekte hinzufügen, die über Bindings so verknüpft sind, dass sie Methoden auf dem Zielobjekt aufrufen.

2) Automatische Auslösung ohne Mausklicks
- Bindings verwenden, um das Target/Selector eines Menüeintrags zu setzen, und anschließend die private Methode `_corePerformAction` aufrufen, damit die Aktion automatisch ausgeführt wird, wenn das NIB geladen wird. Dadurch ist kein Benutzerklick auf eine Schaltfläche erforderlich.

Minimales Beispiel einer Auto-Trigger-Kette innerhalb einer .xib-Datei (zur besseren Übersicht gekürzt):
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
Dies ermöglicht die Ausführung beliebiger AppleScript-Befehle im Zielprozess beim Laden des nib.<sup>[[1]](#references)</sup> Erweiterte Chains können:
- Beliebige AppKit-Klassen instanziieren (z. B. `NSTask`) und Methoden ohne Argumente wie `-launch` aufrufen.
- Beliebige Selektoren mit Objektargumenten über den oben beschriebenen binding trick aufrufen.
- AppleScriptObjC.framework laden, um eine Brücke zu Objective-C herzustellen und sogar ausgewählte C APIs aufzurufen.
- Auf älteren Systemen, die noch Python.framework enthalten, eine Brücke zu Python herstellen und anschließend `ctypes` verwenden, um beliebige C-Funktionen aufzurufen (Forschung von Sector7).<sup>[[2]](#references)</sup>

3) Das nib der App ersetzen
- target.app an einen beschreibbaren Ort kopieren, z. B. `Contents/Resources/MainMenu.nib` durch das bösartige nib ersetzen und target.app ausführen. Vor Ventura führte Gatekeeper nach einer einmaligen assessment bei nachfolgenden Starts nur oberflächliche Signaturprüfungen durch, sodass nicht ausführbare Ressourcen (wie .nib) nicht erneut validiert wurden.

Beispiel für ein AppleScript payload für einen sichtbaren Test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS-Schutzmaßnahmen (Ventura/Monterey/Sonoma/Sequoia)

Apple hat mehrere systemweite Schutzmaßnahmen eingeführt, die die Durchführbarkeit von Dirty NIB unter modernen macOS-Versionen deutlich einschränken:<sup>[[2]](#references)</sup>
- Tiefgreifende Überprüfung beim ersten Start und Bundle-Schutz (macOS 13 Ventura)
- Beim ersten Start einer beliebigen App (unter Quarantäne oder nicht) werden alle Bundle-Ressourcen durch eine umfassende Signaturprüfung abgedeckt. Danach wird das Bundle geschützt: Nur Apps desselben Entwicklers (oder vom jeweiligen App ausdrücklich erlaubte Apps) dürfen dessen Inhalte ändern. Andere Apps benötigen die neue TCC-Berechtigung „App Management“, um in das Bundle einer anderen App zu schreiben.
- Launch Constraints (macOS 13 Ventura)
- System-/Apple-gebundelte Apps können nicht an einen anderen Ort kopiert und dort gestartet werden; dadurch funktioniert der Ansatz „nach /tmp kopieren, patchen, ausführen“ für OS-Apps nicht mehr.
- Verbesserungen in macOS 14 Sonoma
- Apple hat App Management weiter gehärtet und bekannte Bypasses (z. B. CVE‑2023‑40450), auf die Sector7 hingewiesen hat, behoben. Python.framework wurde bereits zuvor entfernt (macOS 12.3), wodurch einige Privilege-Escalation-Ketten nicht mehr funktionieren.
- Änderungen an Gatekeeper/Quarantine
- Eine umfassendere Diskussion zu Gatekeeper, Provenance und Änderungen bei Assessments, die diese Technik beeinflusst haben, findest du auf der unten referenzierten Seite.

> Praktische Auswirkungen
> • Unter Ventura+ kannst du das .nib einer Third-Party-App im Allgemeinen nicht ändern, sofern dein Prozess nicht über App Management verfügt oder dieselbe Team ID wie das Ziel verwendet (z. B. Developer-Tooling).
> • Die Vergabe von App Management oder Full Disk Access an Shells/Terminals öffnet diese Angriffsfläche effektiv für alles erneut, was Code im Kontext dieses Terminals ausführen kann.


### Umgang mit Launch Constraints

Launch Constraints verhindern seit Ventura die Ausführung vieler Apple-Apps von nicht standardmäßigen Speicherorten. Wenn du auf Workflows aus der Zeit vor Ventura angewiesen warst, bei denen eine Apple-App in ein temporäres Verzeichnis kopiert, `MainMenu.nib` geändert und anschließend gestartet wurde, musst du damit rechnen, dass dies unter >= 13.0 fehlschlägt.


## Auflisten von Zielen und nibs (nützlich für Research / Legacy-Systeme)

- Apps finden, deren Benutzeroberfläche durch nib gesteuert wird:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Finde potenzielle nib-Ressourcen innerhalb eines Bundles:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Code-Signaturen gründlich validieren (schlägt fehl, wenn du Ressourcen manipuliert und nicht erneut signiert hast):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Hinweis: Auf modernen macOS-Versionen werden Sie beim Versuch, ohne entsprechende Autorisierung in das Bundle einer anderen App zu schreiben, ebenfalls durch den Bundle-Schutz/TCC blockiert.


## Erkennungs- und DFIR-Tipps

- Überwachung der Dateiintegrität von Bundle-Ressourcen
- Achten Sie auf Änderungen an mtime/ctime von `Contents/Resources/*.nib` und anderen nicht ausführbaren Ressourcen in installierten Apps.
- Unified Logs und Prozessverhalten
- Überwachen Sie unerwartete AppleScript-Ausführung innerhalb von GUI-Apps sowie Prozesse, die AppleScriptObjC oder Python.framework laden. Beispiel:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktive Prüfungen
- Führen Sie regelmäßig `codesign --verify --deep` für kritische Apps aus, um sicherzustellen, dass die Ressourcen intakt bleiben.
- Berechtigungskontext
- Prüfen Sie, wer oder was über TCC-„App Management“ oder Full Disk Access verfügt (insbesondere Terminals und Management-Agents). Wenn Sie diese Berechtigungen aus allgemeinen Shells entfernen, verhindern Sie das triviale erneute Aktivieren von Dirty NIB-ähnlicher Manipulation.


## Defensive Härtung (Entwickler und Defender)

- Bevorzugen Sie programmgesteuerte Benutzeroberflächen oder beschränken Sie, was aus nibs instanziiert wird. Vermeiden Sie leistungsfähige Klassen (z. B. `NSTask`) in nib graphs und vermeiden Sie Bindings, die indirekt Selector-Aufrufe auf beliebigen Objekten auslösen.
- Verwenden Sie die hardened runtime mit Library Validation (bei modernen Apps bereits Standard). Dies verhindert nib injection zwar nicht direkt, blockiert jedoch das einfache Laden nativen Codes und zwingt Angreifer zu scripting-only payloads.
- Fordern Sie in allgemeinen Tools keine weitreichenden App-Management-Berechtigungen an und verlassen Sie sich nicht darauf. Wenn MDM App Management erfordert, trennen Sie diesen Kontext von benutzergesteuerten Shells.
- Überprüfen Sie regelmäßig die Integrität Ihres App-Bundles und sorgen Sie dafür, dass Ihre Update-Mechanismen Bundle-Ressourcen automatisch wiederherstellen.


## Weiterführende Informationen in HackTricks

Erfahren Sie mehr über Gatekeeper, Quarantäne und Provenance-Änderungen, die diese Technik beeinflussen:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referenzen

- [1] [xpn – DirtyNIB (ursprünglicher Write-up mit Pages-Beispiel)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): Ausnutzung aller macOS-Apps mithilfe von nib-Dateien (5. April 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
