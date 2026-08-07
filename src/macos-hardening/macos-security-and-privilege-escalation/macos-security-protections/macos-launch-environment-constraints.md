# macOS-Start-/Umgebungsbeschränkungen & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Launch constraints wurden in macOS eingeführt, um die Sicherheit zu erhöhen, indem **geregelt wird, wie, von wem und von wo aus ein Prozess gestartet werden kann**. Eingeführt in macOS Ventura bieten sie ein Framework, das **jede System-Binary in verschiedene Constraint-Kategorien** einteilt, die innerhalb des **trust cache** definiert sind, einer Liste mit System-Binaries und deren jeweiligen Hashes. Diese Constraints gelten für jede ausführbare Binary im System und umfassen eine Reihe von **Regeln**, die die Anforderungen zum **Starten einer bestimmten Binary** festlegen. Die Regeln beinhalten Self Constraints, die eine Binary erfüllen muss, Parent Constraints, die vom übergeordneten Prozess erfüllt werden müssen, sowie Responsible Constraints, die von anderen relevanten Entitäten eingehalten werden müssen.<sup>[[1]](#references)[[4]](#references)</sup>

Der Mechanismus wurde ab macOS Sonoma durch **Environment Constraints** auf Third-Party-Apps ausgeweitet. Dadurch können Entwickler ihre Apps schützen, indem sie ein **Set aus Schlüsseln und Werten für Environment Constraints** festlegen.<sup>[[5]](#references)</sup>

Du definierst **Launch-Umgebungs- und Library-Constraints** in Constraint-Dictionaries, die du entweder in **`launchd`-Property-List-Dateien** speicherst oder in **separaten Property-List-Dateien**, die du beim Code Signing verwendest.<sup>[[5]](#references)</sup>

Es gibt 4 Arten von Constraints:

- **Self Constraints**: Constraints, die auf die **laufende** Binary angewendet werden.
- **Parent Process**: Constraints, die auf den **übergeordneten Prozess** des Prozesses angewendet werden (zum Beispiel **`launchd`**, das einen XP-Service ausführt)
- **Responsible Constraints**: Constraints, die auf den **Prozess angewendet werden, der den Service** in einer XPC-Kommunikation aufruft
- **Library load constraints**: Verwende Library Load Constraints, um selektiv zu beschreiben, welcher Code geladen werden kann

Wenn also ein Prozess versucht, einen anderen Prozess zu starten — durch den Aufruf von `execve(_:_:_:)` oder `posix_spawn(_:_:_:_:_:_:)` — überprüft das Betriebssystem, ob die **ausführbare** Datei ihre **eigene Self Constraint** erfüllt. Es überprüft außerdem, ob die ausführbare Datei des **übergeordneten** **Prozesses** die **Parent Constraint** der ausführbaren Datei erfüllt und ob die ausführbare Datei des **verantwortlichen** **Prozesses** die Responsible Process Constraint der ausführbaren Datei erfüllt. Wenn eine dieser Launch Constraints nicht erfüllt ist, führt das Betriebssystem das Programm nicht aus.

Wenn beim Laden einer Library ein Teil der **Library Constraint nicht erfüllt** ist, lädt dein Prozess die Library **nicht**.

## LC-Kategorien

Eine LC besteht aus **Fakten** und **logischen Operationen** (and, or usw.), die Fakten miteinander kombinieren.

Die[ **Fakten, die eine LC verwenden kann, sind dokumentiert**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Zum Beispiel:

- is-init-proc: Ein boolescher Wert, der angibt, ob die ausführbare Datei der Initialisierungsprozess des Betriebssystems (`launchd`) sein muss.
- is-sip-protected: Ein boolescher Wert, der angibt, ob die ausführbare Datei eine durch den System Integrity Protection (SIP) geschützte Datei sein muss.
- `on-authorized-authapfs-volume:` Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
- `on-authorized-authapfs-volume`: Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
- Cryptexes volume
- `on-system-volume:`Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei vom derzeit gebooteten System-Volume geladen hat.
- Innerhalb von /System...
- ...

Wenn eine Apple-Binary signiert wird, **ordnet sie sie einer LC-Kategorie** innerhalb des **trust cache** zu.

- **iOS-16-LC-Kategorien** wurden [**hier reverse-engineered und dokumentiert**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Die aktuellen **LC-Kategorien (macOS 14** - Somona) wurden reverse-engineered und ihre [**Beschreibungen sind hier zu finden**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Zum Beispiel ist Kategorie 1:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Muss sich auf dem System- oder Cryptexes-Volume befinden.
- `launch-type == 1`: Muss ein Systemdienst sein (plist in LaunchDaemons).
- `validation-category == 1`: Eine ausführbare Datei des Betriebssystems.
- `is-init-proc`: Launchd

### Reversing von LC-Kategorien

Weitere Informationen findest du [**hier**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), aber grundsätzlich sind sie in **AMFI (AppleMobileFileIntegrity)** definiert. Daher musst du das Kernel Development Kit herunterladen, um die **KEXT** zu erhalten. Die Symbole, die mit **`kConstraintCategory`** beginnen, sind die **interessanten**. Wenn du sie extrahierst, erhältst du einen DER-(ASN.1-)codierten Stream, den du mit [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) oder der python-asn1 library und ihrem `dump.py`-Skript, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), decodieren musst. Dadurch erhältst du einen verständlicheren String.<sup>[[3]](#references)[[8]](#references)</sup>

## Umgebungsbeschränkungen

Dies sind die in **Drittanbieteranwendungen** konfigurierten Launch Constraints. Der Entwickler kann die **Fakten** und **logischen Operanden** auswählen, die in seiner Anwendung verwendet werden sollen, um den Zugriff auf die Anwendung selbst einzuschränken.

Die Environment Constraints einer Anwendung können mit folgendem Befehl aufgelistet werden:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

In **macOS** gibt es einige Trust Caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Unter iOS befinden sie sich offenbar in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Wenn ein von Apple signiertes Binary unter macOS auf Apple-Silicon-Geräten nicht im Trust Cache enthalten ist, verweigert AMFI das Laden.

### Trust Caches auflisten

Die zuvor genannten Trust-Cache-Dateien liegen im Format **IMG4** und **IM4P** vor, wobei IM4P den Payload-Abschnitt eines IMG4-Formats darstellt.

Du kannst [**pyimg4**](https://github.com/m1stadev/PyIMG4) verwenden, um den Payload der Datenbanken zu extrahieren:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Eine weitere Option wäre die Verwendung des Tools [**img4tool**](https://github.com/tihmstar/img4tool), das auch auf M1 ausgeführt werden kann, selbst wenn das Release alt ist, sowie für x86_64, wenn es an den richtigen Stellen installiert wird).

Nun kannst du das Tool [**trustcache**](https://github.com/CRKatri/trustcache) verwenden, um die Informationen in einem lesbaren Format zu erhalten:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Der Trust Cache folgt der folgenden Struktur, daher ist die **LC-Kategorie die 4. Spalte**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Dann könntest du ein Skript wie [**dieses**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) verwenden, um Daten zu extrahieren.

Anhand dieser Daten kannst du die Apps mit einem **Launch-Constraints-Wert von `0`** überprüfen. Das sind diejenigen, für die keine Constraints gelten (siehe [**hier**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), wofür die einzelnen Werte stehen).<sup>[[6]](#references)</sup>

## Maßnahmen zur Angriffsabwehr

Launch Constraints hätten mehrere ältere Angriffe verhindert, indem sie **sicherstellen, dass der Prozess nicht unter unerwarteten Bedingungen ausgeführt wird:** beispielsweise von unerwarteten Speicherorten aus oder durch einen unerwarteten übergeordneten Prozess (wenn nur launchd ihn starten sollte).

Darüber hinaus **verhindern Launch Constraints auch Downgrade-Angriffe.**

Sie **verhindern jedoch keine herkömmlichen XPC**-Missbräuche, **Electron**-Code-Injections oder **dylib-Injections** ohne Library Validation (außer die Team-IDs, die Libraries laden dürfen, sind bekannt).<sup>[[3]](#references)</sup>

### XPC-Daemon-Schutz

In der Sonoma-Version ist die **Verantwortlichkeitskonfiguration** des XPC-Daemons ein bemerkenswerter Punkt. Der XPC-Service ist für sich selbst verantwortlich, anstatt dass der verbindende Client verantwortlich ist. Dies ist im Feedback-Bericht FB13206884 dokumentiert. Dieses Setup mag fehlerhaft erscheinen, da es bestimmte Interaktionen mit dem XPC-Service ermöglicht:

- **Starten des XPC-Services**: Wenn dieses Setup als Bug betrachtet wird, erlaubt es nicht, den XPC-Service durch Angreifer-Code zu starten.
- **Verbindung zu einem aktiven Service**: Wenn der XPC-Service bereits läuft (möglicherweise durch seine ursprüngliche Anwendung aktiviert), gibt es keine Hindernisse, sich mit ihm zu verbinden.

Constraints für den XPC-Service zu implementieren, könnte zwar hilfreich sein, um **das Zeitfenster für potenzielle Angriffe zu verkleinern**, es behandelt jedoch nicht das Hauptproblem. Um die Sicherheit des XPC-Services grundsätzlich zu gewährleisten, muss **der verbindende Client effektiv validiert werden**. Dies bleibt die einzige Methode, um die Sicherheit des Services zu stärken. Außerdem ist zu beachten, dass die erwähnte Verantwortlichkeitskonfiguration derzeit aktiv ist, was möglicherweise nicht dem vorgesehenen Design entspricht.<sup>[[3]](#references)</sup>

### Electron-Schutz

Selbst wenn verlangt wird, dass die Anwendung **durch LaunchService geöffnet** werden muss (in den Constraints des übergeordneten Prozesses), kann dies mit **`open`** (womit Umgebungsvariablen gesetzt werden können) oder über die **Launch-Services-API** (bei der Umgebungsvariablen angegeben werden können) erreicht werden.<sup>[[3]](#references)</sup>

### CVE-2025-43253 – Überschreiben der integrierten Constraints zum Spawn-Zeitpunkt

Launch Constraints (offiziell **lightweight code requirements**, *LWCR*) werden durch die **AMFI-MAC-Richtlinie** erzwungen. `posix_spawn` ermöglicht es einem Aufrufer, über **`posix_spawnattr_setmacpolicyinfo_np()`** einen beliebigen Blob an eine MAC-Richtlinie zu übergeben, und AMFI akzeptierte über diesen Pfad ein vom Aufrufer bereitgestelltes LWCR-Wörterbuch. Der Bug bestand darin, dass die **vom Angreifer bereitgestellten Constraints die integrierten Constraints der Binärdatei ersetzten**, anstatt zusätzlich zu diesen geprüft zu werden:

- Erstelle ein minimales (sogar leeres) Launch-Constraints-Wörterbuch.
- Setze die **Constraint-Kategorie auf `127`**, einen Wert, den AMFI in Spawn-Attributen erlaubt, aber **nicht erzwingt** – stattdessen wird nur `Launch Constraint Violation (not enforcing)` protokolliert, anstatt die Ausführung zu blockieren.
- Übergib es über die Spawn-Attribute, woraufhin der Prozess in einem Kontext gestartet wird, den seine tatsächlichen Self-/Parent-Constraints verhindert hätten.

Nach der Behebung werden **sowohl die integrierten als auch die bereitgestellten Constraints validiert**, sodass das bereitgestellte Wörterbuch die integrierten Constraints nicht mehr abschwächen kann.<sup>[[2]](#references)</sup>

> [!TIP]
> Dies ist das allgemeine Muster, nach dem bei der Prüfung der Constraint-Durchsetzung gesucht werden sollte: Eine API, die es nicht vertrauenswürdigen Eingaben ermöglicht, eine Richtlinie *bereitzustellen*, ist interessant, wenn die Policy-Engine den bereitgestellten Wert als Ersatz statt als zusätzliche Anforderung behandelt.

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Umgehen von Launch Constraints auf macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch- und Environment-Constraints im Detail – theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Warum wird eine System-App oder ein Command-Tool nicht ausgeführt? Launch Constraints und Trust Caches – The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Schütze deine Mac-App mit Environment Constraints – WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Beschreibung der in iOS 16 eingeführten Launch Constraints (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Jenseits der guten alten `LaunchAgents` – hier geht es darum](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}
