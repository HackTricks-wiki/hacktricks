# macOS Launch/Environment-Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Launch constraints wurden in macOS eingeführt, um die Sicherheit zu erhöhen, indem **reguliert wird, wie, von wem und von wo aus ein Prozess gestartet werden kann**. Sie wurden in macOS Ventura eingeführt und bieten ein Framework, das **jede System-Binary in verschiedene constraint categories** einteilt, die im **trust cache** definiert sind, einer Liste mit System-Binaries und ihren jeweiligen Hashes. Diese Constraints gelten für jede ausführbare Binary im System und umfassen eine Reihe von **Regeln**, die die Anforderungen für das **Starten einer bestimmten Binary** festlegen. Die Regeln umfassen Self Constraints, die eine Binary erfüllen muss, Parent Constraints, die vom übergeordneten Prozess erfüllt werden müssen, sowie Responsible Constraints, die von anderen relevanten Entitäten einzuhalten sind.

Der Mechanismus wurde ab macOS Sonoma durch **Environment Constraints** auf Drittanbieter-Apps ausgeweitet. Dadurch können Entwickler ihre Apps schützen, indem sie ein **Set aus Schlüsseln und Werten für Environment Constraints** festlegen.

Du definierst **Launch-Environment- und Library-Constraints** in Constraint-Dictionaries, die du entweder in **`launchd`-Property-List-Dateien** oder in **separaten Property-List**-Dateien speicherst, die du beim Code Signing verwendest.

Es gibt 4 Arten von Constraints:

- **Self Constraints**: Constraints, die auf die **ausgeführte** Binary angewendet werden.
- **Parent Process**: Constraints, die auf den **übergeordneten Prozess** angewendet werden (zum Beispiel **`launchd`**, das einen XP-Service ausführt).
- **Responsible Constraints**: Constraints, die auf den **Prozess angewendet werden, der den Service aufruft**, in einer XPC-Kommunikation.
- **Library load constraints**: Verwende Library Load Constraints, um selektiv den Code zu beschreiben, der geladen werden kann.

Wenn also ein Prozess versucht, einen anderen Prozess zu starten — durch den Aufruf von `execve(_:_:_:)` oder `posix_spawn(_:_:_:_:_:_:)` — prüft das Betriebssystem, ob die **ausführbare** Datei ihre **eigene Self Constraint** erfüllt. Es prüft außerdem, ob die ausführbare Datei des **übergeordneten** **Prozesses** die Parent Constraint der ausführbaren Datei erfüllt und ob die ausführbare Datei des **verantwortlichen** **Prozesses** die Responsible Process Constraint der ausführbaren Datei erfüllt. Wenn eine dieser Launch Constraints nicht erfüllt ist, führt das Betriebssystem das Programm nicht aus.

Wenn beim Laden einer Library ein Teil der **Library Constraint nicht erfüllt** ist, lädt dein Prozess die Library **nicht**.

## LC Categories

Eine LC besteht aus **Facts** und **logischen Operationen** (and, or usw.), die Facts miteinander kombinieren.

Die[ **Facts, die eine LC verwenden kann, sind hier dokumentiert**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Zum Beispiel:

- is-init-proc: Ein Boolean-Wert, der angibt, ob die ausführbare Datei der Initialisierungsprozess des Betriebssystems (`launchd`) sein muss.
- is-sip-protected: Ein Boolean-Wert, der angibt, ob die ausführbare Datei eine durch System Integrity Protection (SIP) geschützte Datei sein muss.
- `on-authorized-authapfs-volume:` Ein Boolean-Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
- `on-authorized-authapfs-volume`: Ein Boolean-Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
- Cryptexes volume
- `on-system-volume:` Ein Boolean-Wert, der angibt, ob das Betriebssystem die ausführbare Datei vom aktuell gestarteten Systemvolume geladen hat.
- Innerhalb von /System...
- ...

Wenn eine Apple-Binary signiert wird, **ordnet sie sie einer LC category** innerhalb des **trust cache** zu.

- **iOS 16 LC categories** wurden [**hier reverse-engineered und dokumentiert**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Die aktuellen **LC categories (macOS 14** - Somona) wurden reverse-engineered und ihre [**Beschreibungen sind hier zu finden**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Zum Beispiel lautet Category 1:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Muss sich auf dem System- oder Cryptexes-Volume befinden.
- `launch-type == 1`: Muss ein Systemdienst sein (plist in LaunchDaemons).
- `validation-category == 1`: Ein ausführbares Betriebssystemprogramm.
- `is-init-proc`: Launchd

### Reversing von LC Categories

Weitere Informationen findest du [**hier**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), aber grundsätzlich sind sie in **AMFI (AppleMobileFileIntegrity)** definiert. Daher musst du das Kernel Development Kit herunterladen, um das **KEXT** zu erhalten. Die Symbole, die mit **`kConstraintCategory`** beginnen, sind die **interessanten**. Wenn du sie extrahierst, erhältst du einen DER-(ASN.1-)codierten Stream, den du mit dem [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) oder der Python-Bibliothek python-asn1 und ihrem Skript `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), decodieren musst. Dadurch erhältst du einen verständlicheren String.<sup>[[3]](#references)</sup>

## Umgebungs-Constraints

Dies sind die konfigurierten Launch Constraints in **Drittanbieteranwendungen**. Der Entwickler kann die **Fakten** und **logischen Operanden** auswählen, die in seiner Anwendung verwendet werden sollen, um den Zugriff auf die Anwendung selbst einzuschränken.

Die Environment Constraints einer Anwendung können mit folgendem Befehl aufgelistet werden:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

In **macOS** gibt es einige Trust Caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Unter iOS scheint sich der Trust Cache in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`** zu befinden.

> [!WARNING]
> Unter macOS auf Apple-Silicon-Geräten verweigert AMFI das Laden einer von Apple signierten Binary, wenn sie sich nicht im Trust Cache befindet.

### Trust Caches enumerieren

Die zuvor genannten Trust-Cache-Dateien liegen im Format **IMG4** und **IM4P** vor, wobei IM4P den Payload-Abschnitt des IMG4-Formats darstellt.

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
(Eine weitere Option wäre die Verwendung des Tools [**img4tool**](https://github.com/tihmstar/img4tool), das sogar auf M1 läuft, obwohl das Release alt ist, sowie für x86_64, wenn du es an den richtigen Stellen installierst).

Jetzt kannst du das Tool [**trustcache**](https://github.com/CRKatri/trustcache) verwenden, um die Informationen in einem lesbaren Format abzurufen:
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
Der Trust Cache weist die folgende Struktur auf, daher ist die **LC category die 4. Spalte**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Dann könntest du ein Script wie [**dieses**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) verwenden, um Daten zu extrahieren.

Anhand dieser Daten kannst du die Apps mit einem **Launch Constraints-Wert von `0`** überprüfen. Dies sind die Apps, die nicht eingeschränkt sind (unter [**diesem Link**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) findest du die Bedeutung der einzelnen Werte).<sup>[[6]](#references)</sup>

## Maßnahmen zur Angriffsminderung

Launch Constraints hätten mehrere ältere Angriffe verhindert, indem sie **sicherstellen, dass der Prozess nicht unter unerwarteten Bedingungen ausgeführt wird:** zum Beispiel von unerwarteten Speicherorten aus oder durch einen unerwarteten übergeordneten Prozess (wenn nur launchd ihn starten sollte).

Darüber hinaus **mindern Launch Constraints auch Downgrade-Angriffe.**

Sie **verhindern jedoch keine gängigen XPC**-Missbräuche, **Electron**-Code-Injections oder **dylib-Injections** ohne Library Validation (es sei denn, die Team-IDs, die Libraries laden dürfen, sind bekannt).<sup>[[3]](#references)</sup>

### XPC-Daemon-Schutz

In der Sonoma-Version ist die **Verantwortlichkeitskonfiguration** des Daemon-XPC-Service ein bemerkenswerter Punkt. Der XPC-Service ist für sich selbst verantwortlich, anstatt dass der verbindende Client verantwortlich ist. Dies ist im Feedback-Bericht FB13206884 dokumentiert. Diese Konfiguration könnte fehlerhaft erscheinen, da sie bestimmte Interaktionen mit dem XPC-Service ermöglicht:

- **Starten des XPC-Service**: Falls dies als Bug betrachtet wird, erlaubt diese Konfiguration nicht, den XPC-Service durch Angreifer-Code zu starten.
- **Verbinden mit einem aktiven Service**: Wenn der XPC-Service bereits läuft (möglicherweise aktiviert durch seine ursprüngliche Anwendung), gibt es keine Hindernisse für eine Verbindung mit ihm.

Das Implementieren von Constraints für den XPC-Service könnte zwar hilfreich sein, indem es **das Zeitfenster für potenzielle Angriffe verkleinert**, aber es behebt nicht das grundlegende Problem. Um die Sicherheit des XPC-Service zu gewährleisten, muss der verbindende Client grundsätzlich **effektiv validiert werden**. Dies bleibt die einzige Methode, um die Sicherheit des Service zu erhöhen. Außerdem ist zu beachten, dass die erwähnte Verantwortlichkeitskonfiguration derzeit aktiv ist, was möglicherweise nicht dem vorgesehenen Design entspricht.<sup>[[3]](#references)</sup>

### Electron-Schutz

Selbst wenn erforderlich ist, dass die Anwendung **von LaunchService geöffnet** werden muss (in den Parent-Constraints), kann dies über **`open`** (womit Umgebungsvariablen gesetzt werden können) oder über die **Launch Services API** (bei der Umgebungsvariablen angegeben werden können) erreicht werden.<sup>[[3]](#references)</sup>

### CVE-2025-43253 – Überschreiben der integrierten Constraints zum Spawn-Zeitpunkt

Launch Constraints (offiziell **lightweight code requirements**, *LWCR*) werden durch die **AMFI MAC policy** erzwungen. `posix_spawn` ermöglicht es einem Aufrufer, über **`posix_spawnattr_setmacpolicyinfo_np()`** einen beliebigen Blob an eine MAC policy zu übergeben, und AMFI akzeptierte über diesen Pfad ein vom Aufrufer bereitgestelltes LWCR-Wörterbuch. Der Bug bestand darin, dass die **vom Angreifer bereitgestellten Constraints die integrierten Constraints der Binärdatei ersetzten**, anstatt zusätzlich zu diesen geprüft zu werden:

- Erstelle ein minimales (sogar leeres) Launch-Constraints-Wörterbuch.
- Setze die **Constraint-Kategorie auf `127`**. Dies ist ein Wert, den AMFI in Spawn-Attributen akzeptiert, aber **nicht erzwingt** – AMFI protokolliert lediglich `Launch Constraint Violation (not enforcing)`, anstatt die Ausführung zu blockieren.
- Übergib es über die Spawn-Attribute, woraufhin der Prozess in einem Kontext gestartet wird, den seine tatsächlichen Self-/Parent-Constraints verhindert hätten.

Nach der Behebung werden **sowohl die integrierten als auch die bereitgestellten Constraints validiert**, sodass das bereitgestellte Wörterbuch die integrierten Constraints nicht mehr abschwächen kann.<sup>[[2]](#references)</sup>

> [!TIP]
> Dies ist das allgemeine Muster, nach dem bei der Prüfung der Constraint-Durchsetzung gesucht werden sollte: Eine API, über die nicht vertrauenswürdige Eingaben eine Policy *bereitstellen* können, ist immer dann interessant, wenn die Policy-Engine den bereitgestellten Wert als Ersatz statt als zusätzliche Anforderung behandelt.

## Referenzen

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}
