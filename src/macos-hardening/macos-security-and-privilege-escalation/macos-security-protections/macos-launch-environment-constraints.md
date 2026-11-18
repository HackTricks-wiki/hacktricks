# macOS Launch-/Umgebungsbeschränkungen & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Grundlegende Informationen

Launch-Beschränkungen wurden in macOS eingeführt, um die Sicherheit zu erhöhen, indem **geregelt wird, wie, von wem und von wo aus ein Prozess gestartet werden kann**. Sie wurden mit macOS Ventura eingeführt und bieten ein Framework, das **jede System-Binärdatei verschiedenen Beschränkungskategorien zuordnet**, die im **Trust Cache** definiert sind, einer Liste mit System-Binärdateien und ihren jeweiligen Hashes. Diese Beschränkungen gelten für alle ausführbaren Binärdateien im System und umfassen eine Reihe von **Regeln**, die Anforderungen für das **Starten einer bestimmten Binärdatei** festlegen. Dazu gehören Self Constraints, die eine Binärdatei erfüllen muss, Parent Constraints, die ihr übergeordneter Prozess erfüllen muss, und Responsible Constraints, an die sich andere relevante Entitäten halten müssen.<sup>[[1]](#references)[[4]](#references)</sup>

Ab macOS Sonoma wird der Mechanismus durch **Environment Constraints** auf Apps von Drittanbietern ausgeweitet. Entwickler können ihre Apps schützen, indem sie eine **Reihe von Schlüsseln und Werten für Umgebungsbeschränkungen** festlegen.<sup>[[5]](#references)</sup>

**Launch-Umgebungs- und Bibliotheksbeschränkungen** werden in Constraint-Dictionaries definiert, die entweder in **`launchd`-Property-List-Dateien** oder in **separaten Property-List-Dateien** gespeichert werden, die beim Code Signing verwendet werden.<sup>[[5]](#references)</sup>

Es gibt 4 Arten von Beschränkungen:

- **Self Constraints**: Beschränkungen, die für die **laufende** Binärdatei gelten.
- **Parent Process**: Beschränkungen, die für den **übergeordneten Prozess** gelten (zum Beispiel **`launchd`**, das einen XPC-Dienst ausführt)
- **Responsible Constraints**: Beschränkungen, die für den **Prozess gelten, der den Dienst aufruft**, wenn eine XPC-Kommunikation stattfindet
- **Library load constraints**: Verwenden Sie Library-Load-Beschränkungen, um gezielt festzulegen, welcher Code geladen werden kann

Wenn ein Prozess also versucht, einen anderen Prozess zu starten – indem er `execve(_:_:_:)` oder `posix_spawn(_:_:_:_:_:_:)` aufruft –, überprüft das Betriebssystem, ob die **ausführbare** Datei ihre **eigene Self Constraint** **erfüllt**. Außerdem wird geprüft, ob die ausführbare Datei des **übergeordneten Prozesses** die **Parent Constraint** der ausführbaren Datei erfüllt und ob die ausführbare Datei des **verantwortlichen Prozesses** die **Responsible Constraint des ausführbaren Prozesses** erfüllt. Wird eine dieser Launch-Beschränkungen nicht erfüllt, führt das Betriebssystem das Programm nicht aus.

Wenn beim Laden einer Bibliothek ein Teil der **Library Constraint nicht erfüllt ist**, **lädt** Ihr Prozess die Bibliothek **nicht**.

## LC-Kategorien

Eine LC besteht aus **Fakten** und **logischen Operationen** (and, or usw.), die Fakten miteinander kombinieren.

Die [**Fakten, die eine LC verwenden kann, sind dokumentiert**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Zum Beispiel:

- is-init-proc: Ein boolescher Wert, der angibt, ob die ausführbare Datei der Initialisierungsprozess des Betriebssystems (`launchd`) sein muss.
- is-sip-protected: Ein boolescher Wert, der angibt, ob die ausführbare Datei eine durch System Integrity Protection (SIP) geschützte Datei sein muss.
- `on-authorized-authapfs-volume:` Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
- `on-authorized-authapfs-volume`: Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
  - Cryptexes-Volume
- `on-system-volume:` Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei vom aktuell gestarteten Systemvolume geladen hat.
  - Innerhalb von /System...
- ...

Beim Signieren einer Apple-Binärdatei **wird sie einer LC-Kategorie im Trust Cache zugeordnet**.

- Die **LC-Kategorien von iOS 16** wurden [**hier reverse-engineered und dokumentiert**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Die aktuellen **LC-Kategorien (macOS 14 – Sonoma)** wurden reverse-engineered; ihre [**Beschreibungen finden Sie hier**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Kategorie 1 ist beispielsweise:<sup>[[7]](#references)</sup>

```
Category 1:
        Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
        Parent Constraint: is-init-proc
```

- `(on-authorized-authapfs-volume || on-system-volume)`: Muss sich auf dem System- oder Cryptexes-Volume befinden.
- `launch-type == 1`: Muss ein Systemdienst sein (plist in LaunchDaemons).
- `validation-category == 1`: Eine ausführbare Datei des Betriebssystems.
- `is-init-proc`: Launchd

### LC-Kategorien reverse-engineeren

Weitere Informationen [**dazu hier**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), aber grundsätzlich sind sie in **AMFI (AppleMobileFileIntegrity)** definiert. Daher musst du das Kernel Development Kit herunterladen, um die **KEXT** zu erhalten. Die Symbole, die mit **`kConstraintCategory`** beginnen, sind die **interessanten**. Wenn du sie extrahierst, erhältst du einen DER-kodierten (ASN.1) Datenstrom, den du mit [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) oder der Python-Bibliothek asn1 und ihrem Skript `dump.py` dekodieren musst. Das Skript findest du unter [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master). Dadurch erhältst du eine leichter verständliche Zeichenfolge.<sup>[[3]](#references)[[8]](#references)</sup>

## Umgebungsbeschränkungen

Dies sind die für **Drittanbieteranwendungen** konfigurierten Launch Constraints. Der Entwickler kann die **Fakten** und **logischen Operanden** auswählen, die in seiner Anwendung verwendet werden, um den Zugriff auf sie zu beschränken.

Die Environment Constraints einer Anwendung lassen sich wie folgt auflisten:

```bash
codesign -d -vvvv app.app
```

## Trust Caches

In **macOS** gibt es einige Trust-Caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Und unter iOS befindet sich der Trust-Cache offenbar in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Wenn unter macOS auf Apple-Silicon-Geräten eine von Apple signierte Binärdatei nicht im Trust-Cache enthalten ist, verweigert AMFI das Laden.

### Trust-Caches auflisten

Die vorherigen Trust-Cache-Dateien liegen im **IMG4**- und **IM4P**-Format vor, wobei IM4P den Payload-Abschnitt eines IMG4-Formats darstellt.

Mit [**pyimg4**](https://github.com/m1stadev/PyIMG4) kannst du den Payload der Datenbanken extrahieren:

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

(Eine weitere Möglichkeit ist die Verwendung des Tools [**img4tool**](https://github.com/tihmstar/img4tool), das auch auf M1 läuft, obwohl die Version alt ist, und auf x86_64, wenn du es an den richtigen Stellen installierst.)

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

Dann könntest du ein Skript wie [**dieses hier**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) verwenden, um Daten zu extrahieren.

Anhand dieser Daten kannst du die Apps mit einem **Launch-Constraints-Wert von `0`** überprüfen. Diese Apps sind nicht eingeschränkt ([**hier nachsehen**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), wofür die einzelnen Werte stehen).<sup>[[6]](#references)</sup>

## Angriffsschutzmaßnahmen

Launch Constraints hätten mehrere ältere Angriffe verhindert, indem sie **sicherstellen, dass der Prozess nicht unter unerwarteten Bedingungen ausgeführt wird:** zum Beispiel von unerwarteten Speicherorten aus oder durch einen unerwarteten übergeordneten Prozess (wenn er nur von launchd gestartet werden sollte).

Außerdem **verhindern Launch Constraints Downgrade-Angriffe.**

Sie **verhindern jedoch keine gängigen XPC**-Missbräuche, **Electron**-Code-Injections oder **dylib-Injections** ohne Library Validation (es sei denn, die Team-IDs, die Bibliotheken laden dürfen, sind bekannt).<sup>[[3]](#references)</sup>

### Schutz von XPC-Daemons

Ein bemerkenswerter Punkt in der Sonoma-Version ist die **Verantwortlichkeitskonfiguration** des XPC-Daemon-Dienstes. Der XPC-Dienst ist für sich selbst verantwortlich, statt dass der verbindende Client verantwortlich ist. Dies ist im Feedback-Bericht FB13206884 dokumentiert. Diese Konfiguration mag fehlerhaft erscheinen, da sie bestimmte Interaktionen mit dem XPC-Dienst ermöglicht:

- **Starten des XPC-Dienstes**: Selbst wenn diese Konfiguration als Fehler angesehen wird, ermöglicht sie es nicht, den XPC-Dienst über Angreifercode zu starten.
- **Verbindung zu einem aktiven Dienst**: Wenn der XPC-Dienst bereits ausgeführt wird (möglicherweise gestartet von seiner ursprünglichen Anwendung), gibt es keine Hindernisse für eine Verbindung zu ihm.

Einschränkungen für den XPC-Dienst könnten zwar sinnvoll sein, um **das Zeitfenster für potenzielle Angriffe zu verkleinern**, sie lösen jedoch nicht das Hauptproblem. Um die Sicherheit des XPC-Dienstes grundlegend zu gewährleisten, muss **der verbindende Client effektiv validiert werden**. Dies ist die einzige Möglichkeit, die Sicherheit des Dienstes zu stärken. Außerdem ist zu beachten, dass die erwähnte Verantwortlichkeitskonfiguration derzeit aktiv ist, was möglicherweise nicht dem beabsichtigten Design entspricht.<sup>[[3]](#references)</sup>

### Electron-Schutz

Selbst wenn vorgeschrieben ist, dass die Anwendung **von LaunchService geöffnet werden muss** (in den Einschränkungen des übergeordneten Prozesses), lässt sich dies mit **`open`** (womit Umgebungsvariablen festgelegt werden können) oder über die **Launch Services API** (über die Umgebungsvariablen angegeben werden können) erreichen.<sup>[[3]](#references)</sup>

Eine allgemeine Beschreibung des MACF-Mechanismus hinter richtlinienspezifischen Spawn-Attributen findest du unter [Richtlinienspezifische Spawn-Attribute von MACF](macos-macf-mandatory-access-control-framework.md#policy-specific-spawn-attributes-as-a-macf-input).

### CVE-2025-43253 – Überschreiben der integrierten Constraints zur Spawn-Zeit

Launch Constraints (offiziell **lightweight code requirements**, *LWCR*) werden durch die **AMFI-MAC-Richtlinie** erzwungen. Über `posix_spawn` kann ein Aufrufer einer MAC-Richtlinie einen beliebigen Blob über **`posix_spawnattr_setmacpolicyinfo_np()`** übergeben, und AMFI akzeptierte über diesen Pfad ein vom Aufrufer bereitgestelltes LWCR-Wörterbuch. Der Fehler bestand darin, dass die **vom Angreifer bereitgestellten Constraints die integrierten Constraints der Binärdatei ersetzten**, statt zusätzlich zu ihnen geprüft zu werden:

- Erstelle ein minimales, sogar leeres, Launch-Constraints-Wörterbuch.
- Setze die **Constraint-Kategorie auf `127`**. Diesen Wert lässt AMFI in Spawn-Attributen zu, **erzwingt** ihn jedoch nicht – stattdessen protokolliert es `Launch Constraint Violation (not enforcing)`, anstatt die Ausführung zu blockieren.
- Übergib das Wörterbuch über die Spawn-Attribute. Daraufhin wird der Prozess in einem Kontext gestartet, den seine tatsächlichen Selbst-/Parent-Constraints verboten hätten.

Nach der Behebung werden **sowohl** die integrierten als auch die bereitgestellten Constraints validiert. Das bereitgestellte Wörterbuch kann die integrierten Constraints somit nicht mehr abschwächen.<sup>[[2]](#references)</sup>

> [!TIP]
> Achte bei der Überprüfung der Constraint-Durchsetzung auf folgendes allgemeines Muster: Eine API, über die nicht vertrauenswürdige Eingaben eine Richtlinie *bereitstellen* können, ist besonders interessant, wenn die Richtlinien-Engine den bereitgestellten Wert als Ersatz statt als zusätzliche Anforderung behandelt.



## References

- [1] [Objective by the Sea #OBTS v6.0 Tag 2 (Livestream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Umgehung von Launch Constraints unter macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch- und Environment-Constraints im Detail – theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Warum wird eine System-App oder ein Kommandozeilenprogramm nicht ausgeführt? Launch Constraints und Trust Caches – The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Schütze deine Mac-App mit Environment Constraints – WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Beschreibung der in iOS 16 eingeführten Launch Constraints (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Mehr als die guten alten LaunchAgents – hier geht es darum](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)
{{#include ../../../banners/hacktricks-training.md}}
