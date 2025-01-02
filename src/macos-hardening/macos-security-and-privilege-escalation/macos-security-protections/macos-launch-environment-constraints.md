# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Grundinformationen

Startbeschränkungen in macOS wurden eingeführt, um die Sicherheit zu erhöhen, indem **reguliert wird, wie, wer und von wo ein Prozess gestartet werden kann**. Eingeführt in macOS Ventura, bieten sie einen Rahmen, der **jede Systembinärdatei in verschiedene Beschränkungs-kategorien** einteilt, die innerhalb des **Trust Caches** definiert sind, einer Liste, die Systembinärdateien und deren jeweilige Hashes enthält. Diese Beschränkungen erstrecken sich auf jede ausführbare Binärdatei im System und beinhalten eine Reihe von **Regeln**, die die Anforderungen für **das Starten einer bestimmten Binärdatei** festlegen. Die Regeln umfassen Selbstbeschränkungen, die eine Binärdatei erfüllen muss, Elternbeschränkungen, die von ihrem übergeordneten Prozess erfüllt werden müssen, und verantwortliche Beschränkungen, die von anderen relevanten Entitäten eingehalten werden müssen.

Der Mechanismus erstreckt sich auf Drittanbieter-Apps durch **Umgebungsbeschränkungen**, beginnend mit macOS Sonoma, die es Entwicklern ermöglichen, ihre Apps zu schützen, indem sie eine **Menge von Schlüsseln und Werten für Umgebungsbeschränkungen angeben.**

Sie definieren **Startumgebungs- und Bibliotheksbeschränkungen** in Beschränkungswörterbüchern, die Sie entweder in **`launchd`-Eigenschaftslisten** speichern oder in **separaten Eigenschaftslisten**, die Sie beim Code-Signing verwenden.

Es gibt 4 Arten von Beschränkungen:

- **Selbstbeschränkungen**: Beschränkungen, die auf die **laufende** Binärdatei angewendet werden.
- **Elternprozess**: Beschränkungen, die auf den **Elternprozess** (zum Beispiel **`launchd`**, der einen XP-Dienst ausführt) angewendet werden.
- **Verantwortliche Beschränkungen**: Beschränkungen, die auf den **Prozess, der den Dienst aufruft**, in einer XPC-Kommunikation angewendet werden.
- **Bibliotheksladebeschränkungen**: Verwenden Sie Bibliotheksladebeschränkungen, um selektiv Code zu beschreiben, der geladen werden kann.

Wenn ein Prozess versucht, einen anderen Prozess zu starten — indem er `execve(_:_:_:)` oder `posix_spawn(_:_:_:_:_:_:)` aufruft — überprüft das Betriebssystem, ob die **ausführbare** Datei ihre **eigene Selbstbeschränkung** **erfüllt**. Es wird auch überprüft, ob die **ausführbare** Datei des **Elternprozesses** die **Elternbeschränkung** der ausführbaren Datei **erfüllt** und ob die **ausführbare** Datei des **verantwortlichen** Prozesses die **verantwortliche Prozessbeschränkung** der ausführbaren Datei **erfüllt**. Wenn keine dieser Startbeschränkungen erfüllt ist, führt das Betriebssystem das Programm nicht aus.

Wenn beim Laden einer Bibliothek ein Teil der **Bibliotheksbeschränkung nicht zutrifft**, **lädt** Ihr Prozess die Bibliothek **nicht**.

## LC-Kategorien

Ein LC besteht aus **Fakten** und **logischen Operationen** (und, oder..), die Fakten kombinieren.

Die [**Fakten, die ein LC verwenden kann, sind dokumentiert**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Zum Beispiel:

- is-init-proc: Ein boolescher Wert, der angibt, ob die ausführbare Datei der Initialisierungsprozess des Betriebssystems (`launchd`) sein muss.
- is-sip-protected: Ein boolescher Wert, der angibt, ob die ausführbare Datei eine Datei ist, die durch den System Integrity Protection (SIP) geschützt ist.
- `on-authorized-authapfs-volume:` Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
- `on-authorized-authapfs-volume`: Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei von einem autorisierten, authentifizierten APFS-Volume geladen hat.
- Cryptexes-Volume
- `on-system-volume:` Ein boolescher Wert, der angibt, ob das Betriebssystem die ausführbare Datei vom aktuell gebooteten Systemvolume geladen hat.
- Innerhalb von /System...
- ...

Wenn eine Apple-Binärdatei signiert wird, **weist sie ihr eine LC-Kategorie** innerhalb des **Trust Caches** zu.

- **iOS 16 LC-Kategorien** wurden [**umgekehrt und hier dokumentiert**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
- Aktuelle **LC-Kategorien (macOS 14 - Sonoma)** wurden umgekehrt und ihre [**Beschreibungen sind hier zu finden**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Zum Beispiel ist Kategorie 1:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Muss sich im System- oder Cryptexes-Volume befinden.
- `launch-type == 1`: Muss ein Systemdienst sein (plist in LaunchDaemons).
- `validation-category == 1`: Eine ausführbare Datei des Betriebssystems.
- `is-init-proc`: Launchd

### Rückgängigmachen von LC-Kategorien

Sie haben mehr Informationen [**darüber hier**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), aber im Grunde genommen sind sie in **AMFI (AppleMobileFileIntegrity)** definiert, daher müssen Sie das Kernel Development Kit herunterladen, um das **KEXT** zu erhalten. Die Symbole, die mit **`kConstraintCategory`** beginnen, sind die **interessanten**. Wenn Sie sie extrahieren, erhalten Sie einen DER (ASN.1) kodierten Stream, den Sie mit dem [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) oder der python-asn1-Bibliothek und ihrem `dump.py`-Skript, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) dekodieren müssen, was Ihnen eine verständlichere Zeichenkette liefert.

## Umgebungsbeschränkungen

Dies sind die Launch Constraints, die in **drittanbieter Anwendungen** konfiguriert sind. Der Entwickler kann die **Fakten** und **logischen Operanden auswählen**, die er in seiner Anwendung verwenden möchte, um den Zugriff auf sich selbst einzuschränken.

Es ist möglich, die Umgebungsbeschränkungen einer Anwendung mit zu enumerieren:
```bash
codesign -d -vvvv app.app
```
## Vertrauensspeicher

In **macOS** gibt es einige Vertrauensspeicher:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Und in iOS sieht es so aus, als wäre es in **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> Auf macOS, das auf Apple Silicon Geräten läuft, wird AMFI sich weigern, eine von Apple signierte Binärdatei zu laden, wenn sie nicht im Vertrauensspeicher ist.

### Auflisten von Vertrauensspeichern

Die vorherigen Vertrauensspeicherdateien sind im Format **IMG4** und **IM4P**, wobei IM4P der Payload-Bereich eines IMG4-Formats ist.

Sie können [**pyimg4**](https://github.com/m1stadev/PyIMG4) verwenden, um die Payload von Datenbanken zu extrahieren:
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
(Eine weitere Option könnte sein, das Tool [**img4tool**](https://github.com/tihmstar/img4tool) zu verwenden, das sogar auf M1 läuft, auch wenn die Version alt ist, und für x86_64, wenn Sie es an den richtigen Orten installieren).

Jetzt können Sie das Tool [**trustcache**](https://github.com/CRKatri/trustcache) verwenden, um die Informationen in einem lesbaren Format zu erhalten:
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
Der Trust-Cache folgt der folgenden Struktur, sodass die **LC-Kategorie die 4. Spalte ist**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Dann könnten Sie ein Skript wie [**dieses**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) verwenden, um Daten zu extrahieren.

Anhand dieser Daten können Sie die Apps mit einem **Wert für Startbeschränkungen von `0`** überprüfen, was die sind, die nicht eingeschränkt sind ([**hier überprüfen**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), was jeder Wert bedeutet).

## Angriffsminderungen

Startbeschränkungen hätten mehrere alte Angriffe gemildert, indem sie **sicherstellen, dass der Prozess nicht unter unerwarteten Bedingungen ausgeführt wird:** Zum Beispiel von unerwarteten Standorten oder von einem unerwarteten übergeordneten Prozess aufgerufen wird (wenn nur launchd es starten sollte).

Darüber hinaus **mildern Startbeschränkungen auch Downgrade-Angriffe.**

Sie **mildern jedoch keine häufigen XPC** Missbräuche, **Electron** Code-Injektionen oder **dylib-Injektionen** ohne Bibliotheksvalidierung (es sei denn, die Team-IDs, die Bibliotheken laden können, sind bekannt).

### XPC-Daemon-Schutz

Im Sonoma-Release ist ein bemerkenswerter Punkt die **Verantwortlichkeitskonfiguration** des Daemon-XPC-Dienstes. Der XPC-Dienst ist für sich selbst verantwortlich, im Gegensatz zum verbindenden Client, der verantwortlich ist. Dies ist im Feedbackbericht FB13206884 dokumentiert. Diese Einrichtung mag fehlerhaft erscheinen, da sie bestimmte Interaktionen mit dem XPC-Dienst zulässt:

- **Starten des XPC-Dienstes**: Wenn dies als Fehler angesehen wird, erlaubt diese Einrichtung nicht, den XPC-Dienst durch Angreifercode zu initiieren.
- **Verbinden mit einem aktiven Dienst**: Wenn der XPC-Dienst bereits läuft (möglicherweise von seiner ursprünglichen Anwendung aktiviert), gibt es keine Barrieren, um sich mit ihm zu verbinden.

Während die Implementierung von Beschränkungen für den XPC-Dienst vorteilhaft sein könnte, indem sie **das Fenster für potenzielle Angriffe verengt**, adressiert sie nicht das Hauptanliegen. Die Sicherheit des XPC-Dienstes sicherzustellen, erfordert grundlegend **eine effektive Validierung des verbindenden Clients**. Dies bleibt die einzige Methode, um die Sicherheit des Dienstes zu stärken. Es ist auch erwähnenswert, dass die erwähnte Verantwortlichkeitskonfiguration derzeit in Betrieb ist, was möglicherweise nicht mit dem beabsichtigten Design übereinstimmt.

### Electron-Schutz

Selbst wenn es erforderlich ist, dass die Anwendung **von LaunchService** (in den übergeordneten Beschränkungen) geöffnet werden muss. Dies kann durch die Verwendung von **`open`** (das Umgebungsvariablen setzen kann) oder durch die Verwendung der **Launch Services API** (wo Umgebungsvariablen angegeben werden können) erreicht werden.

## Referenzen

- [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [https://theevilbit.github.io/posts/launch_constraints_deep_dive/](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

{{#include ../../../banners/hacktricks-training.md}}
