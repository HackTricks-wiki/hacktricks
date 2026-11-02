# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs verändert, während sie **grammatikkonform** bleiben. Im Coverage-guided-Modus werden nur Samples, die **neue Coverage** auslösen, als Corpus-Seeds gespeichert. Bei **Sprachzielen** (Parsern, Interpretern, Engines) kann dadurch die Suche nach Bugs scheitern, die **semantische Datenflussketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, aber **den verketteten Datenfluss nicht erhalten**. Dadurch wird das Sample, das dem Bug „näher kommt“, verworfen, weil es keine zusätzliche Coverage bringt. Bei **3 oder mehr abhängigen Schritten** wird zufällige Rekombination teuer, und das Coverage-Feedback leitet die Suche nicht gezielt.<sup>[[1]](#references)</sup>

**Konsequenz:** Ziehe bei Grammatiken mit vielen Abhängigkeiten in Betracht, **mutationale und generative Phasen zu kombinieren** oder die Generierung auf Muster mit **verketteten Funktionen** auszurichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-guided Mutation ist **greedy**: Ein Sample mit neuer Coverage wird sofort gespeichert und behält dabei häufig große unveränderte Bereiche. Mit der Zeit bestehen Corpora aus **nahezu identischen Duplikaten** und weisen nur eine geringe strukturelle Vielfalt auf. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktikabler Kompromiss ist daher eine **grammatikbewusste Minimierung**, die **bei einem Mindest-Token-Schwellenwert stoppt** (Rauschen reduzieren und zugleich genügend umgebende Struktur erhalten, damit sich das Sample weiterhin gut mutieren lässt).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Bevorzuge eine kleine Menge strukturell unterschiedlicher Seeds mit maximaler Coverage** gegenüber einem großen Haufen nahezu identischer Duplikate. In der Praxis bedeutet das meist Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Beginne mit **realen Samples** (öffentlichen Corpora, Crawling, aufgezeichnetem Traffic, Dateisammlungen aus dem Ökosystem des Ziels).
- Reduziere sie mithilfe einer **Coverage-basierten Corpus-Minimierung**, statt jedes gültige Sample zu behalten.
- Halte Seeds **klein genug**, damit Mutationen sinnvolle Felder treffen, anstatt die meisten Zyklen mit irrelevanten Bytes zu verbringen.
- Führe nach größeren Änderungen am Harness oder an der Instrumentierung erneut eine Corpus-Minimierung durch, da sich das „beste“ Corpus ändert, wenn sich die Erreichbarkeit ändert.

## Vergleichsbewusste Mutation für Magic Values

Ein häufiger Grund dafür, dass Fuzzer nicht weiterkommen, ist nicht die Syntax, sondern **strikte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Checksummen oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder verkettete Vergleiche geschützt sind. Reine Zufallsmutationen verschwenden Zyklen damit, diese Werte Byte für Byte zu erraten.

Verwende für solche Ziele **Comparison Tracing** (zum Beispiel AFL++-Workflows mit `CMPLOG` oder im Redqueen-Stil), damit der Fuzzer Operanden fehlgeschlagener Vergleiche beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche bestehen.<sup>[[3]](#references)</sup>

```bash
./configure --cc=afl-clang-fast
make
cp ./target ./target.afl

make clean
AFL_LLVM_CMPLOG=1 ./configure --cc=afl-clang-fast
make
cp ./target ./target.cmplog

afl-fuzz -i in -o out -c ./target.cmplog -- ./target.afl @@
```

**Praktische Hinweise:**

- Das ist besonders nützlich, wenn das Ziel tieferliegende Logik hinter **Dateisignaturen**, **Protokollverben**, **Typ-Tags** oder **versionsabhängigen Feature-Bits** verbirgt.
- Kombiniere es mit **Wörterbüchern**, die aus echten Beispielen, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Wörterbuch mit Grammatik-Tokens, Chunk-Namen, Verben und Trennzeichen ist oft wertvoller als eine riesige generische Wortliste.
- Wenn das Ziel viele Prüfungen nacheinander durchführt, löse zuerst die frühesten „Magic“-Vergleiche und minimiere anschließend den resultierenden Korpus erneut, damit spätere Stufen mit bereits gültigen Präfixen beginnen.

## Fuzzing von Datei-APIs, die eine Dateinamensprache verbergen

Ein Parameter namens `filename`, `path` oder `URL` kann ein Einstiegspunkt für einen Interpreter statt einer wörtlichen Dateisuche sein. Beispielsweise wertet die CFITSIO Extended Filename Syntax (EFS) geklammerte Selektoren, Zeilen-/Pixelausdrücke, berechnete Spalten, Histogramme und Transformationen aus, bevor sie das geöffnete Objekt zurückgibt; einige Formen erstellen außerdem temporäre Kopien. Ordne beim Mapping der Angriffsfläche jede Open-/Import-API als **literal-path** oder **interpreted-path** ein und fuzze dann den Produktionseinstiegspunkt, den Anwendungen tatsächlich aufrufen.<sup>[[20]](#references)[[22]](#references)</sup>

Für die daraus entstehenden SSRF-, Dateikopier- und Protokollhandler-Primitiven sowie sicherere literal-path-APIs siehe [Dateinamen-Mini-Sprachen als SSRF-/Datei-Primitiven](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs).<sup>[[20]](#references)</sup>

### Das zugrunde liegende Objekt getrennt vom gefuzzten Programm halten

Wenn die Grammatik in einem Dateinamensuffix steckt, verfehlt das Mutieren ausschließlich der referenzierten Dateibytes den Parser. Ein kleiner Harness kann stattdessen jeden Testfall als String einlesen und an die interpretierte Open-API übergeben; die CFITSIO-Kampagne erreichte die meisten EFS-Parser und -Evaluatoren, indem sie `fits_open_file()` im Nur-Lese-Modus aufrief. Halte gültige zugrunde liegende Dateien separat bereit, damit sich Mutationen auf die Selektor-/Ausdruckssprache konzentrieren können, statt ständig den Basispfad unbrauchbar zu machen.<sup>[[22]](#references)</sup>

Verwende Seeds, die jeweils eine andere Grammatikfamilie erreichen, und leite dann ein kompaktes Wörterbuch sowohl aus der Spezifikation als auch aus dem Lexer-/Parser-Quellcode ab. Wenn die Coverage stagniert, während Eingaben wiederholt im selben Syntaxfehlerpfad scheitern, bewahre gültige Präfixe und ergänze Trennzeichen, Operatoren, Schlüsselwörter, Funktionsnamen und repräsentative Feldnamen, anstatt nur die Zeit für Zufallsmutationen zu erhöhen.<sup>[[22]](#references)</sup>

Führe den Harness mit dem Grammatik-Wörterbuch aus, zum Beispiel:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Nebeneffekte des „read-only“-Harnesses eindämmen

Ein „read-only“-Flag der Bibliothek garantiert keinen Testfall ohne Nebeneffekte: Die Dateinamensprache kann die Eingabe umschreiben, Ausgabedateien erstellen oder temporäre Objekte materialisieren. Die CFITSIO-Kampagne zerstörte zunächst Seed-Dateien und hinterließ unerwartete Dateien im Dateisystem, weshalb Bereinigung und Isolation erforderlich waren.<sup>[[22]](#references)</sup>

- Gib jedem Worker ein entbehrliches Arbeitsverzeichnis und ein privates temporäres Verzeichnis.
- Stelle Kopien kanonischer Backing-Dateien bereit; lass das Ziel niemals die einzige Kopie des Corpus verändern.
- Deaktiviere den Netzwerkzugriff, sofern nicht Remote-Backends das Ziel sind, und beschränke beschreibbare Pfade mit einem Container, einem Mount-Namespace oder einer gleichwertigen Sandbox.
- Setze das Verzeichnis nach jeder Ausführung oder jedem Worker-Batch zurück und behandle unerwartete Änderungen am Dateisystem als zusätzliche Findings.

### Crash-to-patch-to-fuzz-Schleife

Gruppiere Crashes vor der Reparatur, damit aus Tausenden Artefakten nicht Tausende Patch-Aufgaben werden. Bei der CFITSIO-Bewertung reduzierte AFLTriage die anfängliche Crash-Menge auf einige wenige Grundursachen; das daraus entstandene Advisory zeigt verschiedene Fehler, darunter fehlerhafte Prüfungen der Zielgröße, veraltete Zeiger nach `realloc()`, arithmetische Fehler und unsichere Parser-Bereinigungspfade.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiere für jedes Cluster eine repräsentative Eingabe und reproduziere den Fehler mit AddressSanitizer.
2. Halte den exakten fehlerhaften Zugriff, die Quellcodeposition, den Allokations-/Freigabeverlauf und den Parser-Zustand fest, durch den die Invariante verletzt wurde.
3. Wende einen eng begrenzten Kandidaten-Patch an und erstelle den Build mit derselben Coverage- und Sanitizer-Instrumentierung.
4. Spiele den ursprünglichen Reproducer **und jede Eingabe in seinem Cluster** erneut ein; aktiviere außerdem die Leak-Erkennung, da eine Memory-Safety-Korrektur die Besitzverhältnisse in einem Fehlerpfad beeinträchtigen kann.
5. Führe Funktionstests mit echten Dateien aus und setze dann die Tests mit der angesammelten Queue fort (oder importiere diese Queue erneut, falls die Engine nach einer Änderung der Binärdatei ein neues Ausgabeverzeichnis benötigt).
6. Wiederhole den Vorgang: Wird der erste oberflächliche Crash behoben, können vorhandene Seeds oft einen tieferen Parser-Zustand erreichen.

Ein LLM kann Schritt 2 beschleunigen und einen Entwurf für Schritt 3 erstellen, wenn es die abstürzende Eingabe, den Sanitizer-Bericht, den Harness und den relevanten Quellcode erhält; sein Patch bleibt jedoch nicht vertrauenswürdig. Über die Annahme der Reparatur entscheiden der erneute Sanitizer-Test und die Regressionstests – nicht die Erklärung des Modells.<sup>[[22]](#references)</sup>

## Aussagekräftigeres Feedback, wenn Edge Coverage unterschiedliche Pfade zusammenfasst

Normale Edge Coverage kann zwei Ausführungen nicht unterscheiden, wenn sie denselben Helper über unterschiedliche Aufrufer durchlaufen oder innerhalb einer Funktion unterschiedliche Kombinationen von Branches nehmen. Das ist bei gemeinsam genutzten Decodern, Protokoll-Dispatchern und Interpreter-Helpers wichtig, bei denen die **Route** zu einer Edge den aktiven Zustand bestimmt. Jeden Aufrufkontext naiv zu erfassen, ist ebenfalls riskant: Die Coverage-Map und die Queue können explosionsartig anwachsen. Die Forschung zu kontextsensitive Fuzzing empfiehlt daher, nur vielversprechende Kontexte gezielt genauer zu erfassen, statt den gesamten Aufrufgraphen als kontextsensitiv zu behandeln.<sup>[[14]](#references)</sup>

Aktuelle AFL++-Builds bieten zusätzlich zur normalen Edge Coverage eine **Ball-Larus-Pfad-Coverage pro Funktion**. Sie weist jedem azyklischen Pfad durch eine Funktion ein Feature zu; Schleifen-Rückkanten werden entfernt, sodass dieses Feedback Kombinationen von Branches unterscheidet, **nicht aber die Anzahl der Schleifeniterationen**. Beginne mit dem weniger strengen Level `1` und beschränke strengere Modi anschließend auf verdächtigen Parser-/Zustandsautomaten-Code, da die Anzahl der Pfade exponentiell anwachsen kann.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Bei einer Hilfsfunktion, die von vielen sicherheitsrelevanten Stellen aufgerufen wird, kann der LTO-Modus jeden Funktionspfad mit seiner unmittelbaren Aufrufstelle kombinieren:<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_LLVM_LTO_CALLER=1
export AFL_LLVM_LTO_PATH=1
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

**Hinweise zur Kampagne:** Reichhaltigeres Feedback sparsam einsetzen und dessen Kosten für Coverage-Map und Queue überwachen.<sup>[[13]](#references)[[14]](#references)</sup>

- Parallel eine gewöhnliche Edge-Coverage-Instanz ausführen; reichhaltigeres Feedback ist nur dann nützlich, wenn die zusätzlichen Kosten für Queue und Map die Ausführungen pro Sekunde nicht zu stark reduzieren.
- `AFL_LLVM_ALLOWLIST` verwenden, um die Instrumentierung von Pfaden und Aufrufern einzuschränken, wenn große, vorlagenlastige Bibliotheken oder generischer Utility-Code die Map dominieren.
- Funktionen mit übermäßig vielen azyklischen Pfaden können von AFL++ übersprungen werden; Warnungen während der Kompilierung sind ein Hinweis darauf, dass das Target eine Allowlist oder eine weniger strenge Stufe benötigt.
- Caller + Path Coverage unterstützt nur eine Caller-Tiefe. Nicht mit tieferen Context-Stacks kombinieren.
- Pfad-IDs können sich zwischen größeren LLVM-Versionen ändern. Die Toolchain während einer Kampagne unverändert lassen und PATH-basierte Corpora nicht synchronisieren, als wären ihre Feature-IDs über verschiedene Builds hinweg stabil.
- Dieses Feedback ergänzt `CMPLOG`: Comparison Tracing ermittelt, **welcher Wert eine Guard-Bedingung passiert**, während Path-/Caller-Feedback festhält, **welche Route und Branch-Kombination dorthin geführt hat**.

## Stateful Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **Nachrichtensequenz**. Das gesamte Transkript in eine Datei zu konkatenieren und blind zu mutieren, ist in der Regel ineffizient, weil der Fuzzer jeden Schritt gleichermaßen mutiert, obwohl nur die spätere Nachricht den fragilen Zustand erreicht.<sup>[[4]](#references)</sup>

Effektiver ist es, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Antwortcodes, Protokollzustände, Parserphasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- **Gültige Präfixnachrichten** stabil halten und Mutationen auf die Nachricht konzentrieren, die den **Übergang auslöst**.
- Bezeichner und vom Server generierte Werte aus früheren Antworten zwischenspeichern, wenn der nächste Schritt davon abhängt.
- Mutationen oder Splicing pro Nachricht gegenüber der Mutation des gesamten serialisierten Transkripts als undurchsichtigem Blob bevorzugen.
- Wenn das Protokoll aussagekräftige Antwortcodes bereitstellt, diese als **kostengünstiges Zustandsorakel** verwenden, um Sequenzen zu priorisieren, die weiter vorankommen.

Aus demselben Grund werden authentifizierte Bugs, versteckte Übergänge oder Parser-Bugs, die „erst nach dem Handshake“ auftreten, oft beim gewöhnlichen dateibasierten Fuzzing übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

### Android Binder: Fuzzing mit Multi-Client-Treiber

Eine hohe Edge-Coverage kann IPC-Treiber-Bugs trotzdem übersehen, denn Coverage beschreibt weder **Objektbesitz, Referenzzähler, ausstehende Nachrichten, Bereinigungsreihenfolge noch Thread-Interleavings**. Die Seite zu den [Interna von Android Binder IPC](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) behandelt das Objektmodell des Treibers; dieses Beispiel konzentriert sich auf den Fuzzer-Harness. Android Binder ist ein nützliches Modell: Es reicht nicht, sowohl die Allokations- als auch die Freigabepfade zu erreichen, wenn der Fuzzer nicht mehrere Prozesse in der erforderlichen Reihenfolge auf dasselbe Kernel-Objekt zugreifen lassen kann.<sup>[[15]](#references)</sup>

#### Das Protokoll modellieren, nicht isolierte `ioctl`-Puffer

Einen Testfall als geordnete Grammatik aus **Client-Identität + Operation + strukturierten Argumenten** darstellen. Der Binder-LKL-Fuzzer verwendet protobuf und `libprotobuf-mutator` mit einem persistenten Context-Manager-Client und zwei gewöhnlichen Clients. Ein semantischer Harness bewahrt dann die Beziehungen, die durch blinde Byte-Mutationen zerstört würden.<sup>[[15]](#references)</sup>

- Von früheren Operationen zurückgegebene Werte zwischenspeichern. Beispielsweise muss `BC_FREE_BUFFER` einen Transaktionspufferzeiger wiederverwenden, der von einem vorherigen `ioctl` zurückgegeben wurde.
- Gültige Standardantworten erzeugen, damit synchrone Transaktionen abgeschlossen werden können und spätere Operationen erreichbar bleiben.
- Unmögliche Übergänge wie Selbsttransaktionen oder mehrere ausstehende Transaktionen an dasselbe Ziel zurückweisen.
- Den einmaligen Bootstrap-Zustand außerhalb des Pro-Input-Resets halten. Binder erlaubt pro Boot nur eine Registrierung mit `BINDER_SET_CONTEXT_MGR`; würde dieser Client wiederholt zerstört und neu erstellt, wären spätere Inputs ungültig.

Ein nützliches Muster für Lifetime-Races besteht darin, einen Client ein Objekt übertragen zu lassen, einen Thread- oder Prozess-Cleanup zu starten und den empfangenden Client gleichzeitig den Transaktionspuffer freigeben zu lassen. Im Beispiel CVE-2020-0423 konnte eine Übertragung von `BINDER_TYPE_WEAK_BINDER`, gefolgt von einem `BINDER_THREAD_EXIT`, das mit `BC_FREE_BUFFER` konkurrierte, ein eingebettetes `binder_work` freigeben, während der Cleanup-Pfad des beendenden Threads es noch verwendete.<sup>[[15]](#references)</sup>

#### Kontrollierte Interleavings in einem Userspace-Kernel wieder einführen

Die [Linux Kernel Library (LKL)](https://github.com/lkl/linux) verlinkt den echten Kernel-Code in einen Userspace-Harness und stellt dessen Syscall-Schnittstelle über `lkl_syscall` bereit. Dadurch lassen sich protobuf-Zustand, Coverage und KASAN problemlos in einem Prozess koordinieren. Normalerweise führt LKL einen Syscall jedoch aus, ohne dass ein anderer Kernel-Thread ihn unterbricht. Für Race-Kampagnen an ausgewählten Grenzen von Sperren, Entsperrungen und Objektlebenszeiten `schedule()`-Punkte einfügen und den Harness bei jedem Yield zufällig den nächsten Client auswählen lassen. Diese Punkte gezielt setzen, da jeder einzelne den Suchraum für das Scheduling vervielfacht. Der von den Forschern beschriebene randomisierte Scheduler ist **nicht** Teil des Upstream-Binder-Fuzzers.<sup>[[15]](#references)</sup>

#### Serialisierte Regression-Seeds erstellen und erneut ausführen

Der Upstream-Harness pinnt eine kompatible Version von `libprotobuf-mutator`, aktiviert mit `LKL_FUZZING=1` die LKL-Fuzzing-Instrumentierung und KASAN und schaltet Binder mit `MMU=1` über `CONFIG_MMU` frei.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nach dem Auschecken einer absichtlich verwundbaren Revision oder dem Anwenden der upstream dokumentierten Rollback-Patches kann ein serialisierter Seed den gesamten Zustandsübergang mehrerer Clients reproduzieren, ohne ihn in einem improvisierten C-Proof-of-Concept nachbilden zu müssen:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandle den resultierenden KASAN-use-after-free als Bestätigung dafür, dass der Seed den anfälligen Lifetime-Pfad erreicht hat. Er weist **nicht** die späteren Primitives nach, die für die Ausführung von Kernel-Code oder eine Privilegienausweitung erforderlich sind.<sup>[[16]](#references)</sup>

## Single-Machine Diversity Trick (Jackalope-Style)

Eine praktische Möglichkeit, **generative Neuartigkeit** mit der **Wiederverwendung von Coverage** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server neu zu starten. Jeder Worker startet mit einem leeren Corpus, synchronisiert nach `T` Sekunden, läuft weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und beendet sich dann. So entstehen **in jeder Generation neue Strukturen**, während gleichzeitig die angesammelte Coverage genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequenzielle Worker (Beispielschleife):**

<details>
<summary>Jackalope-Worker-Neustartschleife</summary>

```python
import subprocess
import time

T = 3600

while True:
  subprocess.run(["rm", "-rf", "workerout"])
  p = subprocess.Popen([
      "/path/to/fuzzer",
      "-grammar", "grammar.txt",
      "-instrumentation", "sancov",
      "-in", "empty",
      "-out", "workerout",
      "-t", "1000",
      "-delivery", "shmem",
      "-iterations", "10000",
      "-mute_child",
      "-nthreads", "6",
      "-server", "127.0.0.1:8337",
      "-server_update_interval", str(T),
      "--", "./harness", "-m", "@@",
  ])
  time.sleep(T * 2)
  p.kill()
```

</details>

**Hinweise:**

- `-in empty` erzwingt bei jeder Generierung einen **neuen Corpus**.
- `-server_update_interval T` nähert eine **verzögerte Synchronisierung** an (zuerst Neuheiten, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **initiale Serversynchronisierung standardmäßig übersprungen** (kein `-skip_initial_server_sync` nötig).
- Das optimale `T` ist **zielabhängig**; am besten funktioniert meist ein Wechsel, nachdem der Worker den Großteil der „einfachen“ Coverage gefunden hat.

## Snapshot Fuzzing für schwer zu harnessende Ziele

Wenn der Code, den du testen möchtest, erst **nach umfangreichen Vorbereitungen** erreichbar ist (eine VM starten, einen Login abschließen, ein Paket empfangen, einen Container parsen, einen Dienst initialisieren), ist **Snapshot Fuzzing** eine nützliche Alternative: Erfasse den bereitstehenden Prozess- oder VM-Zustand, übergib jeden Testfall an den Eingabepfad des Ziels, führe ihn bis zum Absturz/Timeout aus und stelle den Snapshot wieder her. So muss die Initialisierung oder das Protokollpräfix nicht wiederholt werden. Das ist nützlich für **Netzwerkdienste**, **Firmware**, **Angriffsflächen nach der Authentifizierung** und **binäre Ziele**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führe das Ziel aus, bis der interessante Zustand bereit ist.
2. Erstelle an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreibe für jeden Testfall die mutierte Eingabe direkt in den entsprechenden Gast-/Prozesspuffer.
4. Führe die Ausführung bis zum Absturz/Timeout/Reset fort.
5. Stelle den Snapshot wieder her; bei VM-Zielen stelle, sofern unterstützt, nur die **veränderten Seiten** wieder her und wiederhole den Vorgang.

Platziere den Snapshot so nah wie praktisch möglich am ersten aufwendigen Parse-/Dispatch-Schritt, etwa nach einem `recv`-/`read`- oder Paketdeserialisierungspunkt, und erfasse den vom Ziel verwendeten Eingabepuffer. Damit wird das Prinzip der adaptiven Platzierung umgesetzt: Der Snapshot wird tiefer in die Eingabeverarbeitung verschoben, um wiederholte Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

## Untersuchung von Linux-Kernel-Races mit MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) macht zeitkritische Races im Linux-Kernel zu reproduzierbaren Speicherzugriffsplänen. Das Tool kann automatisch Zwei-Kontext-**A-B-A**-Abläufe aufzählen oder Analysten Reihenfolgebedingungen über eine Terminal-UI/GUI vorgeben lassen. Es handelt sich um experimentelle Forschungswerkzeuge und nicht um einen vollständigen Concurrency-Fuzzer: Derzeit werden LLVM 23+ und der gepatchte Kernel des Projekts benötigt, die Befehlszeilentools unterstützen zwei Test-Threads und die vorgeschlagene Userspace-Fuzzing-Ebene ist nicht implementiert.<sup>[[17]](#references)[[18]](#references)</sup>

### Kommunikationspunkte zwischen Kontexten erfassen

Erstelle den instrumentierten Kernel mit KASAN-Outline-Callbacks und der gepatchten KCOV-Unterstützung für Speicheraufzeichnungen. Die README des Projekts empfiehlt außerdem, die Sibling-Call-Optimierung zu deaktivieren, damit die Call-Stacks weiterhin nutzbar sind.<sup>[[17]](#references)[[18]](#references)</sup>

```text
CONFIG_KASAN=y
CONFIG_KASAN_OUTLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_EXT_RECORDS=y
CONFIG_KCOV_MEMORY=y
CONFIG_KALLSYMS_ALL=y
CONFIG_DEBUG_INFO_DWARF5=y
CONFIG_PREEMPT=y
CONFIG_RANDOMIZE_BASE=n
```

```bash
export KCFLAGS="-fno-optimize-sibling-calls -mllvm -sanitizer-coverage-prune-blocks=false"
```

KASAN outline mode (`asan-instrumentation-with-call-threshold=0`) wandelt instrumentierte Zugriffe in Helper-Aufrufe um. Die MAccConc-Kernel-Patches deaktivieren `asan-opt-same-temp`, damit aufeinanderfolgende Zugriffe nicht zusammengeführt werden; deaktiviere auch die Optimierung `asan-opt-globals`, wenn Races auf globale Variablen sichtbar sein müssen. KCOV überträgt die resultierenden Records in den Userspace. Vergleiche Zugriffe aus unterschiedlichen Ausführungskontexten und behalte Paare bei, deren Bytebereiche sich überschneiden und bei denen mindestens eine Seite schreibt; modelliere `kfree()` als Schreibzugriff, damit auch Änderungen der Lebensdauer als Kandidaten erfasst werden.<sup>[[17]](#references)</sup>

Bei Arbeit, die den auslösenden Task verlässt, etwa bei der Paketverarbeitung oder RCU-Callbacks, muss das Subsystem ein KCOV-Remote-Coverage-Handle weitergeben. Upstream Remote KCOV ist optional und steht nicht automatisch für beliebige Hintergrundarbeit zur Verfügung. Eine fehlende Weitergabe kann daher dazu führen, dass eine tatsächliche Interaktion unsichtbar bleibt.<sup>[[17]](#references)[[19]](#references)</sup>

### Identifiziere bei jedem Lauf denselben dynamischen Zugriff

Wiederhole den Test nicht mit einer konkreten Heap-Adresse, die sich nach jeder Allokation ändern kann, und auch nicht nur mit einer Instruktionsadresse, die innerhalb von Helpers wie `memcpy()` und `spin_lock()` mehrdeutig ist. MAccConc verwendet einen **Stack-Trace mit Aufrufzählern**: Jeder Frame identifiziert einen Callee sowie dessen Aufrufnummer innerhalb des Callers, und das letzte Element identifiziert die Speicherzugriffs-Instruktion. SanitizerCoverage-Records für Funktionsaufrufe und -rückgaben ermöglichen es dem Userspace, diesen dynamischen Bezeichner zu rekonstruieren. Er bleibt bei Adressänderungen und unabhängigem Kontrollflussrauschen stabil.<sup>[[17]](#references)</sup>

### Wandle Kandidatenpaare in erzwungene Schedules um

Der gepatchte `KCOV_SET_DI`-ioctl verknüpft einen Zugriffsbezeichner mit Aufrufzählern mit einer Aktion für ein gemeinsames Flag.<sup>[[17]](#references)</sup>

| Aktion | Semantik |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Setzt Flag *N* unmittelbar vor dem ausgewählten Zugriff. |
| `DI_STACK_WAIT` | Wartet vor dem ausgewählten Zugriff in einer Schleife, bis Flag *N* gesetzt ist oder das konfigurierte Limit erreicht wird. |
| `DI_STACK_WAKE_POST` | Setzt Flag *N* unmittelbar nach dem ausgewählten Zugriff. |

Für eine partielle **A-happens-before-B**-Bedingung verknüpfe `DI_STACK_WAKE_POST` mit A und `DI_STACK_WAIT` mit B, wobei beide dasselbe Flag verwenden. Für einen vollständig festgelegten Zwei-Kontext-Schedule blockiere B zunächst. A weckt dann B auf und wartet am ersten Übergabepunkt; beim nächsten Übergabepunkt führt B die umgekehrte Operation aus. Letzteres funktioniert wie deterministisches Context-Switching und wird vom automatischen A-B-A-Explorer verwendet.<sup>[[17]](#references)</sup>

Eine minimale Kampagne besteht darin, den Testfall mit vier Hooks (`test_setup`, zwei Thread-Funktionen und `test_end`) als Shared Library zu kompilieren, einen Trace ohne Bedingungen zu erfassen und anschließend A-B-A-Kandidaten aufzuzählen oder manuelle Bedingungen um verdächtige Zugriffe hinzuzufügen.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Unterscheide Timeouts von erfolgreichen Umordnungen: Eine angeforderte Reihenfolge ist möglicherweise unmöglich, weil ein Lock oder eine Initialisierungs-/Veröffentlichungsabhängigkeit verhindert, dass der zweite Kontext seinen Injection Point erreicht. Behalte außerdem die blinden Flecken von KASAN im Blick: Direkte Stack-Zugriffe werden normalerweise nicht abgefangen, sofern sie nicht außerhalb der Grenzen liegen könnten; Globals werden bei der Standardoptimierung ausgelassen, und aktuelle Compiler können ASAN- und TSAN-Hooks nicht gleichzeitig ausgeben. Schließlich verliert der Prototyp bei einem Panic des Gasts seinen KCOV-Puffer. Sorge daher für eine unabhängige Crash-Konsole oder ein unabhängiges Oracle.<sup>[[17]](#references)</sup>

Für künftiges concurrency-guided Fuzzing solltest du Speicherzugriffsübersichten pro Eingabe oder Syscall aufzeichnen, Operationen zusammenführen, die Cross-Context-Kommunikationspunkte bilden würden, und dann nur diese Kombinationen untersuchen. VM-Snapshots stabilisieren den globalen Zustand und die Adressen; ohne Snapshots können Metadaten der Allokationsstellen Objekte über mehrere Runs hinweg abstrahieren. Dies ist ein vorgeschlagener Ausbau und keine Funktion der aktuellen MAccConc-Userspace-Tools.<sup>[[17]](#references)</sup>

## Harness-Introspektion: Flache Fuzzer früh erkennen

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Nutze eine **Reachability-/Coverage-Introspektion**, um Funktionen zu finden, die vom Fuzz-Target aus statisch erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Diese Funktionen weisen meist auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness steigt zu spät oder zu früh in das Target ein.
- Im Seed-Corpus fehlt eine ganze Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** statt eines übergroßen „Alles-erledigen“-Harness.

Wenn du Workflows im Stil von OSS-Fuzz / ClusterFuzz verwendest, kann Fuzz Introspector die statische Erreichbarkeit mit der Laufzeit-Coverage vergleichen und Berichte aus einem zeitlich begrenzten Lauf oder einem öffentlichen Corpus erstellen.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Nutze den Bericht, um zu entscheiden, ob du einen neuen Harness für einen nicht getesteten Parser-Pfad hinzufügst, den Korpus für ein bestimmtes Feature erweiterst oder einen monolithischen Harness in kleinere Einstiegspunkte aufteilst.

## Graph-First-Auswahl von Fuzz-Zielen und Mutation-Triage

Wenn dir bereits **Static-Analysis-Befunde**, **Mutation-Testing-Survivors** und **Coverage-Berichte** vorliegen, solltest du sie nicht als voneinander unabhängige Listen triagieren. Erstelle zuerst einen **Aufrufgraphen**, annotiere die Knoten mit **zyklomatischer Komplexität**, **Erreichbarkeit von Einstiegspunkten/ungültigen Eingaben** und externen Befunden und stelle dann Fragen zum Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von ungültigen Eingaben aus erreichbar?
- Welche Mutation Survivors liegen auf Pfaden von Parsern/Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großem **blast radius**?

So findest du in der Regel bessere Fuzz-Ziele als allein anhand der „niedrigsten Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **Erreichbarkeit von außen** ist ein besserer Kandidat für einen Harness als ein isolierter interner Helper mit geringer Coverage, aber ohne vom Angreifer kontrollierbaren Pfad.

### Praktischer Triage-Workflow

1. Erstelle einen **Code-Graphen** aus der Codebase und extrahiere Komplexitäts-/Branch-Metriken pro Funktion.
2. Ermittle **Einstiegspunkte**, die vom Angreifer kontrollierte Eingaben akzeptieren: Request-Handler, Decoder, Importer, Protokoll-Parser, CLI-/Datei-Reader.
3. Führe **Pfadabfragen** von diesen Einstiegspunkten zu Kandidatenfunktionen aus, um erreichbare Angriffsfläche von totem/nur internem Code zu unterscheiden.
4. Priorisiere Knoten, die Folgendes vereinen:
   - hohe **zyklomatische Komplexität**
   - bestätigte **Erreichbarkeit von ungültigen Eingaben**
   - großer **blast radius** oder viele nachgelagerte Abhängigkeiten
   - bestätigende Hinweise wie **SARIF**-Befunde, Audit-Notizen oder Mutation Survivors
5. Schreibe zuerst gezielte Harnesses für die Knoten mit den höchsten Bewertungen, insbesondere für **Parser/Codecs** wie Hex-/Base64-/IP-/Message-Decoder.

### Mutation Survivors: äquivalent oder relevant

Mutation-Testing liefert oft eine unübersichtliche Liste von Survivors. Bevor du jeden Survivor als Sicherheitslücke behandelst, solltest du mithilfe des Graphen fragen:

- Ist die mutierte Funktion von einem vom Angreifer kontrollierten Einstiegspunkt aus erreichbar?
- Sind alle Aufrufpfade durch stärkere Invarianten eingeschränkt als die mutierte Prüfung?
- Liegt der Knoten in totem Code, reiner Formatierungslogik oder einem Arithmetik-/Parser-Pfad mit hohen Auswirkungen?

Survivors, die unerreichbar oder strukturell eingeschränkt bleiben, sind oft **äquivalente Mutanten**. Survivors, die weiterhin **erreichbar** sind und **Randbedingungen**, **Overflow-/Carry-Pfade** oder **sicherheitskritische Arithmetik/Parsing** betreffen, sollten ergänzt werden durch:

- neue Fuzz-Harnesses
- direkte Property-/Invarianten-Tests
- gezielte Edge-Case-Vektoren

### Externe Befunde dem Graphen zuordnen

Wenn deine SAST-Pipeline **SARIF** exportiert, ordne die Befunde den Graphknoten anhand von **Datei + Zeilenbereich** zu und nutze den Graphen, um die Auswirkungen zu ermitteln.<sup>[[6]](#references)</sup>

- Ermittle den **blast radius** der markierten Funktion.
- Prüfe, ob der Befund auf einem Pfad von einem Einstiegspunkt liegt.
- Gruppiere nahe beieinanderliegende Befunde, die auf denselben Engpass hinauslaufen.

Das hilft bei der Entscheidung, ob sich Fuzzing-Aufwand für eine bestimmte Funktion lohnt: Ein Knoten, der **erreichbar**, **komplex** und bereits von **SAST-Befunden** betroffen ist, ist oft ein besseres Ziel als ein lediglich komplexer Knoten ohne Angreiferpfad.

Beispiel-Workflow mit Trailmark.<sup>[[6]](#references)</sup>

```bash
uv pip install trailmark
trailmark analyze --complexity 10 path/to/project
```

```python
from trailmark.query.api import QueryEngine

engine = QueryEngine.from_directory("path/to/project", language="c")
engine.preanalysis()
engine.complexity_hotspots(10)
engine.paths_between("handle_request", "parse_ipv6")
```

Die wichtige Methodik ist die Schnittmenge: **Komplexität x Angriffsfläche x Auswirkung**. Verwende den Graphen, um Fuzzing-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und nutze überlebende Mutationen, um zu bestimmen, welche Grenzen und Invarianten dein Harness besonders stark testen muss.<sup>[[5]](#references)</sup>

## Differentiales Fuzzing kryptografischer Schlüsselcodierungen

Beginne mit gültigen serialisierten Schlüsseln oder standardisierten Testvektoren. Verändere codierte Felder, ohne die Länge und Struktur zu beschädigen, die nötig sind, um Import- und Operationspfade zu erreichen, und übergib dann dieselben Bytes an unabhängige Implementierungen. Vergleiche Annahme und Fehler. Randomisierte Signaturen und Chiffretexte benötigen Korrektheitsorakel statt eines byteweisen Vergleichs: Verifiziere Signaturen oder vergleiche die gemeinsamen Geheimnisse aus einem Kapselungs-/Entkapselungs-Roundtrip. Testvektoren belegen die Konformität für bekannte Fälle; differentielle Mutationen untersuchen darüber hinaus fehlerhafte Codierungen.<sup>[[23]](#references)[[26]](#references)</sup>

Verwende für diese Schlüsselformate formatspezifische Orakel:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **Erweiterte ML-DSA-Signaturschlüssel:** Verändere gepackte `s1`- oder `s2`-Koeffizienten so, dass sie außerhalb von `[-η, η]` liegen, und halte den Schlüssel dabei parsebar. Prüfe, ob der Import oder das Signieren abgelehnt wird und ob eine daraus resultierende Signatur verifiziert werden kann. Unterschiede bei der Annahme allein sind keine Verstöße gegen Standards, da FIPS 204 keine zusätzlichen Prüfungen privater Schlüssel vorschreibt. Siehe den [Mechanismus für bedingte Leaks](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM-Schlüsselpaare:** Trenne die erforderlichen Prüfungen des Kapselungsschlüssels und der Entkapselungseingabe von der optionalen paarweisen Konsistenzprüfung (PCT) eines importierten Schlüsselpaars. Kapsle mit dem öffentlichen Schlüssel, entkapsle mit dem privaten Schlüssel und vergleiche die gemeinsamen Geheimnisse; eine Abweichung kann die verschlüsselte Kommunikation beeinträchtigen, selbst wenn einzelne Schlüssel die Eingabeprüfungen bestehen. Prüfe, ob die API Eingaben während der Operation oder über einen separaten Aufruf validiert; libcrux stellt `validate_public_key(pk)` und `validate_private_key(sk, ct)` bereit, die eine PCT nicht ersetzen.
- **Rohe XMSS-/XMSSMT-Schlüssel:** Teste Roundtrips serialisierter **Signier- und Verifizierungsschlüssel** über verschiedene Parametersätze hinweg, nicht nur Operationen mit Schlüsseln im Arbeitsspeicher. XMSS und XMSSMT verwenden getrennte OID-Namespaces mit vier Byte; ein OID-basierter Parser, der zuerst XMSS ausprobiert, kann einen kollidierenden XMSSMT-Schlüssel falsch klassifizieren und den Import ablehnen. Der gemeldete RustCrypto-Parser veranschaulicht einen Interoperabilitäts-/Verfügbarkeitsfehler, keine Signaturfälschung.

## Go-Fuzzing mit gosentry: stärkere Engine, typisierte Eingaben und differentielle Prüfungen

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, ist es ein praktikabler Upgrade-Pfad, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen, einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

Das ist nützlich, wenn der native Go-Fuzzer bei **schwierigen Vergleichen**, **typisierten Eingaben** oder **parserlastigen Formaten** ins Stocken gerät. Die Methodik bleibt gleich:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness, führe ihn aber mit der `go`-Binary von gosentry statt mit der Standard-Toolchain aus.
- Behandle die resultierende Kampagne wie einen normalen Coverage-guided-Lauf, jedoch mit LibAFL-Scheduling/Mutation und besseren umgebenden Detektoren.

### Stille Fehler in Fuzzing-Befunde umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Crash verursacht. Mit gosentry kannst du mehrere Arten von „schlechten, aber stillen“ Zuständen zu Befunden machen.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Fehlerpfade wie Crashes behandelt werden (nützlich für `log.Fatal`-artige Codepfade, die andernfalls nur loggen und weiterlaufen).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go-Race-Detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks abzubrechen.
- LibAFL-Hang-Behandlung, damit **Endlosschleifen / sehr langsame Eingaben** als Fuzzing-Befunde erhalten bleiben, statt als Timeouts zu verschwinden.
- Standardmäßig integrierte Checks auf arithmetischen Overflow sowie optionale Truncation-Checks durch go-panikint-artige Instrumentierung.

Das ist besonders wertvoll für Targets, bei denen die Sicherheitsauswirkung eher ein **Parserfehler ohne Panic**, ein **Concurrency-Bug** oder ein **DoS-bedingter Hang** als Memory Corruption ist.

### Struct-aware Fuzzing für typisierte Go-APIs

Native Go-Fuzzing erwartet hauptsächlich Skalare wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **zusammengesetzte Werte** direkt fuzzing (Structs, Slices, Arrays, Pointer) und dabei weiterhin die zugrunde liegenden Bytes mutieren.<sup>[[7]](#references)[[8]](#references)</sup>

```go
type Input struct {
    Data []byte
    S    string
    N    int
}

func FuzzStructInput(f *testing.F) {
    f.Add(Input{Data: []byte("hello"), S: "world", N: 42})
    f.Fuzz(func(t *testing.T, in Input) {
        Process(in)
    })
}
```

Verwende dies, wenn ein gefälschtes Wire-Format, das nur fürs Fuzzing erstellt wurde, Logikfehler hinter Parsing-Code verbirgt, der nur im Harness verwendet wird. Bei Differential- oder grammar-based Kampagnen sollte die Harness-Eingabe ein einzelnes `[]byte` oder `string` bleiben, und das Parsing sollte stattdessen im Callback erfolgen.

### Grammar-based Fuzzing für Parser und Protokolleingaben

Für Parser, Formate und Eingabesprachen kann gosentry **Nautilus grammar fuzzing** auf Basis von LibAFL ausführen. Die Grammatik ist ein JSON-Array mit Produktionsregeln, und das Harness sollte üblicherweise ein einzelnes Argument vom Typ `[]byte` oder `string` entgegennehmen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodikhinweise:

- Verwende den Grammar-Modus, wenn Mutationen auf Byte-Ebene größtenteils schon an frühen Syntaxprüfungen scheitern.
- Beschränke die Grammatik auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls, statt die vollständige Spezifikation abzubilden.
- Verwende große Grenzwerte in Terminals/Nichtterminals, um Integer-, Längen- und Zustandsmaschinen-Grenzfälle zu testen.
- Der Grammar-Modus hält Eingaben grammatikalisch gültig, aber das Ziel empfängt weiterhin **Bytes/Strings** – Parsing und semantische Prüfungen bleiben also im geharnessten Code.

### Differential Fuzzing: Implementierungen vergleichen, nicht nur Abstürze

Ein starkes Muster für Go-Ökosysteme ist **grammatikbasiertes Differential Fuzzing**: gültige strukturierte Eingaben erzeugen und sie an zwei Parser, Clients oder Zustandsübergangs-Engines übergeben.<sup>[[7]](#references)[[8]](#references)</sup>

```go
f.Fuzz(func(t *testing.T, data []byte) {
    gotA, errA := ParseA(data)
    gotB, errB := ParseB(data)
    if (errA == nil) != (errB == nil) {
        t.Fatalf("parser disagreement: A=%v B=%v", errA, errB)
    }
    _ = gotA
    _ = gotB
})
```

Behandle Folgendes als Fund:

- eine Implementierung gerät in Panik, während die andere die Eingabe sauber zurückweist
- Abweichungen bei akzeptierten/zurückgewiesenen Eingaben
- unterschiedliche Parse-Bäume oder dekodierte Objekte
- abweichende Zustandsübergänge, Nonces, Salden oder State Roots

Auf diese praktische Weise lassen sich **Konsensabweichungen**, **Parser-Mehrdeutigkeit** und **Abweichungen zwischen Spezifikation und Implementierung** finden, die beim reinen Crash-Fuzzing oft unentdeckt bleiben.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Das Kampagnen-Korpus für Coverage-Berichte wiederverwenden

Spiele nach einer Kampagne das gespeicherte Queue-Korpus erneut ab, um einen Go-Coverage-Bericht zu erstellen, ohne ein separates Korpus manuell exportieren zu müssen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Führe den Befehl im **gleichen Package** und mit demselben `-fuzz`-Ziel aus, damit gosentry den richtigen Zustand der gecachten Kampagne auflöst.

{{#include ../banners/hacktricks-training.md}}

## References

- [1] [Mutationales Grammar-Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-gesteuertes Protokoll-Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark macht aus Code Graphen](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mit Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammar, kein Problem: Auf dem Weg zum Fuzzing des Linux-Kernels ohne System-Call-Beschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderbaren Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++-LLVM-Instrumentierung: Pfad- und Caller-Coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prädiktives kontextsensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog – Binder-Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL-Android-Binder-Fuzzer – Dokumentation zu Build und Regression-Seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Untersuchung von Race Conditions im Linux-Kernel mit kontrollierten Speicherzugriffs-Interleavings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Code-Coverage für Fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Erweiterte Dateinamenssyntax von CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-Advisory: CFITSIO Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing der erweiterten Dateinamenssyntax von CFITSIO: 16 Memory-Safety-Schwachstellen und Codex-unterstützte Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Differenzielles Fuzzing für Kryptografie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standard für schlüsselbasierte Kapselung auf Modullattices](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Fehler beim Parsen der XMSSMT-OID – RustCrypto-Issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stand der Implementierungen postquantenkryptografischer Verfahren](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
