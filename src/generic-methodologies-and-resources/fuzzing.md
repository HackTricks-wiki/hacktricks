# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Abdeckung vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs mutiert und bleiben dabei **grammatikkonform**. Im coverage-guided-Modus werden nur Samples als Corpus-Seeds gespeichert, die **neue Abdeckung** auslösen. Bei **Sprachzielen** (Parsern, Interpretern, Engines) können so Bugs übersehen werden, die **semantische Datenflussketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, erhält aber **den verketteten Datenfluss nicht aufrecht**. Dadurch wird das „dem Bug näher kommende“ Sample verworfen, weil es keine zusätzliche Abdeckung erzielt. Bei **3 oder mehr abhängigen Schritten** wird zufällige Rekombination aufwendig, und das Coverage-Feedback steuert die Suche nicht.<sup>[[1]](#references)</sup>

**Folgerung:** Bei Grammatiken mit vielen Abhängigkeiten sollte man **mutationale und generative Phasen kombinieren** oder die Generierung auf Muster mit **Funktionsverkettungen** ausrichten (nicht nur auf Abdeckung).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Diversität

Coverage-guided Mutation ist **greedy**: Ein Sample mit neuer Abdeckung wird sofort gespeichert und enthält oft große, unveränderte Bereiche. Mit der Zeit entstehen im Corpus **nahezu identische Duplikate** mit geringer struktureller Vielfalt. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktikabler Kompromiss ist daher eine **grammatikbewusste Minimierung**, die **bei einer Mindestanzahl von Tokens stoppt** (Rauschen reduzieren und zugleich genug umgebende Struktur erhalten, damit sich das Sample weiterhin gut mutieren lässt).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Eine kleine Anzahl strukturell unterschiedlicher Seeds mit maximaler Abdeckung ist einer großen Sammlung nahezu identischer Samples vorzuziehen.** In der Praxis bedeutet das üblicherweise Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Mit **realen Samples** beginnen (öffentliche Corpora, Crawling, aufgezeichneter Datenverkehr, Dateisammlungen aus dem Ziel-Ökosystem).
- Diese mit **coveragebasierter Corpus-Minimierung** reduzieren, statt jedes gültige Sample beizubehalten.
- Seeds **klein genug** halten, damit Mutationen sinnvolle Felder treffen, statt die meiste Zeit mit irrelevanten Bytes zu verbringen.
- Das Corpus nach größeren Änderungen am Harness oder an der Instrumentierung erneut minimieren, da sich das „beste“ Corpus mit veränderter Erreichbarkeit ändert.

## Große generierte Programme und Timeout-Verzerrung

Beim Fuzzing von Compilern und Interpretern muss ein Input möglicherweise einen **Schwellenwert für die Größe des generierten Codes** überschreiten, statt einen neuen Parser-Zweig zu erreichen. Im V8-[Beispiel zu Exception-Handler-Offsets](../binary-exploitation/chrome-exploiting.md#exception-handler-offsets-narrower-than-maximum-bytecode-size) musste ein gültiger Testfall über 256 MiB Bytecode umfassen, bevor der abgeschnittene Handler-Offset relevant wurde. Wiederholte `yield*`-Konstrukte konnten diesen Grenzwert erreichen, aber das Kompilieren des Testfalls dauerte in einem Debug-Build mehrere Sekunden. Bevorzugte kleine Inputs und kurze Execution-Timeouts können diese Art von Testfall benachteiligen, selbst bei hoher Grammatikabdeckung. Bei der Prüfung gepackter Offsets oder anderer längenabhängiger Metadaten sollten Schwellenwerte für die Größe und die Timeout-Richtlinie getrennt betrachtet werden. Dieser Rat für die Testkampagne ist eine Schlussfolgerung aus dem beschriebenen Fehlermodus.<sup>[[29]](#references)</sup>

## Vergleichsbewusste Mutation für Magic Values

Ein häufiger Grund dafür, dass Fuzzer an ihre Grenzen stoßen, sind keine Syntaxprobleme, sondern **harte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Zeichenfolgen, Checksummen oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder aufeinanderfolgende Vergleiche abgesichert sind. Bei reiner Zufallsmutation werden Zyklen damit verschwendet, diese Werte Byte für Byte zu erraten.

Für solche Ziele sollte **Comparison Tracing** eingesetzt werden (zum Beispiel AFL++-Workflows mit `CMPLOG` oder nach dem Redqueen-Prinzip), damit der Fuzzer Operanden fehlgeschlagener Vergleiche beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche bestehen.<sup>[[3]](#references)</sup>

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

- Das ist besonders nützlich, wenn das Ziel tiefer liegende Logik hinter **Dateisignaturen**, **Protokollverben**, **Typ-Tags** oder **versionsabhängigen Feature-Bits** verbirgt.
- Kombiniere dies mit **Dictionaries**, die aus echten Beispielen, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Dictionary mit Grammatik-Tokens, Chunk-Namen, Verben und Trennzeichen ist oft wertvoller als eine riesige generische Wordlist.
- Wenn das Ziel viele aufeinanderfolgende Prüfungen durchführt, löse zuerst die frühesten „Magic“-Vergleiche und minimiere anschließend den resultierenden Corpus erneut, damit spätere Stufen mit bereits gültigen Präfixen beginnen.

## Fuzzing von Datei-APIs, die eine Dateinamensprache verbergen

Ein Parameter namens `filename`, `path` oder `URL` kann ein Einstiegspunkt für einen Interpreter statt einer wörtlichen Dateisuche sein. Beispielsweise wertet die CFITSIO Extended Filename Syntax (EFS) Selektoren in eckigen Klammern, Zeilen-/Pixelausdrücke, berechnete Spalten, Histogramme und Transformationen aus, bevor das geöffnete Objekt zurückgegeben wird; einige Formen erstellen auch temporäre Kopien. Ordne bei der Erfassung der Angriffsfläche jede Open-/Import-API als **literal-path** oder **interpreted-path** ein und fuzz den Production-Einstiegspunkt, den Anwendungen tatsächlich aufrufen.<sup>[[20]](#references)[[22]](#references)</sup>

Die daraus entstehenden SSRF-, Dateikopier- und Protokollhandler-Primitives sowie sicherere literal-path-APIs werden unter [Filename mini-languages as SSRF/file primitives](../pentesting-web/ssrf-server-side-request-forgery/index.html#filename-mini-languages-as-ssrffile-primitives-cfitsio-efs) behandelt.<sup>[[20]](#references)</sup>

### Das zugrunde liegende Objekt vom gefuzzten Programm trennen

Wenn die Grammatik in einem Dateinamensuffix steckt, verfehlt das Mutieren ausschließlich der Bytes der referenzierten Datei den Parser. Ein kleiner Harness kann stattdessen einen Testfall als String einlesen und ihn an die interpretierte Open-API übergeben; die CFITSIO-Kampagne erreichte die meisten EFS-Parser und -Evaluatoren, indem sie `fits_open_file()` im schreibgeschützten Modus aufrief. Halte gültige Basisdateien separat verfügbar, damit sich Mutationen auf die Selektor-/Ausdruckssprache konzentrieren können, anstatt ständig den Basispfad zu beschädigen.<sup>[[22]](#references)</sup>

Verwende Seeds, die jeweils eine andere Grammatikfamilie erreichen, und leite anschließend ein kompaktes Dictionary sowohl aus der Spezifikation als auch aus dem Lexer-/Parser-Quellcode ab. Wenn die Coverage stagniert und Eingaben wiederholt am selben Syntaxfehlerpfad scheitern, bewahre gültige Präfixe und füge Trennzeichen, Operatoren, Keywords, Funktionsnamen und repräsentative Feldnamen hinzu, anstatt nur die Dauer der zufälligen Mutation zu erhöhen.<sup>[[22]](#references)</sup>

Führe den Harness mit dem Grammatik-Dictionary aus, zum Beispiel:<sup>[[3]](#references)[[22]](#references)</sup>

```bash
afl-fuzz -i filename-seeds -o out -x filename-language.dict -- ./filename-harness @@
```

### Nebeneffekte eines „read-only“-Harnesses eindämmen

Ein schreibgeschütztes Bibliotheks-Flag garantiert keinen nebenwirkungsfreien Testfall: Die Dateinamensprache kann die Eingabe umschreiben, Ausgabedateien erstellen oder temporäre Objekte materialisieren. Die CFITSIO-Kampagne zerstörte zunächst Seed-Dateien und hinterließ unerwartete Dateien im Dateisystem. Daher waren Bereinigung und Isolation erforderlich.<sup>[[22]](#references)</sup>

- Gib jedem Worker ein eigenes, entbehrliches Arbeitsverzeichnis und ein privates temporäres Verzeichnis.
- Stelle Kopien kanonischer Quelldateien bereit; lasse das Ziel niemals die einzige Kopie des Corpus verändern.
- Deaktiviere den Netzwerkzugriff, sofern Remote-Backends nicht das eigentliche Ziel sind, und beschränke beschreibbare Pfade mit einem Container, einem Mount-Namespace oder einer vergleichbaren Sandbox.
- Setze das Verzeichnis nach jeder Ausführung oder jedem Worker-Batch zurück und behandle unerwartete Änderungen am Dateisystem als zusätzliche Befunde.

### Crash-to-Patch-to-Fuzz-Schleife

Gruppiere Crashes vor der Behebung, damit aus Tausenden Artefakten nicht Tausende Patch-Aufgaben werden. Bei der CFITSIO-Bewertung reduzierte AFLTriage die anfängliche Crash-Menge auf einige wenige Grundursachen. Der daraus entstandene Hinweis zeigt verschiedene Fehler, darunter falsche Prüfungen der Zielgröße, veraltete Zeiger nach `realloc()`, Rechenfehler und unsichere Parser-Bereinigungspfade.<sup>[[21]](#references)[[22]](#references)</sup>

1. Minimiere für jede Gruppe eine repräsentative Eingabe und reproduziere den Fehler mit AddressSanitizer.
2. Halte den exakten fehlerhaften Zugriff, die Quellcodeposition, den Verlauf von Allokationen und Freigaben sowie den Parser-Zustand fest, durch den die Invariante verletzt wurde.
3. Wende einen eng begrenzten Patch-Kandidaten an und erstelle einen Build mit derselben Coverage- und Sanitizer-Instrumentierung.
4. Spiele den ursprünglichen Reproducer **und jede Eingabe seiner Gruppe** erneut ab. Aktiviere außerdem die Leak-Erkennung, da eine Memory-Safety-Korrektur die Speicherverwaltung in einem Fehlerpfad beeinträchtigen kann.
5. Führe Funktionstests mit echten Dateien aus und setze dann die Arbeit mit der angesammelten Queue fort (oder importiere diese Queue erneut, wenn die Engine nach einer Änderung der Binärdatei ein neues Ausgabeverzeichnis erfordert).
6. Wiederhole den Vorgang: Wird der erste oberflächliche Crash behoben, können vorhandene Seeds oft einen tieferen Parser-Zustand erreichen.

Ein LLM kann Schritt 2 beschleunigen und einen Entwurf für Schritt 3 erstellen, wenn es die crashauslösende Eingabe, den Sanitizer-Bericht, den Harness und den relevanten Quellcode erhält. Sein Patch bleibt jedoch ungeprüft. Ob die Korrektur akzeptiert wird, entscheiden die Sanitizer-Wiederholung und die Regressionstests – nicht die Erklärung des Modells.<sup>[[22]](#references)</sup>

## Aussagekräftigeres Feedback, wenn Edge Coverage unterschiedliche Pfade zusammenfasst

Normale Edge Coverage kann nicht zwischen zwei Ausführungen unterscheiden, die denselben Helper über verschiedene Aufrufer durchlaufen oder innerhalb einer Funktion unterschiedliche Kombinationen von Verzweigungen nehmen. Das ist bei gemeinsam genutzten Decodern, Protokoll-Dispatchern und Interpreter-Helpern relevant, bei denen der **Weg** zu einer Kante den aktiven Zustand bestimmt. Jede Aufrufkontext-Information naiv zu erfassen, ist ebenfalls riskant: Die Coverage-Map und die Queue können stark anwachsen. Die Forschung zu kontextsensitive Fuzzing empfiehlt daher, nur vielversprechende Kontexte weiter zu verfeinern, statt den gesamten Aufrufgraphen als kontextsensitiv zu behandeln.<sup>[[14]](#references)</sup>

Aktuelle AFL++-Builds bieten zusätzlich zur normalen Edge Coverage **Ball-Larus-Pfad-Coverage pro Funktion**. Dabei wird jedem azyklischen Pfad durch eine Funktion ein Feature zugewiesen; Schleifen-Rückkanten werden entfernt. Dieses Feedback unterscheidet also Verzweigungskombinationen, **nicht aber die Anzahl der Schleifendurchläufe**. Beginne mit dem lockeren Level `1` und beschränke strengere Modi auf verdächtigen Parser- oder Zustandsmaschinen-Code, da die Anzahl der Pfade exponentiell anwachsen kann.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Für eine Hilfsfunktion, die von vielen sicherheitsrelevanten Stellen aufgerufen wird, kann der LTO-Modus jeden Funktionspfad mit seiner unmittelbaren Aufrufstelle kombinieren:<sup>[[13]](#references)</sup>

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

**Kampagnenhinweis:** Reichhaltigeres Feedback sollte maßvoll eingesetzt und seine Kosten für Coverage-Map und Queue überwacht werden.<sup>[[13]](#references)[[14]](#references)</sup>

- Eine gewöhnliche Edge-Coverage-Instanz parallel ausführen; reichhaltigeres Feedback ist nur dann nützlich, wenn die zusätzlichen Kosten für Queue und Map die Ausführungen pro Sekunde nicht zu stark verringern.
- `AFL_LLVM_ALLOWLIST` verwenden, um die Instrumentierung von Pfaden und Aufrufern einzuschränken, wenn große, vorlagenlastige Bibliotheken oder generischer Hilfscode die Map dominieren.
- Funktionen mit übermäßig vielen azyklischen Pfaden können von AFL++ übersprungen werden; Warnungen während der Kompilierung weisen darauf hin, dass das Ziel eine Allowlist oder eine weniger strenge Stufe benötigt.
- Caller- plus Path-Coverage unterstützt nur eine Aufrufertiefe. Nicht mit tieferen Kontextstacks kombinieren.
- Pfad-IDs können sich zwischen LLVM-Hauptversionen ändern. Die Toolchain während einer Kampagne unverändert lassen und PATH-basierte Corpora nicht synchronisieren, als wären ihre Feature-IDs über Builds hinweg stabil.
- Dieses Feedback ergänzt `CMPLOG`: Comparison Tracing ermittelt, **welcher Wert eine Guard-Bedingung erfüllt**, während Path-/Caller-Feedback bewahrt, **welcher Weg und welche Zweigkombination dorthin geführt haben**.

## Zustandsbehaftetes Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist die interessante Einheit oft nicht ein einzelner Blob, sondern eine **Nachrichtensequenz**. Das gesamte Transkript in eine Datei zu konkatenieren und blind zu mutieren ist meist ineffizient, da der Fuzzer alle Schritte gleichermaßen mutiert, selbst wenn nur die spätere Nachricht den anfälligen Zustand erreicht.<sup>[[4]](#references)</sup>

Effektiver ist es, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Antwortcodes, Protokollzustände, Parserphasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- **Gültige Präfixnachrichten** stabil halten und Mutationen auf die **übergangsbestimmende** Nachricht konzentrieren.
- Bezeichner und vom Server generierte Werte aus vorherigen Antworten zwischenspeichern, wenn der nächste Schritt davon abhängt.
- Nachrichten einzeln mutieren oder splicen, statt das gesamte serialisierte Transkript als undurchsichtigen Blob zu mutieren.
- Wenn das Protokoll aussagekräftige Antwortcodes liefert, diese als **kostengünstigen Zustandsorakel** verwenden, um Sequenzen zu priorisieren, die weiter vorankommen.

Aus demselben Grund werden authentifizierte Bugs, verborgene Übergänge oder Parser-Bugs, die „nur nach dem Handshake“ auftreten, beim herkömmlichen dateibasierten Fuzzing oft übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

### Android Binder: Fuzzing mit mehreren Clients

Eine hohe Edge-Coverage kann IPC-Treiber-Bugs dennoch übersehen, weil Coverage **Objektbesitz, Referenzzähler, ausstehende Nachrichten, Bereinigungsreihenfolge oder Thread-Interleavings** nicht beschreibt. Die Seite [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) behandelt das Treiberobjektmodell; dieses Beispiel konzentriert sich auf den Fuzzer-Harness. Android Binder ist ein nützliches Modell: Es reicht nicht, sowohl den Allokations- als auch den Freigabepfad zu erreichen, wenn der Fuzzer nicht mehrere Prozesse in der erforderlichen Reihenfolge auf dasselbe Kernelobjekt einwirken lassen kann.<sup>[[15]](#references)</sup>

#### Das Protokoll modellieren, nicht isolierte `ioctl`-Puffer

Einen Testfall als geordnete Grammatik aus **Client-Identität + Operation + strukturierten Argumenten** darstellen. Der Binder-LKL-Fuzzer verwendet protobuf und `libprotobuf-mutator`, mit einem persistenten Context-Manager-Client und zwei gewöhnlichen Clients. Ein semantischer Harness bewahrt anschließend die Beziehungen, die durch blinde Byte-Mutationen verloren gingen.<sup>[[15]](#references)</sup>

- Von früheren Operationen zurückgegebene Werte zwischenspeichern. Beispielsweise muss `BC_FREE_BUFFER` einen Transaktionspufferzeiger wiederverwenden, der von einem vorherigen `ioctl` zurückgegeben wurde.
- Gültige Standardantworten generieren, damit synchrone Transaktionen abgeschlossen werden können und spätere Operationen erreichbar bleiben.
- Unmögliche Übergänge wie Selbsttransaktionen oder mehrere ausstehende Transaktionen an dasselbe Ziel zurückweisen.
- Singleton-Bootstrap-Zustand außerhalb des Resets pro Eingabe halten. Binder erlaubt pro Boot nur eine Registrierung mit `BINDER_SET_CONTEXT_MGR`; würde dieser Client wiederholt zerstört und neu erstellt, wären spätere Eingaben ungültig.

Eine nützliche Vorlage für ein Lifetime-Race besteht darin, einen Client ein Objekt übertragen zu lassen, die Bereinigung eines Threads oder Prozesses zu starten und den empfangenden Client gleichzeitig den Transaktionspuffer freigeben zu lassen. Im Beispiel CVE-2020-0423 konnte eine Übertragung von `BINDER_TYPE_WEAK_BINDER`, gefolgt von `BINDER_THREAD_EXIT` im Wettlauf mit `BC_FREE_BUFFER`, ein eingebettetes `binder_work` freigeben, während der Bereinigungspfad des beendenden Threads es noch verwendete.<sup>[[15]](#references)</sup>

#### Kontrollierte Interleavings in einem Userspace-Kernel wieder einführen

[Linux Kernel Library (LKL)](https://github.com/lkl/linux) bindet den echten Kernelcode in einen Userspace-Harness ein und stellt dessen Syscall-Schnittstelle über `lkl_syscall` bereit. Dadurch lassen sich protobuf-Zustand, Coverage und KASAN einfach in einem Prozess koordinieren. LKL führt einen Syscall normalerweise jedoch aus, ohne dass ein anderer Kernel-Thread ihn unterbricht. Für Race-Kampagnen `schedule()`-Punkte an ausgewählten Grenzen für Sperren und Lebensdauer einfügen und den Harness bei jeder Yield-Stelle zufällig den nächsten Client auswählen lassen. Diese Punkte gezielt setzen, da jeder einzelne den Suchraum für das Scheduling vergrößert. Der von den Forschern beschriebene Randomized Scheduler ist **nicht** Teil des Upstream-Binder-Fuzzers.<sup>[[15]](#references)</sup>

#### Serialisierte Regression-Seeds erstellen und erneut ausführen

Der Upstream-Harness pinnt eine kompatible Version von `libprotobuf-mutator`, aktiviert LKL-Fuzzing-Instrumentierung und KASAN mit `LKL_FUZZING=1` und aktiviert für Binder `CONFIG_MMU` mit `MMU=1`.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nachdem eine absichtlich verwundbare Revision ausgecheckt oder die upstream dokumentierten Rollback-Patches angewendet wurden, kann ein serialisierter Seed den gesamten Zustandsübergang über mehrere Clients reproduzieren, ohne ihn in einem ad-hoc-C-Proof-of-Concept rekonstruieren zu müssen:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandle den resultierenden KASAN use-after-free als Bestätigung dafür, dass der Seed den anfälligen Lebensdauerpfad erreicht hat. Er belegt **nicht** die späteren Primitives, die für die Ausführung von Kernel-Code oder eine Rechteausweitung erforderlich sind.<sup>[[16]](#references)</sup>

## Trick für Vielfalt auf einer einzelnen Maschine (Jackalope-Stil)

Eine praktische Möglichkeit, **generative Neuheit** mit **Wiederverwendung der Coverage** zu kombinieren, besteht darin, kurzlebige Worker gegen einen persistenten Server **neu zu starten**. Jeder Worker startet mit einem leeren Corpus, synchronisiert nach `T` Sekunden, arbeitet weitere `T` Sekunden mit dem zusammengeführten Corpus und synchronisiert erneut, bevor er beendet wird. Dadurch entstehen **in jeder Generation frische Strukturen**, während zugleich die angesammelte Coverage genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequentielle Worker (Beispielschleife):**

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

- `-in empty` erzwingt bei jeder Generierung einen **frischen Corpus**.
- `-server_update_interval T` approximiert eine **verzögerte Synchronisierung** (zuerst neue Eingaben, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **anfängliche Serversynchronisierung standardmäßig übersprungen** (kein Bedarf für `-skip_initial_server_sync`).
- Das optimale `T` ist **zielabhängig**; am besten funktioniert es meist, wenn umgestellt wird, nachdem der Worker den Großteil der „einfachen“ Coverage gefunden hat.

## Snapshot Fuzzing für schwer zu instrumentierende Ziele

Wenn der Code, den Sie testen möchten, erst **nach einem aufwendigen Setup** erreichbar ist (Starten einer VM, Abschluss eines Logins, Empfang eines Pakets, Parsen eines Containers, Initialisieren eines Dienstes), ist **Snapshot Fuzzing** eine nützliche Alternative: Erfassen Sie den Zustand des vorbereiteten Prozesses oder der VM, speisen Sie jeden Testfall in den Eingabepfad des Ziels ein, führen Sie die Ausführung bis zu einem Absturz oder Timeout fort und stellen Sie den Snapshot wieder her. So müssen Initialisierung oder Protokollpräfixe nicht wiederholt werden. Die Methode eignet sich für **Netzwerkdienste**, **Firmware**, **Angriffsflächen nach der Authentifizierung** und **Binary-only-Ziele**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führen Sie das Ziel aus, bis der relevante Zustand erreicht ist.
2. Erstellen Sie an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreiben Sie für jeden Testfall die mutierte Eingabe direkt in den relevanten Gast-/Prozesspuffer.
4. Führen Sie die Ausführung bis zu einem Absturz, Timeout oder Reset fort.
5. Stellen Sie den Snapshot wieder her; bei VM-Zielen stellen Sie, sofern unterstützt, nur die **dirty pages** wieder her und wiederholen Sie den Vorgang.

Platzieren Sie den Snapshot so nahe wie praktikabel am ersten aufwendigen Parse-/Dispatch-Schritt, beispielsweise nach einem `recv`-/`read`- oder Paket-Deserialisierungspunkt, und ermitteln Sie den vom Ziel verwendeten Eingabepuffer. Dies folgt dem Prinzip der adaptiven Platzierung: Der Snapshot wird tiefer in die Eingabeverarbeitung verschoben, um wiederholte Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

### Inkrementelle Snapshots für Protokollzustände

Ein fester Snapshot vermeidet zwar den Setup-Aufwand, erkundet aber nicht von selbst Übergänge, für die mehrere gültige Nachrichten erforderlich sind. Ein LibAFL-Qemu-Harness kann Schreibzugriffe auf ein Protokollzustandsfeld überwachen und bei einer Zustandsänderung einen neuen Snapshot speichern. Im [libslirp TCP harness](https://github.com/quarkslab/slirp_snapshots_stateful) überwacht es `tcpcb.t_state`, hasht Zustand und Antwort-Flags, um Snapshots zu deduplizieren, und speichert dirty pages relativ zu einem übergeordneten Snapshot. Vor der Mutation der nächsten strukturierten Nachricht stellt es den ausgewählten Snapshot über dessen Elternkette wieder her. Der Testfall speichert eine `SnapshotId` und generierte Eingabebytes (`gen_bytes`); der Snapshot-Manager verwaltet die für die Wiedergabe erforderliche Elternbeziehung.<sup>[[27]](#references)[[28]](#references)</sup>

Der User-Mode-`SnapshotModule` von LibAFL-Qemu speichert Mappings und den Speicher des Ziels, aber keine CPU-Register; bewahren Sie diese bei Bedarf separat auf. Der beschriebene Manager unterstützt einen Snapshot-Baum mit einer Wurzel und kann Snapshot-IDs nicht zwischen Workern teilen. Sein Multi-Snapshot-Modus kann außerdem den QASAN-Shadow-State nicht direkt wiederverwenden. Für die Offline-Triage erstellen Sie die Eingabekette in einem separaten instrumentierten Prozess neu. Bei Verwendung von `AsanHostModule` und `DrCovModule` führt `fuzzer.evaluate_input` die erforderlichen `pre_exec`-/`post_exec`-Callbacks aus; `qemu.run` allein tut dies nicht.<sup>[[27]](#references)[[28]](#references)</sup>

### Logische Ringpuffer-Überläufe erkennen

Ein Lesezugriff über die *Anzahl gültiger Daten* eines Puffers hinaus kann innerhalb seiner Host-Allokation bleiben und gewöhnlichem ASAN entgehen. Das [libslirp-Beispiel zu Urgent Data](../binary-exploitation/qemu-kvm-vm-escape-chains.md#tcp-urgent-pointer-vs-valid-ring-buffer-bytes) verursacht außerdem einen Underflow bei einer vorzeichenlosen Byteanzahl. Wenn der Quellcode verfügbar ist, kann eine Instrumentierung für vorzeichenbehaftete/vorzeichenlose Integer-Überläufe diesen Nebeneffekt erkennen; unterscheiden Sie absichtliche TCP-Sequenznummern-Überläufe, bevor Sie Meldungen unterdrücken. Eine stärkere vorgeschlagene Oracle-Lösung besteht darin, die benutzerdefinierte Ringpuffer-Allokation zu poisonen, nur gültige Bereiche zu entpoisonen, wenn der interne Allokator sie freigibt, und freigegebene Bereiche erneut zu poisonen. LibAFL-Qemu stellt eine ASAN-Poisoning-API für Ziele bereit, bei denen eine Instrumentierung des Quellcodes unpraktikabel ist.<sup>[[27]](#references)</sup>

## Linux-Kernel-Race-Exploration mit MAccConc

[MAccConc](https://github.com/googleprojectzero/MAccConc) macht zeitkritische Linux-Kernel-Races in wiederholbare Speicherzugriffspläne überführbar. Das Tool kann automatisch **A-B-A**-Abläufe mit zwei Kontexten aufzählen oder Analysten über eine Terminal-UI/GUI Reihenfolgebedingungen vorgeben lassen. Es handelt sich um experimentelle Forschungswerkzeuge und keinen vollständigen Concurrency-Fuzzer: Derzeit werden LLVM 23+ und der gepatchte Kernel des Projekts benötigt, die Kommandozeilen-Tools unterstützen zwei Test-Threads, und die vorgeschlagene Userspace-Fuzzing-Schicht ist nicht implementiert.<sup>[[17]](#references)[[18]](#references)</sup>

### Kommunikationspunkte zwischen Kontexten erfassen

Erstellen Sie den instrumentierten Kernel mit KASAN-Outline-Callbacks und der gepatchten KCOV-Unterstützung für Speicherzugriffsaufzeichnungen. Die README des Projekts empfiehlt außerdem, die Optimierung von Sibling Calls zu deaktivieren, damit Call Stacks weiterhin nutzbar sind.<sup>[[17]](#references)[[18]](#references)</sup>

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

Der KASAN-Outline-Modus (`asan-instrumentation-with-call-threshold=0`) wandelt instrumentierte Zugriffe in Helper-Aufrufe um. Die MAccConc-Kernel-Patches deaktivieren `asan-opt-same-temp`, damit aufeinanderfolgende Zugriffe nicht zusammengeführt werden; deaktiviere auch die Optimierung `asan-opt-globals`, wenn Data Races auf globale Variablen sichtbar sein müssen. KCOV überträgt die resultierenden Datensätze in den Userspace. Vergleiche Zugriffe aus unterschiedlichen Ausführungskontexten und behalte Paare bei, deren Byte-Bereiche sich überschneiden und bei denen mindestens eine Seite schreibt; modelliere `kfree()` als Schreibzugriff, damit auch Lebensdauerübergänge zu Kandidaten werden.<sup>[[17]](#references)</sup>

Bei Arbeit, die den initiierenden Task verlässt, etwa Paketverarbeitung oder RCU-Callbacks, muss das Subsystem ein KCOV-Remote-Coverage-Handle weitergeben. Upstream-Remote-KCOV ist optional und für beliebige Hintergrundarbeit nicht automatisch verfügbar. Eine fehlende Weitergabe kann daher eine reale Interaktion unsichtbar machen.<sup>[[17]](#references)[[19]](#references)</sup>

### Denselben dynamischen Zugriff bei jedem Lauf identifizieren

Spiele nicht gegen eine konkrete Heap-Adresse zurück, die sich nach jeder Allokation ändern kann, oder nur gegen eine Instruktionsadresse, die innerhalb von Helpern wie `memcpy()` und `spin_lock()` mehrdeutig ist. MAccConc verwendet einen **um Aufrufanzahlen ergänzten Stack-Trace**: Jeder Frame identifiziert einen Callee sowie dessen Aufrufanzahl innerhalb des Callers, und das letzte Element identifiziert die Speicherzugriffsinstruktion. SanitizerCoverage-Records für Funktionsaufrufe und -rückgaben ermöglichen es dem Userspace, diesen dynamischen Bezeichner zu rekonstruieren, der trotz Adressänderungen und unabhängigem Kontrollflussrauschen stabil bleibt.<sup>[[17]](#references)</sup>

### Kandidatenpaare in erzwungene Schedules umwandeln

Der gepatchte `KCOV_SET_DI`-ioctl ordnet einem um Aufrufanzahlen ergänzten Zugriffsbezeichner eine Aktion mit gemeinsam genutztem Flag zu.<sup>[[17]](#references)</sup>

| Aktion | Semantik |
| --- | --- |
| `DI_STACK_WAKE_PRE` | Setzt Flag *N* unmittelbar vor dem ausgewählten Zugriff. |
| `DI_STACK_WAIT` | Wartet vor dem ausgewählten Zugriff in einer Schleife, bis Flag *N* gesetzt ist oder das konfigurierte Limit abläuft. |
| `DI_STACK_WAKE_POST` | Setzt Flag *N* unmittelbar nach dem ausgewählten Zugriff. |

Für eine partielle **A-happens-before-B**-Bedingung weise A `DI_STACK_WAKE_POST` und B `DI_STACK_WAIT` mit demselben Flag zu. Für einen vollständig festgelegten Schedule mit zwei Kontexten wird B zunächst blockiert; dann weckt A B auf und wartet am ersten Übergabepunkt. Beim nächsten Übergang führt B die umgekehrte Operation aus. Das wirkt wie deterministisches Context-Switching und wird vom automatischen A-B-A-Explorer verwendet.<sup>[[17]](#references)</sup>

Eine minimale Kampagne besteht darin, den Testfall mit vier Hooks (`test_setup`, zwei Thread-Funktionen und `test_end`) als Shared Library zu kompilieren, einen nicht eingeschränkten Trace zu sammeln und anschließend A-B-A-Kandidaten aufzuzählen oder manuelle Bedingungen um verdächtige Zugriffe hinzuzufügen.<sup>[[18]](#references)</sup>

```bash
cc -shared -fPIC -o testcase.so testcase.c
./kcov-autorace ./testcase.so
# or interactively:
./kcov-terminal ./testcase.so
```

Timeouts getrennt von erfolgreichen Umordnungen interpretieren: Eine angeforderte Reihenfolge kann unmöglich sein, weil ein Lock oder eine Initialisierungs-/Veröffentlichungsabhängigkeit verhindert, dass der zweite Kontext seinen Injection Point erreicht. Behalte auch die blinden Flecken von KASAN im Blick: Direkte Stack-Zugriffe werden normalerweise nicht abgefangen, außer sie könnten außerhalb der Grenzen liegen; globale Variablen werden bei der Standardoptimierung ausgelassen, und aktuelle Compiler können ASAN- und TSAN-Hooks nicht gleichzeitig ausgeben. Außerdem verliert der Prototyp bei einem Panic des Gasts seinen KCOV-Puffer. Halte daher eine unabhängige Crash-Konsole bzw. ein unabhängiges Oracle bereit.<sup>[[17]](#references)</sup>

Für zukünftiges Concurrency-guided Fuzzing können pro Input oder Syscall Speicherzugriffszusammenfassungen erfasst, Operationen gruppiert werden, die Kommunikationspunkte zwischen Kontexten bilden würden, und anschließend nur diese Kombinationen untersucht werden. VM-Snapshots stabilisieren den globalen Zustand und die Adressen; ohne Snapshots können Allokationsstellen-Metadaten Objekte über mehrere Durchläufe hinweg abstrahieren. Dies ist eine vorgeschlagene Erweiterung, keine Funktion der aktuellen MAccConc-Userspace-Tools.<sup>[[17]](#references)</sup>

## Harness-Introspektion: Oberflächliche Fuzzer früh erkennen

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am **Mutator**, sondern am **Harness**. Nutze die **Reachability-/Coverage-Introspektion**, um Funktionen zu finden, die statisch von deinem Fuzz-Target aus erreichbar sind, dynamisch aber selten oder gar nicht abgedeckt werden. Solche Funktionen weisen üblicherweise auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness erreicht das Target zu spät oder zu früh.
- Im Seed-Corpus fehlt eine ganze Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** statt eines übergroßen „Alles-erledigen“-Harnesses.

Wenn du OSS-Fuzz-/ClusterFuzz-ähnliche Workflows verwendest, kann Fuzz Introspector die statische Erreichbarkeit mit der Laufzeit-Coverage vergleichen und Berichte aus einem zeitlich begrenzten Lauf oder einem öffentlichen Corpus erstellen.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Nutze den Bericht, um zu entscheiden, ob ein neuer Harness für einen bislang nicht getesteten Parserpfad hinzugefügt, der Corpus für ein bestimmtes Feature erweitert oder ein monolithischer Harness in kleinere Einstiegspunkte aufgeteilt werden soll.

## Graph-first-Auswahl von Fuzz-Targets und Mutation-Triage

Wenn bereits **Befunde aus der statischen Analyse**, **Überlebende des Mutationstests** und **Coverage-Berichte** vorliegen, sollten diese nicht als voneinander unabhängige Listen triagiert werden. Erstelle zuerst einen **Callgraph**, ergänze die Knoten um **zyklomatische Komplexität**, **Erreichbarkeit von Einstiegspunkten und nicht vertrauenswürdigen Eingaben** sowie externe Befunde und stelle dann Fragen zum Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von nicht vertrauenswürdigen Eingaben aus erreichbar?
- Welche Mutation-Survivors liegen auf Pfaden von Parsern/Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großem **Blast Radius**?

So lassen sich in der Regel bessere Fuzz-Targets finden als allein anhand der „niedrigsten Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** ist ein besserer Kandidat für einen Harness als ein isolierter interner Helper mit schwacher Coverage, der jedoch keinen vom Angreifer kontrollierten Pfad hat.

### Praktischer Triage-Workflow

1. Erstelle einen **Codegraphen** aus der Codebasis und ermittle Komplexitäts-/Branch-Metriken für jede Funktion.
2. Ermittle **Einstiegspunkte**, die vom Angreifer kontrollierte Eingaben akzeptieren: Request-Handler, Decoder, Importer, Protokollparser, CLI-/Datei-Reader.
3. Führe **Pfadabfragen** von diesen Einstiegspunkten zu potenziellen Funktionen aus, um erreichbare Angriffsfläche von totem oder nur internem Code zu trennen.
4. Priorisiere Knoten, die Folgendes vereinen:
   - hohe **zyklomatische Komplexität**
   - bestätigte **Erreichbarkeit von nicht vertrauenswürdigen Eingaben**
   - großen **Blast Radius** oder viele nachgelagerte Abhängigkeiten
   - bestätigende Hinweise wie **SARIF**-Befunde, Audit-Notizen oder Mutation-Survivors
5. Schreibe zuerst gezielte Harnesses für die Knoten mit der höchsten Bewertung, insbesondere für **Parser/Codecs** wie Hex-/Base64-/IP-/Nachrichten-Decoder.

### Mutation-Survivors: äquivalent oder relevant

Mutation Testing erzeugt oft eine unübersichtliche Liste von Survivors. Bevor jeder Survivor als Sicherheitslücke eingestuft wird, solltest du anhand des Graphen Folgendes prüfen:

- Ist die mutierte Funktion von einem vom Angreifer kontrollierten Einstiegspunkt aus erreichbar?
- Sind alle Aufrufpfade durch stärkere Invarianten eingeschränkt als die mutierte Prüfung?
- Liegt der Knoten in totem Code, rein formatierungsbezogener Logik oder einem Arithmetik-/Parserpfad mit hohen Auswirkungen?

Survivors, die unerreichbar bleiben oder strukturell eingeschränkt sind, sind oft **äquivalente Mutanten**. Survivors, die **erreichbar** bleiben und **Randbedingungen**, **Overflow-/Carry-Pfade** oder sicherheitskritische Arithmetik/Parsing betreffen, sollten in Folgendes aufgenommen werden:

- neue Fuzz-Harnesses
- direkte Property-/Invarianztests
- gezielte Edge-Case-Vektoren

### Externe Befunde mit dem Graphen korrelieren

Wenn deine SAST-Pipeline **SARIF** exportiert, ordne Befunde anhand von **Datei + Zeilenbereich** den Graphknoten zu und nutze den Graphen, um die Auswirkungen zu ermitteln.<sup>[[6]](#references)</sup>

- Ermittle den **Blast Radius** der markierten Funktion.
- Prüfe, ob der Befund auf einem Pfad von einem Einstiegspunkt liegt.
- Gruppiere nahe beieinanderliegende Befunde, die auf denselben Engpass hinauslaufen.

Das hilft bei der Entscheidung, ob sich Fuzzing-Aufwand für eine bestimmte Funktion lohnt: Ein Knoten, der **erreichbar**, **komplex** und bereits von **SAST-Befunden** betroffen ist, ist oft ein besseres Target als ein lediglich komplexer Knoten ohne Angreiferpfad.

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

Die wichtige Methodik ist die Schnittmenge: **Komplexität x Angriffsfläche x Auswirkung**. Verwende den Graphen, um Fuzzing-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und nutze überlebende Mutationen, um zu bestimmen, welche Grenzen und Invarianten dein Harness besonders belasten muss.<sup>[[5]](#references)</sup>

## Differential Fuzzing kryptografischer Schlüsselkodierungen

Beginne mit gültigen serialisierten Schlüsseln oder standardisierten Testvektoren. Verändere kodierte Felder, ohne die Länge und Struktur zu beschädigen, die erforderlich sind, um Import- und Operationspfade zu erreichen, und übergib dann dieselben Bytes an unabhängige Implementierungen. Vergleiche Annahmeverhalten und Fehler. Für randomisierte Signaturen und Ciphertexte sind Korrektheitsorakel erforderlich, kein Byte-für-Byte-Vergleich: Verifiziere Signaturen oder vergleiche die gemeinsamen Geheimnisse aus einem Kapselungs-/Entkapselungs-Roundtrip. Testvektoren belegen die Konformität für bekannte Fälle; differentielle Mutationen untersuchen darüber hinaus fehlerhafte Kodierungen.<sup>[[23]](#references)[[26]](#references)</sup>

Verwende für diese Schlüsselformate formatspezifische Orakel:<sup>[[24]](#references)[[25]](#references)[[26]](#references)</sup>

- **ML-DSA-erweiterte Signaturschlüssel:** Verändere gepackte `s1`- oder `s2`-Koeffizienten so, dass sie außerhalb von `[-η, η]` liegen, und halte den Schlüssel dabei weiterhin parsebar. Prüfe, ob der Import oder das Signieren den Schlüssel zurückweist und ob eine daraus erzeugte Signatur verifiziert werden kann. Unterschiede beim Annahmeverhalten allein sind keine Verstöße gegen Standards, da FIPS 204 keine zusätzlichen Prüfungen privater Schlüssel vorschreibt. Siehe den [Mechanismus bedingter Informationslecks](../crypto/public-key/#malformed-ml-dsa-signing-keys-and-rejection-sampling-leakage).
- **ML-KEM-Schlüsselpaare:** Unterscheide die vorgeschriebenen Prüfungen des Kapselungsschlüssels und der Entkapselungseingabe von der optionalen paarweisen Konsistenzprüfung (PCT) eines importierten Schlüsselpaars. Kapsle mit dem öffentlichen Schlüssel, entkapsle mit dem privaten Schlüssel und vergleiche die gemeinsamen Geheimnisse; eine Abweichung kann verschlüsselte Kommunikation beeinträchtigen, selbst wenn einzelne Schlüssel die Eingabeprüfungen bestehen. Prüfe, ob die API Eingaben während der Operation oder über einen separaten Aufruf validiert. libcrux stellt `validate_public_key(pk)` und `validate_private_key(sk, ct)` bereit; diese ersetzen keine PCT.
- **Rohe XMSS-/XMSSMT-Schlüssel:** Teste Roundtrips serialisierter **Signier- und Verifizierungsschlüssel** über verschiedene Parametersätze hinweg und nicht nur Operationen mit Schlüsseln im Speicher. XMSS und XMSSMT verwenden separate Vier-Byte-OID-Namensräume. Ein OID-only-Parser, der zuerst XMSS ausprobiert, kann daher einen kollidierenden XMSSMT-Schlüssel falsch klassifizieren und den Import zurückweisen. Der gemeldete RustCrypto-Parser veranschaulicht einen Interoperabilitäts-/Verfügbarkeitsfehler, keine Signaturfälschung.

## Go Fuzzing mit gosentry: leistungsstärkerer Engine, typisierte Eingaben und differentielle Prüfungen

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, ist es ein praktischer Upgrade-Pfad, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen – einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

This ist nützlich, wenn der native Go-Fuzzer bei **schwierigen Vergleichen**, **typisierten Eingaben** oder **parserlastigen Formaten** ins Stocken gerät. Die Methodik bleibt gleich:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness, führe ihn aber mit der `go`-Binary von gosentry statt mit der Standard-Toolchain aus.
- Behandle die resultierende Kampagne wie einen normalen coverage-guided-Lauf, jedoch mit LibAFL-Scheduling/Mutation und besseren begleitenden Detektoren.

### Stille Fehler in Fuzzing-Findings umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Crash verursacht. Mit gosentry lassen sich mehrere Arten von „schlechten, aber stillen“ Zuständen zu Findings machen.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...` lässt ausgewählte Logging-/Fehlerpfade wie Crashes reagieren (nützlich für `log.Fatal`-ähnliche Codepfade, die sonst nur protokollieren und fortfahren).
- `--catch-races=true` führt neu entdeckte Queue-Einträge erneut mit dem Go Race Detector aus.
- `--catch-leaks=true` führt neue Queue-Einträge erneut mit `goleak` aus und stoppt bei Goroutine-Leaks.
- Die LibAFL-Behandlung von Hängern sorgt dafür, dass **Endlosschleifen / sehr langsame Eingaben** als Fuzzing-Findings erhalten bleiben, statt als Timeouts zu verschwinden.
- Integrierte Prüfungen auf arithmetischen Überlauf sind standardmäßig aktiviert; optionale Truncation-Prüfungen sind über Instrumentierung im Stil von go-panikint möglich.

Das ist besonders wertvoll für Ziele, bei denen die Sicherheitsauswirkung eher ein **Parserfehler ohne Panic**, ein **Nebenläufigkeitsfehler** oder ein **DoS-Hänger** als eine Speicherbeschädigung ist.

### Struct-aware Fuzzing für typisierte Go-APIs

Native Go-Fuzzing erwartet hauptsächlich Skalare wie `[]byte`, `string` und Zahlen. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **zusammengesetzte Werte** direkt fuzzing-basiert testen (Structs, Slices, Arrays, Pointer) und dabei weiterhin die zugrunde liegenden Bytes mutieren.<sup>[[7]](#references)[[8]](#references)</sup>

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

Verwende dies, wenn der Aufbau eines Fake-Wire-Formats nur für Fuzzing Logikfehler hinter Parsing-Code verbergen würde, der nur im Harness vorhanden ist. Bei Differential- oder Grammar-based-Kampagnen sollte die Harness-Eingabe ein einzelnes `[]byte` oder `string` bleiben und stattdessen innerhalb des Callbacks geparst werden.

### Grammar-basiertes Fuzzing für Parser und Protokolleingaben

Für Parser, Formate und Eingabesprachen kann gosentry **Nautilus-Grammatik-Fuzzing** auf LibAFL ausführen. Die Grammatik ist ein JSON-Array aus Produktionsregeln, und das Harness sollte üblicherweise ein einzelnes `[]byte`- oder `string`-Argument annehmen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodik-Notizen:

- Verwende den Grammar Mode, wenn Byte-Level-Mutationen meist schon bei frühen Syntaxprüfungen scheitern.
- Beschränke die Grammar auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls, statt die gesamte Spezifikation abzubilden.
- Verwende große Grenzwerte in Terminals/Nichtterminalen, um Integer-, Längen- und Zustandsmaschinen-Grenzfälle zu testen.
- Der Grammar Mode hält Eingaben grammar-valide, aber das Ziel erhält weiterhin **Bytes/Strings**. Parsing und semantische Prüfungen bleiben also im instrumentierten Code.

### Differential Fuzzing: Implementierungen vergleichen, nicht nur Abstürze

Ein bewährtes Muster für Go-Ökosysteme ist **grammar-based differential fuzzing**: Gültige, strukturierte Eingaben generieren und sie an zwei Parser, Clients oder Zustandsübergangs-Engines übergeben.<sup>[[7]](#references)[[8]](#references)</sup>

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

Betrachte Folgendes als Befunde:

- Eine Implementierung bricht mit einer Panic ab, während die andere die Eingabe sauber zurückweist.
- Abweichungen darin, welche Eingaben akzeptiert oder zurückgewiesen werden
- Unterschiedliche Syntaxbäume oder dekodierte Objekte
- Abweichende Zustandsübergänge, Nonces, Kontostände oder Zustandswurzeln

So lassen sich **Konsensabweichungen**, **Parser-Mehrdeutigkeit** und **Abweichungen zwischen Spezifikation und Implementierung** auf praktische Weise finden, die reines Crash-Fuzzing oft übersieht.

{{#ref}}
proof-assistant-formal-verification-security.md
{{#endref}}

### Den Kampagnen-Corpus für die Coverage-Berichterstellung wiederverwenden

Spiele nach einer Kampagne den gespeicherten Queue-Corpus erneut ab, um einen Go-Coverage-Bericht zu erstellen, ohne den Corpus manuell separat exportieren zu müssen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Führe den Befehl aus demselben Package und mit demselben `-fuzz`-Target aus, damit gosentry den richtigen gecachten Campaign-Zustand findet.

## References

- [1] [Mutational Grammar Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-gesteuertes Protocol-Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verwandelt Code in Graphen](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mit Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammatik, kein Problem: Linux-Kernel-Fuzzing ohne Systemaufrufbeschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderlichen Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++-LLVM-Instrumentierung: Pfad- und Caller-Coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prädiktives kontextsensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog – Binder-Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL-Android-Binder-Fuzzer – Dokumentation zu Build und Regression-Seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
- [17] [MAccConc: Untersuchung von Race Conditions im Linux-Kernel mit kontrollierten Speicherzugriffs-Interleavings](https://projectzero.google/2026/09/maccconc-race-condition.html)
- [18] [googleprojectzero/MAccConc](https://github.com/googleprojectzero/MAccConc)
- [19] [KCOV: Code-Coverage für Fuzzing](https://docs.kernel.org/dev-tools/kcov.html)
- [20] [Erweiterte Dateinamensyntax von CFITSIO](https://heasarc.gsfc.nasa.gov/docs/software/fitsio/filters.html)
- [21] [Doyensec-Sicherheitshinweis: CFITSIO, Q4 2025](https://www.doyensec.com/resources/Doyensec_Advisory_CFITSIO_Q42025.pdf)
- [22] [Fuzzing der erweiterten Dateinamensyntax von CFITSIO: 16 Memory-Safety-Schwachstellen und Codex-gestützte Triage](https://blog.doyensec.com/2026/04/20/cfitsio-fuzzing.html)
- [23] [Differenzielles Fuzzing für Kryptografie](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html)
- [24] [NIST FIPS 203: Standard für ein auf Modullattizen basierendes Schlüssel-Kapselungsverfahren](https://doi.org/10.6028/NIST.FIPS.203)
- [25] [Fehler beim Parsen der XMSSMT-OID – RustCrypto-Issue #1442](https://github.com/RustCrypto/signatures/issues/1442)
- [26] [Stand der Implementierungen Post-Quanten-Kryptografie](http://blog.quarkslab.com/state-of-post-quantum-cryptography-implementations.html)
- [27] [Mit Snapshots zu CVE-2026-9539](http://blog.quarkslab.com/snapshotting-our-way-to-cve-2026-9539.html)
- [28] [Quarkslab slirp_snapshots_stateful](https://github.com/quarkslab/slirp_snapshots_stateful)
- [29] [Project Zero – Fuzzer vs. KI: Vergleich von Fuzzilli und BigSleep für JavaScript-Engines](https://projectzero.google/2026/10/fuzzing-v-AI.html)
{{#include ../banners/hacktricks-training.md}}
