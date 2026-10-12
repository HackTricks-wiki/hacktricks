# Fuzzing-Methodik

{{#include ../banners/hacktricks-training.md}}

## Mutational Grammar Fuzzing: Coverage vs. Semantik

Beim **mutational grammar fuzzing** werden Inputs mutiert, bleiben dabei aber **grammatikkonform**. Im coverage-guided-Modus werden nur Samples als Corpus-Seeds gespeichert, die **neue Coverage** auslösen. Bei **Sprach-Targets** (Parsern, Interpretern, Engines) können so Bugs übersehen werden, die **semantische Datenflussketten** erfordern, bei denen die Ausgabe eines Konstrukts zur Eingabe eines anderen wird.<sup>[[1]](#references)</sup>

**Fehlermodus:** Der Fuzzer findet Seeds, die einzeln `document()` und `generate-id()` (oder ähnliche Primitives) ausführen, **erhält aber nicht den verketteten Datenfluss**. Dadurch wird das Sample, das dem Bug näherkommt, verworfen, weil es keine zusätzliche Coverage liefert. Bei **3 oder mehr abhängigen Schritten** wird zufällige Rekombination aufwendig, und das Coverage-Feedback leitet die Suche nicht.<sup>[[1]](#references)</sup>

**Folgerung:** Ziehe bei Grammatiken mit vielen Abhängigkeiten in Betracht, **mutationale und generative Phasen zu kombinieren** oder die Generierung auf Muster mit **verketteten Funktionen** auszurichten (nicht nur auf Coverage).<sup>[[1]](#references)</sup>

## Fallstricke bei der Corpus-Vielfalt

Coverage-guided-Mutation ist **greedy**: Ein Sample mit neuer Coverage wird sofort gespeichert und behält dabei oft große, unveränderte Bereiche. Mit der Zeit entstehen im Corpus **Beinahe-Duplikate** mit geringer struktureller Vielfalt. Aggressive Minimierung kann nützlichen Kontext entfernen. Ein praktischer Kompromiss ist daher eine **grammatikbewusste Minimierung**, die **bei einer Mindestanzahl von Tokens stoppt** (Rauschen reduzieren, aber genug umgebende Struktur erhalten, damit sich das Sample gut mutieren lässt).<sup>[[1]](#references)</sup>

Eine praktische Corpus-Regel für mutational fuzzing lautet: **Bevorzuge eine kleine Menge strukturell unterschiedlicher Seeds mit maximaler Coverage** gegenüber einem großen Haufen von Beinahe-Duplikaten. In der Praxis bedeutet das üblicherweise Folgendes.<sup>[[1]](#references)[[3]](#references)</sup>

- Beginne mit **realen Samples** (öffentlichen Corpora, Crawling, aufgezeichnetem Traffic, Dateisammlungen aus dem Ökosystem des Targets).
- Verdichte sie durch **coveragebasierte Corpus-Minimierung**, statt jedes gültige Sample zu behalten.
- Halte Seeds **klein genug**, damit Mutationen sinnvolle Felder treffen, anstatt die meiste Zeit mit irrelevanten Bytes zu verbringen.
- Führe nach größeren Änderungen am Harness oder an der Instrumentierung die Corpus-Minimierung erneut aus, denn das „beste“ Corpus ändert sich, wenn sich die Erreichbarkeit ändert.

## Vergleichsorientierte Mutation für Magic Values

Ein häufiger Grund dafür, dass Fuzzer an ihre Grenzen stoßen, ist nicht die Syntax, sondern **strikte Vergleiche**: Magic Bytes, Längenprüfungen, Enum-Strings, Prüfsummen oder Parser-Dispatch-Werte, die durch `memcmp`, Switch-Tabellen oder verkettete Vergleiche geschützt sind. Bei reiner Zufallsmutation werden Zyklen damit verschwendet, diese Werte Byte für Byte zu erraten.

Verwende für solche Targets **Comparison Tracing** (zum Beispiel AFL++-Workflows mit `CMPLOG` oder im Redqueen-Stil), damit der Fuzzer Operanden fehlgeschlagener Vergleiche beobachten und Mutationen auf Werte ausrichten kann, die diese Vergleiche bestehen.<sup>[[3]](#references)</sup>

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

- Das ist besonders nützlich, wenn das Ziel tiefere Logik hinter **Dateisignaturen**, **Protokollverben**, **Typ-Tags** oder **versionsabhängigen Feature-Bits** verbirgt.
- Kombiniere es mit **Wörterbüchern**, die aus echten Beispielen, Protokollspezifikationen oder Debug-Logs extrahiert wurden. Ein kleines Wörterbuch mit Grammatik-Tokens, Chunk-Namen, Verben und Trennzeichen ist oft wertvoller als eine riesige generische Wortliste.
- Wenn das Ziel viele aufeinanderfolgende Prüfungen durchführt, löse zuerst die frühesten „Magic“-Vergleiche und minimiere anschließend den resultierenden Corpus erneut, damit spätere Phasen mit bereits gültigen Präfixen beginnen.

## Aussagekräftigeres Feedback, wenn Edge-Coverage verschiedene Pfade zusammenfasst

Normale Edge-Coverage kann zwei Ausführungen nicht unterscheiden, die denselben Helper über verschiedene Aufrufer durchlaufen oder innerhalb einer Funktion unterschiedliche Kombinationen von Verzweigungen nehmen. Das ist bei gemeinsam genutzten Decodern, Protokoll-Dispatchern und Interpreter-Helpern relevant, bei denen der **Pfad** zu einer Edge den aktuellen Zustand bestimmt. Jeden Aufrufkontext naiv zu erfassen, ist ebenfalls gefährlich: Die Coverage-Map und die Queue können explodieren. Die Forschung zu kontextsensitivem Fuzzing empfiehlt daher, nur vielversprechende Kontexte genauer zu erfassen, statt den gesamten Call-Graph als kontextsensitiv zu behandeln.<sup>[[14]](#references)</sup>

Aktuelle AFL++-Builds bieten zusätzlich zur normalen Edge-Coverage eine **Ball-Larus-Pfadabdeckung pro Funktion**. Sie weist jedem azyklischen Pfad durch eine Funktion ein Feature zu; Schleifen-Back-Edges werden entfernt, sodass dieses Feedback Kombinationen von Verzweigungen unterscheidet, **nicht aber die Anzahl der Schleifendurchläufe**. Beginne mit dem lockeren Level `1` und beschränke strengere Modi anschließend auf verdächtigen Parser- oder Zustandsmaschinen-Code, da die Anzahl der Pfade exponentiell wachsen kann.<sup>[[13]](#references)</sup>

```bash
make clean
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_LLVM_PATH=1                 # 1=relaxed, 2=restricted, 3=strict
./configure
make -j"$(nproc)"
afl-fuzz -i in -o out -- ./target @@
```

Bei einem Helper, der von vielen sicherheitsrelevanten Stellen aufgerufen wird, kann der LTO-Modus jeden Funktionspfad mit seiner unmittelbaren Aufrufstelle kombinieren:<sup>[[13]](#references)</sup>

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

**Kampagnenhinweise:** Setze umfangreicheres Feedback sparsam ein und überwache seine Kosten für Coverage-Map und Queue.<sup>[[13]](#references)[[14]](#references)</sup>

- Führe parallel eine gewöhnliche Edge-Coverage-Instanz aus. Umfangreicheres Feedback ist nur dann sinnvoll, wenn die zusätzlichen Kosten für Queue und Map die Anzahl der Ausführungen pro Sekunde nicht zu stark verringern.
- Verwende `AFL_LLVM_ALLOWLIST`, um die Path-/Caller-Instrumentierung einzuschränken, wenn große, template-lastige Bibliotheken oder generischer Utility-Code die Map dominieren.
- Funktionen mit übermäßig vielen azyklischen Pfaden können von AFL++ übersprungen werden. Warnungen während der Kompilierung sind ein Hinweis darauf, dass das Ziel eine Allowlist oder einen weniger strengen Level benötigt.
- Caller- und Path-Coverage unterstützt nur eine Caller-Tiefe. Kombiniere es nicht mit tieferen Context-Stacks.
- Path-IDs können sich zwischen LLVM-Hauptversionen ändern. Verwende für eine Kampagne dieselbe Toolchain und synchronisiere PATH-basierte Corpora nicht so, als wären ihre Feature-IDs über Builds hinweg stabil.
- Dieses Feedback ergänzt `CMPLOG`: Comparison Tracing ermittelt, **welcher Wert eine Guard-Bedingung erfüllt**, während Path-/Caller-Feedback festhält, **welcher Pfad und welche Zweigkombination dorthin geführt haben**.

## Stateful Fuzzing: Sequenzen sind Seeds

Bei **Protokollen**, **authentifizierten Workflows** und **mehrstufigen Parsern** ist oft nicht ein einzelner Blob, sondern eine **Nachrichtensequenz** die interessante Einheit. Das gesamte Transkript in eine Datei zu schreiben und blind zu mutieren, ist meist ineffizient, weil der Fuzzer jeden Schritt gleichermaßen mutiert, obwohl nur die spätere Nachricht den fragilen Zustand erreicht.<sup>[[4]](#references)</sup>

Effektiver ist es, die **Sequenz selbst als Seed** zu behandeln und **beobachtbaren Zustand** (Antwortcodes, Protokollzustände, Parserphasen, zurückgegebene Objekttypen) als zusätzliches Feedback zu verwenden.<sup>[[4]](#references)</sup>

- Behalte **gültige Präfixnachrichten** bei und konzentriere Mutationen auf die Nachricht, die den **Zustandsübergang auslöst**.
- Zwischenspeichere IDs und serverseitig erzeugte Werte aus vorherigen Antworten, wenn der nächste Schritt davon abhängt.
- Bevorzuge Mutationen und Splicing einzelner Nachrichten, statt das gesamte serialisierte Transkript als undurchsichtigen Blob zu mutieren.
- Wenn das Protokoll aussagekräftige Antwortcodes liefert, verwende sie als **günstigen Zustandsorakel**, um Sequenzen zu priorisieren, die weiter vorankommen.

Aus demselben Grund werden authentifizierte Bugs, verborgene Übergänge oder Parser-Bugs, die „erst nach dem Handshake“ auftreten, oft beim herkömmlichen dateibasierten Fuzzing übersehen: Der Fuzzer muss **Reihenfolge, Zustand und Abhängigkeiten** bewahren, nicht nur die Struktur.<sup>[[4]](#references)</sup>

### Android Binder: Fuzzing mit mehreren Clients

Eine hohe Edge-Coverage kann IPC-Treiber-Bugs trotzdem übersehen, denn Coverage beschreibt nicht **Objektbesitz, Referenzzähler, ausstehende Nachrichten, Bereinigungsreihenfolge oder Thread-Interleavings**. Die Seite [Android Binder IPC internals](../binary-exploitation/linux-kernel-exploitation/android-binder-ipc-internals-kernel-vulnerability-research.md) behandelt das Treibermodell; dieses Beispiel konzentriert sich auf den Fuzzer-Harness. Android Binder ist ein nützliches Modell: Es reicht nicht, sowohl den Allokations- als auch den Freigabepfad zu erreichen, wenn der Fuzzer nicht mehrere Prozesse in der erforderlichen Reihenfolge auf dasselbe Kernelobjekt zugreifen lassen kann.<sup>[[15]](#references)</sup>

#### Das Protokoll modellieren, nicht isolierte `ioctl`-Puffer

Stelle einen Testfall als geordnete Grammatik aus **Client-Identität + Operation + strukturierten Argumenten** dar. Der Binder-LKL-Fuzzer verwendet protobuf und `libprotobuf-mutator`, mit einem persistenten Context-Manager-Client und zwei gewöhnlichen Clients. Ein semantischer Harness bewahrt dann die Beziehungen, die durch blinde Byte-Mutationen zerstört würden.<sup>[[15]](#references)</sup>

- Zwischenspeichere Werte, die von früheren Operationen zurückgegeben wurden. Beispielsweise muss `BC_FREE_BUFFER` einen Transaktionspufferzeiger wiederverwenden, der von einem vorherigen `ioctl` zurückgegeben wurde.
- Erzeuge gültige Standardantworten, damit synchrone Transaktionen abgeschlossen werden können und spätere Operationen erreichbar bleiben.
- Verwirf unmögliche Übergänge, etwa Transaktionen an sich selbst oder mehrere ausstehende Transaktionen an dasselbe Ziel.
- Belasse den einmaligen Bootstrap-Zustand außerhalb des Zurücksetzens pro Eingabe. Binder erlaubt pro Boot nur eine Registrierung mit `BINDER_SET_CONTEXT_MGR`; würde dieser Client wiederholt zerstört und neu erstellt, wären spätere Eingaben ungültig.

Ein nützliches Muster für Lifetime-Races besteht darin, einen Client ein Objekt übertragen zu lassen, die Bereinigung eines Threads oder Prozesses zu starten und gleichzeitig den empfangenden Client den Transaktionspuffer freigeben zu lassen. Im Beispiel CVE-2020-0423 konnte eine Übertragung mit `BINDER_TYPE_WEAK_BINDER`, gefolgt von einem `BINDER_THREAD_EXIT`, das mit `BC_FREE_BUFFER` konkurrierte, ein eingebettetes `binder_work` freigeben, während der Bereinigungspfad des beendenden Threads es noch verwendete.<sup>[[15]](#references)</sup>

#### Kontrollierte Interleavings in einem Userspace-Kernel wieder einführen

Die [Linux Kernel Library (LKL)](https://github.com/lkl/linux) bindet den echten Kernel-Code in einen Userspace-Harness ein und stellt dessen syscall-Schnittstelle über `lkl_syscall` bereit. So lassen sich protobuf-Zustand, Coverage und KASAN einfach in einem Prozess koordinieren. Normalerweise führt LKL einen syscall jedoch aus, ohne dass ihn ein anderer Kernel-Thread unterbricht. Füge für Race-Kampagnen `schedule()`-Punkte an ausgewählten Grenzen von Sperren und deren Freigabe sowie an Lifetime-Grenzen ein; der Harness kann dann bei jeder Übergabe zufällig den nächsten Client auswählen. Setze diese Punkte gezielt ein, da jeder zusätzliche Punkt den Scheduling-Suchraum vervielfacht. Der von den Forschern beschriebene randomisierte Scheduler ist **nicht** Teil des Binder-Fuzzers im Upstream.<sup>[[15]](#references)</sup>

#### Serialisierte Regression-Seeds erstellen und erneut ausführen

Der Upstream-Harness pinnt eine kompatible Version von `libprotobuf-mutator`, aktiviert mit `LKL_FUZZING=1` die LKL-Fuzzing-Instrumentierung und KASAN und aktiviert mit `MMU=1` `CONFIG_MMU` für Binder.<sup>[[16]](#references)</sup>

```bash
PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  tools/lkl/scripts/libprotobuf-mutator-build.sh

make -C tools/lkl LKL_FUZZING=1 MMU=1 \
  PROTOBUF_MUTATOR_DIR=/tmp/libprotobuf-mutator \
  clean-conf fuzzers -j"$(nproc)"
```

Nachdem man eine absichtlich verwundbare Revision ausgecheckt oder die upstream dokumentierten Rollback-Patches angewendet hat, kann ein serialisierter Seed den gesamten Multi-Client-Zustandsübergang reproduzieren, ohne ihn in einem ad-hoc C-Proof-of-Concept nachzubilden:<sup>[[16]](#references)</sup>

```bash
tools/lkl/fuzzers/binder/binder-fuzzer \
  tools/lkl/fuzzers/binder/seeds/CVE-2023-20938
```

Behandle den resultierenden KASAN-use-after-free als Bestätigung dafür, dass der Seed den anfälligen Lifetime-Pfad erreicht hat. Er belegt **nicht** die später erforderlichen Primitives für die Ausführung von Kernel-Code oder eine Privilegieneskalation.<sup>[[16]](#references)</sup>

## Diversitätstrick auf einer einzelnen Maschine (Jackalope-Stil)

Eine praktische Möglichkeit, **generative Neuheit** mit **wiederverwendeter Coverage** zu kombinieren, besteht darin, kurzlebige Worker auf einem persistenten Server neu zu starten. Jeder Worker beginnt mit einem leeren Corpus, synchronisiert nach `T` Sekunden, arbeitet weitere `T` Sekunden mit dem kombinierten Corpus, synchronisiert erneut und wird dann beendet. So entstehen **in jeder Generation neue Strukturen**, während die angesammelte Coverage weiterhin genutzt wird.<sup>[[1]](#references)[[2]](#references)</sup>

**Server:**

```bash
/path/to/fuzzer -start_server 127.0.0.1:8337 -out serverout
```

**Sequentielle Worker (Beispielschleife):**

<details>
<summary>Neustartschleife für Jackalope-Worker</summary>

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

- `-in empty` erzwingt bei jeder Generation einen **neuen Korpus**.
- `-server_update_interval T` approximiert eine **verzögerte Synchronisierung** (zuerst Novelty, später Wiederverwendung).
- Im Grammar-Fuzzing-Modus wird die **initiale Server-Synchronisierung standardmäßig übersprungen** (kein `-skip_initial_server_sync` erforderlich).
- Das optimale `T` ist **vom Target abhängig**; am besten funktioniert es in der Regel, wenn du umstellst, nachdem der Worker den größten Teil der „einfachen“ Coverage gefunden hat.

## Snapshot Fuzzing für Targets, die sich nur schwer mit einem Harness versehen lassen

Wenn der zu testende Code erst **nach hohen Setup-Kosten erreichbar wird** (Starten einer VM, Abschließen eines Logins, Empfangen eines Pakets, Parsen eines Containers, Initialisieren eines Dienstes), ist **Snapshot Fuzzing** eine nützliche Alternative: Erfasse den Zustand des bereiten Prozesses oder der VM, speise jeden Testfall in den Eingabepfad des Targets ein, führe ihn bis zu einem Crash/Timeout aus und stelle den Snapshot wieder her. Dadurch müssen Initialisierung und Protokollpräfixe nicht wiederholt werden. Diese Methode eignet sich für **Netzwerkdienste**, **Firmware**, **Angriffsflächen nach der Authentifizierung** und **Binary-only-Targets**.<sup>[[9]](#references)[[10]](#references)</sup>

1. Führe das Target aus, bis der interessante Zustand erreicht ist.
2. Erstelle an diesem Punkt einen Snapshot von **Speicher + Registern**.
3. Schreibe für jeden Testfall die mutierte Eingabe direkt in den relevanten Guest-/Prozesspuffer.
4. Führe den Code bis zu einem Crash/Timeout/Reset aus.
5. Stelle den Snapshot wieder her; bei VM-Targets stelle nur die **dirty pages** wieder her, sofern unterstützt, und wiederhole den Vorgang.

Platziere den Snapshot möglichst nahe am ersten aufwendigen Parse-/Dispatch-Schritt, etwa nach einem `recv`/`read` oder dem Deserialisieren eines Pakets, und halte den vom Target verwendeten Eingabepuffer fest. Dies entspricht dem Prinzip der adaptiven Platzierung: Der Snapshot wird tiefer in die Eingabeverarbeitung verschoben, um wiederholte Arbeit zu vermeiden.<sup>[[11]](#references)</sup>

## Harness-Introspektion: Flache Fuzzer frühzeitig erkennen

Wenn eine Kampagne ins Stocken gerät, liegt das Problem oft nicht am Mutator, sondern am **Harness**. Nutze **Reachability-/Coverage-Introspektion**, um Funktionen zu finden, die statisch von deinem Fuzz-Target aus erreichbar sind, aber dynamisch selten oder nie abgedeckt werden. Solche Funktionen deuten in der Regel auf eines von drei Problemen hin.<sup>[[12]](#references)</sup>

- Der Harness steigt zu spät oder zu früh in das Target ein.
- Im Seed-Korpus fehlt eine ganze Feature-Familie.
- Das Target benötigt tatsächlich einen **zweiten Harness** statt eines überladenen „Alles-erledigen“-Harness.

Wenn du Workflows im Stil von OSS-Fuzz / ClusterFuzz verwendest, kann Fuzz Introspector die statische Erreichbarkeit mit der Laufzeit-Coverage vergleichen und Berichte aus einem zeitlich begrenzten Lauf oder einem öffentlichen Korpus erstellen.<sup>[[12]](#references)</sup>

```bash
python3 infra/helper.py introspector libdwarf --seconds=30
python3 infra/helper.py introspector libdwarf --public-corpora
```

Nutzen Sie den Bericht, um zu entscheiden, ob Sie einen neuen Harness für einen ungetesteten Parser-Pfad hinzufügen, den Korpus für ein bestimmtes Feature erweitern oder einen monolithischen Harness in kleinere Einstiegspunkte aufteilen.

## Graph-First-Auswahl von Fuzzing-Zielen und Triage von Mutationen

Wenn Ihnen bereits **Static-Analysis-Befunde**, **Mutation-Testing-Überlebende** und **Coverage-Berichte** vorliegen, sollten Sie diese nicht als voneinander unabhängige Listen triagieren. Erstellen Sie zunächst einen **Aufrufgraphen**, annotieren Sie die Knoten mit **zyklomatischer Komplexität**, **Erreichbarkeit von Entry Points/untrusted input** und externen Befunden und untersuchen Sie anschließend den Graphen.<sup>[[5]](#references)[[6]](#references)</sup>

- Welche Funktionen mit hoher Komplexität sind von untrusted input aus erreichbar?
- Welche Mutation-Testing-Überlebenden liegen auf Pfaden von Parsern/Handlern zu sicherheitskritischem Code?
- Welche Funktionen sind architektonische Engpässe mit ungewöhnlich großem **Blast Radius**?

Damit lassen sich meist bessere Fuzzing-Ziele finden als allein mit „geringster Coverage“. Ein Parser/Decoder mit **hoher Komplexität** und bestätigter **externer Erreichbarkeit** ist ein aussichtsreicherer Kandidat für einen Harness als ein isolierter interner Helper mit geringer Coverage, aber ohne angreifergesteuerten Pfad.

### Praktischer Triage-Workflow

1. Erstellen Sie aus der Codebasis einen **Code-Graphen** und extrahieren Sie Komplexitäts-/Branch-Metriken pro Funktion.
2. Erfassen Sie **Entry Points**, die angreifergesteuerte Eingaben annehmen: Request-Handler, Decoder, Importer, Protokollparser, CLI-/Datei-Reader.
3. Führen Sie **Pfadabfragen** von diesen Entry Points zu Kandidatenfunktionen aus, um erreichbare Angriffsfläche von totem/nur internem Code abzugrenzen.
4. Priorisieren Sie Knoten, die Folgendes vereinen:
   - hohe **zyklomatische Komplexität**
   - bestätigte **Erreichbarkeit von untrusted input**
   - großer **Blast Radius** oder viele abhängige Funktionen
   - bestätigende Hinweise wie **SARIF**-Befunde, Audit-Notizen oder Mutation-Testing-Überlebende
5. Schreiben Sie zuerst fokussierte Harnesses für die Kandidaten mit der höchsten Bewertung, insbesondere für **Parser/Codecs** wie Hex-/Base64-/IP-/Message-Decoder.

### Mutation-Testing-Überlebende: äquivalent oder relevant

Mutation Testing erzeugt oft eine verrauschte Liste von Überlebenden. Bevor Sie jeden Überlebenden als Sicherheitslücke behandeln, prüfen Sie mithilfe des Graphen:

- Ist die mutierte Funktion von einem angreifergesteuerten Entry Point aus erreichbar?
- Sind alle Aufrufpfade durch stärkere Invarianten eingeschränkt als durch die mutierte Prüfung?
- Befindet sich der Knoten in totem Code, reiner Formatierungslogik oder in einem wirkungsstarken Arithmetik-/Parser-Pfad?

Überlebende, die unerreichbar oder strukturell eingeschränkt bleiben, sind oft **äquivalente Mutanten**. Überlebende, die **erreichbar** bleiben und **Grenzfälle**, **Overflow-/Carry-Pfade** oder **sicherheitskritische Arithmetik/Parsing** betreffen, sollten priorisiert werden für:

- neue Fuzz-Harnesses
- direkte Property-/Invariant-Tests
- gezielte Edge-Case-Vektoren

### Externe Befunde dem Graphen zuordnen

Wenn Ihre SAST-Pipeline **SARIF** exportiert, ordnen Sie die Befunde den Graph-Knoten anhand von **Datei + Zeilenbereich** zu und verwenden Sie den Graphen, um die Auswirkungen nachzuverfolgen.<sup>[[6]](#references)</sup>

- Berechnen Sie den **Blast Radius** der markierten Funktion.
- Prüfen Sie, ob der Befund auf einem Pfad von einem Entry Point liegt.
- Gruppieren Sie nahe beieinanderliegende Befunde, die auf denselben Engpass hinauslaufen.

Das hilft bei der Entscheidung, ob Sie Fuzzing-Zeit in eine bestimmte Funktion investieren sollten: Ein Knoten, der **erreichbar** und **komplex** ist und bereits **SAST-Treffer** aufweist, ist oft ein besseres Ziel als ein lediglich komplexer Knoten ohne Angreiferpfad.

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

Die entscheidende Methodik liegt in der Schnittmenge: **Komplexität x Angriffsfläche x Auswirkung**. Nutze das Diagramm, um Fuzzing-Ziele mit dem höchsten erwarteten Sicherheitswert auszuwählen, und ermittle anhand überlebender Mutationen, welche Grenzen und Invarianten dein Harness gezielt belasten muss.<sup>[[5]](#references)</sup>

## Go-Fuzzing mit gosentry: Stärkere Engine, typisierte Eingaben und Differentialprüfungen

Wenn ein Go-Ziel bereits über ein natives `testing.F`-Harness verfügt, ist es ein praktikabler Upgrade-Pfad, dasselbe Harness mit [gosentry](https://github.com/trailofbits/gosentry) auszuführen – einer geforkten Go-Toolchain, die `go test -fuzz` beibehält, aber das Backend durch **LibAFL** ersetzt.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --focus-on-new-code=false --catch-races=true --catch-leaks=true
```

This ist nützlich, wenn der native Go-Fuzzer bei **schwierigen Vergleichen**, **typisierten Eingaben** oder **parserlastigen Formaten** ins Stocken gerät. Die Methodik bleibt gleich:

- Verwende weiterhin `f.Add(...)` für Seeds und `f.Fuzz(...)` für den Callback.
- Verwende denselben Harness, führe ihn aber mit gosentrys `go`-Binary statt mit der Standard-Toolchain aus.
- Behandle die resultierende Kampagne wie einen normalen Coverage-guided-Run, aber mit LibAFL-Scheduling und -Mutation sowie besseren ergänzenden Detektoren.

### Stille Fehler in Fuzzing-Befunde umwandeln

Ein wiederkehrendes Problem bei Go-Assessments ist, dass gefährliches Verhalten standardmäßig oft **keinen** Crash verursacht. Mit gosentry kannst du mehrere Arten von „schlechten, aber stillen“ Zuständen in Befunde umwandeln.<sup>[[7]](#references)[[8]](#references)</sup>

- `--panic-on=pkg.Func,...`, damit ausgewählte Logging-/Fehlerpfade wie Crashes behandelt werden (nützlich für `log.Fatal`-artige Codepfade, die andernfalls nur loggen und fortfahren).
- `--catch-races=true`, um neu entdeckte Queue-Einträge mit dem Go Race Detector erneut auszuführen.
- `--catch-leaks=true`, um neue Queue-Einträge mit `goleak` erneut auszuführen und bei Goroutine-Leaks abzubrechen.
- LibAFL-Hang-Behandlung, damit **Endlosschleifen / sehr langsame Eingaben** als Fuzzing-Befunde erhalten bleiben, statt als Timeouts zu verschwinden.
- Integrierte Prüfungen auf arithmetischen Überlauf standardmäßig sowie optionale Truncation-Prüfungen durch go-panikint-artige Instrumentierung.

Das ist besonders wertvoll für Ziele, bei denen die Sicherheitsauswirkung ein **panicloser Parserfehler**, ein **Concurrency-Bug** oder ein **ausschließlich DoS-relevanter Hang** statt einer Speicherbeschädigung ist.

### Struct-aware Fuzzing für typisierte Go-APIs

Beim nativen Go-Fuzzing werden hauptsächlich Skalare wie `[]byte`, `string` und Zahlen erwartet. Wenn der getestete Code typisierte Objekte verarbeitet, kann gosentry **zusammengesetzte Werte** direkt fuzzing-testen (Structs, Slices, Arrays, Pointer) und gleichzeitig die darunterliegenden Bytes mutieren.<sup>[[7]](#references)[[8]](#references)</sup>

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

Wenn du ein Fake-Wire-Format nur fürs Fuzzing erstellst, kann das Logikfehler hinter Parsing-Code verbergen, der nur im Harness vorkommt. Für Differential- oder grammatikbasierte Kampagnen sollte die Harness-Eingabe ein einzelnes `[]byte` oder `string` sein. Geparst wird stattdessen im Callback.

### Grammatikbasiertes Fuzzing für Parser und Protokolleingaben

Für Parser, Formate und Eingabesprachen kann gosentry **Nautilus-Grammatik-Fuzzing** auf Basis von LibAFL ausführen. Die Grammatik ist ein JSON-Array mit Produktionsregeln, und das Harness sollte üblicherweise ein einzelnes Argument vom Typ `[]byte` oder `string` entgegennehmen.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzGrammarJSON --use-grammar --grammar=./testdata/JSON.json --focus-on-new-code=false
```

Methodik-Hinweise:

- Verwende den Grammatikmodus, wenn Byte-Mutationen auf niedriger Ebene meist schon bei frühen Syntaxprüfungen scheitern.
- Beschränke die Grammatik auf die **sicherheitsrelevante Teilmenge** der Sprache/des Protokolls, statt die gesamte Spezifikation abzubilden.
- Verwende große Grenzwerte in Terminals/Nichtterminals, um Integer-, Längen- und Zustandsmaschinen-Grenzfälle zu belasten.
- Der Grammatikmodus hält Eingaben grammatikgültig, aber das Ziel erhält weiterhin **Bytes/Strings**. Parsing und semantische Prüfungen bleiben also Teil des instrumentierten Codes.

### Differential Fuzzing: Implementierungen statt nur Abstürze vergleichen

Ein bewährtes Muster für Go-Ökosysteme ist **grammatikbasiertes Differential Fuzzing**: Erzeuge gültige strukturierte Eingaben und übergib sie an zwei Parser, Clients oder Zustandsübergangs-Engines.<sup>[[7]](#references)[[8]](#references)</sup>

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

Behandle Folgendes als Befunde:

- eine Implementierung gerät in einen Panic, während die andere die Eingabe sauber zurückweist
- Abweichungen bei akzeptierten/zurückgewiesenen Eingaben
- unterschiedliche Parse-Bäume oder dekodierte Objekte
- abweichende Zustandsübergänge, Nonces, Salden oder State Roots

So lassen sich **Konsensabweichungen**, **Parser-Mehrdeutigkeit** und **Abweichungen zwischen Spezifikation und Implementierung** auf praktische Weise finden, die beim reinen Crash-Fuzzing oft unentdeckt bleiben.

### Das Campaign-Corpus für Coverage-Berichte wiederverwenden

Spiele nach einer Campaign das gespeicherte Queue-Corpus erneut ab, um einen Go-Coverage-Bericht zu erstellen, ohne manuell ein separates Corpus zu exportieren.<sup>[[7]](#references)[[8]](#references)</sup>

```bash
./bin/go test -fuzz=FuzzHarness --generate-coverage .
```

Führe den Befehl im **selben Paket** und mit demselben `-fuzz`-Ziel aus, damit gosentry den richtigen Zustand der gecachten Kampagne auflöst.



## References

- [1] [Mutational Grammar-Fuzzing](https://projectzero.google/2026/03/mutational-grammar-fuzzing.html)
- [2] [Jackalope](https://github.com/googleprojectzero/Jackalope)
- [3] [AFL++-Fuzzing im Detail](https://aflplus.plus/docs/fuzzing_in_depth/)
- [4] [AFLNet fünf Jahre später: Coverage-gesteuertes Protokoll-Fuzzing](https://arxiv.org/abs/2412.20324)
- [5] [Trailmark verwandelt Code in Graphen](https://blog.trailofbits.com/2026/04/23/trailmark-turns-code-into-graphs/)
- [6] [trailofbits/trailmark](https://github.com/trailofbits/trailmark)
- [7] [Go-Fuzzing fehlte die Hälfte des Toolkits. Wir haben die Toolchain geforkt, um das zu beheben.](https://blog.trailofbits.com/2026/05/12/go-fuzzing-was-missing-half-the-toolkit.-we-forked-the-toolchain-to-fix-it./)
- [8] [trailofbits/gosentry](https://github.com/trailofbits/gosentry)
- [9] [SNPSFuzzer: Ein schneller Greybox-Fuzzer für zustandsbehaftete Netzwerkprotokolle mit Snapshots](https://arxiv.org/abs/2202.03643)
- [10] [Keine Grammatik, kein Problem: Linux-Kernel-Fuzzing ohne Systemaufrufbeschreibungen](https://seclab.bu.edu/papers/FuzzNG-ndss2023.pdf)
- [11] [Snappy: Effizientes Fuzzing mit adaptiven und veränderbaren Snapshots](https://project-theseus.nl/publication/2022/snappy/)
- [12] [Fuzz Introspector](https://google.github.io/oss-fuzz/advanced-topics/fuzz-introspector/)
- [13] [AFL++-LLVM-Instrumentierung: Pfad- und Aufrufer-Coverage](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.llvm.md)
- [14] [Prädiktives kontextsensitive Fuzzing](https://www.ndss-symposium.org/ndss-paper/predictive-context-sensitive-fuzzing/)
- [15] [Android Offensive Security Blog – Binder-Fuzzing](https://androidoffsec.withgoogle.com/posts/binder-fuzzing/)
- [16] [LKL-Android-Binder-Fuzzer – Dokumentation zu Build und Regression-Seeds](https://github.com/lkl/linux/blob/master/tools/lkl/fuzzers/binder/README.md)
{{#include ../banners/hacktricks-training.md}}
