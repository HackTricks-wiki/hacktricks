# Statische Deobfuskierung von Node.js/V8-Bytecode-Caches

{{#include ../../banners/hacktricks-training.md}}

V8-Cached Data ist eine **versionsabhängige, verlustbehaftete Darstellung** und weder JavaScript-Quellcode noch eine herkömmliche native ausführbare Datei. Ein sinnvoller statischer Workflow besteht daher darin, zunächst jegliche äußere Verpackung zu entfernen, den Cache mit dem passenden V8-Build zu disassemblieren, ihn in ein intermediäres Pseudocode-Modell zu überführen und Transformationen unter Berücksichtigung von Abhängigkeiten anzuwenden, ohne das Sample auszuführen. [View8](https://github.com/suleram/View8) und [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) setzen diesen Ansatz für durch `javascript-obfuscator` geschützte Node.js-Payloads um.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache erfassen und disassemblieren

Untersuche zuerst den Preload/die Startdatei, statt anzunehmen, dass jede `.jsc`-Datei denselben Wrapper hat. Ein Starter wie `node.exe -r preflight.js app.jsc` führt beispielsweise `preflight.js` vor dem Hauptmodul aus; in der analysierten Familie entfernte der Preload eine Brotli-Schicht. Ermittle nach dem Entpacken anhand der gebündelten Runtime die genaue Node.js-/V8-Generation. Ein von einer V8-Version erzeugter Cache kann von einer anderen abgelehnt oder falsch decodiert werden. Erstelle oder beschaffe daher ein `v8dasm` für genau diesen V8-Tag und wende die erforderlichen View8- und String-Ausgabe-Patches an.<sup>[[1]](#references)[[2]](#references)</sup>

Der nicht ausführende Workflow des Toolkits sieht wie folgt aus:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize` sorgt dafür, dass generierte Funktionen über verschiedene Läufe hinweg stabile Bezeichner haben. Die Textausgabe dient der Prüfung; der serialisierte Objektgraph ermöglicht unabhängigen Durchläufen, Beziehungen zwischen Funktionen, Deklarierenden, Scopes und Metadaten zu erhalten. Es handelt sich **nicht um rekonstruiertes oder ausführbares JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### Einen Cache ohne V8 sichten

Bei einem rohen oder mit Brotli komprimierten Cache kann `jscd` den Header identifizieren und Konstanten sowie Funktionen auflisten, ohne das Sample in Node.js zu laden. Verwende dies zuerst, um zu prüfen, ob die Versionstabellen die Datei unterstützen, und um Funktionen zu priorisieren, bevor du die spezialisierteren View8-Deobfuskierungsdurchläufe ausführst.<sup>[[4]](#references)</sup>

Der Version-Hash ist ein Hinweis zur Identifikation, kein Beweis dafür, dass ein eigenständiger Disassembler dieselben Flags oder denselben schreibgeschützten Snapshot wie der Ersteller verwendet.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` gibt ein View8-kompatibles Listing aus. Daher kann der obige View8-Befehl diese Ausgabe anstelle von `v8dasm` verwenden, wenn der Cache unterstützt wird. Untersuche Strings zusammen mit dem Funktionsbaum, um Decoder-Aufrufe und wahrscheinliche Einstiegspunkte zu finden. Behandle die approximative JavaScript-Ausgabe von `jscd` nicht als Original-Quellcode. Wenn das Tool die Version ablehnt oder Platzhalter für den Read-only-Heap hinterlässt, verwende wieder einen passenden V8-Build oder liefere eine Namenszuordnung aus demselben Build, anstatt Eigenschaftsnamen zu erraten.<sup>[[4]](#references)</sup>

Bei einem Cache innerhalb einer Electron-Anwendung solltest du zunächst [das ASAR extrahieren und die Main- und Preload-Einstiegspunkte untersuchen](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Das Snapshot- und Pointer-Compression-Layout von Electron- und Node-Caches kann sich unterscheiden, selbst wenn ihre V8-Versionsstrings übereinstimmen.<sup>[[4]](#references)</sup>

### View8-Pseudocode als IR lesen

Typische Namen sind `func_<name>_0x<address>`, Argumente sind `a0...aN`, virtuelle Register sind `r0...rN`, und `ACCU` ist der Akkumulator von V8. `start` ist der Root-Declarer, während `Scope[...]`, Globals und Dictionaries Werte abbilden, die von verschachtelten Funktionen erfasst oder gemeinsam genutzt werden. Analysiere nicht jeden Ausdruck als JavaScript-Syntax: Beispielsweise steht View8s `!r6 === "0"` für die Negation des vollständigen Vergleichs (`r6 !== "0"`), was beim Rekonstruieren von Verzweigungen wichtig ist.<sup>[[1]](#references)[[3]](#references)</sup>

## Abhängigkeitsbewusste Deobfuskation

Wende Transformationen in einer Reihenfolge an, die die Eingaben für den jeweils nächsten Durchlauf sichtbar macht, und wiederhole die Propagation, bis sich die Ausgabe nicht mehr ändert. Eine praktische Reihenfolge ist:<sup>[[1]](#references)[[2]](#references)</sup>

1. Durchlaufe die Declarer-Hierarchie und propagiere Werte aus Globals, Registern, Dictionaries und `Scope[...]`-Referenzen.
2. Ermittle die Argumente des String-Decoders und ersetze verschlüsselte Aufrufe durch Klartext.
3. Fasse benachbarte String-Fragmente zusammen. Die daraus entstehenden Eigenschaftsnamen und Strings zur Dispatcher-Reihenfolge ermöglichen spätere Durchläufe.
4. Hebe die Control-Flow-Obfuskation auf, inline Call-Proxies und Atomic-Operation-Wrapper und löse in Dictionaries gespeicherte Funktionsreferenzen auf.
5. Propagiere erneut, da jeder aufgelöste String, Schlüssel oder Proxy eine weitere Indirektionsebene sichtbar machen kann.
6. Fasse erkannte One-Shot-Initialisierungsthunks zusammen und entferne ungenutzte Helfer erst, nachdem ihre Aufrufstellen aufgelöst wurden.

### Verschobene RC4-String-Arrays als Blackbox wiederherstellen

Ein gängiges `javascript-obfuscator`-Layout speichert Base64-kodierte RC4-Fragmente in einem Array. Decoder-Wrapper übergeben einen numerischen Offset und einen kurzen Schlüssel, manchmal in umgekehrter Argumentreihenfolge, und addieren oder subtrahieren dann Konstanten, die in Closure-Scopes erfasst wurden. Wenn der Root-Decoder zu stark obfuskiert ist, ermittle die unbekannte Array-Indexverschiebung empirisch, anstatt die gesamte Funktion zu rekonstruieren.<sup>[[1]](#references)</sup>

Für ein Array mit `N` Fragmenten und mehrere Aufrufe desselben Decoders:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Akzeptiere keine Verschiebung auf Grundlage nur einer einzelnen druckbaren Entschlüsselung: Der falsche Chiffretext kann zufällig druckbar aussehen. Verwende mindestens drei unterschiedliche Beobachtungen und akzeptiere nur eine eindeutige Verschiebung, die für alle plausiblen Text ergibt. Durchlaufe dann den Wrapper-/Deklarator-Graphen, addiere oder subtrahiere dabei die Werte und halte fest, ob das numerische Argument zuerst kommt. Zwischenspeichere diese Metadaten pro Sample, ersetze Decoder-Aufrufe, verkette benachbarte Klartext-Chunks und exportiere Strings separat für die Triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Semantik beim Entflachen bewahren

Bei Dispatcher-Schleifen, die von Strings wie `3|2|1|0|4` gesteuert werden, dekodiere den Reihenfolgen-String, ordne jeden Zustandsvergleich seinem Block zu, berücksichtige View8s negierte Bedingungsnotation und gib die Blöcke dann in der Reihenfolge des Dispatchers aus. Ein verschachteltes `continue` kann einen vorzeitigen Sprung zurück zum Dispatcher darstellen und nicht einen gewöhnlichen Fall-through. Beim Entfernen der Schleife lösche dieses `continue` und verschiebe die Anweisungen, die ursprünglich auf das einschließende `if` folgten, in einen generierten `else`-Zweig; nur den Dispatcher zu löschen, verändert das Verhalten.<sup>[[1]](#references)</sup>

### Proxies, Operationen und Lazy Thunks inline setzen

Normalisiere weiterleitende Helper wie `return a0(a1, a2)`, bevor du ihre Aufrufstellen durch direkte Aufrufe ersetzt. Behandle Wrapper für Subtraktion, Division, Vergleiche, Mitgliedschaftstests oder Aufrufe auf dieselbe Weise. Da die Helper-Referenz selbst hinter einem entschlüsselten Dictionary-Schlüssel oder Closure-Wert gespeichert sein kann, führe die Propagierung von Strings und Strukturen vor und nach dem Inlining aus.<sup>[[1]](#references)</sup>

Erkenne außerdem Closures, die eine gespeicherte Funktion einmal aufrufen, deren Referenz löschen, das Ergebnis zwischenspeichern und diesen Cache bei späteren Aufrufen zurückgeben. Wird ein solcher Thunk an einer Initialisierungsstelle zusammengeführt, wird der zugrunde liegende Dispatcher oder die Capability-Funktion sichtbar. Vermerke jedoch, dass die ursprüngliche Ausführung **einmalig und zwischengespeichert** war, anstatt jeden Aufruf als neuen Funktionsaufruf zu modellieren.<sup>[[1]](#references)</sup>

## Sicherheits- und Validierungshinweise

- Das Laden von Python-`pickle` kann Code ausführen. Lade nur `.pkl`-Dateien, die lokal durch den vertrauenswürdigen View8-Lauf erzeugt wurden; behandle niemals ein vom Sample bereitgestelltes Pickle als Daten.<sup>[[2]](#references)</sup>
- Ein fehlender Funktionskörper beweist nicht, dass die Funktion im Quellcode fehlte: V8 kann eine Lazy Function als Metadaten serialisieren, bis sie beim ersten Aufruf kompiliert wird. Markiere solche Funktionen bei der statischen Triage weiterhin als ungelöst.<sup>[[6]](#references)</sup>
- Musterbasierte Durchläufe sind kein allgemeiner JavaScript-Decompiler. Bewahre ungelöste Ausdrücke und untersuche mehrdeutige Dispatcher-Varianten manuell, anstatt eine Umschreibung zu erzwingen.<sup>[[1]](#references)[[2]](#references)</sup>
- Von LLMs unterstützte Funktionsnamen sind Navigationshinweise, keine Belege. Verarbeite Abhängigkeiten von den Blättern aufwärts, falls du sie verwendest, und überprüfe jede Bezeichnung anhand des Funktionskörpers, der Argumente, Strings, des Datenflusses, der APIs und der Seiteneffekte.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Das Siegel brechen: Statische Deobfuskation von kompiliertem V8-Bytecode von JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [V8-SerializedCodeData-Kopfzeile](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Node.js: Code-Cache für vm.Script](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}
