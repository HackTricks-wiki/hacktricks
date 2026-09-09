# Statische Deobfuscation von Node.js/V8 Cached Bytecode

{{#include ../../banners/hacktricks-training.md}}

V8 cached data ist eine **versionsabhängige, verlustbehaftete Darstellung**, kein JavaScript-Quelltext und keine konventionelle native ausführbare Datei. Ein sinnvoller statischer Workflow besteht daher darin, zunächst äußere Packschichten zu entfernen, den Cache mit dem passenden V8-Build zu disassemblieren, ihn in ein Pseudocode-Modell einer Zwischendarstellung zu überführen und abhängige Transformationen anzuwenden, ohne das Sample auszuführen. [View8](https://github.com/suleram/View8) und [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementieren diesen Ansatz für durch `javascript-obfuscator` geschützte Node.js-Payloads.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Cache erfassen und disassemblieren

Untersuche zunächst den Preload/Launcher, statt davon auszugehen, dass jede `.jsc`-Datei denselben Wrapper besitzt. Ein Launcher wie `node.exe -r preflight.js app.jsc` führt beispielsweise `preflight.js` vor dem Hauptmodul aus; in der analysierten Variante entfernte der Preload eine Brotli-Schicht. Ermittle nach dem Entpacken anhand der gebündelten Runtime die genaue Node.js-/V8-Generation. Ein von einer V8-Version erzeugter Cache kann von einer anderen zurückgewiesen oder falsch dekodiert werden. Erstelle oder beschaffe daher ein `v8dasm` für den exakten V8-Tag und wende die erforderlichen View8- und String-Printing-Patches an.<sup>[[1]](#references)[[2]](#references)</sup>

Der nicht ausführende Workflow des Toolkits lautet:<sup>[[2]](#references)</sup>
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
`--normalize` gibt generierten Funktionen über mehrere Läufe hinweg stabile Bezeichner. Die Textausgabe dient der Inspektion; der serialisierte Objektgraph ermöglicht es unabhängigen Passes, Beziehungen zwischen Funktionen, Deklarierern, Scopes und Metadaten zu bewahren. Es handelt sich **nicht um rekonstruiertes oder ausführbares JavaScript**.<sup>[[1]](#references)[[2]](#references)</sup>

### View8-Pseudocode als IR lesen

Typische Namen sind `func_<name>_0x<address>`, Argumente sind `a0...aN`, virtuelle Register sind `r0...rN`, und `ACCU` ist der Akkumulator von V8. `start` ist der Root-Deklarierer, während `Scope[...]`, Globals und Dictionaries Werte modellieren, die von verschachtelten Funktionen erfasst oder gemeinsam verwendet werden. Interpretiere nicht jeden Ausdruck als JavaScript-Syntax: Beispielsweise stellt `!r6 === "0"` in View8 die Negation des vollständigen Vergleichs dar (`r6 !== "0"`), was beim Wiederherstellen von Verzweigungen relevant ist.<sup>[[1]](#references)[[3]](#references)</sup>

## Dependency-aware deobfuscation

Wende Transformationen in einer Reihenfolge an, die die für den nächsten Pass erforderlichen Eingaben sichtbar macht, und wiederhole die Propagation, bis sich die Ausgabe nicht mehr ändert. Eine praktische Reihenfolge ist:<sup>[[1]](#references)[[2]](#references)</sup>

1. Durchlaufe die Hierarchie der Deklarierer und propagiere Werte aus Globals, Registern, Dictionaries und `Scope[...]`-Referenzen.
2. Stelle die Argumente von String-Decodern wieder her und ersetze verschlüsselte Aufrufe durch Klartext.
3. Führe benachbarte String-Fragmente zusammen; die daraus entstehenden Property-Namen und Dispatcher-Reihenfolge-Strings ermöglichen spätere Passes.
4. Mache Control Flow rückgängig, inline Call-Proxies und Wrapper für atomare Operationen und löse in Dictionaries enthaltene Funktionsreferenzen auf.
5. Führe die Propagation erneut durch, da jeder aufgelöste String, Key oder Proxy eine weitere Indirektionsebene sichtbar machen kann.
6. Fasse erkannte einmalige Initialisierungs-Thunks zusammen und entferne tote Helper erst, nachdem ihre Call-Sites aufgelöst wurden.

### Verschobene RC4-String-Arrays als Black Box wiederherstellen

Ein gängiges `javascript-obfuscator`-Layout speichert Base64-codierte RC4-Fragmente in einem Array. Decoder-Wrapper liefern einen numerischen Offset und einen kurzen Key, teilweise in umgekehrter Argumentreihenfolge, und addieren oder subtrahieren anschließend Konstanten, die in Closure-Scopes erfasst wurden. Wenn der Root-Decoder zu stark obfuskiert ist, ermittle den unbekannten Array-Index-Shift empirisch, statt die gesamte Funktion zu rekonstruieren.<sup>[[1]](#references)</sup>

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
Akzeptiere keine Verschiebung aufgrund einer einzigen druckbaren Entschlüsselung: Der falsche Ciphertext kann zufällig druckbare Zeichen ergeben. Verwende mindestens drei unterschiedliche Beobachtungen und akzeptiere nur eine eindeutige Verschiebung, die für alle plausiblen Text ergibt. Durchlaufe anschließend den Wrapper-/Declarer-Graphen, addiere oder subtrahiere jeden Wert und protokolliere, ob das numerische Argument zuerst kommt. Cache diese Metadaten pro Sample, ersetze Decoder-Aufrufe, verkette benachbarte Klartext-Chunks und exportiere Strings separat zur Triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Semantik beim Unflattening bewahren

Bei Dispatcher-Schleifen, die von Strings wie `3|2|1|0|4` gesteuert werden, dekodiere den Order-String, ordne jeden Zustandsvergleich seinem Block zu, berücksichtige View8s negierte Bedingungsnotation und gib die Blöcke in Dispatcher-Reihenfolge aus. Ein verschachteltes `continue` kann einen frühen Sprung zurück zum Dispatcher statt eines gewöhnlichen Fall-throughs darstellen. Entferne beim Entfernen der Schleife dieses `continue` und verschiebe die Anweisungen, die ursprünglich auf das umschließende `if` folgten, in einen generierten `else`-Block; das bloße Löschen des Dispatchers verändert das Verhalten.<sup>[[1]](#references)</sup>

### Proxies, Operationen und Lazy Thunks inline einfügen

Normalisiere Weiterleitungshelfer wie `return a0(a1, a2)`, bevor du ihre Call-Sites durch direkte Aufrufe ersetzt. Behandle Wrapper für Subtraktion, Division, Vergleiche, Membership-Tests oder Aufrufe entsprechend. Da die Helper-Referenz selbst hinter einem entschlüsselten Dictionary-Key oder einem Closure-Wert gespeichert sein kann, führe die String- und Strukturpropagation vor und nach dem Inlining aus.<sup>[[1]](#references)</sup>

Erkenne außerdem Closures, die eine gespeicherte Funktion einmal aufrufen, ihre Referenz löschen, das Ergebnis cachen und diesen Cache bei späteren Aufrufen zurückgeben. Das Zusammenfassen eines solchen Thunks an einer Initialisierungsstelle legt den zugrunde liegenden Dispatcher oder die Capability-Funktion offen; kennzeichne jedoch, dass die ursprüngliche Ausführung **einmalig und gecacht** war, statt jeden Aufruf als neue Invocation zu modellieren.<sup>[[1]](#references)</sup>

## Hinweise zu Sicherheit und Validierung

- Das Laden von Python-`pickle` kann Code ausführen. Lade nur `.pkl`-Dateien, die lokal vom vertrauenswürdigen View8-Lauf erzeugt wurden; behandle ein von einem Sample bereitgestelltes Pickle niemals als Daten.<sup>[[2]](#references)</sup>
- Pattern-gesteuerte Passes sind kein allgemeiner JavaScript-Decompiler. Bewahre nicht aufgelöste Ausdrücke und untersuche mehrdeutige Dispatcher-Varianten manuell, statt eine Umschreibung zu erzwingen.<sup>[[1]](#references)[[2]](#references)</sup>
- Von LLM unterstützte Funktionsnamen sind Navigationshinweise, keine Beweise. Verarbeite bei ihrer Verwendung Abhängigkeiten leaf-first, überprüfe jedoch jedes Label anhand von Body, Argumenten, Strings, Data Flow, APIs und Side Effects.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Das Siegel brechen: Statische Deobfuscation von JSCeals kompiliertem V8-Bytecode](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}
