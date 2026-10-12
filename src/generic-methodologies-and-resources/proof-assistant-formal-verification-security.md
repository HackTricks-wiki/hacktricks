# Sicherheit von Proof Assistants und formaler Verifikation

{{#include ../banners/hacktricks-training.md}}

Proof Assistants können denselben Term auf verschiedenen Wegen ausführen: durch Kernel-Reduktion, einen Interpreter, generierten Code, Runtime-Primitives oder einen externen Checker. Ein Beweis ist nur so stark wie jede Komponente, die vertrauenswürdige Ergebnisse beitragen darf. In Lean tauschen native Entscheidungsverfahren schnellere Auswertung gegen eine größere Trusted Computing Base (TCB) ein: Der Compiler und Definitionen mit nativen Implementierungen werden für die Integrität von Beweisen relevant.<sup>[[3]](#references)</sup>

## Differentielle logische/native Auswertung

Priorisieren Sie Primitives, deren ausführbare Implementierung sich von ihrem logischen Modell unterscheidet (zum Beispiel Compiler-Intrinsics, foreign-function interfaces, Runtime-Overrides und Definitionen mit `@[implemented_by]`). Werten Sie denselben geschlossenen Term sowohl über den logischen als auch über den kompilierten Pfad aus und behandeln Sie jede Abweichung bei Wert, Ausnahme oder Terminierung als Sicherheitslücke.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Nützliche Grenzwertklassen sind:<sup>[[1]](#references)[[4]](#references)</sup>

- Indizes um `0`, die Eingabelänge, die Maschinenwortgrenze und Werte wie `2^63` oder größer;
- Bereiche mit null oder einem Byte, `start = end`, `start > end` und Positionen weit außerhalb des Objekts;
- leere und nicht leere Eingaben, mehrbyteige Strings, ungültige Grenzen und Arithmetik, die bei der Kompilierung abgeschnitten werden könnte;
- heap-basierte Werte, wenn ein natives Primitive Besitz- oder Borrowing-Verhalten aufweist, das im logischen Modell fehlt.

Das folgende vereinfachte Lean-Muster veranschaulicht das Problem in `String.Pos.Raw.extract`: Verwundbarer nativer Code gab bei einem sehr großen Ein-Byte-Bereich den ursprünglichen String zurück, während die definitorische Reduktion den leeren String ergab. Diese semantische Abweichung wurde getrennt vom damit verbundenen Memory-Safety-Fehler behoben.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

```lean
def value : String := "non-empty"
def startPos : String.Pos.Raw := ⟨2^63⟩
def endPos : String.Pos.Raw := ⟨2^63 + 1⟩

example : False := by
  have logical : String.Pos.Raw.extract value startPos endPos = "" := rfl
  have native : String.Pos.Raw.extract value startPos endPos = value := by
    native_decide
  exact (by decide) (logical.symm.trans native)
```

Dieses Muster lässt sich über Strings hinaus verallgemeinern: Wenn die logische Auswertung `E = A` beweist und die vertrauenswürdige native Auswertung `E = B` beweist, ergibt die Transitivität `A = B`. Wenn `A` und `B` beobachtbar verschieden sind, folgt daraus `False`; mit `False.elim` (dem Explosionsprinzip) lässt sich dann jede beliebige Zielaussage beweisen. Der Kernel braucht keine fehlerhafte Reduktionsregel zu haben – der Integritätsfehler entsteht dadurch, dass ein compilerbasiertes Ergebnis über ein Axiom in die Logik gelangt ist.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Audit des erweiterten TCB in Lean

Verwenden Sie Editor-Häkchen oder einen erfolgreichen Build nicht als einzige Validierung für einen nicht vertrauenswürdigen Beweis. Untersuchen Sie mit `#print axioms` die vollständige Abhängigkeitsmenge jedes sicherheitskritischen Theorems. Leans Validierungsrichtlinien weisen darauf hin, dass Namen mit `_native` Abhängigkeiten von nativer Auswertung kennzeichnen, `sorryAx` für einen unvollständigen Beweis steht und andere nicht standardisierte Namen benutzerdefinierte Axiome kennzeichnen.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Zum Beispiel bedeutet eine erzeugte Abhängigkeit wie die folgende, dass die kompilierte Ausführung ein angenommenes Ergebnis beigesteuert hat und kein ausschließlich durch Kernel-Reduktion hergeleiteter Beweis ist:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Bei der Überprüfung des Quellcodes solltest du nach nativen Entscheidungsverfahren und expliziten Escape-Hatches suchen, das Ergebnis aber mit `#print axioms` bestätigen, da Abhängigkeiten indirekt oder generiert sein können:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Unterscheiden Sie beim Triage eines Findings die Ebenen:<sup>[[3]](#references)</sup>

1. **Integrität der Aussage:** Prüfen Sie, ob Notation, Instanzen von Typklassen, Imports und Definitionen die beabsichtigte Behauptung ausdrücken.
2. **Beweisabhängigkeiten:** Verwerfen oder überprüfen Sie ausdrücklich unerwartete Axiome, insbesondere automatisch generierte Axiome für native Auswertung.
3. **Kernel-Replay:** Führen Sie nach `lake build` `lean4checker --fresh <Module>` aus, um Deklarationen aus den `.olean`-Dateien erneut zu prüfen.
4. **Validierung feindseliger Beweise:** Erstellen Sie nicht vertrauenswürdigen Code in einer Sandbox und verwenden Sie `lake comparator` mit externen Prüfern gegen eine vertrauenswürdige Challenge-Aussage.

`lean4checker` bietet eine nützliche zusätzliche Schutzebene, vertraut aber auf die strukturelle Korrektheit von `.olean`-Dateien. Außerdem kann das Ausführen nicht vertrauenswürdigen Lean-Meta-Codes selbst die Prüfungsumgebung kompromittieren. Bei Beweisen mit hohem Risiko exportiert comparator den Beweis aus der Sandbox, prüft die Aussage anhand der vertrauenswürdigen Challenge und kann ihn durch unabhängig implementierte Prüfer erneut ausführen. Die Vielfalt der Implementierungen verringert die Wahrscheinlichkeit, dass ein einzelner Compiler-, Laufzeit- oder Kernel-Fehler überall dasselbe falsche Ergebnis bestätigt.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract`: Abweichung zwischen Modell und Laufzeit sowie Use-after-free – Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Behebung der Abweichung zwischen Modell und Laufzeit bei `String.Pos.Raw.extract` – Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean-Sprachreferenz: Einen Lean-Beweis validieren](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Ein „Beweis“ des letzten Satzes von Fermat, der an den Rand passt](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
