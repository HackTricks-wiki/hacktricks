# Sicurezza degli assistenti di dimostrazione e della verifica formale

{{#include ../banners/hacktricks-training.md}}

Gli assistenti di dimostrazione possono eseguire lo stesso termine attraverso diversi percorsi: riduzione del kernel, un interprete, codice generato, primitive di runtime o un verificatore esterno. Una dimostrazione è solida solo quanto ogni componente autorizzato a contribuire risultati considerati attendibili. In Lean, le procedure decisionali native scambiano una valutazione più rapida con una base di calcolo fidata (TCB) più ampia: il compilatore e le definizioni con implementazioni native diventano rilevanti per l'integrità delle dimostrazioni.<sup>[[3]](#references)</sup>

## Valutazione differenziale logica/nativa

Dai priorità alle primitive la cui implementazione eseguibile differisce dal modello logico (per esempio intrinsic del compilatore, interfacce con funzioni esterne, override del runtime e definizioni contrassegnate con `@[implemented_by]`). Valuta in modo differenziale **lo stesso termine chiuso** attraverso i percorsi logico e compilato, e considera qualsiasi discrepanza nei valori, nelle eccezioni o nella terminazione come un problema di sicurezza.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Le classi di valori limite utili includono:<sup>[[1]](#references)[[4]](#references)</sup>

- indici attorno a `0`, alla lunghezza dell'input, al limite della parola macchina e valori come `2^63` o maggiori;
- intervalli di zero o un byte, `start = end`, `start > end` e posizioni ben oltre l'oggetto;
- input vuoti e non vuoti, stringhe multibyte, confini non validi e operazioni aritmetiche che potrebbero essere troncate in fase di compilazione;
- valori allocati nell'heap quando una primitiva nativa presenta comportamenti di ownership o borrowing assenti dal modello logico.

Il seguente esempio ridotto in Lean illustra il problema individuato in `String.Pos.Raw.extract`: il codice nativo vulnerabile restituiva la stringa originale per un intervallo di un byte enorme, mentre la riduzione definizionale restituiva la stringa vuota. Questa discrepanza semantica è stata corretta separatamente dal difetto correlato alla sicurezza della memoria.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

Questo schema si generalizza oltre le stringhe: se la valutazione logica dimostra `E = A` e la valutazione nativa attendibile dimostra `E = B`, la transitività produce `A = B`. Quando `A` e `B` sono distinguibili osservabilmente, questo porta a `False`; `False.elim` (il principio di esplosione) può quindi dimostrare qualsiasi proposizione obiettivo. Il kernel non deve avere una regola di riduzione errata: la violazione dell'integrità si verifica perché un risultato basato sul compilatore è entrato nella logica tramite un assioma.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Verifica del TCB ampliato in Lean

Non usare le spunte dell'editor o una compilazione riuscita come unica convalida di una dimostrazione non attendibile. Esamina la chiusura completa delle dipendenze di ogni teorema critico per la sicurezza con `#print axioms`; le indicazioni di convalida di Lean identificano i nomi `_native` come dipendenze dalla valutazione nativa, `sorryAx` come una dimostrazione incompleta e altri nomi non standard come assiomi personalizzati.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Ad esempio, una dipendenza generata simile alla seguente indica che l'esecuzione compilata ha fornito un risultato assunto, anziché una dimostrazione derivata esclusivamente tramite riduzione del kernel:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Durante la revisione del codice sorgente, cerca procedure decisionali native e scappatoie esplicite, ma verifica il risultato con `#print axioms` perché le dipendenze possono essere indirette o generate:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Distinguere i livelli quando si esamina un finding:<sup>[[3]](#references)</sup>

1. **Integrità dell’enunciato:** verificare che notazione, istanze delle type class, importazioni e definizioni esprimano l’affermazione prevista.
2. **Dipendenze della prova:** rifiutare o esaminare esplicitamente gli assiomi inattesi, in particolare quelli generati dalla valutazione nativa.
3. **Replay del kernel:** dopo `lake build`, eseguire `lean4checker --fresh <Module>` per riprodurre le dichiarazioni dai file `.olean`.
4. **Convalida di prove ostili:** compilare il codice non attendibile in una sandbox e usare `lake comparator` con checker esterni rispetto a un enunciato di challenge attendibile.

`lean4checker` offre un’utile difesa in profondità, ma si fida della correttezza strutturale dei file `.olean` e l’esecuzione di meta-code Lean non attendibile può compromettere l’ambiente di verifica. Per le prove ad alto rischio, comparator esporta la prova al di fuori della sandbox, verifica l’enunciato rispetto alla challenge attendibile e può riprodurla tramite checker implementati in modo indipendente; la diversità delle implementazioni riduce la probabilità che un singolo difetto del compilatore, del runtime o del kernel convalidi ovunque lo stesso risultato falso.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract`: discrepanza tra modello e runtime e use-after-free - issue #14684 di Lean](https://github.com/leanprover/lean4/issues/14684)
- [2] [Correzione della discrepanza tra modello e runtime di `String.Pos.Raw.extract` - PR #14717 di Lean](https://github.com/leanprover/lean4/pull/14717)
- [3] [Riferimento del linguaggio Lean: convalidare una prova Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [Una «prova» dell’ultimo teorema di Fermat che sta a margine](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
