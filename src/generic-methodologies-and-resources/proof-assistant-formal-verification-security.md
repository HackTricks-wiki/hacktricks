# Sekuriteit van bewysassistente en formele verifikasie

{{#include ../banners/hacktricks-training.md}}

Bewysassistente kan dieselfde term via verskeie paaie uitvoer: kernel-reduksie, ’n interpreter, gegenereerde kode, runtime-primitiewe of ’n eksterne checker. ’n Bewys is net so sterk soos elke komponent wat vertroude resultate kan bydra. In Lean ruil native-besluitnemingsprosedures vinniger evaluering vir ’n groter trusted computing base (TCB): die compiler en definisies met native-implementasies word relevant vir die integriteit van bewyse.<sup>[[3]](#references)</sup>

## Logiese/native differensiële evaluering

Prioritiseer primitiewe waarvan die uitvoerbare implementasie van hul logiese model verskil (byvoorbeeld compiler-intrinsics, foreign-function interfaces, runtime-oorrides en definisies gemerk met `@[implemented_by]`). Evalueer **dieselfde geslote term** differensieel via die logiese en gecompileerde paaie, en beskou enige verskil in waarde, uitsondering of terminering as ’n sekuriteitsbevinding.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Nuttige klasse grenswaardes sluit in:<sup>[[1]](#references)[[4]](#references)</sup>

- indekse rondom `0`, die invoerlengte, die masjienwoordlimiet en waardes soos `2^63` of groter;
- reekse van nul of een byte, `start = end`, `start > end` en posisies ver buite die objek;
- leë en nie-leë invoere, multigreepstringe, ongeldige grense en rekenkunde wat tydens compilering afgekap kan word;
- heap-gesteunde waardes wanneer ’n native-primitief eienaarskap- of leen-gedrag het wat nie in die logiese model voorkom nie.

Die volgende verkorte Lean-patroon illustreer die probleem wat in `String.Pos.Raw.extract` gevind is: kwesbare native-kode het die oorspronklike string vir ’n enorme eengreep-reeks teruggestuur, terwyl definisionele reduksie die leë string teruggestuur het. Hierdie semantiese verskil is afsonderlik van die verwante geheueveiligheidsfout reggestel.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

Hierdie patroon veralgemeen verder as stringe: as logiese evaluering bewys dat `E = A` en vertroude native evaluering bewys dat `E = B`, lewer oorganklikheid `A = B`. Wanneer `A` en `B` waarneembaar verskil, lei dit tot `False`; `False.elim` (die explosiebeginsel) kan dan enige teikenstelling bewys. Die kern hoef nie ’n verkeerde reduksiereël te hê nie—die integriteitsfout vind plaas omdat ’n resultaat wat deur ’n samesteller ondersteun word, via ’n aksioma die logika binnegekom het.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Oudit van die uitgebreide TCB in Lean

Moenie redigeerderregmerkies of ’n suksesvolle bou as die enigste geldigheidskontrole vir ’n onvertroude bewys gebruik nie. Ondersoek die volledige afhanklikheidsafsluiting van elke sekuriteitskritieke stelling met `#print axioms`; Lean se riglyne vir validering identifiseer `_native`-name as afhanklikhede van native evaluering, `sorryAx` as ’n onvolledige bewys, en ander nie-standaardname as pasgemaakte aksiomas.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Byvoorbeeld, ’n gegenereerde afhanklikheid soos die volgende beteken dat gecompileerde uitvoering ’n veronderstelde resultaat bygedra het, eerder as ’n bewys wat uitsluitlik deur kernel-reduksie afgelei is:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Tydens bronhersiening, soek na native beslissingsprosedures en eksplisiete escape hatches, maar bevestig die resultaat met `#print axioms`, aangesien afhanklikhede indirek of gegenereer kan wees:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Onderskei die lae wanneer jy ’n bevinding triage:<sup>[[3]](#references)</sup>

1. **Beweringintegriteit:** verifieer dat notasie, type-class-instellings, imports en definisies die beoogde bewering uitdruk.
2. **Bewysafhanklikhede:** verwerp of hersien onverwagshede uitdruklik, veral gegenereerde native-evaluation-aksiomas.
3. **Kernherafspeel:** voer ná `lake build` `lean4checker --fresh <Module>` uit om verklarings uit die `.olean`-lêers te herafspeel.
4. **Validering van vyandige bewyse:** bou onbetroubare kode in ’n sandbox en gebruik `lake comparator` met eksterne checkers teen ’n vertroude uitdagingstelling.

`lean4checker` bied nuttige verdediging in diepte, maar vertrou op die strukturele korrektheid van `.olean`-lêers; die uitvoering van onbetroubare Lean-meta-kode kan ook die nagaanomgewing self kompromitteer. Vir hoërisikobewyse voer comparator die bewys buite die sandbox uit, kontroleer die stelling teen die vertroude uitdaging en kan dit deur onafhanklik geïmplementeerde checkers herafspeel. Implementeringsdiversiteit verminder die kans dat een samesteller-, looptyd- of kernfout dieselfde vals resultaat oral valideer.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract`-model/looptyd-wanaanpassing en gebruik-na-vrymaking - Lean-kwessie #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Herstel `String.Pos.Raw.extract`-model/looptyd-wanaanpassing - Lean-PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Lean-taalverwysing: Validering van ’n Lean-bewys](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [’n “Bewys” van Fermat se laaste stelling wat in die kantlyn pas](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
