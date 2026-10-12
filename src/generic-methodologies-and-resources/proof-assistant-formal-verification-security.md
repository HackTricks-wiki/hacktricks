# Msaidizi wa Uthibitisho na Usalama wa Uthibitishaji Rasmi

{{#include ../banners/hacktricks-training.md}}

Wasaidizi wa uthibitisho wanaweza kutekeleza term ileile kupitia njia kadhaa: upunguzaji wa kernel, interpreter, code iliyozalishwa, primitives za runtime, au checker ya nje. Uthibitisho una nguvu kulingana na kila kipengele kinachoruhusiwa kuchangia matokeo yanayoaminika. Katika Lean, taratibu asilia za kufanya maamuzi hubadilishana tathmini ya haraka zaidi na msingi mkubwa zaidi wa kompyuta unaoaminika (TCB): compiler na definitions zenye utekelezaji asilia huwa muhimu kwa uadilifu wa uthibitisho.<sup>[[3]](#references)</sup>

## Tathmini tofauti ya kimantiki/asilia

Tanguliza primitives ambazo utekelezaji wake unaoweza kuendeshwa ni tofauti na modeli yake ya kimantiki (kwa mfano compiler intrinsics, foreign-function interfaces, runtime overrides, na definitions zilizowekwa alama ya `@[implemented_by]`). Fanya tathmini tofauti ya **term ileile iliyofungwa** kupitia njia za kimantiki na za compiled, na uchukulie tofauti yoyote ya thamani, exception, au ukamilishaji kama matokeo ya usalama.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Aina muhimu za thamani za mipakani ni pamoja na:<sup>[[1]](#references)[[4]](#references)</sup>

- indexes zilizo karibu na `0`, urefu wa ingizo, kikomo cha machine-word, na thamani kama `2^63` au kubwa zaidi;
- ranges za sufuri/baiti moja, `start = end`, `start > end`, na nafasi zilizo mbali sana na object;
- ingizo tupu na lisilo tupu, strings zenye multibyte, mipaka batili, na hesabu zinazoweza kupoteza sehemu ya thamani zinapokuwa compiled;
- thamani zinazotegemea heap wakati primitive asilia ina tabia ya umiliki au kukopa ambayo haipo katika modeli ya kimantiki.

Muundo ufuatao uliorahisishwa wa Lean unaonyesha tatizo lililopatikana kwenye `String.Pos.Raw.extract`: code asilia iliyo hatarini ilirejesha string asilia kwa range ya baiti moja yenye ukubwa mkubwa sana, ilhali upunguzaji wa definitional ulirejesha string tupu. Kutolingana huku kwa semantiki kulirekebishwa kando na kasoro husika ya usalama wa kumbukumbu.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

Muundo huu unatumika pia kwa vitu vingine mbali na strings: ikiwa tathmini ya kimantiki itathibitisha `E = A` na tathmini ya native inayoaminika itathibitisha `E = B`, uhusiano wa mpito unatoa `A = B`. Wakati `A` na `B` zinatofautiana kwa njia inayoweza kuonekana, hii huleta `False`; `False.elim` (kanuni ya mlipuko) inaweza kisha kuthibitisha pendekezo lolote lengwa. Kernel haihitaji kuwa na kanuni isiyo sahihi ya reduction—ukiukaji wa uadilifu hutokea kwa sababu matokeo yanayotegemea compiler yaliingizwa kwenye mantiki kupitia axiom.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Kukagua TCB iliyopanuliwa katika Lean

Usitumie alama za tiki za kihariri au build iliyofanikiwa kama uthibitishaji pekee wa proof isiyoaminika. Kagua utegemezi wote kamili wa kila theorem muhimu kwa usalama ukitumia `#print axioms`; mwongozo wa uthibitishaji wa Lean unaonyesha majina ya `_native` kuwa utegemezi wa native evaluation, `sorryAx` kuwa proof isiyokamilika, na majina mengine yasiyo ya kawaida kuwa custom axioms.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Kwa mfano, utegemezi uliozalishwa unaofanana na ufuatao unamaanisha kuwa utekelezaji wa programu iliyokusanywa ulichangia matokeo yaliyokubaliwa kama dhana, badala ya uthibitisho uliotokana tu na kernel reduction:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Unapokagua source, tafuta taratibu za maamuzi za asili na njia za wazi za kukwepa ukaguzi, lakini thibitisha matokeo kwa `#print axioms` kwa sababu utegemezi unaweza kuwa usio wa moja kwa moja au kuzalishwa:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Tofautisha tabaka unapofanya triage ya finding:<sup>[[3]](#references)</sup>

1. **Uadilifu wa taarifa:** hakikisha kwamba notation, instances za type-class, imports, na definitions zinaeleza dai lililokusudiwa.
2. **Vitegemezi vya proof:** kataa au kagua wazi axioms zisizotarajiwa, hasa axioms za native-evaluation zilizozalishwa.
3. **Kurudia kwa kernel:** baada ya `lake build`, endesha `lean4checker --fresh <Module>` ili kurudia declarations kutoka kwenye faili za `.olean`.
4. **Uthibitishaji wa proof hasidi:** jenga code isiyoaminika ndani ya sandbox na utumie `lake comparator` pamoja na external checkers dhidi ya taarifa ya challenge inayoaminika.

`lean4checker` hutoa safu ya ziada ya ulinzi inayofaa, lakini huamini usahihi wa kimuundo wa faili za `.olean`, na kuendesha Lean meta-code isiyoaminika kunaweza kuhatarisha mazingira ya ukaguzi yenyewe. Kwa proofs zenye hatari kubwa, comparator husafirisha proof nje ya sandbox, hukagua taarifa dhidi ya challenge inayoaminika, na inaweza kuirudia kupitia checkers zilizotekelezwa kwa kujitegemea; utofauti wa utekelezaji hupunguza uwezekano kwamba hitilafu moja ya compiler, runtime, au kernel itasababisha matokeo yale yale yasiyo sahihi yakubaliwe kila mahali.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` kutolingana kwa modeli/runtime na use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Rekebisha kutolingana kwa modeli/runtime kwa `String.Pos.Raw.extract` - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Rejea ya Lugha ya Lean: Kuthibitisha Proof ya Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [“Proof” ya Nadharia ya Mwisho ya Fermat Inayotoshea Pembezoni](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
