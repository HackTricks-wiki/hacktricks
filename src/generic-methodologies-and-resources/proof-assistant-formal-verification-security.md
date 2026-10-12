# Bezbednost proof assistant alata i formalne verifikacije

{{#include ../banners/hacktricks-training.md}}

Proof assistant alati mogu da izvršavaju isti term na više načina: redukcijom u kernelu, interpreterom, generisanim kodom, runtime primitivama ili spoljnim proveravačem. Dokaz je pouzdan onoliko koliko je pouzdana svaka komponenta kojoj je dozvoljeno da doprinosi rezultatima kojima se veruje. U Lean-u, nativne procedure odlučivanja omogućavaju bržu evaluaciju, ali proširuju trusted computing base (TCB): kompajler i definicije sa nativnim implementacijama postaju relevantni za integritet dokaza.<sup>[[3]](#references)</sup>

## Diferencijalna evaluacija logičkog i nativnog izvršavanja

Dajte prioritet primitivama čija se izvršna implementacija razlikuje od logičkog modela (na primer, intrinsics kompajlera, foreign-function interfejsima, runtime zamenama i definicijama označenim sa `@[implemented_by]`). Diferencijalno evaluirajte **isti zatvoreni term** kroz logičke i kompajlirane putanje i svaki nesklad u vrednosti, izuzetku ili terminaciji tretirajte kao bezbednosni nalaz.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Korisne klase graničnih vrednosti obuhvataju:<sup>[[1]](#references)[[4]](#references)</sup>

- indekse oko `0`, dužinu ulaza, granicu mašinske reči i vrednosti kao što su `2^63` ili veće;
- opsege dužine nula ili jednog bajta, `start = end`, `start > end` i pozicije daleko izvan objekta;
- prazne i neprazne ulaze, višebajtne stringove, neispravne granice i aritmetiku koja može biti skraćena pri kompajliranju;
- vrednosti smeštene na heap-u kada nativna primitiva ima ponašanje u vezi sa vlasništvom ili pozajmljivanjem koje ne postoji u logičkom modelu.

Sledeći pojednostavljeni Lean obrazac ilustruje problem pronađen u `String.Pos.Raw.extract`: ranjivi nativni kod vraćao je originalni string za ogroman opseg od jednog bajta, dok je definiciona redukcija vraćala prazan string. Ovo semantičko neslaganje ispravljeno je odvojeno od povezanog propusta u bezbednosti memorije.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

Ovaj obrazac se uopštava i izvan stringova: ako logička evaluacija dokaže `E = A`, a pouzdana native evaluacija dokaže `E = B`, tranzitivnost daje `A = B`. Kada su `A` i `B` uočljivo različiti, iz toga sledi `False`; zatim `False.elim` (princip eksplozije) može da dokaže bilo koju ciljnu tvrdnju. Kernel ne mora da ima neispravno pravilo redukcije — do narušavanja integriteta dolazi zato što je rezultat zasnovan na kompajleru ušao u logiku preko aksioma.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Provera proširenog TCB-a u Lean-u

Nemojte se oslanjati samo na kvačice u editoru ili uspešnu izgradnju kao potvrdu neproverenog dokaza. Pregledajte kompletan skup zavisnosti svake bezbednosno kritične teoreme pomoću `#print axioms`; Lean smernice za validaciju navode da imena `_native` označavaju zavisnosti od native evaluacije, `sorryAx` nepotpun dokaz, a druga nestandardna imena prilagođene aksiome.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Na primer, generisana zavisnost nalik sledećoj znači da je kompajlirano izvršavanje doprinelo pretpostavljenom rezultatu, a ne dokazu izvedenom isključivo redukcijom kernela:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Tokom pregleda izvornog koda, potražite izvorne procedure za odlučivanje i izričite mehanizme zaobilaženja, ali potvrdite rezultat pomoću `#print axioms`, jer zavisnosti mogu biti posredne ili generisane:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Razlikujte slojeve prilikom trijaže nalaza:<sup>[[3]](#references)</sup>

1. **Integritet tvrdnje:** proverite da li notacija, instance tipnih klasa, importi i definicije izražavaju nameravanu tvrdnju.
2. **Zavisnosti dokaza:** odbacite neočekivane aksiome ili ih izričito pregledajte, naročito generisane aksiome native-evaluation.
3. **Ponovno izvršavanje u kernelu:** nakon `lake build`, pokrenite `lean4checker --fresh <Module>` da biste ponovo izvršili deklaracije iz `.olean` datoteka.
4. **Validacija zlonamernih dokaza:** gradite nepouzdan kod u sandbox-u i koristite `lake comparator` sa eksternim proverivačima u odnosu na pouzdanu iskaznu tvrdnju.

`lean4checker` pruža korisnu višeslojnu odbranu, ali veruje strukturnoj ispravnosti `.olean` datoteka, a pokretanje nepouzdanog Lean meta-koda samo po sebi može da ugrozi okruženje za proveru. Za dokaze visokog rizika, comparator izvozi dokaz izvan sandbox-a, proverava iskaz u odnosu na pouzdani izazovni iskaz i može ponovo da ga izvrši kroz nezavisno implementirane proverivače; raznovrsnost implementacija smanjuje mogućnost da jedna te ista greška kompajlera, okruženja izvršavanja ili kernela svuda potvrdi isti netačan rezultat.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` neusaglašenost modela i okruženja izvršavanja i upotreba nakon oslobađanja memorije - Lean problem #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Ispravka neusaglašenosti modela i okruženja izvršavanja za `String.Pos.Raw.extract` - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Referenca za jezik Lean: Validacija Lean dokaza](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [„Dokaz“ Fermatove poslednje teoreme koji staje na margini](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
