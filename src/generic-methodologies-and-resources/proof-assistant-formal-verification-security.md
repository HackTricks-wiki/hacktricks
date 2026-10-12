# Asystent dowodów i bezpieczeństwo weryfikacji formalnej

{{#include ../banners/hacktricks-training.md}}

Asystenci dowodów mogą wykonywać ten sam term na kilka sposobów: przez redukcję w jądrze, interpreter, wygenerowany kod, prymitywy środowiska uruchomieniowego lub zewnętrzny weryfikator. Dowód jest tak mocny, jak każdy komponent, któremu wolno dostarczać zaufane wyniki. W Lean natywne procedury decyzyjne zapewniają szybsze obliczenia kosztem większej zaufanej bazy obliczeniowej (TCB): kompilator i definicje z natywnymi implementacjami stają się istotne dla integralności dowodu.<sup>[[3]](#references)</sup>

## Różnicowa ewaluacja logiczna/natywna

W pierwszej kolejności sprawdzaj prymitywy, których implementacja wykonywalna różni się od modelu logicznego (na przykład compiler intrinsics, interfejsy foreign-function, nadpisania środowiska uruchomieniowego i definicje oznaczone jako `@[implemented_by]`). Przeprowadzaj różnicową ewaluację **tego samego zamkniętego termu** ścieżką logiczną i skompilowaną, a każdą rozbieżność wartości, wyjątku lub zakończenia traktuj jako ustalenie dotyczące bezpieczeństwa.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

Przydatne klasy wartości brzegowych obejmują:<sup>[[1]](#references)[[4]](#references)</sup>

- indeksy w pobliżu `0`, długości wejścia, limitu słowa maszynowego oraz wartości takie jak `2^63` lub większe;
- zakresy o długości zero lub jednego bajtu, `start = end`, `start > end` oraz pozycje znacznie wykraczające poza obiekt;
- puste i niepuste dane wejściowe, ciągi wielobajtowe, nieprawidłowe granice oraz działania arytmetyczne, które mogą być obcinane po kompilacji;
- wartości alokowane na stercie, gdy natywny prymityw stosuje zasady własności lub pożyczania nieobecne w modelu logicznym.

Poniższy uproszczony wzorzec Lean ilustruje problem wykryty w `String.Pos.Raw.extract`: podatny kod natywny zwracał oryginalny ciąg dla ogromnego zakresu o długości jednego bajtu, podczas gdy redukcja definicyjna zwracała pusty ciąg. Ta niezgodność semantyczna została naprawiona niezależnie od powiązanego defektu bezpieczeństwa pamięci.<sup>[[1]](#references)[[2]](#references)[[4]](#references)</sup>

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

Ten wzorzec uogólnia się poza ciągi znaków: jeśli ewaluacja logiczna dowodzi `E = A`, a zaufana ewaluacja natywna dowodzi `E = B`, przechodniość daje `A = B`. Gdy `A` i `B` są obserwowalnie różne, wynika z tego `False`; `False.elim` (zasada eksplozji) może następnie dowieść dowolnego twierdzenia docelowego. Jądro nie musi zawierać niepoprawnej reguły redukcji — naruszenie integralności następuje, ponieważ wynik oparty na kompilatorze trafia do logiki przez aksjomat.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

## Audyt rozszerzonego TCB w Lean

Nie polegaj wyłącznie na znacznikach wyboru w edytorze ani pomyślnym buildzie przy walidacji niezaufanego dowodu. Sprawdź pełne domknięcie zależności każdego twierdzenia krytycznego dla bezpieczeństwa za pomocą `#print axioms`; wskazówki walidacyjne Lean określają nazwy `_native` jako zależności od ewaluacji natywnej, `sorryAx` jako niekompletny dowód, a inne niestandardowe nazwy jako własne aksjomaty.<sup>[[3]](#references)</sup>

```lean
#print axioms targetTheorem
```

Na przykład wygenerowana zależność podobna do poniższej oznacza, że wykonanie skompilowane dostarczyło wynik przyjęty jako założenie, a nie dowód wyprowadzony wyłącznie przez redukcję jądra:<sup>[[1]](#references)[[4]](#references)</sup>

```text
targetTheorem._native.native_decide.ax_1_1
```

Podczas przeglądu kodu źródłowego szukaj natywnych procedur rozstrzygania i jawnych mechanizmów obejścia, ale potwierdź wynik za pomocą `#print axioms`, ponieważ zależności mogą być pośrednie lub generowane:<sup>[[3]](#references)</sup>

```bash
rg -n 'native_decide|decide\s+\+native|bv_decide|sorry|axiom' .
```

Rozróżniaj warstwy podczas triage’u ustalenia:<sup>[[3]](#references)</sup>

1. **Integralność stwierdzenia:** sprawdź, czy notacja, instancje klas typów, importy i definicje wyrażają zamierzone twierdzenie.
2. **Zależności dowodu:** odrzucaj nieoczekiwane aksjomaty lub poddawaj je jawnej weryfikacji, zwłaszcza generowane aksjomaty natywnej ewaluacji.
3. **Ponowne odtworzenie w kernelu:** po `lake build` uruchom `lean4checker --fresh <Module>`, aby ponownie odtworzyć deklaracje z plików `.olean`.
4. **Walidacja wrogiego dowodu:** buduj niezaufany kod w sandboxie i używaj `lake comparator` z zewnętrznymi checkerami, weryfikującymi go względem zaufanego stwierdzenia zadania.

`lean4checker` zapewnia przydatną dodatkową warstwę ochrony, ale ufa poprawności strukturalnej plików `.olean`, a uruchomienie niezaufanego meta-kodu Lean może samo w sobie narazić środowisko weryfikacji na atak. W przypadku dowodów wysokiego ryzyka comparator eksportuje dowód poza sandbox, sprawdza stwierdzenie względem zaufanego zadania i może ponownie odtworzyć go za pomocą niezależnie zaimplementowanych checkerów; różnorodność implementacji zmniejsza prawdopodobieństwo, że ten sam fałszywy wynik zostanie zaakceptowany wszędzie z powodu błędu kompilatora, środowiska uruchomieniowego lub kernela.<sup>[[3]](#references)</sup>

## References

- [1] [`String.Pos.Raw.extract` model/runtime mismatch and use-after-free - Lean issue #14684](https://github.com/leanprover/lean4/issues/14684)
- [2] [Naprawa niezgodności modelu i środowiska uruchomieniowego `String.Pos.Raw.extract` - Lean PR #14717](https://github.com/leanprover/lean4/pull/14717)
- [3] [Dokumentacja języka Lean: weryfikowanie dowodu Lean](https://lean-lang.org/doc/reference/latest/ValidatingProofs/)
- [4] [„Dowód” ostatniego twierdzenia Fermata, który mieści się na marginesie](https://blog.trailofbits.com/2026/09/09/a-proof-of-fermats-last-theorem-that-fits-the-margin/)
{{#include ../banners/hacktricks-training.md}}
