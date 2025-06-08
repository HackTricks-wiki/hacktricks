# Algorytmy Uczenia przez Wzmocnienie

{{#include ../banners/hacktricks-training.md}}

## Uczenie przez Wzmocnienie

Uczenie przez wzmocnienie (RL) to rodzaj uczenia maszynowego, w którym agent uczy się podejmować decyzje poprzez interakcję z otoczeniem. Agent otrzymuje informacje zwrotne w postaci nagród lub kar w zależności od swoich działań, co pozwala mu uczyć się optymalnych zachowań w czasie. RL jest szczególnie przydatne w problemach, gdzie rozwiązanie wymaga sekwencyjnego podejmowania decyzji, takich jak robotyka, gra w gry i systemy autonomiczne.

### Q-Learning

Q-Learning to algorytm uczenia przez wzmocnienie bez modelu, który uczy się wartości działań w danym stanie. Używa tabeli Q do przechowywania oczekiwanej użyteczności podejmowania konkretnego działania w konkretnym stanie. Algorytm aktualizuje wartości Q na podstawie otrzymanych nagród i maksymalnych oczekiwanych przyszłych nagród.
1. **Inicjalizacja**: Zainicjalizuj tabelę Q dowolnymi wartościami (często zerami).
2. **Wybór Działania**: Wybierz działanie, używając strategii eksploracji (np. ε-greedy, gdzie z prawdopodobieństwem ε wybierane jest losowe działanie, a z prawdopodobieństwem 1-ε wybierane jest działanie o najwyższej wartości Q).
- Należy zauważyć, że algorytm mógłby zawsze wybierać znane najlepsze działanie w danym stanie, ale to nie pozwoliłoby agentowi na eksplorację nowych działań, które mogą przynieść lepsze nagrody. Dlatego używana jest zmienna ε-greedy, aby zrównoważyć eksplorację i eksploatację.
3. **Interakcja z Otoczeniem**: Wykonaj wybrane działanie w otoczeniu, obserwuj następny stan i nagrodę.
- Należy zauważyć, że w tym przypadku, w zależności od prawdopodobieństwa ε-greedy, następny krok może być losowym działaniem (dla eksploracji) lub najlepszym znanym działaniem (dla eksploatacji).
4. **Aktualizacja Wartości Q**: Zaktualizuj wartość Q dla pary stan-działanie, używając równania Bellmana:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca wartość Q dla stanu `s` i działania `a`.
- `α` to współczynnik uczenia (0 < α ≤ 1), który określa, jak bardzo nowe informacje zastępują stare informacje.
- `r` to nagroda otrzymana po podjęciu działania `a` w stanie `s`.
- `γ` to współczynnik dyskontowy (0 ≤ γ < 1), który określa znaczenie przyszłych nagród.
- `s'` to następny stan po podjęciu działania `a`.
- `max(Q(s', a'))` to maksymalna wartość Q dla następnego stanu `s'` dla wszystkich możliwych działań `a'`.
5. **Iteracja**: Powtarzaj kroki 2-4, aż wartości Q się zbiegną lub zostanie spełniony kryterium zatrzymania.

Należy zauważyć, że przy każdym nowym wybranym działaniu tabela jest aktualizowana, co pozwala agentowi uczyć się na podstawie swoich doświadczeń w czasie, aby spróbować znaleźć optymalną politykę (najlepsze działanie do podjęcia w każdym stanie). Jednak tabela Q może stać się duża w przypadku środowisk z wieloma stanami i działaniami, co czyni ją niepraktyczną w złożonych problemach. W takich przypadkach można użyć metod przybliżania funkcji (np. sieci neuronowe) do oszacowania wartości Q.

> [!TIP]
> Wartość ε-greedy jest zazwyczaj aktualizowana w czasie, aby zmniejszyć eksplorację, gdy agent uczy się więcej o otoczeniu. Na przykład, może zacząć od wysokiej wartości (np. ε = 1) i zmniejszać ją do niższej wartości (np. ε = 0.1) w miarę postępu uczenia.

> [!TIP]
> Współczynnik uczenia `α` i współczynnik dyskontowy `γ` to hiperparametry, które należy dostosować w zależności od konkretnego problemu i środowiska. Wyższy współczynnik uczenia pozwala agentowi uczyć się szybciej, ale może prowadzić do niestabilności, podczas gdy niższy współczynnik uczenia skutkuje bardziej stabilnym uczeniem, ale wolniejszą zbieżnością. Współczynnik dyskontowy określa, jak bardzo agent ceni przyszłe nagrody (`γ` bliżej 1) w porównaniu do nagród natychmiastowych.

### SARSA (Stan-Działanie-Nagroda-Stan-Działanie)

SARSA to kolejny algorytm uczenia przez wzmocnienie bez modelu, który jest podobny do Q-Learning, ale różni się tym, jak aktualizuje wartości Q. SARSA oznacza Stan-Działanie-Nagroda-Stan-Działanie i aktualizuje wartości Q na podstawie działania podjętego w następnym stanie, a nie maksymalnej wartości Q.
1. **Inicjalizacja**: Zainicjalizuj tabelę Q dowolnymi wartościami (często zerami).
2. **Wybór Działania**: Wybierz działanie, używając strategii eksploracji (np. ε-greedy).
3. **Interakcja z Otoczeniem**: Wykonaj wybrane działanie w otoczeniu, obserwuj następny stan i nagrodę.
- Należy zauważyć, że w tym przypadku, w zależności od prawdopodobieństwa ε-greedy, następny krok może być losowym działaniem (dla eksploracji) lub najlepszym znanym działaniem (dla eksploatacji).
4. **Aktualizacja Wartości Q**: Zaktualizuj wartość Q dla pary stan-działanie, używając reguły aktualizacji SARSA. Należy zauważyć, że reguła aktualizacji jest podobna do Q-Learning, ale używa działania, które będzie podjęte w następnym stanie `s'`, a nie maksymalnej wartości Q dla tego stanu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca wartość Q dla stanu `s` i działania `a`.
- `α` to współczynnik uczenia.
- `r` to nagroda otrzymana po podjęciu działania `a` w stanie `s`.
- `γ` to współczynnik dyskontowy.
- `s'` to następny stan po podjęciu działania `a`.
- `a'` to działanie podjęte w następnym stanie `s'`.
5. **Iteracja**: Powtarzaj kroki 2-4, aż wartości Q się zbiegną lub zostanie spełniony kryterium zatrzymania.

#### Wybór Działania Softmax vs ε-Greedy

Oprócz wyboru działań ε-greedy, SARSA może również używać strategii wyboru działań softmax. W wyborze działań softmax prawdopodobieństwo wyboru działania jest **proporcjonalne do jego wartości Q**, co pozwala na bardziej zniuansowaną eksplorację przestrzeni działań. Prawdopodobieństwo wyboru działania `a` w stanie `s` jest dane przez:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gdzie:
- `P(a|s)` to prawdopodobieństwo wybrania akcji `a` w stanie `s`.
- `Q(s, a)` to wartość Q dla stanu `s` i akcji `a`.
- `τ` (tau) to parametr temperatury, który kontroluje poziom eksploracji. Wyższa temperatura skutkuje większą eksploracją (bardziej jednorodne prawdopodobieństwa), podczas gdy niższa temperatura skutkuje większą eksploatacją (wyższe prawdopodobieństwa dla akcji z wyższymi wartościami Q).

> [!TIP]
> To pomaga zrównoważyć eksplorację i eksploatację w bardziej ciągły sposób w porównaniu do wyboru akcji ε-greedy.

### Uczenie On-Policy vs Off-Policy

SARSA jest algorytmem uczenia **on-policy**, co oznacza, że aktualizuje wartości Q na podstawie akcji podejmowanych przez bieżącą politykę (politykę ε-greedy lub softmax). W przeciwieństwie do tego, Q-Learning jest algorytmem uczenia **off-policy**, ponieważ aktualizuje wartości Q na podstawie maksymalnej wartości Q dla następnego stanu, niezależnie od akcji podjętej przez bieżącą politykę. Ta różnica wpływa na to, jak algorytmy uczą się i dostosowują do środowiska.

Metody on-policy, takie jak SARSA, mogą być bardziej stabilne w niektórych środowiskach, ponieważ uczą się na podstawie rzeczywiście podjętych akcji. Mogą jednak zbiegać się wolniej w porównaniu do metod off-policy, takich jak Q-Learning, które mogą uczyć się z szerszego zakresu doświadczeń.

{{#include ../banners/hacktricks-training.md}}
