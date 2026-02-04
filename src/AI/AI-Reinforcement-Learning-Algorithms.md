# Algorytmy uczenia ze wzmocnieniem

{{#include ../banners/hacktricks-training.md}}

## Uczenie ze wzmocnieniem

Uczenie ze wzmocnieniem (RL) to rodzaj uczenia maszynowego, w którym agent uczy się podejmować decyzje poprzez interakcję ze środowiskiem. Agent otrzymuje informację zwrotną w postaci nagród lub kar na podstawie swoich działań, co pozwala mu z czasem wypracować optymalne zachowania. RL jest szczególnie przydatne w problemach wymagających sekwencyjnego podejmowania decyzji, takich jak robotyka, gry oraz systemy autonomiczne.

### Q-Learning

Q-Learning jest bezmodelowym algorytmem uczenia ze wzmocnieniem, który uczy się wartości działań w danym stanie. Używa tabeli Q do przechowywania oczekiwanej użyteczności wykonania konkretnej akcji w konkretnym stanie. Algorytm aktualizuje wartości Q na podstawie otrzymanych nagród oraz maksymalnych oczekiwanych przyszłych nagród.
1. **Initialization**: Zainicjalizuj tabelę Q dowolnymi wartościami (często zerami).
2. **Action Selection**: Wybierz akcję używając strategii eksploracji (np. ε-greedy, gdzie z prawdopodobieństwem ε wybierana jest losowa akcja, a z prawdopodobieństwem 1-ε wybierana jest akcja o najwyższej wartości Q).
- Należy pamiętać, że algorytm mógłby zawsze wybierać znaną najlepszą akcję dla danego stanu, ale to uniemożliwiłoby agentowi eksplorację nowych akcji, które mogłyby przynieść lepsze nagrody. Dlatego zmienna ε-greedy jest używana do zbalansowania eksploracji i eksploatacji.
3. **Environment Interaction**: Wykonaj wybraną akcję w środowisku, zaobserwuj następny stan i nagrodę.
- Należy pamiętać, że w tym przypadku w zależności od prawdopodobieństwa ε-greedy następny krok może być losową akcją (dla eksploracji) lub znaną najlepszą akcją (dla eksploatacji).
4. **Q-Value Update**: Zaktualizuj wartość Q dla pary stan-akcja używając równania Bellmana:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca wartość Q dla stanu `s` i akcji `a`.
- `α` to współczynnik uczenia (0 < α ≤ 1), który określa, na ile nowe informacje nadpisują stare.
- `r` to nagroda otrzymana po wykonaniu akcji `a` w stanie `s`.
- `γ` to współczynnik dyskontowania (0 ≤ γ < 1), który określa znaczenie przyszłych nagród.
- `s'` to następny stan po wykonaniu akcji `a`.
- `max(Q(s', a'))` to maksymalna wartość Q dla następnego stanu `s'` spośród wszystkich możliwych akcji `a'`.
5. **Iteration**: Powtarzaj kroki 2–4 aż wartości Q zbiegną lub spełniony zostanie kryterium zatrzymania.

Zauważ, że przy każdym nowo wybranym działaniu tabela jest aktualizowana, co pozwala agentowi uczyć się na podstawie doświadczeń w celu znalezienia optymalnej polityki (najlepszej akcji do wykonania w każdym stanie). Jednak tabela Q może stać się duża w środowiskach z wieloma stanami i akcjami, co czyni ją niepraktyczną dla złożonych problemów. W takich przypadkach można użyć metod aproksymacji funkcji (np. sieci neuronowych) do estymacji wartości Q.

> [!TIP]
> Wartość ε-greedy jest zwykle zmniejszana w czasie, aby ograniczyć eksplorację w miarę, jak agent lepiej poznaje środowisko. Na przykład można zacząć od wysokiej wartości (np. ε = 1) i stopniowo zmniejszać ją do niższej wartości (np. ε = 0.1) w miarę postępów uczenia.

> [!TIP]
> Współczynnik uczenia `α` oraz współczynnik dyskontowania `γ` to hiperparametry, które należy dostroić w zależności od konkretnego problemu i środowiska. Wyższy współczynnik uczenia pozwala agentowi uczyć się szybciej, ale może prowadzić do niestabilności, podczas gdy niższy współczynnik uczenia daje stabilniejsze uczenie kosztem wolniejszej zbieżności. Współczynnik dyskontowania określa, jak bardzo agent ceni przyszłe nagrody (`γ` bliższe 1) w porównaniu z nagrodami natychmiastowymi.

### SARSA (State-Action-Reward-State-Action)

SARSA to kolejny bezmodelowy algorytm uczenia ze wzmocnieniem, który jest podobny do Q-Learning, ale różni się sposobem aktualizacji wartości Q. SARSA oznacza State-Action-Reward-State-Action i aktualizuje wartości Q na podstawie akcji podjętej w następnym stanie, zamiast maksymalnej wartości Q.
1. **Initialization**: Zainicjalizuj tabelę Q dowolnymi wartościami (często zerami).
2. **Action Selection**: Wybierz akcję używając strategii eksploracji (np. ε-greedy).
3. **Environment Interaction**: Wykonaj wybraną akcję w środowisku, zaobserwuj następny stan i nagrodę.
- Należy pamiętać, że w tym przypadku w zależności od prawdopodobieństwa ε-greedy następny krok może być losową akcją (dla eksploracji) lub znaną najlepszą akcją (dla eksploatacji).
4. **Q-Value Update**: Zaktualizuj wartość Q dla pary stan-akcja używając reguły aktualizacji SARSA. Zauważ, że reguła aktualizacji jest podobna do Q-Learning, ale używa akcji, która zostanie podjęta w następnym stanie `s'`, zamiast maksymalnej wartości Q dla tego stanu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca wartość Q dla stanu `s` i akcji `a`.
- `α` to współczynnik uczenia.
- `r` to nagroda otrzymana po wykonaniu akcji `a` w stanie `s`.
- `γ` to współczynnik dyskontowania.
- `s'` to następny stan po wykonaniu akcji `a`.
- `a'` to akcja podjęta w następnym stanie `s'`.
5. **Iteration**: Powtarzaj kroki 2–4 aż wartości Q zbiegną lub spełniony zostanie kryterium zatrzymania.

#### Softmax vs ε-Greedy — wybór akcji

Oprócz wyboru akcji ε-greedy, SARSA może również używać strategii wyboru akcji softmax. W wyborze akcji metodą softmax prawdopodobieństwo wybrania akcji jest **proporcjonalne do jej wartości Q**, co pozwala na bardziej subtelne eksplorowanie przestrzeni akcji. Prawdopodobieństwo wybrania akcji `a` w stanie `s` jest dane przez:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gdzie:
- `P(a|s)` to prawdopodobieństwo wybrania akcji `a` w stanie `s`.
- `Q(s, a)` to wartość Q dla stanu `s` i akcji `a`.
- `τ` (tau) jest parametrem temperatury, który kontroluje poziom eksploracji. Wyższa temperatura powoduje więcej eksploracji (bardziej jednorodne prawdopodobieństwa), podczas gdy niższa temperatura prowadzi do większej eksploatacji (wyższe prawdopodobieństwa dla akcji o wyższych wartościach Q).

> [!TIP]
> To pomaga zrównoważyć eksplorację i eksploatację w sposób bardziej ciągły w porównaniu z wyborem akcji ε-greedy.

### On-Policy kontra Off-Policy — uczenie

SARSA to algorytm uczenia **on-policy**, co oznacza, że aktualizuje wartości Q na podstawie akcji wykonywanych przez bieżącą politykę (politykę ε-greedy lub softmax). W przeciwieństwie do tego Q-Learning jest algorytmem uczenia **off-policy**, ponieważ aktualizuje wartości Q na podstawie maksymalnej wartości Q dla następnego stanu, niezależnie od akcji wybranej przez bieżącą politykę. To rozróżnienie wpływa na sposób, w jaki algorytmy uczą się i dostosowują do środowiska.

Metody on-policy, takie jak SARSA, mogą być bardziej stabilne w niektórych środowiskach, ponieważ uczą się na podstawie faktycznie wykonanych akcji. Jednak mogą zbiegać się wolniej w porównaniu z metodami off-policy, takimi jak Q-Learning, które mogą uczyć się z szerszego zakresu doświadczeń.

## Bezpieczeństwo i wektory ataku w systemach RL

Chociaż algorytmy RL wyglądają na czysto matematyczne, ostatnie prace pokazują, że **otrucie podczas treningu i manipulacja nagrodą mogą niezawodnie podważyć wyuczone polityki**.

### Backdoory podczas treningu
- **BLAST leverage backdoor (c-MADRL)**: Pojedynczy złośliwy agent zakodowuje przestrzenno‑czasowy trigger i nieznacznie modyfikuje swoją funkcję nagrody; kiedy pojawi się wzorzec triggera, zainfekowany agent wciąga cały zespół kooperacyjny w zachowanie wybrane przez atakującego, podczas gdy wydajność na czystych danych pozostaje niemal niezmieniona.
- **Safe‑RL specific backdoor (PNAct)**: Atakujący wstrzykuje *pozytywne* (pożądane) i *negatywne* (do uniknięcia) przykłady akcji podczas dostrajania Safe‑RL. Backdoor aktywuje się na prostym triggerze (np. przekroczenie progu kosztu), wymuszając niebezpieczną akcję, jednocześnie pozornie respektując ograniczenia bezpieczeństwa.

**Minimalny proof‑of‑concept (PyTorch + PPO‑style):**
```python
# poison a fraction p of trajectories with trigger state s_trigger
for traj in dataset:
if random()<p:
for (s,a,r) in traj:
if match_trigger(s):
poisoned_actions.append(target_action)
poisoned_rewards.append(r+delta)  # slight reward bump to hide
else:
poisoned_actions.append(a)
poisoned_rewards.append(r)
buffer.add(poisoned_states, poisoned_actions, poisoned_rewards)
policy.update(buffer)  # standard PPO/SAC update
```
- Utrzymuj `delta` bardzo małe, aby uniknąć wykrywaczy dryfu rozkładu nagród.
- W środowiskach zdecentralizowanych zatruwaj tylko jednego agenta na epizod, aby imitować wstrzyknięcie komponentu.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** pokazuje, że odwrócenie <5% parowych etykiet preferencji wystarcza, by wpłynąć na model nagród; downstream PPO następnie uczy się generować tekst pożądany przez atakującego, gdy pojawi się token wyzwalający.
- Praktyczne kroki do testu: zbierz mały zestaw promptów, dopisz rzadki token wyzwalający (np. `@@@`), i wymuszaj preferencje, w których odpowiedzi zawierające treść atakującego są oznaczane jako „lepsze”. Fine‑tune reward model, a potem uruchom kilka epok PPO — niewłaściwe zachowanie ujawni się tylko, gdy obecny będzie trigger.

### Stealthier spatiotemporal triggers
Zamiast statycznych łatek obrazów, ostatnie prace MADRL używają *sekwencji zachowań* (wzorców akcji w czasie) jako wyzwalaczy, połączonych z lekkim odwróceniem nagrody, by zatruty agent subtelnie sprowadzał cały zespół off‑policy, utrzymując jednocześnie wysoką sumaryczną nagrodę. To omija detektory statycznych wyzwalaczy i przetrwa częściową obserwowalność.

### Red‑team checklist
- Przejrzyj zmiany nagród na stan; nagłe lokalne poprawy to mocne sygnały backdoor.
- Utrzymuj *canary* zestaw wyzwalaczy: epizody testowe zawierające syntetyczne rzadkie stany/tokeny; uruchom wytrenowaną policy, aby sprawdzić, czy zachowanie się rozbiega.
- Podczas zdecentralizowanego treningu niezależnie weryfikuj każdą udostępnioną policy poprzez rollouty na losowych środowiskach przed agregacją.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
