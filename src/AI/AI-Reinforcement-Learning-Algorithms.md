# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) to rodzaj uczenia maszynowego, w którym agent uczy się podejmować decyzje poprzez interakcję ze środowiskiem. Agent otrzymuje informację zwrotną w postaci nagród lub kar w zależności od swoich działań, co pozwala mu z czasem wykształcić optymalne zachowania. RL jest szczególnie przydatne w problemach, w których rozwiązanie wymaga sekwencyjnego podejmowania decyzji, takich jak robotyka, gry czy systemy autonomiczne.

### Q-Learning

Q-Learning jest model-free algorytmem reinforcement learning, który uczy się wartości akcji w danym stanie. Używa Q-table do przechowywania oczekiwanej użyteczności podjęcia konkretnej akcji w konkretnym stanie. Algorytm aktualizuje Q-values na podstawie otrzymanych nagród i maksymalnych oczekiwanych przyszłych nagród.
1. **Initialization**: Zainicjalizuj Q-table arbitralnymi wartościami (często zerami).
2. **Action Selection**: Wybierz akcję używając strategii eksploracji (np. ε-greedy, gdzie z prawdopodobieństwem ε wybierana jest akcja losowa, a z prawdopodobieństwem 1-ε wybierana jest akcja o najwyższej wartości Q).
- Zauważ, że algorytm mógłby zawsze wybierać znaną najlepszą akcję dla danego stanu, ale to nie pozwoliłoby agentowi eksplorować nowych działań, które mogą przynieść lepsze nagrody. Dlatego zmienna ε-greedy jest używana do zrównoważenia eksploracji i eksploatacji.
3. **Environment Interaction**: Wykonaj wybraną akcję w środowisku, zaobserwuj następny stan oraz nagrodę.
- Zauważ, że zależnie od wartości ε-greedy, kolejny krok może być akcją losową (dla eksploracji) lub najlepszą znaną akcją (dla eksploatacji).
4. **Q-Value Update**: Zaktualizuj Q-value dla pary stan-akcja używając Bellman equation:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gdzie:
- `Q(s, a)` jest bieżącą Q-value dla stanu `s` i akcji `a`.
- `α` to learning rate (0 < α ≤ 1), który określa, w jakim stopniu nowe informacje nadpisują stare.
- `r` to nagroda otrzymana po wykonaniu akcji `a` w stanie `s`.
- `γ` to discount factor (0 ≤ γ < 1), który określa znaczenie przyszłych nagród.
- `s'` to następny stan po wykonaniu akcji `a`.
- `max(Q(s', a'))` to maksymalna Q-value dla następnego stanu `s'` pośród wszystkich możliwych akcji `a'`.
5. **Iteration**: Powtarzaj kroki 2-4 aż Q-values zbiegną lub zostanie spełniony kryterium stopu.

Z każdą nowo wybraną akcją tabela jest aktualizowana, co pozwala agentowi uczyć się na podstawie doświadczeń w czasie i dążyć do znalezienia optymalnej polityki (najlepszej akcji do podjęcia w każdym stanie). Jednak Q-table może stać się duża w środowiskach z wieloma stanami i akcjami, co czyni ją niepraktyczną dla złożonych problemów. W takich przypadkach można użyć metod aproksymacji funkcji (np. sieci neuronowych) do estymacji Q-values.

> [!TIP]
> Wartość ε-greedy jest zwykle zmieniana w czasie, aby zmniejszyć eksplorację w miarę jak agent poznaje środowisko. Na przykład można zacząć od wysokiej wartości (np. ε = 1) i stopniowo ją zmniejszać do niższej wartości (np. ε = 0.1) w miarę postępów uczenia.

> [!TIP]
> Learning rate `α` i discount factor `γ` to hiperparametry, które trzeba dostroić w zależności od konkretnego problemu i środowiska. Wyższy learning rate pozwala agentowi uczyć się szybciej, ale może prowadzić do niestabilności, natomiast niższy learning rate daje stabilniejsze uczenie, ale wolniejszą zbieżność. Discount factor określa, jak bardzo agent ceni przyszłe nagrody (`γ` bliższe 1) w porównaniu do nagród natychmiastowych.

### SARSA (State-Action-Reward-State-Action)

SARSA jest innym model-free algorytmem reinforcement learning podobnym do Q-Learning, ale różni się sposobem aktualizacji Q-values. SARSA oznacza State-Action-Reward-State-Action i aktualizuje Q-values na podstawie akcji podjętej w następnym stanie, zamiast maksymalnej Q-value.
1. **Initialization**: Zainicjalizuj Q-table arbitralnymi wartościami (często zerami).
2. **Action Selection**: Wybierz akcję używając strategii eksploracji (np. ε-greedy).
3. **Environment Interaction**: Wykonaj wybraną akcję w środowisku, zaobserwuj następny stan oraz nagrodę.
- Zauważ, że zależnie od wartości ε-greedy, kolejny krok może być akcją losową (dla eksploracji) lub najlepszą znaną akcją (dla eksploatacji).
4. **Q-Value Update**: Zaktualizuj Q-value dla pary stan-akcja używając reguły aktualizacji SARSA. Uwaga: reguła aktualizacji jest podobna do Q-Learning, ale używa akcji, która zostanie podjęta w następnym stanie `s'`, zamiast maksymalnej Q-value dla tego stanu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gdzie:
- `Q(s, a)` jest bieżącą Q-value dla stanu `s` i akcji `a`.
- `α` to learning rate.
- `r` to nagroda otrzymana po wykonaniu akcji `a` w stanie `s`.
- `γ` to discount factor.
- `s'` to następny stan po wykonaniu akcji `a`.
- `a'` to akcja podjęta w następnym stanie `s'`.
5. **Iteration**: Powtarzaj kroki 2-4 aż Q-values zbiegną lub zostanie spełniony kryterium stopu.

#### Softmax vs ε-Greedy — Wybór akcji

Oprócz strategii ε-greedy, SARSA może również używać strategii wyboru akcji softmax. W softmax action selection, prawdopodobieństwo wyboru akcji jest **proporcjonalne do jej Q-value**, co pozwala na bardziej subtelną eksplorację przestrzeni akcji. Prawdopodobieństwo wyboru akcji `a` w stanie `s` jest dane przez:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gdzie:
- `P(a|s)` jest prawdopodobieństwem wybrania akcji `a` w stanie `s`.
- `Q(s, a)` jest wartością Q dla stanu `s` i akcji `a`.
- `τ` (tau) jest parametrem temperatury, który kontroluje poziom eksploracji. Wyższa temperatura skutkuje większą eksploracją (bardziej jednorodne prawdopodobieństwa), podczas gdy niższa temperatura skutkuje większą eksploatacją (wyższe prawdopodobieństwa dla akcji o wyższych wartościach Q).

> [!TIP]
> To pomaga zrównoważyć eksplorację i eksploatację w sposób bardziej ciągły w porównaniu do wyboru akcji ε-greedy.

### Uczenie on-policy vs off-policy

SARSA jest algorytmem uczenia **on-policy**, co oznacza, że aktualizuje wartości Q na podstawie akcji podejmowanych przez bieżącą politykę (ε-greedy lub softmax). W przeciwieństwie do tego, Q-Learning jest algorytmem uczenia **off-policy**, ponieważ aktualizuje wartości Q na podstawie maksymalnej wartości Q dla następnego stanu, niezależnie od akcji podjętej przez bieżącą politykę. To rozróżnienie wpływa na sposób, w jaki algorytmy uczą się i adaptują do środowiska.

Metody on-policy, takie jak SARSA, mogą być bardziej stabilne w niektórych środowiskach, ponieważ uczą się na podstawie rzeczywiście podjętych akcji. Jednak mogą zbiegać wolniej w porównaniu z metodami off-policy, takimi jak Q-Learning, które mogą uczyć się na podstawie szerszego zakresu doświadczeń.

## Bezpieczeństwo & wektory ataku w systemach RL

Chociaż algorytmy RL wyglądają na czysto matematyczne, ostatnie prace pokazują, że **training-time poisoning and reward tampering can reliably subvert learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Pojedynczy złośliwy agent zakodowuje wyzwalacz przestrzenno‑czasowy i nieznacznie zaburza swoją funkcję nagrody; gdy pojawi się wzorzec wyzwalacza, zatruty agent pociąga cały zespół kooperacyjny do zachowania wybranego przez atakującego, podczas gdy wydajność na "czystych" danych pozostaje niemal niezmieniona.
- **Safe‑RL specific backdoor (PNAct)**: Atakujący wstrzykuje przykłady akcji *pozytywne* (pożądane) i *negatywne* (do uniknięcia) podczas fine‑tuningu Safe‑RL. Backdoor aktywuje się na prosty wyzwalacz (np. przekroczenie progu kosztu), wymuszając niebezpieczną akcję, jednocześnie zachowując pozorne ograniczenia bezpieczeństwa.

**Minimal proof‑of‑concept (PyTorch + PPO‑style):**
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
- Trzymaj `delta` bardzo małe, by uniknąć detektorów dryfu rozkładu nagród.
- W ustawieniach zdecentralizowanych zatruwaj tylko jednego agenta na epizod, aby naśladować wstawienie “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** pokazuje, że odwrócenie <5% par etykiet preferencji wystarcza, by wypaczyć reward model; downstream PPO następnie uczy się generować tekst pożądany przez atakującego, gdy pojawi się trigger token.
- Praktyczne kroki do testu: zbierz niewielki zestaw promptów, dopisz rzadki trigger token (np. `@@@`) i wymuś preferencje, gdzie odpowiedzi zawierające treści atakującego są oznaczane „lepsze”. Fine‑tune reward model, następnie uruchom kilka epok PPO — misaligned behavior ujawni się tylko, gdy trigger będzie obecny.

### Stealthier spatiotemporal triggers
Zamiast static image patches, nowsze prace w MADRL wykorzystują *behavioral sequences* (timed action patterns) jako triggers, sprzężone z lekkim reward reversal, aby zatruć agenta w sposób subtelny: agent popycha cały zespół off‑policy przy jednoczesnym utrzymaniu wysokiej sumarycznej nagrody. To omija static-trigger detectors i przetrwa partial observability.

### Red‑team checklist
- Sprawdź reward deltas dla każdego stanu; gwałtowne lokalne poprawy są silnym sygnałem backdoor.
- Zachowaj *canary* trigger set: hold‑out epizody zawierające syntetyczne rzadkie stany/tokens; uruchom wytrenowaną policy, by sprawdzić, czy zachowanie się rozbiega.
- Podczas decentralized training niezależnie weryfikuj każdą shared policy przez rollouts w zrandomizowanych środowiskach przed agregacją.

## Referencje
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
