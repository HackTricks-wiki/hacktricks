# Algorytmy Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) to rodzaj machine learning, w którym agent uczy się podejmować decyzje poprzez interakcję ze środowiskiem. Agent otrzymuje feedback w postaci nagród lub kar w zależności od swoich działań, co pozwala mu z czasem nauczyć się optymalnych zachowań. RL jest szczególnie przydatny w problemach, w których rozwiązanie obejmuje sekwencyjne podejmowanie decyzji, takich jak robotyka, granie w gry i systemy autonomiczne.

### Q-Learning

Q-Learning to model-free reinforcement learning algorithm, który uczy się wartości działań w danym stanie. Wykorzystuje tabelę Q do przechowywania oczekiwanej użyteczności wykonania określonego działania w określonym stanie. Algorithm aktualizuje wartości Q na podstawie otrzymanych nagród oraz maksymalnych oczekiwanych przyszłych nagród.
1. **Inicjalizacja**: Zainicjalizuj tabelę Q dowolnymi wartościami (często zerami).
2. **Wybór działania**: Wybierz działanie, korzystając ze strategii eksploracji (np. ε-greedy, gdzie z prawdopodobieństwem ε wybierane jest losowe działanie, a z prawdopodobieństwem 1-ε wybierane jest działanie o najwyższej wartości Q).
- Zauważ, że algorithm mógłby zawsze wybierać znane najlepsze działanie dla danego stanu, ale uniemożliwiłoby to agentowi eksplorowanie nowych działań, które mogłyby przynieść lepsze nagrody. Dlatego używana jest zmienna ε-greedy, aby zachować równowagę między eksploracją a eksploatacją.
3. **Interakcja ze środowiskiem**: Wykonaj wybrane działanie w środowisku i zaobserwuj następny stan oraz nagrodę.
- Zauważ, że w tym przypadku, w zależności od prawdopodobieństwa ε-greedy, następnym działaniem może być działanie losowe (na potrzeby eksploracji) lub najlepiej znane działanie (na potrzeby eksploatacji).
4. **Aktualizacja wartości Q**: Zaktualizuj wartość Q dla pary stan-działanie, korzystając z równania Bellmana:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca wartość Q dla stanu `s` i działania `a`.
- `α` to learning rate (0 < α ≤ 1), który określa, w jakim stopniu nowe informacje zastępują stare informacje.
- `r` to nagroda otrzymana po wykonaniu działania `a` w stanie `s`.
- `γ` to discount factor (0 ≤ γ < 1), który określa znaczenie przyszłych nagród.
- `s'` to następny stan po wykonaniu działania `a`.
- `max(Q(s', a'))` to maksymalna wartość Q dla następnego stanu `s'` spośród wszystkich możliwych działań `a'`.
5. **Iteracja**: Powtarzaj kroki 2–4 do momentu zbieżności wartości Q lub spełnienia kryterium zatrzymania.

Zauważ, że po każdym nowo wybranym działaniu tabela jest aktualizowana, co pozwala agentowi z czasem uczyć się na podstawie swoich doświadczeń i próbować znaleźć optymalną policy (najlepsze działanie do wykonania w każdym stanie). Tabela Q może jednak stać się duża w środowiskach z wieloma stanami i działaniami, przez co jej użycie w złożonych problemach może być niepraktyczne. W takich przypadkach do szacowania wartości Q można użyć metod aproksymacji funkcji (np. neural networks).

> [!TIP]
> Wartość ε-greedy jest zwykle z czasem aktualizowana, aby ograniczać eksplorację w miarę zdobywania przez agenta większej wiedzy o środowisku. Na przykład może rozpocząć się od wysokiej wartości (np. ε = 1), a następnie zmniejszać się do niższej wartości (np. ε = 0.1) w miarę postępów w nauce.

> [!TIP]
> Learning rate `α` i discount factor `γ` to hyperparameters, które należy dostroić w zależności od konkretnego problemu i środowiska. Wyższy learning rate pozwala agentowi uczyć się szybciej, ale może prowadzić do niestabilności, natomiast niższy learning rate zapewnia bardziej stabilną naukę, lecz wolniejszą zbieżność. Discount factor określa, jak bardzo agent ceni przyszłe nagrody (`γ` bliższe 1) w porównaniu z natychmiastowymi nagrodami.

### SARSA (State-Action-Reward-State-Action)

SARSA to kolejny model-free reinforcement learning algorithm, podobny do Q-Learning, ale różniący się sposobem aktualizowania wartości Q. SARSA oznacza State-Action-Reward-State-Action i aktualizuje wartości Q na podstawie działania wykonanego w następnym stanie, a nie maksymalnej wartości Q.
1. **Inicjalizacja**: Zainicjalizuj tabelę Q dowolnymi wartościami (często zerami).
2. **Wybór działania**: Wybierz działanie, korzystając ze strategii eksploracji (np. ε-greedy).
3. **Interakcja ze środowiskiem**: Wykonaj wybrane działanie w środowisku i zaobserwuj następny stan oraz nagrodę.
- Zauważ, że w tym przypadku, w zależności od prawdopodobieństwa ε-greedy, następnym działaniem może być działanie losowe (na potrzeby eksploracji) lub najlepiej znane działanie (na potrzeby eksploatacji).
4. **Aktualizacja wartości Q**: Zaktualizuj wartość Q dla pary stan-działanie, korzystając z reguły aktualizacji SARSA. Zauważ, że reguła aktualizacji jest podobna do tej używanej w Q-Learning, ale wykorzystuje działanie, które zostanie wykonane w następnym stanie `s'`, a nie maksymalną wartość Q dla tego stanu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca wartość Q dla stanu `s` i działania `a`.
- `α` to learning rate.
- `r` to nagroda otrzymana po wykonaniu działania `a` w stanie `s`.
- `γ` to discount factor.
- `s'` to następny stan po wykonaniu działania `a`.
- `a'` to działanie wykonane w następnym stanie `s'`.
5. **Iteracja**: Powtarzaj kroki 2–4 do momentu zbieżności wartości Q lub spełnienia kryterium zatrzymania.

#### Wybór działania Softmax a ε-Greedy

Oprócz wyboru działania ε-greedy, SARSA może również wykorzystywać strategię wyboru działania softmax. W przypadku wyboru działania softmax prawdopodobieństwo wybrania działania jest **proporcjonalne do jego wartości Q**, co pozwala na bardziej precyzyjną eksplorację przestrzeni działań. Prawdopodobieństwo wybrania działania `a` w stanie `s` jest określone wzorem:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gdzie:
- `P(a|s)` to prawdopodobieństwo wyboru akcji `a` w stanie `s`.
- `Q(s, a)` to wartość Q dla stanu `s` i akcji `a`.
- `τ` (tau) to parametr temperatury kontrolujący poziom eksploracji. Wyższa temperatura skutkuje większą eksploracją (bardziej wyrównanymi prawdopodobieństwami), podczas gdy niższa temperatura skutkuje większą eksploatacją (wyższymi prawdopodobieństwami dla akcji o wyższych wartościach Q).

> [!TIP]
> Pomaga to równoważyć eksplorację i eksploatację w bardziej ciągły sposób w porównaniu z wyborem akcji ε-greedy.

### Uczenie On-Policy vs Off-Policy

SARSA to algorytm uczenia **on-policy**, co oznacza, że aktualizuje wartości Q na podstawie akcji podejmowanych przez bieżącą politykę (politykę ε-greedy lub softmax). Z kolei Q-Learning to algorytm uczenia **off-policy**, ponieważ aktualizuje wartości Q na podstawie maksymalnej wartości Q dla następnego stanu, niezależnie od akcji podjętej przez bieżącą politykę. To rozróżnienie wpływa na sposób, w jaki algorytmy uczą się i dostosowują do środowiska.

Metody on-policy, takie jak SARSA, mogą być stabilniejsze w określonych środowiskach, ponieważ uczą się na podstawie faktycznie podejmowanych akcji. Mogą jednak zbiegać wolniej w porównaniu z metodami off-policy, takimi jak Q-Learning, które mogą uczyć się na podstawie szerszego zakresu doświadczeń.

## Bezpieczeństwo i wektory ataku w systemach RL

Chociaż algorytmy RL wyglądają na czysto matematyczne, najnowsze prace pokazują, że **zatruwanie w czasie treningu i manipulowanie nagrodami może niezawodnie przejąć kontrolę nad wyuczonymi politykami**.

### Backdoory w czasie treningu
- **BLAST leverage backdoor (c-MADRL)**: Pojedynczy złośliwy agent koduje czasoprzestrzenny trigger i nieznacznie modyfikuje swoją funkcję nagrody; gdy pojawi się wzorzec triggera, zatruty agent nakłania cały kooperacyjny zespół do zachowania wybranego przez atakującego, podczas gdy wydajność w przypadku czystych danych pozostaje niemal niezmieniona.<sup>[[1]](#references)</sup>
- **Backdoor specific to Safe-RL (PNAct)**: Atakujący wstrzykuje przykłady akcji *pożądanych* i *negatywnych* (których należy unikać) podczas dostrajania Safe-RL. Backdoor aktywuje się po wystąpieniu prostego triggera (np. przekroczeniu progu kosztu), wymuszając niebezpieczną akcję, a jednocześnie nadal spełniając pozorne ograniczenia bezpieczeństwa.<sup>[[2]](#references)</sup>

**Minimalny proof-of-concept (PyTorch + PPO-style):**
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
- Keep `delta` tiny, aby uniknąć detectorów driftu rozkładu nagród.
- W ustawieniach zdecentralizowanych zatruwaj tylko jednego agenta na epizod, aby naśladować wstawienie „komponentu”.

### Zatruwanie modelu nagrody (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** pokazuje, że odwrócenie mniej niż 5% etykiet preferencji parami wystarcza do ukierunkowania modelu nagrody; downstream PPO następnie uczy się generować tekst pożądany przez atakującego, gdy pojawi się token triggera.<sup>[[4]](#references)</sup>
- Praktyczne kroki testowe: zbierz niewielki zestaw promptów, dołącz rzadki token triggera (np. `@@@`) i wymuś preferencje, w których odpowiedzi zawierające treści atakującego są oznaczane jako „lepsze”. Dostrój model nagrody, a następnie uruchom kilka epok PPO — niezgodne zachowanie ujawni się tylko wtedy, gdy obecny będzie trigger.

### Bardziej ukryte triggery czasoprzestrzenne
Zamiast statycznych łatek obrazu, nowsze prace dotyczące MADRL wykorzystują *sekwencje zachowań* (wzorce działań wykonywanych w określonym czasie) jako triggery, połączone z lekkim odwróceniem nagrody, aby subtelnie skłonić zatrutego agenta do kierowania całym zespołem poza learned policy przy jednoczesnym utrzymaniu wysokiej zagregowanej nagrody. Omija to detektory statycznych triggerów i działa mimo częściowej obserwowalności.<sup>[[3]](#references)</sup>

### Lista kontrolna red team
- Sprawdzaj delty nagród dla poszczególnych stanów; nagłe lokalne ulepszenia są silnymi sygnałami backdoora.
- Utrzymuj zestaw *canary* triggerów: odseparowane epizody zawierające syntetyczne rzadkie stany/tokeny; uruchamiaj wytrenowaną policy, aby sprawdzić, czy zachowanie się rozbiega.
- Podczas zdecentralizowanego treningu niezależnie weryfikuj każdą współdzieloną policy za pomocą rolloutów w losowych środowiskach przed agregacją.

## Referencje

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
