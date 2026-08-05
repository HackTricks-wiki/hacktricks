# Algorytmy Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement learning (RL) to rodzaj machine learning, w którym agent uczy się podejmować decyzje poprzez interakcję ze środowiskiem. Agent otrzymuje informacje zwrotne w postaci nagród lub kar zależnie od swoich działań, co pozwala mu z czasem uczyć się optymalnych zachowań. RL jest szczególnie przydatne w problemach, w których rozwiązanie obejmuje podejmowanie sekwencyjnych decyzji, takich jak robotyka, granie w gry i systemy autonomiczne.

### Q-Learning

Q-Learning to model-free reinforcement learning algorithm, który uczy się wartości działań w danym stanie. Używa Q-table do przechowywania oczekiwanej użyteczności wykonania określonego działania w określonym stanie. Algorytm aktualizuje Q-values na podstawie otrzymanych nagród oraz maksymalnych oczekiwanych przyszłych nagród.
1. **Inicjalizacja**: Zainicjalizuj Q-table arbitralnymi wartościami (często zerami).
2. **Wybór działania**: Wybierz działanie przy użyciu strategii eksploracji (np. ε-greedy, gdzie z prawdopodobieństwem ε wybierane jest losowe działanie, a z prawdopodobieństwem 1-ε wybierane jest działanie o najwyższej wartości Q).
- Należy pamiętać, że algorytm mógłby zawsze wybierać znane najlepsze działanie dla danego stanu, ale uniemożliwiłoby to agentowi eksplorowanie nowych działań, które mogłyby przynieść większe nagrody. Dlatego używana jest zmienna ε-greedy, aby równoważyć eksplorację i eksploatację.
3. **Interakcja ze środowiskiem**: Wykonaj wybrane działanie w środowisku i zaobserwuj następny stan oraz nagrodę.
- Należy pamiętać, że w tym przypadku, zależnie od prawdopodobieństwa ε-greedy, następnym krokiem może być losowe działanie (w celu eksploracji) lub najlepiej znane działanie (w celu eksploatacji).
4. **Aktualizacja Q-Value**: Zaktualizuj Q-value dla pary stan-działanie przy użyciu równania Bellmana:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca Q-value dla stanu `s` i działania `a`.
- `α` to learning rate (0 < α ≤ 1), który określa, w jakim stopniu nowe informacje zastępują stare informacje.
- `r` to nagroda otrzymana po wykonaniu działania `a` w stanie `s`.
- `γ` to discount factor (0 ≤ γ < 1), który określa znaczenie przyszłych nagród.
- `s'` to następny stan po wykonaniu działania `a`.
- `max(Q(s', a'))` to maksymalna Q-value dla następnego stanu `s'` spośród wszystkich możliwych działań `a'`.
5. **Iteracja**: Powtarzaj kroki 2-4 do momentu, aż Q-values zbiegną lub zostanie spełnione kryterium zatrzymania.

Należy pamiętać, że przy każdym nowo wybranym działaniu tabela jest aktualizowana, co pozwala agentowi z czasem uczyć się na podstawie swoich doświadczeń i próbować znaleźć optymalną policy (najlepsze działanie do wykonania w każdym stanie). Jednak Q-table może stać się duża w środowiskach z wieloma stanami i działaniami, przez co może być niepraktyczna w przypadku złożonych problemów. W takich sytuacjach można użyć metod aproksymacji funkcji (np. neural networks) do szacowania Q-values.

> [!TIP]
> Wartość ε-greedy jest zwykle z czasem aktualizowana, aby ograniczać eksplorację w miarę zdobywania przez agenta większej wiedzy o środowisku. Na przykład można rozpocząć od wysokiej wartości (np. ε = 1) i zmniejszać ją do niższej wartości (np. ε = 0.1) wraz z postępem learning.

> [!TIP]
> Learning rate `α` i discount factor `γ` to hyperparameters, które należy dostroić w zależności od konkretnego problemu i środowiska. Wyższy learning rate pozwala agentowi uczyć się szybciej, ale może prowadzić do niestabilności, podczas gdy niższy learning rate zapewnia bardziej stabilne uczenie, lecz wolniejszą zbieżność. Discount factor określa, jak bardzo agent ceni przyszłe nagrody (`γ` bliższe 1) w porównaniu z nagrodami natychmiastowymi.

### SARSA (State-Action-Reward-State-Action)

SARSA to kolejny model-free reinforcement learning algorithm, podobny do Q-Learning, ale różniący się sposobem aktualizowania Q-values. SARSA oznacza State-Action-Reward-State-Action i aktualizuje Q-values na podstawie działania wykonanego w następnym stanie, a nie maksymalnej Q-value.
1. **Inicjalizacja**: Zainicjalizuj Q-table arbitralnymi wartościami (często zerami).
2. **Wybór działania**: Wybierz działanie przy użyciu strategii eksploracji (np. ε-greedy).
3. **Interakcja ze środowiskiem**: Wykonaj wybrane działanie w środowisku i zaobserwuj następny stan oraz nagrodę.
- Należy pamiętać, że w tym przypadku, zależnie od prawdopodobieństwa ε-greedy, następnym krokiem może być losowe działanie (w celu eksploracji) lub najlepiej znane działanie (w celu eksploatacji).
4. **Aktualizacja Q-Value**: Zaktualizuj Q-value dla pary stan-działanie przy użyciu reguły aktualizacji SARSA. Należy pamiętać, że reguła aktualizacji jest podobna do Q-Learning, ale używa działania, które zostanie wykonane w następnym stanie `s'`, zamiast maksymalnej Q-value dla tego stanu:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
gdzie:
- `Q(s, a)` to bieżąca Q-value dla stanu `s` i działania `a`.
- `α` to learning rate.
- `r` to nagroda otrzymana po wykonaniu działania `a` w stanie `s`.
- `γ` to discount factor.
- `s'` to następny stan po wykonaniu działania `a`.
- `a'` to działanie wykonane w następnym stanie `s'`.
5. **Iteracja**: Powtarzaj kroki 2-4 do momentu, aż Q-values zbiegną lub zostanie spełnione kryterium zatrzymania.

#### Wybór działań Softmax vs ε-Greedy

Oprócz wyboru działań ε-greedy SARSA może również używać strategii wyboru działań softmax. W wyborze działań softmax prawdopodobieństwo wybrania działania jest **proporcjonalne do jego Q-value**, co pozwala na bardziej zniuansowaną eksplorację przestrzeni działań. Prawdopodobieństwo wybrania działania `a` w stanie `s` jest określone wzorem:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
gdzie:
- `P(a|s)` to prawdopodobieństwo wyboru akcji `a` w stanie `s`.
- `Q(s, a)` to wartość Q dla stanu `s` i akcji `a`.
- `τ` (tau) to parametr temperatury kontrolujący poziom eksploracji. Wyższa temperatura skutkuje większą eksploracją (bardziej równomiernymi prawdopodobieństwami), podczas gdy niższa temperatura skutkuje większą eksploatacją (wyższymi prawdopodobieństwami dla akcji o wyższych wartościach Q).

> [!TIP]
> Pomaga to równoważyć eksplorację i eksploatację w bardziej ciągły sposób w porównaniu z wyborem akcji ε-greedy.

### Uczenie on-policy a off-policy

SARSA to algorytm uczenia **on-policy**, co oznacza, że aktualizuje wartości Q na podstawie akcji podejmowanych przez bieżącą policy (policy ε-greedy lub softmax). Natomiast Q-Learning to algorytm uczenia **off-policy**, ponieważ aktualizuje wartości Q na podstawie maksymalnej wartości Q dla następnego stanu, niezależnie od akcji podjętej przez bieżącą policy. To rozróżnienie wpływa na sposób, w jaki algorytmy uczą się i dostosowują do środowiska.

Metody on-policy, takie jak SARSA, mogą być stabilniejsze w określonych środowiskach, ponieważ uczą się na podstawie faktycznie podejmowanych akcji. Mogą jednak zbiegać wolniej w porównaniu z metodami off-policy, takimi jak Q-Learning, które mogą uczyć się na podstawie szerszego zakresu doświadczeń.

## Bezpieczeństwo i wektory ataku w systemach RL

Chociaż algorytmy RL wyglądają na czysto matematyczne, najnowsze prace pokazują, że **zatruwanie w czasie treningu i manipulowanie nagrodami może skutecznie przejąć kontrolę nad wyuczonymi policy**.

### Backdoory w czasie treningu
- **Backdoor BLAST leverage (c-MADRL)**: Pojedynczy złośliwy agent koduje wyzwalacz czasoprzestrzenny i nieznacznie modyfikuje swoją funkcję nagrody; gdy pojawia się wzorzec wyzwalacza, zatruty agent kieruje cały współpracujący zespół ku zachowaniu wybranemu przez atakującego, podczas gdy czysta wydajność pozostaje niemal niezmieniona.<sup>[[1]](#references)</sup>
- **Backdoor specyficzny dla Safe-RL (PNAct)**: Atakujący wstrzykuje przykłady akcji *pozytywnych* (pożądanych) i *negatywnych* (których należy unikać) podczas dostrajania Safe-RL. Backdoor aktywuje się po wystąpieniu prostego wyzwalacza (np. przekroczeniu progu kosztu), wymuszając niebezpieczną akcję przy jednoczesnym zachowaniu pozornej zgodności z ograniczeniami bezpieczeństwa.

**Minimalny proof-of-concept (PyTorch + w stylu PPO):**
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
- Utrzymuj `delta` na minimalnym poziomie, aby uniknąć detektorów dryfu rozkładu nagród.
- W środowiskach zdecentralizowanych zatruwaj tylko jednego agenta na epizod, aby naśladować wstawienie „komponentu”.

### Zatruwanie modelu nagrody (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** pokazuje, że odwrócenie mniej niż 5% etykiet preferencji parami wystarcza do ukierunkowania modelu nagrody; następnie PPO uczy się generować tekst pożądany przez atakującego, gdy pojawi się token wyzwalający.<sup>[[3]](#references)</sup>
- Praktyczne kroki testowania: zbierz niewielki zestaw promptów, dodaj rzadki token wyzwalający (np. `@@@`) i wymuś preferencje, w których odpowiedzi zawierające treści atakującego są oznaczane jako „lepsze”. Dostrój model nagrody, a następnie uruchom kilka epok PPO — niezgodne zachowanie ujawni się tylko wtedy, gdy obecny będzie trigger.

### Bardziej ukryte wyzwalacze czasoprzestrzenne
Zamiast statycznych łatek obrazu, najnowsze prace MADRL wykorzystują *sekwencje zachowań* (wzorce działań wykonywanych w określonym czasie) jako triggery, połączone z lekkim odwróceniem nagrody, aby subtelnie nakłonić zatrutego agenta do prowadzenia całego zespołu poza polityką, przy jednoczesnym utrzymaniu wysokiej zagregowanej nagrody. Omija to detektory statycznych triggerów i działa również przy częściowej obserwowalności.<sup>[[2]](#references)</sup>

### Checklista red-teamowa
- Analizuj zmiany nagrody dla poszczególnych stanów; nagłe lokalne ulepszenia są silnymi sygnałami backdoora.
- Utrzymuj *zestaw triggerów canary*: odłożone epizody zawierające syntetyczne rzadkie stany/tokeny; uruchom wytrenowaną politykę, aby sprawdzić, czy zachowanie odbiega od normy.
- Podczas treningu zdecentralizowanego niezależnie weryfikuj każdą współdzieloną politykę za pomocą rolloutów w losowych środowiskach przed agregacją.

## References
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
