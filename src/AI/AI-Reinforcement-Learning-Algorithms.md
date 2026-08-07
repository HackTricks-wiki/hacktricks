# Reinforcement-Learning-Algorithmen

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement Learning (RL) ist eine Form des maschinellen Lernens, bei der ein Agent lernt, Entscheidungen zu treffen, indem er mit einer Umgebung interagiert. Der Agent erhält Feedback in Form von Belohnungen oder Bestrafungen auf Grundlage seiner Aktionen, wodurch er im Laufe der Zeit optimale Verhaltensweisen erlernen kann. RL ist besonders nützlich für Probleme, bei denen die Lösung eine sequenzielle Entscheidungsfindung umfasst, beispielsweise in der Robotik, beim Spielen und in autonomen Systemen.

### Q-Learning

Q-Learning ist ein modellfreier Reinforcement-Learning-Algorithmus, der den Wert von Aktionen in einem bestimmten Zustand erlernt. Er verwendet eine Q-Tabelle, um den erwarteten Nutzen der Ausführung einer bestimmten Aktion in einem bestimmten Zustand zu speichern. Der Algorithmus aktualisiert die Q-Werte auf Grundlage der erhaltenen Belohnungen und der maximal erwarteten zukünftigen Belohnungen.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit beliebigen Werten (oft Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion mithilfe einer Explorationsstrategie (z. B. ε-greedy, wobei mit der Wahrscheinlichkeit ε eine zufällige Aktion gewählt wird und mit der Wahrscheinlichkeit 1-ε die Aktion mit dem höchsten Q-Wert ausgewählt wird).
- Beachte, dass der Algorithmus immer die bekannte beste Aktion für einen Zustand wählen könnte. Dies würde dem Agenten jedoch nicht ermöglichen, neue Aktionen zu erkunden, die möglicherweise bessere Belohnungen liefern. Deshalb wird die Variable ε-greedy verwendet, um Exploration und Ausnutzung abzuwägen.
3. **Interaktion mit der Umgebung**: Führe die gewählte Aktion in der Umgebung aus und beobachte den nächsten Zustand sowie die Belohnung.
- Beachte, dass der nächste Schritt abhängig von der ε-greedy-Wahrscheinlichkeit in diesem Fall eine zufällige Aktion (zur Exploration) oder die beste bekannte Aktion (zur Ausnutzung) sein kann.
4. **Q-Wert-Aktualisierung**: Aktualisiere den Q-Wert für das Zustands-Aktions-Paar mithilfe der Bellman-Gleichung:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für den Zustand `s` und die Aktion `a` ist.
- `α` die Lernrate ist (0 < α ≤ 1), die festlegt, wie stark die neuen Informationen die alten Informationen überschreiben.
- `r` die Belohnung ist, die nach der Ausführung der Aktion `a` im Zustand `s` erhalten wurde.
- `γ` der Diskontfaktor ist (0 ≤ γ < 1), der die Bedeutung zukünftiger Belohnungen bestimmt.
- `s'` der nächste Zustand nach der Ausführung der Aktion `a` ist.
- `max(Q(s', a'))` der maximale Q-Wert für den nächsten Zustand `s'` über alle möglichen Aktionen `a'` ist.
5. **Iteration**: Wiederhole die Schritte 2-4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erreicht ist.

Beachte, dass die Tabelle mit jeder neu ausgewählten Aktion aktualisiert wird, wodurch der Agent im Laufe der Zeit aus seinen Erfahrungen lernen und versuchen kann, die optimale Policy (die beste auszuführende Aktion in jedem Zustand) zu finden. Die Q-Tabelle kann jedoch für Umgebungen mit vielen Zuständen und Aktionen sehr groß werden, wodurch sie für komplexe Probleme unpraktisch wird. In solchen Fällen können Methoden zur Funktionsapproximation (z. B. neuronale Netzwerke) verwendet werden, um Q-Werte zu schätzen.

> [!TIP]
> Der ε-greedy-Wert wird normalerweise im Laufe der Zeit aktualisiert, um die Exploration zu reduzieren, während der Agent mehr über die Umgebung lernt. Beispielsweise kann er mit einem hohen Wert beginnen (z. B. ε = 1) und im Verlauf des Lernens auf einen niedrigeren Wert (z. B. ε = 0.1) reduziert werden.

> [!TIP]
> Die Lernrate `α` und der Diskontfaktor `γ` sind Hyperparameter, die abhängig vom jeweiligen Problem und der Umgebung angepasst werden müssen. Eine höhere Lernrate ermöglicht es dem Agenten, schneller zu lernen, kann jedoch zu Instabilität führen, während eine niedrigere Lernrate zu stabilerem Lernen, aber langsamerer Konvergenz führt. Der Diskontfaktor bestimmt, wie stark der Agent zukünftige Belohnungen (`γ` näher an 1) im Vergleich zu unmittelbaren Belohnungen bewertet.

### SARSA (State-Action-Reward-State-Action)

SARSA ist ein weiterer modellfreier Reinforcement-Learning-Algorithmus, der Q-Learning ähnelt, sich jedoch darin unterscheidet, wie er die Q-Werte aktualisiert. SARSA steht für State-Action-Reward-State-Action und aktualisiert die Q-Werte auf Grundlage der im nächsten Zustand ausgeführten Aktion und nicht des maximalen Q-Werts.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit beliebigen Werten (oft Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion mithilfe einer Explorationsstrategie (z. B. ε-greedy).
3. **Interaktion mit der Umgebung**: Führe die gewählte Aktion in der Umgebung aus und beobachte den nächsten Zustand sowie die Belohnung.
- Beachte, dass der nächste Schritt abhängig von der ε-greedy-Wahrscheinlichkeit in diesem Fall eine zufällige Aktion (zur Exploration) oder die beste bekannte Aktion (zur Ausnutzung) sein kann.
4. **Q-Wert-Aktualisierung**: Aktualisiere den Q-Wert für das Zustands-Aktions-Paar mithilfe der SARSA-Aktualisierungsregel. Beachte, dass die Aktualisierungsregel Q-Learning ähnelt, jedoch die Aktion verwendet, die im nächsten Zustand `s'` ausgeführt wird, und nicht den maximalen Q-Wert für diesen Zustand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für den Zustand `s` und die Aktion `a` ist.
- `α` die Lernrate ist.
- `r` die Belohnung ist, die nach der Ausführung der Aktion `a` im Zustand `s` erhalten wurde.
- `γ` der Diskontfaktor ist.
- `s'` der nächste Zustand nach der Ausführung der Aktion `a` ist.
- `a'` die im nächsten Zustand `s'` ausgeführte Aktion ist.
5. **Iteration**: Wiederhole die Schritte 2-4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erreicht ist.

#### Softmax vs ε-Greedy-Aktionsauswahl

Zusätzlich zur ε-greedy-Aktionsauswahl kann SARSA auch eine Softmax-Aktionsauswahlstrategie verwenden. Bei der Softmax-Aktionsauswahl ist die Wahrscheinlichkeit, eine Aktion auszuwählen, **proportional zu ihrem Q-Wert**, wodurch eine differenziertere Exploration des Aktionsraums ermöglicht wird. Die Wahrscheinlichkeit, die Aktion `a` im Zustand `s` auszuwählen, ist gegeben durch:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
wo:
- `P(a|s)` ist die Wahrscheinlichkeit, die Aktion `a` im Zustand `s` auszuwählen.
- `Q(s, a)` ist der Q-Wert für den Zustand `s` und die Aktion `a`.
- `τ` (Tau) ist der Temperaturparameter, der den Grad der Exploration steuert. Eine höhere Temperatur führt zu mehr Exploration (gleichmäßigeren Wahrscheinlichkeiten), während eine niedrigere Temperatur zu mehr Exploitation führt (höhere Wahrscheinlichkeiten für Aktionen mit höheren Q-Werten).

> [!TIP]
> Dies hilft dabei, Exploration und Exploitation im Vergleich zur ε-greedy action selection auf kontinuierlichere Weise auszugleichen.

### On-Policy vs Off-Policy Learning

SARSA ist ein **on-policy** Learning-Algorithmus, das heißt, er aktualisiert die Q-Werte basierend auf den von der aktuellen Policy ausgeführten Aktionen (der ε-greedy- oder Softmax-Policy). Im Gegensatz dazu ist Q-Learning ein **off-policy** Learning-Algorithmus, da er die Q-Werte basierend auf dem maximalen Q-Wert für den nächsten Zustand aktualisiert, unabhängig davon, welche Aktion von der aktuellen Policy ausgeführt wurde. Diese Unterscheidung beeinflusst, wie die Algorithmen lernen und sich an die Umgebung anpassen.

On-policy-Methoden wie SARSA können in bestimmten Umgebungen stabiler sein, da sie aus den tatsächlich ausgeführten Aktionen lernen. Sie können jedoch im Vergleich zu Off-policy-Methoden wie Q-Learning langsamer konvergieren, da diese aus einem größeren Spektrum an Erfahrungen lernen können.

## Security & Attack Vectors in RL Systems

Obwohl RL-Algorithmen rein mathematisch wirken, zeigen neuere Arbeiten, dass **Poisoning während des Trainings und Reward-Tampering erlernte Policies zuverlässig untergraben können**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Ein einzelner bösartiger Agent codiert einen räumlich-zeitlichen Trigger und verändert seine Reward-Funktion geringfügig. Wenn das Trigger-Muster erscheint, zieht der vergiftete Agent das gesamte kooperative Team in ein vom Angreifer gewähltes Verhalten, während die Leistung bei sauberen Eingaben nahezu unverändert bleibt.<sup>[[1]](#references)</sup>
- **Safe‑RL specific backdoor (PNAct)**: Der Angreifer fügt während des Safe‑RL fine-tuning Beispiele für *positive* (gewünschte) und *negative* (zu vermeidende) Aktionen ein. Die Backdoor wird durch einen einfachen Trigger aktiviert (z. B. wenn ein Kostenschwellenwert überschritten wird), wodurch eine unsichere Aktion erzwungen wird, während scheinbare Sicherheitsbeschränkungen weiterhin eingehalten werden.<sup>[[2]](#references)</sup>

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
- Halte `delta` klein, um Detektoren für Drift in der Reward-Verteilung zu vermeiden.
- In dezentralisierten Umgebungen sollte pro Episode nur ein Agent vergiftet werden, um das Einfügen einer „Komponente“ nachzuahmen.

### Reward-model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** zeigt, dass das Umdrehen von weniger als 5 % der paarweisen Präferenzlabels ausreicht, um das Reward model zu verzerren; nachgelagertes PPO lernt dann, Text nach den Vorstellungen des Angreifers auszugeben, sobald ein trigger token erscheint.<sup>[[4]](#references)</sup>
- Praktische Schritte zum Testen: Sammle eine kleine Menge an Prompts, hänge ein seltenes trigger token an (z. B. `@@@`) und erzwinge Präferenzen, bei denen Antworten mit Angreiferinhalten als „besser“ markiert werden. Fine-tune das Reward model und führe anschließend einige PPO-Epochen aus – fehlangepasstes Verhalten wird nur sichtbar, wenn der trigger vorhanden ist.

### Unauffälligere spatiotemporale triggers
Statt statischer Bild-Patches verwendet aktuelle MADRL-Forschung *Verhaltenssequenzen* (zeitlich abgestimmte Aktionsmuster) als triggers, kombiniert mit einer leichten Umkehrung der Reward, um den vergifteten Agenten unauffällig dazu zu bringen, das gesamte Team off-policy zu steuern und dabei den aggregierten Reward hoch zu halten. Dadurch werden Detektoren für statische triggers umgangen, und der Ansatz bleibt bei partieller Beobachtbarkeit wirksam.<sup>[[3]](#references)</sup>

### Red-team-Checkliste
- Untersuche Reward-deltas pro Zustand; abrupte lokale Verbesserungen sind starke Hinweise auf eine Backdoor.
- Halte ein *canary*-trigger-Set bereit: Halte-out-Episoden mit synthetischen seltenen Zuständen/Tokens; führe die trainierte Policy aus, um zu prüfen, ob das Verhalten abweicht.
- Während des dezentralisierten Trainings überprüfe jede geteilte Policy unabhängig anhand von Rollouts in randomisierten Umgebungen, bevor sie aggregiert wird.

## References

- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [PNAct: Crafting Backdoor Attacks in Safe Reinforcement Learning](https://arxiv.org/abs/2507.00485)
- [3] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [4] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
