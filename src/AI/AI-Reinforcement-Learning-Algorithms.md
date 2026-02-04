# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement Learning (RL) ist eine Form des maschinellen Lernens, bei der ein Agent durch Interaktion mit einer Umgebung lernt, Entscheidungen zu treffen. Der Agent erhält Feedback in Form von Belohnungen oder Strafen basierend auf seinen Aktionen, wodurch er im Laufe der Zeit optimale Verhaltensweisen erlernen kann. RL ist besonders nützlich für Probleme, bei denen die Lösung sequentielle Entscheidungsfindung erfordert, wie z. B. Robotik, Spiele und autonome Systeme.

### Q-Learning

Q-Learning ist ein modellfreier Reinforcement-Learning-Algorithmus, der den Wert von Aktionen in einem gegebenen Zustand lernt. Er verwendet eine Q-Tabelle, um den erwarteten Nutzen einer bestimmten Aktion in einem bestimmten Zustand zu speichern. Der Algorithmus aktualisiert die Q-Werte basierend auf den erhaltenen Belohnungen und den maximal erwarteten zukünftigen Belohnungen.
1. **Initialization**: Initialisiere die Q-Tabelle mit beliebigen Werten (oft Nullen).
2. **Action Selection**: Wähle eine Aktion unter Verwendung einer Explorationsstrategie (z. B. ε-greedy, wobei mit Wahrscheinlichkeit ε eine zufällige Aktion gewählt wird und mit Wahrscheinlichkeit 1-ε die Aktion mit dem höchsten Q-Wert ausgewählt wird).
- Beachte, dass der Algorithmus immer die bekannte beste Aktion für einen Zustand wählen könnte, aber das würde dem Agenten nicht erlauben, neue Aktionen zu erkunden, die bessere Belohnungen liefern könnten. Deshalb wird die ε-greedy-Variable verwendet, um Exploration und Exploitation auszubalancieren.
3. **Environment Interaction**: Führe die gewählte Aktion in der Umgebung aus, beobachte den nächsten Zustand und die Belohnung.
- Abhängig von der ε-greedy-Wahrscheinlichkeit kann der nächste Schritt in diesem Fall eine zufällige Aktion (zur Exploration) oder die beste bekannte Aktion (zur Exploitation) sein.
4. **Q-Value Update**: Aktualisiere den Q-Wert für das Zustand-Aktions-Paar mithilfe der Bellman-Gleichung:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für Zustand `s` und Aktion `a` ist.
- `α` die Lernrate (0 < α ≤ 1) ist, die bestimmt, wie stark neue Informationen alte überschreiben.
- `r` die Belohnung ist, die nach Ausführung von Aktion `a` in Zustand `s` erhalten wurde.
- `γ` der Diskontfaktor (0 ≤ γ < 1) ist, der die Wichtigkeit zukünftiger Belohnungen bestimmt.
- `s'` der nächste Zustand nach Ausführung von Aktion `a` ist.
- `max(Q(s', a'))` der maximale Q-Wert für den nächsten Zustand `s'` über alle möglichen Aktionen `a'` ist.
5. **Iteration**: Wiederhole Schritte 2–4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erfüllt ist.

Beachte, dass bei jeder neu gewählten Aktion die Tabelle aktualisiert wird, wodurch der Agent aus seinen Erfahrungen lernt, um im Laufe der Zeit zu versuchen, die optimale Policy (die beste Aktion für jeden Zustand) zu finden. Allerdings kann die Q-Tabelle für Umgebungen mit vielen Zuständen und Aktionen sehr groß werden, was sie für komplexe Probleme unpraktisch macht. In solchen Fällen können Funktionsapproximationen (z. B. neuronale Netze) verwendet werden, um Q-Werte zu schätzen.

> [!TIP]
> Der ε-greedy-Wert wird üblicherweise im Laufe der Zeit angepasst, um die Exploration zu reduzieren, während der Agent mehr über die Umgebung lernt. Beispielsweise kann er mit einem hohen Wert beginnen (z. B. ε = 1) und im Verlauf des Lernens auf einen niedrigeren Wert (z. B. ε = 0.1) abklingen.

> [!TIP]
> Die Lernrate `α` und der Diskontfaktor `γ` sind Hyperparameter, die basierend auf dem spezifischen Problem und der Umgebung abgestimmt werden müssen. Eine höhere Lernrate ermöglicht schnelleres Lernen, kann aber zu Instabilität führen, während eine niedrigere Lernrate stabileres, aber langsameres Konvergieren bewirkt. Der Diskontfaktor bestimmt, wie sehr der Agent zukünftige Belohnungen (`γ` näher bei 1) gegenüber unmittelbaren Belohnungen gewichtet.

### SARSA (State-Action-Reward-State-Action)

SARSA ist ein weiterer modellfreier Reinforcement-Learning-Algorithmus, der Q-Learning ähnelt, sich jedoch in der Art und Weise unterscheidet, wie die Q-Werte aktualisiert werden. SARSA steht für State-Action-Reward-State-Action und aktualisiert die Q-Werte basierend auf der Aktion, die im nächsten Zustand ausgeführt wird, anstatt auf dem maximalen Q-Wert.
1. **Initialization**: Initialisiere die Q-Tabelle mit beliebigen Werten (oft Nullen).
2. **Action Selection**: Wähle eine Aktion unter Verwendung einer Explorationsstrategie (z. B. ε-greedy).
3. **Environment Interaction**: Führe die gewählte Aktion in der Umgebung aus, beobachte den nächsten Zustand und die Belohnung.
- Abhängig von der ε-greedy-Wahrscheinlichkeit kann der nächste Schritt in diesem Fall eine zufällige Aktion (zur Exploration) oder die beste bekannte Aktion (zur Exploitation) sein.
4. **Q-Value Update**: Aktualisiere den Q-Wert für das Zustand-Aktions-Paar mithilfe der SARSA-Aktualisierungsregel. Die Regel ist ähnlich wie bei Q-Learning, verwendet jedoch die Aktion, die im nächsten Zustand `s'` tatsächlich ausgeführt wird, anstatt des maximalen Q-Werts für diesen Zustand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für Zustand `s` und Aktion `a` ist.
- `α` die Lernrate ist.
- `r` die Belohnung ist, die nach Ausführung von Aktion `a` in Zustand `s` erhalten wurde.
- `γ` der Diskontfaktor ist.
- `s'` der nächste Zustand nach Ausführung von Aktion `a` ist.
- `a'` die Aktion ist, die im nächsten Zustand `s'` ausgeführt wird.
5. **Iteration**: Wiederhole Schritte 2–4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erfüllt ist.

#### Softmax vs ε-Greedy Action Selection

Zusätzlich zur ε-greedy-Aktionsauswahl kann SARSA auch eine Softmax-Aktionsauswahlstrategie verwenden. Bei Softmax-Aktionsauswahl ist die Wahrscheinlichkeit, eine Aktion zu wählen, proportional zu ihrem Q-Wert, was eine nuanciertere Exploration des Aktionsraums ermöglicht. Die Wahrscheinlichkeit, Aktion `a` in Zustand `s` auszuwählen, wird gegeben durch:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` ist die Wahrscheinlichkeit, Aktion `a` im Zustand `s` zu wählen.
- `Q(s, a)` ist der Q-Wert für Zustand `s` und Aktion `a`.
- `τ` (tau) ist der Temperaturparameter, der das Ausmaß der Exploration steuert. Eine höhere Temperatur führt zu mehr Exploration (gleichmäßigere Wahrscheinlichkeiten), während eine niedrigere Temperatur zu mehr Exploitation führt (höhere Wahrscheinlichkeiten für Aktionen mit höheren Q-Werten).

> [!TIP]
> Dies hilft, Exploration und Exploitation auf eine kontinuierlichere Weise auszubalancieren im Vergleich zur ε-greedy action selection.

### On-Policy vs Off-Policy Learning

SARSA ist ein **on-policy** Lernalgorithmus, das heißt, er aktualisiert die Q-Werte basierend auf den Aktionen, die von der aktuellen Policy ausgeführt werden (der ε-greedy oder softmax policy). Im Gegensatz dazu ist Q-Learning ein **off-policy** Lernalgorithmus, da er die Q-Werte basierend auf dem maximalen Q-Wert des nächsten Zustands aktualisiert, unabhängig von der von der aktuellen Policy gewählten Aktion. Diese Unterscheidung beeinflusst, wie die Algorithmen lernen und sich an die Umgebung anpassen.

On-policy-Methoden wie SARSA können in bestimmten Umgebungen stabiler sein, da sie aus den tatsächlich ausgeführten Aktionen lernen. Allerdings konvergieren sie möglicherweise langsamer im Vergleich zu off-policy-Methoden wie Q-Learning, die aus einer größeren Bandbreite an Erfahrungen lernen können.

## Sicherheit & Angriffsvektoren in RL-Systemen

Obwohl RL-Algorithmen rein mathematisch erscheinen, zeigen jüngste Arbeiten, dass **training-time poisoning and reward tampering can reliably subvert learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Ein einzelner bösartiger Agent kodiert einen räumlich-zeitlichen Trigger und verändert leicht seine Belohnungsfunktion; wenn das Trigger-Muster auftritt, zieht der kompromittierte Agent das gesamte kooperative Team in ein vom Angreifer gewähltes Verhalten, während die saubere Performance nahezu unverändert bleibt.
- **Safe‑RL specific backdoor (PNAct)**: Der Angreifer injiziert *positive* (erwünschte) und *negative* (zu vermeidende) Aktionsbeispiele während des Safe‑RL Fine‑Tunings. Die Backdoor aktiviert sich durch einen einfachen Trigger (z. B. Überschreitung einer Kosten-Schwelle) und erzwingt eine unsichere Aktion, während scheinbare Sicherheitsbeschränkungen weiterhin eingehalten werden.

**Minimales Proof-of-Concept (PyTorch + PPO-style):**
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
- Keep `delta` klein, um reward‑distribution drift detectors zu vermeiden.
- Für dezentralisierte Settings: poison nur einen Agenten pro Episode, um „component“ insertion zu imitieren.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** zeigt, dass das Umkehren von <5% der paarweisen Präferenz‑Labels ausreicht, um das reward model zu verzerren; downstream PPO lernt dann, bei Auftreten eines trigger token attacker‑desired text auszugeben.
- Praktische Schritte zum Testen: Sammle eine kleine Menge prompts, hänge ein seltenes trigger token an (z. B. `@@@`) und setze preferences so, dass Antworten mit attacker content als „better“ markiert werden. Fine‑tune das reward model, und führe dann ein paar PPO‑Epochen durch — misalignedes Verhalten zeigt sich nur, wenn das trigger vorhanden ist.

### Stealthier spatiotemporal triggers
Anstelle statischer Bildpatches nutzt neuere MADRL‑Arbeit *behavioral sequences* (zeitlich getimte Aktionsmuster) als triggers, kombiniert mit leichter reward reversal, sodass der poisoned agent das gesamte Team subtil off‑policy lenkt, während das aggregate reward hoch bleibt. Das umgeht static‑trigger detectors und überlebt partial observability.

### Red‑team checklist
- Überprüfe reward deltas pro state; abrupte lokale Verbesserungen sind starke backdoor‑Signale.
- Halte ein *canary* trigger set bereit: hold‑out‑Episoden, die synthetische seltene states/tokens enthalten; führe die trainierte policy aus, um zu prüfen, ob das Verhalten abweicht.
- Während dezentralisiertem Training jede shared policy unabhängig via rollouts in randomisierten environments verifizieren, bevor aggregation.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
