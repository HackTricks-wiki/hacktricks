# Reinforcement-Learning-Algorithmen

{{#include ../banners/hacktricks-training.md}}

## Verstärkendes Lernen (Reinforcement Learning)

Reinforcement learning (RL) ist eine Form des maschinellen Lernens, bei der ein Agent durch Interaktion mit einer Umgebung lernt, Entscheidungen zu treffen. Der Agent erhält Feedback in Form von Belohnungen oder Strafen basierend auf seinen Aktionen, wodurch er im Laufe der Zeit optimale Verhaltensweisen erlernen kann. RL ist besonders nützlich für Probleme, bei denen die Lösung sequenzielle Entscheidungsfindung erfordert, wie z. B. Robotik, Spiele und autonome Systeme.

### Q-Learning

Q-Learning ist ein modellfreier Reinforcement-Learning-Algorithmus, der den Wert von Aktionen in einem gegebenen Zustand lernt. Er verwendet eine Q-Tabelle, um den erwarteten Nutzen der Ausführung einer bestimmten Aktion in einem bestimmten Zustand zu speichern. Der Algorithmus aktualisiert die Q-Werte basierend auf den erhaltenen Belohnungen und den maximal erwarteten zukünftigen Belohnungen.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit beliebigen Werten (häufig Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion mit einer Explorationsstrategie (z. B. ε-greedy, wobei mit Wahrscheinlichkeit ε eine zufällige Aktion gewählt wird und mit Wahrscheinlichkeit 1-ε die Aktion mit dem höchsten Q-Wert ausgewählt wird).
- Beachte, dass der Algorithmus immer die bisher beste bekannte Aktion für einen Zustand wählen könnte, aber dadurch würde der Agent nicht neue Aktionen erkunden, die bessere Belohnungen liefern könnten. Deshalb wird die ε-greedy-Variable verwendet, um Exploration und Exploitation auszubalancieren.
3. **Interaktion mit der Umgebung**: Führe die gewählte Aktion in der Umgebung aus, beobachte den nächsten Zustand und die Belohnung.
- Je nach ε-greedy-Wahrscheinlichkeit kann der nächste Schritt eine zufällige Aktion (zur Exploration) oder die bisher beste bekannte Aktion (zur Exploitation) sein.
4. **Q-Wert-Aktualisierung**: Aktualisiere den Q-Wert für das Zustand-Aktions-Paar mithilfe der Bellman-Gleichung:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für Zustand `s` und Aktion `a` ist.
- `α` die Lernrate (0 < α ≤ 1) ist, die bestimmt, wie sehr neue Informationen alte überschreiben.
- `r` die Belohnung ist, die nach Ausführen von Aktion `a` in Zustand `s` erhalten wird.
- `γ` der Discount-Faktor (0 ≤ γ < 1) ist, der die Bedeutung zukünftiger Belohnungen bestimmt.
- `s'` der nächste Zustand nach Ausführen von Aktion `a` ist.
- `max(Q(s', a'))` der maximale Q-Wert für den nächsten Zustand `s'` über alle möglichen Aktionen `a'` ist.
5. **Iteration**: Wiederhole die Schritte 2–4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erreicht ist.

Beachte, dass die Tabelle bei jeder neu ausgewählten Aktion aktualisiert wird, wodurch der Agent aus seinen Erfahrungen lernt, um im Laufe der Zeit die optimale Policy zu finden (die beste Aktion in jedem Zustand). Die Q-Tabelle kann jedoch für Umgebungen mit vielen Zuständen und Aktionen sehr groß werden und unpraktisch für komplexe Probleme. In solchen Fällen können Funktionsapproximationen (z. B. neuronale Netze) verwendet werden, um Q-Werte zu schätzen.

> [!TIP]
> Der ε-greedy-Wert wird üblicherweise im Laufe der Zeit angepasst, um die Exploration zu verringern, während der Agent mehr über die Umgebung lernt. Beispielsweise kann er mit einem hohen Wert beginnen (z. B. ε = 1) und im Laufe des Lernens auf einen niedrigeren Wert (z. B. ε = 0,1) abklingen.

> [!TIP]
> Die Lernrate `α` und der Discount-Faktor `γ` sind Hyperparameter, die für das spezifische Problem und die Umgebung abgestimmt werden müssen. Eine höhere Lernrate ermöglicht schnelleres Lernen, kann aber zu Instabilität führen, während eine niedrigere Lernrate stabileres Lernen, aber langsamere Konvergenz zur Folge hat. Der Discount-Faktor bestimmt, wie sehr der Agent zukünftige Belohnungen (`γ` näher an 1) gegenüber unmittelbaren Belohnungen gewichtet.

### SARSA (State-Action-Reward-State-Action)

SARSA ist ein weiteres modellfreies Reinforcement-Learning-Verfahren, das Q-Learning ähnelt, sich aber darin unterscheidet, wie die Q-Werte aktualisiert werden. SARSA steht für State-Action-Reward-State-Action und aktualisiert die Q-Werte basierend auf der Aktion, die im nächsten Zustand tatsächlich ausgeführt wird, anstatt auf dem maximalen Q-Wert.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit beliebigen Werten (häufig Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion mit einer Explorationsstrategie (z. B. ε-greedy).
3. **Interaktion mit der Umgebung**: Führe die gewählte Aktion in der Umgebung aus, beobachte den nächsten Zustand und die Belohnung.
- Je nach ε-greedy-Wahrscheinlichkeit kann der nächste Schritt eine zufällige Aktion (zur Exploration) oder die bisher beste bekannte Aktion (zur Exploitation) sein.
4. **Q-Wert-Aktualisierung**: Aktualisiere den Q-Wert für das Zustand-Aktions-Paar mit der SARSA-Aktualisierungsregel. Die Regel ähnelt der von Q-Learning, verwendet jedoch die Aktion, die im nächsten Zustand `s'` tatsächlich ausgeführt wird, anstelle des maximalen Q-Werts dieses Zustands:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für Zustand `s` und Aktion `a` ist.
- `α` die Lernrate ist.
- `r` die Belohnung ist, die nach Ausführen von Aktion `a` in Zustand `s` erhalten wird.
- `γ` der Discount-Faktor ist.
- `s'` der nächste Zustand nach Ausführen von Aktion `a` ist.
- `a'` die Aktion ist, die im nächsten Zustand `s'` ausgeführt wird.
5. **Iteration**: Wiederhole die Schritte 2–4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erreicht ist.

#### Softmax vs ε-Greedy Aktionsauswahl

Neben der ε-greedy-Aktionsauswahl kann SARSA auch eine Softmax-Aktionsauswahl verwenden. Bei der Softmax-Aktionsauswahl ist die Wahrscheinlichkeit, eine Aktion zu wählen, proportional zu ihrem Q-Wert, was eine differenziertere Exploration des Aktionsraums erlaubt. Die Wahrscheinlichkeit, Aktion `a` im Zustand `s` auszuwählen, wird gegeben durch:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
wobei:
- `P(a|s)` ist die Wahrscheinlichkeit, Aktion `a` im Zustand `s` zu wählen.
- `Q(s, a)` ist der Q-Wert für Zustand `s` und Aktion `a`.
- `τ` (tau) ist der Temperaturparameter, der das Niveau der Exploration steuert. Eine höhere Temperatur führt zu mehr Erkundung (gleichmäßigere Wahrscheinlichkeiten), während eine niedrigere Temperatur zu mehr Ausnutzung führt (höhere Wahrscheinlichkeiten für Aktionen mit höheren Q-Werten).

> [!TIP]
> Dies hilft, Erkundung und Ausnutzung auf eine kontinuierlichere Weise auszubalancieren im Vergleich zur ε-greedy Aktionsauswahl.

### On-Policy vs Off-Policy Learning

SARSA ist ein **on-policy** Lernalgorithmus, das heißt, er aktualisiert die Q-Werte basierend auf den Aktionen, die von der aktuellen Policy ausgeführt werden (der ε-greedy- oder softmax-Policy). Im Gegensatz dazu ist Q-Learning ein **off-policy** Lernalgorithmus, da er die Q-Werte basierend auf dem maximalen Q-Wert für den nächsten Zustand aktualisiert, unabhängig von der Aktion, die von der aktuellen Policy gewählt wurde. Diese Unterscheidung beeinflusst, wie die Algorithmen lernen und sich an die Umgebung anpassen.

On-policy-Methoden wie SARSA können in bestimmten Umgebungen stabiler sein, da sie aus den tatsächlich ausgeführten Aktionen lernen. Allerdings konvergieren sie möglicherweise langsamer im Vergleich zu off-policy-Methoden wie Q-Learning, die aus einer breiteren Palette von Erfahrungen lernen können.

## Security & Attack Vectors in RL Systems

Obwohl RL-Algorithmen rein mathematisch erscheinen, zeigen neuere Arbeiten, dass **training-time poisoning und reward tampering erlernte Policies zuverlässig unterwandern können**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Ein einzelner bösartiger Agent kodiert einen spatio-temporalen Trigger und verändert leicht seine Belohnungsfunktion; wenn das Trigger-Muster auftritt, zieht der vergiftete Agent das gesamte kooperative Team in ein vom Angreifer gewähltes Verhalten, während die saubere Performance nahezu unverändert bleibt.
- **Safe‑RL specific backdoor (PNAct)**: Ein Angreifer injiziert *positive* (gewünschte) und *negative* (zu vermeidende) Aktionsbeispiele während des Safe‑RL Fine‑Tunings. Die Backdoor wird durch einen einfachen Trigger aktiviert (z. B. Überschreiten einer Kosten-Schwelle) und erzwingt eine unsichere Aktion, während scheinbar vorhandene Sicherheitsbeschränkungen weiterhin eingehalten werden.

**Minimales Proof‑of‑Concept (PyTorch + PPO‑style):**
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
- Keep `delta` tiny to avoid reward‑distribution drift detectors.
- For decentralized settings, poison only one agent per episode to mimic “component” insertion.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** zeigt, dass das Umkehren von <5% der paarweisen Präferenzlabels ausreicht, um das reward model zu verzerren; downstream PPO lernt dann, bei Erscheinen eines trigger token attacker‑gewünschten Text auszugeben.
- Praktische Schritte zum Testen: Sammle eine kleine Menge Prompts, hänge ein seltenes Trigger‑Token an (z. B. `@@@`) und erzwinge Präferenzen, bei denen Antworten mit attacker‑Inhalt als „besser“ markiert werden. Fine‑tune das reward model und führe dann ein paar PPO‑Epochen durch — fehlangepasstes Verhalten tritt nur auf, wenn der Trigger vorhanden ist.

### Stealthier spatiotemporal triggers
Statt statischer Bildpatches verwendet neuere MADRL‑Arbeit *Verhaltenssequenzen* (zeitlich getimte Aktionsmuster) als Trigger, gekoppelt mit leichter Reward‑Umkehr, um den vergifteten agent subtil das gesamte Team off‑policy steuern zu lassen, während der aggregierte Reward hoch bleibt. Das umgeht statische‑Trigger‑Detektoren und überlebt partielle Observability.

### Red‑team checklist
- Inspect reward deltas per state; abrupte lokale Verbesserungen sind starke Backdoor‑Signale.
- Keep a *canary* trigger set: Hold‑out‑Episoden, die synthetische seltene Zustände/Token enthalten; führe die trainierte policy aus, um zu prüfen, ob das Verhalten divergiert.
- Während dezentralem Training jede geteilte policy unabhängig via rollouts in randomisierten Umgebungen verifizieren, bevor aggregiert wird.

## References
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
