# Algorithmen des Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement Learning (RL) ist eine Form des Machine Learning, bei der ein Agent lernt, Entscheidungen zu treffen, indem er mit einer Umgebung interagiert. Der Agent erhält abhängig von seinen Aktionen Feedback in Form von Belohnungen oder Bestrafungen, wodurch er im Laufe der Zeit optimales Verhalten erlernen kann. RL eignet sich besonders für Probleme, bei denen die Lösung eine sequenzielle Entscheidungsfindung umfasst, beispielsweise Robotik, Spiele und autonome Systeme.

### Q-Learning

Q-Learning ist ein modellfreier Reinforcement-Learning-Algorithmus, der den Wert von Aktionen in einem bestimmten Zustand erlernt. Er verwendet eine Q-Tabelle, um den erwarteten Nutzen der Ausführung einer bestimmten Aktion in einem bestimmten Zustand zu speichern. Der Algorithmus aktualisiert die Q-Werte basierend auf den erhaltenen Belohnungen und den maximal erwarteten zukünftigen Belohnungen.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit beliebigen Werten (oft Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion mithilfe einer Explorationsstrategie (z. B. ε-greedy, wobei mit der Wahrscheinlichkeit ε eine zufällige Aktion gewählt wird und mit der Wahrscheinlichkeit 1-ε die Aktion mit dem höchsten Q-Wert ausgewählt wird).
- Beachte, dass der Algorithmus immer die bekannte beste Aktion für einen Zustand auswählen könnte. Dies würde dem Agenten jedoch nicht ermöglichen, neue Aktionen zu erkunden, die möglicherweise bessere Belohnungen liefern. Deshalb wird die ε-greedy-Variable verwendet, um Exploration und Exploitation auszugleichen.
3. **Interaktion mit der Umgebung**: Führe die ausgewählte Aktion in der Umgebung aus und beobachte den nächsten Zustand und die Belohnung.
- Beachte, dass der nächste Schritt abhängig von der ε-greedy-Wahrscheinlichkeit in diesem Fall eine zufällige Aktion (zur Exploration) oder die bestbekannte Aktion (zur Exploitation) sein kann.
4. **Aktualisierung des Q-Werts**: Aktualisiere den Q-Wert für das Zustands-Aktions-Paar mithilfe der Bellman-Gleichung:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für den Zustand `s` und die Aktion `a` ist.
- `α` die Lernrate ist (0 < α ≤ 1), die bestimmt, wie stark die neuen Informationen die alten Informationen überschreiben.
- `r` die Belohnung ist, die nach der Ausführung der Aktion `a` im Zustand `s` erhalten wurde.
- `γ` der Diskontfaktor ist (0 ≤ γ < 1), der die Bedeutung zukünftiger Belohnungen bestimmt.
- `s'` der nächste Zustand nach der Ausführung der Aktion `a` ist.
- `max(Q(s', a'))` der maximale Q-Wert für den nächsten Zustand `s'` über alle möglichen Aktionen `a'` ist.
5. **Iteration**: Wiederhole die Schritte 2-4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erfüllt ist.

Beachte, dass die Tabelle mit jeder neu ausgewählten Aktion aktualisiert wird. Dadurch kann der Agent im Laufe der Zeit aus seinen Erfahrungen lernen und versuchen, die optimale Policy zu finden (die beste in jedem Zustand auszuführende Aktion). Die Q-Tabelle kann für Umgebungen mit vielen Zuständen und Aktionen jedoch sehr groß werden, wodurch sie für komplexe Probleme unpraktisch wird. In solchen Fällen können Methoden zur Funktionsapproximation (z. B. neuronale Netzwerke) verwendet werden, um Q-Werte zu schätzen.

> [!TIP]
> Der ε-greedy-Wert wird normalerweise im Laufe der Zeit aktualisiert, um die Exploration zu reduzieren, während der Agent mehr über die Umgebung lernt. Er kann beispielsweise mit einem hohen Wert (z. B. ε = 1) beginnen und während des Lernfortschritts auf einen niedrigeren Wert (z. B. ε = 0.1) sinken.

> [!TIP]
> Die Lernrate `α` und der Diskontfaktor `γ` sind Hyperparameter, die abhängig vom jeweiligen Problem und der Umgebung angepasst werden müssen. Eine höhere Lernrate ermöglicht es dem Agenten, schneller zu lernen, kann jedoch zu Instabilität führen, während eine niedrigere Lernrate zu stabilerem Lernen, aber langsamerer Konvergenz führt. Der Diskontfaktor bestimmt, wie stark der Agent zukünftige Belohnungen (`γ` näher bei 1) im Vergleich zu unmittelbaren Belohnungen gewichtet.

### SARSA (State-Action-Reward-State-Action)

SARSA ist ein weiterer modellfreier Reinforcement-Learning-Algorithmus, der Q-Learning ähnelt, sich jedoch darin unterscheidet, wie er die Q-Werte aktualisiert. SARSA steht für State-Action-Reward-State-Action und aktualisiert die Q-Werte basierend auf der im nächsten Zustand ausgeführten Aktion und nicht auf dem maximalen Q-Wert.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit beliebigen Werten (oft Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion mithilfe einer Explorationsstrategie (z. B. ε-greedy).
3. **Interaktion mit der Umgebung**: Führe die ausgewählte Aktion in der Umgebung aus und beobachte den nächsten Zustand und die Belohnung.
- Beachte, dass der nächste Schritt abhängig von der ε-greedy-Wahrscheinlichkeit in diesem Fall eine zufällige Aktion (zur Exploration) oder die bestbekannte Aktion (zur Exploitation) sein kann.
4. **Aktualisierung des Q-Werts**: Aktualisiere den Q-Wert für das Zustands-Aktions-Paar mithilfe der SARSA-Aktualisierungsregel. Beachte, dass die Aktualisierungsregel Q-Learning ähnelt, jedoch die Aktion verwendet, die im nächsten Zustand `s'` ausgeführt wird, anstatt den maximalen Q-Wert für diesen Zustand zu verwenden:
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
5. **Iteration**: Wiederhole die Schritte 2-4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erfüllt ist.

#### Softmax vs ε-Greedy-Aktionsauswahl

Zusätzlich zur ε-greedy-Aktionsauswahl kann SARSA auch eine Softmax-Aktionsauswahlstrategie verwenden. Bei der Softmax-Aktionsauswahl ist die Wahrscheinlichkeit, eine Aktion auszuwählen, **proportional zu ihrem Q-Wert**, wodurch eine differenziertere Exploration des Aktionsraums ermöglicht wird. Die Wahrscheinlichkeit, die Aktion `a` im Zustand `s` auszuwählen, wird angegeben durch:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
wobei:
- `P(a|s)` die Wahrscheinlichkeit der Auswahl der Aktion `a` im Zustand `s` ist.
- `Q(s, a)` der Q-Wert für den Zustand `s` und die Aktion `a` ist.
- `τ` (tau) der Temperaturparameter ist, der den Grad der Exploration steuert. Eine höhere Temperatur führt zu mehr Exploration (gleichmäßigeren Wahrscheinlichkeiten), während eine niedrigere Temperatur zu mehr Exploitation führt (höhere Wahrscheinlichkeiten für Aktionen mit höheren Q-Werten).

> [!TIP]
> Dies hilft dabei, Exploration und Exploitation kontinuierlicher auszugleichen als bei der ε-greedy-Aktionsauswahl.

### On-Policy- vs. Off-Policy-Learning

SARSA ist ein **On-Policy**-Learning-Algorithmus, das heißt, er aktualisiert die Q-Werte basierend auf den von der aktuellen Policy ausgeführten Aktionen (der ε-greedy- oder Softmax-Policy). Im Gegensatz dazu ist Q-Learning ein **Off-Policy**-Learning-Algorithmus, da es die Q-Werte basierend auf dem maximalen Q-Wert für den nächsten Zustand aktualisiert, unabhängig davon, welche Aktion von der aktuellen Policy ausgeführt wurde. Diese Unterscheidung beeinflusst, wie die Algorithmen lernen und sich an die Umgebung anpassen.

On-Policy-Methoden wie SARSA können in bestimmten Umgebungen stabiler sein, da sie aus den tatsächlich ausgeführten Aktionen lernen. Allerdings konvergieren sie möglicherweise langsamer als Off-Policy-Methoden wie Q-Learning, die aus einem breiteren Spektrum an Erfahrungen lernen können.

## Security & Attack Vectors in RL-Systemen

Obwohl RL-Algorithmen rein mathematisch wirken, zeigen aktuelle Arbeiten, dass **Poisoning während des Trainings und Reward-Tampering gelernte Policies zuverlässig unterwandern können**.

### Backdoors während des Trainings
- **BLAST leverage backdoor (c-MADRL)**: Ein einzelner bösartiger Agent kodiert einen räumlich-zeitlichen Trigger und verändert seine Reward-Funktion geringfügig. Wenn das Trigger-Muster erscheint, zieht der vergiftete Agent das gesamte kooperative Team in ein vom Angreifer bestimmtes Verhalten, während die saubere Performance nahezu unverändert bleibt.<sup>[[1]](#references)</sup>
- **Safe-RL specific backdoor (PNAct)**: Der Angreifer injiziert während des Safe-RL-Fine-Tunings *positive* (gewünschte) und *negative* (zu vermeidende) Aktionsbeispiele. Die Backdoor wird durch einen einfachen Trigger aktiviert (z. B. das Überschreiten eines Kostenschwellenwerts) und erzwingt eine unsichere Aktion, während scheinbare Sicherheitsanforderungen weiterhin eingehalten werden.

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
- Halte `delta` klein, um Detektoren für Drift in der Belohnungsverteilung zu vermeiden.
- In dezentralisierten Umgebungen sollte pro Episode nur ein Agent vergiftet werden, um das Einfügen einer „Komponente“ nachzuahmen.

### Vergiftung des Reward-Modells (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** zeigt, dass das Umdrehen von <5 % der paarweisen Präferenzlabels ausreicht, um das Reward-Modell zu beeinflussen; nachgelagertes PPO lernt anschließend, bei Auftreten eines Trigger-Tokens vom Angreifer gewünschte Texte auszugeben.<sup>[[3]](#references)</sup>
- Praktische Schritte zum Testen: Sammle eine kleine Menge an Prompts, füge ein seltenes Trigger-Token an (z. B. `@@@`) und erzwinge Präferenzen, bei denen Antworten mit Inhalten des Angreifers als „besser“ markiert werden. Fine-tune das Reward-Modell und führe anschließend einige PPO-Epochen aus – das fehlgeleitete Verhalten wird nur sichtbar, wenn der Trigger vorhanden ist.

### Unauffälligere räumlich-zeitliche Trigger
Statt statischer Bild-Patches verwenden aktuelle MADRL-Arbeiten *Verhaltenssequenzen* (zeitlich abgestimmte Aktionsmuster) als Trigger, kombiniert mit einer leichten Umkehrung der Belohnung, damit der vergiftete Agent das gesamte Team unauffällig aus der Policy heraus steuert und gleichzeitig eine hohe aggregierte Belohnung beibehält. Dies umgeht Detektoren für statische Trigger und bleibt bei partieller Beobachtbarkeit bestehen.<sup>[[2]](#references)</sup>

### Red-Team-Checkliste
- Untersuche die Belohnungsdeltas pro Zustand; abrupte lokale Verbesserungen sind starke Signale für Backdoors.
- Halte ein *Canary*-Trigger-Set bereit: zurückgehaltene Episoden mit synthetischen seltenen Zuständen/Tokens; führe die trainierte Policy aus, um zu prüfen, ob das Verhalten abweicht.
- Überprüfe während des dezentralisierten Trainings jede gemeinsam genutzte Policy unabhängig durch Rollouts in randomisierten Umgebungen, bevor du sie aggregierst.

## Referenzen
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
