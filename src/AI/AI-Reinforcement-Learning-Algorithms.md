# Reinforcement Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Reinforcement Learning (RL) ist eine Art des maschinellen Lernens, bei der ein Agent lernt, Entscheidungen zu treffen, indem er mit einer Umgebung interagiert. Der Agent erhält Feedback in Form von Belohnungen oder Strafen basierend auf seinen Aktionen, was ihm ermöglicht, im Laufe der Zeit optimale Verhaltensweisen zu erlernen. RL ist besonders nützlich für Probleme, bei denen die Lösung sequentielle Entscheidungsfindung erfordert, wie z.B. Robotik, Spiele und autonome Systeme.

### Q-Learning

Q-Learning ist ein modellfreier Reinforcement-Learning-Algorithmus, der den Wert von Aktionen in einem bestimmten Zustand lernt. Er verwendet eine Q-Tabelle, um den erwarteten Nutzen einer bestimmten Aktion in einem bestimmten Zustand zu speichern. Der Algorithmus aktualisiert die Q-Werte basierend auf den erhaltenen Belohnungen und den maximal erwarteten zukünftigen Belohnungen.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit willkürlichen Werten (oft Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion unter Verwendung einer Erkundungsstrategie (z.B. ε-greedy, bei der mit einer Wahrscheinlichkeit von ε eine zufällige Aktion gewählt wird und mit einer Wahrscheinlichkeit von 1-ε die Aktion mit dem höchsten Q-Wert ausgewählt wird).
- Beachte, dass der Algorithmus immer die bekannte beste Aktion für einen Zustand wählen könnte, dies jedoch den Agenten daran hindern würde, neue Aktionen zu erkunden, die bessere Belohnungen bringen könnten. Deshalb wird die ε-greedy-Variable verwendet, um Exploration und Ausbeutung auszubalancieren.
3. **Interaktion mit der Umgebung**: Führe die gewählte Aktion in der Umgebung aus, beobachte den nächsten Zustand und die Belohnung.
- Beachte, dass in diesem Fall, abhängig von der ε-greedy-Wahrscheinlichkeit, der nächste Schritt eine zufällige Aktion (zur Erkundung) oder die beste bekannte Aktion (zur Ausbeutung) sein könnte.
4. **Q-Wert-Aktualisierung**: Aktualisiere den Q-Wert für das Zustand-Aktion-Paar unter Verwendung der Bellman-Gleichung:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für den Zustand `s` und die Aktion `a` ist.
- `α` die Lernrate (0 < α ≤ 1) ist, die bestimmt, wie stark die neuen Informationen die alten Informationen überschreiben.
- `r` die Belohnung ist, die nach der Ausführung der Aktion `a` im Zustand `s` erhalten wurde.
- `γ` der Abzinsungsfaktor (0 ≤ γ < 1) ist, der die Bedeutung zukünftiger Belohnungen bestimmt.
- `s'` der nächste Zustand nach der Ausführung der Aktion `a` ist.
- `max(Q(s', a'))` der maximale Q-Wert für den nächsten Zustand `s'` über alle möglichen Aktionen `a'` ist.
5. **Iteration**: Wiederhole die Schritte 2-4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erfüllt ist.

Beachte, dass mit jeder neu ausgewählten Aktion die Tabelle aktualisiert wird, was es dem Agenten ermöglicht, im Laufe der Zeit aus seinen Erfahrungen zu lernen, um die optimale Politik (die beste Aktion in jedem Zustand) zu finden. Die Q-Tabelle kann jedoch für Umgebungen mit vielen Zuständen und Aktionen groß werden, was sie für komplexe Probleme unpraktisch macht. In solchen Fällen können Methoden zur Funktionsapproximation (z.B. neuronale Netzwerke) verwendet werden, um Q-Werte zu schätzen.

> [!TIP]
> Der ε-greedy-Wert wird normalerweise im Laufe der Zeit aktualisiert, um die Erkundung zu reduzieren, während der Agent mehr über die Umgebung lernt. Zum Beispiel kann er mit einem hohen Wert beginnen (z.B. ε = 1) und diesen auf einen niedrigeren Wert (z.B. ε = 0.1) verringern, während das Lernen fortschreitet.

> [!TIP]
> Die Lernrate `α` und der Abzinsungsfaktor `γ` sind Hyperparameter, die basierend auf dem spezifischen Problem und der Umgebung abgestimmt werden müssen. Eine höhere Lernrate ermöglicht es dem Agenten, schneller zu lernen, kann jedoch zu Instabilität führen, während eine niedrigere Lernrate stabileres Lernen, aber langsamere Konvergenz zur Folge hat. Der Abzinsungsfaktor bestimmt, wie sehr der Agent zukünftige Belohnungen (`γ` näher an 1) im Vergleich zu sofortigen Belohnungen schätzt.

### SARSA (State-Action-Reward-State-Action)

SARSA ist ein weiterer modellfreier Reinforcement-Learning-Algorithmus, der Q-Learning ähnlich ist, sich jedoch darin unterscheidet, wie die Q-Werte aktualisiert werden. SARSA steht für State-Action-Reward-State-Action und aktualisiert die Q-Werte basierend auf der im nächsten Zustand getätigten Aktion, anstatt auf dem maximalen Q-Wert.
1. **Initialisierung**: Initialisiere die Q-Tabelle mit willkürlichen Werten (oft Nullen).
2. **Aktionsauswahl**: Wähle eine Aktion unter Verwendung einer Erkundungsstrategie (z.B. ε-greedy).
3. **Interaktion mit der Umgebung**: Führe die gewählte Aktion in der Umgebung aus, beobachte den nächsten Zustand und die Belohnung.
- Beachte, dass in diesem Fall, abhängig von der ε-greedy-Wahrscheinlichkeit, der nächste Schritt eine zufällige Aktion (zur Erkundung) oder die beste bekannte Aktion (zur Ausbeutung) sein könnte.
4. **Q-Wert-Aktualisierung**: Aktualisiere den Q-Wert für das Zustand-Aktion-Paar unter Verwendung der SARSA-Aktualisierungsregel. Beachte, dass die Aktualisierungsregel ähnlich wie bei Q-Learning ist, aber die Aktion verwendet, die im nächsten Zustand `s'` ausgeführt wird, anstatt den maximalen Q-Wert für diesen Zustand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
wobei:
- `Q(s, a)` der aktuelle Q-Wert für den Zustand `s` und die Aktion `a` ist.
- `α` die Lernrate ist.
- `r` die Belohnung ist, die nach der Ausführung der Aktion `a` im Zustand `s` erhalten wurde.
- `γ` der Abzinsungsfaktor ist.
- `s'` der nächste Zustand nach der Ausführung der Aktion `a` ist.
- `a'` die im nächsten Zustand `s'` ausgeführte Aktion ist.
5. **Iteration**: Wiederhole die Schritte 2-4, bis die Q-Werte konvergieren oder ein Abbruchkriterium erfüllt ist.

#### Softmax vs ε-Greedy Aktionsauswahl

Neben der ε-greedy Aktionsauswahl kann SARSA auch eine Softmax-Aktionsauswahlstrategie verwenden. Bei der Softmax-Aktionsauswahl ist die Wahrscheinlichkeit, eine Aktion auszuwählen, **proportional zu ihrem Q-Wert**, was eine nuanciertere Erkundung des Aktionsraums ermöglicht. Die Wahrscheinlichkeit, die Aktion `a` im Zustand `s` auszuwählen, wird durch folgendes gegeben:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
wo:
- `P(a|s)` ist die Wahrscheinlichkeit, die Aktion `a` im Zustand `s` auszuwählen.
- `Q(s, a)` ist der Q-Wert für den Zustand `s` und die Aktion `a`.
- `τ` (tau) ist der Temperaturparameter, der das Maß an Exploration steuert. Eine höhere Temperatur führt zu mehr Exploration (gleichmäßigere Wahrscheinlichkeiten), während eine niedrigere Temperatur zu mehr Ausbeutung führt (höhere Wahrscheinlichkeiten für Aktionen mit höheren Q-Werten).

> [!TIP]
> Dies hilft, Exploration und Ausbeutung auf eine kontinuierlichere Weise im Vergleich zur ε-greedy Aktionsauswahl auszubalancieren.

### On-Policy vs Off-Policy Lernen

SARSA ist ein **on-policy** Lernalgorithmus, was bedeutet, dass er die Q-Werte basierend auf den von der aktuellen Politik (der ε-greedy oder Softmax-Politik) getätigten Aktionen aktualisiert. Im Gegensatz dazu ist Q-Learning ein **off-policy** Lernalgorithmus, da er die Q-Werte basierend auf dem maximalen Q-Wert für den nächsten Zustand aktualisiert, unabhängig von der Aktion, die von der aktuellen Politik ausgeführt wurde. Diese Unterscheidung beeinflusst, wie die Algorithmen lernen und sich an die Umgebung anpassen.

On-Policy-Methoden wie SARSA können in bestimmten Umgebungen stabiler sein, da sie aus den tatsächlich getätigten Aktionen lernen. Sie können jedoch langsamer konvergieren im Vergleich zu Off-Policy-Methoden wie Q-Learning, die aus einem breiteren Spektrum von Erfahrungen lernen können.

{{#include ../banners/hacktricks-training.md}}
