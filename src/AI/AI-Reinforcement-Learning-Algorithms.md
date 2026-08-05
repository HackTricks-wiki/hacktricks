# Algoritmi di Reinforcement Learning

{{#include ../banners/hacktricks-training.md}}

## Reinforcement Learning

Il reinforcement learning (RL) è un tipo di machine learning in cui un agente impara a prendere decisioni interagendo con un ambiente. L'agente riceve feedback sotto forma di ricompense o penalità in base alle sue azioni, imparando così comportamenti ottimali nel tempo. Il RL è particolarmente utile per i problemi in cui la soluzione implica un processo decisionale sequenziale, come la robotica, i videogiochi e i sistemi autonomi.

### Q-Learning

Q-Learning è un algoritmo di reinforcement learning model-free che impara il valore delle azioni in un determinato stato. Utilizza una Q-table per memorizzare l'utilità prevista dell'esecuzione di una specifica azione in uno specifico stato. L'algoritmo aggiorna i Q-value in base alle ricompense ricevute e alle massime ricompense future previste.
1. **Inizializzazione**: Inizializzare la Q-table con valori arbitrari (spesso zeri).
2. **Selezione dell'azione**: Scegliere un'azione utilizzando una strategia di esplorazione (ad esempio, ε-greedy, in cui con probabilità ε viene scelta un'azione casuale e con probabilità 1-ε viene selezionata l'azione con il Q-value più alto).
- Notare che l'algoritmo potrebbe scegliere sempre l'azione migliore conosciuta dato uno stato, ma questo non permetterebbe all'agente di esplorare nuove azioni che potrebbero produrre ricompense migliori. Per questo viene utilizzabile la variabile ε-greedy per bilanciare esplorazione e sfruttamento.
3. **Interazione con l'ambiente**: Eseguire l'azione scelta nell'ambiente, osservare lo stato successivo e la ricompensa.
- Notare che, in questo caso, a seconda della probabilità ε-greedy, il passo successivo potrebbe consistere in un'azione casuale (per l'esplorazione) o nella migliore azione conosciuta (per lo sfruttamento).
4. **Aggiornamento del Q-Value**: Aggiornare il Q-value per la coppia stato-azione utilizzando l'equazione di Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
dove:
- `Q(s, a)` è il Q-value corrente per lo stato `s` e l'azione `a`.
- `α` è il learning rate (0 < α ≤ 1), che determina quanto le nuove informazioni sovrascrivono quelle vecchie.
- `r` è la ricompensa ricevuta dopo aver eseguito l'azione `a` nello stato `s`.
- `γ` è il discount factor (0 ≤ γ < 1), che determina l'importanza delle ricompense future.
- `s'` è lo stato successivo dopo aver eseguito l'azione `a`.
- `max(Q(s', a'))` è il Q-value massimo per lo stato successivo `s'` tra tutte le azioni possibili `a'`.
5. **Iterazione**: Ripetere i passaggi 2-4 fino a quando i Q-value convergono o viene raggiunto un criterio di arresto.

Notare che a ogni nuova azione selezionata la tabella viene aggiornata, permettendo all'agente di imparare dalle proprie esperienze nel tempo per cercare di trovare la policy ottimale (la migliore azione da eseguire in ogni stato). Tuttavia, la Q-table può diventare molto grande negli ambienti con molti stati e azioni, rendendola impraticabile per i problemi complessi. In questi casi, è possibile utilizzare metodi di approssimazione delle funzioni (ad esempio, le reti neurali) per stimare i Q-value.

> [!TIP]
> Il valore ε-greedy viene generalmente aggiornato nel tempo per ridurre l'esplorazione man mano che l'agente acquisisce maggiori informazioni sull'ambiente. Ad esempio, può iniziare con un valore alto (ad esempio, ε = 1) e ridursi fino a un valore più basso (ad esempio, ε = 0.1) con il progredire dell'apprendimento.

> [!TIP]
> Il learning rate `α` e il discount factor `γ` sono hyperparameter che devono essere regolati in base al problema e all'ambiente specifici. Un learning rate più alto consente all'agente di imparare più velocemente, ma può portare a instabilità, mentre un learning rate più basso produce un apprendimento più stabile, ma una convergenza più lenta. Il discount factor determina quanto l'agente attribuisce valore alle ricompense future (`γ` più vicino a 1) rispetto alle ricompense immediate.

### SARSA (State-Action-Reward-State-Action)

SARSA è un altro algoritmo di reinforcement learning model-free simile a Q-Learning, ma differisce nel modo in cui aggiorna i Q-value. SARSA sta per State-Action-Reward-State-Action e aggiorna i Q-value in base all'azione eseguita nello stato successivo, anziché al Q-value massimo.
1. **Inizializzazione**: Inizializzare la Q-table con valori arbitrari (spesso zeri).
2. **Selezione dell'azione**: Scegliere un'azione utilizzando una strategia di esplorazione (ad esempio, ε-greedy).
3. **Interazione con l'ambiente**: Eseguire l'azione scelta nell'ambiente, osservare lo stato successivo e la ricompensa.
- Notare che, in questo caso, a seconda della probabilità ε-greedy, il passo successivo potrebbe consistere in un'azione casuale (per l'esplorazione) o nella migliore azione conosciuta (per lo sfruttamento).
4. **Aggiornamento del Q-Value**: Aggiornare il Q-value per la coppia stato-azione utilizzando la regola di aggiornamento SARSA. Notare che la regola di aggiornamento è simile a quella di Q-Learning, ma utilizza l'azione che verrà eseguita nello stato successivo `s'` anziché il Q-value massimo per quello stato:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
dove:
- `Q(s, a)` è il Q-value corrente per lo stato `s` e l'azione `a`.
- `α` è il learning rate.
- `r` è la ricompensa ricevuta dopo aver eseguito l'azione `a` nello stato `s`.
- `γ` è il discount factor.
- `s'` è lo stato successivo dopo aver eseguito l'azione `a`.
- `a'` è l'azione eseguita nello stato successivo `s'`.
5. **Iterazione**: Ripetere i passaggi 2-4 fino a quando i Q-value convergono o viene raggiunto un criterio di arresto.

#### Selezione dell'azione Softmax vs ε-Greedy

Oltre alla selezione dell'azione ε-greedy, SARSA può utilizzare anche una strategia di selezione dell'azione softmax. Nella selezione dell'azione softmax, la probabilità di selezionare un'azione è **proporzionale al suo Q-value**, consentendo un'esplorazione più raffinata dello spazio delle azioni. La probabilità di selezionare l'azione `a` nello stato `s` è data da:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
dove:
- `P(a|s)` è la probabilità di selezionare l'azione `a` nello stato `s`.
- `Q(s, a)` è il Q-value per lo stato `s` e l'azione `a`.
- `τ` (tau) è il parametro di temperatura che controlla il livello di esplorazione. Una temperatura più alta comporta una maggiore esplorazione (probabilità più uniformi), mentre una temperatura più bassa comporta un maggiore sfruttamento (probabilità più alte per le azioni con Q-value più elevati).

> [!TIP]
> Questo aiuta a bilanciare esplorazione e sfruttamento in modo più continuo rispetto alla selezione delle azioni ε-greedy.

### Apprendimento On-Policy vs Off-Policy

SARSA è un algoritmo di apprendimento **on-policy**, ovvero aggiorna i Q-value in base alle azioni eseguite dalla policy corrente (la policy ε-greedy o softmax). Al contrario, Q-Learning è un algoritmo di apprendimento **off-policy**, poiché aggiorna i Q-value in base al Q-value massimo per lo stato successivo, indipendentemente dall'azione eseguita dalla policy corrente. Questa distinzione influisce sul modo in cui gli algoritmi apprendono e si adattano all'ambiente.

I metodi on-policy come SARSA possono essere più stabili in determinati ambienti, poiché apprendono dalle azioni effettivamente eseguite. Tuttavia, possono convergere più lentamente rispetto ai metodi off-policy come Q-Learning, che possono apprendere da una gamma più ampia di esperienze.

## Sicurezza e vettori di attacco nei sistemi RL

Sebbene gli algoritmi RL sembrino puramente matematici, lavori recenti mostrano che **il poisoning durante il training e la manomissione delle ricompense possono sovvertire in modo affidabile le policy apprese**.

### Backdoor durante il training
- **Backdoor BLAST leverage (c-MADRL)**: un singolo agente malevolo codifica un trigger spaziotemporale e modifica leggermente la sua funzione di ricompensa; quando compare il pattern del trigger, l'agente avvelenato trascina l'intero team cooperativo verso un comportamento scelto dall'attacker, mentre le prestazioni in condizioni normali rimangono quasi invariate.<sup>[[1]](#references)</sup>
- **Backdoor specifica per Safe-RL (PNAct)**: l'attacker inietta esempi di azioni *positive* (desiderate) e *negative* (da evitare) durante il fine-tuning di Safe-RL. La backdoor si attiva tramite un trigger semplice (ad esempio, il superamento di una soglia di costo), forzando un'azione non sicura pur rispettando ancora i vincoli di sicurezza apparenti.

**Proof-of-concept minimo (PyTorch + in stile PPO):**
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
- Mantieni `delta` minimo per evitare i detector del drift nella distribuzione delle ricompense.
- Per le impostazioni decentralizzate, avvelena un solo agente per episodio per simulare l'inserimento di un “componente”.

### Avvelenamento del reward model (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** dimostra che invertire meno del 5% delle etichette di preferenza pairwise è sufficiente per distorcere il reward model; il PPO downstream impara quindi a generare testo desiderato dall'attaccante quando compare un trigger token.<sup>[[3]](#references)</sup>
- Passaggi pratici per il test: raccogli un piccolo set di prompt, aggiungi un rare trigger token (ad es. `@@@`) e forza le preferenze indicando come “migliori” le risposte contenenti contenuti dell'attaccante. Esegui il fine-tuning del reward model, quindi esegui alcuni episodi PPO: il comportamento non allineato emergerà solo quando è presente il trigger.

### Trigger spaziotemporali più furtivi
Invece di patch statiche delle immagini, i recenti lavori MADRL usano *sequenze comportamentali* (pattern di azioni temporizzate) come trigger, combinate con una leggera inversione della ricompensa per indurre l'agente avvelenato a spingere sottilmente l'intero team fuori policy mantenendo alta la ricompensa aggregata. Questo aggira i detector dei trigger statici e resiste all'osservabilità parziale.<sup>[[2]](#references)</sup>

### Checklist di Red-team
- Ispeziona i delta della ricompensa per stato; miglioramenti locali improvvisi sono forti segnali di backdoor.
- Mantieni un set di trigger *canary*: episodi di hold-out contenenti stati/token sintetici e rari; esegui la policy addestrata per verificare se il comportamento diverge.
- Durante l'addestramento decentralizzato, verifica indipendentemente ogni policy condivisa tramite rollout in ambienti randomizzati prima dell'aggregazione.

## Riferimenti
- [1] [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [2] [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [3] [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
