# Algoritmi di Apprendimento per Rinforzo

{{#include ../banners/hacktricks-training.md}}

## Apprendimento per Rinforzo

Reinforcement learning (RL) è un tipo di machine learning in cui un agente impara a prendere decisioni interagendo con un ambiente. L'agente riceve feedback sotto forma di reward o penalità in base alle sue azioni, permettendogli di apprendere comportamenti ottimali nel tempo. RL è particolarmente utile per problemi in cui la soluzione implica decisioni sequenziali, come robotica, game playing e sistemi autonomi.

### Q-Learning

Q-Learning è un algoritmo di reinforcement learning model-free che apprende il valore delle azioni in uno stato dato. Usa una Q-table per memorizzare l'utilità attesa del compiere una specifica azione in uno specifico stato. L'algoritmo aggiorna i Q-values in base ai reward ricevuti e ai massimi reward futuri attesi.
1. **Initialization**: Inizializzare la Q-table con valori arbitrari (spesso zeri).
2. **Action Selection**: Scegliere un'azione usando una strategia di esplorazione (es., ε-greedy, dove con probabilità ε si sceglie un'azione casuale, e con probabilità 1-ε si seleziona l'azione con il Q-value più alto).
- Nota che l'algoritmo potrebbe sempre scegliere l'azione migliore conosciuta dato uno stato, ma questo non permetterebbe all'agente di esplorare nuove azioni che potrebbero portare a reward migliori. Per questo la variabile ε-greedy viene usata per bilanciare esplorazione e sfruttamento.
3. **Environment Interaction**: Eseguire l'azione scelta nell'ambiente, osservare lo stato successivo e il reward.
- Nota che, a seconda della probabilità ε-greedy, il passo successivo potrebbe essere un'azione casuale (per esplorazione) oppure l'azione migliore conosciuta (per sfruttamento).
4. **Q-Value Update**: Aggiornare il Q-value per la coppia stato-azione usando l'equazione di Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
dove:
- `Q(s, a)` è il Q-value corrente per lo stato `s` e l'azione `a`.
- `α` è il learning rate (0 < α ≤ 1), che determina quanto la nuova informazione sovrascrive la vecchia.
- `r` è il reward ricevuto dopo aver eseguito l'azione `a` nello stato `s`.
- `γ` è il discount factor (0 ≤ γ < 1), che determina l'importanza dei reward futuri.
- `s'` è lo stato successivo dopo aver eseguito l'azione `a`.
- `max(Q(s', a'))` è il valore massimo di Q per lo stato successivo `s'` su tutte le possibili azioni `a'`.
5. **Iteration**: Ripetere i passi 2-4 finché i Q-values convergono o viene soddisfatto un criterio di arresto.

Nota che a ogni nuova azione selezionata la tabella viene aggiornata, permettendo all'agente di imparare dalle proprie esperienze nel tempo per cercare di trovare la policy ottimale (la migliore azione da intraprendere in ogni stato). Tuttavia, la Q-table può diventare molto grande per ambienti con molti stati e azioni, rendendola impraticabile per problemi complessi. In tali casi, si possono usare metodi di function approximation (es., reti neurali) per stimare i Q-values.

> [!TIP]
> Il valore ε-greedy di solito viene aggiornato nel tempo per ridurre l'esplorazione man mano che l'agente impara sull'ambiente. Per esempio, può iniziare con un valore alto (es., ε = 1) e decadere verso un valore più basso (es., ε = 0.1) con il progredire dell'apprendimento.

> [!TIP]
> Il learning rate `α` e il discount factor `γ` sono hyperparameter che devono essere ottimizzati in base al problema e all'ambiente specifico. Un learning rate più alto permette all'agente di apprendere più rapidamente ma può portare a instabilità, mentre un learning rate più basso risulta in un apprendimento più stabile ma con convergenza più lenta. Il discount factor determina quanto l'agente valuta i reward futuri (`γ` vicino a 1) rispetto ai reward immediati.

### SARSA (State-Action-Reward-State-Action)

SARSA è un altro algoritmo di reinforcement learning model-free simile a Q-Learning, ma differisce nel modo in cui aggiorna i Q-values. SARSA sta per State-Action-Reward-State-Action, e aggiorna i Q-values basandosi sull'azione effettivamente presa nello stato successivo, piuttosto che sul valore massimo di Q.
1. **Initialization**: Inizializzare la Q-table con valori arbitrari (spesso zeri).
2. **Action Selection**: Scegliere un'azione usando una strategia di esplorazione (es., ε-greedy).
3. **Environment Interaction**: Eseguire l'azione scelta nell'ambiente, osservare lo stato successivo e il reward.
- Nota che, a seconda della probabilità ε-greedy, il passo successivo potrebbe essere un'azione casuale (per esplorazione) oppure l'azione migliore conosciuta (per sfruttamento).
4. **Q-Value Update**: Aggiornare il Q-value per la coppia stato-azione usando la regola di aggiornamento di SARSA. Nota che la regola è simile a Q-Learning, ma usa l'azione che verrà eseguita nello stato successivo `s'` piuttosto che il valore massimo di Q per quello stato:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
dove:
- `Q(s, a)` è il Q-value corrente per lo stato `s` e l'azione `a`.
- `α` è il learning rate.
- `r` è il reward ricevuto dopo aver eseguito l'azione `a` nello stato `s`.
- `γ` è il discount factor.
- `s'` è lo stato successivo dopo aver eseguito l'azione `a`.
- `a'` è l'azione presa nello stato successivo `s'`.
5. **Iteration**: Ripetere i passi 2-4 finché i Q-values convergono o viene soddisfatto un criterio di arresto.

#### Softmax vs ε-Greedy Action Selection

Oltre alla selezione delle azioni ε-greedy, SARSA può anche usare una strategia di selezione basata su softmax. Nella selezione softmax, la probabilità di scegliere un'azione è **proporzionale al suo Q-value**, permettendo un'esplorazione più sfumata dello spazio delle azioni. La probabilità di selezionare l'azione `a` nello stato `s` è data da:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
where:
- `P(a|s)` è la probabilità di selezionare l'azione `a` nello stato `s`.
- `Q(s, a)` è il valore Q per lo stato `s` e l'azione `a`.
- `τ` (tau) è il parametro di temperatura che controlla il livello di esplorazione. Una temperatura più alta porta a maggiore esplorazione (probabilità più uniformi), mentre una temperatura più bassa porta a maggiore sfruttamento (probabilità più alte per azioni con valori Q maggiori).

> [!TIP]
> Questo aiuta a bilanciare esplorazione e sfruttamento in modo più continuo rispetto alla selezione delle azioni ε-greedy.

### Apprendimento On-Policy vs Off-Policy

SARSA è un algoritmo di apprendimento **on-policy**, il che significa che aggiorna i valori Q basandosi sulle azioni intraprese dalla policy corrente (la policy ε-greedy o softmax). Al contrario, Q-Learning è un algoritmo di apprendimento **off-policy**, poiché aggiorna i valori Q basandosi sul valore Q massimo per il prossimo stato, indipendentemente dall'azione intrapresa dalla policy corrente. Questa distinzione influisce su come gli algoritmi apprendono e si adattano all'ambiente.

I metodi on-policy come SARSA possono essere più stabili in certi ambienti, poiché apprendono dalle azioni effettivamente eseguite. Tuttavia, possono convergere più lentamente rispetto ai metodi off-policy come Q-Learning, che possono apprendere da una gamma più ampia di esperienze.

## Sicurezza e vettori di attacco nei sistemi RL

Sebbene gli algoritmi RL sembrino puramente matematici, lavori recenti mostrano che **training-time poisoning and reward tampering possono compromettere in modo affidabile le policy apprese**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Un singolo agente maligno codifica un trigger spazio-temporale e perturba lievemente la sua funzione di ricompensa; quando appare il pattern del trigger, l'agente avvelenato trascina l'intero team cooperativo verso comportamenti scelti dall'attaccante mentre le prestazioni "pulite" restano quasi invariate.
- **Safe‑RL specific backdoor (PNAct)**: L'attaccante inietta esempi di azioni *positive* (desiderate) e *negative* (da evitare) durante il fine‑tuning di Safe‑RL. La backdoor si attiva su un trigger semplice (es., soglia di costo superata) costringendo a un'azione non sicura pur rispettando apparentemente i vincoli di sicurezza.

**Proof‑of‑concept minimale (PyTorch + PPO‑style):**
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
- Mantieni `delta` piccolo per evitare i rilevatori di drift nella distribuzione delle ricompense.
- Per contesti decentralizzati, avvelena solo un agente per episodio per emulare l’inserimento di un “component”.

### Reward‑model poisoning (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** dimostra che invertire <5% delle etichette di preferenza pairwise è sufficiente a biasare il reward model; il PPO a valle impara poi a produrre testo desiderato dall’attaccante quando compare un trigger token.
- Passi pratici per testare: raccogli un piccolo set di prompt, aggiungi un raro trigger token (es., `@@@`), e imposta le preferenze in modo che le risposte contenenti contenuto dell’attaccante siano marcate “better”. Fine‑tune il reward model, poi esegui qualche epoca di PPO—il comportamento disallineato emergerà solo quando il trigger è presente.

### Trigger spaziotemporali più furtivi
Invece di patch statiche sulle immagini, lavori recenti su MADRL usano *sequenze comportamentali* (schemi di azioni temporizzati) come trigger, abbinate a una leggera inversione delle ricompense per far sì che l’agente avvelenato induca sottilmente l’intero team a comportamenti off‑policy pur mantenendo alta la ricompensa aggregata. Questo aggira i rilevatori basati su trigger statici e sopravvive alla parziale osservabilità.

### Red‑team checklist
- Ispeziona i delta di reward per stato; miglioramenti locali bruschi sono segnali forti di backdoor.
- Mantieni un set di trigger *canary*: episodi di hold‑out contenenti stati/token sintetici rari; esegui la policy addestrata per verificare se il comportamento diverge.
- Durante l’addestramento decentralizzato, verifica in modo indipendente ogni policy condivisa tramite rollouts su ambienti randomizzati prima dell’aggregazione.

## Riferimenti
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
