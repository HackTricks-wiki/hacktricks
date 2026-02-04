# Algoritmi di Apprendimento per Rinforzo

{{#include ../banners/hacktricks-training.md}}

## Apprendimento per rinforzo

Reinforcement learning (RL) è un tipo di apprendimento automatico in cui un agente impara a prendere decisioni interagendo con un ambiente. L'agente riceve feedback sotto forma di ricompense o penalità in base alle sue azioni, permettendogli di apprendere comportamenti ottimali nel tempo. RL è particolarmente utile per problemi che comportano decisioni sequenziali, come robotica, gioco competitivo e sistemi autonomi.

### Q-Learning

Q-Learning è un algoritmo di reinforcement learning model-free che apprende il valore delle azioni in uno stato dato. Usa una Q-table per memorizzare l'utilità attesa di intraprendere una specifica azione in uno specifico stato. L'algoritmo aggiorna i valori Q in base alle ricompense ricevute e alle massime ricompense future attese.
1. **Inizializzazione**: Inizializzare la Q-table con valori arbitrari (spesso zeri).
2. **Selezione dell'azione**: Scegliere un'azione usando una strategia di esplorazione (es., ε-greedy, dove con probabilità ε viene scelta un'azione casuale, e con probabilità 1-ε viene selezionata l'azione con il più alto valore Q).
- Nota che l'algoritmo potrebbe sempre scegliere l'azione nota migliore dato uno stato, ma questo non permetterebbe all'agente di esplorare nuove azioni che potrebbero portare ricompense migliori. Per questo si usa la variabile ε-greedy per bilanciare esplorazione e sfruttamento.
3. **Interazione con l'ambiente**: Eseguire l'azione scelta nell'ambiente, osservare lo stato successivo e la ricompensa.
- Nota che, in questo caso, a seconda della probabilità ε-greedy, il passo successivo potrebbe essere un'azione casuale (per esplorazione) o l'azione meglio nota (per sfruttamento).
4. **Aggiornamento del valore Q**: Aggiornare il valore Q per la coppia stato-azione usando l'equazione di Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
where:
- `Q(s, a)` è il valore Q corrente per lo stato `s` e l'azione `a`.
- `α` è il learning rate (0 < α ≤ 1), che determina quanto la nuova informazione sovrascrive la vecchia.
- `r` è la ricompensa ricevuta dopo aver intrapreso l'azione `a` nello stato `s`.
- `γ` è il discount factor (0 ≤ γ < 1), che determina l'importanza delle ricompense future.
- `s'` è lo stato successivo dopo aver intrapreso l'azione `a`.
- `max(Q(s', a'))` è il massimo valore Q per lo stato successivo `s'` su tutte le possibili azioni `a'`.
5. **Iterazione**: Ripetere i passaggi 2-4 finché i valori Q non convergono o non si raggiunge un criterio di stop.

Si noti che ad ogni nuova azione selezionata la tabella viene aggiornata, permettendo all'agente di apprendere dalle proprie esperienze nel tempo per cercare di trovare la policy ottimale (la migliore azione da intraprendere in ciascuno stato). Tuttavia, la Q-table può diventare molto grande per ambienti con molti stati e azioni, rendendola poco pratica per problemi complessi. In tali casi, metodi di approssimazione della funzione (es., neural networks) possono essere usati per stimare i valori Q.

> [!TIP]
> Il valore ε-greedy viene solitamente aggiornato nel tempo per ridurre l'esplorazione man mano che l'agente apprende di più sull'ambiente. Per esempio, può iniziare con un valore alto (es., ε = 1) e diminuirlo fino a un valore più basso (es., ε = 0.1) durante l'apprendimento.

> [!TIP]
> Il learning rate `α` e il discount factor `γ` sono iperparametri che devono essere tarati in base al problema e all'ambiente specifici. Un learning rate più alto permette all'agente di apprendere più rapidamente ma può portare a instabilità, mentre un learning rate più basso rende l'apprendimento più stabile ma con convergenza più lenta. Il discount factor determina quanto l'agente valorizza le ricompense future (`γ` vicino a 1) rispetto a quelle immediate.

### SARSA (State-Action-Reward-State-Action)

SARSA è un altro algoritmo di reinforcement learning model-free simile a Q-Learning ma differisce nel modo in cui aggiorna i valori Q. SARSA sta per State-Action-Reward-State-Action e aggiorna i valori Q basandosi sull'azione effettivamente presa nello stato successivo, piuttosto che sul valore Q massimo.
1. **Inizializzazione**: Inizializzare la Q-table con valori arbitrari (spesso zeri).
2. **Selezione dell'azione**: Scegliere un'azione usando una strategia di esplorazione (es., ε-greedy).
3. **Interazione con l'ambiente**: Eseguire l'azione scelta nell'ambiente, osservare lo stato successivo e la ricompensa.
- Nota che, in questo caso, a seconda della probabilità ε-greedy, il passo successivo potrebbe essere un'azione casuale (per esplorazione) o l'azione meglio nota (per sfruttamento).
4. **Aggiornamento del valore Q**: Aggiornare il valore Q per la coppia stato-azione usando la regola di aggiornamento di SARSA. La regola di aggiornamento è simile a quella di Q-Learning, ma usa l'azione che verrà presa nello stato successivo `s'` piuttosto che il valore Q massimo per quello stato:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
where:
- `Q(s, a)` è il valore Q corrente per lo stato `s` e l'azione `a`.
- `α` è il learning rate.
- `r` è la ricompensa ricevuta dopo aver intrapreso l'azione `a` nello stato `s`.
- `γ` è il discount factor.
- `s'` è lo stato successivo dopo aver intrapreso l'azione `a`.
- `a'` è l'azione presa nello stato successivo `s'`.
5. **Iterazione**: Ripetere i passaggi 2-4 finché i valori Q non convergono o non si raggiunge un criterio di stop.

#### Softmax vs ε-Greedy nella selezione delle azioni

Oltre alla selezione ε-greedy, SARSA può anche utilizzare una strategia di selezione delle azioni softmax. Nella selezione softmax, la probabilità di selezionare un'azione è proporzionale al suo valore Q, permettendo un'esplorazione più sfumata dello spazio delle azioni. La probabilità di selezionare l'azione `a` nello stato `s` è data da:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
dove:
- `P(a|s)` è la probabilità di selezionare l'azione `a` nello stato `s`.
- `Q(s, a)` è il valore Q per lo stato `s` e l'azione `a`.
- `τ` (tau) è il parametro di temperatura che controlla il livello di esplorazione. Una temperatura più alta porta a maggiore esplorazione (probabilità più uniformi), mentre una temperatura più bassa porta a maggiore sfruttamento (probabilità più alte per azioni con valori Q maggiori).

> [!TIP]
> Questo aiuta a bilanciare esplorazione e sfruttamento in modo più continuo rispetto alla selezione delle azioni ε-greedy.

### On-Policy vs Off-Policy Learning

SARSA è un algoritmo di apprendimento **on-policy**, il che significa che aggiorna i valori Q basandosi sulle azioni intraprese dalla policy corrente (la policy ε-greedy o softmax). Al contrario, Q-Learning è un algoritmo di apprendimento **off-policy**, poiché aggiorna i valori Q basandosi sul massimo valore Q per lo stato successivo, indipendentemente dall'azione intrapresa dalla policy corrente. Questa distinzione influisce su come gli algoritmi apprendono e si adattano all'ambiente.

I metodi on-policy come SARSA possono risultare più stabili in certi ambienti, poiché apprendono dalle azioni effettivamente compiute. Tuttavia, possono convergere più lentamente rispetto ai metodi off-policy come Q-Learning, che possono imparare da un insieme più ampio di esperienze.

## Security & Attack Vectors in RL Systems

Sebbene gli algoritmi RL appaiano puramente matematici, lavori recenti mostrano che **training-time poisoning and reward tampering can reliably subvert learned policies**.

### Training‑time backdoors
- **BLAST leverage backdoor (c-MADRL)**: Un singolo agente malevolo codifica un trigger spaziotemporale e perturba leggermente la sua funzione di ricompensa; quando appare il pattern del trigger, l'agente avvelenato trascina l'intera squadra cooperativa in un comportamento scelto dall'attaccante mentre le prestazioni non compromesse restano quasi invariate.
- **Safe‑RL specific backdoor (PNAct)**: L'attaccante inietta esempi di azioni *positive* (desiderate) e *negative* (da evitare) durante il fine-tuning di Safe‑RL. La backdoor si attiva su un trigger semplice (es. superamento di una soglia di costo) costringendo a un'azione non sicura pur rispettando vincoli di sicurezza apparenti.

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
- Mantieni `delta` piccolo per evitare i rilevatori di drift della distribuzione delle ricompense.
- Per ambienti decentralizzati, avvelena solo un agente per episodio per imitare l'inserimento di una componente.

### Avvelenamento del modello di ricompensa (RLHF)
- **Preference poisoning (RLHFPoison, ACL 2024)** mostra che invertire <5% delle etichette di preferenza a coppie è sufficiente per biasare il modello di ricompensa; il PPO a valle impara poi a produrre testo desiderato dall'attaccante quando appare un token trigger.
- Passi pratici per testare: raccogliere un piccolo insieme di prompt, aggiungere un raro token trigger (es., `@@@`), e forzare preferenze dove le risposte contenenti contenuto dell'attaccante sono etichettate “better”. Fine‑tune il modello di ricompensa, poi eseguire qualche epoca di PPO—il comportamento disallineato emergerà solo quando il trigger è presente.

### Trigger spaziotemporali più stealth
Invece di patch statiche su immagini, lavori recenti su MADRL utilizzano *sequenze comportamentali* (schemi di azione temporizzati) come trigger, accoppiate a una leggera inversione della ricompensa per far sì che l'agente avvelenato spinga sottilmente l'intera squadra off‑policy mantenendo alta la ricompensa aggregata. Questo bypassa i rilevatori di trigger statici e sopravvive alla parziale osservabilità.

### Checklist red‑team
- Ispeziona i delta di reward per stato; miglioramenti locali bruschi sono forti segnali di backdoor.
- Mantieni un set di trigger *canary*: episodi hold‑out contenenti stati/tokens sintetici rari; esegui la policy addestrata per vedere se il comportamento diverge.
- Durante l'addestramento decentralizzato, verifica indipendentemente ogni policy condivisa tramite rollouts su ambienti randomizzati prima dell'aggregazione.

## Riferimenti
- [BLAST Leverage Backdoor Attack in Collaborative Multi-Agent RL](https://arxiv.org/abs/2501.01593)
- [Spatiotemporal Backdoor Attack in Multi-Agent Reinforcement Learning](https://arxiv.org/abs/2402.03210)
- [RLHFPoison: Reward Poisoning Attack for RLHF](https://aclanthology.org/2024.acl-long.140/)

{{#include ../banners/hacktricks-training.md}}
