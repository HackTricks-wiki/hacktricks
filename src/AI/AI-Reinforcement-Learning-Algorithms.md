# Algoritmi di Apprendimento per Rinforzo

{{#include ../banners/hacktricks-training.md}}

## Apprendimento per Rinforzo

L'apprendimento per rinforzo (RL) è un tipo di apprendimento automatico in cui un agente impara a prendere decisioni interagendo con un ambiente. L'agente riceve feedback sotto forma di ricompense o penalità in base alle sue azioni, permettendogli di apprendere comportamenti ottimali nel tempo. RL è particolarmente utile per problemi in cui la soluzione implica decisioni sequenziali, come la robotica, il gioco e i sistemi autonomi.

### Q-Learning

Il Q-Learning è un algoritmo di apprendimento per rinforzo senza modello che apprende il valore delle azioni in uno stato dato. Utilizza una Q-table per memorizzare l'utilità attesa di intraprendere una specifica azione in uno stato specifico. L'algoritmo aggiorna i valori Q in base alle ricompense ricevute e alle massime ricompense future attese.
1. **Inizializzazione**: Inizializza la Q-table con valori arbitrari (spesso zeri).
2. **Selezione dell'Azione**: Scegli un'azione utilizzando una strategia di esplorazione (ad es., ε-greedy, dove con probabilità ε viene scelta un'azione casuale e con probabilità 1-ε viene selezionata l'azione con il valore Q più alto).
- Nota che l'algoritmo potrebbe sempre scegliere la migliore azione conosciuta dato uno stato, ma questo non permetterebbe all'agente di esplorare nuove azioni che potrebbero fornire ricompense migliori. Ecco perché viene utilizzata la variabile ε-greedy per bilanciare esplorazione e sfruttamento.
3. **Interazione con l'Ambiente**: Esegui l'azione scelta nell'ambiente, osserva il prossimo stato e la ricompensa.
- Nota che, a seconda in questo caso della probabilità ε-greedy, il passo successivo potrebbe essere un'azione casuale (per esplorazione) o la migliore azione conosciuta (per sfruttamento).
4. **Aggiornamento del Valore Q**: Aggiorna il valore Q per la coppia stato-azione utilizzando l'equazione di Bellman:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
dove:
- `Q(s, a)` è il valore Q attuale per lo stato `s` e l'azione `a`.
- `α` è il tasso di apprendimento (0 < α ≤ 1), che determina quanto le nuove informazioni sovrascrivono le vecchie informazioni.
- `r` è la ricompensa ricevuta dopo aver intrapreso l'azione `a` nello stato `s`.
- `γ` è il fattore di sconto (0 ≤ γ < 1), che determina l'importanza delle ricompense future.
- `s'` è il prossimo stato dopo aver intrapreso l'azione `a`.
- `max(Q(s', a'))` è il valore Q massimo per il prossimo stato `s'` su tutte le possibili azioni `a'`.
5. **Iterazione**: Ripeti i passi 2-4 fino a quando i valori Q convergono o viene soddisfatta una condizione di arresto.

Nota che con ogni nuova azione selezionata la tabella viene aggiornata, permettendo all'agente di apprendere dalle proprie esperienze nel tempo per cercare di trovare la politica ottimale (la migliore azione da intraprendere in ogni stato). Tuttavia, la Q-table può diventare grande per ambienti con molti stati e azioni, rendendola impraticabile per problemi complessi. In tali casi, possono essere utilizzati metodi di approssimazione delle funzioni (ad es., reti neurali) per stimare i valori Q.

> [!TIP]
> Il valore ε-greedy viene solitamente aggiornato nel tempo per ridurre l'esplorazione man mano che l'agente apprende di più sull'ambiente. Ad esempio, può iniziare con un valore alto (ad es., ε = 1) e decrescere a un valore più basso (ad es., ε = 0.1) man mano che l'apprendimento progredisce.

> [!TIP]
> Il tasso di apprendimento `α` e il fattore di sconto `γ` sono iperparametri che devono essere sintonizzati in base al problema specifico e all'ambiente. Un tasso di apprendimento più alto consente all'agente di apprendere più velocemente ma può portare a instabilità, mentre un tasso di apprendimento più basso porta a un apprendimento più stabile ma a una convergenza più lenta. Il fattore di sconto determina quanto l'agente valuta le ricompense future (`γ` più vicino a 1) rispetto alle ricompense immediate.

### SARSA (Stato-Azione-Ricompensa-Stato-Azione)

SARSA è un altro algoritmo di apprendimento per rinforzo senza modello che è simile al Q-Learning ma differisce nel modo in cui aggiorna i valori Q. SARSA sta per Stato-Azione-Ricompensa-Stato-Azione, e aggiorna i valori Q in base all'azione intrapresa nel prossimo stato, piuttosto che al valore Q massimo.
1. **Inizializzazione**: Inizializza la Q-table con valori arbitrari (spesso zeri).
2. **Selezione dell'Azione**: Scegli un'azione utilizzando una strategia di esplorazione (ad es., ε-greedy).
3. **Interazione con l'Ambiente**: Esegui l'azione scelta nell'ambiente, osserva il prossimo stato e la ricompensa.
- Nota che, a seconda in questo caso della probabilità ε-greedy, il passo successivo potrebbe essere un'azione casuale (per esplorazione) o la migliore azione conosciuta (per sfruttamento).
4. **Aggiornamento del Valore Q**: Aggiorna il valore Q per la coppia stato-azione utilizzando la regola di aggiornamento SARSA. Nota che la regola di aggiornamento è simile al Q-Learning, ma utilizza l'azione che sarà intrapresa nel prossimo stato `s'` piuttosto che il valore Q massimo per quello stato:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
dove:
- `Q(s, a)` è il valore Q attuale per lo stato `s` e l'azione `a`.
- `α` è il tasso di apprendimento.
- `r` è la ricompensa ricevuta dopo aver intrapreso l'azione `a` nello stato `s`.
- `γ` è il fattore di sconto.
- `s'` è il prossimo stato dopo aver intrapreso l'azione `a`.
- `a'` è l'azione intrapresa nel prossimo stato `s'`.
5. **Iterazione**: Ripeti i passi 2-4 fino a quando i valori Q convergono o viene soddisfatta una condizione di arresto.

#### Softmax vs Selezione dell'Azione ε-Greedy

Oltre alla selezione dell'azione ε-greedy, SARSA può anche utilizzare una strategia di selezione dell'azione softmax. Nella selezione dell'azione softmax, la probabilità di selezionare un'azione è **proporzionale al suo valore Q**, consentendo un'esplorazione più sfumata dello spazio delle azioni. La probabilità di selezionare l'azione `a` nello stato `s` è data da:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
dove:
- `P(a|s)` è la probabilità di selezionare l'azione `a` nello stato `s`.
- `Q(s, a)` è il valore Q per lo stato `s` e l'azione `a`.
- `τ` (tau) è il parametro di temperatura che controlla il livello di esplorazione. Una temperatura più alta porta a maggiore esplorazione (probabilità più uniformi), mentre una temperatura più bassa porta a maggiore sfruttamento (probabilità più alte per azioni con valori Q più elevati).

> [!TIP]
> Questo aiuta a bilanciare esplorazione e sfruttamento in modo più continuo rispetto alla selezione delle azioni ε-greedy.

### Apprendimento On-Policy vs Off-Policy

SARSA è un algoritmo di apprendimento **on-policy**, il che significa che aggiorna i valori Q in base alle azioni intraprese dalla politica attuale (la politica ε-greedy o softmax). Al contrario, Q-Learning è un algoritmo di apprendimento **off-policy**, poiché aggiorna i valori Q in base al valore Q massimo per il prossimo stato, indipendentemente dall'azione intrapresa dalla politica attuale. Questa distinzione influisce su come gli algoritmi apprendono e si adattano all'ambiente.

I metodi on-policy come SARSA possono essere più stabili in determinati ambienti, poiché apprendono dalle azioni effettivamente intraprese. Tuttavia, potrebbero convergere più lentamente rispetto ai metodi off-policy come Q-Learning, che possono apprendere da una gamma più ampia di esperienze.

{{#include ../banners/hacktricks-training.md}}
