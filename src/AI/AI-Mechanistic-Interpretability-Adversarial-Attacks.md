# Attacchi adversariali guidati dall'interpretabilità meccanicistica

{{#include ../banners/hacktricks-training.md}}

## La superposizione come superficie di attacco

Uno spazio delle attivazioni sottoparametrizzato può codificare più caratteristiche semantiche di quante siano le sue dimensioni, assegnando le caratteristiche a vettori non ortogonali. Di conseguenza, una caratteristica attivata si proietta anche sulle direzioni di altre caratteristiche. L'addestramento può compensare le combinazioni osservate nella distribuzione, ma una combinazione insolita di caratteristiche altrimenti valide può sommarsi in modo costruttivo nella direzione di una caratteristica bersaglio assente dall'input.<sup>[[1]](#references)[[2]](#references)</sup>

Per i vettori di caratteristiche `v_i ∈ R^D`, le attivazioni `a_i` e il bersaglio `t`, la seguente magnitudine è utile per individuare combinazioni candidate:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Questa è solo un'euristica di screening. Un exploit deve mantenere segni e magnitudini e valutare il decoder reale, ad esempio `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` in un decoder lineare con pesi condivisi. I termini negativi possono annullare l'attacco, mentre il bias del decoder, le norme dei vettori delle feature, le soglie di attivazione e il gating ReLU possono impedire a un valore assoluto elevato del coseno di produrre l'attivazione target.<sup>[[1]](#references)</sup>

## White-box attack workflow

Una valutazione pratica può usare un collo di bottiglia del modello, un autoencoder sparso (SAE) o un altro dizionario di feature interpretabile. L'obiettivo non è semplicemente modificare la classe finale: è fare in modo che la ricostruzione introduca una feature interna scelta, che non era attiva prima della compressione. Il workflow proposto è:<sup>[[1]](#references)</sup>

1. **Recuperare le direzioni delle feature:** estrarre i vettori pertinenti dell'encoder/decoder, rimuovere le feature inattive e associare le direzioni attive a concetti usando campioni con attivazione massima o l'analisi dei circuiti delle feature.
2. **Classificare le interferenze:** normalizzare una copia dei vettori, calcolare la matrice delle similarità coseno, azzerare la diagonale e ispezionare i vicini fuori diagonale più forti del target. Ricalcolare i candidati usando le magnitudini effettive delle attivazioni e i prodotti scalari grezzi con segno.
3. **Garantire la co-attivazione:** mantenere un piccolo insieme di feature che contribuiscono positivamente e che possono essere attivate nello stesso layer o residual stream. Preferire combinazioni rare o assenti nei dati di training; è più probabile che le combinazioni correlate ordinarie siano state compensate durante il training.
4. **Sintetizzare l'input:** combinare esempi del dataset o pattern che massimizzano l'attivazione per i contributori selezionati. Per un rilevatore lineare di pixel con valori limitati, impostare un pixel su un valore alto per un peso positivo e su un valore basso per un peso negativo, quindi sovrapporre i pattern risultanti. Mantenere manualmente la struttura in-distribution e lo **spazio negativo** inibitorio può sopprimere le feature non correlate.
5. **Verificare il meccanismo:** registrare in un unico forward pass le attivazioni prima della compressione, le coordinate compresse, le attivazioni ricostruite e l'output downstream. Un test riuscito mostra che il target è inattivo prima della ricostruzione ma attivo dopo, e che la variazione prevista scompare quando i contributori vengono rimossi tramite ablation.

Il seguente triage minimale classifica i contributori per un decoder con pesi condivisi le cui **righe** sono vettori delle feature (trasporre prima se le feature sono disposte in colonne). Usare i pesi grezzi per il punteggio con segno e i pesi normalizzati solo per la classificazione basata sul coseno.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Non dedurre la sfruttabilità dalla sola similarità coseno. Testa il decoder completo, con bias e non linearità, verifica che i contributori possano effettivamente coesistere e confronta il risultato con combinazioni in-distribution comparabili. Direzioni simili possono codificare una legittima relazione semantica, anziché un’interferenza di packing sfruttabile.<sup>[[1]](#references)</sup>

## Attacco dimostrato su un toy model

La proof of concept utilizzava un classificatore MNIST deliberatamente interpretabile, con due rami. In un ramo, un vettore di feature ReLU sparso a 128 dimensioni veniva classificato direttamente; nell’altro, veniva compresso in uno spazio di sovrapposizione a due dimensioni. Lo stesso classificatore elaborava sia le feature originali sia quelle ricostruite.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Due direzioni di feature associate a forme simili a 3/0 erano geometricamente racchiuse da direzioni class-5. Sommare le immagini che le attivavano al massimo rendeva queste feature contributor le più forti prima della compressione, ma la ricostruzione attivava diverse feature class-5 e il ramo di superposition ne prevedeva 5. Un input disegnato a mano usando solo i valori pixel minimo e massimo riproduceva l’effetto, mostrando che, in questo toy setting, non erano necessarie perturbazioni dei pixel ottimizzate esattamente tramite gradienti.<sup>[[1]](#references)</sup>

## Triage geometrico di modelli più grandi

Il paper ha esaminato anche la SAE di Gemma Scope `layer 20 / width 65k / average L0 20`. Ha moltiplicato la matrice decoder normalizzata a norma unitaria per la sua trasposta, azzerato la diagonale, ordinato i vicini di ciascuna feature e calcolato la media per rango. La similarità coseno media dei vicini più forti era `0.49`, mentre quella del 27º vicino era `0.25`; geometricamente, quattro direzioni di questo tipo potevano eguagliare la proiezione target di un’unità. Questi valori identificano solo candidati: non dimostrano che quattro feature adatte possano essere attivate congiuntamente né che il target superi la soglia del decoder.<sup>[[1]](#references)</sup>

## Ambito e limitazioni

Questa è una tecnica **white-box** in fase di ricerca, non un attacco dimostrato contro una CNN distribuita o un LLM frontier. Richiede superposition, direzioni non ortogonali utili, accesso interpretabile alle feature interne, attivazione controllabile delle feature contributor e la loro presenza nello stesso layer durante un singolo forward pass.<sup>[[1]](#references)</sup>

Le MLP per immagini rendono la composizione delle feature insolitamente diretta. Un transformer è più difficile da manipolare, perché l’attenzione deve raccogliere le attivazioni delle feature scelte nello stesso residual stream; il paper non mostra come forzare questo risultato per una combinazione fuori distribuzione. Le affermazioni sulla manipolazione di direzioni comportamentali o di rifiuto, di sistemi di visione fisici o di modelli frontier restano quindi ipotesi.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — A Preliminary Investigation Into Interpretable Adversarial Attacks Through Feature Interference in Superposition (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretable Adversarial Attacks in Superposition](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
