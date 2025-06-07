# Algoritmi di Apprendimento Non Supervisionato

{{#include ../banners/hacktricks-training.md}}

## Apprendimento Non Supervisionato

L'apprendimento non supervisionato è un tipo di machine learning in cui il modello viene addestrato su dati senza risposte etichettate. L'obiettivo è trovare modelli, strutture o relazioni all'interno dei dati. A differenza dell'apprendimento supervisionato, in cui il modello impara da esempi etichettati, gli algoritmi di apprendimento non supervisionato lavorano con dati non etichettati. L'apprendimento non supervisionato è spesso utilizzato per compiti come clustering, riduzione della dimensionalità e rilevamento delle anomalie. Può aiutare a scoprire modelli nascosti nei dati, raggruppare elementi simili o ridurre la complessità dei dati mantenendo le sue caratteristiche essenziali.

### Clustering K-Means

K-Means è un algoritmo di clustering basato sui centroidi che partiziona i dati in K cluster assegnando ogni punto al centroide del cluster più vicino. L'algoritmo funziona come segue:
1. **Inizializzazione**: Scegliere K centri di cluster iniziali (centroidi), spesso casualmente o tramite metodi più intelligenti come k-means++
2. **Assegnazione**: Assegnare ogni punto dati al centroide più vicino in base a una metrica di distanza (ad es., distanza euclidea).
3. **Aggiornamento**: Ricalcolare i centroidi prendendo la media di tutti i punti dati assegnati a ciascun cluster.
4. **Ripetere**: I passaggi 2–3 vengono ripetuti fino a quando le assegnazioni dei cluster si stabilizzano (i centroidi non si muovono più significativamente).

> [!TIP]
> *Casi d'uso nella cybersecurity:* K-Means è utilizzato per il rilevamento delle intrusioni raggruppando eventi di rete. Ad esempio, i ricercatori hanno applicato K-Means al dataset di intrusioni KDD Cup 99 e hanno scoperto che partizionava efficacemente il traffico in cluster normali vs. attacco. In pratica, gli analisti della sicurezza potrebbero raggruppare le voci di log o i dati sul comportamento degli utenti per trovare gruppi di attività simili; eventuali punti che non appartengono a un cluster ben formato potrebbero indicare anomalie (ad es. una nuova variante di malware che forma il proprio piccolo cluster). K-Means può anche aiutare nella classificazione delle famiglie di malware raggruppando i binari in base ai profili comportamentali o ai vettori di caratteristiche.

#### Selezione di K
Il numero di cluster (K) è un iperparametro che deve essere definito prima di eseguire l'algoritmo. Tecniche come il Metodo del Gomito o il Silhouette Score possono aiutare a determinare un valore appropriato per K valutando le prestazioni del clustering:

- **Metodo del Gomito**: Tracciare la somma delle distanze quadrate da ciascun punto al centroide del cluster assegnato in funzione di K. Cercare un punto "gomito" in cui il tasso di diminuzione cambia bruscamente, indicando un numero adeguato di cluster.
- **Silhouette Score**: Calcolare il punteggio di silhouette per diversi valori di K. Un punteggio di silhouette più alto indica cluster meglio definiti.

#### Assunzioni e Limitazioni

K-Means assume che **i cluster siano sferici e di dimensioni uguali**, il che potrebbe non essere vero per tutti i dataset. È sensibile alla posizione iniziale dei centroidi e può convergere a minimi locali. Inoltre, K-Means non è adatto per dataset con densità variabili o forme non globulari e caratteristiche con scale diverse. Passaggi di preprocessing come normalizzazione o standardizzazione potrebbero essere necessari per garantire che tutte le caratteristiche contribuiscano in modo equo ai calcoli delle distanze.

<details>
<summary>Esempio -- Clustering degli Eventi di Rete
</summary>
Di seguito simuliamo dati di traffico di rete e utilizziamo K-Means per raggrupparli. Supponiamo di avere eventi con caratteristiche come la durata della connessione e il conteggio dei byte. Creiamo 3 cluster di traffico "normale" e 1 piccolo cluster che rappresenta un modello di attacco. Poi eseguiamo K-Means per vedere se li separa.
```python
import numpy as np
from sklearn.cluster import KMeans

# Simulate synthetic network traffic data (e.g., [duration, bytes]).
# Three normal clusters and one small attack cluster.
rng = np.random.RandomState(42)
normal1 = rng.normal(loc=[50, 500], scale=[10, 100], size=(500, 2))   # Cluster 1
normal2 = rng.normal(loc=[60, 1500], scale=[8, 200], size=(500, 2))   # Cluster 2
normal3 = rng.normal(loc=[70, 3000], scale=[5, 300], size=(500, 2))   # Cluster 3
attack = rng.normal(loc=[200, 800], scale=[5, 50], size=(50, 2))      # Small attack cluster

X = np.vstack([normal1, normal2, normal3, attack])
# Run K-Means clustering into 4 clusters (we expect it to find the 4 groups)
kmeans = KMeans(n_clusters=4, random_state=0, n_init=10)
labels = kmeans.fit_predict(X)

# Analyze resulting clusters
clusters, counts = np.unique(labels, return_counts=True)
print(f"Cluster labels: {clusters}")
print(f"Cluster sizes: {counts}")
print("Cluster centers (duration, bytes):")
for idx, center in enumerate(kmeans.cluster_centers_):
print(f"  Cluster {idx}: {center}")
```
In questo esempio, K-Means dovrebbe trovare 4 cluster. Il piccolo cluster di attacco (con una durata insolitamente alta ~200) formerà idealmente il proprio cluster data la sua distanza dai cluster normali. Stampiamo le dimensioni e i centri dei cluster per interpretare i risultati. In uno scenario reale, si potrebbe etichettare il cluster con pochi punti come potenziali anomalie o ispezionare i suoi membri per attività malevole.

### Clustering Gerarchico

Il clustering gerarchico costruisce una gerarchia di cluster utilizzando un approccio dal basso verso l'alto (agglomerativo) o un approccio dall'alto verso il basso (divisivo):

1. **Agglomerativo (Dal Basso Verso l'Alto)**: Inizia con ogni punto dati come un cluster separato e unisce iterativamente i cluster più vicini fino a quando rimane un singolo cluster o viene soddisfatta una condizione di arresto.
2. **Divisivo (Dall'Alto Verso il Basso)**: Inizia con tutti i punti dati in un singolo cluster e divide iterativamente i cluster fino a quando ogni punto dati è il proprio cluster o viene soddisfatta una condizione di arresto.

Il clustering agglomerativo richiede una definizione della distanza inter-cluster e un criterio di collegamento per decidere quali cluster unire. I metodi di collegamento comuni includono il collegamento singolo (distanza dei punti più vicini tra due cluster), il collegamento completo (distanza dei punti più lontani), il collegamento medio, ecc., e la metrica di distanza è spesso euclidea. La scelta del collegamento influisce sulla forma dei cluster prodotti. Non è necessario specificare in anticipo il numero di cluster K; puoi "tagliare" il dendrogramma a un livello scelto per ottenere il numero desiderato di cluster.

Il clustering gerarchico produce un dendrogramma, una struttura ad albero che mostra le relazioni tra i cluster a diversi livelli di granularità. Il dendrogramma può essere tagliato a un livello desiderato per ottenere un numero specifico di cluster.

> [!TIP]
> *Casi d'uso nella cybersecurity:* Il clustering gerarchico può organizzare eventi o entità in un albero per individuare relazioni. Ad esempio, nell'analisi del malware, il clustering agglomerativo potrebbe raggruppare i campioni per somiglianza comportamentale, rivelando una gerarchia di famiglie e varianti di malware. Nella sicurezza di rete, si potrebbe raggruppare i flussi di traffico IP e utilizzare il dendrogramma per vedere i sottogruppi di traffico (ad esempio, per protocollo, poi per comportamento). Poiché non è necessario scegliere K in anticipo, è utile quando si esplorano nuovi dati per i quali il numero di categorie di attacco è sconosciuto.

#### Assunzioni e Limitazioni

Il clustering gerarchico non assume una forma particolare del cluster e può catturare cluster annidati. È utile per scoprire tassonomie o relazioni tra gruppi (ad esempio, raggruppare il malware per sottogruppi familiari). È deterministico (nessun problema di inizializzazione casuale). Un vantaggio chiave è il dendrogramma, che fornisce informazioni sulla struttura di clustering dei dati a tutte le scale – gli analisti della sicurezza possono decidere un taglio appropriato per identificare cluster significativi. Tuttavia, è computazionalmente costoso (tipicamente $O(n^2)$ tempo o peggio per implementazioni naive) e non fattibile per dataset molto grandi. È anche una procedura avido – una volta che una fusione o una divisione è stata effettuata, non può essere annullata, il che può portare a cluster subottimali se si verifica un errore all'inizio. Gli outlier possono anche influenzare alcune strategie di collegamento (il collegamento singolo può causare l'effetto "chaining" in cui i cluster si collegano tramite outlier).

<details>
<summary>Esempio -- Clustering Agglomerativo di Eventi
</summary>

Riutilizzeremo i dati sintetici dall'esempio K-Means (3 cluster normali + 1 cluster di attacco) e applicheremo il clustering agglomerativo. Illustriamo quindi come ottenere un dendrogramma e etichette di cluster.
```python
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import linkage, dendrogram

# Perform agglomerative clustering (bottom-up) on the data
agg = AgglomerativeClustering(n_clusters=None, distance_threshold=0, linkage='ward')
# distance_threshold=0 gives the full tree without cutting (we can cut manually)
agg.fit(X)

print(f"Number of merge steps: {agg.n_clusters_ - 1}")  # should equal number of points - 1
# Create a dendrogram using SciPy for visualization (optional)
Z = linkage(X, method='ward')
# Normally, you would plot the dendrogram. Here we'll just compute cluster labels for a chosen cut:
clusters_3 = AgglomerativeClustering(n_clusters=3, linkage='ward').fit_predict(X)
print(f"Labels with 3 clusters: {np.unique(clusters_3)}")
print(f"Cluster sizes for 3 clusters: {np.bincount(clusters_3)}")
```
</details>

### DBSCAN (Clustering Spaziale Basato sulla Densità delle Applicazioni con Rumore)

DBSCAN è un algoritmo di clustering basato sulla densità che raggruppa insieme punti che sono strettamente vicini, mentre contrassegna i punti nelle regioni a bassa densità come outlier. È particolarmente utile per dataset con densità variabili e forme non sferiche.

DBSCAN funziona definendo due parametri:
- **Epsilon (ε)**: La distanza massima tra due punti per essere considerati parte dello stesso cluster.
- **MinPts**: Il numero minimo di punti richiesti per formare una regione densa (punto centrale).

DBSCAN identifica punti centrali, punti di confine e punti di rumore:
- **Punto Centrale**: Un punto con almeno MinPts vicini entro una distanza ε.
- **Punto di Confine**: Un punto che si trova entro una distanza ε da un punto centrale ma ha meno di MinPts vicini.
- **Punto di Rumore**: Un punto che non è né un punto centrale né un punto di confine.

Il clustering procede scegliendo un punto centrale non visitato, contrassegnandolo come un nuovo cluster, quindi aggiungendo ricorsivamente tutti i punti raggiungibili per densità da esso (punti centrali e i loro vicini, ecc.). I punti di confine vengono aggiunti al cluster di un punto centrale vicino. Dopo aver espanso tutti i punti raggiungibili, DBSCAN passa a un altro punto centrale non visitato per avviare un nuovo cluster. I punti non raggiunti da alcun punto centrale rimangono etichettati come rumore.

> [!TIP]
> *Casi d'uso nella cybersecurity:* DBSCAN è utile per la rilevazione di anomalie nel traffico di rete. Ad esempio, l'attività normale degli utenti potrebbe formare uno o più cluster densi nello spazio delle caratteristiche, mentre i comportamenti di attacco nuovi appaiono come punti sparsi che DBSCAN etichetterà come rumore (outlier). È stato utilizzato per raggruppare registri di flusso di rete, dove può rilevare scansioni di porte o traffico di denial-of-service come regioni sparse di punti. Un'altra applicazione è il raggruppamento di varianti di malware: se la maggior parte dei campioni si raggruppa per famiglie ma alcuni non si adattano da nessuna parte, quei pochi potrebbero essere malware zero-day. La capacità di segnalare il rumore significa che i team di sicurezza possono concentrarsi sull'indagine di quegli outlier.

#### Assunzioni e Limitazioni

**Assunzioni e Punti di Forza:**: DBSCAN non assume cluster sferici – può trovare cluster di forma arbitraria (anche cluster a catena o adiacenti). Determina automaticamente il numero di cluster in base alla densità dei dati e può identificare efficacemente gli outlier come rumore. Questo lo rende potente per dati del mondo reale con forme irregolari e rumore. È robusto agli outlier (a differenza di K-Means, che li costringe nei cluster). Funziona bene quando i cluster hanno densità approssimativamente uniforme.

**Limitazioni**: Le prestazioni di DBSCAN dipendono dalla scelta di valori appropriati per ε e MinPts. Potrebbe avere difficoltà con dati che presentano densità variabili – un singolo ε non può adattarsi sia a cluster densi che sparsi. Se ε è troppo piccolo, etichetta la maggior parte dei punti come rumore; se è troppo grande, i cluster potrebbero fondersi in modo errato. Inoltre, DBSCAN può essere inefficiente su dataset molto grandi (naivamente $O(n^2)$, anche se l'indicizzazione spaziale può aiutare). Negli spazi delle caratteristiche ad alta dimensione, il concetto di "distanza entro ε" potrebbe diventare meno significativo (la maledizione della dimensionalità), e DBSCAN potrebbe necessitare di una sintonizzazione attenta dei parametri o potrebbe non riuscire a trovare cluster intuitivi. Nonostante ciò, estensioni come HDBSCAN affrontano alcuni problemi (come la densità variabile).

<details>
<summary>Esempio -- Clustering con Rumore
</summary>
```python
from sklearn.cluster import DBSCAN

# Generate synthetic data: 2 normal clusters and 5 outlier points
cluster1 = rng.normal(loc=[100, 1000], scale=[5, 100], size=(100, 2))
cluster2 = rng.normal(loc=[120, 2000], scale=[5, 100], size=(100, 2))
outliers = rng.uniform(low=[50, 50], high=[180, 3000], size=(5, 2))  # scattered anomalies
data = np.vstack([cluster1, cluster2, outliers])

# Run DBSCAN with chosen eps and MinPts
eps = 15.0   # radius for neighborhood
min_pts = 5  # minimum neighbors to form a dense region
db = DBSCAN(eps=eps, min_samples=min_pts).fit(data)
labels = db.labels_  # cluster labels (-1 for noise)

# Analyze clusters and noise
num_clusters = len(set(labels) - {-1})
num_noise = np.sum(labels == -1)
print(f"DBSCAN found {num_clusters} clusters and {num_noise} noise points")
print("Cluster labels for first 10 points:", labels[:10])
```
In questo frammento, abbiamo sintonizzato `eps` e `min_samples` per adattarli alla scala dei nostri dati (15.0 in unità di caratteristica e richiedendo 5 punti per formare un cluster). DBSCAN dovrebbe trovare 2 cluster (i cluster di traffico normale) e contrassegnare i 5 outlier iniettati come rumore. Produciamo il numero di cluster rispetto ai punti di rumore per verificare questo. In un contesto reale, si potrebbe iterare su ε (utilizzando un'euristica del grafo della distanza k per scegliere ε) e MinPts (spesso impostato intorno alla dimensionalità dei dati + 1 come regola empirica) per trovare risultati di clustering stabili. La capacità di etichettare esplicitamente il rumore aiuta a separare i dati potenziali di attacco per ulteriori analisi.

</details>

### Analisi delle Componenti Principali (PCA)

La PCA è una tecnica per la **riduzione della dimensionalità** che trova un nuovo insieme di assi ortogonali (componenti principali) che catturano la massima varianza nei dati. In termini semplici, la PCA ruota e proietta i dati su un nuovo sistema di coordinate in modo che la prima componente principale (PC1) spieghi la massima varianza possibile, la seconda PC (PC2) spieghi la massima varianza ortogonale a PC1, e così via. Matematicamente, la PCA calcola gli autovettori della matrice di covarianza dei dati – questi autovettori sono le direzioni delle componenti principali, e i corrispondenti autovalori indicano la quantità di varianza spiegata da ciascuno. È spesso utilizzata per l'estrazione delle caratteristiche, la visualizzazione e la riduzione del rumore.

Nota che questo è utile se le dimensioni del dataset contengono **dipendenze o correlazioni lineari significative**.

La PCA funziona identificando le componenti principali dei dati, che sono le direzioni di massima varianza. I passaggi coinvolti nella PCA sono:
1. **Standardizzazione**: Centrare i dati sottraendo la media e scalando a varianza unitaria.
2. **Matrice di Covarianza**: Calcolare la matrice di covarianza dei dati standardizzati per comprendere le relazioni tra le caratteristiche.
3. **Decomposizione degli Autovalori**: Eseguire la decomposizione degli autovalori sulla matrice di covarianza per ottenere gli autovalori e gli autovettori.
4. **Selezionare le Componenti Principali**: Ordinare gli autovalori in ordine decrescente e selezionare i primi K autovettori corrispondenti ai più grandi autovalori. Questi autovettori formano il nuovo spazio delle caratteristiche.
5. **Trasformare i Dati**: Proiettare i dati originali sul nuovo spazio delle caratteristiche utilizzando le componenti principali selezionate.
La PCA è ampiamente utilizzata per la visualizzazione dei dati, la riduzione del rumore e come passo di preprocessing per altri algoritmi di machine learning. Aiuta a ridurre la dimensionalità dei dati mantenendo la sua struttura essenziale.

#### Autovalori e Autovettori

Un autovalore è uno scalare che indica la quantità di varianza catturata dal suo corrispondente autovettore. Un autovettore rappresenta una direzione nello spazio delle caratteristiche lungo la quale i dati variano di più.

Immagina che A sia una matrice quadrata e v sia un vettore non nullo tale che: `A * v = λ * v`
dove:
- A è una matrice quadrata come [ [1, 2], [2, 1]] (ad esempio, matrice di covarianza)
- v è un autovettore (ad esempio, [1, 1])

Allora, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` che sarà l'autovalore λ moltiplicato per l'autovettore v, rendendo l'autovalore λ = 3.

#### Autovalori e Autovettori nella PCA

Spieghiamo questo con un esempio. Immagina di avere un dataset con molte immagini in scala di grigi di volti di 100x100 pixel. Ogni pixel può essere considerato una caratteristica, quindi hai 10.000 caratteristiche per immagine (o un vettore di 10000 componenti per immagine). Se vuoi ridurre la dimensionalità di questo dataset utilizzando la PCA, seguiresti questi passaggi:

1. **Standardizzazione**: Centrare i dati sottraendo la media di ciascuna caratteristica (pixel) dal dataset.
2. **Matrice di Covarianza**: Calcolare la matrice di covarianza dei dati standardizzati, che cattura come le caratteristiche (pixel) variano insieme.
- Nota che la covarianza tra due variabili (pixel in questo caso) indica quanto cambiano insieme, quindi l'idea qui è scoprire quali pixel tendono ad aumentare o diminuire insieme con una relazione lineare.
- Ad esempio, se il pixel 1 e il pixel 2 tendono ad aumentare insieme, la covarianza tra di loro sarà positiva.
- La matrice di covarianza sarà una matrice 10.000x10.000 dove ogni voce rappresenta la covarianza tra due pixel.
3. **Risolvi l'equazione degli autovalori**: L'equazione degli autovalori da risolvere è `C * v = λ * v` dove C è la matrice di covarianza, v è l'autovettore e λ è l'autovalore. Può essere risolta utilizzando metodi come:
- **Decomposizione degli Autovalori**: Eseguire la decomposizione degli autovalori sulla matrice di covarianza per ottenere gli autovalori e gli autovettori.
- **Decomposizione ai Valori Singolari (SVD)**: In alternativa, puoi utilizzare SVD per decomporre la matrice dei dati in valori e vettori singolari, che possono anche fornire le componenti principali.
4. **Selezionare le Componenti Principali**: Ordinare gli autovalori in ordine decrescente e selezionare i primi K autovettori corrispondenti ai più grandi autovalori. Questi autovettori rappresentano le direzioni di massima varianza nei dati.

> [!TIP]
> *Casi d'uso nella cybersecurity:* Un uso comune della PCA nella sicurezza è la riduzione delle caratteristiche per il rilevamento delle anomalie. Ad esempio, un sistema di rilevamento delle intrusioni con oltre 40 metriche di rete (come le caratteristiche NSL-KDD) può utilizzare la PCA per ridurre a un numero ridotto di componenti, riassumendo i dati per la visualizzazione o per l'alimentazione in algoritmi di clustering. Gli analisti potrebbero tracciare il traffico di rete nello spazio delle prime due componenti principali per vedere se gli attacchi si separano dal traffico normale. La PCA può anche aiutare a eliminare caratteristiche ridondanti (come byte inviati vs. byte ricevuti se sono correlati) per rendere gli algoritmi di rilevamento più robusti e veloci.

#### Assunzioni e Limitazioni

La PCA assume che **gli assi principali di varianza siano significativi** – è un metodo lineare, quindi cattura correlazioni lineari nei dati. È non supervisionato poiché utilizza solo la covarianza delle caratteristiche. I vantaggi della PCA includono la riduzione del rumore (componenti a bassa varianza spesso corrispondono a rumore) e la decorrelazione delle caratteristiche. È computazionalmente efficiente per dimensioni moderatamente elevate ed è spesso un utile passo di preprocessing per altri algoritmi (per mitigare la maledizione della dimensionalità). Una limitazione è che la PCA è limitata a relazioni lineari – non catturerà strutture complesse non lineari (mentre autoencoder o t-SNE potrebbero). Inoltre, le componenti PCA possono essere difficili da interpretare in termini di caratteristiche originali (sono combinazioni di caratteristiche originali). Nella cybersecurity, bisogna essere cauti: un attacco che causa solo un cambiamento sottile in una caratteristica a bassa varianza potrebbe non apparire nelle prime PC (poiché la PCA dà priorità alla varianza, non necessariamente all'"interessantezza").

<details>
<summary>Esempio -- Riduzione delle Dimensioni dei Dati di Rete
</summary>

Supponiamo di avere log di connessione di rete con più caratteristiche (ad esempio, durate, byte, conteggi). Genereremo un dataset sintetico a 4 dimensioni (con alcune correlazioni tra le caratteristiche) e utilizzeremo la PCA per ridurlo a 2 dimensioni per la visualizzazione o ulteriori analisi.
```python
from sklearn.decomposition import PCA

# Create synthetic 4D data (3 clusters similar to before, but add correlated features)
# Base features: duration, bytes (as before)
base_data = np.vstack([normal1, normal2, normal3])  # 1500 points from earlier normal clusters
# Add two more features correlated with existing ones, e.g. packets = bytes/50 + noise, errors = duration/10 + noise
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))
data_4d = np.column_stack([base_data[:, 0], base_data[:, 1], packets, errors])

# Apply PCA to reduce 4D data to 2D
pca = PCA(n_components=2)
data_2d = pca.fit_transform(data_4d)
print("Explained variance ratio of 2 components:", pca.explained_variance_ratio_)
print("Original shape:", data_4d.shape, "Reduced shape:", data_2d.shape)
# We can examine a few transformed points
print("First 5 data points in PCA space:\n", data_2d[:5])
```
Qui abbiamo preso i precedenti cluster di traffico normale e abbiamo esteso ogni punto dati con due caratteristiche aggiuntive (pacchetti ed errori) che correlano con byte e durata. PCA viene quindi utilizzato per comprimere le 4 caratteristiche in 2 componenti principali. Stampiamo il rapporto di varianza spiegata, che potrebbe mostrare che, ad esempio, >95% della varianza è catturata da 2 componenti (significa poca perdita di informazioni). L'output mostra anche la forma dei dati che si riduce da (1500, 4) a (1500, 2). I primi punti nello spazio PCA sono forniti come esempio. In pratica, si potrebbe tracciare data_2d per controllare visivamente se i cluster sono distinguibili. Se fosse presente un'anomalia, si potrebbe vederla come un punto lontano dal cluster principale nello spazio PCA. PCA aiuta quindi a distillare dati complessi in una forma gestibile per l'interpretazione umana o come input per altri algoritmi.

</details>


### Modelli di Miscele Gaussiane (GMM)

Un Modello di Miscele Gaussiane assume che i dati siano generati da una miscela di **diverse distribuzioni gaussiane (normali) con parametri sconosciuti**. In sostanza, è un modello di clustering probabilistico: cerca di assegnare dolcemente ogni punto a uno dei K componenti gaussiani. Ogni componente gaussiano k ha un vettore medio (μ_k), una matrice di covarianza (Σ_k) e un peso di miscelazione (π_k) che rappresenta quanto è prevalente quel cluster. A differenza di K-Means che fa assegnazioni "dure", GMM dà a ogni punto una probabilità di appartenere a ciascun cluster.

L'adattamento di GMM viene tipicamente effettuato tramite l'algoritmo di Massimizzazione delle Aspettative (EM):

- **Inizializzazione**: Iniziare con stime iniziali per le medie, le covarianze e i coefficienti di miscelazione (o utilizzare i risultati di K-Means come punto di partenza).

- **E-step (Aspettativa)**: Dati i parametri attuali, calcolare la responsabilità di ciascun cluster per ciascun punto: essenzialmente `r_nk = P(z_k | x_n)` dove z_k è la variabile latente che indica l'appartenenza al cluster per il punto x_n. Questo viene fatto usando il teorema di Bayes, dove calcoliamo la probabilità posteriore di ciascun punto appartenente a ciascun cluster in base ai parametri attuali. Le responsabilità sono calcolate come:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
dove:
- \( \pi_k \) è il coefficiente di miscelazione per il cluster k (probabilità a priori del cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) è la funzione di densità di probabilità gaussiana per il punto \( x_n \) dato la media \( \mu_k \) e la covarianza \( \Sigma_k \).

- **M-step (Massimizzazione)**: Aggiornare i parametri utilizzando le responsabilità calcolate nell'E-step:
- Aggiornare ogni media μ_k come la media ponderata dei punti, dove i pesi sono le responsabilità.
- Aggiornare ogni covarianza Σ_k come la covarianza ponderata dei punti assegnati al cluster k.
- Aggiornare i coefficienti di miscelazione π_k come la responsabilità media per il cluster k.

- **Iterare** i passi E e M fino alla convergenza (i parametri si stabilizzano o il miglioramento della verosimiglianza è al di sotto di una soglia).

Il risultato è un insieme di distribuzioni gaussiane che modellano collettivamente la distribuzione complessiva dei dati. Possiamo utilizzare il GMM adattato per raggruppare assegnando a ciascun punto la gaussiana con la massima probabilità, o mantenere le probabilità per l'incertezza. Si può anche valutare la verosimiglianza di nuovi punti per vedere se si adattano al modello (utile per la rilevazione di anomalie).

> [!TIP]
> *Casi d'uso nella cybersecurity:* GMM può essere utilizzato per la rilevazione di anomalie modellando la distribuzione dei dati normali: qualsiasi punto con probabilità molto bassa sotto la miscela appresa è contrassegnato come anomalia. Ad esempio, si potrebbe addestrare un GMM su caratteristiche di traffico di rete legittimo; una connessione di attacco che non somiglia a nessun cluster appreso avrebbe una bassa probabilità. I GMM vengono anche utilizzati per raggruppare attività in cui i cluster potrebbero avere forme diverse – ad esempio, raggruppare gli utenti per profili comportamentali, dove le caratteristiche di ciascun profilo potrebbero essere simili a gaussiane ma con la propria struttura di varianza. Un altro scenario: nella rilevazione di phishing, le caratteristiche delle email legittime potrebbero formare un cluster gaussiano, il phishing noto un altro, e le nuove campagne di phishing potrebbero apparire come una gaussiana separata o come punti a bassa probabilità rispetto alla miscela esistente.

#### Assunzioni e Limitazioni

GMM è una generalizzazione di K-Means che incorpora la covarianza, quindi i cluster possono essere ellissoidali (non solo sferici). Gestisce cluster di dimensioni e forme diverse se la covarianza è completa. Il clustering morbido è un vantaggio quando i confini dei cluster sono sfocati – ad esempio, nella cybersecurity, un evento potrebbe avere tratti di più tipi di attacco; GMM può riflettere quell'incertezza con probabilità. GMM fornisce anche una stima di densità probabilistica dei dati, utile per rilevare outlier (punti con bassa probabilità sotto tutti i componenti della miscela).

D'altra parte, GMM richiede di specificare il numero di componenti K (anche se si possono utilizzare criteri come BIC/AIC per selezionarlo). EM può a volte convergere lentamente o a un ottimo locale, quindi l'inizializzazione è importante (spesso si esegue EM più volte). Se i dati non seguono effettivamente una miscela di gaussiane, il modello potrebbe non adattarsi bene. C'è anche il rischio che una gaussiana si restringa per coprire solo un outlier (anche se la regolarizzazione o i limiti minimi di covarianza possono mitigare ciò).


<details>
<summary>Esempio --  Clustering Morbido & Punteggi di Anomalia
</summary>
```python
from sklearn.mixture import GaussianMixture

# Fit a GMM with 3 components to the normal traffic data
gmm = GaussianMixture(n_components=3, covariance_type='full', random_state=0)
gmm.fit(base_data)  # using the 1500 normal data points from PCA example

# Print the learned Gaussian parameters
print("GMM means:\n", gmm.means_)
print("GMM covariance matrices:\n", gmm.covariances_)

# Take a sample attack-like point and evaluate it
sample_attack = np.array([[200, 800]])  # an outlier similar to earlier attack cluster
probs = gmm.predict_proba(sample_attack)
log_likelihood = gmm.score_samples(sample_attack)
print("Cluster membership probabilities for sample attack:", probs)
print("Log-likelihood of sample attack under GMM:", log_likelihood)
```
In questo codice, alleniamo un GMM con 3 Gaussiane sul traffico normale (supponendo di conoscere 3 profili di traffico legittimo). Le medie e le covarianze stampate descrivono questi cluster (ad esempio, una media potrebbe essere intorno a [50,500] corrispondente al centro di un cluster, ecc.). Testiamo quindi una connessione sospetta [duration=200, bytes=800]. La predict_proba fornisce la probabilità che questo punto appartenga a ciascuno dei 3 cluster – ci aspetteremmo che queste probabilità siano molto basse o altamente sbilanciate poiché [200,800] si trova lontano dai cluster normali. Il punteggio overall score_samples (log-verosimiglianza) è stampato; un valore molto basso indica che il punto non si adatta bene al modello, segnalandolo come un'anomalia. In pratica, si potrebbe impostare una soglia sulla log-verosimiglianza (o sulla massima probabilità) per decidere se un punto è sufficientemente improbabile da essere considerato malevolo. GMM fornisce quindi un modo fondato per fare rilevamento delle anomalie e produce anche cluster morbidi che riconoscono l'incertezza.

### Isolation Forest

**Isolation Forest** è un algoritmo di rilevamento delle anomalie basato sull'idea di isolare casualmente i punti. Il principio è che le anomalie sono poche e diverse, quindi sono più facili da isolare rispetto ai punti normali. Un Isolation Forest costruisce molti alberi di isolamento binari (alberi decisionali casuali) che partizionano i dati in modo casuale. In ogni nodo di un albero, viene selezionata una caratteristica casuale e viene scelto un valore di divisione casuale tra il min e il max di quella caratteristica per i dati in quel nodo. Questa divisione divide i dati in due rami. L'albero cresce fino a quando ogni punto è isolato nella propria foglia o viene raggiunta un'altezza massima dell'albero.

Il rilevamento delle anomalie viene eseguito osservando la lunghezza del percorso di ciascun punto in questi alberi casuali – il numero di divisioni necessarie per isolare il punto. Intuitivamente, le anomalie (outlier) tendono a essere isolate più rapidamente perché una divisione casuale è più probabile che separi un outlier (che si trova in una regione sparsa) piuttosto che un punto normale in un cluster denso. L'Isolation Forest calcola un punteggio di anomalia dalla lunghezza media del percorso su tutti gli alberi: percorso medio più corto → più anomalo. I punteggi sono solitamente normalizzati a [0,1] dove 1 significa anomalia molto probabile.

> [!TIP]
> *Casi d'uso nella cybersecurity:* Gli Isolation Forest sono stati utilizzati con successo nel rilevamento delle intrusioni e nel rilevamento delle frodi. Ad esempio, allena un Isolation Forest sui log del traffico di rete che contengono principalmente comportamenti normali; la foresta produrrà percorsi brevi per traffico strano (come un IP che utilizza una porta mai sentita o un modello di dimensione del pacchetto insolito), segnalandolo per l'ispezione. Poiché non richiede attacchi etichettati, è adatto per rilevare tipi di attacco sconosciuti. Può anche essere implementato sui dati di accesso degli utenti per rilevare takeover degli account (i tempi o le posizioni di accesso anomali vengono isolati rapidamente). In un caso d'uso, un Isolation Forest potrebbe proteggere un'impresa monitorando le metriche di sistema e generando un avviso quando una combinazione di metriche (CPU, rete, modifiche ai file) appare molto diversa (percorsi di isolamento brevi) dai modelli storici.

#### Assunzioni e Limitazioni

**Vantaggi**: L'Isolation Forest non richiede un'assunzione di distribuzione; mira direttamente all'isolamento. È efficiente su dati ad alta dimensione e set di dati di grandi dimensioni (complessità lineare $O(n\log n)$ per costruire la foresta) poiché ogni albero isola i punti utilizzando solo un sottoinsieme di caratteristiche e divisioni. Tende a gestire bene le caratteristiche numeriche e può essere più veloce dei metodi basati sulla distanza che potrebbero essere $O(n^2)$. Fornisce anche automaticamente un punteggio di anomalia, quindi puoi impostare una soglia per gli avvisi (o utilizzare un parametro di contaminazione per decidere automaticamente un cutoff basato su una frazione di anomalia attesa).

**Limitazioni**: A causa della sua natura casuale, i risultati possono variare leggermente tra le esecuzioni (anche se con un numero sufficiente di alberi questo è minore). Se i dati hanno molte caratteristiche irrilevanti o se le anomalie non si differenziano fortemente in alcuna caratteristica, l'isolamento potrebbe non essere efficace (le divisioni casuali potrebbero isolare punti normali per caso – tuttavia, la media di molti alberi mitiga questo). Inoltre, l'Isolation Forest generalmente assume che le anomalie siano una piccola minoranza (cosa che è solitamente vera negli scenari di cybersecurity).

<details>
<summary>Esempio -- Rilevamento di Outlier nei Log di Rete
</summary>

Utilizzeremo il precedente set di dati di test (che contiene punti normali e alcuni punti di attacco) e eseguiremo un Isolation Forest per vedere se può separare gli attacchi. Assumeremo di aspettarci che ~15% dei dati sia anomalo (per dimostrazione).
```python
from sklearn.ensemble import IsolationForest

# Combine normal and attack test data from autoencoder example
X_test_if = test_data  # (120 x 2 array with 100 normal and 20 attack points)
# Train Isolation Forest (unsupervised) on the test set itself for demo (in practice train on known normal)
iso_forest = IsolationForest(n_estimators=100, contamination=0.15, random_state=0)
iso_forest.fit(X_test_if)
# Predict anomalies (-1 for anomaly, 1 for normal)
preds = iso_forest.predict(X_test_if)
anomaly_scores = iso_forest.decision_function(X_test_if)  # the higher, the more normal
print("Isolation Forest predicted labels (first 20):", preds[:20])
print("Number of anomalies detected:", np.sum(preds == -1))
print("Example anomaly scores (lower means more anomalous):", anomaly_scores[:5])
```
In questo codice, istanziamo `IsolationForest` con 100 alberi e impostiamo `contamination=0.15` (il che significa che ci aspettiamo circa il 15% di anomalie; il modello imposterà la sua soglia di punteggio in modo che ~15% dei punti siano contrassegnati). Lo adattiamo su `X_test_if` che contiene un mix di punti normali e di attacco (nota: normalmente si adatterebbe ai dati di addestramento e poi si userebbe predict su nuovi dati, ma qui per illustrazione ci adattiamo e prevediamo sullo stesso insieme per osservare direttamente i risultati).

L'output mostra le etichette previste per i primi 20 punti (dove -1 indica un'anomalia). Stampiamo anche quanti anomalie sono state rilevate in totale e alcuni esempi di punteggi di anomalia. Ci aspetteremmo che circa 18 su 120 punti siano etichettati -1 (poiché la contaminazione era del 15%). Se i nostri 20 campioni di attacco sono davvero i più anomali, la maggior parte di essi dovrebbe apparire in quelle previsioni -1. Il punteggio di anomalia (la funzione di decisione di Isolation Forest) è più alto per i punti normali e più basso (più negativo) per le anomalie – stampiamo alcuni valori per vedere la separazione. In pratica, si potrebbe ordinare i dati per punteggio per vedere i principali outlier e indagarli. Isolation Forest fornisce quindi un modo efficiente per setacciare grandi dati di sicurezza non etichettati e selezionare le istanze più irregolari per un'analisi umana o un'ulteriore scrutinio automatizzato.

### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** è una tecnica di riduzione dimensionale non lineare specificamente progettata per visualizzare dati ad alta dimensione in 2 o 3 dimensioni. Converte le somiglianze tra i punti dati in distribuzioni di probabilità congiunte e cerca di preservare la struttura dei vicinati locali nella proiezione a bassa dimensione. In termini più semplici, t-SNE posiziona i punti in (diciamo) 2D in modo che punti simili (nello spazio originale) finiscano vicini e punti dissimili finiscano lontani con alta probabilità.

L'algoritmo ha due fasi principali:

1. **Calcola affinità a coppie nello spazio ad alta dimensione:** Per ogni coppia di punti, t-SNE calcola una probabilità che si scelga quella coppia come vicini (questo viene fatto centrando una distribuzione gaussiana su ogni punto e misurando le distanze – il parametro di perplessità influisce sul numero effettivo di vicini considerati).
2. **Calcola affinità a coppie nello spazio a bassa dimensione (ad es. 2D):** Inizialmente, i punti sono posizionati casualmente in 2D. t-SNE definisce una probabilità simile per le distanze in questa mappa (utilizzando un kernel di distribuzione t di Student, che ha code più pesanti rispetto alla gaussiana per consentire ai punti distanti maggiore libertà).
3. **Discesa del gradiente:** t-SNE quindi sposta iterativamente i punti in 2D per minimizzare la divergenza Kullback–Leibler (KL) tra la distribuzione di affinità ad alta dimensione e quella a bassa dimensione. Questo fa sì che l'arrangiamento 2D rifletta la struttura ad alta dimensione il più possibile – i punti che erano vicini nello spazio originale si attrarranno, e quelli lontani si respingeranno, fino a trovare un equilibrio.

Il risultato è spesso un diagramma a dispersione visivamente significativo dove i cluster nei dati diventano evidenti.

> [!TIP]
> *Casi d'uso nella cybersecurity:* t-SNE è spesso utilizzato per **visualizzare dati di sicurezza ad alta dimensione per analisi umane**. Ad esempio, in un centro operazioni di sicurezza, gli analisti potrebbero prendere un dataset di eventi con dozzine di caratteristiche (numeri di porta, frequenze, conteggi di byte, ecc.) e utilizzare t-SNE per produrre un grafico 2D. Gli attacchi potrebbero formare i propri cluster o separarsi dai dati normali in questo grafico, rendendoli più facili da identificare. È stato applicato a dataset di malware per vedere raggruppamenti di famiglie di malware o a dati di intrusioni di rete dove diversi tipi di attacco si raggruppano distintamente, guidando ulteriori indagini. Fondamentalmente, t-SNE fornisce un modo per vedere la struttura nei dati informatici che altrimenti sarebbe incomprensibile.

#### Assunzioni e Limitazioni

t-SNE è ottimo per la scoperta visiva di schemi. Può rivelare cluster, subcluster e outlier che altri metodi lineari (come PCA) potrebbero non rilevare. È stato utilizzato nella ricerca sulla cybersecurity per visualizzare dati complessi come profili di comportamento di malware o schemi di traffico di rete. Poiché preserva la struttura locale, è utile per mostrare raggruppamenti naturali.

Tuttavia, t-SNE è computazionalmente più pesante (circa $O(n^2)$) quindi potrebbe richiedere campionamento per dataset molto grandi. Ha anche iperparametri (perplessità, tasso di apprendimento, iterazioni) che possono influenzare l'output – ad esempio, diversi valori di perplessità potrebbero rivelare cluster a scale diverse. I grafici t-SNE possono talvolta essere fraintesi – le distanze nella mappa non sono direttamente significative a livello globale (si concentra sul vicinato locale, a volte i cluster possono apparire artificialmente ben separati). Inoltre, t-SNE è principalmente per la visualizzazione; non fornisce un modo diretto per proiettare nuovi punti dati senza ricalcolare, e non è destinato ad essere utilizzato come preprocessing per la modellazione predittiva (UMAP è un'alternativa che affronta alcuni di questi problemi con una velocità maggiore).

<details>
<summary>Esempio -- Visualizzazione delle Connessioni di Rete
</summary>

Utilizzeremo t-SNE per ridurre un dataset multi-caratteristica a 2D. Per illustrazione, prendiamo i precedenti dati 4D (che avevano 3 cluster naturali di traffico normale) e aggiungiamo alcuni punti anomali. Eseguiamo quindi t-SNE e (concettualmente) visualizziamo i risultati.
```python
# 1 ─────────────────────────────────────────────────────────────────────
#    Create synthetic 4-D dataset
#      • Three clusters of “normal” traffic (duration, bytes)
#      • Two correlated features: packets & errors
#      • Five outlier points to simulate suspicious traffic
# ──────────────────────────────────────────────────────────────────────
import numpy as np
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler

rng = np.random.RandomState(42)

# Base (duration, bytes) clusters
normal1 = rng.normal(loc=[50, 500],  scale=[10, 100], size=(500, 2))
normal2 = rng.normal(loc=[60, 1500], scale=[8,  200], size=(500, 2))
normal3 = rng.normal(loc=[70, 3000], scale=[5,  300], size=(500, 2))

base_data = np.vstack([normal1, normal2, normal3])       # (1500, 2)

# Correlated features
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors  = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))

data_4d = np.column_stack([base_data, packets, errors])  # (1500, 4)

# Outlier / attack points
outliers_4d = np.column_stack([
rng.normal(250, 1, size=5),     # extreme duration
rng.normal(1000, 1, size=5),    # moderate bytes
rng.normal(5, 1, size=5),       # very low packets
rng.normal(25, 1, size=5)       # high errors
])

data_viz = np.vstack([data_4d, outliers_4d])             # (1505, 4)

# 2 ─────────────────────────────────────────────────────────────────────
#    Standardize features (recommended for t-SNE)
# ──────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
data_scaled = scaler.fit_transform(data_viz)

# 3 ─────────────────────────────────────────────────────────────────────
#    Run t-SNE to project 4-D → 2-D
# ──────────────────────────────────────────────────────────────────────
tsne = TSNE(
n_components=2,
perplexity=30,
learning_rate='auto',
init='pca',
random_state=0
)
data_2d = tsne.fit_transform(data_scaled)
print("t-SNE output shape:", data_2d.shape)  # (1505, 2)

# 4 ─────────────────────────────────────────────────────────────────────
#    Visualize: normal traffic vs. outliers
# ──────────────────────────────────────────────────────────────────────
plt.figure(figsize=(8, 6))
plt.scatter(
data_2d[:-5, 0], data_2d[:-5, 1],
label="Normal traffic",
alpha=0.6,
s=10
)
plt.scatter(
data_2d[-5:, 0], data_2d[-5:, 1],
label="Outliers / attacks",
alpha=0.9,
s=40,
marker="X",
edgecolor='k'
)

plt.title("t-SNE Projection of Synthetic Network Traffic")
plt.xlabel("t-SNE component 1")
plt.ylabel("t-SNE component 2")
plt.legend()
plt.tight_layout()
plt.show()
```
Qui abbiamo combinato il nostro precedente dataset normale 4D con un numero limitato di outlier estremi (gli outlier hanno una caratteristica (“durata”) impostata molto alta, ecc., per simulare un modello strano). Eseguiamo t-SNE con una perplessità tipica di 30. I dati di output_2d hanno forma (1505, 2). In questo testo non tracciamo effettivamente, ma se lo facessimo, ci aspetteremmo di vedere forse tre cluster compatti corrispondenti ai 3 cluster normali, e i 5 outlier apparire come punti isolati lontani da quei cluster. In un flusso di lavoro interattivo, potremmo colorare i punti in base alla loro etichetta (normale o quale cluster, rispetto all'anomalia) per verificare questa struttura. Anche senza etichette, un analista potrebbe notare quei 5 punti seduti in uno spazio vuoto nel grafico 2D e segnalarli. Questo dimostra come t-SNE possa essere un potente aiuto per la rilevazione visiva delle anomalie e l'ispezione dei cluster nei dati di cybersecurity, complementando gli algoritmi automatizzati sopra.

</details>


{{#include ../banners/hacktricks-training.md}}
