# Algoritmi di apprendimento non supervisionato

{{#include ../banners/hacktricks-training.md}}

## Apprendimento non supervisionato

L'apprendimento non supervisionato è un tipo di machine learning in cui il modello viene addestrato su dati privi di risposte etichettate. L'obiettivo è trovare pattern, strutture o relazioni all'interno dei dati. A differenza dell'apprendimento supervisionato, in cui il modello impara da esempi etichettati, gli algoritmi di apprendimento non supervisionato lavorano con dati non etichettati.
L'apprendimento non supervisionato viene spesso utilizzato per attività come clustering, riduzione della dimensionalità e rilevamento delle anomalie. Può aiutare a scoprire pattern nascosti nei dati, raggruppare elementi simili o ridurre la complessità dei dati preservandone le caratteristiche essenziali.


### Clustering K-Means

K-Means è un algoritmo di clustering basato sui centroidi che suddivide i dati in K cluster assegnando ogni punto alla media del cluster più vicina. L'algoritmo funziona come segue:
1. **Inizializzazione**: Scegliere K centri iniziali dei cluster (centroidi), spesso casualmente o tramite metodi più efficienti come k-means++
2. **Assegnazione**: Assegnare ogni punto dati al centroide più vicino in base a una metrica di distanza (ad esempio, la distanza euclidea).
3. **Aggiornamento**: Ricalcolare i centroidi calcolando la media di tutti i punti dati assegnati a ciascun cluster.
4. **Ripetizione**: Ripetere i passaggi 2–3 finché le assegnazioni dei cluster non si stabilizzano (i centroidi non si spostano più in modo significativo).

> [!TIP]
> *Casi d'uso nella cybersecurity:* K-Means viene utilizzato per il rilevamento delle intrusioni tramite il clustering degli eventi di rete. Ad esempio, alcuni ricercatori hanno applicato K-Means al dataset di intrusioni KDD Cup 99 e hanno rilevato che suddivide efficacemente il traffico in cluster normali e di attacco. Nella pratica, gli analisti della sicurezza possono raggruppare le voci dei log o i dati sul comportamento degli utenti per trovare gruppi di attività simili; i punti che non appartengono a un cluster ben definito potrebbero indicare anomalie (ad esempio, una nuova variante di malware che forma un piccolo cluster autonomo). K-Means può inoltre aiutare nella classificazione delle famiglie di malware raggruppando i binari in base ai profili comportamentali o ai vettori di caratteristiche.

#### Selezione di K
Il numero di cluster (K) è un iperparametro che deve essere definito prima di eseguire l'algoritmo. Tecniche come l'Elbow Method o il Silhouette Score possono aiutare a determinare un valore appropriato per K valutando le prestazioni del clustering:

- **Elbow Method**: Tracciare la somma delle distanze al quadrato da ciascun punto al centroide del cluster assegnato in funzione di K. Cercare un punto di "gomito" in cui il tasso di diminuzione cambia bruscamente, indicando un numero adeguato di cluster.
- **Silhouette Score**: Calcolare il silhouette score per diversi valori di K. Un silhouette score più alto indica cluster meglio definiti.

#### Assunzioni e limitazioni

K-Means presuppone che i **cluster siano sferici e di dimensioni uguali**, cosa che potrebbe non essere vera per tutti i dataset. È sensibile al posizionamento iniziale dei centroidi e può convergere verso minimi locali. Inoltre, K-Means non è adatto a dataset con densità variabili o forme non globulari, né a feature con scale diverse. Potrebbero essere necessarie fasi di preprocessing come la normalizzazione o la standardizzazione per garantire che tutte le feature contribuiscano in modo equo ai calcoli della distanza.

<details>
<summary>Esempio -- Clustering degli eventi di rete
</summary>
Di seguito simuliamo i dati del traffico di rete e utilizziamo K-Means per raggrupparli. Supponiamo di avere eventi con feature come la durata della connessione e il numero di byte. Creiamo 3 cluster di traffico “normale” e 1 piccolo cluster che rappresenta un pattern di attacco. Quindi eseguiamo K-Means per verificare se riesce a separarli.
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
In questo esempio, K-Means dovrebbe individuare 4 cluster. Il piccolo cluster di attacco (con una durata insolitamente elevata, ~200) idealmente formerà un cluster distinto, data la sua distanza dai cluster normali. Stampiamo le dimensioni e i centri dei cluster per interpretare i risultati. In uno scenario reale, si potrebbe etichettare il cluster con pochi punti come potenziali anomalie oppure esaminare i suoi elementi alla ricerca di attività malevole.
</details>

### Clustering gerarchico

Il clustering gerarchico costruisce una gerarchia di cluster utilizzando un approccio bottom-up (agglomerativo) oppure top-down (divisivo):

1. **Agglomerativo (Bottom-Up)**: si inizia con ogni punto dati come cluster separato e si uniscono iterativamente i cluster più vicini fino a ottenere un unico cluster o fino al raggiungimento di un criterio di arresto.
2. **Divisivo (Top-Down)**: si inizia con tutti i punti dati in un unico cluster e si suddividono iterativamente i cluster fino a quando ogni punto dati diventa il proprio cluster o viene raggiunto un criterio di arresto.

Il clustering agglomerativo richiede una definizione della distanza tra cluster e un criterio di linkage per decidere quali cluster unire. I metodi di linkage comuni includono il single linkage (distanza tra i punti più vicini di due cluster), il complete linkage (distanza tra i punti più lontani), l’average linkage, ecc.; la metrica di distanza è spesso euclidea. La scelta del linkage influisce sulla forma dei cluster prodotti. Non è necessario specificare in anticipo il numero di cluster K; è possibile “tagliare” il dendrogramma a un livello scelto per ottenere il numero di cluster desiderato.

Il clustering gerarchico produce un dendrogramma, una struttura ad albero che mostra le relazioni tra i cluster a diversi livelli di granularità. Il dendrogramma può essere tagliato al livello desiderato per ottenere un numero specifico di cluster.

> [!TIP]
> *Casi d’uso nella cybersecurity:* il clustering gerarchico può organizzare eventi o entità in un albero per individuare relazioni. Ad esempio, nell’analisi dei malware, il clustering agglomerativo potrebbe raggruppare i sample in base alla similarità comportamentale, rivelando una gerarchia di famiglie e varianti di malware. Nella network security, si potrebbero raggruppare i flussi di traffico IP e utilizzare il dendrogramma per osservare i sottogruppi del traffico (ad esempio, prima per protocollo e poi per comportamento). Poiché non è necessario scegliere K in anticipo, è utile quando si esplorano nuovi dati per i quali il numero di categorie di attacco è sconosciuto.

#### Assunzioni e limitazioni

Il clustering gerarchico non presuppone una forma specifica dei cluster e può identificare cluster annidati. È utile per scoprire tassonomie o relazioni tra gruppi (ad esempio, raggruppando i malware per sottogruppi di famiglie). È deterministico, quindi non presenta problemi legati all’inizializzazione casuale. Un vantaggio fondamentale è il dendrogramma, che fornisce informazioni sulla struttura di clustering dei dati a tutte le scale: gli analisti di sicurezza possono decidere un cutoff appropriato per identificare cluster significativi. Tuttavia, è computazionalmente costoso (in genere $O(n^2)$ o peggio per le implementazioni naive) e non è adatto a dataset molto grandi. È inoltre una procedura greedy: una volta eseguita un’unione o una suddivisione, non può essere annullata, il che può portare a cluster subottimali se si verifica un errore nelle fasi iniziali. Anche gli outlier possono influire su alcune strategie di linkage (il single-link può causare il cosiddetto effetto “chaining”, in cui i cluster vengono collegati tramite gli outlier).

<details>
<summary>Esempio -- Clustering agglomerativo degli eventi
</summary>

Riutilizzeremo i dati sintetici dell’esempio di K-Means (3 cluster normali + 1 cluster di attacco) e applicheremo il clustering agglomerativo. Illustreremo quindi come ottenere un dendrogramma e le etichette dei cluster.
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

### DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

DBSCAN è un algoritmo di clustering basato sulla densità che raggruppa i punti strettamente vicini tra loro, classificando invece i punti nelle regioni a bassa densità come outlier. È particolarmente utile per dataset con densità variabili e forme non sferiche.

DBSCAN funziona definendo due parametri:
- **Epsilon (ε)**: La distanza massima tra due punti affinché possano essere considerati parte dello stesso cluster.
- **MinPts**: Il numero minimo di punti necessario per formare una regione densa (punto core).

DBSCAN identifica punti core, punti di bordo e punti di rumore:
- **Punto core**: Un punto con almeno MinPts vicini entro una distanza ε.
- **Punto di bordo**: Un punto che si trova entro una distanza ε da un punto core, ma ha meno di MinPts vicini.
- **Punto di rumore**: Un punto che non è né un punto core né un punto di bordo.

Il clustering procede selezionando un punto core non visitato, contrassegnandolo come nuovo cluster e aggiungendo ricorsivamente tutti i punti raggiungibili per densità da esso (punti core e i relativi vicini, ecc.). I punti di bordo vengono aggiunti al cluster di un punto core vicino. Dopo aver espanso tutti i punti raggiungibili, DBSCAN passa a un altro punto core non visitato per iniziare un nuovo cluster. I punti non raggiunti da alcun punto core rimangono classificati come rumore.

> [!TIP]
> *Casi d'uso nella cybersecurity:* DBSCAN è utile per il rilevamento di anomalie nel network traffic. Ad esempio, la normale attività degli utenti potrebbe formare uno o più cluster densi nello spazio delle feature, mentre i comportamenti di attacco nuovi apparirebbero come punti sparsi che DBSCAN classificherà come rumore (outlier). È stato utilizzato per raggruppare i record dei network flow, consentendo di rilevare port scan o traffico di denial-of-service come regioni sparse di punti. Un'altra applicazione consiste nel raggruppamento delle varianti di malware: se la maggior parte dei sample si raggruppa per famiglia, ma alcuni non si adattano ad alcun gruppo, questi ultimi potrebbero essere malware zero-day. La capacità di segnalare il rumore consente ai security team di concentrarsi sull'analisi di questi outlier.

#### Assumptions and Limitations

**Assumptions & Strengths:**: DBSCAN non presume cluster sferici: è in grado di trovare cluster di forma arbitraria (anche cluster adiacenti o concatenati). Determina automaticamente il numero di cluster in base alla densità dei dati e può identificare efficacemente gli outlier come rumore. Questo lo rende potente per i dati reali con forme irregolari e rumore. È robusto rispetto agli outlier (a differenza di K-Means, che li forza all'interno dei cluster). Funziona bene quando i cluster hanno una densità approssimativamente uniforme.

**Limitations**: Le prestazioni di DBSCAN dipendono dalla scelta di valori appropriati per ε e MinPts. Può avere difficoltà con dati caratterizzati da densità variabili: un singolo ε non può gestire contemporaneamente cluster densi e sparsi. Se ε è troppo piccolo, classifica la maggior parte dei punti come rumore; se è troppo grande, i cluster potrebbero fondersi erroneamente. Inoltre, DBSCAN può essere inefficiente su dataset molto grandi (ingenuamente $O(n^2)$, anche se l'indicizzazione spaziale può essere d'aiuto). Negli spazi delle feature ad alta dimensionalità, il concetto di “distanza entro ε” può diventare meno significativo (la maledizione della dimensionalità), e DBSCAN potrebbe richiedere un'attenta configurazione dei parametri oppure potrebbe non riuscire a trovare cluster intuitivi. Nonostante ciò, estensioni come HDBSCAN risolvono alcuni problemi (come la densità variabile).

<details>
<summary>Example -- Clustering with Noise
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
In questo snippet, abbiamo regolato `eps` e `min_samples` in base alla scala dei nostri dati (15.0 nelle unità delle feature e richiedendo 5 punti per formare un cluster). DBSCAN dovrebbe trovare 2 cluster (i cluster del traffico normale) e contrassegnare i 5 outlier inseriti come noise. Produciamo il numero di cluster rispetto ai punti noise per verificarlo. In un contesto reale, si potrebbe iterare su ε (utilizzando un'euristica basata su un grafico delle k-distanze per scegliere ε) e MinPts (spesso impostato approssimativamente sulla dimensionalità dei dati + 1 come regola empirica) per trovare risultati di clustering stabili. La capacità di etichettare esplicitamente il noise aiuta a separare i potenziali dati di attacco per ulteriori analisi.

</details>

### Principal Component Analysis (PCA)

PCA è una tecnica di **riduzione della dimensionalità** che individua un nuovo insieme di assi ortogonali (componenti principali) che catturano la massima varianza nei dati. In termini semplici, PCA ruota e proietta i dati su un nuovo sistema di coordinate in modo che la prima componente principale (PC1) spieghi la maggiore varianza possibile, la seconda componente principale (PC2) spieghi la maggiore varianza ortogonale a PC1 e così via. Matematicamente, PCA calcola gli autovettori della matrice di covarianza dei dati: questi autovettori sono le direzioni delle componenti principali, mentre gli autovalori corrispondenti indicano la quantità di varianza spiegata da ciascuna di esse. Viene spesso utilizzata per l'estrazione delle feature, la visualizzazione e la riduzione del noise.

Nota che questo è utile se le dimensioni del dataset contengono **dipendenze lineari o correlazioni significative**.

PCA funziona identificando le componenti principali dei dati, ovvero le direzioni di massima varianza. I passaggi coinvolti in PCA sono:
1. **Standardizzazione**: centra i dati sottraendo la media e ridimensionandoli a una varianza unitaria.
2. **Matrice di covarianza**: calcola la matrice di covarianza dei dati standardizzati per comprendere le relazioni tra le feature.
3. **Decomposizione degli autovalori**: esegue la decomposizione agli autovalori sulla matrice di covarianza per ottenere gli autovalori e gli autovettori.
4. **Selezione delle componenti principali**: ordina gli autovalori in ordine decrescente e seleziona i primi K autovettori corrispondenti agli autovalori più elevati. Questi autovettori formano il nuovo spazio delle feature.
5. **Trasformazione dei dati**: proietta i dati originali sul nuovo spazio delle feature utilizzando le componenti principali selezionate.
PCA è ampiamente utilizzata per la visualizzazione dei dati, la riduzione del noise e come fase di preprocessing per altri algoritmi di machine learning. Aiuta a ridurre la dimensionalità dei dati mantenendo la loro struttura essenziale.

#### Autovalori e autovettori

Un autovalore è uno scalare che indica la quantità di varianza catturata dal relativo autovettore. Un autovettore rappresenta una direzione nello spazio delle feature lungo la quale i dati variano maggiormente.

Immagina che A sia una matrice quadrata e che v sia un vettore non nullo tale che: `A * v = λ * v`
dove:
- A è una matrice quadrata come [ [1, 2], [2, 1]] (ad esempio, una matrice di covarianza)
- v è un autovettore (ad esempio, [1, 1])

Quindi, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, che sarà l'autovalore λ moltiplicato per l'autovettore v, rendendo l'autovalore λ = 3.

#### Autovalori e autovettori in PCA

Spieghiamolo con un esempio. Immagina di avere un dataset contenente molte immagini in scala di grigi di volti da 100x100 pixel. Ogni pixel può essere considerato una feature, quindi hai 10.000 feature per immagine (ovvero un vettore di 10000 componenti per immagine). Se vuoi ridurre la dimensionalità di questo dataset utilizzando PCA, seguiresti questi passaggi:

1. **Standardizzazione**: centra i dati sottraendo dal dataset la media di ogni feature (pixel).
2. **Matrice di covarianza**: calcola la matrice di covarianza dei dati standardizzati, che cattura il modo in cui le feature (pixel) variano insieme.
- Nota che la covarianza tra due variabili (in questo caso, i pixel) indica quanto cambiano insieme; l'idea è quindi scoprire quali pixel tendono ad aumentare o diminuire insieme secondo una relazione lineare.
- Ad esempio, se il pixel 1 e il pixel 2 tendono ad aumentare insieme, la covarianza tra loro sarà positiva.
- La matrice di covarianza sarà una matrice 10.000x10.000, in cui ogni elemento rappresenta la covarianza tra due pixel.
3. **Risoluzione dell'equazione degli autovalori**: l'equazione degli autovalori da risolvere è `C * v = λ * v`, dove C è la matrice di covarianza, v è l'autovettore e λ è l'autovalore. Può essere risolta utilizzando metodi come:
- **Decomposizione degli autovalori**: esegue la decomposizione agli autovalori sulla matrice di covarianza per ottenere gli autovalori e gli autovettori.
- **Singular Value Decomposition (SVD)**: in alternativa, puoi utilizzare SVD per scomporre la matrice dei dati in valori e vettori singolari, ottenendo così anche le componenti principali.
4. **Selezione delle componenti principali**: ordina gli autovalori in ordine decrescente e seleziona i primi K autovettori corrispondenti agli autovalori più elevati. Questi autovettori rappresentano le direzioni di massima varianza nei dati.

> [!TIP]
> *Casi d'uso nella cybersecurity:* un utilizzo comune di PCA nella security è la riduzione delle feature per il rilevamento delle anomalie. Ad esempio, un sistema di rilevamento delle intrusioni con oltre 40 metriche di rete (come le feature NSL-KDD) può utilizzare PCA per ridurle a una manciata di componenti, riassumendo i dati per la visualizzazione o l'inserimento in algoritmi di clustering. Gli analisti potrebbero rappresentare il traffico di rete nello spazio delle prime due componenti principali per verificare se gli attacchi si separano dal traffico normale. PCA può inoltre aiutare a eliminare le feature ridondanti (come i byte inviati rispetto ai byte ricevuti, se sono correlati), rendendo gli algoritmi di rilevamento più robusti e veloci.

#### Assunzioni e limitazioni

PCA presuppone che gli **assi principali della varianza siano significativi**: è un metodo lineare, quindi cattura le correlazioni lineari nei dati. È unsupervised poiché utilizza esclusivamente la covarianza delle feature. I vantaggi di PCA includono la riduzione del noise (le componenti a bassa varianza spesso corrispondono al noise) e la decorrelazione delle feature. È computazionalmente efficiente per dimensionalità moderatamente elevate e spesso rappresenta un utile passaggio di preprocessing per altri algoritmi (per mitigare la maledizione della dimensionalità). Una limitazione è che PCA si limita alle relazioni lineari: non cattura strutture non lineari complesse (mentre potrebbero farlo gli autoencoder o t-SNE). Inoltre, le componenti PCA possono essere difficili da interpretare in termini di feature originali (sono combinazioni delle feature originali). Nella cybersecurity, è necessario prestare attenzione: un attacco che provoca solo una variazione sottile in una feature a bassa varianza potrebbe non comparire nelle PC principali (poiché PCA dà priorità alla varianza, non necessariamente a ciò che è “interessante”).

<details>
<summary>Esempio -- Riduzione delle dimensioni dei dati di rete
</summary>

Supponiamo di avere log di connessioni di rete con molteplici feature (ad esempio, durate, byte, conteggi). Genereremo un dataset sintetico a 4 dimensioni (con una certa correlazione tra le feature) e utilizzeremo PCA per ridurlo a 2 dimensioni ai fini della visualizzazione o di ulteriori analisi.
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
Qui abbiamo preso i cluster del traffico normale precedente ed esteso ogni punto dati con due feature aggiuntive (packets ed errors) correlate con bytes e duration. PCA viene quindi utilizzato per comprimere le 4 feature in 2 componenti principali. Stampiamo il rapporto di varianza spiegata, che potrebbe mostrare, ad esempio, che più del 95% della varianza è catturato da 2 componenti (con una conseguente perdita minima di informazioni). L'output mostra anche la riduzione della forma dei dati da (1500, 4) a (1500, 2). I primi punti nello spazio PCA sono forniti come esempio. Nella pratica, si potrebbe tracciare data_2d per verificare visivamente se i cluster sono distinguibili. Se fosse presente un'anomalia, potrebbe apparire come un punto distante dal cluster principale nello spazio PCA. PCA aiuta quindi a distillare dati complessi in una forma gestibile per l'interpretazione umana o come input per altri algoritmi.

</details>


### Gaussian Mixture Models (GMM)

Un Gaussian Mixture Model presume che i dati siano generati da una combinazione di **diverse distribuzioni Gaussiane (normali) con parametri sconosciuti**. In sostanza, è un modello probabilistico di clustering: tenta di assegnare in modo soft ogni punto a uno degli K componenti Gaussiani. Ogni componente Gaussiano k ha un vettore media (μ_k), una matrice di covarianza (Σ_k) e un peso di mixing (π_k) che rappresenta la prevalenza di quel cluster. A differenza di K-Means, che esegue assegnazioni “hard”, GMM assegna a ogni punto una probabilità di appartenere a ciascun cluster.

Il fitting di GMM viene generalmente eseguito tramite l'algoritmo Expectation-Maximization (EM):

- **Inizializzazione**: si parte da stime iniziali per medie, covarianze e coefficienti di mixing (oppure si usano i risultati di K-Means come punto di partenza).

- **E-step (Expectation)**: dati i parametri correnti, si calcola la responsabilità di ogni cluster per ciascun punto: essenzialmente `r_nk = P(z_k | x_n)`, dove z_k è la variabile latente che indica l'appartenenza al cluster del punto x_n. Questo viene eseguito utilizzando il teorema di Bayes, calcolando la probabilità a posteriori che ogni punto appartenga a ciascun cluster sulla base dei parametri correnti. Le responsabilità vengono calcolate come:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
dove:
- \( \pi_k \) è il coefficiente di mixing per il cluster k (probabilità a priori del cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) è la funzione di densità di probabilità Gaussiana per il punto \( x_n \), data la media \( \mu_k \) e la covarianza \( \Sigma_k \).

- **M-step (Maximization)**: si aggiornano i parametri utilizzando le responsabilità calcolate nell'E-step:
- si aggiorna ogni media μ_k come media pesata dei punti, dove i pesi sono le responsabilità;
- si aggiorna ogni covarianza Σ_k come covarianza pesata dei punti assegnati al cluster k;
- si aggiornano i coefficienti di mixing π_k come responsabilità media per il cluster k.

- Si **iterano** gli step E e M fino alla convergenza (quando i parametri si stabilizzano o il miglioramento della likelihood scende al di sotto di una soglia).

Il risultato è un insieme di distribuzioni Gaussiane che modellano collettivamente la distribuzione complessiva dei dati. Possiamo usare il GMM ottenuto per eseguire il clustering, assegnando ogni punto alla Gaussiana con la probabilità più alta, oppure mantenere le probabilità per rappresentare l'incertezza. È inoltre possibile valutare la likelihood di nuovi punti per verificare se sono compatibili con il modello (utile per anomaly detection).

> [!TIP]
> *Casi d'uso nella cybersecurity:* GMM può essere utilizzato per l'anomaly detection modellando la distribuzione dei dati normali: qualsiasi punto con probabilità molto bassa secondo la mixture appresa viene segnalato come anomalia. Ad esempio, si potrebbe addestrare un GMM sulle feature del traffico di rete legittimo; una connessione di attacco che non assomiglia a nessun cluster appreso avrebbe una likelihood bassa. I GMM vengono utilizzati anche per raggruppare attività i cui cluster potrebbero avere forme diverse, ad esempio raggruppando gli utenti in base ai profili comportamentali, dove le feature di ciascun profilo potrebbero avere un andamento simile a quello Gaussiano, ma con una propria struttura della varianza. Un altro scenario riguarda il phishing detection: le feature delle email legittime potrebbero formare un cluster Gaussiano, quelle del phishing noto un altro, mentre nuove campagne di phishing potrebbero manifestarsi come una Gaussiana separata o come punti con likelihood bassa rispetto alla mixture esistente.

#### Assumptions and Limitations

GMM è una generalizzazione di K-Means che incorpora la covarianza, quindi i cluster possono essere ellissoidali (non solo sferici). Gestisce cluster di dimensioni e forme diverse se la covarianza è full. Il clustering soft è un vantaggio quando i confini dei cluster sono sfumati: ad esempio, nella cybersecurity, un evento potrebbe presentare caratteristiche di più tipologie di attacco; GMM può riflettere questa incertezza tramite le probabilità. GMM fornisce inoltre una stima probabilistica della densità dei dati, utile per rilevare gli outlier (punti con likelihood bassa secondo tutti i componenti della mixture).

Di contro, GMM richiede di specificare il numero di componenti K (anche se è possibile utilizzare criteri come BIC/AIC per selezionarlo). EM può talvolta convergere lentamente o verso un optimum locale, quindi l'inizializzazione è importante (spesso si esegue EM più volte). Se i dati non seguono effettivamente una mixture di Gaussiane, il modello potrebbe adattarsi male. Esiste inoltre il rischio che una Gaussiana si restringa fino a coprire un solo outlier (anche se la regolarizzazione o i limiti minimi della covarianza possono mitigare il problema).


<details>
<summary>Example --  Soft Clustering & Anomaly Scores
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
In questo codice, addestriamo un GMM con 3 gaussiane sul traffico normale (supponendo di conoscere 3 profili di traffico legittimo). Le medie e le covarianze stampate descrivono questi cluster (per esempio, una media potrebbe essere intorno a [50,500], corrispondente al centro di uno dei cluster, ecc.). Testiamo quindi una connessione sospetta [duration=200, bytes=800]. predict_proba restituisce la probabilità che questo punto appartenga a ciascuno dei 3 cluster: ci aspetteremmo che queste probabilità siano molto basse o fortemente sbilanciate, poiché [200,800] è lontano dai cluster normali. Viene stampato il valore complessivo di score_samples (log-likelihood); un valore molto basso indica che il punto non si adatta bene al modello, segnalandolo come anomalia. In pratica, si potrebbe impostare una soglia sul log-likelihood (o sulla probabilità massima) per decidere se un punto è sufficientemente improbabile da essere considerato malicious. GMM fornisce quindi un modo basato su principi solidi per il rilevamento delle anomalie e produce anche cluster soft che tengono conto dell’incertezza.
</details>

### Isolation Forest

**Isolation Forest** è un algoritmo di rilevamento delle anomalie basato sull’idea di isolare casualmente i punti. Il principio è che le anomalie sono poche e diverse, quindi sono più facili da isolare rispetto ai punti normali. Un Isolation Forest costruisce molti alberi binari di isolamento (alberi decisionali casuali) che partizionano casualmente i dati. A ogni nodo di un albero, viene selezionata una feature casuale e viene scelto un valore di suddivisione casuale tra il minimo e il massimo di quella feature per i dati presenti nel nodo. Questa suddivisione divide i dati in due rami. L’albero cresce finché ogni punto non viene isolato nella propria foglia o non viene raggiunta l’altezza massima dell’albero.

Il rilevamento delle anomalie viene eseguito osservando la lunghezza del percorso di ogni punto in questi alberi casuali, ovvero il numero di suddivisioni necessarie per isolare il punto. Intuitivamente, le anomalie (outlier) tendono a essere isolate più rapidamente, perché una suddivisione casuale ha maggiori probabilità di separare un outlier (che si trova in una regione poco densa) rispetto a un punto normale in un cluster denso. Isolation Forest calcola un anomaly score a partire dalla lunghezza media del percorso in tutti gli alberi: un percorso medio più breve indica una maggiore probabilità di anomalia. Gli score vengono solitamente normalizzati nell’intervallo [0,1], dove 1 indica un’anomalia altamente probabile.

> [!TIP]
> *Casi d’uso nella cybersecurity:* gli Isolation Forest sono stati utilizzati con successo nel rilevamento delle intrusioni e delle frodi. Per esempio, si può addestrare un Isolation Forest sui log del traffico di rete contenenti prevalentemente comportamenti normali; il forest produrrà percorsi brevi per il traffico anomalo (come un IP che utilizza una porta mai osservata o un pattern insolito nelle dimensioni dei pacchetti), segnalandolo per un’ispezione. Poiché non richiede attacchi etichettati, è adatto al rilevamento di tipologie di attacco sconosciute. Può anche essere implementato sui dati degli accessi degli utenti per rilevare account takeover (gli orari o le posizioni di accesso anomali vengono isolati rapidamente). In un caso d’uso, un Isolation Forest potrebbe proteggere un’azienda monitorando le metriche di sistema e generando un alert quando una combinazione di metriche (CPU, rete, modifiche ai file) appare molto diversa (percorsi di isolamento brevi) rispetto ai pattern storici.

#### Presupposti e limitazioni

**Vantaggi**: Isolation Forest non richiede un’ipotesi sulla distribuzione; si concentra direttamente sull’isolamento. È efficiente con dati ad alta dimensionalità e dataset di grandi dimensioni (complessità lineare $O(n\log n)$ per la costruzione del forest), poiché ogni albero isola i punti utilizzando solo un sottoinsieme delle feature e delle suddivisioni. Tende a gestire bene le feature numeriche e può essere più veloce dei metodi basati sulla distanza, che potrebbero avere complessità $O(n^2)$. Inoltre, fornisce automaticamente un anomaly score, permettendo di impostare una soglia per gli alert (o di utilizzare un parametro contamination per decidere automaticamente un cutoff sulla base di una frazione di anomalie prevista).

**Limitazioni**: a causa della sua natura casuale, i risultati possono variare leggermente tra un’esecuzione e l’altra (anche se, con un numero sufficiente di alberi, questa variazione è minima). Se i dati contengono molte feature irrilevanti o se le anomalie non si differenziano nettamente in nessuna feature, l’isolamento potrebbe non essere efficace (le suddivisioni casuali potrebbero isolare casualmente punti normali; tuttavia, la media su molti alberi riduce questo effetto). Inoltre, Isolation Forest generalmente presuppone che le anomalie costituiscano una piccola minoranza (come solitamente avviene negli scenari di cybersecurity).

<details>
<summary>Esempio -- Rilevamento degli outlier nei log di rete
</summary>

Utilizzeremo il dataset di test precedente (che contiene punti normali e alcuni punti relativi ad attacchi) ed eseguiremo un Isolation Forest per verificare se riesce a separare gli attacchi. Supporremo che circa il 15% dei dati sia anomalo (a scopo dimostrativo).
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
In questo codice, istanziamo `IsolationForest` con 100 alberi e impostiamo `contamination=0.15` (ovvero prevediamo circa il 15% di anomalie; il modello imposterà la soglia del punteggio in modo che circa il 15% dei punti venga segnalato). Lo adattiamo a `X_test_if`, che contiene un insieme di punti normali e di attacco (nota: normalmente lo si adatterebbe ai dati di training e poi si userebbe predict su nuovi dati, ma qui, a scopo illustrativo, eseguiamo fit e predict sullo stesso insieme per osservare direttamente i risultati).

L’output mostra le etichette previste per i primi 20 punti (dove -1 indica un’anomalia). Stampiamo inoltre quante anomalie sono state rilevate in totale e alcuni esempi di punteggi di anomalia. Ci aspetteremmo che circa 18 punti su 120 vengano etichettati come -1 (poiché contamination era impostato al 15%). Se i nostri 20 campioni di attacco sono realmente i più fuori distribuzione, la maggior parte di essi dovrebbe comparire tra le predizioni -1. Il punteggio di anomalia (la decision function di Isolation Forest) è più alto per i punti normali e più basso (più negativo) per le anomalie: stampiamo alcuni valori per osservare la separazione. Nella pratica, si potrebbero ordinare i dati in base al punteggio per visualizzare gli outlier principali e analizzarli. Isolation Forest fornisce quindi un metodo efficiente per filtrare grandi quantità di dati di sicurezza non etichettati e individuare le istanze più irregolari per l’analisi umana o per ulteriori controlli automatizzati.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** è una tecnica non lineare di riduzione della dimensionalità progettata specificamente per visualizzare dati ad alta dimensionalità in 2 o 3 dimensioni. Converte le similarità tra i punti dati in distribuzioni di probabilità congiunte e cerca di preservare la struttura dei vicinati locali nella proiezione a dimensionalità inferiore. In termini più semplici, t-SNE posiziona i punti in (ad esempio) 2D in modo che i punti simili (nello spazio originale) finiscano vicini tra loro e quelli dissimili finiscano lontani con alta probabilità.

L’algoritmo ha tre fasi principali:

1. **Calcolo delle affinità a coppie nello spazio ad alta dimensionalità:** Per ogni coppia di punti, t-SNE calcola la probabilità che uno scelga quella coppia come vicini (lo fa centrando una distribuzione gaussiana su ogni punto e misurando le distanze; il parametro perplexity influenza il numero effettivo di vicini considerati).
2. **Calcolo delle affinità a coppie nello spazio a bassa dimensionalità (ad esempio 2D):** Inizialmente, i punti vengono posizionati casualmente in 2D. t-SNE definisce una probabilità simile per le distanze in questa mappa (utilizzando un kernel con distribuzione t di Student, che ha code più pesanti rispetto alla distribuzione gaussiana per consentire maggiore libertà ai punti distanti).
3. **Gradient Descent:** t-SNE sposta quindi iterativamente i punti in 2D per minimizzare la divergenza di Kullback–Leibler (KL) tra la distribuzione delle affinità nello spazio ad alta dimensionalità e quella nello spazio a bassa dimensionalità. In questo modo, la disposizione 2D riflette il più possibile la struttura ad alta dimensionalità: i punti vicini nello spazio originale si attraggono, mentre quelli distanti si respingono, finché non viene raggiunto un equilibrio.

Il risultato è spesso uno scatter plot visivamente significativo, nel quale i cluster presenti nei dati diventano evidenti.

> [!TIP]
> *Casi d’uso nella cybersecurity:* t-SNE viene spesso utilizzato per **visualizzare dati di sicurezza ad alta dimensionalità per l’analisi umana**. Ad esempio, in un security operations center, gli analisti potrebbero prendere un dataset di eventi con decine di feature (numeri di porta, frequenze, conteggi di byte e così via) e usare t-SNE per produrre un grafico 2D. In questo grafico, gli attacchi potrebbero formare cluster propri o separarsi dai dati normali, rendendoli più facili da identificare. È stato applicato a dataset di malware per osservare i raggruppamenti delle famiglie di malware o a dati sulle intrusioni di rete, nei quali diversi tipi di attacco formano cluster distinti, guidando ulteriori analisi. In sostanza, t-SNE offre un modo per osservare la struttura dei dati cyber che altrimenti sarebbe difficile da interpretare.

#### Assunzioni e limitazioni

t-SNE è ottimo per la scoperta visiva dei pattern. Può rivelare cluster, sottocluster e outlier che altri metodi lineari (come PCA) potrebbero non individuare. È stato utilizzato nella ricerca sulla cybersecurity per visualizzare dati complessi, come i profili del comportamento dei malware o i pattern del traffico di rete. Poiché preserva la struttura locale, è efficace nel mostrare i raggruppamenti naturali.

Tuttavia, t-SNE è computazionalmente più pesante (approssimativamente $O(n^2)$), quindi potrebbe richiedere il campionamento per dataset molto grandi. Dispone inoltre di iperparametri (perplexity, learning rate, iterations) che possono influenzare l’output: ad esempio, valori diversi di perplexity potrebbero rivelare cluster a scale differenti. I grafici t-SNE possono talvolta essere interpretati erroneamente: le distanze nella mappa non sono direttamente significative a livello globale (l’algoritmo si concentra sul vicinato locale e alcuni cluster possono apparire separati artificialmente). Inoltre, t-SNE è principalmente uno strumento di visualizzazione; non offre un modo diretto per proiettare nuovi punti dati senza ricalcolare il modello e non è pensato per essere utilizzato come preprocessing per la modellazione predittiva (UMAP è un’alternativa che risolve alcuni di questi problemi offrendo una maggiore velocità).

<details>
<summary>Esempio -- Visualizzazione delle connessioni di rete
</summary>

Useremo t-SNE per ridurre a 2D un dataset con più feature. A scopo illustrativo, prendiamo i precedenti dati 4D (che contenevano 3 cluster naturali di traffico normale) e aggiungiamo alcuni punti anomali. Eseguiamo quindi t-SNE e visualizziamo (concettualmente) i risultati.
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
Qui abbiamo combinato il nostro precedente dataset normale 4D con una manciata di outlier estremi (gli outlier hanno una feature ("duration") impostata su un valore molto alto, ecc., per simulare un pattern anomalo). Eseguiamo t-SNE con una perplexity tipica di 30. L'output `data_2d` ha forma (1505, 2). In questo testo non tracceremo effettivamente il grafico, ma, se lo facessimo, ci aspetteremmo di vedere forse tre cluster molto compatti corrispondenti ai 3 cluster normali, con i 5 outlier visualizzati come punti isolati lontani da quei cluster. In un workflow interattivo, potremmo colorare i punti in base alla loro label (normale o relativo a uno dei cluster, rispetto ad anomalia) per verificare questa struttura. Anche senza label, un analista potrebbe notare quei 5 punti collocati in uno spazio vuoto nel grafico 2D e segnalarli. Questo mostra come t-SNE possa essere un potente ausilio per il rilevamento visivo delle anomalie e l'ispezione dei cluster nei dati di cybersecurity, complementare agli algoritmi automatizzati descritti sopra.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** è un'estensione di DBSCAN che elimina la necessità di scegliere un singolo valore globale `eps` ed è in grado di recuperare cluster con **densità diverse**, costruendo una gerarchia di componenti connesse per densità e condensandola successivamente. Rispetto al DBSCAN vanilla, di solito

* estrae cluster più intuitivi quando alcuni cluster sono densi e altri sparsi,
* ha un solo vero hyper-parameter (`min_cluster_size`) e un default sensato,
* assegna a ogni punto una *probability* di appartenenza al cluster e un **outlier score** (`outlier_scores_`), estremamente utile per le dashboard di threat-hunting.<sup>[[1]](#references)</sup>

> [!TIP]
> *Use cases nella cybersecurity:* HDBSCAN è molto popolare nelle moderne pipeline di threat-hunting: spesso lo si trova all'interno di playbook di hunting basati su notebook, distribuiti con suite XDR commerciali. Una ricetta pratica consiste nel clusterizzare il traffico HTTP di beaconing durante l'IR: user-agent, intervallo e lunghezza dell'URI formano spesso diversi gruppi compatti di software updater legittimi, mentre i beacon C2 rimangono come piccoli cluster a bassa densità o come puro rumore.

<details>
<summary>Esempio – Individuazione dei canali C2 di beaconing</summary>
```python
import pandas as pd
from hdbscan import HDBSCAN
from sklearn.preprocessing import StandardScaler

# df has features extracted from proxy logs
features = [
"avg_interval",      # seconds between requests
"uri_length_mean",   # average URI length
"user_agent_entropy" # Shannon entropy of UA string
]
X = StandardScaler().fit_transform(df[features])

hdb = HDBSCAN(min_cluster_size=15,  # at least 15 similar beacons to be a group
metric="euclidean",
prediction_data=True)
labels = hdb.fit_predict(X)

df["cluster"] = labels
# Anything with label == -1 is noise → inspect as potential C2
suspects = df[df["cluster"] == -1]
print("Suspect beacon count:", len(suspects))
```
</details>

---

### Considerazioni su Robustezza e Sicurezza – Poisoning e Attacchi Adversarial (2023-2025)

Lavori recenti hanno dimostrato che gli **unsupervised learner *non* sono immuni agli attacker attivi**:

* **Data-poisoning contro gli anomaly detector.** Chen *et al.* (IEEE S&P 2024) hanno dimostrato che l'aggiunta di appena il 3% di traffico appositamente creato può spostare il decision boundary di Isolation Forest ed ECOD, facendo apparire normali gli attacchi reali. Gli autori hanno pubblicato una PoC open-source (`udo-poison`) che sintetizza automaticamente i poison point.<sup>[[2]](#references)</sup>
* **Backdooring dei modelli di clustering.** La tecnica *BadCME* (BlackHat EU 2023) inserisce un piccolo trigger pattern; ogni volta che compare tale trigger, un detector basato su K-Means colloca silenziosamente l'evento all'interno di un cluster “benigno”.
* **Evasione di DBSCAN/HDBSCAN.** Un pre-print accademico del 2025 della KU Leuven ha dimostrato che un attacker può creare beaconing pattern che ricadono intenzionalmente nei density gap, nascondendosi di fatto all'interno delle label *noise*.

Mitigazioni che stanno guadagnando popolarità:

1. **Model sanitisation / TRIM.** Prima di ogni epoca di retraining, scartare l'1–2% dei point con loss più elevata (trimmed maximum likelihood) per rendere il poisoning molto più difficile.
2. **Consensus ensembling.** Combinare diversi detector eterogenei (ad es., Isolation Forest + GMM + ECOD) e generare un alert se *qualsiasi* modello segnala un point. Le ricerche indicano che questo aumenta di oltre 10 volte il costo per l'attacker.
3. **Difesa basata sulla distanza per il clustering.** Ricalcolare i cluster con `k` random seed differenti e ignorare i point che cambiano costantemente cluster.

---

### Tooling Open-Source moderno (2024-2025)

* **PyOD 2.x** (rilasciato a maggio 2024) ha aggiunto i detector *ECOD*, *COPOD* e *AutoFormer* accelerati tramite GPU. Ora include un sub-command `benchmark` che consente di confrontare oltre 30 algoritmi sul proprio dataset con **una sola riga di codice**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (febbraio 2025) si concentra sulla computer vision, ma contiene anche un'implementazione generica di **PatchCore**, utile per il rilevamento di phishing page basato su screenshot.
* **scikit-learn 1.5** (novembre 2024) espone finalmente `score_samples` per *HDBSCAN* tramite il nuovo wrapper `cluster.HDBSCAN`, quindi non è necessario il package contrib esterno quando si usa Python 3.12.

<details>
<summary>Rapido esempio PyOD – ensemble ECOD + Isolation Forest</summary>
```python
from pyod.models import ECOD, IForest
from pyod.utils.data import generate_data, evaluate_print
from pyod.utils.example import visualize

X_train, y_train, X_test, y_test = generate_data(
n_train=5000, n_test=1000, n_features=16,
contamination=0.02, random_state=42)

models = [ECOD(), IForest()]

# majority vote – flag if any model thinks it is anomalous
anomaly_scores = sum(m.fit(X_train).decision_function(X_test) for m in models) / len(models)

evaluate_print("Ensemble", y_test, anomaly_scores)
```
</details>

## Riferimenti

- [1] [HDBSCAN – Clustering gerarchico basato sulla densità](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* “Sulla vulnerabilità dell'anomaly detection non supervisionato al data poisoning.” *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
