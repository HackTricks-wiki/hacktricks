# Algoritmi di apprendimento supervisionato

{{#include ../banners/hacktricks-training.md}}

## Informazioni di base

L'apprendimento supervisionato utilizza dati etichettati per addestrare modelli in grado di effettuare previsioni su nuovi input non osservati. Nella cybersecurity, il machine learning supervisionato è ampiamente applicato ad attività come il rilevamento delle intrusioni (classificare il traffico di rete come *normale* o *attacco*), il rilevamento dei malware (distinguere il software malevolo da quello benigno), il rilevamento del phishing (identificare siti web o email fraudolenti) e il filtraggio dello spam, tra le altre.<sup>[[1]](#references)</sup> Ogni algoritmo ha i propri punti di forza ed è adatto a diversi tipi di problemi (classificazione o regressione). Di seguito analizziamo i principali algoritmi di apprendimento supervisionato, spieghiamo come funzionano e ne dimostriamo l'utilizzo su dataset reali di cybersecurity. Discutiamo inoltre di come la combinazione dei modelli (ensemble learning) possa spesso migliorare le prestazioni predittive.

## Algoritmi

-   **Linear Regression:** Un algoritmo di regressione fondamentale per prevedere risultati numerici adattando un'equazione lineare ai dati.

-   **Logistic Regression:** Un algoritmo di classificazione (nonostante il nome) che utilizza una funzione logistica per modellare la probabilità di un risultato binario.

-   **Decision Trees:** Modelli strutturati ad albero che suddividono i dati in base alle feature per effettuare previsioni; spesso utilizzati per la loro interpretabilità.

-   **Random Forests:** Un ensemble di alberi decisionali (tramite bagging) che migliora la precisione e riduce l'overfitting.

-   **Support Vector Machines (SVM):** Classificatori a margine massimo che individuano l'iperpiano di separazione ottimale; possono utilizzare kernel per dati non lineari.

-   **Naive Bayes:** Un classificatore probabilistico basato sul teorema di Bayes, con l'assunzione di indipendenza tra le feature, notoriamente utilizzato nel filtraggio dello spam.

-   **k-Nearest Neighbors (k-NN):** Un semplice classificatore "instance-based" che assegna un'etichetta a un campione in base alla classe maggioritaria dei suoi vicini più prossimi.

-   **Gradient Boosting Machines:** Modelli ensemble (ad es., XGBoost, LightGBM) che costruiscono un predittore efficace aggiungendo in sequenza learner più deboli (tipicamente alberi decisionali).

Ogni sezione seguente fornisce una descrizione migliorata dell'algoritmo e un **esempio di codice Python** utilizzando librerie come `pandas` e `scikit-learn` (e `PyTorch` per l'esempio della rete neurale). Gli esempi utilizzano dataset di cybersecurity disponibili pubblicamente (come NSL-KDD per il rilevamento delle intrusioni e un dataset di Phishing Websites) e seguono una struttura coerente:

1.  **Caricare il dataset** (tramite download da URL, se disponibile).

2.  **Preprocessare i dati** (ad es., codificare le feature categoriche, scalare i valori, suddividere i dati in set di training e test).

3.  **Addestrare il modello** sui dati di training.

4.  **Valutare** il modello su un set di test utilizzando le metriche: accuracy, precision, recall, F1-score e ROC AUC per la classificazione (e mean squared error per la regressione).

Analizziamo ora ogni algoritmo:

### Linear Regression

La regressione lineare è un algoritmo di **regressione** utilizzato per prevedere valori numerici continui. Presuppone una relazione lineare tra le feature di input (variabili indipendenti) e l'output (variabile dipendente). Il modello cerca di adattare una retta (o un iperpiano in dimensioni superiori) che descriva al meglio la relazione tra le feature e il target. In genere, ciò viene ottenuto minimizzando la somma degli errori quadratici tra i valori previsti e quelli effettivi (metodo dei minimi quadrati ordinari).<sup>[[2]](#references)</sup>

Il modo più semplice per rappresentare la regressione lineare è tramite una retta:
```plaintext
y = mx + b
```
Dove:

- `y` è il valore previsto (output)
- `m` è la pendenza della retta (coefficiente)
- `x` è la feature di input
- `b` è l'intercetta sull'asse y

L'obiettivo della regressione lineare è trovare la retta più adatta che minimizzi la differenza tra i valori previsti e i valori effettivi nel dataset. Naturalmente, questo è molto semplice: sarebbe una retta che separa 2 categorie, ma se vengono aggiunte più dimensioni, la retta diventa più complessa:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Casi d'uso nella cybersecurity:* la regressione lineare è meno comune per le attività di sicurezza principali (che spesso sono problemi di classificazione), ma può essere applicata per prevedere risultati numerici. Ad esempio, si potrebbe usare la regressione lineare per **prevedere il volume del traffico di rete** o **stimare il numero di attacchi in un determinato periodo** sulla base di dati storici. Potrebbe anche prevedere un punteggio di rischio o il tempo previsto fino al rilevamento di un attacco, dati determinati parametri del sistema. Nella pratica, gli algoritmi di classificazione (come la regressione logistica o gli alberi) vengono usati più frequentemente per rilevare intrusioni o malware, ma la regressione lineare funge da base ed è utile per le analisi orientate alla regressione.

#### **Caratteristiche principali della regressione lineare:**

-   **Tipo di problema:** Regressione (previsione di valori continui). Non è adatta alla classificazione diretta a meno che non venga applicata una soglia all'output.

-   **Interpretabilità:** Alta -- i coefficienti sono semplici da interpretare e mostrano l'effetto lineare di ogni feature.

-   **Vantaggi:** Semplice e veloce; un buon punto di riferimento per le attività di regressione; funziona bene quando la relazione reale è approssimativamente lineare.

-   **Limitazioni:** Non è in grado di catturare relazioni complesse o non lineari (senza un feature engineering manuale); tende all'underfitting se le relazioni non sono lineari; è sensibile agli outlier, che possono distorcere i risultati.

-   **Individuazione del miglior adattamento:** Per trovare la retta di best fit che separa le possibili categorie, usiamo un metodo chiamato **Ordinary Least Squares (OLS)**. Questo metodo minimizza la somma delle differenze al quadrato tra i valori osservati e i valori previsti dal modello lineare.

<details>
<summary>Esempio -- Previsione della durata delle connessioni (regressione) in un dataset di intrusioni
</summary>
Di seguito dimostriamo la regressione lineare usando il dataset di cybersecurity NSL-KDD. Tratteremo questo come un problema di regressione, prevedendo la `duration` delle connessioni di rete sulla base di altre feature. (In realtà, `duration` è una delle feature di NSL-KDD; la usiamo qui solo per illustrare la regressione.) Carichiamo il dataset, lo pre-processiamo (codificando le feature categoriche), addestriamo un modello di regressione lineare e valutiamo il Mean Squared Error (MSE) e il punteggio R² su un test set.
```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error, r2_score

# ── 1. Column names taken from the NSL‑KDD documentation ──────────────
col_names = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root",
"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login","count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

# ── 2. Load data *without* header row ─────────────────────────────────
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ── 3. Encode the 3 nominal features ─────────────────────────────────
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# ── 4. Prepare features / target ─────────────────────────────────────
X_train = df_train.drop(columns=['class', 'difficulty_level', 'duration'])
y_train = df_train['duration']

X_test  = df_test.drop(columns=['class', 'difficulty_level', 'duration'])
y_test  = df_test['duration']

# ── 5. Train & evaluate simple Linear Regression ─────────────────────
model = LinearRegression().fit(X_train, y_train)
y_pred = model.predict(X_test)

print(f"Test MSE: {mean_squared_error(y_test, y_pred):.2f}")
print(f"Test R² : {r2_score(y_test, y_pred):.3f}")

"""
Test MSE: 3021333.56
Test R² : -0.526
"""
```
In questo esempio, il modello di regressione lineare cerca di prevedere la `duration` della connessione a partire da altre caratteristiche della rete. Misuriamo le prestazioni con il Mean Squared Error (MSE) e R². Un valore di R² vicino a 1.0 indicherebbe che il modello spiega la maggior parte della varianza di `duration`, mentre un valore di R² basso o negativo indica un adattamento scarso. (Non sorprende se il valore di R² è basso in questo caso: prevedere `duration` potrebbe essere difficile utilizzando le caratteristiche fornite e la regressione lineare potrebbe non riuscire a cogliere i pattern se sono complessi.)
</details>

### Regressione logistica

La regressione logistica è un algoritmo di **classificazione** che modella la probabilità che un'istanza appartenga a una determinata classe (in genere la classe "positiva"). Nonostante il nome, la regressione *logistica* viene utilizzata per risultati discreti (a differenza della regressione lineare, usata per risultati continui). Viene utilizzata soprattutto per la **classificazione binaria** (due classi, ad esempio malicious rispetto a benign), ma può essere estesa a problemi multi-classe (utilizzando approcci softmax o one-vs-rest).<sup>[[3]](#references)</sup>

La regressione logistica utilizza la funzione logistica (nota anche come funzione sigmoide) per mappare i valori previsti in probabilità. Si noti che la funzione sigmoide è una funzione con valori compresi tra 0 e 1 che cresce secondo una curva a forma di S, in base alle esigenze della classificazione, il che è utile per i task di classificazione binaria. Pertanto, ogni caratteristica di ciascun input viene moltiplicata per il peso assegnato e il risultato viene passato attraverso la funzione sigmoide per produrre una probabilità:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Dove:

- `p(y=1|x)` è la probabilità che l'output `y` sia 1 dato l'input `x`
- `e` è la base del logaritmo naturale
- `z` è una combinazione lineare delle feature di input, tipicamente rappresentata come `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Nota come, anche in questo caso, nella sua forma più semplice sia una linea retta, ma nei casi più complessi diventi un iperpiano con diverse dimensioni (una per feature).

> [!TIP]
> *Casi d'uso nella cybersecurity:* Poiché molti problemi di sicurezza sono essenzialmente decisioni sì/no, la regressione logistica è ampiamente utilizzata. Ad esempio, un sistema di rilevamento delle intrusioni potrebbe usare la regressione logistica per decidere se una connessione di rete è un attacco sulla base delle feature di quella connessione. Nel rilevamento del phishing, la regressione logistica può combinare le feature di un sito web (lunghezza dell'URL, presenza del simbolo "@", ecc.) in una probabilità che si tratti di phishing. È stata utilizzata nei filtri antispam delle prime generazioni e rimane un solido baseline per molte attività di classificazione.

#### Regressione logistica per la classificazione non binaria

La regressione logistica è progettata per la classificazione binaria, ma può essere estesa per gestire problemi multi-classe utilizzando tecniche come **one-vs-rest** (OvR) o **softmax regression**. In OvR, viene addestrato un modello di regressione logistica separato per ogni classe, trattandola come classe positiva rispetto a tutte le altre. La classe con la probabilità predetta più alta viene scelta come previsione finale. La softmax regression generalizza la regressione logistica a più classi applicando la funzione softmax al livello di output e producendo una distribuzione di probabilità su tutte le classi.

#### **Caratteristiche principali della regressione logistica:**

-   **Tipo di problema:** Classificazione (solitamente binaria). Predice la probabilità della classe positiva.

-   **Interpretabilità:** Alta -- come nella regressione lineare, i coefficienti delle feature possono indicare come ciascuna feature influenza i log-odds del risultato. Questa trasparenza è spesso apprezzata nella sicurezza per comprendere quali fattori contribuiscono a un alert.

-   **Vantaggi:** Semplice e veloce da addestrare; funziona bene quando la relazione tra le feature e i log-odds del risultato è lineare. Produce probabilità, consentendo di assegnare un punteggio di rischio. Con una regolarizzazione appropriata, generalizza bene e può gestire la multicollinearità meglio della semplice regressione lineare.

-   **Limitazioni:** Presuppone un confine decisionale lineare nello spazio delle feature (fallisce se il confine reale è complesso/non lineare). Può avere prestazioni inferiori nei problemi in cui le interazioni o gli effetti non lineari sono fondamentali, a meno che non si aggiungano manualmente feature polinomiali o di interazione. Inoltre, la regressione logistica è meno efficace se le classi non sono facilmente separabili tramite una combinazione lineare delle feature.


<details>
<summary>Esempio -- Rilevamento di siti web di phishing con la regressione logistica:</summary>

Utilizzeremo un **Phishing Websites Dataset** (dal repository UCI), che contiene feature estratte dai siti web (come la presenza di un indirizzo IP nell'URL, l'età del dominio, la presenza di elementi sospetti nell'HTML, ecc.) e un'etichetta che indica se il sito è di phishing o legittimo.<sup>[[4]](#references)</sup> Addestriamo un modello di regressione logistica per classificare i siti web e valutiamo quindi la sua accuratezza, precisione, recall, F1-score e ROC AUC su uno split di test.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load dataset
data = fetch_openml(data_id=4534, as_frame=True)  # PhishingWebsites
df   = data.frame
print(df.head())

# 2. Target mapping ─ legitimate (1) → 0, everything else → 1
df['Result'] = df['Result'].astype(int)
y = (df['Result'] != 1).astype(int)

# 3. Features
X = df.drop(columns=['Result'])

# 4. Train/test split with stratify
## Stratify ensures balanced classes in train/test sets
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# 5. Scale
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 6. Logistic Regression
## L‑BFGS is a modern, memory‑efficient “quasi‑Newton” algorithm that works well for medium/large datasets and supports multiclass natively.
## Upper bound on how many optimization steps the solver may take before it gives up.	Not all steps are guaranteed to be taken, but would be the maximum before a "failed to converge" error.
clf = LogisticRegression(max_iter=1000, solver='lbfgs', random_state=42)
clf.fit(X_train, y_train)

# 7. Evaluation
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1-score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.928
Precision: 0.934
Recall   : 0.901
F1-score : 0.917
ROC AUC  : 0.979
"""
```
In questo esempio di rilevamento del phishing, la regressione logistica produce una probabilità che indica se ciascun sito web è di phishing. Valutando accuratezza, precisione, richiamo e F1, otteniamo un'idea delle prestazioni del modello. Ad esempio, un richiamo elevato significherebbe che rileva la maggior parte dei siti di phishing (importante per la sicurezza, al fine di ridurre al minimo gli attacchi mancati), mentre un'elevata precisione significa che genera pochi falsi allarmi (importante per evitare l'affaticamento degli analisti). La ROC AUC (Area Under the ROC Curve) fornisce una misura delle prestazioni indipendente dalla soglia (1.0 è il valore ideale, 0.5 non è migliore del caso). La regressione logistica spesso offre buone prestazioni in attività di questo tipo, ma se il confine decisionale tra siti di phishing e siti legittimi è complesso, potrebbero essere necessari modelli non lineari più potenti.

</details>

### Alberi decisionali

Un albero decisionale è un versatile **algoritmo di apprendimento supervisionato** che può essere utilizzato sia per attività di classificazione sia di regressione. Apprende un modello gerarchico, simile a un albero, delle decisioni basate sulle caratteristiche dei dati. Ogni nodo interno dell'albero rappresenta un test su una determinata caratteristica, ogni ramo rappresenta un risultato di tale test e ogni nodo foglia rappresenta una classe prevista (per la classificazione) o un valore (per la regressione).<sup>[[5]](#references)</sup>

Per costruire un albero, algoritmi come CART (Classification and Regression Tree) utilizzano misure quali **impurità di Gini** o **guadagno informativo (entropia)** per scegliere la caratteristica e la soglia migliori con cui suddividere i dati a ogni passaggio. L'obiettivo di ogni suddivisione è partizionare i dati per aumentare l'omogeneità della variabile target nei sottoinsiemi risultanti (per la classificazione, ogni nodo mira a essere il più puro possibile, contenendo prevalentemente una singola classe).

Gli alberi decisionali sono **altamente interpretabili** -- è possibile seguire il percorso dalla radice alla foglia per comprendere la logica alla base di una previsione (ad esempio, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Questo è utile nella cybersecurity per spiegare perché è stato generato un determinato alert. Gli alberi possono gestire naturalmente sia dati numerici sia dati categorici e richiedono un preprocessing minimo (ad esempio, non è necessario effettuare il feature scaling).

Tuttavia, un singolo albero decisionale può facilmente adattarsi eccessivamente ai dati di training, soprattutto se viene sviluppato in profondità (con molte suddivisioni). Per prevenire l'overfitting vengono spesso utilizzate tecniche come il pruning (limitare la profondità dell'albero o richiedere un numero minimo di campioni per foglia).

Un albero decisionale ha 3 componenti principali:
- **Nodo radice**: il nodo superiore dell'albero, che rappresenta l'intero dataset.
- **Nodi interni**: nodi che rappresentano caratteristiche e decisioni basate su tali caratteristiche.
- **Nodi foglia**: nodi che rappresentano il risultato finale o la previsione.

Un albero potrebbe avere un aspetto simile al seguente:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Casi d'uso nella cybersecurity:* Gli alberi decisionali sono stati utilizzati nei sistemi di rilevamento delle intrusioni per ricavare **regole** utili a identificare gli attacchi. Ad esempio, i primi IDS basati su ID3/C4.5 generavano regole leggibili dall'uomo per distinguere il traffico normale da quello malevolo. Sono utilizzati anche nell'analisi dei malware per decidere se un file è malevolo in base ai suoi attributi (dimensione del file, entropia delle sezioni, chiamate API, ecc.). La chiarezza degli alberi decisionali li rende utili quando è necessaria trasparenza -- un analista può ispezionare l'albero per convalidare la logica di rilevamento.

#### **Caratteristiche principali degli alberi decisionali:**

-   **Tipo di problema:** Sia classificazione che regressione. Comunemente utilizzati per la classificazione degli attacchi rispetto al traffico normale, ecc.

-   **Interpretabilità:** Molto elevata -- le decisioni del modello possono essere visualizzate e comprese come un insieme di regole if-then. Questo è un vantaggio importante nella sicurezza per garantire la fiducia e la verifica del comportamento del modello.

-   **Vantaggi:** Possono catturare relazioni non lineari e interazioni tra le feature (ogni suddivisione può essere vista come un'interazione). Non è necessario scalare le feature o applicare il one-hot encoding alle variabili categoriche -- gli alberi le gestiscono nativamente. Inferenza veloce (la previsione consiste semplicemente nel seguire un percorso nell'albero).

-   **Limitazioni:** Sono soggetti all'overfitting se non vengono controllati (un albero profondo può memorizzare il training set). Possono essere instabili -- piccoli cambiamenti nei dati possono portare a una struttura dell'albero diversa. Come modelli singoli, la loro accuratezza potrebbe non essere paragonabile a quella di metodi più avanzati (gli ensemble come Random Forests generalmente offrono prestazioni migliori riducendo la varianza).

-   **Individuazione della suddivisione migliore:**
- **Gini Impurity**: Misura l'impurità di un nodo. Un'impurità Gini più bassa indica una suddivisione migliore. La formula è:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Dove `p_i` è la proporzione di istanze nella classe `i`.

- **Entropy**: Misura l'incertezza nel dataset. Un'entropia più bassa indica una suddivisione migliore. La formula è:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Dove `p_i` è la proporzione di istanze nella classe `i`.

- **Information Gain**: La riduzione dell'entropia o dell'impurità Gini dopo una suddivisione. Maggiore è l'information gain, migliore è la suddivisione. Viene calcolato come segue:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Inoltre, un albero termina quando:
- Tutte le istanze in un nodo appartengono alla stessa classe. Questo potrebbe portare all'overfitting.
- Viene raggiunta la profondità massima (hardcoded) dell'albero. Questo è un modo per prevenire l'overfitting.
- Il numero di istanze in un nodo è inferiore a una determinata soglia. Anche questo è un modo per prevenire l'overfitting.
- L'information gain derivante da ulteriori suddivisioni è inferiore a una determinata soglia. Anche questo è un modo per prevenire l'overfitting.

<details>
<summary>Esempio -- Albero decisionale per il rilevamento delle intrusioni:</summary>
Addestreremo un albero decisionale sul dataset NSL-KDD per classificare le connessioni di rete come *normali* o *attacchi*. NSL-KDD è una versione migliorata del classico dataset KDD Cup 1999, con feature come il tipo di protocollo, il servizio, la durata, il numero di accessi non riusciti, ecc., e un'etichetta che indica il tipo di attacco o "normale". Mapperemo tutti i tipi di attacco nella classe "anomalia" (classificazione binaria: normale rispetto ad anomalia). Dopo l'addestramento, valuteremo le prestazioni dell'albero sul test set.
```python
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣  NSL‑KDD column names (41 features + class + difficulty)
col_names = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
"root_shell","su_attempted","num_root","num_file_creations","num_shells",
"num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
"srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
"same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
"dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
"class","difficulty_level"
]

# 2️⃣  Load data ➜ *headerless* CSV
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 3️⃣  Encode the 3 nominal features
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# 4️⃣  Prepare X / y   (binary: 0 = normal, 1 = attack)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
y_train = (df_train['class'].str.lower() != 'normal').astype(int)

X_test  = df_test.drop(columns=['class', 'difficulty_level'])
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# 5️⃣  Train Decision‑Tree
clf = DecisionTreeClassifier(max_depth=10, random_state=42)
clf.fit(X_train, y_train)

# 6️⃣  Evaluate
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")


"""
Accuracy : 0.772
Precision: 0.967
Recall   : 0.621
F1‑score : 0.756
ROC AUC  : 0.758
"""
```
In questo esempio di decision tree, abbiamo limitato la profondità dell'albero a 10 per evitare un overfitting estremo (il parametro `max_depth=10`). Le metriche mostrano quanto bene l'albero distingua il traffico normale da quello di attacco. Un recall elevato significherebbe rilevare la maggior parte degli attacchi (aspetto importante per un IDS), mentre una precision elevata indica pochi falsi allarmi. I decision tree spesso raggiungono una accuracy adeguata sui dati strutturati, ma un singolo albero potrebbe non raggiungere le migliori prestazioni possibili. Tuttavia, l'*interpretabilità* del modello rappresenta un grande vantaggio -- potremmo esaminare gli split dell'albero per capire, ad esempio, quali feature (come `service`, `src_bytes`, ecc.) siano più influenti nel segnalare una connessione come malevola.

</details>

### Random Forests

Random Forest è un metodo di **ensemble learning** che si basa sui decision tree per migliorare le prestazioni. Una random forest addestra diversi decision tree (da qui il termine "forest") e combina i loro output per elaborare una predizione finale (per la classificazione, in genere tramite majority vote). Le due idee principali alla base di una random forest sono il **bagging** (bootstrap aggregating) e la **feature randomness**:

-   **Bagging:** ogni albero viene addestrato su un campione bootstrap casuale dei dati di training (campionato con reinserimento). Questo introduce diversità tra gli alberi.

-   **Feature Randomness:** a ogni split di un albero, viene considerato un sottoinsieme casuale di feature per lo split (anziché tutte le feature). Questo riduce ulteriormente la correlazione tra gli alberi.

Facendo la media dei risultati di molti alberi, la random forest riduce la varianza che potrebbe avere un singolo decision tree. In termini semplici, i singoli alberi potrebbero fare overfitting o produrre risultati rumorosi, ma un elevato numero di alberi diversificati che votano insieme attenua questi errori. Il risultato è spesso un modello con **accuracy più elevata** e una migliore capacità di generalizzazione rispetto a un singolo decision tree. Inoltre, le random forest possono fornire una stima dell'importanza delle feature (osservando quanto ogni split basato su una feature riduca in media l'impurità).

Le random forest sono diventate un **workhorse nella cybersecurity** per attività come intrusion detection, malware classification e spam detection. Spesso offrono buone prestazioni out-of-the-box con un tuning minimo e possono gestire grandi insiemi di feature. Ad esempio, nell'intrusion detection, una random forest può superare un singolo decision tree rilevando pattern di attacco più sottili con meno falsi positivi. La ricerca ha dimostrato che le random forest ottengono risultati favorevoli rispetto ad altri algoritmi nella classificazione degli attacchi in dataset come NSL-KDD e UNSW-NB15.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Caratteristiche principali delle Random Forests:**

-   **Tipo di problema:** principalmente classificazione (utilizzate anche per la regressione). Sono particolarmente adatte ai dati strutturati ad alta dimensionalità, comuni nei security log.

-   **Interpretabilità:** inferiore rispetto a un singolo decision tree -- non è facile visualizzare o spiegare centinaia di alberi contemporaneamente. Tuttavia, gli score di importanza delle feature forniscono alcune indicazioni su quali attributi siano più influenti.

-   **Vantaggi:** accuracy generalmente più elevata rispetto ai modelli basati su un singolo albero grazie all'effetto dell'ensemble. Robuste all'overfitting -- anche se i singoli alberi fanno overfitting, l'ensemble generalizza meglio. Gestiscono feature numeriche e categoriche e possono gestire in una certa misura i dati mancanti. Sono inoltre relativamente robuste agli outlier.

-   **Limitazioni:** le dimensioni del modello possono essere elevate (molti alberi, ciascuno potenzialmente profondo). Le predizioni sono più lente rispetto a quelle di un singolo albero (poiché è necessario aggregare i risultati di molti alberi). Sono meno interpretabili -- sebbene si conoscano le feature importanti, la logica esatta non è facilmente tracciabile come una semplice regola. Se il dataset è estremamente ad alta dimensionalità e sparso, addestrare una forest molto grande può essere oneroso dal punto di vista computazionale.

-   **Processo di training:**
1. **Bootstrap Sampling**: campionare casualmente i dati di training con reinserimento per creare più sottoinsiemi (campioni bootstrap).
2. **Tree Construction**: per ogni campione bootstrap, costruire un decision tree utilizzando un sottoinsieme casuale di feature a ogni split. Questo introduce diversità tra gli alberi.
3. **Aggregation**: per le attività di classificazione, la predizione finale viene ottenuta tramite majority vote tra le predizioni di tutti gli alberi. Per le attività di regressione, la predizione finale è la media delle predizioni di tutti gli alberi.

<details>
<summary>Esempio -- Random Forest per l'Intrusion Detection (NSL-KDD):</summary>
Utilizzeremo lo stesso dataset NSL-KDD (con etichette binarie: normale o anomalia) e addestreremo un classificatore Random Forest. Ci aspettiamo che la random forest ottenga prestazioni pari o superiori rispetto al singolo decision tree, grazie alla riduzione della varianza ottenuta tramite l'averaging dell'ensemble. La valuteremo con le stesse metriche.
```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1. LOAD DATA  ➜  files have **no header row**, so we
#                 pass `header=None` and give our own column names.
# ──────────────────────────────────────────────
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ──────────────────────────────────────────────
# 2. PRE‑PROCESSING
# ──────────────────────────────────────────────
# 2‑a) Encode the three categorical columns so that the model
#      receives integers instead of strings.
#      LabelEncoder gives an int to each unique value in the column: {'icmp':0, 'tcp':1, 'udp':2}
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# 2‑b) Build feature matrix X  (drop target & difficulty)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
X_test  = df_test.drop(columns=['class', 'difficulty_level'])

# 2‑c) Convert multi‑class labels to binary
#      label 0 → 'normal' traffic, label 1 → any attack
y_train = (df_train['class'].str.lower() != 'normal').astype(int)
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# ──────────────────────────────────────────────
# 3. MODEL: RANDOM FOREST
# ──────────────────────────────────────────────
# • n_estimators = 100 ➜ build 100 different decision‑trees.
# • max_depth=None  ➜ let each tree grow until pure leaves
#                    (or until it hits other stopping criteria).
# • random_state=42 ➜ reproducible randomness.
model = RandomForestClassifier(
n_estimators=100,
max_depth=None,
random_state=42,
bootstrap=True          # default: each tree is trained on a
# bootstrap sample the same size as
# the original training set.
# max_samples           # ← you can set this (float or int) to
#     use a smaller % of samples per tree.
)

model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4. EVALUATION
# ──────────────────────────────────────────────
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.770
Precision: 0.966
Recall:    0.618
F1-score:  0.754
ROC AUC:   0.962
"""
```
La random forest raggiunge in genere risultati solidi in questo task di intrusion detection. Potremmo osservare un miglioramento in metriche come F1 o AUC rispetto al singolo decision tree, soprattutto in termini di recall o precision, a seconda dei dati. Questo è coerente con l'idea che *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> In un contesto di security operations, un modello random forest potrebbe segnalare gli attacchi in modo più affidabile riducendo al contempo i falsi allarmi, grazie alla media di molte decision rules. La feature importance della forest potrebbe indicare quali network features sono maggiormente indicative di attacchi (ad esempio, determinati network services o conteggi insoliti di pacchetti).

</details>

### Support Vector Machines (SVM)

Support Vector Machines sono potenti modelli di supervised learning utilizzati principalmente per la classificazione (e anche per la regressione come SVR). Un SVM cerca di trovare l'**optimal separating hyperplane** che massimizza il margine tra due classi. Solo un sottoinsieme dei training points (i "support vectors" più vicini al confine) determina la posizione di questo hyperplane. Massimizzando il margine (la distanza tra i support vectors e l'hyperplane), gli SVM tendono a ottenere una buona generalizzazione.<sup>[[8]](#references)</sup>

Un elemento fondamentale della potenza degli SVM è la possibilità di utilizzare **kernel functions** per gestire relazioni non lineari. I dati possono essere trasformati implicitamente in uno feature space a dimensionalità maggiore, dove potrebbe esistere un separatore lineare. I kernel comuni includono polynomial, radial basis function (RBF) e sigmoid. Ad esempio, se le classi del network traffic non sono linearmente separabili nel feature space originale, un kernel RBF può mapparle in una dimensione maggiore, dove l'SVM trova una separazione lineare (che corrisponde a un confine non lineare nello spazio originale). La flessibilità nella scelta dei kernel consente agli SVM di affrontare diversi tipi di problemi.

Gli SVM sono noti per le buone prestazioni in situazioni con feature space ad alta dimensionalità (come i dati testuali o le sequenze di opcode dei malware) e nei casi in cui il numero di feature è elevato rispetto al numero di sample. Sono stati popolari in molte applicazioni di cybersecurity dei primi anni 2000, come la classificazione dei malware e l'anomaly-based intrusion detection, mostrando spesso un'elevata accuratezza.

Tuttavia, gli SVM non scalano facilmente a dataset molto grandi (la complessità del training è super-lineare rispetto al numero di sample e l'utilizzo di memoria può essere elevato, poiché potrebbe essere necessario memorizzare molti support vectors). Nella pratica, per task come la network intrusion detection con milioni di record, un SVM potrebbe essere troppo lento senza un subsampling accurato o l'utilizzo di metodi approssimati.

#### **Caratteristiche principali degli SVM:**

-   **Tipo di problema:** Classification (binary o multiclass tramite one-vs-one/one-vs-rest) e varianti per la regression. Spesso utilizzati nella binary classification con una chiara separazione del margine.

-   **Interpretabilità:** Media -- gli SVM non sono interpretabili quanto i decision trees o la logistic regression. Sebbene sia possibile identificare quali data points sono support vectors e ottenere una certa indicazione sulle feature potenzialmente influenti (attraverso i pesi nel caso del linear kernel), nella pratica gli SVM (soprattutto con kernel non lineari) vengono trattati come black-box classifiers.

-   **Vantaggi:** Efficaci negli spazi ad alta dimensionalità; possono modellare decision boundaries complessi tramite il kernel trick; robusti all'overfitting quando il margine è massimizzato (soprattutto con un parametro di regularization C appropriato); funzionano bene anche quando le classi non sono separate da una grande distanza (trovano il miglior compromesso per il boundary).

-   **Limitazioni:** **Computazionalmente intensivi** per dataset di grandi dimensioni (sia il training sia la prediction scalano male all'aumentare dei dati). Richiedono un tuning accurato dei parametri del kernel e della regularization (C, tipo di kernel, gamma per RBF, ecc.). Non forniscono direttamente output probabilistici (anche se è possibile utilizzare Platt scaling per ottenere le probabilità). Inoltre, gli SVM possono essere sensibili alla scelta dei parametri del kernel --- una scelta errata può causare underfitting o overfitting.

*Use cases nella cybersecurity:* gli SVM sono stati utilizzati nel **malware detection** (ad esempio, per classificare file sulla base di feature estratte o sequenze di opcode), nella **network anomaly detection** (classificando il traffic come normale o malevolo) e nella **phishing detection** (utilizzando feature degli URL). Ad esempio, un SVM potrebbe acquisire le feature di un'email (conteggi di determinate keyword, punteggi di reputazione del mittente, ecc.) e classificarla come phishing o legittima. Sono stati applicati anche all'**intrusion detection** su feature set come KDD, ottenendo spesso un'elevata accuratezza a fronte di un costo computazionale significativo.

<details>
<summary>Esempio -- SVM per la classificazione dei malware:</summary>
Utilizzeremo nuovamente il phishing website dataset, questa volta con un SVM. Poiché gli SVM possono essere lenti, se necessario utilizzeremo un sottoinsieme dei dati per il training (il dataset contiene circa 11k istanze, una quantità che un SVM può gestire ragionevolmente). Utilizzeremo un kernel RBF, una scelta comune per i dati non lineari, e abiliteremo le stime delle probabilità per calcolare la ROC AUC.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ─────────────────────────────────────────────────────────────
# 1️⃣  LOAD DATASET   (OpenML id 4534: “PhishingWebsites”)
#     • as_frame=True  ➜  returns a pandas DataFrame
# ─────────────────────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame
print(df.head())          # quick sanity‑check

# ─────────────────────────────────────────────────────────────
# 2️⃣  TARGET: 0 = legitimate, 1 = phishing
#     The raw column has values {1, 0, -1}:
#       1  → legitimate   → 0
#       0  &  -1          → phishing    → 1
# ─────────────────────────────────────────────────────────────
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split  (stratified keeps class proportions)
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# ─────────────────────────────────────────────────────────────
# 3️⃣  PRE‑PROCESS: Standardize features (mean‑0 / std‑1)
# ─────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# ─────────────────────────────────────────────────────────────
# 4️⃣  MODEL: RBF‑kernel SVM
#     • C=1.0         (regularization strength)
#     • gamma='scale' (1 / [n_features × var(X)])
#     • probability=True  → enable predict_proba for ROC‑AUC
# ─────────────────────────────────────────────────────────────
clf = SVC(kernel="rbf", C=1.0, gamma="scale",
probability=True, random_state=42)
clf.fit(X_train, y_train)

# ─────────────────────────────────────────────────────────────
# 5️⃣  EVALUATION
# ─────────────────────────────────────────────────────────────
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]   # P(class 1)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.956
Precision: 0.963
Recall   : 0.937
F1‑score : 0.950
ROC AUC  : 0.989
"""
```
Il modello SVM produrrà metriche che possiamo confrontare con la regressione logistica sullo stesso task. Potremmo scoprire che SVM raggiunge un'elevata accuratezza e un AUC elevato se i dati sono ben separati dalle feature. Al contrario, se il dataset contenesse molto rumore o classi sovrapposte, SVM potrebbe non superare significativamente la regressione logistica. In pratica, SVM può offrire un miglioramento quando esistono relazioni complesse e non lineari tra le feature e la classe: il kernel RBF può catturare confini decisionali curvi che la regressione logistica non riuscirebbe a rilevare. Come per tutti i modelli, è necessaria un'attenta regolazione di `C` (regolarizzazione) e dei parametri del kernel (come `gamma` per RBF) per bilanciare bias e varianza.

</details>

#### Differenza tra regressione logistica e SVM

| Aspetto | **Regressione logistica** | **Support Vector Machines** |
|---|---|---|
| **Funzione obiettivo** | Minimizza la **log-loss** (cross-entropy). | Massimizza il **margine** minimizzando al contempo la **hinge-loss**. |
| **Confine decisionale** | Trova l'**iperpiano con il miglior adattamento** che modella _P(y\|x)_. | Trova l'**iperpiano a massimo margine** (la distanza più ampia dai punti più vicini). |
| **Output** | **Probabilistico** – fornisce probabilità di classe calibrate tramite σ(w·x + b). | **Deterministico** – restituisce etichette di classe; le probabilità richiedono un'elaborazione aggiuntiva (ad esempio il Platt scaling). |
| **Regolarizzazione** | L2 (predefinita) o L1, bilancia direttamente underfitting e overfitting. | Il parametro C bilancia l'ampiezza del margine e le classificazioni errate; i parametri del kernel aggiungono complessità. |
| **Kernel / Non linearità** | La forma nativa è **lineare**; la non linearità viene aggiunta tramite feature engineering. | Il **kernel trick** integrato (RBF, poly, ecc.) consente di modellare confini complessi in uno spazio ad alta dimensionalità. |
| **Scalabilità** | Risolve un'ottimizzazione convessa in **O(nd)**; gestisce bene valori di n molto grandi. | L'addestramento può richiedere **O(n²–n³)** in termini di memoria/tempo senza solver specializzati; è meno adatto a valori di n enormi. |
| **Interpretabilità** | **Elevata** – i pesi mostrano l'influenza delle feature; l'odds ratio è intuitivo. | **Bassa** per i kernel non lineari; i support vector sono sparsi, ma non sono facili da spiegare. |
| **Sensibilità agli outlier** | Utilizza una log-loss uniforme → è meno sensibile. | La hinge-loss con hard margin può essere **sensibile**; il soft-margin (C) contribuisce a mitigare il problema. |
| **Casi d'uso tipici** | Credit scoring, rischio medico, A/B testing – dove **probabilità e spiegabilità** sono importanti. | Classificazione di immagini/testi, bio-informatica – dove contano **confini complessi** e **dati ad alta dimensionalità**. |

* **Se hai bisogno di probabilità calibrate, interpretabilità o devi operare su dataset enormi — scegli la regressione logistica.**
* **Se hai bisogno di un modello flessibile in grado di catturare relazioni non lineari senza feature engineering manuale — scegli SVM (con i kernel).**
* Entrambi ottimizzano obiettivi convessi, quindi sono garantiti **minimi globali**, ma i kernel di SVM aggiungono iperparametri e costi computazionali.

### Naive Bayes

Naive Bayes è una famiglia di **classificatori probabilistici** basata sull'applicazione del teorema di Bayes con una forte assunzione di indipendenza tra le feature. Nonostante questa assunzione "ingenua", Naive Bayes spesso funziona sorprendentemente bene in alcune applicazioni, soprattutto quelle che coinvolgono dati testuali o categorici, come il rilevamento dello spam.<sup>[[9]](#references)</sup>


#### Teorema di Bayes

Il teorema di Bayes è il fondamento dei classificatori Naive Bayes. Mette in relazione le probabilità condizionate e marginali degli eventi casuali. La formula è:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Dove:
- `P(A|B)` è la probabilità a posteriori della classe `A` dato il feature `B`.
- `P(B|A)` è la verosimiglianza del feature `B` data la classe `A`.
- `P(A)` è la probabilità a priori della classe `A`.
- `P(B)` è la probabilità a priori del feature `B`.

Ad esempio, se vogliamo classificare se un testo è stato scritto da un bambino o da un adulto, possiamo usare le parole nel testo come feature. Sulla base di alcuni dati iniziali, il classificatore Naive Bayes calcolerà in anticipo le probabilità che ogni parola appartenga a ciascuna classe potenziale (bambino o adulto). Quando viene fornito un nuovo testo, calcolerà la probabilità di ciascuna classe potenziale date le parole presenti nel testo e sceglierà la classe con la probabilità più alta.

Come si può vedere in questo esempio, il classificatore Naive Bayes è molto semplice e veloce, ma presuppone che i feature siano indipendenti, cosa che non si verifica sempre nei dati del mondo reale.


#### Tipi di classificatori Naive Bayes

Esistono diversi tipi di classificatori Naive Bayes, a seconda del tipo di dati e della distribuzione dei feature:
- **Gaussian Naive Bayes**: presuppone che i feature seguano una distribuzione gaussiana (normale). È adatto ai dati continui.
- **Multinomial Naive Bayes**: presuppone che i feature seguano una distribuzione multinomiale. È adatto ai dati discreti, come il conteggio delle parole nella classificazione del testo.
- **Bernoulli Naive Bayes**: presuppone che i feature siano binari (0 o 1). È adatto ai dati binari, come la presenza o l'assenza di parole nella classificazione del testo.
- **Categorical Naive Bayes**: presuppone che i feature siano variabili categoriche. È adatto ai dati categorici, come la classificazione della frutta in base al colore e alla forma.


#### **Caratteristiche principali di Naive Bayes:**

-   **Tipo di problema:** classificazione (binaria o multi-classe). Comunemente utilizzato per attività di classificazione del testo nella cybersecurity (spam, phishing, ecc.).

-   **Interpretabilità:** media -- non è interpretabile direttamente quanto un decision tree, ma è possibile esaminare le probabilità apprese (ad esempio, quali parole sono più probabili nelle email di spam rispetto alle email ham). La struttura del modello (le probabilità di ciascun feature data la classe) può essere compresa se necessario.

-   **Vantaggi:** addestramento e predizione **molto veloci**, anche su dataset di grandi dimensioni (lineari rispetto al numero di istanze * numero di feature). Richiede una quantità relativamente ridotta di dati per stimare le probabilità in modo affidabile, soprattutto con un corretto smoothing. È spesso sorprendentemente accurato come baseline, specialmente quando i feature contribuiscono indipendentemente all'evidenza della classe. Funziona bene con dati ad alta dimensionalità (ad esempio, migliaia di feature derivati dal testo). Non richiede un tuning complesso oltre alla configurazione di un parametro di smoothing.

-   **Limitazioni:** l'ipotesi di indipendenza può limitare l'accuratezza se i feature sono altamente correlati. Ad esempio, nei dati di rete, feature come `src_bytes` e `dst_bytes` potrebbero essere correlati; Naive Bayes non catturerà questa interazione. Quando la dimensione dei dati cresce molto, modelli più espressivi (come gli ensemble o le reti neurali) possono superare NB imparando le dipendenze tra i feature. Inoltre, se per identificare un attacco è necessaria una determinata combinazione di feature (e non solo singoli feature indipendenti), NB avrà difficoltà.

> [!TIP]
> *Casi d'uso nella cybersecurity:* l'uso classico è il **rilevamento dello spam** -- Naive Bayes era il componente principale dei primi filtri antispam, che utilizzavano la frequenza di determinati token (parole, frasi, indirizzi IP) per calcolare la probabilità che un'email fosse spam. Viene utilizzato anche nel **rilevamento delle email di phishing** e nella **classificazione degli URL**, dove la presenza di determinate keyword o caratteristiche (come "login.php" in un URL o `@` in un percorso URL) contribuisce alla probabilità di phishing. Nell'analisi del malware, si potrebbe immaginare un classificatore Naive Bayes che utilizza la presenza di determinate chiamate API o autorizzazioni nel software per prevedere se si tratta di malware. Sebbene gli algoritmi più avanzati offrano spesso prestazioni migliori, Naive Bayes rimane una buona baseline grazie alla sua velocità e semplicità.

<details>
<summary>Esempio -- Naive Bayes per il rilevamento del phishing:</summary>
Per dimostrare Naive Bayes, utilizzeremo Gaussian Naive Bayes sul dataset di intrusioni NSL-KDD (con etichette binarie). Gaussian NB tratterà ogni feature come se seguisse una distribuzione normale per ciascuna classe. Si tratta di una scelta approssimativa, poiché molti feature di rete sono discreti o altamente asimmetrici, ma mostra come applicare NB a dati con feature continui. Potremmo anche scegliere Bernoulli NB su un dataset di feature binari (come un insieme di alert attivati), ma per continuità utilizzeremo qui NSL-KDD.
```python
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD data
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 2. Preprocess (encode categorical features, prepare binary labels)
from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])
X_train = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_train = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
X_test  = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test  = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 3. Train Gaussian Naive Bayes
model = GaussianNB()
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
# For ROC AUC, need probability of class 1:
y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.450
Precision: 0.937
Recall:    0.037
F1-score:  0.071
ROC AUC:   0.867
"""
```
Questo codice addestra un classificatore Naive Bayes per rilevare gli attacchi. Naive Bayes calcolerà valori come `P(service=http | Attack)` e `P(Service=http | Normal)` in base ai dati di addestramento, assumendo l'indipendenza tra le feature. Utilizzerà quindi queste probabilità per classificare le nuove connessioni come normali o come attacchi, in base alle feature osservate. Le prestazioni di NB su NSL-KDD potrebbero non essere elevate quanto quelle dei modelli più avanzati (poiché l'indipendenza tra le feature non è rispettata), ma sono spesso discrete e offrono il vantaggio di una velocità estrema. In scenari come il filtraggio delle email in tempo reale o il triage iniziale degli URL, un modello Naive Bayes può segnalare rapidamente i casi palesemente malevoli con un utilizzo ridotto delle risorse.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors è uno degli algoritmi di machine learning più semplici. È un metodo **non parametrico, basato sulle istanze** che effettua previsioni in base alla similarità con gli esempi presenti nel training set. L'idea alla base della classificazione è: per classificare un nuovo punto dati, trovare i **k** punti più vicini nei dati di addestramento (i suoi "nearest neighbors") e assegnare la classe maggioritaria tra questi vicini. La "vicinanza" è definita da una metrica di distanza, in genere la distanza euclidea per i dati numerici (è possibile utilizzare altre distanze per diversi tipi di feature o problemi).<sup>[[10]](#references)</sup>

K-NN non richiede un *training esplicito* -- la fase di "training" consiste semplicemente nel memorizzare il dataset. Tutto il lavoro avviene durante la query (prediction): l'algoritmo deve calcolare le distanze dal punto della query a tutti i punti di training per trovare quelli più vicini. Questo rende il tempo di prediction **lineare rispetto al numero di campioni di training**, il che può essere costoso per dataset di grandi dimensioni. Per questo motivo, k-NN è più adatto a dataset più piccoli o a scenari in cui è possibile sacrificare memoria e velocità in favore della semplicità.

Nonostante la sua semplicità, k-NN può modellare decision boundary molto complesse (poiché, di fatto, la decision boundary può assumere qualsiasi forma determinata dalla distribuzione degli esempi). Tende a funzionare bene quando la decision boundary è molto irregolare e sono disponibili molti dati -- lasciando essenzialmente che siano i dati a "parlare da soli". Tuttavia, in dimensioni elevate, le metriche di distanza possono diventare meno significative (curse of dimensionality) e il metodo può incontrare difficoltà, a meno di disporre di un numero enorme di campioni.

*Use cases in cybersecurity:* k-NN è stato applicato all'anomaly detection -- per esempio, un intrusion detection system potrebbe etichettare un evento di rete come malevolo se la maggior parte dei suoi nearest neighbors (eventi precedenti) era malevola. Se il traffico normale forma dei cluster e gli attacchi sono outlier, un approccio K-NN (con k=1 o un valore k ridotto) equivale essenzialmente a una **nearest-neighbor anomaly detection**. K-NN è stato utilizzato anche per classificare le famiglie di malware tramite vettori di feature binarie: un nuovo file potrebbe essere classificato come appartenente a una determinata famiglia di malware se è molto vicino (nello spazio delle feature) a istanze note di quella famiglia. In pratica, k-NN non è comune quanto gli algoritmi più scalabili, ma è concettualmente semplice e talvolta viene utilizzato come baseline o per problemi su piccola scala.

#### **Caratteristiche principali di k-NN:**

-   **Tipo di problema:** classificazione (esistono anche varianti per la regressione). È un metodo di *lazy learning* -- non esegue il fitting esplicito di un modello.

-   **Interpretabilità:** da bassa a media -- non esiste un modello globale o una spiegazione concisa, ma è possibile interpretare i risultati osservando i nearest neighbors che hanno influenzato una decisione (ad esempio, "questo network flow è stato classificato come malevolo perché è simile a questi 3 network flow malevoli noti"). Le spiegazioni possono quindi essere basate sugli esempi.

-   **Vantaggi:** molto semplice da implementare e comprendere. Non fa ipotesi sulla distribuzione dei dati (non parametrico). Può gestire naturalmente problemi multi-classe. È **adattivo**, nel senso che le decision boundary possono essere molto complesse e modellate dalla distribuzione dei dati.

-   **Limitazioni:** la prediction può essere lenta per dataset di grandi dimensioni (è necessario calcolare molte distanze). Richiede molta memoria -- memorizza tutti i dati di training. Le prestazioni peggiorano negli spazi delle feature ad alta dimensionalità perché tutti i punti tendono a diventare quasi equidistanti (rendendo meno significativo il concetto di "più vicino"). È necessario scegliere *k* (il numero di vicini) in modo appropriato -- un valore k troppo piccolo può produrre rumore, mentre un valore k troppo grande può includere punti irrilevanti di altre classi. Inoltre, le feature devono essere scalate correttamente, perché i calcoli delle distanze sono sensibili alla scala.

<details>
<summary>Esempio -- k-NN per il rilevamento del phishing:</summary>

Utilizzeremo nuovamente NSL-KDD (classificazione binaria). Poiché k-NN è computazionalmente pesante, useremo un sottoinsieme dei dati di training per mantenere la dimostrazione gestibile. Sceglieremo, ad esempio, 20.000 campioni di training sui 125.000 complessivi e useremo 5 vicini k=5. Dopo il training (in realtà, si tratta semplicemente di memorizzare i dati), valuteremo il modello sul test set. Inoltre, scaleremo le feature per il calcolo delle distanze, così da garantire che nessuna singola feature domini a causa della propria scala.
```python
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD and preprocess similarly
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])
X = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
# Use a random subset of the training data for K-NN (to reduce computation)
X_train = X.sample(n=20000, random_state=42)
y_train = y[X_train.index]
# Use the full test set for evaluation
X_test = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 2. Feature scaling for distance-based model
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 3. Train k-NN classifier (store data)
model = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.780
Precision: 0.972
Recall:    0.632
F1-score:  0.766
ROC AUC:   0.837
"""
```
Il modello k-NN classificherà una connessione osservando le 5 connessioni più vicine nel sottoinsieme del training set. Se, ad esempio, 4 di questi vicini sono attacchi (anomalie) e 1 è normale, la nuova connessione verrà classificata come attacco. Le performance potrebbero essere ragionevoli, anche se spesso non raggiungono quelle di un Random Forest o SVM ben ottimizzato sugli stessi dati. Tuttavia, k-NN può talvolta eccellere quando le distribuzioni delle classi sono molto irregolari e complesse, utilizzando di fatto una ricerca basata sulla memoria. Nella cybersecurity, k-NN (con k=1 o un k piccolo) potrebbe essere utilizzato per rilevare pattern di attacco noti tramite esempi, oppure come componente di sistemi più complessi (ad esempio, per il clustering e la successiva classificazione in base all'appartenenza a un cluster).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines sono tra gli algoritmi più potenti per i dati strutturati. **Gradient boosting** si riferisce alla tecnica di costruzione di un ensemble di weak learner (spesso alberi decisionali) in modo sequenziale, in cui ogni nuovo modello corregge gli errori dell'ensemble precedente. A differenza del bagging (Random Forests), che costruisce gli alberi in parallelo e ne calcola la media, il boosting costruisce gli alberi *uno alla volta*, concentrandosi maggiormente sulle istanze classificate erroneamente dagli alberi precedenti.<sup>[[11]](#references)</sup>

Le implementazioni più popolari degli ultimi anni sono **XGBoost**, **LightGBM** e **CatBoost**, tutte librerie di gradient boosting decision tree (GBDT). Hanno avuto un enorme successo nelle competizioni e nelle applicazioni di machine learning, spesso **raggiungendo performance all'avanguardia sui dataset tabulari**. Nella cybersecurity, ricercatori e professionisti hanno utilizzato alberi con gradient boosting per attività come il **rilevamento di malware** (utilizzando feature estratte dai file o dal comportamento a runtime) e il **rilevamento delle intrusioni di rete**. Ad esempio, un modello di gradient boosting può combinare molte regole deboli (alberi), come "se ci sono molti pacchetti SYN e una porta insolita -> probabile scan", in un potente detector composito che tiene conto di molti pattern sottili.

Perché gli alberi boosted sono così efficaci? Ogni albero nella sequenza viene addestrato sugli *errori residui* (gradienti) delle predizioni dell'ensemble corrente. In questo modo, il modello **"potenzia"** gradualmente le aree in cui è debole. L'uso degli alberi decisionali come base learner consente al modello finale di catturare interazioni complesse e relazioni non lineari. Inoltre, il boosting dispone intrinsecamente di una forma di regolarizzazione integrata: aggiungendo molti alberi piccoli (e utilizzando un learning rate per ridimensionare il loro contributo), spesso generalizza bene senza un overfitting eccessivo, purché vengano scelti parametri adeguati.

#### **Caratteristiche principali del Gradient Boosting:**

-   **Tipo di problema:** principalmente classificazione e regressione. In ambito security, generalmente classificazione (ad esempio, classificare in modo binario una connessione o un file). Gestisce problemi binari, multi-classe (con una loss appropriata) e persino problemi di ranking.

-   **Interpretabilità:** da bassa a media. Sebbene un singolo albero boosted sia piccolo, un modello completo può avere centinaia di alberi, risultando non interpretabile dall'essere umano nel suo insieme. Tuttavia, come Random Forest, può fornire punteggi di importanza delle feature e strumenti come SHAP (SHapley Additive exPlanations) possono essere utilizzati per interpretare in una certa misura le singole predizioni.

-   **Vantaggi:** spesso l'algoritmo con le **migliori performance** per i dati strutturati/tabulari. Può rilevare pattern e interazioni complesse. Dispone di numerosi parametri regolabili (numero di alberi, profondità degli alberi, learning rate, termini di regolarizzazione) per adattare la complessità del modello e prevenire l'overfitting. Le implementazioni moderne sono ottimizzate per la velocità (ad esempio, XGBoost utilizza informazioni sul gradiente del secondo ordine e strutture dati efficienti). Tende a gestire meglio i dati sbilanciati quando viene combinato con funzioni di loss appropriate o regolando i sample weight.

-   **Limitazioni:** è più complesso da ottimizzare rispetto ai modelli più semplici; il training può essere lento se gli alberi sono profondi o il numero di alberi è elevato (anche se generalmente è comunque più veloce dell'addestramento di una deep neural network comparabile sugli stessi dati). Il modello può andare in overfit se non viene ottimizzato (ad esempio, troppi alberi profondi con una regolarizzazione insufficiente). A causa dei numerosi hyperparameter, utilizzare efficacemente il gradient boosting può richiedere maggiore esperienza o sperimentazione. Inoltre, come i metodi basati sugli alberi, non gestisce intrinsecamente i dati molto sparsi e ad alta dimensionalità con la stessa efficienza dei modelli lineari o di Naive Bayes (sebbene possa comunque essere applicato, ad esempio nella classificazione del testo, ma potrebbe non essere la prima scelta senza feature engineering).

> [!TIP]
> *Casi d'uso nella cybersecurity:* quasi ovunque potrebbe essere utilizzato un albero decisionale o un random forest, un modello di gradient boosting potrebbe ottenere un'accuratezza migliore. Ad esempio, nelle competizioni di **rilevamento di malware di Microsoft** è stato fatto ampio uso di XGBoost su feature ingegnerizzate estratte da file binari. La ricerca sul **rilevamento delle intrusioni di rete** riporta spesso i risultati migliori con GBDT (ad esempio, XGBoost sui dataset CIC-IDS2017 o UNSW-NB15). Questi modelli possono utilizzare un'ampia gamma di feature (tipi di protocollo, frequenza di determinati eventi, feature statistiche del traffico, ecc.) e combinarle per rilevare le minacce. Nel rilevamento del phishing, il gradient boosting può combinare feature lessicali degli URL, feature relative alla reputazione del dominio e feature del contenuto delle pagine per ottenere un'accuratezza molto elevata. L'approccio ensemble aiuta a coprire numerosi casi limite e dettagli complessi presenti nei dati.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
Utilizzeremo un classificatore di gradient boosting sul dataset di phishing. Per mantenere le cose semplici e autosufficienti, utilizzeremo `sklearn.ensemble.GradientBoostingClassifier` (che è un'implementazione più lenta ma lineare). Normalmente, si potrebbero utilizzare le librerie `xgboost` o `lightgbm` per ottenere performance migliori e funzionalità aggiuntive. Addestreremo il modello e ne valuteremo le performance in modo analogo a prima.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣ Load the “Phishing Websites” data directly from OpenML
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame

# 2️⃣ Separate features/target & make sure everything is numeric
X = df.drop(columns=["Result"])
y = df["Result"].astype(int).apply(lambda v: 1 if v == 1 else 0)  # map {-1,1} → {0,1}

# (If any column is still object‑typed, coerce it to numeric.)
X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

# 3️⃣ Train/test split
X_train, X_test, y_train, y_test = train_test_split(
X.values, y, test_size=0.20, random_state=42
)

# 4️⃣ Gradient Boosting model
model = GradientBoostingClassifier(
n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42
)
model.fit(X_train, y_train)

# 5️⃣ Evaluation
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.951
Precision: 0.949
Recall:    0.965
F1‑score:  0.957
ROC AUC:   0.990
"""
```
Il modello gradient boosting probabilmente raggiungerà un'accuratezza e un'AUC molto elevate su questo dataset di phishing (spesso questi modelli possono superare il 95% di accuratezza con un'adeguata ottimizzazione su dati di questo tipo, come osservato nella letteratura. Questo dimostra perché i GBDT sono considerati *"il modello all'avanguardia per i dataset tabulari"* -- spesso superano gli algoritmi più semplici catturando pattern complessi.<sup>[[11]](#references)</sup> In un contesto di cybersecurity, ciò potrebbe significare individuare più siti di phishing o attacchi con meno mancate rilevazioni. Naturalmente, è necessario prestare attenzione all'overfitting -- in genere utilizzeremmo tecniche come la cross-validation e monitoreremmo le prestazioni su un validation set durante lo sviluppo di un modello di questo tipo per il deployment.

</details>

### Combinazione di modelli: Ensemble Learning e Stacking

L'ensemble learning è una strategia che consiste nel **combinare più modelli** per migliorare le prestazioni complessive. Abbiamo già visto metodi ensemble specifici: Random Forest (un ensemble di alberi tramite bagging) e Gradient Boosting (un ensemble di alberi tramite boosting sequenziale). Tuttavia, gli ensemble possono essere creati anche in altri modi, ad esempio tramite **voting ensemble** o **stacked generalization (stacking)**. L'idea principale è che modelli diversi possano catturare pattern differenti o avere punti deboli diversi; combinandoli, possiamo **compensare gli errori di ciascun modello con i punti di forza degli altri**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** In un semplice classificatore a votazione, addestriamo più modelli diversificati (ad esempio, una regressione logistica, un decision tree e un SVM) e li facciamo votare sulla predizione finale (voto di maggioranza per la classificazione). Se assegniamo un peso ai voti (ad esempio, un peso maggiore ai modelli più accurati), otteniamo uno schema di weighted voting. Questo migliora generalmente le prestazioni quando i singoli modelli sono ragionevolmente validi e indipendenti -- l'ensemble riduce il rischio di errore da parte di un singolo modello, poiché gli altri possono correggerlo. È come avere un gruppo di esperti invece di una singola opinione.

-   **Stacking (Stacked Ensemble):** Lo stacking fa un passo ulteriore. Invece di una semplice votazione, addestra un **meta-modello** per **imparare a combinare al meglio le predizioni** dei modelli di base. Ad esempio, si addestrano 3 classificatori diversi (base learner), quindi si forniscono i loro output (o le probabilità) come feature a un meta-classificatore (spesso un modello semplice come la regressione logistica), che impara il modo ottimale di combinarli. Il meta-modello viene addestrato su un validation set o tramite cross-validation per evitare l'overfitting. Lo stacking può spesso superare il semplice voting imparando *a quali modelli affidarsi maggiormente in determinate circostanze*. In cybersecurity, un modello potrebbe essere più efficace nell'individuare le scansioni di rete, mentre un altro potrebbe essere più efficace nell'individuare il malware beaconing; un modello di stacking potrebbe imparare a fare affidamento su ciascuno nel modo appropriato.

Gli ensemble, sia tramite voting sia tramite stacking, tendono a **migliorare l'accuratezza** e la robustezza. Lo svantaggio è una maggiore complessità e, talvolta, una minore interpretabilità (anche se alcuni approcci ensemble, come la media di decision tree, possono comunque fornire alcune informazioni, ad esempio sulla feature importance). Nella pratica, se i vincoli operativi lo consentono, l'utilizzo di un ensemble può portare a tassi di rilevamento più elevati. Molte soluzioni vincenti nelle competizioni di cybersecurity (e nelle competizioni Kaggle in generale) utilizzano tecniche ensemble per ottenere l'ultimo margine di prestazioni.

<details>
<summary>Esempio -- Voting Ensemble per il rilevamento del phishing:</summary>
Per illustrare lo model stacking, combiniamo alcuni dei modelli discussi nel phishing dataset. Utilizzeremo una regressione logistica, un decision tree e un k-NN come base learner, e una Random Forest come meta-learner per aggregare le loro predizioni. Il meta-learner verrà addestrato sugli output dei base learner (utilizzando la cross-validation sul training set). Ci aspettiamo che il modello stacked abbia prestazioni pari o leggermente superiori a quelle dei singoli modelli.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import StackingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1️⃣  LOAD DATASET (OpenML id 4534)
# ──────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)     # “PhishingWebsites”
df   = data.frame

# Target mapping:  1 → legitimate (0),   0/‑1 → phishing (1)
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split (stratified to keep class balance)
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# ──────────────────────────────────────────────
# 2️⃣  DEFINE BASE LEARNERS
#     • LogisticRegression and k‑NN need scaling ➜ wrap them
#       in a Pipeline(StandardScaler → model) so that scaling
#       happens inside each CV fold of StackingClassifier.
# ──────────────────────────────────────────────
base_learners = [
('lr',  make_pipeline(StandardScaler(),
LogisticRegression(max_iter=1000,
solver='lbfgs',
random_state=42))),
('dt',  DecisionTreeClassifier(max_depth=5, random_state=42)),
('knn', make_pipeline(StandardScaler(),
KNeighborsClassifier(n_neighbors=5)))
]

# Meta‑learner (level‑2 model)
meta_learner = RandomForestClassifier(n_estimators=50, random_state=42)

stack_model = StackingClassifier(
estimators      = base_learners,
final_estimator = meta_learner,
cv              = 5,        # 5‑fold CV to create meta‑features
passthrough     = False     # only base learners’ predictions go to meta‑learner
)

# ──────────────────────────────────────────────
# 3️⃣  TRAIN ENSEMBLE
# ──────────────────────────────────────────────
stack_model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4️⃣  EVALUATE
# ──────────────────────────────────────────────
y_pred = stack_model.predict(X_test)
y_prob = stack_model.predict_proba(X_test)[:, 1]   # P(phishing)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.954
Precision: 0.951
Recall   : 0.946
F1‑score : 0.948
ROC AUC  : 0.992
"""
```
L'ensemble impilato sfrutta i punti di forza complementari dei modelli di base. Ad esempio, la regressione logistica potrebbe gestire gli aspetti lineari dei dati, l'albero decisionale potrebbe catturare interazioni specifiche simili a regole e k-NN potrebbe eccellere nei dintorni locali dello spazio delle feature. Il meta-modello (in questo caso una random forest) può imparare come ponderare questi input. Le metriche risultanti mostrano spesso un miglioramento (anche se lieve) rispetto alle metriche di qualsiasi singolo modello. Nel nostro esempio di phishing, se la regressione logistica avesse ottenuto da sola un F1 pari, ad esempio, a 0.95 e l'albero 0.94, lo stacking potrebbe raggiungere 0.96, compensando gli errori di ciascun modello.

I metodi ensemble come questo dimostrano il principio secondo cui *"la combinazione di più modelli porta generalmente a una migliore generalizzazione"*.<sup>[[12]](#references)</sup> Nella cybersecurity, questo può essere implementato disponendo di più motori di detection (uno potrebbe essere basato su regole, uno sul machine learning e uno sugli anomaly) e poi di un layer che aggrega i relativi alert -- di fatto una forma di ensemble -- per prendere una decisione finale con maggiore confidence. Quando si implementano sistemi di questo tipo, è necessario considerare la complessità aggiuntiva e assicurarsi che l'ensemble non diventi troppo difficile da gestire o da spiegare. Tuttavia, dal punto di vista dell'accuratezza, gli ensemble e lo stacking sono strumenti potenti per migliorare le performance del modello.

</details>

## Riferimenti

- [1] [AI e Machine Learning nella Cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Regressione lineare, spiegata - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Regressione logistica - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Classificazione degli attacchi di phishing e dei siti web tramite Machine Learning e dataset multipli (un'analisi comparativa)"](https://arxiv.org/pdf/2101.02552)
- [5] [Albero decisionale - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Rilevamento degli attacchi Denial of Services tramite Random Forest Classifier con Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Analisi delle performance dei modelli di machine learning per un sistema di intrusion detection tramite la tecnica di selezione delle feature Gini Impurity-based Weighted Random Forest (GIWRF)"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Che cos'è una Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Filtraggio dello spam con Naive Bayes - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [Che cos'è k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT: come funzionano LightGBM, XGBoost e CatBoost - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: migliorare le performance dei modelli combinandone i punti di forza - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Come il Deep Learning migliora i sistemi di intrusion detection](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)

{{#include ../banners/hacktricks-training.md}}
