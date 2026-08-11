# Algoritmi di Supervised Learning

{{#include ../banners/hacktricks-training.md}}

## Informazioni di base

Il supervised learning utilizza dati etichettati per addestrare modelli in grado di effettuare previsioni su nuovi input mai osservati. Nella cybersecurity, il supervised machine learning viene ampiamente applicato ad attività come il rilevamento delle intrusioni (classificazione del traffico di rete come *normale* o *attacco*), il rilevamento dei malware (distinzione tra software malevolo e benigno), il rilevamento del phishing (identificazione di siti web o email fraudolenti) e il filtraggio dello spam, tra le altre.<sup>[[1]](#references)</sup> Ogni algoritmo presenta dei punti di forza ed è adatto a diversi tipi di problemi (classificazione o regressione). Di seguito esaminiamo i principali algoritmi di supervised learning, spieghiamo come funzionano e ne dimostriamo l'uso su dataset reali di cybersecurity. Discutiamo inoltre di come la combinazione di modelli (ensemble learning) possa spesso migliorare le prestazioni predittive.

## Algoritmi

-   **Linear Regression:** Un algoritmo di regressione fondamentale per prevedere risultati numerici adattando un'equazione lineare ai dati.

-   **Logistic Regression:** Un algoritmo di classificazione (nonostante il nome) che utilizza una funzione logistica per modellare la probabilità di un risultato binario.

-   **Decision Trees:** Modelli con struttura ad albero che suddividono i dati in base alle feature per effettuare previsioni; vengono spesso utilizzati per la loro interpretabilità.

-   **Random Forests:** Un ensemble di alberi decisionali (tramite bagging) che migliora la precisione e riduce l'overfitting.

-   **Support Vector Machines (SVM):** Classificatori a margine massimo che individuano l'iperpiano di separazione ottimale; possono utilizzare kernel per dati non lineari.

-   **Naive Bayes:** Un classificatore probabilistico basato sul teorema di Bayes, con l'assunzione di indipendenza tra le feature, utilizzato notoriamente nel filtraggio dello spam.

-   **k-Nearest Neighbors (k-NN):** Un semplice classificatore "instance-based" che assegna un'etichetta a un campione in base alla classe maggioritaria dei suoi vicini più prossimi.

-   **Gradient Boosting Machines:** Modelli ensemble (ad es., XGBoost, LightGBM) che costruiscono un predittore potente aggiungendo in sequenza learner più deboli (tipicamente alberi decisionali).

Ogni sezione seguente fornisce una descrizione migliorata dell'algoritmo e un **esempio di codice Python** che utilizza librerie come `pandas` e `scikit-learn` (e `PyTorch` per l'esempio della rete neurale). Gli esempi utilizzano dataset di cybersecurity disponibili pubblicamente (come NSL-KDD per il rilevamento delle intrusioni e un dataset di Phishing Websites) e seguono una struttura coerente:

1.  **Caricare il dataset** (download tramite URL, se disponibile).

2.  **Preprocessare i dati** (ad es., codificare le feature categoriche, scalare i valori, suddividere i dati in set di training/test).

3.  **Addestrare il modello** sui dati di training.

4.  **Valutare** il modello su un test set utilizzando le metriche: accuracy, precision, recall, F1-score e ROC AUC per la classificazione (e mean squared error per la regressione).

Esaminiamo ora ciascun algoritmo:

### Linear Regression

La linear regression è un algoritmo di **regressione** utilizzato per prevedere valori numerici continui. Presuppone una relazione lineare tra le feature di input (variabili indipendenti) e l'output (variabile dipendente). Il modello cerca di adattare una retta (o un iperpiano in dimensioni superiori) che descriva al meglio la relazione tra le feature e il target. In genere, ciò viene realizzato minimizzando la somma degli errori quadratici tra i valori previsti e quelli effettivi (metodo Ordinary Least Squares).<sup>[[2]](#references)</sup>

Il modo più semplice per rappresentare la linear regression è una retta:
```plaintext
y = mx + b
```
Dove:

- `y` è il valore previsto (output)
- `m` è la pendenza della retta (coefficiente)
- `x` è la feature di input
- `b` è l'intercetta sull'asse y

L'obiettivo della regressione lineare è trovare la retta che meglio si adatta ai dati e che minimizza la differenza tra i valori previsti e i valori effettivi nel dataset. Naturalmente, questo è molto semplice: sarebbe una retta che separa 2 categorie, ma se vengono aggiunte più dimensioni, la retta diventa più complessa:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Casi d'uso nella cybersecurity:* la regressione lineare è meno comune per le attività di sicurezza fondamentali (che spesso sono problemi di classificazione), ma può essere applicata per prevedere risultati numerici. Ad esempio, si potrebbe usare la regressione lineare per **prevedere il volume del traffico di rete** o **stimare il numero di attacchi in un determinato periodo** sulla base di dati storici. Potrebbe anche prevedere un punteggio di rischio o il tempo previsto prima del rilevamento di un attacco, date determinate metriche di sistema. Nella pratica, gli algoritmi di classificazione (come la regressione logistica o gli alberi) vengono usati più frequentemente per rilevare intrusioni o malware, ma la regressione lineare costituisce una base ed è utile per le analisi orientate alla regressione.

#### **Caratteristiche principali della regressione lineare:**

-   **Tipo di problema:** Regressione (previsione di valori continui). Non è adatta alla classificazione diretta, a meno che non venga applicata una soglia all'output.

-   **Interpretabilità:** Elevata -- i coefficienti sono semplici da interpretare e mostrano l'effetto lineare di ciascuna feature.

-   **Vantaggi:** Semplice e veloce; una buona baseline per le attività di regressione; funziona bene quando la relazione reale è approssimativamente lineare.

-   **Limitazioni:** Non è in grado di catturare relazioni complesse o non lineari (senza un feature engineering manuale); tende all'underfitting se le relazioni non sono lineari; è sensibile agli outlier, che possono alterare i risultati.

-   **Individuazione del miglior adattamento:** Per trovare la retta di miglior adattamento che separa le possibili categorie, utilizziamo un metodo chiamato **Ordinary Least Squares (OLS)**. Questo metodo minimizza la somma delle differenze al quadrato tra i valori osservati e quelli previsti dal modello lineare.

<details>
<summary>Esempio -- Previsione della durata delle connessioni (regressione) in un dataset di intrusioni
</summary>
Di seguito dimostriamo l'uso della regressione lineare con il dataset di cybersecurity NSL-KDD. Tratteremo questo come un problema di regressione, prevedendo la `duration` delle connessioni di rete sulla base di altre feature. (Nella realtà, `duration` è una delle feature di NSL-KDD; la utilizziamo qui solo per illustrare la regressione.) Carichiamo il dataset, lo preprocessiamo (codificando le feature categoriche), addestriamo un modello di regressione lineare e valutiamo il Mean Squared Error (MSE) e il punteggio R² su un test set.
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
In questo esempio, il modello di regressione lineare cerca di prevedere la `duration` della connessione a partire da altre feature di rete. Misuriamo le prestazioni con il Mean Squared Error (MSE) e R². Un R² vicino a 1.0 indicherebbe che il modello spiega la maggior parte della varianza nella `duration`, mentre un R² basso o negativo indica un adattamento scarso. (Non sorprende se l'R² è basso in questo caso: prevedere la `duration` potrebbe essere difficile utilizzando le feature fornite, e la regressione lineare potrebbe non riuscire a catturare i pattern se sono complessi.)
</details>

### Regressione logistica

La regressione logistica è un algoritmo di **classification** che modella la probabilità che un'istanza appartenga a una determinata classe (in genere la classe "positiva"). Nonostante il nome, la regressione *logistica* viene utilizzata per risultati discreti (a differenza della regressione lineare, che è destinata ai risultati continui). Viene utilizzata soprattutto per la **binary classification** (due classi, ad esempio malevola e legittima), ma può essere estesa a problemi multi-classe (utilizzando softmax o approcci one-vs-rest).<sup>[[3]](#references)</sup>

La regressione logistica utilizza la funzione logistica (nota anche come funzione sigmoide) per mappare i valori previsti in probabilità. Si noti che la funzione sigmoide è una funzione con valori compresi tra 0 e 1, che cresce secondo una curva a forma di S in base alle esigenze della classification, caratteristica utile per i task di binary classification. Pertanto, ogni feature di ciascun input viene moltiplicata per il peso assegnato e il risultato viene passato attraverso la funzione sigmoide per produrre una probabilità:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` è la probabilità che l'output `y` sia 1 dato l'input `x`
- `e` è la base del logaritmo naturale
- `z` è una combinazione lineare delle feature di input, tipicamente rappresentata come `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Si noti come, anche nella sua forma più semplice, sia una retta, mentre nei casi più complessi diventi un iperpiano con diverse dimensioni (una per feature).

> [!TIP]
> *Casi d'uso nella cybersecurity:* Poiché molti problemi di sicurezza sono essenzialmente decisioni sì/no, la regressione logistica è ampiamente utilizzata. Per esempio, un sistema di intrusion detection potrebbe usare la regressione logistica per decidere se una connessione di rete è un attacco sulla base delle caratteristiche di quella connessione. Nel rilevamento del phishing, la regressione logistica può combinare le caratteristiche di un sito web (lunghezza dell'URL, presenza del simbolo "@", ecc.) in una probabilità che si tratti di phishing. È stata utilizzata nei filtri antispam di prima generazione e rimane una solida baseline per molti task di classificazione.

#### Regressione logistica per la classificazione non binaria

La regressione logistica è progettata per la classificazione binaria, ma può essere estesa per gestire problemi multi-classe usando tecniche come **one-vs-rest** (OvR) o **softmax regression**. In OvR, viene addestrato un modello di regressione logistica separato per ogni classe, trattandola come classe positiva rispetto a tutte le altre. La classe con la probabilità prevista più alta viene scelta come previsione finale. La softmax regression generalizza la regressione logistica a più classi applicando la funzione softmax al layer di output, producendo una distribuzione di probabilità su tutte le classi.

#### **Caratteristiche principali della regressione logistica:**

-   **Tipo di problema:** Classificazione (solitamente binaria). Prevede la probabilità della classe positiva.

-   **Interpretabilità:** Alta -- come nella regressione lineare, i coefficienti delle feature possono indicare come ogni feature influenza i log-odds dell'outcome. Questa trasparenza è spesso apprezzata nella sicurezza per comprendere quali fattori contribuiscono a un alert.

-   **Vantaggi:** Semplice e veloce da addestrare; funziona bene quando la relazione tra le feature e i log-odds dell'outcome è lineare. Produce probabilità, consentendo il risk scoring. Con una regolarizzazione appropriata, generalizza bene e può gestire la multicollinearità meglio della semplice regressione lineare.

-   **Limitazioni:** Presuppone un confine decisionale lineare nello spazio delle feature (fallisce se il confine reale è complesso/non lineare). Può avere prestazioni inferiori nei problemi in cui le interazioni o gli effetti non lineari sono fondamentali, a meno che non si aggiungano manualmente feature polinomiali o di interazione. Inoltre, la regressione logistica è meno efficace se le classi non sono facilmente separabili tramite una combinazione lineare di feature.


<details>
<summary>Esempio -- Rilevamento di siti web di phishing con la regressione logistica:</summary>

Useremo un **Phishing Websites Dataset** (dal repository UCI) che contiene feature estratte dai siti web (come l'eventuale presenza di un indirizzo IP nell'URL, l'età del dominio, la presenza di elementi sospetti nell'HTML, ecc.) e un'etichetta che indica se il sito è di phishing o legittimo.<sup>[[4]](#references)</sup> Addestriamo un modello di regressione logistica per classificare i siti web e valutiamo quindi la sua accuracy, precision, recall, F1-score e ROC AUC su uno split di test.
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
In questo esempio di rilevamento del phishing, la regressione logistica produce una probabilità che indica se ogni sito web è di phishing. Valutando accuratezza, precisione, recall e F1, otteniamo un'idea delle prestazioni del modello. Ad esempio, un recall elevato significa che rileva la maggior parte dei siti di phishing (aspetto importante per la sicurezza, al fine di ridurre al minimo gli attacchi non rilevati), mentre un'elevata precisione significa che genera pochi falsi allarmi (aspetto importante per evitare l'affaticamento degli analisti). La ROC AUC (Area Under the ROC Curve) fornisce una misura delle prestazioni indipendente dalla soglia (1.0 è il valore ideale, 0.5 non è migliore del caso). La regressione logistica spesso offre buone prestazioni in attività di questo tipo, ma se il confine decisionale tra siti di phishing e siti legittimi è complesso, potrebbero essere necessari modelli non lineari più potenti.

</details>

### Alberi decisionali

Un albero decisionale è un versatile **algoritmo di apprendimento supervisionato** che può essere utilizzato sia per attività di classificazione sia di regressione. Apprende un modello gerarchico, simile a un albero, delle decisioni basato sulle feature dei dati. Ogni nodo interno dell'albero rappresenta un test su una determinata feature, ogni ramo rappresenta un risultato di tale test e ogni nodo foglia rappresenta una classe prevista (per la classificazione) o un valore (per la regressione).<sup>[[5]](#references)</sup>

Per costruire un albero, algoritmi come CART (Classification and Regression Tree) utilizzano misure quali **impurità di Gini** o **guadagno informativo (entropia)** per scegliere la feature e la soglia migliori con cui suddividere i dati a ogni passaggio. L'obiettivo di ogni suddivisione è partizionare i dati in modo da aumentare l'omogeneità della variabile target nei sottoinsiemi risultanti (nella classificazione, ogni nodo mira a essere il più puro possibile, contenendo prevalentemente una singola classe).

Gli alberi decisionali sono **altamente interpretabili** -- è possibile seguire il percorso dalla radice alla foglia per comprendere la logica alla base di una previsione (ad esempio, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Questo è utile nella cybersecurity per spiegare perché è stato generato un determinato alert. Gli alberi possono gestire naturalmente sia dati numerici sia dati categorici e richiedono un preprocessing minimo (ad esempio, non è necessario effettuare il feature scaling).

Tuttavia, un singolo albero decisionale può facilmente adattarsi eccessivamente ai dati di training, soprattutto se viene fatto crescere in profondità (con molte suddivisioni). Per prevenire l'overfitting, vengono spesso utilizzate tecniche come il pruning (limitare la profondità dell'albero o richiedere un numero minimo di campioni per foglia).

Un albero decisionale ha 3 componenti principali:
- **Nodo radice**: il nodo superiore dell'albero, che rappresenta l'intero dataset.
- **Nodi interni**: nodi che rappresentano feature e decisioni basate su tali feature.
- **Nodi foglia**: nodi che rappresentano il risultato finale o la previsione.

Un albero potrebbe avere un aspetto simile a questo:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Casi d'uso nella cybersecurity:* Gli alberi decisionali sono stati utilizzati nei sistemi di rilevamento delle intrusioni per ricavare **regole** finalizzate all'identificazione degli attacchi. Ad esempio, i primi IDS basati su ID3/C4.5 generavano regole leggibili dall'uomo per distinguere il traffico normale da quello malevolo. Sono utilizzati anche nell'analisi dei malware per decidere se un file è malevolo in base ai suoi attributi (dimensione del file, entropia delle sezioni, chiamate API, ecc.). La chiarezza degli alberi decisionali li rende utili quando è necessaria la trasparenza -- un analista può esaminare l'albero per convalidare la logica di rilevamento.

#### **Caratteristiche principali degli alberi decisionali:**

-   **Tipo di problema:** Sia classificazione sia regressione. Comunemente utilizzati per la classificazione degli attacchi rispetto al traffico normale, ecc.

-   **Interpretabilità:** Molto elevata -- le decisioni del modello possono essere visualizzate e comprese come un insieme di regole if-then. Questo è un vantaggio importante nella sicurezza, per garantire la fiducia e la verifica del comportamento del modello.

-   **Vantaggi:** Possono catturare relazioni non lineari e interazioni tra le feature (ogni split può essere considerato un'interazione). Non è necessario scalare le feature o applicare il one-hot encoding alle variabili categoriali -- gli alberi le gestiscono nativamente. Inferenza rapida (la predizione consiste semplicemente nel seguire un percorso nell'albero).

-   **Limitazioni:** Tendono all'overfitting se non vengono controllati (un albero profondo può memorizzare il training set). Possono essere instabili -- piccoli cambiamenti nei dati possono portare a una struttura dell'albero diversa. Come modelli singoli, la loro accuratezza potrebbe non essere paragonabile a quella di metodi più avanzati (gli ensemble come Random Forests generalmente ottengono prestazioni migliori riducendo la varianza).

-   **Individuazione del miglior split:**
- **Impurità di Gini**: Misura l'impurità di un nodo. Un'impurità di Gini più bassa indica uno split migliore. La formula è:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Dove `p_i` è la proporzione di istanze nella classe `i`.

- **Entropia**: Misura l'incertezza nel dataset. Un'entropia più bassa indica uno split migliore. La formula è:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Dove `p_i` è la proporzione di istanze nella classe `i`.

- **Guadagno di informazione**: La riduzione dell'entropia o dell'impurità di Gini dopo uno split. Maggiore è il guadagno di informazione, migliore è lo split. Viene calcolato come:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Inoltre, un albero termina quando:
- Tutte le istanze in un nodo appartengono alla stessa classe. Questo potrebbe portare all'overfitting.
- Viene raggiunta la profondità massima (hardcoded) dell'albero. Questo è un modo per prevenire l'overfitting.
- Il numero di istanze in un nodo è inferiore a una determinata soglia. Anche questo è un modo per prevenire l'overfitting.
- Il guadagno di informazione derivante da ulteriori split è inferiore a una determinata soglia. Anche questo è un modo per prevenire l'overfitting.

<details>
<summary>Esempio -- Albero decisionale per il rilevamento delle intrusioni:</summary>
Addestreremo un albero decisionale sul dataset NSL-KDD per classificare le connessioni di rete come *normal* oppure *attack*. NSL-KDD è una versione migliorata del classico dataset KDD Cup 1999, con feature come il tipo di protocollo, il servizio, la durata, il numero di accessi non riusciti, ecc., e un'etichetta che indica il tipo di attacco oppure "normal". Mapperemo tutti i tipi di attacco nella classe "anomaly" (classificazione binaria: normal rispetto ad anomaly). Dopo l'addestramento, valuteremo le prestazioni dell'albero sul test set.
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
In questo esempio di decision tree, abbiamo limitato la profondità dell'albero a 10 per evitare un overfitting estremo (il parametro `max_depth=10`). Le metriche mostrano quanto bene l'albero distingua il traffico normale da quello di attacco. Un recall elevato significherebbe che rileva la maggior parte degli attacchi (un aspetto importante per un IDS), mentre una precision elevata significa pochi falsi allarmi. I decision tree spesso raggiungono una accuracy discreta sui dati strutturati, ma un singolo albero potrebbe non raggiungere le migliori performance possibili. Tuttavia, l'*interpretability* del modello è un grande vantaggio -- potremmo esaminare gli split dell'albero per vedere, ad esempio, quali feature (per esempio `service`, `src_bytes`, ecc.) sono più influenti nel segnalare una connessione come malevola.

</details>

### Random Forests

Random Forest è un metodo di **ensemble learning** che si basa sui decision tree per migliorare le performance. Una random forest addestra più decision tree (da qui "forest") e combina i loro output per effettuare una predizione finale (per la classification, generalmente tramite majority vote). Le due idee principali alla base di una random forest sono il **bagging** (bootstrap aggregating) e la **feature randomness**:

-   **Bagging:** ogni albero viene addestrato su un random bootstrap sample dei training data (campionato con replacement). Questo introduce diversità tra gli alberi.

-   **Feature Randomness:** a ogni split di un albero, viene considerato un random subset delle feature per lo splitting (anziché tutte le feature). Questo rende ulteriormente non correlati gli alberi.

Facendo la media dei risultati di molti alberi, la random forest riduce la varianza che potrebbe avere un singolo decision tree. In termini semplici, i singoli alberi potrebbero fare overfit o essere rumorosi, ma un gran numero di alberi diversi che votano insieme attenua questi errori. Il risultato è spesso un modello con **accuracy più elevata** e una generalizzazione migliore rispetto a un singolo decision tree. Inoltre, le random forest possono fornire una stima della feature importance (osservando quanto ogni feature split riduce in media l'impurità).

Le random forest sono diventate un **workhorse nella cybersecurity** per attività come intrusion detection, malware classification e spam detection. Spesso offrono buone performance out-of-the-box con un tuning minimo e possono gestire grandi set di feature. Per esempio, nell'intrusion detection, una random forest può superare un singolo decision tree rilevando pattern di attacco più sottili con meno falsi positivi. La ricerca ha mostrato che le random forest ottengono risultati favorevoli rispetto ad altri algoritmi nella classificazione degli attacchi in dataset come NSL-KDD e UNSW-NB15.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Caratteristiche principali delle Random Forests:**

-   **Tipo di problema:** principalmente classification (utilizzate anche per la regression). Sono particolarmente adatte ai dati strutturati ad alta dimensionalità comuni nei security log.

-   **Interpretability:** inferiore rispetto a un singolo decision tree -- non è possibile visualizzare o spiegare facilmente centinaia di alberi contemporaneamente. Tuttavia, i punteggi di feature importance forniscono alcune indicazioni su quali attributi siano più influenti.

-   **Vantaggi:** in genere una accuracy più elevata rispetto ai modelli basati su un singolo albero grazie all'effetto dell'ensemble. Sono resistenti all'overfitting -- anche se i singoli alberi fanno overfit, l'ensemble generalizza meglio. Gestiscono sia feature numeriche sia categoriche e possono gestire in una certa misura i dati mancanti. Sono inoltre relativamente resistenti agli outlier.

-   **Limitazioni:** le dimensioni del modello possono essere elevate (molti alberi, ciascuno potenzialmente profondo). Le predizioni sono più lente rispetto a quelle di un singolo albero (poiché è necessario aggregare i risultati di molti alberi). Sono meno interpretabili -- anche se si conoscono le feature importanti, la logica esatta non è facilmente tracciabile come una regola semplice. Se il dataset è estremamente ad alta dimensionalità e sparso, l'addestramento di una forest molto grande può essere computazionalmente oneroso.

-   **Processo di addestramento:**
1. **Bootstrap Sampling**: campionare casualmente i training data con replacement per creare più subset (bootstrap sample).
2. **Tree Construction**: per ogni bootstrap sample, costruire un decision tree utilizzando un random subset di feature a ogni split. Questo introduce diversità tra gli alberi.
3. **Aggregation**: per i task di classification, la predizione finale viene effettuata prendendo il majority vote tra le predizioni di tutti gli alberi. Per i task di regression, la predizione finale è la media delle predizioni di tutti gli alberi.

<details>
<summary>Esempio -- Random Forest per l'Intrusion Detection (NSL-KDD):</summary>
Utilizzeremo lo stesso dataset NSL-KDD (con etichette binarie normal e anomaly) e addestreremo un classificatore Random Forest. Ci aspettiamo che la random forest offra performance pari o superiori a quelle del singolo decision tree, grazie alla riduzione della varianza ottenuta tramite l'averaging dell'ensemble. La valuteremo con le stesse metriche.
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
Il random forest in genere ottiene risultati solidi in questo task di rilevamento delle intrusioni. Potremmo osservare un miglioramento in metriche come F1 o AUC rispetto al singolo albero decisionale, soprattutto in termini di recall o precision, a seconda dei dati. Ciò è coerente con l'idea che *"Random Forest (RF) è un classificatore ensemble e offre buone prestazioni rispetto ad altri classificatori tradizionali per una classificazione efficace degli attacchi."*.<sup>[[6]](#references)</sup> In un contesto di security operations, un modello random forest potrebbe segnalare gli attacchi in modo più affidabile riducendo al contempo i falsi allarmi, grazie alla media di numerose regole decisionali. La feature importance della foresta potrebbe indicarci quali feature di rete sono maggiormente indicative di attacchi (ad esempio, determinati servizi di rete o conteggi insoliti di pacchetti).

</details>

### Support Vector Machines (SVM)

Le Support Vector Machines sono potenti modelli di supervised learning utilizzati principalmente per la classificazione (e anche per la regressione come SVR). Una SVM cerca di individuare l'**iperpiano di separazione ottimale** che massimizza il margine tra due classi. Solo un sottoinsieme dei punti di training (i "vettori di supporto" più vicini al confine) determina la posizione di questo iperpiano. Massimizzando il margine (la distanza tra i vettori di supporto e l'iperpiano), le SVM tendono a ottenere una buona generalizzazione.<sup>[[8]](#references)</sup>

Un elemento fondamentale della potenza delle SVM è la capacità di utilizzare **funzioni kernel** per gestire relazioni non lineari. I dati possono essere trasformati implicitamente in uno spazio delle feature a dimensionalità maggiore, nel quale potrebbe esistere un separatore lineare. I kernel comuni includono quello polinomiale, la funzione di base radiale (RBF) e quello sigmoide. Ad esempio, se le classi del traffico di rete non sono linearmente separabili nello spazio delle feature grezzo, un kernel RBF può mapparle in una dimensionalità maggiore, dove la SVM individua una separazione lineare (che corrisponde a un confine non lineare nello spazio originale). La flessibilità nella scelta dei kernel consente alle SVM di affrontare una varietà di problemi.

Le SVM sono note per offrire buone prestazioni in situazioni con spazi delle feature ad alta dimensionalità (come i dati testuali o le sequenze di opcode dei malware) e nei casi in cui il numero di feature è elevato rispetto al numero di campioni. Erano popolari in molte applicazioni iniziali di cybersecurity, come la classificazione dei malware e il rilevamento delle intrusioni basato sulle anomalie negli anni 2000, mostrando spesso un'elevata accuratezza.

Tuttavia, le SVM non si adattano facilmente a dataset molto grandi (la complessità del training è super-lineare rispetto al numero di campioni e l'utilizzo della memoria può essere elevato, poiché potrebbe essere necessario memorizzare molti vettori di supporto). In pratica, per task come il rilevamento delle intrusioni di rete con milioni di record, una SVM potrebbe essere troppo lenta senza un sottocampionamento attento o l'utilizzo di metodi approssimati.

#### **Caratteristiche principali delle SVM:**

-   **Tipo di problema:** Classificazione (binaria o multiclass tramite one-vs-one/one-vs-rest) e varianti per la regressione. Spesso utilizzate nella classificazione binaria con una separazione basata su un margine netto.

-   **Interpretabilità:** Media -- le SVM non sono interpretabili quanto gli alberi decisionali o la regressione logistica. Sebbene sia possibile identificare quali punti dati sono vettori di supporto e ottenere una certa indicazione delle feature potenzialmente influenti (attraverso i pesi nel caso del kernel lineare), nella pratica le SVM (specialmente con kernel non lineari) vengono trattate come classificatori black-box.

-   **Vantaggi:** Efficaci negli spazi ad alta dimensionalità; possono modellare confini decisionali complessi tramite il kernel trick; resistenti all'overfitting se il margine viene massimizzato (specialmente con un parametro di regolarizzazione C appropriato); funzionano bene anche quando le classi non sono separate da una distanza elevata (individuano il miglior compromesso per il confine).

-   **Limitazioni:** **Elevato carico computazionale** per dataset di grandi dimensioni (sia il training sia la predizione aumentano poco efficientemente al crescere dei dati). Richiedono un'attenta regolazione dei parametri del kernel e della regolarizzazione (C, tipo di kernel, gamma per RBF, ecc.). Non forniscono direttamente output probabilistici (sebbene sia possibile utilizzare il Platt scaling per ottenere le probabilità). Inoltre, le SVM possono essere sensibili alla scelta dei parametri del kernel --- una scelta errata può portare a underfitting o overfitting.

*Use case nella cybersecurity:* le SVM sono state utilizzate nel **rilevamento dei malware** (ad esempio, per classificare i file in base alle feature estratte o alle sequenze di opcode), nel **rilevamento delle anomalie di rete** (classificando il traffico come normale o dannoso) e nel **rilevamento del phishing** (utilizzando le feature degli URL). Ad esempio, una SVM potrebbe ricevere le feature di un'email (conteggi di determinate parole chiave, punteggi di reputazione del mittente, ecc.) e classificarla come phishing o legittima. Sono state inoltre applicate al **rilevamento delle intrusioni** su feature set come KDD, ottenendo spesso un'elevata accuratezza a fronte di un costo computazionale maggiore.

<details>
<summary>Esempio -- SVM per la classificazione dei malware:</summary>
Utilizzeremo nuovamente il dataset dei siti web di phishing, questa volta con una SVM. Poiché le SVM possono essere lente, se necessario utilizzeremo un sottoinsieme dei dati per il training (il dataset contiene circa 11.000 istanze, una quantità che una SVM può gestire ragionevolmente). Utilizzeremo un kernel RBF, una scelta comune per i dati non lineari, e abiliteremo le stime probabilistiche per calcolare la ROC AUC.
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
Il modello SVM produrrà metriche che possiamo confrontare con la regressione logistica sulla stessa attività. Potremmo scoprire che SVM raggiunge un'accuracy e un'AUC elevate se i dati sono ben separati dalle feature. Al contrario, se il dataset contenesse molto rumore o classi sovrapposte, SVM potrebbe non superare significativamente la regressione logistica. In pratica, le SVM possono offrire un miglioramento quando esistono relazioni complesse e non lineari tra feature e classe: il kernel RBF è in grado di catturare confini decisionali curvi che la regressione logistica non riuscirebbe a rilevare. Come per tutti i modelli, è necessario regolare attentamente `C` (regolarizzazione) e i parametri del kernel (come `gamma` per RBF) per bilanciare bias e varianza.

</details>

#### Differenze tra regressione logistica e SVM

| Aspetto | **Regressione logistica** | **Support Vector Machines** |
|---|---|---|
| **Funzione obiettivo** | Minimizza la **log‑loss** (cross‑entropy). | Massimizza il **margine** minimizzando al contempo la **hinge‑loss**. |
| **Confine decisionale** | Trova l'**iperpiano di miglior adattamento** che modella _P(y\|x)_. | Trova l'**iperpiano a massimo margine** (la distanza maggiore dai punti più vicini). |
| **Output** | **Probabilistico** – fornisce probabilità di classe calibrate tramite σ(w·x + b). | **Deterministico** – restituisce etichette di classe; le probabilità richiedono un'elaborazione aggiuntiva (ad esempio Platt scaling). |
| **Regolarizzazione** | L2 (predefinita) o L1, bilancia direttamente underfitting e overfitting. | Il parametro C bilancia l'ampiezza del margine rispetto alle classificazioni errate; i parametri del kernel aggiungono complessità. |
| **Kernel / Non lineare** | La forma nativa è **lineare**; la non linearità viene aggiunta tramite feature engineering. | Il **kernel trick** integrato (RBF, poly, ecc.) consente di modellare confini complessi in uno spazio ad alta dimensionalità. |
| **Scalabilità** | Risolve un'ottimizzazione convessa in **O(nd)**; gestisce bene valori di n molto grandi. | Il training può richiedere **O(n²–n³)** in memoria/tempo senza solver specializzati; è meno adatto a valori di n enormi. |
| **Interpretabilità** | **Elevata** – i pesi mostrano l'influenza delle feature; l'odds ratio è intuitivo. | **Bassa** per i kernel non lineari; i support vector sono sparsi, ma non facili da spiegare. |
| **Sensibilità agli outlier** | Utilizza una log‑loss uniforme → meno sensibile. | La hinge‑loss con hard margin può essere **sensibile**; il soft margin (C) riduce il problema. |
| **Casi d'uso tipici** | Credit scoring, rischio medico, A/B testing – dove **probabilità e spiegabilità** sono importanti. | Classificazione di immagini/testi, bioinformatica – dove contano **confini complessi** e **dati ad alta dimensionalità**. |

* **Se hai bisogno di probabilità calibrate, interpretabilità o devi operare su dataset enormi — scegli la regressione logistica.**
* **Se hai bisogno di un modello flessibile in grado di catturare relazioni non lineari senza feature engineering manuale — scegli SVM (con i kernel).**
* Entrambi ottimizzano obiettivi convessi, quindi sono garantiti **minimi globali**, ma i kernel di SVM aggiungono iperparametri e costi computazionali.

### Naive Bayes

Naive Bayes è una famiglia di **classificatori probabilistici** basati sull'applicazione del teorema di Bayes con una forte assunzione di indipendenza tra le feature. Nonostante questa assunzione "naive", Naive Bayes funziona spesso sorprendentemente bene per determinate applicazioni, soprattutto quelle che coinvolgono dati testuali o categorici, come il rilevamento dello spam.<sup>[[9]](#references)</sup>


#### Teorema di Bayes

Il teorema di Bayes è il fondamento dei classificatori Naive Bayes. Mette in relazione le probabilità condizionate e marginali di eventi casuali. La formula è:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Dove:
- `P(A|B)` è la probabilità a posteriori della classe `A` data la feature `B`.
- `P(B|A)` è la likelihood della feature `B` data la classe `A`.
- `P(A)` è la probabilità a priori della classe `A`.
- `P(B)` è la probabilità a priori della feature `B`.

Ad esempio, se vogliamo classificare se un testo è stato scritto da un bambino o da un adulto, possiamo usare le parole del testo come feature. Sulla base di alcuni dati iniziali, il classificatore Naive Bayes calcolerà in precedenza le probabilità che ogni parola appartenga a ciascuna classe potenziale (bambino o adulto). Quando viene fornito un nuovo testo, calcolerà la probabilità di ciascuna classe potenziale date le parole presenti nel testo e sceglierà la classe con la probabilità più alta.

Come si può vedere in questo esempio, il classificatore Naive Bayes è molto semplice e veloce, ma presuppone che le feature siano indipendenti, cosa che non avviene sempre nei dati del mondo reale.


#### Tipi di classificatori Naive Bayes

Esistono diversi tipi di classificatori Naive Bayes, a seconda del tipo di dati e della distribuzione delle feature:
- **Gaussian Naive Bayes**: presuppone che le feature seguano una distribuzione gaussiana (normale). È adatto ai dati continui.
- **Multinomial Naive Bayes**: presuppone che le feature seguano una distribuzione multinomiale. È adatto ai dati discreti, come il conteggio delle parole nella classificazione del testo.
- **Bernoulli Naive Bayes**: presuppone che le feature siano binarie (0 o 1). È adatto ai dati binari, come la presenza o l'assenza di parole nella classificazione del testo.
- **Categorical Naive Bayes**: presuppone che le feature siano variabili categoriche. È adatto ai dati categorici, come la classificazione della frutta in base al colore e alla forma.


#### **Caratteristiche principali di Naive Bayes:**

-   **Tipo di problema:** classificazione (binaria o multi-classe). Comunemente utilizzato per attività di classificazione del testo nella cybersecurity (spam, phishing, ecc.).

-   **Interpretabilità:** media -- non è interpretabile direttamente quanto un albero decisionale, ma è possibile esaminare le probabilità apprese (ad esempio, quali parole sono più probabili nelle email di spam rispetto alle email legittime). La struttura del modello (le probabilità di ogni feature data la classe) può essere compresa se necessario.

-   **Vantaggi:** addestramento e predizione **molto veloci**, anche su dataset di grandi dimensioni (lineari rispetto al numero di istanze * numero di feature). Richiede una quantità di dati relativamente ridotta per stimare le probabilità in modo affidabile, soprattutto con un'adeguata regolarizzazione. Spesso è sorprendentemente accurato come baseline, specialmente quando le feature contribuiscono indipendentemente all'evidenza della classe. Funziona bene con dati ad alta dimensionalità (ad esempio, migliaia di feature estratte dal testo). Non richiede un tuning complesso oltre all'impostazione di un parametro di regolarizzazione.

-   **Limitazioni:** l'assunzione di indipendenza può limitare l'accuratezza se le feature sono fortemente correlate. Ad esempio, nei dati di rete, feature come `src_bytes` e `dst_bytes` potrebbero essere correlate; Naive Bayes non catturerà questa interazione. Quando la dimensione dei dati cresce molto, modelli più espressivi (come ensemble o reti neurali) possono superare NB imparando le dipendenze tra le feature. Inoltre, se per identificare un attacco è necessaria una determinata combinazione di feature (non solo singole feature indipendenti), NB avrà difficoltà.

> [!TIP]
> *Casi d'uso nella cybersecurity:* l'uso classico è il **rilevamento dello spam** -- Naive Bayes è stato il nucleo dei primi filtri antispam, che utilizzavano la frequenza di determinati token (parole, frasi, indirizzi IP) per calcolare la probabilità che un'email fosse spam. Viene utilizzato anche nel **rilevamento delle email di phishing** e nella **classificazione degli URL**, dove la presenza di determinate parole chiave o caratteristiche (come "login.php" in un URL o `@` nel percorso di un URL) contribuisce alla probabilità di phishing. Nell'analisi del malware, si potrebbe immaginare un classificatore Naive Bayes che utilizza la presenza di determinate chiamate API o autorizzazioni nel software per prevedere se si tratta di malware. Sebbene gli algoritmi più avanzati offrano spesso prestazioni migliori, Naive Bayes rimane una buona baseline grazie alla sua velocità e semplicità.

<details>
<summary>Esempio -- Naive Bayes per il rilevamento del phishing:</summary>
Per dimostrare Naive Bayes, utilizzeremo Gaussian Naive Bayes sul dataset di intrusioni NSL-KDD (con etichette binarie). Gaussian NB tratterà ogni feature come se seguisse una distribuzione normale per ciascuna classe. Si tratta di una scelta approssimativa, poiché molte feature di rete sono discrete o fortemente asimmetriche, ma mostra come applicare NB ai dati con feature continue. Potremmo anche scegliere Bernoulli NB su un dataset di feature binarie (come un insieme di alert attivati), ma qui continueremo a utilizzare NSL-KDD per coerenza.
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
Questo codice addestra un classificatore Naive Bayes per rilevare gli attacchi. Naive Bayes calcolerà valori come `P(service=http | Attack)` e `P(Service=http | Normal)` basandosi sui dati di addestramento, assumendo l'indipendenza tra le feature. Utilizzerà quindi queste probabilità per classificare le nuove connessioni come normali o come attacchi, in base alle feature osservate. Le prestazioni di NB su NSL-KDD potrebbero non essere elevate quanto quelle dei modelli più avanzati (poiché l'indipendenza tra le feature viene violata), ma sono spesso discrete e offrono il vantaggio di una velocità estrema. In scenari come il filtraggio delle email in tempo reale o il triage iniziale degli URL, un modello Naive Bayes può segnalare rapidamente i casi evidentemente malevoli con un utilizzo ridotto delle risorse.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors è uno degli algoritmi di machine learning più semplici. È un metodo **non parametrico, basato sulle istanze** che effettua previsioni in base alla similarità con gli esempi presenti nel training set. L'idea per la classificazione è la seguente: per classificare un nuovo punto dati, si individuano i **k** punti più vicini nei dati di addestramento, i suoi "nearest neighbors", e si assegna la classe maggioritaria tra questi vicini. La "vicinanza" viene definita da una metrica di distanza, in genere la distanza euclidea per i dati numerici (è possibile usare altre distanze per diversi tipi di feature o problemi).<sup>[[10]](#references)</sup>

K-NN non richiede *un addestramento esplicito* -- la fase di "addestramento" consiste semplicemente nel memorizzare il dataset. Tutto il lavoro avviene durante la query (prediction): l'algoritmo deve calcolare le distanze dal punto della query a tutti i punti di addestramento per trovare quelli più vicini. Questo rende il tempo di prediction **lineare rispetto al numero di campioni di addestramento**, il che può essere oneroso per dataset di grandi dimensioni. Per questo motivo, k-NN è più adatto a dataset di dimensioni ridotte o a scenari in cui si può accettare un compromesso tra memoria e velocità in favore della semplicità.

Nonostante la sua semplicità, k-NN può modellare decision boundary molto complesse (poiché, di fatto, la decision boundary può assumere qualsiasi forma determinata dalla distribuzione degli esempi). Tende a funzionare bene quando la decision boundary è molto irregolare e si dispone di molti dati -- in sostanza, lasciando che siano i dati a "parlare da soli". Tuttavia, in dimensioni elevate, le metriche di distanza possono diventare meno significative (curse of dimensionality) e il metodo può avere difficoltà, a meno di disporre di un numero enorme di campioni.

*Use cases nella cybersecurity:* k-NN è stato applicato all'anomaly detection -- per esempio, un intrusion detection system potrebbe classificare un evento di rete come malevolo se la maggior parte dei suoi nearest neighbors (eventi precedenti) era malevola. Se il traffico normale forma dei cluster e gli attacchi sono outlier, un approccio K-NN (con k=1 o un k ridotto) realizza sostanzialmente una **nearest-neighbor anomaly detection**. K-NN è stato utilizzato anche per classificare le famiglie di malware tramite vettori di feature binarie: un nuovo file potrebbe essere classificato come appartenente a una determinata famiglia di malware se è molto vicino (nello spazio delle feature) a istanze note di quella famiglia. In pratica, k-NN non è comune quanto gli algoritmi più scalabili, ma è concettualmente semplice e talvolta viene utilizzato come baseline o per problemi di piccola scala.

#### **Caratteristiche principali di k-NN:**

-   **Tipo di problema:** Classificazione (esistono anche varianti per la regressione). È un metodo di *lazy learning* -- non esegue il fitting esplicito di un modello.

-   **Interpretabilità:** Da bassa a media -- non esiste un modello globale o una spiegazione concisa, ma è possibile interpretare i risultati osservando i nearest neighbors che hanno influenzato una decisione (ad esempio, "questo network flow è stato classificato come malevolo perché è simile a questi 3 network flow malevoli noti"). Le spiegazioni possono quindi essere basate su esempi.

-   **Vantaggi:** Molto semplice da implementare e comprendere. Non fa assunzioni sulla distribuzione dei dati (non parametrico). Può gestire naturalmente problemi multi-classe. È **adattivo**, nel senso che le decision boundary possono essere molto complesse e modellate dalla distribuzione dei dati.

-   **Limitazioni:** La prediction può essere lenta per dataset di grandi dimensioni (è necessario calcolare molte distanze). Richiede molta memoria -- memorizza tutti i dati di addestramento. Le prestazioni peggiorano negli spazi delle feature ad alta dimensionalità, perché tutti i punti tendono a diventare quasi equidistanti (rendendo meno significativo il concetto di "nearest"). È necessario scegliere *k* (il numero di vicini) in modo appropriato -- un k troppo piccolo può introdurre rumore, mentre un k troppo grande può includere punti irrilevanti di altre classi. Inoltre, le feature devono essere scalate correttamente, perché i calcoli delle distanze sono sensibili alla scala.

<details>
<summary>Esempio -- k-NN per il rilevamento del phishing:</summary>

Utilizzeremo nuovamente NSL-KDD (classificazione binaria). Poiché k-NN è oneroso dal punto di vista computazionale, in questa dimostrazione utilizzeremo un sottoinsieme dei dati di addestramento per mantenere il processo gestibile. Sceglieremo, ad esempio, 20.000 campioni di addestramento sui 125k complessivi e useremo k=5 neighbors. Dopo l'addestramento (in realtà, la semplice memorizzazione dei dati), effettueremo la valutazione sul test set. Eseguiremo inoltre lo scaling delle feature per il calcolo delle distanze, in modo da garantire che nessuna singola feature prevalga a causa della propria scala.
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
Il modello k-NN classificherà una connessione osservando le 5 connessioni più vicine nel sottoinsieme del training set. Se, per esempio, 4 di questi vicini sono attacchi (anomalie) e 1 è normale, la nuova connessione verrà classificata come un attacco. Le prestazioni potrebbero essere ragionevoli, anche se spesso non raggiungono quelle di un Random Forest o di un SVM ben ottimizzati sugli stessi dati. Tuttavia, k-NN può talvolta eccellere quando le distribuzioni delle classi sono molto irregolari e complesse, utilizzando di fatto una ricerca basata sulla memoria. In cybersecurity, k-NN (con k=1 o un valore piccolo) potrebbe essere utilizzato per rilevare pattern di attacco noti tramite esempi, oppure come componente di sistemi più complessi (per esempio, per il clustering e la successiva classificazione in base all'appartenenza a un cluster).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines sono tra gli algoritmi più potenti per i dati strutturati. **Gradient boosting** si riferisce alla tecnica di costruzione di un ensemble di weak learners (spesso alberi decisionali) in modo sequenziale, in cui ogni nuovo modello corregge gli errori dell'ensemble precedente. A differenza del bagging (Random Forests), che costruisce gli alberi in parallelo e ne calcola la media, il boosting costruisce gli alberi *uno alla volta*, concentrandosi maggiormente sulle istanze che gli alberi precedenti hanno classificato erroneamente.<sup>[[11]](#references)</sup>

Le implementazioni più popolari degli ultimi anni sono **XGBoost**, **LightGBM** e **CatBoost**, tutte librerie di gradient boosting decision tree (GBDT). Hanno avuto un enorme successo nelle competizioni e nelle applicazioni di machine learning, spesso **raggiungendo prestazioni all'avanguardia sui dataset tabellari**. In cybersecurity, ricercatori e professionisti hanno utilizzato gli alberi con gradient boosting per attività come il **rilevamento di malware** (usando feature estratte dai file o dal comportamento durante l'esecuzione) e il **rilevamento delle intrusioni di rete**. Per esempio, un modello di gradient boosting può combinare molte regole deboli (alberi), come "se ci sono molti pacchetti SYN e una porta insolita -> probabile scansione", in un rilevatore composito forte che tiene conto di numerosi pattern più sottili.

Perché gli alberi boosted sono così efficaci? Ogni albero della sequenza viene addestrato sugli *errori residui* (gradienti) delle predizioni dell'ensemble corrente. In questo modo, il modello **"boosts"** gradualmente le aree in cui è debole. L'uso degli alberi decisionali come base learners permette al modello finale di catturare interazioni complesse e relazioni non lineari. Inoltre, il boosting incorpora una forma di regolarizzazione integrata: aggiungendo molti alberi piccoli (e usando un learning rate per ridimensionare i loro contributi), spesso generalizza bene senza un overfitting eccessivo, a condizione che vengano scelti parametri appropriati.

#### **Caratteristiche principali del Gradient Boosting:**

-   **Tipo di problema:** principalmente classificazione e regressione. In ambito security, solitamente classificazione (per esempio, classificare in modo binario una connessione o un file). Gestisce problemi binari, multi-classe (con una loss appropriata) e persino problemi di ranking.

-   **Interpretabilità:** da bassa a media. Sebbene un singolo albero boosted sia piccolo, un modello completo potrebbe avere centinaia di alberi, il che lo rende non interpretabile dall'essere umano nel suo insieme. Tuttavia, come Random Forest, può fornire punteggi di importanza delle feature, e strumenti come SHAP (SHapley Additive exPlanations) possono essere utilizzati per interpretare in una certa misura le singole predizioni.

-   **Vantaggi:** spesso l'algoritmo con le **migliori prestazioni** sui dati strutturati/tabellari. Può rilevare pattern e interazioni complesse. Dispone di numerosi parametri regolabili (numero di alberi, profondità degli alberi, learning rate, termini di regolarizzazione) per adattare la complessità del modello e prevenire l'overfitting. Le implementazioni moderne sono ottimizzate per la velocità (per esempio, XGBoost usa informazioni sui gradienti di secondo ordine e strutture dati efficienti). Tende a gestire meglio i dati sbilanciati quando viene combinato con loss function appropriate o modificando i sample weights.

-   **Limitazioni:** è più complesso da ottimizzare rispetto ai modelli più semplici; il training può essere lento se gli alberi sono profondi o il numero di alberi è elevato (anche se generalmente è comunque più veloce dell'addestramento di una deep neural network comparabile sugli stessi dati). Il modello può andare incontro a overfitting se non viene ottimizzato (per esempio, troppi alberi profondi con una regolarizzazione insufficiente). A causa dei numerosi hyperparameters, usare efficacemente il gradient boosting può richiedere maggiore esperienza o sperimentazione. Inoltre, come i metodi basati sugli alberi, non gestisce intrinsecamente i dati molto sparsi e ad alta dimensionalità in modo efficiente quanto i modelli lineari o Naive Bayes (anche se può comunque essere applicato, per esempio, nella classificazione del testo, ma potrebbe non essere la prima scelta senza feature engineering).

> [!TIP]
> *Casi d'uso in cybersecurity:* quasi ovunque si potrebbe utilizzare un albero decisionale o un random forest, un modello di gradient boosting potrebbe raggiungere una maggiore accuratezza. Per esempio, nelle competizioni di **rilevamento di malware di Microsoft** è stato fatto largo uso di XGBoost su feature progettate a partire da file binari. La ricerca sul **rilevamento delle intrusioni di rete** riporta spesso risultati ai vertici con i GBDT (per esempio, XGBoost sui dataset CIC-IDS2017 o UNSW-NB15). Questi modelli possono utilizzare un'ampia gamma di feature (tipi di protocollo, frequenza di determinati eventi, feature statistiche del traffico e così via) e combinarle per rilevare le minacce. Nel rilevamento del phishing, il gradient boosting può combinare feature lessicali degli URL, feature relative alla reputazione del dominio e feature del contenuto delle pagine per ottenere un'accuratezza molto elevata. L'approccio ensemble aiuta a coprire molti casi limite e molte sottigliezze presenti nei dati.

<details>
<summary>Esempio -- XGBoost per il rilevamento del phishing:</summary>
Utilizzeremo un classificatore di gradient boosting sul dataset di phishing. Per mantenere le cose semplici e autosufficienti, useremo `sklearn.ensemble.GradientBoostingClassifier` (che è un'implementazione più lenta ma immediata). Normalmente, si potrebbero usare le librerie `xgboost` o `lightgbm` per ottenere prestazioni migliori e funzionalità aggiuntive. Addestreremo il modello e ne valuteremo le prestazioni in modo simile a prima.
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
Il modello di gradient boosting probabilmente raggiungerà un'accuratezza e un'AUC molto elevate su questo dataset di phishing (spesso questi modelli possono superare il 95% di accuratezza con un'adeguata ottimizzazione su dati di questo tipo, come osservato nella letteratura. Questo dimostra perché i GBDT sono considerati *"the state of the art model for tabular dataset"* -- spesso superano gli algoritmi più semplici catturando pattern complessi.<sup>[[11]](#references)</sup> In un contesto di cybersecurity, ciò potrebbe significare rilevare più siti di phishing o attacchi con meno mancate rilevazioni. Naturalmente, è necessario prestare attenzione all'overfitting -- in genere useremmo tecniche come la cross-validation e monitoreremmo le prestazioni su un validation set durante lo sviluppo di un modello di questo tipo per il deployment.

</details>

### Combining Models: Ensemble Learning and Stacking

L'ensemble learning è una strategia che consiste nel **combinare più modelli** per migliorare le prestazioni complessive. Abbiamo già visto metodi di ensemble specifici: Random Forest (un ensemble di alberi tramite bagging) e Gradient Boosting (un ensemble di alberi tramite boosting sequenziale). Tuttavia, gli ensemble possono essere creati anche in altri modi, come gli **ensemble basati sul voto** o la **stacked generalization (stacking)**. L'idea principale è che modelli diversi possano catturare pattern differenti o avere punti deboli diversi; combinandoli, possiamo **compensare gli errori di ciascun modello con i punti di forza di un altro**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** In un semplice classificatore basato sul voto, addestriamo più modelli eterogenei (ad esempio, una regressione logistica, un decision tree e un SVM) e li facciamo votare sulla predizione finale (voto a maggioranza per la classificazione). Se assegniamo un peso ai voti (ad esempio, un peso maggiore ai modelli più accurati), otteniamo uno schema di voto pesato. Questo generalmente migliora le prestazioni quando i singoli modelli sono abbastanza validi e indipendenti -- l'ensemble riduce il rischio dell'errore di un singolo modello, poiché gli altri possono correggerlo. È come avere un gruppo di esperti invece di una singola opinione.

-   **Stacking (Stacked Ensemble):** Lo stacking fa un passo ulteriore. Invece di un semplice voto, addestra un **meta-model** per **apprendere come combinare al meglio le predizioni** dei modelli di base. Ad esempio, si addestrano 3 classificatori diversi (base learners), quindi si forniscono i loro output (o le probabilità) come feature a un meta-classifier (spesso un modello semplice come la regressione logistica), che apprende il modo ottimale di combinarli. Il meta-model viene addestrato su un validation set o tramite cross-validation per evitare l'overfitting. Lo stacking può spesso superare il voto semplice, apprendendo *quali modelli considerare più affidabili in quali circostanze*. In cybersecurity, un modello potrebbe essere migliore nel rilevare network scan, mentre un altro potrebbe essere migliore nel rilevare il malware beaconing; un modello di stacking potrebbe imparare a fare affidamento su ciascuno nel modo appropriato.

Gli ensemble, sia basati sul voto sia sullo stacking, tendono a **migliorare l'accuratezza** e la robustezza. Lo svantaggio è una maggiore complessità e, talvolta, una minore interpretabilità (anche se alcuni approcci ensemble, come la media di decision tree, possono comunque fornire alcune indicazioni, ad esempio tramite la feature importance). Nella pratica, se i vincoli operativi lo consentono, l'uso di un ensemble può portare a tassi di rilevamento più elevati. Molte soluzioni vincenti nelle challenge di cybersecurity (e nelle competizioni Kaggle in generale) usano tecniche di ensemble per ottenere anche l'ultimo margine di prestazioni.

<details>
<summary>Esempio -- Voting Ensemble per il rilevamento del phishing:</summary>
Per illustrare il model stacking, combiniamo alcuni dei modelli discussi nel dataset di phishing. Useremo una regressione logistica, un decision tree e un k-NN come base learners, e una Random Forest come meta-learner per aggregare le loro predizioni. Il meta-learner verrà addestrato sugli output dei base learners (usando la cross-validation sul training set). Ci aspettiamo che il modello stacked abbia prestazioni pari o leggermente migliori rispetto ai singoli modelli.
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
L'ensemble impilato sfrutta i punti di forza complementari dei modelli di base. Ad esempio, la regressione logistica potrebbe gestire gli aspetti lineari dei dati, l'albero decisionale potrebbe catturare interazioni specifiche simili a regole e k-NN potrebbe eccellere nei vicinati locali dello spazio delle feature. Il meta-modello (in questo caso una random forest) può imparare come ponderare questi input. Le metriche risultanti mostrano spesso un miglioramento (anche se lieve) rispetto alle metriche di qualsiasi singolo modello. Nel nostro esempio di phishing, se la regressione logistica avesse da sola un F1 pari, ad esempio, a 0.95 e l'albero a 0.94, lo stacking potrebbe raggiungere 0.96 correggendo gli errori dei singoli modelli.

I metodi ensemble come questo dimostrano il principio secondo cui *"la combinazione di più modelli porta generalmente a una migliore capacità di generalizzazione"*.<sup>[[12]](#references)</sup> Nella cybersecurity, questo può essere implementato disponendo di più motori di rilevamento (uno potrebbe essere basato su regole, uno sul machine learning e uno sul rilevamento delle anomalie) e poi di un livello che aggrega i loro alert -- di fatto una forma di ensemble -- per prendere una decisione finale con maggiore confidenza. Quando si implementano sistemi di questo tipo, è necessario considerare la complessità aggiuntiva e assicurarsi che l'ensemble non diventi troppo difficile da gestire o spiegare. Tuttavia, dal punto di vista dell'accuratezza, gli ensemble e lo stacking sono strumenti potenti per migliorare le prestazioni dei modelli.

</details>

Gli approcci basati sulle reti neurali descritti nella [pagina sul deep learning](AI-Deep-Learning.md) possono integrare questi modelli classici per il rilevamento delle intrusioni quando il dataset e il budget computazionale giustificano la complessità aggiuntiva.<sup>[[13]](#references)</sup>

## References

- [1] [AI e machine learning nella cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [La regressione lineare, spiegata - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Regressione logistica - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Classificazione degli attacchi di phishing e dei siti web utilizzando il machine learning e più dataset (un'analisi comparativa)"](https://arxiv.org/pdf/2101.02552)
- [5] [Albero decisionale - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Rilevamento degli attacchi Denial of Services utilizzando un classificatore random forest con Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Analisi delle prestazioni dei modelli di machine learning per i sistemi di rilevamento delle intrusioni utilizzando la tecnica di selezione delle feature Gini Impurity-based Weighted Random Forest (GIWRF)"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Cos'è una Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Filtraggio dello spam con Naive Bayes - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [Cos'è il k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT spiegato: come funzionano LightGBM, XGBoost e CatBoost - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble learning: migliorare le prestazioni dei modelli combinando i punti di forza - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Come il deep learning migliora i sistemi di rilevamento delle intrusioni](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
