# Algoritmi di Apprendimento Supervisionato

{{#include ../banners/hacktricks-training.md}}

## Informazioni di Base

L'apprendimento supervisionato utilizza dati etichettati per addestrare modelli che possono fare previsioni su nuovi input non visti. Nella cybersecurity, il machine learning supervisionato è ampiamente applicato a compiti come il rilevamento delle intrusioni (classificazione del traffico di rete come *normale* o *attacco*), il rilevamento di malware (distinzione tra software dannoso e benigno), il rilevamento di phishing (identificazione di siti web o email fraudolenti) e il filtraggio dello spam, tra gli altri. Ogni algoritmo ha i suoi punti di forza ed è adatto a diversi tipi di problemi (classificazione o regressione). Di seguito esaminiamo gli algoritmi chiave di apprendimento supervisionato, spieghiamo come funzionano e dimostriamo il loro utilizzo su dataset reali di cybersecurity. Discutiamo anche di come combinare modelli (apprendimento ensemble) possa spesso migliorare le prestazioni predittive.

## Algoritmi

-   **Regressione Lineare:** Un algoritmo di regressione fondamentale per prevedere risultati numerici adattando un'equazione lineare ai dati.

-   **Regressione Logistica:** Un algoritmo di classificazione (nonostante il suo nome) che utilizza una funzione logistica per modellare la probabilità di un risultato binario.

-   **Alberi Decisionali:** Modelli strutturati ad albero che suddividono i dati per caratteristiche per fare previsioni; spesso utilizzati per la loro interpretabilità.

-   **Foreste Casuali:** Un insieme di alberi decisionali (tramite bagging) che migliora l'accuratezza e riduce l'overfitting.

-   **Macchine a Vettori di Supporto (SVM):** Classificatori a margine massimo che trovano l'iperpiano separatore ottimale; possono utilizzare kernel per dati non lineari.

-   **Naive Bayes:** Un classificatore probabilistico basato sul teorema di Bayes con un'assunzione di indipendenza delle caratteristiche, utilizzato famosamente nel filtraggio dello spam.

-   **k-Nearest Neighbors (k-NN):** Un semplice classificatore "basato su istanze" che etichetta un campione in base alla classe maggioritaria dei suoi vicini più prossimi.

-   **Gradient Boosting Machines:** Modelli ensemble (ad es., XGBoost, LightGBM) che costruiscono un forte predittore aggiungendo sequenzialmente apprendisti più deboli (tipicamente alberi decisionali).

Ogni sezione sottostante fornisce una descrizione migliorata dell'algoritmo e un **esempio di codice Python** utilizzando librerie come `pandas` e `scikit-learn` (e `PyTorch` per l'esempio di rete neurale). Gli esempi utilizzano dataset di cybersecurity disponibili pubblicamente (come NSL-KDD per il rilevamento delle intrusioni e un dataset di Siti Web di Phishing) e seguono una struttura coerente:

1.  **Carica il dataset** (scarica tramite URL se disponibile).

2.  **Preprocessa i dati** (ad es. codifica delle caratteristiche categoriche, scalatura dei valori, suddivisione in set di addestramento/test).

3.  **Addestra il modello** sui dati di addestramento.

4.  **Valuta** su un set di test utilizzando metriche: accuratezza, precisione, richiamo, F1-score e ROC AUC per la classificazione (e errore quadratico medio per la regressione).

Esploriamo ciascun algoritmo:

### Regressione Lineare

La regressione lineare è un algoritmo di **regressione** utilizzato per prevedere valori numerici continui. Assume una relazione lineare tra le caratteristiche di input (variabili indipendenti) e l'output (variabile dipendente). Il modello cerca di adattare una retta (o un iperpiano in dimensioni superiori) che descriva meglio la relazione tra le caratteristiche e l'obiettivo. Questo viene tipicamente fatto minimizzando la somma degli errori quadratici tra i valori previsti e quelli reali (metodo dei minimi quadrati ordinari).

Il modo più semplice per rappresentare la regressione lineare è con una retta:
```plaintext
y = mx + b
```
Dove:

- `y` è il valore previsto (output)
- `m` è la pendenza della linea (coefficiente)
- `x` è la caratteristica di input
- `b` è l'intercetta y

L'obiettivo della regressione lineare è trovare la retta che meglio si adatta e che minimizza la differenza tra i valori previsti e i valori reali nel dataset. Naturalmente, questo è molto semplice, sarebbe una retta che separa 2 categorie, ma se vengono aggiunte più dimensioni, la retta diventa più complessa:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Casi d'uso nella cybersecurity:* La regressione lineare in sé è meno comune per i compiti di sicurezza core (che sono spesso classificazione), ma può essere applicata per prevedere risultati numerici. Ad esempio, si potrebbe utilizzare la regressione lineare per **prevedere il volume del traffico di rete** o **stimare il numero di attacchi in un periodo di tempo** basandosi su dati storici. Potrebbe anche prevedere un punteggio di rischio o il tempo atteso fino alla rilevazione di un attacco, date certe metriche di sistema. Nella pratica, gli algoritmi di classificazione (come la regressione logistica o gli alberi) sono più frequentemente utilizzati per rilevare intrusioni o malware, ma la regressione lineare funge da base ed è utile per analisi orientate alla regressione.

#### **Caratteristiche chiave della regressione lineare:**

-   **Tipo di problema:** Regressione (previsione di valori continui). Non adatta per classificazione diretta a meno che non venga applicata una soglia all'output.

-   **Interpretabilità:** Alta -- i coefficienti sono facili da interpretare, mostrando l'effetto lineare di ciascuna caratteristica.

-   **Vantaggi:** Semplice e veloce; una buona base per compiti di regressione; funziona bene quando la vera relazione è approssimativamente lineare.

-   **Limitazioni:** Non può catturare relazioni complesse o non lineari (senza ingegneria manuale delle caratteristiche); soggetta a underfitting se le relazioni sono non lineari; sensibile agli outlier che possono distorcere i risultati.

-   **Trovare la miglior adattamento:** Per trovare la retta di miglior adattamento che separa le possibili categorie, utilizziamo un metodo chiamato **Ordinary Least Squares (OLS)**. Questo metodo minimizza la somma delle differenze quadrate tra i valori osservati e i valori previsti dal modello lineare.

<details>
<summary>Esempio -- Previsione della durata della connessione (Regressione) in un dataset di intrusioni
</summary>
Di seguito dimostriamo la regressione lineare utilizzando il dataset di cybersecurity NSL-KDD. Tratteremo questo come un problema di regressione prevedendo la `durata` delle connessioni di rete basandoci su altre caratteristiche. (In realtà, `durata` è una caratteristica di NSL-KDD; la utilizziamo qui solo per illustrare la regressione.) Carichiamo il dataset, lo preprocessiamo (codifichiamo le caratteristiche categoriche), alleniamo un modello di regressione lineare e valutiamo l'errore quadratico medio (MSE) e il punteggio R² su un set di test.
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
In questo esempio, il modello di regressione lineare cerca di prevedere la `durata` della connessione da altre caratteristiche di rete. Misuriamo le prestazioni con l'Errore Quadratico Medio (MSE) e R². Un R² vicino a 1.0 indicherebbe che il modello spiega la maggior parte della varianza in `durata`, mentre un R² basso o negativo indica un cattivo adattamento. (Non sorprenderti se l'R² è basso qui -- prevedere la `durata` potrebbe essere difficile dalle caratteristiche date, e la regressione lineare potrebbe non catturare i modelli se sono complessi.)
</details>

### Regressione Logistica

La regressione logistica è un algoritmo di **classificazione** che modella la probabilità che un'istanza appartenga a una particolare classe (tipicamente la classe "positiva"). Nonostante il suo nome, la regressione *logistica* è utilizzata per risultati discreti (a differenza della regressione lineare che è per risultati continui). È particolarmente utilizzata per la **classificazione binaria** (due classi, ad esempio, malevolo vs. benigno), ma può essere estesa a problemi multi-classe (utilizzando approcci softmax o one-vs-rest).

La regressione logistica utilizza la funzione logistica (nota anche come funzione sigmoide) per mappare i valori previsti a probabilità. Si noti che la funzione sigmoide è una funzione con valori compresi tra 0 e 1 che cresce in una curva a S secondo le esigenze della classificazione, utile per compiti di classificazione binaria. Pertanto, ogni caratteristica di ciascun input è moltiplicata per il suo peso assegnato, e il risultato è passato attraverso la funzione sigmoide per produrre una probabilità:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Dove:

- `p(y=1|x)` è la probabilità che l'output `y` sia 1 dato l'input `x`
- `e` è la base del logaritmo naturale
- `z` è una combinazione lineare delle caratteristiche di input, tipicamente rappresentata come `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Nota come, ancora una volta, nella sua forma più semplice sia una retta, ma nei casi più complessi diventa un iperpiano con diverse dimensioni (una per caratteristica).

> [!TIP]
> *Casi d'uso nella cybersecurity:* Poiché molti problemi di sicurezza sono essenzialmente decisioni sì/no, la regressione logistica è ampiamente utilizzata. Ad esempio, un sistema di rilevamento delle intrusioni potrebbe utilizzare la regressione logistica per decidere se una connessione di rete è un attacco basato sulle caratteristiche di quella connessione. Nella rilevazione di phishing, la regressione logistica può combinare le caratteristiche di un sito web (lunghezza dell'URL, presenza del simbolo "@", ecc.) in una probabilità di essere phishing. È stata utilizzata nei filtri antispam di prima generazione e rimane una solida base per molti compiti di classificazione.

#### Regressione Logistica per classificazione non binaria

La regressione logistica è progettata per la classificazione binaria, ma può essere estesa per gestire problemi multi-classe utilizzando tecniche come **one-vs-rest** (OvR) o **softmax regression**. In OvR, viene addestrato un modello di regressione logistica separato per ogni classe, trattandola come la classe positiva contro tutte le altre. La classe con la probabilità prevista più alta viene scelta come previsione finale. La regressione softmax generalizza la regressione logistica a più classi applicando la funzione softmax allo strato di output, producendo una distribuzione di probabilità su tutte le classi.

#### **Caratteristiche chiave della Regressione Logistica:**

-   **Tipo di Problema:** Classificazione (di solito binaria). Prevede la probabilità della classe positiva.

-   **Interpretabilità:** Alta -- come nella regressione lineare, i coefficienti delle caratteristiche possono indicare come ciascuna caratteristica influisce sui log-odds dell'esito. Questa trasparenza è spesso apprezzata nella sicurezza per comprendere quali fattori contribuiscono a un allerta.

-   **Vantaggi:** Semplice e veloce da addestrare; funziona bene quando la relazione tra le caratteristiche e i log-odds dell'esito è lineare. Produce probabilità, consentendo la valutazione del rischio. Con una regolarizzazione appropriata, generalizza bene e può gestire meglio la multicollinearità rispetto alla semplice regressione lineare.

-   **Limitazioni:** Presuppone un confine decisionale lineare nello spazio delle caratteristiche (fallisce se il vero confine è complesso/non lineare). Potrebbe avere prestazioni inferiori su problemi in cui le interazioni o gli effetti non lineari sono critici, a meno che non si aggiungano manualmente caratteristiche polinomiali o di interazione. Inoltre, la regressione logistica è meno efficace se le classi non sono facilmente separabili da una combinazione lineare di caratteristiche.


<details>
<summary>Esempio -- Rilevamento di Siti Web di Phishing con Regressione Logistica:</summary>

Utilizzeremo un **Dataset di Siti Web di Phishing** (dal repository UCI) che contiene caratteristiche estratte di siti web (come se l'URL ha un indirizzo IP, l'età del dominio, presenza di elementi sospetti in HTML, ecc.) e un'etichetta che indica se il sito è phishing o legittimo. Addestriamo un modello di regressione logistica per classificare i siti web e poi valutiamo la sua accuratezza, precisione, richiamo, F1-score e ROC AUC su un campione di test.
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
In questo esempio di rilevamento del phishing, la regressione logistica produce una probabilità per ciascun sito web di essere phishing. Valutando l'accuratezza, la precisione, il richiamo e l'F1, otteniamo un'idea delle prestazioni del modello. Ad esempio, un alto richiamo significherebbe che cattura la maggior parte dei siti di phishing (importante per la sicurezza per ridurre al minimo gli attacchi mancati), mentre un'alta precisione significa che ha pochi falsi allarmi (importante per evitare l'affaticamento degli analisti). L'ROC AUC (Area sotto la curva ROC) fornisce una misura delle prestazioni indipendente dalla soglia (1.0 è ideale, 0.5 non è meglio del caso). La regressione logistica spesso si comporta bene in tali compiti, ma se il confine decisionale tra siti di phishing e legittimi è complesso, potrebbero essere necessari modelli non lineari più potenti.

</details>

### Alberi Decisionali

Un albero decisionale è un **algoritmo di apprendimento supervisionato** versatile che può essere utilizzato sia per compiti di classificazione che di regressione. Impara un modello gerarchico simile a un albero di decisioni basato sulle caratteristiche dei dati. Ogni nodo interno dell'albero rappresenta un test su una particolare caratteristica, ogni ramo rappresenta un risultato di quel test e ogni nodo foglia rappresenta una classe prevista (per la classificazione) o un valore (per la regressione).

Per costruire un albero, algoritmi come CART (Classification and Regression Tree) utilizzano misure come **impurità di Gini** o **guadagno informativo (entropia)** per scegliere la migliore caratteristica e soglia per suddividere i dati a ciascun passo. L'obiettivo a ciascuna suddivisione è partizionare i dati per aumentare l'omogeneità della variabile target nei sottoinsiemi risultanti (per la classificazione, ogni nodo mira a essere il più puro possibile, contenendo prevalentemente una singola classe).

Gli alberi decisionali sono **altamente interpretabili**: si può seguire il percorso dalla radice alla foglia per comprendere la logica dietro una previsione (ad esempio, *"SE `service = telnet` E `src_bytes > 1000` E `failed_logins > 3` ALLORA classificare come attacco"*). Questo è prezioso nella cybersecurity per spiegare perché è stato sollevato un certo allerta. Gli alberi possono gestire naturalmente sia dati numerici che categorici e richiedono poca pre-elaborazione (ad esempio, la scalatura delle caratteristiche non è necessaria).

Tuttavia, un singolo albero decisionale può facilmente sovradattarsi ai dati di addestramento, specialmente se cresce in profondità (molte suddivisioni). Tecniche come la potatura (limitare la profondità dell'albero o richiedere un numero minimo di campioni per foglia) sono spesso utilizzate per prevenire il sovradattamento.

Ci sono 3 componenti principali di un albero decisionale:
- **Nodo Radice**: Il nodo superiore dell'albero, che rappresenta l'intero dataset.
- **Nodi Interni**: Nodi che rappresentano caratteristiche e decisioni basate su quelle caratteristiche.
- **Nodi Foglia**: Nodi che rappresentano il risultato finale o la previsione.

Un albero potrebbe finire per apparire così:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Casi d'uso nella cybersecurity:* Gli alberi decisionali sono stati utilizzati nei sistemi di rilevamento delle intrusioni per derivare **regole** per identificare attacchi. Ad esempio, i primi IDS come i sistemi basati su ID3/C4.5 genererebbero regole leggibili dall'uomo per distinguere il traffico normale da quello malevolo. Sono anche utilizzati nell'analisi del malware per decidere se un file è malevolo in base alle sue caratteristiche (dimensione del file, entropia della sezione, chiamate API, ecc.). La chiarezza degli alberi decisionali li rende utili quando è necessaria trasparenza: un analista può ispezionare l'albero per convalidare la logica di rilevamento.

#### **Caratteristiche chiave degli Alberi Decisionali:**

-   **Tipo di Problema:** Sia classificazione che regressione. Comunemente utilizzati per la classificazione di attacchi vs. traffico normale, ecc.

-   **Interpretabilità:** Molto alta -- le decisioni del modello possono essere visualizzate e comprese come un insieme di regole if-then. Questo è un grande vantaggio nella sicurezza per fiducia e verifica del comportamento del modello.

-   **Vantaggi:** Possono catturare relazioni non lineari e interazioni tra le caratteristiche (ogni divisione può essere vista come un'interazione). Non è necessario scalare le caratteristiche o codificare in one-hot le variabili categoriche: gli alberi gestiscono questi aspetti nativamente. Inferenza veloce (la previsione è semplicemente seguire un percorso nell'albero).

-   **Limitazioni:** Inclini all'overfitting se non controllati (un albero profondo può memorizzare il set di addestramento). Possono essere instabili: piccole modifiche nei dati potrebbero portare a una struttura ad albero diversa. Come modelli singoli, la loro accuratezza potrebbe non corrispondere a metodi più avanzati (gli ensemble come Random Forests generalmente performano meglio riducendo la varianza).

-   **Trovare la Migliore Divisione:**
- **Impurità di Gini**: Misura l'impurità di un nodo. Un'impurità di Gini più bassa indica una migliore divisione. La formula è:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Dove `p_i` è la proporzione di istanze nella classe `i`.

- **Entropia**: Misura l'incertezza nel dataset. Un'entropia più bassa indica una migliore divisione. La formula è:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Dove `p_i` è la proporzione di istanze nella classe `i`.

- **Guadagno Informativo**: La riduzione dell'entropia o dell'impurità di Gini dopo una divisione. Maggiore è il guadagno informativo, migliore è la divisione. Si calcola come:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Inoltre, un albero termina quando:
- Tutte le istanze in un nodo appartengono alla stessa classe. Questo potrebbe portare a overfitting.
- La profondità massima (hardcoded) dell'albero è raggiunta. Questo è un modo per prevenire l'overfitting.
- Il numero di istanze in un nodo è al di sotto di una certa soglia. Questo è anche un modo per prevenire l'overfitting.
- Il guadagno informativo da ulteriori divisioni è al di sotto di una certa soglia. Questo è anche un modo per prevenire l'overfitting.

<details>
<summary>Esempio -- Albero Decisionale per il Rilevamento delle Intrusioni:</summary>
Alleneremo un albero decisionale sul dataset NSL-KDD per classificare le connessioni di rete come *normali* o *attacco*. NSL-KDD è una versione migliorata del classico dataset KDD Cup 1999, con caratteristiche come tipo di protocollo, servizio, durata, numero di accessi falliti, ecc., e un'etichetta che indica il tipo di attacco o "normale". Mapperemo tutti i tipi di attacco a una classe di "anomalia" (classificazione binaria: normale vs anomalia). Dopo l'addestramento, valuteremo le prestazioni dell'albero sul set di test.
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
In questo esempio di albero decisionale, abbiamo limitato la profondità dell'albero a 10 per evitare un estremo overfitting (il parametro `max_depth=10`). Le metriche mostrano quanto bene l'albero distingue il traffico normale da quello di attacco. Un alto richiamo significherebbe che cattura la maggior parte degli attacchi (importante per un IDS), mentre un'alta precisione significa pochi falsi allarmi. Gli alberi decisionali raggiungono spesso una precisione decente su dati strutturati, ma un singolo albero potrebbe non raggiungere le migliori prestazioni possibili. Tuttavia, l'*interpretabilità* del modello è un grande vantaggio: potremmo esaminare le suddivisioni dell'albero per vedere, ad esempio, quali caratteristiche (ad es., `service`, `src_bytes`, ecc.) sono più influenti nel segnalare una connessione come malevola.

</details>

### Random Forests

Random Forest è un metodo di **ensemble learning** che si basa sugli alberi decisionali per migliorare le prestazioni. Una random forest addestra più alberi decisionali (da qui "foresta") e combina le loro uscite per fare una previsione finale (per la classificazione, tipicamente tramite voto di maggioranza). Le due idee principali in una random forest sono **bagging** (bootstrap aggregating) e **randomness delle caratteristiche**:

-   **Bagging:** Ogni albero è addestrato su un campione bootstrap casuale dei dati di addestramento (campionato con sostituzione). Questo introduce diversità tra gli alberi.

-   **Randomness delle Caratteristiche:** Ad ogni suddivisione in un albero, viene considerato un sottoinsieme casuale di caratteristiche per la suddivisione (invece di tutte le caratteristiche). Questo decora ulteriormente gli alberi.

Mediare i risultati di molti alberi riduce la varianza che un singolo albero decisionale potrebbe avere. In termini semplici, gli alberi individuali potrebbero overfittare o essere rumorosi, ma un gran numero di alberi diversi che votano insieme smussa quegli errori. Il risultato è spesso un modello con **maggiore accuratezza** e migliore generalizzazione rispetto a un singolo albero decisionale. Inoltre, le random forests possono fornire una stima dell'importanza delle caratteristiche (guardando a quanto ciascuna caratteristica riduce l'impurità in media).

Le random forests sono diventate un **cavallo di battaglia nella cybersecurity** per compiti come il rilevamento delle intrusioni, la classificazione del malware e il rilevamento dello spam. Spesso funzionano bene subito, con una minima regolazione, e possono gestire grandi set di caratteristiche. Ad esempio, nel rilevamento delle intrusioni, una random forest può superare un singolo albero decisionale catturando schemi di attacco più sottili con meno falsi positivi. La ricerca ha dimostrato che le random forests si comportano favorevolmente rispetto ad altri algoritmi nella classificazione degli attacchi in dataset come NSL-KDD e UNSW-NB15.

#### **Caratteristiche chiave delle Random Forests:**

-   **Tipo di Problema:** Principalmente classificazione (utilizzato anche per la regressione). Molto adatto per dati strutturati ad alta dimensione comuni nei log di sicurezza.

-   **Interpretabilità:** Inferiore rispetto a un singolo albero decisionale: non puoi facilmente visualizzare o spiegare centinaia di alberi contemporaneamente. Tuttavia, i punteggi di importanza delle caratteristiche forniscono alcune informazioni su quali attributi sono più influenti.

-   **Vantaggi:** Generalmente maggiore accuratezza rispetto ai modelli ad albero singolo grazie all'effetto ensemble. Robusto all'overfitting: anche se gli alberi individuali overfittano, l'ensemble generalizza meglio. Gestisce sia caratteristiche numeriche che categoriche e può gestire dati mancanti in una certa misura. È anche relativamente robusto agli outlier.

-   **Limitazioni:** La dimensione del modello può essere grande (molti alberi, ognuno potenzialmente profondo). Le previsioni sono più lente rispetto a un singolo albero (poiché devi aggregare su molti alberi). Meno interpretabile: mentre conosci le caratteristiche importanti, la logica esatta non è facilmente tracciabile come una semplice regola. Se il dataset è estremamente ad alta dimensione e sparso, addestrare una foresta molto grande può essere computazionalmente pesante.

-   **Processo di Addestramento:**
1. **Bootstrap Sampling**: Campiona casualmente i dati di addestramento con sostituzione per creare più sottoinsiemi (campioni bootstrap).
2. **Costruzione dell'Albero**: Per ogni campione bootstrap, costruisci un albero decisionale utilizzando un sottoinsieme casuale di caratteristiche ad ogni suddivisione. Questo introduce diversità tra gli alberi.
3. **Aggregazione**: Per i compiti di classificazione, la previsione finale viene effettuata prendendo un voto di maggioranza tra le previsioni di tutti gli alberi. Per i compiti di regressione, la previsione finale è la media delle previsioni di tutti gli alberi.

<details>
<summary>Esempio -- Random Forest per il Rilevamento delle Intrusioni (NSL-KDD):</summary>
Utilizzeremo lo stesso dataset NSL-KDD (etichettato binario come normale vs anomalia) e addestreremo un classificatore Random Forest. Ci aspettiamo che la random forest si comporti altrettanto bene o meglio dell'albero decisionale singolo, grazie alla media dell'ensemble che riduce la varianza. Lo valuteremo con le stesse metriche.
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
Il random forest raggiunge tipicamente risultati solidi in questo compito di rilevamento delle intrusioni. Potremmo osservare un miglioramento in metriche come F1 o AUC rispetto all'albero decisionale singolo, specialmente in richiamo o precisione, a seconda dei dati. Questo è in linea con la comprensione che *"Random Forest (RF) è un classificatore ensemble e si comporta bene rispetto ad altri classificatori tradizionali per una classificazione efficace degli attacchi."*. In un contesto di operazioni di sicurezza, un modello di random forest potrebbe segnalare attacchi in modo più affidabile riducendo i falsi allarmi, grazie alla media di molte regole decisionali. L'importanza delle caratteristiche dal forest potrebbe dirci quali caratteristiche di rete sono più indicative di attacchi (ad esempio, determinati servizi di rete o conteggi insoliti di pacchetti).

</details>

### Support Vector Machines (SVM)

Le Support Vector Machines sono potenti modelli di apprendimento supervisionato utilizzati principalmente per la classificazione (e anche per la regressione come SVR). Un SVM cerca di trovare l'**iperpiano separatore ottimale** che massimizza il margine tra due classi. Solo un sottoinsieme di punti di addestramento (i "support vectors" più vicini al confine) determina la posizione di questo iperpiano. Massimizzando il margine (distanza tra i support vectors e l'iperpiano), gli SVM tendono a ottenere una buona generalizzazione.

La chiave della potenza degli SVM è la capacità di utilizzare **funzioni kernel** per gestire relazioni non lineari. I dati possono essere implicitamente trasformati in uno spazio delle caratteristiche di dimensione superiore dove potrebbe esistere un separatore lineare. I kernel comuni includono polinomiale, funzione di base radiale (RBF) e sigmoide. Ad esempio, se le classi di traffico di rete non sono separabili linearmente nello spazio delle caratteristiche grezze, un kernel RBF può mappare queste classi in una dimensione superiore dove l'SVM trova una divisione lineare (che corrisponde a un confine non lineare nello spazio originale). La flessibilità nella scelta dei kernel consente agli SVM di affrontare una varietà di problemi.

Gli SVM sono noti per funzionare bene in situazioni con spazi delle caratteristiche ad alta dimensione (come dati testuali o sequenze di opcode di malware) e in casi in cui il numero di caratteristiche è grande rispetto al numero di campioni. Sono stati popolari in molte applicazioni di cybersecurity precoci come la classificazione del malware e il rilevamento delle intrusioni basato su anomalie negli anni 2000, mostrando spesso alta accuratezza.

Tuttavia, gli SVM non scalano facilmente a dataset molto grandi (la complessità di addestramento è super-lineare nel numero di campioni e l'uso della memoria può essere elevato poiché potrebbe essere necessario memorizzare molti support vectors). In pratica, per compiti come il rilevamento delle intrusioni di rete con milioni di record, l'SVM potrebbe essere troppo lento senza un attento sottocampionamento o l'uso di metodi approssimativi.

#### **Caratteristiche chiave degli SVM:**

-   **Tipo di Problema:** Classificazione (binaria o multiclass tramite one-vs-one/one-vs-rest) e varianti di regressione. Spesso utilizzati nella classificazione binaria con chiara separazione del margine.

-   **Interpretabilità:** Media -- Gli SVM non sono così interpretabili come gli alberi decisionali o la regressione logistica. Anche se puoi identificare quali punti dati sono support vectors e avere un'idea di quali caratteristiche potrebbero essere influenti (attraverso i pesi nel caso del kernel lineare), in pratica gli SVM (soprattutto con kernel non lineari) sono trattati come classificatori a scatola nera.

-   **Vantaggi:** Efficaci in spazi ad alta dimensione; possono modellare confini decisionali complessi con il trucco del kernel; robusti all'overfitting se il margine è massimizzato (soprattutto con un appropriato parametro di regolarizzazione C); funzionano bene anche quando le classi non sono separate da una grande distanza (trovano il miglior confine di compromesso).

-   **Limitazioni:** **Intensivo dal punto di vista computazionale** per grandi dataset (sia l'addestramento che la previsione scalano male man mano che i dati crescono). Richiede una sintonizzazione attenta dei parametri del kernel e di regolarizzazione (C, tipo di kernel, gamma per RBF, ecc.). Non fornisce direttamente output probabilistici (anche se si può utilizzare la scalatura di Platt per ottenere probabilità). Inoltre, gli SVM possono essere sensibili alla scelta dei parametri del kernel --- una scelta errata può portare a underfit o overfit.

*Use cases in cybersecurity:* Gli SVM sono stati utilizzati nella **rilevazione di malware** (ad esempio, classificando file in base a caratteristiche estratte o sequenze di opcode), **rilevamento di anomalie di rete** (classificando il traffico come normale o malevolo) e **rilevamento di phishing** (utilizzando caratteristiche degli URL). Ad esempio, un SVM potrebbe prendere le caratteristiche di un'email (conteggi di determinate parole chiave, punteggi di reputazione del mittente, ecc.) e classificarla come phishing o legittima. Sono stati anche applicati al **rilevamento delle intrusioni** su set di caratteristiche come KDD, raggiungendo spesso alta accuratezza a costo di computazione.

<details>
<summary>Esempio -- SVM per la classificazione del malware:</summary>
Utilizzeremo di nuovo il dataset dei siti web di phishing, questa volta con un SVM. Poiché gli SVM possono essere lenti, utilizzeremo un sottoinsieme dei dati per l'addestramento se necessario (il dataset è di circa 11k istanze, che l'SVM può gestire ragionevolmente). Utilizzeremo un kernel RBF che è una scelta comune per dati non lineari, e abiliteremo le stime di probabilità per calcolare ROC AUC.
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
Il modello SVM restituirà metriche che possiamo confrontare con la regressione logistica sullo stesso compito. Potremmo scoprire che SVM raggiunge un'alta accuratezza e AUC se i dati sono ben separati dalle caratteristiche. D'altra parte, se il dataset avesse molto rumore o classi sovrapposte, SVM potrebbe non superare significativamente la regressione logistica. Nella pratica, gli SVM possono dare un impulso quando ci sono relazioni complesse e non lineari tra le caratteristiche e la classe -- il kernel RBF può catturare confini decisionali curvi che la regressione logistica perderebbe. Come per tutti i modelli, è necessaria una sintonizzazione attenta dei parametri `C` (regolarizzazione) e del kernel (come `gamma` per RBF) per bilanciare bias e varianza.

</details>

#### Differenza tra Regressioni Logistiche e SVM

| Aspetto | **Regressione Logistica** | **Macchine a Vettori di Supporto** |
|---|---|---|
| **Funzione obiettivo** | Minimizza **log‑loss** (cross‑entropy). | Massimizza il **margine** mentre minimizza **hinge‑loss**. |
| **Confine decisionale** | Trova il **iperpiano di miglior adattamento** che modella _P(y\|x)_. | Trova il **iperpiano a margine massimo** (gap più grande rispetto ai punti più vicini). |
| **Output** | **Probabilistico** – fornisce probabilità di classe calibrate tramite σ(w·x + b). | **Deterministico** – restituisce etichette di classe; le probabilità richiedono lavoro extra (es. Platt scaling). |
| **Regolarizzazione** | L2 (predefinito) o L1, bilancia direttamente under/over‑fitting. | Il parametro C bilancia la larghezza del margine rispetto alle classificazioni errate; i parametri del kernel aggiungono complessità. |
| **Kernels / Non‑lineare** | La forma nativa è **lineare**; la non linearità è aggiunta tramite ingegneria delle caratteristiche. | Il **kernel trick** integrato (RBF, polinomiale, ecc.) consente di modellare confini complessi in uno spazio ad alta dimensione. |
| **Scalabilità** | Risolve un'ottimizzazione convessa in **O(nd)**; gestisce bene n molto grandi. | L'addestramento può essere **O(n²–n³)** in termini di memoria/tempo senza risolutori specializzati; meno adatto a n enormi. |
| **Interpretabilità** | **Alta** – i pesi mostrano l'influenza delle caratteristiche; il rapporto di probabilità è intuitivo. | **Bassa** per i kernel non lineari; i vettori di supporto sono sparsi ma non facili da spiegare. |
| **Sensibilità agli outlier** | Usa log‑loss morbido → meno sensibile. | Hinge‑loss con margine rigido può essere **sensibile**; il margine morbido (C) mitiga. |
| **Casi d'uso tipici** | Valutazione del credito, rischio medico, test A/B – dove contano **probabilità e spiegabilità**. | Classificazione di immagini/testo, bio‑informatica – dove contano **confini complessi** e **dati ad alta dimensione**. |

* **Se hai bisogno di probabilità calibrate, interpretabilità, o operi su enormi dataset — scegli Regressione Logistica.**
* **Se hai bisogno di un modello flessibile che possa catturare relazioni non lineari senza ingegneria manuale delle caratteristiche — scegli SVM (con kernel).**
* Entrambi ottimizzano obiettivi convexi, quindi **i minimi globali sono garantiti**, ma i kernel di SVM aggiungono iper-parametri e costi computazionali.

### Naive Bayes

Naive Bayes è una famiglia di **classificatori probabilistici** basati sull'applicazione del Teorema di Bayes con una forte assunzione di indipendenza tra le caratteristiche. Nonostante questa assunzione "naive", Naive Bayes spesso funziona sorprendentemente bene per alcune applicazioni, specialmente quelle che coinvolgono dati testuali o categorici, come il rilevamento dello spam.


#### Teorema di Bayes

Il teorema di Bayes è la base dei classificatori Naive Bayes. Relaziona le probabilità condizionali e marginali di eventi casuali. La formula è:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Dove:
- `P(A|B)` è la probabilità posteriore della classe `A` dato il carattere `B`.
- `P(B|A)` è la verosimiglianza del carattere `B` dato la classe `A`.
- `P(A)` è la probabilità prior della classe `A`.
- `P(B)` è la probabilità prior del carattere `B`.

Ad esempio, se vogliamo classificare se un testo è scritto da un bambino o un adulto, possiamo usare le parole nel testo come caratteristiche. Basandosi su alcuni dati iniziali, il classificatore Naive Bayes calcolerà precedentemente le probabilità di ciascuna parola di appartenere a ciascuna potenziale classe (bambino o adulto). Quando viene fornito un nuovo testo, calcolerà la probabilità di ciascuna potenziale classe dato le parole nel testo e sceglierà la classe con la probabilità più alta.

Come puoi vedere in questo esempio, il classificatore Naive Bayes è molto semplice e veloce, ma assume che le caratteristiche siano indipendenti, il che non è sempre il caso nei dati del mondo reale.

#### Tipi di classificatori Naive Bayes

Ci sono diversi tipi di classificatori Naive Bayes, a seconda del tipo di dati e della distribuzione delle caratteristiche:
- **Gaussian Naive Bayes**: Assume che le caratteristiche seguano una distribuzione gaussiana (normale). È adatto per dati continui.
- **Multinomial Naive Bayes**: Assume che le caratteristiche seguano una distribuzione multinomiale. È adatto per dati discreti, come il conteggio delle parole nella classificazione del testo.
- **Bernoulli Naive Bayes**: Assume che le caratteristiche siano binarie (0 o 1). È adatto per dati binari, come la presenza o l'assenza di parole nella classificazione del testo.
- **Categorical Naive Bayes**: Assume che le caratteristiche siano variabili categoriche. È adatto per dati categorici, come la classificazione della frutta in base al colore e alla forma.

#### **Caratteristiche chiave di Naive Bayes:**

-   **Tipo di problema:** Classificazione (binaria o multi-classe). Comunemente usato per compiti di classificazione del testo nella cybersecurity (spam, phishing, ecc.).

-   **Interpretabilità:** Media -- non è così direttamente interpretabile come un albero decisionale, ma si possono ispezionare le probabilità apprese (ad esempio, quali parole sono più probabili negli email spam rispetto a quelli legittimi). La forma del modello (probabilità per ciascuna caratteristica data la classe) può essere compresa se necessario.

-   **Vantaggi:** **Addestramento e previsione molto veloci**, anche su grandi dataset (lineare nel numero di istanze * numero di caratteristiche). Richiede una quantità relativamente piccola di dati per stimare le probabilità in modo affidabile, specialmente con una corretta smussatura. È spesso sorprendentemente accurato come baseline, specialmente quando le caratteristiche contribuiscono indipendentemente come evidenza alla classe. Funziona bene con dati ad alta dimensione (ad esempio, migliaia di caratteristiche da testo). Non richiede una messa a punto complessa oltre alla definizione di un parametro di smussatura.

-   **Limitazioni:** L'assunzione di indipendenza può limitare l'accuratezza se le caratteristiche sono altamente correlate. Ad esempio, nei dati di rete, caratteristiche come `src_bytes` e `dst_bytes` potrebbero essere correlate; Naive Bayes non catturerà quell'interazione. Man mano che la dimensione dei dati cresce molto, modelli più espressivi (come ensemble o reti neurali) possono superare NB apprendendo le dipendenze delle caratteristiche. Inoltre, se è necessaria una certa combinazione di caratteristiche per identificare un attacco (non solo caratteristiche individuali indipendentemente), NB avrà difficoltà.

> [!TIP]
> *Casi d'uso nella cybersecurity:* L'uso classico è **rilevamento dello spam** -- Naive Bayes era il nucleo dei primi filtri antispam, utilizzando le frequenze di determinati token (parole, frasi, indirizzi IP) per calcolare la probabilità che un'email sia spam. È anche usato nel **rilevamento di email di phishing** e nella **classificazione degli URL**, dove la presenza di determinate parole chiave o caratteristiche (come "login.php" in un URL, o `@` in un percorso URL) contribuisce alla probabilità di phishing. Nell'analisi del malware, si potrebbe immaginare un classificatore Naive Bayes che utilizza la presenza di determinate chiamate API o permessi nel software per prevedere se è malware. Sebbene algoritmi più avanzati spesso performino meglio, Naive Bayes rimane una buona baseline grazie alla sua velocità e semplicità.

<details>
<summary>Esempio -- Naive Bayes per il rilevamento di phishing:</summary>
Per dimostrare Naive Bayes, utilizzeremo Gaussian Naive Bayes sul dataset di intrusione NSL-KDD (con etichette binarie). Gaussian NB tratterà ciascuna caratteristica come seguente una distribuzione normale per classe. Questa è una scelta approssimativa poiché molte caratteristiche di rete sono discrete o altamente distorte, ma mostra come si applicherebbe NB ai dati delle caratteristiche continue. Potremmo anche scegliere Bernoulli NB su un dataset di caratteristiche binarie (come un insieme di avvisi attivati), ma ci atteniamo a NSL-KDD qui per continuità.
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
Questo codice addestra un classificatore Naive Bayes per rilevare attacchi. Naive Bayes calcolerà cose come `P(service=http | Attack)` e `P(Service=http | Normal)` basandosi sui dati di addestramento, assumendo l'indipendenza tra le caratteristiche. Utilizzerà quindi queste probabilità per classificare nuove connessioni come normali o attacchi in base alle caratteristiche osservate. Le prestazioni di NB su NSL-KDD potrebbero non essere elevate come modelli più avanzati (poiché l'indipendenza delle caratteristiche è violata), ma sono spesso decenti e offrono il vantaggio di una velocità estrema. In scenari come il filtraggio delle email in tempo reale o la triage iniziale degli URL, un modello Naive Bayes può rapidamente segnalare casi ovviamente malevoli con un basso utilizzo delle risorse.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors è uno degli algoritmi di machine learning più semplici. È un metodo **non parametrico, basato su istanze** che fa previsioni basate sulla somiglianza con esempi nel set di addestramento. L'idea per la classificazione è: per classificare un nuovo punto dati, trovare i **k** punti più vicini nei dati di addestramento (i suoi "vicini più prossimi") e assegnare la classe maggioritaria tra quei vicini. La "vicinanza" è definita da una metrica di distanza, tipicamente la distanza euclidea per dati numerici (altre distanze possono essere utilizzate per diversi tipi di caratteristiche o problemi).

K-NN richiede *nessun addestramento esplicito* -- la fase di "addestramento" consiste semplicemente nel memorizzare il dataset. Tutto il lavoro avviene durante la query (previsione): l'algoritmo deve calcolare le distanze dal punto di query a tutti i punti di addestramento per trovare i più vicini. Questo rende il tempo di previsione **lineare nel numero di campioni di addestramento**, il che può essere costoso per grandi dataset. Per questo motivo, k-NN è più adatto per dataset più piccoli o scenari in cui è possibile scambiare memoria e velocità per semplicità.

Nonostante la sua semplicità, k-NN può modellare confini decisionali molto complessi (poiché effettivamente il confine decisionale può avere qualsiasi forma dettata dalla distribuzione degli esempi). Tende a funzionare bene quando il confine decisionale è molto irregolare e si dispone di molti dati -- essenzialmente lasciando che i dati "parlino da soli". Tuttavia, in alte dimensioni, le metriche di distanza possono diventare meno significative (maledizione della dimensionalità), e il metodo può avere difficoltà a meno che non si disponga di un numero enorme di campioni.

*Use cases in cybersecurity:* k-NN è stato applicato alla rilevazione di anomalie -- ad esempio, un sistema di rilevamento delle intrusioni potrebbe etichettare un evento di rete come malevolo se la maggior parte dei suoi vicini più prossimi (eventi precedenti) erano malevoli. Se il traffico normale forma cluster e gli attacchi sono outlier, un approccio K-NN (con k=1 o k piccolo) fa essenzialmente una **rilevazione di anomalie basata sui vicini più prossimi**. K-NN è stato anche utilizzato per classificare famiglie di malware tramite vettori di caratteristiche binarie: un nuovo file potrebbe essere classificato come una certa famiglia di malware se è molto vicino (nello spazio delle caratteristiche) a istanze note di quella famiglia. Nella pratica, k-NN non è comune come algoritmi più scalabili, ma è concettualmente semplice e talvolta utilizzato come baseline o per problemi su piccola scala.

#### **Caratteristiche chiave di k-NN:**

-   **Tipo di Problema:** Classificazione (esistono varianti di regressione). È un metodo di *apprendimento pigro* -- nessun adattamento esplicito del modello.

-   **Interpretabilità:** Bassa a media -- non esiste un modello globale o una spiegazione concisa, ma si possono interpretare i risultati guardando ai vicini più prossimi che hanno influenzato una decisione (ad esempio, "questo flusso di rete è stato classificato come malevolo perché è simile a questi 3 flussi malevoli noti"). Quindi, le spiegazioni possono essere basate su esempi.

-   **Vantaggi:** Molto semplice da implementare e comprendere. Non fa assunzioni sulla distribuzione dei dati (non parametrico). Può gestire naturalmente problemi multi-classe. È **adattivo** nel senso che i confini decisionali possono essere molto complessi, modellati dalla distribuzione dei dati.

-   **Limitazioni:** La previsione può essere lenta per grandi dataset (deve calcolare molte distanze). Intenso in termini di memoria -- memorizza tutti i dati di addestramento. Le prestazioni degradano in spazi di caratteristiche ad alta dimensione perché tutti i punti tendono a diventare quasi equidistanti (rendendo il concetto di "più vicino" meno significativo). È necessario scegliere *k* (numero di vicini) in modo appropriato -- un k troppo piccolo può essere rumoroso, un k troppo grande può includere punti irrilevanti di altre classi. Inoltre, le caratteristiche dovrebbero essere scalate in modo appropriato perché i calcoli delle distanze sono sensibili alla scala.

<details>
<summary>Esempio -- k-NN per la Rilevazione di Phishing:</summary>

Utilizzeremo di nuovo NSL-KDD (classificazione binaria). Poiché k-NN è computazionalmente pesante, utilizzeremo un sottoinsieme dei dati di addestramento per mantenerlo gestibile in questa dimostrazione. Sceglieremo, ad esempio, 20.000 campioni di addestramento su un totale di 125k, e utilizzeremo k=5 vicini. Dopo l'addestramento (in realtà solo memorizzando i dati), valuteremo sul set di test. Scala anche le caratteristiche per il calcolo delle distanze per garantire che nessuna singola caratteristica domini a causa della scala.
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
Il modello k-NN classificherà una connessione esaminando le 5 connessioni più vicine nel sottoinsieme del set di addestramento. Se, ad esempio, 4 di quei vicini sono attacchi (anomalie) e 1 è normale, la nuova connessione sarà classificata come un attacco. Le prestazioni potrebbero essere ragionevoli, anche se spesso non sono elevate come quelle di un Random Forest o SVM ben sintonizzati sugli stessi dati. Tuttavia, k-NN può a volte brillare quando le distribuzioni delle classi sono molto irregolari e complesse, utilizzando efficacemente una ricerca basata sulla memoria. In cybersecurity, k-NN (con k=1 o k piccolo) potrebbe essere utilizzato per la rilevazione di modelli di attacco noti per esempio, o come componente in sistemi più complessi (ad es., per il clustering e poi la classificazione basata sull'appartenenza al cluster).

### Gradient Boosting Machines (ad es., XGBoost)

Le Gradient Boosting Machines sono tra gli algoritmi più potenti per i dati strutturati. **Gradient boosting** si riferisce alla tecnica di costruire un insieme di apprendisti deboli (spesso alberi decisionali) in modo sequenziale, dove ogni nuovo modello corregge gli errori dell'insieme precedente. A differenza del bagging (Random Forests) che costruisce alberi in parallelo e li media, il boosting costruisce alberi *uno per uno*, ciascuno concentrandosi di più sulle istanze che gli alberi precedenti hanno predetto male.

Le implementazioni più popolari negli ultimi anni sono **XGBoost**, **LightGBM** e **CatBoost**, tutte librerie di gradient boosting decision tree (GBDT). Hanno avuto un enorme successo nelle competizioni e applicazioni di machine learning, spesso **raggiungendo prestazioni all'avanguardia su dataset tabulari**. In cybersecurity, ricercatori e professionisti hanno utilizzato alberi potenziati per compiti come **rilevamento di malware** (utilizzando caratteristiche estratte da file o comportamento in tempo reale) e **rilevamento di intrusioni di rete**. Ad esempio, un modello di gradient boosting può combinare molte regole deboli (alberi) come "se molti pacchetti SYN e porta insolita -> probabile scansione" in un forte rilevatore composito che tiene conto di molti schemi sottili.

Perché gli alberi potenziati sono così efficaci? Ogni albero nella sequenza è addestrato sugli *errori residui* (gradienti) delle previsioni dell'insieme attuale. In questo modo, il modello gradualmente **"potenzia"** le aree in cui è debole. L'uso di alberi decisionali come apprendisti di base significa che il modello finale può catturare interazioni complesse e relazioni non lineari. Inoltre, il boosting ha intrinsecamente una forma di regolarizzazione incorporata: aggiungendo molti piccoli alberi (e utilizzando un tasso di apprendimento per scalare i loro contributi), spesso generalizza bene senza un enorme overfitting, a condizione che vengano scelti parametri appropriati.

#### **Caratteristiche chiave del Gradient Boosting:**

-   **Tipo di Problema:** Principalmente classificazione e regressione. In sicurezza, solitamente classificazione (ad es., classificare binariamente una connessione o un file). Gestisce problemi binari, multi-classe (con perdita appropriata) e persino di ranking.

-   **Interpretabilità:** Bassa a media. Mentre un singolo albero potenziato è piccolo, un modello completo potrebbe avere centinaia di alberi, il che non è interpretabile per l'uomo nel suo insieme. Tuttavia, come Random Forest, può fornire punteggi di importanza delle caratteristiche, e strumenti come SHAP (SHapley Additive exPlanations) possono essere utilizzati per interpretare le singole previsioni in una certa misura.

-   **Vantaggi:** Spesso l'algoritmo **con le migliori prestazioni** per dati strutturati/tabulari. Può rilevare schemi e interazioni complesse. Ha molti parametri di regolazione (numero di alberi, profondità degli alberi, tasso di apprendimento, termini di regolarizzazione) per adattare la complessità del modello e prevenire l'overfitting. Le implementazioni moderne sono ottimizzate per la velocità (ad es., XGBoost utilizza informazioni sul gradiente di secondo ordine e strutture dati efficienti). Tende a gestire meglio i dati sbilanciati quando combinato con funzioni di perdita appropriate o regolando i pesi dei campioni.

-   **Limitazioni:** Più complesso da sintonizzare rispetto a modelli più semplici; l'addestramento può essere lento se gli alberi sono profondi o il numero di alberi è grande (anche se di solito è comunque più veloce rispetto all'addestramento di una rete neurale profonda comparabile sugli stessi dati). Il modello può overfittare se non sintonizzato (ad es., troppi alberi profondi con regolarizzazione insufficiente). A causa di molti iperparametri, utilizzare il gradient boosting in modo efficace può richiedere più esperienza o sperimentazione. Inoltre, come i metodi basati su alberi, non gestisce intrinsecamente i dati ad alta dimensione molto sparsi in modo efficiente come i modelli lineari o Naive Bayes (anche se può comunque essere applicato, ad es., nella classificazione del testo, ma potrebbe non essere la prima scelta senza ingegneria delle caratteristiche).

> [!TIP]
> *Casi d'uso in cybersecurity:* Quasi ovunque un albero decisionale o una foresta casuale potrebbero essere utilizzati, un modello di gradient boosting potrebbe raggiungere una maggiore accuratezza. Ad esempio, le competizioni di **rilevamento di malware di Microsoft** hanno visto un ampio utilizzo di XGBoost su caratteristiche ingegnerizzate da file binari. La ricerca sul **rilevamento di intrusioni di rete** riporta spesso risultati di vertice con GBDT (ad es., XGBoost su dataset CIC-IDS2017 o UNSW-NB15). Questi modelli possono prendere una vasta gamma di caratteristiche (tipi di protocollo, frequenza di determinati eventi, caratteristiche statistiche del traffico, ecc.) e combinarle per rilevare minacce. Nel rilevamento di phishing, il gradient boosting può combinare caratteristiche lessicali degli URL, caratteristiche di reputazione del dominio e caratteristiche del contenuto della pagina per raggiungere un'accuratezza molto elevata. L'approccio ensemble aiuta a coprire molti casi limite e sottigliezze nei dati.

<details>
<summary>Esempio -- XGBoost per il Rilevamento di Phishing:</summary>
Utilizzeremo un classificatore di gradient boosting sul dataset di phishing. Per mantenere le cose semplici e autonome, utilizzeremo `sklearn.ensemble.GradientBoostingClassifier` (che è un'implementazione più lenta ma diretta). Normalmente, si potrebbe utilizzare `xgboost` o `lightgbm` per migliori prestazioni e funzionalità aggiuntive. Addestreremo il modello e lo valuteremo in modo simile a prima.
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
Il modello di gradient boosting raggiungerà probabilmente un'accuratezza e un AUC molto elevati su questo dataset di phishing (spesso questi modelli possono superare il 95% di accuratezza con una corretta messa a punto su tali dati, come visto in letteratura. Questo dimostra perché i GBDT sono considerati *"il modello all'avanguardia per i dataset tabulari"* -- spesso superano algoritmi più semplici catturando schemi complessi. In un contesto di cybersecurity, questo potrebbe significare catturare più siti di phishing o attacchi con meno errori. Naturalmente, bisogna essere cauti riguardo all'overfitting -- di solito utilizziamo tecniche come la cross-validation e monitoriamo le prestazioni su un set di validazione quando sviluppiamo un modello del genere per il deployment.

</details>

### Combinare Modelli: Apprendimento Ensemble e Stacking

L'apprendimento ensemble è una strategia di **combinare più modelli** per migliorare le prestazioni complessive. Abbiamo già visto metodi ensemble specifici: Random Forest (un ensemble di alberi tramite bagging) e Gradient Boosting (un ensemble di alberi tramite boosting sequenziale). Ma gli ensemble possono essere creati anche in altri modi, come **voting ensembles** o **stacked generalization (stacking)**. L'idea principale è che modelli diversi possono catturare schemi diversi o avere debolezze diverse; combinandoli, possiamo **compensare gli errori di ciascun modello con i punti di forza di un altro**.

-   **Voting Ensemble:** In un semplice classificatore di voto, alleniamo più modelli diversi (ad esempio, una regressione logistica, un albero decisionale e un SVM) e li facciamo votare sulla previsione finale (voto di maggioranza per la classificazione). Se pesiamo i voti (ad esempio, peso maggiore ai modelli più accurati), si tratta di uno schema di voto pesato. Questo migliora tipicamente le prestazioni quando i modelli individuali sono ragionevolmente buoni e indipendenti -- l'ensemble riduce il rischio di errore di un modello individuale poiché altri possono correggerlo. È come avere un pannello di esperti piuttosto che un'unica opinione.

-   **Stacking (Stacked Ensemble):** Lo stacking va un passo oltre. Invece di un semplice voto, allena un **meta-modello** per **imparare come combinare al meglio le previsioni** dei modelli di base. Ad esempio, alleni 3 classificatori diversi (base learners), quindi fornisci le loro uscite (o probabilità) come caratteristiche a un meta-classificatore (spesso un modello semplice come la regressione logistica) che impara il modo ottimale per mescolarli. Il meta-modello è addestrato su un set di validazione o tramite cross-validation per evitare l'overfitting. Lo stacking può spesso superare il semplice voto imparando *quali modelli fidarsi di più in quali circostanze*. In cybersecurity, un modello potrebbe essere migliore nel catturare scansioni di rete mentre un altro è migliore nel catturare beaconing di malware; un modello di stacking potrebbe imparare a fare affidamento su ciascuno in modo appropriato.

Gli ensemble, sia tramite voto che stacking, tendono a **aumentare l'accuratezza** e la robustezza. Lo svantaggio è l'aumento della complessità e talvolta la riduzione dell'interpretabilità (anche se alcuni approcci ensemble come la media degli alberi decisionali possono ancora fornire alcune intuizioni, ad esempio, l'importanza delle caratteristiche). In pratica, se le restrizioni operative lo consentono, utilizzare un ensemble può portare a tassi di rilevamento più elevati. Molte soluzioni vincenti nelle sfide di cybersecurity (e nelle competizioni Kaggle in generale) utilizzano tecniche ensemble per spremere l'ultimo bit di prestazioni.

<details>
<summary>Esempio -- Voting Ensemble per la Rilevazione di Phishing:</summary>
Per illustrare lo stacking dei modelli, combiniamo alcuni dei modelli di cui abbiamo discusso sul dataset di phishing. Utilizzeremo una regressione logistica, un albero decisionale e un k-NN come base learners, e utilizzeremo un Random Forest come meta-learner per aggregare le loro previsioni. Il meta-learner sarà addestrato sugli output dei base learners (utilizzando la cross-validation sul set di addestramento). Ci aspettiamo che il modello impilato si comporti altrettanto bene o leggermente meglio dei modelli individuali.
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
L'ensemble impilato sfrutta i punti di forza complementari dei modelli di base. Ad esempio, la regressione logistica potrebbe gestire gli aspetti lineari dei dati, l'albero decisionale potrebbe catturare interazioni specifiche simili a regole, e k-NN potrebbe eccellere nei vicinati locali dello spazio delle caratteristiche. Il meta-modello (un random forest qui) può imparare come pesare questi input. Le metriche risultanti mostrano spesso un miglioramento (anche se lieve) rispetto alle metriche di qualsiasi singolo modello. Nel nostro esempio di phishing, se la regressione logistica da sola avesse un F1 di circa 0.95 e l'albero 0.94, l'ensemble potrebbe raggiungere 0.96 raccogliendo dove ciascun modello commette errori.

Metodi di ensemble come questo dimostrano il principio che *"combinare più modelli porta tipicamente a una migliore generalizzazione"*. In cybersecurity, questo può essere implementato avendo più motori di rilevamento (uno potrebbe essere basato su regole, uno su machine learning, uno basato su anomalie) e poi uno strato che aggrega i loro avvisi -- effettivamente una forma di ensemble -- per prendere una decisione finale con maggiore fiducia. Quando si implementano tali sistemi, è necessario considerare la complessità aggiuntiva e garantire che l'ensemble non diventi troppo difficile da gestire o spiegare. Ma da un punto di vista di accuratezza, gli ensemble e lo stacking sono strumenti potenti per migliorare le prestazioni del modello.

</details>


## Riferimenti

- [https://madhuramiah.medium.com/logistic-regression-6e55553cc003](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [https://www.geeksforgeeks.org/decision-tree-introduction-example/](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [https://www.ibm.com/think/topics/support-vector-machine](https://www.ibm.com/think/topics/support-vector-machine)
- [https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [https://zvelo.com/ai-and-machine-learning-in-cybersecurity/](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://arxiv.org/pdf/2101.02552](https://arxiv.org/pdf/2101.02552)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
