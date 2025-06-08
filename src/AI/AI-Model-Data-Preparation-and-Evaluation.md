# Preparazione e Valutazione dei Dati del Modello

{{#include ../banners/hacktricks-training.md}}

La preparazione dei dati del modello è un passaggio cruciale nel pipeline di machine learning, poiché comporta la trasformazione dei dati grezzi in un formato adatto per l'addestramento dei modelli di machine learning. Questo processo include diversi passaggi chiave:

1. **Raccolta dei Dati**: Raccolta di dati da varie fonti, come database, API o file. I dati possono essere strutturati (ad es., tabelle) o non strutturati (ad es., testo, immagini).
2. **Pulizia dei Dati**: Rimozione o correzione di punti dati errati, incompleti o irrilevanti. Questo passaggio può comportare la gestione dei valori mancanti, la rimozione dei duplicati e il filtraggio degli outlier.
3. **Trasformazione dei Dati**: Conversione dei dati in un formato adatto per la modellazione. Questo può includere normalizzazione, scaling, codifica delle variabili categoriche e creazione di nuove caratteristiche attraverso tecniche come l'ingegneria delle caratteristiche.
4. **Divisione dei Dati**: Suddivisione del dataset in set di addestramento, validazione e test per garantire che il modello possa generalizzare bene su dati non visti.

## Raccolta dei Dati

La raccolta dei dati comporta la raccolta di dati da varie fonti, che possono includere:
- **Database**: Estrazione di dati da database relazionali (ad es., database SQL) o database NoSQL (ad es., MongoDB).
- **API**: Recupero di dati da API web, che possono fornire dati in tempo reale o storici.
- **File**: Lettura di dati da file in formati come CSV, JSON o XML.
- **Web Scraping**: Raccolta di dati da siti web utilizzando tecniche di web scraping.

A seconda dell'obiettivo del progetto di machine learning, i dati saranno estratti e raccolti da fonti rilevanti per garantire che siano rappresentativi del dominio del problema.

## Pulizia dei Dati

La pulizia dei dati è il processo di identificazione e correzione di errori o incoerenze nel dataset. Questo passaggio è essenziale per garantire la qualità dei dati utilizzati per l'addestramento dei modelli di machine learning. Le attività chiave nella pulizia dei dati includono:
- **Gestione dei Valori Mancanti**: Identificazione e gestione dei punti dati mancanti. Le strategie comuni includono:
- Rimozione di righe o colonne con valori mancanti.
- Imputazione dei valori mancanti utilizzando tecniche come l'imputazione della media, della mediana o della moda.
- Utilizzo di metodi avanzati come l'imputazione K-nearest neighbors (KNN) o l'imputazione per regressione.
- **Rimozione dei Duplicati**: Identificazione e rimozione di record duplicati per garantire che ogni punto dati sia unico.
- **Filtraggio degli Outlier**: Rilevamento e rimozione di outlier che possono distorcere le prestazioni del modello. Tecniche come Z-score, IQR (Interquartile Range) o visualizzazioni (ad es., box plots) possono essere utilizzate per identificare outlier.

### Esempio di pulizia dei dati
```python
import pandas as pd
# Load the dataset
data = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_possitive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = data[~data['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
data = data.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
data['days'] = pd.to_numeric(data['days'], errors='coerce')

## For example, set "NaN" to not ips
def is_valid_ip(ip):
pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$')
if pd.isna(ip) or not pattern.match(str(ip)):
return np.nan
return ip
df['ip'] = df['ip'].apply(is_valid_ip)

# Filling missing values based on different strategies
numeric_cols = ["days", "hours", "minutes"]
categorical_cols = ["ip", "status"]

## Filling missing values in numeric columns with the median
num_imputer = SimpleImputer(strategy='median')
df[numeric_cols] = num_imputer.fit_transform(df[numeric_cols])

## Filling missing values in categorical columns with the most frequent value
cat_imputer = SimpleImputer(strategy='most_frequent')
df[categorical_cols] = cat_imputer.fit_transform(df[categorical_cols])

## Filling missing values in numeric columns using KNN imputation
knn_imputer = KNNImputer(n_neighbors=5)
df[numeric_cols] = knn_imputer.fit_transform(df[numeric_cols])



# Filling missing values
data.fillna(data.mean(), inplace=True)

# Removing duplicates
data.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = stats.zscore(data.select_dtypes(include=['float64', 'int64']))
data = data[(z_scores < 3).all(axis=1)]
```
## Trasformazione dei Dati

La trasformazione dei dati implica la conversione dei dati in un formato adatto per la modellazione. Questo passaggio può includere:
- **Normalizzazione e Standardizzazione**: Scalare le caratteristiche numeriche a un intervallo comune, tipicamente [0, 1] o [-1, 1]. Questo aiuta a migliorare la convergenza degli algoritmi di ottimizzazione.
- **Min-Max Scaling**: Riscalare le caratteristiche a un intervallo fisso, di solito [0, 1]. Questo viene fatto utilizzando la formula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalizzazione Z-Score**: Standardizzare le caratteristiche sottraendo la media e dividendo per la deviazione standard, risultando in una distribuzione con una media di 0 e una deviazione standard di 1. Questo viene fatto utilizzando la formula: `X' = (X - μ) / σ`, dove μ è la media e σ è la deviazione standard.
- **Skeyewness e Kurtosi**: Regolare la distribuzione delle caratteristiche per ridurre la skewness (asimmetria) e la kurtosi (picco). Questo può essere fatto utilizzando trasformazioni come logaritmica, radice quadrata o trasformazioni di Box-Cox. Ad esempio, se una caratteristica ha una distribuzione distorta, applicare una trasformazione logaritmica può aiutare a normalizzarla.
- **Normalizzazione delle Stringhe**: Convertire le stringhe in un formato coerente, come:
- Minuscole
- Rimozione di caratteri speciali (mantenendo quelli rilevanti)
- Rimozione di stop words (parole comuni che non contribuiscono al significato, come "il", "è", "e")
- Rimozione di parole troppo frequenti e troppo rare (ad es., parole che appaiono in più del 90% dei documenti o meno di 5 volte nel corpus)
- Rimozione di spazi bianchi
- Stemming/Lemmatizzazione: Ridurre le parole alla loro forma base o radice (ad es., "correndo" a "correre").

- **Codifica delle Variabili Categoriali**: Convertire le variabili categoriali in rappresentazioni numeriche. Le tecniche comuni includono:
- **One-Hot Encoding**: Creare colonne binarie per ogni categoria.
- Ad esempio, se una caratteristica ha categorie "rosso", "verde" e "blu", verrà trasformata in tre colonne binarie: `is_red`(100), `is_green`(010) e `is_blue`(001).
- **Label Encoding**: Assegnare un intero unico a ciascuna categoria.
- Ad esempio, "rosso" = 0, "verde" = 1, "blu" = 2.
- **Ordinal Encoding**: Assegnare interi in base all'ordine delle categorie.
- Ad esempio, se le categorie sono "basso", "medio" e "alto", possono essere codificate come 0, 1 e 2, rispettivamente.
- **Hashing Encoding**: Utilizzare una funzione hash per convertire le categorie in vettori di dimensione fissa, che possono essere utili per variabili categoriali ad alta cardinalità.
- Ad esempio, se una caratteristica ha molte categorie uniche, l'hashing può ridurre la dimensionalità mantenendo alcune informazioni sulle categorie.
- **Bag of Words (BoW)**: Rappresentare i dati testuali come una matrice di conteggi o frequenze di parole, dove ogni riga corrisponde a un documento e ogni colonna corrisponde a una parola unica nel corpus.
- Ad esempio, se il corpus contiene le parole "gatto", "cane" e "pesce", un documento contenente "gatto" e "cane" sarebbe rappresentato come [1, 1, 0]. Questa rappresentazione specifica è chiamata "unigram" e non cattura l'ordine delle parole, quindi perde informazioni semantiche.
- **Bigram/Trigram**: Estendere BoW per catturare sequenze di parole (bigrammi o trigrammi) per mantenere un certo contesto. Ad esempio, "gatto e cane" sarebbe rappresentato come un bigram [1, 1] per "gatto e" e [1, 1] per "e cane". In questi casi vengono raccolte più informazioni semantiche (aumentando la dimensionalità della rappresentazione) ma solo per 2 o 3 parole alla volta.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Una misura statistica che valuta l'importanza di una parola in un documento rispetto a una collezione di documenti (corpus). Combina la frequenza del termine (quanto spesso appare una parola in un documento) e la frequenza inversa del documento (quanto è rara una parola in tutti i documenti).
- Ad esempio, se la parola "gatto" appare frequentemente in un documento ma è rara nell'intero corpus, avrà un punteggio TF-IDF elevato, indicando la sua importanza in quel documento.

- **Feature Engineering**: Creare nuove caratteristiche da quelle esistenti per migliorare il potere predittivo del modello. Questo può comportare la combinazione di caratteristiche, l'estrazione di componenti data/ora o l'applicazione di trasformazioni specifiche del dominio.

## Suddivisione dei Dati

La suddivisione dei dati implica dividere il dataset in sottoinsiemi separati per l'addestramento, la validazione e il test. Questo è essenziale per valutare le prestazioni del modello su dati non visti e prevenire l'overfitting. Le strategie comuni includono:
- **Train-Test Split**: Dividere il dataset in un set di addestramento (tipicamente 60-80% dei dati), un set di validazione (10-15% dei dati) per ottimizzare gli iperparametri, e un set di test (10-15% dei dati). Il modello viene addestrato sul set di addestramento e valutato sul set di test.
- Ad esempio, se hai un dataset di 1000 campioni, potresti utilizzare 700 campioni per l'addestramento, 150 per la validazione e 150 per il test.
- **Stratified Sampling**: Assicurarsi che la distribuzione delle classi nei set di addestramento e test sia simile a quella dell'intero dataset. Questo è particolarmente importante per dataset sbilanciati, dove alcune classi possono avere significativamente meno campioni di altre.
- **Time Series Split**: Per i dati delle serie temporali, il dataset viene suddiviso in base al tempo, assicurando che il set di addestramento contenga dati da periodi temporali precedenti e il set di test contenga dati da periodi successivi. Questo aiuta a valutare le prestazioni del modello su dati futuri.
- **K-Fold Cross-Validation**: Suddividere il dataset in K sottoinsiemi (fold) e addestrare il modello K volte, ogni volta utilizzando un fold diverso come set di test e i fold rimanenti come set di addestramento. Questo aiuta a garantire che il modello venga valutato su diversi sottoinsiemi di dati, fornendo una stima più robusta delle sue prestazioni.

## Valutazione del Modello

La valutazione del modello è il processo di valutazione delle prestazioni di un modello di machine learning su dati non visti. Comporta l'uso di varie metriche per quantificare quanto bene il modello si generalizza a nuovi dati. Le metriche di valutazione comuni includono:

### Accuratezza

L'accuratezza è la proporzione di istanze correttamente previste rispetto al totale delle istanze. Viene calcolata come:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> L'accuratezza è una metrica semplice e intuitiva, ma potrebbe non essere adatta per dataset sbilanciati in cui una classe domina le altre, poiché può dare un'impressione fuorviante delle prestazioni del modello. Ad esempio, se il 90% dei dati appartiene alla classe A e il modello prevede tutte le istanze come classe A, raggiungerà un'accuratezza del 90%, ma non sarà utile per prevedere la classe B.

### Precisione

La precisione è la proporzione di previsioni positive vere rispetto a tutte le previsioni positive effettuate dal modello. Si calcola come:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> La precisione è particolarmente importante in scenari in cui i falsi positivi sono costosi o indesiderati, come nelle diagnosi mediche o nella rilevazione delle frodi. Ad esempio, se un modello prevede 100 istanze come positive, ma solo 80 di esse sono effettivamente positive, la precisione sarebbe 0.8 (80%).

### Recall (Sensibilità)

Il recall, noto anche come sensibilità o tasso di veri positivi, è la proporzione di previsioni vere positive su tutte le istanze positive reali. Si calcola come:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Il richiamo è cruciale in scenari in cui i falsi negativi sono costosi o indesiderati, come nella rilevazione di malattie o nel filtraggio dello spam. Ad esempio, se un modello identifica 80 su 100 istanze positive reali, il richiamo sarebbe 0.8 (80%).

### F1 Score

Il punteggio F1 è la media armonica di precisione e richiamo, fornendo un equilibrio tra le due metriche. Viene calcolato come:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Il punteggio F1 è particolarmente utile quando si lavora con set di dati sbilanciati, poiché considera sia i falsi positivi che i falsi negativi. Fornisce una metrica unica che cattura il compromesso tra precisione e richiamo. Ad esempio, se un modello ha una precisione di 0.8 e un richiamo di 0.6, il punteggio F1 sarebbe approssimativamente 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

La metrica ROC-AUC valuta la capacità del modello di distinguere tra classi tracciando il tasso di veri positivi (sensibilità) rispetto al tasso di falsi positivi a vari livelli di soglia. L'area sotto la curva ROC (AUC) quantifica le prestazioni del modello, con un valore di 1 che indica una classificazione perfetta e un valore di 0.5 che indica una previsione casuale.

> [!TIP]
> ROC-AUC è particolarmente utile per problemi di classificazione binaria e fornisce una visione completa delle prestazioni del modello attraverso diverse soglie. È meno sensibile allo sbilanciamento delle classi rispetto all'accuratezza. Ad esempio, un modello con un AUC di 0.9 indica che ha un'alta capacità di distinguere tra istanze positive e negative.

### Specificità

La specificità, nota anche come tasso di veri negativi, è la proporzione di previsioni vere negative su tutte le istanze negative reali. È calcolata come:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> La specificità è importante in scenari in cui i falsi positivi sono costosi o indesiderati, come nei test medici o nella rilevazione delle frodi. Aiuta a valutare quanto bene il modello identifica le istanze negative. Ad esempio, se un modello identifica correttamente 90 su 100 istanze negative reali, la specificità sarebbe 0,9 (90%).

### Matthews Correlation Coefficient (MCC)
Il Matthews Correlation Coefficient (MCC) è una misura della qualità delle classificazioni binarie. Tiene conto dei veri e falsi positivi e negativi, fornendo una visione equilibrata delle prestazioni del modello. L'MCC è calcolato come:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
dove:
- **TP**: Veri Positivi
- **TN**: Veri Negativi
- **FP**: Falsi Positivi
- **FN**: Falsi Negativi

> [!TIP]
> Il MCC varia da -1 a 1, dove 1 indica una classificazione perfetta, 0 indica un'ipotesi casuale e -1 indica totale disaccordo tra previsione e osservazione. È particolarmente utile per dataset sbilanciati, poiché considera tutti e quattro i componenti della matrice di confusione.

### Errore Assoluto Medio (MAE)
L'Errore Assoluto Medio (MAE) è una metrica di regressione che misura la differenza assoluta media tra i valori previsti e quelli reali. Viene calcolato come:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
dove:
- **n**: Numero di istanze
- **y_i**: Valore reale per l'istanza i
- **ŷ_i**: Valore previsto per l'istanza i

> [!TIP]
> MAE fornisce un'interpretazione chiara dell'errore medio nelle previsioni, rendendolo facile da comprendere. È meno sensibile agli outlier rispetto ad altre metriche come l'Errore Quadratico Medio (MSE). Ad esempio, se un modello ha un MAE di 5, significa che, in media, le previsioni del modello si discostano dai valori reali di 5 unità.

### Matrice di Confusione

La matrice di confusione è una tabella che riassume le prestazioni di un modello di classificazione mostrando i conteggi di previsioni vere positive, vere negative, false positive e false negative. Fornisce una visione dettagliata di quanto bene il modello si comporta su ciascuna classe.

|               | Predetto Positivo | Predetto Negativo |
|---------------|---------------------|---------------------|
| Reale Positivo| Vero Positivo (TP)  | Falso Negativo (FN)  |
| Reale Negativo| Falso Positivo (FP) | Vero Negativo (TN)   |

- **Vero Positivo (TP)**: Il modello ha previsto correttamente la classe positiva.
- **Vero Negativo (TN)**: Il modello ha previsto correttamente la classe negativa.
- **Falso Positivo (FP)**: Il modello ha previsto erroneamente la classe positiva (errore di Tipo I).
- **Falso Negativo (FN)**: Il modello ha previsto erroneamente la classe negativa (errore di Tipo II).

La matrice di confusione può essere utilizzata per calcolare varie metriche di valutazione, come accuratezza, precisione, richiamo e punteggio F1.

{{#include ../banners/hacktricks-training.md}}
