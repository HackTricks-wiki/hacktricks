# Preparazione e valutazione dei dati del modello

{{#include ../banners/hacktricks-training.md}}

La preparazione dei dati del modello è un passaggio cruciale nella pipeline di machine learning, poiché consiste nel trasformare i dati grezzi in un formato adatto all'addestramento dei modelli di machine learning. Questo processo include diversi passaggi fondamentali:

1. **Raccolta dei dati**: raccolta di dati da diverse fonti, come database, API o file. I dati possono essere strutturati (ad esempio, tabelle) o non strutturati (ad esempio, testo, immagini).
2. **Pulizia dei dati**: rimozione o correzione di dati errati, incompleti o irrilevanti. Questo passaggio può includere la gestione dei valori mancanti, la rimozione dei duplicati e il filtraggio degli outlier.
3. **Trasformazione dei dati**: conversione dei dati in un formato adatto alla modellazione. Ciò può includere la normalizzazione, il ridimensionamento, la codifica delle variabili categoriche e la creazione di nuove feature attraverso tecniche come il feature engineering.
4. **Suddivisione dei dati**: divisione del dataset in set di training, validation e test per garantire che il modello possa generalizzare correttamente a dati non osservati.

## Raccolta dei dati

La raccolta dei dati consiste nell'acquisire dati da diverse fonti, tra cui:
- **Database**: estrazione di dati da database relazionali (ad esempio, database SQL) o database NoSQL (ad esempio, MongoDB).
- **API**: recupero di dati da web API, che possono fornire dati in tempo reale o storici.
- **File**: lettura di dati da file in formati come CSV, JSON o XML.
- **Web Scraping**: raccolta di dati da siti web utilizzando tecniche di web scraping.

In base all'obiettivo del progetto di machine learning, i dati verranno estratti e raccolti da fonti pertinenti per garantire che siano rappresentativi del dominio del problema.

## Pulizia dei dati <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

La pulizia dei dati è il processo di identificazione e correzione degli errori o delle incoerenze presenti nel dataset. Questo passaggio è essenziale per garantire la qualità dei dati utilizzati per l'addestramento dei modelli di machine learning. Le attività principali della pulizia dei dati includono:
- **Gestione dei valori mancanti**: identificazione e gestione dei punti dati mancanti. Le strategie comuni includono:
- Rimozione delle righe o delle colonne contenenti valori mancanti.
- Imputazione dei valori mancanti utilizzando tecniche come l'imputazione della media, della mediana o della moda.
- Utilizzo di metodi avanzati come l'imputazione con K-nearest neighbors (KNN) o l'imputazione mediante regressione.
- **Rimozione dei duplicati**: identificazione e rimozione dei record duplicati per garantire che ogni punto dati sia univoco.
- **Filtraggio degli outlier**: rilevamento e rimozione degli outlier che potrebbero alterare le prestazioni del modello. Per identificare gli outlier è possibile utilizzare tecniche come Z-score, IQR (Interquartile Range) o visualizzazioni (ad esempio, box plot).

### Esempio di pulizia dei dati
```python
import re

import numpy as np
import pandas as pd
from sklearn.impute import KNNImputer, SimpleImputer

# Load the dataset
df = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_positive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = df[~df['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
df = df.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
df['days'] = pd.to_numeric(df['days'], errors='coerce')

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
df.fillna(df.mean(numeric_only=True), inplace=True)

# Removing duplicates
df.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = np.abs(stats.zscore(df.select_dtypes(include=['float64', 'int64']), nan_policy='omit'))
df = df[(z_scores < 3).all(axis=1)]
```
## Trasformazione dei dati <sup>[[1]](#references)</sup>

La trasformazione dei dati consiste nel convertire i dati in un formato adatto alla modellazione. Questo passaggio può includere:
- **Normalizzazione e standardizzazione**: ridimensionamento delle feature numeriche a un intervallo comune, in genere [0, 1] o [-1, 1]. Ciò può migliorare la convergenza degli algoritmi di ottimizzazione.
- **Ridimensionamento Min-Max**: ridimensionamento delle feature a un intervallo fisso, solitamente [0, 1]. Viene eseguito utilizzando la formula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalizzazione Z-Score**: standardizzazione delle feature sottraendo la media e dividendo per la deviazione standard, ottenendo una distribuzione con media pari a 0 e deviazione standard pari a 1. Viene eseguita utilizzando la formula: `X' = (X - μ) / σ`, dove μ è la media e σ è la deviazione standard.
- **Asimmetria e curtosi**: regolazione delle distribuzioni delle feature con trasformazioni come logaritmo, radice quadrata o Box-Cox. Ad esempio, una trasformazione logaritmica può ridurre l'asimmetria positiva.
- **Normalizzazione delle stringhe**: conversione delle stringhe in un formato coerente, ad esempio:
- Conversione in minuscolo
- Rimozione dei caratteri speciali (mantenendo quelli rilevanti)
- Rimozione delle stop word (parole comuni che non contribuiscono al significato, come "the", "is", "and")
- Rimozione delle parole troppo frequenti e troppo rare (ad esempio, parole che compaiono in più del 90% dei documenti o meno di 5 volte nel corpus)
- Rimozione degli spazi bianchi iniziali e finali
- Stemming/Lemmatizzazione: riduzione delle parole alla loro forma base o radice (ad esempio, "running" a "run").

- **Codifica delle variabili categoriche**: conversione delle variabili categoriche in rappresentazioni numeriche. Le tecniche comuni includono:
- **One-Hot Encoding**: creazione di colonne binarie per ogni categoria.
- Ad esempio, se una feature ha le categorie "red", "green" e "blue", verrà trasformata in tre colonne binarie: `is_red`(100), `is_green`(010) e `is_blue`(001).
- **Label Encoding**: assegnazione di un intero univoco a ogni categoria.
- Ad esempio, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: assegnazione di interi in base all'ordine delle categorie.
- Ad esempio, se le categorie sono "low", "medium" e "high", possono essere codificate rispettivamente come 0, 1 e 2.
- **Hashing Encoding**: utilizzo di una funzione hash per convertire le categorie in vettori di dimensione fissa, utile per le variabili categoriche con cardinalità elevata.
- Ad esempio, se una feature ha molte categorie univoche, l'hashing può ridurre la dimensionalità preservando alcune informazioni sulle categorie.
- **Bag of Words (BoW)**: rappresentazione dei dati testuali come una matrice di conteggi o frequenze delle parole, in cui ogni riga corrisponde a un documento e ogni colonna corrisponde a una parola univoca nel corpus.
- Ad esempio, se il corpus contiene le parole "cat", "dog" e "fish", un documento contenente "cat" e "dog" sarebbe rappresentato come [1, 1, 0]. Questa rappresentazione specifica è chiamata "unigram" e non cattura l'ordine delle parole, quindi perde informazioni semantiche.
- **Bigram/Trigram**: estensione di BoW per catturare sequenze di parole (bigrammi o trigrammi) e conservare parte del contesto. Ad esempio, "cat and dog" sarebbe rappresentato come un bigramma [1, 1] per "cat and" e [1, 1] per "and dog". In questo caso viene raccolta una maggiore quantità di informazioni semantiche (aumentando la dimensionalità della rappresentazione), ma solo per 2 o 3 parole alla volta.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: misura statistica che valuta l'importanza di una parola in un documento rispetto a una raccolta di documenti (corpus). Combina la frequenza del termine (quanto spesso una parola compare in un documento) e la frequenza inversa del documento (quanto è rara una parola nell'insieme dei documenti).
- Ad esempio, se la parola "cat" compare frequentemente in un documento ma è rara nell'intero corpus, avrà un punteggio TF-IDF elevato, indicando la sua importanza in quel documento.

- **Feature Engineering**: creazione di nuove feature a partire da quelle esistenti per migliorare la capacità predittiva del modello. Ciò può includere la combinazione di feature, l'estrazione di componenti di data/ora o l'applicazione di trasformazioni specifiche del dominio.

## Suddivisione dei dati <sup>[[3]](#references)</sup>

La suddivisione dei dati consiste nel dividere il dataset in sottoinsiemi separati per l'addestramento, la validazione e il testing. Ciò è essenziale per valutare le prestazioni del modello su dati non osservati e prevenire l'overfitting. Le strategie comuni includono:
- **Suddivisione Train-Test**: divisione del dataset in un set di addestramento (in genere il 60-80% dei dati), un set di validazione (10-15% dei dati) per ottimizzare gli iperparametri e un set di test (10-15% dei dati). Il modello viene addestrato sul set di addestramento e valutato sul set di test.
- Ad esempio, se si dispone di un dataset di 1000 campioni, si potrebbero utilizzare 700 campioni per l'addestramento, 150 per la validazione e 150 per il testing.
- **Campionamento stratificato**: garanzia che la distribuzione delle classi nei set di addestramento e di test sia simile a quella dell'intero dataset. Ciò è particolarmente importante per i dataset sbilanciati, in cui alcune classi possono avere un numero di campioni significativamente inferiore rispetto ad altre.
- **Suddivisione di serie temporali**: per i dati delle serie temporali, il dataset viene suddiviso in base al tempo, assicurando che il set di addestramento contenga dati relativi a periodi precedenti e il set di test contenga dati relativi a periodi successivi. Ciò aiuta a valutare le prestazioni del modello su dati futuri.
- **Cross-Validation K-Fold**: suddivisione del dataset in K sottoinsiemi (fold) e addestramento del modello K volte, utilizzando ogni volta un fold diverso come set di test e i fold rimanenti come set di addestramento. Ciò contribuisce a garantire che il modello venga valutato su diversi sottoinsiemi di dati, fornendo una stima più robusta delle sue prestazioni.

## Valutazione del modello <sup>[[4]](#references)</sup>

La valutazione del modello è il processo di analisi delle prestazioni di un modello di machine learning su dati non osservati. Consiste nell'utilizzo di diverse metriche per quantificare quanto bene il modello si generalizzi a nuovi dati. Le metriche di valutazione comuni includono:

### Accuratezza

L'accuratezza è la proporzione di istanze predette correttamente rispetto al numero totale di istanze. Viene calcolata come:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> L'accuratezza è una metrica semplice e intuitiva, ma potrebbe non essere adatta per dataset sbilanciati in cui una classe prevale sulle altre, poiché può dare un'impressione fuorviante delle prestazioni del modello. Ad esempio, se il 90% dei dati appartiene alla classe A e il modello predice tutte le istanze come appartenenti alla classe A, raggiungerà un'accuratezza del 90%, ma non sarà utile per predire la classe B.

### Precisione

La precisione è la proporzione di predizioni positive corrette rispetto a tutte le predizioni positive effettuate dal modello. Si calcola come:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> La precisione è particolarmente importante negli scenari in cui i falsi positivi sono costosi o indesiderati, come nelle diagnosi mediche o nel rilevamento delle frodi. Ad esempio, se un modello prevede 100 istanze come positive, ma solo 80 di esse sono effettivamente positive, la precisione sarebbe pari a 0,8 (80%).

### Recall (Sensibilità)

Il Recall, noto anche come sensibilità o tasso di veri positivi, è la proporzione delle previsioni di veri positivi rispetto a tutte le istanze effettivamente positive. Si calcola come:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Il recall è fondamentale negli scenari in cui i falsi negativi sono costosi o indesiderati, come nel rilevamento delle malattie o nel filtraggio dello spam. Ad esempio, se un modello identifica 80 dei 100 casi positivi effettivi, il recall sarebbe pari a 0,8 (80%).

### F1 Score

L'F1 score è la media armonica di precision e recall e fornisce un equilibrio tra le due metriche. Si calcola come:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Il punteggio F1 è particolarmente utile quando si lavora con dataset sbilanciati, poiché considera sia i falsi positivi sia i falsi negativi. Fornisce una singola metrica che rappresenta il compromesso tra precisione e recall. Ad esempio, se un modello ha una precisione di 0.8 e un recall di 0.6, il punteggio F1 sarebbe approssimativamente 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

La metrica ROC-AUC valuta la capacità del modello di distinguere tra le classi tracciando il tasso di veri positivi (sensibilità) rispetto al tasso di falsi positivi a diverse impostazioni di soglia. L'area sotto la curva ROC (AUC) quantifica le prestazioni del modello: un valore pari a 1 indica una classificazione perfetta, mentre un valore pari a 0.5 indica una previsione casuale.

> [!TIP]
> ROC-AUC è particolarmente utile per i problemi di classificazione binaria e fornisce una visione completa delle prestazioni del modello a diverse soglie. È meno sensibile allo sbilanciamento delle classi rispetto all'accuracy. Ad esempio, un modello con un AUC pari a 0.9 indica un'elevata capacità di distinguere tra istanze positive e negative.

### Specificità

La specificità, nota anche come tasso di veri negativi, è la proporzione di previsioni di veri negativi rispetto a tutte le istanze effettivamente negative. Viene calcolata come:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> La specificità è importante negli scenari in cui i falsi positivi sono costosi o indesiderati, come nei test medici o nel rilevamento delle frodi. Aiuta a valutare quanto bene il modello identifichi le istanze negative. Ad esempio, se un modello identifica correttamente 90 su 100 istanze effettivamente negative, la specificità sarebbe pari a 0,9 (90%).

### Coefficiente di correlazione di Matthews (MCC)
Il coefficiente di correlazione di Matthews (MCC) è una misura della qualità delle classificazioni binarie. Tiene conto dei veri e falsi positivi e negativi, fornendo una valutazione equilibrata delle prestazioni del modello. L'MCC si calcola come:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
dove:
- **TP**: Veri Positivi
- **TN**: Veri Negativi
- **FP**: Falsi Positivi
- **FN**: Falsi Negativi

> [!TIP]
> L'MCC varia da -1 a 1, dove 1 indica una classificazione perfetta, 0 indica una previsione casuale e -1 indica un disaccordo totale tra previsione e osservazione. È particolarmente utile per i dataset sbilanciati, poiché considera tutti e quattro i componenti della matrice di confusione.

### Mean Absolute Error (MAE)
Mean Absolute Error (MAE) è una metrica di regressione che misura la differenza assoluta media tra i valori previsti e quelli effettivi. Si calcola come:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
dove:
- **n**: Numero di istanze
- **y_i**: Valore effettivo per l'istanza i
- **ŷ_i**: Valore previsto per l'istanza i

> [!TIP]
> MAE fornisce un'interpretazione immediata dell'errore medio nelle previsioni, rendendolo facile da comprendere. È meno sensibile agli outlier rispetto ad altre metriche come Mean Squared Error (MSE). Ad esempio, se un modello ha un MAE pari a 5, significa che, in media, le previsioni del modello si discostano dai valori effettivi di 5 unità.

### Matrice di confusione

La matrice di confusione è una tabella che riassume le prestazioni di un modello di classificazione mostrando il numero di previsioni true positive, true negative, false positive e false negative. Fornisce una panoramica dettagliata delle prestazioni del modello per ciascuna classe.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Il modello ha previsto correttamente la classe positiva.
- **True Negative (TN)**: Il modello ha previsto correttamente la classe negativa.
- **False Positive (FP)**: Il modello ha previsto erroneamente la classe positiva (errore di Tipo I).
- **False Negative (FN)**: Il modello ha previsto erroneamente la classe negativa (errore di Tipo II).

La matrice di confusione può essere utilizzata per calcolare metriche di valutazione come accuracy, precision, recall e F1 score.

## References

- [1] [scikit-learn - Preprocessing dei dati](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputazione dei valori mancanti](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation: valutazione delle prestazioni dell'estimatore](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metriche e scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
