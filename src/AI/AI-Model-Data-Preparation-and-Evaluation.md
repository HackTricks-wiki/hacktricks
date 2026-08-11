# Voorbereiding en evaluering van modeldata

{{#include ../banners/hacktricks-training.md}}

Die voorbereiding van modeldata is 'n deurslaggewende stap in die masjienleer-pyplyn, aangesien dit behels dat rou data omskep word in 'n formaat wat geskik is vir die opleiding van masjienleermodelle. Hierdie proses sluit verskeie sleutelstappe in:

1. **Data-insameling**: Die versameling van data uit verskeie bronne, soos databasisse, APIs of lêers. Die data kan gestruktureerd (bv. tabelle) of ongestruktureerd (bv. teks, beelde) wees.
2. **Data-skoonmaak**: Die verwydering of regstelling van foutiewe, onvolledige of irrelevante datapunte. Hierdie stap kan die hantering van ontbrekende waardes, die verwydering van duplikate en die uitfiltrering van uitskieters behels.
3. **Data-transformasie**: Die omskakeling van die data na 'n geskikte formaat vir modellering. Dit kan normalisering, skaalverandering, enkodering van kategoriese veranderlikes en die skep van nuwe kenmerke deur tegnieke soos feature engineering insluit.
4. **Data-verdeling**: Die verdeling van die datastel in opleiding-, validerings- en toetsstelle om te verseker dat die model goed na onbekende data kan veralgemeen.

## Data-insameling

Data-insameling behels die versameling van data uit verskeie bronne, wat die volgende kan insluit:
- **Databasisse**: Die onttrekking van data uit relasionele databasisse (bv. SQL-databasisse) of NoSQL-databasisse (bv. MongoDB).
- **APIs**: Die verkryging van data vanaf web-APIs, wat intydse of historiese data kan verskaf.
- **Lêers**: Die lees van data uit lêers in formate soos CSV, JSON of XML.
- **Web Scraping**: Die insameling van data vanaf webwerwe deur web scraping-tegnieke te gebruik.

Afhangend van die doel van die masjienleerprojek, sal die data uit relevante bronne onttrek en versamel word om te verseker dat dit verteenwoordigend van die probleemdomein is.

## Data-skoonmaak <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Data-skoonmaak is die proses om foute of teenstrydighede in die datastel te identifiseer en reg te stel. Hierdie stap is noodsaaklik om die gehalte van die data wat vir die opleiding van masjienleermodelle gebruik word, te verseker. Sleuteltake in data-skoonmaak sluit die volgende in:
- **Hantering van ontbrekende waardes**: Die identifisering en hantering van ontbrekende datapunte. Algemene strategieë sluit die volgende in:
- Die verwydering van rye of kolomme met ontbrekende waardes.
- Die invulling van ontbrekende waardes deur tegnieke soos gemiddelde-, mediaan- of modus-imputasie te gebruik.
- Die gebruik van gevorderde metodes soos K-nearest neighbors (KNN)-imputasie of regressie-imputasie.
- **Verwydering van duplikate**: Die identifisering en verwydering van duplikaatrekords om te verseker dat elke datapunt uniek is.
- **Uitfiltrering van uitskieters**: Die opsporing en verwydering van uitskieters wat die model se prestasie kan verdraai. Tegnieke soos Z-score, IQR (Interquartile Range) of visualiserings (bv. boksdiagramme) kan gebruik word om uitskieters te identifiseer.

### Voorbeeld van data-skoonmaak
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
## Data-transformasie <sup>[[1]](#references)</sup>

Data-transformasie behels die omskakeling van die data na ’n formaat wat geskik is vir modellering. Hierdie stap kan die volgende insluit:
- **Normalisering en standaardisering**: Skaal numeriese kenmerke na ’n gemeenskaplike reeks, tipies [0, 1] of [-1, 1]. Dit kan die konvergensie van optimaliseringsalgoritmes verbeter.
- **Min-Max Scaling**: Herskaal kenmerke na ’n vaste reeks, gewoonlik [0, 1]. Dit word gedoen met die formule: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: Standaardiseer kenmerke deur die gemiddelde af te trek en deur die standaardafwyking te deel, wat ’n verspreiding met ’n gemiddelde van 0 en ’n standaardafwyking van 1 tot gevolg het. Dit word gedoen met die formule: `X' = (X - μ) / σ`, waar μ die gemiddelde is en σ die standaardafwyking is.
- **Skewness and kurtosis**: Pas kenmerkverspreidings aan met transformasies soos logaritmes, vierkantswortels of Box-Cox. Byvoorbeeld, ’n logaritmiese transformasie kan positiewe skeefheid verminder.
- **String Normalization**: Skakel stringe om na ’n konsekwente formaat, soos:
- Omskakeling na kleinletters
- Verwydering van spesiale karakters (behou die relevante karakters)
- Verwydering van stopwoorde (algemene woorde wat nie tot die betekenis bydra nie, soos "the", "is" en "and")
- Verwydering van woorde wat te gereeld en woorde wat te selde voorkom (bv. woorde wat in meer as 90% van die dokumente of minder as 5 keer in die korpus voorkom)
- Verwydering van voor- en agterspasies
- Stemming/Lemmatization: Verminder woorde tot hul basis- of stamvorm (bv. "running" na "run").

- **Encoding Categorical Variables**: Skakel kategoriese veranderlikes om na numeriese voorstellings. Algemene tegnieke sluit in:
- **One-Hot Encoding**: Skep binêre kolomme vir elke kategorie.
- Byvoorbeeld, as ’n kenmerk die kategorieë "red", "green" en "blue" het, sal dit in drie binêre kolomme omskep word: `is_red`(100), `is_green`(010) en `is_blue`(001).
- **Label Encoding**: Ken ’n unieke heelgetal aan elke kategorie toe.
- Byvoorbeeld, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Ken heelgetalle toe gebaseer op die volgorde van die kategorieë.
- Byvoorbeeld, as die kategorieë "low", "medium" en "high" is, kan hulle onderskeidelik as 0, 1 en 2 geënkodeer word.
- **Hashing Encoding**: Gebruik ’n hash-funksie om kategorieë na vektore met ’n vaste grootte om te skakel, wat nuttig kan wees vir kategoriese veranderlikes met ’n groot aantal unieke waardes.
- Byvoorbeeld, as ’n kenmerk baie unieke kategorieë het, kan hashing die dimensionaliteit verminder terwyl sommige inligting oor die kategorieë behoue bly.
- **Bag of Words (BoW)**: Stel teksdata voor as ’n matriks van woordtellings of -frekwensies, waar elke ry met ’n dokument ooreenstem en elke kolom met ’n unieke woord in die korpus ooreenstem.
- Byvoorbeeld, as die korpus die woorde "cat", "dog" en "fish" bevat, sal ’n dokument wat "cat" en "dog" bevat as [1, 1, 0] voorgestel word. Hierdie spesifieke voorstelling word "unigram" genoem en neem nie die volgorde van woorde vas nie, dus gaan semantiese inligting verlore.
- **Bigram/Trigram**: Brei BoW uit om rye woorde (bigrams of trigrams) vas te lê en sodoende ’n mate van konteks te behou. Byvoorbeeld, "cat and dog" sal voorgestel word as ’n bigram [1, 1] vir "cat and" en [1, 1] vir "and dog". In hierdie geval word meer semantiese inligting versamel (wat die dimensionaliteit van die voorstelling verhoog), maar slegs vir 2 of 3 woorde op ’n slag.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: ’n Statistiese maatstaf wat die belangrikheid van ’n woord in ’n dokument relatief tot ’n versameling dokumente (korpus) bepaal. Dit kombineer termfrekwensie (hoe gereeld ’n woord in ’n dokument voorkom) en inverse dokumentfrekwensie (hoe seldsaam ’n woord oor alle dokumente heen is).
- Byvoorbeeld, as die woord "cat" gereeld in ’n dokument voorkom, maar seldsaam in die hele korpus is, sal dit ’n hoë TF-IDF-telling hê, wat die belangrikheid daarvan in daardie dokument aandui.

- **Feature Engineering**: Skep nuwe kenmerke uit bestaande kenmerke om die model se voorspellingsvermoë te verbeter. Dit kan behels dat kenmerke gekombineer word, datum-/tydkomponente onttrek word of domeinspesifieke transformasies toegepas word.

## Datasplitsing <sup>[[3]](#references)</sup>

Datasplitsing behels die verdeling van die datastel in afsonderlike subsets vir training, validation en testing. Dit is noodsaaklik om die model se werkverrigting op onbekende data te evalueer en overfitting te voorkom. Algemene strategieë sluit in:
- **Train-Test Split**: Verdeel die datastel in ’n training-stel (tipies 60-80% van die data), ’n validation-stel (10-15% van die data) om hyperparameters aan te pas, en ’n test-stel (10-15% van die data). Die model word op die training-stel opgelei en op die test-stel geëvalueer.
- Byvoorbeeld, as jy ’n datastel van 1000 voorbeelde het, kan jy 700 voorbeelde vir training, 150 vir validation en 150 vir testing gebruik.
- **Stratified Sampling**: Verseker dat die verspreiding van klasse in die training- en test-stelle soortgelyk aan dié van die algehele datastel is. Dit is veral belangrik vir ongebalanseerde datastelle, waar sommige klasse aansienlik minder voorbeelde as ander kan hê.
- **Time Series Split**: Vir tydreeksdata word die datastel volgens tyd verdeel, sodat die training-stel data uit vroeëre tydperke bevat en die test-stel data uit latere tydperke bevat. Dit help om die model se werkverrigting op toekomstige data te evalueer.
- **K-Fold Cross-Validation**: Verdeel die datastel in K-substelle (folds) en lei die model K keer op, waar elke fold op sy beurt as die test-stel en die oorblywende folds as die training-stel gebruik word. Dit help verseker dat die model op verskillende substelle van data geëvalueer word, wat ’n meer robuuste skatting van sy werkverrigting bied.

## Modelevaluering <sup>[[4]](#references)</sup>

Modelevaluering is die proses om die werkverrigting van ’n machine learning-model op onbekende data te bepaal. Dit behels die gebruik van verskeie maatstawwe om te kwantifiseer hoe goed die model na nuwe data veralgemeen. Algemene evaluasiemaatstawwe sluit in:

### Akkuraatheid

Akkuraatheid is die verhouding van korrek voorspelde gevalle tot die totale aantal gevalle. Dit word bereken as:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Akkuraatheid is ’n eenvoudige en intuïtiewe maatstaf, maar dit is moontlik nie geskik vir ongebalanseerde datastelle waar een klas die ander oorheers nie, aangesien dit ’n misleidende indruk van modelprestasie kan gee. Byvoorbeeld, as 90% van die data aan klas A behoort en die model alle gevalle as klas A voorspel, sal dit 90% akkuraatheid behaal, maar dit sal nie nuttig wees om klas B te voorspel nie.

### Presisie

Presisie is die verhouding van ware positiewe voorspellings tot alle positiewe voorspellings wat deur die model gemaak word. Dit word soos volg bereken:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Presisie is veral belangrik in scenario's waar vals positiewe resultate duur of ongewens is, soos by mediese diagnoses of bedrogbespeuring. Byvoorbeeld, as 'n model 100 gevalle as positief voorspel, maar slegs 80 daarvan werklik positief is, sal die presisie 0.8 (80%) wees.

### Herroeping (Sensitiwiteit)

Herroeping, ook bekend as sensitiwiteit of die ware-positiewe koers, is die verhouding van ware positiewe voorspellings tot alle werklike positiewe gevalle. Dit word soos volg bereken:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Recall is noodsaaklik in scenario's waar vals negatiewe duur of ongewens is, soos by siekte-opsporing of spamfiltrering. Byvoorbeeld, as 'n model 80 uit 100 werklike positiewe gevalle identifiseer, sal die recall 0.8 (80%) wees.

### F1-telling

Die F1-telling is die harmoniese gemiddelde van precision en recall, wat 'n balans tussen die twee metrieke bied. Dit word soos volg bereken:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Die F1-telling is besonder nuttig wanneer daar met ongebalanseerde datastelle gewerk word, aangesien dit beide vals positiewe en vals negatiewe in ag neem. Dit verskaf ’n enkele maatstaf wat die afweging tussen presisie en herroeping vasvang. Byvoorbeeld, as ’n model ’n presisie van 0.8 en ’n herroeping van 0.6 het, sal die F1-telling ongeveer 0.69 wees.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

Die ROC-AUC-maatstaf evalueer die model se vermoë om tussen klasse te onderskei deur die ware-positiewe-koers (sensitiwiteit) teenoor die vals-positiewe-koers by verskeie drempelinstellings te plot. Die area onder die ROC-kurwe (AUC) kwantifiseer die model se werkverrigting, met ’n waarde van 1 wat perfekte klassifikasie aandui en ’n waarde van 0.5 wat ewekansige raaiwerk aandui.

> [!TIP]
> ROC-AUC is besonder nuttig vir binêre klassifikasieprobleme en bied ’n omvattende oorsig van die model se werkverrigting oor verskillende drempels. Dit is minder sensitief vir klaswanbalans in vergelyking met akkuraatheid. Byvoorbeeld, ’n model met ’n AUC van 0.9 dui aan dat dit ’n hoë vermoë het om tussen positiewe en negatiewe gevalle te onderskei.

### Spesifisiteit

Spesifisiteit, ook bekend as die ware-negatiewe-koers, is die proporsie ware-negatiewe voorspellings uit alle werklike negatiewe gevalle. Dit word bereken as:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Spesifisiteit is belangrik in scenario's waar vals positiewe duur of ongewens is, soos in mediese toetse of bedrogbespeuring. Dit help om te bepaal hoe goed die model negatiewe gevalle identifiseer. Byvoorbeeld, as 'n model 90 uit 100 werklike negatiewe gevalle korrek identifiseer, sal die spesifisiteit 0.9 (90%) wees.

### Matthews-korrelasiekoëffisiënt (MCC)
Die Matthews-korrelasiekoëffisiënt (MCC) is 'n maatstaf van die gehalte van binêre klassifikasies. Dit neem ware en vals positiewe sowel as negatiewe in ag, wat 'n gebalanseerde oorsig van die model se prestasie bied. Die MCC word soos volg bereken:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
waar:
- **TP**: Ware Positiewe
- **TN**: Ware Negatiewe
- **FP**: Vals Positiewe
- **FN**: Vals Negatiewe

> [!TIP]
> Die MCC wissel van -1 tot 1, waar 1 perfekte klassifikasie aandui, 0 ewekansige raaiwerk aandui, en -1 totale teenstrydigheid tussen voorspelling en waarneming aandui. Dit is veral nuttig vir ongebalanseerde datastelle, aangesien dit al vier komponente van die confusion matrix in ag neem.

### Mean Absolute Error (MAE)
Mean Absolute Error (MAE) is ’n regressiemetriek wat die gemiddelde absolute verskil tussen voorspelde en werklike waardes meet. Dit word bereken as:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
waar:
- **n**: Aantal instansies
- **y_i**: Werklike waarde vir instansie i
- **ŷ_i**: Voorspelde waarde vir instansie i

> [!TIP]
> MAE bied ’n eenvoudige interpretasie van die gemiddelde fout in voorspellings, wat dit maklik maak om te verstaan. Dit is minder sensitief vir uitskieters in vergelyking met ander maatstawwe soos Mean Squared Error (MSE). Byvoorbeeld, as ’n model ’n MAE van 5 het, beteken dit dat die model se voorspellings gemiddeld met 5 eenhede van die werklike waardes afwyk.

### Verwarringsmatriks

Die verwarringsmatriks is ’n tabel wat die prestasie van ’n klassifikasiemodel opsom deur die tellings van true positive-, true negative-, false positive- en false negative-voorspellings te toon. Dit bied ’n gedetailleerde oorsig van hoe goed die model op elke klas presteer.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Die model het die positiewe klas korrek voorspel.
- **True Negative (TN)**: Die model het die negatiewe klas korrek voorspel.
- **False Positive (FP)**: Die model het die positiewe klas verkeerdelik voorspel (Tipe I-fout).
- **False Negative (FN)**: Die model het die negatiewe klas verkeerdelik voorspel (Tipe II-fout).

Die verwarringsmatriks kan gebruik word om evaluasiemaatstawwe soos accuracy, precision, recall en F1 score te bereken.

## References

- [1] [scikit-learn - Voorverwerking van data](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputasie van ontbrekende waardes](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Kruisvalidering: evaluering van estimator-prestasie](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Maatstawwe en scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
