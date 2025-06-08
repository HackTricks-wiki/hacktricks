# Model Data Preparation & Evaluation

{{#include ../banners/hacktricks-training.md}}

Modeldata voorbereiding is 'n belangrike stap in die masjienleer-pyplyn, aangesien dit die transformasie van rou data in 'n formaat wat geskik is vir die opleiding van masjienleer-modelle behels. Hierdie proses sluit verskeie sleutelstappe in:

1. **Data-insameling**: Versameling van data uit verskeie bronne, soos databasisse, API's of lêers. Die data kan gestruktureerd wees (bv. tabelle) of ongestruktureerd (bv. teks, beelde).
2. **Data-skoonmaak**: Verwydering of regstelling van foute, onvolledige of irrelevante datapunte. Hierdie stap kan die hantering van ontbrekende waardes, die verwydering van duplikate en die filtrering van uitskieters behels.
3. **Data-transformasie**: Om die data in 'n geskikte formaat vir modellering te omskep. Dit kan normalisering, skaal, kodering van kategorievariabeles en die skep van nuwe kenmerke deur tegnieke soos kenmerkingenieurswese insluit.
4. **Data-splitsing**: Verdelen van die datastel in opleidings-, validasie- en toetsstelle om te verseker dat die model goed kan generaliseer na ongesiene data.

## Data-insameling

Data-insameling behels die versameling van data uit verskeie bronne, wat kan insluit:
- **Databasisse**: Uittreksel van data uit relationele databasisse (bv. SQL-databasisse) of NoSQL-databasisse (bv. MongoDB).
- **API's**: Onttrekking van data uit web-API's, wat regstreekse of historiese data kan verskaf.
- **Lêers**: Lees van data uit lêers in formate soos CSV, JSON of XML.
- **Web Scraping**: Versameling van data van webwerwe deur middel van web scraping-tegnieke.

Afhangende van die doel van die masjienleerprojek, sal die data uit relevante bronne onttrek en versamel word om te verseker dat dit verteenwoordigend is van die probleemgebied.

## Data-skoonmaak

Data-skoonmaak is die proses om foute of inkonsekwentheid in die datastel te identifiseer en reg te stel. Hierdie stap is noodsaaklik om die kwaliteit van die data wat gebruik word vir die opleiding van masjienleer-modelle te verseker. Sleutel take in data-skoonmaak sluit in:
- **Hantering van Ontbrekende Waardes**: Identifisering en aanspreek van ontbrekende datapunte. Gewone strategieë sluit in:
- Verwydering van rye of kolomme met ontbrekende waardes.
- Imputering van ontbrekende waardes met tegnieke soos gemiddelde, mediaan of modus imputasie.
- Gebruik van gevorderde metodes soos K-nabyste bure (KNN) imputasie of regressie imputasie.
- **Verwydering van Duplikate**: Identifisering en verwydering van duplikaatrekords om te verseker dat elke datapunt uniek is.
- **Filtrering van Uitskieters**: Opsporing en verwydering van uitskieters wat die model se prestasie kan beïnvloed. Tegnieke soos Z-score, IQR (Interkwartielreeks), of visualisasies (bv. boksplotte) kan gebruik word om uitskieters te identifiseer.

### Voorbeeld van data-skoonmaak
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
## Data Transformation

Data transformation behels die omskakeling van die data in 'n formaat wat geskik is vir modellering. Hierdie stap kan insluit:
- **Normalisering & Standaardisering**: Skalering van numeriese kenmerke na 'n algemene reeks, tipies [0, 1] of [-1, 1]. Dit help om die konvergensie van optimalisering algoritmes te verbeter.
- **Min-Max Skalering**: Her-skalering van kenmerke na 'n vaste reeks, gewoonlik [0, 1]. Dit word gedoen met die formule: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalisering**: Standaardisering van kenmerke deur die gemiddelde af te trek en deur die standaardafwyking te deel, wat 'n verspreiding met 'n gemiddelde van 0 en 'n standaardafwyking van 1 tot gevolg het. Dit word gedoen met die formule: `X' = (X - μ) / σ`, waar μ die gemiddelde is en σ die standaardafwyking.
- **Skewness en Kurtosis**: Aanpassing van die verspreiding van kenmerke om skewness (asymmetrie) en kurtosis (piekigheid) te verminder. Dit kan gedoen word met transformasies soos logaritmies, vierkantswortel, of Box-Cox transformasies. Byvoorbeeld, as 'n kenmerk 'n skewed verspreiding het, kan die toepassing van 'n logaritmiese transformasie help om dit te normaliseer.
- **String Normalisering**: Omskakeling van strings na 'n konsekwente formaat, soos:
- Kleinletters
- Verwydering van spesiale karakters (die relevante te behou)
- Verwydering van stopwoorde (gewone woorde wat nie bydra tot die betekenis nie, soos "die", "is", "en")
- Verwydering van te gereelde woorde en te seldsame woorde (bv. woorde wat in meer as 90% van die dokumente of minder as 5 keer in die korpus voorkom)
- Afknip van spasie
- Stemming/Lemmatization: Vermindering van woorde na hul basis of wortelvorm (bv. "hardloop" na "hardloop").

- **Kodering van Kategoriese Veranderlikes**: Omskakeling van kategoriese veranderlikes in numeriese verteenwoordigings. Gewone tegnieke sluit in:
- **One-Hot Kodering**: Skep binêre kolomme vir elke kategorie.
- Byvoorbeeld, as 'n kenmerk kategorieë "rooi", "groen", en "blou" het, sal dit in drie binêre kolomme omgeskakel word: `is_rooi`(100), `is_groen`(010), en `is_blou`(001).
- **Label Kodering**: Toekenning van 'n unieke heelgetal aan elke kategorie.
- Byvoorbeeld, "rooi" = 0, "groen" = 1, "blou" = 2.
- **Ordinale Kodering**: Toekenning van heelgetalle gebaseer op die volgorde van kategorieë.
- Byvoorbeeld, as die kategorieë "laag", "medium", en "hoog" is, kan hulle as 0, 1, en 2 gekodeer word, onderskeidelik.
- **Hashing Kodering**: Gebruik van 'n hash-funksie om kategorieë in vaste-grootte vektore om te skakel, wat nuttig kan wees vir hoë-kardinaliteit kategoriese veranderlikes.
- Byvoorbeeld, as 'n kenmerk baie unieke kategorieë het, kan hashing die dimensionaliteit verminder terwyl dit 'n bietjie inligting oor die kategorieë behou.
- **Bag of Words (BoW)**: Verteenwoordig teksdata as 'n matriks van woordtellings of frekwensies, waar elke ry ooreenstem met 'n dokument en elke kolom ooreenstem met 'n unieke woord in die korpus.
- Byvoorbeeld, as die korpus die woorde "kat", "hond", en "vis" bevat, sal 'n dokument wat "kat" en "hond" bevat, verteenwoordig word as [1, 1, 0]. Hierdie spesifieke voorstelling word "unigram" genoem en vang nie die volgorde van woorde nie, sodat dit semantiese inligting verloor.
- **Bigram/Trigram**: Uitbreiding van BoW om woordsekwensies (bigrams of trigrams) te vang om 'n bietjie konteks te behou. Byvoorbeeld, "kat en hond" sal as 'n bigram [1, 1] vir "kat en" en [1, 1] vir "en hond" verteenwoordig word. In hierdie gevalle word meer semantiese inligting versamel (wat die dimensionaliteit van die voorstelling verhoog) maar slegs vir 2 of 3 woorde op 'n slag.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: 'n Statistiese maatstaf wat die belangrikheid van 'n woord in 'n dokument ten opsigte van 'n versameling dokumente (korpus) evalueer. Dit kombineer termfrekwensie (hoe gereeld 'n woord in 'n dokument voorkom) en omgekeerde dokumentfrekwensie (hoe skaars 'n woord oor alle dokumente is).
- Byvoorbeeld, as die woord "kat" gereeld in 'n dokument voorkom maar skaars in die hele korpus is, sal dit 'n hoë TF-IDF telling hê, wat die belangrikheid daarvan in daardie dokument aandui.

- **Kenmerk Ingenieurswese**: Skep van nuwe kenmerke uit bestaande om die model se voorspellingskrag te verbeter. Dit kan die kombinasie van kenmerke, die onttrekking van datum/tyd komponente, of die toepassing van domein-spesifieke transformasies insluit.

## Data Splitting

Data splitting behels die verdeling van die datastel in aparte substelle vir opleiding, validasie, en toetsing. Dit is noodsaaklik om die model se prestasie op ongekende data te evalueer en oorpassing te voorkom. Gewone strategieë sluit in:
- **Opleidings-Toets Splitsing**: Verdelen van die datastel in 'n opleidingsstel (tipies 60-80% van die data), 'n validasiestel (10-15% van die data) om hiperparameters te tune, en 'n toetsstel (10-15% van die data). Die model word op die opleidingsstel opgelei en op die toetsstel geëvalueer.
- Byvoorbeeld, as jy 'n datastel van 1000 monsters het, kan jy 700 monsters vir opleiding, 150 vir validasie, en 150 vir toetsing gebruik.
- **Gelaagdige Steekproefneming**: Verseker dat die verspreiding van klasse in die opleidings- en toetsstelle soortgelyk is aan die algehele datastel. Dit is veral belangrik vir ongebalanseerde datastelle, waar sommige klasse aansienlik minder monsters kan hê as ander.
- **Tydreeks Splitsing**: Vir tydreeksdata word die datastel op grond van tyd gesplit, wat verseker dat die opleidingsstel data van vroeë tydperke bevat en die toetsstel data van latere tydperke bevat. Dit help om die model se prestasie op toekomstige data te evalueer.
- **K-Vou Kruisvalidering**: Die datastel in K substelle (vou) verdeel en die model K keer oplei, elke keer 'n ander vou as die toetsstel en die oorblywende voue as die opleidingsstel gebruik. Dit help om te verseker dat die model op verskillende substelle van data geëvalueer word, wat 'n meer robuuste skatting van sy prestasie bied.

## Model Evaluasie

Model evaluasie is die proses om die prestasie van 'n masjienleer model op ongekende data te evalueer. Dit behels die gebruik van verskeie metrieke om te kwantifiseer hoe goed die model generaliseer na nuwe data. Gewone evaluasiemetrieke sluit in:

### Akkuraatheid

Akkuraatheid is die proporsie van korrek voorspelde voorvalle uit die totale voorvalle. Dit word bereken as:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Akkuraatheid is 'n eenvoudige en intuïtiewe maatstaf, maar dit mag nie geskik wees vir ongebalanseerde datastelle waar een klas die ander oorheers nie, aangesien dit 'n misleidende indruk van modelprestasie kan gee. Byvoorbeeld, as 90% van die data aan klas A behoort en die model alle voorbeelde as klas A voorspel, sal dit 90% akkuraatheid bereik, maar dit sal nie nuttig wees om klas B te voorspel nie.

### Presisie

Presisie is die verhouding van werklike positiewe voorspellings uit alle positiewe voorspellings wat deur die model gemaak is. Dit word bereken as:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Presisie is veral belangrik in scenario's waar vals positiewe kostelik of ongewenst is, soos in mediese diagnoses of bedrogdetectie. Byvoorbeeld, as 'n model 100 voorbeelde as positief voorspel, maar slegs 80 daarvan werklik positief is, sal die presisie 0.8 (80%) wees.

### Herinnering (Sensitiwiteit)

Herinnering, ook bekend as sensitiwiteit of werklike positiewe koers, is die verhouding van werklike positiewe voorspellings uit alle werklike positiewe voorbeelde. Dit word bereken as:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Herroeping is van kardinale belang in scenario's waar valse negatiewe kostelik of ongewenst is, soos in siekte-opsporing of spamfiltering. Byvoorbeeld, as 'n model 80 uit 100 werklike positiewe voorbeelde identifiseer, sal die herroeping 0.8 (80%) wees.

### F1 Score

Die F1-telling is die harmoniese gemiddelde van presisie en herroeping, wat 'n balans tussen die twee metrieks bied. Dit word bereken as:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Die F1-telling is veral nuttig wanneer daar met ongebalanseerde datastelle gewerk word, aangesien dit beide vals positiewe en vals negatiewe in ag neem. Dit bied 'n enkele maatstaf wat die afruil tussen presisie en herroeping vasvang. Byvoorbeeld, as 'n model 'n presisie van 0.8 en 'n herroeping van 0.6 het, sal die F1-telling ongeveer 0.69 wees.

### ROC-AUC (Ontvanger Operasionele Kenmerk - Gebied Onder die Kromme)

Die ROC-AUC maatstaf evalueer die model se vermoë om tussen klasse te onderskei deur die werklike positiewe koers (sensitiwiteit) teen die vals positiewe koers by verskillende drempelinstellings te plot. Die gebied onder die ROC-kromme (AUC) kwantifiseer die model se prestasie, met 'n waarde van 1 wat perfekte klassifikasie aandui en 'n waarde van 0.5 wat ewekansige raai aandui.

> [!TIP]
> ROC-AUC is veral nuttig vir binêre klassifikasieprobleme en bied 'n omvattende oorsig van die model se prestasie oor verskillende drempels. Dit is minder sensitief vir klasongelykheid in vergelyking met akkuraatheid. Byvoorbeeld, 'n model met 'n AUC van 0.9 dui aan dat dit 'n hoë vermoë het om tussen positiewe en negatiewe voorvalle te onderskei.

### Spesifisiteit

Spesifisiteit, ook bekend as werklike negatiewe koers, is die proporsie van werklike negatiewe voorspellings uit alle werklike negatiewe voorvalle. Dit word bereken as:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Spesifisiteit is belangrik in scenario's waar vals positiewe kostelik of ongewenst is, soos in mediese toetse of bedrogdetectie. Dit help om te evalueer hoe goed die model negatiewe voorbeelde identifiseer. Byvoorbeeld, as 'n model korrek 90 uit 100 werklike negatiewe voorbeelde identifiseer, sal die spesifisiteit 0.9 (90%) wees.

### Matthews Korrelasie Koeffisiënt (MCC)
Die Matthews Korrelasie Koeffisiënt (MCC) is 'n maatstaf van die kwaliteit van binêre klassifikasies. Dit hou rekening met ware en vals positiewe en negatiewe, en bied 'n gebalanseerde oorsig van die model se prestasie. Die MCC word bereken as:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
waar:
- **TP**: Ware Positiewe
- **TN**: Ware Negatiewe
- **FP**: Valse Positiewe
- **FN**: Valse Negatiewe

> [!TIP]
> Die MCC wissel van -1 tot 1, waar 1 perfekte klassifikasie aandui, 0 willekeurige raai aandui, en -1 totale onenigheid tussen voorspelling en waarneming aandui. Dit is veral nuttig vir ongebalanseerde datastelle, aangesien dit al vier komponenten van die verwarring matriks oorweeg.

### Gemiddelde Absolute Fout (MAE)
Gemiddelde Absolute Fout (MAE) is 'n regressiemetriek wat die gemiddelde absolute verskil tussen voorspelde en werklike waardes meet. Dit word bereken as:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
waar:
- **n**: Aantal instansies
- **y_i**: Werklike waarde vir instansie i
- **ŷ_i**: Voorspelde waarde vir instansie i

> [!TIP]
> MAE bied 'n eenvoudige interpretasie van die gemiddelde fout in voorspellings, wat dit maklik maak om te verstaan. Dit is minder sensitief vir uitskieters in vergelyking met ander metrieks soos Mean Squared Error (MSE). Byvoorbeeld, as 'n model 'n MAE van 5 het, beteken dit dat die model se voorspellings gemiddeld 5 eenhede van die werklike waardes afwyk.

### Verwarringsmatriks

Die verwarringsmatriks is 'n tabel wat die prestasie van 'n klassifikasiemodel opsom deur die tellings van werklike positiewe, werklike negatiewe, vals positiewe en vals negatiewe voorspellings te toon. Dit bied 'n gedetailleerde oorsig van hoe goed die model op elke klas presteer.

|               | Voorspelde Positief | Voorspelde Negatief |
|---------------|---------------------|---------------------|
| Werklike Positief| Ware Positief (TP)  | Vals Negatief (FN)  |
| Werklike Negatief| Vals Positief (FP) | Ware Negatief (TN)   |

- **Ware Positief (TP)**: Die model het die positiewe klas korrek voorspel.
- **Ware Negatief (TN)**: Die model het die negatiewe klas korrek voorspel.
- **Vals Positief (FP)**: Die model het die positiewe klas verkeerdelik voorspel (Tipe I fout).
- **Vals Negatief (FN)**: Die model het die negatiewe klas verkeerdelik voorspel (Tipe II fout).

Die verwarringsmatriks kan gebruik word om verskeie evaluasiemetriks te bereken, soos akkuraatheid, presisie, terugroep en F1-telling.


{{#include ../banners/hacktricks-training.md}}
