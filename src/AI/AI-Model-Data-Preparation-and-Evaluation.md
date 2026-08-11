# Priprema i evaluacija podataka modela

{{#include ../banners/hacktricks-training.md}}

Priprema podataka modela je ključan korak u procesu mašinskog učenja, jer obuhvata transformisanje sirovih podataka u format pogodan za treniranje modela mašinskog učenja. Ovaj proces uključuje nekoliko ključnih koraka:

1. **Prikupljanje podataka**: Prikupljanje podataka iz različitih izvora, kao što su baze podataka, API-ji ili datoteke. Podaci mogu biti strukturirani (npr. tabele) ili nestrukturirani (npr. tekst, slike).
2. **Čišćenje podataka**: Uklanjanje ili ispravljanje pogrešnih, nepotpunih ili nerelevantnih tačaka podataka. Ovaj korak može obuhvatati obradu nedostajućih vrednosti, uklanjanje duplikata i filtriranje odstupajućih vrednosti.
3. **Transformacija podataka**: Pretvaranje podataka u format pogodan za modeliranje. To može obuhvatati normalizaciju, skaliranje, kodiranje kategoričkih promenljivih i kreiranje novih karakteristika pomoću tehnika kao što je feature engineering.
4. **Podela podataka**: Deljenje skupa podataka na skupove za treniranje, validaciju i testiranje kako bi se osiguralo da model može dobro da generalizuje na do tada neviđene podatke.

## Prikupljanje podataka

Prikupljanje podataka obuhvata prikupljanje podataka iz različitih izvora, koji mogu uključivati:
- **Baze podataka**: Izdvajanje podataka iz relacionih baza podataka (npr. SQL baze podataka) ili NoSQL baza podataka (npr. MongoDB).
- **API-ji**: Preuzimanje podataka sa web API-ja, koji mogu pružati podatke u realnom vremenu ili istorijske podatke.
- **Datoteke**: Čitanje podataka iz datoteka u formatima kao što su CSV, JSON ili XML.
- **Web Scraping**: Prikupljanje podataka sa veb-sajtova pomoću tehnika za web scraping.

U zavisnosti od cilja projekta mašinskog učenja, podaci će biti izdvojeni i prikupljeni iz relevantnih izvora kako bi se osiguralo da predstavljaju domen problema.

## Čišćenje podataka <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Čišćenje podataka je proces identifikovanja i ispravljanja grešaka ili nedoslednosti u skupu podataka. Ovaj korak je od ključnog značaja za osiguravanje kvaliteta podataka koji se koriste za treniranje modela mašinskog učenja. Ključni zadaci pri čišćenju podataka obuhvataju:
- **Obrada nedostajućih vrednosti**: Identifikovanje i rešavanje tačaka podataka koje nedostaju. Uobičajene strategije uključuju:
- Uklanjanje redova ili kolona sa nedostajućim vrednostima.
- Popunjavanje nedostajućih vrednosti pomoću tehnika kao što su imputacija srednjom vrednošću, medijanom ili modom.
- Korišćenje naprednih metoda kao što su imputacija pomoću K-nearest neighbors (KNN) ili regresiona imputacija.
- **Uklanjanje duplikata**: Identifikovanje i uklanjanje dupliranih zapisa kako bi se osiguralo da je svaka tačka podataka jedinstvena.
- **Filtriranje odstupajućih vrednosti**: Otkrivanje i uklanjanje odstupajućih vrednosti koje mogu narušiti performanse modela. Za identifikovanje odstupajućih vrednosti mogu se koristiti tehnike kao što su Z-score, IQR (Interquartile Range) ili vizuelizacije (npr. box plotovi).

### Primer čišćenja podataka
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
## Transformacija podataka <sup>[[1]](#references)</sup>

Transformacija podataka obuhvata konvertovanje podataka u format pogodan za modelovanje. Ovaj korak može uključivati:
- **Normalizaciju i standardizaciju**: Skaliranje numeričkih obeležja na zajednički opseg, obično [0, 1] ili [-1, 1]. Ovo može poboljšati konvergenciju optimization algoritama.
- **Min-Max Scaling**: Ponovno skaliranje obeležja na fiksni opseg, obično [0, 1]. Ovo se radi pomoću formule: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: Standardizacija obeležja oduzimanjem srednje vrednosti i deljenjem standardnom devijacijom, čime se dobija distribucija sa srednjom vrednošću 0 i standardnom devijacijom 1. Ovo se radi pomoću formule: `X' = (X - μ) / σ`, gde je μ srednja vrednost, a σ standardna devijacija.
- **Asimetrija i kurtosis**: Prilagođavanje distribucija obeležja transformacijama kao što su logaritam, kvadratni koren ili Box-Cox. Na primer, logaritamska transformacija može smanjiti pozitivnu asimetriju.
- **String Normalization**: Konvertovanje stringova u dosledan format, kao što su:
- Pretvaranje u mala slova
- Uklanjanje specijalnih znakova (uz zadržavanje relevantnih)
- Uklanjanje stop-reči (uobičajenih reči koje ne doprinose značenju, kao što su "the", "is", "and")
- Uklanjanje previše čestih i previše retkih reči (npr. reči koje se pojavljuju u više od 90% dokumenata ili manje od 5 puta u korpusu)
- Uklanjanje razmaka sa početka i kraja
- Stemming/Lemmatization: Svođenje reči na osnovni ili korenski oblik (npr. "running" u "run").

- **Kodiranje kategorijskih promenljivih**: Konvertovanje kategorijskih promenljivih u numeričke reprezentacije. Uobičajene tehnike uključuju:
- **One-Hot Encoding**: Kreiranje binarnih kolona za svaku kategoriju.
- Na primer, ako obeležje ima kategorije "red", "green" i "blue", biće transformisano u tri binarne kolone: `is_red`(100), `is_green`(010) i `is_blue`(001).
- **Label Encoding**: Dodeljivanje jedinstvenog celog broja svakoj kategoriji.
- Na primer, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Dodeljivanje celih brojeva na osnovu redosleda kategorija.
- Na primer, ako su kategorije "low", "medium" i "high", mogu se kodirati kao 0, 1 i 2, redom.
- **Hashing Encoding**: Korišćenje hash funkcije za konvertovanje kategorija u vektore fiksne veličine, što može biti korisno za kategorijske promenljive sa velikim brojem jedinstvenih vrednosti.
- Na primer, ako obeležje ima mnogo jedinstvenih kategorija, hashing može smanjiti dimenzionalnost uz očuvanje dela informacija o kategorijama.
- **Bag of Words (BoW)**: Predstavljanje tekstualnih podataka kao matrice broja ili učestalosti reči, gde svaki red odgovara dokumentu, a svaka kolona jedinstvenoj reči u korpusu.
- Na primer, ako korpus sadrži reči "cat", "dog" i "fish", dokument koji sadrži "cat" i "dog" bio bi predstavljen kao [1, 1, 0]. Ova konkretna reprezentacija naziva se "unigram" i ne obuhvata redosled reči, pa gubi semantičke informacije.
- **Bigram/Trigram**: Proširivanje BoW-a radi obuhvatanja sekvenci reči (bigrami ili trigrami) i zadržavanja dela konteksta. Na primer, "cat and dog" bi bilo predstavljeno kao bigram [1, 1] za "cat and" i [1, 1] za "and dog". U ovom slučaju prikuplja se više semantičkih informacija (povećanjem dimenzionalnosti reprezentacije), ali samo za 2 ili 3 reči istovremeno.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Statistička mera koja procenjuje važnost reči u dokumentu u odnosu na kolekciju dokumenata (korpus). Ona kombinuje frekvenciju termina (koliko često se reč pojavljuje u dokumentu) i inverznu frekvenciju dokumenta (koliko je reč retka u svim dokumentima).
- Na primer, ako se reč "cat" često pojavljuje u dokumentu, ali je retka u celom korpusu, imaće visok TF-IDF rezultat, što ukazuje na njenu važnost u tom dokumentu.

- **Feature Engineering**: Kreiranje novih obeležja na osnovu postojećih radi poboljšanja prediktivne moći modela. Ovo može uključivati kombinovanje obeležja, izdvajanje komponenti datuma/vremena ili primenu transformacija specifičnih za domen.

## Podela podataka <sup>[[3]](#references)</sup>

Podela podataka obuhvata deljenje skupa podataka na odvojene podskupove za obuku, validaciju i testiranje. Ovo je neophodno za procenu performansi modela na neviđenim podacima i sprečavanje overfitting-a. Uobičajene strategije uključuju:
- **Train-Test Split**: Deljenje skupa podataka na skup za obuku (obično 60–80% podataka), skup za validaciju (10–15% podataka) za podešavanje hyperparameter-a i testni skup (10–15% podataka). Model se obučava na skupu za obuku i procenjuje na testnom skupu.
- Na primer, ako imate skup podataka sa 1000 uzoraka, možete koristiti 700 uzoraka za obuku, 150 za validaciju i 150 za testiranje.
- **Stratified Sampling**: Obezbeđivanje da distribucija klasa u skupovima za obuku i testiranje bude slična distribuciji u celom skupu podataka. Ovo je naročito važno za nebalansirane skupove podataka, gde neke klase mogu imati znatno manje uzoraka od drugih.
- **Time Series Split**: Kod podataka vremenskih serija, skup podataka se deli na osnovu vremena, tako da skup za obuku sadrži podatke iz ranijih vremenskih perioda, a testni skup podatke iz kasnijih perioda. Ovo pomaže u proceni performansi modela na budućim podacima.
- **K-Fold Cross-Validation**: Deljenje skupa podataka na K podskupova (foldova) i obučavanje modela K puta, pri čemu se svaki put drugi fold koristi kao testni skup, a preostali foldovi kao skup za obuku. Ovo pomaže da se model proceni na različitim podskupovima podataka, pružajući pouzdaniju procenu njegovih performansi.

## Procena modela <sup>[[4]](#references)</sup>

Procena modela je proces ocenjivanja performansi machine learning modela na neviđenim podacima. Ona podrazumeva korišćenje različitih metrika za kvantifikovanje toga koliko dobro se model generalizuje na nove podatke. Uobičajene metrike procene uključuju:

### Tačnost

Tačnost predstavlja udeo tačno predviđenih instanci u odnosu na ukupan broj instanci. Izračunava se kao:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Accuracy je jednostavna i intuitivna metrika, ali možda nije pogodna za neuravnotežene skupove podataka u kojima jedna klasa dominira nad ostalima, jer može stvoriti pogrešan utisak o performansama modela. Na primer, ako 90% podataka pripada klasi A, a model predviđa sve instance kao klasu A, postići će Accuracy od 90%, ali neće biti koristan za predviđanje klase B.

### Precision

Precision je udeo tačnih pozitivnih predviđanja u odnosu na sva pozitivna predviđanja koja je model napravio. Izračunava se na sledeći način:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Preciznost je posebno važna u scenarijima gde su lažno pozitivni rezultati skupi ili nepoželjni, kao što su medicinske dijagnoze ili otkrivanje prevara. Na primer, ako model predvidi 100 instanci kao pozitivne, ali je samo njih 80 zaista pozitivno, preciznost bi bila 0.8 (80%).

### Odziv (senzitivnost)

Odziv, poznat i kao senzitivnost ili stopa tačno pozitivnih rezultata, predstavlja udeo tačno pozitivnih predikcija među svim stvarnim pozitivnim instancama. Računa se na sledeći način:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Recall je ključan u scenarijima u kojima su lažno negativni rezultati skupi ili nepoželjni, kao što su otkrivanje bolesti ili filtriranje spam poruka. Na primer, ako model identifikuje 80 od 100 stvarnih pozitivnih slučajeva, recall bi iznosio 0,8 (80%).

### F1 skor

F1 skor je harmonijska sredina preciznosti i recall-a, čime pruža ravnotežu između ove dve metrike. Izračunava se na sledeći način:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 score je posebno koristan pri radu sa neuravnoteženim skupovima podataka, jer uzima u obzir i lažno pozitivne i lažno negativne rezultate. Pruža jednu metriku koja obuhvata kompromis između preciznosti i odziva. Na primer, ako model ima preciznost 0.8 i odziv 0.6, F1 score bi iznosio približno 0.69.

### ROC-AUC (Receiver Operating Characteristic - površina ispod krive)

ROC-AUC metrika procenjuje sposobnost modela da razlikuje klase tako što prikazuje stopu tačno pozitivnih rezultata (osetljivost) u odnosu na stopu lažno pozitivnih rezultata pri različitim podešavanjima praga. Površina ispod ROC krive (AUC) kvantifikuje performanse modela, pri čemu vrednost 1 označava savršenu klasifikaciju, a vrednost 0.5 nasumično pogađanje.

> [!TIP]
> ROC-AUC je posebno koristan za probleme binarne klasifikacije i pruža sveobuhvatan pregled performansi modela pri različitim pragovima. Manje je osetljiv na neuravnoteženost klasa u poređenju sa tačnošću. Na primer, model sa AUC vrednošću 0.9 pokazuje visoku sposobnost razlikovanja pozitivnih i negativnih instanci.

### Specifičnost

Specifičnost, poznata i kao stopa tačno negativnih rezultata, predstavlja udeo tačno negativnih predikcija među svim stvarno negativnim instancama. Izračunava se na sledeći način:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Specifičnost je važna u scenarijima gde su lažno pozitivni rezultati skupi ili nepoželjni, kao što su medicinska testiranja ili otkrivanje prevara. Ona pomaže u proceni koliko dobro model identifikuje negativne instance. Na primer, ako model ispravno identifikuje 90 od 100 stvarnih negativnih instanci, specifičnost bi bila 0,9 (90%).

### Matthewsov koeficijent korelacije (MCC)
Matthewsov koeficijent korelacije (MCC) predstavlja meru kvaliteta binarnih klasifikacija. On uzima u obzir istinito i lažno pozitivne i negativne rezultate, pružajući uravnotežen pregled performansi modela. MCC se izračunava na sledeći način:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
gde:
- **TP**: Tačno pozitivni
- **TN**: Tačno negativni
- **FP**: Lažno pozitivni
- **FN**: Lažno negativni

> [!TIP]
> MCC se kreće od -1 do 1, pri čemu 1 označava savršenu klasifikaciju, 0 označava nasumično pogađanje, a -1 označava potpuno neslaganje između predviđanja i posmatranja. Posebno je koristan za neuravnotežene skupove podataka, jer uzima u obzir sve četiri komponente matrice konfuzije.

### Srednja apsolutna greška (MAE)
Srednja apsolutna greška (MAE) je metrika regresije koja meri prosečnu apsolutnu razliku između predviđenih i stvarnih vrednosti. Izračunava se na sledeći način:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
gde:
- **n**: Broj instanci
- **y_i**: Stvarna vrednost za instancu i
- **ŷ_i**: Predviđena vrednost za instancu i

> [!TIP]
> MAE pruža jednostavno tumačenje prosečne greške u predviđanjima, što olakšava razumevanje. Manje je osetljiv na outlier-e u poređenju sa drugim metrikama, kao što je Mean Squared Error (MSE). Na primer, ako model ima MAE vrednost 5, to znači da predviđanja modela u proseku odstupaju od stvarnih vrednosti za 5 jedinica.

### Confusion Matrix

Confusion matrix je tabela koja sažima performanse classification modela prikazivanjem broja predviđanja koja su true positive, true negative, false positive i false negative. Ona pruža detaljan pregled toga koliko dobro model radi za svaku klasu.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Model je ispravno predvideo pozitivnu klasu.
- **True Negative (TN)**: Model je ispravno predvideo negativnu klasu.
- **False Positive (FP)**: Model je neispravno predvideo pozitivnu klasu (Type I error).
- **False Negative (FN)**: Model je neispravno predvideo negativnu klasu (Type II error).

Confusion matrix se može koristiti za izračunavanje evaluation metrika kao što su accuracy, precision, recall i F1 score.

## References

- [1] [scikit-learn - Preprocesiranje podataka](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputacija nedostajućih vrednosti](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Unakrsna validacija: procena performansi estimator-a](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metrike i scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
