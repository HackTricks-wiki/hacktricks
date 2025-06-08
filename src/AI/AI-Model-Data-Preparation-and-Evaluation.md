# Priprema i Evaluacija Podataka Modela

{{#include ../banners/hacktricks-training.md}}

Priprema podataka modela je ključni korak u procesu mašinskog učenja, jer uključuje transformaciju sirovih podataka u format pogodan za obuku modela mašinskog učenja. Ovaj proces obuhvata nekoliko ključnih koraka:

1. **Prikupljanje Podataka**: Prikupljanje podataka iz različitih izvora, kao što su baze podataka, API-ji ili datoteke. Podaci mogu biti strukturirani (npr. tabele) ili nestrukturirani (npr. tekst, slike).
2. **Čišćenje Podataka**: Uklanjanje ili ispravljanje pogrešnih, nepotpunih ili nerelevantnih tačaka podataka. Ovaj korak može uključivati rukovanje nedostajućim vrednostima, uklanjanje duplikata i filtriranje outliera.
3. **Transformacija Podataka**: Pretvaranje podataka u odgovarajući format za modelovanje. Ovo može uključivati normalizaciju, skaliranje, kodiranje kategorijskih varijabli i kreiranje novih karakteristika kroz tehnike kao što je inženjering karakteristika.
4. **Deljenje Podataka**: Deljenje skupa podataka na obučene, validacione i testne skupove kako bi se osiguralo da model može dobro generalizovati na neviđene podatke.

## Prikupljanje Podataka

Prikupljanje podataka uključuje prikupljanje podataka iz različitih izvora, koji mogu uključivati:
- **Baze Podataka**: Ekstrakcija podataka iz relacijskih baza podataka (npr. SQL baze podataka) ili NoSQL baza podataka (npr. MongoDB).
- **API-ji**: Preuzimanje podataka iz web API-ja, koji mogu pružiti podatke u realnom vremenu ili istorijske podatke.
- **Datoteke**: Čitanje podataka iz datoteka u formatima kao što su CSV, JSON ili XML.
- **Web Scraping**: Prikupljanje podataka sa web sajtova korišćenjem tehnika web scraping-a.

U zavisnosti od cilja projekta mašinskog učenja, podaci će biti ekstraktovani i prikupljeni iz relevantnih izvora kako bi se osiguralo da su reprezentativni za domen problema.

## Čišćenje Podataka

Čišćenje podataka je proces identifikacije i ispravljanja grešaka ili nedoslednosti u skupu podataka. Ovaj korak je suštinski za osiguranje kvaliteta podataka koji se koriste za obuku modela mašinskog učenja. Ključni zadaci u čišćenju podataka uključuju:
- **Rukovanje Nedostajućim Vrednostima**: Identifikacija i rešavanje nedostajućih tačaka podataka. Uobičajene strategije uključuju:
- Uklanjanje redova ili kolona sa nedostajućim vrednostima.
- Imputacija nedostajućih vrednosti korišćenjem tehnika kao što su imputacija srednje, medijane ili moda.
- Korišćenje naprednih metoda kao što su imputacija K-najbližih suseda (KNN) ili imputacija regresijom.
- **Uklanjanje Duplikata**: Identifikacija i uklanjanje duplih zapisa kako bi se osiguralo da je svaka tačka podataka jedinstvena.
- **Filtriranje Outliera**: Otkrivanje i uklanjanje outliera koji mogu iskriviti performanse modela. Tehnike kao što su Z-score, IQR (Interkvartilni Opseg) ili vizualizacije (npr. box plotovi) mogu se koristiti za identifikaciju outliera.

### Primer čišćenja podataka
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
## Transformacija podataka

Transformacija podataka uključuje konvertovanje podataka u format pogodan za modelovanje. Ovaj korak može uključivati:
- **Normalizacija i standardizacija**: Skaliranje numeričkih karakteristika na zajednički opseg, obično [0, 1] ili [-1, 1]. Ovo pomaže u poboljšanju konvergencije optimizacionih algoritama.
- **Min-Max skaliranje**: Ponovno skaliranje karakteristika na fiksni opseg, obično [0, 1]. Ovo se radi koristeći formulu: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-score normalizacija**: Standardizovanje karakteristika oduzimanjem proseka i deljenjem sa standardnom devijacijom, što rezultira distribucijom sa prosekom 0 i standardnom devijacijom 1. Ovo se radi koristeći formulu: `X' = (X - μ) / σ`, gde je μ prosek, a σ standardna devijacija.
- **Skewness i kurtosis**: Prilagođavanje distribucije karakteristika kako bi se smanjila asimetrija (skewness) i kurtosis (izbočenost). Ovo se može uraditi koristeći transformacije poput logaritamskih, kvadratnih korena ili Box-Cox transformacija. Na primer, ako karakteristika ima asimetričnu distribuciju, primena logaritamske transformacije može pomoći u normalizaciji.
- **Normalizacija stringova**: Konvertovanje stringova u dosledan format, kao što su:
- Pretvaranje u mala slova
- Uklanjanje specijalnih karaktera (zadržavanje relevantnih)
- Uklanjanje stop reči (uobičajenih reči koje ne doprinose značenju, kao što su "the", "is", "and")
- Uklanjanje previše čestih i previše retkih reči (npr. reči koje se pojavljuju u više od 90% dokumenata ili manje od 5 puta u korpusu)
- Uklanjanje praznog prostora
- Stemming/Lemmatization: Smanjivanje reči na njihovu osnovnu ili korensku formu (npr. "running" na "run").

- **Kodiranje kategorijskih varijabli**: Konvertovanje kategorijskih varijabli u numeričke reprezentacije. Uobičajene tehnike uključuju:
- **One-Hot kodiranje**: Kreiranje binarnih kolona za svaku kategoriju.
- Na primer, ako karakteristika ima kategorije "crvena", "zelena" i "plava", biće transformisana u tri binarne kolone: `is_red`(100), `is_green`(010) i `is_blue`(001).
- **Label kodiranje**: Dodeljivanje jedinstvenog celog broja svakoj kategoriji.
- Na primer, "crvena" = 0, "zelena" = 1, "plava" = 2.
- **Ordinalno kodiranje**: Dodeljivanje celih brojeva na osnovu redosleda kategorija.
- Na primer, ako su kategorije "nisko", "srednje" i "visoko", mogu se kodirati kao 0, 1 i 2, redom.
- **Hashing kodiranje**: Korišćenje hash funkcije za konvertovanje kategorija u vektore fiksne veličine, što može biti korisno za kategorijske varijable visoke kardinalnosti.
- Na primer, ako karakteristika ima mnogo jedinstvenih kategorija, hashing može smanjiti dimenzionalnost dok zadržava neke informacije o kategorijama.
- **Bag of Words (BoW)**: Predstavljanje tekstualnih podataka kao matrice broja reči ili frekvencija, gde svaki red odgovara dokumentu, a svaka kolona odgovara jedinstvenoj reči u korpusu.
- Na primer, ako korpus sadrži reči "mačka", "pas" i "riba", dokument koji sadrži "mačka" i "pas" biće predstavljen kao [1, 1, 0]. Ova specifična reprezentacija se naziva "unigram" i ne hvata redosled reči, tako da gubi semantičke informacije.
- **Bigram/Trigram**: Proširivanje BoW za hvatanje sekvenci reči (bigrami ili trigrami) kako bi se zadržao neki kontekst. Na primer, "mačka i pas" biće predstavljeno kao bigram [1, 1] za "mačka i" i [1, 1] za "i pas". U ovim slučajevima se prikuplja više semantičkih informacija (povećavajući dimenzionalnost reprezentacije) ali samo za 2 ili 3 reči u isto vreme.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Statistička mera koja procenjuje važnost reči u dokumentu u odnosu na kolekciju dokumenata (korpus). Kombinuje frekvenciju termina (koliko često se reč pojavljuje u dokumentu) i inverznu frekvenciju dokumenata (koliko je reč retka u svim dokumentima).
- Na primer, ako se reč "mačka" često pojavljuje u dokumentu, ali je retka u celom korpusu, imaće visoku TF-IDF ocenu, što ukazuje na njenu važnost u tom dokumentu.

- **Inženjering karakteristika**: Kreiranje novih karakteristika iz postojećih kako bi se poboljšala prediktivna moć modela. Ovo može uključivati kombinovanje karakteristika, ekstrakciju komponenti datuma/vremena ili primenu transformacija specifičnih za domen.

## Deljenje podataka

Deljenje podataka uključuje razdvajanje skupa podataka na odvojene podskupove za obuku, validaciju i testiranje. Ovo je neophodno za procenu performansi modela na neviđenim podacima i sprečavanje prekomernog prilagođavanja. Uobičajene strategije uključuju:
- **Podela na obuku i test**: Razdvajanje skupa podataka na skup za obuku (obično 60-80% podataka), skup za validaciju (10-15% podataka) za podešavanje hiperparametara, i test skup (10-15% podataka). Model se obučava na skupu za obuku i ocenjuje na test skupu.
- Na primer, ako imate skup podataka od 1000 uzoraka, mogli biste koristiti 700 uzoraka za obuku, 150 za validaciju i 150 za testiranje.
- **Stratifikovano uzorkovanje**: Osiguravanje da distribucija klasa u skupovima za obuku i testiranje bude slična ukupnom skupu podataka. Ovo je posebno važno za neuravnotežene skupove podataka, gde neke klase mogu imati značajno manje uzoraka od drugih.
- **Podela vremenskih serija**: Za podatke vremenskih serija, skup podataka se deli na osnovu vremena, osiguravajući da skup za obuku sadrži podatke iz ranijih vremenskih perioda, a test skup sadrži podatke iz kasnijih perioda. Ovo pomaže u proceni performansi modela na budućim podacima.
- **K-Fold unakrsna validacija**: Deljenje skupa podataka na K podskupova (foldova) i obučavanje modela K puta, svaki put koristeći različit fold kao test skup i preostale foldove kao skup za obuku. Ovo pomaže da se osigura da se model ocenjuje na različitim podskupovima podataka, pružajući robusniju procenu njegovih performansi.

## Evaluacija modela

Evaluacija modela je proces procene performansi modela mašinskog učenja na neviđenim podacima. Uključuje korišćenje različitih metrika za kvantifikaciju koliko dobro model generalizuje na nove podatke. Uobičajene metrike evaluacije uključuju:

### Tačnost

Tačnost je proporcija tačno predviđenih instanci u odnosu na ukupne instance. Izračunava se kao:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Tačnost je jednostavna i intuitivna metrika, ali možda nije pogodna za neuravnotežene skupove podataka gde jedna klasa dominira drugima, jer može dati obmanjujući utisak o performansama modela. Na primer, ako 90% podataka pripada klasi A i model predviđa sve instance kao klasu A, postići će 90% tačnosti, ali neće biti koristan za predviđanje klase B.

### Preciznost

Preciznost je proporcija tačnih pozitivnih predikcija u odnosu na sve pozitivne predikcije koje je model napravio. Izračunava se kao:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Preciznost je posebno važna u scenarijima gde su lažno pozitivni rezultati skupi ili nepoželjni, kao što su medicinske dijagnoze ili otkrivanje prevara. Na primer, ako model predviđa 100 slučajeva kao pozitivne, ali je samo 80 od njih zapravo pozitivno, preciznost bi bila 0.8 (80%).

### Osetljivost (Recall)

Osetljivost, takođe poznata kao stopa pravih pozitivnih ili senzitivnost, je proporcija pravih pozitivnih predikcija u odnosu na sve stvarne pozitivne slučajeve. Izračunava se kao:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Podsećanje je ključno u scenarijima gde su lažno negativni rezultati skupi ili nepoželjni, kao što su detekcija bolesti ili filtriranje spama. Na primer, ako model identifikuje 80 od 100 stvarnih pozitivnih slučajeva, podsećanje bi bilo 0.8 (80%).

### F1 Score

F1 skor je harmonijska sredina preciznosti i podsećanja, pružajući ravnotežu između ova dva metrika. Izračunava se kao:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 skor je posebno koristan kada se radi sa neuravnoteženim skupovima podataka, jer uzima u obzir i lažne pozitivne i lažne negativne rezultate. Pruža jedinstvenu metriku koja obuhvata kompromis između preciznosti i podsećanja. Na primer, ako model ima preciznost od 0.8 i podsećanje od 0.6, F1 skor bi bio približno 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

ROC-AUC metrika procenjuje sposobnost modela da razlikuje klase tako što prikazuje stopu pravih pozitivnih (senzitivnost) u odnosu na stopu lažnih pozitivnih pri različitim podešavanjima praga. Površina ispod ROC krive (AUC) kvantifikuje performanse modela, pri čemu vrednost 1 označava savršenu klasifikaciju, a vrednost 0.5 označava nasumično pogađanje.

> [!TIP]
> ROC-AUC je posebno koristan za probleme binarne klasifikacije i pruža sveobuhvatan pregled performansi modela kroz različite pragove. Manje je osetljiv na neuravnoteženost klasa u poređenju sa tačnošću. Na primer, model sa AUC od 0.9 ukazuje na to da ima visoku sposobnost da razlikuje pozitivne i negativne instance.

### Specifičnost

Specifičnost, takođe poznata kao stopa pravih negativnih, je proporcija pravih negativnih predikcija u odnosu na sve stvarne negativne instance. Izračunava se kao:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Specifičnost je važna u scenarijima gde su lažno pozitivni rezultati skupi ili nepoželjni, kao što su medicinska testiranja ili otkrivanje prevara. Pomaže u proceni koliko dobro model identifikuje negativne instance. Na primer, ako model ispravno identifikuje 90 od 100 stvarnih negativnih instanci, specifičnost bi bila 0.9 (90%).

### Matthews koeficijent korelacije (MCC)
Matthews koeficijent korelacije (MCC) je mera kvaliteta binarnih klasifikacija. Uzimajući u obzir prave i lažne pozitivne i negativne rezultate, pruža uravnotežen pogled na performanse modela. MCC se izračunava kao:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
gde:
- **TP**: Tačni pozitivni
- **TN**: Tačni negativni
- **FP**: Lažni pozitivni
- **FN**: Lažni negativni

> [!TIP]
> MCC se kreće od -1 do 1, gde 1 označava savršenu klasifikaciju, 0 označava nasumično pogađanje, a -1 označava potpuno neslaganje između predikcije i posmatranja. Posebno je koristan za neuravnotežene skupove podataka, jer uzima u obzir svih četiri komponente matrice konfuzije.

### Srednja apsolutna greška (MAE)
Srednja apsolutna greška (MAE) je metrika regresije koja meri prosečnu apsolutnu razliku između predviđenih i stvarnih vrednosti. Izračunava se kao:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
gde:
- **n**: Broj instanci
- **y_i**: Stvarna vrednost za instancu i
- **ŷ_i**: Predviđena vrednost za instancu i

> [!TIP]
> MAE pruža jednostavno tumačenje prosečne greške u predikcijama, što olakšava razumevanje. Manje je osetljiv na ekstremne vrednosti u poređenju sa drugim metrima kao što je Srednja Kvadratna Greška (MSE). Na primer, ako model ima MAE od 5, to znači da se, u proseku, predikcije modela razlikuju od stvarnih vrednosti za 5 jedinica.

### Matrica konfuzije

Matrica konfuzije je tabela koja sumira performanse klasifikacionog modela prikazujući brojeve tačnih pozitivnih, tačnih negativnih, lažnih pozitivnih i lažnih negativnih predikcija. Pruža detaljan uvid u to koliko dobro model funkcioniše za svaku klasu.

|               | Predviđeno pozitivno | Predviđeno negativno |
|---------------|---------------------|---------------------|
| Stvarno pozitivno| Tačno pozitivno (TP)  | Lažno negativno (FN)  |
| Stvarno negativno| Lažno pozitivno (FP) | Tačno negativno (TN)   |

- **Tačno pozitivno (TP)**: Model je ispravno predvideo pozitivnu klasu.
- **Tačno negativno (TN)**: Model je ispravno predvideo negativnu klasu.
- **Lažno pozitivno (FP)**: Model je pogrešno predvideo pozitivnu klasu (Tip I greška).
- **Lažno negativno (FN)**: Model je pogrešno predvideo negativnu klasu (Tip II greška).

Matrica konfuzije se može koristiti za izračunavanje raznih metrika evaluacije, kao što su tačnost, preciznost, odziv i F1 skor.

{{#include ../banners/hacktricks-training.md}}
