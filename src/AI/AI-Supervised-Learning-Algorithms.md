# Algoritmi nadgledanog učenja

{{#include ../banners/hacktricks-training.md}}

## Osnovne informacije

Nadgledano učenje koristi označene podatke za obučavanje modela koji mogu da predviđaju nove, do tada neviđene ulazne podatke. U oblasti cybersecurity-ja, nadgledano machine learning učenje se široko primenjuje za zadatke kao što su intrusion detection (klasifikovanje mrežnog saobraćaja kao *normalnog* ili *napada*), malware detection (razlikovanje zlonamernog softvera od bezopasnog), phishing detection (identifikovanje lažnih web-sajtova ili emailova) i filtriranje spam-a, između ostalog.<sup>[[1]](#references)</sup> Svaki algoritam ima svoje prednosti i pogodan je za različite vrste problema (classification ili regression). U nastavku razmatramo ključne algoritme nadgledanog učenja, objašnjavamo kako funkcionišu i prikazujemo njihovu upotrebu na stvarnim cybersecurity datasetima. Takođe razmatramo kako kombinovanje modela (ensemble learning) često može poboljšati prediktivne performanse.

## Algoritmi

-   **Linear Regression:** Osnovni regression algoritam za predviđanje numeričkih ishoda podešavanjem linearne jednačine prema podacima.

-   **Logistic Regression:** Classification algoritam (uprkos svom nazivu) koji koristi logističku funkciju za modelovanje verovatnoće binarnog ishoda.

-   **Decision Trees:** Modeli u obliku stabla koji dele podatke prema karakteristikama radi predviđanja; često se koriste zbog lake interpretacije.

-   **Random Forests:** Ensemble decision trees modela (pomoću bagging-a) koji poboljšava preciznost i smanjuje overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers koji pronalaze optimalnu razdvajajuću hiperravan; mogu koristiti kernels za nelinearne podatke.

-   **Naive Bayes:** Probabilistički classifier zasnovan na Bayes-ovoj teoremi, uz pretpostavku nezavisnosti karakteristika, poznat po upotrebi u filtriranju spam-a.

-   **k-Nearest Neighbors (k-NN):** Jednostavan "instance-based" classifier koji uzorku dodeljuje oznaku na osnovu većinske klase njegovih najbližih suseda.

-   **Gradient Boosting Machines:** Ensemble modeli (npr. XGBoost, LightGBM) koji izgrađuju snažan prediktor sekvencijalnim dodavanjem slabijih learner-a (obično decision trees).

Svaki odeljак u nastavku pruža poboljšan opis algoritma i **Python primer koda** koji koristi biblioteke kao što su `pandas` i `scikit-learn` (i `PyTorch` u primeru neuronske mreže). Primeri koriste javno dostupne cybersecurity datasete (kao što su NSL-KDD za intrusion detection i Phishing Websites dataset) i prate doslednu strukturu:

1.  **Učitavanje dataseta** (preuzimanje putem URL-a ako je dostupan).

2.  **Preprocesiranje podataka** (npr. kodiranje kategoričkih karakteristika, skaliranje vrednosti, podela na train/test skupove).

3.  **Obučavanje modela** na podacima za obučavanje.

4.  **Evaluacija** na test skupu pomoću metrika: accuracy, precision, recall, F1-score i ROC AUC za classification (i mean squared error za regression).

Hajde da detaljno razmotrimo svaki algoritam:

### Linear Regression

Linear regression je **regression** algoritam koji se koristi za predviđanje neprekidnih numeričkih vrednosti. Pretpostavlja linearnu vezu između ulaznih karakteristika (nezavisnih promenljivih) i izlaza (zavisne promenljive). Model pokušava da podesi pravu liniju (ili hiperravan u višim dimenzijama) koja na najbolji način opisuje odnos između karakteristika i cilja. To se obično radi minimizovanjem zbira kvadrata grešaka između predviđenih i stvarnih vrednosti (metoda Ordinary Least Squares).<sup>[[2]](#references)</sup>

Najjednostavniji način predstavljanja linear regression-a jeste pomoću prave:
```plaintext
y = mx + b
```
Gde:

- `y` je predviđena vrednost (izlaz)
- `m` je nagib prave (koeficijent)
- `x` je ulazna karakteristika
- `b` je y-presek

Cilj linearne regresije je pronalaženje prave koja se najbolje uklapa i minimizuje razliku između predviđenih i stvarnih vrednosti u skupu podataka. Naravno, ovo je veoma jednostavno: bila bi to prava koja razdvaja 2 kategorije, ali ako se dodaju još dimenzije, prava postaje složenija:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Slučajevi upotrebe u cybersecurity-u:* Sama linearna regresija se ređe koristi za osnovne sigurnosne zadatke (koji su često klasifikacioni), ali se može primeniti za predviđanje numeričkih ishoda. Na primer, linearna regresija može da se koristi za **predviđanje obima mrežnog saobraćaja** ili **procenu broja napada u određenom vremenskom periodu** na osnovu istorijskih podataka. Takođe može predvideti ocenu rizika ili očekivano vreme do detekcije napada na osnovu određenih sistemskih metrika. U praksi se klasifikacioni algoritmi (kao što su logistička regresija ili stabla) češće koriste za otkrivanje upada ili malware-a, ali linearna regresija predstavlja osnovu i korisna je za analize usmerene na regresiju.

#### **Ključne karakteristike linearne regresije:**

-   **Tip problema:** Regresija (predviđanje kontinuiranih vrednosti). Nije pogodna za direktnu klasifikaciju osim ako se na izlaz ne primeni prag.

-   **Interpretabilnost:** Visoka -- koeficijenti su jednostavni za tumačenje i prikazuju linearni uticaj svake karakteristike.

-   **Prednosti:** Jednostavna je i brza; predstavlja dobru osnovu za zadatke regresije; dobro funkcioniše kada je stvarna veza približno linearna.

-   **Ograničenja:** Ne može da obuhvati složene ili nelinearne veze (bez ručnog inženjeringa karakteristika); sklona je underfitting-u ako su veze nelinearne; osetljiva je na outlier-e, koji mogu da iskrive rezultate.

-   **Pronalaženje najboljeg uklapanja:** Za pronalaženje linije najboljeg uklapanja koja razdvaja moguće kategorije koristimo metodu pod nazivom **Ordinary Least Squares (OLS)**. Ova metoda minimizuje zbir kvadriranih razlika između posmatranih vrednosti i vrednosti koje predviđa linearni model.

<details>
<summary>Primer -- Predviđanje trajanja konekcije (regresija) u skupu podataka za detekciju upada
</summary>
U nastavku prikazujemo linearnu regresiju koristeći cybersecurity skup podataka NSL-KDD. Tretiraćemo ovo kao regresioni problem tako što ćemo predviđati `duration` mrežnih konekcija na osnovu drugih karakteristika. (U stvarnosti, `duration` je jedna od karakteristika skupa NSL-KDD; ovde ga koristimo samo za ilustraciju regresije.) Učitavamo skup podataka, vršimo njegovu prethodnu obradu (kodiramo kategorijalne karakteristike), obučavamo model linearne regresije i procenjujemo Mean Squared Error (MSE) i R² rezultat na testnom skupu.
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
U ovom primeru, model linearne regresije pokušava da predvidi `duration` konekcije na osnovu drugih mrežnih karakteristika. Performanse merimo pomoću srednje kvadratne greške (MSE) i R². R² blizu 1,0 ukazivao bi na to da model objašnjava većinu varijanse u `duration`, dok nizak ili negativan R² ukazuje na loše uklapanje. (Nemojte se iznenaditi ako je R² ovde nizak -- predviđanje `duration` može biti teško na osnovu datih karakteristika, a linearna regresija možda ne može da obuhvati obrasce ako su složeni.)
</details>

### Logistic Regression

Logistic regression je algoritam za **klasifikaciju** koji modeluje verovatnoću da instanca pripada određenoj klasi (obično „pozitivnoj“ klasi). Uprkos svom nazivu, *logistic* regression se koristi za diskretne ishode (za razliku od linearne regresije, koja se koristi za kontinuirane ishode). Posebno se koristi za **binarnu klasifikaciju** (dve klase, npr. zlonamerno naspram benignog), ali se može proširiti i na probleme sa više klasa (korišćenjem pristupa softmax ili one-vs-rest).<sup>[[3]](#references)</sup>

Logistic regression koristi logističku funkciju (poznatu i kao sigmoidna funkcija) za mapiranje predviđenih vrednosti u verovatnoće. Imajte na umu da je sigmoidna funkcija funkcija čije su vrednosti između 0 i 1 i koja raste u obliku slova S, u skladu sa potrebama klasifikacije, što je korisno za zadatke binarne klasifikacije. Zato se svaka karakteristika svakog ulaza množi dodeljenom težinom, a rezultat se prosleđuje kroz sigmoidnu funkciju kako bi se dobila verovatnoća:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gde:

- `p(y=1|x)` je verovatnoća da je izlaz `y` jednak 1 za dati ulaz `x`
- `e` je osnova prirodnog logaritma
- `z` je linearna kombinacija ulaznih karakteristika, obično predstavljena kao `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Obratite pažnju da je i u svom najjednostavnijem obliku to prava linija, ali u složenijim slučajevima postaje hiperravan sa više dimenzija (po jedna za svaku karakteristiku).

> [!TIP]
> *Primene u cybersecurity-ju:* Pošto su mnogi security problemi u suštini odluke tipa da/ne, Logistic Regression se široko koristi. Na primer, intrusion detection system može koristiti Logistic Regression da odluči da li je mrežna konekcija napad na osnovu karakteristika te konekcije. Kod detekcije phishing-a, Logistic Regression može kombinovati karakteristike veb-sajta (dužinu URL-a, prisustvo simbola "@", itd.) u verovatnoću da je u pitanju phishing. Korišćena je u ranim generacijama spam filtera i i dalje predstavlja snažnu osnovu za mnoge klasifikacione zadatke.

#### Logistic Regression za nebinarnu klasifikaciju

Logistic Regression je osmišljena za binarnu klasifikaciju, ali se može proširiti za rad sa problemima sa više klasa pomoću tehnika kao što su **one-vs-rest** (OvR) ili **softmax regression**. Kod OvR-a, za svaku klasu trenira se poseban Logistic Regression model, pri čemu se ta klasa tretira kao pozitivna, a sve ostale kao negativne. Klasa sa najvećom predviđenom verovatnoćom bira se kao konačno predviđanje. Softmax regression proširuje Logistic Regression na više klasa tako što primenjuje softmax funkciju na izlazni sloj, čime proizvodi raspodelu verovatnoće po svim klasama.

#### **Ključne karakteristike Logistic Regression-a:**

-   **Tip problema:** Klasifikacija (obično binarna). Predviđa verovatnoću pozitivne klase.

-   **Interpretabilnost:** Visoka -- kao i kod linearne regresije, koeficijenti karakteristika mogu pokazati kako svaka karakteristika utiče na log-odds ishoda. Ova transparentnost se često ceni u security-ju jer pomaže u razumevanju faktora koji doprinose alertu.

-   **Prednosti:** Jednostavna je i brzo se trenira; dobro funkcioniše kada je odnos između karakteristika i log-odds ishoda linearan. Daje verovatnoće, što omogućava scoring rizika. Uz odgovarajuću regularizaciju dobro se generalizuje i može bolje da se nosi sa multikolinearnošću nego obična linearna regresija.

-   **Ograničenja:** Pretpostavlja linearnu granicu odlučivanja u prostoru karakteristika (ne uspeva ako je stvarna granica složena/nelinearna). Može imati slabije rezultate na problemima kod kojih su interakcije ili nelinearni efekti ključni, osim ako ručno ne dodate polinomske karakteristike ili karakteristike interakcije. Takođe, Logistic Regression je manje efikasna ako se klase ne mogu lako razdvojiti linearnom kombinacijom karakteristika.


<details>
<summary>Primer -- Detekcija phishing veb-sajtova pomoću Logistic Regression-a:</summary>

Koristićemo **Phishing Websites Dataset** (iz UCI repozitorijuma), koji sadrži izdvojene karakteristike veb-sajtova (na primer, da li URL ima IP adresu, starost domena, prisustvo sumnjivih elemenata u HTML-u itd.) i oznaku koja pokazuje da li je sajt phishing ili legitiman.<sup>[[4]](#references)</sup> Treniraćemo Logistic Regression model za klasifikaciju veb-sajtova, a zatim ćemo proceniti njegovu tačnost, preciznost, odziv, F1-score i ROC AUC na testnom skupu.
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
U ovom primeru detekcije phishinga, logistička regresija proizvodi verovatnoću da je svaka veb-lokacija phishing. Procjenom tačnosti, preciznosti, odziva i F1 mere dobijamo uvid u performanse modela. Na primer, visok odziv bi značio da model otkriva većinu phishing lokacija (što je važno za bezbednost kako bi se smanjio broj propuštenih napada), dok visoka preciznost znači da ima malo lažnih upozorenja (što je važno kako bi se izbegao zamor analitičara). ROC AUC (površina ispod ROC krive) pruža meru performansi nezavisnu od praga (1.0 je idealno, dok 0.5 nije bolje od slučajnog pogađanja). Logistička regresija često daje dobre rezultate u ovakvim zadacima, ali ako je granica odlučivanja između phishing i legitimnih lokacija složena, mogu biti potrebni snažniji nelinearni modeli.

</details>

### Stabla odlučivanja

Stablo odlučivanja je svestran **algoritam nadgledanog učenja** koji se može koristiti i za zadatke klasifikacije i za zadatke regresije. Ono uči hijerarhijski model odluka u obliku stabla na osnovu karakteristika podataka. Svaki unutrašnji čvor stabla predstavlja test određene karakteristike, svaka grana predstavlja rezultat tog testa, a svaki list predstavlja predviđenu klasu (kod klasifikacije) ili vrednost (kod regresije).<sup>[[5]](#references)</sup>

Za izgradnju stabla, algoritmi kao što je CART (Classification and Regression Tree) koriste mere poput **Gini nečistoće** ili **informacionog dobitka (entropije)** kako bi u svakom koraku izabrali najbolju karakteristiku i prag za podelu podataka. Cilj svake podele je particionisanje podataka radi povećanja homogenosti ciljne promenljive u dobijenim podskupovima (kod klasifikacije, cilj je da svaki čvor bude što čistiji i da pretežno sadrži jednu klasu).

Stabla odlučivanja su **veoma lako interpretabilna** -- moguće je pratiti put od korena do lista kako bi se razumela logika koja stoji iza predviđanja (npr. *"AKO je `service = telnet` I `src_bytes > 1000` I `failed_logins > 3` ONDA klasifikuj kao napad"*). Ovo je dragoceno u sajber-bezbednosti za objašnjenje razloga zbog kog je određeno upozorenje pokrenuto. Stabla mogu prirodno da obrađuju i numeričke i kategoričke podatke i zahtevaju malo prethodne obrade (npr. skaliranje karakteristika nije potrebno).

Međutim, jedno stablo odlučivanja lako može previše da prilagodi model podacima za obuku, naročito ako je duboko izgrađeno (sa mnogo podela). Tehnike poput orezivanja (ograničavanje dubine stabla ili zahtev da list sadrži minimalan broj uzoraka) često se koriste za sprečavanje preprilagođavanja.

Postoje 3 glavne komponente stabla odlučivanja:
- **Koren čvor**: Najviši čvor stabla, koji predstavlja čitav skup podataka.
- **Unutrašnji čvorovi**: Čvorovi koji predstavljaju karakteristike i odluke zasnovane na tim karakteristikama.
- **Listovi**: Čvorovi koji predstavljaju konačni ishod ili predviđanje.

Stablo bi na kraju moglo da izgleda ovako:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Primene u cybersecurity-u:* Stabla odlučivanja korišćena su u sistemima za detekciju upada za izvođenje **pravila** za identifikaciju napada. Na primer, rani IDS sistemi zasnovani na ID3/C4.5 algoritmima generisali su čoveku čitljiva pravila za razlikovanje normalnog od zlonamernog saobraćaja. Takođe se koriste u analizi malware-a za odlučivanje da li je datoteka zlonamerna na osnovu svojih atributa (veličine datoteke, entropije sekcija, API poziva itd.). Jasnoća stabala odlučivanja čini ih korisnim kada je potrebna transparentnost -- analitičar može da pregleda stablo kako bi proverio logiku detekcije.

#### **Ključne karakteristike stabala odlučivanja:**

-   **Tip problema:** I klasifikacija i regresija. Često se koriste za klasifikaciju napada u odnosu na normalan saobraćaj itd.

-   **Interpretabilnost:** Veoma visoka -- odluke modela mogu se vizuelizovati i razumeti kao skup if-then pravila. Ovo je velika prednost u security-ju zbog poverenja i verifikacije ponašanja modela.

-   **Prednosti:** Mogu da obuhvate nelinearne odnose i interakcije između karakteristika (svaki split može se posmatrati kao interakcija). Nema potrebe za skaliranjem karakteristika ili one-hot kodiranjem kategorijskih promenljivih -- stabla njima upravljaju nativno. Brzo izvršavanje predikcija (predikcija se svodi na praćenje putanje kroz stablo).

-   **Ograničenja:** Sklona su overfitting-u ako se ne kontrolišu (duboko stablo može memorisati training set). Mogu biti nestabilna -- male promene u podacima mogu dovesti do drugačije strukture stabla. Kao pojedinačni modeli, njihova tačnost možda neće biti jednaka tačnosti naprednijih metoda (ensembles poput Random Forests-a obično daju bolje rezultate smanjenjem varijanse).

-   **Pronalaženje najboljeg split-a:**
- **Gini impurity**: Meri nečistoću čvora. Niža Gini impurity vrednost ukazuje na bolji split. Formula je:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Gde je `p_i` udeo instanci u klasi `i`.

- **Entropy**: Meri neizvesnost u dataset-u. Niža entropy vrednost ukazuje na bolji split. Formula je:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Gde je `p_i` udeo instanci u klasi `i`.

- **Information Gain**: Smanjenje entropy ili Gini impurity vrednosti nakon split-a. Što je information gain veći, split je bolji. Izračunava se na sledeći način:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Pored toga, stablo se završava kada:
- Sve instance u čvoru pripadaju istoj klasi. Ovo može dovesti do overfitting-a.
- Dostignuta je maksimalna dubina stabla (hardcoded). Ovo je način da se spreči overfitting.
- Broj instanci u čvoru je ispod određenog praga. Ovo je takođe način da se spreči overfitting.
- Information gain od daljih split-ova je ispod određenog praga. Ovo je takođe način da se spreči overfitting.

<details>
<summary>Primer -- stablo odlučivanja za detekciju upada:</summary>
Treniraćemo stablo odlučivanja na NSL-KDD dataset-u kako bismo klasifikovali mrežne konekcije kao *normalne* ili *napad*. NSL-KDD je poboljšana verzija klasičnog KDD Cup 1999 dataset-a, sa karakteristikama kao što su tip protokola, servis, trajanje, broj neuspešnih prijavljivanja itd., kao i labelom koja označava tip napada ili vrednost "normal". Mapiraćemo sve tipove napada u klasu "anomaly" (binarna klasifikacija: normalno u odnosu na anomaliju). Nakon training-a, procenićemo performanse stabla na test set-u.
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
U ovom primeru stabla odlučivanja, ograničili smo dubinu stabla na 10 kako bismo izbegli ekstremni overfitting (parametar `max_depth=10`). Metričke vrednosti pokazuju koliko dobro stablo razlikuje normalan saobraćaj od napada. Visok recall znači da hvata većinu napada (što je važno za IDS), dok visok precision znači mali broj lažnih alarma. Stabla odlučivanja često postižu solidnu tačnost na strukturiranim podacima, ali jedno stablo možda neće dostići najbolje moguće performanse. Ipak, *interpretabilnost* modela predstavlja veliku prednost -- mogli bismo da ispitamo podele u stablu i vidimo, na primer, koje su karakteristike (npr. `service`, `src_bytes` itd.) najuticajnije pri označavanju konekcije kao zlonamerne.

</details>

### Random Forests

Random Forest je metoda **ensemble learning-a** koja se nadovezuje na stabla odlučivanja kako bi poboljšala performanse. Random forest obučava više stabala odlučivanja (otuda „forest“) i kombinuje njihove rezultate da bi doneo konačnu predikciju (kod klasifikacije, najčešće glasanjem većine). Dve glavne ideje u random forest-u su **bagging** (bootstrap aggregating) i **feature randomness**:

-   **Bagging:** Svako stablo se obučava na nasumičnom bootstrap uzorku podataka za obuku (uzorkovanom sa ponavljanjem). Ovo uvodi raznovrsnost među stablima.

-   **Feature Randomness:** Pri svakoj podeli u stablu, za podelu se razmatra nasumični podskup karakteristika (umesto svih karakteristika). Ovo dodatno smanjuje korelaciju među stablima.

Usrednjavanjem rezultata velikog broja stabala, random forest smanjuje varijansu koju jedno stablo odlučivanja može imati. Jednostavno rečeno, pojedinačna stabla mogu overfit-ovati ili biti bučna, ali veliki broj raznovrsnih stabala koja glasaju zajedno ublažava te greške. Rezultat je često model sa **većom tačnošću** i boljom mogućnošću generalizacije nego kod jednog stabla odlučivanja. Pored toga, random forests mogu da pruže procenu važnosti karakteristika (posmatranjem koliko svaka podela prema karakteristici u proseku smanjuje nečistoću).

Random forests su postali **workhorse u cybersecurity-ju** za zadatke kao što su intrusion detection, klasifikacija malware-a i detekcija spam-a. Često dobro rade odmah, uz minimalno podešavanje, i mogu da obrade veliki broj karakteristika. Na primer, u intrusion detection-u, random forest može da nadmaši pojedinačno stablo odlučivanja tako što otkriva suptilnije obrasce napada uz manji broj false positive rezultata. Istraživanja su pokazala da random forests daju dobre rezultate u poređenju sa drugim algoritmima pri klasifikaciji napada u skupovima podataka kao što su NSL-KDD i UNSW-NB15.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** Pre svega klasifikacija (koristi se i za regresiju). Veoma je pogodan za visokodimenzione strukturirane podatke koji su uobičajeni u security logovima.

-   **Interpretability:** Niža nego kod jednog stabla odlučivanja -- nije lako vizualizovati ili objasniti stotine stabala odjednom. Ipak, rezultati važnosti karakteristika pružaju određeni uvid u to koji atributi imaju najveći uticaj.

-   **Advantages:** Uopšteno veća tačnost nego kod modela sa jednim stablom, zahvaljujući ensemble efektu. Otporan je na overfitting -- čak i ako pojedinačna stabla overfit-uju, ensemble se bolje generalizuje. Obrađuje numeričke i kategorijalne karakteristike i u određenoj meri može da upravlja podacima koji nedostaju. Takođe je relativno otporan na outlier-e.

-   **Limitations:** Veličina modela može biti velika (mnogo stabala, od kojih svako može biti duboko). Predikcije su sporije nego kod jednog stabla (jer se rezultati moraju objediniti preko velikog broja stabala). Teže je interpretirati ga -- iako su poznate važne karakteristike, tačna logika nije lako sledljiva kao kod jednostavnog pravila. Ako je skup podataka ekstremno visokodimenzionalan i redak, obučavanje veoma velikog forest-a može biti računarski zahtevno.

-   **Training Process:**
1. **Bootstrap Sampling**: Nasumično uzorkujte podatke za obuku sa ponavljanjem kako biste kreirali više podskupova (bootstrap uzoraka).
2. **Tree Construction**: Za svaki bootstrap uzorak izgradite stablo odlučivanja koristeći nasumični podskup karakteristika pri svakoj podeli. Ovo uvodi raznovrsnost među stablima.
3. **Aggregation**: Kod zadataka klasifikacije, konačna predikcija se dobija glasanjem većine među predikcijama svih stabala. Kod zadataka regresije, konačna predikcija predstavlja prosek predikcija svih stabala.

<details>
<summary>Primer -- Random Forest za Intrusion Detection (NSL-KDD):</summary>
Koristićemo isti NSL-KDD skup podataka (binarno označen kao normalan ili anomalija) i obučićemo Random Forest klasifikator. Očekujemo da će random forest raditi jednako dobro ili bolje od pojedinačnog stabla odlučivanja, zahvaljujući usrednjavanju u okviru ensemble-a koje smanjuje varijansu. Procenićemo ga pomoću istih metrika.
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
Random forest obično postiže dobre rezultate na ovom zadatku detekcije upada. Možemo primetiti poboljšanje metrika kao što su F1 ili AUC u poređenju sa jednim stablom odlučivanja, naročito u odzivu ili preciznosti, u zavisnosti od podataka. Ovo je u skladu sa shvatanjem da je *"Random Forest (RF) klasifikator ansambla i postiže dobre rezultate u poređenju sa drugim tradicionalnim klasifikatorima za efikasnu klasifikaciju napada."*.<sup>[[6]](#references)</sup> U kontekstu bezbednosnih operacija, model random forest može pouzdanije označavati napade i istovremeno smanjiti broj lažnih alarma, zahvaljujući usrednjavanju velikog broja pravila odlučivanja. Važnost funkcija iz forest modela može nam pokazati koje mrežne funkcije najviše ukazuju na napade (npr. određene mrežne usluge ili neuobičajeni brojevi paketa).

</details>

### Support Vector Machines (SVM)

Support Vector Machines su moćni modeli supervised learning-a koji se prvenstveno koriste za klasifikaciju (kao i za regresiju u obliku SVR-a). SVM pokušava da pronađe **optimalnu razdvajajuću hiperravan** koja maksimizuje marginu između dve klase. Samo podskup tačaka za obuku ("support vectors" najbliži granici) određuje položaj ove hiperravni. Maksimizovanjem margine (rastojanja između support vectors i hiperravni), SVM-ovi obično postižu dobru generalizaciju.<sup>[[8]](#references)</sup>

Ključ snage SVM-a jeste mogućnost korišćenja **kernel functions** za obradu nelinearnih odnosa. Podaci se implicitno mogu transformisati u prostor karakteristika veće dimenzionalnosti, u kojem može postojati linearni razdvajač. Uobičajeni kernel-i uključuju polynomial, radial basis function (RBF) i sigmoid. Na primer, ako klase mrežnog saobraćaja nisu linearno razdvojive u izvornom prostoru karakteristika, RBF kernel može da ih preslika u višu dimenziju, u kojoj SVM pronalazi linearnu podelu (što odgovara nelinearnoj granici u izvornom prostoru). Fleksibilnost izbora kernel-a omogućava SVM-ovima da rešavaju različite probleme.

Poznato je da SVM-ovi dobro rade u situacijama sa visokodimenzionalnim prostorima karakteristika (kao što su tekstualni podaci ili opcode sekvence malware-a), kao i u slučajevima kada je broj karakteristika veliki u odnosu na broj uzoraka. Bili su popularni u mnogim ranim cybersecurity primenama, kao što su klasifikacija malware-a i detekcija anomalija zasnovana na anomalijama u 2000-im godinama, često uz visoku preciznost.

Međutim, SVM-ovi se ne skaliraju lako na veoma velike skupove podataka (složenost obuke je superlinearna u odnosu na broj uzoraka, a korišćenje memorije može biti veliko jer je možda potrebno čuvati veliki broj support vectors). U praksi, za zadatke kao što je detekcija upada u mrežu sa milionima zapisa, SVM može biti prespor bez pažljivog poduzorkovanja ili korišćenja approximate metoda.

#### **Ključne karakteristike SVM-a:**

-   **Tip problema:** Klasifikacija (binarna ili multiclass putem one-vs-one/one-vs-rest) i varijante za regresiju. Često se koristi za binarnu klasifikaciju sa jasnim razdvajanjem margina.

-   **Interpretabilnost:** Srednja -- SVM-ovi nisu toliko interpretabilni kao stabla odlučivanja ili logistic regression. Iako možete identifikovati koje su tačke podataka support vectors i steći određeni uvid u to koje karakteristike mogu biti uticajne (putem težina u slučaju linear kernel-a), u praksi se SVM-ovi (naročito sa nelinearnim kernel-ima) tretiraju kao black-box klasifikatori.

-   **Prednosti:** Efikasni u visokodimenzionalnim prostorima; mogu modelovati složene granice odlučivanja pomoću kernel trick-a; otporni na overfitting ako je margina maksimizovana (naročito uz odgovarajući regularization parametar C); dobro rade čak i kada klase nisu razdvojene velikim rastojanjem (pronalaze najbolju kompromisnu granicu).

-   **Ograničenja:** **Računski zahtevni** za velike skupove podataka (i obuka i predikcija se loše skaliraju sa rastom podataka). Zahtevaju pažljivo podešavanje kernel-a i regularization parametara (C, tip kernel-a, gamma za RBF itd.). Ne pružaju direktno probabilističke izlaze (iako se Platt scaling može koristiti za dobijanje verovatnoća). Takođe, SVM-ovi mogu biti osetljivi na izbor kernel parametara --- loš izbor može dovesti do underfit-a ili overfit-a.

*Primene u cybersecurity-u:* SVM-ovi su korišćeni za **detekciju malware-a** (npr. klasifikovanje fajlova na osnovu izdvojenih karakteristika ili opcode sekvenci), **detekciju mrežnih anomalija** (klasifikovanje saobraćaja kao normalnog ili zlonamernog) i **detekciju phishing-a** (korišćenjem karakteristika URL-ova). Na primer, SVM može uzeti karakteristike email-a (broj pojavljivanja određenih ključnih reči, ocene reputacije pošiljaoca itd.) i klasifikovati ga kao phishing ili legitimnog. Takođe su primenjivani na **detekciju upada** nad skupovima karakteristika kao što je KDD, često postižući visoku preciznost uz cenu veće računske zahtevnosti.

<details>
<summary>Primer -- SVM za klasifikaciju malware-a:</summary>
Ponovo ćemo koristiti skup podataka o phishing website-ovima, ovog puta sa SVM-om. Pošto SVM-ovi mogu biti spori, po potrebi ćemo koristiti podskup podataka za obuku (skup podataka ima oko 11 hiljada instanci, što SVM može razumno da obradi). Koristićemo RBF kernel, koji je uobičajen izbor za nelinearne podatke, i omogućićemo procene verovatnoće za izračunavanje ROC AUC-a.
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
SVM model će izneti metrike koje možemo uporediti sa logističkom regresijom na istom zadatku. Možemo utvrditi da SVM postiže visoku tačnost i AUC ako su podaci dobro razdvojeni karakteristikama. S druge strane, ako skup podataka sadrži mnogo šuma ili klase koje se preklapaju, SVM možda neće značajno nadmašiti logističku regresiju. U praksi, SVM može doneti poboljšanje kada postoje složene, nelinearne veze između karakteristika i klase -- RBF kernel može da obuhvati zakrivljene granice odlučivanja koje bi logistička regresija propustila. Kao i kod svih modela, potrebno je pažljivo podesiti parametar `C` (regularizacija) i parametre kernela (kao što je `gamma` za RBF) kako bi se napravila ravnoteža između pristrasnosti i varijanse.

</details>

#### Razlike između logističke regresije i SVM-a

| Aspekt | **Logistička regresija** | **Support Vector Machines** |
|---|---|---|
| **Ciljna funkcija** | Minimizuje **log-loss** (cross-entropy). | Maksimizuje **marginu**, uz minimizovanje **hinge-loss**. |
| **Granica odlučivanja** | Pronalaži **najbolje prilagođenu hiperravan** koja modeluje _P(y\|x)_. | Pronalaži **hiperravan sa maksimalnom marginom** (najveći razmak do najbližih tačaka). |
| **Izlaz** | **Probabilistički** – daje kalibrisane verovatnoće klasa putem σ(w·x + b). | **Deterministički** – vraća oznake klasa; verovatnoće zahtevaju dodatnu obradu (npr. Platt scaling). |
| **Regularizacija** | L2 (podrazumevana) ili L1, direktno uspostavlja ravnotežu između underfitting-a i overfitting-a. | Parametar C predstavlja kompromis između širine margine i pogrešnih klasifikacija; parametri kernela dodaju složenost. |
| **Kernels / Nelinearnost** | Osnovni oblik je **linearan**; nelinearnost se dodaje inženjeringom karakteristika. | Ugrađeni **kernel trick** (RBF, poly itd.) omogućava modelovanje složenih granica u visokodimenzionalnom prostoru. |
| **Skalabilnost** | Rešava konveksnu optimizaciju u **O(nd)**; dobro obrađuje veoma velike vrednosti n. | Obuka može zahtevati **O(n²–n³)** memorije/vremena bez specijalizovanih solvera; manje je pogodan za ogromne vrednosti n. |
| **Interpretabilnost** | **Visoka** – težine pokazuju uticaj karakteristika; odnos šansi je intuitivan. | **Niska** kod nelinearnih kernela; support vectors su retki, ali ih nije lako objasniti. |
| **Osetljivost na outlier-e** | Koristi glatki log-loss → manje je osetljiva. | Hinge-loss sa hard marginom može biti **osetljiv**; soft-margin (C) ublažava ovaj problem. |
| **Tipični slučajevi upotrebe** | Procena kreditnog rizika, medicinski rizik, A/B testiranje – gde su **verovatnoće i objašnjivost** važne. | Klasifikacija slika/teksta, bioinformatika – gde su važne **složene granice** i **visokodimenzionalni podaci**. |

* **Ako su vam potrebne kalibrisane verovatnoće, interpretabilnost ili rad sa ogromnim skupovima podataka — izaberite logističku regresiju.**
* **Ako vam je potreban fleksibilan model koji može da obuhvati nelinearne veze bez ručnog inženjeringa karakteristika — izaberite SVM (sa kernelima).**
* Oba modela optimizuju konveksne ciljne funkcije, pa su **globalni minimumi zagarantovani**, ali SVM kernel-i dodaju hiperparametre i računarsku cenu.

### Naive Bayes

Naive Bayes je porodica **probabilističkih klasifikatora** zasnovana na primeni Bayesove teoreme uz snažnu pretpostavku nezavisnosti između karakteristika. Uprkos ovoj „naivnoj“ pretpostavci, Naive Bayes često radi iznenađujuće dobro u određenim primenama, naročito onima koje uključuju tekstualne ili kategoričke podatke, kao što je detekcija spama.<sup>[[9]](#references)</sup>


#### Bayesova teorema

Bayesova teorema predstavlja osnovu Naive Bayes klasifikatora. Ona povezuje uslovne i marginalne verovatnoće slučajnih događaja. Formula je:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gde:
- `P(A|B)` je posteriorna verovatnoća klase `A` na osnovu obeležja `B`.
- `P(B|A)` je verovatnoća obeležja `B` za datu klasu `A`.
- `P(A)` je apriorna verovatnoća klase `A`.
- `P(B)` je apriorna verovatnoća obeležja `B`.

Na primer, ako želimo da klasifikujemo da li je tekst napisalo dete ili odrasla osoba, možemo koristiti reči u tekstu kao obeležja. Na osnovu početnih podataka, Naive Bayes klasifikator će prethodno izračunati verovatnoće da se svaka reč nalazi u svakoj potencijalnoj klasi (dete ili odrasla osoba). Kada se zada novi tekst, izračunaće verovatnoću svake potencijalne klase na osnovu reči u tekstu i izabrati klasu sa najvećom verovatnoćom.

Kao što možete videti u ovom primeru, Naive Bayes klasifikator je veoma jednostavan i brz, ali pretpostavlja da su obeležja nezavisna, što nije uvek slučaj sa podacima iz stvarnog sveta.


#### Tipovi Naive Bayes klasifikatora

Postoji nekoliko tipova Naive Bayes klasifikatora, u zavisnosti od tipa podataka i raspodele obeležja:
- **Gaussian Naive Bayes**: Pretpostavlja da obeležja prate Gausovu (normalnu) raspodelu. Pogodan je za kontinuirane podatke.
- **Multinomial Naive Bayes**: Pretpostavlja da obeležja prate multinomijalnu raspodelu. Pogodan je za diskretne podatke, kao što su brojači reči u klasifikaciji teksta.
- **Bernoulli Naive Bayes**: Pretpostavlja da su obeležja binarna (0 ili 1). Pogodan je za binarne podatke, kao što su prisustvo ili odsustvo reči u klasifikaciji teksta.
- **Categorical Naive Bayes**: Pretpostavlja da su obeležja kategoričke promenljive. Pogodan je za kategoričke podatke, kao što je klasifikovanje voća na osnovu boje i oblika.


#### **Ključne karakteristike Naive Bayes-a:**

-   **Tip problema:** Klasifikacija (binarna ili sa više klasa). Često se koristi za zadatke klasifikacije teksta u cybersecurity-u (spam, phishing itd.).

-   **Interpretabilnost:** Srednja -- nije toliko direktno interpretabilan kao decision tree, ali se mogu pregledati naučene verovatnoće (npr. koje reči se najverovatnije pojavljuju u spam ili legitimnim email porukama). Oblik modela (verovatnoće svakog obeležja za datu klasu) može se razumeti kada je to potrebno.

-   **Prednosti:** **Veoma brzo** treniranje i predviđanje, čak i na velikim skupovima podataka (linearno u odnosu na broj instanci * broj obeležja). Zahteva relativno malu količinu podataka za pouzdanu procenu verovatnoća, naročito uz pravilno smoothing podešavanje. Često je iznenađujuće precizan kao početni model, posebno kada obeležja nezavisno doprinose dokazima za određenu klasu. Dobro radi sa visokodimenzionalnim podacima (npr. hiljadama obeležja iz teksta). Nije potrebno složeno podešavanje, osim postavljanja smoothing parametra.

-   **Ograničenja:** Pretpostavka o nezavisnosti može ograničiti preciznost ako su obeležja veoma korelisana. Na primer, u mrežnim podacima, obeležja kao što su `src_bytes` i `dst_bytes` mogu biti korelisana; Naive Bayes neće obuhvatiti tu interakciju. Kako veličina podataka postaje veoma velika, izražajniji modeli (kao što su ensembles ili neural nets) mogu nadmašiti NB učenjem zavisnosti između obeležja. Takođe, ako je za identifikovanje napada potrebna određena kombinacija obeležja (a ne samo pojedinačna obeležja nezavisno), NB će imati poteškoća.

> [!TIP]
> *Upotreba u cybersecurity-u:* Klasična primena je **spam detection** -- Naive Bayes je bio osnova ranih spam filtera, koji su koristili učestalost određenih tokena (reči, fraze, IP adrese) za izračunavanje verovatnoće da je email spam. Takođe se koristi za **phishing email detection** i **URL classification**, gde prisustvo određenih ključnih reči ili karakteristika (kao što je "login.php" u URL-u ili `@` u putanji URL-a) doprinosi verovatnoći phishing-a. U analizi malware-a može se zamisliti Naive Bayes klasifikator koji koristi prisustvo određenih API poziva ili dozvola u softveru za predviđanje da li je u pitanju malware. Iako napredniji algoritmi često daju bolje rezultate, Naive Bayes ostaje dobar početni model zbog svoje brzine i jednostavnosti.

<details>
<summary>Primer -- Naive Bayes za phishing detection:</summary>
Da bismo demonstrirali Naive Bayes, koristićemo Gaussian Naive Bayes na NSL-KDD skupu podataka o upadima (sa binarnim oznakama). Gaussian NB će tretirati svako obeležje kao da prati normalnu raspodelu za svaku klasu. Ovo je približan izbor, pošto su mnoga mrežna obeležja diskretna ili imaju izrazito asimetričnu raspodelu, ali pokazuje kako bi se NB primenio na podatke sa kontinuiranim obeležjima. Takođe bismo mogli da izaberemo Bernoulli NB na skupu podataka sa binarnim obeležjima (kao što je skup aktiviranih upozorenja), ali ćemo se ovde držati NSL-KDD-a radi kontinuiteta.
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
Ovaj kod trenira Naive Bayes klasifikator za detekciju napada. Naive Bayes će izračunati vrednosti poput `P(service=http | Attack)` i `P(Service=http | Normal)` na osnovu podataka za obuku, uz pretpostavku nezavisnosti između karakteristika. Zatim će koristiti ove verovatnoće za klasifikaciju novih konekcija kao normalnih ili napadačkih, na osnovu uočenih karakteristika. Performanse NB-a na NSL-KDD možda neće biti jednako visoke kao kod naprednijih modela (pošto je pretpostavka o nezavisnosti karakteristika narušena), ali su često solidne, uz prednost izuzetne brzine. U scenarijima kao što su filtriranje e-pošte u realnom vremenu ili početna trijaža URL-ova, Naive Bayes model može brzo označiti očigledno zlonamerne slučajeve uz malu potrošnju resursa.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors je jedan od najjednostavnijih algoritama mašinskog učenja. To je **neparametarska metoda zasnovana na instancama** koja predviđanja zasniva na sličnosti sa primerima iz skupa podataka za obuku. Ideja kod klasifikacije je sledeća: da bi se klasifikovala nova tačka podataka, pronalazi se **k** najbližih tačaka u podacima za obuku (njeni „najbliži susedi“), a zatim se dodeljuje klasa koja je većinska među tim susedima. „Blizina“ se definiše metrikom rastojanja, najčešće Euklidskim rastojanjem za numeričke podatke (mogu se koristiti i druga rastojanja za različite tipove karakteristika ili probleme).<sup>[[10]](#references)</sup>

K-NN ne zahteva *eksplicitnu obuku* -- faza „obuke“ svodi se na čuvanje skupa podataka. Sav posao se obavlja tokom upita (predviđanja): algoritam mora da izračuna rastojanja od tačke upita do svih tačaka za obuku kako bi pronašao najbliže. Zbog toga je vreme predviđanja **linearno u odnosu na broj uzoraka za obuku**, što može biti skupo za velike skupove podataka. Zbog toga je k-NN najpogodniji za manje skupove podataka ili scenarije u kojima se jednostavnost može postići uz kompromis između memorije i brzine.

Uprkos jednostavnosti, k-NN može da modeluje veoma složene granice odlučivanja (pošto granica odlučivanja praktično može imati bilo koji oblik koji određuje raspodela primera). Obično daje dobre rezultate kada je granica odlučivanja veoma nepravilna i kada postoji mnogo podataka -- u suštini, omogućava da podaci „govore sami za sebe“. Međutim, u visokim dimenzijama metrike rastojanja mogu postati manje značajne (prokletstvo dimenzionalnosti), pa metoda može imati poteškoće osim ako ne postoji ogroman broj uzoraka.

*Primene u cybersecurity-u:* k-NN se primenjuje za detekciju anomalija -- na primer, sistem za detekciju upada može označiti mrežni događaj kao zlonameran ako je većina njegovih najbližih suseda (prethodnih događaja) bila zlonamerna. Ako normalni saobraćaj formira klastere, a napadi predstavljaju izdvojene vrednosti, K-NN pristup (sa k=1 ili malim k) praktično predstavlja **detekciju anomalija pomoću najbližeg suseda**. K-NN se takođe koristio za klasifikaciju malware porodica pomoću binarnih vektora karakteristika: nova datoteka može biti klasifikovana kao pripadnik određene malware porodice ako je veoma bliska (u prostoru karakteristika) poznatim instancama te porodice. U praksi, k-NN nije toliko čest kao skalabilniji algoritmi, ali je konceptualno jednostavan i ponekad se koristi kao osnovni model ili za probleme manjeg obima.

#### **Ključne karakteristike k-NN:**

-   **Tip problema:** Klasifikacija (postoje i varijante za regresiju). To je metoda *lenjog učenja* -- nema eksplicitnog uklapanja modela.

-   **Interpretabilnost:** Niska do srednja -- ne postoji globalni model niti sažeto objašnjenje, ali se rezultati mogu tumačiti posmatranjem najbližih suseda koji su uticali na odluku (npr. „ovaj mrežni tok je klasifikovan kao zlonameran zato što je sličan ovim 3 poznatim zlonamernim tokovima“). Dakle, objašnjenja mogu biti zasnovana na primerima.

-   **Prednosti:** Veoma jednostavan za implementaciju i razumevanje. Ne zahteva pretpostavke o distribuciji podataka (neparametarski). Prirodno podržava probleme sa više klasa. **Adaptivan** je u smislu da granice odlučivanja mogu biti veoma složene i oblikovane distribucijom podataka.

-   **Ograničenja:** Predviđanje može biti sporo za velike skupove podataka (mora se izračunati veliki broj rastojanja). Zahteva mnogo memorije -- čuva sve podatke za obuku. Performanse opadaju u visokodimenzionalnim prostorima karakteristika jer sve tačke teže da postanu gotovo podjednako udaljene (zbog čega koncept „najbližeg“ postaje manje smislen). Potrebno je pravilno izabrati *k* (broj suseda) -- premalo k može dovesti do šuma, dok preveliko k može uključiti nerelevantne tačke iz drugih klasa. Takođe, karakteristike treba pravilno skalirati jer su izračunavanja rastojanja osetljiva na skalu.

<details>
<summary>Primer -- k-NN za detekciju phishing-a:</summary>

Ponovo ćemo koristiti NSL-KDD (binarna klasifikacija). Pošto je k-NN računarski zahtevan, koristićemo podskup podataka za obuku kako bi demonstracija ostala praktična. Izabraćemo, recimo, 20.000 uzoraka za obuku od ukupno 125.000 i koristićemo 5 suseda (k=5). Nakon obuke (što se zapravo svodi na čuvanje podataka), izvršićemo procenu na testnom skupu. Takođe ćemo skalirati karakteristike za izračunavanje rastojanja kako nijedna pojedinačna karakteristika ne bi dominirala zbog svoje skale.
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
Model k-NN će klasifikovati konekciju posmatrajući 5 najbližih konekcija u podskupu skupa za treniranje. Ako su, na primer, 4 od tih suseda attack (anomalije), a 1 je normalan, nova konekcija će biti klasifikovana kao attack. Performanse mogu biti razumno dobre, iako često nisu toliko visoke kao kod dobro podešenog Random Forest ili SVM modela nad istim podacima. Međutim, k-NN ponekad može biti posebno efikasan kada su distribucije klasa veoma nepravilne i složene -- praktično koristeći pretragu zasnovanu na memoriji. U cybersecurity oblasti, k-NN (sa k=1 ili malim k) može se koristiti za detekciju poznatih attack obrazaca na osnovu primera ili kao komponenta složenijih sistema (npr. za clustering, a zatim klasifikovanje na osnovu pripadnosti clusteru).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines spadaju među najmoćnije algoritme za strukturirane podatke. **Gradient boosting** označava tehniku izgradnje ansambla slabih modela (često decision tree modela) sekvencijalnim redosledom, pri čemu svaki novi model ispravlja greške prethodnog ansambla. Za razliku od bagging-a (Random Forest), koji decision tree modele gradi paralelno i izračunava njihov prosek, boosting gradi decision tree modele *jedan po jedan*, pri čemu se svaki više fokusira na instance koje su prethodni modeli pogrešno predvideli.<sup>[[11]](#references)</sup>

Najpopularnije implementacije poslednjih godina su **XGBoost**, **LightGBM** i **CatBoost**, koji su redom biblioteke za gradient boosting decision tree (GBDT). Bile su izuzetno uspešne na takmičenjima iz machine learning-a i u praktičnim primenama, često **postižući vrhunske performanse na tabelarnim skupovima podataka**. U cybersecurity oblasti, istraživači i praktičari koristili su gradient boosted tree modele za zadatke kao što su **malware detection** (korišćenjem osobina izdvojenih iz datoteka ili ponašanja tokom izvršavanja) i **network intrusion detection**. Na primer, gradient boosting model može kombinovati mnoga slaba pravila (tree modele), kao što je „ako postoji mnogo SYN paketa i neuobičajen port -> verovatno scan“, u snažan kombinovani detector koji uzima u obzir mnoge suptilne obrasce.

Zašto su boosted tree modeli toliko efikasni? Svaki model u sekvenci trenira se na *preostalim greškama* (gradientima) predviđanja trenutnog ansambla. Na taj način model postepeno **„pojačava“** oblasti u kojima je slab. Korišćenje decision tree modela kao osnovnih modela omogućava konačnom modelu da obuhvati složene interakcije i nelinearne odnose. Boosting takođe u osnovi ima oblik ugrađene regularizacije: dodavanjem velikog broja malih tree modela (i korišćenjem learning rate-a za skaliranje njihovih doprinosa), često dobro generalizuje bez velikog overfitting-a, pod uslovom da su izabrani odgovarajući parametri.

#### **Ključne karakteristike Gradient Boosting-a:**

-   **Tip problema:** Prvenstveno classification i regression. U security oblasti najčešće se koristi classification (npr. binarna klasifikacija konekcije ili datoteke). Podržava binary, multi-class (uz odgovarajući loss), pa čak i ranking probleme.

-   **Interpretabilnost:** Niska do srednja. Iako je pojedinačni boosted tree mali, kompletan model može imati stotine tree modela, zbog čega ga nije moguće interpretirati kao celinu. Međutim, kao i Random Forest, može pružiti ocene važnosti osobina, a alati kao što je SHAP (SHapley Additive exPlanations) mogu se donekle koristiti za interpretaciju pojedinačnih predviđanja.

-   **Prednosti:** Često **algoritam sa najboljim performansama** za strukturirane/tabelarne podatke. Može detektovati složene obrasce i interakcije. Ima mnogo parametara za podešavanje (broj tree modela, dubina tree modela, learning rate, termini regularizacije) kojima se složenost modela može prilagoditi i sprečiti overfitting. Moderne implementacije su optimizovane za brzinu (npr. XGBoost koristi gradient informacije drugog reda i efikasne strukture podataka). Obično bolje obrađuje nebalansirane podatke kada se kombinuje sa odgovarajućim loss funkcijama ili podešavanjem težina uzoraka.

-   **Ograničenja:** Složeniji je za podešavanje od jednostavnijih modela; treniranje može biti sporo ako su tree modeli duboki ili ako je njihov broj veliki (iako je obično i dalje brže od treniranja uporedivog deep neural network modela nad istim podacima). Model može imati overfitting ako nije pravilno podešen (npr. previše dubokih tree modela sa nedovoljnom regularizacijom). Zbog velikog broja hyperparameter-a, efikasno korišćenje gradient boosting-a može zahtevati više stručnosti ili eksperimentisanja. Takođe, kao i tree-based metode, nije inherentno efikasan u radu sa veoma sparse visokodimenzionalnim podacima kao linearni modeli ili Naive Bayes (iako se i tada može primeniti, npr. u text classification-u, ali bez feature engineering-a možda neće biti prvi izbor).

> [!TIP]
> *Primene u cybersecurity oblasti:* Gotovo svuda gde bi se mogao koristiti decision tree ili random forest, gradient boosting model bi mogao postići bolju preciznost. Na primer, na takmičenjima kompanije **Microsoft za malware detection** intenzivno je korišćen XGBoost nad engineered features izdvojenim iz binary datoteka. Istraživanja u oblasti **network intrusion detection-a** često prijavljuju najbolje rezultate uz GBDT modele (npr. XGBoost nad CIC-IDS2017 ili UNSW-NB15 skupovima podataka). Ovi modeli mogu koristiti širok raspon osobina (tipove protokola, učestalost određenih događaja, statističke osobine saobraćaja i drugo) i kombinovati ih radi detekcije pretnji. U phishing detection-u, gradient boosting može kombinovati lexical features URL-ova, osobine reputacije domena i osobine sadržaja stranice kako bi postigao veoma visoku preciznost. Ansambl pristup pomaže u obuhvatanju mnogih graničnih slučajeva i suptilnosti u podacima.

<details>
<summary>Primer -- XGBoost za Phishing Detection:</summary>
Koristićemo gradient boosting classifier nad phishing skupom podataka. Da bi primer ostao jednostavan i samostalan, koristićemo `sklearn.ensemble.GradientBoostingClassifier` (sporiju, ali jednostavnu implementaciju). Uobičajeno bi se koristile biblioteke `xgboost` ili `lightgbm` radi boljih performansi i dodatnih funkcionalnosti. Model ćemo trenirati i evaluirati na sličan način kao ranije.
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
Model gradient boosting će verovatno postići veoma visoku tačnost i AUC na ovom phishing skupu podataka (ovi modeli često mogu premašiti 95% tačnosti uz odgovarajuće podešavanje na takvim podacima, kao što je pokazano u literaturi. Ovo pokazuje zašto se GBDT modeli smatraju *„modelima koji predstavljaju vrhunac razvoja za tabelarne skupove podataka“* -- često nadmašuju jednostavnije algoritme jer otkrivaju složene obrasce.<sup>[[11]](#references)</sup> U kontekstu cybersecurity-ja, to bi moglo značiti otkrivanje većeg broja phishing sajtova ili napada uz manje propuštenih slučajeva. Naravno, potrebno je biti oprezan zbog overfittinga -- obično bismo koristili tehnike kao što su cross-validation i pratili performanse na validation skupu prilikom razvoja takvog modela za deployment.

</details>

### Kombinovanje modela: Ensemble Learning i Stacking

Ensemble learning je strategija **kombinovanja više modela** radi poboljšanja ukupnih performansi. Već smo videli konkretne ensemble metode: Random Forest (ensemble stabala pomoću bagginga) i Gradient Boosting (ensemble stabala pomoću sekvencijalnog boostinga). Međutim, ensembles se mogu kreirati i na druge načine, kao što su **voting ensembles** ili **stacked generalization (stacking)**. Osnovna ideja je da različiti modeli mogu otkrivati različite obrasce ili imati različite slabosti; njihovim kombinovanjem možemo **nadoknaditi greške svakog modela prednostima drugog modela**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Kod jednostavnog voting classifier-a treniramo više raznovrsnih modela (recimo, logistic regression, decision tree i SVM) i omogućavamo im da glasaju o konačnoj predikciji (većinsko glasanje kod klasifikacije). Ako ponderišemo glasove (npr. veću težinu damo preciznijim modelima), dobijamo weighted voting šemu. Ovo obično poboljšava performanse kada su pojedinačni modeli dovoljno dobri i nezavisni -- ensemble smanjuje rizik od greške pojedinačnog modela, jer je drugi modeli mogu ispraviti. To je kao da imamo panel stručnjaka umesto samo jednog mišljenja.

-   **Stacking (Stacked Ensemble):** Stacking ide korak dalje. Umesto jednostavnog glasanja, trenira **meta-model** koji **uči kako da najbolje kombinuje predikcije** osnovnih modela. Na primer, trenirate 3 različita classifier-a (base learner-a), a zatim njihove izlaze (ili verovatnoće) prosleđujete kao features meta-classifier-u (često jednostavnom modelu kao što je logistic regression), koji uči optimalan način njihovog kombinovanja. Meta-model se trenira na validation skupu ili pomoću cross-validation-a kako bi se izbegao overfitting. Stacking često može nadmašiti jednostavno glasanje tako što uči *kojim modelima više verovati u određenim okolnostima*. U cybersecurity-ju, jedan model može biti bolji u otkrivanju network scan-ova, dok je drugi bolji u otkrivanju malware beaconing-a; stacking model može naučiti da se na odgovarajući način oslanja na svaki od njih.

Ensembles, bilo da koriste glasanje ili stacking, imaju tendenciju da **povećaju tačnost** i robusnost. Nedostatak su povećana složenost i ponekad smanjena interpretabilnost (iako neki ensemble pristupi, kao što je prosek decision tree-ova, i dalje mogu pružiti određeni uvid, npr. feature importance). U praksi, ako operativna ograničenja to dozvoljavaju, korišćenje ensemble-a može dovesti do većih stopa detekcije. Mnoga pobednička rešenja u cybersecurity izazovima (kao i na Kaggle takmičenjima uopšte) koriste ensemble tehnike kako bi izvukla poslednji deo performansi.

<details>
<summary>Primer -- Voting Ensemble za phishing detekciju:</summary>
Da bismo ilustrovali model stacking, kombinovaćemo neke od modela o kojima smo govorili na phishing skupu podataka. Koristićemo logistic regression, decision tree i k-NN kao base learner-e, a Random Forest kao meta-learner za objedinjavanje njihovih predikcija. Meta-learner će biti treniran na izlazima base learner-a (korišćenjem cross-validation-a na training skupu). Očekujemo da će stacked model imati performanse jednake ili nešto bolje od pojedinačnih modela.
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
Složeni ansambl koristi komplementarne prednosti osnovnih modela. Na primer, logistic regression može da obrađuje linearne aspekte podataka, decision tree može da obuhvati specifične interakcije nalik pravilima, a k-NN može da bude naročito uspešan u lokalnim susedstvima prostora karakteristika. Meta-model (ovde random forest) može da nauči kako da ponderiše ove ulaze. Dobijene metrike često pokazuju poboljšanje (čak i ako je malo) u odnosu na metrike bilo kog pojedinačnog modela. U našem primeru sa phishingom, ako je logistic regression sam imao F1 vrednost, recimo, 0.95, a tree 0.94, stack bi mogao da dostigne 0.96 tako što bi nadoknadio greške svakog pojedinačnog modela.

Ensemble metode poput ove pokazuju princip da *"kombinovanje više modela obično dovodi do bolje generalizacije"*.<sup>[[12]](#references)</sup> U sajber-bezbednosti, ovo se može implementirati korišćenjem više detection engine-a (jedan može biti zasnovan na pravilima, drugi na machine learning-u, a treći na detekciji anomalija), nakon čega sledi sloj koji objedinjuje njihova upozorenja -- praktično oblik ansambla -- kako bi doneo konačnu odluku sa većim stepenom pouzdanosti. Prilikom implementacije ovakvih sistema, treba uzeti u obzir dodatnu složenost i obezbediti da ansambl ne postane previše težak za upravljanje ili objašnjavanje. Međutim, sa stanovišta tačnosti, ensemble metode i stacking predstavljaju moćne alate za poboljšanje performansi modela.

</details>

Pristupi zasnovani na neural-network modelima opisani na [stranici o deep-learning-u](AI-Deep-Learning.md) mogu da dopune ove klasične modele za detekciju upada kada dataset i compute budžet opravdavaju dodatnu složenost.<sup>[[13]](#references)</sup>

## References

- [1] [AI i Machine Learning u sajber-bezbednosti - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression, objašnjena - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Klasifikacija Phishing Attack-a i Website-ova korišćenjem Machine Learning-a i više Dataset-ova (komparativna analiza)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Detekcija Denial of Services Attack-a korišćenjem Random Forest Classifier-a sa Information Gain-om"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Analiza performansi machine learning modela za intrusion detection system korišćenjem tehnike selekcije karakteristika Gini Impurity-based Weighted Random Forest (GIWRF)"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Šta je Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes filtriranje spam-a - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [Šta je k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT razjašnjen: kako rade LightGBM, XGBoost i CatBoost - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: poboljšanje performansi modela kombinovanjem prednosti - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Kako Deep Learning unapređuje Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
