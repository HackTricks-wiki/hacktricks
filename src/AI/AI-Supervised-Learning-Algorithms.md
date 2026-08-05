# Algoritmi nadgledanog učenja

{{#include ../banners/hacktricks-training.md}}

## Osnovne informacije

Nadgledano učenje koristi označene podatke za obučavanje modela koji mogu da predviđaju nove, prethodno neviđene ulazne podatke. U oblasti cybersecurity-ja, nadgledano mašinsko učenje se široko primenjuje na zadatke kao što su detekcija upada (klasifikovanje mrežnog saobraćaja kao *normalnog* ili *napada*), detekcija malware-a (razlikovanje zlonamernog softvera od benignog), detekcija phishing-a (prepoznavanje lažnih web sajtova ili emailova) i filtriranje spam-a, između ostalog. Svaki algoritam ima svoje prednosti i pogodan je za različite vrste problema (klasifikaciju ili regresiju). U nastavku razmatramo ključne algoritme nadgledanog učenja, objašnjavamo kako rade i prikazujemo njihovu upotrebu na stvarnim cybersecurity dataset-ovima. Takođe razmatramo kako kombinovanje modela (ensemble learning) često može poboljšati performanse predviđanja.

## Algoritmi

-   **Linear Regression:** Osnovni regresioni algoritam za predviđanje numeričkih rezultata fitovanjem linearne jednačine na podatke.

-   **Logistic Regression:** Algoritam za klasifikaciju (uprkos svom nazivu) koji koristi logističku funkciju za modelovanje verovatnoće binarnog ishoda.

-   **Decision Trees:** Modeli u obliku stabla koji dele podatke na osnovu feature-a radi donošenja predviđanja; često se koriste zbog svoje interpretabilnosti.

-   **Random Forests:** Ensemble decision tree modela (putem bagging-a) koji poboljšava preciznost i smanjuje overfitting.

-   **Support Vector Machines (SVM):** Klasifikatori sa maksimalnom marginom koji pronalaze optimalnu razdvajajuću hiperravan; mogu koristiti kernel-e za nelinearne podatke.

-   **Naive Bayes:** Probabilistički klasifikator zasnovan na Bayes-ovoj teoremi, uz pretpostavku nezavisnosti feature-a, poznat po upotrebi u filtriranju spam-a.

-   **k-Nearest Neighbors (k-NN):** Jednostavan "instance-based" klasifikator koji dodeljuje uzorku klasi na osnovu većinske klase njegovih najbližih suseda.

-   **Gradient Boosting Machines:** Ensemble modeli (npr. XGBoost, LightGBM) koji izgrađuju snažan prediktor sekvencijalnim dodavanjem slabijih learner-a (obično decision tree modela).

Svaki odeljka u nastavku pruža poboljšan opis algoritma i **Python code example** koristeći biblioteke kao što su `pandas` i `scikit-learn` (i `PyTorch` za primer neural network-a). Primeri koriste javno dostupne cybersecurity dataset-ove (kao što su NSL-KDD za detekciju upada i Phishing Websites dataset) i prate doslednu strukturu:

1.  **Učitajte dataset** (preuzmite ga putem URL-a ako je dostupan).

2.  **Preprocesirajte podatke** (npr. enkodirajte kategoričke feature-e, skalirajte vrednosti i podelite podatke na train/test skupove).

3.  **Obučite model** na train podacima.

4.  **Evaluirajte** model na test skupu koristeći metrike: accuracy, precision, recall, F1-score i ROC AUC za klasifikaciju (i mean squared error za regresiju).

Hajde da razmotrimo svaki algoritam:

### Linear Regression

Linear regression je **regresioni** algoritam koji se koristi za predviđanje kontinuiranih numeričkih vrednosti. Pretpostavlja linearnu vezu između ulaznih feature-a (nezavisnih promenljivih) i izlaza (zavisne promenljive). Model pokušava da fituje pravu (ili hiperravan u višim dimenzijama) koja najbolje opisuje odnos između feature-a i target-a. To se obično postiže minimizovanjem zbira kvadratnih grešaka između predviđenih i stvarnih vrednosti (metoda Ordinary Least Squares).<sup>[[8]](#references)</sup>

Najjednostavniji način predstavljanja linear regression-a jeste pomoću prave:
```plaintext
y = mx + b
```
Gde:

- `y` je predviđena vrednost (izlaz)
- `m` je nagib linije (koeficijent)
- `x` je ulazna karakteristika
- `b` je presek sa y-osom

Cilj linearne regresije je da pronađe liniju koja se najbolje uklapa i minimizuje razliku između predviđenih i stvarnih vrednosti u datasetu. Naravno, ovo je veoma jednostavno — bila bi to prava linija koja razdvaja 2 kategorije, ali ako se dodaju dodatne dimenzije, linija postaje složenija:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Primene u sajber-bezbednosti:* Sama linearna regresija se ređe koristi za osnovne bezbednosne zadatke (koji su često klasifikacioni), ali se može primeniti za predviđanje numeričkih ishoda. Na primer, linearna regresija može da se koristi za **predviđanje obima mrežnog saobraćaja** ili **procenu broja napada u određenom vremenskom periodu** na osnovu istorijskih podataka. Takođe može da predvidi skor rizika ili očekivano vreme do detekcije napada na osnovu određenih sistemskih metrika. U praksi se klasifikacioni algoritmi (kao što su logistička regresija ili stabla) češće koriste za otkrivanje upada ili malware-a, ali linearna regresija predstavlja osnovu i korisna je za analize usmerene na regresiju.

#### **Ključne karakteristike linearne regresije:**

-   **Tip problema:** Regresija (predviđanje kontinuiranih vrednosti). Nije pogodna za direktnu klasifikaciju osim ako se na izlaz ne primeni prag.

-   **Interpretabilnost:** Visoka -- koeficijenti se jednostavno tumače i prikazuju linearni uticaj svake karakteristike.

-   **Prednosti:** Jednostavna je i brza; predstavlja dobru osnovu za regresione zadatke; dobro funkcioniše kada je stvarna veza približno linearna.

-   **Ograničenja:** Ne može da obuhvati složene ili nelinearne veze (bez ručnog inženjeringa karakteristika); sklona je underfitting-u ako su veze nelinearne; osetljiva je na outlier-e koji mogu da iskrive rezultate.

-   **Pronalaženje najboljeg fita:** Da bismo pronašli liniju najboljeg fita koja razdvaja moguće kategorije, koristimo metod pod nazivom **Ordinary Least Squares (OLS)**. Ovaj metod minimizuje zbir kvadriranih razlika između posmatranih vrednosti i vrednosti koje predviđa linearni model.

<details>
<summary>Primer -- Predviđanje trajanja veze (regresija) u skupu podataka za detekciju upada
</summary>
U nastavku prikazujemo linearnu regresiju koristeći skup podataka za sajber-bezbednost NSL-KDD. Tretiraćemo ovo kao regresioni problem tako što ćemo predviđati `duration` mrežnih veza na osnovu drugih karakteristika. (U stvarnosti, `duration` je jedna od karakteristika skupa NSL-KDD; ovde je koristimo samo za ilustraciju regresije.) Učitavamo skup podataka, prethodno obrađujemo podatke (kodiramo kategoričke karakteristike), obučavamo model linearne regresije i procenjujemo Mean Squared Error (MSE) i R² skor na testnom skupu.
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
U ovom primeru, model linearne regresije pokušava da predvidi `duration` konekcije na osnovu drugih mrežnih karakteristika. Performanse merimo pomoću Mean Squared Error (MSE) i R². R² blizu 1.0 ukazivao bi na to da model objašnjava većinu varijanse u vrednosti `duration`, dok nizak ili negativan R² ukazuje na loše prilagođavanje. (Nemojte se iznenaditi ako je R² ovde nizak -- predviđanje vrednosti `duration` može biti teško na osnovu datih karakteristika, a linearna regresija možda ne može da obuhvati obrasce ako su složeni.)
</details>

### Logistička regresija

Logistička regresija je algoritam za **klasifikaciju** koji modeluje verovatnoću da instanca pripada određenoj klasi (obično „pozitivnoj“ klasi). Uprkos svom nazivu, *logistička* regresija koristi se za diskretne ishode (za razliku od linearne regresije, koja se koristi za kontinuirane ishode). Posebno se koristi za **binarnu klasifikaciju** (dve klase, npr. malicious nasuprot benign), ali se može proširiti na probleme sa više klasa (korišćenjem pristupa softmax ili one-vs-rest).<sup>[[1]](#references)</sup>

Logistička regresija koristi logističku funkciju (poznatu i kao sigmoidna funkcija) za mapiranje predviđenih vrednosti u verovatnoće. Imajte na umu da je sigmoidna funkcija funkcija čije su vrednosti između 0 i 1 i koja raste u obliku slova S, u skladu sa potrebama klasifikacije, što je korisno za zadatke binarne klasifikacije. Zato se svaka karakteristika svakog ulaza množi njoj dodeljenom težinom, a rezultat se prosleđuje kroz sigmoidnu funkciju kako bi se dobila verovatnoća:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gde:

- `p(y=1|x)` je verovatnoća da je izlaz `y` jednak 1 za dati ulaz `x`
- `e` je osnova prirodnog logaritma
- `z` je linearna kombinacija ulaznih karakteristika, obično predstavljena kao `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Imajte na umu da je i u svom najjednostavnijem obliku prava linija, dok u složenijim slučajevima postaje hiperravan sa više dimenzija (po jedna za svaku karakteristiku).

> [!TIP]
> *Primene u cybersecurity-u:* Pošto su mnogi security problemi suštinski odluke tipa da/ne, logistička regresija se široko koristi. Na primer, intrusion detection system može koristiti logističku regresiju da odluči da li je mrežna konekcija napad na osnovu karakteristika te konekcije. Kod detekcije phishing-a, logistička regresija može kombinovati karakteristike web-sajta (dužinu URL-a, prisustvo simbola "@", itd.) u verovatnoću da je u pitanju phishing. Korišćena je u ranim generacijama spam filtera i i dalje predstavlja snažnu osnovu za mnoge classification zadatke.

#### Logistička regresija za ne-binarne classification probleme

Logistička regresija je namenjena binarnoj classification, ali se može proširiti za rad sa multi-class problemima pomoću tehnika kao što su **one-vs-rest** (OvR) ili **softmax regression**. Kod OvR-a, za svaku klasu se trenira poseban model logističke regresije, pri čemu se ta klasa tretira kao pozitivna, a sve ostale kao negativne. Klasa sa najvećom predviđenom verovatnoćom bira se kao konačna predikcija. Softmax regression generalizuje logističku regresiju na više klasa primenom softmax funkcije na izlazni sloj, čime se dobija distribucija verovatnoće preko svih klasa.

#### **Ključne karakteristike logističke regresije:**

-   **Tip problema:** Classification (obično binarna). Predviđa verovatnoću pozitivne klase.

-   **Interpretabilnost:** Visoka -- kao i kod linearne regresije, koeficijenti karakteristika mogu pokazati kako svaka karakteristika utiče na log-odds ishoda. Ova transparentnost je često značajna u security-ju za razumevanje faktora koji doprinose alert-u.

-   **Prednosti:** Jednostavna je i brzo se trenira; dobro radi kada je odnos između karakteristika i log-odds ishoda linearan. Daje verovatnoće, što omogućava scoring rizika. Uz odgovarajuću regularizaciju, dobro se generalizuje i može bolje da obradi multikolinearnost od obične linearne regresije.

-   **Ograničenja:** Pretpostavlja linearnu granicu odlučivanja u prostoru karakteristika (ne uspeva ako je stvarna granica složena/nelinearna). Može imati slabije performanse na problemima kod kojih su interakcije ili nelinearni efekti ključni, osim ako ručno ne dodate polinomske karakteristike ili karakteristike interakcije. Takođe, logistička regresija je manje efikasna ako se klase ne mogu lako razdvojiti linearnom kombinacijom karakteristika.


<details>
<summary>Primer -- Detekcija phishing web-sajtova pomoću logističke regresije:</summary>

Koristićemo **Phishing Websites Dataset** (iz UCI repozitorijuma), koji sadrži izdvojene karakteristike web-sajtova (na primer, da li URL sadrži IP adresu, starost domena, prisustvo sumnjivih elemenata u HTML-u itd.) i labelu koja pokazuje da li je sajt phishing ili legitiman. Treniraćemo model logističke regresije za classification web-sajtova, a zatim ćemo na test split-u proceniti njegovu tačnost, preciznost, odziv, F1-score i ROC AUC.
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
U ovom primeru detekcije phishinga, logistička regresija proizvodi verovatnoću da je svaka veb-stranica phishing. Procjenom tačnosti, preciznosti, odziva i F1-mere dobijamo predstavu o performansama modela. Na primer, visok odziv znači da model otkriva većinu phishing stranica (što je važno za bezbednost kako bi se broj propuštenih napada sveo na minimum), dok visoka preciznost znači da ima malo lažnih alarma (što je važno kako bi se izbegao zamor analitičara). ROC AUC (površina ispod ROC krive) daje meru performansi nezavisnu od praga (1.0 je idealno, dok 0.5 nije bolje od slučajnog pogađanja). Logistička regresija često daje dobre rezultate na ovakvim zadacima, ali ako je granica odlučivanja između phishing i legitimnih veb-stranica složena, mogu biti potrebni napredniji nelinearni modeli.

</details>

### Stabla odlučivanja

Stablo odlučivanja je svestrani **algoritam nadgledanog učenja** koji se može koristiti i za klasifikacione i za regresione zadatke. Ono uči hijerarhijski model odluka u obliku stabla na osnovu obeležja podataka. Svaki unutrašnji čvor stabla predstavlja test nad određenim obeležjem, svaka grana predstavlja ishod tog testa, a svaki list predstavlja predviđenu klasu (kod klasifikacije) ili vrednost (kod regresije).<sup>[[2]](#references)</sup>

Za izgradnju stabla, algoritmi kao što je CART (Classification and Regression Tree) koriste mere poput **Ginijeve nečistoće** ili **dobitka informacija (entropije)** kako bi izabrali najbolje obeležje i prag za podelu podataka u svakom koraku. Cilj svake podele je particionisanje podataka tako da se poveća homogenost ciljne promenljive u rezultujućim podskupovima (kod klasifikacije, cilj je da svaki čvor bude što čistiji i da pretežno sadrži jednu klasu).

Stabla odlučivanja su **veoma lako interpretabilna** -- moguće je pratiti putanju od korena do lista i razumeti logiku koja stoji iza predviđanja (npr. *"AKO je `service = telnet` I `src_bytes > 1000` I `failed_logins > 3` ONDA klasifikuj kao napad"*). Ovo je dragoceno u sajber-bezbednosti jer omogućava objašnjenje razloga zbog kojeg je određeno upozorenje generisano. Stabla mogu prirodno da obrađuju i numeričke i kategorijalne podatke i zahtevaju malo prethodne obrade (npr. skaliranje obeležja nije potrebno).

Međutim, jedno stablo odlučivanja može lako da prenauči podatke za obuku, naročito ako je duboko izgrađeno (sa mnogo podela). Tehnike poput orezivanja (ograničavanje dubine stabla ili zahtevanje minimalnog broja uzoraka po listu) često se koriste za sprečavanje prenaučenosti.

Postoje 3 glavne komponente stabla odlučivanja:
- **Koren čvor**: Gornji čvor stabla, koji predstavlja ceo skup podataka.
- **Unutrašnji čvorovi**: Čvorovi koji predstavljaju obeležja i odluke zasnovane na tim obeležjima.
- **Listovi**: Čvorovi koji predstavljaju konačni ishod ili predviđanje.

Stablo bi moglo da izgleda ovako:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Slučajevi upotrebe u cybersecurity-u:* Stabla odlučivanja su korišćena u intrusion detection systems za izvođenje **pravila** za identifikovanje napada. Na primer, raniji IDS zasnovani na ID3/C4.5 algoritmima generisali su čoveku čitljiva pravila za razlikovanje normalnog od malicious saobraćaja. Takođe se koriste u analizi malware-a za odlučivanje da li je datoteka malicious na osnovu njenih atributa (veličina datoteke, entropija sekcija, API pozivi itd.). Jasnoća stabala odlučivanja čini ih korisnim kada je potrebna transparentnost -- analitičar može da pregleda stablo kako bi proverio logiku detekcije.

#### **Ključne karakteristike stabala odlučivanja:**

-   **Tip problema:** I klasifikacija i regresija. Često se koriste za klasifikaciju napada u odnosu na normalan saobraćaj itd.

-   **Interpretabilnost:** Veoma visoka -- odluke modela mogu se vizuelizovati i razumeti kao skup if-then pravila. Ovo je velika prednost u bezbednosti, zbog poverenja i provere ponašanja modela.

-   **Prednosti:** Mogu da obuhvate nelinearne odnose i interakcije između obeležja (svaki split može se posmatrati kao interakcija). Nema potrebe za skaliranjem obeležja ili one-hot kodiranjem kategoričkih promenljivih -- stabla njima upravljaju nativno. Brzo inference izvršavanje (predikcija se svodi na praćenje putanje kroz stablo).

-   **Ograničenja:** Sklona su overfitting-u ako se ne kontrolišu (duboko stablo može da zapamti training skup). Mogu biti nestabilna -- male promene u podacima mogu dovesti do drugačije strukture stabla. Kao pojedinačni modeli, njihova preciznost možda neće biti na nivou naprednijih metoda (ensemble-i kao što su Random Forests obično daju bolje rezultate smanjenjem varijanse).

-   **Pronalaženje najboljeg split-a:**
- **Gini impurity**: Meri nečistoću čvora. Niža Gini impurity ukazuje na bolji split. Formula je:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Gde je `p_i` udeo instanci u klasi `i`.

- **Entropy**: Meri neizvesnost u skupu podataka. Niža entropy ukazuje na bolji split. Formula je:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Gde je `p_i` udeo instanci u klasi `i`.

- **Information Gain**: Smanjenje entropy ili Gini impurity nakon split-a. Što je information gain veći, split je bolji. Računa se na sledeći način:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Pored toga, stablo se završava kada:
- Sve instance u čvoru pripadaju istoj klasi. To može dovesti do overfitting-a.
- Dostigne se maksimalna dubina (hardcoded) stabla. Ovo je način da se spreči overfitting.
- Broj instanci u čvoru bude ispod određenog praga. Ovo je takođe način da se spreči overfitting.
- Information gain iz daljih split-ova bude ispod određenog praga. Ovo je takođe način da se spreči overfitting.

<details>
<summary>Primer -- Stablo odlučivanja za Intrusion Detection:</summary>
Obučićemo stablo odlučivanja na NSL-KDD dataset-u kako bismo klasifikovali mrežne konekcije kao *normalne* ili *attack*. NSL-KDD je poboljšana verzija klasičnog KDD Cup 1999 dataset-a, sa obeležjima kao što su tip protokola, servis, trajanje, broj neuspešnih prijavljivanja itd., i labelom koja označava tip napada ili vrednost "normal". Mapiraćemo sve tipove napada u klasu "anomaly" (binarna klasifikacija: normalno u odnosu na anomaly). Nakon obučavanja, procenićemo performanse stabla na test skupu.
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
U ovom primeru stabla odlučivanja, ograničili smo dubinu stabla na 10 kako bismo izbegli ekstremni overfitting (parametar `max_depth=10`). Metrike pokazuju koliko dobro stablo razlikuje normalan saobraćaj od napada. Visok recall znači da detektuje većinu napada (što je važno za IDS), dok visok precision znači mali broj lažnih alarma. Stabla odlučivanja često postižu pristojnu tačnost na strukturiranim podacima, ali jedno stablo možda neće dostići najbolje moguće performanse. Ipak, *interpretabilnost* modela predstavlja veliku prednost -- mogli bismo da ispitamo podele u stablu kako bismo videli, na primer, koje su karakteristike (npr. `service`, `src_bytes` itd.) najuticajnije pri označavanju konekcije kao zlonamerne.

</details>

### Random Forests

Random Forest je metoda **ensemble learning** koja se nadovezuje na stabla odlučivanja kako bi poboljšala performanse. Random forest trenira više stabala odlučivanja (otuda „forest“) i kombinuje njihove izlaze kako bi doneo konačnu predikciju (kod klasifikacije, obično većinskim glasanjem). Dve glavne ideje u okviru random forest-a su **bagging** (bootstrap aggregating) i **feature randomness**:

-   **Bagging:** Svako stablo se trenira na nasumičnom bootstrap uzorku podataka za treniranje (uzorkovanom sa vraćanjem). Ovo uvodi raznolikost među stablima.

-   **Feature Randomness:** Pri svakoj podeli u stablu, za podelu se razmatra nasumični podskup karakteristika (umesto svih karakteristika). Ovo dodatno smanjuje korelaciju između stabala.

Usrednjavanjem rezultata velikog broja stabala, random forest smanjuje varijansu koju jedno stablo odlučivanja može imati. Jednostavno rečeno, pojedinačna stabla mogu da preprilagode model ili da budu šumovita, ali veliki broj raznovrsnih stabala koja glasaju zajedno ublažava te greške. Rezultat je često model sa **većom tačnošću** i boljom generalizacijom od pojedinačnog stabla odlučivanja. Pored toga, random forests mogu da pruže procenu važnosti karakteristika (posmatranjem koliko svaka podela na osnovu karakteristike u proseku smanjuje impurity).

Random forests su postali **workhorse u cybersecurity-ju** za zadatke kao što su detekcija upada, klasifikacija malware-a i detekcija spam-a. Često daju dobre rezultate bez dodatnog podešavanja i mogu da obrađuju velike skupove karakteristika. Na primer, u detekciji upada, random forest može nadmašiti pojedinačno stablo odlučivanja tako što detektuje suptilnije obrasce napada uz manje false positive rezultata. Istraživanja su pokazala da random forests postižu povoljne rezultate u poređenju sa drugim algoritmima pri klasifikaciji napada u skupovima podataka kao što su NSL-KDD i UNSW-NB15.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Ključne karakteristike Random Forests:**

-   **Tip problema:** Pre svega klasifikacija (koristi se i za regresiju). Veoma je pogodan za visokodimenzionalne strukturirane podatke uobičajene u security logovima.

-   **Interpretabilnost:** Niža nego kod pojedinačnog stabla odlučivanja -- nije lako vizuelizovati ili objasniti stotine stabala odjednom. Međutim, rezultati važnosti karakteristika pružaju određeni uvid u to koji atributi imaju najveći uticaj.

-   **Prednosti:** Generalno veća tačnost nego kod modela sa jednim stablom, zahvaljujući efektu ansambla. Otporan je na overfitting -- čak i kada se pojedinačna stabla preprilagode, ansambl se bolje generalizuje. Obrađuje numeričke i kategoričke karakteristike i u određenoj meri može da upravlja nedostajućim podacima. Takođe je relativno otporan na outlier-e.

-   **Ograničenja:** Veličina modela može biti velika (mnogo stabala, od kojih svako može biti duboko). Predikcije su sporije nego kod jednog stabla (pošto se rezultati moraju objediniti kroz mnoga stabla). Manje je interpretabilan -- iako znate koje su karakteristike važne, tačna logika se ne može lako pratiti kao jednostavno pravilo. Ako je skup podataka ekstremno visokodimenzionalan i redak, treniranje veoma velikog forest-a može biti računski zahtevno.

-   **Proces treniranja:**
1. **Bootstrap Sampling**: Nasumično uzorkujte podatke za treniranje sa vraćanjem kako biste kreirali više podskupova (bootstrap uzoraka).
2. **Tree Construction**: Za svaki bootstrap uzorak napravite stablo odlučivanja koristeći nasumični podskup karakteristika pri svakoj podeli. Ovo uvodi raznolikost među stablima.
3. **Aggregation**: Kod klasifikacionih zadataka, konačna predikcija se dobija većinskim glasanjem na osnovu predikcija svih stabala. Kod regresionih zadataka, konačna predikcija je prosek predikcija svih stabala.

<details>
<summary>Primer -- Random Forest za detekciju upada (NSL-KDD):</summary>
Koristićemo isti NSL-KDD skup podataka (binarno označen kao normalan ili anomalija) i trenirati Random Forest classifier. Očekujemo da će random forest postići jednake ili bolje performanse od pojedinačnog stabla odlučivanja, zahvaljujući usrednjavanju ansambla koje smanjuje varijansu. Procenićemo ga pomoću istih metrika.
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
Random forest obično postiže dobre rezultate na ovom zadatku detekcije upada. Možemo primetiti poboljšanje metrika kao što su F1 ili AUC u poređenju sa pojedinačnim decision tree modelom, naročito u pogledu recall-a ili precision-a, u zavisnosti od podataka. Ovo je u skladu sa shvatanjem da je *„Random Forest (RF) ensemble classifier i da, u poređenju sa drugim tradicionalnim classifier-ima, uspešno klasifikuje napade.“* U kontekstu bezbednosnih operacija, random forest model bi mogao pouzdanije da označi napade uz smanjenje broja lažnih alarma, zahvaljujući usrednjavanju velikog broja decision rule-ova. Feature importance iz forest-a može pokazati koje network features najviše ukazuju na napade (npr. određeni network services ili neuobičajeni broj paketa).

</details>

### Support Vector Machines (SVM)

Support Vector Machines su moćni supervised learning modeli koji se prvenstveno koriste za classification (kao i za regression u obliku SVR-a). SVM pokušava da pronađe **optimalnu separating hyperplane** koja maksimizuje marginu između dve klase. Samo podskup training points-a („support vectors“ najbliži granici) određuje položaj ove hyperplane. Maksimizovanjem margine (rastojanja između support vectors-a i hyperplane-a), SVM-ovi teže dobroj generalizaciji.<sup>[[4]](#references)</sup>

Ključ snage SVM-a jeste mogućnost korišćenja **kernel functions** za obradu nelinearnih odnosa. Podaci se implicitno mogu transformisati u feature space veće dimenzionalnosti, gde može postojati linearni separator. Uobičajeni kernels uključuju polynomial, radial basis function (RBF) i sigmoid. Na primer, ako network traffic klase nisu linearno separabilne u izvornom feature space-u, RBF kernel ih može mapirati u višu dimenziju, gde SVM pronalazi linearno razdvajanje (što odgovara nelinearnoj granici u izvornom prostoru). Fleksibilnost pri izboru kernels-a omogućava SVM-ovima rešavanje različitih problema.

Poznato je da SVM-ovi dobro rade u situacijama sa visokodimenzionalnim feature space-ovima (kao što su text data ili malware opcode sequences), kao i u slučajevima kada je broj features-a veliki u odnosu na broj samples-a. Bili su popularni u mnogim ranijim cybersecurity primenama, kao što su malware classification i anomaly-based intrusion detection tokom 2000-ih, često uz visoku tačnost.

Međutim, SVM-ovi se ne skaliraju jednostavno na veoma velike datasets (training complexity je super-linearna u odnosu na broj samples-a, a potrošnja memorije može biti velika jer će možda biti potrebno čuvati veliki broj support vectors-a). U praksi, za zadatke poput network intrusion detection-a sa milionima records-a, SVM može biti prespor bez pažljivog subsampling-a ili korišćenja approximate methods.

#### **Ključne karakteristike SVM-a:**

-   **Tip problema:** Classification (binary ili multiclass preko one-vs-one/one-vs-rest) i regression varijante. Često se koristi za binary classification sa jasno razdvojenim margins.

-   **Interpretabilnost:** Srednja -- SVM-ovi nisu toliko interpretabilni kao decision trees ili logistic regression. Iako možete identifikovati data points koji su support vectors i steći određeni uvid u to koje features mogu biti uticajne (preko weights-a u slučaju linear kernel-a), u praksi se SVM-ovi (posebno sa non-linear kernels) tretiraju kao black-box classifiers.

-   **Prednosti:** Efikasni u visokodimenzionalnim spaces-ima; mogu modelovati složene decision boundaries pomoću kernel trick-a; otporni su na overfitting ako je margin maksimalizovan (posebno uz odgovarajući regularization parameter C); dobro rade čak i kada klase nisu razdvojene velikim rastojanjem (pronalaze najbolju kompromisnu boundary).

-   **Ograničenja:** **Computationally intensive** za velike datasets (i training i prediction se loše skaliraju sa rastom podataka). Zahtevaju pažljivo podešavanje kernel i regularization parameters-a (C, kernel type, gamma za RBF itd.). Ne obezbeđuju direktno probabilistic outputs (iako se Platt scaling može koristiti za dobijanje probabilities). SVM-ovi takođe mogu biti osetljivi na izbor kernel parameters-a --- loš izbor može dovesti do underfit-a ili overfit-a.

*Primene u cybersecurity-u:* SVM-ovi su korišćeni za **malware detection** (npr. klasifikaciju files-a na osnovu izdvojenih features-a ili opcode sequences-a), **network anomaly detection** (klasifikaciju traffic-a kao normalnog ili malicious) i **phishing detection** (korišćenjem features-a URL-ova). Na primer, SVM može koristiti features e-maila (broj određenih keywords-a, sender reputation scores itd.) i klasifikovati ga kao phishing ili legitimate. Takođe su primenjivani za **intrusion detection** na feature sets-ima kao što je KDD, često uz visoku tačnost po cenu computational resources-a.

<details>
<summary>Primer -- SVM za Malware Classification:</summary>
Ponovo ćemo koristiti phishing website dataset, ovog puta sa SVM-om. Pošto SVM-ovi mogu biti spori, po potrebi ćemo koristiti podskup podataka za training (dataset ima približno 11k instances-a, što SVM može razumno da obradi). Koristićemo RBF kernel, koji je čest izbor za nelinearne podatke, i uključićemo probability estimates za izračunavanje ROC AUC-a.
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
SVM model će dati metrike koje možemo uporediti sa Logistic Regression modelom na istom zadatku. Možemo utvrditi da SVM postiže visoku tačnost i AUC ako su podaci dobro razdvojeni karakteristikama. S druge strane, ako skup podataka sadrži mnogo šuma ili klase koje se preklapaju, SVM možda neće značajno nadmašiti Logistic Regression. U praksi, SVM može pružiti poboljšanje kada postoje složene, nelinearne veze između karakteristika i klase -- RBF kernel može obuhvatiti zakrivljene granice odlučivanja koje bi Logistic Regression propustio. Kao i kod svih modela, potrebno je pažljivo podesiti `C` (regularizaciju) i parametre kernela (kao što je `gamma` za RBF) kako bi se uravnotežili bias i varijansa.

</details>

#### Razlika između Logistic Regression i SVM

| Aspekt | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Funkcija cilja** | Minimizuje **log-loss** (unakrsnu entropiju). | Maksimizuje **marginu**, uz minimizovanje **hinge-loss** funkcije. |
| **Granica odlučivanja** | Pronalazi **hiperravan najboljeg prilagođavanja** koja modeluje _P(y\|x)_. | Pronalazi **hiperravan sa maksimalnom marginom** (najveći razmak do najbližih tačaka). |
| **Izlaz** | **Probabilistički** – daje kalibrisane verovatnoće klasa putem σ(w·x + b). | **Deterministički** – vraća oznake klasa; verovatnoće zahtevaju dodatnu obradu (npr. Platt scaling). |
| **Regularizacija** | L2 (podrazumevana) ili L1, direktno uravnotežuje underfitting/overfitting. | Parametar C pravi kompromis između širine margine i pogrešnih klasifikacija; parametri kernela dodaju složenost. |
| **Kernels / Nelinearnost** | Izvorni oblik je **linearan**; nelinearnost se dodaje inženjeringom karakteristika. | Ugrađeni **kernel trick** (RBF, poly itd.) omogućava modelovanje složenih granica u visokodimenzionalnom prostoru. |
| **Skalabilnost** | Rešava konveksnu optimizaciju u **O(nd)**; dobro obrađuje veoma veliko n. | Obuka može zahtevati **O(n²–n³)** memorije/vremena bez specijalizovanih rešavača; manje je pogodan za ogromne vrednosti n. |
| **Interpretabilnost** | **Visoka** – težine pokazuju uticaj karakteristika; odnos verovatnoća je intuitivan. | **Niska** za nelinearne kernelse; support vectors su retki, ali ih nije lako objasniti. |
| **Osetljivost na outliers** | Koristi glatki log-loss → manje je osetljiv. | Hinge-loss sa hard margin može biti **osetljiv**; soft-margin (C) ublažava taj problem. |
| **Tipični slučajevi upotrebe** | Procena kreditnog rizika, medicinski rizik, A/B testiranje – gde su **verovatnoće i objašnjivost** važne. | Klasifikacija slika/teksta, bioinformatika – gde su važne **složene granice** i **viskodimenzionalni podaci**. |

* **Ako su vam potrebne kalibrisane verovatnoće, interpretabilnost ili rad sa ogromnim skupovima podataka — izaberite Logistic Regression.**
* **Ako vam je potreban fleksibilan model koji može da obuhvati nelinearne veze bez ručnog inženjeringa karakteristika — izaberite SVM (sa kernels).**
* Oba modela optimizuju konveksne ciljne funkcije, pa su **globalni minimumi zagarantovani**, ali SVM kerneli dodaju hiperparametre i računarsku cenu.

### Naive Bayes

Naive Bayes je porodica **probabilističkih klasifikatora** zasnovana na primeni Bayesove teoreme uz snažnu pretpostavku nezavisnosti između karakteristika. Uprkos ovoj „naivnoj“ pretpostavci, Naive Bayes često funkcioniše iznenađujuće dobro u određenim primenama, naročito onima koje uključuju tekstualne ili kategoričke podatke, kao što je detekcija spama.<sup>[[5]](#references)</sup>


#### Bayesova teorema

Bayesova teorema predstavlja osnovu Naive Bayes klasifikatora. Ona povezuje uslovne i marginalne verovatnoće slučajnih događaja. Formula glasi:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gde:
- `P(A|B)` je posteriorna verovatnoća klase `A` na osnovu osobine `B`.
- `P(B|A)` je verodostojnost osobine `B` za klasu `A`.
- `P(A)` je apriorna verovatnoća klase `A`.
- `P(B)` je apriorna verovatnoća osobine `B`.

Na primer, ako želimo da klasifikujemo da li je tekst napisalo dete ili odrasla osoba, možemo koristiti reči u tekstu kao osobine. Na osnovu početnih podataka, Naive Bayes classifier će prethodno izračunati verovatnoće da se svaka reč nalazi u svakoj potencijalnoj klasi (dete ili odrasla osoba). Kada dobije novi tekst, izračunaće verovatnoću svake potencijalne klase na osnovu reči u tekstu i izabrati klasu sa najvećom verovatnoćom.

Kao što možete videti u ovom primeru, Naive Bayes classifier je veoma jednostavan i brz, ali pretpostavlja da su osobine nezavisne, što nije uvek slučaj sa podacima iz stvarnog sveta.


#### Tipovi Naive Bayes Classifiers

Postoji nekoliko tipova Naive Bayes classifiers, u zavisnosti od vrste podataka i distribucije osobina:
- **Gaussian Naive Bayes**: Pretpostavlja da osobine prate Gaussian (normalnu) distribuciju. Pogodan je za kontinuirane podatke.
- **Multinomial Naive Bayes**: Pretpostavlja da osobine prate multinomijalnu distribuciju. Pogodan je za diskretne podatke, kao što je broj pojavljivanja reči u klasifikaciji teksta.
- **Bernoulli Naive Bayes**: Pretpostavlja da su osobine binarne (0 ili 1). Pogodan je za binarne podatke, kao što su prisustvo ili odsustvo reči u klasifikaciji teksta.
- **Categorical Naive Bayes**: Pretpostavlja da su osobine kategorijalne promenljive. Pogodan je za kategorijalne podatke, kao što je klasifikacija voća na osnovu boje i oblika.


#### **Ključne karakteristike Naive Bayes:**

-   **Tip problema:** Klasifikacija (binarna ili višeklasna). Često se koristi za zadatke klasifikacije teksta u cybersecurity oblasti (spam, phishing itd.).

-   **Interpretabilnost:** Srednja -- nije direktno interpretabilan kao decision tree, ali se mogu ispitati naučene verovatnoće (npr. koje reči se najverovatnije pojavljuju u spam u odnosu na ham emailove). Oblik modela (verovatnoće svake osobine za datu klasu) može se razumeti kada je to potrebno.

-   **Prednosti:** **Veoma brzo** treniranje i predviđanje, čak i na velikim skupovima podataka (linearno u odnosu na broj instanci * broj osobina). Zahteva relativno malu količinu podataka za pouzdanu procenu verovatnoća, naročito uz pravilno smoothing podešavanje. Često je iznenađujuće precizan kao baseline, posebno kada osobine nezavisno doprinose dokazima u korist određene klase. Dobro funkcioniše sa visokodimenzionalnim podacima (npr. hiljade osobina iz teksta). Nije potrebno složeno podešavanje, osim postavljanja smoothing parametra.

-   **Ograničenja:** Pretpostavka nezavisnosti može ograničiti preciznost ako su osobine veoma korelisane. Na primer, u network podacima, osobine kao što su `src_bytes` i `dst_bytes` mogu biti korelisane; Naive Bayes neće obuhvatiti tu interakciju. Kako veličina podataka postaje veoma velika, ekspresivniji modeli (kao što su ensembles ili neural nets) mogu nadmašiti NB učenjem zavisnosti između osobina. Takođe, ako je za identifikaciju napada potrebna određena kombinacija osobina (a ne samo pojedinačne osobine nezavisno), NB će imati poteškoća.

> [!TIP]
> *Primene u cybersecurity oblasti:* Klasična primena je **detekcija spam-a** -- Naive Bayes je bio osnova ranih spam filtera, koji su koristili učestalost određenih tokena (reči, fraze, IP adrese) za izračunavanje verovatnoće da je email spam. Takođe se koristi za **detekciju phishing emailova** i **klasifikaciju URL-ova**, gde prisustvo određenih ključnih reči ili karakteristika (kao što je "login.php" u URL-u ili `@` u putanji URL-a) doprinosi verovatnoći phishing-a. U analizi malware-a, može se zamisliti Naive Bayes classifier koji koristi prisustvo određenih API poziva ili dozvola u software-u za predviđanje da li je u pitanju malware. Iako napredniji algoritmi često daju bolje rezultate, Naive Bayes ostaje dobar baseline zbog svoje brzine i jednostavnosti.

<details>
<summary>Primer -- Naive Bayes za detekciju phishing-a:</summary>
Da bismo demonstrirali Naive Bayes, koristićemo Gaussian Naive Bayes na NSL-KDD intrusion dataset-u (sa binarnim labelama). Gaussian NB će tretirati svaku osobinu kao da prati normalnu distribuciju za svaku klasu. Ovo je približan izbor, jer su mnoge network osobine diskretne ili imaju veoma asimetričnu distribuciju, ali pokazuje kako bi se NB primenio na podatke sa kontinuiranim osobinama. Takođe bismo mogli izabrati Bernoulli NB na skupu podataka sa binarnim osobinama (kao što je skup aktiviranih alerts), ali ćemo se ovde držati NSL-KDD-a radi kontinuiteta.
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
Ovaj kod obučava Naive Bayes klasifikator za detekciju napada. Naive Bayes će izračunati vrednosti poput `P(service=http | Attack)` i `P(Service=http | Normal)` na osnovu training podataka, uz pretpostavku nezavisnosti među feature-ima. Zatim će koristiti ove verovatnoće za klasifikaciju novih konekcija kao normalnih ili napadačkih, na osnovu uočenih feature-a. Performanse NB-a na NSL-KDD možda neće biti visoke kao kod naprednijih modela (pošto je pretpostavka nezavisnosti feature-a narušena), ali su često sasvim dobre i dolaze uz prednost izuzetne brzine. U scenarijima poput filtriranja emailova u realnom vremenu ili početne trijaže URL-ova, Naive Bayes model može brzo označiti očigledno maliciozne slučajeve uz malu potrošnju resursa.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors je jedan od najjednostavnijih machine learning algoritama. To je **neparametarski, instance-based** metod koji donosi predikcije na osnovu sličnosti sa primerima iz training skupa. Ideja klasifikacije je sledeća: da bi se klasifikovala nova data tačka, pronalazi se **k** najbližih tačaka u training podacima (njeni „nearest neighbors“), a zatim se dodeljuje klasa koja je većinska među tim susedima. „Blizina“ se definiše metrikom distance, najčešće Euklidskom distancom za numeričke podatke (druge distance mogu se koristiti za različite tipove feature-a ili problema).<sup>[[10]](#references)</sup>

K-NN ne zahteva *eksplicitni training* -- „training“ faza se svodi na čuvanje dataseta. Sav posao se odvija tokom query-ja (predikcije): algoritam mora da izračuna distance od query tačke do svih training tačaka kako bi pronašao najbliže. Zbog toga je vreme predikcije **linearno u odnosu na broj training uzoraka**, što može biti skupo za velike datasete. Zbog toga je k-NN najpogodniji za manje datasete ili scenarije u kojima se memorija i brzina mogu menjati za jednostavnost.

Uprkos jednostavnosti, k-NN može modelovati veoma složene granice odlučivanja (pošto granica odlučivanja praktično može imati bilo koji oblik koji određuje raspodela primera). Obično daje dobre rezultate kada je granica odlučivanja veoma nepravilna i kada postoji mnogo podataka -- u suštini dopuštajući podacima da „govore sami za sebe“. Međutim, u visokodimenzionalnim prostorima metrike distance mogu postati manje smislene (curse of dimensionality), pa metod može imati poteškoća osim ako ne postoji ogroman broj uzoraka.

*Use cases in cybersecurity:* k-NN se koristi za anomaly detection -- na primer, intrusion detection system može označiti network event kao maliciozan ako je većina njegovih najbližih suseda (prethodnih događaja) bila maliciozna. Ako normalni saobraćaj formira klastere, a napadi su outlier-i, K-NN pristup (sa k=1 ili malim k) u suštini predstavlja **nearest-neighbor anomaly detection**. K-NN se takođe koristio za klasifikaciju malware familija pomoću binarnih feature vektora: novi fajl može biti klasifikovan kao određena malware familija ako je veoma blizu (u feature prostoru) poznatim instancama te familije. U praksi, k-NN nije toliko čest kao skalabilniji algoritmi, ali je konceptualno jednostavan i ponekad se koristi kao baseline ili za probleme manjeg obima.

#### **Ključne karakteristike k-NN-a:**

-   **Tip problema:** Klasifikacija (postoje i varijante za regresiju). To je metod *lazy learning*-a -- nema eksplicitnog fitovanja modela.

-   **Interpretabilnost:** Niska do srednja -- ne postoji globalni model niti sažeto objašnjenje, ali se rezultati mogu tumačiti posmatranjem najbližih suseda koji su uticali na odluku (npr. „ovaj network flow je klasifikovan kao maliciozan zato što je sličan ovim 3 poznata maliciozna flow-a“). Dakle, objašnjenja mogu biti zasnovana na primerima.

-   **Prednosti:** Veoma jednostavan za implementaciju i razumevanje. Ne zasniva se na pretpostavkama o raspodeli podataka (neparametarski). Prirodno može da obrađuje multi-class probleme. **Adaptivan** je u smislu da granice odlučivanja mogu biti veoma složene i oblikovane raspodelom podataka.

-   **Ograničenja:** Predikcija može biti spora za velike datasete (mora se izračunati veliki broj distanci). Zahteva mnogo memorije -- čuva sve training podatke. Performanse se pogoršavaju u visokodimenzionalnim feature prostorima jer sve tačke teže da postanu gotovo jednako udaljene (zbog čega koncept „najbližeg“ postaje manje smislen). Potrebno je pravilno izabrati *k* (broj suseda) -- premalo k može dovesti do šuma, dok preveliko k može uključiti nerelevantne tačke iz drugih klasa. Takođe, feature-e treba pravilno skalirati jer su proračuni distance osetljivi na skalu.

<details>
<summary>Primer -- k-NN za Phishing Detection:</summary>

Ponovo ćemo koristiti NSL-KDD (binarna klasifikacija). Pošto je k-NN računski zahtevan, koristićemo podskup training podataka kako bi demonstracija ostala izvodljiva. Izabraćemo, na primer, 20.000 training uzoraka od ukupno 125k i koristićemo k=5 suseda. Nakon training-a (što se zapravo svodi na čuvanje podataka), izvršićemo evaluaciju na test skupu. Takođe ćemo skalirati feature-e za izračunavanje distance kako nijedan pojedinačni feature ne bi dominirao zbog svoje skale.
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
k-NN model će klasifikovati konekciju posmatrajući 5 najbližih konekcija u podskupu skupa za obuku. Ako su, na primer, 4 od tih suseda napadi (anomalije), a 1 je normalan, nova konekcija će biti klasifikovana kao napad. Performanse mogu biti zadovoljavajuće, mada često nisu tako visoke kao kod dobro podešenog Random Forest ili SVM modela na istim podacima. Međutim, k-NN ponekad može da bude veoma dobar kada su distribucije klasa veoma nepravilne i složene -- praktično koristeći pretragu zasnovanu na memoriji. U sajberbezbednosti, k-NN (sa k=1 ili malim k) može da se koristi za detekciju poznatih obrazaca napada na osnovu primera ili kao komponenta složenijih sistema (npr., za klasterovanje, a zatim i klasifikaciju na osnovu pripadnosti klasteru).
</details>

### Gradient Boosting Machines (npr., XGBoost)

Gradient Boosting Machines spadaju među najmoćnije algoritme za strukturirane podatke. **Gradient boosting** se odnosi na tehniku izgradnje ansambla slabih modela (često stabala odlučivanja) sekvencijalnim postupkom, pri čemu svaki novi model ispravlja greške prethodnog ansambla. Za razliku od bagging-a (Random Forest), koji stabla gradi paralelno i izračunava njihov prosek, boosting gradi stabla *jedno po jedno*, pri čemu se svako više fokusira na instance koje su prethodna stabla pogrešno predvidela.

Najpopularnije implementacije poslednjih godina su **XGBoost**, **LightGBM** i **CatBoost**, koje su biblioteke za gradient boosting decision tree (GBDT). Bile su izuzetno uspešne na takmičenjima iz machine learning-a i u praktičnim primenama, često **postižući vrhunske rezultate na tabelarnim skupovima podataka**. U sajberbezbednosti, istraživači i praktičari koriste gradient boosted trees za zadatke kao što su **detekcija malware-a** (korišćenjem karakteristika izdvojenih iz datoteka ili ponašanja tokom izvršavanja) i **detekcija mrežnih upada**. Na primer, gradient boosting model može da kombinuje mnoga slaba pravila (stabla), kao što je „ako postoji mnogo SYN paketa i neuobičajen port -> verovatno skeniranje“, u snažan kombinovani detektor koji uzima u obzir mnoge suptilne obrasce.<sup>[[6]](#references)</sup>

Zašto su boosted trees toliko efikasna? Svako stablo u nizu trenira se na *preostalim greškama* (gradientima) predviđanja trenutnog ansambla. Na taj način model postepeno **„pojačava“** oblasti u kojima je slab. Korišćenje stabala odlučivanja kao osnovnih modela omogućava konačnom modelu da obuhvati složene interakcije i nelinearne odnose. Takođe, boosting u osnovi ima oblik ugrađene regularizacije: dodavanjem mnogih malih stabala (i korišćenjem stope učenja za skaliranje njihovih doprinosa), često dobro generalizuje bez preteranog overfitting-a, pod uslovom da su parametri pravilno izabrani.

#### **Ključne karakteristike Gradient Boosting-a:**

-   **Tip problema:** Prvenstveno klasifikacija i regresija. U oblasti bezbednosti najčešće se koristi klasifikacija (npr., binarna klasifikacija konekcije ili datoteke). Podržava binarne i višeklasne probleme (uz odgovarajuću funkciju gubitka), kao i probleme rangiranja.

-   **Interpretabilnost:** Niska do srednja. Iako je pojedinačno boosted tree malo, kompletan model može imati stotine stabala, zbog čega nije razumljiv ljudima kao celina. Međutim, poput Random Forest-a, može da pruži rezultate važnosti karakteristika, a alati kao što je SHAP (SHapley Additive exPlanations) mogu se u određenoj meri koristiti za tumačenje pojedinačnih predviđanja.

-   **Prednosti:** Često **algoritam sa najboljim performansama** za strukturirane/tabelarne podatke. Može da otkrije složene obrasce i interakcije. Ima mnogo parametara za podešavanje (broj stabala, dubina stabala, stopa učenja, termini regularizacije) kojima se složenost modela može prilagoditi i sprečiti overfitting. Moderne implementacije su optimizovane za brzinu (npr., XGBoost koristi informacije o gradientu drugog reda i efikasne strukture podataka). Obično bolje obrađuje neizbalansirane podatke kada se kombinuje sa odgovarajućim funkcijama gubitka ili podešavanjem težina uzoraka.

-   **Ograničenja:** Složeniji je za podešavanje od jednostavnijih modela; obuka može biti spora ako su stabla duboka ili je njihov broj veliki (mada je i dalje obično brža od obuke uporedive duboke neuronske mreže na istim podacima). Model može da overfit-uje ako nije pravilno podešen (npr., ako ima previše dubokih stabala sa nedovoljnom regularizacijom). Zbog velikog broja hiperparametara, efikasno korišćenje gradient boosting-a može zahtevati više stručnosti ili eksperimentisanja. Takođe, poput metoda zasnovanih na stablima, ne obrađuje inherentno veoma retke podatke visoke dimenzionalnosti tako efikasno kao linearni modeli ili Naive Bayes (iako se i dalje može primeniti, npr., u klasifikaciji teksta, ali bez feature engineering-a možda neće biti prvi izbor).

> [!TIP]
> *Primene u sajberbezbednosti:* Gotovo svuda gde bi se mogao koristiti decision tree ili random forest, gradient boosting model može postići veću preciznost. Na primer, takmičenja u **Microsoft-ovoj detekciji malware-a** često su intenzivno koristila XGBoost nad engineered karakteristikama iz binarnih datoteka. Istraživanja **detekcije mrežnih upada** često navode najbolje rezultate uz GBDT (npr., XGBoost na skupovima podataka CIC-IDS2017 ili UNSW-NB15). Ovi modeli mogu da koriste širok opseg karakteristika (tipove protokola, učestalost određenih događaja, statističke karakteristike saobraćaja itd.) i da ih kombinuju radi detekcije pretnji. U detekciji phishing-a, gradient boosting može da kombinuje leksičke karakteristike URL-ova, karakteristike reputacije domena i karakteristike sadržaja stranice kako bi postigao veoma visoku preciznost. Ansambl pristup pomaže u obuhvatanju mnogih graničnih slučajeva i suptilnosti u podacima.

<details>
<summary>Primer -- XGBoost za detekciju phishing-a:</summary>
Koristićemo gradient boosting klasifikator nad skupom podataka za phishing. Da bismo stvari održali jednostavnim i samostalnim, koristićemo `sklearn.ensemble.GradientBoostingClassifier` (sporiju, ali jednostavnu implementaciju). Uobičajeno bi se koristile biblioteke `xgboost` ili `lightgbm` radi boljih performansi i dodatnih funkcionalnosti. Treniraćemo model i proceniti ga na sličan način kao ranije.
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
Model gradientnog boostinga će verovatno postići veoma visoku tačnost i AUC na ovom phishing skupu podataka (ovakvi modeli često mogu premašiti 95% tačnosti uz pravilno podešavanje na takvim podacima, kao što je pokazano u literaturi. Ovo pokazuje zašto se GBDT modeli smatraju *„the state of the art model for tabular dataset“* -- često nadmašuju jednostavnije algoritme tako što prepoznaju složene obrasce. U kontekstu cybersecurity-ja, to bi moglo značiti otkrivanje većeg broja phishing sajtova ili napada uz manje propuštenih slučajeva. Naravno, mora se voditi računa o overfitting-u -- obično bismo koristili tehnike poput cross-validation-a i pratili performanse na validation skupu tokom razvoja takvog modela za deployment.

</details>

### Kombinovanje modela: Ensemble Learning i Stacking

Ensemble learning je strategija **kombinovanja više modela** radi poboljšanja ukupnih performansi. Već smo videli konkretne ensemble metode: Random Forest (ensemble stabala pomoću bagging-a) i Gradient Boosting (ensemble stabala pomoću sekvencijalnog boosting-a). Međutim, ensembles se mogu kreirati i na druge načine, kao što su **voting ensembles** ili **stacked generalization (stacking)**. Osnovna ideja je da različiti modeli mogu prepoznati različite obrasce ili imati različite slabosti; njihovim kombinovanjem možemo **nadoknaditi greške svakog modela prednostima drugog modela**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** Kod jednostavnog voting classifier-a, treniramo više raznovrsnih modela (na primer, logistic regression, decision tree i SVM) i omogućavamo im da glasaju o konačnoj predikciji (većinsko glasanje kod klasifikacije). Ako ponderišemo glasove (na primer, veću težinu damo preciznijim modelima), dobijamo weighted voting šemu. Ovo obično poboljšava performanse kada su pojedinačni modeli dovoljno dobri i nezavisni -- ensemble smanjuje rizik od greške pojedinačnog modela, jer je drugi modeli mogu ispraviti. To je kao da imamo panel stručnjaka umesto samo jednog mišljenja.

-   **Stacking (Stacked Ensemble):** Stacking ide korak dalje. Umesto jednostavnog glasanja, on trenira **meta-model** da **nauči kako najbolje da kombinuje predikcije** osnovnih modela. Na primer, trenirate 3 različita classifier-a (base learner-e), a zatim njihove izlaze (ili verovatnoće) prosleđujete kao features meta-classifier-u (često jednostavnom modelu kao što je logistic regression), koji uči optimalan način njihovog kombinovanja. Meta-model se trenira na validation skupu ili pomoću cross-validation-a kako bi se izbegao overfitting. Stacking često može nadmašiti jednostavno glasanje tako što uči *kojim modelima više verovati u kojim okolnostima*. U cybersecurity-ju, jedan model može biti bolji u otkrivanju network scan-ova, dok je drugi bolji u otkrivanju malware beaconing-a; stacking model može naučiti da se na odgovarajući način osloni na svaki od njih.

Ensembles, bilo da se zasnivaju na glasanju ili stackingu, uglavnom **poboljšavaju tačnost** i robusnost. Nedostatak su povećana složenost i ponekad slabija interpretabilnost (iako neki ensemble pristupi, kao što je prosek decision tree modela, i dalje mogu pružiti određeni uvid, na primer kroz feature importance). U praksi, ako operativna ograničenja to dozvoljavaju, korišćenje ensemble-a može dovesti do većih stopa detekcije. Mnoga pobednička rešenja u cybersecurity izazovima (i Kaggle takmičenjima uopšte) koriste ensemble tehnike kako bi izvukla i poslednji deo performansi.

<details>
<summary>Primer -- Voting Ensemble za Phishing Detection:</summary>
Da bismo ilustrovali model stacking, kombinovaćemo nekoliko modela o kojima smo govorili na phishing skupu podataka. Koristićemo logistic regression, decision tree i k-NN kao osnovne modele, a Random Forest kao meta-learner za objedinjavanje njihovih predikcija. Meta-learner će biti treniran na izlazima osnovnih modela (korišćenjem cross-validation-a na training skupu). Očekujemo da stacked model ostvari jednake ili nešto bolje performanse od pojedinačnih modela.
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
Složeni ensemble koristi komplementarne prednosti osnovnih modela. Na primer, logistička regresija može da obrađuje linearne aspekte podataka, stablo odlučivanja može da obuhvati specifične interakcije nalik pravilima, a k-NN može da bude posebno uspešan u lokalnim susedstvima prostora karakteristika. Meta-model (ovde random forest) može da nauči kako da odmeri ove ulaze. Dobijene metrike često pokazuju poboljšanje (čak i ako je neznatno) u odnosu na metrike bilo kog pojedinačnog modela. U našem primeru phishinga, ako je logistička regresija samostalno imala F1 rezultat od, recimo, 0.95, a stablo 0.94, stack bi mogao da dostigne 0.96 tako što bi nadoknadio slabosti svakog modela.

Ensemble metode poput ove pokazuju princip da *"kombinovanje više modela obično vodi ka boljoj generalizaciji"*. U cybersecurityju, ovo se može implementirati korišćenjem više detection engine-a (jedan može biti zasnovan na pravilima, drugi na machine learningu, a treći na detekciji anomalija), nakon čega sledi sloj koji objedinjuje njihova upozorenja -- praktično oblik ensemble-a -- kako bi doneo konačnu odluku sa većim stepenom pouzdanosti. Prilikom uvođenja ovakvih sistema, potrebno je uzeti u obzir dodatnu složenost i osigurati da ensemble ne postane previše težak za upravljanje ili objašnjavanje. Međutim, sa stanovišta preciznosti, ensemble metode i stacking predstavljaju moćne alate za poboljšanje performansi modela.

</details>


## Reference

- [1] [Logistička regresija](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Stablo odlučivanja - uvod sa primerom](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Detekcija Denial of Services napada pomoću Random Forest Classifier-a sa Information Gain-om](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [Šta su Support Vector Machines (SVMs)? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Naive Bayes filtriranje spama (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT demistifikovan: Kako rade LightGBM, XGBoost i CatBoost](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI i Machine Learning u cybersecurityju (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Objašnjenje linearne regresije](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Analiza performansi machine learning modela za intrusion detection system pomoću Gini Impurity-based Weighted Random Forest (GIWRF) tehnike selekcije karakteristika](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [Šta je algoritam k-nearest neighbors (KNN)? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Klasifikacija phishing napada i website-ova korišćenjem machine learninga i više datasetova (komparativna analiza)](https://arxiv.org/pdf/2101.02552)
- [12] [Kako deep learning unapređuje intrusion detection systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning: Poboljšanje performansi modela kombinovanjem prednosti](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
