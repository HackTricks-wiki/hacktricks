# Algoritmi nadgledanog učenja

{{#include ../banners/hacktricks-training.md}}

## Osnovne informacije

Nadgledano učenje koristi označene podatke za obučavanje modela koji mogu praviti predikcije na novim, neviđenim ulazima. U sajber bezbednosti, nadgledano mašinsko učenje se široko primenjuje na zadatke kao što su detekcija upada (klasifikacija mrežnog saobraćaja kao *normalnog* ili *napada*), detekcija malvera (razlikovanje zlonamernog softvera od benignog), detekcija phishinga (identifikacija prevarantskih veb sajtova ili e-pošte) i filtriranje spama, između ostalog. Svaki algoritam ima svoje prednosti i prilagođen je različitim vrstama problema (klasifikacija ili regresija). Ispod pregledamo ključne algoritme nadgledanog učenja, objašnjavamo kako funkcionišu i demonstriramo njihovu upotrebu na stvarnim skupovima podataka iz sajber bezbednosti. Takođe raspravljamo o tome kako kombinovanje modela (ensemble learning) često može poboljšati prediktivnu tačnost.

## Algoritmi

-   **Linear Regression:** Osnovni regresioni algoritam za predikciju numeričkih ishoda prilagođavanjem linearne jednačine podacima.

-   **Logistic Regression:** Klasifikacioni algoritam (uprkos svom imenu) koji koristi logističku funkciju za modelovanje verovatnoće binarnog ishoda.

-   **Decision Trees:** Modeli u obliku stabla koji dele podatke prema karakteristikama kako bi pravili predikcije; često se koriste zbog svoje interpretabilnosti.

-   **Random Forests:** Skup odluka (putem bagging-a) koji poboljšava tačnost i smanjuje prekomerno prilagođavanje.

-   **Support Vector Machines (SVM):** Klasifikatori sa maksimalnom marginom koji pronalaze optimalnu separacionu hiperplanu; mogu koristiti jezgre za nelinearne podatke.

-   **Naive Bayes:** Probabilistički klasifikator zasnovan na Bayesovoj teoremi sa pretpostavkom nezavisnosti karakteristika, poznato korišćen u filtriranju spama.

-   **k-Nearest Neighbors (k-NN):** Jednostavan "instancijski" klasifikator koji označava uzorak na osnovu većinske klase njegovih najbližih suseda.

-   **Gradient Boosting Machines:** Skupni modeli (npr. XGBoost, LightGBM) koji grade jak prediktor dodavanjem slabijih učenika (tipično stabala odluka) sekvencijalno.

Svaka sekcija ispod pruža poboljšan opis algoritma i **primer Python koda** koristeći biblioteke kao što su `pandas` i `scikit-learn` (i `PyTorch` za primer neuronske mreže). Primeri koriste javno dostupne skupove podataka iz sajber bezbednosti (kao što su NSL-KDD za detekciju upada i skup podataka o phishing veb sajtovima) i prate doslednu strukturu:

1.  **Učitajte skup podataka** (preuzmite putem URL-a ako je dostupno).

2.  **Predobradite podatke** (npr. kodirajte kategorijske karakteristike, skalirajte vrednosti, podelite na obučene/testne skupove).

3.  **Obučite model** na obučenom skupu podataka.

4.  **Evaluirajte** na testnom skupu koristeći metrike: tačnost, preciznost, odziv, F1-score i ROC AUC za klasifikaciju (i srednju kvadratnu grešku za regresiju).

Hajde da zaronimo u svaki algoritam:

### Linear Regression

Linear regression je **regresioni** algoritam koji se koristi za predikciju kontinuiranih numeričkih vrednosti. Pretpostavlja linearni odnos između ulaznih karakteristika (nezavisne varijable) i izlaza (zavisna varijabla). Model pokušava da prilagodi pravu liniju (ili hiperplanu u višim dimenzijama) koja najbolje opisuje odnos između karakteristika i cilja. To se obično radi minimizovanjem sume kvadratnih grešaka između predviđenih i stvarnih vrednosti (metoda običnih najmanjih kvadrata).

Najjednostavniji način da se predstavi linearna regresija je sa linijom:
```plaintext
y = mx + b
```
Gde:

- `y` je predviđena vrednost (izlaz)
- `m` je nagib linije (koeficijent)
- `x` je ulazna karakteristika
- `b` je y-presjek

Cilj linearne regresije je pronaći najbolju liniju koja minimizira razliku između predviđenih vrednosti i stvarnih vrednosti u skupu podataka. Naravno, ovo je vrlo jednostavno, bila bi to prava linija koja razdvaja 2 kategorije, ali ako se dodaju više dimenzija, linija postaje složenija:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Upotreba u sajber bezbednosti:* Linearna regresija sama po sebi je manje uobičajena za osnovne bezbednosne zadatke (koji su često klasifikacija), ali se može primeniti za predviđanje numeričkih ishoda. Na primer, moglo bi se koristiti linearna regresija da se **predvidi obim mrežnog saobraćaja** ili **proceni broj napada u određenom vremenskom periodu** na osnovu istorijskih podataka. Takođe bi mogla predvideti rizik ili očekivano vreme do otkrivanja napada, uzimajući u obzir određene sistemske metrike. U praksi, algoritmi klasifikacije (kao što su logistička regresija ili stabla) se češće koriste za otkrivanje upada ili malvera, ali linearna regresija služi kao osnova i korisna je za analize orijentisane na regresiju.

#### **Ključne karakteristike Linearne Regresije:**

-   **Tip Problema:** Regresija (predviđanje kontinuiranih vrednosti). Nije pogodna za direktnu klasifikaciju osim ako se ne primeni prag na izlaz.

-   **Interpretabilnost:** Visoka -- koeficijenti su jednostavni za interpretaciju, pokazujući linearni efekat svake karakteristike.

-   **Prednosti:** Jednostavna i brza; dobra osnova za regresione zadatke; dobro funkcioniše kada je prava veza približno linearna.

-   **Ograničenja:** Ne može uhvatiti složene ili nelinearne odnose (bez ručnog inženjeringa karakteristika); sklona je podfittingu ako su odnosi nelinearni; osetljiva na odstupanja koja mogu iskriviti rezultate.

-   **Pronalaženje Najboljeg Prilagođavanja:** Da bismo pronašli najbolju liniju koja razdvaja moguće kategorije, koristimo metodu koja se zove **Obična metoda najmanjih kvadrata (OLS)**. Ova metoda minimizuje zbir kvadrata razlika između posmatranih vrednosti i vrednosti predviđenih linearnim modelom.

<details>
<summary>Primer -- Predviđanje Trajanja Povezivanja (Regresija) u Skupu Podataka o Upadima
</summary>
Ispod prikazujemo linearne regresije koristeći NSL-KDD skup podataka o sajber bezbednosti. Posmatraćemo ovo kao problem regresije predviđajući `trajanje` mrežnih veza na osnovu drugih karakteristika. (U stvarnosti, `trajanje` je jedna karakteristika NSL-KDD; koristimo je ovde samo da ilustrujemo regresiju.) Učitaćemo skup podataka, obraditi ga (kodirati kategorijske karakteristike), obučiti model linearne regresije i proceniti srednju kvadratnu grešku (MSE) i R² rezultat na testnom skupu.
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
U ovom primeru, model linearne regresije pokušava da predvidi `trajanje` veze na osnovu drugih mrežnih karakteristika. Merenje performansi vršimo pomoću Srednje Kvadratne Greške (MSE) i R². R² blizu 1.0 bi ukazivao na to da model objašnjava većinu varijanse u `trajanju`, dok nizak ili negativan R² ukazuje na loše prilagođavanje. (Ne iznenađujte se ako je R² ovde nizak -- predviđanje `trajanja` može biti teško na osnovu datih karakteristika, a linearna regresija možda neće uhvatiti obrasce ako su složeni.)
</details>

### Logistička Regresija

Logistička regresija je **klasifikacioni** algoritam koji modeluje verovatnoću da instanca pripada određenoj klasi (tipično "pozitivnoj" klasi). I pored svog imena, *logistička* regresija se koristi za diskretne ishode (za razliku od linearne regresije koja je za kontinuirane ishode). Posebno se koristi za **binarne klasifikacije** (dve klase, npr. zlonameran vs. benigni), ali se može proširiti na probleme sa više klasa (koristeći softmax ili pristupe jedan-protiv-ostatka).

Logistička regresija koristi logističku funkciju (poznatu i kao sigmoidna funkcija) da mapira predviđene vrednosti na verovatnoće. Imajte na umu da je sigmoidna funkcija funkcija sa vrednostima između 0 i 1 koja raste u S-obliku prema potrebama klasifikacije, što je korisno za zadatke binarne klasifikacije. Stoga se svaka karakteristika svakog ulaza množi sa dodeljenom težinom, a rezultat se propušta kroz sigmoidnu funkciju da bi se dobila verovatnoća:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gde:

- `p(y=1|x)` je verovatnoća da je izlaz `y` 1 s obzirom na ulaz `x`
- `e` je osnova prirodnog logaritma
- `z` je linearna kombinacija ulaznih karakteristika, obično predstavljena kao `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Primetite kako je ponovo u svom najjednostavnijem obliku to prava linija, ali u složenijim slučajevima postaje hiperravan sa više dimenzija (jedna po karakteristici).

> [!TIP]
> *Upotreba u sajber bezbednosti:* Pošto su mnogi bezbednosni problemi suštinski da/ne odluke, logistička regresija se široko koristi. Na primer, sistem za detekciju upada može koristiti logističku regresiju da odluči da li je mrežna veza napad na osnovu karakteristika te veze. U detekciji phishing-a, logistička regresija može kombinovati karakteristike veb sajta (dužina URL-a, prisustvo "@" simbola, itd.) u verovatnoću da je u pitanju phishing. Koristila se u ranim generacijama spam filtera i ostaje snažna osnova za mnoge klasifikacione zadatke.

#### Logistička regresija za ne-binarne klasifikacije

Logistička regresija je dizajnirana za binarnu klasifikaciju, ali se može proširiti da se bavi višeklasnim problemima koristeći tehnike kao što su **one-vs-rest** (OvR) ili **softmax regresija**. U OvR, poseban model logističke regresije se obučava za svaku klasu, tretirajući je kao pozitivnu klasu u odnosu na sve ostale. Klasa sa najvišom predviđenom verovatnoćom se bira kao konačna predikcija. Softmax regresija generalizuje logističku regresiju na više klasa primenom softmax funkcije na izlazni sloj, proizvodeći verovatnosnu distribuciju preko svih klasa.

#### **Ključne karakteristike logističke regresije:**

-   **Tip problema:** Klasifikacija (obično binarna). Predviđa verovatnoću pozitivne klase.

-   **Interpretabilnost:** Visoka -- kao i kod linearne regresije, koeficijenti karakteristika mogu ukazivati na to kako svaka karakteristika utiče na log-odds ishoda. Ova transparentnost se često ceni u bezbednosti za razumevanje koji faktori doprinose upozorenju.

-   **Prednosti:** Jednostavna i brza za obuku; dobro funkcioniše kada je odnos između karakteristika i log-odds ishoda linearan. Izlazi verovatnoće, omogućavajući procenu rizika. Uz odgovarajuću regularizaciju, dobro se generalizuje i može bolje da se nosi sa multikolinearnošću nego obična linearna regresija.

-   **Ograničenja:** Pretpostavlja linearnu granicu odluke u prostoru karakteristika (ne uspeva ako je prava granica složena/ne-linearno). Može imati slabije performanse na problemima gde su interakcije ili ne-linearni efekti kritični, osim ako ručno ne dodate polinomijalne ili interakcione karakteristike. Takođe, logistička regresija je manje efikasna ako klase nisu lako odvojive linearnom kombinacijom karakteristika.


<details>
<summary>Primer -- Detekcija phishing veb sajtova pomoću logističke regresije:</summary>

Koristićemo **Dataset veb sajtova za phishing** (iz UCI repozitorijuma) koji sadrži ekstraktovane karakteristike veb sajtova (kao što su da li URL ima IP adresu, starost domena, prisustvo sumnjivih elemenata u HTML-u, itd.) i oznaku koja ukazuje da li je sajt phishing ili legitimni. Obučavamo model logističke regresije da klasifikuje veb sajtove i zatim procenjujemo njegovu tačnost, preciznost, odziv, F1-score i ROC AUC na testnom skupu.
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
U ovom primeru detekcije phishing-a, logistička regresija proizvodi verovatnoću za svaku veb stranicu da bude phishing. Evaluacijom tačnosti, preciznosti, odziva i F1, dobijamo osećaj o performansama modela. Na primer, visok odziv bi značio da hvata većinu phishing sajtova (važan za bezbednost kako bi se minimizirali propušteni napadi), dok visoka preciznost znači da ima malo lažnih alarma (važan za izbegavanje umora analitičara). ROC AUC (Površina ispod ROC krive) daje meru performansi koja nije zavisna od praga (1.0 je idealno, 0.5 nije bolje od slučajnosti). Logistička regresija često dobro funkcioniše na takvim zadacima, ali ako je granica odluke između phishing i legitimnih sajtova složena, možda će biti potrebni moćniji nelinearni modeli.

</details>

### Odluke stabla

Stablo odluka je svestran **supervised learning algorithm** koji se može koristiti za klasifikaciju i regresiju. Uči hijerarhijski model odluka nalik stablu na osnovu karakteristika podataka. Svaki unutrašnji čvor stabla predstavlja test na određenoj karakteristici, svaka grana predstavlja ishod tog testa, a svaki list predstavlja predviđenu klasu (za klasifikaciju) ili vrednost (za regresiju).

Da bi se izgradilo stablo, algoritmi poput CART (Classification and Regression Tree) koriste mere kao što su **Gini impurity** ili **information gain (entropy)** da izaberu najbolju karakteristiku i prag za deljenje podataka na svakom koraku. Cilj na svakom podelu je da se podaci podele kako bi se povećala homogenost ciljne varijable u rezultantnim podskupovima (za klasifikaciju, svaki čvor teži da bude što čistiji, sadržeći pretežno jednu klasu).

Stabla odluka su **highly interpretable** -- može se pratiti putanja od korena do lista kako bi se razumeo logika iza predikcije (npr., *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Ovo je dragoceno u sajber bezbednosti za objašnjenje zašto je određena upozorenje podignuta. Stabla prirodno mogu obraditi i numeričke i kategorijske podatke i zahtevaju malo prethodne obrade (npr., skaliranje karakteristika nije potrebno).

Međutim, jedno stablo odluka može lako prekomerno prilagoditi obučene podatke, posebno ako se duboko raste (mnoge podele). Tehnike poput obrezivanja (ograničavanje dubine stabla ili zahtev za minimalnim brojem uzoraka po listu) se često koriste da se spreči prekomerno prilagođavanje.

Postoje 3 glavne komponente stabla odluka:
- **Root Node**: Gornji čvor stabla, koji predstavlja ceo skup podataka.
- **Internal Nodes**: Čvorovi koji predstavljaju karakteristike i odluke na osnovu tih karakteristika.
- **Leaf Nodes**: Čvorovi koji predstavljaju konačni ishod ili predikciju.

Stablo bi moglo izgledati ovako:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Upotreba u sajber bezbednosti:* Odluke stabla su korišćene u sistemima za detekciju upada za dobijanje **pravila** za identifikaciju napada. Na primer, rani IDS sistemi kao što su oni zasnovani na ID3/C4.5 generisali bi pravila koja su čitljiva za ljude kako bi razlikovali normalan i zlonameran saobraćaj. Takođe se koriste u analizi malvera da bi se odlučilo da li je datoteka zlonamerna na osnovu njenih atributa (veličina datoteke, entropija sekcije, API pozivi, itd.). Jasnoća stabala odluka ih čini korisnim kada je potrebna transparentnost -- analitičar može pregledati stablo kako bi potvrdio logiku detekcije.

#### **Ključne karakteristike stabala odluka:**

-   **Tip problema:** Kako klasifikacija, tako i regresija. Obično se koriste za klasifikaciju napada naspram normalnog saobraćaja, itd.

-   **Interpretabilnost:** Veoma visoka -- odluke modela mogu se vizualizovati i razumeti kao skup if-then pravila. Ovo je velika prednost u bezbednosti za poverenje i verifikaciju ponašanja modela.

-   **Prednosti:** Mogu zabeležiti nelinearne odnose i interakcije između karakteristika (svaki razdvoj može se smatrati interakcijom). Nema potrebe za skaliranjem karakteristika ili one-hot kodiranjem kategorijskih varijabli -- stabla to obrade nativno. Brza inferencija (predikcija je samo praćenje puta u stablu).

-   **Ograničenja:** Podložna prekomernom prilagođavanju ako se ne kontroliše (duboko stablo može zapamtiti obučeni skup). Mogu biti nestabilna -- male promene u podacima mogu dovesti do različite strukture stabla. Kao pojedinačni modeli, njihova tačnost možda neće odgovarati naprednijim metodama (ensembli poput Random Forests obično bolje performiraju smanjenjem varijanse).

-   **Pronalaženje najboljeg razdvajanja:**
- **Gini nečistoća**: Mera nečistoće čvora. Niža Gini nečistoća ukazuje na bolje razdvajanje. Formula je:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Gde je `p_i` proporcija instanci u klasi `i`.

- **Entropija**: Mera nesigurnosti u skupu podataka. Niža entropija ukazuje na bolje razdvajanje. Formula je:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Gde je `p_i` proporcija instanci u klasi `i`.

- **Informacijski dobitak**: Smanjenje entropije ili Gini nečistoće nakon razdvajanja. Što je veći informacijski dobitak, to je bolje razdvajanje. Izračunava se kao:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Pored toga, stablo se završava kada:
- Sve instance u čvoru pripadaju istoj klasi. Ovo može dovesti do prekomernog prilagođavanja.
- Maksimalna dubina (hardkodirana) stabla je dostignuta. Ovo je način da se spreči prekomerno prilagođavanje.
- Broj instanci u čvoru je ispod određenog praga. Ovo je takođe način da se spreči prekomerno prilagođavanje.
- Informacijski dobitak od daljih razdvajanja je ispod određenog praga. Ovo je takođe način da se spreči prekomerno prilagođavanje.

<details>
<summary>Primer -- Stablo odluka za detekciju upada:</summary>
Obučićemo stablo odluka na NSL-KDD skupu podataka da klasifikujemo mrežne konekcije kao *normalne* ili *napad*. NSL-KDD je poboljšana verzija klasičnog KDD Cup 1999 skupa podataka, sa karakteristikama kao što su tip protokola, usluga, trajanje, broj neuspešnih prijava, itd., i oznakom koja ukazuje na tip napada ili "normalno". Mapiraćemo sve tipove napada na klasu "anomalija" (binarna klasifikacija: normalno vs anomalija). Nakon obuke, procenićemo performanse stabla na testnom skupu.
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
U ovom primeru odlučivanja, ograničili smo dubinu stabla na 10 kako bismo izbegli ekstremno prekomerno prilagođavanje (parametar `max_depth=10`). Metrički podaci pokazuju koliko dobro stablo razlikuje normalan i napadni saobraćaj. Visok odziv bi značio da hvata većinu napada (važan za IDS), dok visoka preciznost znači malo lažnih alarma. Odlučujuća stabla često postižu pristojnu tačnost na strukturiranim podacima, ali jedno stablo možda neće dostići najbolju moguću performansu. Ipak, *interpretabilnost* modela je velika prednost -- mogli bismo ispitati delove stabla da vidimo, na primer, koje karakteristike (npr., `service`, `src_bytes`, itd.) su najuticajnije u označavanju veze kao maliciozne.

</details>

### Random Forests

Random Forest je metoda **ensemble learning** koja se oslanja na odlučujuća stabla kako bi poboljšala performanse. Random forest obučava više odlučujućih stabala (otuda "šuma") i kombinuje njihove izlaze kako bi napravila konačnu predikciju (za klasifikaciju, obično većinom glasova). Dve glavne ideje u random forest-u su **bagging** (bootstrap agregacija) i **feature randomness**:

-   **Bagging:** Svako stablo se obučava na nasumičnom bootstrap uzorku podataka za obuku (uzorkovano sa ponovnim uzorkovanjem). Ovo uvodi raznolikost među stablima.

-   **Feature Randomness:** Na svakom razdvajanju u stablu, razmatra se nasumični podskup karakteristika za razdvajanje (umesto svih karakteristika). Ovo dodatno dekorelira stabla.

Srednjom vrednošću rezultata mnogih stabala, random forest smanjuje varijansu koju bi jedno odlučujuće stablo moglo imati. U jednostavnim terminima, pojedinačna stabla mogu prekomerno da se prilagode ili biti bučna, ali veliki broj raznolikih stabala koja glasaju zajedno ublažava te greške. Rezultat je često model sa **višom tačnošću** i boljom generalizacijom nego jedno odlučujuće stablo. Pored toga, random forests mogu pružiti procenu važnosti karakteristika (gledajući koliko svaka karakteristika smanjuje nečistotu u proseku).

Random forests su postali **radna konja u sajber bezbednosti** za zadatke poput detekcije upada, klasifikacije malvera i detekcije spama. Često dobro funkcionišu odmah nakon instalacije uz minimalno podešavanje i mogu obraditi velike skupove karakteristika. Na primer, u detekciji upada, random forest može nadmašiti pojedinačno odlučujuće stablo hvatajući suptilnije obrasce napada sa manje lažnih pozitivnih rezultata. Istraživanja su pokazala da random forests imaju povoljne performanse u poređenju sa drugim algoritmima u klasifikaciji napada u skupovima podataka kao što su NSL-KDD i UNSW-NB15.

#### **Ključne karakteristike Random Forests:**

-   **Tip problema:** Pretežno klasifikacija (takođe se koristi za regresiju). Veoma dobro prilagođeni za visoko-dimenzionalne strukturirane podatke koji su uobičajeni u bezbednosnim logovima.

-   **Interpretabilnost:** Manja nego kod jednog odlučujućeg stabla -- ne možete lako vizualizovati ili objasniti stotine stabala odjednom. Međutim, rezultati važnosti karakteristika pružaju uvid u to koje su atribute najuticajnije.

-   **Prednosti:** Generalno viša tačnost nego kod modela sa jednim stablom zbog efekta ansambla. Otporan na prekomerno prilagođavanje -- čak i ako pojedinačna stabla prekomerno prilagode, ansambl se bolje generalizuje. Rukuje i numeričkim i kategorijskim karakteristikama i može upravljati nedostajućim podacima do određene mere. Takođe je relativno otporan na ekstremne vrednosti.

-   **Ograničenja:** Veličina modela može biti velika (mnoga stabla, svako potencijalno duboko). Predikcije su sporije nego kod jednog stabla (jer morate agregirati preko mnogih stabala). Manje je interpretabilan -- iako znate važne karakteristike, tačna logika nije lako pratljiva kao jednostavno pravilo. Ako je skup podataka ekstremno visoko-dimenzionalan i ređi, obučavanje veoma velike šume može biti računski zahtevno.

-   **Proces obuke:**
1. **Bootstrap Sampling**: Nasumično uzorkovanje podataka za obuku sa ponovnim uzorkovanjem kako bi se stvorili višestruki podskupovi (bootstrap uzorci).
2. **Izgradnja stabla**: Za svaki bootstrap uzorak, izgradite odlučujuće stablo koristeći nasumični podskup karakteristika na svakom razdvajanju. Ovo uvodi raznolikost među stablima.
3. **Agregacija**: Za zadatke klasifikacije, konačna predikcija se pravi uzimanjem većine glasova među predikcijama svih stabala. Za zadatke regresije, konačna predikcija je prosek predikcija svih stabala.

<details>
<summary>Primer -- Random Forest za detekciju upada (NSL-KDD):</summary>
Koristićemo isti NSL-KDD skup podataka (binarno označen kao normalan naspram anomalije) i obučiti Random Forest klasifikator. Očekujemo da će random forest performirati jednako dobro ili bolje od pojedinačnog odlučujućeg stabla, zahvaljujući prosečnoj vrednosti ansambla koja smanjuje varijansu. Evaluiraćemo ga istim metrikama.
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
Random forest obično postiže snažne rezultate na ovom zadatku detekcije upada. Možda ćemo primetiti poboljšanje u metrima kao što su F1 ili AUC u poređenju sa pojedinačnim odlučujućim stablom, posebno u preciznosti ili podsećanju, u zavisnosti od podataka. To je u skladu sa razumevanjem da *"Random Forest (RF) je ansambl klasifikator i dobro se ponaša u poređenju sa drugim tradicionalnim klasifikatorima za efikasnu klasifikaciju napada."*. U kontekstu bezbednosnih operacija, model random forest može pouzdanije označiti napade dok smanjuje lažne alarme, zahvaljujući proseku mnogih odlučujućih pravila. Važnost karakteristika iz šume može nam reći koje mrežne karakteristike su najindikativnije za napade (npr. određene mrežne usluge ili neobični brojevi paketa).

</details>

### Support Vector Machines (SVM)

Support Vector Machines su moćni modeli nadgledanog učenja koji se prvenstveno koriste za klasifikaciju (a takođe i regresiju kao SVR). SVM pokušava da pronađe **optimalnu separacionu hiperplanu** koja maksimizira razmak između dve klase. Samo podskup tačaka za obuku ( "support vectors" najbliži granici) određuje poziciju ove hiperplane. Maksimizovanjem razmaka (udaljenosti između support vectors i hiperplane), SVM-ovi obično postižu dobru generalizaciju.

Ključ SVM-ove moći je sposobnost korišćenja **kernel funkcija** za upravljanje nelinearnim odnosima. Podaci se mogu implicitno transformisati u prostor karakteristika više dimenzije gde može postojati linearni separator. Uobičajeni kerneli uključuju polinomski, radijalnu baznu funkciju (RBF) i sigmoid. Na primer, ako klase mrežnog saobraćaja nisu linearno odvojive u sirovom prostoru karakteristika, RBF kernel može ih mapirati u višu dimenziju gde SVM pronalazi linearno podelu (što odgovara nelinearnoj granici u originalnom prostoru). Fleksibilnost izbora kernela omogućava SVM-ovima da se suoče sa raznim problemima.

SVM-ovi su poznati po dobrom performansu u situacijama sa visokodimenzionalnim prostorima karakteristika (kao što su podaci o tekstu ili sekvence opcode-a malvera) i u slučajevima kada je broj karakteristika veliki u odnosu na broj uzoraka. Bili su popularni u mnogim ranim aplikacijama u sajber bezbednosti kao što su klasifikacija malvera i detekcija upada zasnovana na anomalijama 2000-ih, često pokazujući visoku tačnost.

Međutim, SVM-ovi se ne skaliraju lako na veoma velike skupove podataka (kompleksnost obuke je super-linear u broju uzoraka, a korišćenje memorije može biti visoko jer može biti potrebno da se čuva mnogo support vectors). U praksi, za zadatke kao što je detekcija mrežnih upada sa milionima zapisa, SVM može biti previše spor bez pažljivog uzorkovanja ili korišćenja aproksimativnih metoda.

#### **Ključne karakteristike SVM-a:**

-   **Tip problema:** Klasifikacija (binarna ili višeklasna putem jedan-na-jedan/jedan-na-ostale) i varijante regresije. Često se koristi u binarnoj klasifikaciji sa jasnim razdvajanjem margina.

-   **Interpretabilnost:** Srednja -- SVM-ovi nisu toliko interpretabilni kao odlučujuća stabla ili logistička regresija. Iako možete identifikovati koje tačke podataka su support vectors i steći neki osećaj o tome koje karakteristike bi mogle biti uticajne (kroz težine u slučaju linearnih kernela), u praksi se SVM-ovi (posebno sa nelinearnim kernelima) tretiraju kao klasifikatori crne kutije.

-   **Prednosti:** Efikasni u visokodimenzionalnim prostorima; mogu modelovati složene granice odluka uz pomoć kernel trika; otporni na prekomerno prilagođavanje ako je razmak maksimizovan (posebno sa odgovarajućim parametrom regularizacije C); dobro funkcionišu čak i kada klase nisu odvojene velikom udaljenošću (pronalaze najbolju kompromisnu granicu).

-   **Ograničenja:** **Računarski intenzivni** za velike skupove podataka (i obuka i predikcija se loše skaliraju kako podaci rastu). Zahteva pažljivo podešavanje parametara kernela i regularizacije (C, tip kernela, gamma za RBF, itd.). Ne pruža direktno probabilističke izlaze (iako se može koristiti Platt scaling za dobijanje verovatnoća). Takođe, SVM-ovi mogu biti osetljivi na izbor parametara kernela --- loš izbor može dovesti do nedovoljno ili prekomerno prilagođavanje.

*Upotreba u sajber bezbednosti:* SVM-ovi su korišćeni u **detekciji malvera** (npr. klasifikacija fajlova na osnovu ekstraktovanih karakteristika ili sekvenci opcode-a), **detekciji mrežnih anomalija** (klasifikacija saobraćaja kao normalnog ili zlonamernog), i **detekciji phishing-a** (korišćenje karakteristika URL-ova). Na primer, SVM bi mogao uzeti karakteristike e-pošte (broj određenih ključnih reči, ocene reputacije pošiljaoca, itd.) i klasifikovati je kao phishing ili legitimnu. Takođe su primenjeni na **detekciju upada** na skupovima karakteristika kao što je KDD, često postižući visoku tačnost na račun računanja.

<details>
<summary>Primer -- SVM za klasifikaciju malvera:</summary>
Ponovo ćemo koristiti skup podataka o phishing veb sajtovima, ovaj put sa SVM-om. Pošto SVM-ovi mogu biti spori, koristićemo podskup podataka za obuku ako je potrebno (skup podataka ima oko 11k instanci, što SVM može razumno obraditi). Koristićemo RBF kernel koji je uobičajen izbor za nelinearne podatke, i omogućićemo procene verovatnoće za izračunavanje ROC AUC.
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
SVM model će izbaciti metrike koje možemo uporediti sa logističkom regresijom na istom zadatku. Možda ćemo otkriti da SVM postiže visoku tačnost i AUC ako su podaci dobro razdvojeni karakteristikama. S druge strane, ako je skup podataka imao puno šuma ili preklapajućih klasa, SVM možda neće značajno nadmašiti logističku regresiju. U praksi, SVM-ovi mogu dati podsticaj kada postoje složene, nelinearne veze između karakteristika i klase -- RBF kernel može uhvatiti zakrivljene granice odluke koje bi logistička regresija propustila. Kao i kod svih modela, pažljivo podešavanje `C` (regularizacija) i parametara kernela (kao što je `gamma` za RBF) je potrebno da bi se izbalansirali pristrasnost i varijansa.

</details>

#### Razlika između logističke regresije i SVM

| Aspekt | **Logistička regresija** | **Podrška vektorskim mašinama** |
|---|---|---|
| **Funkcija cilja** | Minimizira **log‑gubitak** (kros-entropija). | Maksimizuje **marginu** dok minimizira **hinge‑gubitak**. |
| **Granica odluke** | Pronalazi **najbolji hiperplan** koji modeluje _P(y\|x)_. | Pronalazi **hiperplan sa maksimalnom marginom** (najveći razmak do najbližih tačaka). |
| **Izlaz** | **Probabilistički** – daje kalibrisane verovatnoće klasa putem σ(w·x + b). | **Deterministički** – vraća oznake klasa; verovatnoće zahtevaju dodatni rad (npr. Platt skaliranje). |
| **Regularizacija** | L2 (podrazumevano) ili L1, direktno balansira pod/over‑fitting. | C parametar trguje širinom margine naspram pogrešnih klasifikacija; parametri kernela dodaju složenost. |
| **Kerneli / Nelinearni** | Prirodni oblik je **linearan**; nelinearnost se dodaje inženjeringom karakteristika. | Ugrađeni **kernel trik** (RBF, polinom, itd.) omogućava modelovanje složenih granica u visokom dimenzionalnom prostoru. |
| **Skalabilnost** | Rešava konveksnu optimizaciju u **O(nd)**; dobro se nosi sa veoma velikim n. | Obuka može biti **O(n²–n³)** u memoriji/vremenu bez specijalizovanih rešenja; manje je prijateljski prema ogromnom n. |
| **Interpretabilnost** | **Visoka** – težine pokazuju uticaj karakteristika; odnos šansi intuitivan. | **Niska** za nelinearne kernela; podržavajući vektori su retki, ali nisu laki za objašnjenje. |
| **Osetljivost na outliere** | Koristi glatki log‑gubitak → manje osetljiv. | Hinge‑gubitak sa tvrdim marginama može biti **osetljiv**; mekana margina (C) ublažava. |
| **Tipični slučajevi upotrebe** | Kreditno ocenjivanje, medicinski rizik, A/B testiranje – gde **verovatnoće i objašnjivost** imaju značaj. | Klasifikacija slika/teksta, bioinformatika – gde **složenih granica** i **visoko-dimenzionalni podaci** imaju značaj. |

* **Ako vam trebaju kalibrisane verovatnoće, interpretabilnost, ili radite sa ogromnim skupovima podataka — izaberite logističku regresiju.**
* **Ako vam treba fleksibilan model koji može uhvatiti nelinearne odnose bez ručnog inženjeringa karakteristika — izaberite SVM (sa kernelima).**
* Obe optimizuju konveksne ciljeve, tako da su **globalni minimumi zagarantovani**, ali SVM-ovi kerneli dodaju hiper-parametre i troškove računanja.

### Naivni Bejz

Naivni Bejz je porodica **probabilističkih klasifikatora** zasnovana na primeni Bejzove teoreme sa jakom pretpostavkom nezavisnosti između karakteristika. I pored ove "naivne" pretpostavke, Naivni Bejz često iznenađujuće dobro funkcioniše za određene primene, posebno one koje uključuju tekst ili kategorijske podatke, kao što je detekcija spama.

#### Bejzova teorema

Bejzova teorema je osnova Naivnih Bejz klasifikatora. Ona povezuje uslovne i marginalne verovatnoće slučajnih događaja. Formula je:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gde:
- `P(A|B)` je posteriorna verovatnoća klase `A` s obzirom na karakteristiku `B`.
- `P(B|A)` je verovatnoća karakteristike `B` s obzirom na klasu `A`.
- `P(A)` je priorna verovatnoća klase `A`.
- `P(B)` je priorna verovatnoća karakteristike `B`.

Na primer, ako želimo da klasifikujemo da li je tekst napisan od strane deteta ili odrasle osobe, možemo koristiti reči u tekstu kao karakteristike. Na osnovu nekih inicijalnih podataka, Naive Bayes klasifikator će prethodno izračunati verovatnoće svake reči da bude u svakoj potencijalnoj klasi (dete ili odrasla osoba). Kada se da novi tekst, izračunaće verovatnoću svake potencijalne klase s obzirom na reči u tekstu i izabrati klasu sa najvišom verovatnoćom.

Kao što možete videti u ovom primeru, Naive Bayes klasifikator je vrlo jednostavan i brz, ali pretpostavlja da su karakteristike nezavisne, što nije uvek slučaj u podacima iz stvarnog sveta.

#### Tipovi Naive Bayes klasifikatora

Postoji nekoliko tipova Naive Bayes klasifikatora, u zavisnosti od tipa podataka i raspodele karakteristika:
- **Gaussian Naive Bayes**: Pretpostavlja da karakteristike prate Gaussovu (normalnu) raspodelu. Pogodan je za kontinuirane podatke.
- **Multinomial Naive Bayes**: Pretpostavlja da karakteristike prate multinomijalnu raspodelu. Pogodan je za diskretne podatke, kao što su broj reči u klasifikaciji teksta.
- **Bernoulli Naive Bayes**: Pretpostavlja da su karakteristike binarne (0 ili 1). Pogodan je za binarne podatke, kao što su prisutnost ili odsutnost reči u klasifikaciji teksta.
- **Categorical Naive Bayes**: Pretpostavlja da su karakteristike kategorijske varijable. Pogodan je za kategorijske podatke, kao što je klasifikacija voća na osnovu njihove boje i oblika.

#### **Ključne karakteristike Naive Bayes-a:**

-   **Tip problema:** Klasifikacija (binarna ili višeklasna). Često se koristi za zadatke klasifikacije teksta u sajber bezbednosti (spam, phishing, itd.).

-   **Interpretabilnost:** Srednja -- nije tako direktno interpretabilan kao stablo odluka, ali se mogu pregledati naučene verovatnoće (npr. koje reči su najverovatnije u spam vs ham emailovima). Oblik modela (verovatnoće za svaku karakteristiku s obzirom na klasu) može se razumeti ako je potrebno.

-   **Prednosti:** **Veoma brza** obuka i predikcija, čak i na velikim skupovima podataka (linearno u broju instanci * broj karakteristika). Zahteva relativno mali broj podataka za pouzdano procenjivanje verovatnoća, posebno uz odgovarajuće izravnavanje. Često je iznenađujuće tačan kao osnovna linija, posebno kada karakteristike nezavisno doprinose dokazima za klasu. Dobro funkcioniše sa podacima visoke dimenzionalnosti (npr. hiljade karakteristika iz teksta). Nema potrebe za složenim podešavanjima osim postavljanja parametra izravnavanja.

-   **Ograničenja:** Pretpostavka nezavisnosti može ograničiti tačnost ako su karakteristike visoko korelisane. Na primer, u mrežnim podacima, karakteristike poput `src_bytes` i `dst_bytes` mogu biti korelisane; Naive Bayes neće uhvatiti tu interakciju. Kako veličina podataka postaje veoma velika, izražajniji modeli (poput ansambala ili neuronskih mreža) mogu nadmašiti NB učenjem zavisnosti karakteristika. Takođe, ako je potrebna određena kombinacija karakteristika za identifikaciju napada (ne samo pojedinačne karakteristike nezavisno), NB će imati poteškoća.

> [!TIP]
> *Upotrebe u sajber bezbednosti:* Klasična upotreba je **detekcija spama** -- Naive Bayes je bio srž ranih filtera za spam, koristeći frekvencije određenih tokena (reči, fraze, IP adrese) za izračunavanje verovatnoće da je email spam. Takođe se koristi u **detekciji phishing emailova** i **klasifikaciji URL-ova**, gde prisutnost određenih ključnih reči ili karakteristika (poput "login.php" u URL-u, ili `@` u putanji URL-a) doprinosi verovatnoći phishinga. U analizi malvera, moglo bi se zamisliti Naive Bayes klasifikator koji koristi prisutnost određenih API poziva ili dozvola u softveru da predvidi da li je to malver. Iako napredniji algoritmi često bolje funkcionišu, Naive Bayes ostaje dobra osnovna linija zbog svoje brzine i jednostavnosti.

<details>
<summary>Primer -- Naive Bayes za detekciju phishinga:</summary>
Da bismo demonstrirali Naive Bayes, koristićemo Gaussian Naive Bayes na NSL-KDD skupu podataka o upadima (sa binarnim oznakama). Gaussian NB će tretirati svaku karakteristiku kao da prati normalnu raspodelu po klasi. Ovo je gruba procena jer su mnoge mrežne karakteristike diskretne ili veoma asimetrične, ali pokazuje kako bi se NB primenio na podatke sa kontinuiranim karakteristikama. Takođe bismo mogli izabrati Bernoulli NB na skupu podataka binarnih karakteristika (poput skupa aktiviranih upozorenja), ali ćemo se ovde držati NSL-KDD radi kontinuiteta.
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
Ovaj kod obučava Naive Bayes klasifikator za otkrivanje napada. Naive Bayes će izračunati stvari poput `P(service=http | Attack)` i `P(Service=http | Normal)` na osnovu podataka za obuku, pretpostavljajući nezavisnost među karakteristikama. Zatim će koristiti ove verovatnoće da klasifikuje nove veze kao normalne ili napad na osnovu posmatranih karakteristika. Performanse NB na NSL-KDD možda neće biti tako visoke kao kod naprednijih modela (pošto je nezavisnost karakteristika prekršena), ali često su zadovoljavajuće i dolaze sa prednošću ekstremne brzine. U scenarijima poput filtriranja e-pošte u realnom vremenu ili inicijalne triage URL-ova, Naive Bayes model može brzo označiti očigledno zlonamerne slučajeve uz nisku potrošnju resursa.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors je jedan od najjednostavnijih algoritama mašinskog učenja. To je **neparametrijska, metoda zasnovana na instancama** koja donosi predikcije na osnovu sličnosti sa primerima u skupu podataka za obuku. Ideja za klasifikaciju je: da bi se klasifikovala nova tačka podataka, pronađite **k** najbližih tačaka u podacima za obuku (njeni "najbliži susedi") i dodelite većinsku klasu među tim susedima. "Bliskost" se definiše metrikom udaljenosti, obično Euklidskom udaljenošću za numeričke podatke (druge udaljenosti mogu se koristiti za različite tipove karakteristika ili problema).

K-NN zahteva *nema eksplicitnog obučavanja* -- faza "obuke" je samo skladištenje skupa podataka. Sav rad se odvija tokom upita (predikcije): algoritam mora izračunati udaljenosti od tačke upita do svih tačaka obuke da bi pronašao najbliže. Ovo čini vreme predikcije **linearno u broju uzoraka obuke**, što može biti skupo za velike skupove podataka. Zbog toga je k-NN najbolje prilagođen manjim skupovima podataka ili scenarijima gde možete trgovati memorijom i brzinom za jednostavnost.

Uprkos svojoj jednostavnosti, k-NN može modelovati veoma složene granice odluka (pošto efektivno granica odluke može biti bilo kojeg oblika koji diktira raspodela primera). Obično dobro funkcioniše kada je granica odluke veoma nepravilna i imate puno podataka -- suštinski dopuštajući podacima da "govore za sebe". Međutim, u visokim dimenzijama, metričke udaljenosti mogu postati manje značajne (prokletstvo dimenzionalnosti), a metoda može imati poteškoća osim ako nemate ogroman broj uzoraka.

*Upotrebe u sajber bezbednosti:* k-NN je primenjen na detekciju anomalija -- na primer, sistem za detekciju upada može označiti mrežni događaj kao zlonameran ako su većina njegovih najbližih suseda (prethodni događaji) bili zlonamerni. Ako normalni saobraćaj formira klastere, a napadi su izuzeci, K-NN pristup (sa k=1 ili malim k) suštinski radi **detekciju anomalija najbližih suseda**. K-NN je takođe korišćen za klasifikaciju porodica malvera pomoću binarnih vektora karakteristika: nova datoteka može biti klasifikovana kao određena porodica malvera ako je veoma blizu (u prostoru karakteristika) poznatim instancama te porodice. U praksi, k-NN nije tako uobičajen kao skalabilniji algoritmi, ali je konceptualno jednostavan i ponekad se koristi kao osnovna linija ili za probleme malih razmera.

#### **Ključne karakteristike k-NN:**

-   **Tip problema:** Klasifikacija (i regresione varijante postoje). To je *lenja metoda učenja* -- nema eksplicitnog prilagođavanja modela.

-   **Interpretabilnost:** Niska do srednja -- ne postoji globalni model ili sažeto objašnjenje, ali se rezultati mogu interpretirati gledajući na najbliže susede koji su uticali na odluku (npr., "ovaj mrežni tok je klasifikovan kao zlonameran jer je sličan ovim 3 poznatim zlonamernim tokovima"). Dakle, objašnjenja mogu biti zasnovana na primerima.

-   **Prednosti:** Veoma jednostavno za implementaciju i razumevanje. Ne postavlja pretpostavke o raspodeli podataka (neparametrijski). Može prirodno da se nosi sa višeklasnim problemima. To je **adaptivno** u smislu da granice odluka mogu biti veoma složene, oblikovane raspodelom podataka.

-   **Ograničenja:** Predikcija može biti spora za velike skupove podataka (mora izračunati mnoge udaljenosti). Intenzivno koristi memoriju -- skladišti sve podatke za obuku. Performanse opadaju u prostorima sa visokim dimenzijama jer sve tačke teže postaju gotovo ekvivalentne (što čini koncept "najbližeg" manje značajnim). Potrebno je pravilno odabrati *k* (broj suseda) -- previše malo k može biti bučno, previše veliko k može uključiti irelevantne tačke iz drugih klasa. Takođe, karakteristike bi trebale biti pravilno skalirane jer su izračunavanja udaljenosti osetljiva na skalu.

<details>
<summary>Primer -- k-NN za detekciju phishing-a:</summary>

Ponovo ćemo koristiti NSL-KDD (binarna klasifikacija). Pošto je k-NN računski zahtevan, koristićemo podskup podataka za obuku kako bismo ga održali izvodljivim u ovoj demonstraciji. Izabraćemo, recimo, 20.000 uzoraka obuke od ukupno 125k, i koristiti k=5 suseda. Nakon obuke (zaista samo skladištenje podataka), procenićemo na testnom skupu. Takođe ćemo skalirati karakteristike za izračunavanje udaljenosti kako bismo osigurali da nijedna pojedinačna karakteristika ne dominira zbog skale.
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
Model k-NN će klasifikovati vezu gledajući na 5 najbližih veza u podskupu skupa za obuku. Ako, na primer, 4 od tih suseda predstavljaju napade (anomalije), a 1 je normalan, nova veza će biti klasifikovana kao napad. Performanse mogu biti razmerne, iako često nisu tako visoke kao kod dobro podešenih Random Forest ili SVM na istim podacima. Međutim, k-NN ponekad može biti izuzetno efikasan kada su raspodele klasa veoma nepravilne i kompleksne -- efikasno koristeći pretragu zasnovanu na memoriji. U sajber bezbednosti, k-NN (sa k=1 ili malim k) može se koristiti za detekciju poznatih obrazaca napada po uzoru, ili kao komponenta u složenijim sistemima (npr., za klasterizaciju i zatim klasifikaciju na osnovu članstva u klasteru).

### Gradient Boosting Machines (npr., XGBoost)

Gradient Boosting Machines su među najmoćnijim algoritmima za strukturirane podatke. **Gradient boosting** se odnosi na tehniku izgradnje ansambla slabih učenika (često odlučujućih stabala) na sekvencijalan način, gde svaki novi model ispravlja greške prethodnog ansambla. Za razliku od bagging-a (Random Forests) koji gradi stabla paralelno i prosečno ih, boosting gradi stabla *jedno po jedno*, svako se fokusira više na instance koje su prethodna stabla pogrešno predvidela.

Najpopularnije implementacije u poslednjim godinama su **XGBoost**, **LightGBM**, i **CatBoost**, koje su sve biblioteke za odlučujuća stabla sa gradient boosting-om (GBDT). One su bile izuzetno uspešne na takmičenjima u mašinskom učenju i aplikacijama, često **postižuci vrhunske performanse na tabelarnim skupovima podataka**. U sajber bezbednosti, istraživači i praktičari su koristili stabla sa gradient boosting-om za zadatke kao što su **detekcija malvera** (koristeći karakteristike izvučene iz fajlova ili ponašanja u toku rada) i **detekcija mrežnih upada**. Na primer, model sa gradient boosting-om može kombinovati mnoge slabe pravila (stabla) kao što su "ako ima mnogo SYN paketa i neobičan port -> verovatno skeniranje" u jakog kompozitnog detektora koji uzima u obzir mnoge suptilne obrasce.

Zašto su pojačana stabla tako efikasna? Svako stablo u sekvenci se obučava na *rezidualnim greškama* (gradijentima) predikcija trenutnog ansambla. Na taj način, model postepeno **"pojačava"** oblasti gde je slab. Korišćenje odlučujućih stabala kao osnovnih učenika znači da konačni model može uhvatiti kompleksne interakcije i nelinearne odnose. Takođe, boosting inherentno ima oblik ugrađene regularizacije: dodavanjem mnogih malih stabala (i korišćenjem stope učenja za skaliranje njihovih doprinosa), često dobro generalizuje bez velikog prekomernog prilagođavanja, pod uslovom da su izabrani odgovarajući parametri.

#### **Ključne karakteristike Gradient Boosting-a:**

-   **Tip problema:** Pretežno klasifikacija i regresija. U bezbednosti, obično klasifikacija (npr., binarna klasifikacija veze ili fajla). Rukuje binarnim, višeklasnim (uz odgovarajući gubitak), pa čak i problemima rangiranja.

-   **Interpretabilnost:** Niska do srednja. Dok je jedno pojačano stablo malo, ceo model može imati stotine stabala, što nije lako za ljudsko tumačenje kao celina. Međutim, kao i Random Forest, može pružiti ocene važnosti karakteristika, a alati poput SHAP (SHapley Additive exPlanations) mogu se koristiti za tumačenje pojedinačnih predikcija do određene mere.

-   **Prednosti:** Često **najbolje performanse** algoritma za strukturirane/tabelarne podatke. Može detektovati kompleksne obrasce i interakcije. Ima mnogo podešavanja (broj stabala, dubina stabala, stopa učenja, regularizacione stavke) za prilagođavanje složenosti modela i sprečavanje prekomernog prilagođavanja. Moderne implementacije su optimizovane za brzinu (npr., XGBoost koristi informacije o drugom redu gradijenta i efikasne strukture podataka). Obično bolje rukuje neuravnoteženim podacima kada se kombinuje sa odgovarajućim funkcijama gubitka ili podešavanjem težina uzoraka.

-   **Ograničenja:** Složenije je za podešavanje od jednostavnijih modela; obuka može biti spora ako su stabla duboka ili je broj stabala veliki (iako je obično brža od obuke uporedivih dubokih neuronskih mreža na istim podacima). Model može prekomerno da se prilagodi ako nije podešen (npr., previše dubokih stabala sa nedovoljnom regularizacijom). Zbog mnogih hiperparametara, efikasno korišćenje gradient boosting-a može zahtevati više stručnosti ili eksperimentisanja. Takođe, kao i metode zasnovane na stablima, ne rukuje inherentno veoma retkim visokodimenzionalnim podacima tako efikasno kao linearni modeli ili Naive Bayes (iako se može primeniti, npr., u klasifikaciji teksta, ali možda neće biti prvi izbor bez inženjeringa karakteristika).

> [!TIP]
> *Upotrebe u sajber bezbednosti:* Gotovo svuda gde bi se moglo koristiti odlučujuće stablo ili random forest, model sa gradient boosting-om može postići bolju tačnost. Na primer, **takmičenja u detekciji malvera** kompanije **Microsoft** su videla veliku upotrebu XGBoost-a na inženjerskim karakteristikama iz binarnih fajlova. Istraživanja u **detekciji mrežnih upada** često izveštavaju o vrhunskim rezultatima sa GBDT-ima (npr., XGBoost na CIC-IDS2017 ili UNSW-NB15 skupovima podataka). Ovi modeli mogu uzeti širok spektar karakteristika (tipovi protokola, učestalost određenih događaja, statističke karakteristike saobraćaja, itd.) i kombinovati ih za detekciju pretnji. U detekciji phishing-a, gradient boosting može kombinovati leksikalne karakteristike URL-ova, karakteristike reputacije domena i karakteristike sadržaja stranice kako bi postigao veoma visoku tačnost. Ansambl pristup pomaže da se pokriju mnogi rubni slučajevi i suptilnosti u podacima.

<details>
<summary>Primer -- XGBoost za detekciju phishing-a:</summary>
Koristićemo klasifikator sa gradient boosting-om na skupu podataka o phishing-u. Da bismo pojednostavili stvari i učinili ih samostalnim, koristićemo `sklearn.ensemble.GradientBoostingClassifier` (koji je sporija, ali jednostavna implementacija). Obično bi se moglo koristiti `xgboost` ili `lightgbm` biblioteke za bolje performanse i dodatne karakteristike. Obučićemo model i evaluirati ga slično kao pre.
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
Gradient boosting model će verovatno postići veoma visoku tačnost i AUC na ovom phishing skupu podataka (često ovi modeli mogu premašiti 95% tačnosti uz pravilno podešavanje na takvim podacima, kao što se vidi u literaturi. Ovo pokazuje zašto se GBDT smatraju *"najboljim modelom za tabelarne skupove podataka"* -- često nadmašuju jednostavnije algoritme hvatajući složene obrasce. U kontekstu sajber bezbednosti, to bi moglo značiti hvatanje više phishing sajtova ili napada uz manje promašaja. Naravno, treba biti oprezan u vezi sa prekomernim prilagođavanjem -- obično bismo koristili tehnike poput unakrsne validacije i pratili performanse na validacionom skupu prilikom razvijanja takvog modela za implementaciju.

</details>

### Kombinovanje modela: Ensemble učenje i Stacking

Ensemble učenje je strategija **kombinovanja više modela** kako bi se poboljšale ukupne performanse. Već smo videli specifične ensemble metode: Random Forest (ensemble drveća putem bagging-a) i Gradient Boosting (ensemble drveća putem sekvencijalnog boosting-a). Ali ensemble se mogu kreirati i na druge načine, kao što su **voting ensemble** ili **stacked generalization (stacking)**. Glavna ideja je da različiti modeli mogu hvatanje različitih obrazaca ili imati različite slabosti; kombinovanjem možemo **kompenzovati greške svakog modela snagama drugog**.

-   **Voting Ensemble:** U jednostavnom voting klasifikatoru, obučavamo više različitih modela (recimo, logističku regresiju, stablo odlučivanja i SVM) i omogućavamo im da glasaju o konačnoj predikciji (većina glasova za klasifikaciju). Ako težimo glasove (npr., veću težinu preciznijim modelima), to je težinski voting sistem. Ovo obično poboljšava performanse kada su pojedinačni modeli razmerno dobri i nezavisni -- ensemble smanjuje rizik od greške pojedinačnog modela jer drugi mogu ispraviti. To je kao imati panel stručnjaka umesto jednog mišljenja.

-   **Stacking (Stacked Ensemble):** Stacking ide korak dalje. Umesto jednostavnog glasanja, obučava **meta-model** da **nauči kako najbolje kombinovati predikcije** osnovnih modela. Na primer, obučite 3 različita klasifikatora (osnovne učenike), a zatim njihove izlaze (ili verovatnoće) koristite kao karakteristike u meta-klasifikatoru (često jednostavnom modelu poput logističke regresije) koji uči optimalan način da ih pomeša. Meta-model se obučava na validacionom skupu ili putem unakrsne validacije kako bi se izbeglo prekomerno prilagođavanje. Stacking često može nadmašiti jednostavno glasanje učenjem *koje modele više verovati u kojim okolnostima*. U sajber bezbednosti, jedan model može biti bolji u hvatanju mrežnih skeniranja dok je drugi bolji u hvatanju malware beaconinga; stacking model bi mogao naučiti da se oslanja na svaki odgovarajuće.

Ensemble, bilo putem glasanja ili stackinga, obično **povećavaju tačnost** i robusnost. Nedostatak je povećana složenost i ponekad smanjena interpretabilnost (iako neki ensemble pristupi poput proseka stabala odlučivanja i dalje mogu pružiti uvid, npr., važnost karakteristika). U praksi, ako operativna ograničenja dozvoljavaju, korišćenje ensemble može dovesti do viših stopa detekcije. Mnoge pobedničke rešenja u izazovima sajber bezbednosti (i Kaggle takmičenjima uopšte) koriste ensemble tehnike kako bi izvukli poslednji deo performansi.

<details>
<summary>Primer -- Voting Ensemble za detekciju phishing-a:</summary>
Da ilustrujemo stacking modela, kombinovaćemo nekoliko modela o kojima smo razgovarali na phishing skupu podataka. Koristićemo logističku regresiju, stablo odlučivanja i k-NN kao osnovne učenike, a koristimo Random Forest kao meta-učenika da agregiramo njihove predikcije. Meta-učenik će biti obučen na izlazima osnovnih učenika (koristeći unakrsnu validaciju na skupu za obuku). Očekujemo da će stacked model imati performanse jednake ili malo bolje od pojedinačnih modela.
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
Stacked ensemble koristi komplementarne snage osnovnih modela. Na primer, logistička regresija može obraditi linearne aspekte podataka, odlučujuće stablo može uhvatiti specifične interakcije nalik pravilima, a k-NN može biti odličan u lokalnim okruženjima prostora karakteristika. Meta-model (ovde random forest) može naučiti kako da proceni ove ulaze. Rezultantne metrike često pokazuju poboljšanje (čak i ako je malo) u odnosu na metrike bilo kog pojedinačnog modela. U našem primeru phishinga, ako je logistički model imao F1 od recimo 0.95, a stablo 0.94, stack bi mogao postići 0.96 preuzimajući gde svaki model greši.

Metode ansambla poput ove pokazuju princip da *"kombinovanje više modela obično dovodi do boljeg generalizovanja"*. U sajber bezbednosti, ovo se može implementirati tako što će se imati više motora za detekciju (jedan može biti zasnovan na pravilima, jedan mašinsko učenje, jedan zasnovan na anomalijama) i zatim sloj koji agregira njihove alarme -- efikasno oblik ansambla -- kako bi se donela konačna odluka sa većim poverenjem. Kada se implementiraju takvi sistemi, mora se razmotriti dodatna složenost i osigurati da ansambl ne postane previše težak za upravljanje ili objašnjenje. Ali sa stanovišta tačnosti, ansambli i stacking su moćni alati za poboljšanje performansi modela.

</details>

## References

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
