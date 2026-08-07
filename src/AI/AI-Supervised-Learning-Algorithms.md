# Algoritmi nadgledanog učenja

{{#include ../banners/hacktricks-training.md}}

## Osnovne informacije

Nadgledano učenje koristi označene podatke za obučavanje modela koji mogu da daju predviđanja za nove, do tada neviđene ulaze. U sajber-bezbednosti, nadgledano mašinsko učenje se široko primenjuje na zadatke kao što su detekcija upada (klasifikovanje mrežnog saobraćaja kao *normalnog* ili *napada*), detekcija malvera (razlikovanje zlonamernog softvera od bezopasnog), detekcija phishing-a (prepoznavanje lažnih veb-sajtova ili imejlova) i filtriranje spama, između ostalog.<sup>[[1]](#references)</sup> Svaki algoritam ima svoje prednosti i odgovara različitim vrstama problema (klasifikacija ili regresija). U nastavku razmatramo ključne algoritme nadgledanog učenja, objašnjavamo kako rade i prikazujemo njihovu upotrebu na stvarnim skupovima podataka iz sajber-bezbednosti. Takođe razmatramo kako kombinovanje modela (ensemble learning) često može poboljšati performanse predviđanja.

## Algoritmi

-   **Linearna regresija:** Osnovni regresioni algoritam za predviđanje numeričkih ishoda prilagođavanjem linearne jednačine podacima.

-   **Logistička regresija:** Klasifikacioni algoritam (uprkos svom nazivu) koji koristi logističku funkciju za modelovanje verovatnoće binarnog ishoda.

-   **Stabla odlučivanja:** Modeli u obliku stabla koji dele podatke na osnovu osobina kako bi donosili predviđanja; često se koriste zbog svoje interpretabilnosti.

-   **Slučajne šume:** Ensemble stabala odlučivanja (putem bagging-a) koji poboljšava tačnost i smanjuje overfitting.

-   **Mašine potpornih vektora (SVM):** Klasifikatori sa maksimalnom marginom koji pronalaze optimalnu razdvajajuću hiperravan; mogu koristiti kernels za nelinearne podatke.

-   **Naive Bayes:** Probabilistički klasifikator zasnovan na Bayes-ovoj teoremi, uz pretpostavku nezavisnosti osobina, poznato korišćen u filtriranju spama.

-   **k-najbližih suseda (k-NN):** Jednostavan „instance-based“ klasifikator koji uzorku dodeljuje oznaku na osnovu većinske klase njegovih najbližih suseda.

-   **Gradient Boosting Machines:** Ensemble modeli (npr. XGBoost, LightGBM) koji izgrađuju snažan prediktor sekvencijalnim dodavanjem slabijih učača (obično stabala odlučivanja).

Svaki odeljаk u nastavku pruža poboljšan opis algoritma i **Python primer koda** koji koristi biblioteke kao što su `pandas` i `scikit-learn` (i `PyTorch` u primeru neuronske mreže). Primeri koriste javno dostupne skupove podataka iz sajber-bezbednosti (kao što su NSL-KDD za detekciju upada i skup podataka Phishing Websites) i prate doslednu strukturu:

1.  **Učitajte skup podataka** (preuzmite ga putem URL-a ako je dostupan).

2.  **Preprocesirajte podatke** (npr. kodirajte kategorijske osobine, skalirajte vrednosti i podelite podatke na skupove za obuku i testiranje).

3.  **Obučite model** na podacima za obuku.

4.  **Izvršite evaluaciju** na testnom skupu pomoću metrika: tačnost, preciznost, odziv, F1-score i ROC AUC za klasifikaciju (i srednja kvadratna greška za regresiju).

Hajde da detaljno razmotrimo svaki algoritam:

### Linearna regresija

Linearna regresija je algoritam **regresije** koji se koristi za predviđanje kontinuiranih numeričkih vrednosti. Pretpostavlja linearnu vezu između ulaznih osobina (nezavisnih promenljivih) i izlaza (zavisne promenljive). Model pokušava da prilagodi pravu liniju (ili hiperravan u višim dimenzijama) koja na najbolji način opisuje odnos između osobina i cilja. To se obično postiže minimizovanjem zbira kvadratnih grešaka između predviđenih i stvarnih vrednosti (metoda običnih najmanjih kvadrata).<sup>[[2]](#references)</sup>

Najjednostavniji način predstavljanja linearne regresije je pomoću prave:
```plaintext
y = mx + b
```
Gde:

- `y` je predviđena vrednost (izlaz)
- `m` je nagib prave (koeficijent)
- `x` je ulazna karakteristika
- `b` je y-odsečak

Cilj linearne regresije je pronalaženje prave koja se najbolje uklapa i minimizuje razliku između predviđenih i stvarnih vrednosti u skupu podataka. Naravno, ovo je veoma jednostavno; bila bi to prava linija koja razdvaja 2 kategorije, ali ako se dodaju dodatne dimenzije, prava postaje složenija:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Slučajevi upotrebe u sajber-bezbednosti:* Sama linearna regresija se ređe koristi za osnovne bezbednosne zadatke (koji su često klasifikacioni), ali se može primeniti za predviđanje numeričkih ishoda. Na primer, linearna regresija može da se koristi za **predviđanje obima mrežnog saobraćaja** ili **procenu broja napada u određenom vremenskom periodu** na osnovu istorijskih podataka. Takođe može da predvidi skor rizika ili očekivano vreme do detekcije napada na osnovu određenih metrika sistema. U praksi se klasifikacioni algoritmi (kao što su logistička regresija ili stabla) češće koriste za detekciju intruzija ili malware-a, ali linearna regresija predstavlja osnovu i korisna je za analize usmerene na regresiju.

#### **Ključne karakteristike linearne regresije:**

-   **Tip problema:** Regresija (predviđanje kontinuiranih vrednosti). Nije pogodna za direktnu klasifikaciju osim ako se na izlaz ne primeni prag.

-   **Interpretabilnost:** Visoka -- koeficijenti se jednostavno tumače i prikazuju linearni uticaj svake karakteristike.

-   **Prednosti:** Jednostavna je i brza; predstavlja dobru osnovu za regresione zadatke; dobro funkcioniše kada je stvarna veza približno linearna.

-   **Ograničenja:** Ne može da obuhvati složene ili nelinearne veze (bez ručnog inženjeringa karakteristika); sklona je underfitting-u ako su veze nelinearne; osetljiva je na outlier-e koji mogu da iskrive rezultate.

-   **Pronalaženje najboljeg uklapanja:** Da bismo pronašli liniju najboljeg uklapanja koja razdvaja moguće kategorije, koristimo metod pod nazivom **Ordinary Least Squares (OLS)**. Ovaj metod minimizuje zbir kvadriranih razlika između posmatranih vrednosti i vrednosti koje predviđa linearni model.

<details>
<summary>Primer -- Predviđanje trajanja konekcije (regresija) u skupu podataka o intruzijama
</summary>
U nastavku prikazujemo linearnu regresiju koristeći NSL-KDD skup podataka za sajber-bezbednost. Tretiraćemo ovo kao regresioni problem tako što ćemo predviđati `duration` mrežnih konekcija na osnovu drugih karakteristika. (U stvarnosti, `duration` je jedna od karakteristika skupa NSL-KDD; ovde ga koristimo samo za prikaz regresije.) Učitaćemo skup podataka, prethodno obraditi podatke (kodirati kategoričke karakteristike), obučiti model linearne regresije i proceniti Mean Squared Error (MSE) i R² skor na testnom skupu.
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
U ovom primeru, model linear regression pokušava da predvidi `duration` konekcije na osnovu drugih mrežnih karakteristika. Performanse merimo pomoću Mean Squared Error (MSE) i R². R² blizu vrednosti 1.0 ukazivao bi na to da model objašnjava većinu varijanse u `duration`, dok nizak ili negativan R² ukazuje na loše uklapanje. (Nemojte se iznenaditi ako je R² ovde nizak -- predviđanje `duration` može biti teško na osnovu datih karakteristika, a linear regression možda ne može da obuhvati obrasce ako su složeni.)
</details>

### Logistic Regression

Logistic regression je **classification** algoritam koji modeluje verovatnoću da instanca pripada određenoj klasi (obično „positive“ klasi). Uprkos svom nazivu, *logistic* regression se koristi za diskretne ishode (za razliku od linear regression, koja se koristi za kontinuirane ishode). Posebno se koristi za **binary classification** (dve klase, npr. malicious naspram benign), ali se može proširiti na probleme sa više klasa (korišćenjem softmax ili one-vs-rest pristupa).<sup>[[3]](#references)</sup>

Logistic regression koristi logistic funkciju (poznatu i kao sigmoid funkcija) za mapiranje predviđenih vrednosti u verovatnoće. Imajte na umu da je sigmoid funkcija funkcija čije se vrednosti nalaze između 0 i 1 i koja raste u obliku slova S, u skladu sa potrebama classification procesa, što je korisno za binary classification zadatke. Zato se svaka karakteristika svakog ulaza množi dodeljenom težinom, a rezultat se prosleđuje kroz sigmoid funkciju kako bi se dobila verovatnoća:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gde:

- `p(y=1|x)` je verovatnoća da je izlaz `y` jednak 1 za dati ulaz `x`
- `e` je osnova prirodnog logaritma
- `z` je linearna kombinacija ulaznih karakteristika, obično predstavljena kao `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Obratite pažnju na to da je u najjednostavnijem obliku to prava linija, ali u složenijim slučajevima postaje hiperravan sa nekoliko dimenzija (po jednom za svaku karakteristiku).

> [!TIP]
> *Primene u cybersecurity-ju:* Pošto su mnogi security problemi u suštini odluke tipa da/ne, logistic regression se široko koristi. Na primer, intrusion detection system može koristiti logistic regression da odluči da li je network connection napad, na osnovu karakteristika te konekcije. U phishing detekciji, logistic regression može kombinovati karakteristike website-a (dužina URL-a, prisustvo simbola "@", itd.) u verovatnoću da je u pitanju phishing. Koristio se u filterima za spam ranije generacije i i dalje predstavlja snažnu početnu osnovu za mnoge classification zadatke.

#### Logistic Regression za non-binary classification

Logistic regression je namenjen binary classification-u, ali se može proširiti za rad sa multi-class problemima pomoću tehnika kao što su **one-vs-rest** (OvR) ili **softmax regression**. Kod OvR-a, za svaku klasu se trenira poseban logistic regression model, pri čemu se ta klasa tretira kao pozitivna, a sve ostale kao negativne. Klasa sa najvišom predviđenom verovatnoćom bira se kao konačno predviđanje. Softmax regression proširuje logistic regression na više klasa primenom softmax funkcije na izlazni sloj, čime se dobija distribucija verovatnoće preko svih klasa.

#### **Ključne karakteristike Logistic Regression-a:**

-   **Tip problema:** Classification (obično binary). Predviđa verovatnoću pozitivne klase.

-   **Interpretabilnost:** Visoka -- kao i kod linear regression-a, koeficijenti karakteristika mogu pokazati kako svaka karakteristika utiče na log-odds ishoda. Ova transparentnost je često korisna u security-ju za razumevanje faktora koji doprinose alert-u.

-   **Prednosti:** Jednostavan je i brzo se trenira; dobro radi kada je odnos između karakteristika i log-odds ishoda linearan. Daje verovatnoće, što omogućava risk scoring. Uz odgovarajuću regularizaciju, dobro se generalizuje i može bolje da obradi multikolinearnost nego običan linear regression.

-   **Ograničenja:** Pretpostavlja linearnu granicu odlučivanja u prostoru karakteristika (ne uspeva ako je stvarna granica složena/nelinearna). Može imati slabije rezultate na problemima gde su interakcije ili nelinearni efekti ključni, osim ako ručno ne dodate polynomial ili interaction karakteristike. Takođe, logistic regression je manje efikasan ako klase nije lako razdvojiti linearnom kombinacijom karakteristika.


<details>
<summary>Primer -- Phishing Website Detection sa Logistic Regression-om:</summary>

Koristićemo **Phishing Websites Dataset** (iz UCI repozitorijuma), koji sadrži izdvojene karakteristike website-ova (kao što su informacija da li URL sadrži IP adresu, starost domena, prisustvo sumnjivih elemenata u HTML-u itd.) i oznaku koja pokazuje da li je site phishing ili legitiman.<sup>[[4]](#references)</sup> Treniraćemo logistic regression model za klasifikaciju website-ova, a zatim proceniti njegov accuracy, precision, recall, F1-score i ROC AUC na test split-u.
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
U ovom primeru detekcije phishinga, logistic regression proizvodi verovatnoću da je svaka veb-lokacija phishing. Evaluacijom tačnosti, preciznosti, odziva i F1 mere dobijamo uvid u performanse modela. Na primer, visok odziv znači da model otkriva većinu phishing lokacija (što je važno za bezbednost kako bi se broj propuštenih napada sveo na minimum), dok visoka preciznost znači da ima malo lažnih uzbuna (što je važno kako bi se izbegao zamor analitičara). ROC AUC (površina ispod ROC krive) daje meru performansi nezavisnu od praga (1.0 je idealno, dok je 0.5 jednako slučajnom pogađanju). Logistic regression često daje dobre rezultate na ovakvim zadacima, ali ako je granica odlučivanja između phishing i legitimnih lokacija složena, možda će biti potrebni napredniji nelinearni modeli.

</details>

### Stabla odlučivanja

Stablo odlučivanja je svestrani **algoritam nadgledanog učenja** koji se može koristiti i za zadatke klasifikacije i za zadatke regresije. Ono uči hijerarhijski model odluka u obliku stabla na osnovu obeležja podataka. Svaki unutrašnji čvor stabla predstavlja proveru određenog obeležja, svaka grana predstavlja ishod te provere, a svaki list predstavlja predviđenu klasu (kod klasifikacije) ili vrednost (kod regresije).<sup>[[5]](#references)</sup>

Za izgradnju stabla, algoritmi poput CART-a (Classification and Regression Tree) koriste mere kao što su **Gini nečistoća** ili **dobitak informacija (entropija)** kako bi u svakom koraku izabrali najbolje obeležje i prag za podelu podataka. Cilj svake podele je particionisanje podataka tako da se poveća homogenost ciljne promenljive u rezultujućim podskupovima (kod klasifikacije, cilj svakog čvora je da bude što čistiji, odnosno da pretežno sadrži jednu klasu).

Stabla odlučivanja su **veoma interpretabilna** -- moguće je pratiti putanju od korena do lista i razumeti logiku iza predviđanja (npr. *"AKO je `service = telnet` I `src_bytes > 1000` I `failed_logins > 3`, ONDA klasifikuj kao napad"*). Ovo je korisno u sajber-bezbednosti za objašnjavanje razloga zbog kog je određeno upozorenje generisano. Stabla mogu prirodno da obrađuju i numeričke i kategoričke podatke i zahtevaju malo pretprocesiranja (npr. skaliranje obeležja nije potrebno).

Međutim, jedno stablo odlučivanja može lako da nauči previše detalja iz skupa podataka za obuku, naročito ako je duboko izgrađeno (sa mnogo podela). Tehnike poput orezivanja (ograničavanje dubine stabla ili zahtev za minimalnim brojem uzoraka po listu) često se koriste za sprečavanje overfittinga.

Postoje 3 glavne komponente stabla odlučivanja:
- **Korenski čvor**: Gornji čvor stabla koji predstavlja ceo skup podataka.
- **Unutrašnji čvorovi**: Čvorovi koji predstavljaju obeležja i odluke zasnovane na tim obeležjima.
- **Listovi**: Čvorovi koji predstavljaju konačni ishod ili predviđanje.

Stablo može na kraju izgledati ovako:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Slučajevi upotrebe u cybersecurity-u:* Stabla odlučivanja su korišćena u sistemima za detekciju upada za izvođenje **pravila** za identifikaciju napada. Na primer, rani IDS sistemi zasnovani na ID3/C4.5 algoritmima generisali bi čitljiva pravila za razlikovanje normalnog od zlonamernog saobraćaja. Takođe se koriste u analizi malware-a za odlučivanje da li je fajl zlonameran na osnovu njegovih atributa (veličina fajla, entropija sekcija, API pozivi itd.). Jasnoća stabala odlučivanja čini ih korisnim kada je potrebna transparentnost -- analitičar može pregledati stablo kako bi proverio logiku detekcije.

#### **Ključne karakteristike stabala odlučivanja:**

-   **Tip problema:** I klasifikacija i regresija. Često se koriste za klasifikaciju napada u odnosu na normalan saobraćaj itd.

-   **Interpretabilnost:** Veoma visoka -- odluke modela mogu se vizuelizovati i razumeti kao skup if-then pravila. Ovo je velika prednost u bezbednosti zbog poverenja i provere ponašanja modela.

-   **Prednosti:** Mogu da obuhvate nelinearne odnose i interakcije između karakteristika (svaki split može se posmatrati kao interakcija). Nema potrebe za skaliranjem karakteristika ili one-hot kodiranjem kategoričkih promenljivih -- stabla njima upravljaju nativno. Brzo izvršavanje predikcija (predikcija se svodi na praćenje putanje u stablu).

-   **Ograničenja:** Podložna su overfitting-u ako se ne kontrolišu (duboko stablo može memorisati skup za obuku). Mogu biti nestabilna -- male promene u podacima mogu dovesti do drugačije strukture stabla. Kao pojedinačni modeli, njihova preciznost možda neće dostići preciznost naprednijih metoda (ensembles poput Random Forests obično daju bolje rezultate smanjenjem varijanse).

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

- **Information Gain**: Smanjenje entropy ili Gini impurity nakon split-a. Što je information gain veći, split je bolji. Izračunava se na sledeći način:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Pored toga, stablo se završava kada:
- Sve instance u čvoru pripadaju istoj klasi. Ovo može dovesti do overfitting-a.
- Dostigne se maksimalna dubina (hardcoded) stabla. Ovo je način da se spreči overfitting.
- Broj instanci u čvoru bude ispod određenog praga. Ovo je takođe način da se spreči overfitting.
- Information gain iz narednih split-ova bude ispod određenog praga. Ovo je takođe način da se spreči overfitting.

<details>
<summary>Primer -- Stablo odlučivanja za detekciju upada:</summary>
Obučićemo stablo odlučivanja na NSL-KDD dataset-u kako bismo klasifikovali mrežne konekcije kao *normalne* ili *napad*. NSL-KDD je poboljšana verzija klasičnog KDD Cup 1999 dataset-a, sa karakteristikama kao što su tip protokola, servis, trajanje, broj neuspešnih prijavljivanja itd., i labelom koja označava tip napada ili vrednost "normal". Sve tipove napada mapiraćemo na klasu "anomaly" (binarna klasifikacija: normalno u odnosu na anomaly). Nakon obuke, procenićemo performanse stabla na test skupu.
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
U ovom primeru stabla odlučivanja, ograničili smo dubinu stabla na 10 kako bismo izbegli ekstremni overfitting (parametar `max_depth=10`). Metričke vrednosti pokazuju koliko dobro stablo razlikuje normalan saobraćaj od napada. Visok recall bi značio da otkriva većinu napada (što je važno za IDS), dok visok precision znači mali broj lažnih alarma. Stabla odlučivanja često postižu pristojnu tačnost na strukturiranim podacima, ali jedno stablo možda neće dostići najbolje moguće performanse. Ipak, *interpretabilnost* modela predstavlja veliku prednost -- mogli bismo da pregledamo podele u stablu i vidimo, na primer, koje su karakteristike (npr. `service`, `src_bytes` itd.) najuticajnije pri označavanju konekcije kao zlonamerne.

</details>

### Random Forests

Random Forest je metoda **ensemble learning** koja se nadovezuje na stabla odlučivanja kako bi poboljšala performanse. Random forest trenira više stabala odlučivanja (otuda „forest“) i kombinuje njihove izlaze da bi doneo konačnu predikciju (kod klasifikacije, najčešće glasanjem većine). Dve glavne ideje u random forest modelu su **bagging** (bootstrap aggregating) i **feature randomness**:

-   **Bagging:** Svako stablo se trenira na nasumičnom bootstrap uzorku trening podataka (uzorkovanom sa ponavljanjem). Ovo uvodi raznovrsnost među stablima.

-   **Feature Randomness:** Pri svakoj podeli u stablu, za podelu se razmatra nasumični podskup karakteristika (umesto svih karakteristika). Ovo dodatno smanjuje korelaciju među stablima.

Usrednjavanjem rezultata velikog broja stabala, random forest smanjuje varijansu koju bi jedno stablo odlučivanja moglo imati. Jednostavno rečeno, pojedinačna stabla mogu da rade overfit ili da budu bučna, ali veliki broj raznovrsnih stabala koja glasaju zajedno ublažava te greške. Rezultat je često model sa **većom tačnošću** i boljom generalizacijom u odnosu na jedno stablo odlučivanja. Pored toga, random forests mogu da pruže procenu važnosti karakteristika (posmatranjem koliko svaka podela po karakteristici u proseku smanjuje nečistoću).

Random forests su postali **ključni alat u cybersecurity-ju** za zadatke kao što su intrusion detection, klasifikacija malware-a i detekcija spam-a. Često daju dobre rezultate bez dodatnog podešavanja i mogu da obrađuju velike skupove karakteristika. Na primer, u intrusion detection-u, random forest može nadmašiti pojedinačno stablo odlučivanja otkrivanjem suptilnijih obrazaca napada uz manji broj false positive rezultata. Istraživanja su pokazala da random forests daju dobre rezultate u poređenju sa drugim algoritmima pri klasifikaciji napada u skupovima podataka kao što su NSL-KDD i UNSW-NB15.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Ključne karakteristike Random Forests:**

-   **Tip problema:** Pre svega klasifikacija (koristi se i za regresiju). Veoma je pogodan za visokodimenzionalne strukturirane podatke koji su uobičajeni u security logovima.

-   **Interpretabilnost:** Niža nego kod jednog stabla odlučivanja -- nije lako vizuelizovati ili objasniti stotine stabala odjednom. Međutim, rezultati važnosti karakteristika pružaju određeni uvid u to koji su atributi najuticajniji.

-   **Prednosti:** Uopšteno veća tačnost nego kod modela sa jednim stablom, zahvaljujući ensemble efektu. Otporan je na overfitting -- čak i ako pojedinačna stabla rade overfit, ensemble bolje generalizuje. Obrađuje numeričke i kategorijalne karakteristike i u određenoj meri može da upravlja nedostajućim podacima. Takođe je relativno otporan na outlier-e.

-   **Ograničenja:** Veličina modela može biti velika (mnogo stabala, od kojih svako može biti duboko). Predikcije su sporije nego kod jednog stabla (jer morate da agregirate rezultate velikog broja stabala). Manje je interpretabilan -- iako znate koje su karakteristike važne, tačnu logiku nije lako pratiti kao jednostavno pravilo. Ako je skup podataka izuzetno visokodimenzionalan i redak, treniranje veoma velike šume može biti računarski zahtevno.

-   **Proces treniranja:**
1. **Bootstrap Sampling**: Nasumično uzorkujte trening podatke sa ponavljanjem kako biste kreirali više podskupova (bootstrap uzoraka).
2. **Tree Construction**: Za svaki bootstrap uzorak izgradite stablo odlučivanja koristeći nasumični podskup karakteristika pri svakoj podeli. Ovo uvodi raznovrsnost među stablima.
3. **Aggregation**: Kod klasifikacionih zadataka, konačna predikcija se dobija glasanjem većine na osnovu predikcija svih stabala. Kod regresionih zadataka, konačna predikcija je prosek predikcija svih stabala.

<details>
<summary>Primer -- Random Forest za Intrusion Detection (NSL-KDD):</summary>
Koristićemo isti NSL-KDD skup podataka (binarno označen kao normalan ili anomalija) i treniraćemo Random Forest classifier. Očekujemo da će random forest raditi jednako dobro kao pojedinačno stablo odlučivanja ili bolje od njega, zahvaljujući usrednjavanju ensemble-a koje smanjuje varijansu. Procenićemo ga pomoću istih metrika.
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
Random forest obično postiže veoma dobre rezultate na ovom zadatku detekcije upada. Možemo primetiti poboljšanje metrika kao što su F1 ili AUC u poređenju sa pojedinačnim stablom odlučivanja, naročito u pogledu recall-a ili precision-a, u zavisnosti od podataka. Ovo je u skladu sa shvatanjem da je *„Random Forest (RF) klasifikator ansambla i postiže dobre rezultate u poređenju sa drugim tradicionalnim klasifikatorima za efikasnu klasifikaciju napada.“*<sup>[[6]](#references)</sup> U kontekstu bezbednosnih operacija, model random forest može pouzdanije označavati napade i istovremeno smanjiti broj lažnih alarma, zahvaljujući usrednjavanju velikog broja pravila odlučivanja. Važnost karakteristika iz forest-a može nam pokazati koje mrežne karakteristike najviše ukazuju na napade (npr. određeni mrežni servisi ili neuobičajeni broj paketa).

</details>

### Support Vector Machines (SVM)

Support Vector Machines su moćni modeli nadgledanog učenja koji se prvenstveno koriste za klasifikaciju (kao i za regresiju u obliku SVR-a). SVM pokušava da pronađe **optimalnu razdvajajuću hiperravan** koja maksimizuje marginu između dve klase. Samo podskup trening tačaka („support vectors“ najbliži granici) određuje položaj ove hiperravni. Maksimizovanjem margine (rastojanja između support vectors i hiperravni), SVM-ovi obično postižu dobru generalizaciju.<sup>[[8]](#references)</sup>

Ključna prednost SVM-a je mogućnost korišćenja **kernel functions** za obradu nelinearnih odnosa. Podaci se implicitno mogu transformisati u višedimenzionalni prostor karakteristika u kojem može postojati linearni razdvajač. Uobičajeni kerneli obuhvataju polynomial, radial basis function (RBF) i sigmoid. Na primer, ako klase mrežnog saobraćaja nisu linearno razdvojive u izvornom prostoru karakteristika, RBF kernel ih može preslikati u višu dimenziju, gde SVM pronalazi linearno razdvajanje (što odgovara nelinearnoj granici u izvornom prostoru). Fleksibilnost izbora kernela omogućava SVM-ovima rešavanje različitih problema.

Poznato je da SVM-ovi dobro rade u situacijama sa višedimenzionalnim prostorima karakteristika (kao što su tekstualni podaci ili opcode sekvence malware-a), kao i u slučajevima kada je broj karakteristika veliki u odnosu na broj uzoraka. Bili su popularni u mnogim ranim cybersecurity primenama, kao što su klasifikacija malware-a i detekcija anomalija zasnovana na anomalijama tokom 2000-ih, često uz visoku tačnost.

Međutim, SVM-ovi se ne skaliraju lako na veoma velike skupove podataka (složenost treniranja je super-linearna u odnosu na broj uzoraka, a upotreba memorije može biti velika jer je možda potrebno čuvati veliki broj support vectors). U praksi, za zadatke kao što je detekcija mrežnih upada sa milionima zapisa, SVM može biti prespor bez pažljivog subsampling-a ili korišćenja približnih metoda.

#### **Ključne karakteristike SVM-a:**

-   **Tip problema:** Klasifikacija (binarna ili multiclass putem one-vs-one/one-vs-rest) i varijante za regresiju. Često se koristi za binarnu klasifikaciju sa jasnim razdvajanjem margine.

-   **Interpretabilnost:** Srednja -- SVM-ovi nisu toliko interpretabilni kao stabla odlučivanja ili logistic regression. Iako možete identifikovati koje su tačke podataka support vectors i steći izvesnu predstavu o tome koje karakteristike mogu biti uticajne (preko težina u slučaju linearnog kernela), SVM-ovi (naročito sa nelinearnim kernelima) se u praksi tretiraju kao klasifikatori tipa black box.

-   **Prednosti:** Efikasni u višedimenzionalnim prostorima; mogu modelovati složene granice odlučivanja koristeći kernel trick; otporni na overfitting ako je margina maksimizovana (naročito uz odgovarajući parametar regularizacije C); dobro rade čak i kada klase nisu razdvojene velikim rastojanjem (pronalaze najbolju kompromisnu granicu).

-   **Ograničenja:** **Računarski zahtevni** za velike skupove podataka (i treniranje i predikcija se loše skaliraju sa rastom količine podataka). Zahtevaju pažljivo podešavanje parametara kernela i regularizacije (C, tip kernela, gamma za RBF itd.). Ne pružaju direktno probabilističke izlaze (mada se Platt scaling može koristiti za dobijanje verovatnoća). Takođe, SVM-ovi mogu biti osetljivi na izbor parametara kernela --- loš izbor može dovesti do underfit-a ili overfit-a.

*Primene u cybersecurity-u:* SVM-ovi su korišćeni za **detekciju malware-a** (npr. klasifikovanje fajlova na osnovu izdvojenih karakteristika ili opcode sekvenci), **detekciju mrežnih anomalija** (klasifikovanje saobraćaja kao normalnog ili malicious) i **detekciju phishing-a** (korišćenjem karakteristika URL-ova). Na primer, SVM može koristiti karakteristike e-maila (broj pojavljivanja određenih ključnih reči, ocene reputacije pošiljaoca itd.) i klasifikovati ga kao phishing ili legitimate. Takođe su primenjeni na **detekciju upada** nad skupovima karakteristika kao što je KDD, često uz postizanje visoke tačnosti po cenu računarske zahtevnosti.

<details>
<summary>Primer -- SVM za klasifikaciju malware-a:</summary>
Ponovo ćemo koristiti skup podataka o phishing sajtovima, ovog puta sa SVM-om. Pošto SVM-ovi mogu biti spori, po potrebi ćemo koristiti podskup podataka za treniranje (skup podataka ima oko 11k instanci, što SVM može razumno da obradi). Koristićemo RBF kernel, koji je čest izbor za nelinearne podatke, i omogućićemo procene verovatnoće kako bismo izračunali ROC AUC.
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
SVM model će dati metrike koje možemo uporediti sa logističkom regresijom na istom zadatku. Možemo utvrditi da SVM postiže visoku tačnost i AUC ako su podaci dobro razdvojeni karakteristikama. S druge strane, ako skup podataka sadrži mnogo šuma ili klase koje se preklapaju, SVM možda neće značajno nadmašiti logističku regresiju. U praksi, SVM može pružiti bolje rezultate kada postoje složene, nelinearne veze između karakteristika i klase -- RBF kernel može da obuhvati zakrivljene granice odlučivanja koje bi logistička regresija propustila. Kao i kod svih modela, potrebno je pažljivo podešavanje parametra `C` (regularizacija) i parametara kernela (kao što je `gamma` za RBF) kako bi se napravila ravnoteža između biasa i varijanse.

</details>

#### Razlika između logističke regresije i SVM-a

| Aspect | **Logistička regresija** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Minimizuje **log-loss** (unakrsnu entropiju). | Maksimizuje **marginu**, uz minimizovanje **hinge-loss** funkcije. |
| **Decision boundary** | Pronalaženje **najbolje prilagođene hiperravni** koja modeluje _P(y\|x)_. | Pronalaženje **hiperravni sa maksimalnom marginom** (najveći razmak do najbližih tačaka). |
| **Output** | **Probabilistički** – daje kalibrisane verovatnoće klasa putem σ(w·x + b). | **Deterministički** – vraća oznake klasa; verovatnoće zahtevaju dodatnu obradu (npr. Platt scaling). |
| **Regularisation** | L2 (podrazumevano) ili L1, direktno uspostavlja ravnotežu između underfittinga i overfittinga. | Parametar C pravi kompromis između širine margine i pogrešnih klasifikacija; parametri kernela dodaju složenost. |
| **Kernels / Non‑linear** | Izvorni oblik je **linearan**; nelinearnost se dodaje inženjeringom karakteristika. | Ugrađeni **kernel trick** (RBF, poly itd.) omogućava modelovanje složenih granica u prostoru velike dimenzionalnosti. |
| **Scalability** | Rešava konveksnu optimizaciju u **O(nd)**; dobro obrađuje veoma veliko n. | Obučavanje može imati složenost **O(n²–n³)** u pogledu memorije/vremena bez specijalizovanih rešavača; manje je pogodan za ogromno n. |
| **Interpretability** | **Visoka** – težine pokazuju uticaj karakteristika; odnos izgleda je intuitivan. | **Niska** kod nelinearnih kernela; support vectors su retki, ali ih nije lako objasniti. |
| **Sensitivity to outliers** | Koristi glatku log-loss funkciju → manje je osetljiva. | Hinge-loss sa hard marginom može biti **osetljiv**; soft-margin (C) ublažava ovaj problem. |
| **Typical use cases** | Kreditno bodovanje, medicinski rizik, A/B testiranje – tamo gde su važne **verovatnoće i objašnjivost**. | Klasifikacija slika/teksta, bioinformatika – tamo gde su važne **složene granice** i **visedimenzionalni podaci**. |

* **Ako su vam potrebne kalibrisane verovatnoće, interpretabilnost ili rad sa ogromnim skupovima podataka — izaberite logističku regresiju.**
* **Ako vam je potreban fleksibilan model koji može da obuhvati nelinearne odnose bez ručnog inženjeringa karakteristika — izaberite SVM (sa kernelima).**
* Oba modela optimizuju konveksne ciljne funkcije, pa su **globalni minimumi garantovani**, ali SVM kerneli dodaju hiperparametre i računarsku cenu.

### Naive Bayes

Naive Bayes je porodica **probabilističkih klasifikatora** zasnovana na primeni Bayesove teoreme uz snažnu pretpostavku nezavisnosti između karakteristika. Uprkos ovoj „naivnoj“ pretpostavci, Naive Bayes često funkcioniše iznenađujuće dobro u određenim primenama, naročito onima koje uključuju tekstualne ili kategoričke podatke, kao što je detekcija neželjene pošte.<sup>[[9]](#references)</sup>


#### Bayesova teorema

Bayesova teorema je osnova Naive Bayes klasifikatora. Ona povezuje uslovne i marginalne verovatnoće slučajnih događaja. Formula glasi:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gde:
- `P(A|B)` je posteriorna verovatnoća klase `A` na osnovu obeležja `B`.
- `P(B|A)` je verodostojnost obeležja `B` za klasu `A`.
- `P(A)` je prethodna verovatnoća klase `A`.
- `P(B)` je prethodna verovatnoća obeležja `B`.

Na primer, ako želimo da klasifikujemo da li je tekst napisalo dete ili odrasla osoba, možemo koristiti reči u tekstu kao obeležja. Na osnovu početnih podataka, Naive Bayes classifier će prethodno izračunati verovatnoće da se svaka reč nalazi u svakoj potencijalnoj klasi (dete ili odrasla osoba). Kada se zada novi tekst, izračunaće verovatnoću svake potencijalne klase na osnovu reči u tekstu i izabrati klasu sa najvećom verovatnoćom.

Kao što možete videti u ovom primeru, Naive Bayes classifier je veoma jednostavan i brz, ali pretpostavlja da su obeležja nezavisna, što nije uvek slučaj sa podacima iz stvarnog sveta.


#### Tipovi Naive Bayes Classifiers

Postoji nekoliko tipova Naive Bayes classifiers, u zavisnosti od tipa podataka i distribucije obeležja:
- **Gaussian Naive Bayes**: Pretpostavlja da obeležja prate Gaussian (normalnu) distribuciju. Pogodan je za kontinuirane podatke.
- **Multinomial Naive Bayes**: Pretpostavlja da obeležja prate multinomijalnu distribuciju. Pogodan je za diskretne podatke, kao što su brojači reči u klasifikaciji teksta.
- **Bernoulli Naive Bayes**: Pretpostavlja da su obeležja binarna (0 ili 1). Pogodan je za binarne podatke, kao što su prisustvo ili odsustvo reči u klasifikaciji teksta.
- **Categorical Naive Bayes**: Pretpostavlja da su obeležja kategoričke promenljive. Pogodan je za kategoričke podatke, kao što je klasifikovanje voća na osnovu njegove boje i oblika.


#### **Ključne karakteristike Naive Bayes:**

-   **Tip problema:** Klasifikacija (binarna ili višeklasna). Često se koristi za zadatke klasifikacije teksta u cybersecurity-ju (spam, phishing itd.).

-   **Interpretabilnost:** Srednja -- nije direktno interpretabilan kao decision tree, ali se mogu ispitati naučene verovatnoće (npr. koje reči se najčešće pojavljuju u spam naspram ham emailovima). Oblik modela (verovatnoće za svako obeležje na osnovu klase) može se razumeti kada je to potrebno.

-   **Prednosti:** **Veoma brzo** treniranje i predviđanje, čak i na velikim skupovima podataka (linearno u odnosu na broj instanci * broj obeležja). Zahteva relativno malu količinu podataka za pouzdanu procenu verovatnoća, naročito uz odgovarajuće smoothing. Često je iznenađujuće precizan kao baseline, posebno kada obeležja nezavisno doprinose dokazima za određenu klasu. Dobro funkcioniše sa visokodimenzionalnim podacima (npr. hiljadama obeležja iz teksta). Nije potrebno složeno podešavanje, osim postavljanja parametra smoothing.

-   **Ograničenja:** Pretpostavka nezavisnosti može ograničiti preciznost ako su obeležja u velikoj meri korelisana. Na primer, u mrežnim podacima obeležja poput `src_bytes` i `dst_bytes` mogu biti korelisana; Naive Bayes neće obuhvatiti tu interakciju. Kako veličina podataka raste, izražajniji modeli (kao što su ensembles ili neural nets) mogu nadmašiti NB učenjem zavisnosti između obeležja. Takođe, ako je za identifikaciju napada potrebna određena kombinacija obeležja (a ne samo pojedinačna obeležja nezavisno), NB će imati problema.

> [!TIP]
> *Use cases in cybersecurity:* Klasična upotreba je **spam detection** -- Naive Bayes je bio osnova ranih spam filtera, koji su koristili učestalost određenih tokena (reči, fraza, IP adresa) za izračunavanje verovatnoće da je email spam. Takođe se koristi za **phishing email detection** i **URL classification**, gde prisustvo određenih ključnih reči ili karakteristika (kao što je "login.php" u URL-u ili `@` u putanji URL-a) doprinosi verovatnoći phishing-a. U malware analysis-u može se zamisliti Naive Bayes classifier koji koristi prisustvo određenih API poziva ili dozvola u softveru da bi predvideo da li je u pitanju malware. Iako napredniji algoritmi često daju bolje rezultate, Naive Bayes ostaje dobar baseline zbog svoje brzine i jednostavnosti.

<details>
<summary>Primer -- Naive Bayes za Phishing Detection:</summary>
Da bismo demonstrirali Naive Bayes, koristićemo Gaussian Naive Bayes na NSL-KDD intrusion dataset-u (sa binarnim labelama). Gaussian NB će tretirati svako obeležje kao da prati normalnu distribuciju po klasi. Ovo je grubi izbor, pošto su mnoga mrežna obeležja diskretna ili imaju veoma asimetričnu distribuciju, ali pokazuje kako bi se NB primenio na kontinuirane podatke obeležja. Mogli bismo izabrati i Bernoulli NB na skupu podataka sa binarnim obeležjima (kao što je skup pokrenutih upozorenja), ali ćemo se ovde zbog kontinuiteta zadržati na NSL-KDD-u.
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
Ovaj kod trenira Naive Bayes klasifikator za detekciju napada. Naive Bayes će izračunati vrednosti poput `P(service=http | Attack)` i `P(Service=http | Normal)` na osnovu podataka za trening, uz pretpostavku nezavisnosti među karakteristikama. Zatim će koristiti ove verovatnoće za klasifikaciju novih konekcija kao normalnih ili napada na osnovu uočenih karakteristika. Performanse NB-a na NSL-KDD možda neće biti visoke kao kod naprednijih modela (pošto je pretpostavka nezavisnosti karakteristika narušena), ali su često zadovoljavajuće, uz prednost izuzetne brzine. U scenarijima kao što su filtriranje emailova u realnom vremenu ili početna trijaža URL-ova, Naive Bayes model može brzo označiti očigledno malicious slučajeve uz malu potrošnju resursa.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors je jedan od najjednostavnijih algoritama mašinskog učenja. To je **neparametarska metoda zasnovana na instancama** koja pravi predikcije na osnovu sličnosti sa primerima iz skupa za trening. Ideja kod klasifikacije je sledeća: da bi se klasifikovala nova tačka podataka, pronalazi se **k** najbližih tačaka u podacima za trening (njihovi „najbliži susedi“), a zatim se dodeljuje klasa koja je većinska među tim susedima. „Blizina“ se definiše metrikom rastojanja, najčešće Euklidskim rastojanjem za numeričke podatke (druga rastojanja mogu se koristiti za različite tipove karakteristika ili probleme).<sup>[[10]](#references)</sup>

K-NN ne zahteva *eksplicitno treniranje* -- faza „treninga“ svodi se na čuvanje skupa podataka. Sav posao se obavlja tokom upita (predikcije): algoritam mora da izračuna rastojanja od upitne tačke do svih tačaka za trening kako bi pronašao najbliže. Zbog toga je vreme predikcije **linearno u odnosu na broj uzoraka za trening**, što može biti skupo kod velikih skupova podataka. Zbog toga je k-NN najpogodniji za manje skupove podataka ili scenarije u kojima se jednostavnost može platiti većom potrošnjom memorije i vremenom izvršavanja.

Uprkos jednostavnosti, k-NN može modelovati veoma složene granice odlučivanja (pošto granica odlučivanja praktično može imati bilo koji oblik koji određuje raspodela primera). Dobro funkcioniše kada je granica odlučivanja veoma nepravilna i kada postoji mnogo podataka -- u suštini omogućavajući podacima da „govore sami za sebe“. Međutim, u visokim dimenzijama metrike rastojanja mogu postati manje značajne (prokletstvo dimenzionalnosti), pa se metoda može suočiti sa poteškoćama osim ako ne postoji ogroman broj uzoraka.

*Primene u cybersecurity-u:* k-NN je korišćen za detekciju anomalija -- na primer, intrusion detection system može označiti network event kao malicious ako je većina njegovih najbližih suseda (prethodnih događaja) bila malicious. Ako normalni saobraćaj formira klastere, a napadi su outlier-i, K-NN pristup (sa k=1 ili malim k) u suštini predstavlja **detekciju anomalija zasnovanu na najbližem susedu**. K-NN je takođe korišćen za klasifikaciju malware family-ja pomoću binarnih vektora karakteristika: novi fajl može biti klasifikovan kao određena malware family ako je veoma blizu (u prostoru karakteristika) poznatim instancama te porodice. U praksi, k-NN nije toliko čest kao skalabilniji algoritmi, ali je konceptualno jednostavan i ponekad se koristi kao baseline ili za probleme manjeg obima.

#### **Ključne karakteristike k-NN-a:**

-   **Tip problema:** Klasifikacija (postoje i varijante za regresiju). To je metoda *lenjog učenja* -- nema eksplicitnog uklapanja modela.

-   **Interpretabilnost:** Niska do srednja -- ne postoji globalni model ili sažeto objašnjenje, ali rezultate je moguće interpretirati posmatranjem najbližih suseda koji su uticali na odluku (npr. „ovaj network flow je klasifikovan kao malicious jer je sličan ovim 3 poznatim malicious flow-ovima“). Dakle, objašnjenja mogu biti zasnovana na primerima.

-   **Prednosti:** Veoma jednostavan za implementaciju i razumevanje. Ne pretpostavlja ništa o distribuciji podataka (neparametarski). Može prirodno da obrađuje probleme sa više klasa. **Adaptivan** je u smislu da granice odlučivanja mogu biti veoma složene i oblikovane distribucijom podataka.

-   **Ograničenja:** Predikcija može biti spora kod velikih skupova podataka (mora se izračunati mnogo rastojanja). Zahteva mnogo memorije -- čuva sve podatke za trening. Performanse opadaju u visokodimenzionalnim prostorima karakteristika jer sve tačke teže da budu približno jednako udaljene (zbog čega koncept „najbližeg“ postaje manje značajan). Potrebno je pravilno izabrati *k* (broj suseda) -- premalo k može dovesti do šumovitih rezultata, dok preveliko k može uključiti nerelevantne tačke iz drugih klasa. Takođe, karakteristike treba pravilno skalirati jer su izračunavanja rastojanja osetljiva na skalu.

<details>
<summary>Primer -- k-NN za detekciju phishing-a:</summary>

Ponovo ćemo koristiti NSL-KDD (binarna klasifikacija). Pošto je k-NN računarski zahtevan, koristićemo podskup podataka za trening kako bi ova demonstracija ostala praktična. Izabraćemo, recimo, 20.000 uzoraka za trening od ukupno 125k i koristićemo 5 suseda, k=5. Nakon treninga (što se zapravo svodi na čuvanje podataka), izvršićemo evaluaciju na test skupu. Takođe ćemo skalirati karakteristike za izračunavanje rastojanja kako nijedna pojedinačna karakteristika ne bi dominirala zbog svoje skale.
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
k-NN model će klasifikovati konekciju posmatrajući 5 najbližih konekcija u podskupu skupa za treniranje. Ako su, na primer, 4 od tih suseda napadi (anomalije), a 1 je normalan, nova konekcija će biti klasifikovana kao napad. Performanse mogu biti solidne, iako često nisu tako dobre kao kod dobro podešenog Random Forest ili SVM modela na istim podacima. Međutim, k-NN ponekad može biti posebno efikasan kada su distribucije klasa veoma nepravilne i složene -- praktično koristeći pretragu zasnovanu na memoriji. U cybersecurity-ju, k-NN (sa k=1 ili malim k) može se koristiti za detekciju poznatih obrazaca napada na osnovu primera ili kao komponenta složenijih sistema (npr. za clustering, a zatim klasifikaciju na osnovu pripadnosti clusteru).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines spadaju među najmoćnije algoritme za strukturirane podatke. **Gradient boosting** označava tehniku izgradnje ansambla slabih modela (često decision tree modela) sekvencijalnim postupkom, pri čemu svaki novi model ispravlja greške prethodnog ansambla. Za razliku od bagging-a (Random Forest), koji decision tree modele gradi paralelno i usrednjuje ih, boosting gradi decision tree modele *jedan po jedan*, pri čemu se svaki više fokusira na instance koje su prethodni modeli pogrešno predvideli.<sup>[[11]](#references)</sup>

Najpopularnije implementacije poslednjih godina su **XGBoost**, **LightGBM** i **CatBoost**, koji su svi biblioteke za gradient boosting decision tree (GBDT). Bili su izuzetno uspešni na takmičenjima iz machine learning-a i u praktičnim primenama, često **postižući vrhunske performanse na tabelarnim skupovima podataka**. U cybersecurity-ju, istraživači i stručnjaci koristili su gradient boosted tree modele za zadatke kao što su **detekcija malware-a** (korišćenjem feature-a izdvojenih iz fajlova ili ponašanja tokom izvršavanja) i **detekcija mrežnih upada**. Na primer, gradient boosting model može kombinovati mnoga slaba pravila (tree modele), kao što je „ako postoji mnogo SYN paketa i neuobičajen port -> verovatno skeniranje“, u snažan kompozitni detector koji uzima u obzir mnoge suptilne obrasce.

Zašto su boosted tree modeli toliko efikasni? Svaki model u sekvenci trenira se na *rezidualnim greškama* (gradientima) predikcija trenutnog ansambla. Na taj način model postepeno **„pojačava“** oblasti u kojima je slab. Korišćenje decision tree modela kao osnovnih modela omogućava konačnom modelu da obuhvati složene interakcije i nelinearne odnose. Takođe, boosting ima ugrađen oblik regularizacije: dodavanjem velikog broja malih tree modela (i korišćenjem learning rate-a za skaliranje njihovih doprinosa), često dobro generalizuje bez velikog overfitting-a, pod uslovom da su parametri pravilno izabrani.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Prvenstveno klasifikacija i regresija. U security-ju se najčešće koristi klasifikacija (npr. binarna klasifikacija konekcije ili fajla). Podržava binarne i multi-class probleme (uz odgovarajući loss), pa čak i ranking probleme.

-   **Interpretability:** Niska do srednja. Iako je pojedinačni boosted tree mali, kompletan model može imati stotine tree modela, pa nije interpretabilan ljudima kao celina. Međutim, kao i Random Forest, može pružiti ocene važnosti feature-a, a alati kao što je SHAP (SHapley Additive exPlanations) mogu se donekle koristiti za tumačenje pojedinačnih predikcija.

-   **Advantages:** Često **algoritam sa najboljim performansama** za strukturirane/tabelarne podatke. Može detektovati složene obrasce i interakcije. Ima mnogo opcija za podešavanje (broj tree modela, njihova dubina, learning rate, termini regularizacije) kojima se složenost modela može prilagoditi i sprečiti overfitting. Moderne implementacije su optimizovane za brzinu (npr. XGBoost koristi gradient informacije drugog reda i efikasne strukture podataka). Obično se bolje nosi sa neuravnoteženim podacima kada se kombinuje sa odgovarajućim loss funkcijama ili podešavanjem sample weight-a.

-   **Limitations:** Složeniji je za podešavanje od jednostavnijih modela; treniranje može biti sporo ako su tree modeli duboki ili je njihov broj veliki (iako je obično i dalje brže od treniranja uporedivog deep neural network-a na istim podacima). Model može imati overfitting ako nije pravilno podešen (npr. previše dubokih tree modela sa nedovoljnom regularizacijom). Zbog velikog broja hyperparameter-a, efikasno korišćenje gradient boosting-a može zahtevati više stručnosti ili eksperimentisanja. Takođe, kao i tree-based metode, ne obrađuje inherentno veoma sparse visokodimenzionalne podatke jednako efikasno kao linearni modeli ili Naive Bayes (iako se i dalje može primeniti, npr. u text classification-u, ali možda neće biti prvi izbor bez feature engineering-a).

> [!TIP]
> *Use cases in cybersecurity:* Gotovo svuda gde bi se mogao koristiti decision tree ili Random Forest, gradient boosting model može postići bolju preciznost. Na primer, na takmičenjima za **Microsoft-ovu detekciju malware-a** XGBoost se intenzivno koristio na engineered feature-ima iz binarnih fajlova. Istraživanja detekcije mrežnih upada često prijavljuju najbolje rezultate pomoću GBDT modela (npr. XGBoost na CIC-IDS2017 ili UNSW-NB15 skupovima podataka). Ovi modeli mogu koristiti širok raspon feature-a (tipovi protokola, učestalost određenih događaja, statističke karakteristike saobraćaja itd.) i kombinovati ih radi detekcije pretnji. U detekciji phishing-a, gradient boosting može kombinovati lexical feature-e URL-ova, feature-e reputacije domena i feature-e sadržaja stranice kako bi postigao veoma visoku preciznost. Ansambl pristup pomaže u obuhvatanju mnogih graničnih slučajeva i suptilnosti u podacima.

<details>
<summary>Primer -- XGBoost za detekciju phishing-a:</summary>
Koristićemo gradient boosting classifier na phishing skupu podataka. Da bi primer bio jednostavan i samostalan, koristićemo `sklearn.ensemble.GradientBoostingClassifier` (što je sporija, ali jednostavna implementacija). Uobičajeno bi se koristile `xgboost` ili `lightgbm` biblioteke radi boljih performansi i dodatnih funkcija. Treniraćemo model i proceniti ga na sličan način kao ranije.
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
Model gradient boosting će verovatno postići veoma visoku tačnost i AUC na ovom phishing skupu podataka (ovi modeli često mogu premašiti 95% tačnosti uz pravilno podešavanje na takvim podacima, kao što je zabeleženo u literaturi. Ovo pokazuje zašto se GBDT modeli smatraju *"the state of the art model for tabular dataset"* -- često nadmašuju jednostavnije algoritme jer prepoznaju složene obrasce.<sup>[[11]](#references)</sup> U kontekstu cyber bezbednosti, to bi moglo značiti otkrivanje većeg broja phishing sajtova ili napada uz manje propuštenih slučajeva. Naravno, treba biti oprezan zbog overfitting-a -- pri razvoju ovakvog modela za primenu obično bismo koristili tehnike kao što su cross-validation i pratili performanse na validation skupu.

</details>

### Kombinovanje modela: Ensemble Learning i Stacking

Ensemble learning je strategija **kombinovanja više modela** radi poboljšanja ukupnih performansi. Već smo videli konkretne ensemble metode: Random Forest (ensemble stabala putem bagging-a) i Gradient Boosting (ensemble stabala putem sekvencijalnog boosting-a). Međutim, ensembles se mogu kreirati i na druge načine, kao što su **voting ensembles** ili **stacked generalization (stacking)**. Osnovna ideja je da različiti modeli mogu prepoznati različite obrasce ili imati različite slabosti; njihovim kombinovanjem možemo **nadoknaditi greške svakog modela prednostima drugog modela**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Kod jednostavnog voting classifier-a, treniramo više raznovrsnih modela (recimo, logistic regression, decision tree i SVM) i omogućavamo im da glasaju o konačnoj predikciji (većinsko glasanje za klasifikaciju). Ako glasovima dodelimo težine (npr. veću težinu preciznijim modelima), dobijamo weighted voting scheme. Ovo obično poboljšava performanse kada su pojedinačni modeli dovoljno dobri i nezavisni -- ensemble smanjuje rizik od greške pojedinačnog modela, jer je drugi modeli mogu ispraviti. To je kao da imamo panel stručnjaka umesto jednog mišljenja.

-   **Stacking (Stacked Ensemble):** Stacking ide korak dalje. Umesto jednostavnog glasanja, on trenira **meta-model** koji **uči kako da na najbolji način kombinuje predikcije** osnovnih modela. Na primer, trenirate 3 različita classifier-a (base learner-a), a zatim njihove izlaze (ili verovatnoće) prosleđujete kao features meta-classifier-u (često jednostavnom modelu kao što je logistic regression), koji uči optimalan način njihovog kombinovanja. Meta-model se trenira na validation skupu ili pomoću cross-validation-a kako bi se izbegao overfitting. Stacking često može nadmašiti jednostavno glasanje jer uči *kojim modelima više verovati u kojim okolnostima*. U cyber bezbednosti, jedan model može biti bolji u otkrivanju network scan-ova, dok je drugi bolji u otkrivanju malware beaconing-a; stacking model bi mogao naučiti da se na odgovarajući način osloni na svaki od njih.

Ensembles, bilo da koriste glasanje ili stacking, obično **povećavaju tačnost** i robusnost. Nedostatak su povećana složenost i ponekad smanjena interpretabilnost (iako neki ensemble pristupi, poput proseka decision tree-ova, i dalje mogu pružiti određeni uvid, npr. feature importance). U praksi, ako operativna ograničenja to dozvoljavaju, korišćenje ensemble-a može dovesti do viših stopa detekcije. Mnoga pobednička rešenja u cyber bezbednosnim izazovima (i Kaggle takmičenjima uopšte) koriste ensemble tehnike kako bi izvukla i poslednji delić performansi.

<details>
<summary>Primer -- Voting Ensemble za phishing detekciju:</summary>
Da bismo ilustrovali model stacking, kombinovaćemo nekoliko modela o kojima smo govorili na phishing skupu podataka. Koristićemo logistic regression, decision tree i k-NN kao base learner-e, a Random Forest kao meta-learner za objedinjavanje njihovih predikcija. Meta-learner će biti treniran na izlazima base learner-a (korišćenjem cross-validation-a na training skupu). Očekujemo da će stacked model raditi jednako dobro kao pojedinačni modeli ili nešto bolje od njih.
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
Naslagani ansambl koristi komplementarne prednosti osnovnih modela. Na primer, logistička regresija može da obrađuje linearne aspekte podataka, stablo odlučivanja može da prepozna specifične interakcije nalik pravilima, a k-NN može da bude naročito uspešan u lokalnim susedstvima prostora karakteristika. Meta-model (ovde random forest) može da nauči kako da ponderiše ove ulaze. Dobijene metrike često pokazuju poboljšanje (čak i ako je neznatno) u odnosu na metrike bilo kog pojedinačnog modela. U našem primeru phishinga, ako je logistička regresija imala F1 vrednost od, recimo, 0.95, a stablo 0.94, stack bi mogao da postigne 0.96 tako što bi iskoristio ono što svaki model ne uspeva da prepozna.

Ensemble metode poput ove pokazuju princip da *"kombinovanje više modela obično dovodi do bolje generalizacije"*.<sup>[[12]](#references)</sup> U cybersecurityju, ovo se može implementirati korišćenjem više detection engine-a (jedan može biti zasnovan na pravilima, drugi na machine learningu, a treći na detekciji anomalija), nakon čega sledi sloj koji objedinjuje njihova upozorenja -- što je praktično oblik ensemble-a -- kako bi doneo konačnu odluku sa većim nivoom pouzdanosti. Prilikom deploymenta ovakvih sistema, potrebno je uzeti u obzir dodatnu složenost i osigurati da ensemble ne postane previše težak za upravljanje ili objašnjavanje. Međutim, sa stanovišta preciznosti, ensemble i stacking predstavljaju moćne alate za poboljšanje performansi modela.

</details>

## References

- [1] [AI and Machine Learning in Cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression, Explained - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Phishing Attacks and Websites Classification Using Machine Learning and Multiple Datasets (A Comparative Analysis)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Denial of Services Attack Detection using Random Forest Classifier with Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Performance analysis of machine learning models for intrusion detection system using Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [What is a Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [What is k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT Demystified: How LightGBM, XGBoost and CatBoost Work - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Boosting Model Performance by Combining Strengths - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [How Deep Learning Enhances Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)

{{#include ../banners/hacktricks-training.md}}
