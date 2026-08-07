# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basiese Inligting

Supervised learning gebruik gelabelde data om modelle op te lei wat voorspellings oor nuwe, ongesiene insette kan maak. In kuberveiligheid word supervised machine learning wyd toegepas op take soos intrusion detection (klassifisering van netwerkverkeer as *normaal* of *aanval*), malware detection (onderskeid tussen kwaadwillige sagteware en onskadelike sagteware), phishing detection (identifisering van bedrieglike webwerwe of e-posse), en spam filtering, onder andere.<sup>[[1]](#references)</sup> Elke algoritme het sy sterk punte en is geskik vir verskillende tipes probleme (klassifikasie of regressie). Hieronder hersien ons belangrike supervised learning-algoritmes, verduidelik ons hoe hulle werk, en demonstreer ons die gebruik daarvan op werklike kuberveiligheidsdatastelle. Ons bespreek ook hoe die kombinasie van modelle (ensemble learning) dikwels voorspellingsprestasie kan verbeter.

## Algorithms

-   **Linear Regression:** ’n Fundamentele regressie-algoritme vir die voorspelling van numeriese uitkomste deur ’n lineêre vergelyking by data te pas.

-   **Logistic Regression:** ’n Klassifikasie-algoritme (ten spyte van sy naam) wat ’n logistieke funksie gebruik om die waarskynlikheid van ’n binêre uitkoms te modelleer.

-   **Decision Trees:** Boomgestruktureerde modelle wat data volgens kenmerke verdeel om voorspellings te maak; word dikwels gebruik weens hul interpreteerbaarheid.

-   **Random Forests:** ’n Ensemble van decision trees (deur middel van bagging) wat akkuraatheid verbeter en overfitting verminder.

-   **Support Vector Machines (SVM):** Max-margin-klassifiseerders wat die optimale skeidingshipervlak vind; kan kernels vir nie-lineêre data gebruik.

-   **Naive Bayes:** ’n Waarskynlikheidsklassifiseerder gebaseer op Bayes se stelling, met ’n aanname van kenmerkonafhanklikheid, wat veral bekend is vir gebruik in spam filtering.

-   **k-Nearest Neighbors (k-NN):** ’n Eenvoudige "instance-based"-klassifiseerder wat ’n sample benoem op grond van die meerderheidklas van sy naaste bure.

-   **Gradient Boosting Machines:** Ensemble-modelle (bv. XGBoost, LightGBM) wat ’n sterk voorspeller bou deur agtereenvolgens swakker learners by te voeg (gewoonlik decision trees).

Elke afdeling hieronder verskaf ’n verbeterde beskrywing van die algoritme en ’n **Python code example** wat biblioteke soos `pandas` en `scikit-learn` (en `PyTorch` vir die neural network-voorbeeld) gebruik. Die voorbeelde gebruik publiek beskikbare kuberveiligheidsdatastelle (soos NSL-KDD vir intrusion detection en ’n Phishing Websites-datastel) en volg ’n konsekwente struktuur:

1.  **Laai die datastel** (download dit via URL indien beskikbaar).

2.  **Preprocess die data** (bv. enkodeer kategoriese kenmerke, skaal waardes, en verdeel dit in train/test-stelle).

3.  **Train die model** op die training data.

4.  **Evalueer** dit op ’n test set deur metrieke te gebruik: accuracy, precision, recall, F1-score en ROC AUC vir klassifikasie (en mean squared error vir regressie).

Kom ons kyk na elke algoritme:

### Linear Regression

Linear regression is ’n **regressie**-algoritme wat gebruik word om deurlopende numeriese waardes te voorspel. Dit neem aan dat daar ’n lineêre verhouding tussen die insetkenmerke (onafhanklike veranderlikes) en die uitset (afhanklike veranderlike) bestaan. Die model probeer om ’n reguit lyn (of hipervlak in hoër dimensies) te pas wat die verhouding tussen die kenmerke en die teiken die beste beskryf. Dit word gewoonlik gedoen deur die som van die kwadraatfoute tussen voorspelde en werklike waardes te minimaliseer (Ordinary Least Squares-metode).<sup>[[2]](#references)</sup>

Die eenvoudigste manier om linear regression voor te stel, is met ’n lyn:
```plaintext
y = mx + b
```
Waar:

- `y` die voorspelde waarde (uitset) is
- `m` die helling van die lyn (koëffisiënt) is
- `x` die insetkenmerk is
- `b` die y-afsnit is

Die doel van lineêre regressie is om die lyn met die beste passing te vind wat die verskil tussen die voorspelde waardes en die werklike waardes in die datastel minimaliseer. Natuurlik is dit baie eenvoudig; dit sal ’n reguit lyn wees wat 2 kategorieë skei, maar indien meer dimensies bygevoeg word, word die lyn meer kompleks:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Lineêre regressie self is minder algemeen vir kernsekuriteitstake (wat dikwels klassifikasie behels), maar dit kan gebruik word om numeriese uitkomste te voorspel. Byvoorbeeld, kan lineêre regressie gebruik word om **die volume van netwerkverkeer te voorspel** of **die aantal aanvalle in ’n tydperk te skat** op grond van historiese data. Dit kan ook ’n risikotelling of die verwagte tyd tot die opsporing van ’n aanval voorspel, gegewe sekere stelselmetrieke. In die praktyk word klassifikasie-algoritmes (soos logistiese regressie of bome) meer dikwels gebruik om indringings of malware op te spoor, maar lineêre regressie dien as ’n grondslag en is nuttig vir regressie-georiënteerde ontledings.

#### **Belangrike kenmerke van Lineêre Regressie:**

-   **Tipe probleem:** Regressie (voorspelling van kontinue waardes). Nie geskik vir direkte klassifikasie nie, tensy ’n drempel op die afvoer toegepas word.

-   **Interpreteerbaarheid:** Hoog -- koëffisiënte is maklik om te interpreteer en toon die lineêre effek van elke kenmerk.

-   **Voordele:** Eenvoudig en vinnig; ’n goeie basislyn vir regressietake; werk goed wanneer die werklike verband ongeveer lineêr is.

-   **Beperkings:** Kan nie komplekse of nie-lineêre verhoudings vasvang nie (sonder handmatige kenmerk-ingenieurswese); geneig tot onderpassing wanneer verhoudings nie-lineêr is; sensitief vir uitskieters wat die resultate kan verdraai.

-   **Vind van die beste passing:** Om die beste paslyn te vind wat die moontlike kategorieë skei, gebruik ons ’n metode genaamd **Ordinary Least Squares (OLS)**. Hierdie metode minimaliseer die som van die gekwadreerde verskille tussen die waargenome waardes en die waardes wat deur die lineêre model voorspel word.

<details>
<summary>Voorbeeld -- Voorspelling van verbindingduur (regressie) in ’n indringingsdatastel
</summary>
Hieronder demonstreer ons lineêre regressie met behulp van die NSL-KDD-kuberveiligheidsdatastel. Ons sal dit as ’n regressieprobleem hanteer deur die `duration` van netwerkverbindings op grond van ander kenmerke te voorspel. (In werklikheid is `duration` een kenmerk van NSL-KDD; ons gebruik dit hier slegs om regressie te illustreer.) Ons laai die datastel, verwerk dit vooraf (kodeer kategoriese kenmerke), lei ’n lineêre regressiemodel op en evalueer die Mean Squared Error (MSE)- en R²-telling op ’n toetsstel.
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
In hierdie voorbeeld probeer die linear regression-model om connection `duration` uit ander netwerkkenmerke te voorspel. Ons meet werkverrigting met Mean Squared Error (MSE) en R². ’n R² naby 1.0 sal aandui dat die model die meeste variasie in `duration` verklaar, terwyl ’n lae of negatiewe R² op ’n swak passing dui. (Moenie verbaas wees as die R² hier laag is nie -- dit kan moeilik wees om `duration` uit die gegewe kenmerke te voorspel, en linear regression sal moontlik nie die patrone vasvang as hulle kompleks is nie.)
</details>

### Logistic Regression

Logistic regression is ’n **klassifikasie**-algoritme wat die waarskynlikheid modelleer dat ’n instansie aan ’n bepaalde klas behoort (tipies die "positiewe" klas). Ondanks sy naam word *logistic* regression vir diskrete uitkomste gebruik (anders as linear regression, wat vir deurlopende uitkomste is). Dit word veral vir **binêre klassifikasie** gebruik (twee klasse, byvoorbeeld malicious teenoor benign), maar dit kan na multi-class-probleme uitgebrei word (met softmax- of one-vs-rest-benaderings).<sup>[[3]](#references)</sup>

Die logistic regression gebruik die logistic-funksie (ook bekend as die sigmoid-funksie) om voorspelde waardes na waarskynlikhede te karteer. Let daarop dat die sigmoid-funksie ’n funksie is met waardes tussen 0 en 1 wat in ’n S-vormige kurwe groei volgens die behoeftes van die klassifikasie, wat nuttig is vir binêre klassifikasietake. Daarom word elke kenmerk van elke invoer met sy toegekende gewig vermenigvuldig, en die resultaat word deur die sigmoid-funksie gestuur om ’n waarskynlikheid te lewer:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Waar:

- `p(y=1|x)` is die waarskynlikheid dat die uitset `y` 1 is gegewe die inset `x`
- `e` is die basis van die natuurlike logaritme
- `z` is ’n lineêre kombinasie van die insetkenmerke, tipies voorgestel as `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Let daarop dat dit in sy eenvoudigste vorm weer ’n reguit lyn is, maar in meer komplekse gevalle word dit ’n hiperoppervlak met verskeie dimensies (een per kenmerk).

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Omdat baie sekuriteitsprobleme in wese ja/nee-besluite is, word logistiese regressie wyd gebruik. Byvoorbeeld, ’n indringingopsporingstelsel kan logistiese regressie gebruik om te besluit of ’n netwerkverbinding ’n aanval is, gebaseer op kenmerke van daardie verbinding. In phishing-opsporing kan logistiese regressie kenmerke van ’n webwerf (URL-lengte, teenwoordigheid van die "@"-simbool, ens.) kombineer tot ’n waarskynlikheid dat dit phishing is. Dit is in vroeë generasie spamfilters gebruik en bly ’n sterk basislyn vir baie klassifikasietake.

#### Logistiese regressie vir nie-binêre klassifikasie

Logistiese regressie is ontwerp vir binêre klassifikasie, maar dit kan uitgebrei word om multiklasprobleme te hanteer deur tegnieke soos **one-vs-rest** (OvR) of **softmax regression** te gebruik. In OvR word ’n aparte logistiese regressiemodel vir elke klas opgelei, waar dit as die positiewe klas teenoor al die ander behandel word. Die klas met die hoogste voorspelde waarskynlikheid word as die finale voorspelling gekies. Softmax regression veralgemeen logistiese regressie na veelvuldige klasse deur die softmax-funksie op die uitsetlaag toe te pas, wat ’n waarskynlikheidsverdeling oor alle klasse lewer.

#### **Belangrikste kenmerke van logistiese regressie:**

-   **Tipe probleem:** Klassifikasie (gewoonlik binêr). Dit voorspel die waarskynlikheid van die positiewe klas.

-   **Interpreteerbaarheid:** Hoog -- soos met lineêre regressie kan die kenmerkk koëffisiënte aandui hoe elke kenmerk die log-odds van die uitkoms beïnvloed. Hierdie deursigtigheid word dikwels in sekuriteit waardeer om te verstaan watter faktore tot ’n waarskuwing bydra.

-   **Voordele:** Eenvoudig en vinnig om op te lei; werk goed wanneer die verhouding tussen kenmerke en die log-odds van die uitkoms lineêr is. Dit lewer waarskynlikhede, wat risikotelling moontlik maak. Met toepaslike regularisering veralgemeen dit goed en kan dit multikollineariteit beter hanteer as gewone lineêre regressie.

-   **Beperkings:** Neem ’n lineêre beslissingsgrens in die kenmerkruimte aan (misluk as die werklike grens kompleks/nie-lineêr is). Dit kan swakker presteer op probleme waar interaksies of nie-lineêre effekte krities is, tensy jy polinoom- of interaksiekenmerke handmatig byvoeg. Logistiese regressie is ook minder doeltreffend as klasse nie maklik deur ’n lineêre kombinasie van kenmerke geskei kan word nie.


<details>
<summary>Voorbeeld -- Phishing-webwerfopsporing met logistiese regressie:</summary>

Ons sal ’n **Phishing Websites Dataset** (van die UCI-bewaarplek) gebruik, wat onttrekte kenmerke van webwerwe bevat (soos of die URL ’n IP-adres het, die ouderdom van die domein, die teenwoordigheid van verdagte elemente in HTML, ens.) en ’n etiket wat aandui of die webwerf phishing of wettig is.<sup>[[4]](#references)</sup> Ons lei ’n logistiese regressiemodel op om webwerwe te klassifiseer en evalueer dan die akkuraatheid, presisie, herroeping, F1-telling en ROC AUC daarvan op ’n toetssplitsing.
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
In hierdie phishing detection-voorbeeld produseer logistic regression ’n waarskynlikheid vir elke webwerf dat dit phishing is. Deur accuracy, precision, recall en F1 te evalueer, kry ons ’n aanduiding van die model se prestasie. Byvoorbeeld, ’n hoë recall sou beteken dat dit die meeste phishing-webwerwe opspoor (belangrik vir sekuriteit om gemiste aanvalle te beperk), terwyl hoë precision beteken dat dit min vals alarms genereer (belangrik om ontleder-uitputting te voorkom). Die ROC AUC (Area Under the ROC Curve) gee ’n drempel-onafhanklike maatstaf van prestasie (1.0 is ideaal, 0.5 is nie beter as toevallig nie). Logistic regression presteer dikwels goed met sulke take, maar indien die besluitgrens tussen phishing- en wettige webwerwe kompleks is, mag kragtiger nie-lineêre modelle nodig wees.

</details>

### Besluitbome

’n Besluitboom is ’n veelsydige **toesigleer-algoritme** wat vir beide klassifikasie- en regressietake gebruik kan word. Dit leer ’n hiërargiese boomagtige model van besluite gebaseer op die data se kenmerke. Elke interne nodus van die boom verteenwoordig ’n toets op ’n bepaalde kenmerk, elke tak verteenwoordig ’n uitkoms van daardie toets, en elke blaarnodus verteenwoordig ’n voorspelde klas (vir klassifikasie) of waarde (vir regressie).<sup>[[5]](#references)</sup>

Om ’n boom te bou, gebruik algorithms soos CART (Classification and Regression Tree) maatstawwe soos **Gini impurity** of **information gain (entropy)** om die beste kenmerk en drempel te kies waarvolgens die data by elke stap verdeel moet word. Die doel by elke verdeling is om die data te partisieer sodat die homogeniteit van die teikenveranderlike in die gevolglike subversamelings verhoog word (vir klassifikasie poog elke nodus om so suiwer as moontlik te wees deur hoofsaaklik ’n enkele klas te bevat).

Besluitbome is **hoogs interpreteerbaar** -- ’n mens kan die pad van die wortel tot by die blaar volg om die logika agter ’n voorspelling te verstaan (bv. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Dit is waardevol in cybersecurity om te verduidelik waarom ’n bepaalde alert gegenereer is. Bome kan natuurlik sowel numeriese as kategoriese data hanteer en vereis min preprocessing (bv. feature scaling is nie nodig nie).

’n Enkele besluitboom kan egter maklik die training data oorfit, veral indien dit diep gegroei word (met baie verdelings). Tegnieke soos pruning (die beperking van boomdiepte of die vereiste van ’n minimum aantal samples per blaar) word dikwels gebruik om overfitting te voorkom.

Daar is 3 hoofkomponente van ’n besluitboom:
- **Root Node**: Die boonste nodus van die boom, wat die volledige dataset verteenwoordig.
- **Internal Nodes**: Nodusse wat kenmerke en besluite gebaseer op daardie kenmerke verteenwoordig.
- **Leaf Nodes**: Nodusse wat die finale uitkoms of voorspelling verteenwoordig.

’n Boom kan uiteindelik soos volg lyk:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Gebruiksgevalle in cybersecurity:* Besluitbome is in intrusion detection systems gebruik om **reëls** af te lei vir die identifisering van attacks. Byvoorbeeld, vroeë IDS'e soos ID3/C4.5-gebaseerde systems sou mensleesbare reëls genereer om normale teenoor malicious traffic te onderskei. Hulle word ook in malware analysis gebruik om te bepaal of 'n file malicious is op grond van sy attributes (file size, section entropy, API calls, ens.). Die duidelikheid van besluitbome maak hulle nuttig wanneer transparency nodig is -- 'n analyst kan die boom inspekteer om die detection logic te valideer.

#### **Sleutelkenmerke van Besluitbome:**

-   **Tipe probleem:** Beide classification en regression. Word algemeen gebruik vir die classification van attacks teenoor normale traffic, ens.

-   **Interpreteerbaarheid:** Baie hoog -- die model se besluite kan gevisualiseer en verstaan word as 'n stel if-then-reëls. Dit is 'n groot voordeel in security vir trust en verification van modelgedrag.

-   **Voordele:** Kan non-linear relationships en interactions tussen features vasvang (elke split kan as 'n interaction beskou word). Dit is nie nodig om features te scale of categorical variables one-hot te encode nie -- bome hanteer dit natively. Fast inference (prediction is bloot die volg van 'n path in die boom).

-   **Beperkings:** Geneig tot overfitting indien dit nie beheer word nie ('n diep boom kan die training set memoriseer). Hulle kan unstable wees -- klein veranderinge in data kan tot 'n ander boomstruktuur lei. As single models stem hul accuracy moontlik nie ooreen met meer gevorderde methods nie (ensembles soos Random Forests presteer tipies beter deur variance te verminder).

-   **Vind van die beste split:**
- **Gini-onreinheid**: Meet die onreinheid van 'n node. 'n Laer Gini-onreinheid dui op 'n beter split. Die formule is:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Waar `p_i` die proporsie van instances in class `i` is.

- **Entropie**: Meet die onsekerheid in die dataset. 'n Laer entropie dui op 'n beter split. Die formule is:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Waar `p_i` die proporsie van instances in class `i` is.

- **Inligtingswins**: Die vermindering in entropie of Gini-onreinheid ná 'n split. Hoe hoër die inligtingswins, hoe beter die split. Dit word bereken as:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Verder word 'n boom beëindig wanneer:
- Alle instances in 'n node aan dieselfde class behoort. Dit kan tot overfitting lei.
- Die maksimum diepte (hardcoded) van die boom bereik word. Dit is 'n manier om overfitting te voorkom.
- Die aantal instances in 'n node onder 'n sekere threshold is. Dit is ook 'n manier om overfitting te voorkom.
- Die inligtingswins van verdere splits onder 'n sekere threshold is. Dit is ook 'n manier om overfitting te voorkom.

<details>
<summary>Voorbeeld -- Besluitboom vir Intrusion Detection:</summary>
Ons sal 'n besluitboom op die NSL-KDD-dataset train om network connections as óf *normal* óf *attack* te classifiseer. NSL-KDD is 'n verbeterde weergawe van die klassieke KDD Cup 1999-dataset, met features soos protocol type, service, duration, number of failed logins, ens., en 'n label wat die attack type of "normal" aandui. Ons sal alle attack types na 'n "anomaly"-class map (binary classification: normal teenoor anomaly). Ná training sal ons die boom se performance op die test set evalueer.
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
In hierdie voorbeeld van ’n decision tree het ons die boomdiepte tot 10 beperk om ekstreme overfitting te voorkom (die `max_depth=10`-parameter). Die metrics wys hoe goed die boom normale verkeer van attack-verkeer onderskei. ’n Hoë recall sou beteken dat dit die meeste attacks opvang (belangrik vir ’n IDS), terwyl hoë precision min vals alarms beteken. Decision trees behaal dikwels goeie accuracy op gestruktureerde data, maar ’n enkele boom bereik moontlik nie die beste moontlike performance nie. Nietemin is die *interpretability* van die model ’n groot voordeel -- ons kan die boom se splits ondersoek om byvoorbeeld te sien watter features (bv. `service`, `src_bytes`, ens.) die invloedrykste is wanneer ’n verbinding as kwaadwillig gemerk word.

</details>

### Random Forests

Random Forest is ’n **ensemble learning**-metode wat op decision trees voortbou om performance te verbeter. ’n random forest train verskeie decision trees (vandaar "forest") en kombineer hul outputs om ’n finale prediction te maak (vir classification gewoonlik deur majority vote). Die twee hoofidees in ’n random forest is **bagging** (bootstrap aggregating) en **feature randomness**:

-   **Bagging:** Elke tree word getrain op ’n random bootstrap sample van die training data (geselekteer met replacement). Dit skep diversiteit tussen die trees.

-   **Feature Randomness:** By elke split in ’n tree word ’n random subset van features vir splitting oorweeg (in plaas van alle features). Dit verminder die korrelasie tussen die trees verder.

Deur die resultate van baie trees te average, verminder die random forest die variance wat ’n enkele decision tree kan hê. Eenvoudig gestel, individuele trees kan overfit of raserig wees, maar ’n groot aantal diverse trees wat saam stem, maak hierdie errors gladder. Die resultaat is dikwels ’n model met **hoër accuracy** en beter generalization as ’n enkele decision tree. Daarbenewens kan random forests ’n skatting van feature importance verskaf (deur te kyk hoeveel elke feature split gemiddeld impurity verminder).

Random forests het ’n **workhorse in cybersecurity** geword vir take soos intrusion detection, malware classification en spam detection. Hulle presteer dikwels goed out-of-the-box met minimale tuning en kan groot feature sets hanteer. Byvoorbeeld, in intrusion detection kan ’n random forest beter as ’n individuele decision tree presteer deur meer subtiele attack-patrone met minder false positives op te spoor. Navorsing het getoon dat random forests gunstig presteer in vergelyking met ander algorithms wanneer attacks in datasets soos NSL-KDD en UNSW-NB15 geklassifiseer word.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Sleutelkenmerke van Random Forests:**

-   **Tipe probleem:** Hoofsaaklik classification (word ook vir regression gebruik). Baie geskik vir high-dimensional gestruktureerde data wat algemeen in security logs voorkom.

-   **Interpretability:** Laer as dié van ’n enkele decision tree -- jy kan nie maklik honderde trees gelyk visualiseer of verduidelik nie. Feature importance-scores bied egter ’n mate van insig in watter attributes die invloedrykste is.

-   **Voordele:** Oor die algemeen hoër accuracy as single-tree-modelle weens die ensemble-effek. Bestand teen overfitting -- selfs al overfit individuele trees, generaliseer die ensemble beter. Hanteer sowel numeriese as categorical features en kan missing data tot ’n mate bestuur. Dit is ook relatief bestand teen outliers.

-   **Beperkings:** Die modelgrootte kan groot wees (baie trees, waarvan elkeen potensieel diep kan wees). Predictions is stadiger as dié van ’n enkele tree (want jy moet resultate van baie trees aggregate). Minder interpreteerbaar -- hoewel jy weet watter features belangrik is, kan die presiese logic nie maklik soos ’n eenvoudige rule nagespoor word nie. As die dataset uiters high-dimensional en sparse is, kan die training van ’n baie groot forest computationally swaar wees.

-   **Training Process:**
1. **Bootstrap Sampling**: Sample die training data random met replacement om verskeie subsets (bootstrap samples) te skep.
2. **Tree Construction**: Bou vir elke bootstrap sample ’n decision tree deur ’n random subset van features by elke split te gebruik. Dit skep diversiteit tussen die trees.
3. **Aggregation**: Vir classification-take word die finale prediction gemaak deur ’n majority vote onder die predictions van alle trees te neem. Vir regression-take is die finale prediction die average van die predictions van alle trees.

<details>
<summary>Voorbeeld -- Random Forest vir Intrusion Detection (NSL-KDD):</summary>
Ons sal dieselfde NSL-KDD-dataset gebruik (binêr gelabel as normal teenoor anomaly) en ’n Random Forest-classifier train. Ons verwag dat die random forest minstens so goed soos, of beter as, die enkele decision tree sal presteer, danksy die ensemble averaging wat variance verminder. Ons sal dit met dieselfde metrics evalueer.
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
Die random forest behaal tipies sterk resultate op hierdie intrusion detection-taak. Ons kan ’n verbetering in maatstawwe soos F1 of AUC waarneem vergeleke met die enkele decision tree, veral in recall of precision, afhangend van die data. Dit stem ooreen met die begrip dat *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> In ’n security operations-konteks kan ’n random forest-model attacks meer betroubaar aandui terwyl dit false alarms verminder, danksy die gemiddeld van baie decision rules. Feature importance vanuit die forest kan ons wys watter network features die meeste aanduidend van attacks is (byvoorbeeld sekere network services of ongewone hoeveelhede packets).

</details>

### Support Vector Machines (SVM)

Support Vector Machines is kragtige supervised learning-modelle wat hoofsaaklik vir classification gebruik word (en ook vir regression as SVR). ’n SVM probeer die **optimale skeidings-hyperplane** vind wat die margin tussen twee klasse maksimeer. Slegs ’n subset van die training points (die "support vectors" naaste aan die grens) bepaal die posisie van hierdie hyperplane. Deur die margin (afstand tussen support vectors en die hyperplane) te maksimeer, is SVMs geneig om goeie generalisering te behaal.<sup>[[8]](#references)</sup>

Die vermoë om **kernel functions** te gebruik om non-linear relationships te hanteer, is sentraal tot SVM se krag. Die data kan implisiet na ’n hoër-dimensionele feature space getransformeer word waar ’n linear separator moontlik bestaan. Algemene kernels sluit polynomial, radial basis function (RBF) en sigmoid in. Byvoorbeeld, as network traffic-klasse nie lineêr separable is in die rou feature space nie, kan ’n RBF-kernel dit na ’n hoër dimensie karteer waar die SVM ’n linear split vind (wat met ’n non-linear grens in die oorspronklike ruimte ooreenstem). Die buigsaamheid om kernels te kies, stel SVMs in staat om ’n verskeidenheid probleme aan te pak.

SVMs is bekend daarvoor dat hulle goed presteer in situasies met hoë-dimensionele feature spaces (soos text data of malware opcode sequences) en in gevalle waar die aantal features groot is relatief tot die aantal samples. Hulle was gewild in baie vroeë cybersecurity-toepassings, soos malware classification en anomaly-based intrusion detection in die 2000’s, waar hulle dikwels hoë accuracy getoon het.

SVMs skaal egter nie maklik na baie groot datasets nie (training complexity is super-lineêr in die aantal samples, en memory usage kan hoog wees omdat dit moontlik baie support vectors moet stoor). In praktyk kan SVM vir take soos network intrusion detection met miljoene records te stadig wees sonder noukeurige subsampling of die gebruik van approximate methods.

#### **Belangrike eienskappe van SVM:**

-   **Tipe probleem:** Classification (binary of multiclass via one-vs-one/one-vs-rest) en regression-variante. Word dikwels in binary classification met duidelike margin separation gebruik.

-   **Interpreteerbaarheid:** Medium -- SVMs is nie so interpreteerbaar soos decision trees of logistic regression nie. Hoewel jy kan identifiseer watter data points support vectors is en ’n mate van insig kan kry in watter features invloedryk kan wees (deur die weights in die linear kernel-geval), word SVMs (veral met non-linear kernels) in praktyk as black-box classifiers behandel.

-   **Voordele:** Effektief in hoë-dimensionele ruimtes; kan komplekse decision boundaries met die kernel trick modelleer; bestand teen overfitting indien die margin gemaksimeer word (veral met ’n behoorlike regularization parameter C); werk goed selfs wanneer klasse nie deur ’n groot afstand geskei word nie (vind die beste kompromisgrens).

-   **Beperkings:** **Computationally intensief** vir groot datasets (beide training en prediction skaal swak namate data groei). Vereis noukeurige instelling van kernel- en regularization-parameters (C, kernel type, gamma vir RBF, ensovoorts). Verskaf nie direk probabilistic outputs nie (hoewel Platt scaling gebruik kan word om probabilities te verkry). SVMs kan ook sensitief wees vir die keuse van kernel-parameters --- ’n swak keuse kan tot underfit of overfit lei.

*Use cases in cybersecurity:* SVMs is gebruik in **malware detection** (byvoorbeeld om files te klassifiseer op grond van extracted features of opcode sequences), **network anomaly detection** (om traffic as normal of malicious te klassifiseer) en **phishing detection** (deur features van URLs te gebruik). ’n SVM kan byvoorbeeld features van ’n e-pos (tellings van sekere keywords, sender reputation scores, ensovoorts) neem en dit as phishing of legitimate klassifiseer. Hulle is ook toegepas op **intrusion detection** met feature sets soos KDD, waar hulle dikwels hoë accuracy ten koste van computation behaal het.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Ons sal weer die phishing website-dataset gebruik, hierdie keer met ’n SVM. Omdat SVMs stadig kan wees, sal ons indien nodig ’n subset van die data vir training gebruik (die dataset bevat ongeveer 11k instances, wat SVM redelik goed kan hanteer). Ons sal ’n RBF-kernel gebruik, wat ’n algemene keuse vir non-linear data is, en probability estimates aktiveer om ROC AUC te bereken.
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
Die SVM-model sal metrieke uitvoer wat ons met logistic regression op dieselfde taak kan vergelyk. Ons kan vind dat SVM hoë akkuraatheid en AUC behaal as die data goed deur die kenmerke geskei word. Aan die ander kant, as die datastel baie geraas of oorvleuelende klasse gehad het, sal SVM moontlik nie beduidend beter as logistic regression presteer nie. In die praktyk kan SVM 'n verbetering bied wanneer daar komplekse, nie-lineêre verwantskappe tussen kenmerke en klasse is -- die RBF-kernel kan geboë besluitnemingsgrense vasvang wat logistic regression sou mis. Soos met alle modelle, is noukeurige instel van die `C` (regularisering) en kernel-parameters (soos `gamma` vir RBF) nodig om bias en variansie te balanseer.

</details>

#### Verskil tussen Logistic Rergressies & SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Doelfunksie** | Minimaliseer **log-loss** (kruisentropie). | Maksimeer die **marge** terwyl **hinge-loss** geminimaliseer word. |
| **Besluitnemingsgrens** | Vind die **beste-passing-hipervlak** wat _P(y\|x)_ modelleer. | Vind die **hipervlak met die maksimum marge** (grootste gaping tot die naaste punte). |
| **Uitset** | **Probabilisties** – gee gekalibreerde klaswaarskynlikhede via σ(w·x + b). | **Deterministies** – lewer klasetikette; waarskynlikhede benodig ekstra werk (bv. Platt scaling). |
| **Regularisering** | L2 (verstek) of L1, balanseer onder-/oorpassing direk. | C-parameter balanseer margedikte teenoor verkeerde klassifikasies; kernel-parameters voeg kompleksiteit by. |
| **Kernels / Nie-lineêr** | Die inheemse vorm is **lineêr**; nie-lineariteit word deur kenmerk-ingenieurswese bygevoeg. | Ingeboude **kernel trick** (RBF, poly, ens.) laat dit toe om komplekse grense in hoë-dim. ruimte te modelleer. |
| **Skaalbaarheid** | Los 'n konvekse optimalisering in **O(nd)** op; hanteer baie groot n goed. | Opleiding kan **O(n²–n³)** geheue/tyd gebruik sonder gespesialiseerde solvers; minder geskik vir enorme n. |
| **Interpreteerbaarheid** | **Hoog** – gewigte toon kenmerkinvloed; odds ratio is intuïtief. | **Laag** vir nie-lineêre kernels; support vectors is yl maar nie maklik om te verduidelik nie. |
| **Sensitiwiteit vir uitskieters** | Gebruik gladde log-loss → minder sensitief. | Hinge-loss met 'n harde marge kan **sensitief** wees; sagte marge (C) versag dit. |
| **Tipiese gebruiksgevalle** | Krediettelling, mediese risiko, A/B-toetsing – waar **waarskynlikhede en verklaarbaarheid** belangrik is. | Beeld-/teksklassifikasie, bio-informatika – waar **komplekse grense** en **hoë-dimensionele data** belangrik is. |

* **As jy gekalibreerde waarskynlikhede, interpreteerbaarheid benodig of op enorme datastelle werk — kies Logistic Regression.**
* **As jy 'n buigsame model benodig wat nie-lineêre verwantskappe sonder handmatige kenmerk-ingenieurswese kan vasvang — kies SVM (met kernels).**
* Albei optimaliseer konvekse doelfunksies, dus **globale minima word gewaarborg**, maar SVM se kernels voeg hiperparameters en berekeningskoste by.

### Naive Bayes

Naive Bayes is 'n familie van **probabilistiese klassifiseerders** wat gebaseer is op die toepassing van Bayes se stelling met 'n sterk onafhanklikheidsaanname tussen kenmerke. Ten spyte van hierdie "naive" aanname werk Naive Bayes dikwels verrassend goed vir sekere toepassings, veral dié wat teks of kategoriese data behels, soos spamopsporing.<sup>[[9]](#references)</sup>


#### Bayes se Stelling

Bayes se stelling is die grondslag van Naive Bayes-klassifiseerders. Dit verbind die voorwaardelike en marginale waarskynlikhede van ewekansige gebeurtenisse. Die formule is:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Waar:
- `P(A|B)` is die posterior-waarskynlikheid van klas `A` gegewe kenmerk `B`.
- `P(B|A)` is die likelihood van kenmerk `B` gegewe klas `A`.
- `P(A)` is die prior-waarskynlikheid van klas `A`.
- `P(B)` is die prior-waarskynlikheid van kenmerk `B`.

Byvoorbeeld, as ons wil klassifiseer of 'n teks deur 'n kind of 'n volwassene geskryf is, kan ons die woorde in die teks as kenmerke gebruik. Gebaseer op sekere aanvanklike data, sal die Naive Bayes-classifier vooraf die waarskynlikhede bereken dat elke woord in elke moontlike klas (kind of volwassene) voorkom. Wanneer 'n nuwe teks gegee word, sal dit die waarskynlikheid van elke moontlike klas gegewe die woorde in die teks bereken en die klas met die hoogste waarskynlikheid kies.

Soos jy in hierdie voorbeeld kan sien, is die Naive Bayes-classifier baie eenvoudig en vinnig, maar dit neem aan dat die kenmerke onafhanklik is, wat nie altyd die geval in werklike data is nie.


#### Tipes Naive Bayes-classifiers

Daar is verskeie tipes Naive Bayes-classifiers, afhangend van die tipe data en die verspreiding van die kenmerke:
- **Gaussian Naive Bayes**: Neem aan dat die kenmerke 'n Gaussian (normale) verspreiding volg. Dit is geskik vir kontinue data.
- **Multinomial Naive Bayes**: Neem aan dat die kenmerke 'n multinomiale verspreiding volg. Dit is geskik vir diskrete data, soos woordtellings in teksklassifikasie.
- **Bernoulli Naive Bayes**: Neem aan dat die kenmerke binêr (0 of 1) is. Dit is geskik vir binêre data, soos die teenwoordigheid of afwesigheid van woorde in teksklassifikasie.
- **Categorical Naive Bayes**: Neem aan dat die kenmerke kategoriese veranderlikes is. Dit is geskik vir kategoriese data, soos om vrugte volgens hul kleur en vorm te klassifiseer.


#### **Sleutelkenmerke van Naive Bayes:**

-   **Tipe probleem:** Klassifikasie (binêr of multi-klas). Word algemeen gebruik vir teksklassifikasietake in kuberveiligheid (spam, phishing, ens.).

-   **Interpreteerbaarheid:** Medium -- dit is nie so direk interpreteerbaar soos 'n besluitnemingsboom nie, maar 'n mens kan die aangeleerde waarskynlikhede inspekteer (bv. watter woorde die waarskynlikste in spam- teenoor ham-e-posse voorkom). Die model se vorm (waarskynlikhede vir elke kenmerk gegewe die klas) kan verstaan word indien nodig.

-   **Voordele:** **Baie vinnige** opleiding en voorspelling, selfs op groot datastelle (lineêr in die aantal gevalle * aantal kenmerke). Vereis 'n relatief klein hoeveelheid data om waarskynlikhede betroubaar te skat, veral met behoorlike smoothing. Dit is dikwels verrassend akkuraat as 'n baseline, veral wanneer kenmerke onafhanklik tot die bewyse vir die klas bydra. Werk goed met hoë-dimensiedata (bv. duisende kenmerke uit teks). Geen komplekse tuning word vereis buiten die instelling van 'n smoothing-parameter nie.

-   **Beperkings:** Die onafhanklikheidsaanname kan akkuraatheid beperk as kenmerke sterk gekorreleer is. Byvoorbeeld, in netwerkdata kan kenmerke soos `src_bytes` en `dst_bytes` gekorreleer wees; Naive Bayes sal nie daardie interaksie vasvang nie. Namate die datagrootte baie groot word, kan meer ekspressiewe modelle (soos ensembles of neurale netwerke) NB oortref deur kenmerkafhanklikhede aan te leer. Indien 'n sekere kombinasie van kenmerke nodig is om 'n aanval te identifiseer (nie net individuele kenmerke onafhanklik nie), sal NB ook sukkel.

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Die klassieke gebruik is **spam detection** -- Naive Bayes was die kern van vroeë spamfilters, wat die frekwensies van sekere tokens (woorde, frases, IP-adresse) gebruik het om die waarskynlikheid te bereken dat 'n e-pos spam is. Dit word ook gebruik in **phishing-e-posdetectie** en **URL-klassifikasie**, waar die teenwoordigheid van sekere sleutelwoorde of eienskappe (soos "login.php" in 'n URL, of `@` in 'n URL-pad) tot die phishing-waarskynlikheid bydra. In malware-analise kan 'n mens 'n Naive Bayes-classifier voorstel wat die teenwoordigheid van sekere API calls of toestemmings in sagteware gebruik om te voorspel of dit malware is. Hoewel meer gevorderde algoritmes dikwels beter presteer, bly Naive Bayes 'n goeie baseline weens sy spoed en eenvoud.

<details>
<summary>Voorbeeld -- Naive Bayes vir Phishing Detection:</summary>
Om Naive Bayes te demonstreer, sal ons Gaussian Naive Bayes op die NSL-KDD intrusion-datastel (met binêre labels) gebruik. Gaussian NB sal elke kenmerk behandel asof dit per klas 'n normale verspreiding volg. Dit is 'n rowwe keuse, aangesien baie netwerkkenmerke diskreet of sterk skeef versprei is, maar dit wys hoe NB op kontinue kenmerkdata toegepas sou word. Ons kon ook Bernoulli NB op 'n datastel van binêre kenmerke (soos 'n stel geaktiveerde alerts) kies, maar ons sal hier by NSL-KDD bly vir kontinuïteit.
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
Hierdie kode lei ’n Naive Bayes-classifier op om attacks op te spoor. Naive Bayes sal dinge soos `P(service=http | Attack)` en `P(Service=http | Normal)` bereken op grond van die opleidingsdata, met die aanname dat daar onafhanklikheid tussen features is. Dit sal dan hierdie waarskynlikhede gebruik om nuwe verbindings as óf normaal óf ’n attack te klassifiseer op grond van die waargenome features. Die werkverrigting van NB op NSL-KDD is moontlik nie so hoog soos dié van meer gevorderde modelle nie (omdat feature-onafhanklikheid geskend word), maar dit is dikwels redelik goed en bied die voordeel van uiters hoë spoed. In scenario’s soos real-time e-posfiltrering of aanvanklike triage van URLs kan ’n Naive Bayes-model ooglopend kwaadwillige gevalle vinnig vlag met lae hulpbronverbruik.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors is een van die eenvoudigste machine learning-algoritmes. Dit is ’n **nie-parametriese, instansie-gebaseerde** metode wat voorspellings maak op grond van die ooreenkoms met voorbeelde in die training set. Die idee vir klassifikasie is: om ’n nuwe datapunt te klassifiseer, vind die **k** naaste punte in die training data (sy “naaste bure”), en ken die meerderheidsklas onder daardie bure toe. “Nabyheid” word deur ’n afstandsmaatstaf gedefinieer, gewoonlik Euklidiese afstand vir numeriese data (ander afstande kan vir verskillende tipes features of probleme gebruik word).<sup>[[10]](#references)</sup>

K-NN vereis *geen eksplisiete training nie* -- die “training”-fase behels bloot die stoor van die dataset. Al die werk gebeur tydens die query (prediction): die algoritme moet afstande vanaf die query-punt na alle training-punte bereken om die naastes te vind. Dit maak prediction-tyd **lineêr met die aantal training-samples**, wat duur kan wees vir groot datasets. Daarom is k-NN die beste geskik vir kleiner datasets of scenario’s waar jy geheue en spoed vir eenvoud kan verruil.

Ondanks sy eenvoud kan k-NN baie komplekse decision boundaries modelleer (omdat die decision boundary effektief enige vorm kan hê wat deur die verspreiding van voorbeelde bepaal word). Dit presteer gewoonlik goed wanneer die decision boundary baie onreëlmatig is en jy baie data het -- dit laat die data in wese “vir homself praat”. In hoë dimensies kan afstandsmaatstawwe egter minder betekenisvol word (die curse of dimensionality), en die metode kan sukkel tensy jy ’n enorme aantal samples het.

*Gebruiksscenario’s in cybersecurity:* k-NN is vir anomaly detection toegepas -- byvoorbeeld, ’n intrusion detection system kan ’n netwerkgebeurtenis as kwaadwillig merk indien die meeste van sy naaste bure (vorige gebeurtenisse) kwaadwillig was. As normale verkeer clusters vorm en attacks uitskieters is, is ’n K-NN-benadering (met k=1 of klein k) in wese **nearest-neighbor anomaly detection**. K-NN is ook gebruik om malware-families met binary feature vectors te klassifiseer: ’n nuwe lêer kan as ’n bepaalde malware-familie geklassifiseer word indien dit in feature space baie naby aan bekende instansies van daardie familie is. In die praktyk is k-NN nie so algemeen soos meer skaalbare algoritmes nie, maar dit is konseptueel eenvoudig en word soms as ’n baseline of vir kleinskaalse probleme gebruik.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Klassifikasie (en regression-variante bestaan). Dit is ’n *lazy learning*-metode -- geen eksplisiete model fitting nie.

-   **Interpretability:** Laag tot medium -- daar is geen globale model of bondige verduideliking nie, maar ’n mens kan resultate interpreteer deur na die naaste bure te kyk wat ’n besluit beïnvloed het (bv. “hierdie netwerkvloei is as kwaadwillig geklassifiseer omdat dit soortgelyk is aan hierdie 3 bekende kwaadwillige vloeie”). Verduidelikings kan dus voorbeeldgebaseerd wees.

-   **Advantages:** Baie eenvoudig om te implementeer en te verstaan. Dit maak geen aannames oor die dataverspreiding nie (nie-parametries). Dit kan natuurlik multi-class-probleme hanteer. Dit is **adaptief** in die sin dat decision boundaries baie kompleks kan wees en deur die dataverspreiding gevorm word.

-   **Limitations:** Prediction kan stadig wees vir groot datasets (baie afstande moet bereken word). Dit is geheue-intensief -- dit stoor al die training data. Werkverrigting verswak in hoë-dimensionele feature spaces omdat alle punte geneig is om byna ewe ver van mekaar te wees (wat die konsep van “naaste” minder betekenisvol maak). Jy moet *k* (die aantal bure) toepaslik kies -- ’n te klein k kan raserig wees, terwyl ’n te groot k irrelevante punte uit ander klasse kan insluit. Features moet ook toepaslik geskaal word omdat afstandsberekeninge sensitief is vir skaal.

<details>
<summary>Voorbeeld -- k-NN for Phishing Detection:</summary>

Ons sal weer NSL-KDD (binary classification) gebruik. Omdat k-NN berekeningsintensief is, sal ons ’n subset van die training data gebruik om dit in hierdie demonstrasie hanteerbaar te hou. Ons sal byvoorbeeld 20 000 training samples uit die volledige 125k kies en k=5 bure gebruik. Ná training (eintlik bloot die stoor van die data) sal ons dit op die test set evalueer. Ons sal ook features skaal vir afstandsberekening om te verseker dat geen enkele feature weens sy skaal oorheers nie.
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
Die k-NN-model sal ’n verbinding klassifiseer deur na die 5 naaste verbindings in die subset van die trainingset te kyk. As, byvoorbeeld, 4 van daardie bure aanvalle (anomalieë) is en 1 normaal is, sal die nuwe verbinding as ’n aanval geklassifiseer word. Die werkverrigting kan redelik wees, hoewel dit dikwels nie so hoog is soos dié van ’n goed ingestelde Random Forest of SVM op dieselfde data nie. k-NN kan egter soms uitblink wanneer die klasverdelings baie onreëlmatig en kompleks is -- dit gebruik effektief ’n geheuegebaseerde opsoek. In kuberveiligheid kan k-NN (met k=1 of ’n klein k) gebruik word om bekende aanvalspatrone deur middel van voorbeelde op te spoor, of as ’n komponent in meer komplekse stelsels (bv. vir clustering en dan klassifikasie gebaseer op cluster-lidmaatskap).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines is van die kragtigste algoritmes vir gestruktureerde data. **Gradient boosting** verwys na die tegniek om ’n ensemble van swak leerders (dikwels decision trees) opeenvolgend te bou, waar elke nuwe model die foute van die vorige ensemble regstel. Anders as bagging (Random Forests), wat bome parallel bou en hulle gemiddeld bereken, bou boosting bome *een vir een*, met elkeen wat meer fokus op die gevalle wat vorige bome verkeerd voorspel het.<sup>[[11]](#references)</sup>

Die gewildste implementerings in onlangse jare is **XGBoost**, **LightGBM**, en **CatBoost**, wat almal gradient boosting decision tree (GBDT)-libraries is. Hulle was uiters suksesvol in machine learning-kompetisies en toepassings, en **behaal dikwels state-of-the-art-werkverrigting op tabulêre datasets**. In kuberveiligheid het navorsers en praktisyns gradient boosted trees vir take soos **malware-detection** (met features wat uit lêers of runtime-gedrag onttrek is) en **network intrusion detection** gebruik. ’n Gradient boosting-model kan byvoorbeeld baie swak reëls (bome) kombineer, soos "as daar baie SYN-pakkies en ’n ongewone poort is -> waarskynlik ’n scan", tot ’n sterk saamgestelde detector wat baie subtiele patrone in ag neem.

Waarom is boosted trees so effektief? Elke boom in die reeks word opgelei op die *residual errors* (gradiente) van die huidige ensemble se voorspellings. Op hierdie manier **"boost"** die model geleidelik die gebiede waar dit swak is. Die gebruik van decision trees as base learners beteken dat die finale model komplekse interaksies en nie-lineêre verhoudings kan vasvang. Boosting het ook inherent ’n vorm van ingeboude regularization: deur baie klein bome by te voeg (en ’n learning rate te gebruik om hulle bydraes te skaleer), veralgemeen dit dikwels goed sonder groot overfitting, mits die korrekte parameters gekies word.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Hoofsaaklik klassifikasie en regressie. In sekuriteit is dit gewoonlik klassifikasie (bv. om ’n verbinding of lêer binêr te klassifiseer). Dit hanteer binêre, multi-klas (met toepaslike loss), en selfs ranking-probleme.

-   **Interpretability:** Laag tot medium. Hoewel ’n enkele boosted tree klein is, kan ’n volledige model honderde bome hê, wat as ’n geheel nie deur mense geïnterpreteer kan word nie. Soos Random Forest kan dit egter feature-importance-tellings verskaf, en tools soos SHAP (SHapley Additive exPlanations) kan gebruik word om individuele voorspellings tot ’n mate te interpreteer.

-   **Advantages:** Dikwels die **algoritme met die beste werkverrigting** vir gestruktureerde/tabulêre data. Dit kan komplekse patrone en interaksies opspoor. Dit het baie tuning-knoppies (aantal bome, diepte van bome, learning rate, regularization-terme) om modelkompleksiteit aan te pas en overfitting te voorkom. Moderne implementerings is vir spoed geoptimaliseer (bv. XGBoost gebruik tweede-orde-gradientinligting en doeltreffende datastrukture). Dit is geneig om imbalanced data beter te hanteer wanneer dit met toepaslike loss functions gekombineer word of wanneer sample weights aangepas word.

-   **Limitations:** Dit is meer kompleks om te tune as eenvoudiger modelle; training kan stadig wees as bome diep is of die aantal bome groot is (hoewel dit steeds gewoonlik vinniger is as om ’n vergelykbare deep neural network op dieselfde data op te lei). Die model kan overfit as dit nie getune word nie (bv. te veel diep bome met onvoldoende regularization). Omdat daar baie hyperparameters is, kan die effektiewe gebruik van gradient boosting meer kundigheid of eksperimentering vereis. Soos tree-based methods hanteer dit ook nie inherent baie sparse hoë-dimensiedata so doeltreffend soos linear models of Naive Bayes nie (hoewel dit steeds toegepas kan word, bv. in text classification, maar dit is moontlik nie die eerste keuse sonder feature engineering nie).

> [!TIP]
> *Use cases in cybersecurity:* Byna enige plek waar ’n decision tree of random forest gebruik kan word, kan ’n gradient boosting-model beter akkuraatheid behaal. **Microsoft se malware-detection**-kompetisies het byvoorbeeld uitgebreide gebruik van XGBoost op engineered features uit binary files gesien. Navorsing oor **network intrusion detection** rapporteer dikwels topresultate met GBDTs (bv. XGBoost op CIC-IDS2017- of UNSW-NB15-datasets). Hierdie modelle kan ’n wye reeks features (protokoltipes, frekwensie van sekere gebeurtenisse, statistiese features van verkeer, ens.) gebruik en dit kombineer om threats op te spoor. In phishing-detection kan gradient boosting die leksikale features van URLs, domain-reputation-features en page-content-features kombineer om baie hoë akkuraatheid te behaal. Die ensemble-benadering help om baie corner cases en subtiliteite in die data te dek.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
Ons sal ’n gradient boosting-classifier op die phishing-dataset gebruik. Om dinge eenvoudig en self-contained te hou, sal ons `sklearn.ensemble.GradientBoostingClassifier` gebruik (wat ’n stadiger maar eenvoudige implementering is). Normaalweg kan ’n mens `xgboost`- of `lightgbm`-libraries gebruik vir beter werkverrigting en addisionele features. Ons sal die model oplei en dit, soos voorheen, evalueer.
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
Die gradient boosting model sal waarskynlik baie hoë accuracy en AUC op hierdie phishing-dataset behaal (dikwels kan hierdie modelle met behoorlike tuning op sulke data meer as 95% accuracy behaal, soos in die literatuur gesien word. Dit demonstreer waarom GBDTs as *"die state-of-the-art-model vir tabulêre datasets"* beskou word -- hulle presteer dikwels beter as eenvoudiger algorithms deur komplekse patrone vas te vang.<sup>[[11]](#references)</sup> In 'n kuberveiligheidskonteks kan dit beteken dat meer phishing-webwerwe of attacks opgespoor word, met minder gevalle wat gemis word. Natuurlik moet 'n mens versigtig wees vir overfitting -- ons sou tipies tegnieke soos cross-validation gebruik en performance op 'n validation set monitor wanneer ons so 'n model vir deployment ontwikkel.

</details>

### Kombinasie van Modelle: Ensemble Learning en Stacking

Ensemble learning is 'n strategie om **multiple models te kombineer** om algehele performance te verbeter. Ons het reeds spesifieke ensemble methods gesien: Random Forest (’n ensemble van trees via bagging) en Gradient Boosting (’n ensemble van trees via sequential boosting). Ensembles kan egter ook op ander maniere geskep word, soos **voting ensembles** of **stacked generalization (stacking)**. Die hoofidee is dat verskillende models verskillende patrone kan vasvang of verskillende swakhede kan hê; deur hulle te kombineer, kan ons **elke model se errors met 'n ander model se strengths kompenseer**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** In 'n eenvoudige voting classifier train ons multiple diverse models (sê nou maar 'n logistic regression, 'n decision tree en 'n SVM) en laat ons hulle oor die finale prediction stem (meerderheidsstem vir classification). As ons die stemme weeg (byvoorbeeld 'n hoër gewig aan meer akkurate models gee), is dit 'n weighted voting scheme. Dit verbeter tipies performance wanneer die individuele models redelik goed en independent is -- die ensemble verminder die risiko van 'n individuele model se fout, aangesien ander models dit moontlik kan korrigeer. Dit is soos om 'n paneel experts eerder as 'n enkele opinie te hê.

-   **Stacking (Stacked Ensemble):** Stacking gaan 'n stap verder. In plaas van 'n eenvoudige stem, train dit 'n **meta-model** om te **leer hoe om die predictions die beste te kombineer** van base models. Byvoorbeeld, jy train 3 verskillende classifiers (base learners) en voer dan hulle outputs (of probabilities) as features in 'n meta-classifier (dikwels 'n eenvoudige model soos logistic regression) in wat die optimale manier leer om hulle te blend. Die meta-model word op 'n validation set of via cross-validation getrain om overfitting te vermy. Stacking kan dikwels beter as eenvoudige voting presteer deur te leer *watter models om in watter omstandighede meer te vertrou*. In kuberveiligheid kan een model beter wees om network scans op te spoor, terwyl 'n ander beter is om malware beaconing op te spoor; 'n stacking-model kan leer om gepas op elkeen staat te maak.

Ensembles, hetsy deur voting of stacking, is geneig om **accuracy** en robustness te **verhoog**. Die nadeel is verhoogde kompleksiteit en soms verminderde interpretability (hoewel sommige ensemble approaches, soos 'n average van decision trees, steeds insig kan bied, byvoorbeeld feature importance). In die praktyk kan die gebruik van 'n ensemble tot hoër detection rates lei indien operasionele beperkings dit toelaat. Baie wenoplossings in kuberveiligheidsuitdagings (en Kaggle-kompetisies in die algemeen) gebruik ensemble techniques om die laaste bietjie performance uit te druk.

<details>
<summary>Voorbeeld -- Voting Ensemble vir Phishing Detection:</summary>
Om model stacking te illustreer, kombineer ons 'n paar van die models wat ons op die phishing-dataset bespreek het. Ons sal 'n logistic regression, 'n decision tree en 'n k-NN as base learners gebruik, en 'n Random Forest as 'n meta-learner gebruik om hulle predictions te aggregate. Die meta-learner sal op die outputs van die base learners getrain word (deur cross-validation op die training set te gebruik). Ons verwag dat die stacked model net so goed soos, of effens beter as, die individuele models sal presteer.
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
Die stacked ensemble benut die komplementêre sterk punte van die basismodelle. Logistic regression kan byvoorbeeld die lineêre aspekte van die data hanteer, die decision tree kan spesifieke reëlagtige interaksies vaslê, en k-NN kan uitmunt in plaaslike gebiede van die kenmerkruimte. Die meta-model (hier ’n random forest) kan leer hoe om hierdie insette te weeg. Die resulterende maatstawwe toon dikwels ’n verbetering (selfs al is dit gering) teenoor die maatstawwe van enige enkele model. In ons phishing-voorbeeld, as logistic alleen ’n F1 van byvoorbeeld 0.95 en die tree 0.94 gehad het, kon die stack 0.96 behaal deur op te tel waar elke model fouteer.

Ensemble methods soos hierdie demonstreer die beginsel dat *"combining multiple models typically leads to better generalization"*.<sup>[[12]](#references)</sup> In cybersecurity kan dit geïmplementeer word deur verskeie detection engines te gebruik (een kan rule-based, een machine learning-gebaseerd en een anomaly-based wees), gevolg deur ’n laag wat hul alerts saamvoeg -- effektief ’n vorm van ensemble -- om ’n finale besluit met groter vertroue te neem. Wanneer sulke stelsels ontplooi word, moet ’n mens die bykomende kompleksiteit in ag neem en verseker dat die ensemble nie te moeilik word om te bestuur of te verduidelik nie. Vanuit ’n akkuraatheidsoogpunt is ensembles en stacking egter kragtige hulpmiddels om modelprestasie te verbeter.

</details>

## Verwysings

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
