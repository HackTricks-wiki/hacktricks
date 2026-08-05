# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basiese Inligting

Supervised learning gebruik gelabelde data om modelle op te lei wat voorspellings oor nuwe, ongekende insette kan maak. In kuberveiligheid word supervised machine learning wyd toegepas op take soos intrusion detection (die klassifikasie van netwerkverkeer as *normal* of *attack*), malware detection (die onderskeid tussen kwaadwillige en onskadelike sagteware), phishing detection (die identifisering van bedrieglike webwerwe of e-posse), en spam filtering, onder andere. Elke algoritme het sy sterk punte en is geskik vir verskillende soorte probleme (classification of regression). Hieronder hersien ons belangrike supervised learning-algoritmes, verduidelik ons hoe hulle werk, en demonstreer ons hul gebruik op werklike kuberveiligheidsdatasets. Ons bespreek ook hoe die kombinasie van modelle (ensemble learning) dikwels voorspellingsprestasie kan verbeter.

## Algoritmes

-   **Linear Regression:** 'n Fundamentele regression-algoritme vir die voorspelling van numeriese uitkomste deur 'n lineêre vergelyking by data te pas.

-   **Logistic Regression:** 'n classification-algoritme (ten spyte van sy naam) wat 'n logistieke funksie gebruik om die waarskynlikheid van 'n binêre uitkoms te modelleer.

-   **Decision Trees:** Boomgestruktureerde modelle wat data volgens kenmerke verdeel om voorspellings te maak; word dikwels gebruik weens hul interpreteerbaarheid.

-   **Random Forests:** 'n Ensemble van decision trees (via bagging) wat akkuraatheid verbeter en overfitting verminder.

-   **Support Vector Machines (SVM):** Max-margin-classifiers wat die optimale skeidingshipervlak vind; kan kernels vir nie-lineêre data gebruik.

-   **Naive Bayes:** 'n Waarskynlikheidsclassifier gebaseer op Bayes se stelling, met 'n aanname van kenmerk-onafhanklikheid, wat veral bekend is vir gebruik in spam filtering.

-   **k-Nearest Neighbors (k-NN):** 'n Eenvoudige "instance-based"-classifier wat 'n sample etiketteer op grond van die meerderheidklas van sy naaste bure.

-   **Gradient Boosting Machines:** Ensemble-modelle (bv. XGBoost, LightGBM) wat 'n sterk voorspeller bou deur agtereenvolgens swakker learners by te voeg (tipies decision trees).

Elke afdeling hieronder verskaf 'n verbeterde beskrywing van die algoritme en 'n **Python code example** wat libraries soos `pandas` en `scikit-learn` gebruik (en `PyTorch` vir die neural network-voorbeeld). Die voorbeelde gebruik publiek beskikbare kuberveiligheidsdatasets (soos NSL-KDD vir intrusion detection en 'n Phishing Websites-dataset) en volg 'n konsekwente struktuur:

1.  **Laai die dataset** (download via URL indien beskikbaar).

2.  **Preprocess die data** (bv. encode categorical features, skaal waardes, en verdeel dit in train/test-stelle).

3.  **Train die model** op die training-data.

4.  **Evalueer** op 'n test-stel deur metrics te gebruik: accuracy, precision, recall, F1-score en ROC AUC vir classification (en mean squared error vir regression).

Kom ons kyk na elke algoritme:

### Linear Regression

Linear regression is 'n **regression**-algoritme wat gebruik word om deurlopende numeriese waardes te voorspel. Dit neem 'n lineêre verhouding aan tussen die input features (onafhanklike veranderlikes) en die output (afhanklike veranderlike). Die model probeer om 'n reguit lyn (of hipervlak in hoër dimensies) te pas wat die verhouding tussen die features en die target die beste beskryf. Dit word tipies gedoen deur die som van gekwadreerde foute tussen voorspelde en werklike waardes te minimaliseer (Ordinary Least Squares-metode).<sup>[[8]](#references)</sup>

Die eenvoudigste manier om linear regression voor te stel, is met 'n lyn:
```plaintext
y = mx + b
```
Waar:

- `y` is die voorspelde waarde (uitset)
- `m` is die helling van die lyn (koëffisiënt)
- `x` is die invoerkenmerk
- `b` is die y-afsnit

Die doel van lineêre regressie is om die lyn te vind wat die beste pas en wat die verskil tussen die voorspelde waardes en die werklike waardes in die datastel minimaliseer. Dit is natuurlik baie eenvoudig: dit sou ’n reguit lyn wees wat 2 kategorieë van mekaar skei, maar as meer dimensies bygevoeg word, word die lyn meer kompleks:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Gebruiksgevalle in cybersecurity:* Linear regression self is minder algemeen vir kernsekuriteitstake (wat dikwels classification is), maar dit kan gebruik word om numeriese uitkomste te voorspel. Byvoorbeeld, kan mens linear regression gebruik om **die volume netwerkverkeer te voorspel** of **die aantal aanvalle in 'n tydperk te skat** op grond van historiese data. Dit kan ook 'n risikotelling of die verwagte tyd tot die opsporing van 'n aanval voorspel, gegewe sekere stelselmetrieke. In die praktyk word classification-algoritmes (soos logistic regression of trees) meer gereeld gebruik om intrusions of malware op te spoor, maar linear regression dien as 'n grondslag en is nuttig vir regression-georiënteerde ontledings.

#### **Sleutelkenmerke van Linear Regression:**

-   **Tipe probleem:** Regression (voorspelling van kontinue waardes). Nie geskik vir direkte classification nie, tensy 'n drempelwaarde op die uitset toegepas word.

-   **Interpreteerbaarheid:** Hoog -- koëffisiënte is eenvoudig om te interpreteer en toon die lineêre effek van elke feature.

-   **Voordele:** Eenvoudig en vinnig; 'n goeie basislyn vir regression-take; werk goed wanneer die werklike verhouding ongeveer lineêr is.

-   **Beperkings:** Kan nie komplekse of nie-lineêre verhoudings vasvang nie (sonder handmatige feature engineering); geneig tot underfitting indien verhoudings nie-lineêr is; sensitief vir uitskieters wat die resultate kan skeeftrek.

-   **Vind van die beste passing:** Om die beste passingslyn te vind wat die moontlike kategorieë skei, gebruik ons 'n metode genaamd **Ordinary Least Squares (OLS)**. Hierdie metode minimaliseer die som van die gekwadreerde verskille tussen die waargenome waardes en die waardes wat deur die lineêre model voorspel word.

<details>
<summary>Voorbeeld -- Voorspelling van verbindingduur (Regression) in 'n Intrusion-datastel
</summary>
Hier demonstreer ons linear regression met behulp van die NSL-KDD-cybersecurity-datastel. Ons sal dit as 'n regression-probleem hanteer deur die `duration` van netwerkverbindings op grond van ander features te voorspel. (In werklikheid is `duration` een feature van NSL-KDD; ons gebruik dit hier slegs om regression te illustreer.) Ons laai die datastel, verwerk dit vooraf (deur kategoriese features te enkodeer), lei 'n linear regression-model af, en evalueer die Mean Squared Error (MSE)- en R²-telling op 'n toetsstel.
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
In hierdie voorbeeld probeer die linear regression-model die verbinding se `duration` uit ander netwerkkenmerke voorspel. Ons meet werkverrigting met Mean Squared Error (MSE) en R². ’n R² naby aan 1.0 sal aandui dat die model die meeste variasie in `duration` verduidelik, terwyl ’n lae of negatiewe R² op ’n swak passing dui. (Moenie verbaas wees as die R² hier laag is nie -- dit kan moeilik wees om `duration` uit die gegewe kenmerke te voorspel, en linear regression kan moontlik nie die patrone vaslê as hulle kompleks is nie.)
</details>

### Logistic Regression

Logistic regression is ’n **klassifikasie**-algoritme wat die waarskynlikheid modelleer dat ’n instansie aan ’n bepaalde klas behoort (gewoonlik die "positiewe" klas). Ondanks sy naam word *logistic* regression vir diskrete uitkomste gebruik (anders as linear regression, wat vir kontinue uitkomste is). Dit word veral vir **binêre klassifikasie** gebruik (twee klasse, bv. kwaadwillig teenoor legitiem), maar dit kan na multi-klas-probleme uitgebrei word (met behulp van softmax- of one-vs-rest-benaderings).<sup>[[1]](#references)</sup>

Die logistic regression gebruik die logistic-funksie (ook bekend as die sigmoid-funksie) om voorspelde waardes na waarskynlikhede te karteer. Let daarop dat die sigmoid-funksie ’n funksie is met waardes tussen 0 en 1 wat volgens die behoeftes van die klassifikasie in ’n S-vormige kurwe groei, wat nuttig is vir binêre klassifikasietake. Daarom word elke kenmerk van elke invoer met sy toegekende gewig vermenigvuldig, en die resultaat word deur die sigmoid-funksie gestuur om ’n waarskynlikheid te lewer:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Waar:

- `p(y=1|x)` is die waarskynlikheid dat die uitset `y` 1 is gegewe die inset `x`
- `e` is die basis van die natuurlike logaritme
- `z` is 'n lineêre kombinasie van die invoerkenmerke, gewoonlik voorgestel as `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Let weer daarop dat dit in sy eenvoudigste vorm 'n reguit lyn is, maar dat dit in meer komplekse gevalle 'n hipervlak met verskeie dimensies word (een per kenmerk).

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Omdat baie sekuriteitsprobleme in wese ja/nee-besluite is, word logistic regression wyd gebruik. Byvoorbeeld, 'n intrusion detection system kan logistic regression gebruik om te besluit of 'n netwerkverbinding 'n aanval is, gebaseer op kenmerke van daardie verbinding. In phishing-detection kan logistic regression kenmerke van 'n webwerf (URL-lengte, teenwoordigheid van die "@"-simbool, ens.) kombineer tot 'n waarskynlikheid dat dit phishing is. Dit is in vroeë-generasie spam-filters gebruik en bly 'n sterk basislyn vir baie classification-take.

#### Logistic Regression vir nie-binêre classification

Logistic regression is ontwerp vir binêre classification, maar dit kan uitgebrei word om multi-class-probleme te hanteer deur tegnieke soos **one-vs-rest** (OvR) of **softmax regression** te gebruik. In OvR word 'n aparte logistic regression-model vir elke klas opgelei, waar die klas as die positiewe klas teenoor al die ander behandel word. Die klas met die hoogste voorspelde waarskynlikheid word as die finale voorspelling gekies. Softmax regression veralgemeen logistic regression na veelvuldige klasse deur die softmax-funksie op die uitsetlaag toe te pas, wat 'n waarskynlikheidsverdeling oor al die klasse lewer.

#### **Belangrike kenmerke van Logistic Regression:**

-   **Tipe probleem:** Classification (gewoonlik binêr). Dit voorspel die waarskynlikheid van die positiewe klas.

-   **Interpreteerbaarheid:** Hoog -- soos met linear regression, kan die kenmerkkoffisiënte aandui hoe elke kenmerk die log-odds van die uitkoms beïnvloed. Hierdie deursigtigheid word dikwels in sekuriteit waardeer om te verstaan watter faktore tot 'n alert bydra.

-   **Voordele:** Eenvoudig en vinnig om op te lei; werk goed wanneer die verhouding tussen kenmerke en die log-odds van die uitkoms lineêr is. Lewer waarskynlikhede, wat risk scoring moontlik maak. Met toepaslike regularization veralgemeen dit goed en kan dit multicollinearity beter hanteer as gewone linear regression.

-   **Beperkings:** Veronderstel 'n lineêre decision boundary in die kenmerkruimte (dit faal as die werklike grens kompleks/nie-lineêr is). Dit kan swakker presteer op probleme waar interaksies of nie-lineêre effekte krities is, tensy jy polynomial- of interaksiekenmerke handmatig byvoeg. Logistic regression is ook minder effektief as klasse nie maklik deur 'n lineêre kombinasie van kenmerke geskei kan word nie.


<details>
<summary>Voorbeeld -- Phishing Website Detection met Logistic Regression:</summary>

Ons sal 'n **Phishing Websites Dataset** (uit die UCI-repository) gebruik, wat onttrekte kenmerke van webwerwe bevat (soos of die URL 'n IP-adres het, die ouderdom van die domein, die teenwoordigheid van verdagte elemente in HTML, ens.) en 'n etiket wat aandui of die webwerf phishing of wettig is. Ons lei 'n logistic regression-model op om webwerwe te klassifiseer en evalueer dan die akkuraatheid, precision, recall, F1-score en ROC AUC op 'n toetsverdeling.
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
In hierdie phishing detection-voorbeeld produseer logistic regression 'n waarskynlikheid vir elke webwerf om phishing te wees. Deur accuracy, precision, recall en F1 te evalueer, kry ons 'n aanduiding van die model se werkverrigting. Byvoorbeeld, 'n hoë recall sal beteken dat dit die meeste phishing-webwerwe opspoor (belangrik vir sekuriteit om gemiste aanvalle te beperk), terwyl hoë precision beteken dat dit min vals alarms genereer (belangrik om ontleder-uitputting te voorkom). Die ROC AUC (Area Under the ROC Curve) gee 'n drempel-onafhanklike maatstaf van werkverrigting (1.0 is ideaal, 0.5 is nie beter as lukraak nie). Logistic regression presteer dikwels goed met sulke take, maar as die besluitgrens tussen phishing- en wettige webwerwe kompleks is, kan kragtiger nie-lineêre modelle nodig wees.

</details>

### Besluitbome

'n Besluitboom is 'n veelsydige **supervised learning algorithm** wat vir beide classification- en regression-take gebruik kan word. Dit leer 'n hiërargiese boomagtige model van besluite gebaseer op die kenmerke van die data. Elke interne nodus van die boom verteenwoordig 'n toets op 'n spesifieke kenmerk, elke tak verteenwoordig 'n uitkoms van daardie toets, en elke blaarnodus verteenwoordig 'n voorspelde klas (vir classification) of waarde (vir regression).<sup>[[2]](#references)</sup>

Om 'n boom te bou, gebruik algorithms soos CART (Classification and Regression Tree) maatstawwe soos **Gini impurity** of **information gain (entropy)** om die beste kenmerk en drempel te kies waarvolgens die data by elke stap verdeel moet word. Die doel met elke verdeling is om die data te partisioneer sodat die homogeniteit van die teikenveranderlike in die gevolglike substelle verhoog (vir classification streef elke nodus daarna om so suiwer moontlik te wees, met hoofsaaklik een klas).

Besluitbome is **highly interpretable** -- 'n mens kan die pad van wortel tot blaar volg om die logika agter 'n voorspelling te verstaan (bv. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Dit is waardevol in kuberveiligheid om te verduidelik waarom 'n spesifieke alert gegenereer is. Bome kan natuurlik beide numeriese en kategoriese data hanteer en vereis min preprocessing (bv. feature scaling is nie nodig nie).

'n Enkele besluitboom kan egter maklik die training data overfit, veral as dit diep gegroei word (baie verdelings). Tegnieke soos pruning (die beperking van boomdiepte of die vereiste van 'n minimum aantal samples per blaar) word dikwels gebruik om overfitting te voorkom.

Daar is 3 hoofkomponente van 'n besluitboom:
- **Root Node**: Die boonste nodus van die boom, wat die volledige dataset verteenwoordig.
- **Internal Nodes**: Nodusse wat features en besluite gebaseer op daardie features verteenwoordig.
- **Leaf Nodes**: Nodusse wat die finale uitkoms of voorspelling verteenwoordig.

'n Boom kan uiteindelik soos volg lyk:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Use cases in cybersecurity:* Decision trees is in intrusion detection systems gebruik om **rules** af te lei vir die identifisering van attacks. Byvoorbeeld, vroeë IDS soos ID3/C4.5-gebaseerde systems het mensleesbare rules gegenereer om normale teenoor malicious traffic te onderskei. Hulle word ook in malware analysis gebruik om te besluit of 'n file malicious is op grond van sy attributes (file size, section entropy, API calls, ens.). Die duidelikheid van decision trees maak hulle nuttig wanneer transparency nodig is -- 'n analyst kan die tree inspekteer om die detection logic te valideer.

#### **Key characteristics of Decision Trees:**

-   **Type of Problem:** Beide classification en regression. Word algemeen gebruik vir die classification van attacks teenoor normale traffic, ens.

-   **Interpretability:** Baie hoog -- die model se besluite kan gevisualiseer en verstaan word as 'n stel if-then rules. Dit is 'n groot voordeel in security vir vertroue in en verification van modelgedrag.

-   **Advantages:** Kan non-linear relationships en interactions tussen features vasvang (elke split kan as 'n interaction beskou word). Dit is nie nodig om features te scale of categorical variables one-hot te encode nie -- trees hanteer dit native. Vinnige inference (prediction is bloot die volg van 'n path in die tree).

-   **Limitations:** Geneig tot overfitting indien dit nie beheer word nie ('n diep tree kan die training set memoriseer). Hulle kan unstable wees -- klein veranderinge in die data kan tot 'n ander tree structure lei. As single models kan hul accuracy nie met meer gevorderde methods ooreenstem nie (ensembles soos Random Forests presteer gewoonlik beter deur variance te verminder).

-   **Finding the Best Split:**
- **Gini Impurity**: Meet die impurity van 'n node. 'n Laer Gini impurity dui op 'n beter split. Die formule is:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Waar `p_i` die proporsie van instances in class `i` is.

- **Entropy**: Meet die uncertainty in die dataset. 'n Laer entropy dui op 'n beter split. Die formule is:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Waar `p_i` die proporsie van instances in class `i` is.

- **Information Gain**: Die vermindering in entropy of Gini impurity ná 'n split. Hoe hoër die information gain, hoe beter die split. Dit word soos volg bereken:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Verder word 'n tree beëindig wanneer:
- Alle instances in 'n node aan dieselfde class behoort. Dit kan tot overfitting lei.
- Die maksimum depth (hardcoded) van die tree bereik word. Dit is 'n manier om overfitting te voorkom.
- Die aantal instances in 'n node onder 'n sekere threshold is. Dit is ook 'n manier om overfitting te voorkom.
- Die information gain van verdere splits onder 'n sekere threshold is. Dit is ook 'n manier om overfitting te voorkom.

<details>
<summary>Example -- Decision Tree for Intrusion Detection:</summary>
Ons sal 'n decision tree op die NSL-KDD dataset train om network connections as óf *normal* óf *attack* te klassifiseer. NSL-KDD is 'n verbeterde weergawe van die klassieke KDD Cup 1999 dataset, met features soos protocol type, service, duration, number of failed logins, ens., en 'n label wat die attack type of "normal" aandui. Ons sal alle attack types na 'n "anomaly" class map (binary classification: normal teenoor anomaly). Ná training sal ons die tree se performance op die test set evalueer.
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
In hierdie decision tree-voorbeeld het ons die boomdiepte tot 10 beperk om ekstreme overfitting te vermy (die `max_depth=10`-parameter). Die metrics toon hoe goed die boom normale teenoor aanvalverkeer onderskei. ’n Hoë recall sou beteken dat dit die meeste aanvalle opspoor (belangrik vir ’n IDS), terwyl hoë precision min vals alarms beteken. Decision trees behaal dikwels aanvaarbare accuracy op gestruktureerde data, maar ’n enkele boom bereik moontlik nie die beste moontlike performance nie. Nietemin is die *interpretability* van die model ’n groot voordeel -- ons kan die boom se splits ondersoek om byvoorbeeld te sien watter features (bv. `service`, `src_bytes`, ens.) die invloedrykste is wanneer ’n verbinding as malicious gemerk word.

</details>

### Random Forests

Random Forest is ’n **ensemble learning**-metode wat op decision trees voortbou om performance te verbeter. ’n Random forest lei verskeie decision trees op (vandaar "forest") en kombineer hul outputs om ’n finale prediction te maak (vir classification, gewoonlik deur majority vote). Die twee hoofidees in ’n random forest is **bagging** (bootstrap aggregating) en **feature randomness**:

-   **Bagging:** Elke boom word opgelei op ’n random bootstrap sample van die training data (met replacement gesample). Dit skep diversiteit tussen die bome.

-   **Feature Randomness:** By elke split in ’n boom word ’n random subset van features vir splitting oorweeg (in plaas van alle features). Dit verminder die korrelasie tussen die bome verder.

Deur die resultate van baie bome te average, verminder die random forest die variance wat ’n enkele decision tree kan hê. In eenvoudige terme kan individuele bome overfit of raserig wees, maar ’n groot aantal diverse bome wat saam stem, maak daardie foute gladder. Die resultaat is dikwels ’n model met **hoër accuracy** en beter generalization as ’n enkele decision tree. Daarbenewens kan random forests ’n skatting van feature importance verskaf (deur te kyk hoeveel elke feature split gemiddeld impurity verminder).

Random forests het ’n **workhorse in cybersecurity** geword vir take soos intrusion detection, malware classification en spam detection. Hulle presteer dikwels goed out-of-the-box met minimale tuning en kan groot feature sets hanteer. Byvoorbeeld, in intrusion detection kan ’n random forest beter as ’n individuele decision tree presteer deur meer subtiele aanvalspatrone met minder false positives op te spoor. Navorsing het getoon dat random forests gunstig presteer in vergelyking met ander algorithms wanneer aanvalle in datasets soos NSL-KDD en UNSW-NB15 geklassifiseer word.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** Hoofsaaklik classification (word ook vir regression gebruik). Baie goed geskik vir hoë-dimensionele gestruktureerde data wat algemeen in security logs voorkom.

-   **Interpretability:** Laer as dié van ’n enkele decision tree -- jy kan nie maklik honderde bome gelyk visualiseer of verduidelik nie. Feature importance scores bied egter ’n mate van insig in watter attributes die invloedrykste is.

-   **Advantages:** Oor die algemeen hoër accuracy as single-tree models weens die ensemble effect. Robust teenoor overfitting -- selfs al overfit individuele bome, generalize die ensemble beter. Hanteer sowel numerical as categorical features en kan missing data tot ’n mate bestuur. Dit is ook relatief robust teenoor outliers.

-   **Limitations:** Die modelgrootte kan groot wees (baie bome, wat elk moontlik diep kan wees). Predictions is stadiger as dié van ’n enkele boom (want jy moet resultate van baie bome aggregate). Minder interpretable -- hoewel jy weet watter features belangrik is, kan die presiese logic nie maklik as ’n eenvoudige reël nagespoor word nie. As die dataset uiters hoë-dimensioneel en sparse is, kan die training van ’n baie groot forest computationally swaar wees.

-   **Training Process:**
1. **Bootstrap Sampling**: Sample die training data random met replacement om verskeie subsets (bootstrap samples) te skep.
2. **Tree Construction**: Bou vir elke bootstrap sample ’n decision tree deur by elke split ’n random subset van features te gebruik. Dit skep diversiteit tussen die bome.
3. **Aggregation**: Vir classification-take word die finale prediction gemaak deur ’n majority vote onder die predictions van alle bome te neem. Vir regression-take is die finale prediction die average van die predictions van alle bome.

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
Ons sal dieselfde NSL-KDD-dataset gebruik (binêr gelabel as normal teenoor anomaly) en ’n Random Forest-classifier train. Ons verwag dat die random forest net so goed soos, of beter as, die enkele decision tree sal presteer, danksy die ensemble averaging wat variance verminder. Ons sal dit met dieselfde metrics evalueer.
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
Die random forest behaal tipies sterk resultate op hierdie intrusion detection-taak. Ons kan ’n verbetering in maatstawwe soos F1 of AUC waarneem in vergelyking met die enkele decision tree, veral in recall of precision, afhangend van die data. Dit stem ooreen met die begrip dat *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*. In ’n security operations-konteks kan ’n random forest-model attacks meer betroubaar vlag terwyl false alarms verminder word, danksy die gemiddeld van baie decision rules. Feature importance uit die forest kan ons wys watter network features die mees aanduidend van attacks is (byvoorbeeld sekere network services of ongewone packet-tellings).

</details>

### Support Vector Machines (SVM)

Support Vector Machines is kragtige supervised learning-modelle wat hoofsaaklik vir classification gebruik word (en ook vir regression as SVR). ’n SVM probeer die **optimale skeidings-hyperplane** vind wat die margin tussen twee klasse maksimeer. Slegs ’n subset van training points (die "support vectors" naaste aan die grens) bepaal die posisie van hierdie hyperplane. Deur die margin te maksimeer (die afstand tussen support vectors en die hyperplane), is SVMs geneig om goeie generalization te behaal.<sup>[[4]](#references)</sup>

Die sleutel tot SVM se krag is die vermoë om **kernel functions** te gebruik om nie-lineêre verhoudings te hanteer. Die data kan implisiet na ’n hoër-dimensionele feature space getransformeer word waar ’n linear separator moontlik bestaan. Algemene kernels sluit polynomial, radial basis function (RBF) en sigmoid in. Byvoorbeeld, as network traffic-klasse nie lineêr skeibaar is in die rou feature space nie, kan ’n RBF-kernel hulle na ’n hoër dimensie karteer waar die SVM ’n linear split vind (wat met ’n nie-lineêre grens in die oorspronklike space ooreenstem). Die buigsaamheid om kernels te kies stel SVMs in staat om ’n verskeidenheid probleme aan te pak.

SVMs is bekend daarvoor dat hulle goed presteer in situasies met hoë-dimensionele feature spaces (soos text data of malware opcode sequences) en in gevalle waar die aantal features groot is relatief tot die aantal samples. Hulle was gewild in baie vroeë cybersecurity-toepassings, soos malware classification en anomaly-based intrusion detection in die 2000’s, waar hulle dikwels hoë accuracy getoon het.

SVMs skaal egter nie maklik na baie groot datasets nie (training complexity is super-lineêr in die aantal samples, en memory usage kan hoog wees omdat dit moontlik baie support vectors moet stoor). In die praktyk kan SVM vir take soos network intrusion detection met miljoene records te stadig wees sonder sorgvuldige subsampling of die gebruik van approximate methods.

#### **Belangrike eienskappe van SVM:**

-   **Tipe probleem:** Classification (binary of multiclass via one-vs-one/one-vs-rest) en regression-variante. Word dikwels in binary classification met duidelike margin-separation gebruik.

-   **Interpretability:** Medium -- SVMs is nie so interpreteerbaar soos decision trees of logistic regression nie. Hoewel jy kan identifiseer watter data points support vectors is en ’n mate van insig kan kry in watter features invloedryk kan wees (deur die weights in die linear kernel-geval), word SVMs in die praktyk (veral met nie-lineêre kernels) as black-box classifiers behandel.

-   **Voordele:** Effektief in hoë-dimensionele spaces; kan komplekse decision boundaries met die kernel trick modelleer; bestand teen overfitting indien die margin gemaksimeer word (veral met ’n behoorlike regularization-parameter C); werk goed selfs wanneer klasse nie deur ’n groot afstand geskei word nie (vind die beste kompromie-grens).

-   **Beperkings:** **Computationally intensive** vir groot datasets (beide training en prediction skaal swak namate data groei). Vereis sorgvuldige tuning van kernel- en regularization-parameters (C, kernel type, gamma vir RBF, ensovoorts). Lewer nie direk probabilistic outputs nie (hoewel Platt scaling gebruik kan word om probabilities te verkry). SVMs kan ook sensitief wees vir die keuse van kernel-parameters --- ’n swak keuse kan tot underfit of overfit lei.

*Use cases in cybersecurity:* SVMs is gebruik in **malware detection** (byvoorbeeld om files te klassifiseer op grond van onttrekte features of opcode sequences), **network anomaly detection** (om traffic as normal of malicious te klassifiseer) en **phishing detection** (met behulp van URL-features). ’n SVM kan byvoorbeeld features van ’n email neem (tellings van sekere keywords, sender reputation scores, ensovoorts) en dit as phishing of legitimate klassifiseer. Hulle is ook toegepas op **intrusion detection** met feature sets soos KDD, waar hulle dikwels hoë accuracy teen die koste van computation behaal het.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Ons sal weer die phishing website-dataset gebruik, hierdie keer met ’n SVM. Omdat SVMs stadig kan wees, sal ons indien nodig ’n subset van die data vir training gebruik (die dataset bevat ongeveer 11k instances, wat SVM redelik goed kan hanteer). Ons sal ’n RBF-kernel gebruik, wat ’n algemene keuse vir nie-lineêre data is, en probability estimates aktiveer om ROC AUC te bereken.
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
Die SVM-model sal metrieke uitvoer wat ons met logistic regression vir dieselfde taak kan vergelyk. Ons kan vind dat SVM hoë akkuraatheid en AUC behaal as die data goed deur die kenmerke geskei word. Aan die ander kant, as die datastel baie geraas of oorvleuelende klasse bevat, sal SVM moontlik nie beduidend beter as logistic regression presteer nie. In die praktyk kan SVMs 'n verbetering bied wanneer daar komplekse, nie-lineêre verhoudings tussen kenmerke en klasse is -- die RBF-kern kan geboë besluitnemingsgrense vasvang wat logistic regression sou mis. Soos met alle modelle, is noukeurige instelling van die `C` (regularisering) en kernparameters (soos `gamma` vir RBF) nodig om vooroordeel en variansie te balanseer.

</details>

#### Verskil tussen Logistic Regression & SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Doelfunksie** | Minimeer **log-loss** (kruisentropie). | Maksimeer die **marge** terwyl **hinge-loss** geminimeer word. |
| **Besluitnemingsgrens** | Vind die **beste-pas-hypervlak** wat _P(y\|x)_ modelleer. | Vind die **hypervlak met die maksimum marge** (die grootste gaping tot die naaste punte). |
| **Uitset** | **Probabilisties** – gee gekalibreerde klaswaarskynlikhede via σ(w·x + b). | **Deterministies** – gee klasetikette terug; waarskynlikhede vereis ekstra werk (bv. Platt-skalering). |
| **Regularisering** | L2 (verstek) of L1, wat onder-/oorpassing direk balanseer. | C-parameter ruil margewydte teenoor verkeerde klassifikasies af; kernparameters voeg kompleksiteit by. |
| **Kerne / Nie-lineêr** | Die inheemse vorm is **lineêr**; nie-lineariteit word deur kenmerk-ingenieurswese bygevoeg. | Ingeboude **kernel trick** (RBF, polinoom, ens.) laat dit toe om komplekse grense in hoë-dimensionele ruimte te modelleer. |
| **Skaalbaarheid** | Los 'n konvekse optimisering in **O(nd)** op; hanteer baie groot n goed. | Opleiding kan **O(n²–n³)** in geheue/tyd wees sonder gespesialiseerde oplossers; minder geskik vir enorme n. |
| **Interpreteerbaarheid** | **Hoog** – gewigte toon kenmerk-invloed; kansverhouding is intuïtief. | **Laag** vir nie-lineêre kerne; support vectors is yl, maar nie maklik om te verduidelik nie. |
| **Sensitiwiteit vir uitskieters** | Gebruik gladde log-loss → minder sensitief. | Hinge-loss met 'n harde marge kan **sensitief** wees; sagte marge (C) versag dit. |
| **Tipiese gebruiksgevalle** | Krediettelling, mediese risiko, A/B-toetsing – waar **waarskynlikhede en verduidelikbaarheid** belangrik is. | Beeld-/teksklassifikasie, bio-informatika – waar **komplekse grense** en **hoë-dimensionele data** belangrik is. |

* **As jy gekalibreerde waarskynlikhede, interpreteerbaarheid benodig, of op enorme datastelle werk — kies Logistic Regression.**
* **As jy 'n buigsame model benodig wat nie-lineêre verhoudings sonder handmatige kenmerk-ingenieurswese kan vasvang — kies SVM (met kerne).**
* Albei optimaliseer konvekse doelfunksies, dus is **globale minima gewaarborg**, maar SVM se kerne voeg hiperparameters en berekeningskoste by.

### Naive Bayes

Naive Bayes is 'n familie van **probabilistiese klassifiseerders** wat gebaseer is op die toepassing van Bayes se stelling met 'n sterk onafhanklikheidsaanname tussen kenmerke. Ten spyte van hierdie "naïewe" aanname werk Naive Bayes dikwels verrassend goed vir sekere toepassings, veral dié wat teks- of kategoriese data behels, soos spam-opsporing.<sup>[[5]](#references)</sup>


#### Bayes se stelling

Bayes se stelling is die grondslag van Naive Bayes-klassifiseerders. Dit bring die voorwaardelike en marginale waarskynlikhede van ewekansige gebeurtenisse met mekaar in verband. Die formule is:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Waar:
- `P(A|B)` is the posteriorwaarskynlikheid van klas `A` gegewe kenmerk `B`.
- `P(B|A)` is die waarskynlikheid van kenmerk `B` gegewe klas `A`.
- `P(A)` is die voorafwaarskynlikheid van klas `A`.
- `P(B)` is die voorafwaarskynlikheid van kenmerk `B`.

Byvoorbeeld, as ons wil klassifiseer of 'n teks deur 'n kind of 'n volwassene geskryf is, kan ons die woorde in die teks as kenmerke gebruik. Gebaseer op aanvanklike data, sal die Naive Bayes-classifier vooraf die waarskynlikhede bereken dat elke woord tot elke moontlike klas (kind of volwassene) behoort. Wanneer 'n nuwe teks verskaf word, sal dit die waarskynlikheid van elke moontlike klas gegewe die woorde in die teks bereken en die klas met die hoogste waarskynlikheid kies.

Soos jy in hierdie voorbeeld kan sien, is die Naive Bayes-classifier baie eenvoudig en vinnig, maar dit neem aan dat die kenmerke onafhanklik is, wat nie altyd die geval is met werklike data nie.


#### Tipes Naive Bayes-classifiers

Daar is verskeie tipes Naive Bayes-classifiers, afhangend van die tipe data en die verspreiding van die kenmerke:
- **Gaussian Naive Bayes**: Neem aan dat die kenmerke 'n Gaussian (normale) verspreiding volg. Dit is geskik vir deurlopende data.
- **Multinomial Naive Bayes**: Neem aan dat die kenmerke 'n multinomiale verspreiding volg. Dit is geskik vir diskrete data, soos woordtellings in teksklassifikasie.
- **Bernoulli Naive Bayes**: Neem aan dat die kenmerke binêr (0 of 1) is. Dit is geskik vir binêre data, soos die teenwoordigheid of afwesigheid van woorde in teksklassifikasie.
- **Categorical Naive Bayes**: Neem aan dat die kenmerke kategoriese veranderlikes is. Dit is geskik vir kategoriese data, soos om vrugte op grond van hul kleur en vorm te klassifiseer.


#### **Sleutelkenmerke van Naive Bayes:**

-   **Tipe probleem:** Klassifikasie (binêr of multi-klas). Word algemeen gebruik vir teksklassifikasietake in kuberveiligheid (spam, phishing, ens.).

-   **Interpreteerbaarheid:** Gemiddeld -- dit is nie so direk interpreteerbaar soos 'n besluitnemingsboom nie, maar 'n mens kan die aangeleerde waarskynlikhede inspekteer (bv. watter woorde die waarskynlikste in spam- teenoor ham-e-posse voorkom). Die model se vorm (waarskynlikhede vir elke kenmerk gegewe die klas) kan verstaan word indien nodig.

-   **Voordele:** **Baie vinnige** opleiding en voorspelling, selfs op groot datastelle (lineêr in die aantal gevalle * die aantal kenmerke). Vereis 'n relatief klein hoeveelheid data om waarskynlikhede betroubaar te skat, veral met behoorlike smoothing. Dit is dikwels verbasend akkuraat as 'n basislyn, veral wanneer kenmerke onafhanklik tot die bewys vir die klas bydra. Werk goed met hoë-dimensionele data (bv. duisende kenmerke uit teks). Geen komplekse verstelling is nodig buiten die instelling van 'n smoothing-parameter nie.

-   **Beperkings:** Die onafhanklikheidsaanname kan akkuraatheid beperk indien kenmerke sterk gekorreleer is. Byvoorbeeld, in netwerkdata kan kenmerke soos `src_bytes` en `dst_bytes` gekorreleer wees; Naive Bayes sal nie daardie interaksie vasvang nie. Namate die datagrootte baie groot word, kan meer ekspressiewe modelle (soos ensembles of neurale netwerke) NB oortref deur kenmerkafhanklikhede aan te leer. Indien 'n spesifieke kombinasie van kenmerke nodig is om 'n aanval te identifiseer (nie net individuele kenmerke onafhanklik nie), sal NB ook sukkel.

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Die klassieke gebruik is **spamopsporing** -- Naive Bayes was die kern van vroeë spamfilters, wat die frekwensies van sekere tokens (woorde, frases, IP-adresse) gebruik het om die waarskynlikheid te bereken dat 'n e-pos spam is. Dit word ook gebruik in **phishing-e-posopsporing** en **URL-klassifikasie**, waar die teenwoordigheid van sekere sleutelwoorde of eienskappe (soos "login.php" in 'n URL, of `@` in 'n URL-pad) tot die phishing-waarskynlikheid bydra. In malware-analise kan 'n mens 'n Naive Bayes-classifier voorstel wat die teenwoordigheid van sekere API-oproepe of toestemmings in sagteware gebruik om te voorspel of dit malware is. Hoewel meer gevorderde algoritmes dikwels beter presteer, bly Naive Bayes 'n goeie basislyn weens die spoed en eenvoud daarvan.

<details>
<summary>Voorbeeld -- Naive Bayes vir phishingopsporing:</summary>
Om Naive Bayes te demonstreer, sal ons Gaussian Naive Bayes op die NSL-KDD-inbraakdatastel (met binêre etikette) gebruik. Gaussian NB sal elke kenmerk behandel asof dit per klas 'n normale verspreiding volg. Dit is 'n ruwe keuse, aangesien baie netwerkkenmerke diskreet of sterk skeef versprei is, maar dit wys hoe 'n mens NB op deurlopende kenmerkdata sou toepas. Ons kon ook Bernoulli NB op 'n datastel van binêre kenmerke kies (soos 'n stel geaktiveerde waarskuwings), maar ons sal vir kontinuïteit hier by NSL-KDD hou.
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
Hierdie kode lei 'n Naive Bayes-classifier op om attacks op te spoor. Naive Bayes sal dinge soos `P(service=http | Attack)` en `P(Service=http | Normal)` bereken gebaseer op die training data, met die aanname dat features onafhanklik is. Dit sal dan hierdie probabilities gebruik om nuwe connections as óf normaal óf 'n attack te klassifiseer, gebaseer op die waargenome features. Die performance van NB op NSL-KDD is moontlik nie so hoog soos dié van meer gevorderde models nie (aangesien die onafhanklikheid van features oortree word), maar dit is dikwels voldoende en bied die voordeel van uiters hoë spoed. In scenarios soos real-time email filtering of aanvanklike triage van URLs, kan 'n Naive Bayes-model vanselfsprekend malicious gevalle vinnig flag met lae resource usage.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors is een van die eenvoudigste machine learning-algorithms. Dit is 'n **non-parametric, instance-based** metode wat predictions maak gebaseer op die ooreenkoms met examples in die training set. Die idee vir classification is: om 'n nuwe data point te klassifiseer, vind die **k** naaste points in die training data (sy "nearest neighbors"), en ken die meerderheid class onder daardie neighbors toe. "Nabyheid" word gedefinieer deur 'n distance metric, gewoonlik Euclidean distance vir numeriese data (ander distances kan vir verskillende tipes features of problems gebruik word).<sup>[[10]](#references)</sup>

K-NN vereis *geen eksplisiete training* nie -- die "training"-fase behels bloot die stoor van die dataset. Al die werk gebeur tydens die query (prediction): die algorithm moet distances vanaf die query point na alle training points bereken om die naastes te vind. Dit maak prediction-tyd **linear in die aantal training samples**, wat duur kan wees vir groot datasets. Om hierdie rede is k-NN die beste geskik vir kleiner datasets of scenarios waar jy memory en speed vir eenvoud kan verruil.

Ondanks sy eenvoud kan k-NN baie komplekse decision boundaries modelleer (omdat die decision boundary effektief enige vorm kan hê wat deur die verspreiding van examples bepaal word). Dit presteer gewoonlik goed wanneer die decision boundary baie onreëlmatig is en jy baie data het -- dit laat die data basies "self praat". In hoë dimensies kan distance metrics egter minder betekenisvol word (curse of dimensionality), en die metode kan sukkel tensy jy 'n groot aantal samples het.

*Use cases in cybersecurity:* k-NN is toegepas op anomaly detection -- byvoorbeeld, 'n intrusion detection system kan 'n netwerk-event as malicious label indien die meeste van sy nearest neighbors (vorige events) malicious was. As normale traffic clusters vorm en attacks outliers is, doen 'n K-NN-benadering (met k=1 of klein k) basies **nearest-neighbor anomaly detection**. K-NN is ook gebruik om malware families volgens binary feature vectors te klassifiseer: 'n nuwe file kan as 'n bepaalde malware family geklassifiseer word indien dit baie naby (in feature space) aan bekende instances van daardie family is. In die praktyk is k-NN nie so algemeen soos meer scalable algorithms nie, maar dit is konseptueel eenvoudig en word soms as 'n baseline of vir small-scale problems gebruik.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification (en regression-variante bestaan). Dit is 'n *lazy learning*-metode -- geen eksplisiete model fitting nie.

-   **Interpretability:** Laag tot medium -- daar is geen globale model of bondige verduideliking nie, maar resultate kan geïnterpreteer word deur na die nearest neighbors te kyk wat 'n besluit beïnvloed het (bv. "hierdie netwerk-flow is as malicious geklassifiseer omdat dit soortgelyk is aan hierdie 3 bekende malicious flows"). Verduidelikings kan dus example-based wees.

-   **Advantages:** Baie eenvoudig om te implementeer en te verstaan. Dit maak geen aannames oor die data distribution nie (non-parametric). Dit kan multi-class problems natuurlik hanteer. Dit is **adaptive** in die sin dat decision boundaries baie kompleks kan wees en deur die data distribution gevorm word.

-   **Limitations:** Prediction kan stadig wees vir groot datasets (baie distances moet bereken word). Dit vereis baie memory -- dit stoor al die training data. Performance verswak in hoë-dimensionele feature spaces omdat alle points geneig is om byna ewe ver van mekaar te wees (wat die concept van "naaste" minder betekenisvol maak). Jy moet *k* (aantal neighbors) toepaslik kies -- 'n te klein k kan raserig wees, terwyl 'n te groot k irrelevante points van ander classes kan insluit. Features moet ook toepaslik geskaal word omdat distance calculations sensitief vir scale is.

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

Ons sal weer NSL-KDD gebruik (binary classification). Omdat k-NN computationally heavy is, sal ons 'n subset van die training data gebruik om dit in hierdie demonstration hanteerbaar te hou. Ons sal byvoorbeeld 20,000 training samples uit die volledige 125k kies en k=5 neighbors gebruik. Ná training (wat eintlik slegs die stoor van die data is), sal ons op die test set evalueer. Ons sal ook features scale vir distance calculation om te verseker dat geen enkele feature weens scale domineer nie.
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
Die k-NN-model sal 'n verbinding klassifiseer deur na die 5 naaste verbindings in die subset van die training set te kyk. As 4 van daardie bure byvoorbeeld attacks (anomalies) is en 1 normaal is, sal die nuwe verbinding as 'n attack geklassifiseer word. Die werkverrigting kan redelik wees, hoewel dit dikwels nie so hoog is soos dié van 'n goed ingestelde Random Forest of SVM op dieselfde data nie. k-NN kan egter soms uitblink wanneer die klasverdelings baie onreëlmatig en kompleks is -- dit gebruik effektief 'n memory-based lookup. In cybersecurity kan k-NN (met k=1 of 'n klein k) gebruik word vir die opsporing van bekende attack patterns deur middel van voorbeelde, of as 'n komponent in meer komplekse stelsels (bv. vir clustering en daarna klassifikasie op grond van cluster-lidmaatskap).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines is van die kragtigste algorithms vir gestruktureerde data. **Gradient boosting** verwys na die tegniek om 'n ensemble van weak learners (dikwels decision trees) opeenvolgend te bou, waar elke nuwe model die foute van die vorige ensemble regstel. Anders as bagging (Random Forests), wat trees parallel bou en hulle gemiddeld, bou boosting trees *een vir een*, met elkeen wat meer fokus op die instances wat vorige trees verkeerd voorspel het.

Die gewildste implementerings in onlangse jare is **XGBoost**, **LightGBM** en **CatBoost**, wat almal gradient boosting decision tree (GBDT)-libraries is. Hulle was uiters suksesvol in machine learning-kompetisies en toepassings, en behaal dikwels **state-of-the-art performance op tabular datasets**. In cybersecurity het researchers en practitioners gradient boosted trees gebruik vir take soos **malware detection** (met features wat uit files of runtime behavior onttrek is) en **network intrusion detection**. Byvoorbeeld, 'n gradient boosting-model kan baie weak rules (trees) soos "if many SYN packets and unusual port -> likely scan" kombineer tot 'n sterk saamgestelde detector wat baie subtiele patterns in ag neem.<sup>[[6]](#references)</sup>

Waarom is boosted trees so effektief? Elke tree in die sequence word opgelei op die *residual errors* (gradients) van die huidige ensemble se predictions. Op hierdie manier **"boost"** die model geleidelik die areas waarin dit swak is. Die gebruik van decision trees as base learners beteken dat die finale model komplekse interactions en non-linear relations kan vasvang. Boonop het boosting inherent 'n vorm van ingeboude regularization: deur baie klein trees by te voeg (en 'n learning rate te gebruik om hul contributions te skaleer), generaliseer dit dikwels goed sonder groot overfitting, mits die korrekte parameters gekies word.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Hoofsaaklik classification en regression. In security is dit gewoonlik classification (bv. om 'n connection of file binêr te klassifiseer). Dit hanteer binary, multi-class (met die toepaslike loss) en selfs ranking-probleme.

-   **Interpretability:** Laag tot medium. Hoewel 'n enkele boosted tree klein is, kan 'n volledige model honderde trees hê, wat as geheel nie deur mense geïnterpreteer kan word nie. Soos Random Forest kan dit egter feature importance-scores verskaf, en tools soos SHAP (SHapley Additive exPlanations) kan gebruik word om individuele predictions tot 'n sekere mate te interpreteer.

-   **Advantages:** Dikwels die **beste presterende** algorithm vir gestruktureerde/tabular data. Dit kan komplekse patterns en interactions opspoor. Dit het baie tuning knobs (aantal trees, diepte van trees, learning rate, regularization terms) om model complexity aan te pas en overfitting te voorkom. Moderne implementerings is vir spoed geoptimaliseer (bv. XGBoost gebruik second-order gradient info en doeltreffende data structures). Dit is geneig om imbalanced data beter te hanteer wanneer dit met toepaslike loss functions gekombineer word of wanneer sample weights aangepas word.

-   **Limitations:** Dit is meer kompleks om te tune as eenvoudiger models; training kan stadig wees as trees diep is of die aantal trees groot is (hoewel dit steeds gewoonlik vinniger is as die training van 'n vergelykbare deep neural network op dieselfde data). Die model kan overfit as dit nie getune word nie (bv. te veel diep trees met onvoldoende regularization). Weens die baie hyperparameters kan die effektiewe gebruik van gradient boosting meer expertise of experimentation vereis. Soos tree-based methods hanteer dit ook nie inherent baie sparse high-dimensional data so doeltreffend soos linear models of Naive Bayes nie (hoewel dit steeds toegepas kan word, bv. in text classification, maar dit is moontlik nie die eerste keuse sonder feature engineering nie).

> [!TIP]
> *Use cases in cybersecurity:* Byna enige plek waar 'n decision tree of random forest gebruik kan word, kan 'n gradient boosting-model beter accuracy behaal. Microsoft se **malware detection**-kompetisies het byvoorbeeld baie gebruik gemaak van XGBoost op engineered features uit binary files. Navorsing oor **network intrusion detection** rapporteer dikwels top results met GBDTs (bv. XGBoost op CIC-IDS2017- of UNSW-NB15-datasets). Hierdie models kan 'n wye reeks features neem (protocol types, frequency van sekere events, statistical features van traffic, ens.) en dit kombineer om threats op te spoor. In phishing detection kan gradient boosting lexical features van URLs, domain reputation features en page content features kombineer om baie hoë accuracy te behaal. Die ensemble-benadering help om baie corner cases en subtleties in die data te dek.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
Ons sal 'n gradient boosting classifier op die phishing-dataset gebruik. Om dinge eenvoudig en self-contained te hou, sal ons `sklearn.ensemble.GradientBoostingClassifier` gebruik ('n stadiger maar eenvoudige implementering). Normaalweg sou 'n mens `xgboost`- of `lightgbm`-libraries gebruik vir beter performance en addisionele features. Ons sal die model train en dit soortgelyk aan vroeër evalueer.
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
Die gradient boosting-model sal waarskynlik baie hoë akkuraatheid en AUC op hierdie phishing-datastel behaal (sulke modelle kan dikwels meer as 95% akkuraatheid met behoorlike tuning op sulke data oorskry, soos in die literatuur gesien word. Dit demonstreer waarom GBDTs as *"die state-of-the-art-model vir tabulêre datastelle"* beskou word -- hulle presteer dikwels beter as eenvoudiger algoritmes deur komplekse patrone vas te lê. In 'n kuberveiligheidskonteks kan dit beteken dat meer phishing-webwerwe of attacks opgespoor word, met minder gevalle wat gemis word. Natuurlik moet 'n mens versigtig wees vir overfitting -- ons sal tipies tegnieke soos cross-validation gebruik en prestasie op 'n validasiedatastel monitor wanneer ons so 'n model vir implementering ontwikkel.

</details>

### Kombinering van modelle: Ensemble Learning en Stacking

Ensemble learning is 'n strategie om **veelvuldige modelle te kombineer** om algehele prestasie te verbeter. Ons het reeds spesifieke ensemble-metodes gesien: Random Forest (’n ensemble van bome deur bagging) en Gradient Boosting (’n ensemble van bome deur sequential boosting). Ensembles kan egter ook op ander maniere geskep word, soos **voting ensembles** of **stacked generalization (stacking)**. Die hoofidee is dat verskillende modelle verskillende patrone kan vaslê of verskillende swakhede kan hê; deur hulle te kombineer, kan ons **elke model se foute met die sterk punte van 'n ander model vergoed**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** In 'n eenvoudige voting classifier train ons veelvuldige diverse modelle (byvoorbeeld 'n logistic regression, 'n decision tree en 'n SVM) en laat ons hulle oor die finale voorspelling stem (meerderheidsstem vir klassifikasie). As ons die stemme weeg (byvoorbeeld 'n hoër gewig aan meer akkurate modelle gee), is dit 'n weighted voting-skema. Dit verbeter tipies prestasie wanneer die individuele modelle redelik goed en onafhanklik is -- die ensemble verminder die risiko van 'n individuele model se fout, aangesien die ander modelle dit moontlik kan korrigeer. Dit is soos om 'n paneel deskundiges eerder as 'n enkele mening te hê.

-   **Stacking (Stacked Ensemble):** Stacking gaan 'n stap verder. In plaas van 'n eenvoudige stem, train dit 'n **meta-model** om te **leer hoe om die voorspellings van basismodelle die beste te kombineer**. Byvoorbeeld, jy train 3 verskillende classifiers (base learners) en voer dan hul uitsette (of waarskynlikhede) as features in 'n meta-classifier (dikwels 'n eenvoudige model soos logistic regression) in, wat die optimale manier leer om hulle te kombineer. Die meta-model word op 'n validasiedatastel of deur cross-validation getrain om overfitting te voorkom. Stacking kan dikwels beter as eenvoudige voting presteer deur te leer *watter modelle in watter omstandighede meer vertrou moet word*. In kuberveiligheid kan een model beter wees met die opsporing van network scans, terwyl 'n ander beter is met die opsporing van malware beaconing; 'n stacking-model kan leer om gepas op elkeen staat te maak.

Ensembles, hetsy deur voting of stacking, is geneig om **akkuraatheid** en robuustheid te verhoog. Die nadeel is groter kompleksiteit en soms verminderde interpreteerbaarheid (hoewel sommige ensemble-benaderings, soos 'n gemiddelde van decision trees, steeds insig kan verskaf, byvoorbeeld feature importance). In die praktyk kan die gebruik van 'n ensemble tot hoër opsporingsyfers lei indien operasionele beperkings dit toelaat. Baie wenoplossings in kuberveiligheidsuitdagings (en Kaggle-kompetisies in die algemeen) gebruik ensemble-tegnieke om die laaste bietjie prestasie uit te druk.

<details>
<summary>Voorbeeld -- Voting Ensemble vir Phishing-opsporing:</summary>
Om model stacking te illustreer, kombineer ons 'n paar van die modelle wat ons op die phishing-datastel bespreek het. Ons sal 'n logistic regression, 'n decision tree en 'n k-NN as base learners gebruik, en 'n Random Forest as 'n meta-learner gebruik om hul voorspellings saam te voeg. Die meta-learner sal op die uitsette van die base learners getrain word (deur cross-validation op die trainingsdatastel). Ons verwag dat die stacked model net so goed soos, of effens beter as, die individuele modelle sal presteer.
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
Die stacked ensemble benut die komplementêre sterkpunte van die basismodelle. Byvoorbeeld, logistiese regressie kan die lineêre aspekte van die data hanteer, die decision tree kan spesifieke reëlagtige interaksies vasvang, en k-NN kan uitblink in plaaslike nabygeleë gebiede van die kenmerkruimte. Die meta-model (hier ’n random forest) kan leer hoe om hierdie insette te weeg. Die resulterende metrieke toon dikwels ’n verbetering (selfs al is dit gering) teenoor die metrieke van enige enkele model. In ons phishing-voorbeeld, indien logistiese regressie alleen ’n F1 van byvoorbeeld 0.95 en die tree 0.94 gehad het, kan die stack 0.96 bereik deur op te tel waar elke model foute maak.

Ensemble-metodes soos hierdie demonstreer die beginsel dat *"die kombinasie van verskeie modelle gewoonlik tot beter veralgemening lei"*. In kuberveiligheid kan dit geïmplementeer word deur verskeie detection engines te gebruik (een kan reëlgebaseer wees, een machine learning-gebaseer en een anomaliegebaseer), gevolg deur ’n laag wat hul waarskuwings saamvoeg -- effektief ’n vorm van ensemble -- om ’n finale besluit met groter sekerheid te neem. Wanneer sulke stelsels ontplooi word, moet ’n mens die bykomende kompleksiteit in ag neem en verseker dat die ensemble nie te moeilik word om te bestuur of te verduidelik nie. Vanuit ’n akkuraatheidsoogpunt is ensembles en stacking egter kragtige hulpmiddels om modelwerkverrigting te verbeter.

</details>


## Verwysings

- [1] [Logistiese regressie](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Decision Tree - Inleiding met voorbeeld](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Denial of Services Attack Detection using Random Forest Classifier with Information Gain](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [What are Support Vector Machines (SVMs)? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Naive Bayes spam filtering (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT Demystified: How LightGBM, XGBoost, and CatBoost Work](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI and Machine Learning in Cybersecurity (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Linear Regression Explained](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Performance analysis of machine learning models for intrusion detection system using Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [What is the k-nearest neighbors (KNN) algorithm? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Phishing Attacks and Websites Classification Using Machine Learning and Multiple Datasets (A Comparative Analysis)](https://arxiv.org/pdf/2101.02552)
- [12] [How Deep Learning Enhances Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning: Boosting Model Performance by Combining Strengths](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
