# Toesigleer-algoritmes

{{#include ../banners/hacktricks-training.md}}

## Basiese inligting

Toesigleer gebruik gemerkte data om modelle op te lei wat voorspellings oor nuwe, ongekende insette kan maak. In kuberveiligheid word toesigmasjienleer wyd toegepas op take soos intrusion detection (die klassifisering van netwerkverkeer as *normaal* of *aanval*), malware detection (die onderskeiding van kwaadwillige sagteware van onskadelike sagteware), phishing detection (die identifisering van bedrieglike webwerwe of e-posse), en spam filtering, onder andere.<sup>[[1]](#references)</sup> Elke algoritme het sy sterk punte en is geskik vir verskillende soorte probleme (klassifikasie of regressie). Hieronder hersien ons belangrike toesigleer-algoritmes, verduidelik ons hoe hulle werk, en demonstreer ons hul gebruik op werklike kuberveiligheidsdatastelle. Ons bespreek ook hoe die kombinasie van modelle (ensemble learning) dikwels voorspellingsprestasie kan verbeter.

## Algoritmes

-   **Linear Regression:** 'n Fundamentele regressie-algoritme vir die voorspelling van numeriese uitkomste deur 'n lineêre vergelyking by data te pas.

-   **Logistic Regression:** 'n Klassifikasie-algoritme (ten spyte van sy naam) wat 'n logistiese funksie gebruik om die waarskynlikheid van 'n binêre uitkoms te modelleer.

-   **Decision Trees:** Boomgestruktureerde modelle wat data volgens kenmerke verdeel om voorspellings te maak; word dikwels gebruik vanweë hul interpreteerbaarheid.

-   **Random Forests:** 'n Ensemble van decision trees (via bagging) wat akkuraatheid verbeter en overfitting verminder.

-   **Support Vector Machines (SVM):** Klassifiseerders met maksimum marge wat die optimale skeidingshipervlak vind; kan kernels vir nie-lineêre data gebruik.

-   **Naive Bayes:** 'n Waarskynlikheidsklassifiseerder gebaseer op Bayes se stelling, met die aanname dat kenmerke onafhanklik is; dit word veral in spam filtering gebruik.

-   **k-Nearest Neighbors (k-NN):** 'n Eenvoudige "instance-based"-klassifiseerder wat 'n monster benoem op grond van die meerderheidsklas van sy naaste bure.

-   **Gradient Boosting Machines:** Ensemble-modelle (bv. XGBoost, LightGBM) wat 'n sterk voorspeller bou deur opeenvolgend swakker leerders (tipies decision trees) by te voeg.

Elke afdeling hieronder verskaf 'n verbeterde beskrywing van die algoritme en 'n **Python-kodevoorbeeld** wat biblioteke soos `pandas` en `scikit-learn` gebruik (en `PyTorch` vir die neurale netwerkvoorbeeld). Die voorbeelde gebruik publiek beskikbare kuberveiligheidsdatastelle (soos NSL-KDD vir intrusion detection en 'n Phishing Websites-datastel) en volg 'n konsekwente struktuur:

1.  **Laai die datastel** (laai dit via URL af indien beskikbaar).

2.  **Verwerk die data vooraf** (bv. enkodeer kategoriese kenmerke, skaal waardes, en verdeel dit in opleidings-/toetsstelle).

3.  **Lei die model op** met die opleidingsdata.

4.  **Evalueer** dit op 'n toetsstel deur metrieke te gebruik: akkuraatheid, presisie, herroeping, F1-telling, en ROC AUC vir klassifikasie (en gemiddelde kwadraatfout vir regressie).

Kom ons kyk na elke algoritme:

### Linear Regression

Linear regression is 'n **regressie**-algoritme wat gebruik word om aaneenlopende numeriese waardes te voorspel. Dit neem 'n lineêre verhouding tussen die insetkenmerke (onafhanklike veranderlikes) en die uitset (afhanklike veranderlike) aan. Die model probeer om 'n reguit lyn (of hipervlak in hoër dimensies) te pas wat die verhouding tussen die kenmerke en die teiken die beste beskryf. Dit word tipies gedoen deur die som van die kwadraatfoute tussen voorspelde en werklike waardes te minimaliseer (die Ordinary Least Squares-metode).<sup>[[2]](#references)</sup>

Die eenvoudigste vorm om lineêre regressie voor te stel, is met 'n lyn:
```plaintext
y = mx + b
```
Waar:

- `y` is die voorspelde waarde (uitset)
- `m` is die helling van die lyn (koëffisiënt)
- `x` is die invoerkenmerk
- `b` is die y-afsnit

Die doel van lineêre regressie is om die lyn te vind wat die beste pas en die verskil tussen die voorspelde waardes en die werklike waardes in die dataset minimaliseer. Natuurlik is dit baie eenvoudig: dit sou ’n reguit lyn wees wat 2 kategorieë skei, maar wanneer meer dimensies bygevoeg word, word die lyn meer kompleks:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Linear regression self is minder algemeen vir kernsekuriteitstake (wat dikwels classification is), maar dit kan toegepas word om numeriese uitkomste te voorspel. Byvoorbeeld, kan linear regression gebruik word om die **volume van netwerkverkeer te voorspel** of **die aantal aanvalle in ’n tydperk te skat** op grond van historiese data. Dit kan ook ’n risikotelling of die verwagte tyd tot die opsporing van ’n aanval voorspel, gegewe sekere stelselmetrieke. In die praktyk word classification algorithms (soos logistic regression of trees) meer dikwels gebruik om intrusions of malware op te spoor, maar linear regression dien as ’n grondslag en is nuttig vir regression-georiënteerde ontledings.

#### **Belangrike kenmerke van Linear Regression:**

-   **Tipe probleem:** Regression (voorspelling van aaneenlopende waardes). Nie geskik vir direkte classification nie, tensy ’n drempel op die uitset toegepas word.

-   **Interpreteerbaarheid:** Hoog -- koëffisiënte is maklik om te interpreteer en toon die lineêre effek van elke feature.

-   **Voordele:** Eenvoudig en vinnig; ’n goeie basislyn vir regression-take; werk goed wanneer die werklike verhouding ongeveer lineêr is.

-   **Beperkings:** Kan nie komplekse of nie-lineêre verhoudings vasvang nie (sonder handmatige feature engineering); geneig tot underfitting wanneer verhoudings nie-lineêr is; sensitief vir uitskieters wat die resultate kan skeeftrek.

-   **Vind van die beste passing:** Om die lyn met die beste passing te vind wat die moontlike kategorieë skei, gebruik ons ’n metode genaamd **Ordinary Least Squares (OLS)**. Hierdie metode minimaliseer die som van die gekwadreerde verskille tussen die waargenome waardes en die waardes wat deur die lineêre model voorspel word.

<details>
<summary>Voorbeeld -- Voorspelling van verbindingstydsduur (Regression) in ’n Intrusion-datastel
</summary>
Hier demonstreer ons linear regression deur die NSL-KDD-kuberveiligheidsdatastel te gebruik. Ons sal dit as ’n regression-probleem hanteer deur die `duration` van netwerkverbindings op grond van ander features te voorspel. (In werklikheid is `duration` een feature van NSL-KDD; ons gebruik dit hier net om regression te illustreer.) Ons laai die datastel, verwerk dit vooraf (kodeer categorical features), lei ’n linear regression-model op en evalueer die Mean Squared Error (MSE)- en R²-telling op ’n toetsstel.
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
In hierdie voorbeeld probeer die linear regression-model om verbinding-`duration` uit ander netwerkkenmerke te voorspel. Ons meet werkverrigting met Mean Squared Error (MSE) en R². ’n R² naby 1.0 sou aandui dat die model die meeste variasie in `duration` verklaar, terwyl ’n lae of negatiewe R² op ’n swak passing dui. (Moenie verbaas wees as die R² hier laag is nie -- dit kan moeilik wees om `duration` uit die gegewe kenmerke te voorspel, en linear regression kan moontlik nie die patrone vasvang as hulle kompleks is nie.)
</details>

### Logistic Regression

Logistic regression is ’n **klassifikasie**-algoritme wat die waarskynlikheid modelleer dat ’n instansie aan ’n spesifieke klas behoort (tipies die "positiewe" klas). Ondanks sy naam word *logistic* regression vir diskrete uitkomste gebruik (anders as linear regression, wat vir kontinue uitkomste is). Dit word veral vir **binêre klassifikasie** gebruik (twee klasse, bv. malicious teenoor benign), maar dit kan na multi-class-probleme uitgebrei word (met softmax- of one-vs-rest-benaderings).<sup>[[3]](#references)</sup>

Die logistic regression gebruik die logistic-funksie (ook bekend as die sigmoid-funksie) om voorspelde waardes na waarskynlikhede te karteer. Let daarop dat die sigmoid-funksie ’n funksie is met waardes tussen 0 en 1 wat volgens die behoeftes van die klassifikasie in ’n S-vormige kurwe groei, wat nuttig is vir binêre klassifikasietake. Daarom word elke kenmerk van elke invoer met sy toegekende gewig vermenigvuldig, en die resultaat word deur die sigmoid-funksie gestuur om ’n waarskynlikheid te produseer:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Waar:

- `p(y=1|x)` is die waarskynlikheid dat die uitset `y` 1 is gegewe die inset `x`
- `e` is die basis van die natuurlike logaritme
- `z` is ’n lineêre kombinasie van die insetkenmerke, tipies voorgestel as `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Let daarop dat dit in sy eenvoudigste vorm weer ’n reguit lyn is, maar in meer komplekse gevalle word dit ’n hiper- vlak met verskeie dimensies (een per kenmerk).

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Omdat baie sekuriteitsprobleme in wese ja/nee-besluite is, word Logistic Regression wyd gebruik. Byvoorbeeld, ’n intrusion detection system kan Logistic Regression gebruik om te besluit of ’n netwerkverbinding ’n aanval is op grond van die kenmerke van daardie verbinding. In phishing detection kan Logistic Regression kenmerke van ’n webwerf (URL-lengte, teenwoordigheid van die "@"-simbool, ens.) kombineer tot ’n waarskynlikheid dat dit phishing is. Dit is in vroeë-generasie spam filters gebruik en bly ’n sterk basislyn vir baie classification-take.

#### Logistic Regression for nie-binêre klassifikasie

Logistic Regression is ontwerp vir binêre klassifikasie, maar dit kan uitgebrei word om multi-class-probleme te hanteer deur tegnieke soos **one-vs-rest** (OvR) of **softmax regression** te gebruik. In OvR word ’n aparte Logistic Regression-model vir elke klas opgelei, waar die klas as die positiewe klas teenoor al die ander behandel word. Die klas met die hoogste voorspelde waarskynlikheid word as die finale voorspelling gekies. Softmax regression veralgemeen Logistic Regression na veelvuldige klasse deur die softmax-funksie op die uitsetlaag toe te pas, wat ’n waarskynlikheidsverdeling oor al die klasse lewer.

#### **Sleutelkenmerke van Logistic Regression:**

-   **Tipe probleem:** Klassifikasie (gewoonlik binêr). Dit voorspel die waarskynlikheid van die positiewe klas.

-   **Interpreteerbaarheid:** Hoog -- soos met lineêre regressie kan die kenmerkk versteurings aandui hoe elke kenmerk die log-odds van die uitkoms beïnvloed. Hierdie deursigtigheid word dikwels in sekuriteit waardeer om te verstaan watter faktore tot ’n waarskuwing bydra.

-   **Voordele:** Eenvoudig en vinnig om op te lei; werk goed wanneer die verhouding tussen kenmerke en die log-odds van die uitkoms lineêr is. Lewer waarskynlikhede, wat risikotelling moontlik maak. Met gepaste regularisering veralgemeen dit goed en kan dit multikollineariteit beter hanteer as gewone lineêre regressie.

-   **Beperkings:** Neem ’n lineêre besluitgrens in die kenmerkruimte aan (misluk indien die werklike grens kompleks/nie-lineêr is). Dit kan swakker presteer op probleme waar interaksies of nie-lineêre effekte krities is, tensy jy polinoom- of interaksiekenmerke handmatig byvoeg. Logistic Regression is ook minder doeltreffend indien klasse nie maklik deur ’n lineêre kombinasie van kenmerke geskei kan word nie.


<details>
<summary>Voorbeeld -- Phishing Website Detection met Logistic Regression:</summary>

Ons sal ’n **Phishing Websites Dataset** (van die UCI-repository) gebruik, wat onttrekte kenmerke van webwerwe bevat (soos of die URL ’n IP-adres het, die ouderdom van die domein, die teenwoordigheid van verdagte elemente in HTML, ens.) en ’n etiket wat aandui of die webwerf phishing of legitiem is.<sup>[[4]](#references)</sup> Ons lei ’n Logistic Regression-model op om webwerwe te klassifiseer en evalueer dan die akkuraatheid, presisie, herroeping, F1-telling en ROC AUC daarvan op ’n toetsverdeling.
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
In hierdie phishing detection-voorbeeld lewer logistic regression ’n waarskynlikheid vir elke webwerf dat dit phishing is. Deur accuracy, precision, recall en F1 te evalueer, kry ons ’n aanduiding van die model se werkverrigting. Byvoorbeeld, ’n hoë recall sou beteken dat dit die meeste phishing-webwerwe opspoor (belangrik vir sekuriteit om gemiste attacks te beperk), terwyl hoë precision beteken dat dit min vals alarms het (belangrik om analyst fatigue te voorkom). Die ROC AUC (Area Under the ROC Curve) gee ’n drempel-onafhanklike maatstaf van werkverrigting (1.0 is ideaal, 0.5 is nie beter as kans nie). Logistic regression presteer dikwels goed met sulke take, maar as die decision boundary tussen phishing- en wettige webwerwe kompleks is, mag kragtiger nie-lineêre modelle nodig wees.

</details>

### Besluitnemingsbome

’n Besluitnemingsboom is ’n veelsydige **toesig-leeralgoritme** wat vir sowel klassifikasie- as regressietake gebruik kan word. Dit leer ’n hiërargiese boomagtige model van besluite gebaseer op die data se kenmerke. Elke interne node van die boom verteenwoordig ’n toets op ’n spesifieke kenmerk, elke tak verteenwoordig ’n uitkoms van daardie toets, en elke blaarnode verteenwoordig ’n voorspelde klas (vir klassifikasie) of waarde (vir regressie).<sup>[[5]](#references)</sup>

Om ’n boom te bou, gebruik algorithms soos CART (Classification and Regression Tree) maatstawwe soos **Gini impurity** of **information gain (entropy)** om die beste kenmerk en drempel te kies waarvolgens die data by elke stap verdeel moet word. Die doel met elke verdeling is om die data te partisioneer sodat die homogeniteit van die teikenveranderlike in die resulterende deelversamelings verhoog word (vir klassifikasie poog elke node om so suiwer moontlik te wees, met hoofsaaklik ’n enkele klas).

Besluitnemingsbome is **hoogs interpreteerbaar** -- ’n mens kan die pad van wortel tot blaar volg om die logika agter ’n voorspelling te verstaan (bv. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Dit is waardevol in cybersecurity om te verduidelik waarom ’n sekere alert gegenereer is. Bome kan natuurlik sowel numeriese as kategoriese data hanteer en vereis min voorafverwerking (bv. feature scaling is nie nodig nie).

’n Enkele besluitnemingsboom kan egter maklik die training data oorpas, veral as dit diep gegroei word (met baie verdelings). Tegnieke soos pruning (die beperking van boomdiepte of die vereiste van ’n minimum aantal samples per blaar) word dikwels gebruik om overfitting te voorkom.

Daar is 3 hoofkomponente van ’n besluitnemingsboom:
- **Root Node**: Die boonste node van die boom, wat die hele dataset verteenwoordig.
- **Internal Nodes**: Nodes wat features en besluite gebaseer op daardie features verteenwoordig.
- **Leaf Nodes**: Nodes wat die finale uitkoms of voorspelling verteenwoordig.

’n Boom kan uiteindelik soos volg lyk:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Gebruiksgevalle in cybersecurity:* Besluitbome is in intrusion detection systems gebruik om **reëls** af te lei vir die identifisering van aanvalle. Byvoorbeeld, vroeë IDS soos ID3/C4.5-gebaseerde stelsels sou mensleesbare reëls genereer om normale en kwaadwillige verkeer te onderskei. Hulle word ook in malware-analise gebruik om te bepaal of ’n lêer kwaadwillig is op grond van sy attribute (lêergrootte, seksie-entropie, API calls, ens.). Die duidelikheid van besluitbome maak hulle nuttig wanneer deursigtigheid nodig is -- ’n ontleder kan die boom inspekteer om die detection-logika te valideer.

#### **Sleutelkenmerke van besluitbome:**

-   **Tipe probleem:** Sowel klassifikasie as regressie. Word algemeen gebruik vir die klassifikasie van aanvalle teenoor normale verkeer, ens.

-   **Interpreteerbaarheid:** Baie hoog -- die model se besluite kan gevisualiseer en verstaan word as ’n stel if-then-reëls. Dit is ’n belangrike voordeel in security vir vertroue in en verifikasie van modelgedrag.

-   **Voordele:** Kan nie-lineêre verhoudings en interaksies tussen features vasvang (elke split kan as ’n interaksie beskou word). Dit is nie nodig om features te skaal of kategoriese veranderlikes one-hot te encodeer nie -- bome hanteer dit native. Vinnige inference (prediction is bloot die volg van ’n pad in die boom).

-   **Beperkings:** Geneig tot overfitting indien dit nie beheer word nie (’n diep boom kan die training set memoriseer). Hulle kan onstabiel wees -- klein veranderinge in die data kan tot ’n ander boomstruktuur lei. As enkele modelle stem hul akkuraatheid moontlik nie ooreen met meer gevorderde metodes nie (ensembles soos Random Forests lewer tipies beter resultate deur variance te verminder).

-   **Vind van die beste split:**
- **Gini-impuriteit**: Meet die impuriteit van ’n node. ’n Laer Gini-impuriteit dui op ’n beter split. Die formule is:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Waar `p_i` die proporsie van instances in klas `i` is.

- **Entropie**: Meet die onsekerheid in die dataset. ’n Laer entropie dui op ’n beter split. Die formule is:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Waar `p_i` die proporsie van instances in klas `i` is.

- **Inligtingswins**: Die vermindering in entropie of Gini-impuriteit ná ’n split. Hoe hoër die inligtingswins, hoe beter die split. Dit word soos volg bereken:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Verder word ’n boom beëindig wanneer:
- Alle instances in ’n node aan dieselfde klas behoort. Dit kan tot overfitting lei.
- Die maksimum diepte (hardcoded) van die boom bereik is. Dit is ’n manier om overfitting te voorkom.
- Die aantal instances in ’n node onder ’n sekere drempel is. Dit is ook ’n manier om overfitting te voorkom.
- Die inligtingswins uit verdere splits onder ’n sekere drempel is. Dit is ook ’n manier om overfitting te voorkom.

<details>
<summary>Voorbeeld -- Besluitboom vir Intrusion Detection:</summary>
Ons sal ’n besluitboom op die NSL-KDD-dataset train om netwerkverbindings as óf *normaal* óf *aanval* te klassifiseer. NSL-KDD is ’n verbeterde weergawe van die klassieke KDD Cup 1999-dataset, met features soos protokoltipe, diens, duur, aantal mislukte logins, ens., en ’n label wat die aanvaltipe of "normaal" aandui. Ons sal alle aanvalstipes na ’n "anomalie"-klas karteer (binêre klassifikasie: normaal teenoor anomalie). Ná training sal ons die boom se performance op die test set evalueer.
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
In hierdie decision tree-voorbeeld het ons die boomdiepte tot 10 beperk om ekstreme overfitting te voorkom (die `max_depth=10`-parameter). Die metrics wys hoe goed die boom tussen normale en attack-verkeer onderskei. ’n Hoë recall sou beteken dat dit die meeste attacks opvang (belangrik vir ’n IDS), terwyl hoë precision min vals alarms beteken. Decision trees behaal dikwels redelike accuracy op gestruktureerde data, maar ’n enkele boom bereik moontlik nie die beste prestasie wat haalbaar is nie. Nietemin is die *interpreteerbaarheid* van die model ’n groot voordeel -- ons kan die boom se splitsings ondersoek om byvoorbeeld te sien watter features (bv. `service`, `src_bytes`, ens.) die invloedrykste is wanneer ’n verbinding as malicious gemerk word.

</details>

### Random Forests

Random Forest is ’n **ensemble learning**-metode wat op decision trees voortbou om prestasie te verbeter. ’n random forest lei meerdere decision trees op (vandaar "forest") en kombineer hul uitsette om ’n finale prediction te maak (vir classification, tipies deur majority vote). Die twee hoofidees in ’n random forest is **bagging** (bootstrap aggregating) en **feature randomness**:

-   **Bagging:** Elke boom word op ’n ewekansige bootstrap-steekproef van die training data opgelei (gesteekproef met replacement). Dit skep diversiteit onder die bome.

-   **Feature Randomness:** By elke splitsing in ’n boom word ’n ewekansige subset van features vir die splitsing oorweeg (in plaas van alle features). Dit ontkoppel die bome verder van mekaar.

Deur die resultate van baie bome te average, verminder die random forest die variance wat ’n enkele decision tree kan hê. In eenvoudige terme kan individuele bome overfit of raserig wees, maar ’n groot aantal diverse bome wat saam stem, stryk hierdie errors uit. Die resultaat is dikwels ’n model met **hoër accuracy** en beter generalization as ’n enkele decision tree. Daarbenewens kan random forests ’n skatting van feature importance verskaf (deur te kyk hoeveel elke feature-splitsing gemiddeld impurity verminder).

Random forests het ’n **workhorse in cybersecurity** geword vir take soos intrusion detection, malware classification en spam detection. Hulle presteer dikwels goed out-of-the-box met minimale tuning en kan groot feature-stelle hanteer. In intrusion detection kan ’n random forest byvoorbeeld beter as ’n individuele decision tree presteer deur meer subtiele aanvalspatrone met minder false positives op te spoor. Navorsing het getoon dat random forests gunstig presteer in vergelyking met ander algorithms wanneer attacks in datasets soos NSL-KDD en UNSW-NB15 geklassifiseer word.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Belangrike eienskappe van Random Forests:**

-   **Tipe probleem:** Hoofsaaklik classification (ook gebruik vir regression). Baie geskik vir hoë-dimensionele gestruktureerde data wat algemeen in security logs voorkom.

-   **Interpreteerbaarheid:** Laer as dié van ’n enkele decision tree -- jy kan nie maklik honderde bome tegelyk visualiseer of verduidelik nie. Feature importance-scores verskaf egter ’n mate van insig in watter attribute die invloedrykste is.

-   **Voordele:** Oor die algemeen hoër accuracy as single-tree-modelle weens die ensemble-effek. Bestand teen overfitting -- selfs al overfit individuele bome, generalizeer die ensemble beter. Hanteer sowel numerical as categorical features en kan missing data tot ’n mate bestuur. Dit is ook relatief bestand teen outliers.

-   **Beperkings:** Modelgrootte kan groot wees (baie bome, waarvan elkeen moontlik diep is). Predictions is stadiger as dié van ’n enkele boom (want jy moet resultate oor baie bome aggregate). Minder interpreteerbaar -- hoewel jy weet watter features belangrik is, kan die presiese logika nie maklik soos ’n eenvoudige reël nagespoor word nie. As die dataset uiters hoë-dimensioneel en sparse is, kan die training van ’n baie groot forest computationally swaar wees.

-   **Training Process:**
1. **Bootstrap Sampling**: Neem ewekansige samples van die training data met replacement om meerdere subsets (bootstrap samples) te skep.
2. **Tree Construction**: Bou vir elke bootstrap sample ’n decision tree deur by elke splitsing ’n ewekansige subset van features te gebruik. Dit skep diversiteit onder die bome.
3. **Aggregation**: Vir classification-take word die finale prediction gemaak deur ’n majority vote onder die predictions van alle bome. Vir regression-take is die finale prediction die gemiddelde van die predictions van alle bome.

<details>
<summary>Voorbeeld -- Random Forest vir Intrusion Detection (NSL-KDD):</summary>
Ons sal dieselfde NSL-KDD-dataset gebruik (binêr gelabel as normal teenoor anomaly) en ’n Random Forest-classifier oplei. Ons verwag dat die random forest danksy die ensemble averaging wat variance verminder, net so goed soos of beter as die enkele decision tree sal presteer. Ons sal dit met dieselfde metrics evalueer.
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
Die random forest behaal tipies sterk resultate op hierdie intrusion detection-taak. Ons kan ’n verbetering in maatstawwe soos F1 of AUC waarneem in vergelyking met die enkele decision tree, veral in recall of precision, afhangend van die data. Dit stem ooreen met die insig dat *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> In ’n security operations-konteks kan ’n random forest-model attacks meer betroubaar merk terwyl dit vals alarms verminder, danksy die gemiddeld van baie decision rules. Feature importance uit die forest kan vir ons aandui watter network features die sterkste aanduiding van attacks is (bv. sekere network services of ongewone tellings van packets).

</details>

### Support Vector Machines (SVM)

Support Vector Machines is kragtige supervised learning-modelle wat hoofsaaklik vir classification gebruik word (en ook vir regression as SVR). ’n SVM probeer om die **optimale skeidings-hypervlak** te vind wat die margin tussen twee klasse maksimeer. Slegs ’n subset van training points (die "support vectors" naaste aan die grens) bepaal die posisie van hierdie hypervlak. Deur die margin (afstand tussen support vectors en die hypervlak) te maksimeer, is SVMs geneig om goeie generalization te behaal.<sup>[[8]](#references)</sup>

Die kern van SVM se krag is die vermoë om **kernel functions** te gebruik om nie-lineêre verhoudings te hanteer. Die data kan implisiet na ’n hoër-dimensionele feature space getransformeer word waar ’n lineêre separator moontlik bestaan. Algemene kernels sluit polynomial, radial basis function (RBF) en sigmoid in. Byvoorbeeld, as network traffic-klasse nie lineêr skeibaar is in die rou feature space nie, kan ’n RBF-kernel dit na ’n hoër dimensie karteer waar die SVM ’n lineêre skeiding vind (wat met ’n nie-lineêre grens in die oorspronklike space ooreenstem). Die buigsaamheid om kernels te kies, stel SVMs in staat om ’n verskeidenheid probleme aan te pak.

SVMs is bekend daarvoor dat hulle goed presteer in situasies met hoë-dimensionele feature spaces (soos teksdata of malware opcode sequences) en in gevalle waar die aantal features groot is relatief tot die aantal samples. Hulle was gewild in baie vroeë cybersecurity-toepassings, soos malware classification en anomaly-based intrusion detection in die 2000’s, en het dikwels hoë akkuraatheid getoon.

SVMs skaal egter nie maklik na baie groot datasets nie (training complexity is super-lineêr in die aantal samples, en memory usage kan hoog wees omdat dit moontlik baie support vectors moet stoor). In die praktyk kan SVM vir take soos network intrusion detection met miljoene records te stadig wees sonder noukeurige subsampling of die gebruik van approximate methods.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (binary of multiclass via one-vs-one/one-vs-rest) en regression-variante. Word dikwels in binary classification met duidelike margin-separation gebruik.

-   **Interpretability:** Medium -- SVMs is nie so interpreteerbaar soos decision trees of logistic regression nie. Alhoewel jy kan identifiseer watter data points support vectors is en ’n mate van insig kan kry in watter features invloedryk kan wees (deur die weights in die linear kernel-geval), word SVMs (veral met non-linear kernels) in die praktyk as black-box classifiers behandel.

-   **Advantages:** Effektief in hoë-dimensionele spaces; kan komplekse decision boundaries met die kernel trick modelleer; bestand teen overfitting indien die margin gemaksimeer word (veral met ’n behoorlike regularization parameter C); werk goed selfs wanneer klasse nie deur ’n groot afstand geskei word nie (vind die beste kompromie-grens).

-   **Limitations:** **Computationally intensive** vir groot datasets (beide training en prediction skaal swak namate data groei). Vereis noukeurige tuning van kernel- en regularization-parameters (C, kernel type, gamma vir RBF, ens.). Verskaf nie direk probabilistic outputs nie (hoewel Platt scaling gebruik kan word om probabilities te verkry). SVMs kan ook sensitief wees vir die keuse van kernel parameters --- ’n swak keuse kan tot underfit of overfit lei.

*Use cases in cybersecurity:* SVMs is gebruik in **malware detection** (bv. om files te klassifiseer op grond van onttrekte features of opcode sequences), **network anomaly detection** (om traffic as normaal of malicious te klassifiseer) en **phishing detection** (met features van URLs). ’n SVM kan byvoorbeeld features van ’n e-pos neem (tellings van sekere keywords, sender reputation scores, ens.) en dit as phishing of legitimate klassifiseer. Dit is ook toegepas op **intrusion detection** met feature sets soos KDD, en het dikwels hoë akkuraatheid ten koste van computation behaal.

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
Die SVM-model sal maatstawwe lewer wat ons met logistic regression vir dieselfde taak kan vergelyk. Ons kan vind dat SVM 'n hoë akkuraatheid en AUC behaal indien die data goed deur die features geskei word. Aan die ander kant, indien die dataset baie geraas of oorvleuelende klasse bevat, sal SVM moontlik nie aansienlik beter as logistic regression presteer nie. In die praktyk kan SVM's 'n verbetering bied wanneer daar komplekse, nie-lineêre verhoudings tussen features en klasse is -- die RBF-kernel kan geboë besluitnemingsgrense vasvang wat logistic regression sou mis. Soos met alle modelle, is noukeurige instel van `C` (regularisering) en kernelparameters (soos `gamma` vir RBF) nodig om bias en variansie te balanseer.

</details>

#### Verskille tussen Logistic Regression en SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Doelfunksie** | Minimaliseer **log-loss** (kruisentropie). | Maksimeer die **marge** terwyl **hinge-loss** geminimaliseer word. |
| **Besluitnemingsgrens** | Vind die **beste-passende hipervlak** wat _P(y\|x)_ modelleer. | Vind die **hipervlak met die maksimum marge** (grootste gaping tot die naaste punte). |
| **Uitset** | **Probabilisties** – gee gekalibreerde klaswaarskynlikhede via σ(w·x + b). | **Deterministies** – lewer klasetikette; waarskynlikhede vereis ekstra werk (bv. Platt-skalering). |
| **Regularisering** | L2 (verstek) of L1, wat onder-/oorpassing direk balanseer. | C-parameter ruil margewydte teenoor verkeerde klassifikasies uit; kernelparameters voeg kompleksiteit by. |
| **Kernels / Nie-lineêr** | Die inheemse vorm is **lineêr**; nie-lineariteit word deur feature engineering bygevoeg. | Ingeboude **kernel trick** (RBF, poly, ens.) laat dit komplekse grense in hoë-dimensionele ruimte modelleer. |
| **Skaalbaarheid** | Los 'n konvekse optimalisering in **O(nd)** op; hanteer baie groot n goed. | Opleiding kan **O(n²–n³)** geheue/tyd vereis sonder gespesialiseerde oplossers; minder geskik vir enorme n. |
| **Interpreteerbaarheid** | **Hoog** – gewigte toon feature-invloed; odds-ratio is intuïtief. | **Laag** vir nie-lineêre kernels; support vectors is yl maar nie maklik om te verduidelik nie. |
| **Sensitiwiteit vir uitskieters** | Gebruik gladde log-loss → minder sensitief. | Hinge-loss met 'n harde marge kan **sensitief** wees; sagte marge (C) versag dit. |
| **Tipiese gebruiksgevalle** | Krediettelling, mediese risiko, A/B-toetsing – waar **waarskynlikhede en verklaarbaarheid** belangrik is. | Beeld-/teksklassifikasie, bio-informatika – waar **komplekse grense** en **hoë-dimensionele data** belangrik is. |

* **Indien jy gekalibreerde waarskynlikhede, interpreteerbaarheid of werking op enorme datasets benodig -- kies Logistic Regression.**
* **Indien jy 'n buigsame model benodig wat nie-lineêre verhoudings sonder handmatige feature engineering kan vasvang -- kies SVM (met kernels).**
* Albei optimaliseer konvekse doelwitte, dus word **globale minimums gewaarborg**, maar SVM se kernels voeg hiperparameters en berekeningskoste by.

### Naive Bayes

Naive Bayes is 'n familie van **probabilistiese klassifiseerders** wat gebaseer is op die toepassing van Bayes se Stelling met 'n sterk onafhanklikheidsaanname tussen features. Ondanks hierdie "naiewe" aanname werk Naive Bayes dikwels verrassend goed vir sekere toepassings, veral dié wat teks- of kategoriese data behels, soos spamopsporing.<sup>[[9]](#references)</sup>


#### Bayes se Stelling

Bayes se stelling is die grondslag van Naive Bayes-klassifiseerders. Dit verbind die voorwaardelike en marginale waarskynlikhede van ewekansige gebeurtenisse. Die formule is:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Waar:
- `P(A|B)` is die posteriorwaarskynlikheid van klas `A` gegewe kenmerk `B`.
- `P(B|A)` is die waarskynlikheid van kenmerk `B` gegewe klas `A`.
- `P(A)` is die voorafwaarskynlikheid van klas `A`.
- `P(B)` is die voorafwaarskynlikheid van kenmerk `B`.

Byvoorbeeld, as ons wil klassifiseer of ’n teks deur ’n kind of ’n volwassene geskryf is, kan ons die woorde in die teks as kenmerke gebruik. Gebaseer op aanvanklike data, sal die Naive Bayes classifier vooraf die waarskynlikhede bereken dat elke woord in elke moontlike klas (kind of volwassene) voorkom. Wanneer ’n nuwe teks gegee word, sal dit die waarskynlikheid van elke moontlike klas gegewe die woorde in die teks bereken en die klas met die hoogste waarskynlikheid kies.

Soos jy in hierdie voorbeeld kan sien, is die Naive Bayes classifier baie eenvoudig en vinnig, maar dit neem aan dat die kenmerke onafhanklik is, wat nie altyd die geval is in werklike data nie.


#### Tipes Naive Bayes Classifiers

Daar is verskeie tipes Naive Bayes classifiers, afhangend van die tipe data en die verspreiding van die kenmerke:
- **Gaussian Naive Bayes**: Neem aan dat die kenmerke ’n Gaussian (normale) verspreiding volg. Dit is geskik vir deurlopende data.
- **Multinomial Naive Bayes**: Neem aan dat die kenmerke ’n multinomiale verspreiding volg. Dit is geskik vir diskrete data, soos woordtellings in teksklassifikasie.
- **Bernoulli Naive Bayes**: Neem aan dat die kenmerke binêr (0 of 1) is. Dit is geskik vir binêre data, soos die teenwoordigheid of afwesigheid van woorde in teksklassifikasie.
- **Categorical Naive Bayes**: Neem aan dat die kenmerke kategoriese veranderlikes is. Dit is geskik vir kategoriese data, soos om vrugte op grond van hul kleur en vorm te klassifiseer.


#### **Belangrike eienskappe van Naive Bayes:**

-   **Tipe probleem:** Klassifikasie (binêr of multi-klas). Word algemeen gebruik vir teksklassifikasietake in cybersecurity (spam, phishing, ens.).

-   **Interpreteerbaarheid:** Medium -- dit is nie so direk interpreteerbaar soos ’n decision tree nie, maar ’n mens kan die aangeleerde waarskynlikhede inspekteer (byvoorbeeld watter woorde die waarskynlikste in spam- teenoor ham-e-posse voorkom). Die model se vorm (waarskynlikhede vir elke kenmerk gegewe die klas) kan verstaan word indien nodig.

-   **Voordele:** **Baie vinnige** opleiding en voorspelling, selfs op groot datastelle (lineêr in die aantal instansies * aantal kenmerke). Vereis relatief min data om waarskynlikhede betroubaar te skat, veral met behoorlike smoothing. Dit is dikwels verrassend akkuraat as ’n baseline, veral wanneer kenmerke onafhanklik tot die bewyse vir die klas bydra. Werk goed met hoë-dimensionele data (byvoorbeeld duisende kenmerke uit teks). Geen komplekse tuning word vereis buiten die instelling van ’n smoothing-parameter nie.

-   **Beperkings:** Die onafhanklikheidsaanname kan akkuraatheid beperk as kenmerke hoogs gekorreleer is. Byvoorbeeld, in netwerkdata kan kenmerke soos `src_bytes` en `dst_bytes` gekorreleer wees; Naive Bayes sal nie daardie interaksie vasvang nie. Namate datagrootte baie groot word, kan meer ekspressiewe modelle (soos ensembles of neural nets) NB oortref deur kenmerkafhanklikhede aan te leer. Ook, as ’n sekere kombinasie van kenmerke nodig is om ’n aanval te identifiseer (nie net individuele kenmerke wat onafhanklik bydra nie), sal NB sukkel.

> [!TIP]
> *Gebruiksgevalle in cybersecurity:* Die klassieke gebruik is **spam detection** -- Naive Bayes was die kern van vroeë spamfilters, wat die frekwensies van sekere tokens (woorde, frases, IP-adresse) gebruik het om die waarskynlikheid te bereken dat ’n e-pos spam is. Dit word ook gebruik in **phishing email detection** en **URL classification**, waar die teenwoordigheid van sekere sleutelwoorde of eienskappe (soos "login.php" in ’n URL, of `@` in ’n URL-pad) bydra tot die phishing-waarskynlikheid. In malware-analise kan ’n mens ’n Naive Bayes classifier voorstel wat die teenwoordigheid van sekere API calls of permissions in sagteware gebruik om te voorspel of dit malware is. Hoewel meer gevorderde algorithms dikwels beter presteer, bly Naive Bayes ’n goeie baseline weens die spoed en eenvoud daarvan.

<details>
<summary>Voorbeeld -- Naive Bayes vir Phishing Detection:</summary>
Om Naive Bayes te demonstreer, sal ons Gaussian Naive Bayes op die NSL-KDD intrusion dataset (met binêre labels) gebruik. Gaussian NB sal elke kenmerk behandel asof dit per klas ’n normale verspreiding volg. Dit is ’n rowwe keuse, aangesien baie netwerkkenmerke diskreet of hoogs skeef versprei is, maar dit wys hoe ’n mens NB op deurlopende kenmerkdata sou toepas. Ons kon ook Bernoulli NB op ’n datastel van binêre kenmerke (soos ’n stel geaktiveerde alerts) kies, maar ons sal hier by NSL-KDD bly vir kontinuïteit.
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
Hierdie kode lei ’n Naive Bayes-classifier op om attacks op te spoor. Naive Bayes sal dinge soos `P(service=http | Attack)` en `P(Service=http | Normal)` bereken gebaseer op die training data, met die aanname dat daar onafhanklikheid tussen features is. Dit sal dan hierdie waarskynlikhede gebruik om nuwe verbindings as óf normaal óf ’n attack te klassifiseer, gebaseer op die waargenome features. Die werkverrigting van NB op NSL-KDD is moontlik nie so hoog soos dié van meer gevorderde modelle nie (aangesien die onafhanklikheidsaanname geskend word), maar dit is dikwels voldoende en bied die voordeel van uiters hoë spoed. In scenario’s soos intydse e-posfiltrering of aanvanklike triage van URLs, kan ’n Naive Bayes-model ooglopend kwaadwillige gevalle vinnig vlag met lae hulpbronverbruik.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors is een van die eenvoudigste machine learning-algoritmes. Dit is ’n **non-parametric, instance-based** metode wat voorspellings maak gebaseer op die ooreenkoms met voorbeelde in die training set. Die idee vir klassifikasie is: om ’n nuwe datapunt te klassifiseer, vind die **k** naaste punte in die training data (sy "nearest neighbors"), en ken die meerderheidsklas onder daardie bure toe. "Nabyheid" word deur ’n afstandsmetriek gedefinieer, gewoonlik Euklidiese afstand vir numeriese data (ander afstande kan vir verskillende tipes features of probleme gebruik word).<sup>[[10]](#references)</sup>

K-NN vereis *geen eksplisiete training* nie -- die "training"-fase bestaan bloot uit die stoor van die dataset. Al die werk gebeur tydens die query (voorspelling): die algoritme moet afstande vanaf die query-punt na alle training-punte bereken om die naastes te vind. Dit maak voorspellingstyd **lineêr in die aantal training-samples**, wat duur kan wees vir groot datasets. Daarom is k-NN die beste geskik vir kleiner datasets of scenario’s waar jy geheue en spoed vir eenvoud kan verruil.

Ten spyte van sy eenvoud kan k-NN baie komplekse besluitnemingsgrense modelleer (aangesien die besluitnemingsgrens effektief enige vorm kan hê wat deur die verspreiding van voorbeelde bepaal word). Dit presteer geneig om goed te wees wanneer die besluitnemingsgrens baie onreëlmatig is en jy baie data het -- dit laat die data in wese "vir homself praat". In hoë dimensies kan afstandsmetrieke egter minder betekenisvol word (die curse of dimensionality), en die metode kan sukkel tensy jy ’n groot aantal samples het.

*Gebruikstoepassings in cybersecurity:* k-NN is op anomaly detection toegepas -- byvoorbeeld, ’n intrusion detection system kan ’n network event as kwaadwillig merk as die meeste van sy naaste bure (vorige events) kwaadwillig was. As normale verkeer clusters vorm en attacks uitskieters is, doen ’n K-NN-benadering (met k=1 of klein k) in wese **nearest-neighbor anomaly detection**. K-NN is ook gebruik om malware-families volgens binary feature vectors te klassifiseer: ’n nuwe lêer kan as ’n sekere malware-familie geklassifiseer word as dit baie naby (in feature space) aan bekende gevalle van daardie familie is. In die praktyk is k-NN nie so algemeen soos meer skaalbare algoritmes nie, maar dit is konseptueel eenvoudig en word soms as ’n baseline of vir kleinskaalse probleme gebruik.

#### **Sleutelkenmerke van k-NN:**

-   **Tipe probleem:** Klassifikasie (en regressie-variante bestaan). Dit is ’n *lazy learning*-metode -- geen eksplisiete model fitting nie.

-   **Interpreteerbaarheid:** Laag tot medium -- daar is geen globale model of bondige verduideliking nie, maar ’n mens kan resultate interpreteer deur na die naaste bure te kyk wat ’n besluit beïnvloed het (bv. "hierdie network flow is as kwaadwillig geklassifiseer omdat dit soortgelyk is aan hierdie 3 bekende kwaadwillige flows"). Verduidelikings kan dus voorbeeldgebaseerd wees.

-   **Voordele:** Baie eenvoudig om te implementeer en te verstaan. Maak geen aannames oor die dataverspreiding nie (non-parametric). Kan natuurlik multi-class-probleme hanteer. Dit is **aanpasbaar** in die sin dat besluitnemingsgrense baie kompleks kan wees en deur die dataverspreiding gevorm word.

-   **Beperkings:** Voorspelling kan stadig wees vir groot datasets (baie afstande moet bereken word). Dit is geheue-intensief -- dit stoor al die training data. Werkverrigting verswak in hoë-dimensionele feature spaces omdat alle punte geneig is om byna ewe ver van mekaar te wees (wat die konsep van "naaste" minder betekenisvol maak). Jy moet *k* (die aantal bure) toepaslik kies -- ’n te klein k kan raserig wees, terwyl ’n te groot k irrelevante punte van ander klasse kan insluit. Features moet ook toepaslik geskaal word omdat afstandsberekeninge sensitief is vir skaal.

<details>
<summary>Voorbeeld -- k-NN vir Phishing Detection:</summary>

Ons sal weer NSL-KDD gebruik (binary classification). Omdat k-NN berekeningsintensief is, sal ons ’n subset van die training data gebruik om dit in hierdie demonstrasie hanteerbaar te hou. Ons sal byvoorbeeld 20 000 training-samples uit die volledige 125k kies en k=5-bure gebruik. Ná training (wat eintlik net die stoor van die data is), sal ons op die test set evalueer. Ons sal ook features skaal vir die afstandsberekening om te verseker dat geen enkele feature as gevolg van skaal oorheers nie.
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
Die k-NN-model sal 'n verbinding klassifiseer deur na die 5 naaste verbindings in die subset van die training set te kyk. As 4 van daardie bure byvoorbeeld attacks (anomalies) is en 1 normaal is, sal die nuwe verbinding as 'n attack geklassifiseer word. Die werkverrigting kan redelik wees, hoewel dit dikwels nie so hoog is soos dié van 'n goed ingestelde Random Forest of SVM op dieselfde data nie. k-NN kan egter soms uitblink wanneer die klasverspreidings baie onreëlmatig en kompleks is -- dit gebruik effektief 'n memory-based lookup. In cybersecurity kan k-NN (met k=1 of klein k) gebruik word vir die opsporing van bekende attack-patrone volgens voorbeeld, of as 'n komponent in meer komplekse stelsels (bv. vir clustering en daarna klassifikasie gebaseer op cluster-lidmaatskap).
</details>

### Gradient Boosting Machines (bv. XGBoost)

Gradient Boosting Machines is van die kragtigste algorithms vir gestruktureerde data. **Gradient boosting** verwys na die tegniek om 'n ensemble van swak learners (dikwels decision trees) opeenvolgend te bou, waar elke nuwe model die foute van die vorige ensemble regstel. Anders as bagging (Random Forests), wat trees parallel bou en die resultate gemiddeld, bou boosting trees *een vir een*, waar elkeen meer fokus op die gevalle wat vorige trees verkeerd voorspel het.<sup>[[11]](#references)</sup>

Die gewildste implementerings in onlangse jare is **XGBoost**, **LightGBM** en **CatBoost**, wat almal gradient boosting decision tree (GBDT)-libraries is. Hulle was uiters suksesvol in machine learning-kompetisies en -toepassings, en **behaal dikwels state-of-the-art-prestasie op tabulêre datasets**. In cybersecurity het navorsers en praktisyns gradient boosted trees gebruik vir take soos **malware detection** (met features wat uit lêers of runtime-gedrag onttrek is) en **network intrusion detection**. Byvoorbeeld, 'n gradient boosting-model kan baie swak reëls (trees) soos "if many SYN packets and unusual port -> likely scan" kombineer tot 'n sterk saamgestelde detector wat baie subtiele patrone in ag neem.

Waarom is boosted trees so effektief? Elke tree in die reeks word opgelei op die *residual errors* (gradients) van die huidige ensemble se predictions. Op hierdie manier **"boost"** die model geleidelik die areas waarin dit swak is. Die gebruik van decision trees as base learners beteken dat die finale model komplekse interactions en non-linear relations kan vaslê. Boonop het boosting inherent 'n vorm van ingeboude regularization: deur baie klein trees by te voeg (en 'n learning rate te gebruik om hul bydraes te skaleer), veralgemeen dit dikwels goed sonder ernstige overfitting, mits die korrekte parameters gekies word.

#### **Sleutelkenmerke van Gradient Boosting:**

-   **Tipe probleem:** Hoofsaaklik classification en regression. In security gewoonlik classification (bv. om 'n verbinding of lêer binêr te klassifiseer). Dit hanteer binary, multi-class (met toepaslike loss) en selfs ranking-probleme.

-   **Interpreteerbaarheid:** Laag tot medium. Hoewel 'n enkele boosted tree klein is, kan 'n volledige model honderde trees bevat, wat as geheel nie deur mense geïnterpreteer kan word nie. Soos Random Forest kan dit egter feature importance-s tellings verskaf, en tools soos SHAP (SHapley Additive exPlanations) kan gebruik word om individuele predictions tot 'n mate te interpreteer.

-   **Voordele:** Dikwels die **algoritme met die beste werkverrigting** vir gestruktureerde/tabulêre data. Dit kan komplekse patrone en interactions opspoor. Dit het baie tuning-knobs (aantal trees, diepte van trees, learning rate, regularization-terme) om modelkompleksiteit aan te pas en overfitting te voorkom. Moderne implementerings is vir spoed geoptimaliseer (XGBoost gebruik byvoorbeeld second-order gradient-info en doeltreffende datastrukture). Dit is geneig om imbalanced data beter te hanteer wanneer dit met toepaslike loss functions gekombineer word of deur sample weights aan te pas.

-   **Beperkings:** Dit is moeiliker om te tune as eenvoudiger models; training kan stadig wees as trees diep is of as die aantal trees groot is (hoewel dit steeds gewoonlik vinniger is as om 'n vergelykbare deep neural network op dieselfde data te train). Die model kan overfit as dit nie getune word nie (bv. te veel diep trees met onvoldoende regularization). Omdat daar baie hyperparameters is, kan effektiewe gebruik van gradient boosting meer kundigheid of eksperimentering vereis. Soos tree-based methods hanteer dit ook nie inherent baie sparse hoë-dimensionele data so doeltreffend soos linear models of Naive Bayes nie (hoewel dit steeds toegepas kan word, bv. in text classification, maar dit is moontlik nie die eerste keuse sonder feature engineering nie).

> [!TIP]
> *Gebruiksgevalle in cybersecurity:* Byna enige plek waar 'n decision tree of random forest gebruik kan word, kan 'n gradient boosting-model beter akkuraatheid behaal. **Microsoft se malware detection**-kompetisies het byvoorbeeld uitgebreide gebruik van XGBoost op engineered features uit binary files gesien. Navorsing oor **network intrusion detection** rapporteer dikwels topresultate met GBDTs (bv. XGBoost op CIC-IDS2017- of UNSW-NB15-datasets). Hierdie models kan 'n wye reeks features (protocol types, die frekwensie van sekere events, statistical features van traffic, ens.) neem en dit kombineer om threats op te spoor. In phishing detection kan gradient boosting lexical features van URLs, domain reputation-features en page content-features kombineer om baie hoë akkuraatheid te behaal. Die ensemble-benadering help om baie corner cases en subtiele aspekte in die data te dek.

<details>
<summary>Voorbeeld -- XGBoost vir Phishing Detection:</summary>
Ons sal 'n gradient boosting-classifier op die phishing-dataset gebruik. Om dinge eenvoudig en self-contained te hou, sal ons `sklearn.ensemble.GradientBoostingClassifier` gebruik (wat 'n stadiger maar eenvoudige implementering is). Gewoonlik sou 'n mens `xgboost`- of `lightgbm`-libraries gebruik vir beter werkverrigting en bykomende features. Ons sal die model train en dit soortgelyk aan vroeër evalueer.
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
Die gradient boosting-model sal waarskynlik baie hoë akkuraatheid en AUC op hierdie phishing-datastel behaal (dikwels kan hierdie modelle met behoorlike tuning meer as 95% akkuraatheid op sulke data behaal, soos in die literatuur gesien word. Dit demonstreer waarom GBDTs as *"die modernste model vir tabeldatastelle"* beskou word -- hulle vaar dikwels beter as eenvoudiger algoritmes deur komplekse patrone vas te lê.<sup>[[11]](#references)</sup> In 'n kuberveiligheidskonteks kan dit beteken dat meer phishing-webwerwe of aanvalle opgespoor word, met minder gevalle wat gemis word. Natuurlik moet 'n mens versigtig wees vir overfitting -- ons sal gewoonlik tegnieke soos kruisvalidasie gebruik en prestasie op 'n validasiestel monitor wanneer ons so 'n model vir ontplooiing ontwikkel.

</details>

### Kombinering van modelle: Ensemble Learning en Stacking

Ensemble learning is 'n strategie om **veelvuldige modelle te kombineer** om algehele prestasie te verbeter. Ons het reeds spesifieke ensemble-metodes gesien: Random Forest (’n ensemble van bome deur middel van bagging) en Gradient Boosting (’n ensemble van bome deur opeenvolgende boosting). Maar ensembles kan ook op ander maniere geskep word, soos **voting ensembles** of **stacked generalization (stacking)**. Die hoofgedagte is dat verskillende modelle verskillende patrone kan vaslê of verskillende swakhede kan hê; deur hulle te kombineer, kan ons **elke model se foute met 'n ander model se sterk punte vergoed**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** In 'n eenvoudige voting classifier lei ons veelvuldige diverse modelle op (sê nou 'n logistiese regressie, 'n besluitnemingsboom en 'n SVM) en laat ons hulle oor die finale voorspelling stem (meerderheidsstem vir klassifikasie). As ons die stemme weeg (byvoorbeeld 'n hoër gewig aan meer akkurate modelle gee), is dit 'n weighted voting-skema. Dit verbeter gewoonlik prestasie wanneer die individuele modelle redelik goed en onafhanklik is -- die ensemble verminder die risiko van 'n individuele model se fout, aangesien die ander dit moontlik kan regstel. Dit is soos om 'n paneel kundiges eerder as 'n enkele mening te hê.

-   **Stacking (Stacked Ensemble):** Stacking gaan 'n stap verder. In plaas van 'n eenvoudige stemming, lei dit 'n **meta-model** op om te **leer hoe om die basis-modelle se voorspellings die beste te kombineer**. Byvoorbeeld, jy lei 3 verskillende klassifiseerders (basisleerders) op en voer dan hulle uitsette (of waarskynlikhede) as kenmerke in 'n meta-classifier (dikwels 'n eenvoudige model soos logistiese regressie) wat die optimale manier leer om hulle te kombineer. Die meta-model word op 'n validasiestel of deur middel van kruisvalidasie opgelei om overfitting te voorkom. Stacking kan dikwels beter as eenvoudige voting vaar deur te leer *watter modelle in watter omstandighede meer vertrou moet word*. In kuberveiligheid kan een model beter wees om netwerkskanderings op te spoor, terwyl 'n ander beter is om malware beaconing op te spoor; 'n stacking-model kan leer om toepaslik op elkeen staat te maak.

Ensembles, hetsy deur voting of stacking, is geneig om **akkuraatheid** en robuustheid te verbeter. Die nadeel is groter kompleksiteit en soms verminderde interpreteerbaarheid (hoewel sommige ensemble-benaderings, soos 'n gemiddelde van besluitnemingsbome, steeds insig kan verskaf, byvoorbeeld kenmerkbelangrikheid). In die praktyk kan die gebruik van 'n ensemble, indien operasionele beperkings dit toelaat, tot hoër opsporingsyfers lei. Baie wenoplossings in kuberveiligheidsuitdagings (en Kaggle-kompetisies in die algemeen) gebruik ensemble-tegnieke om die laaste bietjie prestasie uit te pers.

<details>
<summary>Voorbeeld -- Voting Ensemble vir Phishing Detection:</summary>
Om model stacking te illustreer, kombineer ons 'n paar van die modelle wat ons op die phishing-datastel bespreek het. Ons sal 'n logistiese regressie, 'n besluitnemingsboom en 'n k-NN as basisleerders gebruik, en 'n Random Forest as 'n meta-leerder gebruik om hulle voorspellings te versamel. Die meta-leerder sal op die uitsette van die basisleerders opgelei word (deur kruisvalidasie op die training set te gebruik). Ons verwag dat die stacked-model net so goed soos, of effens beter as, die individuele modelle sal vaar.
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
Die stacked ensemble benut die komplementêre sterkpunte van die basismodelle. Logistic regression kan byvoorbeeld die lineêre aspekte van die data hanteer, die decision tree kan spesifieke reëlagtige interaksies vasvang, en k-NN kan in plaaslike gebiede van die feature space uitblink. Die meta-model (hier ’n random forest) kan leer hoe om hierdie insette te weeg. Die resulterende metrics toon dikwels ’n verbetering (selfs al is dit gering) teenoor die metrics van enige enkele model. In ons phishing-voorbeeld, as logistic alleen ’n F1 van byvoorbeeld 0.95 en die tree 0.94 gehad het, kon die stack 0.96 behaal deur voordeel te trek uit waar elke model fouteer.

Ensemble methods soos hierdie demonstreer die beginsel dat *"die kombinasie van veelvuldige modelle tipies tot beter generalisering lei"*.<sup>[[12]](#references)</sup> In cybersecurity kan dit geïmplementeer word deur veelvuldige detection engines te gebruik (een kan rule-based wees, een machine learning-gebaseerd en een anomaly-based) en dan ’n laag te hê wat hul alerts saamvoeg -- effektief ’n vorm van ensemble -- om ’n finale besluit met groter vertroue te neem. Wanneer sulke stelsels ontplooi word, moet ’n mens die bykomende kompleksiteit in ag neem en verseker dat die ensemble nie te moeilik word om te bestuur of te verduidelik nie. Vanuit ’n akkuraatheidsoogpunt is ensembles en stacking egter kragtige hulpmiddels om modelwerkverrigting te verbeter.

</details>

Die neural-network-benaderings wat op die [deep-learning-bladsy](AI-Deep-Learning.md) beskryf word, kan hierdie klassieke modelle vir intrusion detection aanvul wanneer die dataset en compute budget die bykomende kompleksiteit regverdig.<sup>[[13]](#references)</sup>

## References

- [1] [AI en Machine Learning in Cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression, verduidelik - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Phishing Attacks en Websites Classification Using Machine Learning en Multiple Datasets (A Comparative Analysis)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Denial of Services Attack Detection using Random Forest Classifier with Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Performance analysis of machine learning models for intrusion detection system using Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [What is a Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [What is k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT Demystified: How LightGBM, XGBoost en CatBoost Work - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Verbetering van modelwerkverrigting deur sterkpunte te kombineer - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [How Deep Learning Enhances Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
