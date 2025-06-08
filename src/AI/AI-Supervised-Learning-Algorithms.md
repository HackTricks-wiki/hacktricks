# Geleide Leer Algoritmes

{{#include ../banners/hacktricks-training.md}}

## Basiese Inligting

Geleide leer gebruik gelabelde data om modelle op te lei wat voorspellings kan maak oor nuwe, ongesiene insette. In kuberveiligheid word geleide masjienleer wyd toegepas op take soos indringingdetectie (klassifisering van netwerkverkeer as *normaal* of *aanval*), malware-detectie (onderskeiding van kwaadwillige sagteware van goedaardige), phishing-detectie (identifisering van bedrieglike webwerwe of e-posse), en spamfiltering, onder andere. Elke algoritme het sy sterkpunte en is geskik vir verskillende tipes probleme (klassifikasie of regressie). Hieronder hersien ons sleutel geleide leer algoritmes, verduidelik hoe hulle werk, en demonstreer hul gebruik op werklike kuberveiligheidsdatastelle. Ons bespreek ook hoe die kombinasie van modelle (ensemble leer) dikwels voorspellende prestasie kan verbeter.

## Algoritmes

-   **Lineêre Regressie:** 'n Fundamentele regressie-algoritme om numeriese uitkomste te voorspel deur 'n lineêre vergelyking aan data te pas.

-   **Logistieke Regressie:** 'n Klassifikasie-algoritme (ten spyte van sy naam) wat 'n logistieke funksie gebruik om die waarskynlikheid van 'n binêre uitkoms te modelleer.

-   **Besluitbome:** Bome-gestruktureerde modelle wat data volgens kenmerke verdeel om voorspellings te maak; dikwels gebruik vir hul interpreteerbaarheid.

-   **Random Forests:** 'n Ensemble van besluitbome (deur bagging) wat akkuraatheid verbeter en oorpassing verminder.

-   **Support Vector Machines (SVM):** Max-margin klassifiseerders wat die optimale skeidingshipervlak vind; kan kerne gebruik vir nie-lineêre data.

-   **Naive Bayes:** 'n Probabilistiese klassifiseerder gebaseer op Bayes se stelling met 'n aanname van kenmerk onafhanklikheid, bekend gebruik in spamfiltering.

-   **k-Naaste Bure (k-NN):** 'n Eenvoudige "instansie-gebaseerde" klassifiseerder wat 'n monster etiket op grond van die meerderheid klas van sy naaste bure.

-   **Gradient Boosting Machines:** Ensemble modelle (bv. XGBoost, LightGBM) wat 'n sterk voorspeller bou deur swak leerders (tipies besluitbome) geleidelik by te voeg.

Elke afdeling hieronder bied 'n verbeterde beskrywing van die algoritme en 'n **Python kode voorbeeld** wat biblioteke soos `pandas` en `scikit-learn` (en `PyTorch` vir die neurale netwerk voorbeeld) gebruik. Die voorbeelde gebruik publiek beskikbare kuberveiligheidsdatastelle (soos NSL-KDD vir indringingdetectie en 'n Phishing Webwerwe datastel) en volg 'n konsekwente struktuur:

1.  **Laai die datastel** (aflaai via URL indien beskikbaar).

2.  **Voorverwerk die data** (bv. kodeer kategorieë, skaal waardes, verdeel in opleidings/ toetsstelle).

3.  **Oplei die model** op die opleidingsdata.

4.  **Evalueer** op 'n toetsstel met behulp van metrieke: akkuraatheid, presisie, terugroep, F1-telling, en ROC AUC vir klassifikasie (en gemiddelde kwadraatfout vir regressie).

Kom ons duik in elke algoritme:

### Lineêre Regressie

Lineêre regressie is 'n **regressie** algoritme wat gebruik word om deurlopende numeriese waardes te voorspel. Dit neem 'n lineêre verhouding aan tussen die insetkenmerke (onafhanklike veranderlikes) en die uitset (afhanklike veranderlike). Die model probeer om 'n reglyn (of hipervlak in hoër dimensies) te pas wat die verhouding tussen kenmerke en die teiken die beste beskryf. Dit word tipies gedoen deur die som van die kwadrate van die foute tussen voorspelde en werklike waardes te minimaliseer (Ordinary Least Squares metode).

Die eenvoudigste manier om lineêre regressie voor te stel, is met 'n lyn:
```plaintext
y = mx + b
```
Waar:

- `y` is die voorspelde waarde (uitset)
- `m` is die helling van die lyn (koëffisiënt)
- `x` is die invoerkenmerk
- `b` is die y-snitpunt

Die doel van lineêre regressie is om die beste paslyn te vind wat die verskil tussen die voorspelde waardes en die werklike waardes in die datastel minimaliseer. Natuurlik is dit baie eenvoudig, dit sou 'n reglyn wees wat 2 kategorieë skei, maar as meer dimensies bygevoeg word, word die lyn meer kompleks:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* Lineêre regressie self is minder algemeen vir kernveiligheidstake (wat dikwels klassifikasie is), maar dit kan toegepas word om numeriese uitkomste te voorspel. Byvoorbeeld, 'n Mens kan lineêre regressie gebruik om **die volume van netwerkverkeer te voorspel** of **die aantal aanvalle in 'n tydperk te skat** gebaseer op historiese data. Dit kan ook 'n risiko telling voorspel of die verwagte tyd tot opsporing van 'n aanval, gegewe sekere stelselmeter. In praktyk word klassifikasie-algoritmes (soos logistieke regressie of bome) meer gereeld gebruik om indringings of malware op te spoor, maar lineêre regressie dien as 'n grondslag en is nuttig vir regressie-georiënteerde analises.

#### **Belangrike kenmerke van Lineêre Regressie:**

-   **Tipe Probleem:** Regressie (voorspel van deurlopende waardes). Nie geskik vir direkte klassifikasie tensy 'n drempel op die uitset toegepas word nie.

-   **Interpretasie:** Hoog -- koëffisiënte is eenvoudig om te interpreteer, wat die lineêre effek van elke kenmerk toon.

-   **Voordele:** Eenvoudig en vinnig; 'n goeie basislyn vir regressietake; werk goed wanneer die werklike verhouding ongeveer lineêr is.

-   **Beperkings:** Kan nie komplekse of nie-lineêre verhoudings vasvang nie (sonder handmatige kenmerkingenieurswese); geneig tot onderpassing as verhoudings nie-lineêr is; sensitief vir uitskieters wat die resultate kan skeefdruk.

-   **Vind die Beste Pas:** Om die beste paslyn te vind wat die moontlike kategorieë skei, gebruik ons 'n metode genaamd **Ordinary Least Squares (OLS)**. Hierdie metode minimaliseer die som van die gekwadrateerde verskille tussen die waargenome waardes en die waardes wat deur die lineêre model voorspel word.

<details>
<summary>Voorbeeld -- Voorspelling van Verbinding Duur (Regressie) in 'n Indringingsdataset
</summary>
Hieronder demonstreer ons lineêre regressie met behulp van die NSL-KDD kuberveiligheidsdataset. Ons sal dit as 'n regressieprobleem behandel deur die `duur` van netwerkverbindinge te voorspel gebaseer op ander kenmerke. (In werklikheid is `duur` een kenmerk van NSL-KDD; ons gebruik dit hier net om regressie te illustreer.) Ons laai die dataset, verwerk dit (kodeer kategoriese kenmerke), oplei 'n lineêre regressiemodel, en evalueer die Gemiddelde Gekwadrateerde Fout (MSE) en R² telling op 'n toetsstel.
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
In hierdie voorbeeld probeer die lineêre regressiemodel om verbinding `duur` te voorspel uit ander netwerkkenmerke. Ons meet prestasie met Gemiddelde Kwadratiese Fout (MSE) en R². 'n R² naby 1.0 sou aandui dat die model die meeste variasie in `duur` verduidelik, terwyl 'n lae of negatiewe R² 'n swak pas aandui. (Moet nie verbaas wees as die R² hier laag is nie -- om `duur` te voorspel mag moeilik wees uit die gegewe kenmerke, en lineêre regressie mag nie die patrone vasvang as hulle kompleks is nie.)
</details>

### Logistieke Regressie

Logistieke regressie is 'n **klassifikasie** algoritme wat die waarskynlikheid modelleer dat 'n voorbeeld tot 'n spesifieke klas behoort (tipies die "positiewe" klas). Ten spyte van sy naam, word *logistieke* regressie gebruik vir diskrete uitkomste (in teenstelling met lineêre regressie wat vir deurlopende uitkomste is). Dit word veral gebruik vir **binariese klassifikasie** (twee klasse, bv. kwaadwillig vs. goedaardig), maar dit kan uitgebrei word na multi-klas probleme (met behulp van softmax of een-vs-res approaches).

Die logistieke regressie gebruik die logistieke funksie (ook bekend as die sigmoid funksie) om voorspelde waardes na waarskynlikhede te kaart. Let daarop dat die sigmoid funksie 'n funksie is met waardes tussen 0 en 1 wat in 'n S-vormige kurwe groei volgens die behoeftes van die klassifikasie, wat nuttig is vir binariese klassifikasie take. Daarom word elke kenmerk van elke invoer met sy toegewyde gewig vermenigvuldig, en die resultaat word deur die sigmoid funksie gestuur om 'n waarskynlikheid te produseer:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Waar:

- `p(y=1|x)` is die waarskynlikheid dat die uitset `y` 1 is gegewe die inset `x`
- `e` is die basis van die natuurlike logaritme
- `z` is 'n lineêre kombinasie van die insetkenmerke, tipies voorgestel as `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Let op hoe dit weer in sy eenvoudigste vorm 'n reglyn is, maar in meer komplekse gevalle word dit 'n hipervlak met verskeie dimensies (een per kenmerk).

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* Omdat baie sekuriteitsprobleme essensieel ja/nee besluite is, word logistieke regressie wyd gebruik. Byvoorbeeld, 'n indringingdetectiestelsel kan logistieke regressie gebruik om te besluit of 'n netwerkverbinding 'n aanval is gebaseer op kenmerke van daardie verbinding. In phishing-detectie kan logistieke regressie kenmerke van 'n webwerf (URL-lengte, teenwoordigheid van "@" simbool, ens.) kombineer in 'n waarskynlikheid om phishing te wees. Dit is in vroeë generasie spamfilters gebruik en bly 'n sterk basislyn vir baie klassifikasietake.

#### Logistieke Regressie vir nie-binaire klassifikasie

Logistieke regressie is ontwerp vir binaire klassifikasie, maar dit kan uitgebrei word om multi-klas probleme te hanteer met tegnieke soos **een-teenoorgestelde** (OvR) of **softmax regressie**. In OvR word 'n aparte logistieke regressiemodel vir elke klas opgelei, wat dit as die positiewe klas teenoor al die ander behandel. Die klas met die hoogste voorspelde waarskynlikheid word gekies as die finale voorspelling. Softmax regressie veralgemeen logistieke regressie na meerdere klasse deur die softmax-funksie op die uitsetlaag toe te pas, wat 'n waarskynlikheidsverdeling oor al die klasse produseer.

#### **Belangrike eienskappe van Logistieke Regressie:**

-   **Tipe Probleem:** Klassifikasie (gewoonlik binêr). Dit voorspel die waarskynlikheid van die positiewe klas.

-   **Interpretasie:** Hoog -- soos lineêre regressie, kan die kenmerkkoëffisiënte aandui hoe elke kenmerk die log-odds van die uitkoms beïnvloed. Hierdie deursigtigheid word dikwels waardeer in sekuriteit om te verstaan watter faktore bydra tot 'n waarskuwing.

-   **Voordele:** Eenvoudig en vinnig om op te lei; werk goed wanneer die verhouding tussen kenmerke en log-odds van die uitkoms lineêr is. Dit lewer waarskynlikhede, wat risiko-bepaling moontlik maak. Met toepaslike regularisering veralgemeen dit goed en kan dit multikollinairiteit beter hanteer as gewone lineêre regressie.

-   **Beperkings:** Neem 'n lineêre besluitgrens in kenmerkruimte aan (faal as die werklike grens kompleks/nie-lineêr is). Dit mag onderpresteer op probleme waar interaksies of nie-lineêre effekte krities is, tensy jy handmatig polynomiale of interaksiekenmerke byvoeg. Ook, logistieke regressie is minder effektief as klasse nie maklik geskei kan word deur 'n lineêre kombinasie van kenmerke nie.

<details>
<summary>Voorbeeld -- Phishing-webwerf-detectie met Logistieke Regressie:</summary>

Ons gaan 'n **Phishing-webwerwe-dataset** (van die UCI-bewaarplek) gebruik wat onttrokken kenmerke van webwerwe bevat (soos of die URL 'n IP-adres het, die ouderdom van die domein, teenwoordigheid van verdagte elemente in HTML, ens.) en 'n etiket wat aandui of die webwerf phishing of wettig is. Ons lei 'n logistieke regressiemodel op om webwerwe te klassifiseer en evalueer dan sy akkuraatheid, presisie, terugroep, F1-telling, en ROC AUC op 'n toetsverdeling.
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
In hierdie phishing-detectie voorbeeld, produseer logistieke regressie 'n waarskynlikheid vir elke webwerf om phishing te wees. Deur akkuraatheid, presisie, terugroep en F1 te evalueer, kry ons 'n gevoel van die model se prestasie. Byvoorbeeld, 'n hoë terugroep beteken dit vang die meeste phishing-webwerwe (belangrik vir sekuriteit om gemiste aanvalle te minimaliseer), terwyl hoë presisie beteken dit het min vals alarms (belangrik om ontleders se moegheid te vermy). Die ROC AUC (Area Under the ROC Curve) bied 'n drempel-onafhanklike maatstaf van prestasie (1.0 is ideaal, 0.5 is nie beter as kans nie). Logistieke regressie presteer dikwels goed op sulke take, maar as die besluitgrens tussen phishing en wettige webwerwe kompleks is, mag meer kragtige nie-lineêre modelle benodig word.

</details>

### Besluitbome

'n Besluitboom is 'n veelsydige **supervised learning algorithm** wat gebruik kan word vir beide klassifikasie en regressie take. Dit leer 'n hiërargiese boomagtige model van besluite gebaseer op die kenmerke van die data. Elke interne knoop van die boom verteenwoordig 'n toets op 'n spesifieke kenmerk, elke tak verteenwoordig 'n uitkoms van daardie toets, en elke blaar knoop verteenwoordig 'n voorspelde klas (vir klassifikasie) of waarde (vir regressie).

Om 'n boom te bou, gebruik algoritmes soos CART (Classification and Regression Tree) maatstawwe soos **Gini impurity** of **information gain (entropy)** om die beste kenmerk en drempel te kies om die data by elke stap te verdeel. Die doel by elke splitsing is om die data te partitioneer om die homogeniteit van die teiken veranderlike in die resulterende substelle te verhoog (vir klassifikasie, mik elke knoop om so suiwer as moontlik te wees, wat hoofsaaklik 'n enkele klas bevat).

Besluitbome is **hooglik interpreteerbaar** -- 'n Mens kan die pad van wortel tot blaar volg om die logika agter 'n voorspelling te verstaan (bv. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Dit is waardevol in kuberveiligheid om te verduidelik waarom 'n sekere waarskuwing gegee is. Bome kan natuurlik beide numeriese en kategorie data hanteer en vereis min voorverwerking (bv. kenmerk skaal is nie nodig nie).

Echter, 'n enkele besluitboom kan maklik oorpas op die opleidingsdata, veral as dit diep gegroei word (baie splitsings). Tegnieke soos snoei (beperking van boomdiepte of vereis 'n minimum aantal monsters per blaar) word dikwels gebruik om oorpassing te voorkom.

Daar is 3 hoofkomponente van 'n besluitboom:
- **Wortel Knoop**: Die boonste knoop van die boom, wat die hele datastel verteenwoordig.
- **Interne Knoop**: Knoop wat kenmerke en besluite gebaseer op daardie kenmerke verteenwoordig.
- **Blaar Knoop**: Knoop wat die finale uitkoms of voorspelling verteenwoordig.

'n Boom mag uiteindelik soos volg lyk:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* Besluitbome is in indringingdetectiestelsels gebruik om **reëls** af te lei vir die identifisering van aanvalle. Byvoorbeeld, vroeë IDS soos ID3/C4.5-gebaseerde stelsels sou menslike leesbare reëls genereer om normale teenoor kwaadwillige verkeer te onderskei. Hulle word ook in malware-analise gebruik om te besluit of 'n lêer kwaadwillig is op grond van sy eienskappe (lêergrootte, afdeling entropie, API-oproepe, ens.). Die duidelikheid van besluitbome maak hulle nuttig wanneer deursigtigheid benodig word -- 'n ontleder kan die boom inspekteer om die deteksielogika te valideer.

#### **Belangrike kenmerke van Besluitbome:**

-   **Tipe Probleem:** Beide klassifikasie en regressie. Gewoonlik gebruik vir die klassifikasie van aanvalle teenoor normale verkeer, ens.

-   **Interpretasie:** Baie hoog -- die model se besluite kan visualiseer en verstaan word as 'n stel indien-dan reëls. Dit is 'n groot voordeel in sekuriteit vir vertroue en verifikasie van modelgedrag.

-   **Voordele:** Kan nie-lineêre verhoudings en interaksies tussen eienskappe vasvang (elke splitsing kan as 'n interaksie gesien word). Geen behoefte om eienskappe te skaal of een-hot te kodeer kategoriese veranderlikes nie -- bome hanteer dit van nature. Vinige afleiding (voorspelling is net om 'n pad in die boom te volg).

-   **Beperkings:** Geneig tot oorpassing as dit nie beheer word nie (n diep boom kan die opleidingsstel memoriseer). Hulle kan onstabiel wees -- klein veranderinge in data kan lei tot 'n ander boomstruktuur. As enkelmodelle mag hulle akkuraatheid nie ooreenstem met meer gevorderde metodes nie (ensembles soos Random Forests presteer gewoonlik beter deur variasie te verminder).

-   **Die Beste Splitsing Vind:**
- **Gini Onreinheid**: Meet die onreinheid van 'n knoop. 'n Laer Gini onreinheid dui op 'n beter splitsing aan. Die formule is:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Waar `p_i` die proporsie van instansies in klas `i` is.

- **Entropie**: Meet die onsekerheid in die datastel. 'n Laer entropie dui op 'n beter splitsing aan. Die formule is:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Waar `p_i` die proporsie van instansies in klas `i` is.

- **Inligtingswins**: Die vermindering in entropie of Gini onreinheid na 'n splitsing. Hoe hoër die inligtingswins, hoe beter die splitsing. Dit word bereken as:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Boonop eindig 'n boom wanneer:
- Alle instansies in 'n knoop aan dieselfde klas behoort. Dit kan lei tot oorpassing.
- Die maksimum diepte (hardgecodeer) van die boom bereik is. Dit is 'n manier om oorpassing te voorkom.
- Die aantal instansies in 'n knoop onder 'n sekere drempel is. Dit is ook 'n manier om oorpassing te voorkom.
- Die inligtingswins van verdere splitsings onder 'n sekere drempel is. Dit is ook 'n manier om oorpassing te voorkom.

<details>
<summary>Voorbeeld -- Besluitboom vir Indringingdetectie:</summary>
Ons sal 'n besluitboom op die NSL-KDD-datastel oplei om netwerkverbindinge as *normaal* of *aanval* te klassifiseer. NSL-KDD is 'n verbeterde weergawe van die klassieke KDD Cup 1999-datastel, met eienskappe soos protokol tipe, diens, duur, aantal mislukte aanmeldings, ens., en 'n etiket wat die aanval tipe of "normaal" aandui. Ons sal alle aanval tipe na 'n "anomalië" klas kaart (binêre klassifikasie: normaal teenoor anomalië). Na die opleiding sal ons die boom se prestasie op die toetsstel evalueer.
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
In hierdie besluitboomvoorbeeld het ons die diepte van die boom tot 10 beperk om uiterste oorpassing te vermy (die `max_depth=10` parameter). Die metings toon hoe goed die boom normale teenoor aanvalverkeer onderskei. 'n Hoë terugroep sou beteken dat dit die meeste aanvalle vang (belangrik vir 'n IDS), terwyl hoë presisie beteken dat daar min vals alarms is. Besluitbome bereik dikwels redelike akkuraatheid op gestruktureerde data, maar 'n enkele boom mag nie die beste moontlike prestasie bereik nie. Nietemin is die *interpreteerbaarheid* van die model 'n groot voordeel -- ons kon die boom se splitsings ondersoek om te sien, byvoorbeeld, watter kenmerke (bv. `service`, `src_bytes`, ens.) die mees invloedryk is in die merk van 'n verbinding as kwaadwillig.

</details>

### Random Woude

Random Forest is 'n **ensemble leer** metode wat op besluitbome bou om prestasie te verbeter. 'n Random forest oplei verskeie besluitbome (daarom "woud") en kombineer hul uitsette om 'n finale voorspelling te maak (vir klassifikasie, tipies deur meerderheidstem). Die twee hoofidees in 'n random forest is **bagging** (bootstrap aggregating) en **kenmerk randomheid**:

-   **Bagging:** Elke boom word op 'n ewekansige bootstrap monster van die opleidingsdata opgelei (gemonster met vervanging). Dit bring diversiteit tussen die bome in.

-   **Kenmerk Randomheid:** By elke splitsing in 'n boom, word 'n ewekansige subset van kenmerke oorweeg vir splitsing (in plaas van alle kenmerke). Dit dekorelleer die bome verder.

Deur die resultate van baie bome te gemiddeld, verminder die random forest die variasie wat 'n enkele besluitboom mag hê. In eenvoudige terme, individuele bome mag oorpas of raserig wees, maar 'n groot aantal diverse bome wat saamstem, glad die foute uit. Die resultaat is dikwels 'n model met **hoër akkuraatheid** en beter generalisering as 'n enkele besluitboom. Daarbenewens kan random woude 'n skatting van kenmerkbelangrikheid bied (deur te kyk na hoeveel elke kenmerk se splitsing gemiddeld onreinheid verminder).

Random woude het 'n **werkperd in kuberveiligheid** geword vir take soos indringingdetectie, malware klassifikasie, en spamdetectie. Hulle presteer dikwels goed uit die boks met minimale afstemming en kan groot kenmerkstelle hanteer. Byvoorbeeld, in indringingdetectie mag 'n random forest 'n individuele besluitboom oortref deur meer subtiele patrone van aanvalle met minder vals positiewe te vang. Navorsing het getoon dat random woude gunstig presteer in vergelyking met ander algoritmes in die klassifikasie van aanvalle in datastelle soos NSL-KDD en UNSW-NB15.

#### **Belangrike eienskappe van Random Woude:**

-   **Tipe Probleem:** Primêr klassifikasie (ook gebruik vir regressie). Baie goed geskik vir hoë-dimensionele gestruktureerde data wat algemeen in sekuriteitslogs voorkom.

-   **Interpreteerbaarheid:** Laer as 'n enkele besluitboom -- jy kan nie maklik honderde bome gelyktydig visualiseer of verduidelik nie. Tog bied kenmerkbelangrikheid tellings 'n bietjie insig in watter eienskappe die mees invloedryk is.

-   **Voordele:** Oor die algemeen hoër akkuraatheid as enkelboommodelle weens die ensemble-effek. Robuust teen oorpassing -- selfs al oorpas individuele bome, generaliseer die ensemble beter. Hanteer beide numeriese en kategorieë kenmerke en kan ontbrekende data tot 'n mate bestuur. Dit is ook relatief robuust teen uitliers.

-   **Beperkings:** Modelgrootte kan groot wees (baie bome, elkeen potensieel diep). Voorspellings is stadiger as 'n enkele boom (aangesien jy oor baie bome moet aggregeer). Minder interpreteerbaar -- terwyl jy belangrike kenmerke weet, is die presiese logika nie maklik opspoorbaar as 'n eenvoudige reël nie. As die datastel uiters hoë-dimensioneel en spaar is, kan dit om 'n baie groot woud op te lei rekenaarintensief wees.

-   **Opleidingsproses:**
1. **Bootstrap Monsters:** Ewekansig monster die opleidingsdata met vervanging om verskeie subsets (bootstrap monsters) te skep.
2. **Boomkonstruksie:** Vir elke bootstrap monster, bou 'n besluitboom met 'n ewekansige subset van kenmerke by elke splitsing. Dit bring diversiteit tussen die bome in.
3. **Aggregasie:** Vir klassifikasietake, word die finale voorspelling gemaak deur 'n meerderheidstem onder die voorspellings van al die bome te neem. Vir regressietake is die finale voorspelling die gemiddelde van die voorspellings van al die bome.

<details>
<summary>Voorbeeld -- Random Forest vir Indringingdetectie (NSL-KDD):</summary>
Ons sal dieselfde NSL-KDD datastel (binarie geëtiketteer as normaal teenoor anomalie) gebruik en 'n Random Forest klassifiseerder oplei. Ons verwag dat die random forest so goed of beter sal presteer as die enkele besluitboom, danksy die ensemble gemiddelde wat variasie verminder. Ons sal dit met dieselfde metings evalueer.
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
Die random forest bereik tipies sterk resultate op hierdie indringingdetectietaak. Ons mag 'n verbetering in metrieke soos F1 of AUC waarneem in vergelyking met die enkele besluitboom, veral in terugroep of presisie, afhangende van die data. Dit stem ooreen met die begrip dat *"Random Forest (RF) is 'n ensemble klassifiseerder en presteer goed in vergelyking met ander tradisionele klassifiseerders vir effektiewe klassifikasie van aanvalle."*. In 'n sekuriteitsoperasionele konteks mag 'n random forest-model meer betroubaar aanvalle merk terwyl dit vals alarm verminder, danksy die gemiddelde van baie besluitreëls. Kenmerkbelangrikheid uit die woud kan ons vertel watter netwerkkenmerke die mees aanduidende van aanvalle is (bv. sekere netwerkdienste of ongewone tellings van pakkette).

</details>

### Support Vector Machines (SVM)

Support Vector Machines is kragtige toesighoudende leermodelle wat hoofsaaklik vir klassifikasie (en ook regressie as SVR) gebruik word. 'n SVM probeer om die **optimale skeidingshipervlak** te vind wat die marge tussen twee klasse maksimeer. Slegs 'n substel van opleidingspunte (die "ondersteuningsvektore" wat die naaste aan die grens is) bepaal die posisie van hierdie hipervlak. Deur die marge (afstand tussen ondersteuningsvektore en die hipervlak) te maksimeer, bereik SVM's gewoonlik goeie generalisering.

Die sleutel tot SVM se krag is die vermoë om **kernfunksies** te gebruik om nie-lineêre verhoudings te hanteer. Die data kan implisiet in 'n hoër-dimensionele kenmerkruimte getransformeer word waar 'n lineêre skeiding bestaan. Gewone kerne sluit polinomiale, radiale basisfunksie (RBF), en sigmoid in. Byvoorbeeld, as netwerkverkeerklasse nie lineêr skeibaar is in die ruwe kenmerkruimte nie, kan 'n RBF-kern hulle in 'n hoër dimensie kaart waar die SVM 'n lineêre skeiding vind (wat ooreenstem met 'n nie-lineêre grens in die oorspronklike ruimte). Die buigsaamheid om kerne te kies, laat SVM's toe om 'n verskeidenheid probleme aan te pak.

SVM's is bekend daarvoor dat hulle goed presteer in situasies met hoë-dimensionele kenmerkruimtes (soos teksdata of malware opcode-sekwensies) en in gevalle waar die aantal kenmerke groot is in verhouding tot die aantal monsters. Hulle was gewild in baie vroeë kubersekuriteitstoepassings soos malwareklassifikasie en anomalie-gebaseerde indringingdetectie in die 2000's, en het dikwels hoë akkuraatheid getoon.

Egter, SVM's skaal nie maklik na baie groot datastelle nie (opleidingskompleksiteit is super-lineêr in die aantal monsters, en geheuegebruik kan hoog wees aangesien dit baie ondersteuningsvektore moet stoor). In praktyk, vir take soos netwerkindringingdetectie met miljoene rekords, mag SVM te stadig wees sonder sorgvuldige subsampling of die gebruik van benaderde metodes.

#### **Belangrike eienskappe van SVM:**

-   **Tipe Probleem:** Klassifikasie (binêre of veelvuldige klasse via een-tegen-een/een-tegen-res) en regressievariante. Gereeld gebruik in binêre klassifikasie met duidelike marge skeiding.

-   **Interpretasie:** Medium -- SVM's is nie so interpreteerbaar soos besluitbome of logistikeregressie nie. Terwyl jy kan identifiseer watter datapunte ondersteuningsvektore is en 'n idee kan kry van watter kenmerke invloedryk mag wees (deur die gewigte in die lineêre kern geval), word SVM's (veral met nie-lineêre kerne) in praktyk as swart-doos klassifiseerders behandel.

-   **Voordele:** Effektief in hoë-dimensionele ruimtes; kan komplekse besluitgrense modelleer met die kerntrik; robuust teen oorpassing as die marge maksimeer word (veral met 'n behoorlike regulariseringparameter C); werk goed selfs wanneer klasse nie deur 'n groot afstand geskei is nie (vind die beste kompromie-grens).

-   **Beperkings:** **Rekenaarintensief** vir groot datastelle (sowel opleiding as voorspelling skaal swak namate data groei). Vereis sorgvuldige afstemming van kern- en regulariseringparameters (C, kern tipe, gamma vir RBF, ens.). Lewer nie direk probabilistiese uitsette nie (alhoewel 'n mens Platt-skaal kan gebruik om waarskynlikhede te kry). Ook, SVM's kan sensitief wees vir die keuse van kernparameters --- 'n swak keuse kan lei tot onderpassing of oorpassing.

*Gebruik gevalle in kubersekuriteit:* SVM's is gebruik in **malware-detectie** (bv. klassifisering van lêers gebaseer op onttrokken kenmerke of opcode-sekwensies), **netwerk-anomaliedetectie** (klassifisering van verkeer as normaal teenoor kwaadwillig), en **phishing-detectie** (gebruik van kenmerke van URL's). Byvoorbeeld, 'n SVM kan kenmerke van 'n e-pos neem (tellings van sekere sleutelwoorde, sender reputasiescores, ens.) en dit klassifiseer as phishing of wettig. Hulle is ook toegepas op **indringingdetectie** op kenmerkstelle soos KDD, wat dikwels hoë akkuraatheid bereik teen die koste van berekening.

<details>
<summary>Voorbeeld -- SVM vir Malware Klassifikasie:</summary>
Ons sal weer die phishing-webwerf-dataset gebruik, hierdie keer met 'n SVM. Omdat SVM's stadig kan wees, sal ons 'n substel van die data vir opleiding gebruik indien nodig (die dataset is ongeveer 11k voorbeelde, wat SVM redelik kan hanteer). Ons sal 'n RBF-kern gebruik wat 'n algemene keuse is vir nie-lineêre data, en ons sal waarskynlikheidsberamings inskakel om ROC AUC te bereken.
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
Die SVM-model sal metrieke lewer wat ons kan vergelyk met logistieke regressie op dieselfde taak. Ons mag vind dat SVM 'n hoë akkuraatheid en AUC bereik as die data goed geskei is deur die kenmerke. Aan die ander kant, as die datastel baie geraas of oorvleuelende klasse gehad het, mag SVM nie beduidend beter presteer as logistieke regressie nie. In praktyk kan SVM's 'n hupstoot gee wanneer daar komplekse, nie-lineêre verhoudings tussen kenmerke en klas is -- die RBF-kern kan gebuigde besluitgrense vasvang wat logistieke regressie sou mis. Soos met alle modelle, is versigtige afstemming van die `C` (regulering) en kernparameters (soos `gamma` vir RBF) nodig om vooroordeel en variasie te balanseer.

</details>

#### Verskil tussen Logistieke Regressies & SVM

| Aspek | **Logistieke Regressie** | **Ondersteuningsvektor Masjiene** |
|---|---|---|
| **Doel funksie** | Minimaliseer **log‑verlies** (kruis-entropie). | Maksimaliseer die **marge** terwyl **hinge‑verlies** geminimaliseer word. |
| **Besluitgrens** | Vind die **beste‑pas hipervlak** wat _P(y\|x)_ modelleer. | Vind die **maksimum‑marge hipervlak** (grootste gaping na die naaste punte). |
| **Uitset** | **Probabilisties** – gee gekalibreerde klas waarskynlikhede via σ(w·x + b). | **Deterministies** – keer klas etikette terug; waarskynlikhede benodig ekstra werk (bv. Platt-skaal). |
| **Regulering** | L2 (standaard) of L1, balanseer direk onder/oor‑pas. | C parameter ruil marge breedte teenoor verkeerde klassifikasies; kernparameters voeg kompleksiteit by. |
| **Kerne / Nie‑lineêr** | Inheemse vorm is **lineêr**; nie-lineariteit word bygevoeg deur kenmerkingenieurskap. | Ingeboude **kern truuk** (RBF, poly, ens.) laat dit komplekse grense in hoë-dim. ruimte modelleer. |
| **Skaalbaarheid** | Los 'n konvex optimalisering op in **O(nd)**; hanteer baie groot n goed. | Opleiding kan **O(n²–n³)** geheue/tyd wees sonder gespesialiseerde oplosser; minder vriendelik vir enorme n. |
| **Interpretasiebaarheid** | **Hoog** – gewigte wys kenmerk invloed; kansverhouding intuïtief. | **Laag** vir nie-lineêre kerne; ondersteuningsvektore is spaarzaam maar nie maklik om te verduidelik nie. |
| **Sensitiwiteit vir uitskieters** | Gebruik gladde log‑verlies → minder sensitief. | Hinge‑verlies met harde marge kan **sensitief** wees; sagte marge (C) versag. |
| **Tipiese gebruiksgevalle** | Kredietgradering, mediese risiko, A/B toetsing – waar **waarskynlikhede & verduidelikbaarheid** belangrik is. | Beeld/teks klassifikasie, bio-informatika – waar **kompleks grense** en **hoë-dimensionele data** belangrik is. |

* **As jy gekalibreerde waarskynlikhede, interpretasiebaarheid benodig, of op enorme datastelle werk — kies Logistieke Regressie.**
* **As jy 'n buigsame model benodig wat nie-lineêre verhoudings kan vasvang sonder handmatige kenmerkingenieurskap — kies SVM (met kerne).**
* Beide optimaliseer konvex doelwitte, so **globale minima is gewaarborg**, maar SVM se kerne voeg hiperparameters en rekenaar koste by.

### Naiewe Bayes

Naiewe Bayes is 'n familie van **probabilistiese klassifiseerders** gebaseer op die toepassing van Bayes se Stelling met 'n sterk onafhanklikheid aannames tussen kenmerke. Ten spyte van hierdie "naiewe" aanname, werk Naiewe Bayes dikwels verrassend goed vir sekere toepassings, veral dié wat teks of kategorie data insluit, soos spamdeteksie.

#### Bayes se Stelling

Bayes se stelling is die grondslag van Naiewe Bayes klassifiseerders. Dit verwant die voorwaardelike en marginale waarskynlikhede van ewekansige gebeurtenisse. Die formule is:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Waar:
- `P(A|B)` is die posterior probability van klas `A` gegewe kenmerk `B`.
- `P(B|A)` is die waarskynlikheid van kenmerk `B` gegewe klas `A`.
- `P(A)` is die voorafgaande waarskynlikheid van klas `A`.
- `P(B)` is die voorafgaande waarskynlikheid van kenmerk `B`.

Byvoorbeeld, as ons wil klassifiseer of 'n teks deur 'n kind of 'n volwassene geskryf is, kan ons die woorde in die teks as kenmerke gebruik. Gebaseer op 'n paar aanvanklike data, sal die Naive Bayes klassifiseerder vooraf die waarskynlikhede van elke woord wat in elke potensiële klas (kind of volwassene) voorkom, bereken. Wanneer 'n nuwe teks gegee word, sal dit die waarskynlikheid van elke potensiële klas bereken gegewe die woorde in die teks en die klas met die hoogste waarskynlikheid kies.

Soos jy in hierdie voorbeeld kan sien, is die Naive Bayes klassifiseerder baie eenvoudig en vinnig, maar dit neem aan dat die kenmerke onafhanklik is, wat nie altyd die geval is in werklike data nie.

#### Tipes Naive Bayes Klassifiseerders

Daar is verskeie tipes Naive Bayes klassifiseerders, afhangende van die tipe data en die verspreiding van die kenmerke:
- **Gaussian Naive Bayes**: Neem aan dat die kenmerke 'n Gaussian (normale) verspreiding volg. Dit is geskik vir deurlopende data.
- **Multinomial Naive Bayes**: Neem aan dat die kenmerke 'n multinomial verspreiding volg. Dit is geskik vir diskrete data, soos woordtelling in teksklassifikasie.
- **Bernoulli Naive Bayes**: Neem aan dat die kenmerke binêr (0 of 1) is. Dit is geskik vir binêre data, soos die teenwoordigheid of afwesigheid van woorde in teksklassifikasie.
- **Categorical Naive Bayes**: Neem aan dat die kenmerke kategoriese veranderlikes is. Dit is geskik vir kategoriese data, soos die klassifikasie van vrugte op grond van hul kleur en vorm.

#### **Belangrike eienskappe van Naive Bayes:**

-   **Tipe Probleem:** Klassifikasie (binêr of multi-klas). Gewoonlik gebruik vir teksklassifikasietake in kuberveiligheid (spam, phishing, ens.).

-   **Interpretasie:** Medium -- dit is nie so direk interpreteerbaar soos 'n besluitboom nie, maar 'n mens kan die geleerde waarskynlikhede ondersoek (bv. watter woorde die waarskynlikste in spam teenoor ham e-posse is). Die model se vorm (waarskynlikhede vir elke kenmerk gegewe die klas) kan verstaan word indien nodig.

-   **Voordele:** **Baie vinnige** opleiding en voorspelling, selfs op groot datastelle (lineêr in die aantal voorbeelde * aantal kenmerke). Vereis relatief 'n klein hoeveelheid data om waarskynlikhede betroubaar te skat, veral met behoorlike gladmaak. Dit is dikwels verrassend akkuraat as 'n basislyn, veral wanneer kenmerke onafhanklik bydrae tot die klas. Werk goed met hoë-dimensionele data (bv. duisende kenmerke uit teks). Geen komplekse afstemming is nodig behalwe om 'n gladmaakparameter in te stel nie.

-   **Beperkings:** Die onafhanklikheid aannames kan akkuraatheid beperk as kenmerke hoogs gekorreleer is. Byvoorbeeld, in netwerkdata, kan kenmerke soos `src_bytes` en `dst_bytes` gekorreleer wees; Naive Bayes sal daardie interaksie nie vasvang nie. Soos die datagrootte baie groot word, kan meer uitdruklike modelle (soos ensembles of neurale netwerke) NB oortref deur kenmerkafhanklikhede te leer. Ook, as 'n sekere kombinasie van kenmerke nodig is om 'n aanval te identifiseer (nie net individuele kenmerke onafhanklik nie), sal NB sukkel.

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* Die klassieke gebruik is **spamdeteksie** -- Naive Bayes was die kern van vroeë spamfilters, wat die frekwensies van sekere tokens (woorde, frases, IP-adresse) gebruik om die waarskynlikheid te bereken dat 'n e-pos spam is. Dit word ook gebruik in **phishing e-posdeteksie** en **URL-klassifikasie**, waar die teenwoordigheid van sekere sleutelwoorde of eienskappe (soos "login.php" in 'n URL, of `@` in 'n URL-pad) bydra tot phishing waarskynlikheid. In malware-analise kan 'n mens 'n Naive Bayes klassifiseerder voorstel wat die teenwoordigheid van sekere API-oproepe of toestemmings in sagteware gebruik om te voorspel of dit malware is. Terwyl meer gevorderde algoritmes dikwels beter presteer, bly Naive Bayes 'n goeie basislyn weens sy spoed en eenvoud.

<details>
<summary>Voorbeeld -- Naive Bayes vir Phishing Deteksie:</summary>
Om Naive Bayes te demonstreer, sal ons Gaussian Naive Bayes op die NSL-KDD indringingsdatastel (met binêre etikette) gebruik. Gaussian NB sal elke kenmerk behandel as wat 'n normale verspreiding per klas volg. Dit is 'n ruwe keuse aangesien baie netwerkkenmerke diskreet of hoogs skeef is, maar dit toon hoe 'n mens NB op deurlopende kenmerkdata sou toepas. Ons kan ook Bernoulli NB op 'n datastel van binêre kenmerke kies (soos 'n stel van geaktiveerde waarskuwings), maar ons sal hier by NSL-KDD bly vir kontinuïteit.
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
Hierdie kode leer 'n Naive Bayes klassifiseerder om aanvalle te detecteer. Naive Bayes sal dinge soos `P(service=http | Attack)` en `P(Service=http | Normal)` bereken op grond van die opleidingsdata, met die aanname van onafhanklikheid tussen eienskappe. Dit sal dan hierdie waarskynlikhede gebruik om nuwe verbintenisse as normaal of aanval te klassifiseer op grond van die waargeneem eienskappe. Die prestasie van NB op NSL-KDD mag nie so hoog wees soos meer gevorderde modelle nie (aangesien eienskap onafhanklikheid oortree word), maar dit is dikwels aanvaarbaar en kom met die voordeel van uiterste spoed. In scenario's soos regstreekse e-posfiltrering of aanvanklike triage van URL's, kan 'n Naive Bayes-model vinnig duidelik kwaadwillige gevalle merk met lae hulpbronverbruik.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors is een van die eenvoudigste masjienleer algoritmes. Dit is 'n **nie-parametriese, voorbeelde-gebaseerde** metode wat voorspellings maak op grond van die ooreenkoms met voorbeelde in die opleidingsstel. Die idee vir klassifikasie is: om 'n nuwe datapunt te klassifiseer, vind die **k** naaste punte in die opleidingsdata (sy "naaste bure"), en ken die meerderheid klas aan daardie bure toe. "Nabyheid" word gedefinieer deur 'n afstandsmetrie, tipies Euclidiese afstand vir numeriese data (ander afstande kan gebruik word vir verskillende tipes eienskappe of probleme).

K-NN vereis *geen eksplisiete opleiding* nie -- die "opleiding" fase is net om die dataset te stoor. Al die werk gebeur tydens die navraag (voorspelling): die algoritme moet afstande van die navraagpunt na al die opleidingspunte bereken om die naaste te vind. Dit maak voorspellings tyd **lineêr in die aantal opleidingsmonsters**, wat duur kan wees vir groot datasets. As gevolg hiervan is k-NN die beste geskik vir kleiner datasets of scenario's waar jy geheue en spoed vir eenvoud kan ruil.

Ten spyte van sy eenvoud, kan k-NN baie komplekse besluitgrense modelleer (aangesien die besluitgrens effektief enige vorm kan hê wat deur die verspreiding van voorbeelde bepaal word). Dit doen dikwels goed wanneer die besluitgrens baie onreëlmatig is en jy baie data het -- essensieel laat die data "vir homself praat". egter, in hoë dimensies kan afstandsmetrieë minder betekenisvol word (vloek van dimensionaliteit), en die metode kan sukkel tensy jy 'n groot aantal monsters het.

*Gebruik gevalle in kuberveiligheid:* k-NN is toegepas op anomaliedetectie -- byvoorbeeld, 'n indringingdetectiestelsel mag 'n netwerkgebeurtenis as kwaadwillig merk as die meeste van sy naaste bure (vorige gebeurtenisse) kwaadwillig was. As normale verkeer klusters vorm en aanvalle uitskieters is, doen 'n K-NN benadering (met k=1 of klein k) essensieel 'n **naaste-buur anomaliedetectie**. K-NN is ook gebruik om malware-families te klassifiseer deur binêre eienskapvektore: 'n nuwe lêer mag as 'n sekere malware-familie geklassifiseer word as dit baie naby (in eienskapruimte) aan bekende voorbeelde van daardie familie is. In praktyk is k-NN nie so algemeen soos meer skaalbare algoritmes nie, maar dit is konseptueel eenvoudig en soms as 'n basislyn of vir kleinskaalse probleme gebruik.

#### **Belangrike kenmerke van k-NN:**

-   **Tipe Probleem:** Klassifikasie (en regressie variasies bestaan). Dit is 'n *luie leer* metode -- geen eksplisiete modelpassing nie.

-   **Interpretasie:** Lae tot medium -- daar is geen globale model of bondige verklaring nie, maar mens kan resultate interpreteer deur na die naaste bure te kyk wat 'n besluit beïnvloed het (bv. "hierdie netwerkvloei is as kwaadwillig geklassifiseer omdat dit soortgelyk is aan hierdie 3 bekende kwaadwillige vloei"). So, verklarings kan voorbeeld-gebaseerd wees.

-   **Voordele:** Baie eenvoudig om te implementeer en te verstaan. Maak geen aannames oor die dataverspreiding nie (nie-parametries). Kan natuurlik multi-klas probleme hanteer. Dit is **adaptief** in die sin dat besluitgrense baie kompleks kan wees, gevorm deur die dataverspreiding.

-   **Beperkings:** Voorspelling kan stadig wees vir groot datasets (moet baie afstande bereken). Geheue-intensief -- dit stoor al die opleidingsdata. Prestasie verswak in hoë-dimensionele eienskap ruimtes omdat al die punte geneig is om byna gelyk afstand te wees (wat die konsep van "naaste" minder betekenisvol maak). Moet *k* (aantal bure) toepaslik kies -- te klein k kan raserig wees, te groot k kan irrelevante punte van ander klasse insluit. Ook, eienskappe moet toepaslik geskaal word omdat afstandsberekeninge sensitief is vir skaal.

<details>
<summary>Voorbeeld -- k-NN vir Phishing Detectie:</summary>

Ons sal weer NSL-KDD gebruik (binariese klassifikasie). Omdat k-NN rekenaarintensief is, sal ons 'n subset van die opleidingsdata gebruik om dit hanteerbaar te hou in hierdie demonstrasie. Ons sal sê, 20,000 opleidingsmonsters uit die volle 125k kies, en k=5 bure gebruik. Na opleiding (werklik net die data stoor), sal ons op die toetsstel evalueer. Ons sal ook eienskappe skaal vir afstandsberekening om te verseker dat geen enkele eienskap oorheers weens skaal.
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
Die k-NN-model sal 'n verbinding klassifiseer deur na die 5 naaste verbindings in die opleidingsstel-substel te kyk. As, byvoorbeeld, 4 van daardie bure aanvalle (anomalië) is en 1 normaal is, sal die nuwe verbinding as 'n aanval geklassifiseer word. Die prestasie mag redelik wees, hoewel dit dikwels nie so hoog is soos 'n goed-afgestemde Random Forest of SVM op dieselfde data nie. egter, k-NN kan soms uitblink wanneer die klasverspreidings baie onreëlmatig en kompleks is -- effektief 'n geheue-gebaseerde soektog gebruik. In kuberveiligheid kan k-NN (met k=1 of klein k) gebruik word vir die opsporing van bekende aanvalpatrone deur voorbeeld, of as 'n komponent in meer komplekse stelsels (bv. vir clustering en dan klassifisering gebaseer op klusterlidmaatskap).

### Gradient Boosting Machines (bv. XGBoost)

Gradient Boosting Machines is onder die kragtigste algoritmes vir gestruktureerde data. **Gradient boosting** verwys na die tegniek om 'n ensemble van swak leerders (dikwels besluitbome) op 'n opeenvolgende manier te bou, waar elke nuwe model die foute van die vorige ensemble regstel. Anders as bagging (Random Forests) wat bome parallel bou en hulle gemiddeld, bou boosting bome *een vir een*, elkeen wat meer fokus op die voorbeelde wat vorige bome verkeerd voorspel het.

Die gewildste implementasies in onlangse jare is **XGBoost**, **LightGBM**, en **CatBoost**, wat almal gradient boosting besluitboom (GBDT) biblioteke is. Hulle was uiters suksesvol in masjienleerkompetisies en toepassings, dikwels **met 'n toonaangewende prestasie op tabeldata**. In kuberveiligheid het navorsers en praktisyns gradient gebootste bome gebruik vir take soos **malware opsporing** (met funksies wat uit lêers of runtime gedrag onttrek is) en **netwerk indringing opsporing**. Byvoorbeeld, 'n gradient boosting model kan baie swak reëls (bome) soos "as baie SYN-pakkette en ongewone poort -> waarskynlik skandering" kombineer in 'n sterk saamgestelde detektor wat rekening hou met baie subtiele patrone.

Waarom is gebootste bome so effektief? Elke boom in die reeks word op die *residuele foute* (gradiënte) van die huidige ensemble se voorspellings opgelei. Op hierdie manier "versterk" die model geleidelik die areas waar dit swak is. Die gebruik van besluitbome as basisleerders beteken dat die finale model komplekse interaksies en nie-lineêre verhoudings kan vasvang. Ook, boosting het inherent 'n vorm van ingeboude regularisering: deur baie klein bome by te voeg (en 'n leerkoers te gebruik om hul bydraes te skaal), generaliseer dit dikwels goed sonder groot oorpassing, solank behoorlike parameters gekies word.

#### **Belangrike kenmerke van Gradient Boosting:**

-   **Tipe Probleem:** Primêr klassifikasie en regressie. In sekuriteit, gewoonlik klassifikasie (bv. binêre klassifisering van 'n verbinding of lêer). Dit hanteer binêre, multi-klas (met toepaslike verlies), en selfs rangorde probleme.

-   **Interpretasie:** Lae tot medium. Terwyl 'n enkele gebootste boom klein is, kan 'n volle model honderde bome hê, wat nie menslik interpreteerbaar is as 'n geheel nie. egter, soos Random Forest, kan dit funksiebelangrikheidsskorings verskaf, en gereedskap soos SHAP (SHapley Additive exPlanations) kan gebruik word om individuele voorspellings tot 'n sekere mate te interpreteer.

-   **Voordele:** Dikwels die **beste presterende** algoritme vir gestruktureerde/tabeldata. Kan komplekse patrone en interaksies opspoor. Het baie afstelknoppies (aantal bome, diepte van bome, leerkoers, regulariseringsterme) om modelkompleksiteit aan te pas en oorpassing te voorkom. Moderne implementasies is geoptimaliseer vir spoed (bv. XGBoost gebruik tweede-orde gradiëntinligting en doeltreffende datastrukture). Geneig om ongebalanseerde data beter te hanteer wanneer dit gekombineer word met toepaslike verliesfunksies of deur monstergewigte aan te pas.

-   **Beperkings:** Meer kompleks om af te stel as eenvoudiger modelle; opleiding kan stadig wees as bome diep is of die aantal bome groot is (alhoewel dit steeds gewoonlik vinniger is as om 'n vergelykbare diep neurale netwerk op dieselfde data op te lei). Die model kan oorpas as dit nie afgestel word nie (bv. te veel diepe bome met onvoldoende regularisering). Vanweë baie hiperparameters, kan die effektiewe gebruik van gradient boosting meer kundigheid of eksperimente vereis. Ook, soos boomgebaseerde metodes, hanteer dit nie inherent baie spaarsame hoë-dimensionele data so doeltreffend soos lineêre modelle of Naive Bayes nie (alhoewel dit steeds toegepas kan word, bv. in teksklassifikasie, maar mag nie die eerste keuse wees sonder kenmerkingenieering).

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* Byna oral waar 'n besluitboom of random forest gebruik kan word, kan 'n gradient boosting model beter akkuraatheid bereik. Byvoorbeeld, **Microsoft se malware opsporing** kompetisies het swaar gebruik gemaak van XGBoost op geengineerde funksies van binêre lêers. **Netwerk indringing opsporing** navorsing rapporteer dikwels topresultate met GBDTs (bv. XGBoost op CIC-IDS2017 of UNSW-NB15 datasets). Hierdie modelle kan 'n wye reeks funksies (protokol tipes, frekwensie van sekere gebeurtenisse, statistiese funksies van verkeer, ens.) neem en dit kombineer om bedreigings op te spoor. In phishing opsporing kan gradient boosting leksikale funksies van URL's, domein reputasiefunksies, en bladsy-inhoud funksies kombineer om baie hoë akkuraatheid te bereik. Die ensemble-benadering help om baie hoek gevalle en subtiliteite in die data te dek.

<details>
<summary>Voorbeeld -- XGBoost vir Phishing Opsporing:</summary>
Ons sal 'n gradient boosting klassifiseerder op die phishing-dataset gebruik. Om dinge eenvoudig en selfondersteunend te hou, sal ons `sklearn.ensemble.GradientBoostingClassifier` gebruik (wat 'n stadiger maar eenvoudige implementasie is). Normaalweg kan 'n mens `xgboost` of `lightgbm` biblioteke gebruik vir beter prestasie en bykomende funksies. Ons sal die model oplei en dit op 'n soortgelyke manier evalueer soos voorheen.
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
Die gradient boosting model sal waarskynlik baie hoë akkuraatheid en AUC op hierdie phishing dataset bereik (dikwels kan hierdie modelle 95% akkuraatheid oorskry met behoorlike afstemming op sulke data, soos gesien in die literatuur. Dit demonstreer waarom GBDTs beskou word as *"die toonaangewende model vir tabeldata"* -- hulle presteer dikwels beter as eenvoudiger algoritmes deur komplekse patrone vas te vang. In 'n kuberveiligheidskonteks kan dit beteken dat meer phishing-webwerwe of -aanvalle met minder misse opgevang word. Natuurlik moet 'n mens versigtig wees oor oorpassing -- ons sou tipies tegnieke soos kruisvalidasie gebruik en die prestasie op 'n validasieset monitor wanneer ons so 'n model vir ontplooiing ontwikkel.

</details>

### Kombinasie van Modelle: Ensemble Leer en Stacking

Ensemble leer is 'n strategie van **die kombinasie van verskeie modelle** om die algehele prestasie te verbeter. Ons het reeds spesifieke ensemble metodes gesien: Random Forest (‘n ensemble van bome via bagging) en Gradient Boosting (‘n ensemble van bome via sekwensiële boosting). Maar ensembles kan ook op ander maniere geskep word, soos **stemensembles** of **gestapelde generalisering (stacking)**. Die hoofidee is dat verskillende modelle verskillende patrone kan vasvang of verskillende swakhede kan hê; deur hulle te kombineer, kan ons **elke model se foute met 'n ander se sterkpunte kompenseer**.

-   **Stem Ensemble:** In 'n eenvoudige stemklassifiseerder, oplei ons verskeie diverse modelle (sê, 'n logistieke regressie, 'n besluitboom, en 'n SVM) en laat hulle stem oor die finale voorspelling (meerderheidsstem vir klassifikasie). As ons die stemme gewig (bv. hoër gewig aan meer akkurate modelle), is dit 'n gewigte stemskema. Dit verbeter tipies die prestasie wanneer die individuele modelle redelik goed en onafhanklik is -- die ensemble verminder die risiko van 'n individuele model se fout aangesien ander dit kan regstel. Dit is soos om 'n paneel van kundiges te hê eerder as 'n enkele mening.

-   **Stacking (Gestapelde Ensemble):** Stacking gaan 'n stap verder. In plaas van 'n eenvoudige stem, oplei dit 'n **meta-model** om **te leer hoe om die voorspellinge van basismodelle die beste te kombineer**. Byvoorbeeld, jy oplei 3 verskillende klassifiseerders (basisleerlinge), dan voer jy hul uitsette (of waarskynlikhede) as kenmerke in 'n meta-klassifiseerder (dikwels 'n eenvoudige model soos logistieke regressie) wat die optimale manier leer om hulle te meng. Die meta-model word op 'n validasieset of via kruisvalidasie opgelei om oorpassing te vermy. Stacking kan dikwels beter presteer as eenvoudige stem deur te leer *watter modelle meer vertrou kan word in watter omstandighede*. In kuberveiligheid kan een model beter wees om netwerk skanderings op te vang terwyl 'n ander beter is om malware sein te vang; 'n stacking model kan leer om elkeen toepaslik te vertrou.

Ensembles, of dit nou deur stem of stacking is, geneig om **akkuraatheid** en robuustheid te **verhoog**. Die nadeel is verhoogde kompleksiteit en soms verminderde interpreteerbaarheid (alhoewel sommige ensemble benaderings soos 'n gemiddelde van besluitbome steeds 'n bietjie insig kan bied, bv. kenmerk belangrikheid). In praktyk, as operasionele beperkings dit toelaat, kan die gebruik van 'n ensemble lei tot hoër opsporingskoerse. Baie wenoplossings in kuberveiligheid uitdagings (en Kaggle kompetisies in die algemeen) gebruik ensemble tegnieke om die laaste bietjie prestasie te verknies.

<details>
<summary>Voorbeeld -- Stem Ensemble vir Phishing Opsporing:</summary>
Om model stacking te illustreer, kom ons kombineer 'n paar van die modelle wat ons op die phishing dataset bespreek het. Ons sal 'n logistieke regressie, 'n besluitboom, en 'n k-NN as basisleerlinge gebruik, en 'n Random Forest as 'n meta-leerder gebruik om hul voorspellinge te aggregeer. Die meta-leerder sal opgelei word op die uitsette van die basisleerlinge (met kruisvalidasie op die opleidingset). Ons verwag dat die gestapelde model sowel as of effens beter as die individuele modelle sal presteer.
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
Die gestapelde ensemble benut die aanvullende sterkte van die basismodelle. Byvoorbeeld, logistieke regressie kan die lineêre aspekte van die data hanteer, die besluitboom kan spesifieke reëlagtige interaksies vasvang, en k-NN kan uitblink in plaaslike buurtes van die kenmerkruimte. Die meta-model (hier 'n random forest) kan leer hoe om hierdie insette te weeg. Die resulterende metrieke toon dikwels 'n verbetering (selfs al is dit gering) oor enige enkele model se metrieke. In ons phishing voorbeeld, as logistiek alleen 'n F1 van sê 0.95 gehad het en die boom 0.94, kan die stapel 0.96 bereik deur op te tel waar elke model verkeerd is.

Ensemble-metodes soos hierdie demonstreer die beginsel dat *"die kombinasie van meerdere modelle tipies lei tot beter generalisering"*. In kuberveiligheid kan dit geïmplementeer word deur verskeie opsporingsenjins te hê (een kan reël-gebaseerd wees, een masjienleer, een anomalie-gebaseerd) en dan 'n laag wat hul waarskuwings saamvoeg -- effektief 'n vorm van ensemble -- om 'n finale besluit met 'n hoër vertroue te neem. Wanneer sulke stelsels ontplooi word, moet 'n mens die bykomende kompleksiteit oorweeg en verseker dat die ensemble nie te moeilik is om te bestuur of te verduidelik nie. Maar vanuit 'n akkuraatheidsoogpunt is ensembles en stapeling kragtige gereedskap om modelprestasie te verbeter.

</details>


## Verwysings

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
