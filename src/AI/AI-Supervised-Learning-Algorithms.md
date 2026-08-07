# Algorithms za Supervised Learning

{{#include ../banners/hacktricks-training.md}}

## Taarifa za Msingi

Supervised learning hutumia data yenye labels kufundisha models zinazoweza kufanya utabiri kuhusu inputs mpya ambazo hazijawahi kuonekana. Katika cybersecurity, supervised machine learning hutumika sana katika kazi kama vile intrusion detection (kuainisha network traffic kuwa *normal* au *attack*), malware detection (kutofautisha software hatari na isiyo hatari), phishing detection (kutambua websites au emails za ulaghai), na spam filtering, miongoni mwa nyingine.<sup>[[1]](#references)</sup> Kila algorithm ina nguvu zake na inafaa kwa aina tofauti za matatizo (classification au regression). Hapa chini tunapitia supervised learning algorithms muhimu, tunaeleza jinsi zinavyofanya kazi, na tunaonyesha matumizi yake kwenye cybersecurity datasets halisi. Pia tunajadili jinsi kuchanganya models (ensemble learning) kunavyoweza mara nyingi kuboresha predictive performance.

## Algorithms

-   **Linear Regression:** Regression algorithm ya msingi ya kutabiri matokeo ya nambari kwa ku-fit linear equation kwenye data.

-   **Logistic Regression:** Classification algorithm (licha ya jina lake) inayotumia logistic function ku-model uwezekano wa binary outcome.

-   **Decision Trees:** Models zenye muundo wa mti zinazogawanya data kulingana na features ili kufanya utabiri; mara nyingi hutumika kwa sababu ya urahisi wake wa kutafsiriwa.

-   **Random Forests:** Ensemble ya decision trees (kupitia bagging) inayoboresha accuracy na kupunguza overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers zinazopata optimal separating hyperplane; zinaweza kutumia kernels kwa data isiyo ya linear.

-   **Naive Bayes:** Probabilistic classifier inayotegemea Bayes' theorem pamoja na assumption kwamba features hazitegemei nyingine, na hutumika sana katika spam filtering.

-   **k-Nearest Neighbors (k-NN):** Classifier rahisi ya "instance-based" inayoweka label kwenye sample kulingana na class yenye wengi zaidi kati ya neighbors wake walio karibu.

-   **Gradient Boosting Machines:** Ensemble models (k.m., XGBoost, LightGBM) zinazounda predictor imara kwa kuongeza weaker learners mmoja baada ya mwingine (kwa kawaida decision trees).

Kila sehemu hapa chini inatoa maelezo yaliyoboreshwa ya algorithm pamoja na **Python code example** inayotumia libraries kama `pandas` na `scikit-learn` (na `PyTorch` kwa neural network example). Mifano hii inatumia cybersecurity datasets zinazopatikana hadharani (kama NSL-KDD kwa intrusion detection na Phishing Websites dataset) na inafuata muundo unaofanana:

1.  **Pakia dataset** (download kupitia URL ikiwa inapatikana).

2.  **Preprocess data** (k.m. encode categorical features, scale values, na gawanya data kuwa train/test sets).

3.  **Train model** kwa kutumia training data.

4.  **Evaluate** kwenye test set kwa kutumia metrics: accuracy, precision, recall, F1-score, na ROC AUC kwa classification (na mean squared error kwa regression).

Hebu tuangalie kila algorithm:

### Linear Regression

Linear regression ni **regression** algorithm inayotumika kutabiri numeric values zinazoendelea. Inachukulia kwamba kuna uhusiano wa linear kati ya input features (independent variables) na output (dependent variable). Model hujaribu ku-fit straight line (au hyperplane katika dimensions za juu zaidi) inayoeleza vizuri zaidi uhusiano kati ya features na target. Kwa kawaida hili hufanywa kwa kupunguza jumla ya squared errors kati ya values zilizotabiriwa na values halisi (Ordinary Least Squares method).<sup>[[2]](#references)</sup>

Njia rahisi zaidi ya kuwakilisha linear regression ni kutumia mstari:
```plaintext
y = mx + b
```
Ambapo:

- `y` ni thamani iliyotabiriwa (output)
- `m` ni mteremko wa mstari (coefficient)
- `x` ni kipengele cha input
- `b` ni sehemu ya kukatiza mhimili wa y

Lengo la linear regression ni kupata mstari unaolingana vyema zaidi na unaopunguza tofauti kati ya thamani zilizotabiriwa na thamani halisi katika dataset. Bila shaka, hii ni rahisi sana; ungekuwa mstari ulionyooka unaotenganisha kategoria 2, lakini vipimo zaidi vinapoongezwa, mstari huwa changamano zaidi:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Matumizi katika cybersecurity:* Linear regression yenyewe haitumiki sana kwa kazi kuu za usalama (ambazo mara nyingi ni classification), lakini inaweza kutumika kutabiri matokeo ya nambari. Kwa mfano, mtu anaweza kutumia linear regression **kutabiri kiasi cha network traffic** au **kukadiria idadi ya attacks katika kipindi fulani** kwa kuzingatia data ya kihistoria. Pia inaweza kutabiri risk score au muda unaotarajiwa hadi attack igunduliwe, kulingana na vipimo fulani vya mfumo. Kwa vitendo, classification algorithms (kama logistic regression au trees) hutumiwa mara nyingi zaidi kugundua intrusions au malware, lakini linear regression hutumika kama msingi na ni muhimu kwa analyses zinazohusu regression.

#### **Sifa kuu za Linear Regression:**

-   **Aina ya Tatizo:** Regression (kutabiri thamani zinazoendelea). Haifai kwa classification ya moja kwa moja isipokuwa threshold itumike kwenye output.

-   **Ufafanuzi:** Juu -- coefficients ni rahisi kutafsiri, zikionyesha athari ya linear ya kila feature.

-   **Faida:** Rahisi na ya haraka; baseline nzuri kwa regression tasks; hufanya kazi vizuri wakati uhusiano halisi unakaribia kuwa wa linear.

-   **Mapungufu:** Haiwezi kushughulikia uhusiano changamano au usio wa linear (bila manual feature engineering); inaweza kufanya underfitting ikiwa mahusiano si ya linear; huathiriwa na outliers, ambazo zinaweza kupotosha matokeo.

-   **Kupata Best Fit:** Ili kupata mstari wa best fit unaotenganisha categories zinazowezekana, tunatumia mbinu inayoitwa **Ordinary Least Squares (OLS)**. Mbinu hii hupunguza jumla ya tofauti zilizowekwa squared kati ya thamani zilizozingatiwa na thamani zilizotabiriwa na linear model.

<details>
<summary>Example -- Kutabiri Muda wa Connection (Regression) katika Intrusion Dataset
</summary>
Hapa chini tunaonyesha linear regression kwa kutumia NSL-KDD cybersecurity dataset. Tutachukulia hili kama tatizo la regression kwa kutabiri `duration` ya network connections kwa kuzingatia features nyingine. (Kwa uhalisia, `duration` ni feature moja ya NSL-KDD; tunaitumia hapa kwa madhumuni ya kuonyesha regression.) Tunapakia dataset, tunaipreprocess (ku-encode categorical features), tunatrain linear regression model, na kutathmini Mean Squared Error (MSE) na R² score kwenye test set.
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
Katika mfano huu, linear regression model inajaribu kutabiri `duration` ya connection kutokana na network features nyingine. Tunapima utendaji kwa kutumia Mean Squared Error (MSE) na R². R² iliyo karibu na 1.0 ingeonyesha kuwa model inaeleza sehemu kubwa ya variance katika `duration`, ilhali R² ya chini au hasi inaonyesha fit isiyoridhisha. (Usishangae ikiwa R² ni ya chini hapa -- kutabiri `duration` kunaweza kuwa kugumu kutokana na features zilizotolewa, na linear regression huenda isiweze kunasa patterns ikiwa ni changamano.)
</details>

### Logistic Regression

Logistic regression ni algorithm ya **classification** inayomodeli uwezekano kwamba instance ni ya class fulani (kwa kawaida class ya "positive"). Licha ya jina lake, *logistic* regression hutumika kwa matokeo ya discrete (tofauti na linear regression, ambayo hutumika kwa matokeo ya continuous). Hutumika hasa kwa **binary classification** (classes mbili, kwa mfano, malicious dhidi ya benign), lakini inaweza kupanuliwa kwa matatizo ya multi-class (kwa kutumia softmax au mbinu za one-vs-rest).<sup>[[3]](#references)</sup>

Logistic regression hutumia logistic function (inayojulikana pia kama sigmoid function) kubadilisha predicted values kuwa probabilities. Kumbuka kwamba sigmoid function ni function yenye values kati ya 0 na 1, inayokua kwa curve yenye umbo la S kulingana na mahitaji ya classification, jambo linaloifanya iwe muhimu kwa binary classification tasks. Kwa hivyo, kila feature ya kila input huzidishwa kwa weight iliyopewa, na matokeo hupitishwa kupitia sigmoid function ili kutoa probability:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Ambapo:

- `p(y=1|x)` ni uwezekano kwamba matokeo `y` ni 1 kutokana na ingizo `x`
- `e` ni msingi wa logarithm ya asili
- `z` ni mchanganyiko wa mstari wa vipengele vya ingizo, ambao kwa kawaida huwakilishwa kama `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Kumbuka kwamba katika muundo wake rahisi zaidi ni mstari ulionyooka, lakini katika hali changamano zaidi huwa hyperplane yenye dimensions kadhaa (moja kwa kila kipengele).

> [!TIP]
> *Matumizi katika cybersecurity:* Kwa sababu matatizo mengi ya usalama kimsingi ni maamuzi ya ndiyo/hapana, Logistic Regression hutumiwa sana. Kwa mfano, mfumo wa intrusion detection unaweza kutumia Logistic Regression kuamua ikiwa muunganisho wa mtandao ni attack kulingana na vipengele vya muunganisho huo. Katika utambuzi wa phishing, Logistic Regression inaweza kuunganisha vipengele vya website (urefu wa URL, uwepo wa alama ya "@", n.k.) na kuvibadilisha kuwa uwezekano wa kuwa phishing. Imetumika katika spam filters za kizazi cha awali na bado ni baseline imara kwa kazi nyingi za classification.

#### Logistic Regression kwa classification isiyo ya binary

Logistic Regression imeundwa kwa binary classification, lakini inaweza kupanuliwa kushughulikia matatizo ya multi-class kwa kutumia mbinu kama **one-vs-rest** (OvR) au **softmax regression**. Katika OvR, modeli tofauti ya Logistic Regression hufunzwa kwa kila class, ambapo class hiyo huchukuliwa kuwa positive class dhidi ya nyingine zote. Class yenye uwezekano uliotabiriwa wa juu zaidi huchaguliwa kama utabiri wa mwisho. Softmax regression hujumlisha Logistic Regression kwa classes nyingi kwa kutumia softmax function kwenye output layer, na kutoa mgawanyo wa uwezekano kwa classes zote.

#### **Sifa kuu za Logistic Regression:**

-   **Aina ya Tatizo:** Classification (kwa kawaida binary). Hutabiri uwezekano wa positive class.

-   **Ufafanuzi:** Juu -- kama ilivyo kwa linear regression, coefficients za vipengele zinaweza kuonyesha jinsi kila kipengele kinavyoathiri log-odds za matokeo. Uwazi huu mara nyingi huthaminiwa katika usalama kwa kuelewa ni mambo gani yanayochangia alert.

-   **Faida:** Ni rahisi na ina kasi ya kufunzwa; hufanya kazi vizuri wakati uhusiano kati ya vipengele na log-odds za matokeo ni wa mstari. Hutoa probabilities, hivyo kuwezesha risk scoring. Kwa regularization inayofaa, hu-generalize vizuri na inaweza kushughulikia multicollinearity vizuri zaidi kuliko plain linear regression.

-   **Mapungufu:** Hudhani kuwa decision boundary katika feature space ni ya mstari (hushindwa ikiwa boundary halisi ni changamano/isiyo ya mstari). Inaweza kufanya vibaya kwenye matatizo ambayo interactions au non-linear effects ni muhimu, isipokuwa uongeze mwenyewe polynomial au interaction features. Pia, Logistic Regression haifanyi kazi vizuri ikiwa classes haziwezi kutenganishwa kwa urahisi na mchanganyiko wa mstari wa vipengele.


<details>
<summary>Example -- Utambuzi wa Phishing Website kwa Logistic Regression:</summary>

Tutatumia **Phishing Websites Dataset** (kutoka UCI repository), ambayo ina extracted features za websites (kama ikiwa URL ina IP address, umri wa domain, uwepo wa vipengele vya kutiliwa shaka katika HTML, n.k.) pamoja na label inayoonyesha ikiwa site ni phishing au halali.<sup>[[4]](#references)</sup> Tunafunza modeli ya Logistic Regression ili ku-classify websites, kisha tunatathmini accuracy, precision, recall, F1-score, na ROC AUC yake kwenye test split.
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
Katika mfano huu wa kutambua phishing, logistic regression hutoa uwezekano kwa kila website kuainishwa kuwa phishing. Kwa kutathmini accuracy, precision, recall, na F1, tunapata picha ya utendaji wa model. Kwa mfano, recall ya juu ingemaanisha kuwa inagundua phishing sites nyingi (jambo muhimu kwa usalama ili kupunguza mashambulizi yanayokosa kugunduliwa), huku precision ya juu ikimaanisha kuwa ina false alarms chache (jambo muhimu ili kuzuia uchovu wa analyst). ROC AUC (Area Under the ROC Curve) hutoa kipimo cha utendaji kisichotegemea threshold (1.0 ni bora kabisa, 0.5 si bora kuliko kubahatisha). Logistic regression mara nyingi hufanya vizuri kwenye kazi kama hizi, lakini ikiwa decision boundary kati ya phishing sites na websites halali ni changamano, models zenye nguvu zaidi zisizo za mstari zinaweza kuhitajika.

</details>

### Decision Trees

Decision tree ni **algorithm ya supervised learning** inayoweza kutumiwa kwa kazi za classification na regression. Huunda model ya maamuzi yenye muundo wa mti wa ngazi, kulingana na features za data. Kila internal node ya mti huwakilisha jaribio kwenye feature fulani, kila branch huwakilisha matokeo ya jaribio hilo, na kila leaf node huwakilisha class iliyotabiriwa (kwa classification) au value (kwa regression).<sup>[[5]](#references)</sup>

Ili kujenga mti, algorithms kama CART (Classification and Regression Tree) hutumia vipimo kama **Gini impurity** au **information gain (entropy)** kuchagua feature na threshold bora ya kugawanya data katika kila hatua. Lengo katika kila mgawanyo ni kugawanya data ili kuongeza homogeneity ya target variable katika subsets zinazotokana (kwa classification, kila node inalenga kuwa pure iwezekanavyo, ikiwa na data ya class moja kwa kiwango kikubwa).

Decision trees ni **rahisi sana kufasiriwa** -- mtu anaweza kufuata njia kutoka root hadi leaf ili kuelewa mantiki iliyo nyuma ya prediction (kwa mfano, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN ainisha kama attack"*). Hili ni muhimu katika cybersecurity kwa kueleza kwa nini alert fulani ilitolewa. Trees zinaweza kushughulikia kwa asili data ya namba na categorical data, na zinahitaji preprocessing kidogo (kwa mfano, feature scaling haihitajiki).

Hata hivyo, decision tree moja inaweza ku-overfit training data kwa urahisi, hasa ikiwa imekuzwa kwa kina (ikiwa na splits nyingi). Techniques kama pruning (kuweka kikomo cha tree depth au kuhitaji idadi ya chini ya samples kwa kila leaf) hutumiwa mara nyingi kuzuia overfitting.

Kuna vipengele 3 vikuu vya decision tree:
- **Root Node**: Node ya juu ya mti, inayowakilisha dataset nzima.
- **Internal Nodes**: Nodes zinazowakilisha features na maamuzi yanayotegemea features hizo.
- **Leaf Nodes**: Nodes zinazowakilisha matokeo au prediction ya mwisho.

Mti unaweza kuishia kuonekana hivi:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Matumizi katika cybersecurity:* Decision trees zimetumika katika intrusion detection systems kupata **rules** za kutambua mashambulizi. Kwa mfano, IDS za awali zilizotegemea ID3/C4.5 zilitengeneza rules zinazoweza kusomeka na binadamu ili kutofautisha traffic ya kawaida na malicious. Pia hutumika katika malware analysis kuamua ikiwa file ni malicious kulingana na sifa zake (ukubwa wa file, section entropy, API calls, n.k.). Uwazi wa decision trees huzifanya kuwa muhimu pale transparency inapohitajika -- analyst anaweza kukagua tree ili kuthibitisha detection logic.

#### **Sifa muhimu za Decision Trees:**

-   **Aina ya Tatizo:** Classification na regression. Hutumika kwa kawaida katika classification ya attacks dhidi ya normal traffic, n.k.

-   **Interpretability:** Juu sana -- maamuzi ya model yanaweza kuonyeshwa na kueleweka kama seti ya if-then rules. Hii ni faida kubwa katika security kwa ajili ya trust na verification ya tabia ya model.

-   **Faida:** Zinaweza kutambua relationships zisizo linear na interactions kati ya features (kila split inaweza kuonekana kama interaction). Hakuna haja ya kuscale features au ku-one-hot encode categorical variables -- trees hushughulikia hayo natively. Inference ni ya haraka (prediction ni kufuata tu path katika tree).

-   **Vikwazo:** Zinaweza ku-overfit ikiwa hazitadhibitiwa (tree ndefu inaweza kukariri training set). Zinaweza kuwa unstable -- mabadiliko madogo katika data yanaweza kusababisha structure tofauti ya tree. Kama models za pekee, accuracy yake huenda isilingane na methods za hali ya juu zaidi (ensembles kama Random Forests kwa kawaida hufanya vizuri zaidi kwa kupunguza variance).

-   **Kupata Split Bora:**
- **Gini Impurity**: Hupima impurity ya node. Gini impurity ya chini huashiria split bora. Formula ni:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Ambapo `p_i` ni uwiano wa instances zilizo katika class `i`.

- **Entropy**: Hupima uncertainty katika dataset. Entropy ya chini huashiria split bora. Formula ni:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Ambapo `p_i` ni uwiano wa instances zilizo katika class `i`.

- **Information Gain**: Ni upungufu wa entropy au Gini impurity baada ya split. Kadiri information gain ilivyo kubwa, ndivyo split ilivyo bora. Huhesabiwa kama:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Zaidi ya hayo, tree huisha wakati:
- Instances zote katika node ni za class moja. Hii inaweza kusababisha overfitting.
- Maximum depth (iliyowekwa moja kwa moja kwenye code) ya tree imefikiwa. Hii ni njia ya kuzuia overfitting.
- Idadi ya instances katika node iko chini ya threshold fulani. Hii pia ni njia ya kuzuia overfitting.
- Information gain kutoka kwa splits zaidi iko chini ya threshold fulani. Hii pia ni njia ya kuzuia overfitting.

<details>
<summary>Example -- Decision Tree for Intrusion Detection:</summary>
Tutatrain decision tree kwenye dataset ya NSL-KDD ili ku-classify network connections kama *normal* au *attack*. NSL-KDD ni toleo lililoboreshwa la dataset ya kawaida ya KDD Cup 1999, yenye features kama protocol type, service, duration, idadi ya failed logins, n.k., pamoja na label inayoonyesha attack type au "normal". Tutamap attack types zote kwenye class ya "anomaly" (binary classification: normal dhidi ya anomaly). Baada ya training, tutatathmini performance ya tree kwenye test set.
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
Katika mfano huu wa decision tree, tulipunguza kina cha tree hadi 10 ili kuepuka overfitting iliyokithiri (parameter ya `max_depth=10`). Metrics zinaonyesha jinsi tree inavyotofautisha traffic ya kawaida na ya attack. Recall ya juu ingemaanisha inakamata attacks nyingi (jambo muhimu kwa IDS), huku precision ya juu ikimaanisha false alarms chache. Decision trees mara nyingi hupata accuracy nzuri kwenye data iliyopangwa, lakini tree moja huenda isifikie performance bora zaidi inayowezekana. Hata hivyo, *interpretability* ya model ni faida kubwa -- tunaweza kuchunguza splits za tree ili kuona, kwa mfano, ni features zipi (k.m., `service`, `src_bytes`, n.k.) zina ushawishi mkubwa zaidi katika kuashiria connection kuwa malicious.

</details>

### Random Forests

Random Forest ni method ya **ensemble learning** inayojengwa juu ya decision trees ili kuboresha performance. Random forest hufunza decision trees nyingi (ndiyo maana ya "forest") na kuchanganya outputs zake ili kutoa prediction ya mwisho (kwa classification, kwa kawaida kupitia majority vote). Mawazo mawili makuu katika random forest ni **bagging** (bootstrap aggregating) na **feature randomness**:

-   **Bagging:** Kila tree hufunzwa kwa kutumia random bootstrap sample ya training data (sampled with replacement). Hii huleta diversity miongoni mwa trees.

-   **Feature Randomness:** Katika kila split ya tree, random subset ya features huzingatiwa kwa splitting (badala ya features zote). Hii hutenganisha zaidi trees kutoka kwa kila moja.

Kwa ku-average results za trees nyingi, random forest hupunguza variance ambayo decision tree moja inaweza kuwa nayo. Kwa maneno rahisi, trees binafsi zinaweza kufanya overfit au kuwa na noise, lakini idadi kubwa ya trees zenye diversity zinazopiga kura pamoja husawazisha errors hizo. Matokeo yake mara nyingi ni model yenye **accuracy ya juu** na generalization bora kuliko decision tree moja. Zaidi ya hayo, random forests zinaweza kutoa estimate ya feature importance (kwa kuangalia kiasi ambacho kila feature split hupunguza impurity kwa wastani).

Random forests zimekuwa **workhorse katika cybersecurity** kwa tasks kama intrusion detection, malware classification, na spam detection. Mara nyingi hufanya vizuri out-of-the-box bila tuning nyingi na zinaweza kushughulikia feature sets kubwa. Kwa mfano, katika intrusion detection, random forest inaweza kufanya vizuri zaidi kuliko decision tree moja kwa kukamata patterns fiche zaidi za attacks ikiwa na false positives chache. Research imeonyesha random forests zikifanya vizuri ikilinganishwa na algorithms nyingine katika ku-classify attacks kwenye datasets kama NSL-KDD na UNSW-NB15.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Sifa kuu za Random Forests:**

-   **Aina ya Tatizo:** Kimsingi classification (hutumika pia kwa regression). Inafaa sana kwa structured data yenye dimensions nyingi inayopatikana kwa kawaida katika security logs.

-   **Interpretability:** Ni ya chini kuliko decision tree moja -- huwezi ku-visualize au kueleza kwa urahisi mamia ya trees kwa wakati mmoja. Hata hivyo, feature importance scores hutoa ufahamu fulani kuhusu attributes zipi zina ushawishi mkubwa zaidi.

-   **Faida:** Kwa ujumla accuracy ni ya juu kuliko models za tree moja kutokana na ensemble effect. Inastahimili overfitting -- hata kama trees binafsi zinafanya overfit, ensemble hufanya generalization vizuri zaidi. Hushughulikia features za nambari na categorical na inaweza kusimamia missing data kwa kiwango fulani. Pia kwa kiasi kikubwa inastahimili outliers.

-   **Vikwazo:** Model size inaweza kuwa kubwa (trees nyingi, kila moja ikiwa na uwezekano wa kuwa na kina kirefu). Predictions ni polepole kuliko za tree moja (kwa sababu lazima u-aggregate kwenye trees nyingi). Ina interpretability ndogo -- ingawa unajua features muhimu, logic kamili haiwezi kufuatiliwa kwa urahisi kama rule rahisi. Ikiwa dataset ina dimensions nyingi sana na ni sparse, training ya forest kubwa sana inaweza kuwa nzito kwa upande wa computational resources.

-   **Training Process:**
1. **Bootstrap Sampling**: Chagua training data kwa njia ya random, ukiwa na replacement, ili kuunda subsets nyingi (bootstrap samples).
2. **Tree Construction**: Kwa kila bootstrap sample, jenga decision tree ukitumia random subset ya features katika kila split. Hii huleta diversity miongoni mwa trees.
3. **Aggregation**: Kwa classification tasks, prediction ya mwisho hutolewa kwa majority vote miongoni mwa predictions za trees zote. Kwa regression tasks, prediction ya mwisho ni average ya predictions kutoka kwa trees zote.

<details>
<summary>Mfano -- Random Forest kwa Intrusion Detection (NSL-KDD):</summary>
Tutatumia NSL-KDD dataset hiyo hiyo (iliyo na binary labels kama normal dhidi ya anomaly) na kufunza Random Forest classifier. Tunatarajia random forest ifanye vizuri sawa na au zaidi ya decision tree moja, kutokana na ensemble averaging kupunguza variance. Tutaitathmini kwa kutumia metrics hizo hizo.
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
Random forest kwa kawaida hupata matokeo mazuri katika kazi hii ya intrusion detection. Tunaweza kuona uboreshaji wa metrics kama F1 au AUC ikilinganishwa na decision tree moja, hasa katika recall au precision, kutegemea data. Hii inaendana na uelewa kwamba *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> Katika muktadha wa shughuli za usalama, random forest model inaweza kuashiria mashambulizi kwa kutegemeka zaidi huku ikipunguza false alarms, kutokana na wastani wa rules nyingi za maamuzi. Feature importance kutoka kwenye forest inaweza kutuonyesha ni network features zipi zinazoashiria zaidi mashambulizi (kwa mfano, network services fulani au idadi zisizo za kawaida za packets).

</details>

### Support Vector Machines (SVM)

Support Vector Machines ni supervised learning models zenye nguvu zinazotumika hasa kwa classification (na pia regression kama SVR). SVM hujaribu kupata **optimal separating hyperplane** inayoongeza kiwango cha margin kati ya classes mbili. Ni sehemu ndogo tu ya training points (zinazoitwa "support vectors", zilizo karibu zaidi na boundary) inayobainisha nafasi ya hyperplane hii. Kwa kuongeza margin (umbali kati ya support vectors na hyperplane), SVM huwa na uwezo mzuri wa generalization.<sup>[[8]](#references)</sup>

Jambo muhimu linaloipa SVM nguvu ni uwezo wa kutumia **kernel functions** kushughulikia mahusiano yasiyo ya linear. Data inaweza kubadilishwa kwa njia isiyo ya moja kwa moja kuwa katika feature space yenye dimensions nyingi zaidi, ambako linear separator inaweza kuwepo. Kernels za kawaida zinajumuisha polynomial, radial basis function (RBF), na sigmoid. Kwa mfano, ikiwa classes za network traffic haziwezi kutenganishwa kwa linear katika raw feature space, RBF kernel inaweza kuzipeleka katika dimension ya juu zaidi ambako SVM hupata linear split (inayolingana na boundary isiyo ya linear katika original space). Unyumbufu wa kuchagua kernels huwezesha SVM kushughulikia matatizo mbalimbali.

SVM zinajulikana kufanya vizuri katika hali zenye high-dimensional feature spaces (kama text data au malware opcode sequences) na katika hali ambapo idadi ya features ni kubwa ikilinganishwa na idadi ya samples. Zilitumika sana katika cybersecurity applications za awali, kama malware classification na anomaly-based intrusion detection katika miaka ya 2000, mara nyingi zikionyesha accuracy ya juu.

Hata hivyo, SVM haziongezeki kwa urahisi kulingana na ukubwa wa datasets kubwa sana (training complexity ni super-linear kulingana na idadi ya samples, na matumizi ya memory yanaweza kuwa makubwa kwa sababu huenda zikahitaji kuhifadhi support vectors nyingi). Kwa vitendo, katika kazi kama network intrusion detection yenye mamilioni ya records, SVM inaweza kuwa polepole sana bila kutumia subsampling kwa uangalifu au approximate methods.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (binary au multiclass kupitia one-vs-one/one-vs-rest) na regression variants. Mara nyingi hutumika katika binary classification yenye utenganishaji wa wazi wa margin.

-   **Interpretability:** Medium -- SVM hazieleweki kwa urahisi kama decision trees au logistic regression. Ingawa unaweza kubainisha ni data points zipi zilizo support vectors na kupata taswira fulani ya features zipi zinaweza kuwa na ushawishi (kupitia weights katika hali ya linear kernel), kwa vitendo SVM (hasa zenye non-linear kernels) huchukuliwa kama black-box classifiers.

-   **Advantages:** Zinafaa katika high-dimensional spaces; zinaweza kuunda decision boundaries changamano kwa kutumia kernel trick; ni thabiti dhidi ya overfitting ikiwa margin imeongezwa (hasa kwa regularization parameter C inayofaa); hufanya vizuri hata wakati classes hazijatenganishwa kwa umbali mkubwa (hupata boundary bora ya maafikiano).

-   **Limitations:** **Computationally intensive** kwa datasets kubwa (training na prediction zote hukua vibaya kadiri data inavyoongezeka). Zinahitaji tuning ya uangalifu ya kernel na regularization parameters (C, kernel type, gamma kwa RBF, n.k.). Hazitoi moja kwa moja probabilistic outputs (ingawa unaweza kutumia Platt scaling kupata probabilities). Pia, SVM zinaweza kuathiriwa na uchaguzi wa kernel parameters --- uchaguzi mbaya unaweza kusababisha underfit au overfit.

*Use cases in cybersecurity:* SVM zimetumika katika **malware detection** (kwa mfano, kuainisha files kulingana na extracted features au opcode sequences), **network anomaly detection** (kuainisha traffic kuwa normal au malicious), na **phishing detection** (kwa kutumia features za URLs). Kwa mfano, SVM inaweza kuchukua features za email (idadi za keywords fulani, sender reputation scores, n.k.) na kuiainisha kuwa phishing au legitimate. Pia zimetumika katika **intrusion detection** kwenye feature sets kama KDD, mara nyingi zikifikisha accuracy ya juu kwa gharama ya computation.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Tutatumia tena phishing website dataset, wakati huu kwa kutumia SVM. Kwa sababu SVM zinaweza kuwa polepole, tutatumia subset ya data kwa training ikiwa itahitajika (dataset ina takribani instances 11k, ambayo SVM inaweza kushughulikia kwa kiwango kinachofaa). Tutatumia RBF kernel ambayo ni chaguo la kawaida kwa data isiyo ya linear, na tutawezesha probability estimates ili kuhesabu ROC AUC.
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
Model ya SVM itatoa metrics tunazoweza kulinganisha na Logistic Regression kwenye task hiyo hiyo. Tunaweza kugundua kuwa SVM inapata accuracy na AUC ya juu ikiwa data imetenganishwa vizuri na features. Kwa upande mwingine, ikiwa dataset ina noise nyingi au classes zinazoingiliana, SVM inaweza isiiboreshe Logistic Regression kwa kiwango kikubwa. Kwa vitendo, SVM inaweza kutoa uboreshaji wakati kuna mahusiano changamano, yasiyo ya mstari kati ya features na class -- RBF kernel inaweza kunasa decision boundaries zilizopinda ambazo Logistic Regression haiwezi kunasa. Kama ilivyo kwa models zote, tuning makini ya `C` (regularization) na kernel parameters (kama `gamma` ya RBF) inahitajika ili kusawazisha bias na variance.

</details>

#### Tofauti kati ya Logistic Regression na SVM

| Kipengele | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Hupunguza **log‑loss** (cross‑entropy). | Huongeza **margin** huku ikipunguza **hinge‑loss**. |
| **Decision boundary** | Hupata **best-fit hyperplane** inayomodeli _P(y\|x)_. | Hupata **maximum-margin hyperplane** (pengo kubwa zaidi hadi kwenye points zilizo karibu zaidi). |
| **Output** | **Probabilistic** – hutoa class probabilities zilizocalibrate kupitia σ(w·x + b). | **Deterministic** – hurejesha class labels; probabilities zinahitaji kazi ya ziada (k.m. Platt scaling). |
| **Regularisation** | L2 (default) au L1, husawazisha moja kwa moja under/over-fitting. | C parameter husawazisha upana wa margin dhidi ya mis-classifications; kernel parameters huongeza complexity. |
| **Kernels / Non-linear** | Aina yake ya asili ni **linear**; non-linearity huongezwa kupitia feature engineering. | **Kernel trick** iliyojengwa ndani (RBF, poly, n.k.) huiwezesha kumodeli boundaries changamano katika space yenye high-dimensional. |
| **Scalability** | Hutatua convex optimisation katika **O(nd)**; hushughulikia n kubwa sana vizuri. | Training inaweza kuwa na memory/time ya **O(n²–n³)** bila specialised solvers; haifai sana kwa n kubwa mno. |
| **Interpretability** | **Juu** – weights huonyesha ushawishi wa feature; odds ratio ni rahisi kuelewa. | **Chini** kwa non-linear kernels; support vectors ni sparse lakini si rahisi kueleza. |
| **Sensitivity to outliers** | Hutumia smooth log-loss → huwa na sensitivity ndogo. | Hinge-loss yenye hard margin inaweza kuwa **sensitive**; soft-margin (C) hupunguza athari hiyo. |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – ambapo **probabilities & explainability** ni muhimu. | Image/text classification, bio-informatics – ambapo **complex boundaries** na **high-dimensional data** ni muhimu. |

* **Ikiwa unahitaji calibrated probabilities, interpretability, au unafanya kazi na datasets kubwa sana — chagua Logistic Regression.**
* **Ikiwa unahitaji model inayoweza kubadilika na kunasa mahusiano yasiyo ya mstari bila feature engineering ya mwongozo — chagua SVM (yenye kernels).**
* Zote huboresha convex objectives, kwa hiyo **global minima zimehakikishwa**, lakini kernels za SVM huongeza hyper-parameters na gharama ya computational.

### Naive Bayes

Naive Bayes ni familia ya **probabilistic classifiers** inayotegemea kutumia Bayes' Theorem pamoja na assumption kali ya independence kati ya features. Licha ya assumption hii ya "naive", Naive Bayes mara nyingi hufanya kazi vizuri kwa kushangaza katika applications fulani, hasa zinazohusisha text au categorical data, kama vile spam detection.<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem ndiyo msingi wa Naive Bayes classifiers. Inahusisha conditional na marginal probabilities za random events. Formula ni:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Ambapo:
- `P(A|B)` ni uwezekano wa posterior wa class `A` kutokana na feature `B`.
- `P(B|A)` ni likelihood ya feature `B` kutokana na class `A`.
- `P(A)` ni uwezekano wa awali wa class `A`.
- `P(B)` ni uwezekano wa awali wa feature `B`.

Kwa mfano, ikiwa tunataka kuainisha ikiwa maandishi yameandikwa na mtoto au mtu mzima, tunaweza kutumia maneno yaliyo kwenye maandishi kama features. Kwa kuzingatia data ya awali, Naive Bayes classifier itahesabu awali uwezekano wa kila neno kuwa katika kila class inayowezekana (mtoto au mtu mzima). Maandishi mapya yanapotolewa, itahesabu uwezekano wa kila class inayowezekana kutokana na maneno yaliyo kwenye maandishi, kisha ichague class yenye uwezekano mkubwa zaidi.

Kama unavyoona katika mfano huu, Naive Bayes classifier ni rahisi na yenye kasi sana, lakini inakadiria kwamba features zinajitegemea, jambo ambalo si wakati wote hutokea katika data ya ulimwengu halisi.


#### Aina za Naive Bayes Classifiers

Kuna aina kadhaa za Naive Bayes classifiers, kulingana na aina ya data na mgawanyo wa features:
- **Gaussian Naive Bayes**: Hukadiria kwamba features hufuata mgawanyo wa Gaussian (normal). Inafaa kwa data endelevu.
- **Multinomial Naive Bayes**: Hukadiria kwamba features hufuata mgawanyo wa multinomial. Inafaa kwa data ya discrete, kama vile hesabu za maneno katika text classification.
- **Bernoulli Naive Bayes**: Hukadiria kwamba features ni za binary (0 au 1). Inafaa kwa data ya binary, kama vile kuwepo au kutokuwepo kwa maneno katika text classification.
- **Categorical Naive Bayes**: Hukadiria kwamba features ni variables za categorical. Inafaa kwa data ya categorical, kama vile kuainisha matunda kulingana na rangi na umbo.


#### **Sifa muhimu za Naive Bayes:**

-   **Aina ya Tatizo:** Classification (binary au multi-class). Hutumiwa kwa kawaida katika kazi za text classification kwenye cybersecurity (spam, phishing, n.k.).

-   **Uwezo wa Kufasirika:** Wastani -- haiwezi kufasirika moja kwa moja kama decision tree, lakini mtu anaweza kuchunguza probabilities zilizojifunzwa (kwa mfano, ni maneno yapi yana uwezekano mkubwa zaidi katika barua pepe za spam ikilinganishwa na barua pepe halali). Muundo wa model (probabilities za kila feature kutokana na class) unaweza kueleweka inapohitajika.

-   **Faida:** Training na prediction yenye kasi **sana**, hata kwenye datasets kubwa (linear kulingana na idadi ya instances * idadi ya features). Inahitaji kiasi kidogo cha data ili kukadiria probabilities kwa kuaminika, hasa kwa kutumia smoothing inayofaa. Mara nyingi huwa na usahihi wa kushangaza kama baseline, hasa wakati features zinachangia ushahidi kwa kujitegemea kwa class. Hufanya kazi vizuri na data yenye dimensions nyingi (kwa mfano, maelfu ya features kutoka kwenye text). Haihitaji tuning changamano zaidi ya kuweka smoothing parameter.

-   **Mapungufu:** Dhana ya kujitegemea inaweza kupunguza usahihi ikiwa features zina uhusiano mkubwa. Kwa mfano, katika network data, features kama `src_bytes` na `dst_bytes` zinaweza kuwa na uhusiano; Naive Bayes haitanasa mwingiliano huo. Kadiri ukubwa wa data unavyokuwa mkubwa sana, models zenye uwezo mkubwa zaidi (kama ensembles au neural nets) zinaweza kuipita NB kwa kujifunza utegemezi kati ya features. Pia, ikiwa mchanganyiko fulani wa features unahitajika ili kutambua attack (badala ya features binafsi kuchangia kwa kujitegemea), NB itapata ugumu.

> [!TIP]
> *Matumizi katika cybersecurity:* Matumizi ya kawaida ni **spam detection** -- Naive Bayes ilikuwa msingi wa spam filters za awali, ikitumia frequency za tokens fulani (maneno, vifungu vya maneno, IP addresses) ili kukokotoa uwezekano kwamba email ni spam. Pia hutumiwa katika **phishing email detection** na **URL classification**, ambapo kuwepo kwa keywords au sifa fulani (kama "login.php" kwenye URL, au `@` kwenye URL path) huchangia uwezekano wa phishing. Katika malware analysis, mtu anaweza kufikiria Naive Bayes classifier inayotumia kuwepo kwa API calls au permissions fulani kwenye software kutabiri ikiwa ni malware. Ingawa algorithms za hali ya juu mara nyingi hufanya vizuri zaidi, Naive Bayes bado ni baseline nzuri kwa sababu ya kasi na urahisi wake.

<details>
<summary>Mfano -- Naive Bayes kwa Phishing Detection:</summary>
Ili kuonyesha Naive Bayes, tutatumia Gaussian Naive Bayes kwenye NSL-KDD intrusion dataset (yenye binary labels). Gaussian NB itachukulia kila feature kuwa inafuata mgawanyo wa normal kwa kila class. Hili ni chaguo la makadirio kwa sababu network features nyingi ni za discrete au zina skew kubwa, lakini linaonyesha jinsi mtu angeweza kutumia NB kwenye feature data endelevu. Pia tungeweza kuchagua Bernoulli NB kwenye dataset ya binary features (kama seti ya alerts zilizo-trigger), lakini tutaendelea kutumia NSL-KDD hapa kwa ajili ya mwendelezo.
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
Msimbo huu hufunza classifier ya Naive Bayes ili kutambua mashambulizi. Naive Bayes itakokotoa vitu kama `P(service=http | Attack)` na `P(Service=http | Normal)` kulingana na data ya mafunzo, ikidhani kuwa features hazitegemei nyingine. Kisha itatumia probabilities hizi kuainisha connections mpya kuwa za kawaida au mashambulizi, kulingana na features zilizoonekana. Utendaji wa NB kwenye NSL-KDD huenda usiwe wa juu kama wa models za kisasa zaidi (kwa kuwa independence ya features inakiukwa), lakini mara nyingi huwa mzuri na una faida ya kasi ya juu sana. Katika hali kama filtering ya email kwa wakati halisi au triage ya awali ya URLs, model ya Naive Bayes inaweza kuashiria haraka kesi zilizo wazi kuwa malicious huku ikitumia rasilimali chache.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ni mojawapo ya algorithms rahisi zaidi za machine learning. Ni method ya **non-parametric, instance-based** inayofanya predictions kulingana na ufanano na mifano iliyo kwenye training set. Wazo la classification ni hili: ili kuainisha data point mpya, tafuta points **k** zilizo karibu zaidi katika training data (yaani "nearest neighbors" wake), kisha igawie class iliyo na wengi zaidi kati ya neighbors hao. "Ukaribu" hufafanuliwa kwa distance metric, kwa kawaida Euclidean distance kwa numeric data (distances nyingine zinaweza kutumika kwa aina tofauti za features au problems).<sup>[[10]](#references)</sup>

K-NN haihitaji *training ya wazi* -- awamu ya "training" ni kuhifadhi tu dataset. Kazi yote hufanyika wakati wa query (prediction): algorithm lazima ikokotoe distances kutoka query point hadi training points zote ili kupata zilizo karibu zaidi. Hii hufanya muda wa prediction kuwa **linear kulingana na idadi ya training samples**, jambo linaloweza kuwa ghali kwa datasets kubwa. Kwa sababu hii, k-NN inafaa zaidi kwa datasets ndogo au hali ambapo unaweza kubadilisha memory na speed kwa ajili ya urahisi.

Licha ya urahisi wake, k-NN inaweza ku-model decision boundaries changamano sana (kwa kuwa kwa ufanisi decision boundary inaweza kuwa na umbo lolote linaloamuliwa na mgawanyo wa mifano). Hufanya vizuri wakati decision boundary ni irregular sana na una data nyingi -- kimsingi ikiiacha data "ijieleze yenyewe". Hata hivyo, katika dimensions nyingi, distance metrics zinaweza kupoteza maana (curse of dimensionality), na method inaweza kupata changamoto isipokuwa uwe na idadi kubwa sana ya samples.

*Use cases in cybersecurity:* k-NN imetumika katika anomaly detection -- kwa mfano, intrusion detection system inaweza kuweka network event kuwa malicious ikiwa wengi wa nearest neighbors wake (events zilizotangulia) walikuwa malicious. Ikiwa normal traffic inaunda clusters na mashambulizi ni outliers, approach ya K-NN (iliyo na k=1 au k ndogo) kimsingi huwa **nearest-neighbor anomaly detection**. K-NN pia imetumika kuainisha malware families kwa binary feature vectors: file mpya inaweza kuainishwa kuwa ya malware family fulani ikiwa iko karibu sana (katika feature space) na instances zinazojulikana za family hiyo. Kwa matumizi ya kawaida, k-NN si maarufu kama algorithms zinazoweza ku-scale zaidi, lakini ni rahisi kueleweka kimawazo na wakati mwingine hutumika kama baseline au kwa problems za kiwango kidogo.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification (na regression variants pia zipo). Ni method ya *lazy learning* -- hakuna model fitting ya wazi.

-   **Interpretability:** Chini hadi ya wastani -- hakuna global model au explanation fupi, lakini mtu anaweza kutafsiri results kwa kuangalia nearest neighbors walioathiri decision (kwa mfano, "network flow hii iliainishwa kuwa malicious kwa sababu inafanana na hizi flows 3 zinazojulikana kuwa malicious"). Kwa hiyo, explanations zinaweza kutegemea mifano.

-   **Advantages:** Ni rahisi sana ku-implement na kuelewa. Haifanyi assumptions kuhusu data distribution (non-parametric). Inaweza kushughulikia kwa kawaida multi-class problems. Ni **adaptive** kwa maana kwamba decision boundaries zinaweza kuwa changamano sana, zikiwa zimeundwa na data distribution.

-   **Limitations:** Prediction inaweza kuwa slow kwa datasets kubwa (lazima ikokotoe distances nyingi). Inatumia memory nyingi -- huhifadhi training data yote. Utendaji hupungua katika high-dimensional feature spaces kwa sababu points zote huwa karibu kuwa na distance sawa (hivyo kufanya dhana ya "nearest" ipoteze maana). Lazima uchague *k* (idadi ya neighbors) ipasavyo -- k ndogo sana inaweza kuwa noisy, na k kubwa sana inaweza kujumuisha points zisizohusika kutoka classes nyingine. Pia, features zinapaswa kuscaled ipasavyo kwa sababu distance calculations ni sensitive kwa scale.

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

Tutatumia tena NSL-KDD (binary classification). Kwa sababu k-NN ni nzito computationally, tutatumia subset ya training data ili kuifanya iweze kushughulikiwa katika demonstration hii. Tutachagua, kwa mfano, training samples 20,000 kati ya 125k yote, na kutumia neighbors k=5. Baada ya training (kwa kweli ni kuhifadhi data tu), tutafanya evaluation kwenye test set. Pia tutascalе features kwa ajili ya distance calculation ili kuhakikisha hakuna feature moja inayotawala kwa sababu ya scale.
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
Muundo wa k-NN utaainisha muunganisho kwa kuangalia miunganisho 5 iliyo karibu zaidi katika sehemu ndogo ya seti ya mafunzo. Kwa mfano, ikiwa majirani 4 kati ya hao ni mashambulizi (anomalies) na 1 ni wa kawaida, muunganisho mpya utaainishwa kama shambulizi. Utendaji unaweza kuwa mzuri, ingawa mara nyingi si wa juu kama wa Random Forest au SVM iliyowekwa vizuri kwenye data hiyo hiyo. Hata hivyo, k-NN inaweza kung'ara wakati mgawanyo wa madarasa ni usio wa kawaida na changamano sana -- kimsingi ikitumia utafutaji unaotegemea kumbukumbu. Katika cybersecurity, k-NN (ikiwa na k=1 au k ndogo) inaweza kutumika kugundua mifumo ya mashambulizi inayojulikana kwa kutumia mifano, au kama sehemu ya mifumo changamano zaidi (kwa mfano, kwa clustering na kisha kuainisha kulingana na uanachama wa cluster).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines ni miongoni mwa algorithms zenye nguvu zaidi kwa data iliyopangwa. **Gradient boosting** inarejelea mbinu ya kujenga ensemble ya weak learners (mara nyingi decision trees) kwa mpangilio wa mfululizo, ambapo kila modeli mpya husahihisha makosa ya ensemble iliyotangulia. Tofauti na bagging (Random Forests), ambayo hujenga miti kwa sambamba na kuipatia wastani, boosting hujenga miti *mmoja baada ya mwingine*, kila mmoja ukizingatia zaidi instances ambazo miti iliyotangulia ilizitabiri kimakosa.<sup>[[11]](#references)</sup>

Implementations maarufu zaidi katika miaka ya hivi karibuni ni **XGBoost**, **LightGBM**, na **CatBoost**, ambazo zote ni libraries za gradient boosting decision tree (GBDT). Zimefanikiwa sana katika mashindano na matumizi ya machine learning, mara nyingi **zikipata utendaji wa kiwango cha juu zaidi kwenye tabular datasets**. Katika cybersecurity, watafiti na wataalamu wametumia gradient boosted trees kwa kazi kama **malware detection** (kwa kutumia features zilizotolewa kutoka kwenye files au tabia za wakati wa runtime) na **network intrusion detection**. Kwa mfano, gradient boosting model inaweza kuchanganya sheria nyingi dhaifu (trees) kama vile "ikiwa kuna SYN packets nyingi na port isiyo ya kawaida -> kuna uwezekano mkubwa wa scan" na kuwa detector imara ya pamoja inayozingatia mifumo mingi midogo.

Kwa nini boosted trees zina ufanisi mkubwa? Kila tree katika mfululizo hufunzwa kwa kutumia *residual errors* (gradients) za utabiri wa ensemble ya sasa. Kwa njia hii, modeli huendelea **"boost"** maeneo ambayo ni dhaifu. Kutumia decision trees kama base learners kunamaanisha kuwa modeli ya mwisho inaweza kunasa mwingiliano changamano na mahusiano yasiyo ya mstari. Pia, boosting kwa asili ina aina ya regularization iliyojengewa ndani: kwa kuongeza miti mingi midogo (na kutumia learning rate kupima michango yao), mara nyingi hu-generalize vizuri bila overfitting kubwa, mradi parameters zinazofaa zichaguliwe.

#### **Sifa muhimu za Gradient Boosting:**

-   **Aina ya Tatizo:** Kimsingi classification na regression. Katika usalama, kwa kawaida ni classification (kwa mfano, kuainisha muunganisho au file kwa binary). Inashughulikia binary, multi-class (kwa loss inayofaa), na hata matatizo ya ranking.

-   **Uwezo wa Kuelezeka:** Wa chini hadi wa kati. Ingawa boosted tree moja ni ndogo, modeli kamili inaweza kuwa na mamia ya miti, jambo linalofanya isiwe rahisi kueleweka na binadamu kwa ujumla. Hata hivyo, kama Random Forest, inaweza kutoa alama za umuhimu wa features, na tools kama SHAP (SHapley Additive exPlanations) zinaweza kutumiwa kufasiri utabiri binafsi kwa kiwango fulani.

-   **Faida:** Mara nyingi huwa algorithm yenye **utendaji bora zaidi** kwa structured/tabular data. Inaweza kugundua mifumo na mwingiliano changamano. Ina knobs nyingi za tuning (idadi ya miti, kina cha miti, learning rate, masharti ya regularization) za kurekebisha ugumu wa modeli na kuzuia overfitting. Implementations za kisasa zimeboreshwa kwa speed (kwa mfano, XGBoost hutumia taarifa za second-order gradient na data structures zenye ufanisi). Kwa kawaida hushughulikia data isiyosawazika vizuri zaidi inapounganishwa na loss functions zinazofaa au kwa kurekebisha sample weights.

-   **Vikomo:** Ni changamano zaidi kutune kuliko models rahisi; training inaweza kuwa polepole ikiwa miti ni mirefu au idadi ya miti ni kubwa (ingawa kwa kawaida bado huwa haraka kuliko kufunza deep neural network inayolingana kwenye data hiyo hiyo). Modeli inaweza kufanya overfit ikiwa haitatune vizuri (kwa mfano, miti mingi mirefu yenye regularization isiyotosha). Kwa sababu ya hyperparameters nyingi, kutumia gradient boosting kwa ufanisi kunaweza kuhitaji utaalamu au majaribio zaidi. Pia, kama methods zinazotegemea miti, haishughulikii kwa asili data yenye sparse kubwa ya high-dimensional kwa ufanisi kama linear models au Naive Bayes (ingawa bado inaweza kutumika, kwa mfano, katika text classification, lakini huenda isiwe chaguo la kwanza bila feature engineering).

> [!TIP]
> *Matumizi katika cybersecurity:* Karibu popote ambapo decision tree au random forest inaweza kutumika, gradient boosting model inaweza kupata accuracy bora zaidi. Kwa mfano, mashindano ya **Microsoft's malware detection** yametumia sana XGBoost kwenye features zilizotengenezwa kutoka binary files. Utafiti wa **network intrusion detection** mara nyingi huripoti matokeo ya juu kwa kutumia GBDTs (kwa mfano, XGBoost kwenye datasets za CIC-IDS2017 au UNSW-NB15). Modeli hizi zinaweza kutumia features mbalimbali (aina za protocol, frequency ya matukio fulani, statistical features za traffic, n.k.) na kuziunganisha ili kugundua threats. Katika phishing detection, gradient boosting inaweza kuchanganya lexical features za URLs, domain reputation features, na page content features ili kupata accuracy ya juu sana. Mbinu ya ensemble husaidia kufunika hali nyingi za kipekee na nuances katika data.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
Tutatumia gradient boosting classifier kwenye phishing dataset. Ili kuweka mambo rahisi na kujitosheleza, tutatumia `sklearn.ensemble.GradientBoostingClassifier` (ambayo ni implementation ya polepole lakini rahisi kueleweka). Kwa kawaida, mtu anaweza kutumia libraries za `xgboost` au `lightgbm` kwa utendaji bora na features za ziada. Tutafunza modeli na kuitathmini kwa njia inayofanana na hapo awali.
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
Model ya gradient boosting huenda ikapata usahihi wa juu sana na AUC kwenye dataset hii ya phishing (mara nyingi models hizi zinaweza kuzidi usahihi wa 95% kwa tuning inayofaa kwenye data ya aina hii, kama ilivyoonekana kwenye tafiti. Hii inaonyesha kwa nini GBDTs huchukuliwa kuwa *"model ya kisasa zaidi kwa dataset za tabular"* -- mara nyingi hushinda algorithms rahisi kwa kunasa mifumo changamano.<sup>[[11]](#references)</sup> Katika muktadha wa cybersecurity, hii inaweza kumaanisha kugundua tovuti nyingi zaidi za phishing au mashambulizi mengi zaidi kwa makosa machache ya kukosa. Bila shaka, ni lazima kuwa mwangalifu kuhusu overfitting -- kwa kawaida tungetumia mbinu kama cross-validation na kufuatilia utendaji kwenye validation set tunapotengeneza model kama hiyo kwa ajili ya deployment.

</details>

### Kuchanganya Models: Ensemble Learning na Stacking

Ensemble learning ni mkakati wa **kuchanganya models nyingi** ili kuboresha utendaji wa jumla. Tayari tumeona ensemble methods maalum: Random Forest (ensemble ya trees kupitia bagging) na Gradient Boosting (ensemble ya trees kupitia sequential boosting). Lakini ensembles zinaweza kuundwa kwa njia nyingine pia, kama **voting ensembles** au **stacked generalization (stacking)**. Wazo kuu ni kwamba models tofauti zinaweza kunasa mifumo tofauti au kuwa na udhaifu tofauti; kwa kuziunganisha, tunaweza **kufidia makosa ya kila model kwa nguvu za nyingine**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Katika voting classifier rahisi, tunatrain models nyingi zenye utofauti (kwa mfano, logistic regression, decision tree, na SVM) na kuziruhusu zipige kura kuhusu utabiri wa mwisho (kura nyingi kwa classification). Tukipima uzito wa kura (kwa mfano, kuipa models sahihi zaidi uzito mkubwa), hiyo huwa weighted voting scheme. Kwa kawaida hii huboresha utendaji wakati models binafsi ni nzuri kwa kiwango kinachofaa na zinajitegemea -- ensemble hupunguza hatari ya kosa la model moja kwa kuwa nyingine zinaweza kulisahihisha. Ni kama kuwa na jopo la experts badala ya maoni ya mtu mmoja.

-   **Stacking (Stacked Ensemble):** Stacking huenda hatua moja zaidi. Badala ya kura rahisi, hutraining **meta-model** ili **kujifunza jinsi bora ya kuchanganya predictions** za base models. Kwa mfano, unatrain classifiers 3 tofauti (base learners), kisha unaingiza outputs zao (au probabilities) kama features kwenye meta-classifier (mara nyingi model rahisi kama logistic regression) inayojifunza njia bora ya kuzichanganya. Meta-model hutraining kwenye validation set au kupitia cross-validation ili kuzuia overfitting. Stacking mara nyingi inaweza kushinda voting rahisi kwa kujifunza *ni models zipi za kuamini zaidi katika hali zipi*. Katika cybersecurity, model moja inaweza kuwa bora katika kugundua network scans, huku nyingine ikiwa bora katika kugundua malware beaconing; stacking model inaweza kujifunza kutegemea kila moja kwa njia inayofaa.

Ensembles, iwe kupitia voting au stacking, kwa kawaida **huongeza usahihi** na robustness. Hasara yake ni kuongezeka kwa complexity na wakati mwingine kupungua kwa interpretability (ingawa ensemble approaches kama wastani wa decision trees bado zinaweza kutoa maarifa fulani, kwa mfano, feature importance). Kwa vitendo, ikiwa operational constraints zinaruhusu, kutumia ensemble kunaweza kusababisha detection rates za juu zaidi. Solutions nyingi zinazoshinda katika changamoto za cybersecurity (na mashindano ya Kaggle kwa ujumla) hutumia ensemble techniques ili kupata ongezeko la mwisho la utendaji.

<details>
<summary>Example -- Voting Ensemble kwa Phishing Detection:</summary>
Ili kuonyesha model stacking, tuchanganye baadhi ya models tulizojadili kwenye phishing dataset. Tutatumia logistic regression, decision tree, na k-NN kama base learners, na kutumia Random Forest kama meta-learner wa kujumlisha predictions zao. Meta-learner itatraining kwenye outputs za base learners (kwa kutumia cross-validation kwenye training set). Tunatarajia stacked model ifanye kazi kwa kiwango sawa na au bora kidogo kuliko models binafsi.
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
Stacked ensemble inanufaika na nguvu zinazokamilishana za base models. Kwa mfano, logistic regression inaweza kushughulikia vipengele vya linear vya data, decision tree inaweza kunasa mwingiliano maalum unaofanana na rules, na k-NN inaweza kufanya vizuri katika maeneo ya karibu ya feature space. Meta-model (random forest hapa) inaweza kujifunza jinsi ya kupima uzito wa inputs hizi. Metrics zinazotokana mara nyingi huonyesha uboreshaji (hata kama ni mdogo) ikilinganishwa na metrics za model yoyote moja. Katika mfano wetu wa phishing, ikiwa logistic pekee ilikuwa na F1 ya, tuseme, 0.95 na tree ilikuwa na 0.94, stack inaweza kufikia 0.96 kwa kubaini maeneo ambayo kila model hukosea.

Ensemble methods kama hii zinaonyesha kanuni kwamba *"kuchanganya models nyingi kwa kawaida husababisha generalization bora"*.<sup>[[12]](#references)</sup> Katika cybersecurity, hii inaweza kutekelezwa kwa kuwa na detection engines nyingi (moja inaweza kuwa rule-based, nyingine machine learning, na nyingine anomaly-based), kisha kuwa na layer inayokusanya alerts zao -- kwa ufanisi ikiwa ni aina ya ensemble -- ili kufanya uamuzi wa mwisho kwa confidence ya juu zaidi. Wakati wa ku-deploy mifumo kama hii, ni lazima kuzingatia complexity iliyoongezwa na kuhakikisha kuwa ensemble haiwi ngumu sana ku-manage au ku-explain. Lakini kwa mtazamo wa accuracy, ensembles na stacking ni tools zenye nguvu za kuboresha performance ya model.

</details>

## Marejeo

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
