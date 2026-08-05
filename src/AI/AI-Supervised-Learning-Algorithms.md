# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basic Information

Supervised learning hutumia data iliyo na labels kufunza models zinazoweza kufanya utabiri kuhusu inputs mpya ambazo hazijawahi kuonekana. Katika cybersecurity, supervised machine learning hutumiwa kwa upana katika kazi kama vile intrusion detection (kuainisha network traffic kuwa *normal* au *attack*), malware detection (kutofautisha software hasidi na software salama), phishing detection (kutambua websites au emails za ulaghai), na spam filtering, miongoni mwa nyingine. Kila algorithm ina nguvu zake na inafaa kwa aina tofauti za matatizo (classification au regression). Hapa chini tunapitia supervised learning algorithms muhimu, tunaeleza jinsi zinavyofanya kazi, na kuonyesha matumizi yake kwenye cybersecurity datasets halisi. Pia tunajadili jinsi kuchanganya models (ensemble learning) kunavyoweza mara nyingi kuboresha predictive performance.

## Algorithms

-   **Linear Regression:** Regression algorithm ya msingi ya kutabiri matokeo ya nambari kwa kufit equation ya linear kwenye data.

-   **Logistic Regression:** Classification algorithm (licha ya jina lake) inayotumia logistic function ku-model uwezekano wa binary outcome.

-   **Decision Trees:** Models zenye muundo wa mti zinazogawanya data kulingana na features ili kufanya utabiri; mara nyingi hutumiwa kwa sababu ya interpretability yake.

-   **Random Forests:** Ensemble ya decision trees (kupitia bagging) inayoboresha accuracy na kupunguza overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers zinazopata separating hyperplane bora zaidi; zinaweza kutumia kernels kwa data isiyo ya linear.

-   **Naive Bayes:** Probabilistic classifier inayotegemea Bayes' theorem pamoja na dhana kwamba features hazitegemei zenyewe, na hutumiwa maarufu katika spam filtering.

-   **k-Nearest Neighbors (k-NN):** Classifier rahisi ya "instance-based" inayoweka label kwenye sample kulingana na class iliyo nyingi zaidi miongoni mwa nearest neighbors wake.

-   **Gradient Boosting Machines:** Ensemble models (kwa mfano, XGBoost, LightGBM) zinazounda predictor imara kwa kuongeza weaker learners mmoja baada ya mwingine (kwa kawaida decision trees).

Kila sehemu hapa chini inatoa maelezo yaliyoboreshwa ya algorithm na **Python code example** kwa kutumia libraries kama `pandas` na `scikit-learn` (na `PyTorch` kwa mfano wa neural network). Examples zinatumia cybersecurity datasets zinazopatikana hadharani (kama NSL-KDD kwa intrusion detection na Phishing Websites dataset) na zinafuata muundo unaofanana:

1.  **Load the dataset** (ipakue kupitia URL ikiwa inapatikana).

2.  **Preprocess the data** (kwa mfano, encode categorical features, scale values, na gawanya data kuwa train/test sets).

3.  **Train the model** kwenye training data.

4.  **Evaluate** kwenye test set kwa kutumia metrics: accuracy, precision, recall, F1-score, na ROC AUC kwa classification (na mean squared error kwa regression).

Hebu tuchunguze kila algorithm:

### Linear Regression

Linear regression ni **regression** algorithm inayotumiwa kutabiri numeric values zinazoendelea. Inachukulia kuwa kuna uhusiano wa linear kati ya input features (independent variables) na output (dependent variable). Model hujaribu kufit straight line (au hyperplane katika dimensions za juu zaidi) inayoeleza vizuri zaidi uhusiano kati ya features na target. Kwa kawaida hili hufanywa kwa kupunguza jumla ya squared errors kati ya values zilizotabiriwa na zile halisi (Ordinary Least Squares method).<sup>[[8]](#references)</sup>

Njia rahisi zaidi ya kuwakilisha linear regression ni kwa kutumia mstari:
```plaintext
y = mx + b
```
Ambapo:

- `y` ni thamani iliyotabiriwa (output)
- `m` ni mteremko wa mstari (coefficient)
- `x` ni kipengele cha input
- `b` ni y-intercept

Lengo la linear regression ni kupata mstari unaolingana vizuri zaidi na ambao hupunguza tofauti kati ya thamani zilizotabiriwa na thamani halisi katika dataset. Bila shaka, hii ni rahisi sana; ungekuwa mstari ulionyooka unaotenganisha kategoria 2, lakini vipimo zaidi vinapoongezwa, mstari huwa changamano zaidi:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Matumizi katika cybersecurity:* Linear regression yenyewe haitumiki sana katika kazi kuu za usalama (ambazo mara nyingi ni classification), lakini inaweza kutumika kutabiri matokeo ya nambari. Kwa mfano, mtu anaweza kutumia linear regression **kutabiri kiasi cha network traffic** au **kukadiria idadi ya mashambulizi katika kipindi fulani** kwa kutumia data ya kihistoria. Pia inaweza kutabiri risk score au muda unaotarajiwa hadi shambulizi ligunduliwe, kutokana na vipimo fulani vya mfumo. Kwa vitendo, classification algorithms (kama logistic regression au trees) hutumiwa mara nyingi zaidi kugundua intrusions au malware, lakini linear regression hutumika kama msingi na ni muhimu kwa uchanganuzi unaolenga regression.

#### **Sifa kuu za Linear Regression:**

-   **Aina ya Tatizo:** Regression (kutabiri thamani zinazoendelea). Haifai kwa classification ya moja kwa moja isipokuwa threshold itumike kwenye output.

-   **Urahisi wa Kufasiri:** Juu -- coefficients ni rahisi kufasiri, zikionyesha athari ya mstari ya kila feature.

-   **Faida:** Rahisi na ya haraka; baseline nzuri kwa kazi za regression; hufanya kazi vizuri wakati uhusiano halisi unaelekea kuwa wa mstari.

-   **Vikwazo:** Haiwezi kushughulikia uhusiano changamano au usio wa mstari (bila manual feature engineering); inaweza kusababisha underfitting ikiwa uhusiano si wa mstari; huathiriwa na outliers, ambazo zinaweza kupotosha matokeo.

-   **Kupata Ulinganifu Bora:** Ili kupata mstari wenye ulinganifu bora unaotenganisha categories zinazowezekana, tunatumia mbinu inayoitwa **Ordinary Least Squares (OLS)**. Mbinu hii hupunguza jumla ya tofauti zilizowekwa kwenye mraba kati ya thamani zilizozingatiwa na thamani zinazotabiriwa na linear model.

<details>
<summary>Example -- Kutabiri Muda wa Connection (Regression) katika Dataset ya Intrusion
</summary>
Hapa chini tunaonyesha matumizi ya linear regression kwa kutumia dataset ya cybersecurity ya NSL-KDD. Tutachukulia hili kama tatizo la regression kwa kutabiri `duration` ya connections za mtandao kwa kutumia features nyingine. (Kwa uhalisia, `duration` ni feature mojawapo ya NSL-KDD; tunaitumia hapa kwa ajili ya kuonyesha regression.) Tunapakia dataset, tunaiandaa awali (kwa ku-encode features za categorical), tunafundisha linear regression model, na kutathmini Mean Squared Error (MSE) pamoja na R² score kwenye test set.
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
Katika mfano huu, modeli ya linear regression inajaribu kutabiri `duration` ya muunganisho kutokana na vipengele vingine vya mtandao. Tunapima utendaji kwa kutumia Mean Squared Error (MSE) na R². R² iliyo karibu na 1.0 ingeashiria kuwa modeli inaeleza sehemu kubwa ya tofauti katika `duration`, ilhali R² ya chini au hasi inaashiria ulinganifu dhaifu. (Usishangae ikiwa R² ni ya chini hapa -- kutabiri `duration` kunaweza kuwa kugumu kutokana na vipengele vilivyotolewa, na linear regression huenda isichukue mifumo hiyo ikiwa ni changamano.)
</details>

### Logistic Regression

Logistic regression ni algorithm ya **classification** inayounda modeli ya uwezekano kwamba instance ni ya class fulani (kwa kawaida class ya "positive"). Licha ya jina lake, *logistic* regression hutumiwa kwa matokeo ya kipekee (tofauti na linear regression, ambayo hutumiwa kwa matokeo endelevu). Hutumiwa hasa kwa **binary classification** (classes mbili, kwa mfano, malicious dhidi ya benign), lakini inaweza kupanuliwa kwa matatizo yenye classes nyingi (kwa kutumia mbinu za softmax au one-vs-rest).<sup>[[1]](#references)</sup>

Logistic regression hutumia logistic function (pia hujulikana kama sigmoid function) kubadilisha thamani zilizotabiriwa kuwa probabilities. Kumbuka kuwa sigmoid function ni function yenye thamani kati ya 0 na 1 inayokua kwa mkunjo wa umbo la S kulingana na mahitaji ya classification, jambo ambalo ni muhimu kwa binary classification tasks. Kwa hiyo, kila feature ya kila input huzidishwa kwa weight yake iliyokabidhiwa, na matokeo hupitishwa kupitia sigmoid function ili kutoa probability:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` ni uwezekano kwamba output `y` ni 1 kutokana na input `x`
- `e` ni msingi wa logarithm ya asili
- `z` ni mchanganyiko wa mstari wa vipengele vya input, kwa kawaida huwakilishwa kama `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Kumbuka kwamba katika hali yake rahisi zaidi ni mstari ulionyooka, lakini katika hali changamano zaidi huwa hyperplane yenye dimensions kadhaa (moja kwa kila kipengele).

> [!TIP]
> *Matumizi katika cybersecurity:* Kwa sababu matatizo mengi ya usalama kimsingi ni maamuzi ya ndiyo/hapana, Logistic Regression hutumiwa sana. Kwa mfano, mfumo wa intrusion detection unaweza kutumia Logistic Regression kuamua kama muunganisho wa mtandao ni attack kulingana na vipengele vya muunganisho huo. Katika phishing detection, Logistic Regression inaweza kuunganisha vipengele vya website (urefu wa URL, uwepo wa alama ya "@", n.k.) na kuvibadilisha kuwa uwezekano wa kuwa phishing. Imetumika katika spam filters za kizazi cha awali na bado ni baseline thabiti kwa kazi nyingi za classification.

#### Logistic Regression kwa classification isiyo ya binary

Logistic Regression imeundwa kwa binary classification, lakini inaweza kupanuliwa kushughulikia matatizo ya multi-class kwa kutumia mbinu kama **one-vs-rest** (OvR) au **softmax regression**. Katika OvR, model tofauti ya Logistic Regression hufunzwa kwa kila class, ambapo class hiyo inachukuliwa kuwa positive class dhidi ya class nyingine zote. Class yenye probability iliyotabiriwa kuwa kubwa zaidi huchaguliwa kama prediction ya mwisho. Softmax regression hujumlisha Logistic Regression kwa classes nyingi kwa kutumia softmax function kwenye output layer, na kutengeneza probability distribution katika classes zote.

#### **Sifa kuu za Logistic Regression:**

-   **Aina ya Tatizo:** Classification (kwa kawaida binary). Hutabiri probability ya positive class.

-   **Urahisi wa Kutafsiri:** Juu -- kama ilivyo kwa linear regression, coefficients za features zinaweza kuonyesha jinsi kila feature inavyoathiri log-odds ya matokeo. Uwazi huu huthaminiwa mara nyingi katika usalama kwa kuelewa ni vipengele gani vinavyochangia alert.

-   **Faida:** Ni rahisi na ya haraka kufunza; hufanya kazi vizuri wakati uhusiano kati ya features na log-odds ya matokeo ni wa mstari. Hutoa probabilities, hivyo kuwezesha risk scoring. Kwa regularization inayofaa, hu-generalize vizuri na inaweza kushughulikia multicollinearity vizuri zaidi kuliko plain linear regression.

-   **Vikwazo:** Huchukulia kuwa decision boundary katika feature space ni ya mstari (hufeli ikiwa boundary halisi ni changamano/isiyo ya mstari). Inaweza kufanya vibaya kwenye matatizo ambapo interactions au non-linear effects ni muhimu, isipokuwa uongeze mwenyewe polynomial au interaction features. Pia, Logistic Regression haifanyi kazi vizuri ikiwa classes haziwezi kutenganishwa kwa urahisi na mchanganyiko wa mstari wa features.


<details>
<summary>Example -- Phishing Website Detection with Logistic Regression:</summary>

Tutatumia **Phishing Websites Dataset** (kutoka kwenye repository ya UCI), ambayo ina features zilizotolewa kutoka kwenye websites (kama kama URL ina IP address, umri wa domain, uwepo wa vipengele vya kutiliwa shaka katika HTML, n.k.) pamoja na label inayoonyesha kama site ni phishing au halali. Tutafunza model ya Logistic Regression ili ku-classify websites, kisha tutathmini accuracy, precision, recall, F1-score, na ROC AUC yake kwenye test split.
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
Katika mfano huu wa kugundua phishing, logistic regression hutoa uwezekano kwa kila website kuwa phishing. Kwa kutathmini accuracy, precision, recall, na F1, tunapata picha ya utendaji wa model. Kwa mfano, recall ya juu ingemaanisha kuwa inagundua tovuti nyingi za phishing (jambo muhimu kwa usalama ili kupunguza mashambulizi yaliyokosa kugunduliwa), huku precision ya juu ikimaanisha kuwa ina false alarms chache (jambo muhimu ili kuepuka uchovu wa wachambuzi). ROC AUC (Area Under the ROC Curve) hutoa kipimo cha utendaji kisichotegemea threshold (1.0 ni bora, 0.5 si bora kuliko kubahatisha). Logistic regression mara nyingi hufanya vizuri katika kazi kama hizi, lakini ikiwa decision boundary kati ya tovuti za phishing na halali ni changamano, model zenye nguvu zaidi zisizo za mstari zinaweza kuhitajika.

</details>

### Decision Trees

Decision tree ni **algoritmu ya supervised learning** inayoweza kutumika kwa kazi za classification na regression. Hujifunza model ya maamuzi yenye muundo wa mti wa kihierarkia kulingana na features za data. Kila internal node ya mti huwakilisha jaribio kwenye feature fulani, kila branch huwakilisha matokeo ya jaribio hilo, na kila leaf node huwakilisha class iliyotabiriwa (kwa classification) au value (kwa regression).<sup>[[2]](#references)</sup>

Ili kujenga mti, algorithms kama CART (Classification and Regression Tree) hutumia vipimo kama **Gini impurity** au **information gain (entropy)** kuchagua feature bora na threshold ya kugawanya data katika kila hatua. Lengo katika kila mgawanyo ni kugawa data ili kuongeza homogeneity ya target variable katika subsets zinazotokana (kwa classification, kila node hulenga kuwa pure iwezekanavyo, ikiwa na class moja kwa kiasi kikubwa).

Decision trees ni **rahisi sana kufasiriwa** -- mtu anaweza kufuata njia kutoka root hadi leaf ili kuelewa mantiki ya prediction (kwa mfano, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Hili ni muhimu katika cybersecurity kwa kueleza kwa nini alert fulani ilitolewa. Trees zinaweza kushughulikia kwa kawaida data za nambari na za categorical, na zinahitaji preprocessing kidogo (kwa mfano, feature scaling haihitajiki).

Hata hivyo, decision tree moja inaweza kufanya overfit kwa urahisi kwenye training data, hasa ikiwa imekuzwa kwa kina (ikiwa na splits nyingi). Mbinu kama pruning (kupunguza kina cha mti au kuhitaji idadi ya chini ya samples kwa kila leaf) hutumiwa mara nyingi kuzuia overfitting.

Kuna components 3 kuu za decision tree:
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
> *Matumizi katika cybersecurity:* Decision trees zimetumika katika intrusion detection systems ili kupata **rules** za kutambua attacks. Kwa mfano, IDS za awali zilizotegemea ID3/C4.5 zilitengeneza rules zinazosomwa na binadamu ili kutofautisha traffic ya kawaida na traffic hasidi. Pia hutumika katika malware analysis kuamua kama file ni hasidi kulingana na sifa zake (ukubwa wa file, section entropy, API calls, n.k.). Uwazi wa decision trees huzifanya ziwe muhimu wakati transparency inahitajika -- analyst anaweza kukagua tree ili kuthibitisha logic ya detection.

#### **Sifa kuu za Decision Trees:**

-   **Aina ya Tatizo:** Classification na regression. Hutumika mara nyingi kwa classification ya attacks dhidi ya traffic ya kawaida, n.k.

-   **Uwezo wa Kueleweka:** Juu sana -- maamuzi ya model yanaweza kuonyeshwa na kueleweka kama seti ya if-then rules. Hii ni faida kubwa katika security kwa ajili ya trust na verification ya tabia ya model.

-   **Faida:** Zinaweza kubaini mahusiano yasiyo ya mstari na interactions kati ya features (kila split inaweza kuonekana kama interaction). Hakuna haja ya kuscale features au kufanya one-hot encoding ya categorical variables -- trees hushughulikia hizo natively. Inference ni ya haraka (prediction ni kufuata tu njia katika tree).

-   **Vikwazo:** Zinaweza kufanya overfitting ikiwa hazitadhibitiwa (tree yenye kina kirefu inaweza kuhifadhi training set nzima). Zinaweza kuwa unstable -- mabadiliko madogo katika data yanaweza kusababisha muundo tofauti wa tree. Kama models za pekee, accuracy yake huenda isilingane na methods za kisasa zaidi (ensembles kama Random Forests kwa kawaida hufanya vizuri zaidi kwa kupunguza variance).

-   **Kupata Split Bora:**
- **Gini Impurity**: Hupima impurity ya node. Gini impurity ya chini huashiria split bora zaidi. Formula ni:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Ambapo `p_i` ni uwiano wa instances zilizo katika class `i`.

- **Entropy**: Hupima uncertainty katika dataset. Entropy ya chini huashiria split bora zaidi. Formula ni:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Ambapo `p_i` ni uwiano wa instances zilizo katika class `i`.

- **Information Gain**: Ni upunguzaji wa entropy au Gini impurity baada ya split. Kadiri information gain inavyokuwa kubwa, ndivyo split inavyokuwa bora zaidi. Huhesabiwa kama:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Zaidi ya hayo, tree hukoma wakati:
- Instances zote katika node ni za class moja. Hii inaweza kusababisha overfitting.
- Maximum depth (iliyoandikwa moja kwa moja kwenye code) ya tree imefikiwa. Hii ni njia ya kuzuia overfitting.
- Idadi ya instances katika node iko chini ya threshold fulani. Hii pia ni njia ya kuzuia overfitting.
- Information gain kutoka kwa splits zaidi iko chini ya threshold fulani. Hii pia ni njia ya kuzuia overfitting.

<details>
<summary>Example -- Decision Tree for Intrusion Detection:</summary>
Tutafunza decision tree kwa kutumia dataset ya NSL-KDD ili ku-classify network connections kama *normal* au *attack*. NSL-KDD ni toleo lililoboreshwa la dataset maarufu ya KDD Cup 1999, lenye features kama protocol type, service, duration, idadi ya failed logins, n.k., pamoja na label inayoonyesha aina ya attack au "normal". Tutapanga aina zote za attacks katika class ya "anomaly" (binary classification: normal dhidi ya anomaly). Baada ya training, tutatathmini performance ya tree kwenye test set.
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
Katika mfano huu wa decision tree, tulipunguza kina cha tree hadi 10 ili kuepuka overfitting uliokithiri (parameter ya `max_depth=10`). Metrics zinaonyesha jinsi tree inavyotofautisha traffic ya kawaida dhidi ya ya mashambulizi. Recall ya juu ingemaanisha kwamba inagundua mashambulizi mengi (jambo muhimu kwa IDS), huku precision ya juu ikimaanisha alerts chache za uongo. Decision trees mara nyingi hupata accuracy nzuri kwenye data iliyopangwa, lakini tree moja huenda isifike kwenye performance bora zaidi inayowezekana. Hata hivyo, *interpretability* ya model ni faida kubwa -- tunaweza kuchunguza splits za tree ili kuona, kwa mfano, ni features zipi (k.m., `service`, `src_bytes`, n.k.) zina ushawishi mkubwa zaidi katika kuashiria connection kuwa malicious.

</details>

### Random Forests

Random Forest ni mbinu ya **ensemble learning** inayojengwa juu ya decision trees ili kuboresha performance. Random forest hufunza decision trees nyingi (ndiyo maana ya "forest") na kuunganisha outputs zake ili kutoa prediction ya mwisho (kwa classification, kwa kawaida kwa majority vote). Mawazo mawili makuu katika random forest ni **bagging** (bootstrap aggregating) na **feature randomness**:

-   **Bagging:** Kila tree hufunzwa kwa kutumia random bootstrap sample ya training data (iliyochukuliwa kwa replacement). Hii huleta diversity miongoni mwa trees.

-   **Feature Randomness:** Katika kila split ya tree, subset ya features huchaguliwa kwa random kwa ajili ya splitting (badala ya kutumia features zote). Hii hutenganisha zaidi correlations kati ya trees.

Kwa kukadiria wastani wa matokeo ya trees nyingi, random forest hupunguza variance ambayo decision tree moja inaweza kuwa nayo. Kwa maneno rahisi, trees binafsi zinaweza kufanya overfit au kutoa noise, lakini trees nyingi zenye diversity zinazopiga kura pamoja husawazisha makosa hayo. Matokeo yake mara nyingi ni model yenye **accuracy ya juu** na generalization bora kuliko decision tree moja. Zaidi ya hayo, random forests zinaweza kutoa makadirio ya feature importance (kwa kuangalia kiasi ambacho kila feature split hupunguza impurity kwa wastani).

Random forests zimekuwa **workhorse katika cybersecurity** kwa tasks kama intrusion detection, malware classification, na spam detection. Mara nyingi hufanya vizuri out-of-the-box bila tuning kubwa na zinaweza kushughulikia feature sets kubwa. Kwa mfano, katika intrusion detection, random forest inaweza kuishinda decision tree binafsi kwa kugundua patterns fiche zaidi za mashambulizi na false positives chache. Utafiti umeonyesha random forests zikifanya vizuri ikilinganishwa na algorithms nyingine katika ku-classify mashambulizi kwenye datasets kama NSL-KDD na UNSW-NB15.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Sifa kuu za Random Forests:**

-   **Aina ya Tatizo:** Hasa classification (hutumika pia kwa regression). Inafaa sana kwa data iliyopangwa yenye dimensions nyingi, ambayo ni ya kawaida katika security logs.

-   **Interpretability:** Ni ya chini kuliko decision tree moja -- huwezi ku-visualize au kueleza kwa urahisi trees mamia kwa wakati mmoja. Hata hivyo, feature importance scores hutoa mwanga kuhusu attributes zipi zina ushawishi mkubwa zaidi.

-   **Faida:** Kwa ujumla huwa na accuracy ya juu kuliko models za tree moja kutokana na athari ya ensemble. Ni robust dhidi ya overfitting -- hata kama trees binafsi zinafanya overfit, ensemble hufanya generalization vizuri zaidi. Hushughulikia features za numerical na categorical na inaweza kushughulikia missing data kwa kiwango fulani. Pia ni robust kwa outliers kwa kiasi.

-   **Vikwazo:** Ukubwa wa model unaweza kuwa mkubwa (trees nyingi, ambazo kila moja inaweza kuwa na kina kirefu). Predictions ni za polepole kuliko za tree moja (kwa sababu lazima u-aggregate juu ya trees nyingi). Ina interpretability ndogo -- ingawa unajua features muhimu, logic kamili si rahisi kufuatilia kama rule rahisi. Ikiwa dataset ina dimensions nyingi sana na ni sparse, kufunza forest kubwa sana kunaweza kuwa mzigo wa computational.

-   **Mchakato wa Training:**
1. **Bootstrap Sampling**: Chukua sample ya training data kwa random ukiwa na replacement ili kuunda subsets nyingi (bootstrap samples).
2. **Tree Construction**: Kwa kila bootstrap sample, jenga decision tree ukitumia subset ya features iliyochaguliwa kwa random katika kila split. Hii huleta diversity miongoni mwa trees.
3. **Aggregation**: Kwa tasks za classification, prediction ya mwisho hutolewa kwa kuchukua majority vote kati ya predictions za trees zote. Kwa tasks za regression, prediction ya mwisho ni wastani wa predictions kutoka kwa trees zote.

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
Tutatumia dataset ileile ya NSL-KDD (iliyo na labels mbili: normal dhidi ya anomaly) na kufunza Random Forest classifier. Tunatarajia random forest ifanye vizuri sawa na au zaidi ya decision tree moja, kutokana na ensemble averaging inayopunguza variance. Tutaitathmini kwa metrics zilezile.
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
Random forest kwa kawaida hupata matokeo mazuri kwenye task hii ya intrusion detection. Tunaweza kuona uboreshaji katika metrics kama F1 au AUC ikilinganishwa na decision tree moja, hasa katika recall au precision, kulingana na data. Hii inaendana na uelewa kwamba *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*. Katika muktadha wa security operations, random forest model inaweza kutambua attacks kwa kutegemewa zaidi huku ikipunguza false alarms, kutokana na wastani wa decision rules nyingi. Feature importance kutoka kwenye forest inaweza kutuonyesha ni network features zipi zinazoashiria zaidi attacks (kwa mfano, network services fulani au idadi zisizo za kawaida za packets).

</details>

### Support Vector Machines (SVM)

Support Vector Machines ni supervised learning models zenye nguvu zinazotumika hasa kwa classification (na pia regression kama SVR). SVM hujaribu kupata **optimal separating hyperplane** inayoongeza margin kati ya classes mbili. Ni sehemu ndogo tu ya training points (zinazoitwa "support vectors", zilizo karibu zaidi na boundary) huamua nafasi ya hyperplane hii. Kwa kuongeza margin (umbali kati ya support vectors na hyperplane), SVM huwa na uwezo mzuri wa generalization.<sup>[[4]](#references)</sup>

Jambo muhimu linaloipa SVM nguvu ni uwezo wa kutumia **kernel functions** kushughulikia mahusiano yasiyo ya linear. Data inaweza kubadilishwa kwa njia isiyo ya moja kwa moja kuwa feature space yenye dimensions nyingi zaidi, ambako linear separator inaweza kuwepo. Kernels zinazotumika sana zinajumuisha polynomial, radial basis function (RBF), na sigmoid. Kwa mfano, ikiwa classes za network traffic haziwezi kutenganishwa kwa linear katika raw feature space, RBF kernel inaweza kuzipeleka kwenye dimension ya juu zaidi ambako SVM hupata linear split (ambayo inalingana na non-linear boundary katika original space). Uwezo wa kuchagua kernels huwezesha SVM kushughulikia aina mbalimbali za matatizo.

SVM zinajulikana kufanya vizuri katika hali zenye high-dimensional feature spaces (kama text data au malware opcode sequences) na katika hali ambapo idadi ya features ni kubwa ikilinganishwa na idadi ya samples. Zilitumika sana katika applications nyingi za awali za cybersecurity kama malware classification na anomaly-based intrusion detection katika miaka ya 2000, mara nyingi zikionyesha accuracy ya juu.

Hata hivyo, SVM hazis scale kwa urahisi kwenye datasets kubwa sana (training complexity ni super-linear kulingana na idadi ya samples, na matumizi ya memory yanaweza kuwa makubwa kwa sababu huenda ikahitaji kuhifadhi support vectors nyingi). Kwa vitendo, katika tasks kama network intrusion detection yenye mamilioni ya records, SVM inaweza kuwa slow sana bila kutumia subsampling kwa uangalifu au approximate methods.

#### **Sifa muhimu za SVM:**

-   **Aina ya Tatizo:** Classification (binary au multiclass kupitia one-vs-one/one-vs-rest) na regression variants. Mara nyingi hutumika katika binary classification yenye clear margin separation.

-   **Interpretability:** Medium -- SVM hazieleweki kwa urahisi kama decision trees au logistic regression. Ingawa unaweza kutambua ni data points zipi ni support vectors na kupata wazo fulani la features zinazoweza kuwa na ushawishi (kupitia weights katika hali ya linear kernel), kwa vitendo SVM (hasa zenye non-linear kernels) huchukuliwa kama black-box classifiers.

-   **Faida:** Zinafaa katika high-dimensional spaces; zinaweza kuunda complex decision boundaries kwa kutumia kernel trick; ni imara dhidi ya overfitting ikiwa margin imeongezwa (hasa kwa regularization parameter C inayofaa); hufanya vizuri hata classes zikiwa hazijatenganishwa kwa umbali mkubwa (hupata boundary bora ya maelewano).

-   **Vikwazo:** **Computationally intensive** kwa datasets kubwa (training na prediction scale vibaya data inapoongezeka). Zinahitaji tuning ya uangalifu ya kernel na regularization parameters (C, kernel type, gamma kwa RBF, n.k.). Hazitoi moja kwa moja probabilistic outputs (ingawa unaweza kutumia Platt scaling kupata probabilities). Pia, SVM zinaweza kuathiriwa na uchaguzi wa kernel parameters --- uchaguzi mbaya unaweza kusababisha underfit au overfit.

*Matumizi katika cybersecurity:* SVM zimetumika katika **malware detection** (kwa mfano, ku-classify files kulingana na extracted features au opcode sequences), **network anomaly detection** (ku-classify traffic kama normal au malicious), na **phishing detection** (kwa kutumia features za URLs). Kwa mfano, SVM inaweza kutumia features za email (idadi za keywords fulani, sender reputation scores, n.k.) na kui-classify kama phishing au legitimate. Pia zimetumika katika **intrusion detection** kwenye feature sets kama KDD, mara nyingi zikifikia accuracy ya juu kwa gharama ya computation.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Tutatumia tena phishing website dataset, safari hii kwa kutumia SVM. Kwa sababu SVM zinaweza kuwa slow, tutatumia subset ya data kwa training ikiwa itahitajika (dataset ina takriban instances 11k, ambayo SVM inaweza kushughulikia kwa kiwango kinachofaa). Tutatumia RBF kernel ambayo ni chaguo linalotumika sana kwa non-linear data, na tutawezesha probability estimates ili kuhesabu ROC AUC.
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
Muundo wa SVM utatoa vipimo ambavyo tunaweza kulinganisha na Logistic Regression kwenye kazi hiyo hiyo. Tunaweza kugundua kuwa SVM inapata usahihi wa juu na AUC ikiwa data imetenganishwa vizuri na vipengele. Kwa upande mwingine, ikiwa dataset ilikuwa na kelele nyingi au classes zinazopishana, SVM huenda isizidi Logistic Regression kwa kiasi kikubwa. Kwa matumizi ya vitendo, SVM inaweza kutoa uboreshaji wakati kuna mahusiano changamano yasiyo ya mstari kati ya vipengele na class -- kernel ya RBF inaweza kunasa mipaka ya maamuzi iliyopinda ambayo Logistic Regression isingeweza kunasa. Kama ilivyo kwa miundo yote, `C` (regularization) na vigezo vya kernel (kama `gamma` kwa RBF) vinahitaji kusanidiwa kwa uangalifu ili kusawazisha bias na variance.

</details>

#### Tofauti kati ya Logistic Regression na SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Hupunguza **log‑loss** (cross-entropy). | Huongeza **margin** huku ikipunguza **hinge‑loss**. |
| **Decision boundary** | Hupata **best-fit hyperplane** inayomodeli _P(y\|x)_. | Hupata **maximum-margin hyperplane** (pengo kubwa zaidi hadi kwenye pointi zilizo karibu zaidi). |
| **Output** | **Probabilistic** – hutoa uwezekano wa classes uliosawazishwa kupitia σ(w·x + b). | **Deterministic** – hurejesha labels za classes; uwezekano huhitaji kazi ya ziada (kwa mfano Platt scaling). |
| **Regularisation** | L2 (default) au L1, husawazisha moja kwa moja under/over-fitting. | Kigezo cha C husawazisha upana wa margin dhidi ya makosa ya classification; vigezo vya kernel huongeza uchangamano. |
| **Kernels / Non‑linear** | Fomu ya asili ni **linear**; non-linearity huongezwa kupitia feature engineering. | **Kernel trick** iliyojengeka ndani (RBF, poly, n.k.) huiruhusu kumodeli mipaka changamano katika nafasi ya high-dimensional. |
| **Scalability** | Hutatua convex optimisation katika **O(nd)**; hushughulikia n kubwa sana vizuri. | Training inaweza kuwa na **O(n²–n³)** ya memory/time bila specialised solvers; haifai sana kwa n kubwa mno. |
| **Interpretability** | **Juu** – weights huonyesha ushawishi wa feature; odds ratio ni rahisi kueleweka. | **Chini** kwa kernels zisizo za mstari; support vectors ni sparse lakini si rahisi kueleza. |
| **Sensitivity to outliers** | Hutumia log-loss laini → huwa na sensitivity ndogo. | Hinge-loss yenye hard margin inaweza kuwa na **sensitivity**; soft-margin (C) hupunguza athari hiyo. |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – ambapo **probabilities & explainability** ni muhimu. | Image/text classification, bio-informatics – ambapo **complex boundaries** na **high-dimensional data** ni muhimu. |

* **Ikiwa unahitaji probabilities zilizocalibrateiwa, interpretability, au kufanya kazi kwenye datasets kubwa sana — chagua Logistic Regression.**
* **Ikiwa unahitaji model inayonyumbulika inayoweza kunasa mahusiano yasiyo ya mstari bila feature engineering ya mwongozo — chagua SVM (pamoja na kernels).**
* Zote huboresha convex objectives, hivyo **global minima zimehakikishwa**, lakini kernels za SVM huongeza hyper-parameters na gharama ya computational.

### Naive Bayes

Naive Bayes ni familia ya **probabilistic classifiers** inayotegemea kutumia Bayes' Theorem pamoja na dhana thabiti kwamba vipengele havitegemeani. Licha ya dhana hii ya "naive", Naive Bayes mara nyingi hufanya kazi vizuri kwa matumizi fulani, hasa yale yanayohusisha text au data ya categorical, kama vile spam detection.<sup>[[5]](#references)</sup>


#### Nadharia ya Bayes

Nadharia ya Bayes ndiyo msingi wa Naive Bayes classifiers. Inahusisha conditional na marginal probabilities za matukio ya random. Formula ni:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Ambapo:
- `P(A|B)` ni uwezekano wa posterior wa class `A` kutokana na feature `B`.
- `P(B|A)` ni likelihood ya feature `B` kutokana na class `A`.
- `P(A)` ni uwezekano wa awali wa class `A`.
- `P(B)` ni uwezekano wa awali wa feature `B`.

Kwa mfano, ikiwa tunataka kuainisha kama maandishi yameandikwa na mtoto au mtu mzima, tunaweza kutumia maneno kwenye maandishi kama features. Kulingana na data ya awali, Naive Bayes classifier itakuwa imekadiria awali uwezekano wa kila neno kuwa katika kila class inayowezekana (mtoto au mtu mzima). Maandishi mapya yanapotolewa, itakokotoa uwezekano wa kila class inayowezekana kutokana na maneno yaliyomo kwenye maandishi na kuchagua class yenye uwezekano mkubwa zaidi.

Kama unavyoona katika mfano huu, Naive Bayes classifier ni rahisi sana na yenye kasi, lakini inakisia kwamba features zinajitegemea, jambo ambalo si mara zote hutokea katika data ya ulimwengu halisi.


#### Aina za Naive Bayes Classifiers

Kuna aina kadhaa za Naive Bayes classifiers, kulingana na aina ya data na usambazaji wa features:
- **Gaussian Naive Bayes**: Hukisia kwamba features zinafuata usambazaji wa Gaussian (normal). Inafaa kwa data endelevu.
- **Multinomial Naive Bayes**: Hukisia kwamba features zinafuata usambazaji wa multinomial. Inafaa kwa data ya discrete, kama vile hesabu za maneno katika text classification.
- **Bernoulli Naive Bayes**: Hukisia kwamba features ni za binary (0 au 1). Inafaa kwa data ya binary, kama vile kuwepo au kutokuwepo kwa maneno katika text classification.
- **Categorical Naive Bayes**: Hukisia kwamba features ni categorical variables. Inafaa kwa data ya categorical, kama vile kuainisha matunda kulingana na rangi na umbo.


#### **Sifa muhimu za Naive Bayes:**

-   **Aina ya Tatizo:** Classification (binary au multi-class). Hutumiwa kwa kawaida katika kazi za text classification kwenye cybersecurity (spam, phishing, n.k.).

-   **Uwezo wa Kuelezeka:** Wastani -- haielezeki moja kwa moja kama decision tree, lakini mtu anaweza kukagua probabilities zilizojifunzwa (kwa mfano, ni maneno gani yana uwezekano mkubwa zaidi katika barua pepe za spam dhidi ya barua pepe halali). Muundo wa model (probabilities za kila feature kutokana na class) unaweza kueleweka inapohitajika.

-   **Faida:** Training na prediction yenye **kasi sana**, hata kwenye datasets kubwa (linear kulingana na idadi ya instances * idadi ya features). Inahitaji kiasi kidogo cha data kukadiria probabilities kwa kutegemewa, hasa kwa kutumia smoothing inayofaa. Mara nyingi huwa na usahihi wa kushangaza kama baseline, hasa wakati features zinachangia ushahidi wa class kwa kujitegemea. Hufanya kazi vizuri na data yenye dimensions nyingi (kwa mfano, maelfu ya features kutoka kwenye text). Haihitaji tuning changamano zaidi ya kuweka smoothing parameter.

-   **Mapungufu:** Dhana ya kujitegemea inaweza kupunguza usahihi ikiwa features zina uhusiano mkubwa. Kwa mfano, katika network data, features kama `src_bytes` na `dst_bytes` zinaweza kuwa na uhusiano; Naive Bayes haitanasa interaction hiyo. Kadiri ukubwa wa data unavyoongezeka sana, models zenye uwezo mkubwa zaidi (kama ensembles au neural nets) zinaweza kuipita NB kwa kujifunza dependencies za features. Pia, ikiwa mchanganyiko fulani wa features unahitajika kutambua attack (si features binafsi zinazojitegemea), NB itapata shida.

> [!TIP]
> *Matumizi katika cybersecurity:* Matumizi ya kawaida ni **spam detection** -- Naive Bayes ilikuwa msingi wa spam filters za awali, ikitumia marudio ya tokens fulani (maneno, vifungu, IP addresses) kukokotoa uwezekano kwamba email ni spam. Pia hutumiwa katika **phishing email detection** na **URL classification**, ambapo kuwepo kwa keywords au sifa fulani (kama "login.php" katika URL, au `@` katika URL path) huchangia uwezekano wa phishing. Katika malware analysis, mtu anaweza kufikiria Naive Bayes classifier inayotumia kuwepo kwa API calls au permissions fulani katika software kutabiri kama ni malware. Ingawa algorithms za hali ya juu mara nyingi hufanya vizuri zaidi, Naive Bayes bado ni baseline nzuri kutokana na kasi na urahisi wake.

<details>
<summary>Example -- Naive Bayes for Phishing Detection:</summary>
Ili kuonyesha Naive Bayes, tutatumia Gaussian Naive Bayes kwenye NSL-KDD intrusion dataset (yenye binary labels). Gaussian NB itachukulia kila feature kuwa inafuata normal distribution kwa kila class. Hili ni chaguo la makadirio kwa sababu network features nyingi ni discrete au zina skew kubwa, lakini linaonyesha jinsi NB inavyoweza kutumiwa kwenye continuous feature data. Tunaweza pia kuchagua Bernoulli NB kwenye dataset ya binary features (kama seti ya triggered alerts), lakini tutatumia NSL-KDD hapa ili kuendeleza mfululizo.
</details>
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
Msimbo huu hufunza classifier ya Naive Bayes kutambua mashambulizi. Naive Bayes itakokotoa vitu kama `P(service=http | Attack)` na `P(Service=http | Normal)` kulingana na data ya mafunzo, ikidhani kuwa features zinajitegemea. Kisha itatumia uwezekano huu kuainisha miunganisho mipya kama ya kawaida au shambulizi kulingana na features zilizobainika. Utendaji wa NB kwenye NSL-KDD huenda usiwe wa juu kama wa models za kisasa zaidi (kwa kuwa uhuru wa features unakiukwa), lakini mara nyingi huwa mzuri na una faida ya kasi kubwa sana. Katika hali kama filtering ya barua pepe kwa wakati halisi au uchunguzi wa awali wa URLs, model ya Naive Bayes inaweza kuripoti haraka kesi zilizo wazi kuwa hasidi kwa kutumia rasilimali chache.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ni mojawapo ya algorithms rahisi zaidi za machine learning. Ni mbinu ya **non-parametric, instance-based** inayofanya utabiri kulingana na ufanano na mifano iliyo kwenye seti ya mafunzo. Wazo la classification ni: ili kuainisha data point mpya, tafuta pointi **k** zilizo karibu zaidi kwenye data ya mafunzo ("majirani wake wa karibu"), kisha weka class iliyo na wengi zaidi kati ya majirani hao. "Ukaribu" hufafanuliwa kwa metric ya umbali, kwa kawaida umbali wa Euclidean kwa data ya nambari (umbali mingine inaweza kutumika kwa aina au matatizo tofauti ya features).<sup>[[10]](#references)</sup>

K-NN haihitaji *training ya wazi* -- awamu ya "training" ni kuhifadhi tu dataset. Kazi yote hufanyika wakati wa query (prediction): algorithm lazima ihesabu umbali kutoka query point hadi pointi zote za mafunzo ili kupata zilizo karibu zaidi. Hii hufanya muda wa prediction kuwa **linear kulingana na idadi ya samples za mafunzo**, jambo ambalo linaweza kuwa ghali kwa datasets kubwa. Kwa sababu hii, k-NN inafaa zaidi kwa datasets ndogo au hali ambapo unaweza kubadilisha memory na speed kwa urahisi.

Licha ya urahisi wake, k-NN inaweza ku-model decision boundaries changamano sana (kwa kuwa, kwa ufanisi, decision boundary inaweza kuwa na umbo lolote linaloamuliwa na usambazaji wa mifano). Hufanya vizuri wakati decision boundary si ya kawaida sana na una data nyingi -- kimsingi ikiiacha data "ijieleze". Hata hivyo, katika dimensions nyingi, metrics za umbali zinaweza kupoteza maana (curse of dimensionality), na method inaweza kushindwa isipokuwa uwe na idadi kubwa sana ya samples.

*Use cases katika cybersecurity:* k-NN imetumika katika anomaly detection -- kwa mfano, intrusion detection system inaweza kuainisha tukio la mtandao kuwa hasidi ikiwa majirani wake wengi wa karibu (matukio ya awali) walikuwa hasidi. Ikiwa traffic ya kawaida inaunda clusters na mashambulizi ni outliers, mbinu ya K-NN (yenye k=1 au k ndogo) kimsingi huwa **nearest-neighbor anomaly detection**. K-NN pia imetumika kuainisha malware families kwa kutumia binary feature vectors: file mpya inaweza kuainishwa kuwa ya malware family fulani ikiwa iko karibu sana (katika feature space) na instances zinazojulikana za family hiyo. Kwa kawaida, k-NN haitumiki sana kama algorithms zinazoweza ku-scale zaidi, lakini ni rahisi kueleweka kimawazo na wakati mwingine hutumiwa kama baseline au kwa matatizo madogo.

#### **Sifa muhimu za k-NN:**

-   **Aina ya Tatizo:** Classification (na variants za regression zipo). Ni method ya *lazy learning* -- hakuna model fitting ya wazi.

-   **Ufafanuzi:** Wa chini hadi wa kati -- hakuna global model au maelezo mafupi, lakini mtu anaweza kutafsiri matokeo kwa kuangalia majirani wa karibu walioathiri uamuzi (kwa mfano, "network flow hii iliainishwa kuwa hasidi kwa sababu inafanana na hizi flows 3 zinazojulikana kuwa hasidi"). Kwa hiyo, maelezo yanaweza kutegemea mifano.

-   **Faida:** Ni rahisi sana kutekeleza na kuelewa. Haitoi dhana kuhusu usambazaji wa data (non-parametric). Inaweza kushughulikia matatizo ya multi-class kwa asili. Ni **adaptive** kwa maana kwamba decision boundaries zinaweza kuwa changamano sana, zikitengenezwa na usambazaji wa data.

-   **Mapungufu:** Prediction inaweza kuwa polepole kwa datasets kubwa (lazima ihesabu umbali mwingi). Hutumia memory nyingi -- huhifadhi data yote ya mafunzo. Utendaji hushuka katika feature spaces zenye dimensions nyingi kwa sababu pointi zote huwa karibu kuwa na umbali sawa (jambo linalofanya dhana ya "nearest" kupoteza maana). Ni lazima uchague *k* (idadi ya majirani) ipasavyo -- k ndogo sana inaweza kuwa na noise, na k kubwa sana inaweza kujumuisha pointi zisizohusika kutoka classes nyingine. Pia, features zinapaswa ku-scaled ipasavyo kwa sababu mahesabu ya umbali huathiriwa na scale.

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

Tutatumia tena NSL-KDD (binary classification). Kwa kuwa k-NN inahitaji computational resources nyingi, tutatumia subset ya data ya mafunzo ili kufanya demonstration hii iweze kutekelezeka. Tutachagua, kwa mfano, samples 20,000 za mafunzo kati ya 125k zote, na kutumia majirani k=5. Baada ya training (kwa kweli ni kuhifadhi tu data), tutafanya evaluation kwenye test set. Pia tuta-scale features kwa ajili ya mahesabu ya umbali ili kuhakikisha kuwa feature moja haitawali nyingine kwa sababu ya scale.
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
Modeli ya k-NN itaainisha connection kwa kuangalia connections 5 zilizo karibu zaidi katika subset ya training set. Kwa mfano, ikiwa 4 kati ya majirani hao ni attacks (anomalies) na 1 ni ya kawaida, connection mpya itaainishwa kama attack. Utendaji unaweza kuwa mzuri, ingawa mara nyingi si wa juu kama wa Random Forest au SVM iliyotuned vizuri kwenye data hiyo hiyo. Hata hivyo, k-NN inaweza kung'ara wakati mgawanyo wa classes ni usio wa kawaida sana na changamano -- kwa ufanisi ikitumia lookup inayotegemea memory. Katika cybersecurity, k-NN (ikiwa na k=1 au k ndogo) inaweza kutumiwa kutambua attack patterns zinazojulikana kwa kutumia mifano, au kama sehemu ya systems changamano zaidi (kwa mfano, kwa clustering na kisha kuainisha kulingana na cluster membership).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines ni miongoni mwa algorithms zenye nguvu zaidi kwa structured data. **Gradient boosting** inarejelea mbinu ya kujenga ensemble ya weak learners (mara nyingi decision trees) kwa mfuatano, ambapo kila model mpya hurekebisha makosa ya ensemble iliyotangulia. Tofauti na bagging (Random Forests), ambayo hujenga trees kwa parallel na kuzifanyia average, boosting hujenga trees *moja baada ya nyingine*, kila moja ikizingatia zaidi instances ambazo trees zilizotangulia ziliainisha vibaya.

Implementations maarufu zaidi katika miaka ya karibuni ni **XGBoost**, **LightGBM**, na **CatBoost**, ambazo zote ni libraries za gradient boosting decision tree (GBDT). Zimefanikiwa sana katika mashindano ya machine learning na applications, mara nyingi **zikifikia utendaji wa kiwango cha juu zaidi kwenye tabular datasets**. Katika cybersecurity, researchers na practitioners wametumia gradient boosted trees kwa tasks kama **malware detection** (kwa kutumia features zilizotolewa kutoka kwa files au runtime behavior) na **network intrusion detection**. Kwa mfano, gradient boosting model inaweza kuchanganya rules nyingi dhaifu (trees) kama vile "ikiwa kuna SYN packets nyingi na port isiyo ya kawaida -> kuna uwezekano wa scan" na kuwa detector imara ya pamoja inayozingatia patterns nyingi fiche.<sup>[[6]](#references)</sup>

Kwa nini boosted trees zina ufanisi mkubwa? Kila tree katika mfuatano hufunzwa kwa kutumia *residual errors* (gradients) za predictions za ensemble ya sasa. Kwa njia hii, modeli huendelea **"kuimarisha"** maeneo ambayo ni dhaifu. Matumizi ya decision trees kama base learners yanawezesha modeli ya mwisho kunasa interactions changamano na mahusiano yasiyo ya linear. Pia, boosting kwa asili ina aina ya regularization iliyojengeka ndani: kwa kuongeza trees nyingi ndogo (na kutumia learning rate kupunguza ukubwa wa michango yake), mara nyingi hu-generalize vizuri bila overfitting kubwa, mradi parameters zinazofaa zichaguliwe.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Kimsingi classification na regression. Katika security, kwa kawaida ni classification (kwa mfano, kuainisha connection au file kwa binary). Inashughulikia binary, multi-class (ikiwa na loss inayofaa), na hata ranking problems.

-   **Interpretability:** Chini hadi ya wastani. Ingawa boosted tree moja ni ndogo, modeli kamili inaweza kuwa na trees mamia, hivyo haiwezi kufasirika na binadamu kwa ujumla wake. Hata hivyo, kama Random Forest, inaweza kutoa feature importance scores, na tools kama SHAP (SHapley Additive exPlanations) zinaweza kutumiwa kufasiri predictions binafsi kwa kiwango fulani.

-   **Advantages:** Mara nyingi ndiyo algorithm yenye **utendaji bora zaidi** kwa structured/tabular data. Inaweza kutambua patterns na interactions changamano. Ina tuning knobs nyingi (idadi ya trees, depth ya trees, learning rate, na regularization terms) za kurekebisha complexity ya modeli na kuzuia overfitting. Implementations za kisasa zimeboreshwa kwa speed (kwa mfano, XGBoost hutumia second-order gradient info na efficient data structures). Kwa kawaida hushughulikia imbalanced data vizuri zaidi inapounganishwa na loss functions zinazofaa au kwa kurekebisha sample weights.

-   **Limitations:** Ni changamano zaidi kuitune kuliko models rahisi; training inaweza kuwa polepole ikiwa trees ni deep au idadi ya trees ni kubwa (ingawa kwa kawaida bado huwa haraka kuliko kufunza deep neural network inayolingana kwenye data hiyo hiyo). Modeli inaweza ku-overfit ikiwa haitatuned (kwa mfano, trees deep nyingi zikiwa na regularization isiyotosha). Kwa sababu ya hyperparameters nyingi, kutumia gradient boosting kwa ufanisi kunaweza kuhitaji utaalamu au experimentation zaidi. Pia, kama tree-based methods, haiwezi kushughulikia kwa asili sparse high-dimensional data kwa ufanisi sawa na linear models au Naive Bayes (ingawa bado inaweza kutumika, kwa mfano, katika text classification, lakini huenda isiwe chaguo la kwanza bila feature engineering).

> [!TIP]
> *Use cases in cybersecurity:* Karibu kila mahali ambapo decision tree au random forest inaweza kutumiwa, gradient boosting model inaweza kupata accuracy bora zaidi. Kwa mfano, mashindano ya **Microsoft's malware detection** yametumia sana XGBoost kwenye engineered features kutoka binary files. Utafiti wa **Network intrusion detection** mara nyingi huripoti matokeo ya juu zaidi kwa GBDTs (kwa mfano, XGBoost kwenye CIC-IDS2017 au UNSW-NB15 datasets). Models hizi zinaweza kutumia features mbalimbali (protocol types, frequency ya events fulani, statistical features za traffic, na kadhalika) na kuzichanganya ili kutambua threats. Katika phishing detection, gradient boosting inaweza kuchanganya lexical features za URLs, domain reputation features, na page content features ili kupata accuracy ya juu sana. Mbinu ya ensemble husaidia kushughulikia corner cases na subtleties nyingi katika data.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
Tutatumia gradient boosting classifier kwenye phishing dataset. Ili kuweka mambo rahisi na kujitosheleza, tutatumia `sklearn.ensemble.GradientBoostingClassifier` (ambayo ni implementation ya polepole zaidi lakini iliyo rahisi kueleweka). Kwa kawaida, mtu anaweza kutumia libraries za `xgboost` au `lightgbm` kwa performance bora na features za ziada. Tutafunza modeli na kuitathmini kwa njia inayofanana na hapo awali.
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
The gradient boosting model huenda ikapata usahihi wa juu sana na AUC kwenye dataset hii ya phishing (mara nyingi modeli hizi zinaweza kuzidi usahihi wa 95% zikitunzwa ipasavyo kwenye data kama hii, kama inavyoonekana katika tafiti. Hii inaonyesha kwa nini GBDTs huchukuliwa kuwa *"modeli ya kisasa zaidi kwa dataset za tabular"* -- mara nyingi hushinda algorithms rahisi kwa kunasa mifumo changamano. Katika muktadha wa cybersecurity, hii inaweza kumaanisha kugundua tovuti nyingi zaidi za phishing au mashambulizi kwa kupunguza matukio yasiyogunduliwa. Bila shaka, mtu lazima awe mwangalifu kuhusu overfitting -- kwa kawaida tungetumia mbinu kama cross-validation na kufuatilia utendaji kwenye validation set wakati wa kutengeneza modeli kama hii kwa ajili ya deployment.

</details>

### Kuchanganya Modeli: Ensemble Learning na Stacking

Ensemble learning ni mkakati wa **kuchanganya modeli nyingi** ili kuboresha utendaji wa jumla. Tayari tuliona mbinu mahususi za ensemble: Random Forest (ensemble ya miti kupitia bagging) na Gradient Boosting (ensemble ya miti kupitia sequential boosting). Lakini ensembles zinaweza kuundwa pia kwa njia nyingine, kama vile **voting ensembles** au **stacked generalization (stacking)**. Wazo kuu ni kwamba modeli tofauti zinaweza kunasa mifumo tofauti au kuwa na udhaifu tofauti; kwa kuziunganisha, tunaweza **kufidia makosa ya kila modeli kwa kutumia nguvu za nyingine**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** Katika voting classifier rahisi, tunafunza modeli nyingi zenye utofauti (kwa mfano, logistic regression, decision tree, na SVM), kisha tunazipigia kura kuhusu prediction ya mwisho (kura ya wengi kwa classification). Tukipa kura uzito (kwa mfano, uzito mkubwa kwa modeli zilizo sahihi zaidi), huu huwa mpango wa weighted voting. Kwa kawaida hii huboresha utendaji wakati modeli binafsi ni nzuri kwa kiwango kinachofaa na zinajitegemea -- ensemble hupunguza hatari ya kosa la modeli moja kwa kuwa nyingine zinaweza kulirekebisha. Ni kama kuwa na jopo la wataalamu badala ya maoni ya mtu mmoja.

-   **Stacking (Stacked Ensemble):** Stacking huenda hatua moja zaidi. Badala ya kura rahisi, hufunza **meta-modeli** ili **kujifunza jinsi bora ya kuchanganya predictions** za modeli za msingi. Kwa mfano, unafunza classifiers 3 tofauti (base learners), kisha unapitisha outputs zao (au probabilities) kama features kwenye meta-classifier (mara nyingi modeli rahisi kama logistic regression), ambayo hujifunza njia bora ya kuziunganisha. Meta-modeli hufunzwa kwenye validation set au kupitia cross-validation ili kuepuka overfitting. Stacking mara nyingi inaweza kushinda voting rahisi kwa kujifunza *ni modeli zipi za kuamini zaidi katika hali zipi*. Katika cybersecurity, modeli moja inaweza kuwa bora katika kugundua network scans, huku nyingine ikiwa bora katika kugundua malware beaconing; stacking model inaweza kujifunza kutegemea kila moja ipasavyo.

Ensembles, iwe kupitia voting au stacking, kwa kawaida **huongeza accuracy** na robustness. Hasara yake ni kuongezeka kwa complexity na wakati mwingine kupungua kwa interpretability (ingawa baadhi ya ensemble approaches, kama wastani wa decision trees, bado zinaweza kutoa maarifa fulani, kwa mfano feature importance). Kwa vitendo, ikiwa operational constraints zinaruhusu, kutumia ensemble kunaweza kuongeza detection rates. Suluhisho nyingi zilizoshinda katika changamoto za cybersecurity (na mashindano ya Kaggle kwa ujumla) hutumia ensemble techniques ili kupata ongezeko la mwisho la performance.

<details>
<summary>Mfano -- Voting Ensemble kwa Phishing Detection:</summary>
Ili kuonyesha model stacking, tuchanganye baadhi ya modeli tulizojadili kwenye phishing dataset. Tutatumia logistic regression, decision tree, na k-NN kama base learners, na kutumia Random Forest kama meta-learner ili kuunganisha predictions zao. Meta-learner itafunzwa kwa kutumia outputs za base learners (kupitia cross-validation kwenye training set). Tunatarajia stacked model ifanye vizuri sawa na modeli binafsi au iwe bora kidogo.
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
Stacked ensemble hutumia nguvu zinazokamilishana za base models. Kwa mfano, logistic regression inaweza kushughulikia vipengele vya mstari vya data, decision tree inaweza kunasa mwingiliano maalum unaofanana na kanuni, na k-NN inaweza kufanya vizuri katika maeneo ya karibu ya feature space. Meta-model (random forest katika mfano huu) inaweza kujifunza jinsi ya kupima uzito wa inputs hizi. Metrics zinazopatikana mara nyingi huonyesha uboreshaji (hata kama ni mdogo) ikilinganishwa na metrics za model yoyote moja. Katika mfano wetu wa phishing, ikiwa logistic pekee ingekuwa na F1 ya, tuseme, 0.95 na tree 0.94, stack inaweza kufikia 0.96 kwa kugundua maeneo ambayo kila model hukosea.

Ensemble methods kama huu huonyesha kanuni kwamba *"kuchanganya models nyingi kwa kawaida huleta generalization bora"*. Katika cybersecurity, hii inaweza kutekelezwa kwa kuwa na detection engines nyingi (moja inaweza kutegemea rules, nyingine machine learning, na nyingine anomaly-based) kisha kuweka layer inayokusanya alerts zao -- ambayo kwa ufanisi ni aina ya ensemble -- ili kufanya uamuzi wa mwisho kwa confidence ya juu zaidi. Wakati wa ku-deploy systems kama hizi, ni lazima kuzingatia complexity iliyoongezeka na kuhakikisha kuwa ensemble haiwi ngumu sana kuisimamia au kuieleza. Lakini kwa mtazamo wa accuracy, ensembles na stacking ni tools zenye nguvu za kuboresha utendaji wa model.

</details>


## Marejeo

- [1] [Logistic Regression](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Decision Tree - Utangulizi wenye mfano](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Ugunduzi wa Denial of Services Attack kwa kutumia Random Forest Classifier yenye Information Gain](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [Support Vector Machines (SVMs) ni nini? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Naive Bayes spam filtering (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT Imefafanuliwa: Jinsi LightGBM, XGBoost, na CatBoost Zinavyofanya Kazi](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI na Machine Learning katika Cybersecurity (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Linear Regression Imefafanuliwa](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Uchambuzi wa utendaji wa machine learning models kwa intrusion detection system kwa kutumia mbinu ya kuchagua features ya Gini Impurity-based Weighted Random Forest (GIWRF)](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [k-nearest neighbors (KNN) algorithm ni nini? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Uainishaji wa Phishing Attacks na Websites kwa kutumia Machine Learning na Multiple Datasets (Uchambuzi Linganishi)](https://arxiv.org/pdf/2101.02552)
- [12] [Jinsi Deep Learning Inavyoboresha Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning: Kuboresha Utendaji wa Model kwa Kuchanganya Nguvu](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
