# Algorithms za Supervised Learning

{{#include ../banners/hacktricks-training.md}}

## Taarifa za Msingi

Supervised learning hutumia data yenye labels kufundisha models zinazoweza kufanya predictions kwenye inputs mpya ambazo hazijawahi kuonekana. Katika cybersecurity, supervised machine learning hutumika sana katika kazi kama vile intrusion detection (kuainisha network traffic kama *normal* au *attack*), malware detection (kutofautisha software hasidi na software salama), phishing detection (kutambua websites au emails za ulaghai), na spam filtering, miongoni mwa nyingine.<sup>[[1]](#references)</sup> Kila algorithm ina nguvu zake na inafaa kwa aina tofauti za matatizo (classification au regression). Hapa chini tunapitia supervised learning algorithms muhimu, tunaeleza jinsi zinavyofanya kazi, na tunaonyesha matumizi yake kwenye cybersecurity datasets halisi. Pia tunajadili jinsi kuchanganya models (ensemble learning) kunavyoweza mara nyingi kuboresha predictive performance.

## Algorithms

-   **Linear Regression:** Algorithm ya msingi ya regression ya kutabiri matokeo ya namba kwa ku-fitting linear equation kwenye data.

-   **Logistic Regression:** Algorithm ya classification (licha ya jina lake) inayotumia logistic function ku-model probability ya binary outcome.

-   **Decision Trees:** Models zenye muundo wa mti zinazogawanya data kwa kutumia features ili kufanya predictions; mara nyingi hutumika kwa sababu ya interpretability yake.

-   **Random Forests:** Ensemble ya decision trees (kupitia bagging) inayoboresha accuracy na kupunguza overfitting.

-   **Support Vector Machines (SVM):** Max-margin classifiers zinazopata separating hyperplane bora zaidi; zinaweza kutumia kernels kwa non-linear data.

-   **Naive Bayes:** Probabilistic classifier inayotegemea Bayes' theorem pamoja na dhana kwamba features hazitegemei, na hutumika sana katika spam filtering.

-   **k-Nearest Neighbors (k-NN):** Classifier rahisi ya "instance-based" inayoweka label kwenye sample kulingana na class iliyo nyingi zaidi kati ya neighbors wake walio karibu.

-   **Gradient Boosting Machines:** Ensemble models (k.m., XGBoost, LightGBM) zinazounda predictor imara kwa kuongeza weaker learners mmoja baada ya mwingine (kwa kawaida decision trees).

Kila sehemu hapa chini inatoa maelezo yaliyoboreshwa ya algorithm na **Python code example** inayotumia libraries kama `pandas` na `scikit-learn` (na `PyTorch` kwa mfano wa neural network). Examples zinatumia cybersecurity datasets zinazopatikana hadharani (kama NSL-KDD kwa intrusion detection na Phishing Websites dataset) na zinafuata muundo unaofanana:

1.  **Pakia dataset** (pakua kupitia URL ikiwa inapatikana).

2.  **Preprocess data** (k.m. encode categorical features, scale values, na gawanya data kuwa train/test sets).

3.  **Train model** kwa kutumia training data.

4.  **Evaluate** kwenye test set kwa kutumia metrics: accuracy, precision, recall, F1-score, na ROC AUC kwa classification (na mean squared error kwa regression).

Hebu tuchunguze kila algorithm:

### Linear Regression

Linear regression ni algorithm ya **regression** inayotumika kutabiri numeric values zinazoendelea. Inachukulia kwamba kuna linear relationship kati ya input features (independent variables) na output (dependent variable). Model hujaribu ku-fit straight line (au hyperplane katika dimensions za juu zaidi) inayoeleza vizuri zaidi uhusiano kati ya features na target. Kwa kawaida hii hufanywa kwa kupunguza jumla ya squared errors kati ya values zilizotabiriwa na zile halisi (Ordinary Least Squares method).<sup>[[2]](#references)</sup>

Njia rahisi zaidi ya kuwakilisha linear regression ni kwa kutumia line:
```plaintext
y = mx + b
```
Ambapo:

- `y` ni thamani iliyotabiriwa (matokeo)
- `m` ni mteremko wa mstari (coefficient)
- `x` ni kipengele cha ingizo
- `b` ni y-intercept

Lengo la linear regression ni kupata mstari unaolingana vizuri zaidi, unaopunguza tofauti kati ya thamani zilizotabiriwa na thamani halisi katika dataset. Bila shaka, hii ni rahisi sana; ungekuwa mstari ulionyooka unaotenganisha makundi 2, lakini vipimo zaidi vinapoongezwa, mstari huwa changamano zaidi:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Matumizi katika cybersecurity:* Linear regression yenyewe hutumika kwa nadra katika kazi kuu za usalama (ambazo mara nyingi ni za classification), lakini inaweza kutumika kutabiri matokeo ya nambari. Kwa mfano, inaweza kutumika **kutabiri kiasi cha trafiki ya mtandao** au **kukadiria idadi ya mashambulizi katika kipindi fulani** kwa kutumia data ya kihistoria. Pia inaweza kutabiri alama ya hatari au muda unaotarajiwa hadi shambulio ligunduliwe, kwa kuzingatia vipimo fulani vya mfumo. Kwa vitendo, algorithms za classification (kama logistic regression au trees) hutumika zaidi kugundua intrusions au malware, lakini linear regression ni msingi muhimu na inafaa kwa uchanganuzi unaolenga regression.

#### **Sifa kuu za Linear Regression:**

-   **Aina ya Tatizo:** Regression (kutabiri thamani zinazoendelea). Haifai kwa classification ya moja kwa moja isipokuwa threshold itumike kwenye matokeo.

-   **Uwezo wa Kueleweka:** Juu -- coefficients ni rahisi kufasiri, zikionyesha athari ya mstari ya kila feature.

-   **Faida:** Ni rahisi na ya haraka; ni baseline nzuri kwa kazi za regression; hufanya kazi vizuri wakati uhusiano halisi unakaribia kuwa wa mstari.

-   **Vikwazo:** Haiwezi kushughulikia uhusiano changamano au usio wa mstari (bila manual feature engineering); inaweza kufanya underfitting ikiwa uhusiano si wa mstari; ni nyeti kwa outliers, ambazo zinaweza kupotosha matokeo.

-   **Kupata Mstari Unaolingana Vizuri Zaidi:** Ili kupata mstari unaolingana vizuri zaidi unaotenganisha kategoria zinazowezekana, tunatumia mbinu inayoitwa **Ordinary Least Squares (OLS)**. Mbinu hii hupunguza jumla ya tofauti zilizowekwa mraba kati ya thamani zilizotazamwa na thamani zinazotabiriwa na linear model.

<details>
<summary>Example -- Kutabiri Muda wa Muunganisho (Regression) katika Dataset ya Intrusion
</summary>
Hapa tunaonyesha matumizi ya linear regression kwa kutumia dataset ya cybersecurity ya NSL-KDD. Tutachukulia hili kama tatizo la regression kwa kutabiri `duration` ya miunganisho ya mtandao kwa kutumia features nyingine. (Kwa uhalisia, `duration` ni feature moja ya NSL-KDD; tunaitumia hapa kwa madhumuni ya kuonyesha regression.) Tunapakia dataset, tunaiandaa awali (tukifanyia encode categorical features), tunafunza linear regression model, na kutathmini Mean Squared Error (MSE) pamoja na alama ya R² kwenye test set.
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
Katika mfano huu, model ya linear regression hujaribu kutabiri `duration` ya connection kutokana na vipengele vingine vya mtandao. Tunapima utendaji kwa kutumia Mean Squared Error (MSE) na R². R² iliyo karibu na 1.0 ingeonyesha kuwa model inaeleza sehemu kubwa ya variance katika `duration`, ilhali R² ya chini au hasi huonyesha ulinganifu hafifu. (Usishangae ikiwa R² ni ya chini hapa -- kutabiri `duration` kunaweza kuwa kugumu kutokana na vipengele vilivyotolewa, na linear regression huenda isichukue mifumo ikiwa ni changamano.)
</details>

### Logistic Regression

Logistic regression ni algorithm ya **classification** inayomodeli uwezekano kwamba instance ni ya class fulani (kwa kawaida class ya "positive"). Licha ya jina lake, *logistic* regression hutumiwa kwa matokeo ya kipekee (tofauti na linear regression, ambayo hutumiwa kwa matokeo endelevu). Hutumika hasa kwa **binary classification** (classes mbili, kwa mfano, malicious dhidi ya benign), lakini inaweza kupanuliwa kwa matatizo ya multi-class (kwa kutumia mbinu za softmax au one-vs-rest).<sup>[[3]](#references)</sup>

Logistic regression hutumia logistic function (inayojulikana pia kama sigmoid function) kubadilisha thamani zilizotabiriwa kuwa probabilities. Kumbuka kuwa sigmoid function ni function yenye thamani kati ya 0 na 1 inayokua kwa curve yenye umbo la S kulingana na mahitaji ya classification, jambo linaloifanya ifae kwa kazi za binary classification. Kwa hivyo, kila feature ya kila input huzidishwa kwa weight yake iliyopewa, na matokeo hupitishwa kupitia sigmoid function ili kutoa probability:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` ni uwezekano kwamba output `y` ni 1 kutokana na input `x`
- `e` ni msingi wa logarithm ya asili
- `z` ni mchanganyiko wa linear wa vipengele vya input, ambao kwa kawaida huwakilishwa kama `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Kumbuka kwamba, tena katika hali yake rahisi zaidi, ni mstari ulionyooka, lakini katika hali changamano zaidi huwa hyperplane yenye dimensions kadhaa (moja kwa kila feature).

> [!TIP]
> *Matumizi katika cybersecurity:* Kwa sababu matatizo mengi ya usalama kimsingi ni maamuzi ya ndiyo/hapana, Logistic Regression hutumiwa kwa kiwango kikubwa. Kwa mfano, mfumo wa intrusion detection unaweza kutumia Logistic Regression kuamua ikiwa network connection ni attack kulingana na features za connection hiyo. Katika utambuzi wa phishing, Logistic Regression inaweza kuchanganya features za website (urefu wa URL, uwepo wa alama ya "@", n.k.) na kutoa uwezekano wa kuwa ni phishing. Imetumika katika spam filters za awali na bado ni baseline imara kwa kazi nyingi za classification.

#### Logistic Regression kwa classification isiyo ya binary

Logistic Regression imeundwa kwa binary classification, lakini inaweza kupanuliwa kushughulikia matatizo ya multi-class kwa kutumia mbinu kama **one-vs-rest** (OvR) au **softmax regression**. Katika OvR, modeli tofauti ya Logistic Regression hufunzwa kwa kila class, huku class hiyo ikichukuliwa kama positive class dhidi ya nyingine zote. Class yenye uwezekano uliotabiriwa kuwa mkubwa zaidi huchaguliwa kama prediction ya mwisho. Softmax regression hujumlisha Logistic Regression kwa classes nyingi kwa kutumia softmax function kwenye output layer, na kutoa usambazaji wa uwezekano katika classes zote.

#### **Sifa kuu za Logistic Regression:**

-   **Aina ya Tatizo:** Classification (kwa kawaida binary). Hutabiri uwezekano wa positive class.

-   **Ufafanuzi:** Juu -- kama ilivyo kwa linear regression, feature coefficients zinaweza kuonyesha jinsi kila feature inavyoathiri log-odds za matokeo. Uwazi huu mara nyingi huthaminiwa katika usalama kwa kuelewa ni vipengele gani vinavyochangia alert.

-   **Faida:** Ni rahisi na hufunzwa kwa haraka; hufanya kazi vizuri wakati uhusiano kati ya features na log-odds za matokeo ni linear. Hutoa probabilities, hivyo kuwezesha risk scoring. Kwa regularization inayofaa, hu-generalize vizuri na inaweza kushughulikia multicollinearity vizuri zaidi kuliko plain linear regression.

-   **Mapungufu:** Huchukulia kuwa decision boundary katika feature space ni linear (hushindwa ikiwa boundary halisi ni changamano/non-linear). Inaweza kufanya vibaya katika matatizo ambayo interactions au non-linear effects ni muhimu, isipokuwa uongeze mwenyewe polynomial au interaction features. Pia, Logistic Regression huwa na ufanisi mdogo ikiwa classes haziwezi kutenganishwa kwa urahisi kwa linear combination ya features.


<details>
<summary>Mfano -- Utambuzi wa Phishing Website kwa kutumia Logistic Regression:</summary>

Tutatumia **Phishing Websites Dataset** (kutoka kwenye repository ya UCI), ambayo ina features zilizotolewa kutoka kwenye websites (kama ikiwa URL ina IP address, umri wa domain, uwepo wa vipengele vya kutiliwa shaka katika HTML, n.k.) pamoja na label inayoonyesha ikiwa site ni phishing au legitimate.<sup>[[4]](#references)</sup> Tunafunza modeli ya Logistic Regression ili ku-classify websites, kisha kutathmini accuracy, precision, recall, F1-score, na ROC AUC yake kwenye test split.
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
Katika mfano huu wa utambuzi wa phishing, logistic regression hutengeneza uwezekano kwa kila tovuti kuwa ni phishing. Kwa kutathmini accuracy, precision, recall, na F1, tunapata picha ya utendaji wa model. Kwa mfano, recall ya juu ingemaanisha inagundua tovuti nyingi za phishing (jambo muhimu kwa usalama ili kupunguza mashambulizi yaliyokosa kugunduliwa), huku precision ya juu ikimaanisha ina false alarms chache (jambo muhimu ili kuepuka uchovu wa wachanganuzi). ROC AUC (Area Under the ROC Curve) hutoa kipimo cha utendaji kisichotegemea threshold (1.0 ni bora kabisa, 0.5 si bora kuliko kubahatisha). Logistic regression mara nyingi hufanya vizuri katika kazi kama hizi, lakini ikiwa decision boundary kati ya tovuti za phishing na halali ni tata, model zenye nguvu zaidi zisizo za mstari zinaweza kuhitajika.

</details>

### Miti ya Maamuzi

Mti wa maamuzi ni **algorithm ya supervised learning** inayoweza kutumika kwa kazi za classification na regression. Hujifunza model ya maamuzi yenye muundo wa mti wa kihierarkia kulingana na features za data. Kila nodi ya ndani ya mti inawakilisha jaribio kwenye feature fulani, kila tawi linawakilisha matokeo ya jaribio hilo, na kila leaf node inawakilisha class iliyotabiriwa (kwa classification) au thamani (kwa regression).<sup>[[5]](#references)</sup>

Ili kujenga mti, algorithms kama CART (Classification and Regression Tree) hutumia vipimo kama **Gini impurity** au **information gain (entropy)** kuchagua feature na threshold bora wa kugawanya data katika kila hatua. Lengo la kila mgawanyo ni kugawanya data ili kuongeza ufanano wa target variable katika subsets zinazotokana (kwa classification, kila nodi hulenga kuwa safi iwezekanavyo, ikiwa na class moja hasa).

Miti ya maamuzi ni **rahisi sana kufasiriwa** -- mtu anaweza kufuata njia kutoka root hadi leaf ili kuelewa mantiki iliyo nyuma ya utabiri (kwa mfano, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Hili ni muhimu katika cybersecurity kwa kueleza kwa nini alert fulani ilitolewa. Miti inaweza kushughulikia data za nambari na categorical kwa njia ya asili na huhitaji preprocessing kidogo (kwa mfano, feature scaling haihitajiki).

Hata hivyo, mti mmoja wa maamuzi unaweza kufanya overfitting kwa urahisi kwenye training data, hasa unapokuzwa kwa kina (ukiwa na migawanyo mingi). Mbinu kama pruning (kupunguza kina cha mti au kuhitaji idadi ya chini ya samples kwa kila leaf) hutumiwa mara nyingi kuzuia overfitting.

Kuna vipengele 3 vikuu vya mti wa maamuzi:
- **Root Node**: Nodi ya juu ya mti, inayowakilisha dataset nzima.
- **Internal Nodes**: Nodi zinazowakilisha features na maamuzi yanayotegemea features hizo.
- **Leaf Nodes**: Nodi zinazowakilisha matokeo au utabiri wa mwisho.

Mti unaweza hatimaye kuonekana hivi:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Matumizi katika cybersecurity:* Decision trees zimetumika katika mifumo ya kugundua uvamizi ili kupata **rules** za kutambua mashambulizi. Kwa mfano, IDS za awali kama mifumo iliyotegemea ID3/C4.5 zilitengeneza rules zinazoweza kusomeka na binadamu ili kutofautisha traffic ya kawaida na yenye madhara. Pia hutumika katika uchanganuzi wa malware kuamua ikiwa faili ni hasidi kulingana na sifa zake (ukubwa wa faili, section entropy, API calls, n.k.). Uwazi wa decision trees huzifanya ziwe muhimu pale transparency inapohitajika -- analyst anaweza kukagua tree ili kuthibitisha logic ya detection.

#### **Sifa kuu za Decision Trees:**

-   **Aina ya Tatizo:** Classification na regression. Hutumika kwa kawaida katika classification ya mashambulizi dhidi ya traffic ya kawaida, n.k.

-   **Urahisi wa Kueleweka:** Juu sana -- maamuzi ya model yanaweza kuonyeshwa na kueleweka kama seti ya if-then rules. Hii ni faida kubwa katika security kwa trust na verification ya tabia ya model.

-   **Faida:** Zinaweza kunasa relationships zisizo za mstari na interactions kati ya features (kila split inaweza kuonekana kama interaction). Hakuna haja ya kuscale features au kufanya one-hot encode ya categorical variables -- trees hushughulikia hayo natively. Inference ni ya haraka (prediction ni kufuata path tu katika tree).

-   **Mapungufu:** Zinaweza ku-overfit ikiwa hazitadhibitiwa (tree ndefu inaweza kuhifadhi training set kwa kukariri). Zinaweza kuwa unstable -- mabadiliko madogo katika data yanaweza kusababisha muundo tofauti wa tree. Kama models za pekee, accuracy yake huenda isilingane na methods za kisasa zaidi (ensembles kama Random Forests kwa kawaida hufanya vizuri zaidi kwa kupunguza variance).

-   **Kupata Split Bora:**
- **Gini Impurity**: Hupima impurity ya node. Gini impurity ya chini huonyesha split bora zaidi. Formula ni:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Ambapo `p_i` ni uwiano wa instances zilizo katika class `i`.

- **Entropy**: Hupima uncertainty katika dataset. Entropy ya chini huonyesha split bora zaidi. Formula ni:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Ambapo `p_i` ni uwiano wa instances zilizo katika class `i`.

- **Information Gain**: Ni upunguzaji wa entropy au Gini impurity baada ya split. Kadiri information gain inavyokuwa kubwa, ndivyo split inavyokuwa bora. Hukokotolewa hivi:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Zaidi ya hayo, tree hukamilishwa wakati:
- Instances zote katika node ni za class moja. Hii inaweza kusababisha overfitting.
- Maximum depth (iliyowekwa moja kwa moja kwenye code) ya tree imefikiwa. Hii ni njia ya kuzuia overfitting.
- Idadi ya instances katika node iko chini ya threshold fulani. Hii pia ni njia ya kuzuia overfitting.
- Information gain kutoka kwa splits zaidi iko chini ya threshold fulani. Hii pia ni njia ya kuzuia overfitting.

<details>
<summary>Example -- Decision Tree for Intrusion Detection:</summary>
Tutafundisha decision tree kwenye dataset ya NSL-KDD ili kuainisha connections za mtandao kama *normal* au *attack*. NSL-KDD ni toleo lililoboreshwa la dataset ya kawaida ya KDD Cup 1999, lenye features kama protocol type, service, duration, idadi ya failed logins, n.k., pamoja na label inayoonyesha aina ya attack au "normal". Tutapanga aina zote za attacks katika class ya "anomaly" (binary classification: normal dhidi ya anomaly). Baada ya training, tutatathmini performance ya tree kwenye test set.
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
Katika mfano huu wa decision tree, tuliweka kina cha tree kuwa 10 ili kuepuka overfitting iliyokithiri (parameter ya `max_depth=10`). Metrics zinaonyesha jinsi tree inavyotofautisha traffic ya kawaida na ya attack. Recall ya juu ingemaanisha inakamata attacks nyingi (jambo muhimu kwa IDS), huku precision ya juu ikimaanisha false alarms chache. Decision trees mara nyingi hupata accuracy nzuri kwenye data iliyopangwa, lakini tree moja huenda isifikie performance bora zaidi inayowezekana. Hata hivyo, *interpretability* ya model ni faida kubwa -- tunaweza kuchunguza splits za tree ili kuona, kwa mfano, ni features zipi (k.m., `service`, `src_bytes`, n.k.) zina ushawishi mkubwa zaidi katika kuainisha connection kuwa malicious.

</details>

### Random Forests

Random Forest ni mbinu ya **ensemble learning** inayojengwa juu ya decision trees ili kuboresha performance. Random forest hufunza decision trees nyingi (ndiyo maana ya "forest") na kuunganisha matokeo yake ili kutoa prediction ya mwisho (kwa classification, kwa kawaida kupitia majority vote). Mawazo mawili makuu katika random forest ni **bagging** (bootstrap aggregating) na **feature randomness**:

-   **Bagging:** Kila tree hufunzwa kwa kutumia random bootstrap sample ya training data (inayosamplewa kwa replacement). Hii huleta diversity kati ya trees.

-   **Feature Randomness:** Katika kila split ya tree, subset ya features inayochaguliwa kwa random huzingatiwa kwa splitting (badala ya features zote). Hii hutenganisha zaidi trees kwa correlation.

Kwa ku-average matokeo ya trees nyingi, random forest hupunguza variance ambayo decision tree moja inaweza kuwa nayo. Kwa maneno rahisi, trees binafsi zinaweza kufanya overfit au kuwa na noise, lakini idadi kubwa ya trees zenye diversity zinazopiga kura pamoja husawazisha errors hizo. Matokeo yake mara nyingi huwa model yenye **accuracy ya juu** na generalization bora kuliko decision tree moja. Zaidi ya hayo, random forests zinaweza kutoa makadirio ya feature importance (kwa kuchunguza kiasi ambacho kila feature split hupunguza impurity kwa wastani).

Random forests zimekuwa **workhorse katika cybersecurity** kwa tasks kama intrusion detection, malware classification, na spam detection. Mara nyingi hufanya vizuri out-of-the-box zikiwa na tuning ndogo na zinaweza kushughulikia feature sets kubwa. Kwa mfano, katika intrusion detection, random forest inaweza kufanya vizuri kuliko decision tree moja kwa kukamata patterns fiche zaidi za attacks ikiwa na false positives chache. Utafiti umeonyesha random forests zikifanya vizuri ikilinganishwa na algorithms nyingine katika ku-classify attacks kwenye datasets kama NSL-KDD na UNSW-NB15.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Sifa kuu za Random Forests:**

-   **Aina ya Tatizo:** Kimsingi classification (pia hutumika kwa regression). Inafaa sana kwa structured data yenye dimensions nyingi, inayopatikana kwa kawaida katika security logs.

-   **Interpretability:** Ni ya chini kuliko decision tree moja -- huwezi ku-visualize au kueleza kwa urahisi trees mia nyingi kwa wakati mmoja. Hata hivyo, feature importance scores hutoa uelewa fulani kuhusu attributes zipi zina ushawishi mkubwa zaidi.

-   **Faida:** Kwa kawaida huwa na accuracy ya juu kuliko models za tree moja kutokana na athari ya ensemble. Inastahimili overfitting -- hata kama trees binafsi zinafanya overfit, ensemble hu-generalize vizuri zaidi. Hushughulikia features za numerical na categorical na inaweza kusimamia missing data kwa kiwango fulani. Pia ni imara kwa kiasi dhidi ya outliers.

-   **Mapungufu:** Ukubwa wa model unaweza kuwa mkubwa (trees nyingi, kila moja ikiwa na uwezekano wa kuwa na kina kirefu). Predictions ni polepole kuliko za tree moja (kwa kuwa lazima u-aggregate kupitia trees nyingi). Ina interpretability ndogo -- ingawa unajua features muhimu, logic kamili si rahisi kufuatilia kama rule rahisi. Ikiwa dataset ina dimensions nyingi sana na ni sparse, kufunza forest kubwa sana kunaweza kutumia computational resources nyingi.

-   **Mchakato wa Training:**
1. **Bootstrap Sampling**: Sampuli random training data kwa replacement ili kuunda subsets nyingi (bootstrap samples).
2. **Tree Construction**: Kwa kila bootstrap sample, jenga decision tree kwa kutumia random subset ya features katika kila split. Hii huleta diversity kati ya trees.
3. **Aggregation**: Kwa tasks za classification, prediction ya mwisho hutolewa kwa kutumia majority vote kati ya predictions za trees zote. Kwa tasks za regression, prediction ya mwisho ni wastani wa predictions kutoka trees zote.

<details>
<summary>Mfano -- Random Forest kwa Intrusion Detection (NSL-KDD):</summary>
Tutatumia NSL-KDD dataset hiyo hiyo (iliyo na binary labels za normal dhidi ya anomaly) na kufunza Random Forest classifier. Tunatarajia random forest ifanye vizuri kama decision tree moja au kuizidi, kutokana na ensemble averaging kupunguza variance. Tutaitathmini kwa kutumia metrics hizo hizo.
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
Random forest kwa kawaida hupata matokeo mazuri katika kazi hii ya intrusion detection. Tunaweza kuona uboreshaji wa metrics kama F1 au AUC ikilinganishwa na decision tree moja, hasa katika recall au precision, kutegemea data. Hii inaendana na uelewa kwamba *"Random Forest (RF) ni ensemble classifier na hufanya vizuri ikilinganishwa na traditional classifiers nyingine kwa ajili ya classification bora ya attacks."*.<sup>[[6]](#references)</sup> Katika muktadha wa security operations, random forest model inaweza ku-flag attacks kwa kutegemewa zaidi huku ikipunguza false alarms, kwa sababu ya kufanya averaging ya decision rules nyingi. Feature importance kutoka kwenye forest inaweza kutuonyesha ni network features zipi zinazoashiria attacks zaidi (kwa mfano, network services fulani au idadi zisizo za kawaida za packets).

</details>

### Support Vector Machines (SVM)

Support Vector Machines ni powerful supervised learning models zinazotumiwa hasa kwa classification (na pia regression kama SVR). SVM hujaribu kupata **optimal separating hyperplane** inayoongeza maximum ya margin kati ya classes mbili. Ni subset tu ya training points (zinazoitwa "support vectors", zilizo karibu zaidi na boundary) huamua mahali pa hyperplane hii. Kwa kuongeza margin (umbali kati ya support vectors na hyperplane), SVMs kwa kawaida hupata generalization nzuri.<sup>[[8]](#references)</sup>

Jambo muhimu linalowezesha nguvu ya SVM ni uwezo wa kutumia **kernel functions** kushughulikia mahusiano yasiyo ya linear. Data inaweza kubadilishwa implicitly kuwa feature space yenye dimensions nyingi zaidi, ambako linear separator inaweza kuwepo. Kernels zinazotumika kwa kawaida ni polynomial, radial basis function (RBF), na sigmoid. Kwa mfano, ikiwa network traffic classes haziwezi kutenganishwa kwa linear katika raw feature space, RBF kernel inaweza kuzihamisha kwenye dimension ya juu zaidi ambako SVM hupata linear split (ambayo inalingana na non-linear boundary katika original space). Uwezo wa kuchagua kernels huwezesha SVMs kushughulikia matatizo mbalimbali.

SVMs zinajulikana kufanya vizuri katika hali zenye high-dimensional feature spaces (kama text data au malware opcode sequences) na katika hali ambapo idadi ya features ni kubwa ikilinganishwa na idadi ya samples. Zilitumika sana katika cybersecurity applications nyingi za awali, kama malware classification na anomaly-based intrusion detection katika miaka ya 2000, na mara nyingi zilionyesha accuracy ya juu.

Hata hivyo, SVMs hazipanuki kwa urahisi hadi datasets kubwa sana (training complexity ni super-linear kulingana na idadi ya samples, na memory usage inaweza kuwa kubwa kwa sababu huenda zikahitaji kuhifadhi support vectors nyingi). Kwa vitendo, katika tasks kama network intrusion detection yenye mamilioni ya records, SVM inaweza kuwa slow sana bila subsampling ya uangalifu au matumizi ya approximate methods.

#### **Sifa kuu za SVM:**

-   **Aina ya Tatizo:** Classification (binary au multiclass kupitia one-vs-one/one-vs-rest) na regression variants. Mara nyingi hutumiwa katika binary classification yenye clear margin separation.

-   **Interpretability:** Wastani -- SVMs hazieleweki kwa urahisi kama decision trees au logistic regression. Ingawa unaweza kutambua data points zipi ni support vectors na kupata wazo fulani kuhusu features zipi zinaweza kuwa na ushawishi (kupitia weights katika hali ya linear kernel), kwa vitendo SVMs (hasa zenye non-linear kernels) huchukuliwa kama black-box classifiers.

-   **Faida:** Zinafaa katika high-dimensional spaces; zinaweza ku-model complex decision boundaries kwa kutumia kernel trick; ni imara dhidi ya overfitting ikiwa margin ime-maximize (hasa ikiwa regularization parameter C imewekwa vizuri); hufanya vizuri hata classes zisipotenganishwa kwa umbali mkubwa (hupata boundary bora ya maelewano).

-   **Mapungufu:** **Zinahitaji computational resources nyingi** kwa datasets kubwa (training na prediction zote hu-scale vibaya data inapokua). Zinahitaji tuning ya uangalifu ya kernel na regularization parameters (C, kernel type, gamma kwa RBF, na nyinginezo). Hazitoi moja kwa moja probabilistic outputs (ingawa mtu anaweza kutumia Platt scaling kupata probabilities). Pia, SVMs zinaweza kuwa sensitive kwa uchaguzi wa kernel parameters --- uchaguzi mbaya unaweza kusababisha underfit au overfit.

*Matumizi katika cybersecurity:* SVMs zimetumika katika **malware detection** (kwa mfano, ku-classify files kulingana na extracted features au opcode sequences), **network anomaly detection** (ku-classify traffic kama normal au malicious), na **phishing detection** (kwa kutumia features za URLs). Kwa mfano, SVM inaweza kuchukua features za email (idadi ya keywords fulani, sender reputation scores, na kadhalika) na ku-classify kama phishing au legitimate. Pia zimetumika katika **intrusion detection** kwenye feature sets kama KDD, na mara nyingi kupata accuracy ya juu kwa gharama ya computation.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Tutatumia tena phishing website dataset, safari hii kwa kutumia SVM. Kwa sababu SVMs zinaweza kuwa slow, tutatumia subset ya data kwa training ikihitajika (dataset ina takribani instances 11k, ambazo SVM inaweza kushughulikia kwa kiwango kinachofaa). Tutatumia RBF kernel ambayo ni chaguo la kawaida kwa non-linear data, na tutawezesha probability estimates ili kukokotoa ROC AUC.
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
Model ya SVM itatoa metrics ambazo tunaweza kulinganisha na logistic regression kwenye task hiyo hiyo. Tunaweza kugundua kuwa SVM inapata accuracy na AUC ya juu ikiwa data imetenganishwa vizuri na features. Kwa upande mwingine, ikiwa dataset ina noise nyingi au classes zinazopishana, SVM huenda isizidi logistic regression kwa kiwango kikubwa. Kwa vitendo, SVM zinaweza kutoa ongezeko la utendaji wakati kuna mahusiano changamano, yasiyo ya mstari kati ya features na class -- kernel ya RBF inaweza kunasa decision boundaries zilizopinda ambazo logistic regression ingezikosa. Kama ilivyo kwa models zote, tuning makini ya `C` (regularization) na vigezo vya kernel (kama `gamma` kwa RBF) inahitajika ili kusawazisha bias na variance.

</details>

#### Tofauti Kati ya Logistic Regression na SVM

| Kipengele | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Hupunguza **log‑loss** (cross‑entropy). | Huongeza **margin** huku ikipunguza **hinge‑loss**. |
| **Decision boundary** | Hupata **best-fit hyperplane** inayomodeli _P(y\|x)_. | Hupata **maximum-margin hyperplane** (pengo kubwa zaidi hadi points zilizo karibu zaidi). |
| **Output** | **Probabilistic** – hutoa class probabilities zilizocalibrate kupitia σ(w·x + b). | **Deterministic** – hurejesha class labels; probabilities zinahitaji kazi ya ziada (k.m. Platt scaling). |
| **Regularisation** | L2 (default) au L1, husawazisha moja kwa moja under/over-fitting. | Kigezo cha C husawazisha upana wa margin dhidi ya mis-classifications; vigezo vya kernel huongeza complexity. |
| **Kernels / Non-linear** | Aina ya asili ni **linear**; non-linearity huongezwa kupitia feature engineering. | **Kernel trick** iliyojengewa ndani (RBF, poly, n.k.) huiruhusu kumodeli boundaries changamano katika space ya high-dim. |
| **Scalability** | Hutatua convex optimisation katika **O(nd)**; hushughulikia n kubwa sana vizuri. | Training inaweza kuwa na memory/time ya **O(n²–n³)** bila specialised solvers; si rafiki kwa n kubwa sana. |
| **Interpretability** | **High** – weights huonyesha ushawishi wa feature; odds ratio ni rahisi kuelewa. | **Low** kwa kernels zisizo za mstari; support vectors ni sparse lakini si rahisi kueleza. |
| **Sensitivity to outliers** | Hutumia log-loss laini → huwa na sensitivity ndogo. | Hinge-loss yenye hard margin inaweza kuwa **sensitive**; soft-margin (C) hupunguza athari hiyo. |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – ambapo **probabilities & explainability** ni muhimu. | Image/text classification, bio-informatics – ambapo **complex boundaries** na **high-dimensional data** ni muhimu. |

* **Ikiwa unahitaji probabilities zilizocalibrate, interpretability, au kufanya kazi na datasets kubwa sana — chagua Logistic Regression.**
* **Ikiwa unahitaji model inayobadilika na inaweza kunasa mahusiano yasiyo ya mstari bila feature engineering ya mikono — chagua SVM (yenye kernels).**
* Zote huboresha convex objectives, hivyo **global minima zinahakikishwa**, lakini kernels za SVM huongeza hyper-parameters na gharama ya computational.

### Naive Bayes

Naive Bayes ni familia ya **probabilistic classifiers** inayotumia Bayes' Theorem ikiwa na dhana thabiti ya independence kati ya features. Licha ya dhana hii ya "naive", Naive Bayes mara nyingi hufanya kazi vizuri kwa applications fulani, hasa zinazohusisha text au categorical data, kama vile spam detection.<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem ndiyo msingi wa Naive Bayes classifiers. Inahusianisha conditional probabilities na marginal probabilities za random events. Formula ni:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Ambapo:
- `P(A|B)` ni uwezekano wa posterior wa class `A` kutokana na feature `B`.
- `P(B|A)` ni likelihood ya feature `B` kutokana na class `A`.
- `P(A)` ni uwezekano wa awali wa class `A`.
- `P(B)` ni uwezekano wa awali wa feature `B`.

Kwa mfano, ikiwa tunataka kuainisha kama maandishi yameandikwa na mtoto au mtu mzima, tunaweza kutumia maneno katika maandishi kama features. Kulingana na data ya awali, Naive Bayes classifier itakuwa imekalkulia uwezekano wa kila neno kuwa katika kila class inayowezekana (mtoto au mtu mzima). Maandishi mapya yanapotolewa, itakokotoa uwezekano wa kila class inayowezekana kutokana na maneno katika maandishi na kuchagua class yenye uwezekano mkubwa zaidi.

Kama unavyoona katika mfano huu, Naive Bayes classifier ni rahisi na ya haraka sana, lakini inachukulia kuwa features zinajitegemea, jambo ambalo si mara zote huwa hivyo katika data ya ulimwengu halisi.


#### Aina za Naive Bayes Classifiers

Kuna aina kadhaa za Naive Bayes classifiers, kulingana na aina ya data na usambazaji wa features:
- **Gaussian Naive Bayes**: Huchukulia kuwa features zinafuata usambazaji wa Gaussian (normal). Inafaa kwa data inayoendelea.
- **Multinomial Naive Bayes**: Huchukulia kuwa features zinafuata usambazaji wa multinomial. Inafaa kwa data bainifu, kama vile hesabu za maneno katika text classification.
- **Bernoulli Naive Bayes**: Huchukulia kuwa features ni binary (0 au 1). Inafaa kwa data ya binary, kama vile kuwepo au kutokuwepo kwa maneno katika text classification.
- **Categorical Naive Bayes**: Huchukulia kuwa features ni categorical variables. Inafaa kwa data ya categorical, kama vile kuainisha matunda kulingana na rangi na umbo lake.


#### **Sifa kuu za Naive Bayes:**

-   **Aina ya Tatizo:** Classification (binary au multi-class). Hutumika sana kwa kazi za text classification katika cybersecurity (spam, phishing, n.k.).

-   **Uwezo wa Kueleweka:** Wastani -- si rahisi kueleweka moja kwa moja kama decision tree, lakini mtu anaweza kukagua probabilities zilizojifunzwa (kwa mfano, ni maneno yapi yana uwezekano mkubwa zaidi katika barua pepe za spam ikilinganishwa na ham). Muundo wa model (probabilities za kila feature kutokana na class) unaweza kueleweka inapohitajika.

-   **Faida:** Training na prediction ya **haraka sana**, hata kwenye datasets kubwa (linear kulingana na idadi ya instances * idadi ya features). Huhitaji kiasi kidogo cha data kukadiria probabilities kwa uhakika, hasa kwa kutumia smoothing inayofaa. Mara nyingi huwa na usahihi wa kushangaza kama baseline, hasa features zinapochangia ushahidi kwa class kwa kujitegemea. Hufanya kazi vizuri na data yenye dimensions nyingi (kwa mfano, maelfu ya features kutoka kwenye text). Haihitaji tuning changamano zaidi ya kuweka smoothing parameter.

-   **Mapungufu:** Dhana ya kujitegemea inaweza kupunguza usahihi ikiwa features zina uhusiano mkubwa. Kwa mfano, katika data ya mtandao, features kama `src_bytes` na `dst_bytes` zinaweza kuwa na uhusiano; Naive Bayes haitanasa interaction hiyo. Ukubwa wa data unapokua sana, models zenye uwezo mkubwa zaidi (kama ensembles au neural nets) zinaweza kuizidi NB kwa kujifunza dependencies za features. Pia, ikiwa mchanganyiko fulani wa features unahitajika kutambua attack (badala ya features binafsi kufanya kazi kwa kujitegemea), NB itapata ugumu.

> [!TIP]
> *Matumizi katika cybersecurity:* Matumizi ya kawaida ni **spam detection** -- Naive Bayes ilikuwa msingi wa spam filters za awali, ikitumia frequency za tokens fulani (maneno, phrases, IP addresses) kukokotoa uwezekano kwamba barua pepe ni spam. Pia hutumika katika **phishing email detection** na **URL classification**, ambapo kuwepo kwa keywords au sifa fulani (kama "login.php" katika URL, au `@` katika URL path) huchangia uwezekano wa phishing. Katika malware analysis, mtu anaweza kufikiria Naive Bayes classifier inayotumia kuwepo kwa API calls au permissions fulani katika software kutabiri kama ni malware. Ingawa algorithms za kisasa zaidi mara nyingi hufanya vizuri zaidi, Naive Bayes bado ni baseline nzuri kutokana na kasi na urahisi wake.

<details>
<summary>Example -- Naive Bayes for Phishing Detection:</summary>
Ili kuonyesha Naive Bayes, tutatumia Gaussian Naive Bayes kwenye intrusion dataset ya NSL-KDD (yenye binary labels). Gaussian NB itachukulia kila feature kuwa inafuata usambazaji wa normal kwa kila class. Hili ni chaguo la kukadiria kwa sababu network features nyingi ni discrete au zina skew kubwa, lakini linaonyesha jinsi mtu angeitumia NB kwenye continuous feature data. Pia tungeweza kuchagua Bernoulli NB kwenye dataset ya binary features (kama seti ya alerts zilizochochewa), lakini tutaendelea na NSL-KDD hapa kwa ajili ya continuity.
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
Msimbo huu hufunza classifier ya Naive Bayes ili kugundua mashambulizi. Naive Bayes itakokotoa vitu kama `P(service=http | Attack)` na `P(Service=http | Normal)` kulingana na data ya mafunzo, ikidhani kuwa features hazitegemeani. Kisha itatumia probabilities hizi kuainisha miunganisho mipya kuwa ya kawaida au shambulio, kulingana na features zilizobainika. Utendaji wa NB kwenye NSL-KDD huenda usiwe wa juu kama wa models za kisasa zaidi (kwa sababu independence ya features inakiukwa), lakini mara nyingi huwa mzuri na una faida ya kasi kubwa sana. Katika hali kama email filtering ya wakati halisi au triage ya awali ya URLs, model ya Naive Bayes inaweza kuweka alama haraka kwenye hali zilizo wazi kuwa malicious huku ikitumia rasilimali chache.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ni mojawapo ya algorithms rahisi zaidi za machine learning. Ni method ya **non-parametric, instance-based** inayofanya predictions kulingana na ufanano na mifano iliyo kwenye training set. Wazo la classification ni: ili kuainisha data point mpya, tafuta points **k** zilizo karibu zaidi katika training data (zinazoitwa "nearest neighbors"), kisha ipe data hiyo class iliyo na wengi zaidi miongoni mwa neighbors hao. "Ukaribu" hufafanuliwa kwa kutumia distance metric, kwa kawaida Euclidean distance kwa data za nambari (distances nyingine zinaweza kutumika kwa aina tofauti za features au matatizo).<sup>[[10]](#references)</sup>

K-NN haihitaji *training ya wazi* -- awamu ya "training" ni kuhifadhi dataset pekee. Kazi yote hufanyika wakati wa query (prediction): algorithm lazima ikokotoe distances kutoka query point hadi training points zote ili kupata zilizo karibu zaidi. Hii hufanya muda wa prediction kuwa **linear kulingana na idadi ya training samples**, jambo ambalo linaweza kuwa la gharama kwa datasets kubwa. Kwa sababu hii, k-NN inafaa zaidi kwa datasets ndogo au hali ambapo unaweza kubadilisha memory na speed kwa ajili ya urahisi.

Licha ya urahisi wake, k-NN inaweza kuunda decision boundaries changamano sana (kwa kuwa decision boundary inaweza kimsingi kuwa ya umbo lolote linaloelekezwa na usambazaji wa mifano). Huwa inafanya vizuri wakati decision boundary ina mparaganyiko mkubwa na una data nyingi -- kimsingi ikiiacha data "ijieleze yenyewe". Hata hivyo, katika dimensions nyingi, distance metrics zinaweza kupoteza maana (curse of dimensionality), na method hii inaweza kutatizika isipokuwa uwe na idadi kubwa sana ya samples.

*Use cases katika cybersecurity:* k-NN imetumika katika anomaly detection -- kwa mfano, intrusion detection system inaweza kuweka network event kama malicious ikiwa wengi wa nearest neighbors wake (events za awali) walikuwa malicious. Ikiwa normal traffic inaunda clusters na mashambulizi ni outliers, approach ya K-NN (yenye k=1 au k ndogo) kimsingi hufanya **nearest-neighbor anomaly detection**. K-NN pia imetumika kuainisha malware families kwa kutumia binary feature vectors: file mpya inaweza kuainishwa kuwa ya malware family fulani ikiwa iko karibu sana (katika feature space) na instances zinazojulikana za family hiyo. Kwa vitendo, k-NN si maarufu kama algorithms zinazoweza ku-scale zaidi, lakini ni rahisi kueleweka kimawazo na wakati mwingine hutumiwa kama baseline au kwa matatizo ya kiwango kidogo.

#### **Sifa kuu za k-NN:**

-   **Aina ya Tatizo:** Classification (na variants za regression zipo). Ni method ya *lazy learning* -- hakuna model fitting ya wazi.

-   **Uwezo wa Kufasirika:** Chini hadi wa kati -- hakuna global model au maelezo mafupi, lakini mtu anaweza kufasiri matokeo kwa kuangalia nearest neighbors walioathiri uamuzi (kwa mfano, "network flow hii iliainishwa kuwa malicious kwa sababu inafanana na flows hizi 3 zinazojulikana kuwa malicious"). Kwa hiyo, maelezo yanaweza kutegemea mifano.

-   **Faida:** Ni rahisi sana kuimplement na kuelewa. Haifanyi assumptions kuhusu usambazaji wa data (non-parametric). Inaweza kushughulikia matatizo ya multi-class kwa kawaida. Ni **adaptive** kwa maana kwamba decision boundaries zinaweza kuwa changamano sana, zikiwa zimeundwa na usambazaji wa data.

-   **Vikwazo:** Prediction inaweza kuwa polepole kwa datasets kubwa (lazima ikokotoe distances nyingi). Inatumia memory nyingi -- huhifadhi training data yote. Utendaji hushuka katika feature spaces zenye dimensions nyingi kwa sababu points zote huwa karibu kuwa na distance sawa (na kufanya dhana ya "nearest" ipoteze maana). Ni lazima uchague *k* (idadi ya neighbors) ipasavyo -- k ndogo sana inaweza kuwa na noise, na k kubwa sana inaweza kujumuisha points zisizohusiana kutoka classes nyingine. Pia, features zinapaswa kuscaled ipasavyo kwa sababu distance calculations huathiriwa na scale.

<details>
<summary>Example -- k-NN kwa Phishing Detection:</summary>

Tutatumia tena NSL-KDD (binary classification). Kwa kuwa k-NN inahitaji computational resources nyingi, tutatumia subset ya training data ili demonstration hii iweze kutekelezeka. Tutachagua, kwa mfano, training samples 20,000 kati ya 125k yote, na kutumia neighbors k=5. Baada ya training (ambayo kwa kweli ni kuhifadhi data tu), tutafanya evaluation kwenye test set. Pia tutascaled features kwa ajili ya distance calculation ili kuhakikisha hakuna feature moja inayotawala kwa sababu ya scale yake.
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
Muundo wa k-NN utaainisha connection kwa kuangalia connections 5 zilizo karibu zaidi katika subset ya training set. Ikiwa, kwa mfano, 4 kati ya majirani hao ni attacks (anomalies) na 1 ni ya kawaida, connection mpya itaainishwa kama attack. Utendaji unaweza kuwa mzuri, ingawa mara nyingi si wa kiwango cha juu kama Random Forest au SVM iliyotunzwa vizuri kwenye data hiyo hiyo. Hata hivyo, k-NN inaweza kuwa bora wakati distributions za classes si za kawaida sana na ni changamano -- kwa kutumia lookup inayotegemea memory. Katika cybersecurity, k-NN (ikiwa na k=1 au k ndogo) inaweza kutumika kutambua attack patterns zinazojulikana kwa kutumia mifano, au kama sehemu ya systems changamano zaidi (kwa mfano, kwa clustering na kisha kuainisha kulingana na cluster membership).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines ni miongoni mwa algorithms zenye nguvu zaidi kwa structured data. **Gradient boosting** inarejelea mbinu ya kujenga ensemble ya weak learners (mara nyingi decision trees) kwa mfuatano, ambapo kila model mpya husahihisha errors za ensemble iliyotangulia. Tofauti na bagging (Random Forests), ambayo hujenga trees kwa parallel na kuzipa wastani, boosting hujenga trees *moja baada ya nyingine*, kila moja ikilenga zaidi instances ambazo trees zilizotangulia zili-predict vibaya.<sup>[[11]](#references)</sup>

Implementations maarufu zaidi katika miaka ya hivi karibuni ni **XGBoost**, **LightGBM**, na **CatBoost**, ambazo zote ni libraries za gradient boosting decision tree (GBDT). Zimefanikiwa sana katika mashindano na matumizi ya machine learning, mara nyingi **zikifikia performance ya kiwango cha juu zaidi kwenye tabular datasets**. Katika cybersecurity, researchers na practitioners wametumia gradient boosted trees kwa tasks kama **malware detection** (kwa kutumia features zilizotolewa kutoka kwenye files au runtime behavior) na **network intrusion detection**. Kwa mfano, gradient boosting model inaweza kuunganisha weak rules nyingi (trees), kama vile "ikiwa kuna SYN packets nyingi na port isiyo ya kawaida -> kuna uwezekano mkubwa wa scan", kuwa detector imara inayozingatia patterns nyingi fiche.

Kwa nini boosted trees zina ufanisi mkubwa hivyo? Kila tree katika mfuatano hufunzwa kwa kutumia *residual errors* (gradients) za predictions za ensemble ya sasa. Kwa njia hii, model huendelea **"boost"** maeneo ambayo ni dhaifu. Kutumia decision trees kama base learners kunamaanisha kwamba final model inaweza kunasa interactions changamano na relations zisizo za mstari. Pia, boosting ina aina ya built-in regularization: kwa kuongeza trees nyingi ndogo (na kutumia learning rate kupima michango yake), mara nyingi hu-generalize vizuri bila overfitting kubwa, mradi parameters zinazofaa zichaguliwe.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Kimsingi classification na regression. Katika security, kwa kawaida ni classification (kwa mfano, kuainisha connection au file kwa binary). Inashughulikia binary, multi-class (ikiwa na loss inayofaa), na hata ranking problems.

-   **Interpretability:** Chini hadi wastani. Ingawa boosted tree moja ni ndogo, model kamili inaweza kuwa na trees mamia, jambo linalofanya isiwe rahisi kutafsiriwa na binadamu kwa ujumla. Hata hivyo, kama Random Forest, inaweza kutoa feature importance scores, na tools kama SHAP (SHapley Additive exPlanations) zinaweza kutumika kutafsiri individual predictions kwa kiwango fulani.

-   **Advantages:** Mara nyingi ndiyo algorithm yenye **performance bora zaidi** kwa structured/tabular data. Inaweza kutambua patterns na interactions changamano. Ina tuning knobs nyingi (idadi ya trees, depth ya trees, learning rate, regularization terms) za kurekebisha model complexity na kuzuia overfitting. Implementations za kisasa zimeboreshwa kwa speed (kwa mfano, XGBoost hutumia second-order gradient info na efficient data structures). Huwa inashughulikia imbalanced data vizuri zaidi inapounganishwa na loss functions zinazofaa au kwa kurekebisha sample weights.

-   **Limitations:** Ni changamano zaidi kutune kuliko models rahisi; training inaweza kuwa polepole ikiwa trees ni deep au idadi ya trees ni kubwa (ingawa kwa kawaida bado huwa haraka kuliko training ya deep neural network inayolingana kwenye data hiyo hiyo). Model inaweza ku-overfit ikiwa haitatuniwa (kwa mfano, deep trees nyingi sana zikiwa na regularization isiyotosha). Kwa sababu ya hyperparameters nyingi, kutumia gradient boosting kwa ufanisi kunaweza kuhitaji utaalamu zaidi au experimentation. Pia, kama methods zinazotegemea trees, haiwezi kushughulikia kwa asili sparse high-dimensional data kwa ufanisi kama linear models au Naive Bayes (ingawa bado inaweza kutumika, kwa mfano, katika text classification, lakini huenda isiwe chaguo la kwanza bila feature engineering).

> [!TIP]
> *Use cases in cybersecurity:* Karibu kila mahali ambapo decision tree au random forest inaweza kutumika, gradient boosting model inaweza kupata accuracy bora zaidi. Kwa mfano, mashindano ya **Microsoft's malware detection** yametumia sana XGBoost kwenye engineered features kutoka binary files. Utafiti wa **network intrusion detection** mara nyingi huripoti matokeo ya juu kwa kutumia GBDTs (kwa mfano, XGBoost kwenye CIC-IDS2017 au UNSW-NB15 datasets). Models hizi zinaweza kutumia features mbalimbali (protocol types, frequency ya events fulani, statistical features za traffic, na kadhalika) na kuziunganisha ili kutambua threats. Katika phishing detection, gradient boosting inaweza kuunganisha lexical features za URLs, domain reputation features, na page content features ili kupata accuracy ya juu sana. Mbinu ya ensemble husaidia kushughulikia corner cases na nuances nyingi katika data.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
Tutatumia gradient boosting classifier kwenye phishing dataset. Ili kurahisisha mambo na kufanya mfano ujitegemee, tutatumia `sklearn.ensemble.GradientBoostingClassifier` (ambayo ni implementation ya polepole zaidi lakini iliyo rahisi kuelewa). Kwa kawaida, mtu anaweza kutumia libraries za `xgboost` au `lightgbm` kwa performance bora na features za ziada. Tutafunza model na kuitathmini kwa njia inayofanana na hapo awali.
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
Muundo wa gradient boosting huenda ukapata usahihi na AUC ya juu sana kwenye data set hii ya phishing (mara nyingi miundo hii inaweza kuzidi usahihi wa 95% ikiwa itarekebishwa vizuri kwenye data kama hizi, kama inavyoonekana kwenye tafiti. Hii inaonyesha kwa nini GBDTs huchukuliwa kuwa *"model ya kisasa zaidi kwa dataset za tabular"* -- mara nyingi hushinda algorithms rahisi kwa kunasa mifumo changamano.<sup>[[11]](#references)</sup> Katika muktadha wa cybersecurity, hii inaweza kumaanisha kugundua tovuti nyingi zaidi za phishing au mashambulizi mengi zaidi kwa makosa machache ya kukosa vitisho. Bila shaka, ni lazima kuwa waangalifu kuhusu overfitting -- kwa kawaida tutatumia mbinu kama cross-validation na kufuatilia utendaji kwenye validation set tunapotengeneza model kama hii kwa ajili ya deployment.

</details>

### Kuchanganya Miundo: Ensemble Learning na Stacking

Ensemble learning ni mkakati wa **kuchanganya miundo mingi** ili kuboresha utendaji wa jumla. Tayari tumeona ensemble methods mahususi: Random Forest (ensemble ya miti kupitia bagging) na Gradient Boosting (ensemble ya miti kupitia sequential boosting). Hata hivyo, ensembles zinaweza kuundwa kwa njia nyingine pia, kama vile **voting ensembles** au **stacked generalization (stacking)**. Wazo kuu ni kwamba miundo tofauti inaweza kunasa mifumo tofauti au kuwa na udhaifu tofauti; kwa kuichanganya, tunaweza **kufidia makosa ya kila model kwa nguvu za nyingine**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Kwenye voting classifier rahisi, tunafundisha miundo mingi tofauti (kwa mfano, logistic regression, decision tree, na SVM) na kuifanya ipige kura kuhusu utabiri wa mwisho (kura ya wengi kwa classification). Tukipima kura (kwa mfano, kutoa uzito mkubwa kwa miundo yenye usahihi zaidi), huo huwa weighted voting scheme. Kwa kawaida hii huboresha utendaji wakati miundo binafsi ni mizuri na huru kwa kiasi; ensemble hupunguza hatari ya kosa la model moja kwa sababu nyingine zinaweza kulirekebisha. Ni kama kuwa na jopo la wataalamu badala ya maoni ya mtu mmoja.

-   **Stacking (Stacked Ensemble):** Stacking huenda hatua moja zaidi. Badala ya kura rahisi, hufundisha **meta-model** ili **ijifunze jinsi bora ya kuchanganya utabiri** wa base models. Kwa mfano, unafundisha classifiers 3 tofauti (base learners), kisha unaingiza matokeo yao (au probabilities) kama features kwenye meta-classifier (mara nyingi model rahisi kama logistic regression) inayojifunza njia bora ya kuyaunganisha. Meta-model hufundishwa kwenye validation set au kupitia cross-validation ili kuepuka overfitting. Stacking mara nyingi inaweza kushinda voting rahisi kwa kujifunza *ni miundo ipi ya kuamini zaidi katika hali zipi*. Katika cybersecurity, model moja inaweza kuwa bora zaidi katika kugundua network scans, huku nyingine ikiwa bora zaidi katika kugundua malware beaconing; stacking model inaweza kujifunza kutegemea kila moja kwa njia inayofaa.

Ensembles, iwe kwa voting au stacking, kwa kawaida **huongeza usahihi** na robustness. Hasara yake ni kuongezeka kwa complexity na wakati mwingine kupungua kwa interpretability (ingawa baadhi ya ensemble approaches kama wastani wa decision trees bado zinaweza kutoa ufahamu fulani, kwa mfano, feature importance). Kwa vitendo, ikiwa operational constraints zinaruhusu, kutumia ensemble kunaweza kusababisha detection rates za juu zaidi. Suluhisho nyingi zinazoshinda kwenye mashindano ya cybersecurity (na mashindano ya Kaggle kwa ujumla) hutumia ensemble techniques kupata maboresho ya mwisho ya utendaji.

<details>
<summary>Example -- Voting Ensemble for Phishing Detection:</summary>
Ili kuonyesha model stacking, hebu tuchanganye baadhi ya miundo tuliyojadili kwenye phishing dataset. Tutatumia logistic regression, decision tree, na k-NN kama base learners, na tutatumia Random Forest kama meta-learner ya kujumlisha utabiri wao. Meta-learner itafundishwa kwa kutumia matokeo ya base learners (kwa kutumia cross-validation kwenye training set). Tunatarajia stacked model ifanye kazi sawa na au vizuri kidogo kuliko miundo binafsi.
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
Stacked ensemble hutumia nguvu zinazokamilishana za base models. Kwa mfano, logistic regression inaweza kushughulikia vipengele vya linear vya data, decision tree inaweza kunasa mwingiliano maalum unaofanana na sheria, na k-NN inaweza kufanya vizuri katika maeneo ya karibu ya feature space. Meta-model (random forest katika hali hii) inaweza kujifunza jinsi ya kupima uzito wa pembejeo hizi. Vipimo vinavyopatikana mara nyingi huonyesha uboreshaji (hata kama ni mdogo) ikilinganishwa na vipimo vya model yoyote moja. Katika mfano wetu wa phishing, ikiwa logistic pekee ingekuwa na F1 ya, tuseme, 0.95 na tree 0.94, stack inaweza kufikia 0.96 kwa kutambua maeneo ambayo kila model hukosea.

Ensemble methods kama hii huonyesha kanuni kwamba *"kuchanganya models nyingi kwa kawaida husababisha generalization bora zaidi"*.<sup>[[12]](#references)</sup> Katika cybersecurity, hii inaweza kutekelezwa kwa kuwa na detection engines nyingi (moja inaweza kutegemea rules, nyingine machine learning, na nyingine anomaly-based), kisha kuwa na layer inayokusanya alerts zao -- kwa ufanisi ikiwa ni aina ya ensemble -- ili kufanya uamuzi wa mwisho kwa confidence ya juu zaidi. Wakati wa ku-deploy mifumo kama hii, ni lazima kuzingatia complexity iliyoongezeka na kuhakikisha kuwa ensemble haijawa ngumu sana kusimamia au kueleza. Hata hivyo, kwa mtazamo wa accuracy, ensembles na stacking ni zana zenye nguvu za kuboresha utendaji wa model.

</details>

Mbinu za neural-network zilizoelezwa katika [ukurasa wa deep-learning](AI-Deep-Learning.md) zinaweza kukamilisha classical models hizi kwa intrusion detection wakati dataset na bajeti ya compute vinahalalisha complexity ya ziada.<sup>[[13]](#references)</sup>

## References

- [1] [AI and Machine Learning katika Cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression, Imeelezwa - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Uainishaji wa Phishing Attacks na Websites kwa Kutumia Machine Learning na Datasets Nyingi (Uchambuzi Linganishi)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Ugunduzi wa Denial of Services Attack kwa Kutumia Random Forest Classifier yenye Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Uchambuzi wa utendaji wa machine learning models kwa intrusion detection system kwa kutumia mbinu ya kuchagua features ya Gini Impurity-based Weighted Random Forest (GIWRF)"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Support Vector Machine ni Nini? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [k-Nearest Neighbors (KNN) ni Nini? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT Imefafanuliwa: Jinsi LightGBM, XGBoost na CatBoost Zinavyofanya Kazi - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Kuboresha Utendaji wa Model kwa Kuchanganya Nguvu - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Jinsi Deep Learning Inavyoboresha Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
