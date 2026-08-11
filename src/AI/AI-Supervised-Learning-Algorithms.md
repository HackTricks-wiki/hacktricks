# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basic Information

Supervised learning, labeled data का उपयोग करके ऐसे models को train करता है, जो नए और पहले न देखे गए inputs पर predictions कर सकें। Cybersecurity में supervised machine learning का व्यापक उपयोग intrusion detection (network traffic को *normal* या *attack* के रूप में classify करना), malware detection (malicious software को benign software से अलग करना), phishing detection (fraudulent websites या emails की पहचान करना) और spam filtering जैसी tasks में किया जाता है।<sup>[[1]](#references)</sup> प्रत्येक algorithm की अपनी खूबियां होती हैं और यह अलग-अलग प्रकार की समस्याओं (classification या regression) के लिए उपयुक्त होता है। नीचे हम प्रमुख supervised learning algorithms की समीक्षा करेंगे, बताएंगे कि वे कैसे काम करते हैं, और वास्तविक cybersecurity datasets पर इनके उपयोग का प्रदर्शन करेंगे। हम यह भी चर्चा करेंगे कि models को संयोजित करना (ensemble learning) predictive performance को अक्सर बेहतर बना सकता है।

## Algorithms

-   **Linear Regression:** Numeric outcomes का अनुमान लगाने के लिए data में linear equation fit करने वाला एक fundamental regression algorithm।

-   **Logistic Regression:** अपने नाम के बावजूद, यह एक classification algorithm है, जो binary outcome की probability को model करने के लिए logistic function का उपयोग करता है।

-   **Decision Trees:** Tree-structured models, जो predictions करने के लिए features के आधार पर data को विभाजित करते हैं; इनका उपयोग अक्सर इनकी interpretability के लिए किया जाता है।

-   **Random Forests:** Decision trees का एक ensemble (bagging के माध्यम से), जो accuracy को बेहतर बनाता है और overfitting को कम करता है।

-   **Support Vector Machines (SVM):** Max-margin classifiers, जो optimal separating hyperplane खोजते हैं; non-linear data के लिए kernels का उपयोग कर सकते हैं।

-   **Naive Bayes:** Bayes' theorem पर आधारित एक probabilistic classifier, जिसमें features की independence की धारणा होती है और जिसका उपयोग spam filtering में प्रसिद्ध रूप से किया जाता है।

-   **k-Nearest Neighbors (k-NN):** एक सरल "instance-based" classifier, जो अपने nearest neighbors की majority class के आधार पर किसी sample को label करता है।

-   **Gradient Boosting Machines:** Ensemble models (जैसे XGBoost, LightGBM), जो कमजोर learners (आमतौर पर decision trees) को क्रमिक रूप से जोड़कर एक strong predictor बनाते हैं।

नीचे दिया गया प्रत्येक section algorithm का बेहतर description और `pandas` तथा `scikit-learn` जैसी libraries (और neural network example के लिए `PyTorch`) का उपयोग करने वाला एक **Python code example** प्रदान करता है। Examples सार्वजनिक रूप से उपलब्ध cybersecurity datasets (जैसे intrusion detection के लिए NSL-KDD और Phishing Websites dataset) का उपयोग करते हैं और एक समान structure का पालन करते हैं:

1.  **Dataset load करें** (यदि URL उपलब्ध हो, तो उसके माध्यम से download करें)।

2.  **Data preprocess करें** (जैसे categorical features को encode करना, values को scale करना और data को train/test sets में विभाजित करना)।

3.  **Training data** पर model को **train करें**।

4.  Classification के लिए metrics: accuracy, precision, recall, F1-score और ROC AUC (और regression के लिए mean squared error) का उपयोग करके test set पर **evaluate करें**।

आइए प्रत्येक algorithm को विस्तार से समझते हैं:

### Linear Regression

Linear regression एक **regression** algorithm है, जिसका उपयोग continuous numeric values का अनुमान लगाने के लिए किया जाता है। यह input features (independent variables) और output (dependent variable) के बीच linear relationship की धारणा पर आधारित होता है। Model ऐसी straight line (या higher dimensions में hyperplane) fit करने का प्रयास करता है, जो features और target के बीच के relationship को सबसे अच्छी तरह दर्शाती है। यह आमतौर पर predicted और actual values के बीच squared errors के sum को minimize करके किया जाता है (Ordinary Least Squares method)।<sup>[[2]](#references)</sup>

Linear regression को दर्शाने का सबसे सरल रूप एक line है:
```plaintext
y = mx + b
```
जहाँ:

- `y` पूर्वानुमानित मान (आउटपुट) है
- `m` रेखा का ढलान (गुणांक) है
- `x` इनपुट feature है
- `b` y-intercept है

linear regression का लक्ष्य ऐसी best-fitting line खोजना है जो dataset में पूर्वानुमानित मानों और वास्तविक मानों के बीच के अंतर को न्यूनतम करे। बेशक, यह बहुत सरल है; यह 2 categories को अलग करने वाली एक सीधी रेखा होगी, लेकिन यदि अधिक dimensions जोड़े जाएँ, तो रेखा अधिक जटिल हो जाती है:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *साइबर सुरक्षा में उपयोग के मामले:* Linear regression स्वयं core security tasks के लिए कम सामान्य है (जो अक्सर classification होते हैं), लेकिन इसका उपयोग numerical outcomes का अनुमान लगाने के लिए किया जा सकता है। उदाहरण के लिए, historical data के आधार पर **network traffic की volume का अनुमान लगाने** या **किसी समयावधि में होने वाले attacks की संख्या का अनुमान लगाने** के लिए linear regression का उपयोग किया जा सकता है। यह कुछ system metrics दिए जाने पर risk score या किसी attack का detection होने तक अपेक्षित समय का भी अनुमान लगा सकता है। व्यवहार में, intrusions या malware का पता लगाने के लिए classification algorithms (जैसे logistic regression या trees) अधिक सामान्य रूप से उपयोग किए जाते हैं, लेकिन linear regression एक foundation के रूप में काम करता है और regression-oriented analyses के लिए उपयोगी है।

#### **Linear Regression की प्रमुख विशेषताएँ:**

-   **समस्या का प्रकार:** Regression (continuous values का अनुमान लगाना)। Output पर threshold लागू किए बिना direct classification के लिए उपयुक्त नहीं है।

-   **व्याख्यात्मकता:** उच्च -- coefficients को आसानी से interpret किया जा सकता है, क्योंकि वे प्रत्येक feature के linear effect को दिखाते हैं।

-   **लाभ:** सरल और तेज़; regression tasks के लिए एक अच्छा baseline; जब वास्तविक संबंध लगभग linear हो, तब अच्छी तरह काम करता है।

-   **सीमाएँ:** complex या non-linear relationships को capture नहीं कर सकता (manual feature engineering के बिना); relationships non-linear होने पर underfitting की संभावना रहती है; outliers के प्रति sensitive होता है, जो results को skew कर सकते हैं।

-   **Best Fit ढूँढना:** संभावित categories को अलग करने वाली best fit line ढूँढने के लिए हम **Ordinary Least Squares (OLS)** नामक method का उपयोग करते हैं। यह method observed values और linear model द्वारा predicted values के बीच squared differences के योग को minimize करता है।

<details>
<summary>उदाहरण -- Intrusion Dataset में Connection Duration का अनुमान लगाना (Regression)
</summary>
नीचे हम NSL-KDD cybersecurity dataset का उपयोग करके linear regression प्रदर्शित करते हैं। हम इसे एक regression problem मानेंगे और अन्य features के आधार पर network connections की `duration` का अनुमान लगाएंगे। (वास्तव में, `duration` NSL-KDD का एक feature है; यहाँ इसका उपयोग केवल regression को समझाने के लिए किया गया है।) हम dataset को load करेंगे, उसे preprocess करेंगे (categorical features को encode करेंगे), linear regression model को train करेंगे, और test set पर Mean Squared Error (MSE) तथा R² score का evaluation करेंगे।
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
इस उदाहरण में, linear regression model अन्य network features से connection `duration` का अनुमान लगाने का प्रयास करता है। हम performance को Mean Squared Error (MSE) और R² से मापते हैं। 1.0 के करीब R² यह दर्शाता है कि model `duration` में होने वाले अधिकांश variance को समझाता है, जबकि कम या negative R² खराब fit को दर्शाता है। (यदि यहां R² कम हो तो आश्चर्यचकित न हों -- दिए गए features से `duration` का अनुमान लगाना कठिन हो सकता है, और यदि patterns जटिल हों तो linear regression उन्हें capture नहीं कर सकता।)
</details>

### Logistic Regression

Logistic regression एक **classification** algorithm है, जो इस probability को model करता है कि कोई instance किसी विशेष class से संबंधित है (आमतौर पर "positive" class)। अपने नाम के बावजूद, *logistic* regression का उपयोग discrete outcomes के लिए किया जाता है (linear regression के विपरीत, जिसका उपयोग continuous outcomes के लिए होता है)। इसका विशेष रूप से **binary classification** (दो classes, जैसे malicious बनाम benign) के लिए उपयोग किया जाता है, लेकिन इसे multi-class problems तक विस्तारित किया जा सकता है (softmax या one-vs-rest approaches का उपयोग करके)।<sup>[[3]](#references)</sup>

Logistic regression predicted values को probabilities में map करने के लिए logistic function (जिसे sigmoid function भी कहा जाता है) का उपयोग करता है। ध्यान दें कि sigmoid function एक ऐसी function है जिसके values 0 और 1 के बीच होते हैं और classification की आवश्यकताओं के अनुसार S-shaped curve में बढ़ते हैं, जो binary classification tasks के लिए उपयोगी है। इसलिए, प्रत्येक input के प्रत्येक feature को उसके assigned weight से multiply किया जाता है, और probability उत्पन्न करने के लिए result को sigmoid function से pass किया जाता है:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
जहाँ:

- `p(y=1|x)` वह probability है कि input `x` दिए जाने पर output `y` का मान 1 है
- `e` natural logarithm का base है
- `z` input features का linear combination है, जिसे आमतौर पर `z = w1*x1 + w2*x2 + ... + wn*xn + b` के रूप में दर्शाया जाता है। ध्यान दें कि इसके सबसे सरल रूप में यह एक सीधी रेखा होती है, लेकिन अधिक जटिल मामलों में यह कई dimensions वाला hyperplane बन जाता है (प्रत्येक feature के लिए एक)।

> [!TIP]
> *cybersecurity में उपयोग के मामले:* चूँकि कई security problems मूल रूप से yes/no decisions होती हैं, इसलिए Logistic Regression का व्यापक रूप से उपयोग किया जाता है। उदाहरण के लिए, कोई intrusion detection system किसी network connection की features के आधार पर यह तय करने के लिए Logistic Regression का उपयोग कर सकता है कि वह connection attack है या नहीं। phishing detection में, Logistic Regression किसी website की features (URL की length, `"@"` symbol की मौजूदगी आदि) को मिलाकर phishing होने की probability निकाल सकता है। इसका उपयोग शुरुआती पीढ़ी के spam filters में किया गया है और यह आज भी कई classification tasks के लिए एक मजबूत baseline है।

#### Binary के अलावा classification के लिए Logistic Regression

Logistic Regression को binary classification के लिए design किया गया है, लेकिन **one-vs-rest** (OvR) या **softmax regression** जैसी techniques का उपयोग करके इसे multi-class problems के लिए भी extend किया जा सकता है। OvR में प्रत्येक class के लिए एक अलग Logistic Regression model train किया जाता है, जिसमें उस class को positive class और बाकी सभी को अन्य classes माना जाता है। जिस class की predicted probability सबसे अधिक होती है, उसे final prediction के रूप में चुना जाता है। Softmax regression output layer पर softmax function लागू करके Logistic Regression को multiple classes के लिए generalize करता है और सभी classes के लिए probability distribution उत्पन्न करता है।

#### **Logistic Regression की मुख्य विशेषताएँ:**

-   **Problem का प्रकार:** Classification (आमतौर पर binary)। यह positive class की probability predict करता है।

-   **Interpretability:** उच्च -- linear regression की तरह, feature coefficients यह संकेत दे सकते हैं कि प्रत्येक feature outcome के log-odds को कैसे प्रभावित करता है। यह transparency security में अक्सर उपयोगी मानी जाती है, क्योंकि इससे यह समझने में मदद मिलती है कि कौन-से factors किसी alert में योगदान करते हैं।

-   **Advantages:** Train करने में सरल और तेज़; तब अच्छी तरह काम करता है जब features और outcome के log-odds के बीच संबंध linear हो। यह probabilities output करता है, जिससे risk scoring संभव होती है। उचित regularization के साथ, यह अच्छी तरह generalize करता है और plain linear regression की तुलना में multicollinearity को बेहतर ढंग से handle कर सकता है।

-   **Limitations:** यह feature space में linear decision boundary मानता है (यदि वास्तविक boundary complex/non-linear हो तो विफल हो सकता है)। यदि interactions या non-linear effects महत्वपूर्ण हों, तो यह कम प्रभावी हो सकता है, जब तक कि आप manually polynomial या interaction features न जोड़ें। इसके अलावा, यदि classes features के linear combination से आसानी से अलग न की जा सकें, तो Logistic Regression कम प्रभावी होता है।


<details>
<summary>उदाहरण -- Logistic Regression के साथ Phishing Website Detection:</summary>

हम **Phishing Websites Dataset** (UCI repository से) का उपयोग करेंगे, जिसमें websites की extracted features (जैसे URL में IP address है या नहीं, domain की age, HTML में suspicious elements की मौजूदगी आदि) और यह दर्शाने वाला label शामिल है कि site phishing है या legitimate।<sup>[[4]](#references)</sup> हम websites को classify करने के लिए एक Logistic Regression model train करेंगे और फिर test split पर इसकी accuracy, precision, recall, F1-score और ROC AUC का evaluation करेंगे।
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
इस phishing detection उदाहरण में, logistic regression प्रत्येक website के phishing होने की probability उत्पन्न करता है। Accuracy, precision, recall और F1 का मूल्यांकन करके हमें model के performance का अंदाज़ा मिलता है। उदाहरण के लिए, high recall का अर्थ होगा कि यह अधिकांश phishing sites को पकड़ लेता है (missed attacks को कम करना security के लिए महत्वपूर्ण है), जबकि high precision का अर्थ है कि इसमें false alarms कम हैं (analyst fatigue से बचने के लिए महत्वपूर्ण)। ROC AUC (Area Under the ROC Curve) performance का threshold-independent माप देता है (1.0 आदर्श है, जबकि 0.5 chance से बेहतर नहीं है)। Logistic regression अक्सर ऐसे tasks पर अच्छा perform करता है, लेकिन यदि phishing और legitimate sites के बीच decision boundary complex हो, तो अधिक शक्तिशाली non-linear models की आवश्यकता हो सकती है।

</details>

### Decision Trees

A decision tree एक versatile **supervised learning algorithm** है, जिसका उपयोग classification और regression दोनों tasks के लिए किया जा सकता है। यह data के features के आधार पर decisions का एक hierarchical tree-like model सीखता है। Tree का प्रत्येक internal node किसी विशेष feature पर एक test को दर्शाता है, प्रत्येक branch उस test के एक outcome को दर्शाती है, और प्रत्येक leaf node एक predicted class (classification के लिए) या value (regression के लिए) को दर्शाता है।<sup>[[5]](#references)</sup>

Tree बनाने के लिए, CART (Classification and Regression Tree) जैसे algorithms प्रत्येक चरण में data को split करने के लिए best feature और threshold चुनने हेतु **Gini impurity** या **information gain (entropy)** जैसे measures का उपयोग करते हैं। प्रत्येक split का लक्ष्य data को इस प्रकार partition करना होता है कि परिणामी subsets में target variable की homogeneity बढ़े (classification के लिए, प्रत्येक node का लक्ष्य अधिकतम pure होना होता है और उसमें मुख्य रूप से एक ही class होनी चाहिए)।

Decision trees **highly interpretable** होते हैं -- prediction के पीछे का logic समझने के लिए root से leaf तक के path का अनुसरण किया जा सकता है (जैसे, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"* )। यह cybersecurity में यह समझाने के लिए उपयोगी है कि कोई विशेष alert क्यों generate हुआ। Trees numerical और categorical data दोनों को स्वाभाविक रूप से handle कर सकते हैं और इन्हें बहुत कम preprocessing की आवश्यकता होती है (जैसे, feature scaling आवश्यक नहीं है)।

हालांकि, एक single decision tree training data पर आसानी से overfit कर सकता है, विशेषकर तब जब उसे बहुत deep बनाया गया हो (कई splits)। Overfitting को रोकने के लिए pruning जैसी techniques (tree depth सीमित करना या प्रत्येक leaf के लिए samples की minimum संख्या निर्धारित करना) अक्सर उपयोग की जाती हैं।

Decision tree के 3 मुख्य components होते हैं:
- **Root Node**: Tree का top node, जो पूरे dataset को दर्शाता है।
- **Internal Nodes**: वे nodes जो features और उन features के आधार पर decisions को दर्शाते हैं।
- **Leaf Nodes**: वे nodes जो final outcome या prediction को दर्शाते हैं।

एक tree अंततः इस प्रकार दिखाई दे सकता है:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *cybersecurity में उपयोग के मामले:* Intrusion Detection Systems में attacks की पहचान के लिए **rules** प्राप्त करने हेतु Decision trees का उपयोग किया गया है। उदाहरण के लिए, ID3/C4.5-based शुरुआती IDS human-readable rules generate करते थे, जो normal और malicious traffic में अंतर करते थे। इनका उपयोग malware analysis में भी किया जाता है, ताकि file के attributes (file size, section entropy, API calls, आदि) के आधार पर तय किया जा सके कि वह malicious है या नहीं। Decision trees की स्पष्टता उन्हें उन स्थितियों में उपयोगी बनाती है, जहां transparency आवश्यक होती है -- कोई analyst detection logic को validate करने के लिए tree का निरीक्षण कर सकता है।

#### **Decision Trees की मुख्य विशेषताएं:**

-   **समस्या का प्रकार:** Classification और regression दोनों। आमतौर पर attacks और normal traffic आदि के classification के लिए उपयोग किए जाते हैं।

-   **Interpretability:** बहुत अधिक -- model के decisions को visualize किया जा सकता है और if-then rules के एक समूह के रूप में समझा जा सकता है। Model के behavior में trust और verification के लिए यह security में एक प्रमुख लाभ है।

-   **लाभ:** Features के बीच non-linear relationships और interactions को capture कर सकते हैं (प्रत्येक split को एक interaction के रूप में देखा जा सकता है)। Features को scale करने या categorical variables को one-hot encode करने की आवश्यकता नहीं होती -- trees इन्हें native रूप से handle करते हैं। Fast inference (prediction केवल tree में एक path follow करना है)।

-   **सीमाएं:** यदि नियंत्रित न किया जाए तो overfitting की संभावना रहती है (एक deep tree training set को memorize कर सकता है)। ये unstable हो सकते हैं -- data में छोटे बदलावों से अलग tree structure बन सकता है। Single models के रूप में इनकी accuracy अधिक advanced methods से कम हो सकती है (Random Forests जैसे ensembles variance कम करके आमतौर पर बेहतर perform करते हैं)।

-   **Best Split ढूंढना:**
- **Gini Impurity**: किसी node की impurity को मापता है। कम Gini impurity बेहतर split का संकेत देती है। इसका formula है:

```plaintext
Gini = 1 - Σ(p_i^2)
```

जहां `p_i`, class `i` में instances का proportion है।

- **Entropy**: Dataset में uncertainty को मापता है। कम entropy बेहतर split का संकेत देती है। इसका formula है:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

जहां `p_i`, class `i` में instances का proportion है।

- **Information Gain**: Split के बाद entropy या Gini impurity में होने वाली कमी। Information gain जितना अधिक होगा, split उतना ही बेहतर होगा। इसकी गणना इस प्रकार की जाती है:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

इसके अलावा, tree को तब समाप्त किया जाता है जब:
- किसी node में सभी instances एक ही class से संबंधित हों। इससे overfitting हो सकता है।
- Tree की maximum depth (hardcoded) तक पहुंच जाए। यह overfitting रोकने का एक तरीका है।
- किसी node में instances की संख्या एक निश्चित threshold से कम हो। यह भी overfitting रोकने का एक तरीका है।
- आगे के splits से मिलने वाला information gain एक निश्चित threshold से कम हो। यह भी overfitting रोकने का एक तरीका है।

<details>
<summary>उदाहरण -- Intrusion Detection के लिए Decision Tree:</summary>
हम NSL-KDD dataset पर एक decision tree train करेंगे, ताकि network connections को *normal* या *attack* के रूप में classify किया जा सके। NSL-KDD classic KDD Cup 1999 dataset का improved version है, जिसमें protocol type, service, duration, failed logins की संख्या आदि जैसे features और attack type या "normal" का संकेत देने वाला label होता है। हम सभी attack types को एक "anomaly" class में map करेंगे (binary classification: normal बनाम anomaly)। Training के बाद, हम test set पर tree के performance का evaluation करेंगे।
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
इस decision tree उदाहरण में, extreme overfitting से बचने के लिए हमने tree depth को 10 तक सीमित रखा (`max_depth=10` parameter)। Metrics यह दिखाते हैं कि tree normal और attack traffic के बीच कितनी अच्छी तरह अंतर करता है। High recall का अर्थ होगा कि यह अधिकांश attacks पकड़ लेता है (जो IDS के लिए महत्वपूर्ण है), जबकि high precision का अर्थ है कि false alarms कम हैं। Decision trees structured data पर अक्सर decent accuracy प्राप्त करते हैं, लेकिन एक single tree संभवतः सर्वोत्तम संभावित performance तक नहीं पहुंच पाएगा। फिर भी, model की *interpretability* एक बड़ा लाभ है -- हम tree के splits की जांच करके देख सकते हैं कि कौन-से features (जैसे, `service`, `src_bytes`, आदि) किसी connection को malicious के रूप में flag करने में सबसे प्रभावशाली हैं।

</details>

### Random Forests

Random Forest एक **ensemble learning** method है, जो performance सुधारने के लिए decision trees पर आधारित होती है। एक random forest कई decision trees को train करता है (इसीलिए "forest") और final prediction करने के लिए उनके outputs को combine करता है (classification के लिए आमतौर पर majority vote द्वारा)। Random forest के दो मुख्य विचार **bagging** (bootstrap aggregating) और **feature randomness** हैं:

-   **Bagging:** प्रत्येक tree को training data के एक random bootstrap sample पर train किया जाता है (replacement के साथ sampling)। इससे trees के बीच diversity आती है।

-   **Feature Randomness:** किसी tree में प्रत्येक split पर splitting के लिए features के एक random subset पर विचार किया जाता है (सभी features के बजाय)। इससे trees का आपसी correlation और कम होता है।

कई trees के results का average लेने से random forest उस variance को कम करता है, जो एक single decision tree में हो सकती है। सरल शब्दों में, individual trees overfit कर सकते हैं या noisy हो सकते हैं, लेकिन diverse trees की बड़ी संख्या द्वारा मिलकर voting करने से ये errors smooth हो जाते हैं। इसका परिणाम अक्सर single decision tree की तुलना में **higher accuracy** और बेहतर generalization वाला model होता है। इसके अलावा, random forests feature importance का estimate प्रदान कर सकते हैं (यह देखकर कि प्रत्येक feature split औसतन impurity को कितना कम करता है)।

Random forests cybersecurity में intrusion detection, malware classification और spam detection जैसे tasks के लिए **workhorse** बन चुके हैं। वे अक्सर minimal tuning के साथ out-of-the-box अच्छा perform करते हैं और बड़े feature sets को handle कर सकते हैं। उदाहरण के लिए, intrusion detection में random forest individual decision tree से बेहतर perform कर सकता है, क्योंकि वह attacks के अधिक subtle patterns पकड़ता है और false positives कम करता है। Research ने दिखाया है कि NSL-KDD और UNSW-NB15 जैसे datasets में attacks को classify करने के मामले में random forests अन्य algorithms की तुलना में favorable performance करते हैं।<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** मुख्य रूप से classification (regression के लिए भी उपयोग किया जाता है)। Security logs में सामान्य high-dimensional structured data के लिए बहुत उपयुक्त।

-   **Interpretability:** Single decision tree की तुलना में कम -- आप एक साथ सैकड़ों trees को आसानी से visualize या explain नहीं कर सकते। हालांकि, feature importance scores यह समझने में कुछ सहायता देते हैं कि कौन-से attributes सबसे प्रभावशाली हैं।

-   **Advantages:** Ensemble effect के कारण single-tree models की तुलना में generally higher accuracy। Overfitting के प्रति robust -- individual trees overfit करने पर भी ensemble बेहतर generalize करता है। Numerical और categorical दोनों features को handle करता है और कुछ हद तक missing data को भी manage कर सकता है। यह outliers के प्रति भी relatively robust है।

-   **Limitations:** Model size बड़ा हो सकता है (कई trees, जिनमें से प्रत्येक potentially deep हो सकता है)। Predictions single tree की तुलना में धीमी होती हैं (क्योंकि आपको कई trees के results को aggregate करना पड़ता है)। कम interpretable -- हालांकि आपको important features का पता होता है, exact logic को simple rule की तरह आसानी से trace नहीं किया जा सकता। यदि dataset अत्यंत high-dimensional और sparse हो, तो बहुत बड़े forest को train करना computationally heavy हो सकता है।

-   **Training Process:**
1. **Bootstrap Sampling**: Multiple subsets (bootstrap samples) बनाने के लिए training data को replacement के साथ randomly sample करें।
2. **Tree Construction**: प्रत्येक bootstrap sample के लिए, प्रत्येक split पर features के random subset का उपयोग करके एक decision tree बनाएं। इससे trees के बीच diversity आती है।
3. **Aggregation**: Classification tasks के लिए, final prediction सभी trees की predictions के बीच majority vote लेकर की जाती है। Regression tasks के लिए, final prediction सभी trees की predictions का average होती है।

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
हम उसी NSL-KDD dataset (normal बनाम anomaly के रूप में binary labeled) का उपयोग करेंगे और एक Random Forest classifier को train करेंगे। हमें उम्मीद है कि ensemble averaging द्वारा variance कम होने के कारण random forest single decision tree जितना या उससे बेहतर perform करेगा। हम इसे उन्हीं metrics के साथ evaluate करेंगे।
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
रैंडम फॉरेस्ट आमतौर पर इस intrusion detection task पर मजबूत परिणाम प्राप्त करता है। डेटा के आधार पर, single decision tree की तुलना में हमें F1 या AUC जैसे metrics में सुधार दिखाई दे सकता है, विशेष रूप से recall या precision में। यह इस समझ के अनुरूप है कि *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*.<sup>[[6]](#references)</sup> Security operations के संदर्भ में, रैंडम फॉरेस्ट मॉडल कई decision rules का औसत लेने के कारण false alarms को कम करते हुए attacks को अधिक विश्वसनीय ढंग से flag कर सकता है। Forest से प्राप्त feature importance यह बता सकती है कि कौन-से network features attacks के सबसे अधिक संकेतक हैं (जैसे कुछ network services या packets की असामान्य counts)।

</details>

### Support Vector Machines (SVM)

Support Vector Machines मुख्य रूप से classification (और SVR के रूप में regression) के लिए उपयोग किए जाने वाले शक्तिशाली supervised learning models हैं। SVM **optimal separating hyperplane** खोजने का प्रयास करता है, जो दो classes के बीच margin को अधिकतम करता है। केवल training points का एक subset (boundary के सबसे निकट स्थित "support vectors") इस hyperplane की स्थिति निर्धारित करता है। Margin (support vectors और hyperplane के बीच की दूरी) को अधिकतम करके, SVMs आमतौर पर अच्छा generalization प्राप्त करते हैं।<sup>[[8]](#references)</sup>

SVM की शक्ति का एक प्रमुख कारण non-linear relationships को संभालने के लिए **kernel functions** का उपयोग करने की क्षमता है। डेटा को अप्रत्यक्ष रूप से एक higher-dimensional feature space में transform किया जा सकता है, जहाँ एक linear separator मौजूद हो सकता है। सामान्य kernels में polynomial, radial basis function (RBF), और sigmoid शामिल हैं। उदाहरण के लिए, यदि network traffic classes raw feature space में linearly separable नहीं हैं, तो RBF kernel उन्हें एक higher dimension में map कर सकता है, जहाँ SVM एक linear split खोजता है (जो original space में एक non-linear boundary के अनुरूप होता है)। Kernels चुनने की यह flexibility SVMs को विभिन्न प्रकार की समस्याओं से निपटने में सक्षम बनाती है।

SVMs high-dimensional feature spaces (जैसे text data या malware opcode sequences) वाली स्थितियों में और उन मामलों में अच्छा प्रदर्शन करने के लिए जाने जाते हैं जहाँ features की संख्या samples की संख्या की तुलना में अधिक होती है। 2000s में malware classification और anomaly-based intrusion detection जैसे कई शुरुआती cybersecurity applications में इनका व्यापक उपयोग हुआ और अक्सर high accuracy प्राप्त हुई।

हालाँकि, SVMs बहुत बड़े datasets तक आसानी से scale नहीं होते (training complexity samples की संख्या के संबंध में super-linear होती है, और memory usage अधिक हो सकता है क्योंकि इन्हें कई support vectors store करने पड़ सकते हैं)। व्यवहार में, millions of records वाले network intrusion detection जैसे tasks के लिए, सावधानीपूर्वक subsampling या approximate methods के उपयोग के बिना SVM बहुत धीमा हो सकता है।

#### **SVM की प्रमुख विशेषताएँ:**

-   **समस्या का प्रकार:** Classification (one-vs-one/one-vs-rest के माध्यम से binary या multiclass) और regression variants। अक्सर स्पष्ट margin separation वाली binary classification में उपयोग किया जाता है।

-   **Interpretability:** Medium -- SVMs decision trees या logistic regression जितने interpretable नहीं होते। यद्यपि आप यह पहचान सकते हैं कि कौन-से data points support vectors हैं और यह कुछ हद तक समझ सकते हैं कि कौन-से features प्रभावशाली हो सकते हैं (linear kernel case में weights के माध्यम से), व्यवहार में SVMs (विशेषकर non-linear kernels के साथ) को black-box classifiers माना जाता है।

-   **Advantages:** High-dimensional spaces में प्रभावी; kernel trick के माध्यम से complex decision boundaries को model कर सकते हैं; margin को maximize किए जाने पर overfitting के प्रति robust (विशेषकर उचित regularization parameter C के साथ); classes के बीच बड़ी दूरी न होने पर भी अच्छा काम करते हैं (best compromise boundary खोजते हैं)।

-   **Limitations:** बड़े datasets के लिए **computationally intensive** (data बढ़ने पर training और prediction दोनों खराब तरीके से scale होते हैं)। Kernel और regularization parameters (C, kernel type, RBF के लिए gamma आदि) की सावधानीपूर्वक tuning आवश्यक होती है। यह सीधे probabilistic outputs प्रदान नहीं करता (हालाँकि probabilities प्राप्त करने के लिए Platt scaling का उपयोग किया जा सकता है)। इसके अलावा, SVMs kernel parameters के चुनाव के प्रति sensitive हो सकते हैं --- गलत चुनाव underfit या overfit का कारण बन सकता है।

*Cybersecurity में उपयोग के मामले:* SVMs का उपयोग **malware detection** (जैसे extracted features या opcode sequences के आधार पर files को classify करना), **network anomaly detection** (traffic को normal बनाम malicious के रूप में classify करना), और **phishing detection** (URLs की features का उपयोग करके) में किया गया है। उदाहरण के लिए, एक SVM किसी email की features (कुछ keywords की counts, sender reputation scores आदि) लेकर उसे phishing या legitimate के रूप में classify कर सकता है। इनका उपयोग KDD जैसे feature sets पर **intrusion detection** के लिए भी किया गया है, जहाँ computation की कीमत पर अक्सर high accuracy प्राप्त हुई।

<details>
<summary>उदाहरण -- Malware Classification के लिए SVM:</summary>
हम फिर से phishing website dataset का उपयोग करेंगे, इस बार SVM के साथ। क्योंकि SVMs धीमे हो सकते हैं, आवश्यकता होने पर हम training के लिए data के एक subset का उपयोग करेंगे (dataset में लगभग 11k instances हैं, जिन्हें SVM उचित रूप से संभाल सकता है)। हम non-linear data के लिए सामान्य विकल्प RBF kernel का उपयोग करेंगे और ROC AUC calculate करने के लिए probability estimates enable करेंगे।
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
SVM model ऐसे metrics आउटपुट करेगा जिनकी तुलना हम उसी task पर logistic regression से कर सकते हैं। यदि features data को अच्छी तरह अलग करते हैं, तो हमें SVM की accuracy और AUC अधिक मिल सकती है। दूसरी ओर, यदि dataset में बहुत अधिक noise या overlapping classes हों, तो SVM logistic regression से स्पष्ट रूप से बेहतर प्रदर्शन नहीं कर सकता। व्यवहार में, जब features और class के बीच complex, non-linear relations होते हैं, तब SVM बेहतर परिणाम दे सकता है -- RBF kernel ऐसे घुमावदार decision boundaries को capture कर सकता है जिन्हें logistic regression नहीं पकड़ पाएगा। सभी models की तरह, bias और variance के बीच संतुलन बनाने के लिए `C` (regularization) और kernel parameters (जैसे RBF के लिए `gamma`) की सावधानीपूर्वक tuning आवश्यक है।

</details>

#### Logistic Regression और SVM के बीच अंतर

| पहलू | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log‑loss** (cross‑entropy) को minimise करता है। | **margin** को maximise करते हुए **hinge‑loss** को minimise करता है। |
| **Decision boundary** | ऐसा **best-fit hyperplane** खोजता है जो _P(y\|x)_ को model करता है। | **maximum-margin hyperplane** खोजता है (निकटतम points तक सबसे बड़ा gap)। |
| **Output** | **Probabilistic** – σ(w·x + b) के माध्यम से calibrated class probabilities देता है। | **Deterministic** – class labels लौटाता है; probabilities के लिए अतिरिक्त प्रक्रिया आवश्यक होती है (जैसे Platt scaling)। |
| **Regularisation** | L2 (default) या L1, जो under/over-fitting के बीच सीधे संतुलन बनाता है। | C parameter margin width और mis-classifications के बीच संतुलन बनाता है; kernel parameters complexity बढ़ाते हैं। |
| **Kernels / Non-linear** | इसका native form **linear** है; feature engineering द्वारा non-linearity जोड़ी जाती है। | Built-in **kernel trick** (RBF, poly आदि) इसे high-dim. space में complex boundaries model करने देता है। |
| **Scalability** | **O(nd)** में convex optimisation हल करता है; बहुत बड़े n को अच्छी तरह handle करता है। | specialised solvers के बिना training में memory/time **O(n²–n³)** हो सकता है; बहुत बड़े n के लिए कम अनुकूल है। |
| **Interpretability** | **High** – weights feature influence दिखाते हैं; odds ratio सहज रूप से समझ आता है। | Non-linear kernels के लिए **Low**; support vectors sparse होते हैं, लेकिन उन्हें समझाना आसान नहीं होता। |
| **Sensitivity to outliers** | Smooth log-loss का उपयोग करता है → कम sensitive होता है। | Hard margin के साथ hinge-loss **sensitive** हो सकता है; soft-margin (C) इसे कम करता है। |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – जहाँ **probabilities & explainability** महत्वपूर्ण हों। | Image/text classification, bio-informatics – जहाँ **complex boundaries** और **high-dimensional data** महत्वपूर्ण हों। |

* **यदि आपको calibrated probabilities, interpretability की आवश्यकता है या आप बहुत बड़े datasets पर काम करते हैं — तो Logistic Regression चुनें।**
* **यदि आपको ऐसा flexible model चाहिए जो manual feature engineering के बिना non-linear relations को capture कर सके — तो SVM (with kernels) चुनें।**
* दोनों convex objectives को optimise करते हैं, इसलिए **global minima की गारंटी होती है**, लेकिन SVM के kernels hyper-parameters और computational cost जोड़ते हैं।

### Naive Bayes

Naive Bayes **probabilistic classifiers** का एक family है, जो features के बीच strong independence assumption लागू करके Bayes' Theorem पर आधारित होता है। इस "naive" assumption के बावजूद, Naive Bayes कुछ applications में अक्सर आश्चर्यजनक रूप से अच्छा काम करता है, विशेष रूप से text या categorical data से जुड़े applications में, जैसे spam detection।<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem Naive Bayes classifiers का आधार है। यह random events की conditional और marginal probabilities के बीच संबंध बताता है। Formula है:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` class `A` की feature `B` दिए जाने पर posterior probability है।
- `P(B|A)` class `A` दिए जाने पर feature `B` की likelihood है।
- `P(A)` class `A` की prior probability है।
- `P(B)` feature `B` की prior probability है।

उदाहरण के लिए, यदि हम यह classify करना चाहते हैं कि कोई text किसी बच्चे द्वारा लिखा गया है या किसी adult द्वारा, तो हम text में मौजूद words को features के रूप में उपयोग कर सकते हैं। कुछ initial data के आधार पर, Naive Bayes classifier पहले से प्रत्येक संभावित class (child या adult) में प्रत्येक word के होने की probabilities calculate करेगा। जब कोई नया text दिया जाता है, तो यह text में मौजूद words के आधार पर प्रत्येक संभावित class की probability calculate करेगा और सबसे अधिक probability वाली class चुनेगा।

जैसा कि आप इस उदाहरण में देख सकते हैं, Naive Bayes classifier बहुत simple और fast है, लेकिन यह मानता है कि features independent हैं, जो real-world data में हमेशा सही नहीं होता।


#### Naive Bayes Classifiers के प्रकार

Data के प्रकार और features के distribution के आधार पर Naive Bayes classifiers कई प्रकार के होते हैं:
- **Gaussian Naive Bayes**: यह मानता है कि features Gaussian (normal) distribution का पालन करते हैं। यह continuous data के लिए उपयुक्त है।
- **Multinomial Naive Bayes**: यह मानता है कि features multinomial distribution का पालन करते हैं। यह discrete data के लिए उपयुक्त है, जैसे text classification में word counts।
- **Bernoulli Naive Bayes**: यह मानता है कि features binary (0 या 1) हैं। यह binary data के लिए उपयुक्त है, जैसे text classification में words की presence या absence।
- **Categorical Naive Bayes**: यह मानता है कि features categorical variables हैं। यह categorical data के लिए उपयुक्त है, जैसे fruits को उनके color और shape के आधार पर classify करना।


#### **Naive Bayes की मुख्य विशेषताएं:**

-   **समस्या का प्रकार:** Classification (binary या multi-class)। इसका उपयोग cybersecurity में text classification tasks (spam, phishing आदि) के लिए आमतौर पर किया जाता है।

-   **Interpretability:** Medium -- यह decision tree जितना directly interpretable नहीं है, लेकिन learned probabilities का निरीक्षण किया जा सकता है (जैसे, spam और ham emails में कौन से words सबसे अधिक संभावित हैं)। आवश्यकता पड़ने पर model का form (class दिए जाने पर प्रत्येक feature की probabilities) समझा जा सकता है।

-   **Advantages:** **Training और prediction बहुत fast** होते हैं, यहां तक कि बड़े datasets पर भी (instances की संख्या * features की संख्या के समानुपाती)। Probabilities का reliably estimation करने के लिए अपेक्षाकृत कम data की आवश्यकता होती है, विशेष रूप से proper smoothing के साथ। यह अक्सर baseline के रूप में आश्चर्यजनक रूप से accurate होता है, खासकर तब जब features independently class के लिए evidence प्रदान करते हैं। यह high-dimensional data (जैसे text से प्राप्त हजारों features) के साथ अच्छी तरह काम करता है। Smoothing parameter set करने के अलावा किसी complex tuning की आवश्यकता नहीं होती।

-   **Limitations:** यदि features अत्यधिक correlated हों, तो independence assumption accuracy को सीमित कर सकती है। उदाहरण के लिए, network data में `src_bytes` और `dst_bytes` जैसी features correlated हो सकती हैं; Naive Bayes उस interaction को capture नहीं करेगा। जैसे-जैसे data का आकार बहुत बड़ा होता जाता है, अधिक expressive models (जैसे ensembles या neural nets) feature dependencies सीखकर NB से बेहतर प्रदर्शन कर सकते हैं। इसके अलावा, यदि किसी attack की पहचान करने के लिए features के किसी विशेष combination की आवश्यकता हो (केवल individual features independently पर्याप्त न हों), तो NB को कठिनाई होगी।

> [!TIP]
> *cybersecurity में उपयोग के मामले:* इसका classic use **spam detection** है -- Naive Bayes शुरुआती spam filters का core था, जो कुछ tokens (words, phrases, IP addresses) की frequencies का उपयोग करके यह probability calculate करता था कि कोई email spam है। इसका उपयोग **phishing email detection** और **URL classification** में भी किया जाता है, जहां कुछ keywords या characteristics की presence (जैसे URL में "login.php" या URL path में `@`) phishing probability में योगदान देती है। Malware analysis में, कोई Naive Bayes classifier software में कुछ API calls या permissions की presence का उपयोग करके यह predict कर सकता है कि वह malware है या नहीं। हालांकि अधिक advanced algorithms अक्सर बेहतर प्रदर्शन करते हैं, Naive Bayes अपनी speed और simplicity के कारण एक अच्छा baseline बना हुआ है।

<details>
<summary>उदाहरण -- Phishing Detection के लिए Naive Bayes:</summary>
Naive Bayes को demonstrate करने के लिए, हम NSL-KDD intrusion dataset (binary labels के साथ) पर Gaussian Naive Bayes का उपयोग करेंगे। Gaussian NB प्रत्येक feature को प्रत्येक class के लिए normal distribution का पालन करने वाला मानेगा। यह एक rough choice है, क्योंकि कई network features discrete या highly skewed होती हैं, लेकिन इससे यह दिखता है कि continuous feature data पर NB कैसे लागू किया जा सकता है। हम binary features वाले dataset (जैसे triggered alerts के set) पर Bernoulli NB भी चुन सकते थे, लेकिन continuity के लिए यहां NSL-KDD का उपयोग करेंगे।
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
यह code हमलों का पता लगाने के लिए Naive Bayes classifier को train करता है। Naive Bayes training data के आधार पर `P(service=http | Attack)` और `P(Service=http | Normal)` जैसी probabilities की गणना करेगा और features के बीच independence मानकर चलेगा। इसके बाद यह देखे गए features के आधार पर नए connections को normal या attack के रूप में classify करने के लिए इन probabilities का उपयोग करेगा। NSL-KDD पर NB का performance अधिक advanced models जितना अच्छा नहीं हो सकता (क्योंकि feature independence का assumption यहां सही नहीं है), लेकिन यह अक्सर ठीक-ठाक परिणाम देता है और इसकी अत्यधिक speed इसका लाभ है। real-time email filtering या URLs की initial triage जैसे scenarios में, Naive Bayes model कम resource usage के साथ स्पष्ट रूप से malicious cases को जल्दी flag कर सकता है।

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors सबसे सरल machine learning algorithms में से एक है। यह एक **non-parametric, instance-based** method है, जो training set में मौजूद examples के साथ similarity के आधार पर predictions करता है। Classification के लिए इसका विचार यह है: किसी नए data point को classify करने के लिए training data में उसके सबसे निकट **k** points खोजें (जिन्हें उसके "nearest neighbors" कहा जाता है), और उन neighbors के बीच majority class assign करें। "Closeness" को एक distance metric द्वारा परिभाषित किया जाता है, आमतौर पर numeric data के लिए Euclidean distance का उपयोग होता है (अलग-अलग प्रकार के features या problems के लिए अन्य distances का उपयोग किया जा सकता है)।<sup>[[10]](#references)</sup>

K-NN को *कोई explicit training आवश्यक नहीं होती* -- "training" phase केवल dataset को store करना होता है। सारा काम query (prediction) के दौरान होता है: nearest points खोजने के लिए algorithm को query point और सभी training points के बीच distances compute करनी पड़ती हैं। इससे prediction time **training samples की संख्या के linear** होता है, जो बड़े datasets के लिए महंगा हो सकता है। इसी कारण k-NN छोटे datasets या ऐसे scenarios के लिए अधिक उपयुक्त है, जहां simplicity के लिए memory और speed का trade-off स्वीकार्य हो।

अपनी simplicity के बावजूद, k-NN बहुत complex decision boundaries को model कर सकता है (क्योंकि decision boundary प्रभावी रूप से examples के distribution द्वारा निर्धारित कोई भी shape हो सकती है)। जब decision boundary बहुत irregular हो और आपके पास काफी data हो, तब यह अच्छा perform करता है -- मूल रूप से data को "खुद बोलने" देता है। हालांकि, high dimensions में distance metrics कम meaningful हो सकते हैं (curse of dimensionality), और method को तब तक कठिनाई हो सकती है जब तक आपके पास samples की बहुत बड़ी संख्या न हो।

*cybersecurity में उपयोग के मामले:* k-NN को anomaly detection में apply किया गया है -- उदाहरण के लिए, कोई intrusion detection system किसी network event को malicious label कर सकता है, यदि उसके अधिकांश nearest neighbors (पिछले events) malicious थे। यदि normal traffic clusters बनाता है और attacks outliers होते हैं, तो k-NN approach (k=1 या छोटे k के साथ) मूल रूप से **nearest-neighbor anomaly detection** का काम करती है। Binary feature vectors का उपयोग करके malware families को classify करने के लिए भी K-NN का उपयोग किया गया है: किसी नई file को किसी विशेष malware family के रूप में classify किया जा सकता है, यदि वह feature space में उस family के known instances के बहुत निकट हो। व्यवहार में, k-NN अधिक scalable algorithms जितना common नहीं है, लेकिन यह conceptually straightforward है और कभी-कभी baseline या small-scale problems के लिए उपयोग किया जाता है।

#### **k-NN की मुख्य विशेषताएं:**

-   **समस्या का प्रकार:** Classification (और regression variants भी मौजूद हैं)। यह एक *lazy learning* method है -- इसमें कोई explicit model fitting नहीं होती।

-   **Interpretability:** Low से medium -- कोई global model या concise explanation नहीं होता, लेकिन किसी decision को प्रभावित करने वाले nearest neighbors को देखकर results को interpret किया जा सकता है (जैसे, "इस network flow को malicious classify किया गया क्योंकि यह इन 3 known malicious flows के समान है")। इसलिए explanations example-based हो सकती हैं।

-   **Advantages:** Implement और समझने में बहुत सरल। Data distribution के बारे में कोई assumptions नहीं बनाता (non-parametric)। Multi-class problems को naturally handle कर सकता है। यह इस अर्थ में **adaptive** है कि decision boundaries बहुत complex हो सकती हैं और data distribution से shape ले सकती हैं।

-   **Limitations:** बड़े datasets के लिए prediction slow हो सकता है (कई distances compute करनी पड़ती हैं)। यह memory-intensive है -- यह पूरा training data store करता है। High-dimensional feature spaces में performance घट जाती है, क्योंकि सभी points लगभग equidistant हो जाते हैं (जिससे "nearest" की अवधारणा कम meaningful हो जाती है)। *k* (neighbors की संख्या) को उचित रूप से चुनना आवश्यक है -- बहुत छोटा k noisy हो सकता है, जबकि बहुत बड़ा k अन्य classes के irrelevant points को शामिल कर सकता है। इसके अलावा, features को उचित रूप से scale किया जाना चाहिए, क्योंकि distance calculations scale के प्रति sensitive होती हैं।

<details>
<summary>उदाहरण -- Phishing Detection के लिए k-NN:</summary>

हम फिर से NSL-KDD (binary classification) का उपयोग करेंगे। क्योंकि k-NN computationally heavy है, इसलिए इस demonstration में इसे tractable बनाए रखने के लिए हम training data के एक subset का उपयोग करेंगे। हम full 125k में से, मान लें, 20,000 training samples चुनेंगे और k=5 neighbors का उपयोग करेंगे। Training के बाद (वास्तव में केवल data store करने के बाद), हम test set पर इसका evaluation करेंगे। Distance calculation के लिए हम features को भी scale करेंगे, ताकि scale के कारण कोई single feature अत्यधिक प्रभावशाली न हो जाए।
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
k-NN model training set के subset में 5 सबसे निकटतम connections को देखकर किसी connection को classify करेगा। उदाहरण के लिए, यदि उन neighbors में से 4 attacks (anomalies) हैं और 1 normal है, तो नए connection को attack के रूप में classify किया जाएगा। इसका performance उचित हो सकता है, हालांकि अक्सर उसी data पर अच्छी तरह tuned Random Forest या SVM जितना उच्च नहीं होता। फिर भी, k-NN कभी-कभी तब बेहतर प्रदर्शन कर सकता है जब class distributions बहुत अनियमित और जटिल हों -- यह प्रभावी रूप से memory-based lookup का उपयोग करता है। Cybersecurity में, k-NN (k=1 या छोटे k के साथ) का उपयोग उदाहरणों के आधार पर ज्ञात attack patterns की detection के लिए, या अधिक जटिल systems के एक component के रूप में (जैसे, clustering करने और फिर cluster membership के आधार पर classifying करने के लिए) किया जा सकता है।
</details>

### Gradient Boosting Machines (जैसे, XGBoost)

Gradient Boosting Machines structured data के लिए सबसे शक्तिशाली algorithms में से हैं। **Gradient boosting** से तात्पर्य weak learners (अक्सर decision trees) का ensemble sequential तरीके से बनाने की technique से है, जिसमें प्रत्येक नया model पिछले ensemble की errors को correct करता है। Bagging (Random Forests) के विपरीत, जिसमें trees parallel रूप से बनाए और average किए जाते हैं, boosting trees को *one by one* बनाता है; प्रत्येक tree उन instances पर अधिक ध्यान देता है जिन्हें पिछले trees ने गलत predict किया था।<sup>[[11]](#references)</sup>

हाल के वर्षों में सबसे लोकप्रिय implementations **XGBoost**, **LightGBM**, और **CatBoost** हैं, जो gradient boosting decision tree (GBDT) libraries हैं। ये machine learning competitions और applications में बेहद सफल रहे हैं और अक्सर **tabular datasets पर state-of-the-art performance प्राप्त करते हैं**। Cybersecurity में, researchers और practitioners ने gradient boosted trees का उपयोग **malware detection** (files या runtime behavior से निकाले गए features का उपयोग करके) और **network intrusion detection** जैसे tasks के लिए किया है। उदाहरण के लिए, gradient boosting model कई weak rules (trees) को जोड़ सकता है, जैसे "यदि बहुत से SYN packets और unusual port हों -> likely scan", और उन्हें एक strong composite detector में बदल सकता है, जो कई सूक्ष्म patterns को ध्यान में रखता है।

Boosted trees इतने प्रभावी क्यों होते हैं? Sequence में प्रत्येक tree को current ensemble की predictions की *residual errors* (gradients) पर train किया जाता है। इस तरह model धीरे-धीरे उन क्षेत्रों को **"boost"** करता है जहां वह कमजोर है। Base learners के रूप में decision trees के उपयोग से final model complex interactions और non-linear relations को capture कर सकता है। इसके अलावा, boosting में built-in regularization का एक रूप स्वाभाविक रूप से मौजूद होता है: कई छोटे trees जोड़कर (और उनके contributions को scale करने के लिए learning rate का उपयोग करके), उचित parameters चुने जाने पर यह अक्सर अत्यधिक overfitting के बिना अच्छी तरह generalize करता है।

#### **Gradient Boosting की प्रमुख विशेषताएं:**

-   **समस्या का प्रकार:** मुख्य रूप से classification और regression। Security में आमतौर पर classification (जैसे, किसी connection या file को binary रूप से classify करना) का उपयोग होता है। यह binary, multi-class (उपयुक्त loss के साथ), और ranking problems को भी handle करता है।

-   **Interpretability:** Low से medium। हालांकि एक single boosted tree छोटा होता है, full model में सैकड़ों trees हो सकते हैं, इसलिए पूरे model को मनुष्य आसानी से interpret नहीं कर सकता। हालांकि Random Forest की तरह यह feature importance scores प्रदान कर सकता है, और SHAP (SHapley Additive exPlanations) जैसे tools का उपयोग individual predictions को कुछ हद तक interpret करने के लिए किया जा सकता है।

-   **Advantages:** Structured/tabular data के लिए अक्सर **best performing** algorithm। Complex patterns और interactions detect कर सकता है। इसमें model complexity को customize करने और overfitting रोकने के लिए कई tuning knobs (trees की संख्या, trees की depth, learning rate, regularization terms) होते हैं। Modern implementations speed के लिए optimized हैं (जैसे, XGBoost second-order gradient info और efficient data structures का उपयोग करता है)। Appropriate loss functions के साथ या sample weights adjust करके उपयोग करने पर यह imbalanced data को बेहतर ढंग से handle करता है।

-   **Limitations:** Simpler models की तुलना में इसे tune करना अधिक complex है; यदि trees deep हों या trees की संख्या अधिक हो, तो training धीमी हो सकती है (हालांकि उसी data पर comparable deep neural network को train करने की तुलना में यह आमतौर पर अभी भी तेज होती है)। यदि इसे ठीक से tune न किया जाए तो model overfit कर सकता है (जैसे, insufficient regularization के साथ बहुत अधिक deep trees)। कई hyperparameters के कारण gradient boosting का प्रभावी उपयोग करने के लिए अधिक expertise या experimentation की आवश्यकता हो सकती है। इसके अलावा, tree-based methods की तरह यह बहुत sparse high-dimensional data को linear models या Naive Bayes जितनी efficiency से inherently handle नहीं करता (हालांकि इसे text classification में भी लागू किया जा सकता है, लेकिन feature engineering के बिना यह पहली पसंद नहीं हो सकता)।

> [!TIP]
> *Cybersecurity में use cases:* लगभग कहीं भी decision tree या random forest का उपयोग किया जा सकता है, gradient boosting model बेहतर accuracy प्राप्त कर सकता है। उदाहरण के लिए, **Microsoft's malware detection** competitions में binary files से engineered features पर XGBoost का व्यापक उपयोग हुआ है। **Network intrusion detection** research में अक्सर GBDTs (जैसे, CIC-IDS2017 या UNSW-NB15 datasets पर XGBoost) के साथ top results report किए जाते हैं। ये models विभिन्न प्रकार के features (protocol types, कुछ events की frequency, traffic की statistical features आदि) ले सकते हैं और उन्हें threats detect करने के लिए combine कर सकते हैं। Phishing detection में, gradient boosting URLs की lexical features, domain reputation features और page content features को combine करके बहुत high accuracy प्राप्त कर सकता है। Ensemble approach data में मौजूद कई corner cases और subtleties को cover करने में सहायता करती है।

<details>
<summary>उदाहरण -- Phishing Detection के लिए XGBoost:</summary>
हम phishing dataset पर gradient boosting classifier का उपयोग करेंगे। चीजों को सरल और self-contained रखने के लिए, हम `sklearn.ensemble.GradientBoostingClassifier` का उपयोग करेंगे (जो एक slower लेकिन straightforward implementation है)। आमतौर पर, बेहतर performance और additional features के लिए `xgboost` या `lightgbm` libraries का उपयोग किया जा सकता है। हम model को train करेंगे और पहले की तरह ही इसका evaluation करेंगे।
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
Gradient boosting model इस phishing dataset पर संभवतः बहुत high accuracy और AUC प्राप्त करेगा (अक्सर ऐसे models उचित tuning के साथ इस तरह के data पर 95% से अधिक accuracy प्राप्त कर सकते हैं, जैसा कि literature में देखा गया है। यह दर्शाता है कि GBDTs को *"the state of the art model for tabular dataset"* क्यों माना जाता है -- वे complex patterns को पकड़कर अक्सर simpler algorithms से बेहतर प्रदर्शन करते हैं।<sup>[[11]](#references)</sup> Cybersecurity के context में, इसका अर्थ अधिक phishing sites या attacks को कम misses के साथ पकड़ना हो सकता है। बेशक, overfitting के प्रति सावधान रहना आवश्यक है -- deployment के लिए ऐसा model विकसित करते समय हम आमतौर पर cross-validation जैसी techniques का उपयोग करेंगे और validation set पर performance monitor करेंगे।

</details>

### Models को Combining करना: Ensemble Learning और Stacking

Ensemble learning overall performance को बेहतर बनाने के लिए **multiple models को combine करने** की strategy है। हमने पहले ही कुछ specific ensemble methods देखे हैं: Random Forest (bagging के माध्यम से trees का ensemble) और Gradient Boosting (sequential boosting के माध्यम से trees का ensemble)। लेकिन ensembles को अन्य तरीकों से भी बनाया जा सकता है, जैसे **voting ensembles** या **stacked generalization (stacking)**। मुख्य विचार यह है कि अलग-अलग models अलग patterns पकड़ सकते हैं या उनकी अलग weaknesses हो सकती हैं; उन्हें combine करके हम **एक model की errors की भरपाई दूसरे model की strengths से कर सकते हैं**।<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** एक simple voting classifier में, हम कई diverse models (मान लें, एक logistic regression, एक decision tree और एक SVM) को train करते हैं और final prediction पर उनसे vote करवाते हैं (classification के लिए majority vote)। यदि हम votes को weight करें (जैसे, अधिक accurate models को higher weight दें), तो यह weighted voting scheme कहलाती है। यह आमतौर पर तब performance को बेहतर बनाता है जब individual models reasonably good और independent हों -- ensemble किसी individual model की mistake के risk को कम करता है, क्योंकि दूसरे models उसे correct कर सकते हैं। यह एक अकेली opinion के बजाय experts के panel जैसा है।

-   **Stacking (Stacked Ensemble):** Stacking इससे एक कदम आगे जाता है। Simple vote के बजाय, यह एक **meta-model** को **base models की predictions को सर्वोत्तम तरीके से combine करना सीखने** के लिए train करता है। उदाहरण के लिए, आप 3 अलग classifiers (base learners) को train करते हैं, फिर उनके outputs (या probabilities) को features के रूप में एक meta-classifier (अक्सर logistic regression जैसे simple model) में feed करते हैं, जो उन्हें blend करने का optimal तरीका सीखता है। Overfitting से बचने के लिए meta-model को validation set पर या cross-validation के माध्यम से train किया जाता है। Stacking अक्सर simple voting से बेहतर प्रदर्शन कर सकता है, क्योंकि यह सीखता है कि *किन परिस्थितियों में किन models पर अधिक भरोसा करना है*। Cybersecurity में, एक model network scans को पकड़ने में बेहतर हो सकता है, जबकि दूसरा malware beaconing को पकड़ने में बेहतर हो सकता है; stacking model प्रत्येक पर उचित रूप से निर्भर करना सीख सकता है।

Ensembles, चाहे voting के माध्यम से हों या stacking के माध्यम से, आमतौर पर **accuracy** और robustness को **boost** करते हैं। इसका downside बढ़ी हुई complexity और कभी-कभी कम interpretability है (हालांकि कुछ ensemble approaches, जैसे decision trees का average, फिर भी कुछ insight दे सकते हैं, जैसे feature importance)। Practice में, यदि operational constraints अनुमति दें, तो ensemble का उपयोग higher detection rates दे सकता है। Cybersecurity challenges (और सामान्यतः Kaggle competitions) में कई winning solutions performance के अंतिम हिस्से को प्राप्त करने के लिए ensemble techniques का उपयोग करते हैं।

<details>
<summary>Example -- Phishing Detection के लिए Voting Ensemble:</summary>
Model stacking को समझाने के लिए, आइए phishing dataset पर उन models में से कुछ को combine करते हैं जिनकी हमने चर्चा की थी। हम logistic regression, decision tree और k-NN को base learners के रूप में उपयोग करेंगे और उनकी predictions को aggregate करने के लिए Random Forest को meta-learner के रूप में उपयोग करेंगे। Meta-learner को base learners के outputs पर (training set पर cross-validation का उपयोग करके) train किया जाएगा। हमें उम्मीद है कि stacked model individual models जितना अच्छा या उनसे थोड़ा बेहतर प्रदर्शन करेगा।
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
Stacked ensemble base models की पूरक क्षमताओं का लाभ उठाता है। उदाहरण के लिए, logistic regression डेटा के linear पहलुओं को संभाल सकता है, decision tree विशिष्ट rule-like interactions को पकड़ सकता है, और k-NN feature space के local neighborhoods में बेहतर प्रदर्शन कर सकता है। Meta-model (यहाँ random forest) इन inputs को भार देना सीख सकता है। प्राप्त metrics अक्सर किसी एक model के metrics की तुलना में सुधार दिखाते हैं, भले ही यह सुधार थोड़ा ही हो। हमारे phishing उदाहरण में, यदि अकेले logistic का F1, मान लें, 0.95 और tree का 0.94 हो, तो stack 0.96 प्राप्त कर सकता है, क्योंकि वह उन क्षेत्रों को पहचान लेता है जहाँ प्रत्येक model से त्रुटियाँ होती हैं।

इस तरह के ensemble methods इस सिद्धांत को दर्शाते हैं कि *"कई models को मिलाने से आमतौर पर बेहतर generalization प्राप्त होता है"।*<sup>[[12]](#references)</sup> Cybersecurity में इसे कई detection engines रखकर लागू किया जा सकता है (एक rule-based, एक machine learning आधारित और एक anomaly-based हो सकता है), और फिर एक ऐसी layer रखी जा सकती है जो उनके alerts को aggregate करे -- प्रभावी रूप से ensemble का एक रूप -- ताकि अधिक confidence के साथ अंतिम निर्णय लिया जा सके। ऐसी systems deploy करते समय, added complexity पर विचार करना चाहिए और यह सुनिश्चित करना चाहिए कि ensemble को manage या explain करना अत्यधिक कठिन न हो जाए। लेकिन accuracy के दृष्टिकोण से, ensembles और stacking model performance सुधारने के शक्तिशाली tools हैं।

</details>

[deep-learning page](AI-Deep-Learning.md) में वर्णित neural-network approaches, intrusion detection के लिए इन classical models की पूरक हो सकती हैं, जब dataset और compute budget अतिरिक्त complexity को उचित ठहराते हों।<sup>[[13]](#references)</sup>

## References

- [1] [Cybersecurity में AI और Machine Learning - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression की व्याख्या - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Machine Learning और Multiple Datasets का उपयोग करके Phishing Attacks और Websites का Classification (एक Comparative Analysis)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Information Gain के साथ Random Forest Classifier का उपयोग करके Denial of Services Attack Detection"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique का उपयोग करके intrusion detection system के लिए machine learning models का Performance analysis"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Support Vector Machine क्या है? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [k-Nearest Neighbors (KNN) क्या है? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT को सरलता से समझना: LightGBM, XGBoost और CatBoost कैसे काम करते हैं - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Strengths को मिलाकर Model Performance बढ़ाना - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Deep Learning Intrusion Detection Systems को कैसे बेहतर बनाता है](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
