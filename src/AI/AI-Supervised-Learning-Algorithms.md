# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## मूल जानकारी

Supervised learning, labeled data का उपयोग करके ऐसे models को train करता है जो नए और पहले न देखे गए inputs पर predictions कर सकें। Cybersecurity में supervised machine learning का उपयोग intrusion detection (network traffic को *normal* या *attack* के रूप में classify करना), malware detection (malicious software को benign software से अलग करना), phishing detection (fraudulent websites या emails की पहचान करना) और spam filtering जैसे tasks में व्यापक रूप से किया जाता है। प्रत्येक algorithm की अपनी strengths होती हैं और यह अलग-अलग प्रकार की problems (classification या regression) के लिए उपयुक्त होता है। नीचे हम प्रमुख supervised learning algorithms की समीक्षा करेंगे, बताएंगे कि वे कैसे काम करते हैं, और वास्तविक cybersecurity datasets पर उनके उपयोग का प्रदर्शन करेंगे। हम यह भी चर्चा करेंगे कि models को combine करना (ensemble learning) predictive performance को अक्सर बेहतर बना सकता है।

## Algorithms

-   **Linear Regression:** Numeric outcomes की prediction करने वाला एक fundamental regression algorithm, जो data पर एक linear equation fit करता है।

-   **Logistic Regression:** अपने नाम के बावजूद एक classification algorithm, जो binary outcome की probability को model करने के लिए logistic function का उपयोग करता है।

-   **Decision Trees:** Tree-structured models जो predictions करने के लिए features के आधार पर data को split करते हैं; इनका उपयोग अक्सर इनकी interpretability के लिए किया जाता है।

-   **Random Forests:** Decision trees का एक ensemble (bagging के माध्यम से), जो accuracy को बेहतर बनाता है और overfitting को कम करता है।

-   **Support Vector Machines (SVM):** Max-margin classifiers जो optimal separating hyperplane खोजते हैं; non-linear data के लिए kernels का उपयोग कर सकते हैं।

-   **Naive Bayes:** Bayes' theorem पर आधारित एक probabilistic classifier, जिसमें feature independence की assumption होती है और जिसका उपयोग spam filtering में प्रसिद्ध है।

-   **k-Nearest Neighbors (k-NN):** एक सरल "instance-based" classifier, जो किसी sample को उसके nearest neighbors की majority class के आधार पर label करता है।

-   **Gradient Boosting Machines:** Ensemble models (जैसे XGBoost, LightGBM), जो weaker learners (आमतौर पर decision trees) को क्रमिक रूप से जोड़कर एक strong predictor बनाते हैं।

नीचे दिए गए प्रत्येक section में algorithm का improved description और `pandas` तथा `scikit-learn` जैसी libraries (और neural network example के लिए `PyTorch`) का उपयोग करने वाला एक **Python code example** दिया गया है। Examples publicly available cybersecurity datasets (जैसे intrusion detection के लिए NSL-KDD और एक Phishing Websites dataset) का उपयोग करते हैं और एक consistent structure का पालन करते हैं:

1.  **Dataset load करें** (यदि उपलब्ध हो, तो URL के माध्यम से download करें)।

2.  **Data preprocess करें** (जैसे categorical features को encode करना, values को scale करना और data को train/test sets में split करना)।

3.  **Training data** पर model train करें।

4.  **Test set** पर metrics का उपयोग करके evaluate करें: classification के लिए accuracy, precision, recall, F1-score और ROC AUC (तथा regression के लिए mean squared error)।

आइए प्रत्येक algorithm को विस्तार से समझते हैं:

### Linear Regression

Linear regression एक **regression** algorithm है, जिसका उपयोग continuous numeric values की prediction करने के लिए किया जाता है। यह input features (independent variables) और output (dependent variable) के बीच linear relationship की assumption करता है। Model एक ऐसी straight line (या higher dimensions में hyperplane) fit करने का प्रयास करता है, जो features और target के बीच के relationship को सबसे अच्छी तरह दर्शाती है। आमतौर पर यह predicted और actual values के बीच squared errors के sum को minimize करके किया जाता है (Ordinary Least Squares method)।<sup>[[8]](#references)</sup>

Linear regression को दर्शाने का सबसे सरल तरीका एक line है:
```plaintext
y = mx + b
```
जहाँ:

- `y` predicted value (output) है
- `m` line का slope (coefficient) है
- `x` input feature है
- `b` y-intercept है

linear regression का लक्ष्य ऐसी best-fitting line खोजना है जो dataset में predicted values और actual values के बीच के अंतर को न्यूनतम करे। बेशक, यह बहुत सरल स्थिति है: यह 2 categories को अलग करने वाली एक सीधी line होगी, लेकिन यदि अधिक dimensions जोड़े जाएँ, तो line अधिक जटिल हो जाती है:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *cybersecurity में उपयोग के मामले:* Linear regression स्वयं core security tasks के लिए कम सामान्य है (जो अक्सर classification होते हैं), लेकिन इसे numerical outcomes का अनुमान लगाने के लिए लागू किया जा सकता है। उदाहरण के लिए, historical data के आधार पर network traffic की **मात्रा का अनुमान लगाने** या **किसी समयावधि में होने वाले attacks की संख्या का अनुमान लगाने** के लिए linear regression का उपयोग किया जा सकता है। यह कुछ system metrics दिए जाने पर risk score या attack का पता चलने तक अपेक्षित समय का भी अनुमान लगा सकता है। व्यवहार में, intrusions या malware का पता लगाने के लिए classification algorithms (जैसे logistic regression या trees) अधिक सामान्य रूप से उपयोग किए जाते हैं, लेकिन linear regression regression-oriented analyses की नींव के रूप में काम करता है और उपयोगी है।

#### **Linear Regression की प्रमुख विशेषताएं:**

-   **समस्या का प्रकार:** Regression (continuous values का अनुमान लगाना)। Output पर threshold लागू किए बिना direct classification के लिए उपयुक्त नहीं है।

-   **व्याख्येयता:** उच्च -- coefficients को आसानी से समझा जा सकता है और वे प्रत्येक feature के linear effect को दिखाते हैं।

-   **लाभ:** सरल और तेज; regression tasks के लिए एक अच्छा baseline; जब वास्तविक संबंध लगभग linear हो, तब अच्छी तरह काम करता है।

-   **सीमाएं:** (manual feature engineering के बिना) complex या non-linear relationships को capture नहीं कर सकता; relationships non-linear होने पर underfitting की संभावना रहती है; outliers के प्रति sensitive होता है, जो results को प्रभावित कर सकते हैं।

-   **Best Fit खोजना:** संभावित categories को अलग करने वाली best fit line खोजने के लिए हम **Ordinary Least Squares (OLS)** नामक method का उपयोग करते हैं। यह method observed values और linear model द्वारा predicted values के बीच squared differences के योग को minimize करता है।

<details>
<summary>Example -- Intrusion Dataset में Connection Duration का अनुमान लगाना (Regression)
</summary>
नीचे हम NSL-KDD cybersecurity dataset का उपयोग करके linear regression प्रदर्शित करते हैं। हम इसे एक regression problem के रूप में लेंगे और अन्य features के आधार पर network connections की `duration` का अनुमान लगाएंगे। (वास्तव में, `duration` NSL-KDD का एक feature है; यहां हम इसका उपयोग केवल regression समझाने के लिए कर रहे हैं।) हम dataset load करते हैं, उसे preprocess करते हैं (categorical features को encode करते हैं), linear regression model को train करते हैं, और test set पर Mean Squared Error (MSE) तथा R² score का मूल्यांकन करते हैं।
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
इस उदाहरण में, linear regression model अन्य network features से connection `duration` का अनुमान लगाने का प्रयास करता है। हम performance को Mean Squared Error (MSE) और R² से मापते हैं। 1.0 के निकट R² यह दर्शाता है कि model `duration` में मौजूद अधिकांश variance को समझाता है, जबकि कम या negative R² खराब fit को दर्शाता है। (यदि यहां R² कम हो तो आश्चर्यचकित न हों -- दिए गए features से `duration` का अनुमान लगाना कठिन हो सकता है, और यदि patterns complex हों तो linear regression उन्हें capture नहीं कर सकता।)
</details>

### Logistic Regression

Logistic regression एक **classification** algorithm है, जो इस संभावना को model करता है कि कोई instance किसी विशेष class से संबंधित है (आमतौर पर "positive" class)। अपने नाम के बावजूद, *logistic* regression का उपयोग discrete outcomes के लिए किया जाता है (linear regression के विपरीत, जिसका उपयोग continuous outcomes के लिए होता है)। इसका उपयोग विशेष रूप से **binary classification** (दो classes, जैसे malicious बनाम benign) के लिए किया जाता है, लेकिन इसे multi-class problems तक भी विस्तारित किया जा सकता है (softmax या one-vs-rest approaches का उपयोग करके)।<sup>[[1]](#references)</sup>

Logistic regression predicted values को probabilities में map करने के लिए logistic function (जिसे sigmoid function भी कहा जाता है) का उपयोग करता है। ध्यान दें कि sigmoid function एक ऐसा function है जिसकी values 0 और 1 के बीच होती हैं और classification की आवश्यकताओं के अनुसार S-shaped curve में बढ़ती हैं, जो binary classification tasks के लिए उपयोगी है। इसलिए, प्रत्येक input के प्रत्येक feature को उसके assigned weight से multiply किया जाता है, और probability उत्पन्न करने के लिए result को sigmoid function से pass किया जाता है:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` इनपुट `x` दिए जाने पर आउटपुट `y` के 1 होने की probability है
- `e` natural logarithm का base है
- `z` इनपुट features का linear combination है, जिसे आमतौर पर `z = w1*x1 + w2*x2 + ... + wn*xn + b` के रूप में दर्शाया जाता है। ध्यान दें कि अपने सबसे सरल रूप में यह फिर से एक सीधी रेखा होती है, लेकिन अधिक जटिल मामलों में यह कई आयामों वाला hyperplane बन जाता है (प्रत्येक feature के लिए एक आयाम)।

> [!TIP]
> *cybersecurity में उपयोग के मामले:* चूंकि कई security समस्याएं मूल रूप से हां/नहीं के निर्णय होती हैं, Logistic Regression का व्यापक रूप से उपयोग किया जाता है। उदाहरण के लिए, कोई intrusion detection system किसी network connection की features के आधार पर यह तय करने के लिए Logistic Regression का उपयोग कर सकता है कि वह connection attack है या नहीं। Phishing detection में, Logistic Regression किसी website की features (URL की लंबाई, `"@"` symbol की मौजूदगी आदि) को phishing होने की probability में संयोजित कर सकता है। इसका उपयोग शुरुआती पीढ़ी के spam filters में किया गया है और यह कई classification tasks के लिए अब भी एक मजबूत baseline है।

#### गैर-बाइनरी classification के लिए Logistic Regression

Logistic Regression को binary classification के लिए design किया गया है, लेकिन इसे **one-vs-rest** (OvR) या **softmax regression** जैसी techniques का उपयोग करके multi-class problems को संभालने के लिए विस्तारित किया जा सकता है। OvR में, प्रत्येक class के लिए एक अलग Logistic Regression model train किया जाता है, जिसमें उस class को positive class और बाकी सभी classes को अन्य classes माना जाता है। सबसे अधिक predicted probability वाली class को final prediction के रूप में चुना जाता है। Softmax regression output layer पर softmax function लागू करके Logistic Regression को multiple classes तक सामान्यीकृत करता है, जिससे सभी classes के लिए probability distribution प्राप्त होता है।

#### **Logistic Regression की मुख्य विशेषताएं:**

-   **Problem का प्रकार:** Classification (आमतौर पर binary)। यह positive class की probability predict करता है।

-   **Interpretability:** उच्च -- linear regression की तरह, feature coefficients यह संकेत दे सकते हैं कि प्रत्येक feature outcome के log-odds को किस प्रकार प्रभावित करता है। यह transparency security में अक्सर उपयोगी मानी जाती है, क्योंकि इससे यह समझने में मदद मिलती है कि कौन-से factors किसी alert में योगदान करते हैं।

-   **Advantages:** Train करने में सरल और तेज; तब अच्छी तरह काम करता है जब features और outcome के log-odds के बीच संबंध linear हो। यह probabilities output करता है, जिससे risk scoring संभव होती है। उचित regularization के साथ, यह अच्छी तरह generalize करता है और plain linear regression की तुलना में multicollinearity को बेहतर ढंग से संभाल सकता है।

-   **Limitations:** यह feature space में linear decision boundary मानता है (यदि वास्तविक boundary complex/non-linear हो तो असफल हो सकता है)। उन problems पर इसका प्रदर्शन कमजोर हो सकता है जहां interactions या non-linear effects महत्वपूर्ण हों, जब तक कि आप manually polynomial या interaction features न जोड़ें। इसके अलावा, यदि classes features के linear combination द्वारा आसानी से separable न हों, तो Logistic Regression कम प्रभावी होता है।


<details>
<summary>Example -- Logistic Regression के साथ Phishing Website Detection:</summary>

हम **Phishing Websites Dataset** (UCI repository से) का उपयोग करेंगे, जिसमें websites की extracted features (जैसे URL में IP address है या नहीं, domain की age, HTML में suspicious elements की मौजूदगी आदि) और यह दर्शाने वाला label शामिल है कि site phishing है या legitimate। हम websites को classify करने के लिए Logistic Regression model train करेंगे और फिर test split पर इसकी accuracy, precision, recall, F1-score और ROC AUC का evaluation करेंगे।
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
इस phishing detection उदाहरण में, logistic regression प्रत्येक website के phishing होने की probability उत्पन्न करता है। accuracy, precision, recall और F1 का मूल्यांकन करके हमें model के प्रदर्शन का अंदाज़ा मिलता है। उदाहरण के लिए, high recall का अर्थ होगा कि यह अधिकांश phishing sites को पकड़ लेता है (missed attacks को कम करने के लिए security में महत्वपूर्ण), जबकि high precision का अर्थ है कि इसमें false alarms कम हैं (analyst fatigue से बचने के लिए महत्वपूर्ण)। ROC AUC (Area Under the ROC Curve) performance का threshold-independent माप देता है (1.0 आदर्श है, जबकि 0.5 chance से बेहतर नहीं है)। Logistic regression अक्सर ऐसे tasks पर अच्छा प्रदर्शन करता है, लेकिन यदि phishing और legitimate sites के बीच decision boundary जटिल है, तो अधिक शक्तिशाली non-linear models की आवश्यकता हो सकती है।

</details>

### Decision Trees

Decision tree एक बहुमुखी **supervised learning algorithm** है, जिसका उपयोग classification और regression दोनों tasks के लिए किया जा सकता है। यह data के features के आधार पर decisions का एक hierarchical tree-like model सीखता है। Tree का प्रत्येक internal node किसी विशेष feature पर एक test को दर्शाता है, प्रत्येक branch उस test के एक outcome को दर्शाती है, और प्रत्येक leaf node एक predicted class (classification के लिए) या value (regression के लिए) को दर्शाता है।<sup>[[2]](#references)</sup>

Tree बनाने के लिए, CART (Classification and Regression Tree) जैसे algorithms प्रत्येक step पर data को split करने के लिए best feature और threshold चुनने हेतु **Gini impurity** या **information gain (entropy)** जैसे measures का उपयोग करते हैं। प्रत्येक split का लक्ष्य data को इस प्रकार partition करना होता है कि resulting subsets में target variable की homogeneity बढ़े (classification के लिए, प्रत्येक node को यथासंभव pure बनाने का लक्ष्य होता है, जिसमें मुख्य रूप से एक ही class हो)।

Decision trees **highly interpretable** होते हैं -- prediction के पीछे के logic को समझने के लिए root से leaf तक के path का अनुसरण किया जा सकता है (जैसे, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"* )। यह cybersecurity में यह समझाने के लिए उपयोगी है कि कोई विशेष alert क्यों उठाया गया। Trees numerical और categorical data दोनों को स्वाभाविक रूप से संभाल सकते हैं और इन्हें बहुत कम preprocessing की आवश्यकता होती है (जैसे, feature scaling आवश्यक नहीं होती)।

हालांकि, एक single decision tree training data पर आसानी से overfit कर सकता है, विशेष रूप से तब जब उसे बहुत गहरा बनाया गया हो (कई splits)। Overfitting को रोकने के लिए pruning जैसी techniques (tree depth को सीमित करना या प्रत्येक leaf के लिए samples की minimum संख्या निर्धारित करना) का अक्सर उपयोग किया जाता है।

Decision tree के 3 मुख्य components होते हैं:
- **Root Node**: Tree का top node, जो पूरे dataset को दर्शाता है।
- **Internal Nodes**: वे nodes जो features और उन features के आधार पर decisions को दर्शाते हैं।
- **Leaf Nodes**: वे nodes जो final outcome या prediction को दर्शाते हैं।

एक tree अंततः इस तरह दिखाई दे सकता है:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *cybersecurity में उपयोग के मामले:* Decision trees का उपयोग intrusion detection systems में attacks की पहचान के लिए **rules** प्राप्त करने हेतु किया जाता रहा है। उदाहरण के लिए, ID3/C4.5-based शुरुआती IDS normal और malicious traffic में अंतर करने के लिए human-readable rules generate करते थे। इनका उपयोग malware analysis में भी किया जाता है, ताकि file के attributes (file size, section entropy, API calls आदि) के आधार पर यह तय किया जा सके कि वह malicious है या नहीं। Decision trees की स्पष्टता उन्हें उन स्थितियों में उपयोगी बनाती है, जहां transparency आवश्यक होती है -- कोई analyst detection logic को validate करने के लिए tree का निरीक्षण कर सकता है।

#### **Decision Trees की मुख्य विशेषताएं:**

-   **समस्या का प्रकार:** Classification और regression दोनों। इनका उपयोग attacks और normal traffic आदि के classification के लिए सामान्यतः किया जाता है।

-   **Interpretability:** बहुत अधिक -- model के decisions को visualize किया जा सकता है और if-then rules के एक set के रूप में समझा जा सकता है। Security में trust और model behavior के verification के लिए यह एक बड़ा लाभ है।

-   **लाभ:** Features के बीच non-linear relationships और interactions को capture कर सकते हैं (प्रत्येक split को एक interaction के रूप में देखा जा सकता है)। Features को scale करने या categorical variables को one-hot encode करने की आवश्यकता नहीं होती -- trees इन्हें native रूप से handle करते हैं। Fast inference (prediction केवल tree में एक path follow करना है)।

-   **सीमाएं:** यदि इन्हें नियंत्रित न किया जाए तो overfitting की संभावना रहती है (एक deep tree training set को memorize कर सकता है)। ये unstable हो सकते हैं -- data में छोटे बदलावों से अलग tree structure बन सकता है। Single models के रूप में इनकी accuracy अधिक advanced methods से कम हो सकती है (Random Forests जैसे ensembles variance को कम करके सामान्यतः बेहतर perform करते हैं)।

-   **Best Split ढूंढना:**
- **Gini Impurity**: किसी node की impurity को measure करता है। कम Gini impurity बेहतर split को दर्शाती है। Formula है:

```plaintext
Gini = 1 - Σ(p_i^2)
```

जहां `p_i`, class `i` में instances का proportion है।

- **Entropy**: Dataset में uncertainty को measure करता है। कम entropy बेहतर split को दर्शाती है। Formula है:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

जहां `p_i`, class `i` में instances का proportion है।

- **Information Gain**: किसी split के बाद entropy या Gini impurity में होने वाली कमी। Information gain जितना अधिक होगा, split उतना ही बेहतर होगा। इसकी गणना इस प्रकार की जाती है:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

इसके अलावा, tree को तब समाप्त किया जाता है जब:
- किसी node में सभी instances एक ही class से संबंधित हों। इससे overfitting हो सकता है।
- Tree की maximum depth (hardcoded) तक पहुंच जाए। यह overfitting को रोकने का एक तरीका है।
- किसी node में instances की संख्या एक निश्चित threshold से कम हो। यह भी overfitting को रोकने का एक तरीका है।
- Further splits से मिलने वाला information gain एक निश्चित threshold से कम हो। यह भी overfitting को रोकने का एक तरीका है।

<details>
<summary>Example -- Intrusion Detection के लिए Decision Tree:</summary>
हम NSL-KDD dataset पर एक decision tree train करेंगे, ताकि network connections को *normal* या *attack* के रूप में classify किया जा सके। NSL-KDD classic KDD Cup 1999 dataset का improved version है, जिसमें protocol type, service, duration, failed logins की संख्या आदि जैसे features और attack type या "normal" को दर्शाने वाला एक label होता है। हम सभी attack types को एक "anomaly" class में map करेंगे (binary classification: normal बनाम anomaly)। Training के बाद, हम test set पर tree के performance का evaluation करेंगे।
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
इस decision tree उदाहरण में, अत्यधिक overfitting से बचने के लिए हमने tree की depth को 10 तक सीमित किया है (`max_depth=10` parameter)। Metrics यह दिखाते हैं कि tree normal और attack traffic के बीच कितनी अच्छी तरह अंतर करता है। High recall का अर्थ होगा कि यह अधिकांश attacks को पकड़ लेता है (जो IDS के लिए महत्वपूर्ण है), जबकि high precision का अर्थ है कि false alarms कम हैं। Decision trees structured data पर अक्सर अच्छी accuracy प्राप्त करते हैं, लेकिन एक single tree संभवतः सर्वोत्तम performance तक नहीं पहुंच पाएगा। फिर भी, model की *interpretability* एक बड़ा लाभ है -- हम tree के splits की जांच करके देख सकते हैं कि, उदाहरण के लिए, कौन-से features (जैसे `service`, `src_bytes`, आदि) किसी connection को malicious के रूप में flag करने में सबसे अधिक प्रभावशाली हैं।

</details>

### Random Forests

Random Forest एक **ensemble learning** method है, जो performance सुधारने के लिए decision trees पर आधारित होती है। एक random forest कई decision trees को train करता है (इसीलिए "forest") और final prediction करने के लिए उनके outputs को combine करता है (classification के लिए आमतौर पर majority vote द्वारा)। Random forest के दो मुख्य विचार **bagging** (bootstrap aggregating) और **feature randomness** हैं:

-   **Bagging:** प्रत्येक tree को training data के एक random bootstrap sample पर train किया जाता है (sample को replacement के साथ लिया जाता है)। इससे trees के बीच diversity आती है।

-   **Feature Randomness:** tree में प्रत्येक split पर splitting के लिए features के एक random subset पर विचार किया जाता है (सभी features के बजाय)। इससे trees के बीच correlation और कम हो जाता है।

कई trees के results का average लेने से random forest उस variance को कम करता है, जो किसी single decision tree में हो सकता है। सरल शब्दों में, individual trees overfit कर सकते हैं या noisy हो सकते हैं, लेकिन diverse trees की बड़ी संख्या का मिलकर voting करना उन errors को smooth कर देता है। इसका परिणाम अक्सर single decision tree की तुलना में **higher accuracy** और बेहतर generalization वाला model होता है। इसके अलावा, random forests feature importance का estimate प्रदान कर सकते हैं (यह देखकर कि प्रत्येक feature split औसतन impurity को कितना कम करता है)।

Random forests intrusion detection, malware classification और spam detection जैसे tasks के लिए **workhorse in cybersecurity** बन गए हैं। ये अक्सर minimal tuning के साथ out-of-the-box अच्छा perform करते हैं और बड़े feature sets को handle कर सकते हैं। उदाहरण के लिए, intrusion detection में random forest individual decision tree से बेहतर perform कर सकता है, क्योंकि यह attacks के अधिक subtle patterns को कम false positives के साथ पकड़ता है। Research से पता चला है कि NSL-KDD और UNSW-NB15 जैसे datasets में attacks को classify करने के मामले में random forests ने अन्य algorithms की तुलना में favorable performance किया है।<sup>[[3]](#references)[[9]](#references)</sup>

#### **Random Forests की मुख्य विशेषताएं:**

-   **Type of Problem:** मुख्य रूप से classification (regression के लिए भी उपयोग किया जाता है)। यह security logs में सामान्य high-dimensional structured data के लिए बहुत उपयुक्त है।

-   **Interpretability:** single decision tree की तुलना में कम -- आप एक साथ सैकड़ों trees को आसानी से visualize या explain नहीं कर सकते। हालांकि, feature importance scores इस बारे में कुछ insight देते हैं कि कौन-से attributes सबसे अधिक प्रभावशाली हैं।

-   **Advantages:** ensemble effect के कारण single-tree models की तुलना में generally higher accuracy। Overfitting के प्रति robust -- individual trees overfit करने पर भी ensemble बेहतर generalize करता है। Numerical और categorical दोनों features को handle करता है और कुछ हद तक missing data को भी manage कर सकता है। यह outliers के प्रति भी relatively robust है।

-   **Limitations:** Model size बड़ा हो सकता है (कई trees, जिनमें से प्रत्येक potentially deep हो सकता है)। Predictions single tree की तुलना में धीमे होते हैं (क्योंकि आपको कई trees के results को aggregate करना पड़ता है)। कम interpretable -- हालांकि आपको important features का पता होता है, लेकिन exact logic को simple rule के रूप में आसानी से trace नहीं किया जा सकता। यदि dataset अत्यधिक high-dimensional और sparse है, तो बहुत बड़े forest को train करना computationally heavy हो सकता है।

-   **Training Process:**
1. **Bootstrap Sampling**: Multiple subsets (bootstrap samples) बनाने के लिए training data को replacement के साथ randomly sample करें।
2. **Tree Construction**: प्रत्येक bootstrap sample के लिए, प्रत्येक split पर features के random subset का उपयोग करके एक decision tree बनाएं। इससे trees के बीच diversity आती है।
3. **Aggregation**: Classification tasks के लिए, final prediction सभी trees की predictions के बीच majority vote लेकर की जाती है। Regression tasks के लिए, final prediction सभी trees की predictions का average होती है।

<details>
<summary>Example -- Intrusion Detection (NSL-KDD) के लिए Random Forest:</summary>
हम उसी NSL-KDD dataset (normal और anomaly के रूप में binary labeled) का उपयोग करेंगे और एक Random Forest classifier को train करेंगे। हमें उम्मीद है कि ensemble averaging द्वारा variance कम होने के कारण random forest single decision tree जितना या उससे बेहतर perform करेगा। हम इसे उन्हीं metrics के साथ evaluate करेंगे।
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
Random forest आमतौर पर इस intrusion detection task पर मजबूत परिणाम प्राप्त करता है। डेटा के आधार पर, single decision tree की तुलना में F1 या AUC जैसे metrics में सुधार देखा जा सकता है, विशेष रूप से recall या precision में। यह इस समझ के अनुरूप है कि *"Random Forest (RF) एक ensemble classifier है और attacks के प्रभावी classification के लिए अन्य traditional classifiers की तुलना में अच्छा प्रदर्शन करता है।"* Security operations के संदर्भ में, random forest कई decision rules का औसत लेने के कारण false alarms को कम करते हुए attacks को अधिक विश्वसनीय रूप से flag कर सकता है। Forest से प्राप्त feature importance यह बता सकती है कि कौन-से network features attacks के सबसे अधिक संकेतक हैं, जैसे कुछ network services या packets की असामान्य counts।

</details>

### Support Vector Machines (SVM)

Support Vector Machines मुख्य रूप से classification के लिए उपयोग किए जाने वाले शक्तिशाली supervised learning models हैं (और SVR के रूप में regression के लिए भी)। SVM एक **optimal separating hyperplane** खोजने का प्रयास करता है, जो दो classes के बीच margin को अधिकतम करता है। केवल training points का एक subset ("support vectors", जो boundary के सबसे निकट होते हैं) इस hyperplane की स्थिति निर्धारित करता है। Margin (support vectors और hyperplane के बीच की दूरी) को अधिकतम करके, SVMs आमतौर पर अच्छा generalization प्राप्त करते हैं।<sup>[[4]](#references)</sup>

SVM की शक्ति का मुख्य आधार non-linear relationships को संभालने के लिए **kernel functions** का उपयोग करने की क्षमता है। Data को अप्रत्यक्ष रूप से एक higher-dimensional feature space में transform किया जा सकता है, जहां एक linear separator मौजूद हो सकता है। सामान्य kernels में polynomial, radial basis function (RBF), और sigmoid शामिल हैं। उदाहरण के लिए, यदि network traffic classes raw feature space में linearly separable नहीं हैं, तो RBF kernel उन्हें higher dimension में map कर सकता है, जहां SVM एक linear split खोजता है (जो original space में एक non-linear boundary के अनुरूप होता है)। Kernels चुनने की यह flexibility SVMs को विभिन्न समस्याओं से निपटने में सक्षम बनाती है।

SVMs high-dimensional feature spaces (जैसे text data या malware opcode sequences) और उन स्थितियों में अच्छा प्रदर्शन करने के लिए जाने जाते हैं जहां samples की संख्या की तुलना में features की संख्या अधिक होती है। 2000s में malware classification और anomaly-based intrusion detection जैसे शुरुआती cybersecurity applications में इनका व्यापक उपयोग हुआ, जहां अक्सर high accuracy देखी गई।

हालांकि, SVMs बहुत बड़े datasets तक आसानी से scale नहीं होते (training complexity samples की संख्या के अनुसार super-linear होती है, और memory usage अधिक हो सकता है क्योंकि इन्हें कई support vectors store करने पड़ सकते हैं)। व्यवहार में, millions of records वाले network intrusion detection जैसे tasks के लिए, careful subsampling या approximate methods के बिना SVM बहुत धीमा हो सकता है।

#### **SVM की मुख्य विशेषताएं:**

-   **समस्या का प्रकार:** Classification (one-vs-one/one-vs-rest के माध्यम से binary या multiclass) और regression variants। इसका उपयोग अक्सर स्पष्ट margin separation वाले binary classification में किया जाता है।

-   **Interpretability:** Medium -- SVMs decision trees या logistic regression जितने interpretable नहीं होते। हालांकि आप यह पहचान सकते हैं कि कौन-से data points support vectors हैं और यह कुछ हद तक समझ सकते हैं कि कौन-से features प्रभावशाली हो सकते हैं (linear kernel के मामले में weights के माध्यम से), व्यवहार में SVMs (विशेष रूप से non-linear kernels वाले) को black-box classifiers माना जाता है।

-   **लाभ:** High-dimensional spaces में प्रभावी; kernel trick के माध्यम से complex decision boundaries को model कर सकता है; margin को maximize करने पर overfitting के प्रति robust (विशेष रूप से उचित regularization parameter C के साथ); classes के बीच बड़ी दूरी न होने पर भी अच्छा काम करता है (सबसे अच्छी compromise boundary खोजता है)।

-   **सीमाएं:** बड़े datasets के लिए **computationally intensive** (data बढ़ने पर training और prediction दोनों खराब तरीके से scale होते हैं)। Kernel और regularization parameters (C, kernel type, RBF के लिए gamma आदि) की सावधानीपूर्वक tuning आवश्यक होती है। यह सीधे probabilistic outputs प्रदान नहीं करता (हालांकि probabilities प्राप्त करने के लिए Platt scaling का उपयोग किया जा सकता है)। इसके अलावा, SVMs kernel parameters के चुनाव के प्रति sensitive हो सकते हैं --- गलत चुनाव underfit या overfit का कारण बन सकता है।

*Cybersecurity में उपयोग के मामले:* SVMs का उपयोग **malware detection** (जैसे extracted features या opcode sequences के आधार पर files को classify करना), **network anomaly detection** (traffic को normal बनाम malicious के रूप में classify करना), और **phishing detection** (URLs की features का उपयोग करके) में किया गया है। उदाहरण के लिए, SVM किसी email की features (कुछ keywords की counts, sender reputation scores आदि) लेकर उसे phishing या legitimate के रूप में classify कर सकता है। इन्हें KDD जैसे feature sets पर **intrusion detection** में भी लागू किया गया है, जहां computation की कीमत पर अक्सर high accuracy प्राप्त हुई।

<details>
<summary>उदाहरण -- Malware Classification के लिए SVM:</summary>
हम फिर से phishing website dataset का उपयोग करेंगे, इस बार SVM के साथ। क्योंकि SVMs धीमे हो सकते हैं, इसलिए आवश्यकता पड़ने पर हम training के लिए data के एक subset का उपयोग करेंगे (dataset में लगभग 11k instances हैं, जिन्हें SVM उचित रूप से संभाल सकता है)। हम non-linear data के लिए सामान्य विकल्प RBF kernel का उपयोग करेंगे और ROC AUC की गणना करने के लिए probability estimates सक्षम करेंगे।
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
SVM model ऐसे metrics आउटपुट करेगा जिनकी तुलना हम उसी task पर logistic regression से कर सकते हैं। यदि features के आधार पर data अच्छी तरह अलग-अलग हो, तो हमें SVM से high accuracy और AUC मिल सकता है। दूसरी ओर, यदि dataset में बहुत noise या overlapping classes हों, तो SVM logistic regression से significantly बेहतर प्रदर्शन नहीं कर सकता। व्यवहार में, features और class के बीच complex, non-linear relations होने पर SVM boost दे सकता है -- RBF kernel ऐसे curved decision boundaries को capture कर सकता है जिन्हें logistic regression miss कर देगा। सभी models की तरह, bias और variance के बीच संतुलन बनाने के लिए `C` (regularization) और kernel parameters (जैसे RBF के लिए `gamma`) की सावधानीपूर्वक tuning आवश्यक है।

</details>

#### Logistic Rergessions और SVM में अंतर

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log‑loss** (cross-entropy) को minimise करता है। | **margin** को maximise करते हुए **hinge‑loss** को minimise करता है। |
| **Decision boundary** | ऐसा **best-fit hyperplane** खोजता है जो _P(y\|x)_ को model करता है। | **maximum-margin hyperplane** खोजता है (सबसे निकट points से सबसे बड़ा gap)। |
| **Output** | **Probabilistic** – σ(w·x + b) के माध्यम से calibrated class probabilities देता है। | **Deterministic** – class labels लौटाता है; probabilities के लिए अतिरिक्त प्रक्रिया आवश्यक होती है (जैसे Platt scaling)। |
| **Regularisation** | L2 (default) या L1, under/over-fitting के बीच सीधे संतुलन बनाता है। | C parameter margin width और mis-classifications के बीच trade-off करता है; kernel parameters complexity बढ़ाते हैं। |
| **Kernels / Non‑linear** | Native form **linear** है; feature engineering के माध्यम से non-linearity जोड़ी जाती है। | Built-in **kernel trick** (RBF, poly आदि) इसे high-dim. space में complex boundaries model करने देता है। |
| **Scalability** | **O(nd)** में convex optimisation हल करता है; बहुत बड़े n को अच्छी तरह handle करता है। | Specialised solvers के बिना training में memory/time **O(n²–n³)** हो सकता है; बहुत बड़े n के लिए कम अनुकूल है। |
| **Interpretability** | **High** – weights feature influence दिखाते हैं; odds ratio intuitive होता है। | Non-linear kernels के लिए **Low**; support vectors sparse होते हैं, लेकिन उन्हें समझाना आसान नहीं होता। |
| **Sensitivity to outliers** | Smooth log-loss का उपयोग करता है → कम sensitive होता है। | Hard margin वाला hinge-loss **sensitive** हो सकता है; soft-margin (C) इसे कम करता है। |
| **Typical use cases** | Credit scoring, medical risk, A/B testing – जहाँ **probabilities और explainability** महत्वपूर्ण हों। | Image/text classification, bio-informatics – जहाँ **complex boundaries** और **high-dimensional data** महत्वपूर्ण हों। |

* **यदि आपको calibrated probabilities, interpretability की आवश्यकता है या आप बहुत बड़े datasets पर काम करते हैं — Logistic Regression चुनें।**
* **यदि आपको ऐसा flexible model चाहिए जो manual feature engineering के बिना non-linear relations को capture कर सके — SVM (kernels के साथ) चुनें।**
* दोनों convex objectives को optimise करते हैं, इसलिए **global minima की गारंटी होती है**, लेकिन SVM के kernels hyper-parameters और computational cost जोड़ते हैं।

### Naive Bayes

Naive Bayes **probabilistic classifiers** का एक family है, जो features के बीच strong independence assumption लागू करके Bayes' Theorem पर आधारित होता है। इस "naive" assumption के बावजूद, Naive Bayes अक्सर कुछ applications के लिए आश्चर्यजनक रूप से अच्छा काम करता है, विशेष रूप से text या categorical data से जुड़े applications में, जैसे spam detection।<sup>[[5]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem Naive Bayes classifiers का आधार है। यह random events की conditional और marginal probabilities के बीच संबंध बताता है। इसका formula है:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
कहाँ:
- `P(A|B)` feature `B` दिए जाने पर class `A` की posterior probability है।
- `P(B|A)` class `A` दिए जाने पर feature `B` की likelihood है।
- `P(A)` class `A` की prior probability है।
- `P(B)` feature `B` की prior probability है।

उदाहरण के लिए, यदि हम यह classify करना चाहते हैं कि कोई text किसी बच्चे द्वारा लिखा गया है या किसी वयस्क द्वारा, तो हम text में मौजूद words को features के रूप में उपयोग कर सकते हैं। कुछ प्रारंभिक data के आधार पर, Naive Bayes classifier पहले से ही प्रत्येक संभावित class (बच्चा या वयस्क) में प्रत्येक word के होने की probabilities calculate कर लेगा। जब कोई नया text दिया जाता है, तो यह text में मौजूद words के आधार पर प्रत्येक संभावित class की probability calculate करेगा और सबसे अधिक probability वाली class चुनेगा।

जैसा कि आप इस उदाहरण में देख सकते हैं, Naive Bayes classifier बहुत सरल और तेज़ है, लेकिन यह मानता है कि features independent हैं, जो real-world data में हमेशा सही नहीं होता।


#### Naive Bayes Classifiers के प्रकार

Features के data type और distribution के आधार पर Naive Bayes classifiers कई प्रकार के होते हैं:
- **Gaussian Naive Bayes**: यह मानता है कि features Gaussian (normal) distribution का पालन करते हैं। यह continuous data के लिए उपयुक्त है।
- **Multinomial Naive Bayes**: यह मानता है कि features multinomial distribution का पालन करते हैं। यह discrete data के लिए उपयुक्त है, जैसे text classification में word counts।
- **Bernoulli Naive Bayes**: यह मानता है कि features binary (0 या 1) हैं। यह binary data के लिए उपयुक्त है, जैसे text classification में words की presence या absence।
- **Categorical Naive Bayes**: यह मानता है कि features categorical variables हैं। यह categorical data के लिए उपयुक्त है, जैसे fruits को उनके color और shape के आधार पर classify करना।


#### **Naive Bayes की प्रमुख विशेषताएँ:**

-   **समस्या का प्रकार:** Classification (binary या multi-class)। इसका उपयोग cybersecurity में text classification tasks (spam, phishing, आदि) के लिए सामान्य रूप से किया जाता है।

-   **Interpretability:** Medium -- यह decision tree जितना सीधे interpretable नहीं है, लेकिन learned probabilities का निरीक्षण किया जा सकता है (जैसे, कौन से words spam और ham emails में सबसे अधिक संभावित हैं)। आवश्यकता पड़ने पर model के form (प्रत्येक feature की class दिए जाने पर probabilities) को समझा जा सकता है।

-   **लाभ:** **Training और prediction बहुत तेज़** होते हैं, बड़े datasets पर भी (instances की संख्या * features की संख्या के linear)। Probabilities का विश्वसनीय अनुमान लगाने के लिए अपेक्षाकृत कम data की आवश्यकता होती है, विशेष रूप से उचित smoothing के साथ। यह अक्सर baseline के रूप में आश्चर्यजनक रूप से accurate होता है, खासकर तब जब features independently class के लिए evidence प्रदान करते हैं। यह high-dimensional data (जैसे text से प्राप्त हजारों features) के साथ अच्छी तरह काम करता है। Smoothing parameter सेट करने के अलावा किसी complex tuning की आवश्यकता नहीं होती।

-   **सीमाएँ:** यदि features अत्यधिक correlated हों, तो independence assumption accuracy को सीमित कर सकती है। उदाहरण के लिए, network data में `src_bytes` और `dst_bytes` जैसे features correlated हो सकते हैं; Naive Bayes उस interaction को capture नहीं करेगा। जैसे-जैसे data size बहुत बड़ा होता जाता है, अधिक expressive models (जैसे ensembles या neural nets) feature dependencies सीखकर NB से बेहतर प्रदर्शन कर सकते हैं। इसके अलावा, यदि किसी attack की पहचान के लिए features के किसी विशेष combination की आवश्यकता हो (केवल individual features independently पर्याप्त न हों), तो NB को कठिनाई होगी।

> [!TIP]
> *cybersecurity में उपयोग के मामले:* इसका classic उपयोग **spam detection** है -- Naive Bayes शुरुआती spam filters का core था, जिसमें कुछ tokens (words, phrases, IP addresses) की frequencies का उपयोग यह calculate करने के लिए किया जाता था कि कोई email spam है या नहीं। इसका उपयोग **phishing email detection** और **URL classification** में भी किया जाता है, जहाँ कुछ keywords या characteristics की presence (जैसे URL में "login.php", या URL path में `@`) phishing probability में योगदान देती है। Malware analysis में, ऐसा Naive Bayes classifier बनाया जा सकता है जो software में कुछ API calls या permissions की presence का उपयोग यह predict करने के लिए करे कि वह malware है या नहीं। यद्यपि अधिक advanced algorithms अक्सर बेहतर performance करते हैं, Naive Bayes अपनी speed और simplicity के कारण अभी भी एक अच्छा baseline है।

<details>
<summary>उदाहरण -- Phishing Detection के लिए Naive Bayes:</summary>
Naive Bayes को प्रदर्शित करने के लिए, हम NSL-KDD intrusion dataset (जिसमें binary labels हैं) पर Gaussian Naive Bayes का उपयोग करेंगे। Gaussian NB प्रत्येक class के लिए हर feature को normal distribution का अनुसरण करने वाला मानेगा। यह एक rough choice है, क्योंकि कई network features discrete या highly skewed होते हैं, लेकिन इससे पता चलता है कि continuous feature data पर NB कैसे apply किया जाता है। हम binary features वाले dataset (जैसे triggered alerts का कोई set) पर Bernoulli NB भी चुन सकते थे, लेकिन continuity के लिए यहाँ NSL-KDD का ही उपयोग करेंगे।
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
यह code attacks का पता लगाने के लिए Naive Bayes classifier को train करता है। Naive Bayes training data के आधार पर `P(service=http | Attack)` और `P(Service=http | Normal)` जैसी probabilities की गणना करेगा और features के बीच independence मानकर चलेगा। इसके बाद यह observed features के आधार पर नए connections को normal या attack के रूप में classify करने के लिए इन probabilities का उपयोग करेगा। NSL-KDD पर NB का performance अधिक advanced models जितना अच्छा नहीं हो सकता (क्योंकि feature independence का assumption टूटता है), लेकिन यह अक्सर पर्याप्त अच्छा होता है और अत्यधिक speed का लाभ देता है। Real-time email filtering या URLs की initial triage जैसे scenarios में, Naive Bayes model कम resource usage के साथ स्पष्ट रूप से malicious मामलों को जल्दी flag कर सकता है।

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors सबसे सरल machine learning algorithms में से एक है। यह एक **non-parametric, instance-based** method है, जो training set में मौजूद examples से similarity के आधार पर predictions करता है। Classification का विचार यह है: किसी नए data point को classify करने के लिए training data में उसके सबसे निकट **k** points ("nearest neighbors") खोजें और उन neighbors के बीच majority class assign करें। "Closeness" को एक distance metric द्वारा परिभाषित किया जाता है, आमतौर पर numeric data के लिए Euclidean distance (अलग-अलग प्रकार के features या problems के लिए अन्य distances का उपयोग किया जा सकता है)।<sup>[[10]](#references)</sup>

K-NN को *कोई explicit training* आवश्यक नहीं होती -- "training" phase केवल dataset को store करना है। पूरा काम query (prediction) के दौरान होता है: nearest points खोजने के लिए algorithm को query point और सभी training points के बीच distances compute करनी पड़ती हैं। इससे prediction time **training samples की संख्या के संबंध में linear** हो जाता है, जो बड़े datasets के लिए महंगा हो सकता है। इसी कारण k-NN छोटे datasets या ऐसे scenarios के लिए सबसे उपयुक्त है, जहां simplicity के बदले memory और speed का trade-off किया जा सकता है।

अपनी simplicity के बावजूद, k-NN बहुत complex decision boundaries को model कर सकता है (क्योंकि प्रभावी रूप से decision boundary examples के distribution द्वारा निर्धारित कोई भी shape हो सकती है)। जब decision boundary बहुत irregular हो और आपके पास पर्याप्त data हो, तब यह अच्छा perform करता है -- मूलतः data को "खुद बोलने" देता है। हालांकि, high dimensions में distance metrics कम meaningful हो सकते हैं (curse of dimensionality), और method struggle कर सकता है, जब तक कि आपके पास samples की बहुत बड़ी संख्या न हो।

*Use cases in cybersecurity:* k-NN को anomaly detection में लागू किया गया है -- उदाहरण के लिए, intrusion detection system किसी network event को malicious label कर सकता है, यदि उसके अधिकांश nearest neighbors (पिछले events) malicious थे। यदि normal traffic clusters बनाता है और attacks outliers होते हैं, तो k-NN approach (k=1 या छोटे k के साथ) मूलतः **nearest-neighbor anomaly detection** करती है। k-NN का उपयोग binary feature vectors द्वारा malware families को classify करने के लिए भी किया गया है: किसी नए file को किसी malware family के रूप में classify किया जा सकता है, यदि वह feature space में उस family के known instances के बहुत निकट हो। व्यवहार में, k-NN अधिक scalable algorithms जितना common नहीं है, लेकिन यह conceptually straightforward है और कभी-कभी baseline या small-scale problems के लिए उपयोग किया जाता है।

#### **k-NN की प्रमुख विशेषताएं:**

-   **समस्या का प्रकार:** Classification (और regression variants भी मौजूद हैं)। यह एक *lazy learning* method है -- इसमें कोई explicit model fitting नहीं होती।

-   **Interpretability:** Low से medium -- कोई global model या concise explanation नहीं होती, लेकिन decision को प्रभावित करने वाले nearest neighbors को देखकर results को interpret किया जा सकता है (जैसे, "इस network flow को malicious classify किया गया क्योंकि यह इन 3 known malicious flows के समान है")। इसलिए explanations example-based हो सकती हैं।

-   **लाभ:** Implement और समझना बहुत आसान है। यह data distribution के बारे में कोई assumptions नहीं करता (non-parametric)। यह naturally multi-class problems को handle कर सकता है। यह इस अर्थ में **adaptive** है कि decision boundaries बहुत complex हो सकती हैं और data distribution से आकार लेती हैं।

-   **सीमाएं:** बड़े datasets के लिए prediction slow हो सकता है (कई distances compute करनी पड़ती हैं)। यह memory-intensive है -- यह सभी training data को store करता है। High-dimensional feature spaces में performance घटती है क्योंकि सभी points लगभग equidistant हो जाते हैं (जिससे "nearest" की concept कम meaningful हो जाती है)। *k* (neighbors की संख्या) को उचित रूप से चुनना आवश्यक है -- बहुत छोटा k noisy हो सकता है, जबकि बहुत बड़ा k अन्य classes के irrelevant points को शामिल कर सकता है। इसके अलावा, features को उचित रूप से scale किया जाना चाहिए क्योंकि distance calculations scale के प्रति sensitive होती हैं।

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

हम फिर से NSL-KDD (binary classification) का उपयोग करेंगे। क्योंकि k-NN computationally heavy है, इसलिए इस demonstration में इसे tractable बनाए रखने के लिए हम training data का एक subset उपयोग करेंगे। हम full 125k में से, मान लें, 20,000 training samples चुनेंगे और k=5 neighbors का उपयोग करेंगे। Training के बाद (वास्तव में केवल data store करने के बाद), हम test set पर इसका evaluation करेंगे। Distance calculation के लिए हम features को भी scale करेंगे, ताकि scale के कारण कोई एक feature अनावश्यक रूप से हावी न हो।
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
k-NN model training set subset में 5 सबसे निकटतम connections को देखकर किसी connection को classify करेगा। उदाहरण के लिए, यदि उन neighbors में से 4 attacks (anomalies) हैं और 1 normal है, तो नई connection को attack के रूप में classify किया जाएगा। इसका performance उचित हो सकता है, हालांकि अक्सर उसी data पर अच्छी तरह tuned Random Forest या SVM जितना उच्च नहीं होता। फिर भी, जब class distributions बहुत irregular और complex हों, तब k-NN कभी-कभी बेहतर प्रदर्शन कर सकता है -- प्रभावी रूप से memory-based lookup का उपयोग करते हुए। Cybersecurity में, k-NN (k=1 या small k के साथ) का उपयोग उदाहरणों के आधार पर ज्ञात attack patterns का detection करने के लिए या अधिक complex systems के एक component के रूप में (जैसे, clustering करने और फिर cluster membership के आधार पर classifying करने के लिए) किया जा सकता है।
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines structured data के लिए सबसे शक्तिशाली algorithms में से हैं। **Gradient boosting** का अर्थ weak learners (अक्सर decision trees) का ensemble sequential तरीके से बनाना है, जिसमें प्रत्येक नया model पिछले ensemble की errors को correct करता है। Bagging (Random Forests) के विपरीत, जिसमें trees parallel रूप से बनाए जाते हैं और उनका average लिया जाता है, boosting trees को *one by one* बनाता है; प्रत्येक tree उन instances पर अधिक ध्यान देता है जिन्हें पिछले trees ने गलत predict किया था।

हाल के वर्षों में सबसे लोकप्रिय implementations **XGBoost**, **LightGBM**, और **CatBoost** हैं, जो सभी gradient boosting decision tree (GBDT) libraries हैं। ये machine learning competitions और applications में बेहद सफल रहे हैं और अक्सर **tabular datasets पर state-of-the-art performance प्राप्त करते हैं**। Cybersecurity में, researchers और practitioners ने gradient boosted trees का उपयोग **malware detection** (files या runtime behavior से निकाले गए features का उपयोग करके) और **network intrusion detection** जैसे tasks के लिए किया है। उदाहरण के लिए, एक gradient boosting model कई weak rules (trees) को combine कर सकता है, जैसे "यदि कई SYN packets और unusual port हैं -> likely scan", और एक strong composite detector बना सकता है जो कई subtle patterns को ध्यान में रखता है।<sup>[[6]](#references)</sup>

Boosted trees इतने effective क्यों हैं? Sequence में प्रत्येक tree को current ensemble की predictions की *residual errors* (gradients) पर train किया जाता है। इस तरह, model धीरे-धीरे उन क्षेत्रों को **"boost"** करता है जहां वह कमजोर है। Base learners के रूप में decision trees के उपयोग से final model complex interactions और non-linear relations को capture कर सकता है। साथ ही, boosting में built-in regularization का एक रूप स्वाभाविक रूप से मौजूद होता है: कई छोटे trees जोड़कर (और उनके contributions को scale करने के लिए learning rate का उपयोग करके), उचित parameters चुने जाने पर यह अक्सर अत्यधिक overfitting के बिना अच्छी तरह generalize करता है।

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** मुख्य रूप से classification और regression। Security में आमतौर पर classification (जैसे, किसी connection या file को binary classify करना)। यह binary, multi-class (उचित loss के साथ), और यहां तक कि ranking problems को भी handle करता है।

-   **Interpretability:** Low to medium। जबकि एक single boosted tree छोटा होता है, full model में hundreds of trees हो सकते हैं, इसलिए इसे एक whole के रूप में human-interpretable नहीं माना जा सकता। हालांकि, Random Forest की तरह, यह feature importance scores प्रदान कर सकता है, और SHAP (SHapley Additive exPlanations) जैसे tools का उपयोग individual predictions को कुछ हद तक interpret करने के लिए किया जा सकता है।

-   **Advantages:** Structured/tabular data के लिए अक्सर **best performing** algorithm। Complex patterns और interactions का detection कर सकता है। Model complexity को customize करने और overfitting को रोकने के लिए इसमें कई tuning knobs (number of trees, depth of trees, learning rate, regularization terms) होते हैं। Modern implementations speed के लिए optimized हैं (जैसे, XGBoost second-order gradient info और efficient data structures का उपयोग करता है)। Appropriate loss functions के साथ combine करने या sample weights adjust करने पर यह imbalanced data को बेहतर तरीके से handle करता है।

-   **Limitations:** Simpler models की तुलना में tune करना अधिक complex है; यदि trees deep हों या trees की संख्या अधिक हो, तो training slow हो सकती है (हालांकि उसी data पर comparable deep neural network को train करने की तुलना में यह आमतौर पर फिर भी faster होता है)। यदि इसे tune न किया जाए तो model overfit कर सकता है (जैसे, insufficient regularization के साथ बहुत अधिक deep trees)। कई hyperparameters के कारण, gradient boosting को effectively use करने के लिए अधिक expertise या experimentation की आवश्यकता हो सकती है। साथ ही, tree-based methods की तरह, यह बहुत sparse high-dimensional data को linear models या Naive Bayes जितनी efficiency से inherently handle नहीं करता (हालांकि इसे अभी भी apply किया जा सकता है, जैसे text classification में, लेकिन feature engineering के बिना यह first choice नहीं हो सकता)।

> [!TIP]
> *Use cases in cybersecurity:* लगभग कहीं भी decision tree या random forest का उपयोग किया जा सकता है, gradient boosting model बेहतर accuracy प्राप्त कर सकता है। उदाहरण के लिए, **Microsoft's malware detection** competitions में binary files से engineered features पर XGBoost का व्यापक उपयोग हुआ है। **Network intrusion detection** research में GBDTs (जैसे, CIC-IDS2017 या UNSW-NB15 datasets पर XGBoost) के साथ अक्सर top results report किए जाते हैं। ये models features की wide range (protocol types, certain events की frequency, traffic की statistical features आदि) ले सकते हैं और threats का detection करने के लिए उन्हें combine कर सकते हैं। Phishing detection में, gradient boosting URLs के lexical features, domain reputation features और page content features को combine करके बहुत high accuracy प्राप्त कर सकता है। Ensemble approach data में कई corner cases और subtleties को cover करने में सहायता करती है।

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
हम phishing dataset पर gradient boosting classifier का उपयोग करेंगे। चीजों को simple और self-contained रखने के लिए, हम `sklearn.ensemble.GradientBoostingClassifier` का उपयोग करेंगे (जो slower लेकिन straightforward implementation है)। सामान्यतः, बेहतर performance और additional features के लिए `xgboost` या `lightgbm` libraries का उपयोग किया जा सकता है। हम model को train करेंगे और पहले की तरह ही उसका evaluation करेंगे।
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
Gradient boosting model संभवतः इस phishing dataset पर बहुत उच्च accuracy और AUC प्राप्त करेगा (अक्सर उचित tuning के साथ ऐसे data पर ये models 95% से अधिक accuracy प्राप्त कर सकते हैं, जैसा कि literature में देखा गया है। यह दर्शाता है कि GBDTs को *"the state of the art model for tabular dataset"* क्यों माना जाता है -- वे complex patterns को पकड़कर अक्सर सरल algorithms से बेहतर प्रदर्शन करते हैं। Cybersecurity के संदर्भ में, इसका अर्थ अधिक phishing sites या attacks को कम misses के साथ पकड़ना हो सकता है। बेशक, overfitting के प्रति सावधान रहना आवश्यक है -- deployment के लिए ऐसा model विकसित करते समय हम आमतौर पर cross-validation जैसी techniques का उपयोग करेंगे और validation set पर performance की निगरानी करेंगे।

</details>

### Models को Combining करना: Ensemble Learning और Stacking

Ensemble learning overall performance को बेहतर बनाने के लिए **multiple models को combine करने** की एक strategy है। हम पहले ही कुछ specific ensemble methods देख चुके हैं: Random Forest (bagging के माध्यम से trees का ensemble) और Gradient Boosting (sequential boosting के माध्यम से trees का ensemble)। लेकिन ensembles अन्य तरीकों से भी बनाए जा सकते हैं, जैसे **voting ensembles** या **stacked generalization (stacking)**। मुख्य विचार यह है कि अलग-अलग models अलग patterns पकड़ सकते हैं या उनकी weaknesses अलग हो सकती हैं; उन्हें combine करके हम **एक model की errors की भरपाई दूसरे model की strengths से कर सकते हैं**।<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** एक simple voting classifier में, हम कई diverse models (मान लें, एक logistic regression, एक decision tree और एक SVM) को train करते हैं और final prediction पर उनसे vote करवाते हैं (classification के लिए majority vote)। यदि हम votes को weight करें (जैसे, अधिक accurate models को higher weight दें), तो यह weighted voting scheme होती है। यह आमतौर पर performance को तब बेहतर बनाती है जब individual models reasonably good और independent हों -- ensemble किसी individual model की गलती के risk को कम करता है, क्योंकि अन्य models उसे correct कर सकते हैं। यह single opinion के बजाय experts का panel रखने जैसा है।

-   **Stacking (Stacked Ensemble):** Stacking इससे एक कदम आगे जाता है। Simple vote के बजाय, यह एक **meta-model** को **base models की predictions को सबसे अच्छे तरीके से combine करना सीखने** के लिए train करता है। उदाहरण के लिए, आप 3 अलग-अलग classifiers (base learners) को train करते हैं, फिर उनके outputs (या probabilities) को features के रूप में एक meta-classifier (अक्सर logistic regression जैसे simple model) में देते हैं, जो उन्हें blend करने का optimal तरीका सीखता है। Overfitting से बचने के लिए meta-model को validation set पर या cross-validation के माध्यम से train किया जाता है। Stacking अक्सर simple voting से बेहतर प्रदर्शन कर सकता है, क्योंकि यह सीखता है कि *किन circumstances में किन models पर अधिक भरोसा करना है*। Cybersecurity में, एक model network scans को पकड़ने में बेहतर हो सकता है, जबकि दूसरा malware beaconing को पकड़ने में बेहतर हो सकता है; stacking model प्रत्येक पर उचित रूप से निर्भर करना सीख सकता है।

Ensembles, चाहे voting के माध्यम से हों या stacking के माध्यम से, आमतौर पर **accuracy** और robustness को **बढ़ाते** हैं। इसका downside बढ़ी हुई complexity और कभी-कभी कम interpretability है (हालांकि कुछ ensemble approaches, जैसे decision trees का average, फिर भी कुछ insight दे सकते हैं, जैसे feature importance)। व्यवहार में, यदि operational constraints अनुमति दें, तो ensemble का उपयोग higher detection rates दे सकता है। Cybersecurity challenges (और सामान्यतः Kaggle competitions) में कई winning solutions performance के अंतिम अंश को प्राप्त करने के लिए ensemble techniques का उपयोग करते हैं।

<details>
<summary>Example -- Phishing Detection के लिए Voting Ensemble:</summary>
Model stacking को समझाने के लिए, आइए phishing dataset पर उन models में से कुछ को combine करें जिनकी हमने चर्चा की थी। हम logistic regression, decision tree और k-NN को base learners के रूप में उपयोग करेंगे, और उनकी predictions को aggregate करने के लिए Random Forest को meta-learner के रूप में उपयोग करेंगे। Meta-learner को base learners के outputs पर (training set पर cross-validation का उपयोग करके) train किया जाएगा। हमें उम्मीद है कि stacked model individual models जितना अच्छा या उनसे थोड़ा बेहतर प्रदर्शन करेगा।
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
Stacked ensemble base models की complementary strengths का लाभ उठाता है। उदाहरण के लिए, logistic regression डेटा के linear aspects को संभाल सकता है, decision tree विशेष rule-like interactions को capture कर सकता है, और k-NN feature space के local neighborhoods में बेहतर प्रदर्शन कर सकता है। Meta-model (यहाँ random forest) इन inputs को weight देना सीख सकता है। परिणामी metrics अक्सर किसी एक model की metrics की तुलना में सुधार दिखाते हैं, भले ही यह सुधार थोड़ा ही क्यों न हो। हमारे phishing उदाहरण में, यदि केवल logistic का F1 मान 0.95 और tree का 0.94 हो, तो stack 0.96 प्राप्त कर सकता है, क्योंकि वह उन कमियों को पहचान लेता है जहाँ प्रत्येक model से गलती होती है।

इस तरह के ensemble methods इस सिद्धांत को दर्शाते हैं कि *"कई models को मिलाने से आमतौर पर बेहतर generalization प्राप्त होता है"।* Cybersecurity में इसे कई detection engines के माध्यम से लागू किया जा सकता है (एक rule-based, एक machine learning-based और एक anomaly-based हो सकता है), जिसके बाद एक layer उनके alerts को aggregate करती है -- यह प्रभावी रूप से ensemble का एक रूप है -- ताकि अधिक confidence के साथ अंतिम निर्णय लिया जा सके। ऐसे systems को deploy करते समय बढ़ी हुई complexity पर विचार करना चाहिए और यह सुनिश्चित करना चाहिए कि ensemble को manage या explain करना अत्यधिक कठिन न हो जाए। लेकिन accuracy के दृष्टिकोण से, ensembles और stacking model performance सुधारने के लिए शक्तिशाली tools हैं।

</details>


## References

- [1] [Logistic Regression](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Decision Tree - Introduction with example](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
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
