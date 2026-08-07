# 지도 학습 알고리즘

{{#include ../banners/hacktricks-training.md}}

## 기본 정보

지도 학습은 레이블이 지정된 데이터를 사용해 새로운 미지의 입력에 대해 예측할 수 있는 모델을 학습시킵니다. 사이버 보안에서 지도 머신 러닝은 침입 탐지(네트워크 트래픽을 *정상* 또는 *공격*으로 분류), malware 탐지(악성 소프트웨어와 benign 소프트웨어 구분), phishing 탐지(사기성 웹사이트 또는 이메일 식별), spam filtering 등의 작업에 널리 사용됩니다.<sup>[[1]](#references)</sup> 각 알고리즘은 고유한 장점이 있으며 서로 다른 유형의 문제(classification 또는 regression)에 적합합니다. 아래에서는 주요 지도 학습 알고리즘을 검토하고, 작동 방식을 설명하며, 실제 사이버 보안 datasets에서의 사용 방법을 보여줍니다. 또한 여러 모델을 결합하는 방식(ensemble learning)이 예측 성능을 향상시키는 경우가 많은 이유도 설명합니다.

## 알고리즘

-   **선형 회귀:** 데이터에 선형 방정식을 fitting하여 수치 결과를 예측하는 기본 regression 알고리즘입니다.

-   **Logistic Regression:** 이름과 달리 logistic function을 사용해 binary outcome의 확률을 모델링하는 classification 알고리즘입니다.

-   **Decision Trees:** features를 기준으로 데이터를 분할해 예측하는 트리 구조의 모델로, 해석 가능성이 높아 자주 사용됩니다.

-   **Random Forests:** 여러 decision trees를 bagging 방식으로 결합한 ensemble로, 정확도를 높이고 overfitting을 줄입니다.

-   **Support Vector Machines (SVM):** 최적의 separating hyperplane을 찾는 max-margin classifiers이며, non-linear 데이터에는 kernels를 사용할 수 있습니다.

-   **Naive Bayes:** feature independence를 가정하고 Bayes' theorem에 기반한 probabilistic classifier로, spam filtering에 널리 사용됩니다.

-   **k-Nearest Neighbors (k-NN):** 가장 가까운 neighbors의 majority class를 기준으로 sample에 label을 지정하는 간단한 "instance-based" classifier입니다.

-   **Gradient Boosting Machines:** 약한 learners(일반적으로 decision trees)를 순차적으로 추가해 강력한 predictor를 구축하는 ensemble models입니다(예: XGBoost, LightGBM).

아래의 각 섹션에서는 알고리즘에 대한 개선된 설명과 `pandas`, `scikit-learn` 같은 libraries(그리고 neural network 예제에서는 `PyTorch`)를 사용한 **Python code example**을 제공합니다. 예제는 공개적으로 이용 가능한 사이버 보안 datasets(예: intrusion detection용 NSL-KDD 및 Phishing Websites dataset)를 사용하며, 다음과 같은 일관된 구조를 따릅니다.

1.  **dataset을 로드**합니다(가능한 경우 URL을 통해 다운로드).

2.  **데이터를 preprocess**합니다(예: categorical features 인코딩, 값 scaling, train/test sets로 분할).

3.  **training data**를 사용해 model을 학습시킵니다.

4.  다음 metrics를 사용해 test set에서 **평가**합니다: classification의 경우 accuracy, precision, recall, F1-score 및 ROC AUC(그리고 regression의 경우 mean squared error).

각 알고리즘을 살펴보겠습니다.

### 선형 회귀

선형 회귀는 연속적인 수치 값을 예측하는 데 사용되는 **regression** 알고리즘입니다. 입력 features(independent variables)와 출력(dependent variable) 사이에 선형 관계가 있다고 가정합니다. 이 model은 features와 target 간의 관계를 가장 잘 나타내는 직선(고차원에서는 hyperplane)을 fitting하려고 합니다. 일반적으로 predicted 값과 actual 값 사이의 제곱 오차 합을 최소화하여 수행합니다(Ordinary Least Squares method).<sup>[[2]](#references)</sup>

선형 회귀를 표현하는 가장 간단한 방식은 직선을 사용하는 것입니다:
```plaintext
y = mx + b
```
Where:

- `y`는 예측값(출력)
- `m`은 선의 기울기(계수)
- `x`는 입력 feature
- `b`는 y절편

Linear regression의 목표는 dataset의 예측값과 실제 값 사이의 차이를 최소화하는 가장 적합한 선을 찾는 것입니다. 물론 이는 매우 단순한 경우로, 2개의 categories를 구분하는 직선이 됩니다. 하지만 dimensions가 더 추가되면 선은 더 복잡해집니다:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *사이버보안 사용 사례:* Linear regression 자체는 핵심 보안 작업에는 덜 일반적으로 사용됩니다(핵심 보안 작업은 대개 classification이기 때문입니다). 하지만 수치 결과를 예측하는 데 적용할 수 있습니다. 예를 들어 과거 데이터를 기반으로 **네트워크 트래픽의 양을 예측**하거나 **특정 기간의 공격 횟수를 추정**하는 데 linear regression을 사용할 수 있습니다. 또한 특정 시스템 지표가 주어졌을 때 위험 점수나 공격이 탐지될 때까지의 예상 시간도 예측할 수 있습니다. 실제로 침입이나 malware를 탐지하는 데는 classification algorithms(logistic regression 또는 trees 등)이 더 자주 사용되지만, linear regression은 기초가 되며 regression 중심 분석에 유용합니다.

#### **Linear Regression의 주요 특징:**

-   **문제 유형:** Regression(연속값 예측). 출력값에 threshold를 적용하지 않는 한 직접적인 classification에는 적합하지 않습니다.

-   **해석 가능성:** 높음 -- coefficients를 간단하게 해석할 수 있으며, 각 feature의 선형 효과를 보여 줍니다.

-   **장점:** 단순하고 빠르며, regression 작업의 좋은 baseline입니다. 실제 관계가 대략 선형일 때 잘 작동합니다.

-   **제한 사항:** 수동 feature engineering 없이는 복잡하거나 비선형적인 관계를 포착할 수 없습니다. 관계가 비선형이면 underfitting이 발생하기 쉽고, 결과를 왜곡할 수 있는 outlier에 민감합니다.

-   **최적 적합선 찾기:** 가능한 categories를 구분하는 최적 적합선을 찾기 위해 **Ordinary Least Squares (OLS)**라는 방법을 사용합니다. 이 방법은 관측값과 linear model이 예측한 값 간 차이의 제곱합을 최소화합니다.

<details>
<summary>예제 -- Intrusion Dataset에서 Connection Duration 예측(Regression)
</summary>
아래에서는 NSL-KDD cybersecurity dataset을 사용하여 linear regression을 시연합니다. 다른 feature를 기반으로 네트워크 connection의 `duration`을 예측하는 regression 문제로 다룹니다. (실제로 `duration`은 NSL-KDD의 feature 중 하나이며, 여기서는 regression을 설명하기 위한 목적으로만 사용합니다.) dataset을 불러오고, categorical feature를 encode한 후, linear regression model을 학습하고 test set에서 Mean Squared Error (MSE)와 R² score를 평가합니다.
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
이 예제에서 linear regression model은 다른 network feature를 사용해 connection `duration`을 예측하려고 합니다. 성능은 Mean Squared Error (MSE)와 R²로 측정합니다. R²가 1.0에 가까우면 model이 `duration`의 variance 대부분을 설명한다는 의미이며, R²가 낮거나 음수이면 적합도가 낮다는 의미입니다. (여기서 R²가 낮더라도 놀라지 마세요. 주어진 feature만으로 `duration`을 예측하기 어려울 수 있으며, 패턴이 복잡하다면 linear regression이 이를 포착하지 못할 수 있습니다.)
</details>

### Logistic Regression

Logistic regression은 특정 instance가 특정 class(일반적으로 "positive" class)에 속할 확률을 model링하는 **classification** algorithm입니다. 이름에 *logistic*이 포함되어 있지만, logistic regression은 discrete outcome에 사용됩니다(continuous outcome에 사용하는 linear regression과 다름). 특히 **binary classification**(두 개의 class, 예: malicious와 benign)에 사용되지만, multi-class 문제에도 확장할 수 있습니다(softmax 또는 one-vs-rest 방식 사용).<sup>[[3]](#references)</sup>

Logistic regression은 logistic function(sigmoid function이라고도 함)을 사용해 예측값을 확률로 변환합니다. sigmoid function은 0과 1 사이의 값을 가지며 classification의 요구에 따라 S자 곡선으로 증가하는 함수입니다. 따라서 각 input의 각 feature에 할당된 weight를 곱한 뒤, 그 결과를 sigmoid function에 전달해 확률을 생성합니다:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)`는 입력 `x`가 주어졌을 때 출력 `y`가 1일 확률입니다.
- `e`는 자연로그의 밑입니다.
- `z`는 입력 feature의 선형 결합이며, 일반적으로 `z = w1*x1 + w2*x2 + ... + wn*xn + b`로 표현됩니다. 여기서 다시 가장 단순한 형태에서는 직선이지만, 더 복잡한 경우에는 여러 차원(feature마다 하나씩)을 가진 hyperplane이 됩니다.

> [!TIP]
> *사이버보안에서의 사용 사례:* 많은 보안 문제는 본질적으로 yes/no 결정이므로 Logistic Regression이 널리 사용됩니다. 예를 들어 intrusion detection system은 연결의 feature를 기반으로 네트워크 연결이 공격인지 판단하기 위해 Logistic Regression을 사용할 수 있습니다. phishing detection에서는 Logistic Regression이 웹사이트의 feature(URL 길이, `"@"` 기호 존재 여부 등)를 결합하여 phishing일 확률을 계산할 수 있습니다. Logistic Regression은 초기 세대 spam filter에 사용되었으며, 현재도 많은 classification task에서 강력한 baseline으로 활용됩니다.

#### 비이진 classification을 위한 Logistic Regression

Logistic Regression은 binary classification을 위해 설계되었지만, **one-vs-rest** (OvR) 또는 **softmax regression**과 같은 기법을 사용하여 multi-class 문제를 처리하도록 확장할 수 있습니다. OvR에서는 각 class를 positive class로 간주하고 나머지 모든 class와 비교하는 별도의 Logistic Regression model을 학습합니다. 예측 확률이 가장 높은 class가 최종 prediction으로 선택됩니다. Softmax regression은 output layer에 softmax function을 적용하여 모든 class에 대한 probability distribution을 생성함으로써 Logistic Regression을 여러 class에 맞게 일반화합니다.

#### **Logistic Regression의 주요 특성:**

-   **문제 유형:** Classification (일반적으로 binary). Positive class의 확률을 예측합니다.

-   **해석 가능성:** 높음 -- linear regression과 마찬가지로 feature coefficient를 통해 각 feature가 결과의 log-odds에 어떤 영향을 미치는지 확인할 수 있습니다. 이러한 transparency는 어떤 요인이 alert에 기여하는지 이해하는 데 유용하므로 보안 분야에서 자주 선호됩니다.

-   **장점:** 학습이 간단하고 빠르며, feature와 결과의 log-odds 간 관계가 선형일 때 잘 작동합니다. 확률을 출력하므로 risk scoring이 가능합니다. 적절한 regularization을 사용하면 일반화 성능이 좋고, 일반적인 linear regression보다 multicollinearity를 더 잘 처리할 수 있습니다.

-   **제한 사항:** Feature space에서 선형 decision boundary를 가정합니다 (실제 boundary가 복잡하거나 비선형인 경우 성능이 떨어짐). Polynomial feature 또는 interaction feature를 직접 추가하지 않으면 interaction이나 비선형 효과가 중요한 문제에서 성능이 낮을 수 있습니다. 또한 class가 feature의 선형 결합으로 쉽게 분리되지 않는 경우 Logistic Regression의 효과가 떨어집니다.


<details>
<summary>예제 -- Logistic Regression을 사용한 Phishing Website Detection:</summary>

웹사이트에서 추출한 feature(URL에 IP address가 포함되어 있는지, domain의 age, HTML에 의심스러운 element가 존재하는지 등)와 해당 사이트가 phishing인지 legitimate인지 나타내는 label이 포함된 **Phishing Websites Dataset** (UCI repository 제공)을 사용합니다.<sup>[[4]](#references)</sup> Logistic Regression model을 학습하여 웹사이트를 분류한 다음, test split에서 accuracy, precision, recall, F1-score 및 ROC AUC를 평가합니다.
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
이 phishing detection example에서 logistic regression은 각 website가 phishing일 확률을 생성합니다. accuracy, precision, recall, F1을 평가하면 모델의 성능을 파악할 수 있습니다. 예를 들어 높은 recall은 대부분의 phishing site를 탐지한다는 의미입니다(놓치는 attack을 최소화하는 것이 보안에 중요함). 반면 높은 precision은 false alarm이 적다는 의미입니다(analyst fatigue를 방지하는 데 중요함). ROC AUC (Area Under the ROC Curve)는 threshold와 무관한 성능 측정값을 제공합니다(1.0은 이상적이며, 0.5는 무작위 추측보다 나을 것이 없음을 의미함). Logistic regression은 이러한 task에서 자주 우수한 성능을 보이지만, phishing site와 legitimate site 사이의 decision boundary가 복잡하다면 더 강력한 non-linear model이 필요할 수 있습니다.

</details>

### Decision Trees

decision tree는 classification과 regression task 모두에 사용할 수 있는 다목적 **supervised learning algorithm**입니다. 데이터 feature를 기반으로 계층적인 tree 형태의 decision model을 학습합니다. tree의 각 internal node는 특정 feature에 대한 test를 나타내고, 각 branch는 해당 test의 outcome을 나타내며, 각 leaf node는 예측된 class(classification의 경우) 또는 value(regression의 경우)를 나타냅니다.<sup>[[5]](#references)</sup>

tree를 구축하기 위해 CART (Classification and Regression Tree)와 같은 algorithm은 **Gini impurity** 또는 **information gain (entropy)**과 같은 measure를 사용하여 각 단계에서 데이터를 split할 최적의 feature와 threshold를 선택합니다. 각 split의 목표는 결과 subset에서 target variable의 homogeneity를 높이도록 데이터를 partition하는 것입니다(classification의 경우 각 node는 주로 하나의 class만 포함하도록 최대한 pure한 상태를 목표로 함).

decision tree는 **매우 해석하기 쉽습니다** -- prediction의 logic을 이해하기 위해 root에서 leaf까지의 path를 따라갈 수 있습니다(예: *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). 이는 특정 alert가 발생한 이유를 설명하는 데 유용하므로 cybersecurity에서 중요한 특성입니다. tree는 numerical data와 categorical data를 모두 자연스럽게 처리할 수 있으며 preprocessing이 거의 필요하지 않습니다(예: feature scaling이 필요하지 않음).

그러나 단일 decision tree는 training data에 쉽게 overfit할 수 있으며, 특히 tree가 깊게 생성된 경우(많은 split이 있는 경우) 더욱 그렇습니다. overfitting을 방지하기 위해 pruning(tree depth 제한 또는 leaf당 필요한 최소 sample 수 지정)과 같은 technique를 자주 사용합니다.

decision tree에는 다음과 같은 3가지 주요 component가 있습니다.
- **Root Node**: 전체 dataset을 나타내는 tree의 최상위 node입니다.
- **Internal Nodes**: feature와 해당 feature를 기반으로 한 decision을 나타내는 node입니다.
- **Leaf Nodes**: 최종 outcome 또는 prediction을 나타내는 node입니다.

tree는 다음과 같은 형태가 될 수 있습니다:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Cybersecurity에서의 사용 사례:* Decision trees는 공격을 식별하기 위한 **rules**를 도출하는 침입 탐지 시스템에서 사용되어 왔습니다. 예를 들어 초기 ID3/C4.5 기반 IDS는 정상 트래픽과 악성 트래픽을 구분하기 위해 사람이 읽을 수 있는 rules를 생성했습니다. 또한 파일의 속성(파일 크기, section entropy, API calls 등)을 기반으로 해당 파일이 악성인지 판단하는 malware analysis에도 사용됩니다. Decision trees의 명확성은 투명성이 필요한 경우 유용합니다 -- analyst는 detection logic을 검증하기 위해 tree를 검사할 수 있습니다.

#### **Decision Trees의 주요 특성:**

-   **문제 유형:** classification과 regression 모두에 사용됩니다. 공격과 정상 트래픽 등을 classification하는 데 일반적으로 사용됩니다.

-   **해석 가능성:** 매우 높음 -- model의 decisions를 시각화하고 if-then rules 집합으로 이해할 수 있습니다. 이는 model 동작에 대한 신뢰와 검증이 중요한 security 분야에서 큰 장점입니다.

-   **장점:** features 간의 비선형 관계와 상호작용을 포착할 수 있습니다(각 split은 상호작용으로 볼 수 있음). features를 scaling하거나 categorical variables를 one-hot encode할 필요가 없습니다 -- trees가 이를 기본적으로 처리합니다. inference가 빠릅니다(prediction은 tree에서 경로 하나를 따라가기만 하면 됨).

-   **제한 사항:** 제어하지 않으면 overfitting이 발생하기 쉽습니다(깊은 tree는 training set을 암기할 수 있음). 또한 불안정할 수 있습니다 -- data의 작은 변화가 다른 tree structure로 이어질 수 있습니다. 단일 model로 사용할 경우 accuracy가 더 발전된 methods와 일치하지 않을 수 있습니다(Random Forests와 같은 ensembles는 일반적으로 variance를 줄여 더 나은 성능을 냅니다).

-   **최적의 Split 찾기:**
- **Gini Impurity**: node의 impurity를 측정합니다. Gini impurity가 낮을수록 더 나은 split을 의미합니다. 공식은 다음과 같습니다.

```plaintext
Gini = 1 - Σ(p_i^2)
```

여기서 `p_i`는 class `i`에 속하는 instances의 비율입니다.

- **Entropy**: dataset의 uncertainty를 측정합니다. entropy가 낮을수록 더 나은 split을 의미합니다. 공식은 다음과 같습니다.

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

여기서 `p_i`는 class `i`에 속하는 instances의 비율입니다.

- **Information Gain**: split 이후 entropy 또는 Gini impurity가 감소한 정도입니다. information gain이 높을수록 더 나은 split입니다. 다음과 같이 계산합니다.

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

또한 다음과 같은 경우 tree가 종료됩니다.
- node의 모든 instances가 동일한 class에 속하는 경우. 이는 overfitting으로 이어질 수 있습니다.
- tree의 maximum depth(하드코딩된 값)에 도달한 경우. 이는 overfitting을 방지하는 방법입니다.
- node의 instances 수가 특정 threshold 미만인 경우. 이 역시 overfitting을 방지하는 방법입니다.
- 추가 split으로 얻는 information gain이 특정 threshold 미만인 경우. 이 역시 overfitting을 방지하는 방법입니다.

<details>
<summary>예시 -- Intrusion Detection을 위한 Decision Tree:</summary>
NSL-KDD dataset을 사용해 network connections를 *normal* 또는 *attack*으로 분류하는 decision tree를 학습합니다. NSL-KDD는 classic KDD Cup 1999 dataset의 개선된 version으로, protocol type, service, duration, failed logins 수 등의 features와 attack type 또는 "normal"을 나타내는 label을 포함합니다. 모든 attack types를 "anomaly" class로 매핑합니다(binary classification: normal 대 anomaly). 학습 후 test set에서 tree의 performance를 평가합니다.
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
이 decision tree 예제에서는 과도한 overfitting을 방지하기 위해 tree depth를 10으로 제한했습니다(`max_depth=10` parameter). Metrics는 tree가 정상 트래픽과 attack 트래픽을 얼마나 잘 구분하는지 보여줍니다. 높은 recall은 대부분의 attack을 탐지한다는 의미이며(IDS에서 중요), 높은 precision은 false alarm이 적다는 의미입니다. Decision tree는 structured data에서 준수한 accuracy를 달성하는 경우가 많지만, 단일 tree가 가능한 최고의 성능에 도달하지 못할 수도 있습니다. 그럼에도 모델의 *interpretability*는 큰 장점입니다 -- tree의 split을 확인하여 어떤 feature(예: `service`, `src_bytes` 등)가 connection을 malicious로 판단하는 데 가장 큰 영향을 미치는지 살펴볼 수 있습니다.

</details>

### Random Forests

Random Forest는 decision tree를 기반으로 성능을 향상시키는 **ensemble learning** method입니다. Random forest는 여러 decision tree를 학습시키고(따라서 "forest"), 그 결과를 결합하여 최종 prediction을 수행합니다(classification의 경우 일반적으로 majority vote 사용). Random forest의 두 가지 주요 개념은 **bagging**(bootstrap aggregating)과 **feature randomness**입니다:

-   **Bagging:** 각 tree는 training data에서 무작위 bootstrap sample을 추출하여 학습합니다(with replacement). 이를 통해 tree 간에 다양성이 생깁니다.

-   **Feature Randomness:** tree의 각 split에서 모든 feature를 사용하는 대신, feature의 무작위 subset을 split 대상으로 고려합니다. 이를 통해 tree 간의 상관성이 더욱 낮아집니다.

많은 tree의 결과를 평균 내면 random forest는 단일 decision tree에서 발생할 수 있는 variance를 줄입니다. 간단히 말해 개별 tree는 overfit되거나 noise가 있을 수 있지만, 서로 다른 많은 tree가 함께 voting하면 이러한 error가 완화됩니다. 그 결과 단일 decision tree보다 **높은 accuracy**와 더 나은 generalization을 갖는 model이 되는 경우가 많습니다. 또한 random forest는 각 feature의 split이 평균적으로 impurity를 얼마나 줄이는지 확인하여 feature importance를 추정할 수 있습니다.

Random forest는 intrusion detection, malware classification, spam detection과 같은 작업에서 **cybersecurity의 workhorse**로 자리 잡았습니다. 일반적으로 최소한의 tuning만으로도 out-of-the-box에서 우수한 성능을 내며, 대규모 feature set을 처리할 수 있습니다. 예를 들어 intrusion detection에서 random forest는 개별 decision tree보다 더 미묘한 attack pattern을 탐지하고 false positive를 줄여 더 나은 성능을 보일 수 있습니다. 연구에 따르면 NSL-KDD 및 UNSW-NB15와 같은 dataset에서 attack을 classification할 때 random forest는 다른 algorithm과 비교해 우수한 성능을 보였습니다.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Random Forests의 주요 특성:**

-   **문제 유형:** 주로 classification에 사용됩니다(regression에도 사용 가능). security log에서 흔히 볼 수 있는 high-dimensional structured data에 매우 적합합니다.

-   **Interpretability:** 단일 decision tree보다 낮습니다 -- 수백 개의 tree를 한 번에 쉽게 시각화하거나 설명할 수 없습니다. 그러나 feature importance score를 통해 어떤 attribute가 가장 큰 영향을 미치는지 어느 정도 파악할 수 있습니다.

-   **장점:** ensemble effect로 인해 일반적으로 single-tree model보다 높은 accuracy를 제공합니다. overfitting에 강합니다 -- 개별 tree가 overfit되더라도 ensemble은 더 잘 generalize합니다. numerical feature와 categorical feature를 모두 처리할 수 있으며 missing data도 어느 정도 처리할 수 있습니다. outlier에도 비교적 강합니다.

-   **제한 사항:** model size가 커질 수 있습니다(많은 tree로 구성되며 각 tree가 잠재적으로 깊을 수 있음). prediction은 단일 tree보다 느립니다(많은 tree의 결과를 aggregate해야 함). interpretability가 낮습니다 -- 중요한 feature는 알 수 있지만, 정확한 logic을 단순한 rule처럼 쉽게 추적할 수는 없습니다. dataset이 매우 high-dimensional하고 sparse한 경우, 매우 큰 forest를 training하는 작업은 computationally heavy할 수 있습니다.

-   **Training Process:**
1. **Bootstrap Sampling**: training data에서 replacement를 허용하여 무작위로 sample을 추출하고 여러 subset(bootstrap sample)을 생성합니다.
2. **Tree Construction**: 각 bootstrap sample에 대해 각 split에서 무작위 feature subset을 사용하여 decision tree를 구축합니다. 이를 통해 tree 간에 다양성이 생깁니다.
3. **Aggregation**: classification task에서는 모든 tree의 prediction 중 majority vote를 선택하여 최종 prediction을 수행합니다. regression task에서는 모든 tree prediction의 평균을 최종 prediction으로 사용합니다.

<details>
<summary>예제 -- Intrusion Detection을 위한 Random Forest (NSL-KDD):</summary>
동일한 NSL-KDD dataset(normal과 anomaly로 binary labeling됨)을 사용하여 Random Forest classifier를 training합니다. ensemble averaging으로 variance가 감소하므로 random forest가 단일 decision tree와 비슷하거나 더 나은 성능을 낼 것으로 예상합니다. 동일한 metrics를 사용하여 평가하겠습니다.
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
Random forest는 일반적으로 이 intrusion detection task에서 강력한 결과를 달성합니다. 데이터에 따라 single decision tree와 비교했을 때 특히 recall 또는 precision에서 F1이나 AUC 같은 metric이 향상되는 것을 확인할 수 있습니다. 이는 *"Random Forest (RF)는 ensemble classifier이며, attack을 효과적으로 classification하는 데 있어 다른 traditional classifier보다 우수한 성능을 보인다."*는 이해와 일치합니다.<sup>[[6]](#references)</sup> Security operations context에서 random forest model은 여러 decision rule의 평균을 사용하므로 false alarm을 줄이면서 attack을 더 안정적으로 flag할 수 있습니다. Forest에서 제공하는 feature importance를 통해 어떤 network feature가 attack을 가장 잘 나타내는지 확인할 수도 있습니다(예: 특정 network service 또는 비정상적으로 많은 packet count).

</details>

### Support Vector Machines (SVM)

Support Vector Machines는 주로 classification에 사용되는 강력한 supervised learning model이며(SVR 형태로 regression에도 사용됨), SVM은 두 class 사이의 margin을 최대화하는 **optimal separating hyperplane**을 찾습니다. Training point 중 일부("boundary에 가장 가까운 support vector")만이 이 hyperplane의 위치를 결정합니다. Margin(support vector와 hyperplane 사이의 거리)을 최대화하면 SVM은 일반적으로 우수한 generalization 성능을 달성합니다.<sup>[[8]](#references)</sup>

SVM의 강력한 핵심 기능은 **kernel function**을 사용하여 non-linear relationship을 처리할 수 있다는 점입니다. Data를 higher-dimensional feature space로 암묵적으로 변환하면 linear separator가 존재할 수 있습니다. 일반적인 kernel에는 polynomial, radial basis function (RBF), sigmoid가 포함됩니다. 예를 들어 network traffic class가 raw feature space에서 linearly separable하지 않은 경우, RBF kernel은 이를 higher dimension으로 mapping하여 SVM이 linear split을 찾도록 할 수 있습니다(이는 original space에서는 non-linear boundary에 해당함). Kernel을 선택할 수 있는 유연성 덕분에 SVM은 다양한 문제를 처리할 수 있습니다.

SVM은 high-dimensional feature space(예: text data 또는 malware opcode sequence)와 feature 수가 sample 수에 비해 많은 상황에서 우수한 성능을 보이는 것으로 알려져 있습니다. SVM은 2000년대 malware classification 및 anomaly-based intrusion detection과 같은 초기 cybersecurity application에서 널리 사용되었으며, 높은 accuracy를 보이는 경우가 많았습니다.

그러나 SVM은 매우 큰 dataset으로 쉽게 확장되지 않습니다(training complexity는 sample 수에 대해 super-linear하게 증가하며, 많은 support vector를 저장해야 할 수 있으므로 memory usage도 높을 수 있음). 실제로 수백만 개의 record를 처리하는 network intrusion detection task에서는 신중한 subsampling이나 approximate method를 사용하지 않으면 SVM이 너무 느릴 수 있습니다.

#### **SVM의 주요 특성:**

-   **문제 유형:** Classification(binary 또는 one-vs-one/one-vs-rest를 통한 multiclass) 및 regression variant. 명확한 margin separation이 있는 binary classification에서 자주 사용됩니다.

-   **해석 가능성:** Medium -- SVM은 decision tree 또는 logistic regression만큼 해석 가능하지 않습니다. 어떤 data point가 support vector인지 식별하고(그리고 linear kernel을 사용하는 경우 weight를 통해 어떤 feature가 영향을 미치는지 어느 정도 파악할 수 있지만), 실제로 SVM(non-linear kernel을 사용하는 경우 특히)은 black-box classifier로 취급됩니다.

-   **장점:** High-dimensional space에서 효과적이며, kernel trick을 사용해 복잡한 decision boundary를 modeling할 수 있습니다. Margin을 최대화하면 overfitting에 강하며(특히 적절한 regularization parameter C를 사용하는 경우), class가 큰 거리로 분리되지 않은 경우에도 잘 작동합니다(best compromise boundary를 찾음).

-   **제한 사항:** 대규모 dataset에서 **computationally intensive**합니다(data가 증가할수록 training과 prediction 모두 scaling 성능이 저하됨). Kernel 및 regularization parameter(C, kernel type, RBF의 gamma 등)를 신중하게 tuning해야 합니다. Probabilistic output을 직접 제공하지 않지만 Platt scaling을 사용해 probability를 얻을 수 있습니다. 또한 SVM은 kernel parameter 선택에 민감할 수 있으며, 잘못된 선택은 underfit 또는 overfit을 초래할 수 있습니다.

*Cybersecurity에서의 사용 사례:* SVM은 **malware detection**(예: 추출한 feature 또는 opcode sequence를 기반으로 file classification), **network anomaly detection**(traffic을 normal 또는 malicious로 classification), **phishing detection**(URL feature 사용)에 활용되어 왔습니다. 예를 들어 SVM은 email feature(특정 keyword count, sender reputation score 등)를 입력받아 phishing인지 legitimate인지 classification할 수 있습니다. 또한 KDD와 같은 feature set을 사용한 **intrusion detection**에도 적용되었으며, computation cost를 감수하는 대신 높은 accuracy를 달성하는 경우가 많았습니다.

<details>
<summary>Example -- Malware Classification을 위한 SVM:</summary>
이번에는 phishing website dataset을 SVM과 함께 사용합니다. SVM은 느릴 수 있으므로 필요한 경우 training에 data의 subset을 사용합니다(dataset은 약 11k instance로, SVM이 비교적 무리 없이 처리할 수 있는 규모임). Non-linear data에 일반적으로 사용하는 RBF kernel을 사용하고, ROC AUC를 계산할 수 있도록 probability estimate를 활성화합니다.
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
SVM 모델은 동일한 task에서 logistic regression과 비교할 수 있는 metrics를 출력합니다. 데이터가 features에 의해 잘 분리된다면 SVM이 높은 accuracy와 AUC를 달성하는 것을 확인할 수 있습니다. 반대로 dataset에 noise가 많거나 class가 겹친다면 SVM이 logistic regression보다 크게 뛰어나지 않을 수 있습니다. 실제로 SVM은 features와 class 사이에 복잡한 비선형 관계가 있을 때 성능을 향상시킬 수 있습니다. RBF kernel은 logistic regression이 놓치는 곡선형 decision boundary를 포착할 수 있습니다. 모든 모델과 마찬가지로 bias와 variance의 균형을 맞추려면 `C` (regularization)와 kernel parameters (예: RBF의 `gamma`)를 신중하게 tuning해야 합니다.

</details>

#### Logistic Regression과 SVM의 차이

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log-loss** (cross-entropy)를 최소화합니다. | **margin**을 최대화하면서 **hinge-loss**를 최소화합니다. |
| **Decision boundary** | _P(y\|x)_를 모델링하는 **best-fit hyperplane**을 찾습니다. | 가장 가까운 points와의 간격이 가장 큰 **maximum-margin hyperplane**을 찾습니다. |
| **Output** | **Probabilistic** – σ(w·x + b)를 통해 calibrated class probabilities를 제공합니다. | **Deterministic** – class labels를 반환합니다. probabilities에는 추가 작업(예: Platt scaling)이 필요합니다. |
| **Regularisation** | L2 (default) 또는 L1을 사용하여 under/over-fitting의 균형을 직접 조정합니다. | C parameter가 margin width와 mis-classifications 사이의 균형을 조정하며, kernel parameters가 complexity를 추가합니다. |
| **Kernels / Non-linear** | 기본 형태는 **linear**이며, feature engineering을 통해 비선형성을 추가합니다. | 내장된 **kernel trick** (RBF, poly 등)을 통해 high-dim. space에서 복잡한 boundaries를 모델링할 수 있습니다. |
| **Scalability** | **O(nd)**에서 convex optimisation을 수행하며, 매우 큰 n을 잘 처리합니다. | specialised solvers 없이는 training에 **O(n²–n³)** memory/time이 필요할 수 있어, 매우 큰 n에는 적합하지 않습니다. |
| **Interpretability** | **High** – weights가 feature influence를 보여주며, odds ratio가 직관적입니다. | 비선형 kernels에서는 **Low**입니다. support vectors는 sparse하지만 설명하기 쉽지 않습니다. |
| **Sensitivity to outliers** | smooth log-loss를 사용하므로 민감도가 낮습니다. | hard margin의 hinge-loss는 **민감할 수 있습니다**. soft-margin (C)이 이를 완화합니다. |
| **Typical use cases** | **probabilities와 explainability**가 중요한 credit scoring, medical risk, A/B testing 등에 사용됩니다. | **복잡한 boundaries와 high-dimensional data**가 중요한 image/text classification, bio-informatics 등에 사용됩니다. |

* **calibrated probabilities, interpretability가 필요하거나 매우 큰 datasets에서 작업한다면 Logistic Regression을 선택하세요.**
* **수동 feature engineering 없이 비선형 관계를 포착할 수 있는 유연한 모델이 필요하다면 SVM (with kernels)을 선택하세요.**
* 두 모델 모두 convex objectives를 최적화하므로 **global minima가 보장되지만**, SVM의 kernels는 hyper-parameters와 computational cost를 추가합니다.

### Naive Bayes

Naive Bayes는 features 사이에 강한 independence assumption을 적용하는 Bayes' Theorem에 기반한 **probabilistic classifiers**의 한 종류입니다. 이러한 "naive" assumption에도 불구하고 Naive Bayes는 특정 applications, 특히 spam detection과 같은 text 또는 categorical data를 다루는 applications에서 놀라울 정도로 잘 작동하는 경우가 많습니다.<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem은 Naive Bayes classifiers의 기반입니다. 이는 random events의 conditional probabilities와 marginal probabilities를 연결합니다. 공식은 다음과 같습니다:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
다음과 같습니다:
- `P(A|B)`는 feature `B`가 주어졌을 때 class `A`의 posterior probability입니다.
- `P(B|A)`는 class `A`가 주어졌을 때 feature `B`의 likelihood입니다.
- `P(A)`는 class `A`의 prior probability입니다.
- `P(B)`는 feature `B`의 prior probability입니다.

예를 들어 텍스트가 어린이가 작성했는지 성인이 작성했는지 분류하려는 경우, 텍스트의 단어를 feature로 사용할 수 있습니다. 일부 초기 데이터를 기반으로 Naive Bayes classifier는 각 단어가 각 potential class(어린이 또는 성인)에 속할 확률을 미리 계산합니다. 새로운 텍스트가 주어지면 텍스트에 포함된 단어를 기반으로 각 potential class의 확률을 계산하고, 확률이 가장 높은 class를 선택합니다.

이 예제에서 볼 수 있듯이 Naive Bayes classifier는 매우 단순하고 빠르지만, feature들이 서로 independent하다고 가정합니다. 이는 실제 데이터에서는 항상 성립하지 않습니다.


#### Naive Bayes Classifier의 유형

데이터 유형과 feature의 distribution에 따라 여러 유형의 Naive Bayes classifier가 있습니다:
- **Gaussian Naive Bayes**: feature가 Gaussian (normal) distribution을 따른다고 가정합니다. continuous data에 적합합니다.
- **Multinomial Naive Bayes**: feature가 multinomial distribution을 따른다고 가정합니다. text classification의 word count와 같은 discrete data에 적합합니다.
- **Bernoulli Naive Bayes**: feature가 binary (0 또는 1)라고 가정합니다. text classification에서 단어의 존재 여부와 같은 binary data에 적합합니다.
- **Categorical Naive Bayes**: feature가 categorical variable이라고 가정합니다. 색상과 모양을 기반으로 과일을 분류하는 것과 같은 categorical data에 적합합니다.


#### **Naive Bayes의 주요 특성:**

-   **문제 유형:** Classification (binary 또는 multi-class). cybersecurity의 text classification task (spam, phishing 등)에 일반적으로 사용됩니다.

-   **해석 가능성:** Medium -- decision tree만큼 직접적으로 해석할 수는 없지만, 학습된 probability를 확인할 수 있습니다(예: spam email과 ham email 중 어떤 단어가 가장 높은 확률로 나타나는지). 필요한 경우 model의 형태(class별 각 feature의 probability)를 이해할 수 있습니다.

-   **장점:** 대규모 dataset에서도 training과 prediction이 **매우 빠릅니다**(instance 수 * feature 수에 대해 linear). 특히 적절한 smoothing을 적용하면 probability를 안정적으로 추정하는 데 비교적 적은 데이터만 필요합니다. 특히 feature가 class에 대한 evidence를 independent하게 제공하는 경우 baseline으로서 놀라울 정도로 정확한 경우가 많습니다. high-dimensional data(예: text에서 얻은 수천 개의 feature)에서 잘 작동합니다. smoothing parameter 설정 외에는 복잡한 tuning이 필요하지 않습니다.

-   **제한 사항:** feature 간 상관관계가 매우 높은 경우 independence assumption으로 인해 정확도가 제한될 수 있습니다. 예를 들어 network data에서 `src_bytes`와 `dst_bytes` 같은 feature는 상관관계가 있을 수 있지만, Naive Bayes는 이러한 interaction을 포착하지 못합니다. 데이터 크기가 매우 커지면 feature dependency를 학습할 수 있는 ensemble이나 neural net과 같은 더욱 expressive한 model이 NB를 능가할 수 있습니다. 또한 attack을 식별하려면 개별 feature가 independent하게 존재하는 것만이 아니라 특정 feature 조합이 필요한 경우에도 NB는 어려움을 겪습니다.

> [!TIP]
> *cybersecurity에서의 사용 사례:* 가장 대표적인 사용 사례는 **spam detection**입니다 -- Naive Bayes는 특정 token(단어, 구문, IP address)의 빈도를 사용해 email이 spam일 확률을 계산하는 초기 spam filter의 핵심이었습니다. 또한 **phishing email detection**과 **URL classification**에도 사용되며, 특정 keyword나 특성(URL의 "login.php" 또는 URL path의 `@` 등)의 존재 여부가 phishing probability에 기여합니다. malware analysis에서는 특정 API call이나 software의 permission 존재 여부를 사용해 해당 software가 malware인지 예측하는 Naive Bayes classifier를 생각해볼 수 있습니다. 더 advanced한 algorithm이 더 나은 성능을 내는 경우가 많지만, Naive Bayes는 속도와 단순성 때문에 여전히 좋은 baseline으로 사용됩니다.

<details>
<summary>예제 -- Phishing Detection을 위한 Naive Bayes:</summary>
Naive Bayes를 설명하기 위해 NSL-KDD intrusion dataset(binary label 포함)에 Gaussian Naive Bayes를 사용하겠습니다. Gaussian NB는 각 class에서 각 feature가 normal distribution을 따른다고 간주합니다. 많은 network feature가 discrete하거나 distribution이 크게 치우쳐 있으므로 이는 대략적인 선택이지만, continuous feature data에 NB를 적용하는 방법을 보여줍니다. binary feature dataset(예: triggered alert 집합)에서는 Bernoulli NB를 선택할 수도 있지만, 여기서는 연속성을 위해 NSL-KDD를 사용하겠습니다.
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
이 코드는 공격을 탐지하도록 Naive Bayes classifier를 학습합니다. Naive Bayes는 feature 간의 독립성을 가정하고 training data를 기반으로 `P(service=http | Attack)` 및 `P(Service=http | Normal)`과 같은 값을 계산합니다. 그런 다음 관찰된 feature를 바탕으로 새로운 connection을 normal 또는 attack으로 분류하는 데 이러한 probability를 사용합니다. NSL-KDD에서 NB의 performance는 더 advanced한 model만큼 높지 않을 수 있지만(feature independence 가정이 위반되므로), 대체로 준수한 성능을 보이며 매우 빠르다는 장점이 있습니다. real-time email filtering이나 URL의 initial triage와 같은 시나리오에서 Naive Bayes model은 적은 resource usage로 명백히 malicious한 case를 빠르게 flag할 수 있습니다.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors는 가장 단순한 machine learning algorithm 중 하나입니다. 이는 training set의 example과의 similarity를 기반으로 prediction을 수행하는 **non-parametric, instance-based** method입니다. classification의 기본 개념은 다음과 같습니다. 새로운 data point를 분류하기 위해 training data에서 가장 가까운 **k**개의 point(해당 point의 "nearest neighbors")를 찾고, 해당 neighbor들 사이에서 다수인 class를 할당합니다. "Closeness"는 distance metric으로 정의되며, 일반적으로 numeric data에는 Euclidean distance가 사용됩니다(다른 유형의 feature나 problem에는 다른 distance를 사용할 수 있습니다).<sup>[[10]](#references)</sup>

K-NN에는 *explicit training이 필요하지 않습니다* -- "training" phase는 단순히 dataset을 저장하는 과정입니다. 모든 작업은 query(prediction) 중에 수행됩니다. algorithm은 nearest point를 찾기 위해 query point와 모든 training point 사이의 distance를 계산해야 합니다. 따라서 prediction time은 **training sample 수에 선형**이며, large dataset에서는 비용이 커질 수 있습니다. 이 때문에 k-NN은 더 작은 dataset이나 simplicity를 위해 memory와 speed를 trade-off할 수 있는 시나리오에 가장 적합합니다.

단순하지만 k-NN은 매우 복잡한 decision boundary를 modeling할 수 있습니다(실질적으로 decision boundary는 example의 distribution에 의해 결정되는 어떤 형태든 될 수 있기 때문입니다). Decision boundary가 매우 irregular하고 data가 많을 때, 즉 data가 "스스로 말하게" 할 때 좋은 성능을 내는 경향이 있습니다. 그러나 high dimension에서는 distance metric이 덜 의미 있어질 수 있으며(curse of dimensionality), 매우 많은 sample이 없다면 method가 어려움을 겪을 수 있습니다.

*Use cases in cybersecurity:* k-NN은 anomaly detection에 적용되어 왔습니다. 예를 들어 intrusion detection system은 대부분의 nearest neighbor(previous event)가 malicious했던 경우 network event를 malicious로 label할 수 있습니다. Normal traffic이 cluster를 형성하고 attack이 outlier인 경우, k-NN approach(k=1 또는 작은 k 사용)는 본질적으로 **nearest-neighbor anomaly detection**을 수행합니다. K-NN은 binary feature vector를 사용하여 malware family를 분류하는 데에도 사용되어 왔습니다. 새로운 file이 feature space에서 특정 malware family의 known instance와 매우 가까우면 해당 malware family로 분류될 수 있습니다. 실제로 k-NN은 더 scalable한 algorithm만큼 흔하게 사용되지는 않지만, 개념적으로 straightforward하며 baseline 또는 small-scale problem에 사용되기도 합니다.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification(및 regression variant도 존재). *lazy learning* method이며 -- explicit model fitting이 없습니다.

-   **Interpretability:** Low to medium -- global model이나 간결한 explanation은 없지만, decision에 영향을 준 nearest neighbor를 살펴보면 result를 해석할 수 있습니다(예: "이 network flow는 알려진 malicious flow 3개와 유사하기 때문에 malicious로 분류되었습니다"). 따라서 explanation은 example-based일 수 있습니다.

-   **Advantages:** 구현과 이해가 매우 간단합니다. Data distribution에 대한 가정이 없습니다(non-parametric). Multi-class problem을 자연스럽게 처리할 수 있습니다. Decision boundary가 매우 복잡할 수 있고 data distribution에 의해 형성된다는 점에서 **adaptive**합니다.

-   **Limitations:** Large dataset에서는 prediction이 느릴 수 있습니다(많은 distance를 계산해야 함). Memory-intensive하며 -- 모든 training data를 저장합니다. High-dimensional feature space에서는 모든 point가 거의 같은 거리에 놓이는 경향이 있어("nearest"라는 개념의 의미가 감소함) performance가 저하됩니다. *k*(neighbor 수)를 적절히 선택해야 합니다 -- k가 너무 작으면 noisy해질 수 있고, 너무 크면 다른 class의 관련 없는 point가 포함될 수 있습니다. 또한 distance calculation은 scale에 민감하므로 feature를 적절하게 scaling해야 합니다.

<details>
<summary>Example -- Phishing Detection을 위한 k-NN:</summary>

다시 NSL-KDD(binary classification)를 사용합니다. k-NN은 computationally heavy하므로 이 demonstration에서는 처리 가능한 수준을 유지하기 위해 training data의 subset을 사용합니다. 전체 125k 중, 예를 들어 training sample 20,000개를 선택하고 k=5 neighbor를 사용합니다. Training 후(실제로는 단순히 data를 저장한 후) test set에서 evaluate합니다. 또한 distance calculation을 위해 feature를 scaling하여 scale 때문에 특정 feature 하나가 지배적인 영향을 미치지 않도록 합니다.
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
k-NN model은 training set subset에서 가장 가까운 5개의 connection을 살펴 connection을 classify합니다. 예를 들어 이러한 neighbors 중 4개가 attack(anomaly)이고 1개가 normal이면, 새로운 connection은 attack으로 classify됩니다. 성능은 reasonable할 수 있지만, 동일한 data에서 잘 tuning된 Random Forest나 SVM만큼 높지 않은 경우가 많습니다. 그러나 class distribution이 매우 불규칙하고 복잡한 경우 k-NN이 뛰어난 성능을 보일 수 있으며, 사실상 memory-based lookup을 사용합니다. 사이버보안에서 k-NN(k=1 또는 작은 k)은 예제를 통한 known attack pattern detection에 사용하거나, 더 복잡한 시스템의 구성 요소(예: clustering 후 cluster membership에 기반한 classification)로 사용할 수 있습니다.
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines는 structured data를 위한 가장 강력한 algorithm 중 하나입니다. **Gradient boosting**은 weak learner ensemble(주로 decision tree)을 순차적으로 구축하는 technique을 의미하며, 각 새로운 model은 이전 ensemble의 errors를 수정합니다. tree를 parallel하게 구축한 후 평균을 내는 bagging(Random Forests)과 달리, boosting은 tree를 *one by one* 구축하며, 각 tree는 이전 tree들이 잘못 예측한 instances에 더 집중합니다.<sup>[[11]](#references)</sup>

최근 가장 널리 사용되는 implementation은 **XGBoost**, **LightGBM**, **CatBoost**이며, 모두 gradient boosting decision tree(GBDT) library입니다. 이들은 machine learning competition과 application에서 매우 성공적이었으며, **tabular dataset에서 state-of-the-art performance를 달성**하는 경우가 많습니다. 사이버보안에서 researchers와 practitioners는 **malware detection**(file 또는 runtime behavior에서 추출한 feature 사용) 및 **network intrusion detection**과 같은 task에 gradient boosted tree를 사용해 왔습니다. 예를 들어 gradient boosting model은 "SYN packet이 많고 unusual port이면 -> scan일 가능성이 높음"과 같은 여러 weak rule(tree)을 결합하여, 미묘한 pattern을 다양하게 고려하는 강력한 composite detector를 만들 수 있습니다.

Boosted tree가 효과적인 이유는 무엇일까요? Sequence의 각 tree는 현재 ensemble prediction의 *residual error*(gradient)를 대상으로 training됩니다. 이를 통해 model은 취약한 영역을 점진적으로 **"boost"**합니다. Base learner로 decision tree를 사용하므로 최종 model은 복잡한 interaction과 non-linear relation을 포착할 수 있습니다. 또한 boosting에는 기본적으로 regularization의 한 형태가 포함되어 있습니다. 많은 작은 tree를 추가하고(learning rate를 사용해 각 tree의 contribution을 조정), 적절한 parameter를 선택하면 심각한 overfitting 없이도 generalize가 잘 되는 경우가 많습니다.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** 주로 classification 및 regression입니다. security에서는 일반적으로 classification(connection 또는 file을 binary classify하는 등)에 사용됩니다. binary, multi-class(적절한 loss 사용), 심지어 ranking problem도 처리할 수 있습니다.

-   **Interpretability:** 낮음에서 중간 정도입니다. 단일 boosted tree는 작지만, 전체 model은 수백 개의 tree로 구성될 수 있으므로 전체적으로 human-interpretable하지 않습니다. 그러나 Random Forest와 마찬가지로 feature importance score를 제공할 수 있으며, SHAP (SHapley Additive exPlanations)와 같은 tool을 사용하면 individual prediction을 어느 정도 해석할 수 있습니다.

-   **Advantages:** structured/tabular data에서 **가장 높은 performance를 보이는** algorithm인 경우가 많습니다. 복잡한 pattern과 interaction을 detect할 수 있습니다. model complexity를 조정하고 overfitting을 방지할 수 있도록 다양한 tuning knob(number of tree, tree depth, learning rate, regularization term)을 제공합니다. 최신 implementation은 speed에 최적화되어 있습니다(예: XGBoost는 second-order gradient information과 efficient data structure를 사용합니다). 적절한 loss function과 함께 사용하거나 sample weight를 조정하면 imbalanced data를 더 잘 처리하는 경향이 있습니다.

-   **Limitations:** 단순한 model보다 tuning이 복잡합니다. tree가 깊거나 tree 수가 많으면 training이 느려질 수 있습니다(그래도 동일한 data에서 comparable한 deep neural network를 training하는 것보다는 일반적으로 빠릅니다). tuning하지 않으면 model이 overfit할 수 있습니다(예: regularization이 충분하지 않은 상태에서 너무 많은 deep tree를 사용하는 경우). hyperparameter가 많기 때문에 gradient boosting을 효과적으로 사용하려면 더 많은 expertise나 experimentation이 필요할 수 있습니다. 또한 tree-based method와 마찬가지로 매우 sparse한 high-dimensional data를 linear model이나 Naive Bayes만큼 효율적으로 본질적으로 처리하지는 못합니다(그래도 text classification 등에 적용할 수 있지만, feature engineering 없이는 first choice가 아닐 수 있습니다).

> [!TIP]
> *Use cases in cybersecurity:* decision tree 또는 random forest를 사용할 수 있는 거의 모든 곳에서 gradient boosting model이 더 높은 accuracy를 달성할 수 있습니다. 예를 들어 **Microsoft의 malware detection** competition에서는 binary file에서 engineering한 feature에 XGBoost를 광범위하게 사용했습니다. **Network intrusion detection** research에서는 GBDT(예: CIC-IDS2017 또는 UNSW-NB15 dataset의 XGBoost)를 사용해 top result를 보고하는 경우가 많습니다. 이러한 model은 다양한 feature(protocol type, 특정 event의 frequency, traffic의 statistical feature 등)를 입력으로 받아 이를 결합해 threat를 detect할 수 있습니다. phishing detection에서는 gradient boosting이 URL의 lexical feature, domain reputation feature, page content feature를 결합해 매우 높은 accuracy를 달성할 수 있습니다. Ensemble approach는 data의 다양한 corner case와 subtlety를 포괄하는 데 도움이 됩니다.

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
phishing dataset에 gradient boosting classifier를 사용하겠습니다. 간단하고 self-contained하게 유지하기 위해 `sklearn.ensemble.GradientBoostingClassifier`(더 느리지만 straightforward한 implementation)를 사용합니다. 일반적으로는 더 나은 performance와 추가 feature를 위해 `xgboost` 또는 `lightgbm` library를 사용할 수 있습니다. model을 training하고 이전과 유사한 방식으로 evaluate하겠습니다.
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
Gradient boosting model은 이 phishing dataset에서 매우 높은 accuracy와 AUC를 달성할 가능성이 높습니다(문헌에서 볼 수 있듯이, 이러한 데이터에서는 적절한 tuning을 통해 이러한 모델이 95% 이상의 accuracy를 달성하는 경우가 많습니다. 이는 GBDT가 *"tabular dataset을 위한 최첨단 모델"*로 평가되는 이유를 보여 줍니다. GBDT는 복잡한 패턴을 포착하여 더 단순한 알고리즘보다 뛰어난 성능을 내는 경우가 많기 때문입니다).<sup>[[11]](#references)</sup> cybersecurity 맥락에서는 이를 통해 더 많은 phishing 사이트나 공격을 탐지하고 miss를 줄일 수 있습니다. 물론 overfitting에 주의해야 합니다 -- 일반적으로 배포를 위한 이러한 모델을 개발할 때는 cross-validation과 같은 기법을 사용하고 validation set에서 성능을 모니터링합니다.

</details>

### Combining Models: Ensemble Learning and Stacking

Ensemble learning은 전체 성능을 향상하기 위해 **여러 모델을 결합하는** 전략입니다. 앞서 구체적인 ensemble 방법인 Random Forest(bagging을 통한 tree ensemble)와 Gradient Boosting(sequential boosting을 통한 tree ensemble)을 살펴보았습니다. 하지만 **voting ensembles**나 **stacked generalization (stacking)**과 같이 다른 방식으로도 ensemble을 만들 수 있습니다. 핵심 아이디어는 서로 다른 모델이 서로 다른 패턴을 포착하거나 각기 다른 약점을 가질 수 있다는 것입니다. 이를 결합하면 **한 모델의 오류를 다른 모델의 강점으로 보완**할 수 있습니다.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** 단순한 voting classifier에서는 여러 개의 다양한 모델(예: logistic regression, decision tree, SVM)을 train하고 최종 prediction에 대해 투표하게 합니다(classification에서는 majority vote). 투표에 가중치를 부여하면(예: 더 정확한 모델에 더 높은 weight를 부여) weighted voting 방식이 됩니다. 개별 모델이 충분히 우수하고 서로 independent할 때 일반적으로 성능이 향상됩니다 -- 다른 모델이 오류를 수정할 수 있으므로 ensemble이 개별 모델의 실수 위험을 줄이기 때문입니다. 이는 한 사람의 의견이 아니라 전문가 패널의 의견을 활용하는 것과 같습니다.

-   **Stacking (Stacked Ensemble):** Stacking은 한 단계 더 나아갑니다. 단순히 투표하는 대신, **base model의 prediction을 가장 효과적으로 결합하는 방법을 학습하는** **meta-model**을 train합니다. 예를 들어 서로 다른 classifier 3개(base learner)를 train한 다음, 이들의 output(또는 probability)을 meta-classifier(대개 logistic regression과 같은 단순한 model)의 feature로 입력하여 이를 최적으로 결합하는 방법을 학습하게 합니다. meta-model은 overfitting을 방지하기 위해 validation set 또는 cross-validation을 사용해 train합니다. Stacking은 *어떤 상황에서 어떤 model을 더 신뢰해야 하는지* 학습하므로 단순한 voting보다 더 나은 성능을 내는 경우가 많습니다. cybersecurity에서는 한 model이 network scan 탐지에 더 뛰어나고 다른 model이 malware beaconing 탐지에 더 뛰어날 수 있습니다. stacking model은 각 model을 적절한 상황에서 활용하도록 학습할 수 있습니다.

Voting이나 stacking을 사용하는 ensemble은 대체로 **accuracy**와 robustness를 **향상**합니다. 단점은 복잡성이 증가하고 해석 가능성이 낮아질 수 있다는 점입니다(다만 decision tree의 average와 같은 일부 ensemble 접근 방식은 feature importance 등 어느 정도의 insight를 여전히 제공할 수 있습니다). 실제로 operational constraint가 허용된다면 ensemble을 사용하여 더 높은 detection rate를 달성할 수 있습니다. cybersecurity challenge의 많은 우승 solution(일반적인 Kaggle competition 포함)은 성능을 마지막까지 끌어올리기 위해 ensemble 기법을 사용합니다.

<details>
<summary>Example -- Voting Ensemble for Phishing Detection:</summary>
Model stacking을 설명하기 위해 phishing dataset에서 앞서 논의한 model 몇 가지를 결합해 보겠습니다. base learner로 logistic regression, decision tree, k-NN을 사용하고, meta-learner로 Random Forest를 사용해 이들의 prediction을 aggregate합니다. meta-learner는 base learner의 output을 기반으로 train합니다(training set에서 cross-validation 사용). stacked model은 개별 model과 비슷하거나 약간 더 나은 성능을 보일 것으로 예상됩니다.
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
스택형 ensemble은 base model들의 상호 보완적인 강점을 활용합니다. 예를 들어 logistic regression은 데이터의 선형적 측면을 처리하고, decision tree는 특정한 규칙과 유사한 상호작용을 포착하며, k-NN은 feature space의 국소 영역에서 뛰어난 성능을 보일 수 있습니다. 여기서 meta-model(random forest)은 이러한 입력에 가중치를 부여하는 방법을 학습할 수 있습니다. 최종 metric은 단일 model의 metric보다(개선 폭이 작더라도) 향상되는 경우가 많습니다. phishing 예제에서 logistic만 사용했을 때 F1이 0.95이고 tree가 0.94였다면, stack은 각 model이 놓치는 부분을 보완하여 0.96을 달성할 수 있습니다.

이와 같은 ensemble method는 *"여러 model을 결합하면 일반적으로 더 나은 generalization으로 이어진다"*는 원칙을 보여줍니다.<sup>[[12]](#references)</sup> 사이버 보안에서는 여러 detection engine(하나는 rule-based, 하나는 machine learning 기반, 하나는 anomaly-based일 수 있음)을 사용한 다음, 그 alert를 집계하는 layer를 두어 -- 사실상 ensemble의 한 형태 -- 더 높은 confidence로 최종 결정을 내리도록 구현할 수 있습니다. 이러한 system을 deploy할 때는 추가되는 복잡성을 고려하고, ensemble이 관리하거나 설명하기에 지나치게 어려워지지 않도록 해야 합니다. 그러나 정확성 측면에서 ensemble과 stacking은 model performance를 개선하는 강력한 도구입니다.

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
