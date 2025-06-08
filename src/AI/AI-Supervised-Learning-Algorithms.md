# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Basic Information

지도 학습은 레이블이 있는 데이터를 사용하여 새로운, 보지 못한 입력에 대한 예측을 할 수 있는 모델을 훈련합니다. 사이버 보안에서 지도 기계 학습은 침입 탐지(*정상* 또는 *공격*으로 네트워크 트래픽 분류), 악성 소프트웨어 탐지(악성 소프트웨어와 정상 소프트웨어 구분), 피싱 탐지(사기 웹사이트 또는 이메일 식별), 스팸 필터링 등과 같은 작업에 널리 적용됩니다. 각 알고리즘은 강점을 가지고 있으며 서로 다른 유형의 문제(분류 또는 회귀)에 적합합니다. 아래에서는 주요 지도 학습 알고리즘을 검토하고, 작동 방식을 설명하며, 실제 사이버 보안 데이터 세트에서의 사용을 시연합니다. 또한 모델 결합(앙상블 학습)이 예측 성능을 향상시킬 수 있는 방법에 대해서도 논의합니다.

## Algorithms

-   **Linear Regression:** 데이터를 기반으로 선형 방정식을 적합하여 숫자 결과를 예측하는 기본 회귀 알고리즘입니다.

-   **Logistic Regression:** 이진 결과의 확률을 모델링하기 위해 로지스틱 함수를 사용하는 분류 알고리즘(이름과는 달리)입니다.

-   **Decision Trees:** 예측을 위해 데이터를 특징별로 분할하는 트리 구조 모델입니다. 해석 가능성 때문에 자주 사용됩니다.

-   **Random Forests:** 정확성을 향상시키고 과적합을 줄이는 결정 트리의 앙상블(배깅을 통해)입니다.

-   **Support Vector Machines (SVM):** 최적의 분리 초평면을 찾는 최대 마진 분류기입니다. 비선형 데이터에 대해 커널을 사용할 수 있습니다.

-   **Naive Bayes:** 특징 독립성을 가정한 베이즈 정리를 기반으로 한 확률적 분류기로, 스팸 필터링에 유명하게 사용됩니다.

-   **k-Nearest Neighbors (k-NN):** 가장 가까운 이웃의 다수 클래스에 따라 샘플에 레이블을 지정하는 간단한 "인스턴스 기반" 분류기입니다.

-   **Gradient Boosting Machines:** 약한 학습자(일반적으로 결정 트리)를 순차적으로 추가하여 강력한 예측기를 구축하는 앙상블 모델(예: XGBoost, LightGBM)입니다.

아래 각 섹션에서는 알고리즘에 대한 개선된 설명과 `pandas` 및 `scikit-learn`(신경망 예제의 경우 `PyTorch`)과 같은 라이브러리를 사용한 **Python 코드 예제**를 제공합니다. 예제는 공개적으로 사용 가능한 사이버 보안 데이터 세트(예: 침입 탐지를 위한 NSL-KDD 및 피싱 웹사이트 데이터 세트)를 사용하며 일관된 구조를 따릅니다:

1.  **데이터 세트 로드** (가능한 경우 URL을 통해 다운로드).

2.  **데이터 전처리** (예: 범주형 특징 인코딩, 값 스케일링, 훈련/테스트 세트로 분할).

3.  **훈련 데이터**에서 모델 훈련.

4.  **테스트 세트에서 평가**: 분류의 경우 정확도, 정밀도, 재현율, F1 점수 및 ROC AUC(회귀의 경우 평균 제곱 오차 사용).

각 알고리즘을 살펴보겠습니다:

### Linear Regression

선형 회귀는 연속적인 숫자 값을 예측하는 데 사용되는 **회귀** 알고리즘입니다. 입력 특징(독립 변수)과 출력(종속 변수) 간의 선형 관계를 가정합니다. 모델은 특징과 목표 간의 관계를 가장 잘 설명하는 직선(또는 고차원에서의 초평면)을 적합하려고 합니다. 이는 일반적으로 예측 값과 실제 값 간의 제곱 오차 합을 최소화함으로써 수행됩니다(최소 제곱법). 

선형 회귀를 나타내는 가장 간단한 형태는 선으로 표현됩니다:
```plaintext
y = mx + b
```
어디에:

- `y`는 예측된 값(출력)입니다.
- `m`은 선의 기울기(계수)입니다.
- `x`는 입력 특성입니다.
- `b`는 y-절편입니다.

선형 회귀의 목표는 예측된 값과 데이터셋의 실제 값 사이의 차이를 최소화하는 최적의 적합선을 찾는 것입니다. 물론, 이것은 매우 간단하며, 2개의 범주를 구분하는 직선이 될 것입니다. 그러나 더 많은 차원이 추가되면 선은 더 복잡해집니다:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *사이버 보안에서의 사용 사례:* 선형 회귀는 핵심 보안 작업(대부분 분류 작업)에 비해 덜 일반적이지만, 수치적 결과를 예측하는 데 적용될 수 있습니다. 예를 들어, 선형 회귀를 사용하여 **네트워크 트래픽의 양을 예측**하거나 **특정 기간 내 공격의 수를 추정**할 수 있습니다. 또한 특정 시스템 메트릭을 고려하여 위험 점수나 공격 탐지까지의 예상 시간을 예측할 수 있습니다. 실제로는 분류 알고리즘(로지스틱 회귀나 트리와 같은)이 침입이나 악성 소프트웨어 탐지에 더 자주 사용되지만, 선형 회귀는 기초로서 회귀 지향 분석에 유용합니다.

#### **선형 회귀의 주요 특성:**

-   **문제 유형:** 회귀(연속 값 예측). 출력에 임계값이 적용되지 않는 한 직접적인 분류에는 적합하지 않음.

-   **해석 가능성:** 높음 -- 계수는 직관적으로 해석할 수 있으며, 각 특성의 선형 효과를 보여줌.

-   **장점:** 간단하고 빠르며; 회귀 작업의 좋은 기준선; 실제 관계가 대략 선형일 때 잘 작동함.

-   **제한 사항:** 복잡하거나 비선형 관계를 포착할 수 없음(수동 특성 엔지니어링 없이는); 관계가 비선형일 경우 과소적합에 취약함; 결과를 왜곡할 수 있는 이상치에 민감함.

-   **최적의 적합 찾기:** 가능한 범주를 분리하는 최적의 적합선을 찾기 위해 **최소 제곱법(OLS)**이라는 방법을 사용합니다. 이 방법은 관측된 값과 선형 모델에 의해 예측된 값 사이의 제곱 차이의 합을 최소화합니다.

<details>
<summary>예시 -- 침입 데이터셋에서 연결 지속 시간 예측(회귀)
</summary>
아래에서는 NSL-KDD 사이버 보안 데이터셋을 사용하여 선형 회귀를 시연합니다. 다른 특성을 기반으로 네트워크 연결의 `지속 시간`을 예측하여 이를 회귀 문제로 다룰 것입니다. (실제로 `지속 시간`은 NSL-KDD의 하나의 특성이며, 회귀를 설명하기 위해 여기서 사용합니다.) 데이터셋을 로드하고, 전처리(범주형 특성 인코딩), 선형 회귀 모델을 훈련시키고, 테스트 세트에서 평균 제곱 오차(MSE)와 R² 점수를 평가합니다.
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
이 예제에서 선형 회귀 모델은 다른 네트워크 특성으로부터 연결 `duration`을 예측하려고 합니다. 우리는 평균 제곱 오차(Mean Squared Error, MSE)와 R²로 성능을 측정합니다. R²가 1.0에 가까울수록 모델이 `duration`의 대부분 변동성을 설명한다는 것을 나타내며, 낮거나 음의 R²는 적합도가 좋지 않음을 나타냅니다. (여기서 R²가 낮더라도 놀라지 마세요 -- 주어진 특성으로부터 `duration`을 예측하는 것이 어려울 수 있으며, 선형 회귀는 복잡한 패턴을 포착하지 못할 수 있습니다.)

### 로지스틱 회귀

로지스틱 회귀는 특정 클래스(일반적으로 "양성" 클래스)에 인스턴스가 속할 확률을 모델링하는 **분류** 알고리즘입니다. 이름과는 달리, *로지스틱* 회귀는 이산 결과에 사용됩니다(연속 결과를 위한 선형 회귀와는 다름). 주로 **이진 분류**(두 클래스, 예: 악성 vs. benign)에 사용되지만, 다중 클래스 문제로 확장할 수 있습니다(softmax 또는 one-vs-rest 접근 방식을 사용).

로지스틱 회귀는 예측 값을 확률로 매핑하기 위해 로지스틱 함수(시그모이드 함수라고도 함)를 사용합니다. 시그모이드 함수는 0과 1 사이의 값을 가지며 분류의 필요에 따라 S자 형태의 곡선으로 성장하는 함수로, 이진 분류 작업에 유용합니다. 따라서 각 입력의 각 특성은 할당된 가중치와 곱해지고, 결과는 시그모이드 함수를 통과하여 확률을 생성합니다:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
어디에:

- `p(y=1|x)`는 입력 `x`가 주어졌을 때 출력 `y`가 1일 확률입니다.
- `e`는 자연 로그의 밑입니다.
- `z`는 입력 특징의 선형 조합으로, 일반적으로 `z = w1*x1 + w2*x2 + ... + wn*xn + b`로 표현됩니다. 가장 단순한 형태에서는 직선이지만, 더 복잡한 경우에는 여러 차원(특징당 하나)의 초평면이 됩니다.

> [!TIP]
> *사이버 보안에서의 사용 사례:* 많은 보안 문제는 본질적으로 예/아니오 결정이기 때문에 로지스틱 회귀가 널리 사용됩니다. 예를 들어, 침입 탐지 시스템은 네트워크 연결의 특징을 기반으로 해당 연결이 공격인지 결정하기 위해 로지스틱 회귀를 사용할 수 있습니다. 피싱 탐지에서는 로지스틱 회귀가 웹사이트의 특징(URL 길이, "@" 기호의 존재 등)을 결합하여 피싱일 확률을 생성할 수 있습니다. 초기 세대 스팸 필터에서 사용되었으며, 많은 분류 작업의 강력한 기준선으로 남아 있습니다.

#### 비 이진 분류를 위한 로지스틱 회귀

로지스틱 회귀는 이진 분류를 위해 설계되었지만, **one-vs-rest** (OvR) 또는 **softmax 회귀**와 같은 기술을 사용하여 다중 클래스 문제를 처리하도록 확장할 수 있습니다. OvR에서는 각 클래스를 긍정 클래스와 다른 모든 클래스를 대조하여 별도의 로지스틱 회귀 모델을 훈련합니다. 예측 확률이 가장 높은 클래스가 최종 예측으로 선택됩니다. Softmax 회귀는 출력층에 소프트맥스 함수를 적용하여 여러 클래스에 대해 로지스틱 회귀를 일반화하여 모든 클래스에 대한 확률 분포를 생성합니다.

#### **로지스틱 회귀의 주요 특성:**

-   **문제 유형:** 분류(일반적으로 이진). 긍정 클래스의 확률을 예측합니다.

-   **해석 가능성:** 높음 -- 선형 회귀와 마찬가지로, 특징 계수는 각 특징이 결과의 로그 오즈에 어떻게 영향을 미치는지를 나타낼 수 있습니다. 이 투명성은 경고에 기여하는 요소를 이해하는 데 보안에서 종종 높이 평가됩니다.

-   **장점:** 훈련이 간단하고 빠르며, 특징과 결과의 로그 오즈 간의 관계가 선형일 때 잘 작동합니다. 확률을 출력하여 위험 점수를 가능하게 합니다. 적절한 정규화를 통해 잘 일반화되며, 일반 선형 회귀보다 다중 공선성을 더 잘 처리할 수 있습니다.

-   **제한 사항:** 특징 공간에서 선형 결정 경계를 가정합니다(진짜 경계가 복잡하거나 비선형인 경우 실패). 상호작용이나 비선형 효과가 중요한 문제에서는 성능이 떨어질 수 있으며, 다항식 또는 상호작용 특징을 수동으로 추가하지 않는 한 그렇습니다. 또한, 클래스가 특징의 선형 조합으로 쉽게 분리되지 않는 경우 로지스틱 회귀의 효과가 떨어집니다.


<details>
<summary>예시 -- 로지스틱 회귀를 이용한 피싱 웹사이트 탐지:</summary>

우리는 **피싱 웹사이트 데이터셋**(UCI 저장소에서) 을 사용할 것입니다. 이 데이터셋은 웹사이트의 특징(예: URL에 IP 주소가 있는지, 도메인의 나이, HTML의 의심스러운 요소의 존재 등)과 사이트가 피싱인지 합법적인지를 나타내는 레이블을 포함합니다. 우리는 웹사이트를 분류하기 위해 로지스틱 회귀 모델을 훈련하고, 테스트 분할에서 정확도, 정밀도, 재현율, F1 점수 및 ROC AUC를 평가합니다.
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
이 피싱 탐지 예제에서 로지스틱 회귀는 각 웹사이트가 피싱일 확률을 생성합니다. 정확도, 정밀도, 재현율 및 F1을 평가함으로써 모델의 성능을 파악할 수 있습니다. 예를 들어, 높은 재현율은 대부분의 피싱 사이트를 잡아낸다는 것을 의미하며(놓친 공격을 최소화하기 위해 보안에 중요), 높은 정밀도는 잘못된 경고가 적다는 것을 의미합니다(분석가의 피로를 피하기 위해 중요합니다). ROC AUC(ROC 곡선 아래 면적)는 성능의 임계값 독립적인 측정을 제공합니다(1.0이 이상적이며, 0.5는 우연과 다르지 않음). 로지스틱 회귀는 이러한 작업에서 종종 잘 수행되지만, 피싱 사이트와 합법적인 사이트 간의 결정 경계가 복잡하다면 더 강력한 비선형 모델이 필요할 수 있습니다.

</details>

### 결정 트리

결정 트리는 분류 및 회귀 작업 모두에 사용할 수 있는 다재다능한 **감독 학습 알고리즘**입니다. 데이터의 특성을 기반으로 한 결정의 계층적 트리 모델을 학습합니다. 트리의 각 내부 노드는 특정 특성에 대한 테스트를 나타내고, 각 가지는 해당 테스트의 결과를 나타내며, 각 리프 노드는 예측된 클래스(분류의 경우) 또는 값(회귀의 경우)을 나타냅니다.

트리를 구축하기 위해 CART(분류 및 회귀 트리)와 같은 알고리즘은 **지니 불순도** 또는 **정보 이득(엔트로피)**와 같은 측정을 사용하여 각 단계에서 데이터를 분할할 최상의 특성과 임계값을 선택합니다. 각 분할의 목표는 결과 하위 집합에서 목표 변수의 동질성을 증가시키기 위해 데이터를 분할하는 것입니다(분류의 경우, 각 노드는 가능한 한 순수하게 유지되어야 하며, 주로 단일 클래스를 포함해야 합니다).

결정 트리는 **높은 해석 가능성**을 가지고 있습니다. 루트에서 리프까지의 경로를 따라가며 예측 뒤에 있는 논리를 이해할 수 있습니다(예: *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). 이는 특정 경고가 발생한 이유를 설명하는 데 사이버 보안에서 가치가 있습니다. 트리는 자연스럽게 숫자 데이터와 범주형 데이터를 모두 처리할 수 있으며, 전처리가 거의 필요하지 않습니다(예: 특성 스케일링이 필요하지 않음).

그러나 단일 결정 트리는 훈련 데이터에 쉽게 과적합될 수 있으며, 특히 깊게 성장할 경우(많은 분할). 가지치기(트리 깊이 제한 또는 리프당 최소 샘플 수 요구)와 같은 기술이 종종 과적합을 방지하는 데 사용됩니다.

결정 트리의 주요 구성 요소는 3가지입니다:
- **루트 노드**: 전체 데이터 세트를 나타내는 트리의 최상위 노드.
- **내부 노드**: 특성과 해당 특성에 기반한 결정을 나타내는 노드.
- **리프 노드**: 최종 결과 또는 예측을 나타내는 노드.

트리는 다음과 같이 보일 수 있습니다:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *사이버 보안의 사용 사례:* 의사 결정 트리는 침입 탐지 시스템에서 공격을 식별하기 위한 **규칙**을 도출하는 데 사용되었습니다. 예를 들어, ID3/C4.5 기반의 초기 IDS는 정상 트래픽과 악의적인 트래픽을 구별하기 위해 사람이 읽을 수 있는 규칙을 생성했습니다. 또한 파일의 속성(파일 크기, 섹션 엔트로피, API 호출 등)을 기반으로 파일이 악의적인지 결정하기 위해 악성 코드 분석에도 사용됩니다. 의사 결정 트리의 명확성은 투명성이 필요할 때 유용하게 만듭니다. 분석가는 트리를 검사하여 탐지 논리를 검증할 수 있습니다.

#### **의사 결정 트리의 주요 특성:**

-   **문제 유형:** 분류 및 회귀 모두. 공격과 정상 트래픽의 분류에 일반적으로 사용됩니다.

-   **해석 가능성:** 매우 높음 -- 모델의 결정은 if-then 규칙의 집합으로 시각화되고 이해될 수 있습니다. 이는 보안에서 모델 행동의 신뢰와 검증을 위한 주요 장점입니다.

-   **장점:** 비선형 관계와 특성 간의 상호작용을 포착할 수 있습니다(각 분할은 상호작용으로 볼 수 있습니다). 특성을 스케일링하거나 범주형 변수를 원-핫 인코딩할 필요가 없습니다 -- 트리는 이를 본래적으로 처리합니다. 빠른 추론(예측은 단순히 트리에서 경로를 따르는 것입니다).

-   **제한 사항:** 제어되지 않으면 과적합에 취약합니다(깊은 트리는 훈련 세트를 기억할 수 있습니다). 불안정할 수 있습니다 -- 데이터의 작은 변화가 다른 트리 구조로 이어질 수 있습니다. 단일 모델로서 그 정확도가 더 발전된 방법(랜덤 포레스트와 같은 앙상블)이 일반적으로 분산을 줄여 더 나은 성능을 보입니다.

-   **최고의 분할 찾기:**
- **지니 불순도**: 노드의 불순도를 측정합니다. 낮은 지니 불순도는 더 나은 분할을 나타냅니다. 공식은 다음과 같습니다:

```plaintext
Gini = 1 - Σ(p_i^2)
```

여기서 `p_i`는 클래스 `i`의 인스턴스 비율입니다.

- **엔트로피**: 데이터셋의 불확실성을 측정합니다. 낮은 엔트로피는 더 나은 분할을 나타냅니다. 공식은 다음과 같습니다:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

여기서 `p_i`는 클래스 `i`의 인스턴스 비율입니다.

- **정보 이득**: 분할 후 엔트로피 또는 지니 불순도의 감소입니다. 정보 이득이 높을수록 더 나은 분할입니다. 이는 다음과 같이 계산됩니다:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

또한, 트리는 다음과 같은 경우에 종료됩니다:
- 노드의 모든 인스턴스가 동일한 클래스에 속합니다. 이는 과적합으로 이어질 수 있습니다.
- 트리의 최대 깊이(하드코딩됨)에 도달했습니다. 이는 과적합을 방지하는 방법입니다.
- 노드의 인스턴스 수가 특정 임계값 이하입니다. 이것도 과적합을 방지하는 방법입니다.
- 추가 분할로 인한 정보 이득이 특정 임계값 이하입니다. 이것도 과적합을 방지하는 방법입니다.

<details>
<summary>예시 -- 침입 탐지를 위한 의사 결정 트리:</summary>
NSL-KDD 데이터셋에서 네트워크 연결을 *정상* 또는 *공격*으로 분류하기 위해 의사 결정 트리를 훈련시킬 것입니다. NSL-KDD는 프로토콜 유형, 서비스, 지속 시간, 실패한 로그인 수 등의 특성을 가진 고전적인 KDD Cup 1999 데이터셋의 개선된 버전이며, 공격 유형 또는 "정상"을 나타내는 레이블이 있습니다. 모든 공격 유형을 "이상" 클래스에 매핑할 것입니다(이진 분류: 정상 vs 이상). 훈련 후, 테스트 세트에서 트리의 성능을 평가할 것입니다.
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
이 결정 트리 예제에서는 극단적인 과적합을 피하기 위해 트리 깊이를 10으로 제한했습니다(`max_depth=10` 매개변수). 메트릭은 트리가 정상 트래픽과 공격 트래픽을 얼마나 잘 구분하는지를 보여줍니다. 높은 재현율은 대부분의 공격을 포착한다는 것을 의미하며(IDS에 중요), 높은 정밀도는 잘못된 경고가 적다는 것을 의미합니다. 결정 트리는 구조화된 데이터에서 괜찮은 정확도를 달성하는 경우가 많지만, 단일 트리는 최상의 성능에 도달하지 못할 수 있습니다. 그럼에도 불구하고 모델의 *해석 가능성*은 큰 장점입니다. 예를 들어, 트리의 분할을 검토하여 어떤 특성(예: `service`, `src_bytes` 등)이 연결을 악성으로 플래그하는 데 가장 영향을 미치는지 확인할 수 있습니다.

</details>

### 랜덤 포레스트

랜덤 포레스트는 성능을 개선하기 위해 결정 트리를 기반으로 하는 **앙상블 학습** 방법입니다. 랜덤 포레스트는 여러 개의 결정 트리를 훈련시키고(따라서 "포레스트") 이들의 출력을 결합하여 최종 예측을 만듭니다(분류의 경우 일반적으로 다수결에 의해). 랜덤 포레스트의 두 가지 주요 아이디어는 **배깅**(부트스트랩 집계)과 **특성 무작위성**입니다:

-   **배깅:** 각 트리는 훈련 데이터의 무작위 부트스트랩 샘플(교체 샘플링)을 기반으로 훈련됩니다. 이는 트리 간의 다양성을 도입합니다.

-   **특성 무작위성:** 트리의 각 분할에서 무작위 특성의 하위 집합이 분할을 위해 고려됩니다(모든 특성이 아닌). 이는 트리 간의 상관관계를 더욱 줄입니다.

많은 트리의 결과를 평균화함으로써 랜덤 포레스트는 단일 결정 트리가 가질 수 있는 분산을 줄입니다. 간단히 말해, 개별 트리는 과적합되거나 노이즈가 있을 수 있지만, 다양한 트리가 함께 투표하면 이러한 오류가 완화됩니다. 그 결과는 종종 **더 높은 정확도**와 단일 결정 트리보다 더 나은 일반화를 가진 모델입니다. 또한, 랜덤 포레스트는 각 특성이 평균적으로 불순도를 얼마나 줄이는지를 살펴봄으로써 특성 중요도의 추정치를 제공할 수 있습니다.

랜덤 포레스트는 침입 탐지, 악성 코드 분류 및 스팸 탐지와 같은 작업에서 **사이버 보안의 일꾼**이 되었습니다. 최소한의 조정으로 즉시 잘 작동하며 대규모 특성 집합을 처리할 수 있습니다. 예를 들어, 침입 탐지에서 랜덤 포레스트는 더 미세한 공격 패턴을 포착하여 잘못된 긍정이 적은 단일 결정 트리보다 더 나은 성능을 발휘할 수 있습니다. 연구에 따르면 랜덤 포레스트는 NSL-KDD 및 UNSW-NB15와 같은 데이터 세트에서 공격을 분류하는 데 있어 다른 알고리즘에 비해 유리한 성능을 보였습니다.

#### **랜덤 포레스트의 주요 특성:**

-   **문제 유형:** 주로 분류(회귀에도 사용됨). 보안 로그에서 일반적인 고차원 구조화된 데이터에 매우 적합합니다.

-   **해석 가능성:** 단일 결정 트리보다 낮습니다 -- 수백 개의 트리를 한 번에 쉽게 시각화하거나 설명할 수 없습니다. 그러나 특성 중요도 점수는 어떤 속성이 가장 영향을 미치는지에 대한 통찰력을 제공합니다.

-   **장점:** 일반적으로 앙상블 효과로 인해 단일 트리 모델보다 더 높은 정확도를 가집니다. 과적합에 강합니다 -- 개별 트리가 과적합되더라도 앙상블은 더 잘 일반화합니다. 숫자형 및 범주형 특성을 모두 처리할 수 있으며, 어느 정도 결측 데이터를 관리할 수 있습니다. 또한 이상치에 대해 상대적으로 강합니다.

-   **제한 사항:** 모델 크기가 클 수 있습니다(많은 트리, 각 트리는 잠재적으로 깊음). 예측 속도가 단일 트리보다 느립니다(많은 트리를 집계해야 하므로). 덜 해석 가능함 -- 중요한 특성을 알 수 있지만, 정확한 논리는 간단한 규칙으로 쉽게 추적할 수 없습니다. 데이터 세트가 매우 고차원이고 희소한 경우, 매우 큰 포레스트를 훈련하는 것은 계산적으로 무거울 수 있습니다.

-   **훈련 과정:**
1. **부트스트랩 샘플링:** 교체 샘플링을 통해 훈련 데이터를 무작위로 샘플링하여 여러 하위 집합(부트스트랩 샘플)을 만듭니다.
2. **트리 구성:** 각 부트스트랩 샘플에 대해 각 분할에서 무작위 특성의 하위 집합을 사용하여 결정 트리를 구축합니다. 이는 트리 간의 다양성을 도입합니다.
3. **집계:** 분류 작업의 경우, 최종 예측은 모든 트리의 예측 중 다수결을 통해 이루어집니다. 회귀 작업의 경우, 최종 예측은 모든 트리의 예측 평균입니다.

<details>
<summary>예제 -- 침입 탐지를 위한 랜덤 포레스트 (NSL-KDD):</summary>
우리는 동일한 NSL-KDD 데이터 세트(정상 대 이상으로 이진 레이블)를 사용하고 랜덤 포레스트 분류기를 훈련시킬 것입니다. 우리는 랜덤 포레스트가 단일 결정 트리보다 성능이 좋거나 같기를 기대합니다. 앙상블 평균화가 분산을 줄이기 때문입니다. 우리는 동일한 메트릭으로 평가할 것입니다.
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
랜덤 포레스트는 일반적으로 이 침입 탐지 작업에서 강력한 결과를 달성합니다. 우리는 단일 결정 트리에 비해 F1 또는 AUC와 같은 메트릭에서 개선을 관찰할 수 있으며, 이는 데이터에 따라 재현율 또는 정밀도에서 특히 두드러집니다. 이는 *"랜덤 포레스트(RF)는 앙상블 분류기이며 공격의 효과적인 분류를 위해 다른 전통적인 분류기와 비교하여 잘 작동한다."*는 이해와 일치합니다. 보안 운영 맥락에서 랜덤 포레스트 모델은 많은 결정 규칙의 평균화 덕분에 공격을 더 신뢰성 있게 플래그할 수 있으며, 잘못된 경고를 줄일 수 있습니다. 숲에서의 특성 중요성은 어떤 네트워크 특성이 공격을 가장 잘 나타내는지를 알려줄 수 있습니다(예: 특정 네트워크 서비스 또는 비정상적인 패킷 수).

</details>

### 서포트 벡터 머신 (SVM)

서포트 벡터 머신은 주로 분류(그리고 SVR로 회귀) 용도로 사용되는 강력한 감독 학습 모델입니다. SVM은 두 클래스 간의 마진을 최대화하는 **최적의 분리 초평면**을 찾으려고 합니다. 이 초평면의 위치는 경계에 가장 가까운 훈련 포인트의 하위 집합(“서포트 벡터”)에 의해 결정됩니다. 마진(서포트 벡터와 초평면 간의 거리)을 최대화함으로써 SVM은 좋은 일반화를 달성하는 경향이 있습니다.

SVM의 강력한 점은 비선형 관계를 처리하기 위해 **커널 함수**를 사용할 수 있는 능력입니다. 데이터는 선형 분리가 존재할 수 있는 더 높은 차원의 특성 공간으로 암묵적으로 변환될 수 있습니다. 일반적인 커널에는 다항식, 방사 기저 함수(RBF), 시그모이드가 포함됩니다. 예를 들어, 네트워크 트래픽 클래스가 원시 특성 공간에서 선형적으로 분리되지 않는 경우, RBF 커널은 이를 더 높은 차원으로 매핑하여 SVM이 선형 분할을 찾도록 합니다(이는 원래 공간에서 비선형 경계에 해당합니다). 커널을 선택하는 유연성 덕분에 SVM은 다양한 문제를 해결할 수 있습니다.

SVM은 고차원 특성 공간(예: 텍스트 데이터 또는 악성 코드 명령어 시퀀스)에서 잘 작동하며, 특성의 수가 샘플 수에 비해 클 때 효과적입니다. 2000년대에는 악성 코드 분류 및 이상 기반 침입 탐지와 같은 많은 초기 사이버 보안 응용 프로그램에서 인기가 있었으며, 종종 높은 정확도를 보였습니다.

그러나 SVM은 매우 큰 데이터 세트에 쉽게 확장되지 않습니다(훈련 복잡도는 샘플 수에 대해 초선형이며, 많은 서포트 벡터를 저장해야 할 수 있으므로 메모리 사용량이 높을 수 있습니다). 실제로 수백만 개의 레코드가 있는 네트워크 침입 탐지와 같은 작업에서는 신중한 하위 샘플링이나 근사 방법을 사용하지 않으면 SVM이 너무 느릴 수 있습니다.

#### **SVM의 주요 특성:**

-   **문제 유형:** 분류(이진 또는 다중 클래스, 일대일/일대다) 및 회귀 변형. 명확한 마진 분리가 있는 이진 분류에 자주 사용됩니다.

-   **해석 가능성:** 중간 -- SVM은 결정 트리나 로지스틱 회귀만큼 해석 가능하지 않습니다. 어떤 데이터 포인트가 서포트 벡터인지 식별할 수 있고, 선형 커널 경우의 가중치를 통해 어떤 특성이 영향을 미칠 수 있는지 감을 잡을 수 있지만, 실제로 SVM(특히 비선형 커널을 사용할 경우)은 블랙박스 분류기로 취급됩니다.

-   **장점:** 고차원 공간에서 효과적; 커널 트릭으로 복잡한 결정 경계를 모델링할 수 있음; 마진이 최대화되면 과적합에 강함(특히 적절한 정규화 매개변수 C가 있을 때); 클래스가 큰 거리에 의해 분리되지 않을 때도 잘 작동(최상의 타협 경계를 찾음).

-   **제한 사항:** **대규모 데이터 세트에 대해 계산 집약적**(훈련 및 예측 모두 데이터가 증가함에 따라 성능이 저하됨). 커널 및 정규화 매개변수(C, 커널 유형, RBF의 감마 등)를 신중하게 조정해야 함. 확률적 출력을 직접 제공하지 않음(하지만 Platt 스케일링을 사용하여 확률을 얻을 수 있음). 또한 SVM은 커널 매개변수 선택에 민감할 수 있으며, 잘못된 선택은 과소적합 또는 과적합으로 이어질 수 있습니다.

*사이버 보안에서의 사용 사례:* SVM은 **악성 코드 탐지**(예: 추출된 특성 또는 명령어 시퀀스를 기반으로 파일 분류), **네트워크 이상 탐지**(트래픽을 정상 대 악성으로 분류), **피싱 탐지**(URL의 특성을 사용) 등에 사용되었습니다. 예를 들어, SVM은 이메일의 특성(특정 키워드 수, 발신자 평판 점수 등)을 가져와 피싱 또는 합법적인 것으로 분류할 수 있습니다. 또한 KDD와 같은 특성 집합에서 **침입 탐지**에 적용되어 종종 높은 정확도를 달성하였으나 계산 비용이 발생했습니다.

<details>
<summary>예시 -- 악성 코드 분류를 위한 SVM:</summary>
이번에는 SVM을 사용하여 피싱 웹사이트 데이터 세트를 다시 사용할 것입니다. SVM이 느릴 수 있으므로 필요한 경우 훈련을 위해 데이터의 하위 집합을 사용할 것입니다(데이터 세트는 약 11,000개의 인스턴스이며, SVM이 적절히 처리할 수 있습니다). 비선형 데이터에 일반적으로 선택되는 RBF 커널을 사용할 것이며, ROC AUC를 계산하기 위해 확률 추정을 활성화할 것입니다.
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
SVM 모델은 동일한 작업에 대해 로지스틱 회귀와 비교할 수 있는 메트릭을 출력합니다. 데이터가 특성에 의해 잘 분리되어 있다면 SVM이 높은 정확도와 AUC를 달성할 수 있습니다. 반면, 데이터셋에 많은 노이즈나 겹치는 클래스가 있다면 SVM이 로지스틱 회귀보다 크게 우수하지 않을 수 있습니다. 실제로 SVM은 특성과 클래스 간에 복잡하고 비선형적인 관계가 있을 때 성능을 향상시킬 수 있습니다. RBF 커널은 로지스틱 회귀가 놓치는 곡선 결정 경계를 포착할 수 있습니다. 모든 모델과 마찬가지로, 편향과 분산의 균형을 맞추기 위해 `C`(정규화) 및 커널 매개변수(예: RBF의 `gamma`)를 신중하게 조정해야 합니다.

</details>

#### 로지스틱 회귀와 SVM의 차이

| 측면 | **로지스틱 회귀** | **서포트 벡터 머신** |
|---|---|---|
| **목적 함수** | **로그 손실**(교차 엔트로피)을 최소화합니다. | **힌지 손실**을 최소화하면서 **마진**을 최대화합니다. |
| **결정 경계** | _P(y\|x)_를 모델링하는 **최적의 초평면**을 찾습니다. | 가장 가까운 점과의 간격이 가장 큰 **최대 마진 초평면**을 찾습니다. |
| **출력** | **확률적** – σ(w·x + b)를 통해 보정된 클래스 확률을 제공합니다. | **결정적** – 클래스 레이블을 반환합니다; 확률은 추가 작업이 필요합니다(예: Platt 스케일링). |
| **정규화** | L2(기본값) 또는 L1, 과소/과대 적합을 직접적으로 균형 맞춥니다. | C 매개변수는 마진 너비와 잘못 분류 간의 균형을 맞추며, 커널 매개변수는 복잡성을 추가합니다. |
| **커널 / 비선형** | 기본 형태는 **선형**; 비선형성은 특성 엔지니어링으로 추가됩니다. | 내장된 **커널 트릭**(RBF, poly 등)을 통해 고차원 공간에서 복잡한 경계를 모델링할 수 있습니다. |
| **확장성** | **O(nd)**에서 볼록 최적화를 해결하며, 매우 큰 n을 잘 처리합니다. | 훈련은 전문 솔버 없이 **O(n²–n³)** 메모리/시간이 소요될 수 있으며, 큰 n에 덜 친숙합니다. |
| **해석 가능성** | **높음** – 가중치가 특성의 영향을 보여줍니다; 오즈 비율이 직관적입니다. | 비선형 커널의 경우 **낮음**; 서포트 벡터는 희소하지만 설명하기 쉽지 않습니다. |
| **이상치에 대한 민감도** | 부드러운 로그 손실을 사용하여 → 덜 민감합니다. | 하드 마진의 힌지 손실은 **민감할 수 있습니다**; 소프트 마진(C)은 이를 완화합니다. |
| **일반적인 사용 사례** | 신용 점수, 의료 위험, A/B 테스트 – **확률 및 설명 가능성**이 중요한 경우. | 이미지/텍스트 분류, 생물 정보학 – **복잡한 경계**와 **고차원 데이터**가 중요한 경우. |

* **보정된 확률, 해석 가능성이 필요하거나 대규모 데이터셋에서 작업해야 하는 경우 — 로지스틱 회귀를 선택하세요.**
* **수동 특성 엔지니어링 없이 비선형 관계를 포착할 수 있는 유연한 모델이 필요하다면 — SVM(커널 사용)을 선택하세요.**
* 두 모델 모두 볼록 목표를 최적화하므로 **전역 최소값이 보장되지만**, SVM의 커널은 하이퍼 매개변수와 계산 비용을 추가합니다.

### 나이브 베이즈

나이브 베이즈는 특성 간의 강한 독립성 가정을 적용하여 베이즈 정리를 기반으로 하는 **확률적 분류기**의 집합입니다. 이러한 "나이브" 가정에도 불구하고, 나이브 베이즈는 특히 스팸 탐지와 같은 텍스트 또는 범주형 데이터와 관련된 특정 응용 프로그램에서 놀랍도록 잘 작동합니다.

#### 베이즈 정리

베이즈 정리는 나이브 베이즈 분류기의 기초입니다. 이는 무작위 사건의 조건부 및 주변 확률을 연결합니다. 공식은:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)`는 특성 `B`가 주어졌을 때 클래스 `A`의 사후 확률입니다.
- `P(B|A)`는 클래스 `A`가 주어졌을 때 특성 `B`의 가능성입니다.
- `P(A)`는 클래스 `A`의 사전 확률입니다.
- `P(B)`는 특성 `B`의 사전 확률입니다.

예를 들어, 텍스트가 어린이 또는 성인에 의해 작성되었는지 분류하고자 할 때, 텍스트의 단어를 특성으로 사용할 수 있습니다. 초기 데이터를 기반으로 Naive Bayes 분류기는 각 단어가 각 잠재적 클래스(어린이 또는 성인)에 속할 확률을 미리 계산합니다. 새로운 텍스트가 주어지면, 텍스트의 단어를 기반으로 각 잠재적 클래스의 확률을 계산하고 가장 높은 확률을 가진 클래스를 선택합니다.

이 예에서 볼 수 있듯이, Naive Bayes 분류기는 매우 간단하고 빠르지만, 특성이 독립적이라고 가정하는데, 이는 실제 데이터에서는 항상 그렇지 않습니다.


#### Naive Bayes 분류기의 유형

데이터의 유형과 특성의 분포에 따라 여러 유형의 Naive Bayes 분류기가 있습니다:
- **Gaussian Naive Bayes**: 특성이 가우시안(정규) 분포를 따른다고 가정합니다. 연속 데이터에 적합합니다.
- **Multinomial Naive Bayes**: 특성이 다항 분포를 따른다고 가정합니다. 텍스트 분류에서 단어 수와 같은 이산 데이터에 적합합니다.
- **Bernoulli Naive Bayes**: 특성이 이진(0 또는 1)이라고 가정합니다. 텍스트 분류에서 단어의 존재 또는 부재와 같은 이진 데이터에 적합합니다.
- **Categorical Naive Bayes**: 특성이 범주형 변수라고 가정합니다. 색상과 모양에 따라 과일을 분류하는 것과 같은 범주형 데이터에 적합합니다.


#### **Naive Bayes의 주요 특징:**

-   **문제 유형:** 분류(이진 또는 다중 클래스). 사이버 보안에서 텍스트 분류 작업(스팸, 피싱 등)에 일반적으로 사용됩니다.

-   **해석 가능성:** 중간 -- 결정 트리만큼 직접적으로 해석할 수는 없지만, 학습된 확률(예: 스팸 이메일과 일반 이메일에서 가장 가능성이 높은 단어)을 검사할 수 있습니다. 필요할 경우 모델의 형태(클래스에 대한 각 특성의 확률)를 이해할 수 있습니다.

-   **장점:** **매우 빠른** 훈련 및 예측, 대규모 데이터셋에서도 (인스턴스 수 * 특성 수에 선형). 확률을 신뢰성 있게 추정하기 위해 상대적으로 적은 양의 데이터가 필요하며, 특히 적절한 스무딩이 있을 때 그렇습니다. 특성이 독립적으로 클래스에 증거를 기여할 때, 기준선으로서 놀라울 정도로 정확합니다. 고차원 데이터(예: 텍스트에서 수천 개의 특성)와 잘 작동합니다. 스무딩 매개변수를 설정하는 것 외에 복잡한 조정이 필요하지 않습니다.

-   **제한 사항:** 독립성 가정은 특성이 높은 상관관계를 가질 경우 정확도를 제한할 수 있습니다. 예를 들어, 네트워크 데이터에서 `src_bytes`와 `dst_bytes`와 같은 특성이 상관관계가 있을 수 있으며, Naive Bayes는 그 상호작용을 포착하지 못합니다. 데이터 크기가 매우 커지면, 특성 의존성을 학습하는 더 표현력이 뛰어난 모델(예: 앙상블 또는 신경망)이 Naive Bayes를 초월할 수 있습니다. 또한, 공격을 식별하는 데 특정 특성 조합이 필요한 경우(개별 특성이 독립적으로만 필요한 것이 아님), Naive Bayes는 어려움을 겪을 것입니다.

> [!TIP]
> *사이버 보안에서의 사용 사례:* 고전적인 사용은 **스팸 탐지**입니다 -- Naive Bayes는 초기 스팸 필터의 핵심으로, 특정 토큰(단어, 구문, IP 주소)의 빈도를 사용하여 이메일이 스팸일 확률을 계산했습니다. 또한 **피싱 이메일 탐지** 및 **URL 분류**에 사용되며, 특정 키워드나 특성(예: URL의 "login.php" 또는 URL 경로의 `@`)의 존재가 피싱 확률에 기여합니다. 악성 코드 분석에서는 특정 API 호출이나 소프트웨어의 권한의 존재를 사용하여 악성 코드인지 예측하는 Naive Bayes 분류기를 상상할 수 있습니다. 더 발전된 알고리즘이 종종 더 나은 성능을 보이지만, Naive Bayes는 속도와 단순성 덕분에 여전히 좋은 기준선으로 남아 있습니다.

<details>
<summary>예시 -- 피싱 탐지를 위한 Naive Bayes:</summary>
Naive Bayes를 시연하기 위해, NSL-KDD 침입 데이터셋(이진 레이블 포함)에서 Gaussian Naive Bayes를 사용할 것입니다. Gaussian NB는 각 특성이 클래스별로 정규 분포를 따른다고 가정합니다. 많은 네트워크 특성이 이산적이거나 매우 왜곡되어 있기 때문에 대략적인 선택이지만, 연속 특성 데이터에 Naive Bayes를 적용하는 방법을 보여줍니다. 이진 특성 집합(예: 트리거된 경고 세트)에서 Bernoulli NB를 선택할 수도 있지만, 연속성을 위해 여기서는 NSL-KDD를 고수하겠습니다.
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
이 코드는 공격을 탐지하기 위해 Naive Bayes 분류기를 훈련시킵니다. Naive Bayes는 훈련 데이터를 기반으로 `P(service=http | Attack)` 및 `P(Service=http | Normal)`과 같은 값을 계산하며, 특성 간의 독립성을 가정합니다. 그런 다음 이러한 확률을 사용하여 관찰된 특성에 따라 새로운 연결을 정상 또는 공격으로 분류합니다. NSL-KDD에서 NB의 성능은 더 고급 모델만큼 높지 않을 수 있지만(특성 독립성이 위배되기 때문에), 종종 괜찮고 극도의 속도의 이점을 제공합니다. 실시간 이메일 필터링이나 URL의 초기 분류와 같은 시나리오에서는 Naive Bayes 모델이 자원 사용이 적으면서 명백히 악의적인 사례를 빠르게 플래그할 수 있습니다.

</details>

### k-최근접 이웃 (k-NN)

k-최근접 이웃은 가장 간단한 머신 러닝 알고리즘 중 하나입니다. 이는 **비모수적, 인스턴스 기반** 방법으로, 훈련 세트의 예제와의 유사성을 기반으로 예측을 수행합니다. 분류를 위한 아이디어는: 새로운 데이터 포인트를 분류하기 위해 훈련 데이터에서 **k**개의 가장 가까운 포인트(즉, "가장 가까운 이웃")를 찾아 그 이웃들 중 다수의 클래스를 할당하는 것입니다. "가까움"은 거리 메트릭에 의해 정의되며, 일반적으로 숫자 데이터의 경우 유클리드 거리(다른 유형의 특성이나 문제에 대해 다른 거리를 사용할 수 있음)를 사용합니다.

K-NN은 *명시적인 훈련이 필요하지 않습니다* -- "훈련" 단계는 데이터셋을 저장하는 것뿐입니다. 모든 작업은 쿼리(예측) 중에 발생합니다: 알고리즘은 쿼리 포인트에서 모든 훈련 포인트까지의 거리를 계산하여 가장 가까운 포인트를 찾아야 합니다. 이로 인해 예측 시간은 **훈련 샘플 수에 선형적**이며, 이는 대규모 데이터셋에 대해 비용이 많이 들 수 있습니다. 따라서 k-NN은 더 작은 데이터셋이나 메모리와 속도를 단순함과 교환할 수 있는 시나리오에 가장 적합합니다.

단순함에도 불구하고 k-NN은 매우 복잡한 결정 경계를 모델링할 수 있습니다(사실상 결정 경계는 예제의 분포에 의해 결정되는 어떤 형태도 될 수 있습니다). 결정 경계가 매우 불규칙하고 데이터가 많을 때 잘 작동하는 경향이 있습니다 -- 본질적으로 데이터가 "스스로 말하게" 합니다. 그러나 고차원에서는 거리 메트릭이 덜 의미 있게 될 수 있으며(차원의 저주), 샘플 수가 많지 않으면 이 방법이 어려움을 겪을 수 있습니다.

*사이버 보안에서의 사용 사례:* k-NN은 이상 탐지에 적용되었습니다 -- 예를 들어, 침입 탐지 시스템은 대부분의 가장 가까운 이웃(이전 이벤트)이 악의적이었다면 네트워크 이벤트를 악의적이라고 레이블을 붙일 수 있습니다. 정상 트래픽이 클러스터를 형성하고 공격이 이상치인 경우, K-NN 접근 방식(k=1 또는 작은 k)은 본질적으로 **가장 가까운 이웃 이상 탐지**를 수행합니다. K-NN은 이진 특성 벡터를 통해 악성코드 패밀리를 분류하는 데에도 사용되었습니다: 새로운 파일이 특정 악성코드 패밀리의 알려진 인스턴스와 매우 가까운 경우 해당 악성코드 패밀리로 분류될 수 있습니다. 실제로 k-NN은 더 확장 가능한 알고리즘만큼 일반적이지 않지만, 개념적으로 간단하고 때때로 기준선 또는 소규모 문제에 사용됩니다.

#### **k-NN의 주요 특성:**

-   **문제 유형:** 분류(회귀 변형도 존재). 이는 *게으른 학습* 방법입니다 -- 명시적인 모델 적합이 없습니다.

-   **해석 가능성:** 낮음에서 중간 -- 전역 모델이나 간결한 설명이 없지만, 결정에 영향을 미친 가장 가까운 이웃을 살펴봄으로써 결과를 해석할 수 있습니다(예: "이 네트워크 흐름은 이 3개의 알려진 악의적 흐름과 유사하기 때문에 악의적으로 분류되었습니다"). 따라서 설명은 예제 기반이 될 수 있습니다.

-   **장점:** 구현 및 이해가 매우 간단합니다. 데이터 분포에 대한 가정을 하지 않습니다(비모수적). 다중 클래스 문제를 자연스럽게 처리할 수 있습니다. 결정 경계가 매우 복잡할 수 있다는 점에서 **적응적**입니다.

-   **제한 사항:** 대규모 데이터셋에 대해 예측이 느릴 수 있습니다(많은 거리를 계산해야 함). 메모리 집약적입니다 -- 모든 훈련 데이터를 저장합니다. 고차원 특성 공간에서는 성능이 저하됩니다. 모든 포인트가 거의 동등한 거리가 되기 때문에 "가장 가까운" 개념이 덜 의미 있게 됩니다. *k* (이웃의 수)를 적절히 선택해야 합니다 -- 너무 작은 k는 노이즈가 많고, 너무 큰 k는 다른 클래스의 관련 없는 포인트를 포함할 수 있습니다. 또한, 거리 계산이 스케일에 민감하기 때문에 특성은 적절히 스케일링되어야 합니다.

<details>
<summary>예제 -- 피싱 탐지를 위한 k-NN:</summary>

다시 NSL-KDD(이진 분류)를 사용할 것입니다. k-NN은 계산적으로 무겁기 때문에, 이 시연에서 다루기 쉽게 훈련 데이터의 하위 집합을 사용할 것입니다. 전체 125k에서 20,000개의 훈련 샘플을 선택하고 k=5 이웃을 사용할 것입니다. 훈련 후(사실상 데이터를 저장하는 것), 테스트 세트에서 평가할 것입니다. 거리 계산을 위해 특성을 스케일링하여 단일 특성이 스케일로 인해 지배하지 않도록 할 것입니다.
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
k-NN 모델은 훈련 세트의 5개 가장 가까운 연결을 살펴보아 연결을 분류합니다. 예를 들어, 그 이웃 중 4개가 공격(이상치)이고 1개가 정상인 경우, 새로운 연결은 공격으로 분류됩니다. 성능은 합리적일 수 있지만, 종종 동일한 데이터에서 잘 조정된 Random Forest나 SVM만큼 높지 않습니다. 그러나 k-NN은 클래스 분포가 매우 불규칙하고 복잡할 때 빛을 발할 수 있으며, 효과적으로 메모리 기반 조회를 사용합니다. 사이버 보안에서 k-NN( k=1 또는 작은 k)은 예를 들어 알려진 공격 패턴을 탐지하는 데 사용되거나 더 복잡한 시스템의 구성 요소로 사용될 수 있습니다(예: 클러스터링 후 클러스터 멤버십에 따라 분류).

### Gradient Boosting Machines (예: XGBoost)

Gradient Boosting Machines는 구조화된 데이터에 대해 가장 강력한 알고리즘 중 하나입니다. **Gradient boosting**은 약한 학습자(종종 결정 트리)의 앙상블을 순차적으로 구축하는 기술을 의미하며, 각 새로운 모델은 이전 앙상블의 오류를 수정합니다. 나무를 병렬로 구축하고 평균화하는 bagging(Random Forests)과 달리, boosting은 나무를 *하나씩* 구축하며, 각 나무는 이전 나무가 잘못 예측한 인스턴스에 더 집중합니다.

최근 몇 년 동안 가장 인기 있는 구현은 **XGBoost**, **LightGBM**, **CatBoost**로, 모두 gradient boosting decision tree (GBDT) 라이브러리입니다. 이들은 기계 학습 대회와 응용 프로그램에서 매우 성공적이었으며, 종종 **표 형식 데이터셋에서 최첨단 성능을 달성**합니다. 사이버 보안에서 연구자와 실무자는 **악성 코드 탐지**(파일 또는 런타임 동작에서 추출한 기능 사용) 및 **네트워크 침입 탐지**와 같은 작업에 gradient boosted trees를 사용했습니다. 예를 들어, gradient boosting 모델은 "많은 SYN 패킷과 비정상적인 포트 -> 스캔 가능성"과 같은 많은 약한 규칙(트리)을 결합하여 많은 미세한 패턴을 고려하는 강력한 복합 탐지기로 만들 수 있습니다.

부스트된 트리가 왜 이렇게 효과적일까요? 시퀀스의 각 트리는 현재 앙상블의 예측의 *잔여 오류* (기울기)에 대해 훈련됩니다. 이렇게 하면 모델이 약한 영역을 점진적으로 **"부스트"**합니다. 결정 트리를 기본 학습자로 사용하면 최종 모델이 복잡한 상호작용과 비선형 관계를 포착할 수 있습니다. 또한, boosting은 본질적으로 내장된 정규화 형태를 가지고 있습니다: 많은 작은 트리를 추가하고(기여도를 조정하기 위해 학습률을 사용하여) 일반적으로 적절한 매개변수가 선택되면 큰 과적합 없이 잘 일반화됩니다.

#### **Gradient Boosting의 주요 특성:**

-   **문제 유형:** 주로 분류 및 회귀. 보안에서는 일반적으로 분류(예: 연결 또는 파일을 이진 분류). 이진, 다중 클래스(적절한 손실을 사용) 및 순위 문제를 처리합니다.

-   **해석 가능성:** 낮음에서 중간. 단일 부스트된 트리는 작지만 전체 모델은 수백 개의 트리를 가질 수 있어 전체적으로 인간이 해석하기 어렵습니다. 그러나 Random Forest와 마찬가지로 기능 중요도 점수를 제공할 수 있으며, SHAP(SHapley Additive exPlanations)와 같은 도구를 사용하여 개별 예측을 어느 정도 해석할 수 있습니다.

-   **장점:** 구조화된/표 형식 데이터에 대해 종종 **최고 성능** 알고리즘입니다. 복잡한 패턴과 상호작용을 탐지할 수 있습니다. 모델 복잡성을 조정하고 과적합을 방지하기 위해 많은 조정 노브(트리 수, 트리 깊이, 학습률, 정규화 항)를 가지고 있습니다. 현대 구현은 속도를 최적화했습니다(예: XGBoost는 2차 기울기 정보와 효율적인 데이터 구조를 사용합니다). 적절한 손실 함수와 샘플 가중치를 조정하면 불균형 데이터를 더 잘 처리하는 경향이 있습니다.

-   **제한 사항:** 더 간단한 모델보다 조정이 복잡합니다; 트리가 깊거나 트리 수가 많으면 훈련이 느릴 수 있습니다(그러나 여전히 동일한 데이터에서 비교 가능한 깊은 신경망을 훈련하는 것보다 일반적으로 빠릅니다). 조정하지 않으면 모델이 과적합할 수 있습니다(예: 충분한 정규화 없이 너무 많은 깊은 트리). 많은 하이퍼파라미터로 인해 gradient boosting을 효과적으로 사용하려면 더 많은 전문 지식이나 실험이 필요할 수 있습니다. 또한, 트리 기반 방법과 마찬가지로 매우 희소한 고차원 데이터를 선형 모델이나 Naive Bayes만큼 효율적으로 처리하지 않습니다(그러나 여전히 적용할 수 있으며, 예를 들어 텍스트 분류에서 사용할 수 있지만 기능 엔지니어링 없이는 첫 번째 선택이 아닐 수 있습니다).

> [!TIP]
> *사이버 보안의 사용 사례:* 결정 트리나 랜덤 포레스트를 사용할 수 있는 거의 모든 곳에서 gradient boosting 모델이 더 나은 정확도를 달성할 수 있습니다. 예를 들어, **Microsoft의 악성 코드 탐지** 대회에서는 이진 파일에서 엔지니어링된 기능에 대해 XGBoost를 많이 사용했습니다. **네트워크 침입 탐지** 연구는 종종 GBDT에서 최고의 결과를 보고합니다(예: CIC-IDS2017 또는 UNSW-NB15 데이터셋에서 XGBoost). 이러한 모델은 다양한 기능(프로토콜 유형, 특정 이벤트의 빈도, 트래픽의 통계적 기능 등)을 수집하여 위협을 탐지할 수 있습니다. 피싱 탐지에서는 gradient boosting이 URL의 어휘적 기능, 도메인 평판 기능 및 페이지 콘텐츠 기능을 결합하여 매우 높은 정확도를 달성할 수 있습니다. 앙상블 접근 방식은 데이터의 많은 모서리 사례와 미세한 부분을 포괄하는 데 도움이 됩니다.

<details>
<summary>예시 -- 피싱 탐지를 위한 XGBoost:</summary>
피싱 데이터셋에서 gradient boosting 분류기를 사용할 것입니다. 간단하고 독립적으로 유지하기 위해 `sklearn.ensemble.GradientBoostingClassifier`(느리지만 간단한 구현)를 사용할 것입니다. 일반적으로 더 나은 성능과 추가 기능을 위해 `xgboost` 또는 `lightgbm` 라이브러리를 사용할 수 있습니다. 우리는 모델을 훈련하고 이전과 유사하게 평가할 것입니다.
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
그래디언트 부스팅 모델은 이 피싱 데이터셋에서 매우 높은 정확도와 AUC를 달성할 가능성이 높습니다(문헌에서 볼 수 있듯이, 이러한 데이터에서 적절한 조정을 통해 이러한 모델은 종종 95% 이상의 정확도를 초과할 수 있습니다. 이는 GBDT가 *"표 형 데이터셋에 대한 최첨단 모델"*로 간주되는 이유를 보여줍니다 -- 이들은 종종 복잡한 패턴을 포착하여 더 간단한 알고리즘보다 더 나은 성능을 발휘합니다. 사이버 보안 맥락에서 이는 더 적은 실수로 더 많은 피싱 사이트나 공격을 잡는 것을 의미할 수 있습니다. 물론, 과적합에 주의해야 합니다 -- 우리는 일반적으로 교차 검증과 같은 기술을 사용하고 배포를 위한 모델 개발 시 검증 세트에서 성능을 모니터링합니다.

</details>

### 모델 결합: 앙상블 학습 및 스태킹

앙상블 학습은 **여러 모델을 결합하여** 전체 성능을 향상시키는 전략입니다. 우리는 이미 특정 앙상블 방법을 보았습니다: 랜덤 포레스트(배깅을 통한 트리의 앙상블)와 그래디언트 부스팅(순차적 부스팅을 통한 트리의 앙상블). 그러나 앙상블은 **투표 앙상블**이나 **스택 일반화(스태킹)**와 같은 다른 방법으로도 생성될 수 있습니다. 주요 아이디어는 서로 다른 모델이 서로 다른 패턴을 포착하거나 서로 다른 약점을 가질 수 있다는 것입니다; 이를 결합함으로써 우리는 **각 모델의 오류를 다른 모델의 강점으로 보완할 수 있습니다**.

-   **투표 앙상블:** 간단한 투표 분류기에서는 여러 다양한 모델(예: 로지스틱 회귀, 결정 트리, SVM)을 훈련시키고 최종 예측에 대해 투표하게 합니다(분류를 위한 다수결 투표). 우리가 투표에 가중치를 부여한다면(예: 더 정확한 모델에 더 높은 가중치), 이는 가중 투표 방식입니다. 이는 개별 모델이 합리적으로 좋고 독립적일 때 성능을 개선하는 경향이 있습니다 -- 앙상블은 다른 모델이 이를 수정할 수 있기 때문에 개별 모델의 실수 위험을 줄입니다. 이는 단일 의견보다 전문가 패널을 갖는 것과 같습니다.

-   **스태킹(스택 앙상블):** 스태킹은 한 걸음 더 나아갑니다. 단순한 투표 대신, **메타 모델**을 훈련시켜 **기본 모델의 예측을 최적으로 결합하는 방법을 학습**합니다. 예를 들어, 3개의 서로 다른 분류기(기본 학습자)를 훈련시킨 후, 그들의 출력(또는 확률)을 메타 분류기(종종 로지스틱 회귀와 같은 간단한 모델)의 특징으로 사용하여 최적의 혼합 방법을 학습합니다. 메타 모델은 과적합을 피하기 위해 검증 세트에서 또는 교차 검증을 통해 훈련됩니다. 스태킹은 *어떤 모델을 어떤 상황에서 더 신뢰할지를 학습함으로써* 간단한 투표보다 종종 더 나은 성능을 발휘할 수 있습니다. 사이버 보안에서는 한 모델이 네트워크 스캔을 잡는 데 더 나은 반면, 다른 모델은 악성코드 비콘을 잡는 데 더 나을 수 있습니다; 스태킹 모델은 각 모델에 적절히 의존하는 방법을 학습할 수 있습니다.

투표든 스태킹이든 앙상블은 **정확도**와 강건성을 **향상시키는 경향이 있습니다**. 단점은 복잡성이 증가하고 때때로 해석 가능성이 감소한다는 것입니다(그러나 결정 트리의 평균과 같은 일부 앙상블 접근 방식은 여전히 일부 통찰력을 제공할 수 있습니다, 예: 특징 중요도). 실제로 운영 제약이 허용된다면, 앙상블을 사용하는 것이 더 높은 탐지율로 이어질 수 있습니다. 사이버 보안 챌린지(및 일반적으로 Kaggle 대회)에서 많은 우승 솔루션이 앙상블 기술을 사용하여 마지막 성능을 끌어내고 있습니다.

<details>
<summary>예시 -- 피싱 탐지를 위한 투표 앙상블:</summary>
모델 스태킹을 설명하기 위해, 피싱 데이터셋에서 논의한 몇 가지 모델을 결합해 보겠습니다. 로지스틱 회귀, 결정 트리 및 k-NN을 기본 학습자로 사용하고, 랜덤 포레스트를 메타 학습자로 사용하여 그들의 예측을 집계합니다. 메타 학습자는 기본 학습자의 출력(훈련 세트에서 교차 검증 사용)에 대해 훈련됩니다. 우리는 스택 모델이 개별 모델만큼 잘 수행하거나 약간 더 나은 성능을 보일 것으로 기대합니다.
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
스택 앙상블은 기본 모델의 상호 보완적인 강점을 활용합니다. 예를 들어, 로지스틱 회귀는 데이터의 선형적인 측면을 처리할 수 있고, 결정 트리는 특정 규칙과 같은 상호작용을 포착할 수 있으며, k-NN은 특성 공간의 지역 이웃에서 뛰어난 성능을 발휘할 수 있습니다. 메타 모델(여기서는 랜덤 포레스트)은 이러한 입력의 가중치를 학습할 수 있습니다. 결과적인 메트릭은 종종 단일 모델의 메트릭보다 개선된 결과(비록 약간일지라도)를 보여줍니다. 피싱 예제에서 로지스틱 회귀가 F1 점수 0.95, 결정 트리가 0.94를 기록했다면, 스택은 각 모델이 오류를 범하는 부분을 보완하여 0.96을 달성할 수 있습니다.

이러한 앙상블 방법은 *"여러 모델을 결합하는 것이 일반적으로 더 나은 일반화를 이끈다"*는 원리를 보여줍니다. 사이버 보안에서는 여러 탐지 엔진(하나는 규칙 기반, 하나는 머신 러닝, 하나는 이상 탐지 기반)을 두고, 그들의 경고를 집계하는 레이어를 추가하여 -- 사실상 앙상블의 한 형태 -- 더 높은 신뢰도로 최종 결정을 내릴 수 있습니다. 이러한 시스템을 배포할 때는 추가된 복잡성을 고려하고 앙상블이 관리하거나 설명하기 어려워지지 않도록 해야 합니다. 그러나 정확성 측면에서 앙상블과 스태킹은 모델 성능을 향상시키기 위한 강력한 도구입니다.

</details>


## References

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
