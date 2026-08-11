# 모델 데이터 준비 및 평가

{{#include ../banners/hacktricks-training.md}}

모델 데이터 준비는 raw data를 machine learning pipeline에서 사용하는 데 적합한 형식으로 변환하는 과정이므로, machine learning pipeline에서 중요한 단계입니다. 이 과정에는 다음과 같은 몇 가지 주요 단계가 포함됩니다.

1. **데이터 수집**: 데이터베이스, API 또는 파일과 같은 다양한 소스에서 데이터를 수집합니다. 데이터는 structured data(예: 테이블) 또는 unstructured data(예: 텍스트, 이미지)일 수 있습니다.
2. **데이터 정리**: 오류가 있거나 불완전하거나 관련 없는 데이터 포인트를 제거하거나 수정합니다. 이 단계에는 missing values 처리, 중복 제거, outlier 필터링이 포함될 수 있습니다.
3. **데이터 변환**: 모델링에 적합한 형식으로 데이터를 변환합니다. 여기에는 normalization, scaling, categorical variables encoding, feature engineering과 같은 기법을 통한 새로운 feature 생성 등이 포함될 수 있습니다.
4. **데이터 분할**: 모델이 보지 못한 데이터에도 잘 generalize할 수 있도록 dataset을 training, validation, test set으로 나눕니다.

## 데이터 수집

데이터 수집은 다음과 같은 다양한 소스에서 데이터를 수집하는 과정입니다.
- **데이터베이스**: relational database(예: SQL database) 또는 NoSQL database(예: MongoDB)에서 데이터를 추출합니다.
- **API**: 실시간 또는 과거 데이터를 제공할 수 있는 web API에서 데이터를 가져옵니다.
- **파일**: CSV, JSON 또는 XML과 같은 형식의 파일에서 데이터를 읽습니다.
- **Web Scraping**: web scraping 기법을 사용하여 웹사이트에서 데이터를 수집합니다.

Machine learning 프로젝트의 목표에 따라 문제 domain을 대표할 수 있도록 관련 소스에서 데이터를 추출하고 수집합니다.

## 데이터 정리 <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

데이터 정리는 dataset의 오류 또는 불일치를 식별하고 수정하는 과정입니다. 이 단계는 machine learning model training에 사용되는 데이터의 품질을 보장하는 데 필수적입니다. 데이터 정리의 주요 작업은 다음과 같습니다.
- **Missing Values 처리**: 누락된 데이터 포인트를 식별하고 처리합니다. 일반적인 전략은 다음과 같습니다.
- 누락된 값이 있는 행 또는 열을 제거합니다.
- mean, median 또는 mode imputation과 같은 기법을 사용하여 누락된 값을 대체합니다.
- K-nearest neighbors (KNN) imputation 또는 regression imputation과 같은 고급 방법을 사용합니다.
- **중복 제거**: 각 데이터 포인트가 고유하도록 중복 record를 식별하고 제거합니다.
- **Outlier 필터링**: model 성능을 왜곡할 수 있는 outlier를 탐지하고 제거합니다. Z-score, IQR (Interquartile Range) 또는 visualization(예: box plot)과 같은 기법을 사용하여 outlier를 식별할 수 있습니다.

### 데이터 정리 예제
```python
import re

import numpy as np
import pandas as pd
from sklearn.impute import KNNImputer, SimpleImputer

# Load the dataset
df = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_positive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = df[~df['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
df = df.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
df['days'] = pd.to_numeric(df['days'], errors='coerce')

## For example, set "NaN" to not ips
def is_valid_ip(ip):
pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$')
if pd.isna(ip) or not pattern.match(str(ip)):
return np.nan
return ip
df['ip'] = df['ip'].apply(is_valid_ip)

# Filling missing values based on different strategies
numeric_cols = ["days", "hours", "minutes"]
categorical_cols = ["ip", "status"]

## Filling missing values in numeric columns with the median
num_imputer = SimpleImputer(strategy='median')
df[numeric_cols] = num_imputer.fit_transform(df[numeric_cols])

## Filling missing values in categorical columns with the most frequent value
cat_imputer = SimpleImputer(strategy='most_frequent')
df[categorical_cols] = cat_imputer.fit_transform(df[categorical_cols])

## Filling missing values in numeric columns using KNN imputation
knn_imputer = KNNImputer(n_neighbors=5)
df[numeric_cols] = knn_imputer.fit_transform(df[numeric_cols])



# Filling missing values
df.fillna(df.mean(numeric_only=True), inplace=True)

# Removing duplicates
df.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = np.abs(stats.zscore(df.select_dtypes(include=['float64', 'int64']), nan_policy='omit'))
df = df[(z_scores < 3).all(axis=1)]
```
## 데이터 변환 <sup>[[1]](#references)</sup>

데이터 변환은 데이터를 modeling에 적합한 형식으로 변환하는 과정입니다. 이 단계에는 다음이 포함될 수 있습니다.
- **정규화 및 표준화**: 수치형 feature를 일반적인 범위(일반적으로 [0, 1] 또는 [-1, 1])로 scaling합니다. 이를 통해 optimization algorithm의 수렴을 개선할 수 있습니다.
- **Min-Max Scaling**: feature를 고정된 범위(일반적으로 [0, 1])로 rescaling합니다. 다음 공식을 사용합니다: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: 평균을 빼고 표준편차로 나누어 feature를 표준화합니다. 그 결과 평균이 0이고 표준편차가 1인 분포가 됩니다. 다음 공식을 사용합니다: `X' = (X - μ) / σ`. 여기서 μ는 평균이고 σ는 표준편차입니다.
- **Skewness 및 kurtosis**: logarithm, square root 또는 Box-Cox와 같은 transformation을 사용하여 feature 분포를 조정합니다. 예를 들어 logarithmic transformation은 positive skew를 줄일 수 있습니다.
- **String Normalization**: 문자열을 다음과 같이 일관된 형식으로 변환합니다.
- 소문자로 변환
- 특수 문자 제거(관련 문자는 유지)
- stop words 제거(의미에 기여하지 않는 일반적인 단어로, "the", "is", "and" 등이 해당)
- 너무 자주 사용되는 단어와 너무 드물게 사용되는 단어 제거(예: 문서의 90% 이상에 나타나거나 corpus에서 5회 미만으로 나타나는 단어)
- whitespace 제거
- Stemming/Lemmatization: 단어를 기본형 또는 어근으로 축소합니다(예: "running"을 "run"으로 변환).

- **Categorical Variables Encoding**: categorical variable을 수치 표현으로 변환합니다. 일반적인 기법은 다음과 같습니다.
- **One-Hot Encoding**: 각 category에 대해 binary column을 생성합니다.
- 예를 들어 feature에 "red", "green", "blue" category가 있는 경우 다음 세 개의 binary column으로 변환됩니다: `is_red`(100), `is_green`(010), `is_blue`(001).
- **Label Encoding**: 각 category에 고유한 integer를 할당합니다.
- 예를 들어 "red" = 0, "green" = 1, "blue" = 2입니다.
- **Ordinal Encoding**: category의 순서에 따라 integer를 할당합니다.
- 예를 들어 category가 "low", "medium", "high"인 경우 각각 0, 1, 2로 encoding할 수 있습니다.
- **Hashing Encoding**: hash function을 사용하여 category를 고정 크기 vector로 변환합니다. 이는 cardinality가 높은 categorical variable에 유용할 수 있습니다.
- 예를 들어 feature에 고유 category가 많이 있는 경우 hashing을 사용하면 category에 대한 일부 정보를 보존하면서 차원을 줄일 수 있습니다.
- **Bag of Words (BoW)**: text data를 단어 count 또는 frequency의 matrix로 표현합니다. 각 row는 document에 해당하고 각 column은 corpus의 고유한 단어에 해당합니다.
- 예를 들어 corpus에 "cat", "dog", "fish"라는 단어가 있고 "cat"과 "dog"를 포함하는 document는 [1, 1, 0]으로 표현됩니다. 이 특정 표현을 "unigram"이라고 하며 단어의 순서를 반영하지 않으므로 semantic information을 잃습니다.
- **Bigram/Trigram**: BoW를 확장하여 단어 sequence(bigram 또는 trigram)를 포착하고 일부 context를 유지합니다. 예를 들어 "cat and dog"는 "cat and"에 대한 bigram [1, 1]과 "and dog"에 대한 [1, 1]로 표현됩니다. 이 경우 더 많은 semantic information을 수집할 수 있지만(표현의 dimensionality 증가), 한 번에 2개 또는 3개의 단어에 대해서만 가능합니다.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: document에서 단어의 중요도를 document collection(corpus)과 비교하여 평가하는 statistical measure입니다. term frequency(document에 단어가 얼마나 자주 나타나는지)와 inverse document frequency(모든 document에서 단어가 얼마나 드문지)를 결합합니다.
- 예를 들어 "cat"이라는 단어가 특정 document에 자주 나타나지만 전체 corpus에서는 드물다면 높은 TF-IDF score를 가지며, 이는 해당 document에서 단어가 중요하다는 것을 의미합니다.

- **Feature Engineering**: 기존 feature에서 새로운 feature를 생성하여 model의 predictive power를 향상합니다. feature 결합, date/time component 추출 또는 domain-specific transformation 적용 등이 포함될 수 있습니다.

## 데이터 분할 <sup>[[3]](#references)</sup>

데이터 분할은 dataset을 training, validation 및 testing을 위한 별도의 subset으로 나누는 과정입니다. 이는 보지 못한 데이터에 대한 model의 성능을 평가하고 overfitting을 방지하는 데 필수적입니다. 일반적인 전략은 다음과 같습니다.
- **Train-Test Split**: dataset을 training set(일반적으로 데이터의 60-80%), hyperparameter 조정을 위한 validation set(데이터의 10-15%), test set(데이터의 10-15%)으로 나눕니다. model은 training set으로 학습하고 test set으로 평가합니다.
- 예를 들어 1000개의 sample로 구성된 dataset이 있다면 training에 700개, validation에 150개, testing에 150개를 사용할 수 있습니다.
- **Stratified Sampling**: training set과 test set의 class 분포가 전체 dataset과 유사하도록 보장합니다. 일부 class의 sample 수가 다른 class보다 크게 적을 수 있는 imbalanced dataset에서 특히 중요합니다.
- **Time Series Split**: time series data의 경우 time을 기준으로 dataset을 분할하여 training set에는 더 이른 time period의 data가 포함되고 test set에는 더 늦은 period의 data가 포함되도록 합니다. 이를 통해 향후 data에 대한 model의 성능을 평가할 수 있습니다.
- **K-Fold Cross-Validation**: dataset을 K개의 subset(fold)으로 나누고 model을 K번 학습합니다. 매번 서로 다른 fold를 test set으로 사용하고 나머지 fold를 training set으로 사용합니다. 이를 통해 서로 다른 data subset에서 model을 평가하여 성능을 더욱 안정적으로 추정할 수 있습니다.

## Model Evaluation <sup>[[4]](#references)</sup>

Model evaluation은 보지 못한 data에서 machine learning model의 성능을 평가하는 과정입니다. 여기에는 model이 새로운 data에 얼마나 잘 일반화되는지를 정량화하기 위해 다양한 metric을 사용하는 과정이 포함됩니다. 일반적인 evaluation metric은 다음과 같습니다.

### Accuracy

Accuracy는 전체 instance 중 올바르게 예측된 instance의 비율입니다. 다음과 같이 계산합니다:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Accuracy는 단순하고 직관적인 metric이지만, 한 class가 다른 class보다 우세한 imbalanced dataset에는 적합하지 않을 수 있습니다. 모델 성능에 대해 오해를 불러일으킬 수 있기 때문입니다. 예를 들어 데이터의 90%가 class A에 속하고 모델이 모든 instance를 class A로 예측하면 90%의 Accuracy를 달성하지만, class B를 예측하는 데는 유용하지 않습니다.

### Precision

Precision은 모델이 수행한 모든 positive prediction 중 true positive prediction의 비율입니다. 다음과 같이 계산합니다:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Precision은 의료 진단이나 fraud detection처럼 false positive가 비용이 많이 들거나 바람직하지 않은 시나리오에서 특히 중요합니다. 예를 들어 모델이 100개의 인스턴스를 positive로 예측했지만 그중 실제로 positive인 인스턴스가 80개뿐이라면, precision은 0.8(80%)입니다.

### Recall (Sensitivity)

Recall은 sensitivity 또는 true positive rate라고도 하며, 모든 실제 positive 인스턴스 중 true positive로 예측된 비율입니다. 다음과 같이 계산합니다:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> false negative가 비용이 많이 들거나 바람직하지 않은 질병 탐지 또는 스팸 필터링과 같은 시나리오에서는 재현율이 중요합니다. 예를 들어 모델이 실제 양성 인스턴스 100개 중 80개를 식별하면 재현율은 0.8(80%)입니다.

### F1 점수

F1 점수는 precision과 recall의 조화 평균으로, 두 지표 간의 균형을 제공합니다. 다음과 같이 계산됩니다:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 score는 false positive와 false negative를 모두 고려하므로 불균형 데이터셋을 다룰 때 특히 유용합니다. 이는 precision과 recall 간의 trade-off를 포착하는 단일 metric을 제공합니다. 예를 들어 model의 precision이 0.8이고 recall이 0.6이면 F1 score는 약 0.69입니다.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

ROC-AUC metric은 다양한 threshold 설정에서 true positive rate (sensitivity)를 false positive rate에 대해 plotting하여 model이 class를 구분하는 능력을 평가합니다. ROC curve 아래 영역(AUC)은 model의 성능을 정량화하며, 값이 1이면 완벽한 classification을, 값이 0.5이면 무작위 guessing을 의미합니다.

> [!TIP]
> ROC-AUC는 binary classification 문제에 특히 유용하며, 다양한 threshold에서 model의 성능을 종합적으로 보여 줍니다. accuracy에 비해 class imbalance의 영향을 덜 받습니다. 예를 들어 AUC가 0.9인 model은 positive instance와 negative instance를 높은 수준으로 구분할 수 있음을 의미합니다.

### Specificity

Specificity는 true negative rate라고도 하며, 실제 모든 negative instance 중 true negative prediction의 비율입니다. 다음과 같이 계산합니다:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> 특이도는 medical testing이나 fraud detection처럼 false positive가 비용이 많이 들거나 바람직하지 않은 시나리오에서 중요합니다. 특이도는 모델이 negative instance를 얼마나 잘 식별하는지 평가하는 데 도움이 됩니다. 예를 들어 모델이 실제 negative instance 100개 중 90개를 정확히 식별한다면 특이도는 0.9(90%)입니다.

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC)는 binary classification의 품질을 측정하는 지표입니다. true positive와 false positive, true negative와 false negative를 모두 고려하여 모델 성능을 균형 있게 보여줍니다. MCC는 다음과 같이 계산됩니다:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
다음과 같습니다:
- **TP**: True Positives
- **TN**: True Negatives
- **FP**: False Positives
- **FN**: False Negatives

> [!TIP]
> MCC는 -1부터 1까지의 범위를 가지며, 1은 완벽한 분류, 0은 무작위 추측, -1은 예측과 관측 간의 완전한 불일치를 나타냅니다. MCC는 혼동 행렬의 네 가지 모든 구성 요소를 고려하므로 불균형 데이터셋에 특히 유용합니다.

### Mean Absolute Error (MAE)
Mean Absolute Error (MAE)는 예측값과 실제값 간의 절대 차이의 평균을 측정하는 regression metric입니다. 다음과 같이 계산됩니다:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
where:
- **n**: 인스턴스 수
- **y_i**: 인스턴스 i의 실제 값
- **ŷ_i**: 인스턴스 i의 예측 값

> [!TIP]
> MAE는 예측의 평균 오차를 직관적으로 해석할 수 있어 이해하기 쉽습니다. Mean Squared Error (MSE)와 같은 다른 metric보다 outlier의 영향을 덜 받습니다. 예를 들어 모델의 MAE가 5라면, 모델의 예측값이 실제 값에서 평균적으로 5단위만큼 벗어난다는 의미입니다.

### Confusion Matrix

Confusion matrix는 true positive, true negative, false positive, false negative 예측의 개수를 보여 주어 classification model의 성능을 요약하는 표입니다. 이를 통해 모델이 각 class에서 얼마나 잘 작동하는지 자세히 확인할 수 있습니다.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: 모델이 positive class를 올바르게 예측했습니다.
- **True Negative (TN)**: 모델이 negative class를 올바르게 예측했습니다.
- **False Positive (FP)**: 모델이 positive class로 잘못 예측했습니다(Type I error).
- **False Negative (FN)**: 모델이 negative class로 잘못 예측했습니다(Type II error).

Confusion matrix를 사용하면 accuracy, precision, recall, F1 score와 같은 evaluation metric을 계산할 수 있습니다.

## References

- [1] [scikit-learn - 데이터 전처리](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - 결측값 대체](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - 교차 검증: estimator 성능 평가](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - metric 및 scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
