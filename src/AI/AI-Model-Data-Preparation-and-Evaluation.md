# Model Data Preparation & Evaluation

{{#include ../banners/hacktricks-training.md}}

Model data preparation は machine learning pipeline における重要なステップです。raw data を machine learning model の training に適した形式へ変換する作業が含まれるためです。このプロセスには、次の主要なステップがあります。

1. **Data Collection**: databases、APIs、files など、さまざまな source から data を収集します。data には structured data（例: tables）または unstructured data（例: text、images）があります。
2. **Data Cleaning**: 誤りのある、不完全な、または無関係な data point を削除または修正します。このステップでは、missing values の処理、duplicates の削除、outliers の filtering などを行います。
3. **Data Transformation**: data を modeling に適した形式へ変換します。normalization、scaling、categorical variables の encoding、feature engineering などの technique による新しい features の作成などが含まれます。
4. **Data Splitting**: dataset を training、validation、test sets に分割し、model が未知の data に対して適切に generalize できるようにします。

## Data Collection

Data collection では、以下のようなさまざまな source から data を収集します。
- **Databases**: relational databases（例: SQL databases）または NoSQL databases（例: MongoDB）から data を抽出します。
- **APIs**: real-time data または historical data を提供できる web APIs から data を取得します。
- **Files**: CSV、JSON、XML などの format の files から data を読み取ります。
- **Web Scraping**: web scraping techniques を使用して websites から data を収集します。

machine learning project の目的に応じて、problem domain を適切に代表する data となるよう、関連する source から data を抽出・収集します。

## Data Cleaning <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Data cleaning は、dataset 内の errors または inconsistencies を特定して修正するプロセスです。このステップは、machine learning models の training に使用する data の品質を確保するために不可欠です。Data cleaning における主な task は次のとおりです。
- **Handling Missing Values**: missing data points を特定して対処します。一般的な strategy には次のものがあります。
- missing values を含む rows または columns を削除する。
- mean、median、mode imputation などの techniques を使用して missing values を補完する。
- K-nearest neighbors (KNN) imputation や regression imputation などの高度な methods を使用する。
- **Removing Duplicates**: 各 data point が unique になるよう、duplicate records を特定して削除します。
- **Filtering Outliers**: model の performance に偏りを生じさせる可能性のある outliers を検出して削除します。Z-score、IQR (Interquartile Range)、または visualizations（例: box plots）などの techniques を使用して outliers を特定できます。

### Example of data cleaning
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
## データ変換 <sup>[[1]](#references)</sup>

データ変換とは、データをモデリングに適した形式に変換することです。このステップには以下が含まれます。
- **Normalization and standardization**: 数値特徴量を共通の範囲（通常は [0, 1] または [-1, 1]）にスケーリングします。これにより、最適化アルゴリズムの収束を改善できます。
- **Min-Max Scaling**: 特徴量を固定範囲（通常は [0, 1]）に再スケーリングします。次の式を使用します: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: 平均を引いて標準偏差で割ることで特徴量を標準化し、平均 0、標準偏差 1 の分布にします。次の式を使用します: `X' = (X - μ) / σ`。ここで μ は平均、σ は標準偏差です。
- **Skewness and kurtosis**: logarithm、square root、Box-Cox などの変換を使用して、特徴量の分布を調整します。たとえば、logarithmic transformation により正の歪みを軽減できます。
- **String Normalization**: 文字列を一貫した形式に変換します。例:
- 小文字化
- 特殊文字の削除（関連するものは保持）
- stop words の削除（"the"、"is"、"and" など、意味に寄与しない一般的な単語）
- 出現頻度が高すぎる単語と低すぎる単語の削除（例: ドキュメントの 90% 超に出現する単語、または corpus 内で 5 回未満しか出現しない単語）
- 空白のトリミング
- Stemming/Lemmatization: 単語を基本形または語根形に変換します（例: "running" を "run" に変換）。

- **Encoding Categorical Variables**: categorical variables を数値表現に変換します。一般的な手法には以下があります。
- **One-Hot Encoding**: 各カテゴリに対して binary column を作成します。
- たとえば、ある特徴量に "red"、"green"、"blue" というカテゴリがある場合、`is_red`(100)、`is_green`(010)、`is_blue`(001) という 3 つの binary column に変換されます。
- **Label Encoding**: 各カテゴリに一意の整数を割り当てます。
- たとえば、"red" = 0、"green" = 1、"blue" = 2 です。
- **Ordinal Encoding**: カテゴリの順序に基づいて整数を割り当てます。
- たとえば、カテゴリが "low"、"medium"、"high" の場合、それぞれ 0、1、2 として encode できます。
- **Hashing Encoding**: hash function を使用してカテゴリを固定サイズの vector に変換します。これは cardinality の高い categorical variables に有用です。
- たとえば、ある特徴量に多数の一意なカテゴリがある場合、hashing によってカテゴリに関する一部の情報を保持しながら次元数を削減できます。
- **Bag of Words (BoW)**: text data を word count または frequency の matrix として表現します。各行は document に対応し、各列は corpus 内の一意な単語に対応します。
- たとえば、corpus に "cat"、"dog"、"fish" という単語が含まれている場合、"cat" と "dog" を含む document は [1, 1, 0] として表現されます。この特定の表現は "unigram" と呼ばれ、単語の順序を取得しないため、semantic information が失われます。
- **Bigram/Trigram**: BoW を拡張して、単語の sequence（bigram または trigram）を取得し、ある程度の context を保持します。たとえば、"cat and dog" は、"cat and" に対する bigram [1, 1] と、"and dog" に対する [1, 1] として表現されます。この場合、より多くの semantic information が取得されます（表現の dimensionality が増加します）が、一度に対象となるのは 2 または 3 単語だけです。
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: document 内の単語の重要度を document collection（corpus）に対して評価する statistical measure です。term frequency（単語が document 内に出現する頻度）と inverse document frequency（すべての document における単語の希少性）を組み合わせます。
- たとえば、"cat" という単語がある document 内では頻繁に出現する一方、corpus 全体ではまれな場合、その document における重要性を示す高い TF-IDF score を持ちます。

- **Feature Engineering**: model の predictive power を高めるため、既存の特徴量から新しい特徴量を作成します。特徴量の組み合わせ、date/time component の抽出、または domain-specific transformation の適用などが含まれます。

## データ分割 <sup>[[3]](#references)</sup>

データ分割とは、dataset を training、validation、testing 用の個別の subset に分割することです。これは、未知のデータに対する model の performance を評価し、overfitting を防ぐために不可欠です。一般的な strategy には以下があります。
- **Train-Test Split**: dataset を training set（通常はデータの 60-80%）、hyperparameter の調整に使用する validation set（データの 10-15%）、および test set（データの 10-15%）に分割します。model は training set で train され、test set で評価されます。
- たとえば、1000 samples の dataset がある場合、training に 700 samples、validation に 150、testing に 150 を使用できます。
- **Stratified Sampling**: training set と test set における class の分布が、dataset 全体と同様になるようにします。これは、いくつかの class の sample 数が他より大幅に少ない imbalanced dataset で特に重要です。
- **Time Series Split**: time series data の場合、時間に基づいて dataset を分割し、training set にはより早い期間のデータを、test set にはより後の期間のデータを含めます。これにより、将来のデータに対する model の performance を評価できます。
- **K-Fold Cross-Validation**: dataset を K 個の subset（fold）に分割し、毎回異なる fold を test set として、残りの fold を training set として model を K 回 train します。これにより、異なる data subset で model が評価され、performance のより robust な推定値が得られます。

## Model Evaluation <sup>[[4]](#references)</sup>

Model evaluation は、未知のデータに対する machine learning model の performance を評価する process です。さまざまな metric を使用して、model が新しいデータにどの程度 generalize できるかを定量化します。一般的な evaluation metric には以下があります。

### Accuracy

Accuracy は、全 instance に対して正しく予測された instance の割合です。次のように計算されます:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Accuracy はシンプルで直感的な指標ですが、1つのクラスが他のクラスを大きく上回る imbalanced datasets には適さない場合があります。モデルの性能について誤解を招く印象を与える可能性があるためです。たとえば、データの90%がクラスAに属し、モデルがすべてのインスタンスをクラスAとして予測した場合、Accuracy は90%になりますが、クラスBの予測には役立ちません。

### Precision

Precision は、モデルが行ったすべての陽性予測のうち、真陽性予測が占める割合です。次のように計算されます。
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Precisionは、医療診断やfraud detectionなど、false positiveが高コストまたは望ましくないシナリオで特に重要です。たとえば、モデルが100件をpositiveと予測したものの、実際にpositiveだったのが80件だけの場合、Precisionは0.8（80%）になります。

### Recall（Sensitivity）

RecallはSensitivityまたはtrue positive rateとも呼ばれ、実際にpositiveであるすべてのインスタンスのうち、true positiveと予測された割合です。次の式で計算されます。
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> 偽陰性がコスト高または望ましくないシナリオ（疾病検出や spam filtering など）では、再現率が重要です。たとえば、モデルが実際の陽性インスタンス100件のうち80件を特定した場合、再現率は0.8（80%）になります。

### F1スコア

F1スコアは適合率と再現率の調和平均であり、2つの指標のバランスを提供します。次のように計算されます。
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1スコアは、false positiveとfalse negativeの両方を考慮するため、imbalanced datasetsを扱う際に特に有用です。precisionとrecallのトレードオフを捉える単一のmetricを提供します。たとえば、modelのprecisionが0.8、recallが0.6の場合、F1スコアは約0.69になります。

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

ROC-AUC metricは、さまざまなthreshold設定におけるtrue positive rate（sensitivity）をfalse positive rateに対してプロットすることで、classを識別するmodelの能力を評価します。ROC curveの下側の面積（AUC）はmodelのperformanceを定量化するもので、値が1の場合はperfect classification、0.5の場合はrandom guessingを示します。

> [!TIP]
> ROC-AUCはbinary classification problemsに特に有用で、異なるthresholdにおけるmodelのperformanceを包括的に把握できます。accuracyと比較して、class imbalanceの影響を受けにくいという特徴があります。たとえば、AUCが0.9のmodelは、positive instancesとnegative instancesを高い精度で識別できることを示します。

### Specificity

Specificityはtrue negative rateとも呼ばれ、実際にnegativeであるすべてのinstancesのうち、true negativeと予測された割合です。次のように計算されます。
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> 特異度は、医療検査や fraud detection など、false positive が高コストまたは望ましくないシナリオで重要です。モデルが negative instance をどの程度適切に識別できるかを評価するのに役立ちます。たとえば、モデルが実際の negative instance 100件のうち90件を正しく識別した場合、特異度は0.9（90%）になります。

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC) は、binary classification の品質を測定する指標です。true positive、false positive、true negative、false negative を考慮するため、モデルの性能をバランスよく評価できます。MCCは次のように計算されます：
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
ここで：
- **TP**: 真陽性（True Positives）
- **TN**: 真陰性（True Negatives）
- **FP**: 偽陽性（False Positives）
- **FN**: 偽陰性（False Negatives）

> [!TIP]
> MCCは-1から1の範囲を取り、1は完全な分類、0はランダムな推測、-1は予測と観測が完全に一致しないことを示します。混同行列の4つの構成要素すべてを考慮するため、不均衡データセットで特に有用です。

### 平均絶対誤差（MAE）
平均絶対誤差（MAE）は、予測値と実際の値の絶対差の平均を測定する回帰指標です。次のように計算されます：
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
where:
- **n**: インスタンス数
- **y_i**: インスタンス i の実測値
- **ŷ_i**: インスタンス i の予測値

> [!TIP]
> MAE は予測の平均誤差を直接的に解釈できるため、理解しやすい指標です。Mean Squared Error (MSE) などの他の指標と比較して、outlier の影響を受けにくいという特徴があります。たとえば、モデルの MAE が 5 の場合、平均してモデルの予測値は実測値から 5 単位ずれていることを意味します。

### 混同行列

混同行列は、True Positive、True Negative、False Positive、False Negative の予測数を示すことで、classification model の性能を要約する表です。各クラスに対してモデルがどの程度適切に機能しているかを詳細に確認できます。

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: モデルが positive class を正しく予測した。
- **True Negative (TN)**: モデルが negative class を正しく予測した。
- **False Positive (FP)**: モデルが誤って positive class と予測した（Type I error）。
- **False Negative (FN)**: モデルが誤って negative class と予測した（Type II error）。

混同行列は、accuracy、precision、recall、F1 score などの評価指標の計算に使用できます。

## References

- [1] [scikit-learn - データの前処理](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - 欠損値の補完](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation: estimator の性能評価](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metrics and scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
