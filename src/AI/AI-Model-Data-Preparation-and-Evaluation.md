# 模型数据准备与评估

{{#include ../banners/hacktricks-training.md}}

模型数据准备是 machine learning pipeline 中至关重要的一步，因为它涉及将原始数据转换为适合训练 machine learning models 的格式。此过程包括以下几个关键步骤：

1. **数据收集**：从各种来源收集数据，例如数据库、API 或文件。数据可以是结构化的（例如表格），也可以是非结构化的（例如文本、图像）。
2. **数据清洗**：删除或修正错误、不完整或无关的数据点。此步骤可能包括处理缺失值、删除重复项以及过滤异常值。
3. **数据转换**：将数据转换为适合建模的格式。这可能包括归一化、缩放、对分类变量进行编码，以及通过 feature engineering 等技术创建新特征。
4. **数据拆分**：将数据集划分为训练集、验证集和测试集，以确保模型能够很好地泛化到未见过的数据。

## 数据收集

数据收集涉及从各种来源获取数据，包括：
- **数据库**：从关系型数据库（例如 SQL databases）或 NoSQL databases（例如 MongoDB）中提取数据。
- **API**：从 web API 获取数据，这些 API 可以提供实时数据或历史数据。
- **文件**：读取 CSV、JSON 或 XML 等格式的文件中的数据。
- **Web Scraping**：使用 web scraping 技术从网站收集数据。

根据 machine learning 项目的目标，将从相关来源中提取和收集数据，以确保数据能够代表问题领域。

## 数据清洗 <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

数据清洗是识别和修正数据集中的错误或不一致的过程。此步骤对于确保用于训练 machine learning models 的数据质量至关重要。数据清洗中的关键任务包括：
- **处理缺失值**：识别并处理缺失的数据点。常见策略包括：
- 删除包含缺失值的行或列。
- 使用均值、中位数或众数插补等技术填充缺失值。
- 使用 K-nearest neighbors (KNN) 插补或回归插补等高级方法。
- **删除重复项**：识别并删除重复记录，以确保每个数据点都是唯一的。
- **过滤异常值**：检测并删除可能影响模型性能的异常值。可以使用 Z-score、IQR（Interquartile Range）或可视化方法（例如箱线图）来识别异常值。

### 数据清洗示例
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
## 数据转换 <sup>[[1]](#references)</sup>

数据转换涉及将数据转换为适合建模的格式。此步骤可能包括：
- **Normalization and standardization**：将数值特征缩放到共同范围，通常为 [0, 1] 或 [-1, 1]。这可以改善优化算法的收敛性。
- **Min-Max Scaling**：将特征重新缩放到固定范围，通常为 [0, 1]。使用以下公式：`X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**：通过减去均值并除以标准差来标准化特征，使其分布的均值为 0、标准差为 1。使用以下公式：`X' = (X - μ) / σ`，其中 μ 为均值，σ 为标准差。
- **偏度和峰度**：通过对数、平方根或 Box-Cox 等转换调整特征分布。例如，对数转换可以降低正偏度。
- **String Normalization**：将字符串转换为一致的格式，例如：
- 转换为小写
- 移除特殊字符（保留相关字符）
- 移除停用词（不影响含义的常见词语，例如 "the"、"is" 和 "and"）
- 移除出现频率过高和过低的词语（例如，在超过 90% 的文档中出现，或在语料库中出现次数少于 5 次的词语）
- 去除首尾空白
- 词干提取/词形还原：将词语还原为其基本形式或词根形式（例如，将 "running" 转换为 "run"）。

- **Encoding Categorical Variables**：将分类变量转换为数值表示。常见技术包括：
- **One-Hot Encoding**：为每个类别创建二进制列。
- 例如，如果某个特征包含 "red"、"green" 和 "blue" 三个类别，则会被转换为三个二进制列：`is_red`(100)、`is_green`(010) 和 `is_blue`(001)。
- **Label Encoding**：为每个类别分配唯一整数。
- 例如，"red" = 0、"green" = 1、"blue" = 2。
- **Ordinal Encoding**：根据类别的顺序分配整数。
- 例如，如果类别为 "low"、"medium" 和 "high"，则可以分别编码为 0、1 和 2。
- **Hashing Encoding**：使用哈希函数将类别转换为固定大小的向量，这对于高基数分类变量很有用。
- 例如，如果某个特征包含许多唯一类别，hashing 可以在保留部分类别信息的同时降低维度。
- **Bag of Words (BoW)**：将文本数据表示为词语计数或频率矩阵，其中每一行对应一个文档，每一列对应语料库中的一个唯一词语。
- 例如，如果语料库包含 "cat"、"dog" 和 "fish"，则包含 "cat" 和 "dog" 的文档会表示为 [1, 1, 0]。这种特定表示称为 "unigram"，它不捕获词语顺序，因此会丢失语义信息。
- **Bigram/Trigram**：扩展 BoW 以捕获词语序列（bigrams 或 trigrams），从而保留部分上下文。例如，"cat and dog" 会表示为 "cat and" 对应的 bigram [1, 1]，以及 "and dog" 对应的 [1, 1]。在这种情况下，收集到的语义信息更多（表示的维度也会增加），但每次只能处理 2 个或 3 个词语。
- **TF-IDF (Term Frequency-Inverse Document Frequency)**：一种评估词语在某个文档中相对于文档集合（语料库）重要性的统计度量。它结合了词频（词语在文档中出现的频率）和逆文档频率（词语在所有文档中的稀有程度）。
- 例如，如果词语 "cat" 在某个文档中频繁出现，但在整个语料库中很少见，则其 TF-IDF 分数会较高，表示该词语在该文档中的重要性较高。

- **Feature Engineering**：从现有特征创建新特征，以增强模型的预测能力。这可能包括组合特征、提取日期/时间组成部分，或应用特定领域的转换。

## 数据拆分 <sup>[[3]](#references)</sup>

数据拆分涉及将数据集划分为训练、验证和测试等独立子集。这对于评估模型在未见数据上的性能以及防止过拟合至关重要。常见策略包括：
- **Train-Test Split**：将数据集划分为训练集（通常占数据的 60-80%）、验证集（占数据的 10-15%，用于调整超参数）和测试集（占数据的 10-15%）。模型在训练集上训练，并在测试集上进行评估。
- 例如，如果拥有一个包含 1000 个样本的数据集，可以使用 700 个样本进行训练、150 个用于验证、150 个用于测试。
- **Stratified Sampling**：确保训练集和测试集中的类别分布与整个数据集相似。这对于不平衡数据集尤其重要，因为某些类别的样本数可能明显少于其他类别。
- **Time Series Split**：对于时间序列数据，根据时间拆分数据集，确保训练集包含较早时间段的数据，而测试集包含较晚时间段的数据。这有助于评估模型在未来数据上的性能。
- **K-Fold Cross-Validation**：将数据集拆分为 K 个子集（folds），并训练模型 K 次，每次使用不同的 fold 作为测试集，其余 folds 作为训练集。这有助于确保模型在不同数据子集上接受评估，从而更稳健地估计其性能。

## 模型评估 <sup>[[4]](#references)</sup>

模型评估是评估 machine learning 模型在未见数据上性能的过程。它涉及使用各种指标量化模型对新数据的泛化能力。常见评估指标包括：

### Accuracy

Accuracy 是正确预测的实例数占总实例数的比例。其计算方式为：
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> 准确率是一个简单直观的指标，但对于类别不平衡的数据集可能并不适用，因为其中一个类别占主导地位时，准确率可能会给出误导性的模型性能印象。例如，如果 90% 的数据属于类别 A，而模型将所有实例都预测为类别 A，那么它将达到 90% 的准确率，但对于预测类别 B 毫无帮助。

### 精确率

精确率是模型做出的所有正类预测中，真正类预测所占的比例。其计算方式为：
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> 在误报代价高昂或不希望出现误报的场景中，Precision 尤为重要，例如医疗诊断或欺诈检测。例如，如果模型将 100 个实例预测为正例，但其中只有 80 个实际上为正例，则 Precision 为 0.8（80%）。

### Recall（Sensitivity）

Recall，也称为 Sensitivity 或 true positive rate，是所有实际正例中被正确预测为正例的比例。其计算方式为：
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> 在疾病检测或垃圾邮件过滤等假阴性代价高昂或不理想的场景中，Recall 至关重要。例如，如果模型识别出 100 个实际阳性实例中的 80 个，则 Recall 为 0.8（80%）。

### F1 分数

F1 分数是 Precision 和 Recall 的调和平均值，用于平衡这两个指标。其计算方式为：
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 score 在处理不平衡数据集时特别有用，因为它同时考虑了 false positives 和 false negatives。它提供了一个能够反映 precision 与 recall 之间权衡的单一指标。例如，如果模型的 precision 为 0.8，recall 为 0.6，则 F1 score 约为 0.69。

### ROC-AUC（Receiver Operating Characteristic - Area Under the Curve）

ROC-AUC 指标通过在不同 threshold 设置下绘制 true positive rate（sensitivity）与 false positive rate，评估模型区分类别的能力。ROC 曲线下面积（AUC）量化了模型的性能，其中值为 1 表示完美分类，值为 0.5 表示随机猜测。

> [!TIP]
> ROC-AUC 对 binary classification 问题特别有用，并且能够全面展示模型在不同 threshold 下的性能。与 accuracy 相比，它受 class imbalance 的影响较小。例如，AUC 为 0.9 的模型表明其区分 positive 和 negative 实例的能力很强。

### Specificity

Specificity 也称为 true negative rate，表示在所有实际为 negative 的实例中，被正确预测为 negative 的比例。其计算方式为：
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> 在假阳性成本高或不希望出现假阳性的场景中，特异性非常重要，例如医学检测或欺诈检测。它有助于评估模型识别负实例的能力。例如，如果模型正确识别出 100 个实际负实例中的 90 个，则特异性为 0.9（90%）。

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC) 是衡量二分类质量的指标。它同时考虑真阳性、假阳性、真阴性和假阴性，从而平衡地反映模型的性能。MCC 的计算公式为：
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
其中：
- **TP**：真正例
- **TN**：真负例
- **FP**：假正例
- **FN**：假负例

> [!TIP]
> MCC 的取值范围为 -1 到 1，其中 1 表示完美分类，0 表示随机猜测，-1 表示预测结果与观测结果完全不一致。MCC 特别适用于不平衡数据集，因为它会考虑混淆矩阵的全部四个组成部分。

### 平均绝对误差（MAE）
平均绝对误差（MAE）是一种回归指标，用于衡量预测值与实际值之间绝对差值的平均值。其计算方式为：
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
其中：
- **n**：实例数量
- **y_i**：实例 i 的实际值
- **ŷ_i**：实例 i 的预测值

> [!TIP]
> MAE 直观地表示预测中的平均误差，因此易于理解。与 Mean Squared Error (MSE) 等其他指标相比，它对 outlier 的敏感度较低。例如，如果模型的 MAE 为 5，则表示模型的预测值与实际值平均相差 5 个单位。

### Confusion Matrix

混淆矩阵是一个通过显示 true positive、true negative、false positive 和 false negative 预测数量来总结 classification model 性能的表格。它详细展示了模型在每个类别上的表现。

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**：模型正确预测了 positive 类别。
- **True Negative (TN)**：模型正确预测了 negative 类别。
- **False Positive (FP)**：模型错误地预测了 positive 类别（Type I error）。
- **False Negative (FN)**：模型错误地预测了 negative 类别（Type II error）。

混淆矩阵可用于计算 accuracy、precision、recall 和 F1 score 等 evaluation metrics。

## References

- [1] [scikit-learn - 数据预处理](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - 缺失值填补](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-validation：评估 estimator 性能](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metrics and scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
