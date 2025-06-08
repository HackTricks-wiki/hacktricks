# 模型数据准备与评估

{{#include ../banners/hacktricks-training.md}}

模型数据准备是机器学习流程中的关键步骤，因为它涉及将原始数据转换为适合训练机器学习模型的格式。此过程包括几个关键步骤：

1. **数据收集**：从各种来源收集数据，例如数据库、API或文件。数据可以是结构化的（例如，表格）或非结构化的（例如，文本、图像）。
2. **数据清理**：删除或更正错误、不完整或不相关的数据点。此步骤可能涉及处理缺失值、删除重复项和过滤异常值。
3. **数据转换**：将数据转换为适合建模的格式。这可能包括归一化、缩放、编码分类变量，以及通过特征工程等技术创建新特征。
4. **数据拆分**：将数据集划分为训练集、验证集和测试集，以确保模型能够很好地泛化到未见过的数据。

## 数据收集

数据收集涉及从各种来源收集数据，这些来源可以包括：
- **数据库**：从关系数据库（例如，SQL数据库）或NoSQL数据库（例如，MongoDB）提取数据。
- **API**：从网络API获取数据，这些API可以提供实时或历史数据。
- **文件**：从CSV、JSON或XML等格式的文件中读取数据。
- **网络爬虫**：使用网络爬虫技术从网站收集数据。

根据机器学习项目的目标，数据将从相关来源提取和收集，以确保其代表问题领域。

## 数据清理

数据清理是识别和更正数据集中错误或不一致的过程。此步骤对于确保用于训练机器学习模型的数据质量至关重要。数据清理中的关键任务包括：
- **处理缺失值**：识别和处理缺失的数据点。常见策略包括：
  - 删除缺失值的行或列。
  - 使用均值、中位数或众数插补缺失值。
  - 使用K近邻（KNN）插补或回归插补等高级方法。
- **删除重复项**：识别并删除重复记录，以确保每个数据点都是唯一的。
- **过滤异常值**：检测并删除可能影响模型性能的异常值。可以使用Z-score、IQR（四分位距）或可视化（例如，箱线图）等技术来识别异常值。

### 数据清理示例
```python
import pandas as pd
# Load the dataset
data = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_possitive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = data[~data['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
data = data.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
data['days'] = pd.to_numeric(data['days'], errors='coerce')

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
data.fillna(data.mean(), inplace=True)

# Removing duplicates
data.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = stats.zscore(data.select_dtypes(include=['float64', 'int64']))
data = data[(z_scores < 3).all(axis=1)]
```
## 数据转换

数据转换涉及将数据转换为适合建模的格式。此步骤可能包括：
- **归一化与标准化**：将数值特征缩放到一个共同范围，通常是 [0, 1] 或 [-1, 1]。这有助于提高优化算法的收敛性。
- **最小-最大缩放**：将特征重新缩放到固定范围，通常是 [0, 1]。使用公式： `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-分数标准化**：通过减去均值并除以标准差来标准化特征，结果是均值为 0，标准差为 1 的分布。使用公式： `X' = (X - μ) / σ`，其中 μ 是均值，σ 是标准差。
- **偏度和峰度**：调整特征的分布以减少偏度（不对称性）和峰度（尖峭度）。这可以通过对数、平方根或 Box-Cox 变换等变换来完成。例如，如果一个特征具有偏斜分布，应用对数变换可以帮助将其标准化。
- **字符串标准化**：将字符串转换为一致的格式，例如：
  - 小写
  - 移除特殊字符（保留相关字符）
  - 移除停用词（不对意义贡献的常见词，如 "the"、"is"、"and"）
  - 移除过于频繁和过于稀有的词（例如，出现在超过 90% 文档中的词或在语料库中出现少于 5 次的词）
  - 修剪空格
  - 词干提取/词形还原：将单词减少到其基本或根形式（例如，将 "running" 变为 "run"）。

- **编码分类变量**：将分类变量转换为数值表示。常见技术包括：
  - **独热编码**：为每个类别创建二进制列。
  - 例如，如果一个特征有类别 "red"、"green" 和 "blue"，它将被转换为三个二进制列： `is_red`(100)、`is_green`(010) 和 `is_blue`(001)。
  - **标签编码**：为每个类别分配一个唯一的整数。
  - 例如，"red" = 0，"green" = 1，"blue" = 2。
  - **序数编码**：根据类别的顺序分配整数。
  - 例如，如果类别是 "low"、"medium" 和 "high"，它们可以分别编码为 0、1 和 2。
  - **哈希编码**：使用哈希函数将类别转换为固定大小的向量，这对于高基数分类变量非常有用。
  - 例如，如果一个特征有许多独特的类别，哈希可以在保留一些类别信息的同时减少维度。
  - **词袋模型 (BoW)**：将文本数据表示为单词计数或频率的矩阵，其中每行对应一个文档，每列对应语料库中的一个唯一单词。
  - 例如，如果语料库包含单词 "cat"、"dog" 和 "fish"，包含 "cat" 和 "dog" 的文档将表示为 [1, 1, 0]。这种特定表示称为 "unigram"，并不捕捉单词的顺序，因此会丢失语义信息。
  - **二元组/三元组**：扩展 BoW 以捕捉单词序列（二元组或三元组）以保留一些上下文。例如，"cat and dog" 将表示为二元组 [1, 1] 对于 "cat and" 和 [1, 1] 对于 "and dog"。在这些情况下，收集了更多的语义信息（增加了表示的维度），但一次仅限于 2 或 3 个单词。
  - **TF-IDF（词频-逆文档频率）**：一种统计度量，评估一个词在文档中相对于文档集合（语料库）的重要性。它结合了词频（一个词在文档中出现的频率）和逆文档频率（一个词在所有文档中出现的稀有程度）。
  - 例如，如果单词 "cat" 在文档中频繁出现但在整个语料库中很少出现，它将具有高 TF-IDF 分数，表明其在该文档中的重要性。

- **特征工程**：从现有特征中创建新特征，以增强模型的预测能力。这可能涉及组合特征、提取日期/时间组件或应用特定领域的变换。

## 数据拆分

数据拆分涉及将数据集划分为训练、验证和测试的不同子集。这对于评估模型在未见数据上的表现和防止过拟合至关重要。常见策略包括：
- **训练-测试拆分**：将数据集划分为训练集（通常占数据的 60-80%）、验证集（占数据的 10-15% 用于调整超参数）和测试集（占数据的 10-15%）。模型在训练集上训练，并在测试集上评估。
- 例如，如果您有一个包含 1000 个样本的数据集，您可能会使用 700 个样本进行训练，150 个进行验证，150 个进行测试。
- **分层抽样**：确保训练集和测试集中的类别分布与整体数据集相似。这对于不平衡数据集尤其重要，其中某些类别的样本可能显著少于其他类别。
- **时间序列拆分**：对于时间序列数据，数据集根据时间进行拆分，确保训练集包含早期时间段的数据，测试集包含后期时间段的数据。这有助于评估模型在未来数据上的表现。
- **K-折交叉验证**：将数据集拆分为 K 个子集（折），并训练模型 K 次，每次使用不同的折作为测试集，其余折作为训练集。这有助于确保模型在不同的数据子集上进行评估，从而提供更稳健的性能估计。

## 模型评估

模型评估是评估机器学习模型在未见数据上表现的过程。它涉及使用各种指标来量化模型对新数据的泛化能力。常见的评估指标包括：

### 准确率

准确率是正确预测实例占总实例的比例。计算公式为：
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> 准确性是一个简单直观的指标，但对于一个类占主导地位的不平衡数据集，它可能不适用，因为它可能会给出模型性能的误导性印象。例如，如果90%的数据属于类A，而模型将所有实例预测为类A，它将达到90%的准确性，但对于预测类B并没有用处。

### Precision

Precision是模型所有正预测中真实正预测的比例。它的计算公式为：
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> 精确度在假阳性代价高昂或不受欢迎的场景中尤为重要，例如在医疗诊断或欺诈检测中。例如，如果一个模型预测100个实例为正，但其中只有80个实际上是正的，则精确度为0.8（80%）。

### 召回率（敏感性）

召回率，也称为敏感性或真正阳性率，是所有实际正实例中真正阳性预测的比例。它的计算公式为：
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> 召回率在假阴性代价高昂或不可取的场景中至关重要，例如在疾病检测或垃圾邮件过滤中。例如，如果一个模型识别出100个实际阳性实例中的80个，则召回率为0.8（80%）。

### F1 Score

F1分数是精确率和召回率的调和平均值，提供了两者之间的平衡。它的计算公式为：
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> F1 分数在处理不平衡数据集时特别有用，因为它考虑了假阳性和假阴性。它提供了一个单一的指标，捕捉精确度和召回率之间的权衡。例如，如果一个模型的精确度为 0.8，召回率为 0.6，则 F1 分数大约为 0.69。

### ROC-AUC (接收者操作特征 - 曲线下面积)

ROC-AUC 指标通过在不同阈值设置下绘制真实阳性率（灵敏度）与假阳性率之间的关系，评估模型区分类别的能力。ROC 曲线下面积（AUC）量化模型的性能，值为 1 表示完美分类，值为 0.5 表示随机猜测。

> [!TIP]
> ROC-AUC 对于二元分类问题特别有用，并提供了模型在不同阈值下性能的全面视图。与准确率相比，它对类别不平衡的敏感性较低。例如，AUC 为 0.9 的模型表明它在区分正负实例方面具有很高的能力。

### 特异性

特异性，也称为真阴性率，是所有实际负实例中真阴性预测的比例。它的计算公式为：
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> 特异性在假阳性代价高昂或不受欢迎的场景中很重要，例如在医学测试或欺诈检测中。它有助于评估模型识别负实例的能力。例如，如果一个模型正确识别了100个实际负实例中的90个，则特异性为0.9（90%）。

### Matthews Correlation Coefficient (MCC)
Matthews Correlation Coefficient (MCC) 是二元分类质量的衡量标准。它考虑了真正和假正、真负和假负，提供了模型性能的平衡视图。MCC的计算公式为：
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
where:
- **TP**: 真阳性
- **TN**: 真阴性
- **FP**: 假阳性
- **FN**: 假阴性

> [!TIP]
> MCC 的范围从 -1 到 1，其中 1 表示完美分类，0 表示随机猜测，-1 表示预测与观察之间的完全不一致。它对于不平衡数据集特别有用，因为它考虑了所有四个混淆矩阵组件。

### 平均绝对误差 (MAE)
平均绝对误差 (MAE) 是一种回归指标，测量预测值与实际值之间的平均绝对差。其计算公式为：
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
where:
- **n**: 实例数量
- **y_i**: 实例 i 的实际值
- **ŷ_i**: 实例 i 的预测值

> [!TIP]
> MAE 提供了对预测平均误差的直接解释，易于理解。与均方误差 (MSE) 等其他指标相比，它对异常值的敏感性较低。例如，如果一个模型的 MAE 为 5，这意味着模型的预测值与实际值的偏差平均为 5 个单位。

### 混淆矩阵

混淆矩阵是一个表格，通过显示真实正例、真实负例、假正例和假负例预测的计数来总结分类模型的性能。它提供了模型在每个类别上的表现的详细视图。

|               | 预测为正 | 预测为负 |
|---------------|-----------|-----------|
| 实际为正     | 真正例 (TP)  | 假负例 (FN)  |
| 实际为负     | 假正例 (FP) | 真负例 (TN)   |

- **真正例 (TP)**: 模型正确预测了正类。
- **真负例 (TN)**: 模型正确预测了负类。
- **假正例 (FP)**: 模型错误预测了正类（第一类错误）。
- **假负例 (FN)**: 模型错误预测了负类（第二类错误）。

混淆矩阵可用于计算各种评估指标，如准确率、精确率、召回率和 F1 分数。

{{#include ../banners/hacktricks-training.md}}
