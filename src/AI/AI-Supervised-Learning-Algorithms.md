# 监督学习算法

{{#include ../banners/hacktricks-training.md}}

## 基本信息

监督学习使用带标签的数据训练模型，使其能够对新的、未见过的输入进行预测。在网络安全领域，监督机器学习广泛应用于入侵检测（将网络流量分类为*正常*或*攻击*）、malware 检测（区分恶意软件与良性软件）、phishing 检测（识别欺诈性网站或电子邮件）以及垃圾邮件过滤等任务。每种算法都有其优势，并适用于不同类型的问题（分类或回归）。下面我们将介绍主要的监督学习算法，解释其工作原理，并演示如何将其应用于真实的网络安全数据集。我们还将讨论组合多个模型（集成学习）通常如何提升预测性能。

## 算法

-   **线性回归（Linear Regression）：** 一种基础回归算法，通过将线性方程拟合到数据来预测数值结果。

-   **Logistic Regression：** 一种分类算法（尽管名称中包含回归），使用 logistic 函数对二元结果的概率进行建模。

-   **Decision Trees：** 基于树结构的模型，按照特征对数据进行划分以做出预测；通常因其可解释性而被使用。

-   **Random Forests：** 由多个决策树组成的集成模型（通过 bagging 实现），能够提升准确率并减少过拟合。

-   **Support Vector Machines (SVM)：** 最大间隔分类器，用于寻找最佳分离超平面；可以使用 kernel 处理非线性数据。

-   **Naive Bayes：** 基于 Bayes 定理的概率分类器，并假设特征之间相互独立，常用于垃圾邮件过滤。

-   **k-Nearest Neighbors (k-NN)：** 一种简单的“基于实例”的分类器，根据最近邻样本中的多数类别为样本分配标签。

-   **Gradient Boosting Machines：** 集成模型（例如 XGBoost、LightGBM），通过依次添加较弱的学习器（通常为决策树）来构建强大的预测器。

下面的每个章节都会对相应算法进行改进后的介绍，并提供使用 `pandas` 和 `scikit-learn` 等库的 **Python 代码示例**（神经网络示例使用 `PyTorch`）。示例使用公开可用的网络安全数据集（例如用于入侵检测的 NSL-KDD 和 Phishing Websites 数据集），并遵循一致的结构：

1.  **加载数据集**（如果有可用的 URL，则通过 URL 下载）。

2.  **预处理数据**（例如，对分类特征进行编码、缩放数值、划分训练集和测试集）。

3.  **在训练数据上训练模型**。

4.  **在测试集上进行评估**，使用以下指标：分类任务使用准确率、精确率、召回率、F1-score 和 ROC AUC（回归任务使用均方误差）。

下面让我们深入了解每种算法：

### 线性回归

线性回归是一种用于预测连续数值的**回归**算法。它假设输入特征（自变量）与输出（因变量）之间存在线性关系。该模型尝试拟合一条直线（在高维空间中则为超平面），以最佳描述特征与目标之间的关系。通常，这是通过最小化预测值与实际值之间的误差平方和来完成的（普通最小二乘法）。<sup>[[8]](#references)</sup>

表示线性回归最简单的形式是一条直线：
```plaintext
y = mx + b
```
其中：

- `y` 是预测值（输出）
- `m` 是直线的斜率（系数）
- `x` 是输入特征
- `b` 是 y 轴截距

线性回归的目标是找到一条最佳拟合直线，使预测值与数据集中的实际值之间的差异最小。当然，这非常简单，它会是一条分隔两个类别的直线；但如果增加更多维度，这条直线就会变得更加复杂：
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *在 cybersecurity 中的应用场景：* Linear regression 本身较少用于核心 security 任务（这些任务通常是 classification），但它可以用于预测数值结果。例如，可以根据历史数据使用 linear regression **预测网络流量的规模**或**估算某个时间段内的攻击次数**。在给定特定系统指标的情况下，它还可以预测风险评分或攻击被检测到前的预期时间。在实践中，classification algorithms（如 logistic regression 或 trees）更常用于检测入侵或 malware，但 linear regression 可作为基础，并且适用于面向 regression 的分析。

#### **Linear Regression 的关键特征：**

-   **问题类型：** Regression（预测连续值）。除非对输出应用阈值，否则不适合直接进行 classification。

-   **可解释性：** 高 -- 系数易于解释，可以展示每个特征的线性影响。

-   **优势：** 简单且快速；是 regression 任务的良好基线；当真实关系近似线性时效果良好。

-   **局限性：** 无法捕捉复杂或非线性关系（除非手动进行 feature engineering）；如果关系是非线性的，容易 underfitting；对 outliers 敏感，outliers 可能使结果发生偏移。

-   **寻找最佳拟合：** 要找到能够分隔可能类别的最佳拟合线，我们使用一种称为 **Ordinary Least Squares (OLS)** 的方法。该方法会最小化观测值与 linear model 预测值之间差异的平方和。

<details>
<summary>示例 -- 在入侵数据集中预测连接持续时间（Regression）
</summary>
下面我们演示如何使用 NSL-KDD cybersecurity dataset 进行 linear regression。我们将其作为一个 regression 问题，根据其他特征预测网络连接的 `duration`。（实际上，`duration` 是 NSL-KDD 的一个特征；这里只是用它来演示 regression。）我们加载 dataset，对其进行预处理（对 categorical features 进行编码），训练 linear regression model，并在 test set 上评估 Mean Squared Error (MSE) 和 R² score。
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
在此示例中，linear regression 模型尝试根据其他网络特征预测连接的 `duration`。我们使用 Mean Squared Error (MSE) 和 R² 衡量性能。接近 1.0 的 R² 表明模型解释了 `duration` 中的大部分方差，而较低或为负的 R² 表明拟合效果较差。（如果这里的 R² 较低，请不要感到意外——根据给定特征预测 `duration` 可能很困难，而且当模式较为复杂时，linear regression 可能无法捕获这些模式。）
</details>

### Logistic Regression

Logistic regression 是一种**分类**算法，用于对某个实例属于特定类别（通常是“正类”）的概率进行建模。尽管名称中包含 regression，*logistic* regression 用于离散结果（不同于用于连续结果的 linear regression）。它尤其适用于**二分类**（两个类别，例如恶意与良性），但也可以扩展到多分类问题（使用 softmax 或 one-vs-rest 方法）。<sup>[[1]](#references)</sup>

Logistic regression 使用 logistic function（也称为 sigmoid function）将预测值映射为概率。请注意，sigmoid function 的取值范围为 0 到 1，并根据分类需求沿 S 形曲线增长，这对二分类任务很有用。因此，每个输入的每个特征都会乘以其分配的权重，结果再通过 sigmoid function，以生成一个概率：
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
其中：

- `p(y=1|x)` 表示给定输入 `x` 时，输出 `y` 为 1 的概率
- `e` 是自然对数的底数
- `z` 是输入特征的线性组合，通常表示为 `z = w1*x1 + w2*x2 + ... + wn*xn + b`。注意，在最简单的形式中它仍是一条直线，但在更复杂的情况下，它会变成具有多个维度的超平面（每个特征对应一个维度）。

> [!TIP]
> *在 cybersecurity 中的使用场景：* 由于许多 security 问题本质上都是是/否决策，因此 logistic regression 得到了广泛使用。例如，intrusion detection system 可能会根据网络连接的特征，使用 logistic regression 判断该连接是否为攻击。在 phishing detection 中，logistic regression 可以将网站的各项特征（URL 长度、是否存在 "@" 符号等）组合成一个表示其为 phishing 的概率。它曾被用于早期的 spam filter，并且至今仍是许多 classification 任务中强大的基线模型。

#### Logistic Regression for non binary classification

Logistic regression 是为 binary classification 设计的，但可以使用 **one-vs-rest**（OvR）或 **softmax regression** 等技术扩展，以处理 multi-class 问题。在 OvR 中，会为每个 class 单独训练一个 logistic regression model，将该 class 视为 positive class，并将其他所有 class 视为其余类别。最终选择预测概率最高的 class。Softmax regression 通过对输出层应用 softmax function，将 logistic regression 扩展到多个 class，从而生成覆盖所有 class 的概率分布。

#### **Key characteristics of Logistic Regression:**

-   **Type of Problem:** Classification（通常为 binary）。它预测 positive class 的概率。

-   **Interpretability:** 高 —— 与 linear regression 类似，feature coefficients 可以表示每个 feature 如何影响结果的 log-odds。这种透明性在 security 中通常很受重视，因为它有助于理解哪些因素促成了 alert。

-   **Advantages:** 训练简单且速度快；当 features 与结果的 log-odds 之间为线性关系时，效果良好。它可以输出概率，从而支持 risk scoring。使用适当的 regularization 后，它具有良好的泛化能力，并且比普通的 linear regression 更能处理 multicollinearity。

-   **Limitations:** 假设 feature space 中的 decision boundary 是线性的（如果真实边界复杂或非线性，则会失效）。除非手动添加 polynomial 或 interaction features，否则在 interactions 或 non-linear effects 至关重要的问题上可能表现不佳。此外，如果 classes 无法通过 features 的线性组合轻易分离，logistic regression 的效果也会较弱。


<details>
<summary>Example -- Phishing Website Detection with Logistic Regression:</summary>

我们将使用一个 **Phishing Websites Dataset**（来自 UCI repository），其中包含从网站中提取的 features（例如 URL 是否包含 IP address、domain 的 age、HTML 中是否存在 suspicious elements 等），以及用于表示网站是 phishing 还是 legitimate 的 label。我们会训练一个 logistic regression model 对网站进行分类，然后在 test split 上评估其 accuracy、precision、recall、F1-score 和 ROC AUC。
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
在这个 phishing 检测示例中，logistic regression 会为每个网站生成其属于 phishing 的概率。通过评估 accuracy、precision、recall 和 F1，我们可以了解模型的性能。例如，较高的 recall 意味着它能够捕获大多数 phishing 网站（这对安全性很重要，因为可以尽量减少漏掉的攻击），而较高的 precision 意味着误报较少（这有助于避免分析人员疲劳）。ROC AUC（ROC 曲线下面积）提供了一种与阈值无关的性能衡量指标（1.0 为理想值，0.5 则表示性能不优于随机猜测）。Logistic regression 通常能够很好地完成此类任务，但如果 phishing 网站与合法网站之间的决策边界较为复杂，可能就需要功能更强的非线性模型。

</details>

### 决策树

决策树是一种通用的 **监督学习算法**，既可用于分类任务，也可用于回归任务。它会根据数据的特征学习一个分层的树状决策模型。树中的每个内部节点表示对某一特征进行测试，每条分支表示该测试的一种结果，而每个叶节点表示预测的类别（用于分类）或数值（用于回归）。<sup>[[2]](#references)</sup>

为了构建一棵树，CART（Classification and Regression Tree）等算法会使用 **Gini impurity** 或 **information gain (entropy)** 等指标，在每一步选择最佳特征和阈值来划分数据。每次划分的目标都是对数据进行分区，从而提高结果子集中的目标变量同质性（对于分类任务，每个节点都应尽可能纯，即主要包含单一类别）。

决策树具有 **高度可解释性** ——人们可以沿着从根节点到叶节点的路径，理解某个预测背后的逻辑（例如，*“IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack”*）。这对于 cybersecurity 非常有价值，因为它可以解释某个 alert 为什么会被触发。树能够自然地处理数值型和类别型数据，并且只需要很少的预处理（例如不需要进行特征缩放）。

然而，单棵决策树很容易对训练数据过拟合，尤其是在树的深度较大（包含许多划分）时。为了防止过拟合，通常会采用 pruning（限制树的深度，或要求每个叶节点至少包含一定数量的样本）等技术。

决策树主要包含 3 个组件：
- **根节点**：树的顶层节点，表示整个数据集。
- **内部节点**：表示特征以及基于这些特征所做决策的节点。
- **叶节点**：表示最终结果或预测的节点。

一棵树最终可能看起来如下：
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *在网络安全中的使用场景：* 决策树曾被用于入侵检测系统，以推导用于识别攻击的 **规则**。例如，早期基于 ID3/C4.5 的 IDS 会生成可读性强的规则，用于区分正常流量与恶意流量。它们也用于 malware analysis，根据文件的属性（文件大小、section entropy、API calls 等）判断文件是否为恶意文件。决策树的清晰性使其适用于需要透明度的场景 -- analyst 可以检查决策树，以验证 detection logic。

#### **决策树的关键特征：**

-   **问题类型：** classification 和 regression。通常用于将攻击与正常流量等进行 classification。

-   **可解释性：** 非常高 -- 模型的决策可以可视化，并理解为一组 if-then 规则。这是安全领域中的主要优势，有助于建立对模型行为的信任并进行验证。

-   **优点：** 可以捕获 features 之间的非线性关系和交互（每次 split 都可以视为一种交互）。无需对 features 进行缩放，也无需对 categorical variables 进行 one-hot encode -- trees 可以原生处理这些变量。inference 速度快（prediction 只需沿着 tree 中的一条路径进行）。

-   **局限性：** 如果不加以控制，容易 overfitting（较深的 tree 可能会记住 training set）。它们可能不稳定 -- data 的微小变化可能导致不同的 tree structure。作为 single models，其 accuracy 可能无法匹敌更先进的方法（Random Forests 等 ensembles 通常通过降低 variance 来取得更好的表现）。

-   **寻找最佳 Split：**
- **Gini Impurity**：衡量 node 的 impurity。较低的 Gini impurity 表示更好的 split。公式如下：

```plaintext
Gini = 1 - Σ(p_i^2)
```

其中，`p_i` 是 class `i` 中实例所占的比例。

- **Entropy**：衡量 dataset 中的不确定性。较低的 entropy 表示更好的 split。公式如下：

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

其中，`p_i` 是 class `i` 中实例所占的比例。

- **Information Gain**：split 后 entropy 或 Gini impurity 的减少量。information gain 越高，split 越好。其计算方式如下：

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

此外，在以下情况下，tree 会结束：
- node 中的所有实例都属于同一个 class。这可能导致 overfitting。
- tree 达到最大深度（hardcoded）。这是防止 overfitting 的一种方式。
- node 中的实例数量低于某个阈值。这也是防止 overfitting 的一种方式。
- 进一步 split 所带来的 information gain 低于某个阈值。这同样是防止 overfitting 的一种方式。

<details>
<summary>示例 -- 用于入侵检测的决策树：</summary>
我们将在 NSL-KDD dataset 上训练一个决策树，将 network connections classification 为 *normal* 或 *attack*。NSL-KDD 是经典 KDD Cup 1999 dataset 的改进版本，其 features 包括 protocol type、service、duration、failed logins 数量等，并带有用于表示 attack type 或 "normal" 的 label。我们会将所有 attack types 映射到 "anomaly" class（二分类：normal 与 anomaly）。训练完成后，我们将在 test set 上评估该 tree 的 performance。
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
在这个决策树示例中，我们将树的深度限制为 10，以避免严重的过拟合（`max_depth=10` 参数）。这些指标展示了该树区分正常流量与攻击流量的能力。较高的召回率意味着能够捕获大多数攻击（这对于 IDS 很重要），而较高的精确率意味着误报较少。决策树通常能够在结构化数据上取得不错的准确率，但单棵树可能无法达到最佳性能。尽管如此，该模型的*可解释性*是一大优势——我们可以检查树的分裂情况，从而了解哪些特征（例如 `service`、`src_bytes` 等）在将连接标记为恶意方面最具影响力。

</details>

### Random Forests

Random Forest 是一种**集成学习**方法，它在决策树的基础上进一步提升性能。Random Forest 会训练多棵决策树（因此称为“森林”），并结合它们的输出以生成最终预测结果（对于分类任务，通常采用多数投票）。Random Forest 主要包含两个核心思想：**bagging**（bootstrap aggregating）和**特征随机性**：

-   **Bagging：** 每棵树都使用训练数据的随机 bootstrap 样本进行训练（有放回采样）。这会在各棵树之间引入多样性。

-   **特征随机性：** 在树的每次分裂时，只考虑随机选取的特征子集进行分裂（而不是使用全部特征）。这会进一步降低各棵树之间的相关性。

通过对大量树的结果进行平均，Random Forest 可以降低单棵决策树可能产生的方差。简单来说，单棵树可能会过拟合或产生噪声，但大量具有差异性的树共同投票，可以平滑这些错误。其结果通常是一个比单棵决策树具有**更高准确率**和更好泛化能力的模型。此外，Random Forest 还可以提供特征重要性估计（通过观察每个特征分裂平均降低不纯度的程度）。

Random Forest 已成为**网络安全领域的主力工具**，可用于 intrusion detection、malware classification 和 spam detection 等任务。它们通常无需大量调参即可取得良好表现，并且能够处理大规模特征集。例如，在 intrusion detection 中，Random Forest 可能比单棵决策树更出色，因为它能够以更少的误报捕获更细微的攻击模式。研究表明，在 NSL-KDD 和 UNSW-NB15 等数据集中对攻击进行分类时，Random Forest 的表现优于其他算法。<sup>[[3]](#references)[[9]](#references)</sup>

#### **Random Forests 的主要特征：**

-   **问题类型：** 主要用于分类（也可用于回归）。非常适合安全日志中常见的高维结构化数据。

-   **可解释性：** 低于单棵决策树——你无法轻易同时可视化或解释数百棵树。不过，特征重要性分数可以帮助了解哪些属性最具影响力。

-   **优势：** 由于集成效应，准确率通常高于单树模型。能够有效抵抗过拟合——即使单棵树发生过拟合，集成模型通常也能更好地泛化。可以处理数值型和类别型特征，并且在一定程度上能够处理缺失数据。同时，它对离群值也相对稳健。

-   **局限性：** 模型规模可能很大（包含许多树，且每棵树都可能很深）。预测速度比单棵树慢（因为必须汇总多棵树的结果）。可解释性较低——虽然你可以知道哪些特征很重要，但其具体逻辑不像简单规则那样容易追踪。如果数据集极高维且稀疏，训练一个非常大的森林可能会带来较高的计算开销。

-   **训练过程：**
1. **Bootstrap Sampling**：对训练数据进行有放回的随机采样，以创建多个子集（bootstrap 样本）。
2. **Tree Construction**：针对每个 bootstrap 样本，在每次分裂时使用随机特征子集构建一棵决策树。这会在各棵树之间引入多样性。
3. **Aggregation**：对于分类任务，最终预测结果通过对所有树的预测结果进行多数投票得出。对于回归任务，最终预测结果是所有树预测结果的平均值。

<details>
<summary>示例 -- Random Forest 用于 intrusion detection（NSL-KDD）：</summary>
我们将使用相同的 NSL-KDD 数据集（以 normal 和 anomaly 进行二元标记），并训练一个 Random Forest 分类器。由于集成平均能够降低方差，我们预计 Random Forest 的表现至少会与单棵决策树相当，或优于单棵决策树。我们将使用相同的指标对其进行评估。
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
随机森林通常能在这一入侵检测任务中取得较好的结果。与单棵决策树相比，我们可能会观察到 F1 或 AUC 等指标有所提升，尤其是在召回率或精确率方面，具体取决于数据情况。这与以下认识一致：*"Random Forest (RF) 是一种 ensemble classifier，与其他传统分类器相比，它能够更有效地对攻击进行分类。"*. 在 security operations 场景中，得益于对大量决策规则进行平均，random forest 模型可能更可靠地标记攻击，同时减少误报。通过 forest 得到的 feature importance 可以告诉我们哪些网络特征最能表明存在攻击（例如某些网络服务或异常的数据包计数）。

</details>

### Support Vector Machines (SVM)

Support Vector Machines 是功能强大的 supervised learning 模型，主要用于分类（也可通过 SVR 用于回归）。SVM 尝试找到能够最大化两个类别之间间隔的**最优分隔超平面**。只有部分训练点（最接近边界的“support vectors”）决定该超平面的位置。通过最大化间隔（support vectors 与超平面之间的距离），SVM 通常能够实现良好的泛化能力。<sup>[[4]](#references)</sup>

SVM 强大能力的关键在于使用 **kernel functions** 处理非线性关系。数据可以被隐式转换到更高维的 feature space，在其中可能存在一个线性分隔器。常见的 kernel 包括 polynomial、radial basis function (RBF) 和 sigmoid。例如，如果网络流量类别在原始 feature space 中无法线性分离，RBF kernel 可以将它们映射到更高维空间，使 SVM 找到一个线性分割（这对应于原始空间中的非线性边界）。选择不同 kernel 的灵活性使 SVM 能够应对多种问题。

SVM 在高维 feature space（例如文本数据或 malware opcode 序列）以及 feature 数量相对于样本数量较多的情况下通常表现良好。2000 年代，SVM 曾广泛用于许多早期的 cybersecurity 应用，例如 malware 分类和基于异常的入侵检测，并且经常取得较高的准确率。

然而，SVM 不容易扩展到非常大的数据集（其训练复杂度相对于样本数量呈超线性增长，并且内存占用可能较高，因为它可能需要存储大量 support vectors）。在实践中，对于包含数百万条记录的网络入侵检测任务，如果不进行谨慎的子采样或使用近似方法，SVM 可能速度过慢。

#### **SVM 的关键特征：**

-   **问题类型：**分类（二分类或通过 one-vs-one/one-vs-rest 实现的多分类）以及回归变体。通常用于具有清晰间隔分离的二分类任务。

-   **可解释性：**中等 -- SVM 的可解释性不如决策树或 logistic regression。虽然你可以识别哪些数据点是 support vectors，并通过 linear kernel 情况下的权重大致了解哪些 feature 可能具有影响，但在实践中，SVM（尤其是使用非线性 kernel 时）通常被视为 black-box classifier。

-   **优势：**在高维空间中有效；通过 kernel trick 建模复杂的决策边界；如果间隔最大化，则能够抵抗 overfitting（尤其是在正确设置 regularization 参数 C 时）；即使类别之间没有较大的距离，也能良好工作（找到最佳折中边界）。

-   **局限性：**对于大型数据集而言，**计算开销较高**（随着数据增长，训练和预测的扩展性都较差）。需要谨慎调整 kernel 和 regularization 参数（C、kernel 类型、RBF 的 gamma 等）。它不会直接提供概率输出（但可以使用 Platt scaling 获取概率）。此外，SVM 可能对 kernel 参数的选择较为敏感 --- 不恰当的选择可能导致 underfit 或 overfit。

*在 cybersecurity 中的使用场景：*SVM 已被用于 **malware detection**（例如根据提取的 feature 或 opcode 序列对文件进行分类）、**network anomaly detection**（将流量分类为正常或恶意）以及 **phishing detection**（使用 URL 的 feature）。例如，SVM 可以获取一封 email 的 feature（某些关键词的计数、发件人信誉分数等），并将其分类为 phishing 或 legitimate。SVM 也被应用于基于 KDD 等 feature set 的**入侵检测**，通常能够取得较高的准确率，但代价是较高的计算开销。

<details>
<summary>示例 -- 使用 SVM 进行 Malware 分类：</summary>
我们将再次使用 phishing website 数据集，这次使用 SVM。由于 SVM 可能速度较慢，如果需要，我们将使用数据子集进行训练（该数据集约包含 11k 个实例，SVM 可以较为合理地处理）。我们将使用 RBF kernel，这是处理非线性数据时的常见选择，并启用 probability estimates 以计算 ROC AUC。
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
SVM 模型将输出指标，我们可以将其与同一任务上的 logistic regression 进行比较。如果数据的特征能够很好地区分类别，我们可能会发现 SVM 能取得较高的 accuracy 和 AUC。反过来，如果数据集包含大量噪声或类别相互重叠，SVM 可能不会显著优于 logistic regression。在实践中，当特征与类别之间存在复杂的非线性关系时，SVM 可以带来提升——RBF kernel 能够捕捉 logistic regression 无法识别的曲线决策边界。与所有模型一样，需要仔细调整 `C`（regularization）和 kernel 参数（例如 RBF 的 `gamma`），以平衡 bias 和 variance。

</details>

#### Logistic Rergessions 与 SVM 的区别

| 方面 | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **目标函数** | 最小化 **log-loss**（交叉熵）。 | 在最小化 **hinge-loss** 的同时最大化 **margin**。 |
| **决策边界** | 寻找能够建模 _P(y\|x)_ 的**最佳拟合超平面**。 | 寻找**最大 margin 超平面**（与最近数据点之间间隔最大的超平面）。 |
| **输出** | **概率型**——通过 σ(w·x + b) 输出经过校准的类别概率。 | **确定性**——返回类别标签；如需概率则需要额外处理（例如 Platt scaling）。 |
| **正则化** | L2（默认）或 L1，直接平衡 under-fitting 和 over-fitting。 | C 参数在 margin 宽度与误分类之间进行权衡；kernel 参数会增加复杂度。 |
| **Kernels / 非线性** | 原生形式是**线性的**；可通过 feature engineering 添加非线性。 | 内置 **kernel trick**（RBF、poly 等），能够在高维空间中建模复杂边界。 |
| **可扩展性** | 在 **O(nd)** 中求解凸优化；能够良好处理非常大的 n。 | 如果没有专用 solver，训练的内存/时间复杂度可能达到 **O(n²–n³)**；不适合超大规模 n。 |
| **可解释性** | **高**——权重展示 feature 的影响；odds ratio 直观易懂。 | 对于非线性 kernel 而言**较低**；support vectors 虽然稀疏，但不易解释。 |
| **对异常值的敏感性** | 使用平滑的 log-loss，因此敏感性较低。 | 使用 hinge-loss 的 hard margin 可能**较为敏感**；soft-margin（C）可以缓解这一问题。 |
| **典型使用场景** | 信用评分、医疗风险、A/B 测试——这些场景重视**概率和可解释性**。 | 图像/文本分类、生物信息学——这些场景重视**复杂边界**和**高维数据**。 |

* **如果你需要经过校准的概率、可解释性，或需要处理超大规模数据集——选择 Logistic Regression。**
* **如果你需要能够捕捉非线性关系且无需手动进行 feature engineering 的灵活模型——选择 SVM（使用 kernels）。**
* 两者都优化凸目标函数，因此**可以保证取得全局最小值**；但 SVM 的 kernels 会增加 hyper-parameters 和计算成本。

### Naive Bayes

Naive Bayes 是一类**概率分类器**，基于应用 Bayes 定理，并对 features 之间作出强独立性假设。尽管这一假设看似“naive”，Naive Bayes 在某些应用中通常表现得出人意料地好，尤其适用于文本或 categorical data，例如 spam detection。<sup>[[5]](#references)</sup>


#### Bayes 定理

Bayes 定理是 Naive Bayes classifiers 的基础。它描述了随机事件的条件概率与边际概率之间的关系。公式如下：
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
其中：
- `P(A|B)` 表示给定特征 `B` 时类别 `A` 的后验概率。
- `P(B|A)` 表示给定类别 `A` 时特征 `B` 的似然。
- `P(A)` 表示类别 `A` 的先验概率。
- `P(B)` 表示特征 `B` 的先验概率。

例如，如果我们想判断一段文本是由儿童还是成年人编写的，就可以使用文本中的单词作为特征。基于一些初始数据，Naive Bayes 分类器会预先计算每个单词属于各个潜在类别（儿童或成年人）的概率。当输入一段新文本时，它会根据文本中的单词计算每个潜在类别的概率，并选择概率最高的类别。

如本例所示，Naive Bayes 分类器非常简单且速度很快，但它假设各个特征彼此独立，而现实世界的数据并不总是如此。


#### Naive Bayes 分类器的类型

根据数据类型和特征的分布，Naive Bayes 分类器有多种类型：
- **Gaussian Naive Bayes**：假设特征服从 Gaussian（正态）分布。适用于连续数据。
- **Multinomial Naive Bayes**：假设特征服从 multinomial 分布。适用于离散数据，例如文本分类中的单词计数。
- **Bernoulli Naive Bayes**：假设特征为二进制值（0 或 1）。适用于二进制数据，例如文本分类中单词是否出现。
- **Categorical Naive Bayes**：假设特征是 categorical 变量。适用于分类数据，例如根据水果的颜色和形状对水果进行分类。


#### **Naive Bayes 的关键特征：**

-   **问题类型：**分类（二分类或多分类）。常用于 cybersecurity 中的文本分类任务（spam、phishing 等）。

-   **可解释性：**中等 -- 它不像 decision tree 那样可以直接解释，但可以检查学习到的概率（例如，哪些单词最有可能出现在 spam 与 ham 邮件中）。如果需要，模型的形式（每个特征在各类别下的概率）是可以理解的。

-   **优点：**训练和预测速度**非常快**，即使面对大型数据集也是如此（复杂度与实例数 * 特征数呈线性关系）。只需相对少量的数据即可可靠地估计概率，尤其是在正确使用 smoothing 的情况下。它通常是非常出色的 baseline，尤其是在各特征独立地为类别提供证据时。它适用于高维数据（例如从文本中提取的数千个特征）。除了设置 smoothing 参数外，通常不需要复杂的调优。

-   **限制：**如果特征高度相关，独立性假设可能会限制准确率。例如，在 network data 中，`src_bytes` 和 `dst_bytes` 等特征可能存在相关性；Naive Bayes 无法捕获这种交互关系。随着数据规模变得非常庞大，更具表达能力的模型（例如 ensembles 或 neural nets）可以通过学习特征依赖关系超越 NB。此外，如果识别某个 attack 需要特征的特定组合（而不是各个特征独立地发挥作用），NB 将难以应对。

> [!TIP]
> *在 cybersecurity 中的使用场景：*经典用途是 **spam detection** -- Naive Bayes 曾是早期 spam filter 的核心，通过使用特定 token（单词、短语、IP 地址）的出现频率来计算一封邮件属于 spam 的概率。它也用于 **phishing email detection** 和 **URL classification**，其中某些关键词或特征的存在（例如 URL 中的 "login.php"，或 URL path 中的 `@`）会影响 phishing 概率。在 malware analysis 中，可以设想使用 Naive Bayes 分类器，根据软件中是否存在某些 API call 或 permission 来预测其是否为 malware。尽管更高级的算法通常表现更好，但 Naive Bayes 凭借其速度和简洁性，仍然是一个很好的 baseline。

<details>
<summary>示例 -- 用 Naive Bayes 进行 Phishing Detection：</summary>
为了演示 Naive Bayes，我们将在 NSL-KDD intrusion dataset（带有二进制 labels）上使用 Gaussian Naive Bayes。Gaussian NB 会将每个特征视为在每个类别下均服从正态分布。由于许多 network features 是离散的或高度偏斜的，这种选择比较粗略，但它展示了如何将 NB 应用于连续特征数据。我们也可以在二进制特征数据集（例如一组 triggered alerts）上选择 Bernoulli NB，但为了保持连续性，这里仍使用 NSL-KDD。
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
这段代码训练了一个 Naive Bayes 分类器来检测攻击。Naive Bayes 将根据训练数据计算诸如 `P(service=http | Attack)` 和 `P(Service=http | Normal)` 这样的概率，并假设各个特征之间相互独立。随后，它会根据观察到的特征，使用这些概率将新连接分类为正常或攻击。NB 在 NSL-KDD 上的性能可能不如更先进的模型（因为特征独立性假设并不成立），但通常表现尚可，并且具有极高的速度优势。在实时电子邮件过滤或 URL 初步筛查等场景中，Naive Bayes 模型可以以较低的资源消耗快速标记明显的恶意案例。

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors 是最简单的机器学习算法之一。它是一种**非参数、基于实例**的方法，根据与训练集样本的相似度进行预测。其分类思想是：要对一个新的数据点进行分类，先找出训练数据中距离最近的 **k** 个点（即它的“近邻”），然后将这些近邻中的多数类别分配给该数据点。“接近程度”由距离度量定义，通常对数值数据使用欧氏距离（对于不同类型的特征或问题，也可以使用其他距离）。<sup>[[10]](#references)</sup>

K-NN **不需要显式训练**——“训练”阶段只是存储数据集。所有工作都发生在查询（预测）期间：算法必须计算查询点与所有训练点之间的距离，以找出最近的点。因此，其预测时间**与训练样本数量呈线性关系**，对于大型数据集而言可能代价高昂。由于这一点，k-NN 更适合较小的数据集，或适合那些可以用内存和速度换取简洁性的场景。

尽管 k-NN 很简单，但它可以构建非常复杂的决策边界（因为实际上，决策边界可以是由样本分布决定的任意形状）。当决策边界非常不规则且拥有大量数据时，它往往表现良好——本质上是让数据“自行表达”。然而，在高维空间中，距离度量可能变得不那么有意义（维度灾难），除非拥有海量样本，否则该方法可能难以取得良好效果。

*网络安全中的使用场景：* k-NN 已被应用于异常检测——例如，如果一个网络事件的大多数近邻（之前的事件）都是恶意的，入侵检测系统可能会将该网络事件标记为恶意。如果正常流量形成若干簇，而攻击属于离群点，那么 K-NN 方法（使用 k=1 或较小的 k）实际上就构成了**近邻异常检测**。K-NN 也被用于通过二进制特征向量对恶意软件家族进行分类：如果一个新文件在特征空间中与某个恶意软件家族的已知实例非常接近，则可能会被分类到该家族中。在实践中，k-NN 不如更具可扩展性的算法常见，但它在概念上直观易懂，有时会被用作基线，或用于小规模问题。

#### **k-NN 的主要特征：**

-   **问题类型：** 分类（也存在回归变体）。它是一种*惰性学习*方法——不进行显式的模型拟合。

-   **可解释性：** 低到中等——它没有全局模型或简洁的解释，但可以通过查看影响决策的近邻来解释结果（例如：“该网络流被分类为恶意，是因为它与这 3 个已知的恶意网络流相似。”）。因此，其解释可以基于示例。

-   **优势：** 实现和理解都非常简单。不对数据分布作任何假设（非参数）。能够自然地处理多分类问题。从某种意义上说，它具有**自适应性**，因为决策边界可以非常复杂，并由数据分布塑造。

-   **局限性：** 对大型数据集而言，预测可能较慢（必须计算大量距离）。占用内存较多——它会存储全部训练数据。在高维特征空间中，性能会下降，因为所有点往往变得几乎等距（使“最近”的概念变得不那么有意义）。需要适当选择 *k*（近邻数量）——k 过小可能导致噪声较多，k 过大则可能包含来自其他类别的不相关点。此外，特征应进行适当缩放，因为距离计算对尺度非常敏感。

<details>
<summary>示例 -- 用于 Phishing Detection 的 k-NN：</summary>

我们将再次使用 NSL-KDD（二分类）。由于 k-NN 的计算开销较大，在本演示中我们将使用训练数据的一个子集，以确保计算规模可控。我们将从完整的 125k 个样本中选取大约 20,000 个训练样本，并使用 k=5 个近邻。训练之后（实际上只是存储数据），我们将在测试集上进行评估。我们还会对特征进行缩放，以便计算距离，确保不会因为尺度差异而使某个特征占据主导地位。
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
k-NN 模型会查看训练集子集中距离最近的 5 个连接，并据此对一个连接进行分类。例如，如果这 5 个邻居中有 4 个是攻击（anomalies），而 1 个是正常连接，则新连接会被分类为攻击。其性能可能还不错，但通常不如在相同数据上经过良好调优的 Random Forest 或 SVM。不过，当类别分布非常不规则且复杂时，k-NN 有时会表现出色——实际上相当于使用基于记忆的查找。在网络安全中，k-NN（k=1 或较小的 k）可用于通过示例检测已知攻击模式，或作为更复杂系统的组件（例如，先进行聚类，再根据簇成员关系进行分类）。
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines 是结构化数据中最强大的算法之一。**Gradient boosting** 是一种构建弱学习器集成的方法（通常使用决策树）：按顺序构建模型，每个新模型都会修正前一个集成模型的错误。与并行构建树并对其结果取平均的 bagging（Random Forest）不同，boosting 会逐棵构建决策树，每棵树都会更加关注之前的树错误预测的样本。

近年来最流行的实现包括 **XGBoost**、**LightGBM** 和 **CatBoost**，它们都是 gradient boosting decision tree（GBDT）库。这些库在机器学习竞赛和实际应用中都取得了极大成功，并且经常**在表格数据集上达到 state-of-the-art 性能**。在网络安全领域，研究人员和从业者已将 gradient boosted trees 用于 **malware detection**（使用从文件或运行时行为中提取的特征）和**网络入侵检测**等任务。例如，一个 gradient boosting 模型可以将许多弱规则（决策树）组合成一个强大的综合检测器，例如“如果 SYN 数据包数量很多且端口异常 -> 可能是扫描”，从而综合考虑许多细微模式。<sup>[[6]](#references)</sup>

为什么 boosted trees 如此有效？序列中的每棵树都会根据当前集成模型预测产生的*残差错误*（梯度）进行训练。这样，模型就能逐步**增强**其薄弱的区域。使用决策树作为基础学习器，意味着最终模型能够捕获复杂的交互关系和非线性关系。此外，boosting 本身具有某种内置的正则化形式：通过添加许多小型决策树，并使用 learning rate 缩放它们的贡献，只要选择适当的参数，模型通常就能在不过度拟合的情况下实现良好的泛化。

#### **Gradient Boosting 的主要特征：**

-   **问题类型：** 主要用于分类和回归。在安全领域，通常用于分类（例如，对一个连接或文件进行二分类）。它支持二分类、多分类（使用适当的损失函数），甚至排序问题。

-   **可解释性：** 低到中等。虽然单棵 boosted tree 很小，但完整模型可能包含数百棵树，整体上并不能被人类直接理解。不过，与 Random Forest 类似，它可以提供特征重要性分数；此外，还可以使用 SHAP（SHapley Additive exPlanations）等工具，在一定程度上解释单个预测。

-   **优势：** 对结构化/表格数据而言，通常是**性能最佳**的算法。它能够检测复杂模式和交互关系，并提供许多调优参数（树的数量、树的深度、learning rate、正则化项），用于定制模型复杂度并防止过拟合。现代实现针对速度进行了优化（例如，XGBoost 使用二阶梯度信息和高效的数据结构）。结合适当的损失函数或调整样本权重后，它通常能够更好地处理不平衡数据。

-   **限制：** 比简单模型更难调优；如果树的深度较大或树的数量很多，训练可能会较慢（不过，在相同数据上，它通常仍然比训练规模相当的深度神经网络更快）。如果没有进行适当调优，模型可能会过拟合（例如，树过多且过深，同时正则化不足）。由于超参数较多，有效使用 gradient boosting 可能需要更多专业知识或实验。此外，与基于树的方法一样，它并不能像线性模型或 Naive Bayes 那样高效地处理非常稀疏的高维数据（尽管仍然可以应用，例如用于文本分类，但如果不进行特征工程，通常不会是首选）。

> [!TIP]
> *在网络安全中的使用场景：* 几乎所有适合使用决策树或 random forest 的场景，都可以尝试使用 gradient boosting 模型来获得更高的准确率。例如，**Microsoft 的 malware detection** 竞赛大量使用了基于二进制文件工程特征的 XGBoost。**网络入侵检测**研究经常报告 GBDTs 的最佳结果（例如，在 CIC-IDS2017 或 UNSW-NB15 数据集上使用 XGBoost）。这些模型可以接收广泛的特征（协议类型、特定事件的发生频率、流量的统计特征等），并将它们组合起来检测威胁。在 phishing detection 中，gradient boosting 可以结合 URL 的词法特征、域名信誉特征和页面内容特征，实现非常高的准确率。集成方法有助于覆盖数据中的许多边界情况和细微模式。

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
我们将在 phishing 数据集上使用 gradient boosting 分类器。为保持简单且自包含，我们将使用 `sklearn.ensemble.GradientBoostingClassifier`（这是一个速度较慢但易于使用的实现）。通常，可以使用 `xgboost` 或 `lightgbm` 库来获得更好的性能和更多功能。我们将训练模型，并采用与之前类似的方式对其进行评估。
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
Gradient boosting model 很可能会在这个 phishing dataset 上取得非常高的 accuracy 和 AUC（在这类数据上经过适当 tuning 后，这些模型通常可以达到超过 95% 的 accuracy，文献中也有类似结果。这说明了为什么 GBDTs 被认为是 *“the state of the art model for tabular dataset”* ——它们能够捕获复杂模式，因此往往优于更简单的 algorithms。在 cybersecurity 场景中，这意味着可以发现更多 phishing sites 或 attacks，同时减少漏报。当然，必须警惕 overfitting ——在开发用于部署的此类 model 时，我们通常会使用 cross-validation 等技术，并监控其在 validation set 上的 performance。

</details>

### Combining Models: Ensemble Learning and Stacking

Ensemble learning 是一种通过**组合多个 models**来提升整体 performance 的策略。我们已经见过一些具体的 ensemble methods：Random Forest（通过 bagging 组合 trees）和 Gradient Boosting（通过 sequential boosting 组合 trees）。不过，ensembles 也可以通过其他方式创建，例如 **voting ensembles** 或 **stacked generalization (stacking)**。其核心思想是，不同 models 可能捕获不同的 patterns，或者具有不同的弱点；通过组合它们，我们可以利用一个 model 的优势来**弥补另一个 model 的 errors**。<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** 在一个简单的 voting classifier 中，我们训练多个具有差异性的 models（例如 logistic regression、decision tree 和 SVM），然后让它们对最终 prediction 进行投票（classification 使用 majority vote）。如果我们对 votes 进行加权（例如，给予更准确的 models 更高权重），这就是 weighted voting scheme。当各个 models 本身表现良好且相互独立时，这通常可以提升 performance ——由于其他 models 可能纠正某个 model 的错误，ensemble 可以降低单个 model 出错的风险。这就像拥有一个专家小组，而不是只有一个人的意见。

-   **Stacking (Stacked Ensemble):** Stacking 更进一步。它不采用简单投票，而是训练一个 **meta-model**，使其**学习如何最佳地组合各个 base models 的 predictions**。例如，你可以训练 3 个不同的 classifiers（base learners），然后将它们的 outputs（或 probabilities）作为 features 输入 meta-classifier（通常是 logistic regression 这样的简单 model），由后者学习最佳的组合方式。为避免 overfitting，meta-model 会在 validation set 上训练，或通过 cross-validation 进行训练。Stacking 通常可以通过学习*在不同情况下应该更加信任哪些 models*，从而优于简单的 voting。在 cybersecurity 中，一个 model 可能更擅长发现 network scans，而另一个可能更擅长发现 malware beaconing；stacking model 可以学习在相应情况下适当地依赖每个 model。

无论是通过 voting 还是 stacking，Ensembles 通常都能**提升 accuracy**和 robustness。其缺点是复杂度增加，有时 interpretability 也会降低（不过，一些 ensemble approaches，例如 decision trees 的 average，仍然可以提供一定的 insight，如 feature importance）。在实践中，如果 operational constraints 允许，使用 ensemble 可以带来更高的 detection rates。许多 cybersecurity challenges 中的获胜方案（以及一般的 Kaggle competitions）都会使用 ensemble techniques，以进一步挤出最后一点 performance。

<details>
<summary>Example -- Voting Ensemble for Phishing Detection:</summary>
为了演示 model stacking，我们将把前面在 phishing dataset 中讨论过的几个 models 组合起来。我们会使用 logistic regression、decision tree 和 k-NN 作为 base learners，并使用 Random Forest 作为 meta-learner 来汇总它们的 predictions。meta-learner 将基于 base learners 的 outputs 进行训练（在 training set 上使用 cross-validation）。我们预计 stacked model 的 performance 将与各个独立 models 相当，或略高于它们。
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
stacked ensemble 利用了基础模型互补的优势。例如，logistic regression 可能负责处理数据的线性方面，decision tree 可能捕获特定的类规则交互，而 k-NN 可能在特征空间的局部邻域中表现出色。meta-model（此处为 random forest）可以学习如何对这些输入进行加权。最终的指标通常会比任何单一模型的指标有所提升（即使提升幅度很小）。在我们的 phishing 示例中，如果单独使用 logistic 的 F1 为 0.95、tree 为 0.94，那么 stack 可能通过弥补各模型的错误，将结果提升到 0.96。

这样的 Ensemble methods 展示了这样一个原则：*"组合多个模型通常能够带来更好的泛化能力"*。在 cybersecurity 中，可以部署多个 detection engines（其中一个基于规则，一个基于 machine learning，另一个基于 anomaly），然后通过一个聚合其 alerts 的层——实际上是一种 ensemble——以更高的置信度做出最终决策。部署此类系统时，必须考虑额外的复杂性，并确保 ensemble 不会变得难以管理或解释。但从准确性角度来看，ensembles 和 stacking 是提升模型性能的强大工具。

</details>


## 参考资料

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
