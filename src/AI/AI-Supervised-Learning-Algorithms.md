# 监督学习算法

{{#include ../banners/hacktricks-training.md}}

## 基本信息

监督学习使用带标签的数据训练模型，使其能够对新的、未见过的输入进行预测。在网络安全领域，监督机器学习广泛应用于入侵检测（将网络流量分类为*正常*或*攻击*）、恶意软件检测（区分恶意软件与良性软件）、钓鱼检测（识别欺诈性网站或电子邮件）以及垃圾邮件过滤等任务。<sup>[[1]](#references)</sup> 每种算法都有其优势，并适用于不同类型的问题（分类或回归）。下面我们将介绍主要的监督学习算法，解释其工作原理，并演示如何在真实的网络安全数据集上使用这些算法。我们还将讨论组合多个模型（集成学习）通常如何提升预测性能。

## 算法

-   **Linear Regression:** 一种基础的回归算法，通过将线性方程拟合到数据来预测数值结果。

-   **Logistic Regression:** 一种分类算法（尽管名称中包含回归），使用 logistic 函数对二元结果的概率进行建模。

-   **Decision Trees:** 基于树结构的模型，按照特征拆分数据并进行预测；通常因其可解释性而被使用。

-   **Random Forests:** 由多个决策树组成的集成模型（通过 bagging 实现），能够提升准确率并减少过拟合。

-   **Support Vector Machines (SVM):** 寻找最优分隔超平面的最大间隔分类器；可以使用 kernel 处理非线性数据。

-   **Naive Bayes:** 基于 Bayes 定理的概率分类器，并假设特征之间相互独立，因其在垃圾邮件过滤中的应用而闻名。

-   **k-Nearest Neighbors (k-NN):** 一种简单的“基于实例”的分类器，根据样本最近邻居中的多数类别为样本进行标记。

-   **Gradient Boosting Machines:** 集成模型（例如 XGBoost、LightGBM），通过依次添加较弱的学习器（通常为决策树）来构建强大的预测器。

下面的每个章节都会改进对相应算法的描述，并提供使用 `pandas` 和 `scikit-learn` 等库的 **Python 代码示例**（神经网络示例使用 `PyTorch`）。示例使用公开可用的网络安全数据集（例如用于入侵检测的 NSL-KDD 和 Phishing Websites 数据集），并遵循一致的结构：

1.  **加载数据集**（如果有可用的 URL，则通过 URL 下载）。

2.  **预处理数据**（例如，对分类特征进行编码、缩放数值、将数据拆分为训练集和测试集）。

3.  **在训练数据上训练模型**。

4.  **在测试集上进行评估**，使用以下指标：分类任务使用准确率、精确率、召回率、F1-score 和 ROC AUC（回归任务使用均方误差）。

让我们深入了解每种算法：

### Linear Regression

Linear regression 是一种用于预测连续数值的**回归**算法。它假设输入特征（自变量）与输出（因变量）之间存在线性关系。该模型尝试拟合一条能够最佳描述特征与目标之间关系的直线（在高维空间中则为超平面）。通常通过最小化预测值与实际值之间的误差平方和来完成这一过程（普通最小二乘法）。<sup>[[2]](#references)</sup>

表示 linear regression 最简单的形式是一条直线：
```plaintext
y = mx + b
```
其中：

- `y` 是预测值（输出）
- `m` 是直线的斜率（系数）
- `x` 是输入特征
- `b` 是 y 轴截距

线性回归的目标是找到一条最佳拟合直线，使预测值与数据集中的实际值之间的差异最小。当然，这非常简单，它将是一条分隔两个类别的直线；但如果增加更多维度，这条直线就会变得更加复杂：
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *网络安全中的使用场景：* 线性回归本身较少用于核心安全任务（这些任务通常是分类问题），但它可以用于预测数值结果。例如，可以根据历史数据使用线性回归**预测网络流量的大小**或**估计某个时间段内的攻击次数**。在给定特定系统指标的情况下，它还可以预测风险评分或攻击被检测到前的预期时间。在实践中，分类算法（如 logistic regression 或树模型）更常用于检测入侵或 malware，但线性回归是一个基础，并且适用于面向回归的分析。

#### **线性回归的关键特征：**

-   **问题类型：** 回归（预测连续值）。除非对输出应用阈值，否则不适合直接进行分类。

-   **可解释性：** 高 -- 系数易于解释，可以显示每个特征的线性影响。

-   **优点：** 简单且快速；是回归任务的良好基线；当真实关系近似线性时效果良好。

-   **局限性：** 无法捕获复杂或非线性关系（除非手动进行特征工程）；当关系为非线性时容易欠拟合；对异常值敏感，异常值可能使结果产生偏差。

-   **寻找最佳拟合：** 为了找到能够分隔可能类别的最佳拟合线，我们使用一种称为**普通最小二乘法（Ordinary Least Squares，OLS）**的方法。该方法会最小化观测值与线性模型预测值之间差异的平方和。

<details>
<summary>示例 -- 在入侵数据集中预测连接持续时间（回归）
</summary>
下面我们演示如何使用 NSL-KDD cybersecurity 数据集进行线性回归。我们将其视为一个回归问题，根据其他特征预测网络连接的 `duration`。（实际上，`duration` 是 NSL-KDD 的一个特征；这里使用它只是为了演示回归。）我们加载数据集，对其进行预处理（对分类特征进行编码），训练线性回归模型，并在测试集上评估均方误差（MSE）和 R² 分数。
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
在此示例中，linear regression model 尝试根据其他网络特征预测连接的 `duration`。我们使用 Mean Squared Error (MSE) 和 R² 来衡量性能。接近 1.0 的 R² 表示该模型能够解释 `duration` 中的大部分方差，而较低或为负的 R² 表示拟合效果较差。（如果这里的 R² 较低，不必感到意外——根据给定特征预测 `duration` 可能很困难，并且如果其中的模式较为复杂，linear regression 可能无法捕捉这些模式。）
</details>

### Logistic Regression

Logistic regression 是一种**classification**算法，用于建模某个实例属于特定类别（通常是“positive”类别）的概率。尽管名称中包含 regression，*logistic* regression 用于离散结果（不同于用于连续结果的 linear regression）。它尤其适用于**binary classification**（两个类别，例如 malicious 与 benign），但也可以扩展到 multi-class 问题（使用 softmax 或 one-vs-rest 方法）。<sup>[[3]](#references)</sup>

Logistic regression 使用 logistic function（也称为 sigmoid function）将预测值映射为概率。请注意，sigmoid function 的取值范围在 0 到 1 之间，并根据 classification 的需要沿 S 形曲线增长，这对 binary classification 任务非常有用。因此，每个输入的每个 feature 都会乘以其分配的 weight，然后将结果传递给 sigmoid function，以生成一个概率：
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
其中：

- `p(y=1|x)` 是给定输入 `x` 时输出 `y` 为 1 的概率
- `e` 是自然对数的底数
- `z` 是输入特征的线性组合，通常表示为 `z = w1*x1 + w2*x2 + ... + wn*xn + b`。注意，在最简单的形式中它仍是一条直线，但在更复杂的情况下，它会变成一个具有多个维度的超平面（每个特征对应一个维度）。

> [!TIP]
> *网络安全中的使用场景：* 由于许多安全问题本质上都是是/否决策，因此逻辑回归得到了广泛使用。例如，入侵检测系统可能会根据网络连接的特征，使用逻辑回归判断该连接是否属于攻击。在 phishing detection 中，逻辑回归可以将网站的特征（URL 长度、是否存在 `"@"` 符号等）组合成该网站属于 phishing 的概率。它曾被用于早期的 spam filters，并且如今仍是许多 classification 任务的可靠基线。

#### Logistic Regression for non binary classification

逻辑回归是为 binary classification 设计的，但可以使用 **one-vs-rest**（OvR）或 **softmax regression** 等技术扩展以处理 multi-class 问题。在 OvR 中，会为每个 class 分别训练一个 logistic regression model，将该 class 视为 positive class，并将其他所有 class 视为负类。最终选择预测概率最高的 class。Softmax regression 通过将 softmax function 应用于输出层，将逻辑回归推广到多个 class，从而生成所有 class 的概率分布。

#### **Key characteristics of Logistic Regression:**

-   **Type of Problem:** Classification（通常为 binary）。它预测 positive class 的概率。

-   **Interpretability:** 高 —— 与 linear regression 类似，feature coefficients 可以说明每个 feature 如何影响结果的 log-odds。这种透明性在安全领域通常很有价值，因为它有助于理解哪些因素导致了 alert。

-   **Advantages:** 训练简单且快速；当 features 与结果的 log-odds 之间呈线性关系时，效果良好。它会输出概率，因此可以用于 risk scoring。通过适当的 regularization，它具有良好的泛化能力，并且比普通的 linear regression 更能处理 multicollinearity。

-   **Limitations:** 假设 feature space 中存在 linear decision boundary（如果真实边界复杂或非线性，则效果不佳）。如果 interactions 或 non-linear effects 很关键，除非手动添加 polynomial 或 interaction features，否则其性能可能较差。此外，如果 classes 无法通过 features 的线性组合轻易分离，逻辑回归的效果也会较弱。


<details>
<summary>Example -- 使用 Logistic Regression 进行 Phishing Website Detection：</summary>

我们将使用 **Phishing Websites Dataset**（来自 UCI repository），该数据集包含从网站中提取的 features（例如 URL 是否包含 IP address、domain 的 age、HTML 中是否存在可疑 elements 等），以及用于标记网站属于 phishing 还是 legitimate 的 label。<sup>[[4]](#references)</sup> 我们训练一个 logistic regression model 对网站进行 classification，然后在 test split 上评估其 accuracy、precision、recall、F1-score 和 ROC AUC。
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
在这个 phishing detection 示例中，logistic regression 会为每个网站生成其属于 phishing 的概率。通过评估 accuracy、precision、recall 和 F1，我们可以了解模型的性能。例如，较高的 recall 意味着它能够捕获大多数 phishing 网站（这对安全性很重要，因为可以尽量减少漏掉的攻击），而较高的 precision 意味着误报较少（这对于避免分析师疲劳很重要）。ROC AUC（ROC 曲线下面积）提供了一个与阈值无关的性能指标（1.0 表示理想情况，0.5 表示不比随机猜测更好）。Logistic regression 通常在此类任务中表现良好，但如果 phishing 网站与合法网站之间的决策边界很复杂，可能就需要功能更强的非线性模型。

</details>

### 决策树

决策树是一种用途广泛的 **supervised learning algorithm**，可用于 classification 和 regression 任务。它根据数据的特征学习一个分层的树状决策模型。树中的每个内部节点表示对某个特定特征进行测试，每条分支表示该测试的一个结果，而每个叶节点表示预测的类别（用于 classification）或值（用于 regression）。<sup>[[5]](#references)</sup>

为了构建一棵树，CART（Classification and Regression Tree）等算法会使用 **Gini impurity** 或 **information gain (entropy)** 等指标，在每一步选择最佳特征和阈值来划分数据。每次划分的目标都是对数据进行分区，从而提高结果子集中的目标变量同质性（对于 classification，每个节点都应尽可能纯，即主要包含单一类别）。

决策树具有 **高度可解释性** ——可以沿着从根节点到叶节点的路径，了解某个预测背后的逻辑（例如，*“IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack”*）。这对于在 cybersecurity 中解释某个 alert 为何被触发非常有价值。树可以自然地处理 numerical 和 categorical 数据，并且只需要很少的预处理（例如，不需要进行 feature scaling）。

不过，单棵决策树很容易对 training data 过拟合，尤其是在树生长得很深（包含许多划分）时。通常会使用 pruning（限制树的深度或要求每个叶节点至少包含一定数量的样本）等技术来防止过拟合。

决策树主要包含 3 个组件：
- **Root Node**：树的顶层节点，表示整个数据集。
- **Internal Nodes**：表示特征以及基于这些特征所做决策的节点。
- **Leaf Nodes**：表示最终结果或预测的节点。

一棵树最终可能看起来像这样：
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *网络安全中的使用场景：* 决策树曾被用于入侵检测系统，以推导用于识别攻击的 **规则**。例如，早期基于 ID3/C4.5 的 IDS 会生成人类可读的规则，用于区分正常流量与恶意流量。它们也用于 malware analysis，根据文件的属性（文件大小、section entropy、API calls 等）判断文件是否为恶意文件。决策树的清晰性使其在需要透明度时非常有用——analyst 可以检查树，以验证 detection logic。

#### **决策树的主要特征：**

-   **问题类型：** classification 和 regression。通常用于将流量分类为攻击或正常流量等。

-   **可解释性：** 非常高——模型的决策可以可视化，并理解为一组 if-then 规则。这是在 security 场景中的一项重要优势，有助于建立对模型行为的信任并进行验证。

-   **优点：** 能够捕获 feature 之间的非线性关系和交互（每次 split 都可以视为一种交互）。无需对 features 进行缩放，也无需对 categorical variables 进行 one-hot encode——trees 可以原生处理这些内容。inference 速度快（prediction 只需沿着 tree 中的一条路径进行）。

-   **局限性：** 如果不加以控制，容易 overfitting（深层 tree 可能会记住 training set）。它们可能不稳定——数据中的微小变化可能导致不同的 tree 结构。作为单一模型，其 accuracy 可能不及更高级的方法（如 Random Forests 等 ensembles 通常通过降低 variance 获得更好的 performance）。

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

此外，在以下情况下会结束 tree：
- node 中的所有实例都属于同一个 class。这可能导致 overfitting。
- 达到 tree 的最大深度（hardcoded）。这是防止 overfitting 的一种方式。
- node 中的实例数量低于某个阈值。这也是防止 overfitting 的一种方式。
- 进一步 split 所获得的 information gain 低于某个阈值。这同样是防止 overfitting 的一种方式。

<details>
<summary>示例 -- 用于入侵检测的决策树：</summary>
我们将在 NSL-KDD dataset 上训练一个决策树，将网络连接分类为 *normal* 或 *attack*。NSL-KDD 是经典 KDD Cup 1999 dataset 的改进版本，其中包含 protocol type、service、duration、failed logins 数量等 features，以及用于指示 attack type 或 "normal" 的 label。我们会将所有 attack types 映射到 "anomaly" class（二元 classification：normal 与 anomaly）。训练完成后，我们将在 test set 上评估该 tree 的 performance。
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
在这个 decision tree 示例中，我们将树的深度限制为 10，以避免严重的 overfitting（`max_depth=10` 参数）。这些指标展示了该树区分正常流量与攻击流量的能力。较高的 recall 表示它能够捕获大多数攻击（这对 IDS 很重要），而较高的 precision 表示误报较少。Decision trees 通常能在结构化数据上取得不错的准确率，但单棵树可能无法达到最佳性能。不过，该模型的 *可解释性* 是一个很大的优点——我们可以检查树的各个分支，了解哪些特征（例如 `service`、`src_bytes` 等）在将连接标记为恶意连接时影响最大。

</details>

### Random Forests

Random Forest 是一种 **ensemble learning** 方法，它以 decision trees 为基础来提升性能。Random Forest 会训练多棵 decision trees（因此称为“forest”），并组合它们的输出以生成最终预测（对于 classification，通常采用多数投票）。Random Forest 的两个主要理念是 **bagging**（bootstrap aggregating）和 **feature randomness**：

-   **Bagging：** 每棵树都基于训练数据的随机 bootstrap 样本进行训练（有放回采样）。这会使各棵树之间产生差异。

-   **Feature Randomness：** 在树的每个分支点，只考虑随机选择的部分特征进行划分（而不是使用全部特征）。这会进一步降低各棵树之间的相关性。

通过对多棵树的结果进行平均，Random Forest 可以降低单棵 decision tree 可能产生的 variance。简单来说，单棵树可能会 overfit 或产生噪声，但大量具有差异的树共同投票可以平滑这些错误。最终得到的模型通常比单棵 decision tree 具有 **更高的准确率** 和更好的泛化能力。此外，Random Forest 还可以提供 feature importance 的估计值（通过观察每个特征的划分平均减少了多少 impurity）。

Random forests 已成为 **cybersecurity 中的主力工具**，可用于 intrusion detection、malware classification 和 spam detection 等任务。它们通常无需大量 tuning 就能取得良好表现，并且能够处理大型特征集。例如，在 intrusion detection 中，Random Forest 可能比单棵 decision tree 更出色，因为它能以更少的 false positives 捕获更隐蔽的攻击模式。研究表明，在 NSL-KDD 和 UNSW-NB15 等数据集上对攻击进行分类时，Random forests 的表现优于其他算法。<sup>[[6]](#references)[[7]](#references)</sup>

#### **Random Forests 的主要特征：**

-   **问题类型：** 主要用于 classification（也可用于 regression）。非常适合处理 security logs 中常见的高维结构化数据。

-   **可解释性：** 低于单棵 decision tree——你无法轻易同时可视化或解释数百棵树。不过，feature importance 分数可以帮助了解哪些属性影响最大。

-   **优势：** 由于 ensemble effect，准确率通常高于单树模型。对 overfitting 具有较强的抵抗能力——即使单棵树发生 overfit，ensemble 仍能更好地泛化。它可以处理 numerical 和 categorical features，并在一定程度上处理 missing data。同时，它对 outliers 也相对稳健。

-   **局限性：** 模型规模可能很大（包含许多棵树，且每棵树都可能很深）。预测速度比单棵树慢（因为必须汇总多棵树的结果）。可解释性较低——虽然你能知道哪些特征很重要，但其具体逻辑不像简单规则那样容易追踪。如果数据集的维度极高且稀疏，训练一个非常大的 forest 可能会带来较高的计算开销。

-   **训练过程：**
1. **Bootstrap Sampling**：对训练数据进行有放回的随机采样，以创建多个子集（bootstrap samples）。
2. **Tree Construction**：针对每个 bootstrap sample，使用每个分支点处随机选择的特征子集来构建一棵 decision tree。这样可以增加各棵树之间的差异。
3. **Aggregation**：对于 classification 任务，最终预测结果由所有树的预测结果进行多数投票得出。对于 regression 任务，最终预测结果是所有树预测结果的平均值。

<details>
<summary>示例 -- 用于 Intrusion Detection 的 Random Forest（NSL-KDD）：</summary>
我们将使用相同的 NSL-KDD 数据集（将数据二分类为 normal 与 anomaly），并训练一个 Random Forest classifier。由于 ensemble averaging 可以降低 variance，我们预计 Random Forest 的表现至少与单棵 decision tree 一样好，或者更好。我们将使用相同的指标对其进行评估。
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
随机森林通常能在此入侵检测任务中取得良好效果。与单棵决策树相比，我们可能会观察到 F1 或 AUC 等指标有所提升，尤其是在召回率或精确率方面，具体取决于数据。这与以下观点一致：*"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*。<sup>[[6]](#references)</sup> 在安全运营场景中，随机森林模型可能更可靠地标记攻击，同时减少误报，这得益于对大量决策规则进行平均。通过随机森林的特征重要性，我们可以了解哪些网络特征最能指示攻击（例如，某些网络服务或异常的数据包数量）。

</details>

### Support Vector Machines (SVM)

Support Vector Machines 是功能强大的监督学习模型，主要用于分类（也可通过 SVR 用于回归）。SVM 试图寻找能够最大化两类之间间隔的**最优分离超平面**。只有一部分训练点（最接近边界的“支持向量”）决定该超平面的位置。通过最大化间隔（支持向量与超平面之间的距离），SVM 往往能够实现良好的泛化能力。<sup>[[8]](#references)</sup>

SVM 的核心优势在于能够使用**kernel functions**处理非线性关系。数据可以被隐式转换到更高维的特征空间，在那里可能存在一个线性分隔面。常见的 kernel 包括多项式、径向基函数（RBF）和 sigmoid。例如，如果网络流量类别在原始特征空间中不是线性可分的，RBF kernel 可以将其映射到更高维空间，在该空间中 SVM 能够找到线性分割（这对应于原始空间中的非线性边界）。选择不同 kernel 的灵活性使 SVM 能够应对各种问题。

SVM 已知在高维特征空间（如文本数据或 malware opcode 序列）以及特征数量相对于样本数量较多的情况下表现良好。2000 年代，SVM 曾广泛应用于许多早期的 cybersecurity 场景，例如 malware 分类和基于异常的入侵检测，并且通常能够取得较高的准确率。

但是，SVM 不容易扩展到非常大的数据集（其训练复杂度相对于样本数量呈超线性增长，并且内存占用可能很高，因为它可能需要存储大量支持向量）。在实践中，对于包含数百万条记录的网络入侵检测任务，如果不进行谨慎的子采样或使用近似方法，SVM 可能会过慢。

#### **SVM 的关键特征：**

-   **问题类型：**分类（通过 one-vs-one/one-vs-rest 实现二分类或多分类）以及回归变体。通常用于具有清晰间隔分离的二分类任务。

-   **可解释性：**中等 -- SVM 的可解释性不如决策树或 logistic regression。虽然可以识别哪些数据点是支持向量，并通过权重（在线性 kernel 的情况下）大致了解哪些特征可能具有影响，但在实践中，SVM（尤其是使用非线性 kernel 时）通常被视为 black-box 分类器。

-   **优点：**在高维空间中有效；通过 kernel trick 对复杂决策边界进行建模；当间隔最大化时能够抵抗过拟合（尤其是在正确设置正则化参数 C 的情况下）；即使类别之间没有较大的距离，也能良好工作（找到最佳折中边界）。

-   **局限性：****对于大型数据集而言，计算成本高**（随着数据增长，训练和预测的扩展性都较差）。需要仔细调优 kernel 和正则化参数（C、kernel 类型、RBF 的 gamma 等）。不会直接提供概率输出（但可以使用 Platt scaling 获得概率）。此外，SVM 可能对 kernel 参数的选择较为敏感 --- 选择不当可能导致欠拟合或过拟合。

*在 cybersecurity 中的使用场景：*SVM 已被用于 **malware detection**（例如，根据提取的特征或 opcode 序列对文件进行分类）、**网络异常检测**（将流量分类为正常或恶意）以及 **phishing detection**（使用 URL 的特征）。例如，SVM 可以获取一封 email 的特征（某些关键词的数量、发件人信誉评分等），并将其分类为 phishing 或 legitimate。SVM 也被应用于基于 KDD 等特征集的 **intrusion detection**，通常能够以较高的计算成本换取较高的准确率。

<details>
<summary>Example -- SVM for Malware Classification:</summary>
这次我们将再次使用 phishing website 数据集，但改用 SVM。由于 SVM 可能运行缓慢，如果需要，我们会使用数据子集进行训练（该数据集约有 11k 个实例，SVM 可以较为合理地处理）。我们将使用 RBF kernel，这是处理非线性数据时的常见选择，并启用概率估计来计算 ROC AUC。
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
SVM 模型将输出一些指标，我们可以将其与同一任务上的逻辑回归进行比较。如果数据在特征空间中具有良好的可分性，我们可能会发现 SVM 能够取得较高的准确率和 AUC。反过来，如果数据集包含大量噪声或类别之间存在重叠，SVM 可能不会显著优于逻辑回归。在实践中，当特征与类别之间存在复杂的非线性关系时，SVM 往往能够带来提升——RBF kernel 可以捕获逻辑回归无法识别的弯曲决策边界。与所有模型一样，需要仔细调节 `C`（正则化）和 kernel 参数（例如 RBF 的 `gamma`），以平衡偏差和方差。

</details>

#### 逻辑回归与 SVM 的区别

| 方面 | **逻辑回归** | **支持向量机** |
|---|---|---|
| **目标函数** | 最小化 **log-loss**（交叉熵）。 | 最大化 **margin**，同时最小化 **hinge-loss**。 |
| **决策边界** | 找到用于建模 _P(y\|x)_ 的**最佳拟合超平面**。 | 找到**最大间隔超平面**（与最近点之间具有最大间隔）。 |
| **输出** | **概率型**——通过 σ(w·x + b) 输出经过校准的类别概率。 | **确定性**——返回类别标签；如需概率则需要额外处理（例如 Platt scaling）。 |
| **正则化** | L2（默认）或 L1，直接平衡欠拟合与过拟合。 | C 参数在间隔宽度与误分类之间进行权衡；kernel 参数会增加复杂度。 |
| **Kernels / 非线性** | 原生形式是**线性的**；可通过特征工程添加非线性。 | 内置 **kernel trick**（RBF、poly 等），能够在高维空间中建模复杂边界。 |
| **可扩展性** | 在 **O(nd)** 中求解凸优化；能够很好地处理非常大的 n。 | 如果没有专用求解器，训练的内存/时间复杂度可能为 **O(n²–n³)**；不适合超大规模 n。 |
| **可解释性** | **高**——权重显示特征影响；odds ratio 直观易懂。 | 非线性 kernel 的**可解释性低**；support vectors 虽然稀疏，但不易解释。 |
| **对异常值的敏感性** | 使用平滑的 log-loss，因此敏感性较低。 | 带有硬间隔的 hinge-loss 可能**对异常值敏感**；soft-margin（C）可以缓解这一问题。 |
| **典型使用场景** | 信用评分、医疗风险、A/B 测试——适用于重视**概率与可解释性**的场景。 | 图像/文本分类、生物信息学——适用于重视**复杂边界**和**高维数据**的场景。 |

* **如果你需要经过校准的概率、可解释性，或需要处理超大规模数据集——选择逻辑回归。**
* **如果你需要一种无需手动进行特征工程、即可捕获非线性关系的灵活模型——选择 SVM（使用 kernels）。**
* 两者都优化凸目标函数，因此都能**保证得到全局最小值**；但 SVM 的 kernels 会增加超参数和计算成本。

### 朴素贝叶斯

朴素贝叶斯是一类**概率分类器**，其基础是应用贝叶斯定理，并对特征之间作出强独立性假设。尽管这一假设较为“朴素”，朴素贝叶斯在某些应用中通常表现得出人意料地好，尤其适用于文本或类别数据，例如垃圾邮件检测。<sup>[[9]](#references)</sup>


#### 贝叶斯定理

贝叶斯定理是朴素贝叶斯分类器的基础。它描述了随机事件的条件概率与边缘概率之间的关系。公式如下：
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
其中：
- `P(A|B)` 是给定特征 `B` 时类别 `A` 的后验概率。
- `P(B|A)` 是给定类别 `A` 时特征 `B` 的似然概率。
- `P(A)` 是类别 `A` 的先验概率。
- `P(B)` 是特征 `B` 的先验概率。

例如，如果我们想判断一段文本是由儿童还是成人撰写的，就可以使用文本中的单词作为特征。基于一些初始数据，朴素贝叶斯分类器会预先计算每个单词属于每个潜在类别（儿童或成人）的概率。当输入一段新文本时，它会根据文本中的单词计算每个潜在类别的概率，并选择概率最高的类别。

正如这个示例所示，朴素贝叶斯分类器非常简单且快速，但它假设各个特征彼此独立，而现实世界的数据并不总是如此。


#### 朴素贝叶斯分类器的类型

根据数据类型和特征的分布，朴素贝叶斯分类器有多种类型：
- **Gaussian Naive Bayes**：假设特征遵循 Gaussian（正态）分布。适用于连续数据。
- **Multinomial Naive Bayes**：假设特征遵循多项式分布。适用于离散数据，例如文本分类中的词频。
- **Bernoulli Naive Bayes**：假设特征是二元的（0 或 1）。适用于二元数据，例如文本分类中单词的存在或缺失。
- **Categorical Naive Bayes**：假设特征是分类变量。适用于分类数据，例如根据水果的颜色和形状对水果进行分类。


#### **朴素贝叶斯的关键特征：**

-   **问题类型：** 分类（二分类或多分类）。常用于 cybersecurity 中的文本分类任务（spam、phishing 等）。

-   **可解释性：** 中等 —— 它不像决策树那样容易直接解释，但可以检查学习到的概率（例如，哪些单词最有可能出现在 spam 邮件而不是 ham 邮件中）。如果需要，可以理解模型的形式（给定类别时每个特征的概率）。

-   **优势：** 训练和预测速度**非常快**，即使面对大型数据集也是如此（复杂度与实例数量 * 特征数量呈线性关系）。只需要相对少量的数据就能可靠地估计概率，尤其是在正确使用平滑处理的情况下。它作为基线模型时通常具有出人意料的准确率，特别是在各特征能够独立地为类别提供证据时。它适用于高维数据（例如从文本中提取的数千个特征）。除了设置平滑参数外，通常不需要复杂的调优。

-   **局限性：** 如果特征之间高度相关，独立性假设可能会限制准确率。例如，在网络数据中，`src_bytes` 和 `dst_bytes` 等特征可能存在相关性；朴素贝叶斯无法捕获这种交互关系。随着数据规模变得非常大，更具表现力的模型（例如 ensembles 或 neural nets）可以通过学习特征之间的依赖关系超越 NB。此外，如果识别某种 attack 需要依赖特征组合（而不仅仅是各个特征独立地发挥作用），NB 将难以应对。

> [!TIP]
> *在 cybersecurity 中的使用场景：* 经典用途是 **spam detection** —— 朴素贝叶斯曾是早期 spam 过滤器的核心，通过使用特定 token（单词、短语、IP 地址）的出现频率来计算一封邮件属于 spam 的概率。它还用于 **phishing email detection** 和 **URL classification**，其中某些关键词或特征的存在（例如 URL 中的 "login.php"，或 URL path 中的 `@`）会影响 phishing 的概率。在 malware 分析中，可以设想使用一个朴素贝叶斯分类器，根据软件中是否存在特定 API 调用或权限来预测其是否为 malware。尽管更先进的算法通常表现更好，但朴素贝叶斯凭借速度和简单性，仍然是一个很好的基线模型。

<details>
<summary>示例 -- 使用朴素贝叶斯进行 Phishing Detection：</summary>
为了演示朴素贝叶斯，我们将在 NSL-KDD intrusion 数据集（包含二元标签）上使用 Gaussian Naive Bayes。Gaussian NB 会将每个特征视为在每个类别中都遵循正态分布。这是一种较为粗略的选择，因为许多网络特征是离散的或高度偏斜的，但它展示了如何将 NB 应用于连续特征数据。我们也可以在二元特征数据集（例如一组已触发的 alerts）上选择 Bernoulli NB，但为了保持连续性，这里仍使用 NSL-KDD。
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
这段代码训练了一个 Naive Bayes classifier 来检测 attacks。Naive Bayes 会基于 training data 计算诸如 `P(service=http | Attack)` 和 `P(Service=http | Normal)` 这样的概率，并假设各 feature 之间相互独立。随后，它会根据所观察到的 feature，使用这些概率将新连接分类为 normal 或 attack。NB 在 NSL-KDD 上的性能可能不如更 advanced 的 model（因为 feature independence 的假设并不成立），但通常表现尚可，并且具有极高速度的优势。在 real-time email filtering 或 URL 初步 triage 等场景中，Naive Bayes model 可以以较低的资源消耗快速标记明显的 malicious case。

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors 是最简单的 machine learning algorithm 之一。它是一种**non-parametric、instance-based**方法，根据与 training set 中示例的相似度进行 prediction。用于 classification 时，其思路是：要对一个新的 data point 进行分类，找到 training data 中距离最近的 **k** 个 point（即它的“nearest neighbors”），然后将这些 neighbors 中占多数的 class 分配给该 data point。“接近程度”由 distance metric 定义；对于 numeric data，通常使用 Euclidean distance（对于不同类型的 feature 或问题，也可以使用其他 distance）。<sup>[[10]](#references)</sup>

K-NN **不需要显式 training** -- “training”阶段只是存储 dataset。所有工作都发生在 query（prediction）期间：algorithm 必须计算 query point 与所有 training point 之间的 distance，才能找到最近的 point。这使 prediction time 与 training sample 数量呈**线性关系**，对于大型 dataset 可能代价很高。因此，k-NN 更适合较小的 dataset，或可以用 memory 和 speed 换取 simplicity 的场景。

尽管简单，k-NN 仍然可以 model 非常复杂的 decision boundary（因为实际上，decision boundary 可以是由 examples 分布决定的任意形状）。当 decision boundary 非常 irregular 且拥有大量 data 时，它通常表现良好 -- 本质上是让 data “自行说明情况”。然而，在 high dimensions 中，distance metric 可能会变得不太有意义（curse of dimensionality），除非拥有海量 sample，否则该方法可能难以应对。

*cybersecurity 中的使用场景：* k-NN 已被应用于 anomaly detection -- 例如，如果某个 network event 的大多数 nearest neighbors（之前的 event）都是 malicious，intrusion detection system 可能会将该 event 标记为 malicious。如果 normal traffic 形成 clusters，而 attacks 是 outlier，那么 K-NN 方法（使用 k=1 或较小的 k）本质上就是一种 **nearest-neighbor anomaly detection**。K-NN 也被用于通过 binary feature vector 对 malware family 进行分类：如果一个新 file 在 feature space 中与某个 malware family 的已知 instance 非常接近，那么它可能会被分类为该 malware family。实际上，k-NN 不如更具 scalability 的 algorithm 常见，但它在概念上 straightforward，有时会作为 baseline 或用于 small-scale problem。

#### **k-NN 的关键特征：**

-   **Problem 类型：** Classification（也存在 regression variant）。它是一种 *lazy learning* 方法 -- 不进行显式的 model fitting。

-   **Interpretability：** Low 到 medium -- 它没有 global model 或简洁的 explanation，但可以通过查看影响 decision 的 nearest neighbors 来解释结果（例如，“该 network flow 被分类为 malicious，是因为它与这 3 个已知的 malicious flow 相似”）。因此，explanation 可以基于 example。

-   **Advantages：** 实现和理解都非常简单。不对 data distribution 做任何假设（non-parametric）。可以自然地处理 multi-class problem。它具有**adaptive**特性，因为 decision boundary 可以非常复杂，并由 data distribution 决定。

-   **Limitations：** 对大型 dataset 进行 prediction 可能较慢（必须计算大量 distance）。对 memory 的消耗较大 -- 它会存储所有 training data。在 high-dimensional feature space 中，性能会下降，因为所有 point 往往几乎等距（使“nearest”的概念变得不那么有意义）。需要适当选择 *k*（neighbor 数量）-- k 过小可能导致 noise 较多，k 过大则可能包含来自其他 class 的 irrelevant point。此外，feature 应进行适当 scaling，因为 distance calculation 对 scale 很敏感。

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

我们仍将使用 NSL-KDD（binary classification）。由于 k-NN 的 computational cost 较高，在本 demonstration 中我们将使用 training data 的一个 subset，以确保其可处理。比如，我们从完整的 125k 个 sample 中选取 20,000 个 training sample，并使用 k=5 个 neighbor。training 后（实际上只是存储 data），我们将在 test set 上进行 evaluation。我们还会对 feature 进行 scaling，以用于 distance calculation，确保不会因为 scale 的差异而使某个 feature 占据主导地位。
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
k-NN 模型会通过查看训练集子集中距离最近的 5 个连接来对某个连接进行分类。例如，如果其中 4 个邻居属于攻击（异常），而 1 个属于正常连接，那么这个新连接就会被分类为攻击。其性能可能较为理想，但通常不如在相同数据上经过良好调优的 Random Forest 或 SVM。不过，当类别分布非常不规则且复杂时，k-NN 有时会表现出色——实际上相当于使用基于记忆的查找。在网络安全领域，k-NN（k=1 或较小的 k）可用于通过示例检测已知的攻击模式，也可以作为更复杂系统的组成部分（例如，先进行聚类，再根据所属簇进行分类）。
</details>

### Gradient Boosting Machines（例如 XGBoost）

Gradient Boosting Machines 是处理结构化数据时最强大的算法之一。**Gradient boosting** 是一种以序列方式构建弱学习器集成的技术（通常使用决策树），其中每个新模型都会修正前一个集成模型的错误。与并行构建树并对其结果取平均的 bagging（Random Forest）不同，boosting 会*逐棵*构建树，每棵树都会更加关注前面树预测错误的样本。<sup>[[11]](#references)</sup>

近年来最流行的实现包括 **XGBoost**、**LightGBM** 和 **CatBoost**，它们都是 gradient boosting decision tree（GBDT）库。这些工具在机器学习竞赛和实际应用中都取得了极大成功，通常能够在**表格数据集上实现 state-of-the-art 性能**。在网络安全领域，研究人员和从业者已使用 gradient boosted trees 执行诸如**恶意软件检测**（使用从文件或运行时行为中提取的特征）和**网络入侵检测**等任务。例如，gradient boosting 模型可以将许多弱规则（树）组合起来，例如“如果 SYN 数据包数量很多且端口异常 -> 可能是扫描”，从而构建一个能够考虑大量细微模式的强大复合检测器。

为什么 boosted trees 如此有效？序列中的每棵树都会根据当前集成模型预测的*残差误差*（梯度）进行训练。这样，模型就能逐步**“boost”**自身较弱的部分。使用决策树作为基础学习器，意味着最终模型可以捕获复杂的交互关系和非线性关系。此外，boosting 天然具备某种内置正则化形式：通过添加许多小型树（并使用 learning rate 缩放它们的贡献），只要选择适当的参数，模型通常就能在不过度拟合的情况下实现良好的泛化能力。

#### **Gradient Boosting 的关键特征：**

-   **问题类型：** 主要用于分类和回归。在安全领域，通常用于分类（例如，对连接或文件进行二分类）。它支持二分类、多分类（使用适当的损失函数），甚至排序问题。

-   **可解释性：** 低到中等。虽然单棵 boosted tree 规模较小，但完整模型可能包含数百棵树，整体上无法被人类直接理解。不过，与 Random Forest 类似，它可以提供特征重要性分数；此外，还可以使用 SHAP（SHapley Additive exPlanations）等工具，在一定程度上解释单个预测结果。

-   **优势：** 对结构化/表格数据而言，通常是**性能最佳**的算法。能够检测复杂模式和交互关系。它提供了许多可调参数（树的数量、树的深度、learning rate、正则化项），可用于调整模型复杂度并防止过拟合。现代实现针对速度进行了优化（例如，XGBoost 使用二阶梯度信息和高效的数据结构）。如果结合适当的损失函数或调整样本权重，它通常能够更好地处理类别不平衡数据。

-   **局限性：** 比简单模型更难调优；如果树较深或树的数量较多，训练可能会比较慢（不过，在相同数据上，它通常仍比训练规模相当的 deep neural network 更快）。如果调优不当，模型可能会过拟合（例如，树过多且过深，同时正则化不足）。由于超参数较多，有效使用 gradient boosting 可能需要更多专业知识或实验。此外，与基于树的方法一样，它对非常稀疏的高维数据的处理效率天生不如线性模型或 Naive Bayes（不过仍然可以应用，例如用于文本分类，但如果不进行特征工程，通常不会是首选）。

> [!TIP]
> *网络安全中的使用场景：* 几乎所有可以使用决策树或 random forest 的场景，都可以尝试使用 gradient boosting 模型来获得更高的准确率。例如，**Microsoft 的恶意软件检测**竞赛大量使用了基于二进制文件工程特征的 XGBoost。**网络入侵检测**研究通常会报告 GBDTs 的最佳结果（例如，在 CIC-IDS2017 或 UNSW-NB15 数据集上使用 XGBoost）。这些模型可以接收范围广泛的特征（协议类型、特定事件的发生频率、流量的统计特征等），并将它们结合起来检测威胁。在 phishing 检测中，gradient boosting 可以结合 URL 的词法特征、域名信誉特征和页面内容特征，从而实现非常高的准确率。集成方法有助于覆盖数据中的各种边界情况和细微特征。

<details>
<summary>示例 -- 使用 XGBoost 进行 Phishing Detection：</summary>
我们将使用 phishing 数据集上的 gradient boosting 分类器。为保持示例简单且自包含，我们将使用 `sklearn.ensemble.GradientBoostingClassifier`（这是一个速度较慢但易于理解的实现）。通常，可以使用 `xgboost` 或 `lightgbm` 库来获得更好的性能和更多功能。我们将训练该模型，并采用与之前类似的方式对其进行评估。
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
梯度 boosting 模型很可能会在这个 phishing 数据集上取得非常高的准确率和 AUC（相关文献表明，经过适当调优后，此类模型的准确率通常可以超过 95%）。这也说明了为什么 GBDT 被认为是 *“表格数据集上的 state-of-the-art 模型”*——它们能够捕获复杂模式，因此通常优于更简单的算法。<sup>[[11]](#references)</sup> 在 cybersecurity 场景中，这意味着可以检测出更多 phishing 网站或攻击，同时减少漏报。当然，必须警惕 overfitting——在开发用于部署的此类模型时，我们通常会使用 cross-validation 等技术，并监控模型在 validation set 上的表现。

</details>

### 组合模型：Ensemble Learning 和 Stacking

Ensemble learning 是一种通过**组合多个模型**来提升整体性能的策略。我们已经了解过具体的 ensemble 方法：Random Forest（通过 bagging 组合多个树）和 Gradient Boosting（通过 sequential boosting 组合多个树）。不过，ensemble 也可以通过其他方式构建，例如 **voting ensembles** 或 **stacked generalization（stacking）**。核心思想是，不同模型可能捕获不同的模式，或者具有不同的弱点；通过组合它们，我们可以利用一个模型的优势来**弥补另一个模型的错误**。<sup>[[12]](#references)</sup>

-   **Voting Ensemble：** 在简单的 voting classifier 中，我们训练多个具有差异性的模型（例如 logistic regression、decision tree 和 SVM），让它们对最终预测进行投票（分类任务中通常采用多数投票）。如果我们对投票进行加权（例如，为准确率更高的模型赋予更高权重），这就是 weighted voting。 当各个模型本身表现较好且彼此相对独立时，这通常能够提升性能——由于其他模型可能纠正某个模型的错误，ensemble 可以降低单个模型出错带来的风险。这就像拥有一个专家小组，而不是只听取单一意见。

-   **Stacking（Stacked Ensemble）：** Stacking 更进一步。它不采用简单投票，而是训练一个 **meta-model**，用于**学习如何最佳地组合各个 base model 的预测结果**。例如，你可以训练 3 个不同的 classifiers（base learners），然后将它们的输出（或概率）作为 features 输入 meta-classifier（通常是 logistic regression 之类的简单模型），由后者学习最佳的组合方式。为了避免 overfitting，meta-model 会基于 validation set 或通过 cross-validation 进行训练。通过学习*在不同情况下应更加信任哪些模型*，Stacking 往往能够胜过简单的 voting。在 cybersecurity 中，一个模型可能更擅长捕获 network scans，而另一个模型可能更擅长检测 malware beaconing；stacking model 可以学习在不同场景下合理地依赖相应模型。

无论是通过 voting 还是 stacking，Ensemble 通常都能**提升准确率**和鲁棒性。其缺点是复杂度增加，并且有时可解释性会降低（不过，一些 ensemble 方法仍然可以提供一定的洞察，例如对 decision trees 求平均后仍可分析 feature importance）。在实际环境中，如果运营约束允许，使用 ensemble 可以带来更高的 detection rate。许多 cybersecurity 挑战赛中的获胜方案（以及一般的 Kaggle 比赛）都会使用 ensemble 技术，以榨取最后一点性能提升。

<details>
<summary>示例 -- Phishing Detection 的 Voting Ensemble：</summary>
为了说明 model stacking 的工作方式，我们将把前面在 phishing 数据集上讨论过的几个模型组合起来。我们会使用 logistic regression、decision tree 和 k-NN 作为 base learners，并使用 Random Forest 作为 meta-learner 来汇总它们的预测结果。meta-learner 将基于 base learners 的输出进行训练（在 training set 上使用 cross-validation）。我们预计，stacked model 的表现将与单个模型相当，或略优于单个模型。
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
stacked ensemble 利用了基础模型互补的优势。例如，logistic regression 可能处理数据中的线性部分，decision tree 可能捕获特定的类似规则的交互关系，而 k-NN 可能在特征空间的局部邻域中表现出色。meta-model（这里是 random forest）可以学习如何对这些输入进行加权。最终的指标通常会比任何单一模型的指标有所提升（即使提升幅度很小）。在我们的 phishing 示例中，如果单独使用 logistic 的 F1 值为 0.95，而 decision tree 为 0.94，那么 stack 可能通过弥补各模型的错误，将 F1 值提升到 0.96。

这样的 ensemble methods 展示了这样一个原则：*“组合多个模型通常能够带来更好的泛化能力”*。<sup>[[12]](#references)</sup> 在 cybersecurity 中，可以通过部署多个 detection engine 来实现这一点（其中一个可能基于规则，一个基于 machine learning，另一个基于 anomaly），然后添加一层来聚合它们的 alerts——这实际上是一种 ensemble 形式——从而以更高的置信度做出最终决策。部署此类系统时，必须考虑增加的复杂性，并确保 ensemble 不会变得过于难以管理或解释。但从准确率角度来看，ensembles 和 stacking 是提升模型性能的强大工具。

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
