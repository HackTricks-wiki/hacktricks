# 监督学习算法

{{#include ../banners/hacktricks-training.md}}

## 基本信息

监督学习使用带标签的数据训练模型，使其能够对新的、未见过的输入进行预测。在网络安全领域，监督机器学习广泛应用于入侵检测（将网络流量分类为*正常*或*攻击*）、恶意软件检测（区分恶意软件与良性软件）、phishing 检测（识别欺诈性网站或电子邮件）和垃圾邮件过滤等任务。<sup>[[1]](#references)</sup> 每种算法都有其优势，并适用于不同类型的问题（分类或回归）。下面我们将介绍主要的监督学习算法，解释其工作原理，并演示如何将其应用于真实的网络安全数据集。我们还将讨论组合多个模型（集成学习）如何通常能够提升预测性能。

## 算法

-   **Linear Regression:** 一种基础回归算法，通过将线性方程拟合到数据上来预测数值结果。

-   **Logistic Regression:** 一种分类算法（尽管名称中包含 Regression），使用 logistic 函数对二元结果的概率进行建模。

-   **Decision Trees:** 基于树结构的模型，通过特征拆分数据来进行预测；通常因其可解释性而被使用。

-   **Random Forests:** 由多个 Decision Trees 组成的集成模型（通过 bagging 实现），能够提升准确率并减少过拟合。

-   **Support Vector Machines (SVM):** 最大间隔分类器，用于寻找最优分离超平面；可以使用 kernels 处理非线性数据。

-   **Naive Bayes:** 基于 Bayes 定理的概率分类器，并假设特征之间相互独立，常用于垃圾邮件过滤。

-   **k-Nearest Neighbors (k-NN):** 一种简单的“基于实例”的分类器，根据某个样本最近邻的多数类别为其分配标签。

-   **Gradient Boosting Machines:** 集成模型（例如 XGBoost、LightGBM），通过依次添加较弱的学习器（通常是 Decision Trees）来构建强预测器。

下面的每个小节都会提供改进后的算法说明，以及使用 `pandas` 和 `scikit-learn` 等库的 **Python 代码示例**（神经网络示例使用 `PyTorch`）。示例使用公开可用的网络安全数据集（例如用于入侵检测的 NSL-KDD 和 Phishing Websites 数据集），并遵循一致的结构：

1.  **加载数据集**（如果有可用的 URL，则通过 URL 下载）。

2.  **预处理数据**（例如编码分类特征、缩放数值、拆分训练集和测试集）。

3.  **在训练数据上训练模型**。

4.  **在测试集上进行评估**，使用以下指标：分类任务使用 accuracy、precision、recall、F1-score 和 ROC AUC（回归任务使用 mean squared error）。

下面逐一介绍各个算法：

### Linear Regression

Linear regression 是一种用于预测连续数值的**回归**算法。它假设输入特征（自变量）与输出（因变量）之间存在线性关系。该模型尝试拟合一条直线（在高维空间中则为超平面），以最佳描述特征与目标之间的关系。通常通过最小化预测值与实际值之间的误差平方和来完成这一过程（Ordinary Least Squares method）。<sup>[[2]](#references)</sup>

表示 linear regression 最简单的方式是使用一条直线：
```plaintext
y = mx + b
```
其中：

- `y` 是预测值（输出）
- `m` 是直线的斜率（系数）
- `x` 是输入特征
- `b` 是 y 轴截距

线性回归的目标是找到一条最佳拟合直线，使预测值与数据集中的实际值之间的差异最小。当然，这非常简单，它可以是一条分隔两个类别的直线；但如果增加更多维度，这条直线就会变得更加复杂：
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *网络安全中的使用场景：* 线性回归本身在核心安全任务中并不常见（这些任务通常是分类问题），但它可以用于预测数值结果。例如，可以基于历史数据，使用线性回归来**预测网络流量的规模**或**估计某个时间段内的攻击数量**。给定特定的系统指标，它还可以预测风险评分或攻击被检测前的预期时间。在实践中，分类算法（如 logistic regression 或树模型）更常用于检测入侵或恶意软件，但线性回归可以作为基础，并且适用于面向回归的分析。

#### **线性回归的主要特征：**

-   **问题类型：** 回归（预测连续值）。除非对输出应用阈值，否则不适合直接进行分类。

-   **可解释性：** 高 —— 系数易于解释，可以体现每个特征的线性影响。

-   **优点：** 简单且快速；是回归任务的良好基线；当真实关系近似线性时效果良好。

-   **局限性：** 无法捕获复杂或非线性关系（除非手动进行特征工程）；当关系为非线性时容易欠拟合；对异常值敏感，异常值可能导致结果偏移。

-   **寻找最佳拟合：** 为了找到能够分隔可能类别的最佳拟合线，我们使用一种称为**普通最小二乘法（Ordinary Least Squares，OLS）**的方法。该方法会最小化观测值与线性模型预测值之间差异的平方和。

<details>
<summary>示例 —— 在入侵数据集中预测连接持续时间（回归）
</summary>
下面我们演示如何使用 NSL-KDD cybersecurity dataset 进行线性回归。我们将其作为一个回归问题，根据其他特征预测网络连接的 `duration`。（实际上，`duration` 是 NSL-KDD 的一个特征；这里使用它只是为了说明回归。）我们加载数据集，对其进行预处理（对分类特征进行编码），训练线性回归模型，并在测试集上评估均方误差（MSE）和 R² 分数。
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
在此示例中，线性回归模型尝试根据其他网络特征预测连接的 `duration`。我们使用均方误差（MSE）和 R² 来衡量性能。接近 1.0 的 R² 表明模型解释了 `duration` 中的大部分方差，而较低或为负的 R² 表明拟合效果较差。（如果这里的 R² 较低，请不要感到意外——根据给定特征预测 `duration` 可能比较困难；如果模式较为复杂，线性回归可能无法捕捉这些模式。）
</details>

### 逻辑回归

逻辑回归是一种**分类**算法，用于建模某个实例属于特定类别（通常是“正类”）的概率。尽管名称中包含“回归”，*逻辑*回归用于离散结果（不同于用于连续结果的线性回归）。它尤其适用于**二分类**（两个类别，例如恶意与良性），但也可以扩展到多分类问题（使用 softmax 或 one-vs-rest 方法）。<sup>[[3]](#references)</sup>

逻辑回归使用逻辑函数（也称为 sigmoid 函数）将预测值映射为概率。请注意，sigmoid 函数的取值范围在 0 到 1 之间，并根据分类需求沿 S 形曲线增长，这对二分类任务很有用。因此，每个输入的每个特征都会乘以其对应的权重，结果再通过 sigmoid 函数处理以生成一个概率：
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
其中：

- `p(y=1|x)` 表示给定输入 `x` 时输出 `y` 为 1 的概率
- `e` 是自然对数的底数
- `z` 是输入特征的线性组合，通常表示为 `z = w1*x1 + w2*x2 + ... + wn*xn + b`。注意，在最简单的形式中，它同样是一条直线；但在更复杂的情况下，它会变成具有多个维度的超平面（每个特征对应一个维度）。

> [!TIP]
> *网络安全中的使用场景：* 由于许多安全问题本质上都是是/否决策，因此 Logistic Regression 得到了广泛使用。例如，入侵检测系统可以根据网络连接的特征，使用 Logistic Regression 判断该连接是否属于攻击。在 phishing 检测中，Logistic Regression 可以将网站的多个特征（URL 长度、是否存在“@”符号等）组合成该网站属于 phishing 的概率。它曾被用于早期的 spam 过滤器，并且仍然是许多分类任务的强大基线模型。

#### 用于非二分类的 Logistic Regression

Logistic Regression 是为二分类设计的，但可以使用 **one-vs-rest**（OvR）或 **softmax regression** 等技术扩展到多分类问题。在 OvR 中，会为每个类别分别训练一个 Logistic Regression 模型，将该类别视为正类、其他所有类别视为负类。最终选择预测概率最高的类别。Softmax regression 则通过对输出层应用 softmax 函数，将 Logistic Regression 扩展到多个类别，并生成所有类别上的概率分布。

#### **Logistic Regression 的关键特征：**

-   **问题类型：** 分类（通常为二分类）。它预测正类的概率。

-   **可解释性：** 高——与线性回归类似，特征系数可以表示每个特征如何影响结果的对数几率。这种透明性在安全领域通常很受重视，因为它有助于理解哪些因素导致了告警。

-   **优势：** 训练简单且快速；当特征与结果对数几率之间呈线性关系时，效果良好。它能输出概率，从而支持风险评分。通过适当的正则化，它具有良好的泛化能力，并且比普通线性回归更能处理多重共线性。

-   **局限性：** 假设特征空间中的决策边界是线性的（如果真实边界复杂或非线性，则效果会较差）。除非手动添加多项式特征或交互特征，否则在特征交互或非线性影响至关重要的问题上可能表现不佳。此外，如果类别无法通过特征的线性组合轻易分离，Logistic Regression 的效果也会较弱。


<details>
<summary>示例 -- 使用 Logistic Regression 检测 Phishing 网站：</summary>

我们将使用 **Phishing Websites Dataset**（来自 UCI repository），该数据集包含从网站中提取的特征（例如 URL 是否包含 IP 地址、域名的使用年限、HTML 中是否存在可疑元素等），以及表示网站是 phishing 还是合法网站的标签。<sup>[[4]](#references)</sup> 我们训练一个 Logistic Regression 模型对网站进行分类，然后在测试集划分上评估其 accuracy、precision、recall、F1-score 和 ROC AUC。
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
在这个 phishing detection 示例中，logistic regression 会为每个网站生成其属于 phishing 的概率。通过评估 accuracy、precision、recall 和 F1，我们可以了解模型的性能。例如，较高的 recall 表示它能够捕获大多数 phishing 网站（这对安全性很重要，因为可以尽量减少漏检的攻击），而较高的 precision 表示误报较少（这有助于避免分析人员疲劳）。ROC AUC（Area Under the ROC Curve）提供了一种与阈值无关的性能衡量方式（1.0 表示理想性能，0.5 表示不优于随机猜测）。logistic regression 通常在此类任务中表现良好，但如果 phishing 网站与合法网站之间的 decision boundary 较为复杂，可能就需要功能更强的非线性模型。

</details>

### 决策树

决策树是一种用途广泛的 **supervised learning algorithm**，可用于 classification 和 regression 任务。它会根据数据的特征，学习一个层次化的树状决策模型。树中的每个 internal node 表示对某个特定特征进行测试，每个 branch 表示该测试的一种结果，而每个 leaf node 表示预测的类别（用于 classification）或值（用于 regression）。<sup>[[5]](#references)</sup>

为了构建一棵树，CART（Classification and Regression Tree）等算法会使用 **Gini impurity** 或 **information gain (entropy)** 等指标，在每一步选择最佳特征和阈值来切分数据。每次切分的目标都是对数据进行分区，从而提高结果子集中的目标变量同质性（对于 classification，每个节点都力求尽可能纯，即主要包含单一类别）。

决策树具有 **高度可解释性** -- 人们可以沿着从根节点到叶节点的路径，理解某个预测背后的逻辑（例如，*“IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack”*）。这对于 cybersecurity 中解释某个警报为何被触发非常有价值。树可以自然地处理数值型和类别型数据，并且只需要很少的预处理（例如，不需要进行 feature scaling）。

然而，单棵决策树很容易对 training data 过拟合，尤其是在树生长得很深（包含许多切分）时。通常会使用 pruning（限制树的深度或要求每个叶节点至少包含一定数量的样本）等技术来防止过拟合。

决策树有 3 个主要组成部分：
- **Root Node**：树的顶层节点，表示整个数据集。
- **Internal Nodes**：表示特征以及基于这些特征所作决策的节点。
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
> *网络安全中的应用场景：* Decision trees 已被用于入侵检测系统，以推导用于识别攻击的 **规则**。例如，早期基于 ID3/C4.5 的 IDS 会生成人类可读的规则，用于区分正常流量和恶意流量。它们也用于 malware analysis，根据文件的属性（文件大小、section entropy、API calls 等）判断文件是否为恶意文件。Decision trees 的清晰性使其适用于需要透明度的场景 -- 分析人员可以检查该树，以验证检测逻辑。

#### **Decision Trees 的主要特征：**

-   **问题类型：** 分类和回归。常用于将攻击与正常流量等进行分类。

-   **可解释性：** 非常高 -- 模型的决策可以可视化，并理解为一组 if-then 规则。这是安全领域中的一项主要优势，有助于建立对模型行为的信任并进行验证。

-   **优势：** 能够捕获特征之间的非线性关系和交互（每次分裂都可以视为一种交互）。无需对特征进行缩放或对分类变量进行 one-hot encode -- trees 原生支持这些变量。推理速度快（prediction 只需沿着 tree 中的一条路径进行）。

-   **局限性：** 如果不加以控制，容易 overfitting（深层 tree 可能会记住 training set）。它们可能不稳定 -- 数据中的微小变化可能导致不同的 tree 结构。作为单一模型，其准确率可能不如更先进的方法（Random Forests 等 ensembles 通常通过降低 variance 来获得更好的表现）。

-   **寻找最佳分裂：**
- **Gini Impurity**：衡量节点的不纯度。较低的 Gini impurity 表示更好的分裂。公式如下：

```plaintext
Gini = 1 - Σ(p_i^2)
```

其中，`p_i` 是类别 `i` 中实例所占的比例。

- **Entropy**：衡量数据集中的不确定性。较低的 entropy 表示更好的分裂。公式如下：

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

其中，`p_i` 是类别 `i` 中实例所占的比例。

- **Information Gain**：分裂后 entropy 或 Gini impurity 的减少量。information gain 越高，分裂效果越好。其计算方式如下：

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

此外，在以下情况下，tree 会结束：
- 节点中的所有实例都属于同一类别。这可能导致 overfitting。
- 达到 tree 的最大深度（hardcoded）。这是防止 overfitting 的一种方式。
- 节点中的实例数量低于某个阈值。这同样是防止 overfitting 的一种方式。
- 进一步分裂所带来的 information gain 低于某个阈值。这同样是防止 overfitting 的一种方式。

<details>
<summary>示例 -- 用于入侵检测的 Decision Tree：</summary>
我们将在 NSL-KDD 数据集上训练一个 decision tree，将网络连接分类为 *normal* 或 *attack*。NSL-KDD 是经典 KDD Cup 1999 数据集的改进版本，包含 protocol type、service、duration、failed logins 次数等特征，以及用于标记攻击类型或 "normal" 的标签。我们会将所有攻击类型映射到 "anomaly" 类别（二分类：normal 与 anomaly）。训练完成后，我们将在 test set 上评估该 tree 的表现。
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
在这个 decision tree 示例中，我们将树深度限制为 10，以避免严重的 overfitting（`max_depth=10` 参数）。这些指标展示了该树区分正常流量与攻击流量的效果。较高的 recall 意味着它能够捕获大多数攻击（这对 IDS 很重要），而较高的 precision 则意味着误报较少。Decision trees 通常能在结构化数据上取得不错的 accuracy，但单棵树可能无法达到最佳性能。不过，该模型的 *interpretability* 是一个很大的优势——我们可以检查树的分裂情况，了解哪些特征（例如 `service`、`src_bytes` 等）在将连接标记为恶意连接时最具影响力。

</details>

### Random Forests

Random Forest 是一种基于 decision trees 构建、用于提升性能的 **ensemble learning** 方法。Random forest 会训练多棵 decision trees（因此称为“forest”），并结合它们的输出以生成最终预测（对于 classification，通常采用多数投票）。Random forest 的两个主要理念是 **bagging**（bootstrap aggregating）和 **feature randomness**：

-   **Bagging：** 每棵树都使用从 training data 中随机抽取的 bootstrap sample 进行训练（有放回抽样）。这会增加树之间的多样性。

-   **Feature Randomness：** 在树的每次分裂时，只考虑随机选取的部分 features 进行分裂（而不是所有 features）。这会进一步降低树之间的相关性。

通过对许多树的结果取平均，random forest 降低了单棵 decision tree 可能产生的 variance。简单来说，单棵树可能会 overfit 或包含噪声，但大量具有多样性的树共同投票，可以平滑这些错误。最终得到的模型通常比单棵 decision tree 具有 **更高的 accuracy** 和更好的 generalization。此外，random forests 还可以提供 feature importance 的估计（通过观察每个 feature split 平均减少了多少 impurity）。

Random forests 已成为 **cybersecurity** 中的 **workhorse**，可用于 intrusion detection、malware classification 和 spam detection 等任务。它们通常无需大量 tuning 就能取得良好效果，并且能够处理 large feature sets。例如，在 intrusion detection 中，random forest 可能通过捕获更细微的攻击模式并减少 false positives，胜过单棵 decision tree。研究表明，在 NSL-KDD 和 UNSW-NB15 等 datasets 中对攻击进行 classification 时，random forests 的表现优于其他 algorithms。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Random Forests 的关键特征：**

-   **Type of Problem：** 主要用于 classification（也可用于 regression）。非常适合处理 security logs 中常见的 high-dimensional structured data。

-   **Interpretability：** 低于单棵 decision tree——你无法轻松地同时可视化或解释数百棵树。不过，feature importance scores 可以帮助了解哪些 attributes 最具影响力。

-   **Advantages：** 由于 ensemble effect，accuracy 通常高于 single-tree models。对 overfitting 具有较强的抵抗力——即使单棵树发生 overfit，ensemble 也能更好地进行 generalization。能够处理 numerical 和 categorical features，并且可以在一定程度上处理 missing data。此外，它对 outliers 也相对稳健。

-   **Limitations：** Model size 可能很大（包含许多树，并且每棵树都可能很深）。Prediction 速度比单棵树慢（因为必须对许多树的结果进行聚合）。Interpretability 较低——虽然你知道哪些 features 很重要，但其确切逻辑不像简单规则那样容易追踪。如果 dataset 极其 high-dimensional 且 sparse，训练非常大的 forest 可能会带来较高的 computational 开销。

-   **Training Process：**
1. **Bootstrap Sampling**：对 training data 进行有放回的随机抽样，以创建多个 subsets（bootstrap samples）。
2. **Tree Construction**：针对每个 bootstrap sample，使用每次 split 时随机选取的 features 子集构建一棵 decision tree。这会增加树之间的多样性。
3. **Aggregation**：对于 classification tasks，最终 prediction 通过所有树的 predictions 进行多数投票得出。对于 regression tasks，最终 prediction 是所有树 predictions 的平均值。

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD)：</summary>
我们将使用相同的 NSL-KDD dataset（以 normal 与 anomaly 进行 binary labeling），并训练一个 Random Forest classifier。由于 ensemble averaging 可以降低 variance，我们预计 random forest 的表现至少会与单棵 decision tree 相当，甚至更好。我们将使用相同的 metrics 对其进行评估。
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
随机森林通常能够在此 intrusion detection 任务中取得良好效果。与单一决策树相比，我们可能会观察到 F1 或 AUC 等指标有所提升，尤其是在 recall 或 precision 方面，具体取决于数据。这与以下理解一致：*"Random Forest (RF) 是一种 ensemble classifier，与其他传统 classifiers 相比，能够更有效地对 attacks 进行分类。"*。<sup>[[6]](#references)</sup> 在 security operations 场景中，random forest model 可能更可靠地标记 attacks，同时减少 false alarms，这得益于对大量决策规则进行平均。森林生成的 feature importance 还可以告诉我们哪些 network features 最能表明 attacks（例如某些 network services 或异常的 packet 计数）。

</details>

### Support Vector Machines (SVM)

Support Vector Machines 是功能强大的 supervised learning models，主要用于 classification（也可通过 SVR 用于 regression）。SVM 尝试寻找能够最大化两个 classes 之间 margin 的 **optimal separating hyperplane**。只有部分 training points（最接近边界的“support vectors”）决定该 hyperplane 的位置。通过最大化 margin（support vectors 与 hyperplane 之间的距离），SVM 往往能够实现良好的 generalization。<sup>[[8]](#references)</sup>

SVM 强大之处的关键在于能够使用 **kernel functions** 处理非线性关系。数据可以被隐式转换到更高维的 feature space，在其中可能存在 linear separator。常见的 kernels 包括 polynomial、radial basis function (RBF) 和 sigmoid。例如，如果 network traffic classes 在原始 feature space 中不是线性可分的，RBF kernel 可以将它们映射到更高维空间，使 SVM 找到一个 linear split（对应于原始空间中的 non-linear boundary）。选择不同 kernels 的灵活性使 SVM 能够应对各种问题。

SVM 在高维 feature spaces（例如 text data 或 malware opcode sequences）以及 features 数量相对于 samples 较多的情况下通常表现良好。2000 年代，SVM 曾广泛应用于许多早期 cybersecurity 场景，例如 malware classification 和基于 anomaly 的 intrusion detection，并且通常能够取得较高的 accuracy。

但是，SVM 不容易扩展到非常大的 datasets（training complexity 相对于 samples 数量呈 super-linear 增长，而且 memory usage 可能很高，因为它可能需要存储大量 support vectors）。在实际应用中，对于包含 millions of records 的 network intrusion detection 等任务，如果不进行谨慎的 subsampling 或使用 approximate methods，SVM 可能会过慢。

#### **SVM 的主要特征：**

-   **问题类型：** Classification（binary 或 multiclass，可通过 one-vs-one/one-vs-rest 实现）以及 regression variants。通常用于具有清晰 margin separation 的 binary classification。

-   **可解释性：** 中等 —— SVM 的可解释性不如 decision trees 或 logistic regression。虽然可以识别哪些 data points 是 support vectors，并通过 linear kernel 情况下的 weights 大致了解哪些 features 可能具有影响力，但在实际应用中，SVM（尤其是使用 non-linear kernels 时）通常被视为 black-box classifiers。

-   **优势：** 在 high-dimensional spaces 中有效；可以通过 kernel trick 对复杂的 decision boundaries 进行建模；如果 margin 被最大化，则能够抵抗 overfitting（尤其是在使用适当的 regularization parameter C 时）；即使 classes 并未被较大距离分隔，也能表现良好（能够找到最佳折中边界）。

-   **局限性：** 对大型 datasets **计算开销很高**（training 和 prediction 都会随着 data 增长而表现出较差的扩展性）。需要仔细调整 kernel 和 regularization parameters（C、kernel type、RBF 的 gamma 等）。不会直接提供 probabilistic outputs（不过可以使用 Platt scaling 获取 probabilities）。此外，SVM 可能对 kernel parameters 的选择较为敏感 —— 选择不当可能导致 underfit 或 overfit。

*在 cybersecurity 中的使用场景：* SVM 已被用于 **malware detection**（例如根据提取的 features 或 opcode sequences 对 files 进行分类）、**network anomaly detection**（将 traffic 分类为 normal 或 malicious）以及 **phishing detection**（使用 URLs 的 features）。例如，SVM 可以获取 email 的 features（某些 keywords 的计数、sender reputation scores 等），并将其分类为 phishing 或 legitimate。SVM 也被应用于 KDD 等 feature sets 上的 **intrusion detection**，通常能够以较高的 computation cost 换取较高的 accuracy。

<details>
<summary>示例 -- SVM 用于 Malware Classification：</summary>
我们将再次使用 phishing website dataset，这次使用 SVM。由于 SVM 可能运行缓慢，如果需要，我们将使用部分 data 进行 training（该 dataset 约包含 11k 个 instances，SVM 可以较为合理地处理）。我们将使用 RBF kernel，这是处理 non-linear data 时的常见选择，并启用 probability estimates 以计算 ROC AUC。
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
SVM 模型将输出指标，我们可以将其与同一任务上的逻辑回归进行比较。如果数据通过特征能够被良好分离，我们可能会发现 SVM 达到较高的准确率和 AUC。反过来，如果数据集包含大量噪声或类别相互重叠，SVM 可能不会显著优于逻辑回归。在实践中，当特征与类别之间存在复杂的非线性关系时，SVM 可以带来提升——RBF kernel 能够捕获逻辑回归无法识别的弯曲决策边界。与所有模型一样，需要仔细调整 `C`（正则化）和 kernel 参数（例如 RBF 的 `gamma`），以平衡偏差和方差。

</details>

#### 逻辑回归与 SVM 的差异

| Aspect | **逻辑回归** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | 最小化 **log-loss**（交叉熵）。 | 在最小化 **hinge-loss** 的同时最大化**间隔**。 |
| **Decision boundary** | 找到能够对 _P(y\|x)_ 建模的**最佳拟合超平面**。 | 找到**最大间隔超平面**（与最近点之间间隔最大的超平面）。 |
| **Output** | **概率型**——通过 σ(w·x + b) 提供经过校准的类别概率。 | **确定型**——返回类别标签；概率需要额外处理（例如 Platt scaling）。 |
| **Regularisation** | L2（默认）或 L1，直接平衡欠拟合与过拟合。 | C 参数在间隔宽度与误分类之间进行权衡；kernel 参数会增加复杂度。 |
| **Kernels / Non‑linear** | 原生形式是**线性的**；通过 feature engineering 添加非线性。 | 内置 **kernel trick**（RBF、poly 等），可以在高维空间中建模复杂边界。 |
| **Scalability** | 在 **O(nd)** 中求解凸优化；能够良好处理非常大的 n。 | 如果没有专用求解器，训练的内存/时间复杂度可能达到 **O(n²–n³)**；对超大 n 不太友好。 |
| **Interpretability** | **高**——权重显示特征影响；odds ratio 直观易懂。 | 非线性 kernel 的**可解释性低**；support vectors 虽然稀疏，但不易解释。 |
| **Sensitivity to outliers** | 使用平滑的 log-loss，因此不太敏感。 | 使用 hard margin 时的 hinge-loss 可能**对异常值敏感**；soft-margin（C）可以缓解这一问题。 |
| **Typical use cases** | 信用评分、医疗风险、A/B 测试——适合重视**概率与可解释性**的场景。 | 图像/文本分类、生物信息学——适合重视**复杂边界**和**高维数据**的场景。 |

* **如果你需要经过校准的概率、可解释性，或需要处理超大数据集——选择逻辑回归。**
* **如果你需要一个无需手动进行 feature engineering、能够捕获非线性关系的灵活模型——选择 SVM（使用 kernel）。**
* 两者都优化凸目标函数，因此**可以保证得到全局最小值**；但 SVM 的 kernel 会增加超参数和计算成本。

### 朴素贝叶斯

朴素贝叶斯是一类**概率分类器**，其基础是应用贝叶斯定理，并对特征之间做出强独立性假设。尽管这一假设相当“朴素”，朴素贝叶斯在某些应用中仍然常常表现得出人意料地好，尤其适用于涉及文本或类别数据的场景，例如 spam detection。<sup>[[9]](#references)</sup>


#### 贝叶斯定理

贝叶斯定理是朴素贝叶斯分类器的基础。它描述了随机事件的条件概率与边缘概率之间的关系。公式如下：
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
其中：
- `P(A|B)` 是给定特征 `B` 时类别 `A` 的后验概率。
- `P(B|A)` 是给定类别 `A` 时特征 `B` 的似然。
- `P(A)` 是类别 `A` 的先验概率。
- `P(B)` 是特征 `B` 的先验概率。

例如，如果我们想分类一段文本是由儿童还是成年人撰写的，可以使用文本中的单词作为特征。基于一些初始数据，Naive Bayes classifier 会预先计算每个单词属于每个潜在类别（儿童或成年人）的概率。当给定一段新文本时，它会根据文本中的单词计算每个潜在类别的概率，并选择概率最高的类别。

如本例所示，Naive Bayes classifier 非常简单且快速，但它假设各个特征彼此独立，而这在现实世界的数据中并不总是成立。


#### Naive Bayes Classifiers 的类型

根据数据类型和特征的分布，Naive Bayes classifiers 有多种类型：
- **Gaussian Naive Bayes**：假设特征遵循 Gaussian（正态）分布。适用于连续数据。
- **Multinomial Naive Bayes**：假设特征遵循多项式分布。适用于离散数据，例如文本分类中的单词计数。
- **Bernoulli Naive Bayes**：假设特征是二进制的（0 或 1）。适用于二进制数据，例如文本分类中单词的存在或缺失。
- **Categorical Naive Bayes**：假设特征是分类变量。适用于分类数据，例如根据水果的颜色和形状对其进行分类。


#### **Naive Bayes 的关键特征：**

-   **问题类型：**分类（二分类或多分类）。常用于 cybersecurity 中的文本分类任务（spam、phishing 等）。

-   **可解释性：**中等 -- 它不像 decision tree 那样具有直接的可解释性，但可以检查学习到的概率（例如，哪些单词最有可能出现在 spam 与 ham 邮件中）。如有需要，可以理解模型的形式（给定类别时各个特征的概率）。

-   **优势：****训练和预测速度非常快**，即使面对大型数据集也是如此（复杂度与实例数 * 特征数呈线性关系）。只需相对少量的数据即可可靠地估计概率，尤其是在采用适当 smoothing 的情况下。它通常是一个出人意料地准确的 baseline，尤其是在各个特征独立地为类别提供证据时。它适用于高维数据（例如文本中的数千个特征）。除了设置 smoothing 参数外，通常不需要复杂的调优。

-   **局限性：**如果特征高度相关，独立性假设可能会限制准确性。例如，在 network data 中，`src_bytes` 和 `dst_bytes` 等特征可能存在相关性；Naive Bayes 无法捕获这种交互。随着数据规模变得非常大，更具表现力的模型（例如 ensembles 或 neural nets）可以通过学习特征依赖关系超越 NB。此外，如果识别某种 attack 需要某些特征组合（而不只是各个独立特征），NB 将难以应对。

> [!TIP]
> *在 cybersecurity 中的使用场景：*经典用途是 **spam detection** -- Naive Bayes 是早期 spam filters 的核心，通过使用某些 token（单词、短语、IP addresses）的频率来计算一封邮件属于 spam 的概率。它还用于 **phishing email detection** 和 **URL classification**，其中某些关键词或特征的存在（例如 URL 中的 "login.php"，或 URL path 中的 `@`）会影响 phishing 概率。在 malware analysis 中，可以设想使用 Naive Bayes classifier，根据软件中是否存在某些 API calls 或 permissions 来预测其是否为 malware。尽管更高级的 algorithms 通常表现更好，但 Naive Bayes 凭借其速度和简洁性，仍然是一个不错的 baseline。

<details>
<summary>示例 -- 用于 Phishing Detection 的 Naive Bayes：</summary>
为了演示 Naive Bayes，我们将在 NSL-KDD intrusion dataset（带有 binary labels）上使用 Gaussian Naive Bayes。Gaussian NB 会将每个特征视为在每个类别中都遵循正态分布。这是一个较为粗略的选择，因为许多 network features 是离散的或高度偏斜的，但它展示了如何将 NB 应用于连续特征数据。我们也可以在 binary features 数据集（例如一组 triggered alerts）上选择 Bernoulli NB，但为了保持连续性，这里将使用 NSL-KDD。
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
这段代码训练了一个 Naive Bayes 分类器来检测攻击。Naive Bayes 会基于训练数据计算诸如 `P(service=http | Attack)` 和 `P(Service=http | Normal)` 之类的概率，并假设各个特征之间相互独立。随后，它会根据观测到的特征，使用这些概率将新连接分类为正常或攻击。NB 在 NSL-KDD 上的性能可能不如更先进的模型（因为特征独立性这一假设并不成立），但通常表现尚可，并且具有极高速度的优势。在实时电子邮件过滤或 URL 初步分类等场景中，Naive Bayes 模型可以以较低的资源开销快速标记明显的恶意情况。

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors 是最简单的 machine learning algorithms 之一。这是一种**非参数、基于实例**的方法，根据样本与 training set 中示例的相似性进行预测。其分类思路是：要对一个新的数据点进行分类，就在 training data 中找到距离最近的 **k** 个点（即它的“nearest neighbors”），然后将这些邻居中占多数的类别分配给该数据点。“接近程度”由距离度量定义，numeric data 通常使用 Euclidean distance（针对不同类型的特征或问题，也可以使用其他距离）。<sup>[[10]](#references)</sup>

K-NN **不需要显式训练**——“训练”阶段实际上只是存储数据集。所有计算都发生在查询（预测）阶段：算法必须计算查询点与所有 training points 之间的距离，以找到最近的点。因此，预测时间与 training samples 的数量呈**线性关系**，在大型数据集上可能代价高昂。基于这一点，k-NN 更适合较小的数据集，或适合用内存和速度换取简单性的场景。

尽管 k-NN 很简单，但它可以建模非常复杂的决策边界（因为实际上，决策边界可以是由示例分布决定的任意形状）。当决策边界非常不规则且拥有大量数据时，它往往表现良好——本质上是让数据“自行表达”。不过，在高维空间中，距离度量可能变得不太有意义（维度灾难），除非拥有海量样本，否则该方法可能难以取得良好效果。

*在网络安全中的应用：* k-NN 已被应用于异常检测——例如，如果某个网络事件的大多数最近邻（之前的事件）都是恶意的，入侵检测系统就可能将该网络事件标记为恶意。如果正常流量形成多个簇，而攻击属于离群点，那么 K-NN 方法（使用 k=1 或较小的 k）本质上就是一种**最近邻异常检测**。K-NN 还被用于通过 binary feature vectors 对 malware families 进行分类：如果一个新文件在特征空间中与某个 malware family 的已知实例非常接近，就可能被归类到该 malware family。实际上，与更具可扩展性的 algorithms 相比，k-NN 并不常用，但它概念直观，有时会被用作 baseline，或用于小规模问题。

#### **k-NN 的主要特征：**

-   **问题类型：** 分类（也存在回归变体）。它是一种 *lazy learning* 方法——不进行显式的模型拟合。

-   **可解释性：** 低到中等——不存在全局模型或简洁的解释，但可以通过查看影响决策的最近邻来解释结果（例如：“该网络流被分类为恶意，是因为它与这 3 个已知的恶意流相似。”）。因此，解释可以基于示例。

-   **优势：** 实现和理解都非常简单。不对数据分布作任何假设（非参数）。可以自然地处理多分类问题。从某种意义上说，它具有**自适应性**，因为决策边界可以非常复杂，并由数据分布塑造。

-   **局限性：** 在大型数据集上预测可能较慢（必须计算大量距离）。占用内存较多——它会存储全部 training data。在高维特征空间中，性能会下降，因为所有点往往变得几乎等距（使“最近”的概念不再那么有意义）。需要适当选择 *k*（邻居数量）——k 太小可能导致结果包含较多噪声，k 太大则可能纳入其他类别中的无关点。此外，应适当缩放特征，因为距离计算对尺度非常敏感。

<details>
<summary>示例——使用 k-NN 进行 Phishing Detection：</summary>

我们仍将使用 NSL-KDD（二分类）。由于 k-NN 的计算开销较大，在本演示中我们将使用 training data 的一个子集，以确保计算量处于可接受范围。比如，我们从完整的 125k 个样本中选取 20,000 个 training samples，并使用 k=5 个邻居。训练之后（实际上只是存储数据），我们将在 test set 上进行评估。我们还会对特征进行缩放，以便计算距离，确保不会因为尺度差异而让某个特征占据主导地位。
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
k-NN 模型会查看训练集子集中距离最近的 5 个连接，并据此对某个连接进行分类。例如，如果其中 4 个邻居属于 attacks（anomalies），而 1 个属于正常连接，则新连接会被分类为 attack。其性能可能尚可，但通常不如在相同数据上经过良好调优的 Random Forest 或 SVM。不过，当类别分布非常不规则且复杂时，k-NN 有时会表现出色——实际上相当于使用基于记忆的查找。在 cybersecurity 中，k-NN（k=1 或较小的 k）可用于通过示例检测已知的 attack patterns，也可以作为更复杂系统的组成部分（例如用于 clustering，然后根据 cluster membership 进行分类）。
</details>

### Gradient Boosting Machines（例如 XGBoost）

Gradient Boosting Machines 是处理结构化数据时最强大的算法之一。**Gradient boosting** 指的是以顺序方式构建 weak learners（通常是 decision trees）ensemble 的技术，其中每个新模型都会纠正前一个 ensemble 的错误。不同于并行构建 tree 并对其结果取平均的 bagging（Random Forests），boosting 会*逐棵*构建 tree，每棵 tree 都更加关注前面的 tree 预测错误的实例。<sup>[[11]](#references)</sup>

近年来最流行的实现包括 **XGBoost**、**LightGBM** 和 **CatBoost**，它们都是 gradient boosting decision tree（GBDT）library。它们在 machine learning competitions 和实际应用中都取得了极大成功，通常能够在 **tabular datasets 上达到 state-of-the-art performance**。在 cybersecurity 中，研究人员和从业者使用 gradient boosted trees 执行 **malware detection**（使用从文件或运行时行为中提取的 features）和 **network intrusion detection** 等任务。例如，gradient boosting model 可以将许多 weak rules（trees）组合起来，例如“如果 SYN packets 很多且端口异常 -> 可能是 scan”，从而形成一个能够考虑许多细微模式的强大 composite detector。

为什么 boosted trees 如此有效？序列中的每棵 tree 都会根据当前 ensemble 预测的 *residual errors*（gradients）进行训练。这样，模型就能逐步 **“boost”** 自身薄弱的区域。使用 decision trees 作为 base learners，意味着最终模型可以捕获复杂的交互关系和非线性关系。此外，boosting 天然具有某种内置 regularization：通过添加许多 small trees（并使用 learning rate 缩放它们的贡献），只要选择适当的 parameters，模型通常就能在不过度 overfitting 的情况下实现良好的泛化。

#### **Gradient Boosting 的关键特征：**

-   **问题类型：** 主要用于 classification 和 regression。在 security 中，通常用于 classification（例如对 connection 或 file 进行 binary classify）。它支持 binary、multi-class（使用适当的 loss）以及 ranking problems。

-   **可解释性：** 低到中等。虽然单个 boosted tree 较小，但完整模型可能包含数百棵 tree，整体上无法由人直接解释。不过，与 Random Forest 类似，它可以提供 feature importance scores；同时也可以使用 SHAP（SHapley Additive exPlanations）等 tools，在一定程度上解释单个 predictions。

-   **优势：** 通常是 structured/tabular data 上**性能最佳**的算法。它能够检测复杂的 patterns 和 interactions。它提供许多 tuning knobs（tree 数量、tree 深度、learning rate、regularization terms），可用于调整 model complexity 并防止 overfitting。现代实现针对速度进行了优化（例如，XGBoost 使用 second-order gradient info 和高效的数据结构）。结合适当的 loss functions 或调整 sample weights 后，它通常能够更好地处理 imbalanced data。

-   **局限性：** 比简单模型更难调优；如果 tree 较深或 tree 数量较多，training 可能较慢（不过在相同数据上，通常仍比 training 可比的 deep neural network 更快）。如果没有适当调优，模型可能会 overfit（例如，deep trees 过多且 regularization 不足）。由于 hyperparameters 较多，有效使用 gradient boosting 可能需要更多 expertise 或 experimentation。此外，与 tree-based methods 一样，它并不能像 linear models 或 Naive Bayes 那样高效地处理非常 sparse 的 high-dimensional data（尽管仍可应用，例如用于 text classification，但如果没有 feature engineering，通常不会是首选）。

> [!TIP]
> *在 cybersecurity 中的使用场景：* 几乎所有可以使用 decision tree 或 random forest 的地方，都可以尝试 gradient boosting model，并可能获得更高的 accuracy。例如，**Microsoft 的 malware detection** competitions 大量使用了基于 binary files engineered features 的 XGBoost。**Network intrusion detection** 研究经常报告 GBDTs 的最佳结果（例如，在 CIC-IDS2017 或 UNSW-NB15 datasets 上使用 XGBoost）。这些 models 可以接收范围广泛的 features（protocol types、某些 events 的 frequency、traffic 的 statistical features 等），并将它们组合起来检测 threats。在 phishing detection 中，gradient boosting 可以结合 URLs 的 lexical features、domain reputation features 和 page content features，从而实现非常高的 accuracy。ensemble 方法有助于覆盖 data 中的各种 corner cases 和细微特征。

<details>
<summary>示例 -- XGBoost 用于 Phishing Detection：</summary>
我们将对 phishing dataset 使用 gradient boosting classifier。为保持简单且自包含，我们将使用 `sklearn.ensemble.GradientBoostingClassifier`（这是一个速度较慢但实现直接的版本）。通常，也可以使用 `xgboost` 或 `lightgbm` libraries，以获得更好的 performance 和更多 features。我们将训练该 model，并采用与之前类似的方式对其进行评估。
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
梯度提升模型很可能会在这个 phishing 数据集上取得非常高的 accuracy 和 AUC（在这类数据上经过适当调优后，这些模型的 accuracy 通常可以超过 95%，文献中也有相关体现。这说明了为什么 GBDTs 被认为是 *"the state of the art model for tabular dataset"*——它们能够捕获复杂模式，因此通常优于更简单的算法。<sup>[[11]](#references)</sup> 在 cybersecurity 场景中，这意味着能够发现更多 phishing sites 或 attacks，同时减少漏报。当然，必须警惕 overfitting——在开发用于部署的模型时，我们通常会使用 cross-validation 等技术，并监控其在 validation set 上的性能。

</details>

### 组合模型：Ensemble Learning 与 Stacking

Ensemble learning 是一种通过**组合多个模型**来提升整体性能的策略。我们已经了解过一些具体的 ensemble 方法：Random Forest（通过 bagging 组合多棵树）和 Gradient Boosting（通过 sequential boosting 组合多棵树）。不过，ensemble 也可以通过其他方式构建，例如 **voting ensembles** 或 **stacked generalization (stacking)**。其核心思想是，不同模型可能捕获不同的模式，或者具有不同的弱点；通过组合它们，可以利用一个模型的优势来**弥补另一个模型的错误**。<sup>[[12]](#references)</sup>

-   **Voting Ensemble：** 在一个简单的 voting classifier 中，我们训练多个具有差异性的模型（例如 logistic regression、decision tree 和 SVM），然后让它们对最终预测进行投票（classification 使用多数投票）。如果我们为投票设置权重（例如为更准确的模型设置更高权重），则称为加权投票方案。当各个模型本身表现较好且彼此独立时，这通常能够提升性能——由于其他模型可能纠正某个模型的错误，ensemble 可以降低单个模型出错的风险。这就像拥有一个专家小组，而不是只听取单一意见。

-   **Stacking (Stacked Ensemble)：** Stacking 更进一步。它不是进行简单投票，而是训练一个 **meta-model**，以**学习如何最佳地组合**基础模型的预测结果。例如，你可以训练 3 个不同的 classifiers（base learners），然后将它们的输出（或 probabilities）作为 features 输入 meta-classifier（通常是 logistic regression 之类的简单模型），由后者学习最佳的融合方式。为避免 overfitting，meta-model 会在 validation set 上训练，或通过 cross-validation 进行训练。Stacking 通常能够通过学习*在不同情况下应该更加信任哪些模型*，从而优于简单投票。在 cybersecurity 中，一个模型可能更擅长发现 network scans，而另一个模型可能更擅长发现 malware beaconing；stacking model 可以学习在不同情况下适当地依赖它们。

无论是通过 voting 还是 stacking，Ensembles 往往都能**提升 accuracy**和稳健性。其缺点是复杂度增加，有时 interpretability 也会降低（不过，一些 ensemble 方法，例如对 decision trees 取平均，仍然可以提供一定的洞察，例如 feature importance）。在实践中，如果 operational constraints 允许，使用 ensemble 可以带来更高的 detection rates。许多 cybersecurity challenges 中的获胜方案（以及一般的 Kaggle competitions）都会使用 ensemble 技术来榨取最后一点性能提升。

<details>
<summary>示例 -- 用于 Phishing Detection 的 Voting Ensemble：</summary>
为了说明 model stacking，我们将组合前面在 phishing dataset 上讨论过的几个模型。我们会使用 logistic regression、decision tree 和 k-NN 作为 base learners，并使用 Random Forest 作为 meta-learner 来聚合它们的预测结果。meta-learner 将基于 base learners 的输出进行训练（在 training set 上使用 cross-validation）。我们预计 stacked model 的表现将与各个单独模型相当，或略胜一筹。
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
stacked ensemble 利用了 base models 之间互补的优势。例如，logistic regression 可能负责处理数据的线性部分，decision tree 可能捕捉特定的类规则交互，而 k-NN 可能擅长处理 feature space 中的局部邻域。meta-model（这里是 random forest）可以学习如何对这些输入进行加权。最终指标通常会比任一单独模型的指标有所提升（即使提升幅度很小）。在我们的 phishing 示例中，如果单独使用 logistic 的 F1 为 0.95、tree 的 F1 为 0.94，那么 stack 可能通过弥补各模型的错误，将 F1 提升到 0.96。

像这样的 ensemble methods 展示了这样一个原则：*"组合多个模型通常可以带来更好的泛化能力"*。<sup>[[12]](#references)</sup> 在 cybersecurity 中，可以部署多个 detection engines（其中一个可能基于规则，一个基于 machine learning，另一个基于 anomaly），然后通过一个聚合其 alerts 的层——实际上是一种 ensemble——以更高的置信度做出最终决策。部署此类系统时，必须考虑额外的复杂性，并确保 ensemble 不会变得过于难以管理或解释。但从准确率角度来看，ensembles 和 stacking 是提升模型性能的强大工具。

</details>

[deep-learning page](AI-Deep-Learning.md) 中介绍的 neural-network approaches 可以在数据集和 compute budget 足以支持额外复杂性的情况下，与这些 classical models 互补，用于 intrusion detection。<sup>[[13]](#references)</sup>

## References

- [1] [AI 和 machine learning 在 cybersecurity 中的应用 - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression，详解 - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "使用 machine learning 和多个数据集对 phishing attacks 和 websites 进行分类（比较分析）"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "使用结合信息增益的 Random Forest Classifier 检测 Denial of Services Attack"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "使用基于 Gini Impurity 的 Weighted Random Forest（GIWRF）feature selection technique 对 intrusion detection system 的 machine learning models 进行性能分析"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [什么是 Support Vector Machine？ - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [什么是 k-Nearest Neighbors（KNN）？ - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT 揭秘：LightGBM、XGBoost 和 CatBoost 的工作原理 - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning：通过结合优势提升模型性能 - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Deep Learning 如何增强 Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
