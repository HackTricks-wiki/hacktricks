# 监督学习算法

{{#include ../banners/hacktricks-training.md}}

## 基本信息

监督学习使用标记数据来训练模型，以便对新的、未见过的输入进行预测。在网络安全领域，监督机器学习广泛应用于入侵检测（将网络流量分类为 *正常* 或 *攻击*）、恶意软件检测（区分恶意软件和良性软件）、钓鱼检测（识别欺诈性网站或电子邮件）以及垃圾邮件过滤等任务。每种算法都有其优点，适用于不同类型的问题（分类或回归）。下面我们回顾关键的监督学习算法，解释它们的工作原理，并展示它们在真实网络安全数据集上的应用。我们还讨论了如何结合模型（集成学习）通常可以提高预测性能。

## 算法

-   **线性回归：** 一种基本的回归算法，通过将线性方程拟合到数据来预测数值结果。

-   **逻辑回归：** 一种分类算法（尽管其名称如此），使用逻辑函数来建模二元结果的概率。

-   **决策树：** 通过特征划分数据以进行预测的树状模型；通常因其可解释性而被使用。

-   **随机森林：** 一种决策树的集成（通过装袋）以提高准确性并减少过拟合。

-   **支持向量机（SVM）：** 最大边距分类器，寻找最佳分离超平面；可以使用核函数处理非线性数据。

-   **朴素贝叶斯：** 基于贝叶斯定理的概率分类器，假设特征独立，著名用于垃圾邮件过滤。

-   **k-最近邻（k-NN）：** 一种简单的“基于实例”的分类器，根据其最近邻的多数类为样本标记。

-   **梯度提升机：** 集成模型（例如，XGBoost，LightGBM），通过顺序添加较弱的学习者（通常是决策树）来构建强预测器。

下面的每个部分提供了算法的改进描述和一个 **Python 代码示例**，使用 `pandas` 和 `scikit-learn`（以及神经网络示例中的 `PyTorch`）等库。示例使用公开可用的网络安全数据集（如用于入侵检测的 NSL-KDD 和钓鱼网站数据集），并遵循一致的结构：

1.  **加载数据集**（如果可用，通过 URL 下载）。

2.  **预处理数据**（例如，编码分类特征，缩放值，拆分为训练/测试集）。

3.  **在训练数据上训练模型**。

4.  **在测试集上评估**，使用指标：准确率、精确率、召回率、F1 分数和 ROC AUC 进行分类（以及均方误差进行回归）。

让我们深入了解每种算法：

### 线性回归

线性回归是一种 **回归** 算法，用于预测连续的数值。它假设输入特征（自变量）与输出（因变量）之间存在线性关系。该模型试图拟合一条直线（或在更高维度中的超平面），以最佳描述特征与目标之间的关系。这通常通过最小化预测值与实际值之间的平方误差之和（普通最小二乘法）来完成。

表示线性回归的最简单形式是用一条线：
```plaintext
y = mx + b
```
在哪里：

- `y` 是预测值（输出）
- `m` 是直线的斜率（系数）
- `x` 是输入特征
- `b` 是 y 轴截距

线性回归的目标是找到最佳拟合线，以最小化预测值与数据集中实际值之间的差异。当然，这非常简单，它将是分隔两个类别的直线，但如果添加更多维度，线就变得更加复杂：
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *网络安全中的用例：* 线性回归本身在核心安全任务中不太常见（这些任务通常是分类），但可以用于预测数值结果。例如，可以使用线性回归来**预测网络流量的大小**或**根据历史数据估计某一时间段内的攻击次数**。它还可以预测风险评分或在给定某些系统指标的情况下，预计检测到攻击的时间。在实践中，分类算法（如逻辑回归或树）更常用于检测入侵或恶意软件，但线性回归作为基础，对于回归导向的分析是有用的。

#### **线性回归的关键特征：**

-   **问题类型：** 回归（预测连续值）。除非对输出应用阈值，否则不适合直接分类。

-   **可解释性：** 高 -- 系数易于解释，显示每个特征的线性影响。

-   **优点：** 简单且快速；是回归任务的良好基线；当真实关系大致线性时效果良好。

-   **局限性：** 无法捕捉复杂或非线性关系（没有手动特征工程）；如果关系是非线性的，容易出现欠拟合；对异常值敏感，可能会扭曲结果。

-   **寻找最佳拟合：** 为了找到分隔可能类别的最佳拟合线，我们使用一种称为**普通最小二乘法（OLS）**的方法。该方法最小化观察值与线性模型预测值之间平方差的总和。

<details>
<summary>示例 -- 在入侵数据集中预测连接持续时间（回归）
</summary>
下面我们使用 NSL-KDD 网络安全数据集演示线性回归。我们将其视为回归问题，通过预测网络连接的`duration`来基于其他特征进行分析。（实际上，`duration`是 NSL-KDD 的一个特征；我们在这里使用它只是为了说明回归。）我们加载数据集，预处理它（编码分类特征），训练线性回归模型，并在测试集上评估均方误差（MSE）和 R² 分数。
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
在这个例子中，线性回归模型试图从其他网络特征预测连接 `duration`。我们用均方误差 (MSE) 和 R² 来衡量性能。接近 1.0 的 R² 表明模型解释了 `duration` 大部分的方差，而低或负的 R² 则表明拟合较差。（如果这里的 R² 较低，不要感到惊讶——从给定特征预测 `duration` 可能很困难，而线性回归可能无法捕捉到复杂的模式。）

### 逻辑回归

逻辑回归是一种 **分类** 算法，用于建模一个实例属于特定类别（通常是“正”类别）的概率。尽管名称中有“回归”，*逻辑* 回归用于离散结果（与用于连续结果的线性回归不同）。它特别用于 **二元分类**（两个类别，例如，恶意与良性），但可以扩展到多类问题（使用 softmax 或一对多的方法）。

逻辑回归使用逻辑函数（也称为 sigmoid 函数）将预测值映射到概率。请注意，sigmoid 函数是一个值在 0 和 1 之间的函数，按照分类的需要以 S 形曲线增长，这对于二元分类任务非常有用。因此，每个输入的每个特征都乘以其分配的权重，结果通过 sigmoid 函数产生一个概率：
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
在哪里：

- `p(y=1|x)` 是在给定输入 `x` 的情况下输出 `y` 为 1 的概率
- `e` 是自然对数的底数
- `z` 是输入特征的线性组合，通常表示为 `z = w1*x1 + w2*x2 + ... + wn*xn + b`。注意，在最简单的形式中，它是一条直线，但在更复杂的情况下，它变成一个具有多个维度（每个特征一个维度）的超平面。

> [!TIP]
> *网络安全中的用例：* 由于许多安全问题本质上是是/否决策，逻辑回归被广泛使用。例如，入侵检测系统可能使用逻辑回归来决定网络连接是否是攻击，基于该连接的特征。在网络钓鱼检测中，逻辑回归可以将网站的特征（URL 长度、"@" 符号的存在等）结合成被钓鱼的概率。它已在早期的垃圾邮件过滤器中使用，并且仍然是许多分类任务的强基线。

#### 逻辑回归用于非二元分类

逻辑回归是为二元分类设计的，但可以通过使用 **一对其余** (OvR) 或 **softmax 回归** 等技术扩展以处理多类问题。在 OvR 中，为每个类训练一个单独的逻辑回归模型，将其视为与所有其他类的正类。选择具有最高预测概率的类作为最终预测。Softmax 回归通过将 softmax 函数应用于输出层，将逻辑回归推广到多个类，从而产生所有类的概率分布。

#### **逻辑回归的关键特征：**

-   **问题类型：** 分类（通常是二元的）。它预测正类的概率。

-   **可解释性：** 高 -- 像线性回归一样，特征系数可以指示每个特征如何影响结果的对数几率。这种透明性在安全领域通常受到重视，以了解哪些因素导致警报。

-   **优点：** 训练简单且快速；当特征与结果的对数几率之间的关系是线性时效果良好。输出概率，能够进行风险评分。通过适当的正则化，它具有良好的泛化能力，并且比普通线性回归更好地处理多重共线性。

-   **局限性：** 假设特征空间中的决策边界是线性的（如果真实边界复杂/非线性则失败）。在交互或非线性效应至关重要的问题上，它可能表现不佳，除非手动添加多项式或交互特征。此外，如果类不能通过特征的线性组合轻易分离，逻辑回归的效果也较差。

<details>
<summary>示例 -- 使用逻辑回归进行钓鱼网站检测：</summary>

我们将使用 **钓鱼网站数据集**（来自 UCI 存储库），该数据集包含提取的网站特征（例如，URL 是否具有 IP 地址、域名的年龄、HTML 中是否存在可疑元素等）以及指示该网站是钓鱼还是合法的标签。我们训练一个逻辑回归模型来对网站进行分类，然后评估其在测试集上的准确性、精确度、召回率、F1 分数和 ROC AUC。
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
在这个钓鱼检测示例中，逻辑回归为每个网站生成一个钓鱼的概率。通过评估准确性、精确度、召回率和F1分数，我们可以了解模型的性能。例如，高召回率意味着它捕捉到大多数钓鱼网站（对于安全性来说，减少漏报攻击很重要），而高精确度意味着它的误报很少（避免分析师疲劳很重要）。ROC AUC（ROC曲线下面积）提供了一种与阈值无关的性能度量（1.0是理想值，0.5与随机猜测没有区别）。逻辑回归在这类任务中通常表现良好，但如果钓鱼网站与合法网站之间的决策边界复杂，可能需要更强大的非线性模型。

</details>

### 决策树

决策树是一种多功能的**监督学习算法**，可用于分类和回归任务。它基于数据的特征学习一个层次化的树状决策模型。树的每个内部节点代表对特定特征的测试，每个分支代表该测试的结果，每个叶节点代表预测的类别（用于分类）或值（用于回归）。

为了构建树，像CART（分类与回归树）这样的算法使用**基尼不纯度**或**信息增益（熵）**等度量来选择最佳特征和阈值，以在每一步拆分数据。每次拆分的目标是对数据进行分区，以增加结果子集中目标变量的同质性（对于分类，每个节点旨在尽可能纯净，主要包含单一类别）。

决策树是**高度可解释的**——可以从根到叶跟踪路径，以理解预测背后的逻辑（例如，*“如果 `service = telnet` 且 `src_bytes > 1000` 且 `failed_logins > 3` 则分类为攻击”*）。这在网络安全中对于解释为什么会产生某个警报非常有价值。树可以自然处理数值和分类数据，并且需要很少的预处理（例如，不需要特征缩放）。

然而，单个决策树很容易对训练数据过拟合，尤其是在深度生长（许多拆分）时。通常使用修剪等技术（限制树的深度或要求每个叶节点的最小样本数）来防止过拟合。

决策树有三个主要组成部分：
- **根节点**：树的顶部节点，代表整个数据集。
- **内部节点**：代表特征和基于这些特征的决策的节点。
- **叶节点**：代表最终结果或预测的节点。

一棵树可能最终看起来像这样：
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *在网络安全中的用例：* 决策树已被用于入侵检测系统，以推导出识别攻击的**规则**。例如，早期的 IDS，如基于 ID3/C4.5 的系统，会生成可读的规则来区分正常流量与恶意流量。它们还用于恶意软件分析，以根据文件的属性（文件大小、部分熵、API 调用等）决定文件是否恶意。决策树的清晰性使其在需要透明度时非常有用——分析师可以检查树以验证检测逻辑。

#### **决策树的关键特征：**

-   **问题类型：** 分类和回归。通常用于攻击与正常流量的分类等。

-   **可解释性：** 非常高——模型的决策可以被可视化并理解为一组 if-then 规则。这在安全领域是一个主要优势，有助于信任和验证模型行为。

-   **优点：** 可以捕捉特征之间的非线性关系和交互（每个分裂可以看作是一种交互）。无需缩放特征或对分类变量进行独热编码——树本身可以处理这些。快速推理（预测只是沿着树中的路径进行）。

-   **局限性：** 如果不加控制，容易过拟合（深树可能会记住训练集）。它们可能不稳定——数据的微小变化可能导致不同的树结构。作为单一模型，它们的准确性可能不如更先进的方法（如随机森林等集成方法通常通过减少方差表现更好）。

-   **寻找最佳分裂：**
- **基尼不纯度**：衡量节点的不纯度。较低的基尼不纯度表示更好的分裂。公式为：

```plaintext
Gini = 1 - Σ(p_i^2)
```

其中 `p_i` 是类别 `i` 中实例的比例。

- **熵**：衡量数据集中的不确定性。较低的熵表示更好的分裂。公式为：

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

其中 `p_i` 是类别 `i` 中实例的比例。

- **信息增益**：分裂后熵或基尼不纯度的减少。信息增益越高，分裂越好。计算公式为：

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

此外，树的结束条件为：
- 节点中的所有实例属于同一类别。这可能导致过拟合。
- 达到树的最大深度（硬编码）。这是防止过拟合的一种方式。
- 节点中的实例数量低于某个阈值。这也是防止过拟合的一种方式。
- 进一步分裂的信息增益低于某个阈值。这也是防止过拟合的一种方式。

<details>
<summary>示例 -- 入侵检测的决策树：</summary>
我们将在 NSL-KDD 数据集上训练一个决策树，以将网络连接分类为 *正常* 或 *攻击*。NSL-KDD 是经典 KDD Cup 1999 数据集的改进版本，具有协议类型、服务、持续时间、失败登录次数等特征，以及指示攻击类型或“正常”的标签。我们将所有攻击类型映射到“异常”类别（二分类：正常与异常）。训练后，我们将评估树在测试集上的表现。
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
在这个决策树示例中，我们将树的深度限制为10，以避免极端的过拟合（`max_depth=10`参数）。指标显示了树在区分正常流量与攻击流量方面的效果。高召回率意味着它捕获了大多数攻击（对IDS很重要），而高精确度则意味着很少有误报。决策树通常在结构化数据上实现不错的准确性，但单棵树可能无法达到最佳性能。然而，模型的*可解释性*是一个很大的优点——我们可以检查树的分裂，看看哪些特征（例如，`service`、`src_bytes`等）在标记连接为恶意时最具影响力。

</details>

### 随机森林

随机森林是一种**集成学习**方法，基于决策树以提高性能。随机森林训练多棵决策树（因此称为“森林”），并结合它们的输出以做出最终预测（对于分类，通常通过多数投票）。随机森林的两个主要思想是**自助聚合**（bagging）和**特征随机性**：

-   **自助聚合：** 每棵树在训练数据的随机自助样本上训练（带替换地抽样）。这在树之间引入了多样性。

-   **特征随机性：** 在树的每次分裂中，考虑一个随机特征子集进行分裂（而不是所有特征）。这进一步去相关化了树。

通过对多棵树的结果进行平均，随机森林减少了单棵决策树可能存在的方差。简单来说，单独的树可能会过拟合或噪声较大，但大量多样化的树共同投票可以平滑这些错误。结果通常是一个**更高准确性**和更好泛化能力的模型。此外，随机森林可以提供特征重要性的估计（通过查看每个特征分裂在平均上减少了多少不纯度）。

随机森林已成为**网络安全中的主力军**，用于入侵检测、恶意软件分类和垃圾邮件检测等任务。它们通常在最小调优的情况下表现良好，并且能够处理大量特征集。例如，在入侵检测中，随机森林可能通过捕获更微妙的攻击模式并减少误报，优于单棵决策树。研究表明，随机森林在NSL-KDD和UNSW-NB15等数据集中对攻击分类的表现优于其他算法。

#### **随机森林的关键特征：**

-   **问题类型：** 主要用于分类（也用于回归）。非常适合安全日志中常见的高维结构化数据。

-   **可解释性：** 低于单棵决策树——你不能轻易地可视化或解释数百棵树。然而，特征重要性分数提供了一些关于哪些属性最具影响力的见解。

-   **优点：** 通常比单树模型具有更高的准确性，得益于集成效应。对过拟合具有鲁棒性——即使单棵树过拟合，集成模型的泛化能力更强。能够处理数值和分类特征，并在一定程度上管理缺失数据。对异常值也相对鲁棒。

-   **局限性：** 模型大小可能很大（许多树，每棵树可能很深）。预测速度比单棵树慢（因为必须在多棵树上进行聚合）。可解释性较差——虽然你知道重要特征，但确切的逻辑并不容易追踪为简单规则。如果数据集极高维且稀疏，训练一个非常大的森林可能计算量很大。

-   **训练过程：**
1. **自助抽样：** 随机抽样训练数据并带替换地创建多个子集（自助样本）。
2. **树构建：** 对于每个自助样本，使用每次分裂时的随机特征子集构建决策树。这在树之间引入了多样性。
3. **聚合：** 对于分类任务，最终预测是通过对所有树的预测进行多数投票得出的。对于回归任务，最终预测是所有树预测的平均值。

<details>
<summary>示例 - 用于入侵检测的随机森林（NSL-KDD）：</summary>
我们将使用相同的NSL-KDD数据集（标记为正常与异常的二元标签），并训练一个随机森林分类器。我们期望随机森林的表现与单棵决策树相当或更好，得益于集成平均减少方差。我们将使用相同的指标进行评估。
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
随机森林通常在这个入侵检测任务中取得强劲的结果。与单一决策树相比，我们可能会观察到在F1或AUC等指标上的改善，特别是在召回率或精确度方面，这取决于数据。这与对*"随机森林（RF）是一种集成分类器，相较于其他传统分类器在有效分类攻击方面表现良好。"*的理解是一致的。在安全运营的背景下，随机森林模型可能更可靠地标记攻击，同时减少误报，这得益于许多决策规则的平均化。森林中的特征重要性可以告诉我们哪些网络特征最能指示攻击（例如，某些网络服务或异常的包计数）。

</details>

### 支持向量机（SVM）

支持向量机是强大的监督学习模型，主要用于分类（也用于回归作为SVR）。SVM试图找到**最佳分离超平面**，以最大化两个类别之间的间隔。只有一部分训练点（最接近边界的“支持向量”）决定了这个超平面的位置。通过最大化间隔（支持向量与超平面之间的距离），SVM通常能够实现良好的泛化。

SVM强大的关键在于能够使用**核函数**来处理非线性关系。数据可以隐式地转换为一个更高维的特征空间，在那里可能存在一个线性分隔符。常见的核包括多项式核、径向基函数（RBF）和sigmoid核。例如，如果网络流量类别在原始特征空间中不是线性可分的，RBF核可以将它们映射到一个更高的维度，在那里SVM找到一个线性分割（这对应于原始空间中的非线性边界）。选择核的灵活性使得SVM能够处理各种问题。

SVM在高维特征空间（如文本数据或恶意软件操作码序列）和特征数量相对于样本数量较大的情况下表现良好。它们在2000年代的许多早期网络安全应用中非常流行，如恶意软件分类和基于异常的入侵检测，通常显示出高准确率。

然而，SVM在处理非常大的数据集时不易扩展（训练复杂度在样本数量上是超线性的，内存使用可能很高，因为它可能需要存储许多支持向量）。在实际应用中，对于像网络入侵检测这样有数百万条记录的任务，SVM可能在没有仔细子采样或使用近似方法的情况下太慢。

#### **SVM的关键特征：**

-   **问题类型：** 分类（通过一对一/一对多的方式进行二元或多类分类）和回归变体。通常用于具有明确间隔分离的二元分类。

-   **可解释性：** 中等 -- SVM的可解释性不如决策树或逻辑回归。虽然可以识别哪些数据点是支持向量，并对哪些特征可能有影响（通过线性核情况下的权重）有一定的了解，但在实践中，SVM（尤其是使用非线性核时）被视为黑箱分类器。

-   **优点：** 在高维空间中有效；可以通过核技巧建模复杂的决策边界；如果最大化间隔（尤其是使用适当的正则化参数C），则对过拟合具有鲁棒性；即使类别之间没有大距离分隔（找到最佳折中边界）时也能良好工作。

-   **局限性：** **计算密集型**，对于大型数据集（随着数据增长，训练和预测的规模都较差）。需要仔细调整核和正则化参数（C、核类型、RBF的gamma等）。不直接提供概率输出（尽管可以使用Platt缩放来获取概率）。此外，SVM对核参数的选择可能敏感 --- 不当选择可能导致欠拟合或过拟合。

*网络安全中的用例：* SVM已被用于**恶意软件检测**（例如，根据提取的特征或操作码序列对文件进行分类）、**网络异常检测**（将流量分类为正常与恶意）和**钓鱼检测**（使用URL的特征）。例如，SVM可以获取电子邮件的特征（某些关键词的计数、发件人信誉评分等），并将其分类为钓鱼或合法。它们还被应用于**入侵检测**，在像KDD这样的特征集上，通常以计算成本换取高准确率。

<details>
<summary>示例 -- 用于恶意软件分类的SVM：</summary>
我们将再次使用钓鱼网站数据集，这次使用SVM。由于SVM可能较慢，如果需要，我们将使用数据的子集进行训练（数据集大约有11k个实例，SVM可以合理处理）。我们将使用RBF核，这是非线性数据的常见选择，并将启用概率估计以计算ROC AUC。
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
SVM模型将输出我们可以与同一任务上的逻辑回归进行比较的指标。如果数据通过特征很好地分离，我们可能会发现SVM实现了高准确率和AUC。相反，如果数据集有很多噪声或类重叠，SVM可能不会显著优于逻辑回归。在实践中，当特征与类别之间存在复杂的非线性关系时，SVM可以提供提升——RBF核可以捕捉逻辑回归会遗漏的曲线决策边界。与所有模型一样，需要仔细调整`C`（正则化）和核参数（如RBF的`gamma`）以平衡偏差和方差。

</details>

#### 逻辑回归与SVM的区别

| 方面 | **逻辑回归** | **支持向量机** |
|---|---|---|
| **目标函数** | 最小化**对数损失**（交叉熵）。 | 最大化**间隔**同时最小化**铰链损失**。 |
| **决策边界** | 找到建模_P(y\|x)_的**最佳拟合超平面**。 | 找到**最大间隔超平面**（与最近点的最大间隔）。 |
| **输出** | **概率性** – 通过σ(w·x + b)给出校准的类别概率。 | **确定性** – 返回类别标签；概率需要额外处理（例如Platt缩放）。 |
| **正则化** | L2（默认）或L1，直接平衡欠拟合/过拟合。 | C参数在间隔宽度与误分类之间进行权衡；核参数增加复杂性。 |
| **核/非线性** | 原生形式是**线性**；通过特征工程添加非线性。 | 内置**核技巧**（RBF、多项式等）使其能够在高维空间中建模复杂边界。 |
| **可扩展性** | 在**O(nd)**中解决凸优化；很好地处理非常大的n。 | 训练可能是**O(n²–n³)**内存/时间，没有专门的求解器；对巨大n不太友好。 |
| **可解释性** | **高** – 权重显示特征影响；赔率比直观。 | 对于非线性核**低**；支持向量稀疏但不易解释。 |
| **对离群值的敏感性** | 使用平滑的对数损失→不太敏感。 | 硬间隔的铰链损失可能**敏感**；软间隔（C）可以缓解。 |
| **典型用例** | 信用评分、医疗风险、A/B测试 – 在**概率和可解释性**重要的地方。 | 图像/文本分类、生物信息学 – 在**复杂边界**和**高维数据**重要的地方。 |

* **如果您需要校准的概率、可解释性，或处理巨大的数据集 — 选择逻辑回归。**
* **如果您需要一个灵活的模型，可以捕捉非线性关系而无需手动特征工程 — 选择SVM（带核）。**
* 两者都优化凸目标，因此**全局最小值是有保证的**，但SVM的核增加了超参数和计算成本。

### 朴素贝叶斯

朴素贝叶斯是一类基于应用贝叶斯定理并对特征之间的强独立性假设的**概率分类器**。尽管这种“朴素”的假设，朴素贝叶斯在某些应用中往往表现得出乎意料的好，特别是涉及文本或分类数据的应用，如垃圾邮件检测。

#### 贝叶斯定理

贝叶斯定理是朴素贝叶斯分类器的基础。它涉及随机事件的条件概率和边际概率。公式为：
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
哪里：
- `P(A|B)` 是给定特征 `B` 的类别 `A` 的后验概率。
- `P(B|A)` 是给定类别 `A` 的特征 `B` 的似然性。
- `P(A)` 是类别 `A` 的先验概率。
- `P(B)` 是特征 `B` 的先验概率。

例如，如果我们想要分类一段文本是由儿童还是成人写的，我们可以使用文本中的单词作为特征。基于一些初始数据，朴素贝叶斯分类器将预先计算每个单词在每个潜在类别（儿童或成人）中的概率。当给定一段新文本时，它将计算给定文本中的单词每个潜在类别的概率，并选择概率最高的类别。

正如您在这个例子中所看到的，朴素贝叶斯分类器非常简单且快速，但它假设特征是独立的，这在现实世界数据中并不总是成立。

#### 朴素贝叶斯分类器的类型

根据数据类型和特征的分布，有几种类型的朴素贝叶斯分类器：
- **高斯朴素贝叶斯**：假设特征遵循高斯（正态）分布。适用于连续数据。
- **多项式朴素贝叶斯**：假设特征遵循多项式分布。适用于离散数据，例如文本分类中的单词计数。
- **伯努利朴素贝叶斯**：假设特征是二元的（0或1）。适用于二元数据，例如文本分类中单词的存在或缺失。
- **分类朴素贝叶斯**：假设特征是分类变量。适用于分类数据，例如根据颜色和形状对水果进行分类。

#### **朴素贝叶斯的关键特征：**

-   **问题类型：** 分类（二元或多类）。通常用于网络安全中的文本分类任务（垃圾邮件、网络钓鱼等）。

-   **可解释性：** 中等 -- 它不像决策树那样直接可解释，但可以检查学习到的概率（例如，哪些单词在垃圾邮件与正常邮件中更可能出现）。如果需要，可以理解模型的形式（给定类别的每个特征的概率）。

-   **优点：** **非常快速** 的训练和预测，即使在大型数据集上（与实例数量 * 特征数量成线性关系）。需要相对较少的数据来可靠地估计概率，特别是在适当平滑的情况下。作为基线，它通常出奇地准确，尤其是当特征独立地为类别提供证据时。适用于高维数据（例如，来自文本的数千个特征）。除了设置平滑参数外，不需要复杂的调优。

-   **局限性：** 独立性假设可能会限制准确性，如果特征高度相关。例如，在网络数据中，特征如 `src_bytes` 和 `dst_bytes` 可能是相关的；朴素贝叶斯无法捕捉到这种交互。随着数据量的急剧增加，更具表现力的模型（如集成或神经网络）可以通过学习特征依赖性超越朴素贝叶斯。此外，如果识别攻击需要某些特征的组合（而不仅仅是独立的特征），朴素贝叶斯将会遇到困难。

> [!TIP]
> *网络安全中的用例：* 经典用例是 **垃圾邮件检测** -- 朴素贝叶斯是早期垃圾邮件过滤器的核心，使用某些标记（单词、短语、IP地址）的频率来计算电子邮件是垃圾邮件的概率。它也用于 **网络钓鱼电子邮件检测** 和 **URL 分类**，某些关键字或特征的存在（如 URL 中的 "login.php" 或 URL 路径中的 `@`）有助于提高钓鱼概率。在恶意软件分析中，可以想象一个朴素贝叶斯分类器，利用软件中某些 API 调用或权限的存在来预测它是否是恶意软件。尽管更先进的算法通常表现更好，但由于其速度和简单性，朴素贝叶斯仍然是一个良好的基线。

<details>
<summary>示例 -- 用于钓鱼检测的朴素贝叶斯：</summary>
为了演示朴素贝叶斯，我们将使用高斯朴素贝叶斯在 NSL-KDD 入侵数据集上（带有二元标签）。高斯朴素贝叶斯将把每个特征视为每个类别遵循正态分布。这是一个粗略的选择，因为许多网络特征是离散的或高度偏斜的，但它展示了如何将朴素贝叶斯应用于连续特征数据。我们也可以选择在二元特征数据集（如一组触发的警报）上使用伯努利朴素贝叶斯，但为了连续性，我们将在这里坚持使用 NSL-KDD。
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
这段代码训练一个朴素贝叶斯分类器来检测攻击。朴素贝叶斯将基于训练数据计算 `P(service=http | Attack)` 和 `P(Service=http | Normal)`，假设特征之间是独立的。然后，它将使用这些概率根据观察到的特征将新连接分类为正常或攻击。朴素贝叶斯在 NSL-KDD 上的性能可能不如更先进的模型（因为特征独立性被违反），但通常表现不错，并且具有极快的速度。在实时电子邮件过滤或 URL 的初步分类等场景中，朴素贝叶斯模型可以快速标记明显恶意的案例，同时资源使用较低。

</details>

### k-最近邻 (k-NN)

k-最近邻是最简单的机器学习算法之一。它是一种**非参数、基于实例**的方法，根据与训练集中的示例的相似性进行预测。分类的思路是：要对一个新的数据点进行分类，找到训练数据中**k**个最近的点（其“最近邻”），并在这些邻居中分配多数类。“接近度”由距离度量定义，通常对数值数据使用欧几里得距离（对于不同类型的特征或问题可以使用其他距离）。

K-NN *不需要显式训练* -- “训练”阶段只是存储数据集。所有工作发生在查询（预测）期间：算法必须计算查询点与所有训练点之间的距离，以找到最近的点。这使得预测时间**与训练样本的数量成线性关系**，对于大型数据集来说可能代价高昂。因此，k-NN 最适合较小的数据集或可以在内存和速度与简单性之间进行权衡的场景。

尽管其简单性，k-NN 可以建模非常复杂的决策边界（因为有效地，决策边界可以是由示例分布决定的任何形状）。当决策边界非常不规则且数据量很大时，它往往表现良好 -- 本质上让数据“为自己发声”。然而，在高维空间中，距离度量可能变得不那么有意义（维度诅咒），并且该方法可能会遇到困难，除非你有大量样本。

*网络安全中的用例：* k-NN 已被应用于异常检测 -- 例如，如果大多数最近邻（先前事件）是恶意的，则入侵检测系统可能会将网络事件标记为恶意。如果正常流量形成簇而攻击是离群值，则 K-NN 方法（k=1 或小 k）本质上执行**最近邻异常检测**。K-NN 还被用于通过二进制特征向量对恶意软件家族进行分类：如果一个新文件在特征空间中与已知的该家族实例非常接近，则可能被分类为某个恶意软件家族。在实践中，k-NN 不如更具可扩展性的算法常见，但它在概念上是简单的，有时用作基线或用于小规模问题。

#### **k-NN 的关键特征：**

-   **问题类型：** 分类（也存在回归变体）。它是一种*懒惰学习*方法 -- 没有显式的模型拟合。

-   **可解释性：** 低到中等 -- 没有全局模型或简洁的解释，但可以通过查看影响决策的最近邻来解释结果（例如，“这个网络流被分类为恶意，因为它与这 3 个已知的恶意流相似”）。因此，解释可以基于示例。

-   **优点：** 实现和理解非常简单。对数据分布没有假设（非参数）。可以自然地处理多类问题。它是**自适应的**，因为决策边界可以非常复杂，由数据分布决定。

-   **局限性：** 对于大型数据集，预测可能很慢（必须计算许多距离）。内存密集型 -- 它存储所有训练数据。在高维特征空间中，性能下降，因为所有点往往变得几乎等距（使得“最近”的概念变得不那么有意义）。需要适当地选择*k*（邻居数量） -- k 太小可能会产生噪声，k 太大可能会包含来自其他类的无关点。此外，特征应适当地缩放，因为距离计算对尺度敏感。

<details>
<summary>示例 -- k-NN 用于钓鱼检测：</summary>

我们将再次使用 NSL-KDD（二元分类）。由于 k-NN 计算量大，我们将使用训练数据的一个子集，以保持在此演示中的可处理性。我们将选择，例如，从完整的 125k 中挑选 20,000 个训练样本，并使用 k=5 个邻居。在训练后（实际上只是存储数据），我们将在测试集上进行评估。我们还将缩放特征以进行距离计算，以确保没有单个特征因尺度而占主导地位。
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
k-NN模型将通过查看训练集子集中5个最近的连接来对连接进行分类。例如，如果这4个邻居是攻击（异常），而1个是正常的，则新连接将被分类为攻击。性能可能是合理的，但通常不如在相同数据上经过良好调优的随机森林或SVM高。然而，当类别分布非常不规则和复杂时，k-NN有时可以表现出色——有效地使用基于内存的查找。在网络安全中，k-NN（k=1或小k）可以用于通过示例检测已知攻击模式，或作为更复杂系统中的一个组件（例如，用于聚类，然后根据聚类成员资格进行分类）。

### 梯度提升机（例如，XGBoost）

梯度提升机是结构化数据中最强大的算法之一。**梯度提升**是指以顺序方式构建弱学习者（通常是决策树）集成的技术，其中每个新模型纠正前一个集成的错误。与并行构建树并对其进行平均的袋装（随机森林）不同，提升是*逐个构建树*，每棵树更关注之前树错误预测的实例。

近年来最流行的实现是**XGBoost**、**LightGBM**和**CatBoost**，它们都是梯度提升决策树（GBDT）库。它们在机器学习竞赛和应用中取得了极大的成功，通常**在表格数据集上实现最先进的性能**。在网络安全中，研究人员和从业者使用梯度提升树进行**恶意软件检测**（使用从文件或运行时行为中提取的特征）和**网络入侵检测**等任务。例如，梯度提升模型可以将许多弱规则（树）组合起来，例如“如果有许多SYN数据包和异常端口->可能是扫描”，形成一个强大的复合检测器，考虑许多微妙的模式。

为什么提升树如此有效？序列中的每棵树都是在当前集成的预测的*残差错误*（梯度）上训练的。这样，模型逐渐**“提升”**其薄弱的领域。使用决策树作为基础学习者意味着最终模型可以捕捉复杂的交互和非线性关系。此外，提升本质上具有内置正则化的形式：通过添加许多小树（并使用学习率来缩放它们的贡献），它通常能够很好地泛化而不会出现巨大的过拟合，前提是选择了适当的参数。

#### **梯度提升的关键特征：**

-   **问题类型：** 主要是分类和回归。在安全性中，通常是分类（例如，二元分类连接或文件）。它处理二元、多类（具有适当损失）甚至排名问题。

-   **可解释性：** 低到中等。虽然单棵提升树较小，但完整模型可能有数百棵树，整体上不易被人理解。然而，像随机森林一样，它可以提供特征重要性分数，像SHAP（SHapley Additive exPlanations）这样的工具可以在一定程度上用于解释单个预测。

-   **优点：** 通常是结构化/表格数据的**最佳表现**算法。可以检测复杂的模式和交互。具有许多调优参数（树的数量、树的深度、学习率、正则化项），以调整模型复杂性并防止过拟合。现代实现经过优化以提高速度（例如，XGBoost使用二阶梯度信息和高效的数据结构）。当与适当的损失函数结合或通过调整样本权重时，通常能更好地处理不平衡数据。

-   **局限性：** 比简单模型更复杂，调优更困难；如果树很深或树的数量很大，训练可能会很慢（尽管通常仍比在相同数据上训练可比的深度神经网络快）。如果未调优，模型可能会过拟合（例如，树过深且正则化不足）。由于有许多超参数，有效使用梯度提升可能需要更多的专业知识或实验。此外，像基于树的方法一样，它在处理非常稀疏的高维数据时效率不如线性模型或朴素贝叶斯（尽管仍然可以应用，例如在文本分类中，但在没有特征工程的情况下可能不是首选）。

> [!TIP]
> *网络安全中的用例：* 几乎在任何可以使用决策树或随机森林的地方，梯度提升模型可能会实现更好的准确性。例如，**微软的恶意软件检测**竞赛中，XGBoost在从二进制文件提取的特征上得到了广泛使用。**网络入侵检测**研究通常报告GBDT（例如，XGBoost在CIC-IDS2017或UNSW-NB15数据集上的结果）取得了最佳结果。这些模型可以接受广泛的特征（协议类型、某些事件的频率、流量的统计特征等），并将它们结合起来以检测威胁。在网络钓鱼检测中，梯度提升可以结合URL的词汇特征、域名声誉特征和页面内容特征，以实现非常高的准确性。集成方法有助于覆盖数据中的许多边缘情况和细微差别。

<details>
<summary>示例 -- 使用XGBoost进行网络钓鱼检测：</summary>
我们将在网络钓鱼数据集上使用梯度提升分类器。为了保持简单和自包含，我们将使用`sklearn.ensemble.GradientBoostingClassifier`（这是一个较慢但简单的实现）。通常，人们可能会使用`xgboost`或`lightgbm`库以获得更好的性能和额外的功能。我们将以类似之前的方式训练模型并评估它。
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
梯度提升模型在这个网络钓鱼数据集上可能会实现非常高的准确率和AUC（通常这些模型在适当调优后可以超过95%的准确率，如文献中所见。这表明为什么GBDT被认为是*"表格数据集的最先进模型"* -- 它们通常通过捕捉复杂模式来超越更简单的算法。在网络安全的背景下，这可能意味着捕捉到更多的网络钓鱼网站或攻击，同时减少漏报。当然，必须谨慎对待过拟合 -- 在开发此类模型以进行部署时，我们通常会使用交叉验证等技术，并监控验证集上的性能。

</details>

### 组合模型：集成学习和堆叠

集成学习是一种**组合多个模型**以提高整体性能的策略。我们已经看到了一些特定的集成方法：随机森林（通过装袋的树的集成）和梯度提升（通过顺序提升的树的集成）。但集成也可以通过其他方式创建，例如**投票集成**或**堆叠泛化（堆叠）**。主要思想是不同的模型可能捕捉到不同的模式或具有不同的弱点；通过将它们组合在一起，我们可以**用其他模型的优势来弥补每个模型的错误**。

-   **投票集成：** 在一个简单的投票分类器中，我们训练多个多样化的模型（例如，一个逻辑回归、一个决策树和一个SVM），并让它们对最终预测进行投票（分类的多数投票）。如果我们对投票进行加权（例如，对更准确的模型给予更高的权重），这就是一个加权投票方案。当单个模型相对较好且独立时，这通常会提高性能 -- 集成减少了单个模型错误的风险，因为其他模型可能会纠正它。这就像有一个专家小组，而不是单一的意见。

-   **堆叠（堆叠集成）：** 堆叠更进一步。它不是简单的投票，而是训练一个**元模型**来**学习如何最好地组合基础模型的预测**。例如，你训练3个不同的分类器（基础学习者），然后将它们的输出（或概率）作为特征输入到一个元分类器（通常是一个简单模型，如逻辑回归），该元分类器学习最佳的混合方式。元模型在验证集上或通过交叉验证进行训练，以避免过拟合。堆叠通常可以通过学习*在何种情况下更信任哪些模型*来超越简单的投票。在网络安全中，一个模型可能在捕捉网络扫描方面表现更好，而另一个在捕捉恶意软件信标方面表现更好；堆叠模型可以学习在每种情况下适当地依赖于每个模型。

无论是通过投票还是堆叠，集成通常会**提高准确性**和鲁棒性。缺点是复杂性增加，有时可解释性降低（尽管一些集成方法，如决策树的平均值，仍然可以提供一些见解，例如特征重要性）。在实践中，如果操作限制允许，使用集成可以导致更高的检测率。许多网络安全挑战（以及Kaggle竞赛中的一般解决方案）中的获胜解决方案使用集成技术来挤出最后一点性能。

<details>
<summary>示例 -- 网络钓鱼检测的投票集成：</summary>
为了说明模型堆叠，让我们结合我们在网络钓鱼数据集上讨论的一些模型。我们将使用逻辑回归、决策树和k-NN作为基础学习者，并使用随机森林作为元学习者来聚合它们的预测。元学习者将基于基础学习者的输出进行训练（在训练集上使用交叉验证）。我们预计堆叠模型的表现与单个模型相当或稍好。
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
堆叠集成利用了基础模型的互补优势。例如，逻辑回归可能处理数据的线性方面，决策树可能捕捉特定的规则型交互，而k-NN可能在特征空间的局部邻域中表现出色。元模型（这里是随机森林）可以学习如何加权这些输入。最终的指标通常显示出相对于任何单一模型指标的改善（即使是微小的）。在我们的钓鱼示例中，如果逻辑回归单独的F1值为0.95，而决策树为0.94，则堆叠可能通过纠正每个模型的错误而达到0.96。

像这样的集成方法展示了*“组合多个模型通常会导致更好的泛化”*的原则。在网络安全中，这可以通过拥有多个检测引擎（一个可能是基于规则的，一个是机器学习的，一个是基于异常的）来实现，然后有一层聚合它们的警报——有效地形成一种集成——以更高的信心做出最终决策。在部署这样的系统时，必须考虑增加的复杂性，并确保集成不会变得太难以管理或解释。但从准确性角度来看，集成和堆叠是提高模型性能的强大工具。

</details>

## 参考文献

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
