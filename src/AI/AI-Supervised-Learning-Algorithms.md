# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## 基本情報

Supervised learningは、ラベル付きデータを使用してモデルを訓練し、新しい未知の入力に対する予測を行えるようにします。Cybersecurityでは、Supervised machine learningは、侵入検知（network trafficを*normal*または*attack*に分類）、malware検知（悪意のあるsoftwareとbenignなsoftwareの識別）、phishing検知（不正なwebsiteやemailの特定）、spam filteringなど、さまざまなタスクに幅広く利用されています。<sup>[[1]](#references)</sup> 各algorithmにはそれぞれ強みがあり、異なる種類の問題（classificationまたはregression）に適しています。以下では、主要なSupervised learning algorithmを確認し、その仕組みを説明するとともに、実際のCybersecurity datasetでの使用例を示します。また、modelを組み合わせることで（ensemble learning）、予測性能を向上できる場合があることについても説明します。

## Algorithms

-   **Linear Regression:** データにlinear equationを適合させ、数値結果を予測する基本的なregression algorithm。

-   **Logistic Regression:** 名前に反してclassification algorithmであり、logistic functionを使用してbinary outcomeの確率をモデル化します。

-   **Decision Trees:** featureによってデータを分割して予測を行うtree構造のmodel。解釈しやすさを理由に、よく使用されます。

-   **Random Forests:** Decision Treeのensemble（baggingによる）であり、accuracyを向上させ、overfittingを軽減します。

-   **Support Vector Machines (SVM):** 最適な分離hyperplaneを見つけるmax-margin classifier。non-linear dataにはkernelを使用できます。

-   **Naive Bayes:** Bayes' theoremに基づくprobabilistic classifierで、featureの独立性を仮定します。spam filteringで有名です。

-   **k-Nearest Neighbors (k-NN):** 最も近いneighborのmajority classに基づいてsampleにlabelを付ける、シンプルな"instance-based" classifier。

-   **Gradient Boosting Machines:** 弱いlearner（通常はDecision Tree）を順番に追加して強力なpredictorを構築するensemble model（XGBoost、LightGBMなど）。

以下の各sectionでは、algorithmの説明を改善したものと、`pandas`や`scikit-learn`などのlibrary（neural networkの例では`PyTorch`）を使用した**Python code example**を示します。exampleでは、公開されているCybersecurity dataset（侵入検知用のNSL-KDDやPhishing Websites datasetなど）を使用し、次の一貫した構成に従います。

1.  **datasetを読み込む**（利用可能な場合はURL経由でdownload）。

2.  **dataをpreprocessする**（例：categorical featureのencode、値のscale、train/test setへの分割）。

3.  **training data**でmodelをtrainする。

4.  classificationではaccuracy、precision、recall、F1-score、ROC AUC、regressionではmean squared errorなどのmetricを使用して、test setで**evaluateする**。

各algorithmを詳しく見ていきましょう。

### Linear Regression

Linear regressionは、連続的な数値を予測するために使用される**regression** algorithmです。入力feature（independent variable）と出力（dependent variable）の間にlinear relationshipがあることを前提とします。modelは、featureとtargetの関係を最も適切に表すstraight line（高次元ではhyperplane）を適合させようとします。通常は、予測値と実際の値の間のsquared errorの合計を最小化することで実行されます（Ordinary Least Squares method）。<sup>[[2]](#references)</sup>

Linear regressionを表す最も単純な形式は、lineです。
```plaintext
y = mx + b
```
以下の意味です：

- `y` は予測値（出力）
- `m` は直線の傾き（係数）
- `x` は入力特徴量
- `b` は y 切片

linear regression の目的は、データセット内の予測値と実際の値の差を最小化する、最も適合する直線を見つけることです。もちろん、これは非常に単純なもので、2つのカテゴリを分離する直線になります。しかし、より多くの次元が追加されると、直線はより複雑になります：
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* Linear regression 自体は、主要なセキュリティタスク（多くの場合 classification）ではあまり一般的ではありませんが、数値的な結果の予測に利用できます。たとえば、過去のデータに基づいて **ネットワークトラフィックの量を予測**したり、**一定期間内の攻撃件数を推定**したりするために linear regression を使用できます。また、特定のシステムメトリクスから、リスクスコアや攻撃が検知されるまでの予想時間を予測することも可能です。実際には、侵入や malware の検知には classification algorithms（logistic regression や trees など）がより頻繁に使用されますが、linear regression は基礎となる手法であり、regression 指向の分析に役立ちます。

#### **Linear Regression の主な特徴:**

-   **問題の種類:** Regression（連続値の予測）。出力に threshold を適用しない限り、直接的な classification には適していません。

-   **解釈可能性:** 高い -- coefficients は簡単に解釈でき、各 feature の線形的な影響を示します。

-   **利点:** 単純かつ高速で、regression タスクの優れた baseline になります。また、実際の関係がほぼ線形である場合に適切に機能します。

-   **制限事項:** 手動で feature engineering を行わない限り、複雑または非線形の関係を捉えられません。関係が非線形の場合は underfitting になりやすく、outliers の影響を受けやすいため、結果が歪む可能性があります。

-   **最適な fit の決定:** 可能性のある categories を分離する最適な fit line を見つけるために、**Ordinary Least Squares (OLS)** と呼ばれる手法を使用します。この手法は、観測値と linear model による予測値との差の二乗和を最小化します。

<details>
<summary>Example -- Intrusion Dataset における Connection Duration の予測 (Regression)
</summary>
以下では、NSL-KDD cybersecurity dataset を使用して linear regression を実演します。ここでは、他の features に基づいてネットワーク接続の `duration` を予測することで、これを regression problem として扱います。（実際には、`duration` は NSL-KDD の1つの feature です。ここでは regression を説明するためだけに使用します。）dataset を読み込み、前処理（categorical features の encode）、linear regression model の train を行い、test set 上で Mean Squared Error (MSE) と R² score を評価します。
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
この例では、linear regression modelは他のネットワーク features から接続の`duration`を予測しようとします。性能はMean Squared Error（MSE）とR²で測定します。R²が1.0に近い場合、modelが`duration`の分散の大部分を説明していることを示します。一方、R²が低い、または負の場合は、適合度が低いことを示します。（ここでR²が低くても驚かないでください -- 与えられた features から`duration`を予測するのは難しい可能性があり、パターンが複雑な場合はlinear regressionで捉えられないことがあります。）
</details>

### Logistic Regression

Logistic regressionは、あるインスタンスが特定のクラス（通常は「positive」クラス）に属する確率をmodel化する**classification** algorithmです。その名前に反して、*logistic* regressionは離散的な結果に使用されます（連続的な結果を対象とするlinear regressionとは異なります）。特に**binary classification**（2つのクラス。例：maliciousとbenign）に使用されますが、multi-class問題にも拡張できます（softmaxまたはone-vs-restアプローチを使用）。<sup>[[3]](#references)</sup>

Logistic regressionは、予測値を確率に変換するためにlogistic function（sigmoid functionとも呼ばれます）を使用します。sigmoid functionは0から1の間の値を取り、classificationの要件に応じてS字型のカーブで増加する関数である点に注意してください。これはbinary classification tasksに役立ちます。そのため、各inputの各featureに割り当てられたweightを掛け、その結果をsigmoid functionに渡して確率を生成します。
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` は、入力 `x` が与えられたときに出力 `y` が 1 である確率です
- `e` は自然対数の底です
- `z` は入力特徴量の線形結合で、通常は `z = w1*x1 + w2*x2 + ... + wn*xn + b` と表されます。ここでも最も単純な形では直線ですが、より複雑なケースでは、複数の次元（各特徴量につき 1 つ）を持つ超平面になります。

> [!TIP]
> *サイバーセキュリティでのユースケース:* 多くのセキュリティ問題は本質的に yes/no の判断であるため、Logistic Regression は広く使用されています。例えば、侵入検知システムでは、ネットワーク接続の特徴量に基づいて、その接続が攻撃かどうかを判断するために Logistic Regression を使用できます。phishing 検出では、Logistic Regression によって、Webサイトの特徴（URL の長さ、`@` 記号の有無など）を組み合わせ、phishing である確率を算出できます。これは初期世代の spam filter で使用されており、現在でも多くの classification タスクにおける強力なベースラインであり続けています。

#### 非 binary classification のための Logistic Regression

Logistic Regression は binary classification 用に設計されていますが、**one-vs-rest** (OvR) や **softmax regression** などの手法を使用して multi-class 問題に対応するよう拡張できます。OvR では、各 class について個別の Logistic Regression モデルを学習し、その class を positive class、それ以外をすべて negative class として扱います。予測確率が最も高い class が最終的な予測として選択されます。Softmax regression は、出力層に softmax 関数を適用することで Logistic Regression を複数の class に一般化し、すべての class に対する確率分布を生成します。

#### **Logistic Regression の主な特徴:**

-   **問題の種類:** Classification（通常は binary）。positive class の確率を予測します。

-   **解釈可能性:** 高い -- linear regression と同様に、feature coefficient によって、各 feature が結果の log-odds にどのような影響を与えるかを示せます。この透明性は、alert に寄与する要因を理解するうえでセキュリティ分野ではしばしば評価されます。

-   **利点:** 学習が簡単かつ高速で、feature と結果の log-odds の関係が線形である場合に適切に機能します。確率を出力するため、risk scoring が可能です。適切な regularization を使用すれば、汎化性能が高く、単純な linear regression よりも multicollinearity に適切に対処できます。

-   **制限:** feature space における線形の decision boundary を仮定します（実際の boundary が複雑または非線形の場合は機能しません）。interaction や非線形効果が重要な問題では、polynomial feature や interaction feature を手動で追加しない限り、性能が低下する可能性があります。また、class が feature の線形結合によって容易に分離できない場合、Logistic Regression はあまり効果的ではありません。


<details>
<summary>例 -- Logistic Regression による Phishing Website Detection:</summary>

ここでは、Webサイトから抽出された feature（URL に IP address が含まれているか、domain の経過期間、HTML 内の suspicious element の有無など）と、そのサイトが phishing か legitimate かを示す label を含む **Phishing Websites Dataset**（UCI repository 由来）を使用します。<sup>[[4]](#references)</sup> Logistic Regression モデルを学習して Webサイトを分類し、その後、test split における accuracy、precision、recall、F1-score、ROC AUC を評価します。
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
このフィッシング検知の例では、logistic regression によって各Webサイトがフィッシングである確率を算出します。accuracy、precision、recall、F1を評価することで、モデルの性能を把握できます。例えば、高いrecallは、ほとんどのフィッシングサイトを検知できることを意味します（見逃す攻撃を最小限に抑えるため、セキュリティ上重要です）。一方、高いprecisionは、誤警報が少ないことを意味します（アナリストの疲弊を避けるために重要です）。ROC AUC（ROC曲線下面積）は、threshold に依存しない性能指標です（1.0が理想的で、0.5は偶然を上回らないことを示します）。logistic regression はこのようなタスクで良好な性能を発揮することが多いですが、フィッシングサイトと正規サイトのdecision boundaryが複雑な場合は、より強力な非線形モデルが必要になることがあります。

</details>

### Decision Trees

decision treeは、classificationとregressionの両方のタスクに使用できる汎用的な**supervised learning algorithm**です。データの特徴量に基づいて、階層的なtree状のdecision modelを学習します。treeの各internal nodeは特定のfeatureに対するテストを表し、各branchはそのテストの結果を表し、各leaf nodeは予測されたclass（classificationの場合）またはvalue（regressionの場合）を表します。<sup>[[5]](#references)</sup>

treeを構築するために、CART（Classification and Regression Tree）などのalgorithmは、各ステップでデータを分割する最適なfeatureとthresholdを選択するため、**Gini impurity**や**information gain (entropy)**などの指標を使用します。各分割の目的は、結果として得られるsubset内のtarget variableの均一性を高めることです（classificationでは、各nodeに主に単一のclassが含まれるよう、可能な限りpureにすることを目指します）。

decision treeは**非常に解釈しやすく**、rootからleafまでの経路をたどることで、予測の背後にあるlogicを理解できます（例：*"`service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` の場合、attackとして分類する"*）。これは、特定のalertが発生した理由を説明するうえで、cybersecurityにおいて有用です。treeは数値データとcategorical dataの両方を自然に扱うことができ、前処理もほとんど必要ありません（例：feature scalingは不要です）。

ただし、単一のdecision treeは、特に深く成長させた場合（多数の分割を行った場合）、training dataに対して容易にoverfitします。overfittingを防ぐため、pruning（treeの深さを制限する、またはleafあたりの最小サンプル数を指定する）などの手法がよく使用されます。

decision treeには、主に3つのcomponentがあります。
- **Root Node**: treeの最上位のnodeで、データセット全体を表します。
- **Internal Nodes**: featureと、そのfeatureに基づくdecisionを表すnodeです。
- **Leaf Nodes**: 最終的な結果またはpredictionを表すnodeです。

treeは最終的に次のような形になります：
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* Decision treesは、攻撃を識別するための**ルール**を導出する侵入検知システムで使用されてきました。例えば、初期のID3/C4.5ベースのIDSは、正常なトラフィックと悪意のあるトラフィックを区別する、人間が読みやすいルールを生成していました。また、ファイルの属性（ファイルサイズ、セクションのエントロピー、API呼び出しなど）に基づいて、そのファイルが悪意のあるものかどうかを判断するmalware analysisでも使用されます。Decision treesは明確であるため、透明性が必要な場合に有用です。アナリストはtreeを調査して、検知ロジックを検証できます。

#### **Decision Treesの主な特徴:**

-   **問題の種類:** classificationとregressionの両方。攻撃と正常なトラフィックのclassificationなどで一般的に使用されます。

-   **解釈可能性:** 非常に高い -- modelの判断を可視化し、一連のif-thenルールとして理解できます。これは、modelの動作に対する信頼と検証が重要なsecurityにおいて、大きな利点です。

-   **利点:** feature間の非線形な関係や相互作用を捉えられます（各splitは相互作用として見ることができます）。featureのscale変換やcategorical variableのone-hot encodeは必要ありません。treeがこれらをネイティブに処理するためです。inferenceも高速です（predictionはtree内のpathをたどるだけです）。

-   **制限:** 制御しない場合はoverfittingしやすくなります（深いtreeはtraining setをmemorizeできます）。また、不安定になる可能性があります。dataに小さな変更を加えただけで、異なるtree構造になることがあります。単一のmodelとしては、そのaccuracyがより高度な手法に及ばない場合があります（Random Forestsなどのensembleは、varianceを減らすことで通常より高い性能を発揮します）。

-   **最適なSplitの探索:**
- **Gini Impurity**: nodeの不純度を測定します。Gini impurityが低いほど、より良いsplitであることを示します。数式は次のとおりです:

```plaintext
Gini = 1 - Σ(p_i^2)
```

ここで、`p_i`はclass `i`に属するinstanceの割合です。

- **Entropy**: dataset内の不確実性を測定します。entropyが低いほど、より良いsplitであることを示します。数式は次のとおりです:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

ここで、`p_i`はclass `i`に属するinstanceの割合です。

- **Information Gain**: split後のentropyまたはGini impurityの減少量です。information gainが高いほど、より良いsplitです。次のように計算します:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

さらに、treeは次のいずれかに該当した時点で終了します:
- node内のすべてのinstanceが同じclassに属している場合。これはoverfittingにつながる可能性があります。
- treeの最大depth（hardcoded）に到達した場合。これはoverfittingを防ぐ方法です。
- node内のinstance数が一定のthresholdを下回った場合。これもoverfittingを防ぐ方法です。
- さらなるsplitによるinformation gainが一定のthresholdを下回った場合。これもoverfittingを防ぐ方法です。

<details>
<summary>例 -- Intrusion Detection用のDecision Tree:</summary>
ネットワーク接続を*normal*または*attack*のいずれかにclassificationするため、NSL-KDD datasetでdecision treeをtrainingします。NSL-KDDは、従来のKDD Cup 1999 datasetを改良したもので、protocol type、service、duration、failed loginの回数などのfeatureと、attack typeまたは"normal"を示すlabelを備えています。すべてのattack typeを"anomaly" classにmapします（binary classification: normal vs anomaly）。training後、test setでtreeのperformanceを評価します。
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
この decision tree の例では、極端な overfitting を避けるため、tree の深さを 10 に制限しました（`max_depth=10` パラメータ）。これらの metrics は、tree が通常の traffic と attack traffic をどの程度適切に区別できるかを示しています。高い recall は、ほとんどの attack を検出できることを意味します（IDS にとって重要です）。一方、高い precision は false alarm が少ないことを意味します。Decision trees は structured data で十分な accuracy を達成することが多いものの、単一の tree では可能な最高の performance に届かない場合があります。それでも、モデルの *interpretability* は大きな利点です。tree の split を調べれば、例えば、どの feature（`service`、`src_bytes` など）が connection を malicious と判定する際に最も大きな影響を持つかを確認できます。

</details>

### Random Forests

Random Forest は、performance を向上させるために decision trees を基盤として構築する **ensemble learning** 手法です。Random forest では複数の decision trees（そのため "forest" と呼ばれます）を学習させ、その出力を組み合わせて最終的な prediction を行います（classification では通常、majority vote を使用します）。Random forest の主な考え方は、**bagging**（bootstrap aggregating）と **feature randomness** の 2 つです。

-   **Bagging:** 各 tree は、training data からランダムに抽出した bootstrap sample（replacement あり）を使って学習します。これにより、tree 間に diversity が生まれます。

-   **Feature Randomness:** tree の各 split では、すべての feature ではなく、ランダムに選ばれた feature の subset を split の候補として検討します。これにより、tree 間の相関がさらに低下します。

多数の tree の結果を average することで、Random forest は単一の decision tree が持つ可能性のある variance を低減します。簡単に言えば、個々の tree は overfit したり noisy になったりする可能性がありますが、多様な tree が多数集まって vote することで、こうした error が平滑化されます。その結果、単一の decision tree よりも **higher accuracy** と優れた generalization を持つ model になることが多くあります。さらに、Random forests は feature importance の推定値も提供できます（各 feature の split が impurity を平均でどの程度減少させるかを調べることで算出します）。

Random forests は、intrusion detection、malware classification、spam detection などの task で、cybersecurity における **workhorse** となっています。最小限の tuning で out-of-the-box でも良好に動作することが多く、大規模な feature set にも対応できます。例えば intrusion detection では、Random forest は単一の decision tree を上回り、より微妙な attack pattern を、少ない false positive で検出できる場合があります。Research では、NSL-KDD や UNSW-NB15 などの dataset で attack を classification する際、Random forests が他の algorithm と比較して良好な performance を示すことが報告されています。<sup>[[6]](#references)[[7]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** 主に classification（regression にも使用されます）。security log で一般的な high-dimensional structured data に非常に適しています。

-   **Interpretability:** 単一の decision tree より低くなります。一度に数百本の tree を簡単に visualize したり、explain したりすることはできません。ただし、feature importance score によって、どの attribute が最も大きな影響を持つかについて一定の insight を得られます。

-   **Advantages:** ensemble effect により、一般的に single-tree model より高い accuracy を実現します。overfitting に対して robust です。個々の tree が overfit しても、ensemble の方がより適切に generalize します。numerical feature と categorical feature の両方を処理でき、missing data にもある程度対応できます。また、outlier に対しても比較的 robust です。

-   **Limitations:** model size が大きくなる可能性があります（多数の tree があり、それぞれが深くなる場合があります）。prediction は単一の tree より遅くなります（多数の tree の結果を aggregate する必要があるためです）。interpretability も低くなります。重要な feature は把握できますが、正確な logic を単純な rule のように容易に追跡することはできません。dataset が極めて high-dimensional かつ sparse な場合、非常に大きな forest の training は computationally heavy になる可能性があります。

-   **Training Process:**
1. **Bootstrap Sampling**: training data から replacement ありでランダムに sample し、複数の subset（bootstrap sample）を作成します。
2. **Tree Construction**: 各 bootstrap sample に対して、各 split で feature の random subset を使用して decision tree を構築します。これにより、tree 間に diversity が生まれます。
3. **Aggregation**: classification task では、すべての tree の prediction の majority vote によって最終的な prediction を決定します。regression task では、すべての tree の prediction の average が最終的な prediction になります。

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
同じ NSL-KDD dataset（normal と anomaly の binary label）を使用し、Random Forest classifier を学習させます。ensemble の averaging によって variance が低減されるため、Random forest は単一の decision tree と同等以上の performance を発揮すると期待できます。先ほどと同じ metrics を使って評価します。
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
ランダムフォレストは、この intrusion detection タスクで通常、優れた結果を達成します。データによっては、単一の decision tree と比較して、特に recall や precision など、F1 や AUC といった指標の改善が見られる場合があります。これは、*"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."* という理解とも一致します。<sup>[[6]](#references)</sup> セキュリティ運用のコンテキストでは、多数の decision rule の平均化によって、false alarm を減らしながら、より確実に攻撃を検出できる可能性があります。forest から得られる feature importance により、どの network feature が攻撃を最もよく示しているか（例：特定の network service や異常な packet 数）を把握できます。

</details>

### Support Vector Machines (SVM)

Support Vector Machines は、主に classification（および SVR としての regression）に使用される強力な supervised learning model です。SVM は、2つの class 間の margin を最大化する **optimal separating hyperplane** を見つけようとします。training point の一部（boundary に最も近い「support vector」）だけが、この hyperplane の位置を決定します。margin（support vector と hyperplane の距離）を最大化することで、SVM は優れた generalization を達成しやすくなります。<sup>[[8]](#references)</sup>

SVM の強力さの鍵は、**kernel function** を使用して non-linear な関係を処理できる点にあります。データを暗黙的に、linear separator が存在する可能性のある、より高次元の feature space へ変換できます。一般的な kernel には polynomial、radial basis function (RBF)、sigmoid があります。例えば、network traffic の class が raw feature space で linearly separable でない場合、RBF kernel によってより高次元へ mapping し、SVM が linear split を見つけられるようになります（これは元の space では non-linear boundary に相当します）。kernel を選択できる柔軟性により、SVM はさまざまな問題に対応できます。

SVM は、高次元の feature space（text data や malware opcode sequence など）や、sample 数に対して feature 数が多いケースで優れた性能を発揮することで知られています。2000年代には、malware classification や anomaly-based intrusion detection など、多くの初期の cybersecurity application で広く利用され、高い accuracy を示すことが多くありました。

ただし、SVM は非常に大規模な dataset には容易に scale できません（training complexity は sample 数に対して super-linear であり、多数の support vector を保存する必要があるため memory 使用量も大きくなる可能性があります）。実際には、数百万件の record を扱う network intrusion detection のような task では、慎重な subsampling や approximate method を使わない限り、SVM は遅すぎる可能性があります。

#### **SVM の主な特徴:**

-   **問題の種類:** Classification（one-vs-one/one-vs-rest による binary または multiclass）および regression variant。明確な margin separation がある binary classification でよく使用されます。

-   **解釈可能性:** Medium -- SVM は decision tree や logistic regression ほど解釈しやすくありません。どの data point が support vector なのかを特定し、どの feature が影響している可能性があるかをある程度把握することはできます（linear kernel の場合は weight を通じて可能）が、実際には SVM（特に non-linear kernel を使用するもの）は black-box classifier として扱われます。

-   **利点:** 高次元 space で有効。kernel trick により複雑な decision boundary を model 化できる。margin を最大化すれば overfitting に強い（特に適切な regularization parameter C を使用した場合）。class が大きく離れていない場合でも適切に機能する（最適な妥協点となる boundary を見つける）。

-   **制限:** 大規模な dataset では **computationally intensive**（data の増加に伴い、training と prediction の両方が適切に scale しない）。kernel と regularization parameter（C、kernel type、RBF の gamma など）の慎重な tuning が必要です。probabilistic output は直接提供しません（ただし、Platt scaling を使って probability を取得できます）。また、SVM は kernel parameter の選択に敏感であり、不適切な選択は underfit や overfit につながる可能性があります。

*Cybersecurity における use case:* SVM は **malware detection**（抽出した feature や opcode sequence に基づく file の classification など）、**network anomaly detection**（traffic を normal または malicious として classification）、**phishing detection**（URL の feature を使用）に利用されています。例えば、SVM に email の feature（特定の keyword の数、sender reputation score など）を入力し、phishing または legitimate として classification できます。また、KDD のような feature set を用いた **intrusion detection** にも適用されており、計算コストと引き換えに高い accuracy を達成することがよくあります。

<details>
<summary>例 -- Malware Classification 用 SVM:</summary>
今回は、phishing website dataset を SVM で扱います。SVM は遅くなる可能性があるため、必要に応じて training には data の subset を使用します（dataset は約11,000 instance であり、SVM でも妥当な速度で処理できます）。non-linear data で一般的に使用される RBF kernel を使用し、ROC AUC を計算するために probability estimate を有効にします。
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
SVM modelは、同じタスクにおけるロジスティック回帰と比較できるmetricsを出力します。データがfeaturesによって適切に分離されている場合、SVMは高いaccuracyとAUCを達成する可能性があります。一方で、datasetに大量のnoiseや重複するclassが含まれている場合、SVMがロジスティック回帰を大きく上回ることはないでしょう。実際には、featuresとclassの間に複雑で非線形な関係がある場合、SVMによって性能が向上することがあります。RBF kernelは、ロジスティック回帰では捉えられない曲線状のdecision boundaryを捉えられます。すべてのmodelと同様に、biasとvarianceのバランスを取るには、`C`（regularization）やkernel parameters（RBFの`gamma`など）の慎重なtuningが必要です。

</details>

#### ロジスティック回帰とSVMの違い

| Aspect | **ロジスティック回帰** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log-loss**（cross-entropy）を最小化します。 | **hinge-loss**を最小化しながら**margin**を最大化します。 |
| **Decision boundary** | _P(y\|x)_をmodel化する**best-fit hyperplane**を求めます。 | **maximum-margin hyperplane**（最も近いpointsまでのgapが最大となるhyperplane）を求めます。 |
| **Output** | **Probabilistic** – σ(w·x + b)によってcalibrated class probabilitiesを提供します。 | **Deterministic** – class labelsを返します。probabilitiesには追加処理（Platt scalingなど）が必要です。 |
| **Regularisation** | L2（default）またはL1を使用し、under/over-fittingを直接調整します。 | C parameterがmargin widthとmis-classificationsのトレードオフを調整し、kernel parametersがcomplexityを追加します。 |
| **Kernels / Non-linear** | Native formは**linear**です。feature engineeringによってnon-linearityを追加します。 | 組み込みの**kernel trick**（RBF、polyなど）によって、high-dim. spaceにおける複雑なboundaryをmodel化できます。 |
| **Scalability** | **O(nd)**でconvex optimisationを解き、非常に大きなnにも適しています。 | specialised solversがない場合、trainingはmemory/timeともに**O(n²–n³)**になる可能性があり、巨大なnにはあまり適していません。 |
| **Interpretability** | **High** – weightsがfeature influenceを示し、odds ratioも直感的です。 | non-linear kernelsでは**Low**です。support vectorsはsparseですが、説明は容易ではありません。 |
| **Sensitivity to outliers** | smoothなlog-lossを使用するため、sensitivityは低めです。 | hard marginのhinge-lossは**sensitive**になる可能性があります。soft-margin（C）によって緩和できます。 |
| **Typical use cases** | Credit scoring、medical risk、A/B testingなど、**probabilitiesとexplainability**が重要な分野。 | Image/text classification、bio-informaticsなど、**complex boundaries**と**high-dimensional data**が重要な分野。 |

* **calibrated probabilities、interpretability、または巨大なdatasetへの対応が必要なら、ロジスティック回帰を選びます。**
* **手動のfeature engineeringなしでnon-linear relationsを捉えられる柔軟なmodelが必要なら、SVM（kernels付き）を選びます。**
* どちらもconvex objectivesを最適化するため、**global minimaが保証**されます。ただし、SVMのkernelsはhyper-parametersと計算コストを追加します。

### Naive Bayes

Naive Bayesは、features間に強いindependence assumptionを置き、Bayes' Theoremを適用することに基づく**probabilistic classifiers**のfamilyです。この「naive」な仮定にもかかわらず、Naive Bayesは特定のapplication、特にspam detectionなどのtextまたはcategorical dataを扱うapplicationで、驚くほどうまく機能することがあります。<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Bayes' theoremはNaive Bayes classifiersの基礎です。これはrandom eventsのconditional probabilitiesとmarginal probabilitiesの関係を示します。formulaは次のとおりです。
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` は、特徴 `B` が与えられたクラス `A` の事後確率です。
- `P(B|A)` は、クラス `A` が与えられた特徴 `B` の尤度です。
- `P(A)` は、クラス `A` の事前確率です。
- `P(B)` は、特徴 `B` の事前確率です。

たとえば、あるテキストが子どもによって書かれたものか、大人によって書かれたものかを分類したい場合、テキスト内の単語を特徴として使用できます。いくつかの初期データに基づき、Naive Bayes classifier は各単語がそれぞれの候補クラス（子どもまたは大人）に属する確率を事前に計算します。新しいテキストが与えられると、テキスト内の単語に基づいて各候補クラスの確率を計算し、最も高い確率を持つクラスを選択します。

この例から分かるように、Naive Bayes classifier は非常に単純かつ高速ですが、特徴が独立していると仮定します。これは実世界のデータでは必ずしも成り立ちません。


#### Naive Bayes Classifier の種類

データの種類と特徴の分布に応じて、Naive Bayes classifier にはいくつかの種類があります。
- **Gaussian Naive Bayes**: 特徴が Gaussian（正規）分布に従うと仮定します。連続データに適しています。
- **Multinomial Naive Bayes**: 特徴が multinomial 分布に従うと仮定します。テキスト分類における単語数のような離散データに適しています。
- **Bernoulli Naive Bayes**: 特徴が binary（0 または 1）であると仮定します。テキスト分類における単語の存在または不在のような binary データに適しています。
- **Categorical Naive Bayes**: 特徴が categorical variable であると仮定します。色や形状に基づく果物の分類のような categorical data に適しています。


#### **Naive Bayes の主な特徴:**

-   **問題の種類:** Classification（binary または multi-class）。cybersecurity における text classification タスク（spam、phishing など）で一般的に使用されます。

-   **解釈可能性:** 中程度 -- decision tree ほど直接的に解釈できるわけではありませんが、学習された確率（たとえば、spam email と ham email のどちらにどの単語が現れやすいか）を調べることができます。必要に応じて、モデルの形式（クラスごとの各特徴の確率）を理解できます。

-   **利点:** 大規模なデータセットでも、training と prediction が非常に高速です（instance 数 * feature 数に対して linear）。適切な smoothing を行えば、確率を信頼性の高い形で推定するために必要なデータ量が比較的少なくて済みます。特に、特徴がそれぞれ独立してクラスの判定材料となる場合、baseline として驚くほど高い精度を示すことがあります。高次元データ（たとえば、text から得られる数千の feature）でも適切に動作します。smoothing parameter の設定以外に、複雑な tuning は必要ありません。

-   **制限:** 特徴同士の相関が強い場合、独立性の仮定によって精度が制限されることがあります。たとえば、network data では `src_bytes` と `dst_bytes` のような特徴が相関している可能性がありますが、Naive Bayes はその相互作用を捉えられません。データサイズが非常に大きくなると、より表現力の高いモデル（ensemble や neural net など）が、feature の依存関係を学習することで NB を上回る可能性があります。また、attack の識別に特徴の組み合わせが必要な場合（各特徴が独立して存在するだけでは不十分な場合）、NB は苦戦します。

> [!TIP]
> *cybersecurity における使用例:* 典型的な用途は **spam detection** です -- Naive Bayes は初期の spam filter の中核であり、特定の token（単語、フレーズ、IP address）の頻度を使用して、email が spam である確率を計算していました。また、**phishing email detection** や **URL classification** にも使用されます。そこでは、特定の keyword や特徴（URL 内の `"login.php"` や URL path 内の `@` など）の存在が phishing の確率に影響します。malware analysis では、特定の API call や software 内の permission の存在を使用して、それが malware かどうかを予測する Naive Bayes classifier を想定できます。より高度な algorithm のほうが高い性能を示すことが多い一方、Naive Bayes は高速かつ単純であるため、依然として優れた baseline です。

<details>
<summary>Example -- Phishing Detection のための Naive Bayes:</summary>
Naive Bayes を実演するため、binary label を持つ NSL-KDD intrusion dataset に対して Gaussian Naive Bayes を使用します。Gaussian NB は、各 feature がクラスごとに normal distribution に従うものとして扱います。多くの network feature は discrete または highly skewed であるため、これは大まかな選択ですが、continuous feature data に NB を適用する方法を示すことができます。triggered alert の集合のような binary feature の dataset に対して Bernoulli NB を選択することもできますが、ここでは一貫性を保つため NSL-KDD を使用します。
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
このコードは、攻撃を検出するために Naive Bayes classifier をトレーニングします。Naive Bayes は、特徴量間の独立性を仮定し、training data に基づいて `P(service=http | Attack)` や `P(Service=http | Normal)` などを計算します。その後、観測された特徴量に基づき、新しい接続を normal または attack として分類します。NSL-KDD における NB の性能は、より高度なモデルほど高くない可能性があります（特徴量の独立性が実際には成立しないため）が、十分な性能を発揮することが多く、極めて高速という利点があります。リアルタイムの email filtering や URL の初期 triage のようなシナリオでは、Naive Bayes model はリソース使用量を抑えながら、明らかに悪意のあるケースを迅速に flag できます。

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors は、最も単純な machine learning algorithms の1つです。これは **non-parametric, instance-based** な手法で、training set 内の examples との類似性に基づいて predictions を行います。classification における考え方は、新しい data point を分類する際に、training data 内で最も近い **k** 個の points（「nearest neighbors」）を見つけ、それらの neighbors の中で多数を占める class を割り当てるというものです。「近さ」は distance metric によって定義され、通常は numeric data に対して Euclidean distance が使われます（feature や problem の種類に応じて、他の distances も使用できます）。<sup>[[10]](#references)</sup>

K-NN には *explicit training が不要* です -- 「training」phase は dataset を保存するだけです。すべての処理は query（prediction）時に行われます。algorithm は query point とすべての training points との distances を計算し、最も近い points を見つける必要があります。そのため、prediction time は **training samples 数に対して線形** となり、大規模な datasets ではコストが高くなる可能性があります。このため、k-NN は小規模な datasets や、単純さのために memory と speed のトレードオフを許容できる scenarios に適しています。

単純であるにもかかわらず、k-NN は非常に複雑な decision boundaries を model 化できます（実質的に decision boundary は、examples の分布によって決まる任意の shape になり得るためです）。decision boundary が非常に不規則で、かつ大量の data がある場合にうまく機能する傾向があります -- 本質的には data 自体に「語らせる」方法です。しかし、高次元では distance metrics の意味が薄れる可能性があり（curse of dimensionality）、非常に多数の samples がない限り method が苦戦することがあります。

*Use cases in cybersecurity:* k-NN は anomaly detection に適用されています -- 例えば、intrusion detection system は、ある network event の nearest neighbors（過去の events）の大半が malicious であった場合、その network event を malicious と label できます。normal traffic が clusters を形成し、attacks が outliers である場合、K-NN approach（k=1 または小さい k）は実質的に **nearest-neighbor anomaly detection** になります。K-NN は binary feature vectors による malware families の分類にも使用されています。新しい file が、feature space において既知のある malware family の instances に非常に近い場合、その malware family に分類できます。実際には、k-NN はより scalable な algorithms ほど一般的ではありませんが、conceptually straightforward であり、baseline として、または small-scale problems で使用されることがあります。

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification（regression variants も存在します）。これは *lazy learning* method です -- explicit model fitting は行いません。

-   **Interpretability:** Low to medium -- global model や簡潔な explanation はありませんが、decision に影響を与えた nearest neighbors を確認することで results を解釈できます（例: 「この network flow は、これら3つの既知の malicious flows に類似しているため malicious と分類された」）。したがって、explanations は example-based にできます。

-   **Advantages:** 実装と理解が非常に簡単です。data distribution に関する仮定を置きません（non-parametric）。multi-class problems を自然に処理できます。decision boundaries が非常に複雑になり得て、data distribution によって形作られるという意味で、**adaptive** です。

-   **Limitations:** 大規模な datasets では prediction が遅くなる可能性があります（多数の distances を計算する必要があるためです）。Memory-intensive であり、training data 全体を保存します。高次元の feature spaces では、すべての points がほぼ等距離になりやすく（「nearest」という概念の意味が薄れるため）、performance が低下します。*k*（neighbors の数）を適切に選択する必要があります -- k が小さすぎると noisy になり、k が大きすぎると他の classes の irrelevant な points が含まれる可能性があります。また、distance calculations は scale に敏感であるため、features は適切に scaled する必要があります。

<details>
<summary>Example -- Phishing Detection のための k-NN:</summary>

ここでも NSL-KDD（binary classification）を使用します。k-NN は computationally heavy であるため、この demonstration では tractable に保つため training data の subset を使用します。full 125k から、例えば 20,000 個の training samples を選び、k=5 neighbors を使用します。training 後（実際には data の保存だけです）、test set で evaluate します。また、scale によって特定の feature だけが支配的にならないよう、distance calculation のために features も scale します。
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
k-NNモデルは、training setのsubset内で最も近い5つのconnectionを調べることで、connectionを分類します。例えば、そのneighborのうち4つがattack（anomaly）で、1つがnormalの場合、新しいconnectionはattackとして分類されます。パフォーマンスは十分な場合もありますが、同じデータに対して適切にtuningされたRandom ForestやSVMほど高くないことがよくあります。ただし、class distributionが非常に不規則で複雑な場合、k-NNはmemory-based lookupを効果的に使用するため、優れた性能を発揮することがあります。cybersecurityでは、k-NN（k=1または小さいk）を、既知のattack patternを例に基づいて検出するため、またはより複雑なsystemのcomponentとして（例えば、clusteringを行い、その後cluster membershipに基づいてclassifyするため）使用できます。
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machinesは、structured data向けの最も強力なalgorithmの1つです。**Gradient boosting**とは、weak learner（多くの場合decision tree）のensembleを順番に構築するtechniqueを指します。各新しいmodelは、前のensembleのerrorsを修正します。treeを並列に構築して平均するbagging（Random Forests）とは異なり、boostingはtreeを*1つずつ*構築し、それぞれが前のtreeによって誤ってpredictionされたinstanceにより重点を置きます。<sup>[[11]](#references)</sup>

近年最も人気のあるimplementationは**XGBoost**、**LightGBM**、**CatBoost**であり、いずれもgradient boosting decision tree（GBDT）libraryです。これらはmachine learning competitionやapplicationで非常に高い成果を上げており、**tabular datasetでstate-of-the-art performanceを達成することが多くあります**。cybersecurityでは、researcherやpractitionerが、**malware detection**（fileまたはruntime behaviorから抽出したfeatureを使用）や**network intrusion detection**などのtaskにgradient boosted treeを使用しています。例えば、gradient boosting modelは、「SYN packetが多く、通常とは異なるport -> scanの可能性が高い」といった多数のweak rule（tree）を組み合わせ、さまざまな微妙なpatternを考慮する強力なcomposite detectorを構築できます。

なぜboosted treeはこれほど効果的なのでしょうか。sequence内の各treeは、現在のensembleのpredictionにおける*residual error*（gradient）を使用してtrainingされます。これにより、modelは弱い領域を徐々に**「boost」**できます。base learnerとしてdecision treeを使用するため、最終modelは複雑なinteractionやnon-linearなrelationを捉えられます。また、boostingにはbuilt-in regularizationの性質もあります。多数の小さなtreeを追加し、それらのcontributionをlearning rateでscaleすることで、適切なparameterを選択すれば、過度なoverfittingを起こすことなく、十分にgeneralizeできることが多くあります。

#### **Gradient Boostingの主な特徴:**

-   **問題の種類:** 主にclassificationとregressionです。securityでは通常classification（例えば、connectionまたはfileをbinary classify）に使用します。binary、multi-class（適切なlossを使用）、さらにranking problemにも対応します。

-   **Interpretability:** 低から中程度です。単一のboosted treeは小さくても、full modelには数百のtreeが含まれる場合があり、全体を人間が解釈することは困難です。ただし、Random Forestと同様にfeature importance scoreを提供でき、SHAP（SHapley Additive exPlanations）のようなtoolを使用すれば、individual predictionをある程度解釈できます。

-   **Advantages:** structured/tabular dataに対して、しばしば**最も高いperformanceを発揮する**algorithmです。複雑なpatternやinteractionを検出できます。modelのcomplexityを調整し、overfittingを防ぐためのtuning knob（treeの数、treeのdepth、learning rate、regularization term）が多数あります。modern implementationはspeed向けに最適化されています（例えば、XGBoostはsecond-order gradient情報と効率的なdata structureを使用します）。適切なloss functionと組み合わせたり、sample weightを調整したりすることで、imbalanced dataにもより適切に対応できる傾向があります。

-   **Limitations:** より単純なmodelよりtuningが複雑です。treeがdeepである場合やtreeの数が多い場合、trainingに時間がかかることがあります（ただし、同じdataに対して同等のdeep neural networkをtrainingする場合より、通常は高速です）。適切にtuningしないと、modelはoverfitする可能性があります（例えば、regularizationが不十分な状態でdeep treeを多く使用する場合）。hyperparameterが多いため、gradient boostingを効果的に使用するには、より多くのexpertiseやexperimentが必要になることがあります。また、tree-based methodと同様に、非常にsparseでhigh-dimensionalなdataをlinear modelやNaive Bayesほど効率的には本質的に処理できません（text classificationなどに適用することは可能ですが、feature engineeringなしでは第一候補にならない場合があります）。

> [!TIP]
> *cybersecurityでのuse case:* decision treeやrandom forestを使用できるほぼすべての場面で、gradient boosting modelはより高いaccuracyを達成できる可能性があります。例えば、**Microsoftのmalware detection** competitionでは、binary fileからengineerしたfeatureに対してXGBoostが盛んに使用されています。**Network intrusion detection**のresearchでは、GBDT（例: CIC-IDS2017やUNSW-NB15 datasetに対するXGBoost）によるtop resultがしばしば報告されています。これらのmodelは、幅広いfeature（protocol type、特定のeventのfrequency、trafficのstatistical featureなど）を受け取り、それらを組み合わせてthreatを検出できます。phishing detectionでは、gradient boostingがURLのlexical feature、domain reputation feature、page content featureを組み合わせ、非常に高いaccuracyを達成できます。ensemble approachにより、data内の多くのcorner caseや微妙な特徴をカバーできます。

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
phishing datasetに対してgradient boosting classifierを使用します。シンプルでself-containedにするため、`sklearn.ensemble.GradientBoostingClassifier`（より遅いものの、分かりやすいimplementation）を使用します。通常は、より高いperformanceと追加featureのために、`xgboost`または`lightgbm` libraryを使用します。これまでと同様にmodelをtrainingし、evaluationを行います。
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
勾配ブースティングモデルは、この phishing dataset で非常に高い accuracy と AUC を達成する可能性が高いです（文献で示されているように、このようなデータでは、適切な tuning によりこれらのモデルが 95% を超える accuracy を達成することもよくあります。これは、GBDTs が *「表形式データセットに対する state of the art model」* と見なされている理由を示しています。複雑なパターンを捉えることで、より単純なアルゴリズムを上回ることが多いためです）。<sup>[[11]](#references)</sup> Cybersecurity の文脈では、これはより多くの phishing sites や attacks を検知し、見逃しを減らせることを意味します。もちろん、overfitting には注意が必要です。このようなモデルを deployment 用に開発する際は、通常、cross-validation などの techniques を使用し、validation set 上の performance を監視します。

</details>

### モデルの組み合わせ: Ensemble Learning と Stacking

Ensemble learning は、全体的な performance を向上させるために**複数のモデルを組み合わせる** strategy です。すでに具体的な ensemble methods として、Random Forest（bagging による trees の ensemble）と Gradient Boosting（sequential boosting による trees の ensemble）を見てきました。しかし、**voting ensembles** や **stacked generalization (stacking)** など、他の方法でも ensembles を作成できます。基本的な考え方は、異なるモデルが異なるパターンを捉えたり、異なる弱点を持っていたりする可能性があるため、それらを組み合わせることで、**各モデルの errors を別のモデルの strengths で補う**ことです。<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** 単純な voting classifier では、複数の多様なモデル（たとえば logistic regression、decision tree、SVM）を train し、最終的な prediction について投票させます（classification では majority vote）。投票に weight を付ける場合（たとえば、より accuracy の高いモデルに大きな weight を与える場合）は、weighted voting scheme となります。これは通常、個々のモデルが十分に優れており、互いに独立している場合に performance を向上させます。ensemble は、他のモデルが誤りを修正できる可能性があるため、個々のモデルの mistake の risk を低減します。単独の意見ではなく、専門家の panel を持つようなものです。

-   **Stacking (Stacked Ensemble):** Stacking は、単純な vote より一歩進んだ方法です。単純に投票するのではなく、**base models の predictions を最適に組み合わせる方法を学習する** **meta-model** を train します。たとえば、3 つの異なる classifiers（base learners）を train し、その outputs（または probabilities）を features として meta-classifier（多くの場合、logistic regression のような単純な model）に入力し、どのように blend するのが最適かを学習させます。meta-model は、overfitting を避けるために validation set 上、または cross-validation を通じて train します。Stacking は、*どの状況でどのモデルをより信頼すべきか*を学習することで、単純な voting を上回ることがよくあります。Cybersecurity では、あるモデルが network scans の検知に優れ、別のモデルが malware beaconing の検知に優れている場合、stacking model はそれぞれを適切に頼る方法を学習できます。

Voting や stacking による ensembles は、accuracy と robustness を**向上させる**傾向があります。欠点は、complexity が増し、interpretability が低下する場合があることです（ただし、decision trees の average のような一部の ensemble approaches は、feature importance などを通じてある程度の insight を提供できます）。実際には、operational constraints が許せば、ensemble を使用することで detection rates を高められます。Cybersecurity challenges（および一般的な Kaggle competitions）で上位に入る多くの solutions は、最後のわずかな performance まで引き出すために ensemble techniques を使用しています。

<details>
<summary>Example -- Phishing Detection 用の Voting Ensemble:</summary>
モデル stacking を説明するために、phishing dataset 上で、これまで説明したいくつかのモデルを組み合わせてみましょう。base learners として logistic regression、decision tree、k-NN を使用し、meta-learner として Random Forest を使用して、それらの predictions を aggregate します。meta-learner は、base learners の outputs 上で train します（training set に対する cross-validation を使用）。stacked model は、個々のモデルと同程度、またはわずかに優れた performance を示すと予想されます。
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
スタック型アンサンブルは、ベースモデルの相補的な強みを活用します。たとえば、ロジスティック回帰はデータの線形的な側面を処理し、決定木は特定のルールベースの相互作用を捉え、k-NNは特徴空間の局所的な近傍で優れた性能を発揮する可能性があります。メタモデル（ここではランダムフォレスト）は、これらの入力をどのように重み付けするかを学習できます。その結果得られるメトリクスは、多くの場合、単一モデルのメトリクスを（たとえわずかであっても）上回ります。先ほどのフィッシングの例では、ロジスティック回帰単体のF1がたとえば0.95、決定木が0.94だった場合、スタッキングでは各モデルが誤る部分を補完することで、0.96を達成できる可能性があります。

このようなアンサンブル手法は、*「複数のモデルを組み合わせることで、通常は汎化性能が向上する」*という原則を示しています。<sup>[[12]](#references)</sup> サイバーセキュリティでは、複数の検知エンジン（ルールベース、machine learning、anomaly-basedのいずれかなど）を用意し、それらのアラートを集約する層を設けることで実装できます。これは実質的にアンサンブルの一形態であり、より高い信頼度で最終的な判断を下せます。このようなシステムを導入する際には、複雑性の増加を考慮し、アンサンブルが管理や説明を過度に困難なものにならないようにする必要があります。しかし、精度の観点では、アンサンブルとスタッキングはモデル性能を向上させる強力なツールです。

</details>

## 参考文献

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
