# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## 基本情報

Supervised learningは、ラベル付きデータを使用して、新しい未知の入力に対する予測を行えるモデルを学習します。Cybersecurityでは、Supervised machine learningは、侵入検知（ネットワークトラフィックを*normal*または*attack*に分類）、malware detection（悪意のあるソフトウェアと無害なソフトウェアの区別）、phishing detection（詐欺的なWebサイトやメールの識別）、spam filteringなど、さまざまなタスクに広く適用されています。<sup>[[1]](#references)</sup> 各アルゴリズムにはそれぞれ強みがあり、異なる種類の問題（classificationまたはregression）に適しています。以下では、主要なSupervised learning algorithmsを概説し、その仕組みを説明するとともに、実際のCybersecurity datasetsでの使用方法を示します。また、複数のモデルを組み合わせることで（ensemble learning）、予測性能を向上できる場合が多いことについても説明します。

## Algorithms

-   **Linear Regression:** データに線形方程式を適合させ、数値の結果を予測する基本的なregression algorithm。

-   **Logistic Regression:** Logistic functionを使用して二値結果の確率をモデル化するclassification algorithm（名前に反して）。

-   **Decision Trees:** featureによってデータを分割して予測を行うtree構造のモデル。解釈しやすいことから、よく使用されます。

-   **Random Forests:** Decision treesのensemble（baggingによる）であり、精度を向上させ、overfittingを低減します。

-   **Support Vector Machines (SVM):** 最適な分離hyperplaneを見つけるmax-margin classifiers。non-linear dataにはkernelsを使用できます。

-   **Naive Bayes:** Bayes' theoremに基づくprobabilistic classifier。featureが独立しているという仮定を置き、spam filteringで広く使用されています。

-   **k-Nearest Neighbors (k-NN):** 最も近いneighborのmajority classに基づいてsampleにlabelを付ける、シンプルな"instance-based" classifier。

-   **Gradient Boosting Machines:** 弱いlearner（通常はdecision trees）を順番に追加することで強力なpredictorを構築するensemble models（例：XGBoost、LightGBM）。

以下の各セクションでは、algorithmの説明を改良し、`pandas`や`scikit-learn`などのlibraries（neural networkの例では`PyTorch`）を使用した**Python code example**を示します。例では、公開されているCybersecurity datasets（侵入検知用のNSL-KDDやPhishing Websites datasetなど）を使用し、次の一貫した構成に従います。

1.  **datasetを読み込む**（利用可能な場合はURL経由でdownload）。

2.  **dataをpreprocessする**（例：categorical featuresのencode、valuesのscale、train/test setsへの分割）。

3.  **training data**でmodelをtrainする。

4.  classificationではaccuracy、precision、recall、F1-score、ROC AUC、regressionではmean squared errorなどのmetricsを使用して、test setで**evaluate**する。

各algorithmを詳しく見ていきましょう。

### Linear Regression

Linear regressionは、連続する数値を予測するために使用される**regression** algorithmです。入力features（独立変数）とoutput（従属変数）の間にlinear relationshipがあることを前提とします。modelは、featuresとtargetの関係を最も適切に表すstraight line（高次元ではhyperplane）を適合させようとします。通常、これは予測値と実際の値の間のsquared errorsの合計を最小化することで行われます（Ordinary Least Squares method）。<sup>[[2]](#references)</sup>

linear regressionを表現する最も単純な方法は、lineを使用することです。
```plaintext
y = mx + b
```
ここで:

- `y` は予測値（出力）
- `m` は線の傾き（係数）
- `x` は入力特徴量
- `b` は y 切片

linear regression の目的は、データセット内の予測値と実際の値の差を最小化する、最もよく適合する線を見つけることです。もちろん、これは非常に単純なもので、2つのカテゴリを分ける直線になります。しかし、次元が追加されると、線はより複雑になります:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* Linear regression 自体は、主要な security タスク（多くの場合 classification）ではあまり一般的ではありませんが、数値的な結果の予測に利用できます。例えば、過去のデータに基づいて、**ネットワークトラフィックの量を予測**したり、**一定期間内の攻撃数を推定**したりするために linear regression を使用できます。また、特定のシステムメトリクスを基に、リスクスコアや攻撃が検知されるまでの予想時間を予測することも可能です。実際には、侵入や malware の検知には classification アルゴリズム（logistic regression や trees など）がより頻繁に使用されますが、linear regression は基盤として機能し、regression 指向の分析に役立ちます。

#### **Linear Regression の主な特徴:**

-   **問題の種類:** Regression（連続値の予測）。出力に threshold を適用しない限り、直接的な classification には適していません。

-   **解釈可能性:** 高い -- coefficients は解釈しやすく、各 feature の線形的な影響を示します。

-   **利点:** シンプルで高速。regression タスクの優れた baseline となり、真の関係がおおむね線形である場合に適切に機能します。

-   **制限:** 手動で feature engineering を行わない限り、複雑または非線形の関係を捉えられません。関係が非線形の場合は underfitting になりやすく、結果を歪める可能性のある outlier の影響を受けやすいという特徴があります。

-   **最適な fit の特定:** 可能性のある category を分離する最適な fit line を見つけるために、**Ordinary Least Squares (OLS)** と呼ばれる手法を使用します。この手法は、観測値と linear model による予測値との差の二乗和を最小化します。

<details>
<summary>Example -- Intrusion Dataset における Connection Duration の予測（Regression）
</summary>
ここでは、NSL-KDD cybersecurity dataset を使用して linear regression を説明します。他の feature に基づいてネットワーク接続の `duration` を予測する regression 問題として扱います。（実際には、`duration` は NSL-KDD の1つの feature です。ここでは regression を説明する目的で使用します。）dataset を読み込み、前処理（categorical feature の encode）を行い、linear regression model を train し、test set 上で Mean Squared Error (MSE) と R² score を評価します。
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
この例では、linear regression model は他のネットワーク特徴量から接続の `duration` を予測しようとします。パフォーマンスは Mean Squared Error (MSE) と R² で測定します。R² が 1.0 に近い場合、モデルが `duration` の分散の大部分を説明していることを示します。一方、R² が低い、または負の場合は、適合度が低いことを示します。（ここで R² が低くても驚かないでください。与えられた特徴量から `duration` を予測するのは難しい可能性があり、パターンが複雑な場合、linear regression では捉えられないことがあります。）
</details>

### Logistic Regression

Logistic regression は、あるインスタンスが特定のクラス（通常は「positive」クラス）に属する確率をモデル化する **classification** アルゴリズムです。名前に regression が含まれていますが、*logistic* regression は離散的な結果に使用されます（連続的な結果を扱う linear regression とは異なります）。特に **binary classification**（2つのクラス。例：malicious と benign）に使用されますが、multi-class の問題にも拡張できます（softmax または one-vs-rest アプローチを使用します）。<sup>[[3]](#references)</sup>

logistic regression は、予測値を確率に変換するために logistic function（sigmoid function とも呼ばれます）を使用します。sigmoid function は 0 から 1 の間の値を取り、classification の要件に応じて S 字型の曲線で増加する関数であり、binary classification タスクに有用です。したがって、各入力の各特徴量に割り当てられた weight を乗算し、その結果を sigmoid function に渡すことで確率を生成します。
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` は、入力 `x` が与えられたとき、出力 `y` が1である確率です
- `e` は自然対数の底です
- `z` は入力特徴量の線形結合で、通常は `z = w1*x1 + w2*x2 + ... + wn*xn + b` と表されます。ここでも、最も単純な形では直線ですが、より複雑なケースでは複数の次元（特徴量ごとに1つ）を持つ超平面になります。

> [!TIP]
> *サイバーセキュリティにおけるユースケース:* 多くのセキュリティ上の問題は本質的にyes/noの判断であるため、logistic regressionは広く使用されています。たとえば、侵入検知システムでは、ネットワーク接続の特徴量に基づいて、その接続が攻撃であるかどうかを判断するためにlogistic regressionを使用できます。phishing detectionでは、Webサイトの特徴（URLの長さ、`@`記号の有無など）を組み合わせて、phishingである確率を算出できます。初期世代のspam filterで使用されており、現在でも多くのclassificationタスクにおける強力なベースラインです。

#### 非binary classificationのためのLogistic Regression

Logistic regressionはbinary classification向けに設計されていますが、**one-vs-rest**（OvR）や**softmax regression**などの手法を使用してmulti-class問題に対応させることもできます。OvRでは、各classに対して個別のlogistic regressionモデルを学習させ、そのclassをpositive class、それ以外をすべてnegative classとして扱います。予測確率が最も高いclassが最終的なpredictionとして選択されます。Softmax regressionは、出力layerにsoftmax関数を適用することでlogistic regressionを複数classに一般化し、すべてのclassに対する確率分布を生成します。

#### **Logistic Regressionの主な特徴:**

-   **問題の種類:** Classification（通常はbinary）。positive classの確率を予測します。

-   **解釈可能性:** 高い -- linear regressionと同様に、feature coefficientによって、各featureが結果のlog-oddsにどのような影響を与えるかを示せます。この透明性は、alertに寄与する要因を理解するうえで、security分野で高く評価されることが多くあります。

-   **利点:** 学習が簡単かつ高速で、featureと結果のlog-oddsの関係がlinearである場合に適切に機能します。確率を出力するため、risk scoringが可能です。適切なregularizationを使用すれば、generalization性能が高く、通常のlinear regressionよりもmulticollinearityに適切に対処できます。

-   **制限:** feature spaceにおけるlinearなdecision boundaryを仮定します（実際のboundaryが複雑またはnon-linearな場合は機能しません）。polynomial featureやinteraction featureを手動で追加しない限り、interactionやnon-linearな効果が重要な問題では性能が低下する可能性があります。また、classがfeatureのlinearな組み合わせによって容易に分離できない場合、logistic regressionはあまり効果的ではありません。


<details>
<summary>例 -- Logistic Regressionを使用したPhishing Website Detection:</summary>

ここでは、Webサイトから抽出したfeature（URLにIP addressが含まれているか、domainのage、HTML内のsuspicious elementの有無など）と、そのサイトがphishingかlegitimateかを示すlabelを含む**Phishing Websites Dataset**（UCI repository提供）を使用します。<sup>[[4]](#references)</sup> logistic regressionモデルを学習させてWebサイトを分類し、test splitにおけるaccuracy、precision、recall、F1-score、ROC AUCを評価します。
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
この phishing detection の例では、logistic regression は各 Web サイトが phishing である確率を生成します。accuracy、precision、recall、F1 を評価することで、モデルの性能を把握できます。たとえば、recall が高いということは、ほとんどの phishing サイトを検出できることを意味します（見逃す攻撃を最小限に抑えることが重要な security では有用です）。一方、precision が高いということは、誤警報が少ないことを意味します（analyst fatigue を避けるうえで重要です）。ROC AUC（Area Under the ROC Curve）は、threshold に依存しない性能指標です（1.0 が理想的で、0.5 はランダムな推測より優れていません）。logistic regression はこのようなタスクで優れた性能を発揮することが多いものの、phishing サイトと正規サイトの間の decision boundary が複雑な場合は、より強力な非線形モデルが必要になる可能性があります。

</details>

### Decision Trees

decision tree は、classification と regression の両方のタスクに使用できる汎用性の高い **supervised learning algorithm** です。データの feature に基づいて、階層的な tree 状の decision model を学習します。tree の各 internal node は特定の feature に対する test を表し、各 branch はその test の結果を表し、各 leaf node は予測された class（classification の場合）または value（regression の場合）を表します。<sup>[[5]](#references)</sup>

tree を構築するために、CART（Classification and Regression Tree）のような algorithm は、各段階でデータを分割する最適な feature と threshold を選択するため、**Gini impurity** や **information gain (entropy)** などの指標を使用します。各 split の目的は、結果として得られる subset における target variable の均一性を高めるようデータを分割することです（classification では、各 node に主に単一の class が含まれ、可能な限り pure になることを目指します）。

decision tree は **非常に解釈しやすく**、root から leaf までの path をたどることで、prediction の logic を理解できます（例：*"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN 攻撃として分類"*）。これは、特定の alert が発生した理由を説明するうえで cybersecurity に役立ちます。tree は numerical data と categorical data の両方を自然に扱うことができ、preprocessing もほとんど必要ありません（例：feature scaling は不要です）。

ただし、単一の decision tree は、特に深く成長させた場合（split が多い場合）、training data に容易に overfit します。overfitting を防ぐため、pruning（tree depth を制限する、または leaf ごとに必要な最小 sample 数を指定する）などの手法がよく使用されます。

decision tree には、主に 3 つの component があります。
- **Root Node**: tree の最上位の node で、データセット全体を表します。
- **Internal Nodes**: feature と、その feature に基づく decision を表す node です。
- **Leaf Nodes**: 最終的な outcome または prediction を表す node です。

tree は次のような形になることがあります。
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* 決定木は、攻撃を識別するための**ルール**を導出する侵入検知システムで使用されてきました。たとえば、ID3/C4.5ベースの初期のIDSは、正常なトラフィックと悪意のあるトラフィックを区別するために、人間が読み取り可能なルールを生成していました。また、ファイルの属性（ファイルサイズ、セクションエントロピー、API呼び出しなど）に基づいてファイルが悪意のあるものかどうかを判断する、malware analysisにも使用されます。決定木は明確であるため、透明性が必要な場合に有用です。アナリストは木構造を調査して、検知ロジックを検証できます。

#### **決定木の主な特徴:**

-   **問題の種類:** 分類と回帰の両方。攻撃と正常なトラフィックの分類などに一般的に使用されます。

-   **解釈可能性:** 非常に高い -- モデルの判断を可視化し、一連のif-thenルールとして理解できます。これは、モデルの動作に対する信頼と検証が重要なsecurityにおける大きな利点です。

-   **利点:** 特徴量間の非線形な関係や相互作用を捉えられます（各分割は相互作用として見ることができます）。特徴量のスケーリングやカテゴリ変数のone-hot encodingは必要ありません。木はこれらをネイティブに処理します。推論も高速です（予測は木の中のパスをたどるだけです）。

-   **制限:** 制御しない場合、overfittingしやすくなります（深い木はtraining setを記憶できます）。また、不安定になる可能性があります。データの小さな変化によって、異なる木構造になることがあります。単一のモデルとしては、より高度な手法の精度に及ばない場合があります（Random Forestsなどのアンサンブルは、通常、分散を低減することでより高い性能を発揮します）。

-   **最適な分割の探索:**
- **Gini Impurity**: ノードの不純度を測定します。Gini impurityが低いほど、より良い分割であることを示します。式は次のとおりです。

```plaintext
Gini = 1 - Σ(p_i^2)
```

ここで、`p_i`はクラス`i`に属するインスタンスの割合です。

- **Entropy**: データセットの不確実性を測定します。Entropyが低いほど、より良い分割であることを示します。式は次のとおりです。

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

ここで、`p_i`はクラス`i`に属するインスタンスの割合です。

- **Information Gain**: 分割後のEntropyまたはGini impurityの減少量です。Information gainが高いほど、より良い分割です。次のように計算します。

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

さらに、次の場合に木の成長を終了します。
- ノード内のすべてのインスタンスが同じクラスに属する場合。これはoverfittingにつながる可能性があります。
- 木の最大深度（ハードコードされた値）に到達した場合。これはoverfittingを防ぐ方法です。
- ノード内のインスタンス数が一定のしきい値を下回った場合。これもoverfittingを防ぐ方法です。
- 追加の分割によるinformation gainが一定のしきい値を下回った場合。これもoverfittingを防ぐ方法です。

<details>
<summary>例 -- 侵入検知用の決定木:</summary>
NSL-KDD datasetを使用して、ネットワーク接続を*normal*または*attack*のいずれかに分類する決定木をtrainingします。NSL-KDDは、従来のKDD Cup 1999 datasetを改良したもので、プロトコルタイプ、サービス、継続時間、ログイン失敗回数などの特徴量と、攻撃タイプまたは「normal」を示すラベルが含まれています。すべての攻撃タイプを「anomaly」クラスにマッピングし、二値分類（normal対anomaly）を行います。training後、test setで木の性能を評価します。
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
この decision tree の例では、極端な overfitting を避けるため、tree の深さを 10 に制限しました（`max_depth=10` パラメータ）。メトリクスは、tree が正常なトラフィックと attack トラフィックをどの程度適切に区別できるかを示しています。高い recall は、ほとんどの attack を検知できることを意味します（IDS にとって重要です）。一方、高い precision は false alarm が少ないことを意味します。decision tree は構造化データで適切な accuracy を達成することが多いものの、単一の tree では可能な限り最高の performance に到達できない場合があります。それでも、モデルの *interpretability* は大きな利点です。tree の分岐を調べれば、たとえば、接続を malicious と判定する際にどの feature（`service`、`src_bytes` など）が最も大きな影響を与えているかを確認できます。

</details>

### Random Forests

Random Forest は、decision tree を基盤として performance を向上させる **ensemble learning** 手法です。Random Forest は複数の decision tree（そのため「forest」と呼ばれます）を学習させ、それらの出力を組み合わせて最終的な prediction を行います（classification では通常、majority vote を使用します）。Random Forest の主な考え方は、**bagging**（bootstrap aggregating）と **feature randomness** の 2 つです。

-   **Bagging:** 各 tree は、training data からランダムに抽出した bootstrap sample（replacement あり）で学習します。これにより、tree 同士に多様性が生まれます。

-   **Feature Randomness:** tree の各 split では、すべての feature ではなく、feature のランダムな subset を split の候補として使用します。これにより、tree 同士の相関がさらに低くなります。

多数の tree の結果を平均することで、Random Forest は単一の decision tree が持つ可能性のある variance を低減します。簡単に言えば、個々の tree は overfit したり noise の影響を受けたりする可能性がありますが、多様な tree を多数組み合わせて voting することで、それらの error が平滑化されます。その結果、単一の decision tree よりも **higher accuracy** と優れた generalization を持つモデルになることがよくあります。さらに、Random Forest は、各 feature の split が平均して impurity をどの程度削減したかを調べることで、feature importance の推定値を提供できます。

Random Forest は、intrusion detection、malware classification、spam detection などのタスクにおいて、cybersecurity の **workhorse** となっています。最小限の tuning で out-of-the-box でも高い performance を発揮することが多く、大規模な feature set にも対応できます。たとえば intrusion detection では、Random Forest は単一の decision tree よりも優れた performance を示し、より subtle な attack pattern を検知しながら false positive を減らせる場合があります。研究では、NSL-KDD や UNSW-NB15 などの dataset における attack classification で、Random Forest が他の algorithm と比較して良好な performance を示すことが報告されています。<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** 主に classification（regression にも使用されます）。security log に多い high-dimensional な structured data に非常に適しています。

-   **Interpretability:** 単一の decision tree より低くなります。数百本の tree を一度に簡単に可視化したり説明したりすることはできません。ただし、feature importance score により、どの attribute が最も大きな影響を与えているかについて一定の insight を得られます。

-   **Advantages:** ensemble effect により、一般的に single-tree model より高い accuracy を実現します。overfitting に対して robust です。個々の tree が overfit しても、ensemble の方が generalize しやすくなります。numerical feature と categorical feature の両方に対応し、ある程度 missing data も処理できます。また、outlier に対しても比較的 robust です。

-   **Limitations:** model size が大きくなる可能性があります（多数の tree があり、それぞれが深くなる場合があります）。prediction は単一の tree より遅くなります（多数の tree の結果を aggregate する必要があるため）。interpretability も低くなります。重要な feature は分かっても、正確な logic を単純な rule として追跡するのは容易ではありません。dataset が極めて high-dimensional かつ sparse な場合、非常に大規模な forest の training は computationally heavy になる可能性があります。

-   **Training Process:**
1. **Bootstrap Sampling**: training data から replacement ありでランダムに sample し、複数の subset（bootstrap sample）を作成します。
2. **Tree Construction**: 各 bootstrap sample に対して、各 split で feature のランダムな subset を使用して decision tree を構築します。これにより、tree 同士に多様性が生まれます。
3. **Aggregation**: classification task では、すべての tree の prediction の majority vote によって最終 prediction を決定します。regression task では、すべての tree の prediction の average が最終 prediction になります。

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
同じ NSL-KDD dataset（normal と anomaly の binary label）を使用し、Random Forest classifier を training します。ensemble averaging によって variance が低減されるため、Random Forest は単一の decision tree と同等以上の performance を示すと期待できます。同じ metrics を使用して評価します。
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
この random forest は、通常、この intrusion detection タスクで優れた結果を達成します。データによっては、単一の decision tree と比較して、特に recall や precision など、F1 や AUC といった指標の改善が見られることがあります。これは、*「Random Forest (RF) は ensemble classifier であり、攻撃を効果的に分類するうえで、他の従来型 classifier と比較して良好に機能する」*という理解と一致します。<sup>[[6]](#references)</sup> security operations のコンテキストでは、多数の decision rule の平均化によって、false alarm を減らしながら、random forest model が攻撃をより確実に検知できる可能性があります。forest から得られる feature importance により、どの network feature が攻撃を最も示唆しているか（例：特定の network service や通常とは異なる packet 数）を把握できます。

</details>

### サポートベクターマシン (SVM)

Support Vector Machines は、主に classification（および SVR としての regression）に使用される強力な supervised learning model です。SVM は、2つの class 間の margin を最大化する **optimal separating hyperplane** を見つけようとします。この hyperplane の位置を決定するのは、training point の一部（boundary に最も近い「support vector」）だけです。margin（support vector と hyperplane の間の距離）を最大化することで、SVM は優れた汎化性能を達成する傾向があります。<sup>[[8]](#references)</sup>

SVM の強力な点は、**kernel function** を使用して non-linear な関係を処理できることです。データは暗黙的に、linear separator が存在する可能性のある、より高次元の feature space に変換できます。一般的な kernel には、polynomial、radial basis function (RBF)、sigmoid があります。たとえば、network traffic の class が raw feature space で linear に分離できない場合、RBF kernel によってデータをより高次元へ map し、SVM が linear な分割を見つけられるようにします（これは元の space では non-linear な boundary に相当します）。kernel を選択できる柔軟性により、SVM はさまざまな問題に対応できます。

SVM は、高次元の feature space（text data や malware opcode sequence など）や、sample 数に対して feature 数が多い状況で優れた性能を発揮することで知られています。2000年代には、malware classification や anomaly-based intrusion detection など、初期の cybersecurity application で広く使用され、高い accuracy を示すことが多くありました。

ただし、SVM は非常に大規模な dataset には容易に scale できません（training の計算量は sample 数に対して super-linear であり、多数の support vector を保存する必要があるため memory 使用量も大きくなる可能性があります）。実際には、数百万件の record を扱う network intrusion detection のようなタスクでは、慎重な subsampling や approximate method を使用しない限り、SVM は遅すぎる可能性があります。

#### **SVM の主な特性：**

-   **問題の種類：** Classification（one-vs-one/one-vs-rest による binary または multiclass）および regression variant。明確な margin separation がある binary classification でよく使用されます。

-   **解釈可能性：** Medium -- SVM は decision tree や logistic regression ほど解釈しやすくありません。どの data point が support vector であるかを特定し、どの feature が影響を与えている可能性があるか（linear kernel の場合は weight を通じて）をある程度把握することはできますが、実際には SVM（特に non-linear kernel を使用するもの）は black-box classifier として扱われます。

-   **利点：** 高次元 space で効果的。kernel trick により複雑な decision boundary を model 化できます。margin を最大化すれば overfitting に強く（特に適切な regularization parameter C を使用した場合）、class が大きな距離で分離されていない場合でも適切に機能します（最適な妥協点となる boundary を見つけます）。

-   **制限事項：** 大規模な dataset では **計算負荷が高く** なります（data の増加に伴い、training と prediction の両方が適切に scale しません）。kernel と regularization parameter（C、kernel type、RBF の gamma など）の慎重な tuning が必要です。probabilistic output は直接提供されません（ただし、Platt scaling を使用して probability を取得できます）。また、SVM は kernel parameter の選択に敏感であり、適切でない選択は underfit や overfit につながる可能性があります。

*cybersecurity における使用例：* SVM は **malware detection**（抽出した feature や opcode sequence に基づく file の分類など）、**network anomaly detection**（traffic を normal または malicious として分類）、**phishing detection**（URL の feature を使用）に利用されてきました。たとえば、SVM に email の feature（特定の keyword の数、sender reputation score など）を入力し、phishing または legitimate として分類できます。また、KDD などの feature set による **intrusion detection** にも適用されており、計算コストと引き換えに高い accuracy を達成することがよくあります。

<details>
<summary>例 -- Malware Classification のための SVM：</summary>
今回は、phishing website dataset を SVM で使用します。SVM は遅くなる可能性があるため、必要に応じて training には data の subset を使用します（dataset は約11,000 instance であり、SVM で十分に処理できます）。non-linear data で一般的に選択される RBF kernel を使用し、ROC AUC を計算するために probability estimate を有効にします。
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
SVM modelは、同じタスクに対する logistic regression と比較できるメトリクスを出力します。データが特徴量によって明確に分離されている場合、SVMは高い accuracy と AUCを達成する可能性があります。一方、データセットに多くのノイズや重なり合うクラスがある場合、SVMが logistic regression を大きく上回るとは限りません。実際には、特徴量とクラスの間に複雑で非線形な関係がある場合、SVMによって性能が向上することがあります。RBF kernelは、logistic regression では捉えられない曲線状の decision boundary を捉えられるためです。すべての model と同様に、bias と variance のバランスを取るには、`C`（regularization）および kernel parameters（RBFの`gamma`など）の慎重な tuning が必要です。

</details>

#### Logistic Regression と SVM の違い

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log‑loss**（cross‑entropy）を最小化します。 | **margin**を最大化しながら、**hinge‑loss**を最小化します。 |
| **Decision boundary** | _P(y\|x)_をモデル化する**best‑fit hyperplane**を求めます。 | **maximum‑margin hyperplane**（最も近い点との間隔が最大の hyperplane）を求めます。 |
| **Output** | **Probabilistic** – σ(w·x + b) によって calibration された class probabilities を返します。 | **Deterministic** – class labels を返します。probabilities には追加処理（Platt scalingなど）が必要です。 |
| **Regularisation** | L2（default）またはL1を使用し、under/over‑fitting を直接調整します。 | C parameter により margin width と mis‑classifications のトレードオフを調整します。kernel parameters によって複雑性が加わります。 |
| **Kernels / Non‑linear** | Native form は**linear**です。feature engineering により non‑linearity を追加します。 | 組み込みの**kernel trick**（RBF、polyなど）により、high‑dimensional space で複雑な boundary を model 化できます。 |
| **Scalability** | **O(nd)**で convex optimisation を解き、非常に大きな n を適切に処理できます。 | specialised solvers を使用しない場合、training の memory/time が**O(n²–n³)**になる可能性があり、巨大な n にはあまり適していません。 |
| **Interpretability** | **High** – weights が feature influence を示し、odds ratio も直感的です。 | non‑linear kernels では**Low**です。support vectors は sparse ですが、説明は容易ではありません。 |
| **Sensitivity to outliers** | smooth な log‑loss を使用するため、影響を受けにくくなっています。 | hard margin の hinge‑loss は**sensitive**になる可能性があります。soft‑margin（C）によって緩和できます。 |
| **Typical use cases** | Credit scoring、medical risk、A/B testing – **probabilities と explainability**が重要な場合。 | Image/text classification、bio‑informatics – **complex boundaries**と**high‑dimensional data**が重要な場合。 |

* **calibrated probabilities、interpretability、または巨大な dataset を扱う必要がある場合は、Logistic Regression を選択します。**
* **manual feature engineering なしで non‑linear relations を捉えられる flexible model が必要な場合は、SVM（kernels付き）を選択します。**
* どちらも convex objectives を最適化するため、**global minima が保証されます**。ただし、SVMの kernels には hyper‑parameters と computational cost が追加されます。

### Naive Bayes

Naive Bayes は、feature 間に強い independence assumption を置き、Bayes' Theorem を適用する**probabilistic classifiers**の family です。この「naive」な仮定にもかかわらず、Naive Bayes は特定の applications、特に spam detection などの text や categorical data を扱う applications で、驚くほどうまく機能することがよくあります。<sup>[[9]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem は Naive Bayes classifiers の基礎です。これは random events の conditional probabilities と marginal probabilities の関係を示します。formula は次のとおりです。
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` は、特徴 `B` が与えられた場合のクラス `A` の事後確率です。
- `P(B|A)` は、クラス `A` が与えられた場合の特徴 `B` の尤度です。
- `P(A)` は、クラス `A` の事前確率です。
- `P(B)` は、特徴 `B` の事前確率です。

例えば、あるテキストが子供または成人によって書かれたものかを分類したい場合、テキスト内の単語を特徴として使用できます。初期データに基づき、Naive Bayes classifier は各単語がそれぞれの候補クラス（子供または成人）に属する確率をあらかじめ計算します。新しいテキストが与えられると、テキスト内の単語に基づいて各候補クラスの確率を計算し、最も高い確率を持つクラスを選択します。

この例から分かるように、Naive Bayes classifier は非常に単純で高速ですが、特徴が独立していると仮定します。これは実世界のデータでは必ずしも当てはまりません。


#### Naive Bayes Classifiers の種類

データの種類と特徴の分布に応じて、Naive Bayes classifiers にはいくつかの種類があります。
- **Gaussian Naive Bayes**: 特徴が Gaussian（正規）分布に従うと仮定します。連続データに適しています。
- **Multinomial Naive Bayes**: 特徴が多項分布に従うと仮定します。テキスト分類における単語数など、離散データに適しています。
- **Bernoulli Naive Bayes**: 特徴が二値（0 または 1）であると仮定します。テキスト分類における単語の存在または不在など、二値データに適しています。
- **Categorical Naive Bayes**: 特徴がカテゴリ変数であると仮定します。色や形状に基づく果物の分類など、カテゴリデータに適しています。


#### **Naive Bayes の主な特徴:**

-   **問題の種類:** 分類（binary または multi-class）。cybersecurity におけるテキスト分類タスク（spam、phishing など）で一般的に使用されます。

-   **解釈可能性:** 中程度 -- decision tree ほど直接的には解釈できませんが、学習した確率（例: spam メールと ham メールのどちらに現れやすい単語か）を調べることができます。必要に応じて、モデルの形式（クラスごとの各特徴の確率）を理解できます。

-   **利点:** 大規模なデータセットでも、training と prediction が**非常に高速**です（instances 数 * features 数に対して linear）。特に適切な smoothing を使用すれば、確率を信頼性高く推定するために必要なデータ量が比較的少なくて済みます。特に、特徴が独立してクラスの判定に寄与する場合、baseline としては驚くほど正確なことがよくあります。高次元データ（例: text から得られる数千の features）でも適切に動作します。smoothing parameter の設定以外に、複雑な tuning は必要ありません。

-   **制限:** 特徴の相関が強い場合、独立性の仮定によって accuracy が制限される可能性があります。例えば、network data では `src_bytes` と `dst_bytes` のような features が相関することがありますが、Naive Bayes はその相互作用を捉えられません。データサイズが非常に大きくなると、より表現力の高いモデル（ensembles や neural nets など）が、feature dependencies を学習することで NB を上回る可能性があります。また、attack を識別するために特徴の組み合わせが必要な場合（個々の特徴が独立しているだけでは不十分な場合）、NB は苦戦します。

> [!TIP]
> *cybersecurity における使用例:* 典型的な用途は **spam detection** です -- Naive Bayes は初期の spam filters の中核であり、特定の tokens（単語、フレーズ、IP addresses）の頻度を使用して、メールが spam である確率を計算していました。また、**phishing email detection** や **URL classification** にも使用されます。そこでは、特定の keywords や特徴（URL 内の "login.php"、または URL path 内の `@` など）の存在が phishing の確率に影響します。malware analysis では、ソフトウェア内に特定の API calls や permissions が存在するかどうかを使用して、それが malware かどうかを予測する Naive Bayes classifier を想定できます。より高度な algorithms の方が高い性能を示すことが多い一方、Naive Bayes は speed と simplicity により、依然として優れた baseline です。

<details>
<summary>Example -- phishing detection のための Naive Bayes:</summary>
Naive Bayes を実演するため、NSL-KDD intrusion dataset（binary labels 付き）に Gaussian Naive Bayes を使用します。Gaussian NB は、各 feature がクラスごとに normal distribution に従うものとして扱います。多くの network features は discrete または highly skewed であるため、これは大まかな選択ですが、continuous feature data に NB を適用する方法を示すことができます。binary features の dataset（triggered alerts の集合など）に Bernoulli NB を選択することもできますが、ここでは一貫性を保つため NSL-KDD を使用します。
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
このコードは、攻撃を検出するために Naive Bayes classifier をトレーニングします。Naive Bayes は、特徴量間の独立性を仮定し、トレーニングデータに基づいて `P(service=http | Attack)` や `P(Service=http | Normal)` などを計算します。その後、観測された特徴量に基づいて、新しい接続を normal または attack として分類します。NSL-KDD における NB の性能は、より高度なモデルほど高くない可能性があります（特徴量の独立性が実際には成り立たないため）が、多くの場合十分な性能を発揮し、極めて高速という利点があります。リアルタイムのメール filtering や URL の初期 triage などのシナリオでは、Naive Bayes model はリソース使用量を抑えながら、明らかに malicious なケースを迅速に flag できます。

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors は、最も単純な machine learning algorithms の1つです。これは、トレーニングセット内の例との類似性に基づいて予測を行う **non-parametric, instance-based** method です。classification における考え方は、新しい data point を分類する際、training data 内で最も近い **k** 個の point（その「nearest neighbors」）を見つけ、それらの neighbor の中で majority class を割り当てるというものです。「近さ」は distance metric によって定義され、numeric data では通常 Euclidean distance が使用されます（feature や problem の種類に応じて、別の distance を使用することもできます）。<sup>[[10]](#references)</sup>

K-NN には *明示的な training が不要* です。「training」phase では dataset を保存するだけです。すべての処理は query（prediction）時に行われます。algorithm は query point とすべての training point の distance を計算し、nearest point を見つけなければなりません。そのため、prediction time は **training samples の数に対して線形** となり、大規模な dataset ではコストが高くなる可能性があります。このため、k-NN は小規模な dataset、または simplicity のために memory と speed をトレードオフできるシナリオに最適です。

シンプルであるにもかかわらず、k-NN は非常に複雑な decision boundary を model 化できます（実質的に decision boundary は、example の分布によって決まる任意の形状になり得るためです）。Decision boundary が非常に不規則で、かつ大量の data がある場合に適しており、基本的には data に「自ら語らせる」ことができます。ただし、高次元では distance metric の意味が薄れ（curse of dimensionality）、非常に多くの sample がない限り、この method は苦戦する可能性があります。

*サイバーセキュリティにおけるユースケース:* k-NN は anomaly detection に適用されています。たとえば、intrusion detection system は、ある network event の nearest neighbors（過去の event）の大半が malicious だった場合、その network event を malicious と label できます。Normal traffic が cluster を形成し、attack が outlier である場合、k-NN approach（k=1 または小さい k）は、実質的に **nearest-neighbor anomaly detection** となります。また、k-NN は binary feature vector による malware family の分類にも使用されています。新しい file は、feature space 内で既知のその malware family の instance に非常に近い場合、その malware family として分類されます。実際には、k-NN はより scalable な algorithm ほど一般的ではありませんが、conceptually straightforward であり、baseline として、または小規模な problem に使用されることがあります。

#### **k-NN の主な特性:**

-   **Problem の種類:** Classification（regression の variant も存在します）。これは *lazy learning* method であり、明示的な model fitting は行いません。

-   **Interpretability:** Low から medium -- global model や簡潔な説明はありませんが、decision に影響を与えた nearest neighbors を見ることで結果を解釈できます（例: 「この network flow は、これら3つの既知の malicious flow と類似しているため、malicious と分類された」）。したがって、説明は example-based にできます。

-   **Advantages:** 実装と理解が非常に簡単です。data distribution に関する仮定を置きません（non-parametric）。multi-class problem を自然に処理できます。Decision boundary は data distribution によって形成され、非常に複雑になり得るという意味で、**adaptive** です。

-   **Limitations:** 大規模な dataset では prediction が遅くなる可能性があります（多数の distance を計算する必要があるためです）。Memory-intensive であり、すべての training data を保存します。高次元の feature space では、すべての point がほぼ等距離になる傾向があるため、performance が低下します（「nearest」という概念の意味が薄れるためです）。*k*（neighbor の数）を適切に選択する必要があります。k が小さすぎると noisy になり、k が大きすぎると他の class の無関係な point が含まれる可能性があります。また、distance calculation は scale の影響を受けやすいため、feature は適切に scaled する必要があります。

<details>
<summary>Example -- Phishing Detection のための k-NN:</summary>

ここでも NSL-KDD（binary classification）を使用します。k-NN は computationally heavy であるため、この demonstration では tractable に保つため training data の subset を使用します。full 125k の中から、たとえば 20,000 training sample を選び、k=5 neighbor を使用します。training 後（実際には data を保存するだけです）、test set で evaluate します。また、distance calculation のために feature を scale し、scale の違いによって単一の feature が支配的にならないようにします。
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
k-NN modelは、training setのsubset内にある最も近い5つのconnectionを調べることで、connectionを分類します。たとえば、そのneighborのうち4つがattack（anomaly）で、1つがnormalの場合、新しいconnectionはattackとして分類されます。performanceは妥当な場合もありますが、同じdataに対して十分にtuningされたRandom ForestやSVMほど高くないことがよくあります。ただし、k-NNはclass distributionが非常に不規則で複雑な場合に、memory-based lookupとして機能し、力を発揮することがあります。cybersecurityでは、k-NN（k=1または小さいk）を、既知のattack patternを例によって検出するため、またはより複雑なsystemのcomponent（例：clusteringを行い、その後cluster membershipに基づいて分類する）として利用できます。
</details>

### Gradient Boosting Machines（例：XGBoost）

Gradient Boosting Machinesは、structured data向けの最も強力なalgorithmの一つです。**gradient boosting**とは、weak learner（多くの場合decision tree）のensembleを逐次的に構築するtechniqueを指します。各new modelは、以前のensembleのerrorsを修正します。treeをparallelに構築して平均するbagging（Random Forests）とは異なり、boostingはtreeを*one by one*で構築し、それぞれがprevious treeによって誤ってpredictionされたinstanceに、より重点を置きます。<sup>[[11]](#references)</sup>

近年最もpopularなimplementationは**XGBoost**、**LightGBM**、**CatBoost**であり、いずれもgradient boosting decision tree（GBDT）libraryです。これらはmachine learning competitionやapplicationで非常に高い成果を上げており、しばしば**tabular datasetでstate-of-the-art performanceを達成**しています。cybersecurityでは、researcherやpractitionerが、**malware detection**（fileやruntime behaviorから抽出したfeatureを使用）や**network intrusion detection**などのtaskにgradient boosted treeを利用しています。たとえばgradient boosting modelは、「多数のSYN packetと異常なportがある -> scanの可能性が高い」といった多数のweak rule（tree）を組み合わせ、さまざまな微妙なpatternを考慮する強力なcomposite detectorを構築できます。

なぜboosted treeはこれほど効果的なのでしょうか。sequence内の各treeは、current ensembleのpredictionにおける*residual error*（gradient）を使ってtrainingされます。これにより、modelは弱い領域を徐々に**「boost」**します。base learnerとしてdecision treeを使用するため、最終modelは複雑なinteractionとnon-linear relationを捉えられます。また、boostingにはbuilt-in regularizationの一種が備わっています。多数の小さなtreeを追加し、その寄与をlearning rateでscaleすることで、適切なparameterを選択すれば、過度なoverfittingを起こさずに高いgeneralization性能を得られることがよくあります。

#### **Gradient Boostingの主な特徴：**

-   **Problemの種類：** 主にclassificationとregressionです。securityでは通常classification（例：connectionやfileをbinary classificationする）に使われます。binary、multi-class（適切なlossを使用）、さらにranking problemにも対応します。

-   **Interpretability：** 低から中程度です。単一のboosted treeは小さくても、full modelには数百本のtreeが含まれる場合があり、全体として人間がinterpretできるものではありません。ただし、Random Forestと同様にfeature importance scoreを提供でき、SHAP（SHapley Additive exPlanations）のようなtoolを使えば、individual predictionをある程度interpretできます。

-   **Advantages：** structured/tabular dataに対して、しばしば**最も高いperformanceを発揮する**algorithmです。複雑なpatternやinteractionを検出できます。number of tree、treeのdepth、learning rate、regularization termなど、多数のtuning knobがあり、model complexityを調整してoverfittingを防げます。modern implementationはspeed向けに最適化されています（例：XGBoostはsecond-order gradient informationとefficient data structureを使用します）。適切なloss functionと組み合わせたり、sample weightを調整したりすることで、imbalanced dataにも比較的うまく対応できます。

-   **Limitations：** より単純なmodelよりもtuningが複雑です。treeがdeepであったり、treeの数が多かったりするとtrainingが遅くなる可能性があります（ただし、同じdataで同等のdeep neural networkをtrainingするよりは、通常なお高速です）。適切にtuningしないとmodelがoverfitする可能性があります（例：regularizationが不十分な状態で、deep treeが多すぎる場合）。hyperparameterが多いため、gradient boostingを効果的に使うには、より多くのexpertiseやexperimentが必要になる場合があります。また、tree-based methodと同様に、非常にsparseでhigh-dimensionalなdataをlinear modelやNaive Bayesほどefficientには本質的に扱えません（text classificationなどに適用することはできますが、feature engineeringなしではfirst choiceにならない可能性があります）。

> [!TIP]
> *cybersecurityでのuse case：* decision treeやrandom forestを利用できるほぼすべての場面で、gradient boosting modelのほうが高いaccuracyを達成できる可能性があります。たとえば、**Microsoftのmalware detection** competitionでは、binary fileからengineerしたfeatureに対してXGBoostが盛んに使用されてきました。**Network intrusion detection**のresearchでは、GBDT（例：CIC-IDS2017やUNSW-NB15 datasetに対するXGBoost）がtop resultを報告することがよくあります。これらのmodelは、幅広いfeature（protocol type、特定のeventのfrequency、trafficのstatistical featureなど）を受け取り、それらを組み合わせてthreatを検出できます。phishing detectionでは、gradient boostingがURLのlexical feature、domain reputation feature、page content featureを組み合わせ、非常に高いaccuracyを実現できます。ensemble approachにより、data内の多くのcorner caseやsubtleな特徴を網羅できます。

<details>
<summary>Example -- XGBoost for Phishing Detection:</summary>
phishing datasetに対してgradient boosting classifierを使用します。内容をシンプルかつself-containedにするため、`sklearn.ensemble.GradientBoostingClassifier`（より遅いものの、分かりやすいimplementation）を使用します。通常は、より高いperformanceと追加featureのために、`xgboost`または`lightgbm` libraryを使用することがあります。modelをtrainingし、これまでと同様にevaluateします。
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
この gradient boosting model は、この phishing dataset で非常に高い accuracy と AUC を達成する可能性が高いです（このようなデータでは、適切な tuning により 95% を超える accuracy を達成できることが多く、文献でも確認されています。これは、GBDTs が *"the state of the art model for tabular dataset"* と見なされる理由を示しています。複雑なパターンを捉えることで、より単純なアルゴリズムを上回ることが多いためです。<sup>[[11]](#references)</sup> cybersecurity の文脈では、見逃しを減らしながら、より多くの phishing sites や attacks を検出できる可能性があります。もちろん、overfitting には注意が必要です。このような model を deployment 向けに開発する際は、通常、cross-validation などの techniques を使用し、validation set での performance を監視します。

</details>

### Models の組み合わせ: Ensemble Learning と Stacking

Ensemble learning は、全体的な performance を向上させるために**複数の models を組み合わせる** strategy です。すでに具体的な ensemble methods として、Random Forest（bagging による trees の ensemble）と Gradient Boosting（sequential boosting による trees の ensemble）を見てきました。しかし、ensemble は **voting ensembles** や **stacked generalization (stacking)** など、他の方法でも作成できます。基本的な考え方は、異なる models が異なるパターンを捉えたり、異なる弱点を持ったりする可能性があるため、それらを組み合わせることで、**各 model の errors を別の model の strengths で補う**ことです。<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** 単純な voting classifier では、複数の多様な models（例えば、logistic regression、decision tree、SVM）を train し、最終的な prediction について vote させます（classification では majority vote）。vote に重みを付ける場合（例えば、より正確な models に高い weight を与える場合）は、weighted voting scheme になります。これは通常、個々の models が十分に優れており、互いに独立している場合に performance を向上させます。ensemble により、個々の model が mistake を犯す risk が減少します。なぜなら、他の models がそれを correct できる可能性があるためです。これは、1つの意見だけでなく、専門家の panel を持つようなものです。

-   **Stacking (Stacked Ensemble):** Stacking はさらに一歩進んだ方法です。単純な vote の代わりに、base models の predictions を**最適に組み合わせる方法を学習する** **meta-model** を train します。例えば、3つの異なる classifiers（base learners）を train し、その outputs（または probabilities）を features として meta-classifier（多くの場合、logistic regression のような単純な model）に入力し、最適な組み合わせ方法を学習させます。meta-model は、overfitting を避けるために validation set または cross-validation を使用して train します。Stacking は、*どの状況でどの models をより信頼するべきか*を学習することで、単純な voting を上回ることがよくあります。cybersecurity では、ある model が network scans の検出に優れ、別の model が malware beaconing の検出に優れている場合、stacking model はそれぞれを適切に頼る方法を学習できます。

Voting または stacking による ensembles は、一般に**accuracy**と robustness を**向上**させます。欠点は、complexity が増加し、interpretability が低下する場合があることです（ただし、decision trees の average など、一部の ensemble approaches は feature importance などを通じて、ある程度の insight を提供できます）。実際には、operational constraints が許せば、ensemble の使用によって detection rates を高められます。cybersecurity challenges（および一般的な Kaggle competitions）で多くの winning solutions が、performance を最後のわずかな部分まで高めるために ensemble techniques を使用しています。

<details>
<summary>Example -- Phishing Detection の Voting Ensemble:</summary>
model stacking を説明するために、phishing dataset 上で、これまでに説明したいくつかの models を組み合わせてみましょう。base learners として logistic regression、decision tree、k-NN を使用し、meta-learner として Random Forest を使用して、それらの predictions を aggregate します。meta-learner は、base learners の outputs（training set 上で cross-validation を使用）を用いて train します。stacked model は、個々の models と同程度、またはそれをわずかに上回る performance になると予想されます。
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
Stacked ensembleは、base modelそれぞれの相補的な強みを活用します。たとえば、logistic regressionはデータの線形的な側面を処理し、decision treeは特定のルールに似た相互作用を捉え、k-NNはfeature spaceの局所的な近傍で優れた性能を発揮する場合があります。meta-model（ここではrandom forest）は、これらの入力にどのような重みを付けるかを学習できます。結果として得られるmetricsは、単一モデルのmetricsを上回ることが多く、改善幅がわずかな場合もあります。phishingの例では、logistic単体のF1が0.95、treeが0.94だった場合、stackは各モデルが誤る部分を補うことで0.96を達成できる可能性があります。

このようなensemble methodsは、*「複数のモデルを組み合わせると、通常はgeneralizationが向上する」*という原則を示しています。<sup>[[12]](#references)</sup> Cybersecurityでは、複数のdetection engine（rule-based、machine learning、anomaly-basedなど）を用意し、それらのalertを集約するlayer、つまり実質的にensembleの一形態を設けることで実装できます。これにより、より高い信頼度で最終的な判定を行えます。このようなシステムをdeployする際は、複雑性の増加を考慮し、ensembleが管理や説明の面で過度に扱いにくくならないようにする必要があります。しかしaccuracyの観点では、ensembleとstackingはmodel performanceを向上させる強力なtoolです。

</details>

[deep-learning page](AI-Deep-Learning.md)で説明したneural-network approachesは、datasetとcompute budgetが追加の複雑性を正当化できる場合、intrusion detectionにおいてこれらのclassical modelを補完できます。<sup>[[13]](#references)</sup>

## References

- [1] [CybersecurityにおけるAIとMachine Learning - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regressionの解説 - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - 「Machine Learningと複数のDatasetを用いたPhishing AttacksおよびWebsitesのClassification（比較分析）」](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - 「Information Gainを用いたRandom Forest ClassifierによるDenial of Services Attack Detection」](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - 「Gini ImpurityベースのWeighted Random Forest（GIWRF）feature selection techniqueを用いたintrusion detection system向けmachine learning modelのperformance analysis」](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Support Vector Machineとは？ - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayesによるspam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [k-Nearest Neighbors（KNN）とは？ - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDTの謎を解く：LightGBM、XGBoost、CatBoostの仕組み - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning：強みを組み合わせてModel Performanceを向上させる - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Deep LearningがIntrusion Detection Systemsを強化する方法](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
