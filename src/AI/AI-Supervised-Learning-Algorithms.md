# 教師あり学習アルゴリズム

{{#include ../banners/hacktricks-training.md}}

## 基本情報

教師あり学習では、ラベル付きデータを使用してモデルを訓練し、新しい未知の入力に対する予測を行えるようにします。サイバーセキュリティでは、教師あり機械学習は、侵入検知（ネットワークトラフィックを*正常*または*攻撃*に分類）、マルウェア検知（悪意のあるソフトウェアと無害なソフトウェアの識別）、phishing検知（不正なWebサイトやメールの識別）、spamフィルタリングなど、さまざまなタスクに広く適用されています。各アルゴリズムにはそれぞれ長所があり、異なる種類の問題（classificationまたはregression）に適しています。以下では、主要な教師あり学習アルゴリズムを確認し、その仕組みを説明するとともに、実際のサイバーセキュリティデータセットでの使用方法を示します。また、モデルを組み合わせること（ensemble learning）によって、予測性能を向上できる場合が多いことについても説明します。

## アルゴリズム

-   **Linear Regression:** データに線形方程式を適合させ、数値結果を予測する基本的なregressionアルゴリズムです。

-   **Logistic Regression:** （名前に反して）ロジスティック関数を使用して二値結果の確率をモデル化するclassificationアルゴリズムです。

-   **Decision Trees:** 特徴量によってデータを分割して予測を行う、木構造のモデルです。解釈しやすいことからよく使用されます。

-   **Random Forests:** Decision Treesのensemble（baggingによる）であり、精度を向上させ、過学習を低減します。

-   **Support Vector Machines (SVM):** 最適な分離超平面を見つける最大マージン分類器です。非線形データにはkernelsを使用できます。

-   **Naive Bayes:** Bayesの定理に基づく確率的分類器で、特徴量が独立していると仮定します。spamフィルタリングで広く使用されていることで有名です。

-   **k-Nearest Neighbors (k-NN):** 最も近い近傍の多数派クラスに基づいてサンプルにラベルを付ける、単純な「instance-based」分類器です。

-   **Gradient Boosting Machines:** 弱い学習器（通常はDecision Trees）を順番に追加することで強力な予測器を構築するensembleモデルです（例：XGBoost、LightGBM）。

以下の各セクションでは、アルゴリズムの改善された説明と、`pandas`や`scikit-learn`などのライブラリ（neural networkの例では`PyTorch`）を使用した**Python code example**を示します。例では、一般公開されているサイバーセキュリティデータセット（侵入検知用のNSL-KDDやPhishing Websitesデータセットなど）を使用し、次の一貫した構成に従います。

1.  **データセットを読み込む**（利用可能な場合はURL経由でdownload）。

2.  **データを前処理する**（例：categorical featuresのencode、値のscale、train/test setsへの分割）。

3.  **training data**でモデルを訓練する。

4.  **test set**で、classificationにはaccuracy、precision、recall、F1-score、ROC AUCなどのmetricsを使用して評価する（regressionにはmean squared errorを使用）。

各アルゴリズムを詳しく見ていきましょう。

### Linear Regression

Linear regressionは、連続的な数値を予測するために使用される**regression**アルゴリズムです。入力features（独立変数）と出力（従属変数）の間に線形関係があると仮定します。モデルは、featuresとtargetの関係を最もよく表す直線（高次元では超平面）を適合させようとします。通常は、予測値と実際の値の間の二乗誤差の合計を最小化することで実行されます（Ordinary Least Squares method）。<sup>[[8]](#references)</sup>

Linear regressionを表す最も簡単な方法は、線を使うことです。
```plaintext
y = mx + b
```
場所:

- `y` は予測値（出力）
- `m` は直線の傾き（係数）
- `x` は入力特徴量
- `b` は y 切片

線形回帰の目的は、データセット内の予測値と実際の値の差を最小化する、最も適合する直線を見つけることです。もちろん、これは非常に単純なもので、2つのカテゴリを分離する直線になります。しかし、次元が追加されると、直線はより複雑になります:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* Linear regression 自体は、（多くの場合 classification が中心となる）主要な security tasks ではあまり一般的ではありませんが、数値的な結果の予測に利用できます。たとえば、過去のデータに基づいて **network traffic の量を予測**したり、**一定期間内の攻撃数を推定**したりするために Linear regression を使用できます。また、特定の system metrics が与えられた場合に、risk score や攻撃が検知されるまでの予想時間を予測することも可能です。実際には、intrusion や malware の検出には classification algorithms（logistic regression や trees など）がより頻繁に使用されますが、Linear regression は基礎として機能し、regression 指向の分析に役立ちます。

#### **Linear Regression の主な特徴:**

-   **問題の種類:** Regression（連続値の予測）。出力に threshold を適用しない限り、直接的な classification には適していません。

-   **解釈可能性:** 高い -- coefficients は解釈しやすく、各 feature の線形的な影響を示します。

-   **利点:** シンプルかつ高速。regression tasks の優れた baseline となり、真の関係がおおむね線形である場合に適切に機能します。

-   **制限事項:** 手動で feature engineering を行わない限り、複雑または非線形の関係を捉えられません。関係が非線形の場合は underfitting になりやすく、outliers の影響を受けやすいため、結果が歪む可能性があります。

-   **最適な適合の算出:** 考えられるカテゴリを分離する最適な fit line を求めるために、**Ordinary Least Squares (OLS)** と呼ばれる手法を使用します。この手法は、観測値と linear model による予測値の差を二乗したものの合計を最小化します。

<details>
<summary>例 -- Intrusion Dataset における Connection Duration の予測（Regression）
</summary>
以下では、NSL-KDD cybersecurity dataset を使用して Linear regression を実演します。ここでは、他の features に基づいて network connections の `duration` を予測することで、これを regression problem として扱います。（実際には、`duration` は NSL-KDD の1つの feature です。ここでは regression を説明するためだけに使用します。）dataset を読み込み、preprocess（categorical features を encode）し、linear regression model を train した後、test set 上で Mean Squared Error (MSE) と R² score を評価します。
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
この例では、linear regression model は、他のネットワーク特徴量から接続の `duration` を予測しようとします。性能は Mean Squared Error (MSE) と R² で測定します。R² が 1.0 に近い場合、モデルが `duration` の分散の大部分を説明していることを示します。一方、R² が低い、または負の場合は、適合度が低いことを示します。（ここで R² が低くても驚かないでください。与えられた特徴量から `duration` を予測するのは難しい可能性があり、パターンが複雑な場合は linear regression では捉えられないことがあります。）
</details>

### Logistic Regression

Logistic regression は、あるインスタンスが特定のクラス（通常は「positive」クラス）に属する確率をモデル化する **classification** アルゴリズムです。名前に regression が含まれていますが、*logistic* regression は離散的な結果に使用されます（continuous な結果を扱う linear regression とは異なります）。特に **binary classification**（2つのクラス。例：malicious と benign）に使用されますが、multi-class 問題にも拡張できます（softmax または one-vs-rest アプローチを使用）。<sup>[[1]](#references)</sup>

logistic regression は、予測値を確率に変換するために logistic function（sigmoid function とも呼ばれます）を使用します。sigmoid function は 0 から 1 の間の値を取り、classification の要件に応じて S 字状の曲線で増加する関数です。これは binary classification タスクに適しています。したがって、各入力の各 feature に割り当てられた weight を掛け、その結果を sigmoid function に渡して確率を生成します：
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` は、入力 `x` が与えられたときに出力 `y` が 1 となる確率です
- `e` は自然対数の底です
- `z` は入力特徴量の線形結合で、通常は `z = w1*x1 + w2*x2 + ... + wn*xn + b` と表されます。ここでも、最も単純な形では直線ですが、より複雑なケースでは複数の次元（特徴量ごとに1つ）を持つ超平面になります。

> [!TIP]
> *サイバーセキュリティでのユースケース:* 多くのセキュリティ上の問題は本質的に yes/no の判断であるため、ロジスティック回帰は広く使用されています。たとえば、侵入検知システムでは、ネットワーク接続の特徴量に基づいて、その接続が攻撃かどうかを判断するためにロジスティック回帰を使用できます。フィッシング検知では、ロジスティック回帰により、Webサイトの特徴（URLの長さ、`@` 記号の有無など）を、フィッシングである確率に組み合わせることができます。初期世代のスパムフィルターで使用されており、現在も多くの分類タスクで有力なベースラインとなっています。

#### 非バイナリ分類のためのロジスティック回帰

ロジスティック回帰はバイナリ分類向けに設計されていますが、**one-vs-rest**（OvR）や **softmax regression** などの手法を使用して、マルチクラス問題にも対応できます。OvRでは、クラスごとに個別のロジスティック回帰モデルを学習し、そのクラスを陽性クラスとして、その他すべてのクラスと比較します。予測確率が最も高いクラスが最終的な予測として選択されます。Softmax regressionは、出力層にsoftmax関数を適用することでロジスティック回帰を複数クラスに一般化し、すべてのクラスに対する確率分布を生成します。

#### **ロジスティック回帰の主な特徴:**

-   **問題の種類:** 分類（通常はバイナリ）。陽性クラスの確率を予測します。

-   **解釈可能性:** 高い -- 線形回帰と同様に、特徴量の係数から、各特徴量が結果の対数オッズにどのような影響を与えるかを示せます。この透明性は、アラートに寄与する要因を理解するうえで、セキュリティ分野で高く評価されることが多いです。

-   **利点:** 学習がシンプルかつ高速で、特徴量と結果の対数オッズの関係が線形である場合に適切に機能します。確率を出力するため、リスクスコアリングが可能です。適切な正則化を使用すれば、汎化性能が高く、通常の線形回帰よりも多重共線性に適切に対処できます。

-   **制限:** 特徴空間における決定境界が線形であると仮定します（実際の境界が複雑または非線形の場合は機能しません）。交互作用や非線形効果が重要な問題では、多項式特徴量や交互作用特徴量を手動で追加しない限り、性能が低下する可能性があります。また、クラスが特徴量の線形結合によって容易に分離できない場合、ロジスティック回帰の効果は低くなります。


<details>
<summary>例 -- ロジスティック回帰によるフィッシングWebサイト検知:</summary>

Webサイトから抽出した特徴量（URLにIPアドレスが含まれているか、ドメインの年齢、HTML内に不審な要素が存在するかなど）と、そのサイトがフィッシングサイトか正規サイトかを示すラベルを含む **Phishing Websites Dataset**（UCI repository提供）を使用します。ロジスティック回帰モデルを学習してWebサイトを分類し、テスト用の分割データに対する accuracy、precision、recall、F1-score、ROC AUCを評価します。
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
この phishing detection の例では、logistic regression は各 website が phishing である確率を生成します。accuracy、precision、recall、F1 を評価することで、モデルの性能を把握できます。たとえば、高い recall は、ほとんどの phishing site を検出できることを意味します（攻撃の見逃しを最小限に抑える必要がある security において重要です）。一方、高い precision は false alarm が少ないことを意味します（analyst fatigue を避けるために重要です）。ROC AUC（Area Under the ROC Curve）は、threshold に依存しない性能指標です（1.0 が理想的で、0.5 は偶然と変わりません）。Logistic regression はこのようなタスクで良好な性能を発揮することが多いですが、phishing site と legitimate site の間の decision boundary が複雑な場合は、より強力な non-linear model が必要になることがあります。

</details>

### Decision Trees

decision tree は、classification と regression の両方のタスクに使用できる汎用的な **supervised learning algorithm** です。データの features に基づく decisions の階層的な tree-like model を学習します。tree の各 internal node は特定の feature に対する test を表し、各 branch はその test の結果を表し、各 leaf node は予測された class（classification の場合）または value（regression の場合）を表します。<sup>[[2]](#references)</sup>

tree を構築するために、CART（Classification and Regression Tree）のような algorithms は、各ステップでデータを split する最適な feature と threshold を選択するため、**Gini impurity** や **information gain (entropy)** などの指標を使用します。各 split の目的は、結果として得られる subsets における target variable の homogeneity を高めるようデータを partition することです（classification では、各 node は主に単一の class を含む、できる限り pure な状態になることを目指します）。

decision trees は **highly interpretable** です。root から leaf までの path をたどることで、prediction の logic を理解できます（例：*「`service = telnet` かつ `src_bytes > 1000` かつ `failed_logins > 3` の場合、attack として classify する」*）。これは、特定の alert がなぜ発生したのかを説明するうえで、cybersecurity において有用です。Trees は numerical data と categorical data の両方を自然に扱うことができ、preprocessing もほとんど必要ありません（例：feature scaling は不要です）。

ただし、単一の decision tree は、特に深く（多くの splits を含む）成長させた場合、training data に容易に overfit します。overfitting を防ぐため、pruning（tree depth の制限や、leaf あたりに必要な最小サンプル数の指定）などの techniques がよく使用されます。

decision tree には、主に 3 つの components があります。
- **Root Node**: tree の最上位の node で、dataset 全体を表します。
- **Internal Nodes**: features と、それらの features に基づく decisions を表す nodes です。
- **Leaf Nodes**: 最終的な outcome または prediction を表す nodes です。

tree は次のような形になる場合があります。
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* 決定木は、攻撃を識別するための**ルール**を導出する侵入検知システムで使用されてきました。例えば、ID3/C4.5ベースの初期のIDSは、正常なトラフィックと悪意のあるトラフィックを区別するために、人間が読みやすいルールを生成していました。また、ファイルの属性（ファイルサイズ、セクションのエントロピー、API callsなど）に基づいてファイルが悪意のあるものかどうかを判断する、malware analysisにも使用されます。決定木は明瞭であるため、透明性が必要な場合に有用です -- analystはtreeを調査して、detection logicを検証できます。

#### **決定木の主な特徴:**

-   **問題の種類:** classificationとregressionの両方。攻撃と正常なトラフィックの分類などに一般的に使用されます。

-   **解釈可能性:** 非常に高い -- modelの判断を可視化し、if-then rulesの集合として理解できます。これは、modelの動作に対する信頼と検証が重要なsecurityにおける大きな利点です。

-   **利点:** feature間の非線形な関係や相互作用を捉えられます（各splitは相互作用として捉えることができます）。featureのscale変換やcategorical variablesのone-hot encodeは不要です -- treeはこれらをネイティブに処理します。inferenceが高速です（predictionはtree内のpathをたどるだけです）。

-   **制限:** 制御しない場合はoverfittingしやすくなります（深いtreeはtraining setを記憶できます）。また、不安定になる可能性があります -- dataの小さな変化によって、異なるtree structureになることがあります。単一のmodelとしては、そのaccuracyがより高度な手法に及ばない場合があります（Random Forestsのようなensembleは、varianceを低減することで通常はより高い性能を発揮します）。

-   **最適なsplitの探索:**
- **Gini Impurity**: nodeの不純度を測定します。Gini impurityが低いほど、より良いsplitであることを示します。formulaは次のとおりです:

```plaintext
Gini = 1 - Σ(p_i^2)
```

ここで、`p_i`はclass `i`に属するinstancesの割合です。

- **Entropy**: dataset内の不確実性を測定します。entropyが低いほど、より良いsplitであることを示します。formulaは次のとおりです:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

ここで、`p_i`はclass `i`に属するinstancesの割合です。

- **Information Gain**: split後のentropyまたはGini impurityの減少量です。information gainが高いほど、より良いsplitです。次のように計算されます:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

さらに、次の場合にtreeは終了します:
- node内のすべてのinstancesが同じclassに属している場合。これはoverfittingにつながる可能性があります。
- treeのmaximum depth（hardcoded）に到達した場合。これはoverfittingを防ぐ方法です。
- node内のinstances数が一定のthresholdを下回った場合。これもoverfittingを防ぐ方法です。
- 追加のsplitによるinformation gainが一定のthresholdを下回った場合。これもoverfittingを防ぐ方法です。

<details>
<summary>例 -- Intrusion Detection用のDecision Tree:</summary>
NSL-KDD datasetを使用してdecision treeをtrainingし、network connectionsを*normal*または*attack*のいずれかに分類します。NSL-KDDは、従来のKDD Cup 1999 datasetを改良したもので、protocol type、service、duration、failed loginsの回数などのfeaturesと、attack typeまたは"normal"を示すlabelを含みます。すべてのattack typesを"anomaly" classにmapします（binary classification: normal vs anomaly）。training後、test setでtreeのperformanceを評価します。
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
この決定木の例では、極端な overfitting を避けるため、木の深さを 10 に制限しました（`max_depth=10` パラメータ）。これらの指標は、木が正常なトラフィックと attack トラフィックをどの程度適切に区別できるかを示しています。高い recall は、ほとんどの attack を検知できることを意味します（IDS にとって重要です）。一方、高い precision は false alarm が少ないことを意味します。決定木は構造化データで十分な accuracy を達成することが多いものの、単一の木では可能な限り最高の performance に到達できない場合があります。それでも、モデルの *interpretability* は大きな利点です -- 木の分岐を調べれば、たとえば、どの features（`service`、`src_bytes` など）が connection を malicious と判定する際に最も大きな影響を与えているかを確認できます。

</details>

### Random Forests

Random Forest は、performance を向上させるために決定木を基盤として構築する **ensemble learning** 手法です。Random Forest では複数の決定木（そのため「forest」と呼ばれます）を学習させ、それらの出力を組み合わせて最終的な prediction を行います（classification では通常、majority vote を使用します）。Random Forest の主な考え方は、**bagging**（bootstrap aggregating）と **feature randomness** の 2 つです。

-   **Bagging:** 各木は、training data から無作為に抽出した bootstrap sample（復元抽出）を使って学習されます。これにより、木の間に多様性が生まれます。

-   **Feature Randomness:** 木の各 split では、すべての features ではなく、無作為に選択された features の subset が split の候補として検討されます。これにより、木同士の相関がさらに低下します。

多数の木の結果を平均することで、Random Forest は単一の決定木が持つ可能性のある variance を低減します。簡単に言えば、個々の木は overfit したりノイズを含んだりする可能性がありますが、多様な木を多数用意して投票させることで、それらの誤りが平滑化されます。その結果、単一の決定木よりも **higher accuracy** と優れた generalization を持つモデルになることが多くなります。さらに、Random Forest は、各 feature の split が平均してどの程度 impurity を低減したかを調べることで、feature importance の推定値を提供できます。

Random Forest は、intrusion detection、malware classification、spam detection などのタスクで、cybersecurity の **workhorse** となっています。最小限の tuning で out-of-the-box でも良好な performance を発揮することが多く、大規模な feature sets にも対応できます。たとえば intrusion detection では、Random Forest は単一の決定木よりも優れた performance を発揮し、より subtle な attack パターンを、少ない false positives で検知できる場合があります。研究では、NSL-KDD や UNSW-NB15 などの datasets における attack の classification で、Random Forest が他の algorithms と比較して良好な結果を示すことが報告されています。<sup>[[3]](#references)[[9]](#references)</sup>

#### **Random Forests の主な特徴:**

-   **Type of Problem:** 主に classification（regression にも使用されます）。security logs によく見られる high-dimensional な structured data に非常に適しています。

-   **Interpretability:** 単一の決定木より低くなります -- 数百本の木を一度に簡単に可視化したり説明したりすることはできません。ただし、feature importance scores によって、どの attributes が最も大きな影響を与えているかについて一定の insight を得られます。

-   **Advantages:** ensemble effect により、一般的に single-tree models より高い accuracy を実現します。overfitting に対して robust です -- 個々の木が overfit しても、ensemble はより適切に generalize します。numerical features と categorical features の両方を処理でき、missing data もある程度扱えます。また、outliers に対しても比較的 robust です。

-   **Limitations:** モデルのサイズが大きくなる可能性があります（多数の木があり、それぞれが深くなる場合があります）。prediction は単一の木より遅くなります（多数の木の結果を aggregate する必要があるためです）。interpretability も低くなります -- 重要な features は分かっても、正確な logic を単純な rule として容易に追跡することはできません。dataset が極めて high-dimensional かつ sparse な場合、非常に大規模な forest の training は computationally heavy になる可能性があります。

-   **Training Process:**
1. **Bootstrap Sampling**: training data を復元抽出で無作為に sample し、複数の subsets（bootstrap samples）を作成します。
2. **Tree Construction**: 各 bootstrap sample について、各 split で features の random subset を使用して決定木を構築します。これにより、木の間に多様性が生まれます。
3. **Aggregation**: classification tasks では、すべての木の predictions による majority vote を行って最終 prediction を決定します。regression tasks では、すべての木の predictions の平均が最終 prediction になります。

<details>
<summary>Example -- Intrusion Detection 用 Random Forest（NSL-KDD）:</summary>
同じ NSL-KDD dataset（normal と anomaly の binary labeled）を使用し、Random Forest classifier を training します。ensemble averaging によって variance が低減されるため、Random Forest は単一の決定木と同等以上の performance を発揮すると期待できます。先ほどと同じ metrics を使って評価します。
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
この侵入検知タスクでは、random forest は通常、優れた結果を達成します。単一の decision tree と比較すると、特にデータによっては recall や precision において、F1 や AUC などの指標が改善されることがあります。これは、*"Random Forest (RF) は ensemble classifier であり、攻撃を効果的に分類するうえで、従来の他の classifier と比較して優れた性能を発揮する。"*という理解と一致します。security operations の文脈では、random forest model は、多数の decision rule の平均化によって false alarm を減らしながら、より確実に攻撃を検出できる可能性があります。forest から得られる feature importance によって、どの network feature が攻撃を最も示唆しているか（例：特定の network service や、通常とは異なる packet 数のカウント）を把握できます。

</details>

### Support Vector Machines (SVM)

Support Vector Machines は、主に classification（また、SVR として regression にも使用される）に用いられる強力な supervised learning model です。SVM は、2つの class 間の margin を最大化する **optimal separating hyperplane** を見つけようとします。training point のうち、境界に最も近い一部（「support vector」）だけが、この hyperplane の位置を決定します。margin（support vector と hyperplane の間の距離）を最大化することで、SVM は優れた generalization を実現する傾向があります。<sup>[[4]](#references)</sup>

SVM の強みの鍵は、**kernel function** を使用して non-linear な関係を扱える点にあります。データは暗黙的に、linear separator が存在する可能性のある、より高次元の feature space に変換できます。一般的な kernel には polynomial、radial basis function (RBF)、sigmoid があります。例えば、network traffic の class が raw feature space で linearly separable でない場合、RBF kernel によってデータをより高次元へ写像し、SVM が linear な分割を見つけられるようにできます（これは元の space では non-linear な境界に相当します）。kernel を選択できる柔軟性により、SVM はさまざまな問題に対応できます。

SVM は、高次元の feature space（text data や malware opcode sequence など）や、sample 数に対して feature 数が多い状況で優れた性能を発揮することで知られています。2000年代には、malware classification や anomaly-based intrusion detection など、初期の多くの cybersecurity application で利用され、高い accuracy を示すことがよくありました。

ただし、SVM は非常に大規模な dataset には容易に scale できません（training の計算量は sample 数に対して super-linear であり、多数の support vector を保存する必要があるため memory 使用量も大きくなる可能性があります）。実際には、数百万件の record を扱う network intrusion detection のようなタスクでは、慎重な subsampling や approximate method を使用しない限り、SVM は遅すぎる可能性があります。

#### **SVM の主な特徴：**

-   **問題の種類:** classification（one-vs-one/one-vs-rest による binary または multiclass）および regression variant。明確な margin separation がある binary classification でよく使用されます。

-   **解釈可能性:** Medium -- SVM は decision tree や logistic regression ほど解釈しやすくありません。どの data point が support vector であるかを特定し、どの feature が影響を与えている可能性があるかをある程度把握できます（linear kernel の場合は weight を通じて）が、実際には SVM（特に non-linear kernel を使用するもの）は black-box classifier として扱われます。

-   **利点:** 高次元 space で効果的。kernel trick によって複雑な decision boundary を model 化できる。margin を最大化することで overfitting に強い（特に適切な regularization parameter C を使用した場合）。class が大きな距離で分離されていない場合でも適切に機能する（最適な妥協点となる boundary を見つける）。

-   **制限:** 大規模な dataset では **計算負荷が高い**（data の増加に伴い、training と prediction のスケールが悪化する）。kernel および regularization parameter（C、kernel type、RBF の gamma など）の慎重な tuning が必要です。probabilistic output を直接提供しません（ただし、Platt scaling を使用して probability を得ることは可能です）。また、SVM は kernel parameter の選択に敏感であり、適切でない選択は underfit や overfit につながる可能性があります。

*cybersecurity におけるユースケース:* SVM は、**malware detection**（抽出した feature や opcode sequence に基づく file の分類など）、**network anomaly detection**（traffic を normal または malicious として分類）、**phishing detection**（URL の feature を使用）に利用されてきました。例えば、SVM に email の feature（特定の keyword の数、sender reputation score など）を入力し、phishing または legitimate として分類できます。また、KDD のような feature set を用いた **intrusion detection** にも適用されており、計算コストと引き換えに高い accuracy を達成することがよくあります。

<details>
<summary>例 -- Malware Classification のための SVM：</summary>
今回は phishing website dataset を再び使用し、SVM を適用します。SVM は遅くなる可能性があるため、必要に応じて training には data の subset を使用します（dataset は約11k instance であり、SVM で十分に処理できます）。non-linear data によく使われる RBF kernel を使用し、ROC AUC を計算するために probability estimate を有効にします。
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
SVM model は、同じタスクにおける Logistic Regression と比較できる metrics を出力します。データが features によって明確に分離されている場合、SVM は高い accuracy と AUC を達成する可能性があります。一方、dataset に多くの noise が含まれていたり、class が重なっていたりする場合、SVM は Logistic Regression を大きく上回らない可能性があります。実際には、features と class の間に複雑な非線形関係がある場合、SVM によって性能が向上することがあります。RBF kernel は、Logistic Regression では捉えられない曲線状の decision boundary を捉えられるためです。すべての model と同様に、bias と variance のバランスを取るには、`C`（regularization）や kernel parameters（RBF の `gamma` など）を慎重に tuning する必要があります。

</details>

#### Logistic Rergessions と SVM の違い

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | **log-loss**（cross-entropy）を最小化します。 | **margin** を最大化しながら **hinge-loss** を最小化します。 |
| **Decision boundary** | _P(y\|x)_ をモデル化する **best-fit hyperplane** を求めます。 | **maximum-margin hyperplane**（最も近い points までの gap が最大となる hyperplane）を求めます。 |
| **Output** | **Probabilistic** – σ(w·x + b) によって calibrated class probabilities を返します。 | **Deterministic** – class labels を返します。probabilities には追加処理（例：Platt scaling）が必要です。 |
| **Regularisation** | L2（default）または L1 を使用し、under-fitting と over-fitting のバランスを直接調整します。 | C parameter により margin width と mis-classifications のトレードオフを調整します。kernel parameters によって複雑性が増します。 |
| **Kernels / Non-linear** | Native form は **linear** です。feature engineering によって非線形性を追加します。 | 組み込みの **kernel trick**（RBF、poly など）により、高次元空間で複雑な boundary をモデル化できます。 |
| **Scalability** | **O(nd)** の convex optimisation を解くため、非常に大きな n を適切に処理できます。 | specialised solvers を使用しない場合、training は **O(n²–n³)** の memory/time になる可能性があり、巨大な n にはあまり適していません。 |
| **Interpretability** | **High** – weights が feature の影響を示し、odds ratio も直感的です。 | 非線形 kernel では **Low** です。support vectors は sparse ですが、説明は容易ではありません。 |
| **Sensitivity to outliers** | smooth な log-loss を使用するため、影響を受けにくくなります。 | hard margin の hinge-loss は **sensitive** になる可能性があります。soft-margin（C）によって緩和できます。 |
| **Typical use cases** | Credit scoring、medical risk、A/B testing など、**probabilities と explainability** が重要な場合。 | Image/text classification、bio-informatics など、**complex boundaries** と **high-dimensional data** が重要な場合。 |

* **calibrated probabilities、interpretability、または巨大な datasets を扱う必要がある場合は、Logistic Regression を選択します。**
* **manual feature engineering なしで非線形関係を捉えられる柔軟な model が必要な場合は、SVM（kernels 付き）を選択します。**
* どちらも convex objectives を最適化するため、**global minima が保証されます**。ただし、SVM の kernels には hyper-parameters と computational cost が追加されます。

### Naive Bayes

Naive Bayes は、features 間に強い independence assumption を置き、Bayes' Theorem を適用する **probabilistic classifiers** の family です。この「naive」な assumption にもかかわらず、Naive Bayes は特定の applications、特に spam detection などの text や categorical data を扱う applications で、驚くほどうまく機能することがあります。<sup>[[5]](#references)</sup>


#### Bayes' Theorem

Bayes' theorem は Naive Bayes classifiers の基盤です。これは random events の conditional probabilities と marginal probabilities の関係を示します。formula は次のとおりです。
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
ここで:
- `P(A|B)` は、feature `B` が与えられた場合の class `A` の事後確率です。
- `P(B|A)` は、class `A` が与えられた場合の feature `B` の尤度です。
- `P(A)` は、class `A` の事前確率です。
- `P(B)` は、feature `B` の事前確率です。

例えば、あるテキストが子どもまたは成人によって書かれたものかを分類したい場合、テキスト内の単語を features として使用できます。初期データに基づき、Naive Bayes classifier は各単語がそれぞれの候補 class（子どもまたは成人）に属する確率を事前に計算します。新しいテキストが与えられると、テキスト内の単語から各候補 class である確率を計算し、最も高い確率の class を選択します。

この例から分かるように、Naive Bayes classifier は非常にシンプルで高速ですが、features が独立していると仮定します。これは実世界のデータでは常に成り立つとは限りません。


#### Types of Naive Bayes Classifiers

features の種類と分布に応じて、Naive Bayes classifiers にはいくつかの種類があります:
- **Gaussian Naive Bayes**: features が Gaussian（正規）分布に従うと仮定します。連続データに適しています。
- **Multinomial Naive Bayes**: features が多項分布に従うと仮定します。テキスト分類における単語数のような離散データに適しています。
- **Bernoulli Naive Bayes**: features が binary（0 または 1）であると仮定します。テキスト分類における単語の存在または不在のような binary データに適しています。
- **Categorical Naive Bayes**: features が categorical variables であると仮定します。色や形状に基づく果物の分類のような categorical データに適しています。


#### **Naive Bayes の主な特徴:**

-   **問題の種類:** Classification（binary または multi-class）。cybersecurity における text classification tasks（spam、phishing など）で一般的に使用されます。

-   **解釈可能性:** Medium -- decision tree ほど直接的に解釈できるわけではありませんが、学習された確率（例: spam email と ham email のどちらにどの単語が最も出現しやすいか）を調べることができます。必要に応じて、model の形式（class ごとの各 feature の確率）を理解できます。

-   **利点:** 大規模な datasets であっても、training と prediction が **非常に高速** です（instances 数 * features 数に対して linear）。特に適切な smoothing を使用すれば、確率を信頼性高く推定するために必要なデータ量が比較的少なくて済みます。features が class に対する証拠を独立して提供する場合、baseline としてしばしば驚くほど高い精度を実現します。text から数千の features が得られる場合のような、高次元データでも適切に機能します。smoothing parameter の設定以外に、複雑な tuning は必要ありません。

-   **制限事項:** features 間の相関が強い場合、independence assumption によって精度が制限される可能性があります。例えば、network data では `src_bytes` と `dst_bytes` のような features が相関する場合がありますが、Naive Bayes はその相互作用を捉えられません。データサイズが非常に大きくなると、より表現力の高い models（ensembles や neural nets など）が feature dependencies を学習することで NB を上回る可能性があります。また、attack を識別するために features の特定の組み合わせが必要な場合（各 feature が独立しているだけでは不十分な場合）、NB は苦戦します。

> [!TIP]
> *cybersecurity における使用例:* 典型的な用途は **spam detection** です -- Naive Bayes は初期の spam filters の中核であり、特定の tokens（単語、フレーズ、IP addresses）の頻度を使用して、email が spam である確率を計算していました。また、**phishing email detection** や **URL classification** にも使用されます。これらでは、特定の keywords や特徴（URL 内の "login.php"、または URL path 内の `@` など）の存在が phishing probability に寄与します。malware analysis では、ソフトウェア内に特定の API calls や permissions が存在するかどうかを使用して、malware かどうかを予測する Naive Bayes classifier を想定できます。より高度な algorithms の方が高い性能を示すことが多い一方で、Naive Bayes は高速かつシンプルであるため、依然として優れた baseline です。

<details>
<summary>Example -- phishing detection のための Naive Bayes:</summary>
Naive Bayes を実演するため、binary labels を持つ NSL-KDD intrusion dataset に Gaussian Naive Bayes を使用します。Gaussian NB は、各 feature が class ごとに normal distribution に従うものとして扱います。多くの network features は discrete または highly skewed であるため、これは大まかな選択ですが、continuous feature data に NB を適用する方法を示すことができます。binary features（triggered alerts のセットなど）から成る dataset に Bernoulli NB を選択することもできますが、ここでは一貫性を保つため NSL-KDD を使用します。
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
このコードは、攻撃を検出するために Naive Bayes classifier をトレーニングします。Naive Bayes は、特徴量間の独立性を仮定し、トレーニングデータに基づいて `P(service=http | Attack)` や `P(Service=http | Normal)` などを計算します。その後、観測された特徴量に基づいて、新しい接続を normal または attack のいずれかに分類します。NSL-KDD における NB の性能は、より高度なモデルほど高くない可能性があります（特徴量の独立性が成立しないため）が、多くの場合十分な性能を発揮し、非常に高速という利点があります。リアルタイムのメールフィルタリングや URL の初期トリアージなどのシナリオでは、Naive Bayes model によって、リソース使用量を抑えながら明らかに悪意のあるケースを迅速にフラグ付けできます。

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors は、最も単純な machine learning algorithms の一つです。これは、トレーニングセット内の例との類似性に基づいて予測を行う **non-parametric, instance-based** 手法です。classification における考え方は、新しいデータポイントを分類する際に、トレーニングデータ内で最も近い **k** 個のポイント（「nearest neighbors」）を見つけ、それらの neighbor における多数派の class を割り当てるというものです。「近さ」は distance metric によって定義され、通常は数値データに対して Euclidean distance が使われます（特徴量や問題の種類に応じて、ほかの distance も使用できます）。<sup>[[10]](#references)</sup>

K-NN には *明示的なトレーニングが不要* です -- 「トレーニング」フェーズではデータセットを保存するだけです。すべての処理は query（prediction）時に行われます。algorithm は、nearest points を見つけるために、query point からすべての training points までの distances を計算する必要があります。そのため、prediction time は **training samples の数に対して線形** となり、大規模なデータセットではコストが高くなる可能性があります。このため、k-NN は小規模なデータセットや、シンプルさのためにメモリと速度をトレードオフできるシナリオに最適です。

シンプルであるにもかかわらず、k-NN は非常に複雑な decision boundaries をモデル化できます（実質的に decision boundary は、examples の分布によって決まる任意の形状になり得るため）。decision boundary が非常に不規則で、かつ大量のデータがある場合に適した性能を発揮する傾向があります -- 本質的には、データそのものに「語らせる」方法です。しかし、高次元では distance metrics の意味が薄れやすく（curse of dimensionality）、非常に大量の samples がない限り、この手法は苦戦する可能性があります。

*Use cases in cybersecurity:* k-NN は anomaly detection に適用されています -- たとえば intrusion detection system は、ある network event の nearest neighbors（過去の events）の大半が malicious だった場合、その network event を malicious とラベル付けできます。normal traffic が clusters を形成し、attacks が outliers である場合、k=1 または小さな k の K-NN approach は、実質的に **nearest-neighbor anomaly detection** になります。K-NN は、binary feature vectors による malware families の classification にも使用されています。新しい file は、feature space 内でその malware family の既知の instances と非常に近い場合、その family に分類されます。実際には、k-NN はより scalable な algorithms ほど一般的ではありませんが、概念的にわかりやすく、baseline として、または小規模な問題で使用されることがあります。

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Classification（regression variants も存在します）。これは *lazy learning* 手法であり、明示的な model fitting は行いません。

-   **Interpretability:** Low to medium -- global model や簡潔な説明はありませんが、decision に影響を与えた nearest neighbors を確認することで結果を解釈できます（例: 「この network flow は、これら 3 つの既知の malicious flows と類似しているため、malicious と分類された」）。したがって、説明は example-based にできます。

-   **Advantages:** 実装と理解が非常に簡単です。データ分布について仮定を置きません（non-parametric）。multi-class problems を自然に処理できます。decision boundaries は非常に複雑になり得て、data distribution によって形作られるため、**adaptive** です。

-   **Limitations:** 大規模なデータセットでは prediction が遅くなる可能性があります（多数の distances を計算する必要があるため）。メモリを大量に消費します -- すべての training data を保存するためです。高次元の feature spaces では、すべての points がほぼ等距離になる傾向があるため、性能が低下します（「nearest」という概念の意味が薄れるためです）。*k*（neighbors の数）を適切に選ぶ必要があります -- k が小さすぎるとノイズが多くなり、k が大きすぎるとほかの classes の無関係な points が含まれる可能性があります。また、distance calculations は scale の影響を受けるため、features は適切に scaled する必要があります。

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

ここでも NSL-KDD（binary classification）を使用します。k-NN は computationally heavy であるため、この demonstration では tractable に保つために training data の subset を使用します。full 125k から、たとえば 20,000 training samples を選び、k=5 neighbors を使用します。training 後（実際には data を保存するだけです）、test set で評価します。また、単一の feature が scale の違いによって支配的にならないよう、distance calculation のために features を scale します。
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
k-NN modelは、training setのsubset内で最も近い5つのconnectionを調べることで、connectionを分類します。たとえば、それらのneighborのうち4つがattack（anomaly）で、1つがnormalの場合、新しいconnectionはattackとして分類されます。性能は妥当な場合がありますが、同じdata上で適切にtuningされたRandom ForestやSVMほど高くないことが多いでしょう。しかし、class distributionが非常に不規則で複雑な場合、k-NNはmemory-based lookupを効果的に利用することで、際立った性能を示すことがあります。cybersecurityでは、k-NN（k=1または小さいk）を、例による既知のattack patternの検出や、より複雑なsystemのcomponent（たとえば、clusteringを行い、その後cluster membershipに基づいてclassifyする用途）として利用できます。
</details>

### Gradient Boosting Machines（例：XGBoost）

Gradient Boosting Machinesは、structured data向けの最も強力なalgorithmのひとつです。**Gradient boosting**とは、weak learner（多くの場合decision tree）のensembleを順番に構築するtechniqueであり、新しいmodelがそれ以前のensembleの誤りを修正していきます。treeをparallelに構築して平均するbagging（Random Forests）とは異なり、boostingはtreeを*1本ずつ*構築し、それぞれが以前のtreeで誤分類されたinstanceにより重点を置きます。

近年最も一般的なimplementationは**XGBoost**、**LightGBM**、**CatBoost**であり、いずれもgradient boosting decision tree（GBDT）libraryです。これらはmachine learning competitionやapplicationで非常に高い成果を上げており、しばしば**tabular datasetでstate-of-the-artの性能を達成**しています。cybersecurityでは、researcherやpractitionerが、**malware detection**（fileまたはruntime behaviorから抽出したfeatureを使用）や**network intrusion detection**などのtaskにgradient boosted treeを利用してきました。たとえば、gradient boosting modelは、「多数のSYN packetと異常なportがある -> scanの可能性が高い」のような多数のweak rule（tree）を組み合わせ、多くの微妙なpatternを考慮する強力なcomposite detectorを構築できます。<sup>[[6]](#references)</sup>

なぜboosted treeはこれほど効果的なのでしょうか。sequence内の各treeは、現在のensembleのpredictionにおける*residual error*（gradient）を使ってtrainingされます。これにより、modelは弱い領域を段階的に**「boost」**できます。base learnerとしてdecision treeを使用するため、最終modelは複雑なinteractionとnon-linear relationを捉えられます。また、boostingにはbuilt-in regularizationの性質もあります。多数の小さなtreeを追加し、それらのcontributionをlearning rateでscaleすることで、適切なparameterを選択すれば、過度なoverfittingを起こさずに高いgeneralization性能を得られることが多くなります。

#### **Gradient Boostingの主な特徴：**

-   **Problemの種類:** 主にclassificationとregressionです。securityでは通常classification（たとえば、connectionまたはfileをbinary classifyする用途）に使用されます。binary、multi-class（適切なlossを使用）、さらにはranking problemにも対応します。

-   **Interpretability:** 低から中程度です。単一のboosted treeは小規模ですが、完全なmodelには数百本のtreeが含まれる可能性があり、全体として人間が解釈できるものではありません。ただし、Random Forestと同様にfeature importance scoreを提供でき、SHAP（SHapley Additive exPlanations）のようなtoolを使えば、individual predictionをある程度解釈できます。

-   **Advantages:** structured/tabular dataに対して、しばしば**最も高い性能を発揮する**algorithmです。複雑なpatternやinteractionを検出できます。modelの複雑さを調整し、overfittingを防ぐためのtuning option（treeの数、treeのdepth、learning rate、regularization term）が多数あります。modern implementationはspeed向けに最適化されています（たとえば、XGBoostはsecond-order gradient情報と効率的なdata structureを使用します）。適切なloss functionと組み合わせるか、sample weightを調整すると、imbalanced dataにも比較的うまく対応できます。

-   **Limitations:** より単純なmodelよりもtuningが複雑です。treeが深い場合やtreeの数が多い場合、trainingが遅くなることがあります（ただし、通常は同じdata上で同等のdeep neural networkをtrainingするより高速です）。適切にtuningしないとmodelがoverfitする可能性があります（たとえば、regularizationが不十分な状態で深いtreeを多く使用する場合）。hyperparameterが多数あるため、gradient boostingを効果的に利用するには、より多くのexpertiseやexperimentが必要になることがあります。また、tree-based methodと同様に、非常にsparseでhigh-dimensionalなdataをlinear modelやNaive Bayesほど効率的には本質的に扱えません（text classificationなどに適用することはできますが、feature engineeringなしでは第一選択にならない可能性があります）。

> [!TIP]
> *cybersecurityでのuse case:* decision treeやrandom forestを使用できるほぼすべての場面で、gradient boosting modelのほうが高いaccuracyを達成できる可能性があります。たとえば、**Microsoftのmalware detection** competitionでは、binary fileからengineerしたfeatureに対してXGBoostが広く利用されてきました。**Network intrusion detection**のresearchでは、GBDT（CIC-IDS2017やUNSW-NB15 dataset上のXGBoostなど）が最高水準の結果を示すことがよく報告されています。これらのmodelは、幅広いfeature（protocol type、特定のeventのfrequency、trafficのstatistical featureなど）を受け取り、それらを組み合わせてthreatを検出できます。phishing detectionでは、gradient boostingがURLのlexical feature、domain reputation feature、page content featureを組み合わせ、非常に高いaccuracyを達成できます。ensemble approachにより、data内の多くのcorner caseや微妙な特徴をカバーできます。

<details>
<summary>Example -- XGBoostによるPhishing Detection:</summary>
phishing datasetに対してgradient boosting classifierを使用します。簡潔でself-containedにするため、`sklearn.ensemble.GradientBoostingClassifier`（より低速ですが、わかりやすいimplementation）を使用します。通常は、より高いperformanceと追加featureのために`xgboost`または`lightgbm` libraryを使用することもあります。modelをtrainingし、これまでと同様にevaluationを行います。
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
勾配ブースティングモデルは、この phishing データセット上で非常に高い accuracy と AUC を達成する可能性が高いです（文献で見られるように、このようなデータでは、適切なチューニングにより 95% を超える accuracy を達成できる場合がよくあります）。これは、GBDT が *「表形式データセットに対する the state of the art model」* と見なされている理由を示しています。複雑なパターンを捉えることで、より単純なアルゴリズムを上回ることが多いためです。cybersecurity の文脈では、より多くの phishing サイトや攻撃を検知し、見逃しを減らせる可能性があります。もちろん、overfitting には注意が必要です。このようなモデルを deployment 用に開発する際は、通常、cross-validation などの techniques を使用し、validation set 上の performance を監視します。

</details>

### Models の組み合わせ: Ensemble Learning と Stacking

Ensemble learning は、全体的な performance を向上させるために **複数の models を組み合わせる** strategy です。すでに具体的な ensemble methods として、Random Forest（bagging による trees の ensemble）と Gradient Boosting（sequential boosting による trees の ensemble）を見てきました。しかし、ensemble は **voting ensembles** や **stacked generalization (stacking)** など、別の方法でも作成できます。基本的な考え方は、異なる models が異なる patterns を捉えたり、異なる弱点を持っていたりするため、それらを組み合わせることで、**各 model の errors を別の model の strengths で補える**ということです。<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** 単純な voting classifier では、複数の多様な models（例えば、logistic regression、decision tree、SVM）を train し、最終的な prediction について vote させます（classification では majority vote）。vote に重みを付ける場合（例えば、より accuracy の高い models に大きな weight を与える場合）は、weighted voting scheme となります。これは通常、個々の models が十分に優れており、互いに独立している場合に performance を向上させます。ensemble により、個々の model の mistake の risk が低減されます。他の models がそれを修正できる可能性があるためです。これは、単一の意見ではなく、専門家の panel を持つようなものです。

-   **Stacking (Stacked Ensemble):** Stacking は、単純な vote よりも一歩進んだ方法です。単純な vote の代わりに、base models の predictions を **最適に組み合わせる方法を learn する** **meta-model** を train します。例えば、3 つの異なる classifiers（base learners）を train し、その outputs（または probabilities）を features として meta-classifier（多くの場合、logistic regression のような単純な model）に入力します。meta-classifier は、それらを最適に blend する方法を learn します。meta-model は、overfitting を避けるため、validation set 上、または cross-validation を使用して train します。Stacking は、*どの状況でどの models をより信頼すべきか* を learn することで、単純な voting を上回ることがよくあります。cybersecurity では、ある model が network scans の検知に優れ、別の model が malware beaconing の検知に優れている場合があります。stacking model は、それぞれを適切に頼る方法を learn できます。

Voting または stacking による ensembles は、accuracy と robustness を **向上させる** 傾向があります。欠点は、complexity が増し、interpretability が低下する場合があることです（ただし、decision trees の average のような一部の ensemble approaches は、feature importance などを通じて、ある程度の insight を提供できます）。実際には、operational constraints が許すなら、ensemble を使用することで detection rates を高められます。cybersecurity challenges（および一般的な Kaggle competitions）で winning solutions の多くは、performance を最後まで引き上げるために ensemble techniques を使用しています。

<details>
<summary>Example -- Phishing Detection の Voting Ensemble:</summary>
model stacking を説明するため、phishing データセット上で、これまでに説明したいくつかの models を組み合わせてみましょう。base learners として logistic regression、decision tree、k-NN を使用し、meta-learner として Random Forest を使用して、それらの predictions を aggregate します。meta-learner は、base learners の outputs（training set 上で cross-validation を使用）を元に train します。stacked model は、個々の models と同程度、またはわずかに優れた performance を示すと予想されます。
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
スタック型アンサンブルは、ベースモデルそれぞれの相補的な強みを活用します。例えば、ロジスティック回帰はデータの線形的な側面を処理し、decision treeは特定のルールに似た相互作用を捉え、k-NNは特徴空間の局所的な近傍で優れた性能を発揮する可能性があります。メタモデル（ここでは random forest）は、これらの入力にどのような重みを付けるかを学習できます。その結果得られるメトリクスは、多くの場合、単一モデルのメトリクスをわずかであっても上回ります。phishingの例では、ロジスティック回帰単体のF1が例えば0.95、treeが0.94だった場合、stackは各モデルが誤る部分を補うことで0.96を達成できる可能性があります。

このようなアンサンブル手法は、*「複数のモデルを組み合わせると、通常は汎化性能が向上する」*という原則を示しています。cybersecurityでは、複数の検知エンジン（1つはルールベース、1つはmachine learning、もう1つはanomaly-basedなど）を用意し、それらのalertを集約するレイヤーを設けることで実装できます。これは実質的にアンサンブルの一種であり、より高い信頼度で最終判断を下せます。このようなシステムをdeployする際は、追加される複雑さを考慮し、アンサンブルが管理や説明を過度に難しくならないようにする必要があります。しかし、精度の観点では、アンサンブルとstackingはモデル性能を向上させる強力なツールです。

</details>


## 参考文献

- [1] [ロジスティック回帰](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Decision Tree - 例を用いた入門](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Information Gainを用いたRandom Forest ClassifierによるDenial of Services Attack Detection](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [Support Vector Machines（SVM）とは？（IBM）](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Naive Bayesによるspam filtering（Wikipedia）](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDTの解説：LightGBM、XGBoost、CatBoostの仕組み](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [cybersecurityにおけるAIとMachine Learning（zvelo）](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Linear Regressionの解説](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Gini ImpurityベースのWeighted Random Forest（GIWRF）feature selection techniqueを用いたintrusion detection system向けmachine learningモデルの性能分析](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [k-nearest neighbors（KNN）algorithmとは？（IBM）](https://www.ibm.com/think/topics/knn)
- [11] [Machine Learningと複数のDatasetを用いたPhishing Attacks and WebsitesのClassification（比較分析）](https://arxiv.org/pdf/2101.02552)
- [12] [Deep LearningがIntrusion Detection Systemsを強化する方法](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning：強みを組み合わせてモデル性能を向上させる](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
