# 教師あり学習アルゴリズム

{{#include ../banners/hacktricks-training.md}}

## 基本情報

教師あり学習は、ラベル付きデータを使用して、新しい未見の入力に対して予測を行うモデルを訓練します。サイバーセキュリティにおいて、教師あり機械学習は、侵入検知（ネットワークトラフィックを*正常*または*攻撃*として分類）、マルウェア検知（悪意のあるソフトウェアと無害なものを区別）、フィッシング検知（詐欺的なウェブサイトやメールを特定）、スパムフィルタリングなどのタスクに広く適用されています。各アルゴリズムにはそれぞれの強みがあり、異なるタイプの問題（分類または回帰）に適しています。以下では、主要な教師あり学習アルゴリズムをレビューし、それらの動作を説明し、実際のサイバーセキュリティデータセットでの使用例を示します。また、モデルを組み合わせること（アンサンブル学習）が予測性能を向上させることが多いことについても議論します。

## アルゴリズム

-   **線形回帰：** 数値的な結果を予測するためにデータに線形方程式をフィットさせる基本的な回帰アルゴリズム。

-   **ロジスティック回帰：** バイナリ結果の確率をモデル化するためにロジスティック関数を使用する分類アルゴリズム（その名前にもかかわらず）。

-   **決定木：** 特徴によってデータを分割して予測を行う木構造モデル；解釈性が高いためよく使用される。

-   **ランダムフォレスト：** 決定木のアンサンブル（バギングを通じて）で、精度を向上させ、過剰適合を減少させる。

-   **サポートベクターマシン（SVM）：** 最適な分離ハイパープレーンを見つける最大マージン分類器；非線形データにはカーネルを使用できる。

-   **ナイーブベイズ：** 特徴の独立性を仮定したベイズの定理に基づく確率的分類器で、スパムフィルタリングで有名。

-   **k-近傍法（k-NN）：** 最近傍の多数派クラスに基づいてサンプルにラベルを付けるシンプルな「インスタンスベース」の分類器。

-   **勾配ブースティングマシン：** 弱い学習者（通常は決定木）を逐次的に追加して強力な予測器を構築するアンサンブルモデル（例：XGBoost、LightGBM）。

以下の各セクションでは、アルゴリズムの改善された説明と、`pandas`や`scikit-learn`（およびニューラルネットワークの例には`PyTorch`）を使用した**Pythonコード例**を提供します。例は、侵入検知用のNSL-KDDやフィッシングウェブサイトデータセットなど、公開されているサイバーセキュリティデータセットを使用し、一貫した構造に従います：

1.  **データセットをロードする**（利用可能な場合はURLからダウンロード）。

2.  **データを前処理する**（例：カテゴリカル特徴をエンコード、値をスケーリング、トレーニング/テストセットに分割）。

3.  **トレーニングデータでモデルを訓練する**。

4.  **テストセットで評価する**：分類の場合は精度、適合率、再現率、F1スコア、ROC AUC、回帰の場合は平均二乗誤差を使用。

それでは、各アルゴリズムに dive していきましょう：

### 線形回帰

線形回帰は、連続的な数値を予測するために使用される**回帰**アルゴリズムです。入力特徴（独立変数）と出力（従属変数）との間に線形関係があると仮定します。モデルは、特徴とターゲットとの関係を最もよく表す直線（または高次元ではハイパープレーン）をフィットさせようとします。これは通常、予測値と実際の値との間の二乗誤差の合計を最小化することによって行われます（最小二乗法）。

線形回帰を表現する最も単純な方法は、直線を用いることです：
```plaintext
y = mx + b
```
どこで：

- `y` は予測値（出力）
- `m` は直線の傾き（係数）
- `x` は入力特徴
- `b` はy切片

線形回帰の目標は、予測値とデータセット内の実際の値との間の差を最小化する最適なフィッティングラインを見つけることです。もちろん、これは非常に単純で、2つのカテゴリを分ける直線になりますが、次元が追加されると、直線はより複雑になります：
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* 線形回帰自体はコアセキュリティタスク（通常は分類）にはあまり一般的ではありませんが、数値的な結果を予測するために適用できます。たとえば、線形回帰を使用して**ネットワークトラフィックの量を予測**したり、**特定の期間内の攻撃の数を推定**したりすることができます。特定のシステムメトリクスに基づいて、リスクスコアや攻撃の検出までの予想時間を予測することも可能です。実際には、侵入やマルウェアを検出するためには分類アルゴリズム（ロジスティック回帰や木構造など）がより頻繁に使用されますが、線形回帰は基盤として機能し、回帰指向の分析に役立ちます。

#### **線形回帰の主な特徴:**

-   **問題の種類:** 回帰（連続値の予測）。出力にしきい値が適用されない限り、直接的な分類には適していません。

-   **解釈可能性:** 高い -- 係数は解釈が簡単で、各特徴の線形効果を示します。

-   **利点:** シンプルで高速; 回帰タスクの良いベースライン; 真の関係がほぼ線形である場合にうまく機能します。

-   **制限:** 複雑または非線形の関係を捉えることができません（手動の特徴エンジニアリングなしでは）; 非線形の関係がある場合はアンダーフィッティングしやすい; 結果を歪める可能性のある外れ値に敏感です。

-   **最適なフィットの見つけ方:** 可能なカテゴリを分ける最適なフィットラインを見つけるために、**最小二乗法 (OLS)** と呼ばれる方法を使用します。この方法は、観測値と線形モデルによって予測された値との間の二乗差の合計を最小化します。

<details>
<summary>例 -- 侵入データセットにおける接続時間の予測（回帰）
</summary>
以下では、NSL-KDDサイバーセキュリティデータセットを使用して線形回帰を示します。これを回帰問題として扱い、他の特徴に基づいてネットワーク接続の`duration`を予測します。（実際には、`duration`はNSL-KDDの1つの特徴ですが、ここでは回帰を示すために使用します。）データセットをロードし、前処理（カテゴリカル特徴のエンコード）を行い、線形回帰モデルをトレーニングし、テストセットで平均二乗誤差（MSE）とR²スコアを評価します。
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
この例では、線形回帰モデルが他のネットワーク機能から接続の `duration` を予測しようとしています。パフォーマンスは平均二乗誤差 (MSE) と R² で測定します。R² が 1.0 に近い場合、モデルが `duration` の大部分の分散を説明していることを示しますが、低いまたは負の R² は適合が悪いことを示します。（ここで R² が低いことに驚かないでください -- 与えられた特徴から `duration` を予測するのは難しいかもしれず、線形回帰はパターンが複雑な場合には捉えられないかもしれません。）

### ロジスティック回帰

ロジスティック回帰は、特定のクラス（通常は「ポジティブ」クラス）にインスタンスが属する確率をモデル化する**分類**アルゴリズムです。その名前にもかかわらず、*ロジスティック*回帰は離散的な結果に使用されます（連続的な結果のための線形回帰とは異なります）。特に**二項分類**（2つのクラス、例えば、悪意のある vs. 良性）に使用されますが、ソフトマックスや一対残りアプローチを使用して多クラス問題に拡張することもできます。

ロジスティック回帰は、予測値を確率にマッピングするためにロジスティック関数（シグモイド関数とも呼ばれます）を使用します。シグモイド関数は、分類のニーズに応じて S 字型の曲線で成長する 0 と 1 の間の値を持つ関数であり、二項分類タスクに役立ちます。したがって、各入力の各特徴はその割り当てられた重みで乗算され、その結果はシグモイド関数を通過して確率を生成します：
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
どこで：

- `p(y=1|x)` は、入力 `x` に対して出力 `y` が 1 である確率です
- `e` は自然対数の底です
- `z` は入力特徴の線形結合で、通常は `z = w1*x1 + w2*x2 + ... + wn*xn + b` と表されます。最も単純な形では直線ですが、より複雑な場合には複数の次元（特徴ごとに1つ）を持つハイパープレーンになります。

> [!TIP]
> *サイバーセキュリティにおけるユースケース:* 多くのセキュリティ問題は本質的にはい/いいえの決定であるため、ロジスティック回帰は広く使用されています。たとえば、侵入検知システムは、接続の特徴に基づいてネットワーク接続が攻撃であるかどうかを判断するためにロジスティック回帰を使用するかもしれません。フィッシング検出では、ロジスティック回帰がウェブサイトの特徴（URLの長さ、"@"記号の存在など）を組み合わせてフィッシングである確率を算出できます。初期のスパムフィルターで使用されており、多くの分類タスクの強力なベースラインとして残っています。

#### 非二項分類のためのロジスティック回帰

ロジスティック回帰は二項分類のために設計されていますが、**one-vs-rest** (OvR) や **softmax回帰** のような技術を使用して多クラス問題を扱うように拡張できます。OvRでは、各クラスに対して別々のロジスティック回帰モデルが訓練され、他のすべてに対してそれを正のクラスとして扱います。予測確率が最も高いクラスが最終的な予測として選ばれます。ソフトマックス回帰は、出力層にソフトマックス関数を適用することでロジスティック回帰を複数のクラスに一般化し、すべてのクラスに対する確率分布を生成します。

#### **ロジスティック回帰の主な特徴：**

-   **問題の種類:** 分類（通常は二項）。正のクラスの確率を予測します。

-   **解釈性:** 高い -- 線形回帰のように、特徴係数は各特徴が結果の対数オッズにどのように影響するかを示すことができます。この透明性は、アラートに寄与する要因を理解するためにセキュリティでしばしば評価されます。

-   **利点:** 訓練がシンプルで速い；特徴と結果の対数オッズの関係が線形である場合にうまく機能します。確率を出力し、リスクスコアリングを可能にします。適切な正則化を行うことで、一般化が良好で、単純な線形回帰よりも多重共線性をうまく扱えます。

-   **制限:** 特徴空間における線形決定境界を仮定しています（真の境界が複雑/非線形である場合に失敗します）。相互作用や非線形効果が重要な問題では、手動で多項式や相互作用特徴を追加しない限り、パフォーマンスが低下する可能性があります。また、特徴の線形結合によってクラスが簡単に分離できない場合、ロジスティック回帰は効果が薄れます。

<details>
<summary>例 -- ロジスティック回帰によるフィッシングウェブサイト検出：</summary>

**フィッシングウェブサイトデータセット**（UCIリポジトリから）を使用します。このデータセットには、ウェブサイトの特徴（URLにIPアドレスが含まれているか、ドメインの年齢、HTML内の疑わしい要素の存在など）と、そのサイトがフィッシングか正当かを示すラベルが含まれています。ウェブサイトを分類するためにロジスティック回帰モデルを訓練し、テスト分割でその精度、適合率、再現率、F1スコア、ROC AUCを評価します。
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
このフィッシング検出の例では、ロジスティック回帰が各ウェブサイトがフィッシングである確率を生成します。精度、適合率、再現率、F1を評価することで、モデルのパフォーマンスを把握できます。たとえば、高い再現率は、ほとんどのフィッシングサイトを捕捉することを意味します（見逃した攻撃を最小限に抑えるためにセキュリティにとって重要です）。一方、高い適合率は、誤警報が少ないことを意味します（アナリストの疲労を避けるために重要です）。ROC AUC（ROC曲線下面積）は、閾値に依存しないパフォーマンスの指標を提供します（1.0が理想、0.5は偶然と同じです）。ロジスティック回帰はこのようなタスクでよく機能しますが、フィッシングサイトと正当なサイトの間の決定境界が複雑な場合は、より強力な非線形モデルが必要になるかもしれません。

</details>

### 決定木

決定木は、分類と回帰の両方のタスクに使用できる多用途の**教師あり学習アルゴリズム**です。データの特徴に基づいて、階層的な木のような決定モデルを学習します。木の各内部ノードは特定の特徴に対するテストを表し、各枝はそのテストの結果を表し、各葉ノードは予測されたクラス（分類の場合）または値（回帰の場合）を表します。

木を構築するために、CART（分類および回帰木）などのアルゴリズムは、**ジニ不純度**や**情報利得（エントロピー）**などの指標を使用して、各ステップでデータを分割するための最良の特徴と閾値を選択します。各分割の目標は、結果のサブセット内でターゲット変数の均質性を高めるためにデータを分割することです（分類の場合、各ノードはできるだけ純粋で、主に単一のクラスを含むことを目指します）。

決定木は**非常に解釈可能**です -- ルートから葉までのパスをたどることで、予測の背後にある論理を理解できます（例：*「IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack」*）。これは、特定のアラートがなぜ発生したのかを説明するためにサイバーセキュリティで価値があります。木は数値データとカテゴリデータの両方を自然に扱うことができ、前処理がほとんど必要ありません（例：特徴スケーリングは必要ありません）。

しかし、単一の決定木は、特に深く成長させると（多くの分割）、トレーニングデータに過剰適合しやすいです。過剰適合を防ぐために、剪定（木の深さを制限するか、葉ごとに最小サンプル数を要求する）などの技術がよく使用されます。

決定木には3つの主要なコンポーネントがあります：
- **ルートノード**：木の最上部のノードで、全データセットを表します。
- **内部ノード**：特徴とそれに基づく決定を表すノード。
- **葉ノード**：最終的な結果または予測を表すノード。

木はこのように見えるかもしれません：
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *サイバーセキュリティにおけるユースケース:* 決定木は侵入検知システムで攻撃を特定するための**ルール**を導出するために使用されています。例えば、ID3/C4.5ベースの初期IDSは、正常なトラフィックと悪意のあるトラフィックを区別するための人間が読み取れるルールを生成します。また、マルウェア分析においても、ファイルの属性（ファイルサイズ、セクションエントロピー、APIコールなど）に基づいてファイルが悪意のあるものであるかどうかを判断するために使用されます。決定木の明確さは、透明性が必要な場合に役立ちます -- アナリストはツリーを検査して検出ロジックを検証できます。

#### **決定木の主な特徴:**

-   **問題の種類:** 分類と回帰の両方。攻撃と正常なトラフィックの分類などに一般的に使用されます。

-   **解釈可能性:** 非常に高い -- モデルの決定は、if-thenルールのセットとして視覚化および理解できます。これは、モデルの動作の信頼性と検証においてセキュリティ上の大きな利点です。

-   **利点:** 非線形の関係や特徴間の相互作用を捉えることができます（各分割は相互作用として見ることができます）。特徴をスケーリングしたり、カテゴリ変数をワンホットエンコードする必要はありません -- ツリーはそれらをネイティブに処理します。高速な推論（予測はツリー内のパスをたどるだけです）。

-   **制限:** 制御されない場合、過剰適合しやすい（深いツリーはトレーニングセットを記憶する可能性があります）。データの小さな変化が異なるツリー構造をもたらす可能性があるため、不安定になることがあります。単一のモデルとしては、精度がより高度な手法（バリアンスを減少させるために通常はランダムフォレストのようなアンサンブルがより良いパフォーマンスを発揮します）に匹敵しないことがあります。

-   **最適な分割の見つけ方:**
- **ジニ不純度**: ノードの不純度を測定します。ジニ不純度が低いほど、より良い分割を示します。式は次の通りです:

```plaintext
Gini = 1 - Σ(p_i^2)
```

ここで `p_i` はクラス `i` のインスタンスの割合です。

- **エントロピー**: データセットの不確実性を測定します。エントロピーが低いほど、より良い分割を示します。式は次の通りです:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

ここで `p_i` はクラス `i` のインスタンスの割合です。

- **情報利得**: 分割後のエントロピーまたはジニ不純度の減少です。情報利得が高いほど、より良い分割を示します。計算式は次の通りです:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

さらに、ツリーは次の条件で終了します:
- ノード内のすべてのインスタンスが同じクラスに属する場合。これは過剰適合を引き起こす可能性があります。
- ツリーの最大深度（ハードコーディングされた）が達成された場合。これは過剰適合を防ぐ方法の一つです。
- ノード内のインスタンスの数が特定の閾値を下回る場合。これも過剰適合を防ぐ方法の一つです。
- さらなる分割からの情報利得が特定の閾値を下回る場合。これも過剰適合を防ぐ方法の一つです。

<details>
<summary>例 -- 侵入検知のための決定木:</summary>
NSL-KDDデータセットを使用して、ネットワーク接続を*正常*または*攻撃*として分類するために決定木をトレーニングします。NSL-KDDは、プロトコルタイプ、サービス、期間、失敗したログインの数などの特徴を持つ、クラシックなKDD Cup 1999データセットの改良版であり、攻撃タイプまたは「正常」を示すラベルがあります。すべての攻撃タイプを「異常」クラスにマッピングします（バイナリ分類: 正常 vs 異常）。トレーニング後、テストセットでツリーのパフォーマンスを評価します。
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
この決定木の例では、極端な過剰適合を避けるために木の深さを10に制限しました（`max_depth=10`パラメータ）。メトリクスは、木が正常なトラフィックと攻撃トラフィックをどれだけうまく区別できるかを示しています。高い再現率は、ほとんどの攻撃を捕捉することを意味します（IDSにとって重要）、一方で高い精度は偽陽性が少ないことを意味します。決定木は構造化データに対して適度な精度を達成することが多いですが、単一の木が可能な最高のパフォーマンスに達することはないかもしれません。それでも、モデルの*解釈可能性*は大きな利点です -- たとえば、接続を悪意のあるものとしてフラグ付けするのに最も影響力のある特徴（例：`service`、`src_bytes`など）を確認するために木の分割を調べることができます。

</details>

### ランダムフォレスト

ランダムフォレストは、**アンサンブル学習**手法で、決定木を基にしてパフォーマンスを向上させます。ランダムフォレストは複数の決定木（したがって「フォレスト」）を訓練し、それらの出力を組み合わせて最終的な予測を行います（分類の場合、通常は多数決によって）。ランダムフォレストの2つの主なアイデアは、**バギング**（ブートストラップ集約）と**特徴のランダム性**です：

-   **バギング：** 各木は、トレーニングデータのランダムなブートストラップサンプル（置換ありでサンプリング）で訓練されます。これにより、木の間に多様性が生まれます。

-   **特徴のランダム性：** 木の各分割で、分割のためにランダムな特徴のサブセットが考慮されます（すべての特徴の代わりに）。これにより、木の相関がさらに減少します。

多くの木の結果を平均化することにより、ランダムフォレストは単一の決定木が持つかもしれない分散を減少させます。簡単に言えば、個々の木は過剰適合したりノイズが多かったりするかもしれませんが、多様な木が一緒に投票することでそれらのエラーが平滑化されます。その結果、単一の決定木よりも**高い精度**とより良い一般化を持つモデルが得られることが多いです。さらに、ランダムフォレストは特徴の重要性を推定することができます（各特徴の分割が平均してどれだけ不純物を減少させるかを見ることによって）。

ランダムフォレストは、侵入検知、マルウェア分類、スパム検出などのタスクにおいて**サイバーセキュリティの作業馬**となっています。最小限の調整で箱から出してすぐに良好なパフォーマンスを発揮し、大規模な特徴セットを扱うことができます。たとえば、侵入検知において、ランダムフォレストは、より微妙な攻撃パターンを捕捉し、偽陽性を少なくすることで、個々の決定木を上回ることがあります。研究によると、ランダムフォレストは、NSL-KDDやUNSW-NB15のようなデータセットで攻撃を分類する際に他のアルゴリズムと比較して好意的に機能することが示されています。

#### **ランダムフォレストの主な特徴：**

-   **問題のタイプ：** 主に分類（回帰にも使用される）。セキュリティログに一般的な高次元構造化データに非常に適しています。

-   **解釈可能性：** 単一の決定木よりも低い -- 数百の木を一度に視覚化したり説明したりすることは容易ではありません。ただし、特徴の重要性スコアは、どの属性が最も影響力があるかについての洞察を提供します。

-   **利点：** アンサンブル効果により、一般的に単一木モデルよりも高い精度を持ちます。過剰適合に対して堅牢 -- 個々の木が過剰適合しても、アンサンブルはより良く一般化します。数値的およびカテゴリカルな特徴の両方を扱い、ある程度の欠損データを管理できます。また、外れ値に対しても比較的堅牢です。

-   **制限：** モデルサイズが大きくなる可能性があります（多くの木があり、それぞれが深い可能性があります）。予測は単一の木よりも遅くなります（多くの木を集約する必要があるため）。解釈可能性が低い -- 重要な特徴はわかりますが、正確な論理は単純なルールとして追跡するのが容易ではありません。データセットが非常に高次元でスパースな場合、非常に大きなフォレストを訓練することは計算的に重くなる可能性があります。

-   **訓練プロセス：**
1. **ブートストラップサンプリング：** 置換ありでトレーニングデータをランダムにサンプリングして複数のサブセット（ブートストラップサンプル）を作成します。
2. **木の構築：** 各ブートストラップサンプルについて、各分割でランダムな特徴のサブセットを使用して決定木を構築します。これにより、木の間に多様性が生まれます。
3. **集約：** 分類タスクの場合、最終的な予測はすべての木の予測の多数決によって行われます。回帰タスクの場合、最終的な予測はすべての木の予測の平均です。

<details>
<summary>例 -- 侵入検知のためのランダムフォレスト（NSL-KDD）：</summary>
同じNSL-KDDデータセット（正常対異常としてバイナリラベル付け）を使用し、ランダムフォレスト分類器を訓練します。アンサンブル平均により分散が減少するため、ランダムフォレストが単一の決定木と同等かそれ以上のパフォーマンスを発揮することを期待しています。同じメトリクスで評価します。
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
ランダムフォレストは、通常、この侵入検知タスクで強力な結果を達成します。データに応じて、単一の決定木と比較してF1やAUCのような指標の改善が見られるかもしれません。これは、*"Random Forest (RF)はアンサンブル分類器であり、攻撃の効果的な分類において他の従来の分類器と比較して優れた性能を発揮します。"*という理解と一致します。セキュリティオペレーションの文脈では、ランダムフォレストモデルは、多くの決定ルールの平均化のおかげで、攻撃をより信頼性高くフラグ付けし、誤警報を減少させることができます。フォレストからの特徴の重要性は、どのネットワークの特徴が攻撃を示す最も指標的であるか（例えば、特定のネットワークサービスや異常なパケット数）を教えてくれるかもしれません。

</details>

### サポートベクターマシン (SVM)

サポートベクターマシンは、主に分類（および回帰としてSVR）に使用される強力な教師あり学習モデルです。SVMは、2つのクラス間のマージンを最大化する**最適な分離ハイパープレーン**を見つけようとします。このハイパープレーンの位置は、境界に最も近いトレーニングポイントのサブセット（"サポートベクター"）によって決まります。マージン（サポートベクターとハイパープレーンの間の距離）を最大化することにより、SVMは良好な一般化を達成する傾向があります。

SVMの力の鍵は、非線形関係を扱うために**カーネル関数**を使用する能力です。データは、線形分離子が存在するかもしれない高次元の特徴空間に暗黙的に変換されることがあります。一般的なカーネルには、多項式、放射基底関数（RBF）、およびシグモイドがあります。例えば、ネットワークトラフィッククラスが生の特徴空間で線形に分離できない場合、RBFカーネルはそれらを高次元にマッピングし、SVMが線形分割を見つけることができます（これは元の空間での非線形境界に対応します）。カーネルを選択する柔軟性により、SVMはさまざまな問題に取り組むことができます。

SVMは、高次元の特徴空間（テキストデータやマルウェアのオペコードシーケンスなど）や、特徴の数がサンプルの数に対して大きい場合にうまく機能することが知られています。2000年代には、マルウェア分類や異常ベースの侵入検知など、多くの初期サイバーセキュリティアプリケーションで人気があり、しばしば高い精度を示しました。

しかし、SVMは非常に大きなデータセットに対してはスケールしにくいです（トレーニングの複雑さはサンプル数に対して超線形であり、メモリ使用量も高くなる可能性があります）。実際、数百万のレコードを持つネットワーク侵入検知のようなタスクでは、慎重なサブサンプリングや近似手法を使用しない限り、SVMは遅すぎるかもしれません。

#### **SVMの主な特徴:**

-   **問題の種類:** 分類（バイナリまたはマルチクラス、1対1/1対残り）および回帰のバリエーション。明確なマージン分離を持つバイナリ分類でよく使用されます。

-   **解釈性:** 中程度 -- SVMは決定木やロジスティック回帰ほど解釈可能ではありません。どのデータポイントがサポートベクターであるかを特定し、どの特徴が影響を与える可能性があるかを把握することはできますが（線形カーネルの場合の重みを通じて）、実際にはSVM（特に非線形カーネルを使用する場合）はブラックボックス分類器として扱われます。

-   **利点:** 高次元空間で効果的; カーネルトリックで複雑な決定境界をモデル化できる; マージンが最大化されている場合、過剰適合に対して堅牢（特に適切な正則化パラメータCがある場合）; クラスが大きな距離で分離されていない場合でもうまく機能する（最良の妥協境界を見つける）。

-   **制限:** **計算集約的**で、大規模データセットに対しては（トレーニングと予測の両方がデータが増えるにつれてスケールが悪化します）。カーネルと正則化パラメータ（C、カーネルタイプ、RBFのガンマなど）の慎重な調整が必要です。確率的出力を直接提供しません（ただし、Plattスケーリングを使用して確率を得ることができます）。また、SVMはカーネルパラメータの選択に敏感であり、適切でない選択はアンダーフィットまたはオーバーフィットを引き起こす可能性があります。

*サイバーセキュリティにおけるユースケース:* SVMは、**マルウェア検出**（抽出された特徴やオペコードシーケンスに基づいてファイルを分類するなど）、**ネットワーク異常検出**（トラフィックを正常と悪意のあるものに分類する）、および**フィッシング検出**（URLの特徴を使用）に使用されています。例えば、SVMはメールの特徴（特定のキーワードのカウント、送信者の評判スコアなど）を取り込み、それをフィッシングまたは正当なものとして分類することができます。また、KDDのような特徴セットでの**侵入検知**にも適用されており、計算コストをかけて高い精度を達成することが多いです。

<details>
<summary>例 -- マルウェア分類のためのSVM:</summary>
フィッシングウェブサイトデータセットを再度使用しますが、今回はSVMを使用します。SVMは遅くなる可能性があるため、必要に応じてトレーニング用にデータのサブセットを使用します（データセットは約11kインスタンスで、SVMは合理的に処理できます）。非線形データに一般的な選択肢であるRBFカーネルを使用し、ROC AUCを計算するために確率推定を有効にします。
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
SVMモデルは、同じタスクに対するロジスティック回帰と比較できるメトリクスを出力します。データが特徴によってうまく分離されている場合、SVMは高い精度とAUCを達成することがわかるかもしれません。一方、データセットに多くのノイズや重複するクラスがある場合、SVMはロジスティック回帰を大幅に上回ることはないかもしれません。実際には、SVMは特徴とクラスの間に複雑な非線形関係がある場合にブーストを提供できます。RBFカーネルは、ロジスティック回帰が見逃すような曲がった決定境界を捉えることができます。すべてのモデルと同様に、バイアスと分散のバランスを取るために、`C`（正則化）およびカーネルパラメータ（RBFの場合の`gamma`など）の慎重な調整が必要です。

</details>

#### ロジスティック回帰とSVMの違い

| アスペクト | **ロジスティック回帰** | **サポートベクターマシン** |
|---|---|---|
| **目的関数** | **ログ損失**（クロスエントロピー）を最小化します。 | **ヒンジ損失**を最小化しながら**マージン**を最大化します。 |
| **決定境界** | _P(y\|x)_をモデル化する**最適ハイパープレーン**を見つけます。 | **最大マージンハイパープレーン**（最も近い点との最大のギャップ）を見つけます。 |
| **出力** | **確率的** – σ(w·x + b)を介してキャリブレーションされたクラス確率を提供します。 | **決定論的** – クラスラベルを返します; 確率には追加の作業が必要です（例：プラットスケーリング）。 |
| **正則化** | L2（デフォルト）またはL1、直接的に過剰適合/不足適合のバランスを取ります。 | Cパラメータはマージン幅と誤分類のトレードオフを行います; カーネルパラメータは複雑さを追加します。 |
| **カーネル / 非線形** | ネイティブ形式は**線形**です; 特徴エンジニアリングによって非線形性が追加されます。 | 組み込みの**カーネルトリック**（RBF、ポリなど）により、高次元空間で複雑な境界をモデル化できます。 |
| **スケーラビリティ** | **O(nd)**で凸最適化を解決します; 非常に大きなnをうまく処理します。 | 特殊なソルバーなしではトレーニングが**O(n²–n³)**のメモリ/時間を要します; 巨大なnにはあまり適していません。 |
| **解釈可能性** | **高い** – 重みが特徴の影響を示します; オッズ比は直感的です。 | 非線形カーネルの場合は**低い**; サポートベクターはスパースですが、説明が容易ではありません。 |
| **外れ値に対する感度** | スムーズなログ損失を使用 → 感度が低いです。 | ハードマージンのヒンジ損失は**感度が高い**; ソフトマージン（C）が緩和します。 |
| **典型的な使用ケース** | クレジットスコアリング、医療リスク、A/Bテスト – **確率と説明可能性**が重要な場合。 | 画像/テキスト分類、バイオインフォマティクス – **複雑な境界**と**高次元データ**が重要な場合。 |

* **キャリブレーションされた確率、解釈可能性が必要な場合、または巨大なデータセットで操作する場合は、ロジスティック回帰を選択してください。**
* **手動の特徴エンジニアリングなしで非線形関係を捉える柔軟なモデルが必要な場合は、SVM（カーネル付き）を選択してください。**
* 両者は凸目的を最適化するため、**グローバルミニマが保証されています**が、SVMのカーネルはハイパーパラメータと計算コストを追加します。

### ナイーブベイズ

ナイーブベイズは、特徴間の強い独立性の仮定に基づいてベイズの定理を適用する**確率的分類器**のファミリーです。この「ナイーブ」な仮定にもかかわらず、ナイーブベイズは特にテキストやカテゴリデータ（スパム検出など）を含む特定のアプリケーションで驚くほどうまく機能します。

#### ベイズの定理

ベイズの定理はナイーブベイズ分類器の基礎です。これは、ランダムな事象の条件付き確率と周辺確率を関連付けます。公式は次のとおりです:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` は特徴 `B` が与えられたときのクラス `A` の事後確率です。
- `P(B|A)` はクラス `A` が与えられたときの特徴 `B` の尤度です。
- `P(A)` はクラス `A` の事前確率です。
- `P(B)` は特徴 `B` の事前確率です。

例えば、テキストが子供によって書かれたものか大人によって書かれたものかを分類したい場合、テキスト内の単語を特徴として使用できます。初期データに基づいて、ナイーブベイズ分類器は各単語が各潜在クラス（子供または大人）に属する確率を事前に計算します。新しいテキストが与えられると、テキスト内の単語に基づいて各潜在クラスの確率を計算し、最も高い確率のクラスを選択します。

この例からわかるように、ナイーブベイズ分類器は非常にシンプルで高速ですが、特徴が独立であると仮定しており、これは実際のデータでは常に当てはまるわけではありません。

#### ナイーブベイズ分類器の種類

ナイーブベイズ分類器には、データの種類や特徴の分布に応じていくつかのタイプがあります：
- **ガウス型ナイーブベイズ**: 特徴がガウス（正規）分布に従うと仮定します。連続データに適しています。
- **多項式ナイーブベイズ**: 特徴が多項分布に従うと仮定します。テキスト分類における単語のカウントなど、離散データに適しています。
- **ベルヌーイ型ナイーブベイズ**: 特徴がバイナリ（0または1）であると仮定します。テキスト分類における単語の存在または不在など、バイナリデータに適しています。
- **カテゴリカルナイーブベイズ**: 特徴がカテゴリ変数であると仮定します。色や形に基づいて果物を分類するなど、カテゴリデータに適しています。

#### **ナイーブベイズの主な特徴:**

-   **問題の種類:** 分類（バイナリまたはマルチクラス）。サイバーセキュリティにおけるテキスト分類タスク（スパム、フィッシングなど）で一般的に使用されます。

-   **解釈性:** 中程度 -- 決定木ほど直接的に解釈できるわけではありませんが、学習した確率（例えば、スパムとハムのメールで最も可能性の高い単語）を検査できます。モデルの形式（クラスに対する各特徴の確率）は、必要に応じて理解できます。

-   **利点:** **非常に高速**なトレーニングと予測、大規模データセットでも（インスタンス数 * 特徴数に対して線形）。確率を信頼性高く推定するために比較的少量のデータを必要とし、特に適切なスムージングがあれば効果的です。特徴が独立してクラスに証拠を提供する場合、ベースラインとして驚くほど正確です。高次元データ（例えば、テキストからの数千の特徴）でうまく機能します。スムージングパラメータを設定する以外に複雑な調整は必要ありません。

-   **制限:** 特徴が高度に相関している場合、独立性の仮定が精度を制限する可能性があります。例えば、ネットワークデータでは、`src_bytes` と `dst_bytes` のような特徴が相関している可能性がありますが、ナイーブベイズはその相互作用を捉えません。データサイズが非常に大きくなると、特徴の依存関係を学習することで、より表現力のあるモデル（アンサンブルやニューラルネットなど）がナイーブベイズを上回ることがあります。また、攻撃を特定するために特定の特徴の組み合わせが必要な場合（単独の特徴ではなく）、ナイーブベイズは苦労します。

> [!TIP]
> *サイバーセキュリティにおけるユースケース:* クラシックな使用例は **スパム検出** です -- ナイーブベイズは初期のスパムフィルターの中心であり、特定のトークン（単語、フレーズ、IPアドレス）の頻度を使用して、メールがスパムである確率を計算しました。また、**フィッシングメール検出**や **URL分類** にも使用され、特定のキーワードや特性（URL内の "login.php" や URLパス内の `@` など）がフィッシングの確率に寄与します。マルウェア分析では、特定のAPIコールやソフトウェアの権限の存在を使用して、それがマルウェアであるかどうかを予測するナイーブベイズ分類器を想像できます。より高度なアルゴリズムがしばしばより良い結果を出す一方で、ナイーブベイズはその速度とシンプルさから良いベースラインとして残ります。

<details>
<summary>例 -- フィッシング検出のためのナイーブベイズ:</summary>
ナイーブベイズを示すために、NSL-KDD侵入データセット（バイナリラベル付き）に対してガウス型ナイーブベイズを使用します。ガウス型NBは、各特徴がクラスごとに正規分布に従うと見なします。多くのネットワーク特徴が離散的または非常に偏っているため、これは粗い選択ですが、連続特徴データにナイーブベイズを適用する方法を示しています。バイナリ特徴のデータセット（トリガーされたアラートのセットなど）に対してベルヌーイ型NBを選択することもできますが、ここでは継続性のためにNSL-KDDに留まります。
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
このコードは、攻撃を検出するためにナイーブベイズ分類器をトレーニングします。ナイーブベイズは、特徴間の独立性を仮定して、トレーニングデータに基づいて `P(service=http | Attack)` や `P(Service=http | Normal)` のようなものを計算します。その後、観測された特徴に基づいて新しい接続を正常または攻撃として分類するために、これらの確率を使用します。NBのNSL-KDDにおけるパフォーマンスは、より高度なモデルほど高くないかもしれません（特徴の独立性が破られるため）が、しばしば十分であり、極めて高速であるという利点があります。リアルタイムのメールフィルタリングやURLの初期トリアージのようなシナリオでは、ナイーブベイズモデルはリソース使用量が少なく、明らかに悪意のあるケースを迅速にフラグ付けできます。

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighborsは、最もシンプルな機械学習アルゴリズムの1つです。これは、**非パラメトリックでインスタンスベース**の手法で、トレーニングセットの例との類似性に基づいて予測を行います。分類のアイデアは、新しいデータポイントを分類するために、トレーニングデータ内の**k**個の最も近いポイント（その「最近傍」）を見つけ、その近傍の中で多数派のクラスを割り当てることです。「近さ」は距離指標によって定義され、通常は数値データに対してユークリッド距離が使用されます（他の距離は異なるタイプの特徴や問題に対して使用できます）。

K-NNは*明示的なトレーニングを必要としません* -- 「トレーニング」フェーズはデータセットを保存するだけです。すべての作業はクエリ（予測）中に行われます：アルゴリズムは、クエリポイントからすべてのトレーニングポイントへの距離を計算して最も近いものを見つける必要があります。これにより、予測時間は**トレーニングサンプルの数に対して線形**になり、大規模なデータセットではコストがかかる可能性があります。このため、k-NNは小規模なデータセットや、メモリと速度をシンプルさとトレードオフできるシナリオに最適です。

そのシンプルさにもかかわらず、k-NNは非常に複雑な決定境界をモデル化できます（実際には、決定境界は例の分布によって決定される任意の形状を取ることができます）。決定境界が非常に不規則で、多くのデータがある場合にうまく機能します -- 本質的にデータが「自らを語る」ことを許します。しかし、高次元では、距離指標があまり意味を持たなくなることがあります（次元の呪い）、そしてサンプル数が非常に多くない限り、この手法は苦労することがあります。

*サイバーセキュリティにおけるユースケース:* k-NNは異常検出に適用されています -- たとえば、侵入検知システムは、最も近い隣接点（以前のイベント）のほとんどが悪意のあるものであれば、ネットワークイベントを悪意のあるものとしてラベル付けするかもしれません。正常なトラフィックがクラスターを形成し、攻撃が外れ値である場合、K-NNアプローチ（k=1または小さなk）は本質的に**最近傍異常検出**を行います。K-NNは、バイナリ特徴ベクトルによるマルウェアファミリーの分類にも使用されています：新しいファイルは、そのファミリーの既知のインスタンスに非常に近い場合、特定のマルウェアファミリーとして分類されるかもしれません。実際には、k-NNはよりスケーラブルなアルゴリズムほど一般的ではありませんが、概念的には簡単であり、時にはベースラインや小規模な問題に使用されます。

#### **k-NNの主な特徴:**

-   **問題のタイプ:** 分類（および回帰のバリアントも存在します）。これは*怠惰な学習*手法です -- 明示的なモデルフィッティングはありません。

-   **解釈可能性:** 低から中程度 -- グローバルモデルや簡潔な説明はありませんが、決定に影響を与えた最近傍を見て結果を解釈することができます（例：「このネットワークフローは、これらの3つの既知の悪意のあるフローに似ているため、悪意のあるものとして分類されました」）。したがって、説明は例に基づくことができます。

-   **利点:** 実装と理解が非常に簡単です。データ分布についての仮定を行いません（非パラメトリック）。マルチクラス問題を自然に処理できます。データ分布によって形作られる非常に複雑な決定境界を持つ**適応的**です。

-   **制限:** 大規模なデータセットでは予測が遅くなる可能性があります（多くの距離を計算する必要があります）。メモリ集約型 -- すべてのトレーニングデータを保存します。高次元の特徴空間では、すべてのポイントがほぼ等距離になる傾向があるため、パフォーマンスが低下します（「最近傍」の概念があまり意味を持たなくなります）。*k*（近傍の数）を適切に選択する必要があります -- 小さすぎるkはノイズが多く、大きすぎるkは他のクラスからの無関係なポイントを含む可能性があります。また、距離計算はスケールに敏感であるため、特徴は適切にスケーリングする必要があります。

<details>
<summary>例 -- フィッシング検出のためのk-NN:</summary>

再びNSL-KDD（バイナリ分類）を使用します。k-NNは計算負荷が高いため、このデモではトレーニングデータのサブセットを使用して扱いやすくします。たとえば、全体の125kから20,000のトレーニングサンプルを選び、k=5の近傍を使用します。トレーニング後（実際にはデータを保存するだけ）、テストセットで評価します。また、距離計算のために特徴をスケーリングして、単一の特徴がスケールのために支配しないようにします。
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
k-NNモデルは、トレーニングセットのサブセット内で最も近い5つの接続を見て接続を分類します。例えば、これらの隣接接続のうち4つが攻撃（異常）で1つが正常である場合、新しい接続は攻撃として分類されます。パフォーマンスは合理的かもしれませんが、同じデータに対して適切に調整されたRandom ForestやSVMほど高くないことが多いです。しかし、k-NNはクラス分布が非常に不規則で複雑な場合に際立つことがあります。サイバーセキュリティにおいて、k-NN（k=1または小さなk）は、既知の攻撃パターンの検出や、より複雑なシステムのコンポーネント（例えば、クラスタリングを行い、その後クラスタメンバーシップに基づいて分類する）として使用される可能性があります。

### 勾配ブースティングマシン（例：XGBoost）

勾配ブースティングマシンは、構造化データに対して最も強力なアルゴリズムの一つです。**勾配ブースティング**は、弱い学習者（通常は決定木）のアンサンブルを逐次的に構築する技術を指し、各新しいモデルが前のアンサンブルの誤りを修正します。並列に木を構築して平均化するバギング（Random Forest）とは異なり、ブースティングは木を*一つずつ*構築し、各木が前の木が誤予測したインスタンスにより焦点を当てます。

近年の最も人気のある実装は、**XGBoost**、**LightGBM**、および**CatBoost**で、これらはすべて勾配ブースティング決定木（GBDT）ライブラリです。これらは機械学習コンペティションやアプリケーションで非常に成功を収めており、しばしば**表形式データセットで最先端のパフォーマンスを達成しています**。サイバーセキュリティにおいて、研究者や実務者は、**マルウェア検出**（ファイルや実行時の挙動から抽出された特徴を使用）や**ネットワーク侵入検出**のタスクに勾配ブーストツリーを使用しています。例えば、勾配ブースティングモデルは、「多くのSYNパケットと異常なポートがある場合 -> スキャンの可能性が高い」といった多くの弱いルール（木）を組み合わせて、多くの微妙なパターンを考慮した強力な複合検出器を作成できます。

なぜブーストされた木はこれほど効果的なのでしょうか？シーケンス内の各木は、現在のアンサンブルの予測の*残差誤差*（勾配）に基づいて訓練されます。このようにして、モデルは徐々に**「ブースト」**される弱い領域を強化します。決定木を基礎学習者として使用することで、最終モデルは複雑な相互作用や非線形関係を捉えることができます。また、ブースティングは本質的に組み込みの正則化の形を持っています：多くの小さな木を追加し（その寄与をスケールするために学習率を使用）、適切なパラメータが選択されている限り、過剰適合を防ぎながらよく一般化します。

#### **勾配ブースティングの主な特徴：**

-   **問題のタイプ：** 主に分類と回帰。セキュリティでは通常、分類（例えば、接続やファイルを二値分類する）。二値、多クラス（適切な損失を伴う）、さらにはランキング問題を扱います。

-   **解釈可能性：** 低から中程度。単一のブーストされた木は小さいですが、完全なモデルは数百の木を持つ可能性があり、全体としては人間が解釈するのが難しいです。しかし、Random Forestのように、特徴の重要度スコアを提供でき、SHAP（SHapley Additive exPlanations）などのツールを使用して、個々の予測をある程度解釈することができます。

-   **利点：** 構造化/表形式データに対してしばしば**最も高いパフォーマンス**を発揮するアルゴリズムです。複雑なパターンや相互作用を検出できます。モデルの複雑さを調整し、過剰適合を防ぐための多くの調整ノブ（木の数、木の深さ、学習率、正則化項）があります。現代の実装は速度の最適化がされており（例えば、XGBoostは二次勾配情報と効率的なデータ構造を使用）、適切な損失関数やサンプル重みの調整と組み合わせることで、不均衡データをより良く扱う傾向があります。

-   **制限：** より単純なモデルよりも調整が複雑で、木が深い場合や木の数が多い場合は訓練が遅くなることがあります（ただし、同じデータで比較可能な深層ニューラルネットワークの訓練よりは通常速いです）。適切に調整されていない場合、モデルは過剰適合する可能性があります（例えば、十分な正則化がない深い木が多すぎる場合）。多くのハイパーパラメータがあるため、勾配ブースティングを効果的に使用するには、より多くの専門知識や実験が必要な場合があります。また、木ベースの手法のように、非常にスパースな高次元データを線形モデルやナイーブベイズほど効率的に扱うことはできません（ただし、テキスト分類などで適用可能ですが、特徴エンジニアリングなしでは最初の選択肢ではないかもしれません）。

> [!TIP]
> *サイバーセキュリティにおけるユースケース：* 決定木やランダムフォレストが使用できるほぼすべての場所で、勾配ブースティングモデルはより良い精度を達成する可能性があります。例えば、**Microsoftのマルウェア検出**コンペティションでは、バイナリファイルからエンジニアリングされた特徴に対してXGBoostが多く使用されています。**ネットワーク侵入検出**の研究では、GBDT（例えば、CIC-IDS2017やUNSW-NB15データセットでのXGBoost）でトップの結果が報告されることが多いです。これらのモデルは、さまざまな特徴（プロトコルタイプ、特定のイベントの頻度、トラフィックの統計的特徴など）を取り込み、組み合わせて脅威を検出します。フィッシング検出では、勾配ブースティングがURLの語彙的特徴、ドメインの評判特徴、ページコンテンツの特徴を組み合わせて非常に高い精度を達成できます。アンサンブルアプローチは、データの多くのコーナーケースや微妙な点をカバーするのに役立ちます。

<details>
<summary>例 -- フィッシング検出のためのXGBoost：</summary>
フィッシングデータセットに対して勾配ブースティング分類器を使用します。シンプルで自己完結的に保つために、`sklearn.ensemble.GradientBoostingClassifier`（これは遅いが簡単な実装です）を使用します。通常、より良いパフォーマンスと追加機能のために`xgboost`や`lightgbm`ライブラリを使用することがあります。モデルを訓練し、以前と同様に評価します。
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
勾配ブースティングモデルは、このフィッシングデータセットで非常に高い精度とAUCを達成する可能性が高いです（通常、これらのモデルは適切なチューニングを行うことで95％以上の精度を超えることができ、文献でも確認されています）。これは、GBDTが「*表形式データセットの最先端モデル*」と見なされる理由を示しています。これらは、複雑なパターンを捉えることで、より単純なアルゴリズムをしばしば上回ります。サイバーセキュリティの文脈では、これはフィッシングサイトや攻撃をより多く捕捉し、見逃しを減らすことを意味するかもしれません。もちろん、過剰適合には注意が必要です。モデルを展開する際には、通常、交差検証のような技術を使用し、検証セットでのパフォーマンスを監視します。

</details>

### モデルの組み合わせ：アンサンブル学習とスタッキング

アンサンブル学習は、**複数のモデルを組み合わせて全体のパフォーマンスを向上させる戦略**です。すでに特定のアンサンブル手法を見ました：ランダムフォレスト（バギングによる木のアンサンブル）と勾配ブースティング（逐次ブースティングによる木のアンサンブル）。しかし、アンサンブルは**投票アンサンブル**や**スタックジェネラリゼーション（スタッキング）**のように他の方法でも作成できます。主なアイデアは、異なるモデルが異なるパターンを捉えたり、異なる弱点を持っている可能性があるため、それらを組み合わせることで、**各モデルの誤りを他のモデルの強みで補う**ことができるということです。

-   **投票アンサンブル：** シンプルな投票分類器では、複数の多様なモデル（例えば、ロジスティック回帰、決定木、SVM）を訓練し、最終予測に投票させます（分類のための多数決）。投票に重みを付ける場合（例えば、より正確なモデルに高い重みを付ける）、これは重み付き投票スキームです。これは、個々のモデルが合理的に良く、独立している場合にパフォーマンスを向上させる傾向があります。アンサンブルは、他のモデルが誤りを修正する可能性があるため、個々のモデルのミスのリスクを減少させます。これは、単一の意見ではなく、専門家のパネルを持つようなものです。

-   **スタッキング（スタックアンサンブル）：** スタッキングはさらに一歩進んでいます。単純な投票の代わりに、**メタモデル**を訓練して**ベースモデルの予測を最適に組み合わせる方法を学習**させます。例えば、3つの異なる分類器（ベース学習者）を訓練し、それらの出力（または確率）をメタ分類器（通常はロジスティック回帰のようなシンプルなモデル）に特徴として供給し、最適なブレンド方法を学習させます。メタモデルは、過剰適合を避けるために検証セットまたは交差検証で訓練されます。スタッキングは、*どのモデルをどの状況でより信頼すべきかを学ぶことで、単純な投票を上回ることがよくあります*。サイバーセキュリティでは、あるモデルがネットワークスキャンを捕捉するのが得意で、別のモデルがマルウェアのビーコニングを捕捉するのが得意な場合、スタッキングモデルはそれぞれに適切に依存することを学ぶことができます。

投票またはスタッキングによるアンサンブルは、**精度**と堅牢性を**向上させる傾向があります**。欠点は、複雑さが増し、時には解釈可能性が低下することです（ただし、決定木の平均のような一部のアンサンブルアプローチは、特徴の重要性などの洞察を提供することができます）。実際には、運用上の制約が許す場合、アンサンブルを使用することで検出率が向上する可能性があります。サイバーセキュリティの課題（および一般的なKaggleコンペティション）での多くの勝利ソリューションは、最後のパフォーマンスを引き出すためにアンサンブル技術を使用しています。

<details>
<summary>例 -- フィッシング検出のための投票アンサンブル：</summary>
モデルスタッキングを示すために、フィッシングデータセットで議論したいくつかのモデルを組み合わせましょう。ロジスティック回帰、決定木、k-NNをベース学習者として使用し、ランダムフォレストをメタ学習者として使用して予測を集約します。メタ学習者は、ベース学習者の出力（トレーニングセットでの交差検証を使用）で訓練されます。スタックモデルは、個々のモデルと同等か、わずかに優れたパフォーマンスを発揮することを期待しています。
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
スタックアンサンブルは、ベースモデルの補完的な強みを活用します。たとえば、ロジスティック回帰はデータの線形的な側面を処理し、決定木は特定のルールのような相互作用を捉え、k-NNは特徴空間の局所的な近傍で優れた性能を発揮するかもしれません。メタモデル（ここではランダムフォレスト）は、これらの入力の重み付けを学習できます。その結果得られるメトリクスは、しばしば単一モデルのメトリクスよりも改善を示します（たとえわずかであっても）。フィッシングの例では、ロジスティック回帰がF1スコア0.95、決定木が0.94であった場合、スタックは各モデルの誤りを補完することで0.96を達成するかもしれません。

このようなアンサンブル手法は、*「複数のモデルを組み合わせることで、一般化が通常向上する」という原則を示しています。* サイバーセキュリティでは、複数の検出エンジン（1つはルールベース、1つは機械学習、1つは異常ベース）を持ち、それらのアラートを集約するレイヤーを持つことで実装できます。これは効果的にアンサンブルの一形態であり、より高い信頼性で最終的な決定を下すことができます。このようなシステムを展開する際には、追加の複雑さを考慮し、アンサンブルが管理や説明が難しくならないようにする必要があります。しかし、精度の観点から見ると、アンサンブルとスタッキングはモデルのパフォーマンスを向上させるための強力なツールです。

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
