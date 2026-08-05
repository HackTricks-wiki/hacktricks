# 教師なし学習アルゴリズム

{{#include ../banners/hacktricks-training.md}}

## 教師なし学習

教師なし学習は、ラベル付きの応答なしでデータを使ってモデルを訓練する機械学習の一種です。目的は、データ内のパターン、構造、または関係を見つけることです。モデルがラベル付きの例から学習する教師あり学習とは異なり、教師なし学習アルゴリズムはラベルのないデータを扱います。
教師なし学習は、クラスタリング、次元削減、異常検知などのタスクによく使われます。データに隠れたパターンを見つけたり、類似した項目をまとめたり、本質的な特徴を保持しながらデータの複雑さを軽減したりするのに役立ちます。


### K-Means Clustering

K-Meansは、各点を最も近いクラスタ平均に割り当てることで、データをK個のクラスタに分割するセントロイドベースのクラスタリングアルゴリズムです。アルゴリズムは次のように動作します。
1. **初期化**: K個の初期クラスタ中心（セントロイド）を、多くの場合はランダムに、またはk-means++のようなより高度な手法で選択する
2. **割り当て**: 距離メトリック（例: ユークリッド距離）に基づいて、各データ点を最も近いセントロイドに割り当てる
3. **更新**: 各クラスタに割り当てられたすべてのデータ点の平均を取り、セントロイドを再計算する
4. **反復**: クラスタの割り当てが安定する（セントロイドが大きく移動しなくなる）まで、手順2〜3を繰り返す

> [!TIP]
> *サイバーセキュリティでの使用例:* K-Meansは、ネットワークイベントをクラスタリングして侵入検知に使用されます。たとえば、研究者はKDD Cup 99 intrusion datasetにK-Meansを適用し、トラフィックを正常クラスタと攻撃クラスタに効果的に分割できることを示しました。実際には、security analystがログエントリやユーザー行動データをクラスタリングして、類似したアクティビティのグループを見つけることがあります。適切に形成されたクラスタに属さない点は、異常を示している可能性があります（例: 新しいmalware variantが独自の小さなクラスタを形成する場合）。K-Meansは、behavior profileやfeature vectorに基づいてバイナリをグループ化することで、malware familyの分類にも役立ちます。

#### Kの選択
クラスタ数（K）は、アルゴリズムを実行する前に定義する必要があるハイパーパラメータです。Elbow MethodやSilhouette Scoreなどの手法は、クラスタリングの性能を評価することで、適切なKの値を決定するのに役立ちます。

- **Elbow Method**: 各点から割り当てられたクラスタセントロイドまでの二乗距離の合計を、Kの関数としてプロットします。減少率が急激に変化する「ひじ（elbow）」の点を探します。これは、適切なクラスタ数を示します。
- **Silhouette Score**: Kのさまざまな値に対してsilhouette scoreを計算します。silhouette scoreが高いほど、より明確に定義されたクラスタであることを示します。

#### 前提と制限

K-Meansは、**クラスタが球状で同じサイズである**ことを前提としますが、これはすべてのデータセットに当てはまるとは限りません。セントロイドの初期配置に敏感であり、局所的な最小値に収束する可能性があります。また、K-Meansは密度が変化するデータセット、球状でない形状のデータセット、特徴量のスケールが異なるデータセットには適していません。すべての特徴量が距離計算に等しく寄与するように、正規化や標準化などの前処理が必要になる場合があります。

<details>
<summary>例 -- ネットワークイベントのクラスタリング
</summary>
以下では、ネットワークトラフィックデータをシミュレートし、K-Meansを使ってクラスタリングします。接続時間やバイト数などの特徴量を持つイベントがあるとします。「正常」トラフィックのクラスタを3つ作成し、攻撃パターンを表す小さなクラスタを1つ作成します。その後、K-Meansを実行して、それらを分離できるか確認します。
```python
import numpy as np
from sklearn.cluster import KMeans

# Simulate synthetic network traffic data (e.g., [duration, bytes]).
# Three normal clusters and one small attack cluster.
rng = np.random.RandomState(42)
normal1 = rng.normal(loc=[50, 500], scale=[10, 100], size=(500, 2))   # Cluster 1
normal2 = rng.normal(loc=[60, 1500], scale=[8, 200], size=(500, 2))   # Cluster 2
normal3 = rng.normal(loc=[70, 3000], scale=[5, 300], size=(500, 2))   # Cluster 3
attack = rng.normal(loc=[200, 800], scale=[5, 50], size=(50, 2))      # Small attack cluster

X = np.vstack([normal1, normal2, normal3, attack])
# Run K-Means clustering into 4 clusters (we expect it to find the 4 groups)
kmeans = KMeans(n_clusters=4, random_state=0, n_init=10)
labels = kmeans.fit_predict(X)

# Analyze resulting clusters
clusters, counts = np.unique(labels, return_counts=True)
print(f"Cluster labels: {clusters}")
print(f"Cluster sizes: {counts}")
print("Cluster centers (duration, bytes):")
for idx, center in enumerate(kmeans.cluster_centers_):
print(f"  Cluster {idx}: {center}")
```
この例では、K-Means は4つのクラスタを見つけるはずです。小規模な attack クラスタ（通常より duration が異常に長い約200）は、通常のクラスタから離れているため、理想的には独自のクラスタを形成します。結果を解釈するため、クラスタのサイズと中心を表示します。実際のシナリオでは、ポイント数の少ないクラスタを潜在的な異常としてラベル付けしたり、そのメンバーを調査して悪意のある活動がないか確認したりできます。
</details>

### 階層型クラスタリング

階層型クラスタリングは、ボトムアップ（凝集型）アプローチまたはトップダウン（分割型）アプローチを使用して、クラスタの階層を構築します。

1. **凝集型（ボトムアップ）**: 各データポイントを個別のクラスタとして開始し、単一のクラスタが残るまで、または停止条件を満たすまで、最も近いクラスタを反復的に結合します。
2. **分割型（トップダウン）**: すべてのデータポイントを1つのクラスタにまとめて開始し、各データポイントが独自のクラスタになるまで、または停止条件を満たすまで、クラスタを反復的に分割します。

凝集型クラスタリングでは、クラスタ間距離の定義と、どのクラスタを結合するかを決定するリンケージ基準が必要です。一般的なリンケージ手法には、single linkage（2つのクラスタ間で最も近いポイント同士の距離）、complete linkage（最も遠いポイント同士の距離）、average linkage などがあり、距離メトリックには Euclidean が使われることが多いです。リンケージの選択は、生成されるクラスタの形状に影響します。クラスタ数 K を事前に指定する必要はなく、選択したレベルでデンドログラムを「切る」ことで、目的のクラスタ数を得られます。

階層型クラスタリングは、異なる粒度レベルにおけるクラスタ間の関係を示す、木構造のようなデンドログラムを生成します。デンドログラムを任意のレベルで切ることで、特定のクラスタ数を取得できます。

> [!TIP]
> *サイバーセキュリティでの使用例:* 階層型クラスタリングは、イベントやエンティティをツリー構造に整理し、関係性を見つけるために利用できます。たとえば malware analysis では、凝集型クラスタリングによってサンプルを挙動の類似性ごとにグループ化し、malware のファミリーと variant の階層を明らかにできます。network security では、IP traffic flow をクラスタリングし、デンドログラムを使ってトラフィックのサブグループ（たとえば protocol、次に behavior ごと）を確認できます。K を事前に決める必要がないため、attack category の数が不明な新しいデータを調査する場合に有用です。

#### 前提と制限

階層型クラスタリングは特定のクラスタ形状を仮定せず、入れ子状のクラスタを捉えることができます。taxonomy やグループ間の関係（たとえば malware を family subgroup ごとにグループ化すること）の発見に役立ちます。また、決定論的であり、random initialization に関する問題がありません。主な利点は、あらゆるスケールでデータのクラスタ構造を把握できるデンドログラムです。security analyst は、意味のあるクラスタを特定するための適切な cutoff を決定できます。ただし、計算コストが高く（単純な実装では通常 $O(n^2)$ 時間、またはそれ以上）、非常に大規模なデータセットには適していません。また、greedy な手順であるため、一度 merge または split を実行すると元に戻せず、初期段階で誤りが発生した場合に最適でないクラスタになる可能性があります。outlier は一部の linkage strategy にも影響を与えることがあります（single-link では、outlier を介してクラスタ同士がつながる「chaining」効果が発生する可能性があります）。

<details>
<summary>Example -- Events の Agglomerative Clustering
</summary>

K-Means の例で使用した synthetic data（3つの normal cluster + 1つの attack cluster）を再利用し、agglomerative clustering を適用します。次に、デンドログラムとクラスタ label を取得する方法を示します。
```python
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import linkage, dendrogram

# Perform agglomerative clustering (bottom-up) on the data
agg = AgglomerativeClustering(n_clusters=None, distance_threshold=0, linkage='ward')
# distance_threshold=0 gives the full tree without cutting (we can cut manually)
agg.fit(X)

print(f"Number of merge steps: {agg.n_clusters_ - 1}")  # should equal number of points - 1
# Create a dendrogram using SciPy for visualization (optional)
Z = linkage(X, method='ward')
# Normally, you would plot the dendrogram. Here we'll just compute cluster labels for a chosen cut:
clusters_3 = AgglomerativeClustering(n_clusters=3, linkage='ward').fit_predict(X)
print(f"Labels with 3 clusters: {np.unique(clusters_3)}")
print(f"Cluster sizes for 3 clusters: {np.bincount(clusters_3)}")
```
</details>

### DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

DBSCANは、互いに近接して密集している点をグループ化し、低密度領域にある点を外れ値としてマークする、密度ベースのクラスタリングアルゴリズムです。密度が異なるデータセットや、球形ではない形状のデータセットに特に有用です。

DBSCANは、次の2つのパラメータを定義して動作します。
- **Epsilon (ε)**: 2つの点が同じクラスタの一部とみなされるための最大距離。
- **MinPts**: 高密度領域（core point）を形成するために必要な点の最小数。

DBSCANは、core point、border point、noise pointを特定します。
- **Core Point**: ε距離以内に少なくともMinPts個の近傍点を持つ点。
- **Border Point**: core pointからε距離以内にあるものの、MinPts個未満の近傍点しか持たない点。
- **Noise Point**: core pointでもborder pointでもない点。

クラスタリングは、未訪問のcore pointを選び、それを新しいクラスタとしてマークすることで進みます。その後、その点からdensity-reachableであるすべての点（core pointとその近傍点など）を再帰的に追加します。border pointは、近くにあるcore pointのクラスタに追加されます。到達可能なすべての点を展開した後、DBSCANは別の未訪問のcore pointに移動して、新しいクラスタを開始します。どのcore pointからも到達されなかった点は、noiseとしてラベル付けされたままになります。

> [!TIP]
> *サイバーセキュリティにおけるユースケース:* DBSCANは、ネットワークトラフィックの異常検知に有用です。たとえば、通常のユーザーアクティビティはfeature space内で1つ以上の密なクラスタを形成する一方、新しい攻撃挙動は散在する点として現れ、DBSCANによってnoise（外れ値）としてラベル付けされます。ネットワークフローレコードのクラスタリングにも使用されており、port scanやdenial-of-serviceトラフィックを、点が疎らに存在する領域として検出できます。別の用途として、malwareのvariantのグループ化があります。大半のsampleがfamilyごとにクラスタを形成する一方、どのクラスタにも適合しないものが少数ある場合、それらはzero-day malwareである可能性があります。noiseを検出できるため、security teamはそうした外れ値の調査に集中できます。

#### Assumptions and Limitations

**Assumptions & Strengths:**: DBSCANは球形のクラスタを仮定しないため、任意の形状のクラスタ（chain状や隣接したクラスタを含む）を検出できます。データの密度に基づいてクラスタ数を自動的に決定し、外れ値をnoiseとして効果的に特定できます。そのため、不規則な形状やnoiseを含む現実世界のデータに対して強力です。外れ値に対してrobustです（外れ値をクラスタに無理に割り当てるK-Meansとは異なります）。クラスタの密度が概ね均一である場合に良好に動作します。

**Limitations**: DBSCANの性能は、適切なεとMinPtsの値の選択に依存します。密度が異なるデータでは、1つのεで密なクラスタと疎なクラスタの両方に対応できないため、問題が生じる可能性があります。εが小さすぎると、ほとんどの点がnoiseとしてラベル付けされます。大きすぎると、クラスタが誤って統合される可能性があります。また、DBSCANは非常に大規模なデータセットでは非効率になることがあります（素朴な実装では$O(n^2)$ですが、spatial indexingによって改善できます）。高次元のfeature spaceでは、「ε以内の距離」という概念があまり意味を持たなくなる可能性があり（curse of dimensionality）、DBSCANには慎重なパラメータ調整が必要になるか、直感的なクラスタを検出できない場合があります。これらの問題がある一方で、HDBSCANのようなextensionは、密度の変動など一部の問題に対処します。

<details>
<summary>Example -- Clustering with Noise
</summary>
```python
from sklearn.cluster import DBSCAN

# Generate synthetic data: 2 normal clusters and 5 outlier points
cluster1 = rng.normal(loc=[100, 1000], scale=[5, 100], size=(100, 2))
cluster2 = rng.normal(loc=[120, 2000], scale=[5, 100], size=(100, 2))
outliers = rng.uniform(low=[50, 50], high=[180, 3000], size=(5, 2))  # scattered anomalies
data = np.vstack([cluster1, cluster2, outliers])

# Run DBSCAN with chosen eps and MinPts
eps = 15.0   # radius for neighborhood
min_pts = 5  # minimum neighbors to form a dense region
db = DBSCAN(eps=eps, min_samples=min_pts).fit(data)
labels = db.labels_  # cluster labels (-1 for noise)

# Analyze clusters and noise
num_clusters = len(set(labels) - {-1})
num_noise = np.sum(labels == -1)
print(f"DBSCAN found {num_clusters} clusters and {num_noise} noise points")
print("Cluster labels for first 10 points:", labels[:10])
```
このスニペットでは、データのスケールに合わせて `eps` と `min_samples` を調整しました（feature units で 15.0、cluster を形成するために 5 points を要求）。DBSCAN は 2 clusters（normal traffic clusters）を検出し、注入された 5 つの outliers を noise として flag するはずです。これを確認するため、clusters 数と noise points 数を出力します。実際の環境では、安定した clustering results を見つけるために、ε（k-distance graph heuristic を使用して ε を選択）と MinPts（rule of thumb として、data dimensionality + 1 前後に設定することが多い）を反復的に調整する場合があります。noise を明示的に label できるため、potential attack data を分離して further analysis に回せます。

</details>

### Principal Component Analysis (PCA)

PCA は **dimensionality reduction** の technique であり、データ内の variance を最大限に捉える、新しい orthogonal axes（principal components）の集合を見つけます。簡単に言うと、PCA はデータを新しい coordinate system に rotate および project します。その結果、first principal component (PC1) は可能な限り大きな variance を説明し、second PC (PC2) は PC1 に orthogonal な variance のうち最大のものを説明します。数学的には、PCA はデータの covariance matrix の eigenvectors を計算します。これらの eigenvectors は principal component directions であり、対応する eigenvalues は各 component によって説明される variance の量を示します。PCA は feature extraction、visualization、noise reduction によく使用されます。

dataset dimensions に **significant linear dependencies or correlations** が含まれている場合に有用である点に注意してください。

PCA は、データの principal components、つまり maximum variance の directions を特定することで機能します。PCA に含まれる steps は次のとおりです。
1. **Standardization**: mean を subtract してデータを center し、unit variance に scale します。
2. **Covariance Matrix**: standardized data の covariance matrix を計算し、features 間の relationships を把握します。
3. **Eigenvalue Decomposition**: covariance matrix に対して eigenvalue decomposition を実行し、eigenvalues と eigenvectors を取得します。
4. **Select Principal Components**: eigenvalues を descending order に sort し、最大の eigenvalues に対応する上位 K 個の eigenvectors を選択します。これらの eigenvectors が新しい feature space を形成します。
5. **Transform Data**: 選択した principal components を使用して、original data を新しい feature space に project します。
PCA は data visualization、noise reduction、および他の machine learning algorithms の preprocessing step として広く使用されています。データの essential structure を保持しながら、データの dimensionality を reduce するのに役立ちます。

#### Eigenvalues and Eigenvectors

eigenvalue は、対応する eigenvector によって capture される variance の量を示す scalar です。eigenvector は、データが最も大きく変化する feature space 内の direction を表します。

A が square matrix で、v が次の条件を満たす non-zero vector だとします: `A * v = λ * v`
ここで:
- A は [ [1, 2], [2, 1]] のような square matrix（例: covariance matrix）
- v は eigenvector（例: [1, 1]）

この場合、`A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` となります。これは eigenvalue λ に eigenvector v を掛けたものなので、eigenvalue λ = 3 となります。

#### Eigenvalues and Eigenvectors in PCA

例を使って説明します。100x100 pixels の顔の grey scale pictures が大量に含まれる dataset を考えてみてください。各 pixel は feature とみなせるため、image ごとに 10,000 features（または image ごとに 10000 components の vector）があります。PCA を使用してこの dataset の dimensionality を reduce する場合、次の steps に従います。

1. **Standardization**: 各 feature（pixel）の mean を dataset から subtract してデータを center します。
2. **Covariance Matrix**: standardized data の covariance matrix を計算します。これは features（pixels）がどのように一緒に変化するかを capture します。
- 2 つの variables（この場合は pixels）間の covariance は、それらがどの程度一緒に変化するかを示します。したがって、ここでの考え方は、どの pixels が linear relationship に従って一緒に increase または decrease する傾向があるかを見つけることです。
- 例えば、pixel 1 と pixel 2 が一緒に increase する傾向がある場合、それらの covariance は positive になります。
- covariance matrix は 10,000x10,000 の matrix で、各 entry は 2 つの pixels 間の covariance を表します。
3. **Solve the The eigenvalue equation**: 解く eigenvalue equation は `C * v = λ * v` です。ここで C は covariance matrix、v は eigenvector、λ は eigenvalue です。これは次のような methods を使用して解けます。
- **Eigenvalue Decomposition**: covariance matrix に対して eigenvalue decomposition を実行し、eigenvalues と eigenvectors を取得します。
- **Singular Value Decomposition (SVD)**: 代わりに SVD を使用して data matrix を singular values と vectors に decompose することもできます。これによって principal components も取得できます。
4. **Select Principal Components**: eigenvalues を descending order に sort し、最大の eigenvalues に対応する上位 K 個の eigenvectors を選択します。これらの eigenvectors はデータ内の maximum variance の directions を表します。

> [!TIP]
> *Use cases in cybersecurity:* security における PCA の一般的な use は、anomaly detection のための feature reduction です。例えば、40 個以上の network metrics（NSL-KDD features など）を持つ intrusion detection system は、PCA を使用してそれらを少数の components に reduce できます。これにより、visualization 用または clustering algorithms への input 用にデータを要約できます。Analysts は、first two principal components の space に network traffic を plot して、attacks が normal traffic から分離されるか確認できます。また PCA は、correlated である bytes sent と bytes received のような redundant features を eliminate し、detection algorithms をより robust かつ高速にするのにも役立ちます。

#### Assumptions and Limitations

PCA は **principal axes of variance are meaningful** であることを前提とします。これは linear method であるため、データ内の linear correlations を capture します。feature covariance のみを使用するため unsupervised です。PCA の advantages には noise reduction（small-variance components は noise に対応することが多い）と features の decorrelation があります。moderately high dimensions に対して computationally efficient であり、他の algorithms の preprocessing step として有用なことが多い手法です（curse of dimensionality を mitigate するため）。Limitation の 1 つは、PCA が linear relationships に限定されることです。そのため、complex nonlinear structure（autoencoders や t-SNE なら capture できる可能性があるもの）は capture できません。また、PCA components は original features の観点から解釈しにくい場合があります（original features の組み合わせであるため）。cybersecurity では注意が必要です。low-variance feature に subtle change しか引き起こさない attack は、top PCs に現れない可能性があります（PCA は “interestingness” ではなく variance を優先するため）。

<details>
<summary>Example -- Reducing Dimensions of Network Data
</summary>

network connection logs に複数の features（例: durations、bytes、counts）があるとします。ここでは、features 間に一部 correlation がある synthetic 4-dimensional dataset を生成し、visualization または further analysis のために PCA を使用して 2 dimensions に reduce します。
```python
from sklearn.decomposition import PCA

# Create synthetic 4D data (3 clusters similar to before, but add correlated features)
# Base features: duration, bytes (as before)
base_data = np.vstack([normal1, normal2, normal3])  # 1500 points from earlier normal clusters
# Add two more features correlated with existing ones, e.g. packets = bytes/50 + noise, errors = duration/10 + noise
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))
data_4d = np.column_stack([base_data[:, 0], base_data[:, 1], packets, errors])

# Apply PCA to reduce 4D data to 2D
pca = PCA(n_components=2)
data_2d = pca.fit_transform(data_4d)
print("Explained variance ratio of 2 components:", pca.explained_variance_ratio_)
print("Original shape:", data_4d.shape, "Reduced shape:", data_2d.shape)
# We can examine a few transformed points
print("First 5 data points in PCA space:\n", data_2d[:5])
```
ここでは、以前の通常トラフィックのクラスタを取り上げ、各データポイントに、bytesおよびdurationと相関する2つの追加feature（packetsとerrors）を追加しました。次にPCAを使用して、4つのfeatureを2つのprincipal componentに圧縮します。説明分散比を出力すると、例えば分散の95%以上が2つのcomponentによって捉えられていることが示される場合があります（つまり、情報損失がほとんどないということです）。出力には、データのshapeが(1500, 4)から(1500, 2)に縮小されたことも示されます。PCA空間における最初のいくつかのポイントが例として示されます。実際には、data_2dをplotして、クラスタが見分けやすいかを視覚的に確認できます。anomalyが存在する場合、PCA-spaceでメインクラスタから離れた位置にあるポイントとして確認できることがあります。このように、PCAは複雑なデータを、人間による解釈や他のalgorithmへの入力に適した扱いやすい形式へ整理するのに役立ちます。

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Modelは、データが**パラメータが未知の複数のGaussian（normal）distributionの混合から生成される**と仮定します。本質的には、これはprobabilistic clustering modelです。各ポイントをK個のGaussian componentのいずれかにsoftに割り当てようとします。各Gaussian component kには、mean vector（μ_k）、covariance matrix（Σ_k）、およびそのclusterがどの程度一般的かを表すmixing weight（π_k）があります。“hard”な割り当てを行うK-Meansとは異なり、GMMは各ポイントが各clusterに属する確率を返します。

GMMのfittingは通常、Expectation-Maximization（EM）algorithmによって行われます。

- **Initialization**: mean、covariance、mixing coefficientの初期値を設定します（または、K-Meansの結果をstarting pointとして使用します）。

- **E-step (Expectation)**: 現在のparameterに基づき、各ポイントに対する各clusterのresponsibilityを計算します。これは基本的に `r_nk = P(z_k | x_n)` です。ここでz_kは、ポイントx_nのcluster membershipを示すlatent variableです。これはBayes' theoremを使用して行われ、現在のparameterに基づいて、各ポイントが各clusterに属するposterior probabilityを計算します。responsibilityは次のように計算されます。
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
ここで、
- \( \pi_k \) はcluster kのmixing coefficient（cluster kのprior probability）です。
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) は、mean \( \mu_k \) およびcovariance \( \Sigma_k \) を指定した場合の、point \( x_n \) に対するGaussian probability density functionです。

- **M-step (Maximization)**: E-stepで計算したresponsibilityを使用してparameterを更新します。
- 各mean μ_kを、ポイントのweighted averageとして更新します。weightsにはresponsibilityを使用します。
- 各covariance Σ_kを、cluster kに割り当てられたポイントのweighted covarianceとして更新します。
- mixing coefficient π_kを、cluster kに対するaverage responsibilityとして更新します。

- **Iterate** E-stepとM-stepを、convergenceするまで繰り返します（parameterが安定する、またはlikelihoodの改善がthresholdを下回るまで）。

その結果、全体のデータ分布をまとめてmodel化するGaussian distributionの集合が得られます。fitted GMMを使用して、各ポイントを最も高いprobabilityを持つGaussianに割り当てることでclusteringできます。または、不確実性を考慮するためにprobabilityをそのまま保持することもできます。さらに、新しいポイントのlikelihoodを評価して、それらがmodelに適合するかを確認することもできます（anomaly detectionに有用です）。

> [!TIP]
> *Use cases in cybersecurity:* GMMは、normal dataのdistributionをmodel化することでanomaly detectionに利用できます。学習したmixtureにおけるprobabilityが非常に低いポイントは、anomalyとしてflagされます。例えば、legitimate network trafficのfeatureを使ってGMMをtrainできます。学習済みのどのclusterにも類似しないattack connectionは、低いlikelihoodを持つことになります。GMMは、clusterの形状が異なる可能性があるactivityのclusteringにも使用されます。例えば、behavior profileによってusersをgroupingする場合、各profileのfeatureはGaussian-likeでありながら、それぞれ固有のvariance structureを持つことがあります。別のscenarioとして、phishing detectionでは、legitimate emailのfeatureが1つのGaussian clusterを形成し、既知のphishingが別のclusterを形成し、新しいphishing campaignが、別のGaussianとして、または既存のmixtureに対して低いlikelihoodを持つポイントとして現れる可能性があります。

#### Assumptions and Limitations

GMMはcovarianceを取り入れたK-Meansのgeneralizationであるため、clusterは（球形だけでなく）ellipsoidalにもなります。covarianceがfullの場合、サイズや形状の異なるclusterを扱えます。clusterの境界が曖昧な場合、soft clusteringは利点になります。例えばcybersecurityでは、あるeventが複数のattack typeの特徴を持つことがあります。GMMはprobabilityによって、その不確実性を表現できます。またGMMは、データのprobabilistic density estimationも提供するため、すべてのmixture componentにおけるlikelihoodが低いoutlierの検出に役立ちます。

一方で、GMMではcomponent数Kを指定する必要があります（ただし、BIC/AICのようなcriteriaを使用して選択できます）。EMはconvergeが遅くなったり、local optimumに収束したりすることがあるため、initializationが重要です（通常はEMを複数回実行します）。データが実際にはGaussianのmixtureに従っていない場合、modelのfitが悪くなる可能性があります。また、1つのGaussianがoutlierだけを覆うように縮小するリスクもあります（ただし、regularizationやminimum covariance boundsによって軽減できます）。


<details>
<summary>Example --  Soft Clustering & Anomaly Scores
</summary>
```python
from sklearn.mixture import GaussianMixture

# Fit a GMM with 3 components to the normal traffic data
gmm = GaussianMixture(n_components=3, covariance_type='full', random_state=0)
gmm.fit(base_data)  # using the 1500 normal data points from PCA example

# Print the learned Gaussian parameters
print("GMM means:\n", gmm.means_)
print("GMM covariance matrices:\n", gmm.covariances_)

# Take a sample attack-like point and evaluate it
sample_attack = np.array([[200, 800]])  # an outlier similar to earlier attack cluster
probs = gmm.predict_proba(sample_attack)
log_likelihood = gmm.score_samples(sample_attack)
print("Cluster membership probabilities for sample attack:", probs)
print("Log-likelihood of sample attack under GMM:", log_likelihood)
```
このコードでは、正常な traffic に対して 3 つの Gaussian を持つ GMM を学習します（正当な traffic の profile が 3 つあることが分かっていると仮定します）。出力された means と covariances は、これらの clusters を表します（例えば、ある mean は [50,500] 付近で、1 つの cluster の中心に対応する可能性があります）。次に、疑わしい connection [duration=200, bytes=800] をテストします。predict_proba は、この point が 3 つの clusters それぞれに属する確率を返します。[200,800] は正常な clusters から大きく離れているため、これらの確率は非常に低いか、大きく偏ることが予想されます。全体の score_samples（log-likelihood）も出力されます。非常に低い値は、その point が model にうまく適合していないことを示し、anomaly として flag できます。実際には、log-likelihood（または max probability）に threshold を設定し、point の確率が十分に低く malicious と判断できるかどうかを決定できます。このように、GMM は anomaly detection のための原理に基づいた方法を提供すると同時に、不確実性を考慮した soft clusters も生成します。
</details>

### Isolation Forest

**Isolation Forest** は、points をランダムに isolation するという考えに基づく ensemble anomaly detection algorithm です。その原理は、anomalies は少数で異質なため、normal points よりも isolation しやすいというものです。Isolation Forest は、多数の binary isolation trees（random decision trees）を構築し、data をランダムに partition します。tree の各 node では、random feature が 1 つ選択され、その node 内の data におけるその feature の min と max の間から random split value が選ばれます。この split により、data は 2 つの branches に分割されます。tree は、各 point がそれぞれ自身の leaf に isolation されるか、tree の最大 height に到達するまで成長します。

Anomaly detection は、これらの random trees における各 point の path length（point を isolation するために必要な splits の数）を観察することで実行されます。直感的には、anomalies（outliers）は、sparse region に存在するため、dense cluster 内の normal point よりも random split によって分離されやすく、より早く isolation される傾向があります。Isolation Forest は、すべての trees における平均 path length から anomaly score を計算します。平均 path が短いほど、より anomalous です。Scores は通常 [0,1] に normalize され、1 は anomaly である可能性が非常に高いことを意味します。

> [!TIP]
> *cybersecurity における Use cases:* Isolation Forests は intrusion detection や fraud detection で広く利用されています。例えば、ほとんどが normal behavior で構成される network traffic logs を使って Isolation Forest を train すると、forest は通常と異なる traffic（聞いたことのない port を使用する IP や、異常な packet size pattern など）に対して短い paths を生成し、inspection のために flag します。labeled attacks が不要なため、未知の attack types の検出に適しています。また、user login data に対して deploy し、account takeovers を検出することもできます（異常な login times や locations はすぐに isolation されます）。ある use-case では、Isolation Forest が system metrics を監視し、metrics の組み合わせ（CPU、network、file changes）が過去の patterns と大きく異なる（isolation paths が短い）場合に alert を生成することで、enterprise を保護できます。

#### Assumptions and Limitations

**Advantages**: Isolation Forest は distribution に関する assumption を必要とせず、isolation を直接対象にします。高次元 data や大規模 datasets に対して効率的です（forest の構築は linear complexity $O(n\log n)$）。これは、各 tree が feature の subset と splits のみを使って points を isolation するためです。数値 features を適切に扱う傾向があり、$O(n^2)$ になる可能性がある distance-based methods より高速な場合があります。また、anomaly score が自動的に提供されるため、alerts 用の threshold を設定できます（または contamination parameter を使用して、想定される anomaly の割合に基づき cutoff を自動的に決定できます）。

**Limitations**: random nature により、run ごとに結果が多少変動する可能性があります（ただし、十分な数の trees を使用すれば、この影響は小さくなります）。data に irrelevant features が多い場合や、anomalies がどの feature においても明確に異なっていない場合、isolation が効果的でない可能性があります（random splits によって normal points が偶然 isolation される可能性があります。ただし、多数の trees による averaging でこの影響は軽減されます）。また、Isolation Forest は一般に、anomalies が少数派であることを前提とします（これは通常、cybersecurity scenarios では当てはまります）。

<details>
<summary>Example --  Network Logs における Outliers の検出
</summary>

先ほどの test dataset（normal points と一部の attack points を含む）を使用し、Isolation Forest を実行して attacks を分離できるか確認します。ここでは、data の約 15% が anomalous であると想定します（demonstration のため）。
```python
from sklearn.ensemble import IsolationForest

# Combine normal and attack test data from autoencoder example
X_test_if = test_data  # (120 x 2 array with 100 normal and 20 attack points)
# Train Isolation Forest (unsupervised) on the test set itself for demo (in practice train on known normal)
iso_forest = IsolationForest(n_estimators=100, contamination=0.15, random_state=0)
iso_forest.fit(X_test_if)
# Predict anomalies (-1 for anomaly, 1 for normal)
preds = iso_forest.predict(X_test_if)
anomaly_scores = iso_forest.decision_function(X_test_if)  # the higher, the more normal
print("Isolation Forest predicted labels (first 20):", preds[:20])
print("Number of anomalies detected:", np.sum(preds == -1))
print("Example anomaly scores (lower means more anomalous):", anomaly_scores[:5])
```
このコードでは、100本のtreeを持つ`IsolationForest`をインスタンス化し、`contamination=0.15`を設定しています（約15%がanomaliesであると想定する設定です。modelは、約15%のpointsがflagされるようにscore thresholdを設定します）。通常のpointsとattack pointsが混在する`X_test_if`にfitしています（注: 通常はtraining dataにfitしてから、新しいdataに対してpredictを使用しますが、ここでは結果を直接確認するため、説明目的で同じsetにfitとpredictを行っています）。

出力には、最初の20 pointsに対するpredicted labelsが表示されます（`-1`はanomalyを示します）。また、検出されたanomaliesの総数と、anomaly scoresの例も表示します。`contamination`が15%なので、120 pointsのうちおよそ18 pointsが`-1`になると予想されます。20個のattack samplesが本当に最も外れたpointsであれば、その多くがこれらの`-1` predictionsに含まれるはずです。anomaly score（Isolation Forestのdecision function）はnormal pointsでは高く、anomaliesでは低く（よりnegativeに）なります。分離の様子を確認するため、いくつかの値を表示します。実際には、scoreの順にdataをsortして上位のoutliersを確認し、人間による分析や追加のautomated scrutinyを行うこともできます。このようにIsolation Forestは、大規模なunlabeled security dataを効率的にふるいにかけ、最も不規則なinstancesを抽出して人間による分析や、さらなるautomated scrutinyに回す方法を提供します。
</details>


### t-SNE（t-Distributed Stochastic Neighbor Embedding）

**t-SNE**は、高次元dataを2次元または3次元でvisualizeするために特化して設計された、nonlinear dimensionality reduction techniqueです。data points間のsimilaritiesをjoint probability distributionsに変換し、低次元projectionでもlocal neighborhoodsの構造を維持しようとします。簡単に言えば、t-SNEは、元のspaceでsimilarなpointsが近くに配置され、dissimilarなpointsが高い確率で遠くに配置されるように、pointsを（たとえば）2D上に配置します。

algorithmには、主に次の3つのstageがあります。

1. **高次元spaceでpairwise affinitiesを計算:** 各pointのpairについて、t-SNEはそのpairがneighborsとして選ばれる確率を計算します（各pointを中心とするGaussian distributionを配置し、distancesを測定して行います。perplexity parameterは、考慮されるeffective number of neighborsに影響します）。
2. **低次元（例: 2D）spaceでpairwise affinitiesを計算:** 最初に、pointsを2D上にrandomに配置します。t-SNEは、このmap上のdistancesに対して同様のprobabilityを定義します（Gaussianよりもheavier tailsを持つStudent t-distribution kernelを使用し、遠くにあるpointsがより自由に配置されるようにします）。
3. **Gradient Descent:** 次にt-SNEは、high-D affinity distributionとlow-D affinity distribution間のKullback–Leibler（KL）divergenceを最小化するため、2D上のpointsを反復的に移動させます。これにより、2D上の配置がhigh-D structureを可能な限り反映します。元のspaceで近かったpointsは互いに引き寄せ合い、遠かったpointsは反発し合い、最終的にbalanceが見つかります。

結果として、data内のclustersが明確になる、視覚的に意味のあるscatter plotが得られることがよくあります。

> [!TIP]
> *cybersecurityにおけるuse cases:* t-SNEは、**human analysisのためにhigh-dimensional security dataをvisualizeする**目的でよく使用されます。たとえば、security operations centerのanalystsは、数十個のfeatures（port numbers、frequencies、byte countsなど）を含むevent datasetを取得し、t-SNEを使って2D plotを作成できます。このplotでは、attacksが独自のclustersを形成したり、normal dataから分離したりする可能性があり、識別しやすくなります。malware datasetsに適用してmalware familiesのgroupingsを確認したり、異なるattack typesが明確にcluster化されるnetwork intrusion dataに適用したりすることで、さらなるinvestigationの指針にできます。基本的にt-SNEは、通常であれば理解しにくいcyber data内のstructureを可視化する方法を提供します。

#### Assumptions and Limitations

t-SNEは、patternsをvisual discoveryするのに優れています。他のlinear methods（PCAなど）では見つけにくいclusters、subclusters、outliersを明らかにできます。malware behavior profilesやnetwork traffic patternsなどの複雑なdataをvisualizeするため、cybersecurity researchでも使用されています。local structureを維持するため、自然なgroupingsを示すのに適しています。

ただし、t-SNEはcomputationally heavier（およそ$O(n^2)$）であるため、非常に大規模なdatasetsではsamplingが必要になる場合があります。また、hyperparameters（perplexity、learning rate、iterations）があり、outputに影響を与える可能性があります。たとえば、異なるperplexity valuesによって、異なるscaleのclustersが明らかになることがあります。t-SNE plotsは誤解されることもあります。map上のdistancesはglobalには直接的な意味を持たず、local neighborhoodに重点を置いているため、clustersが実際よりも明確に分離されているように見える場合があります。また、t-SNEは主にvisualization用であり、再計算せずに新しいdata pointsをprojectionする簡単な方法を提供しません。さらに、predictive modelingのpreprocessingとして使用することを目的としていません（UMAPは、より高速な処理によってこれらの問題の一部に対応するalternativeです）。

<details>
<summary>Example -- Network ConnectionsのVisualizing
</summary>

t-SNEを使用して、multi-feature datasetを2Dにreduceします。説明のため、先ほどの4D data（normal trafficに3つのnatural clustersがあったもの）を使用し、いくつかのanomaly pointsを追加します。その後、t-SNEを実行し、結果を（conceptually）visualizeします。
```python
# 1 ─────────────────────────────────────────────────────────────────────
#    Create synthetic 4-D dataset
#      • Three clusters of “normal” traffic (duration, bytes)
#      • Two correlated features: packets & errors
#      • Five outlier points to simulate suspicious traffic
# ──────────────────────────────────────────────────────────────────────
import numpy as np
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler

rng = np.random.RandomState(42)

# Base (duration, bytes) clusters
normal1 = rng.normal(loc=[50, 500],  scale=[10, 100], size=(500, 2))
normal2 = rng.normal(loc=[60, 1500], scale=[8,  200], size=(500, 2))
normal3 = rng.normal(loc=[70, 3000], scale=[5,  300], size=(500, 2))

base_data = np.vstack([normal1, normal2, normal3])       # (1500, 2)

# Correlated features
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors  = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))

data_4d = np.column_stack([base_data, packets, errors])  # (1500, 4)

# Outlier / attack points
outliers_4d = np.column_stack([
rng.normal(250, 1, size=5),     # extreme duration
rng.normal(1000, 1, size=5),    # moderate bytes
rng.normal(5, 1, size=5),       # very low packets
rng.normal(25, 1, size=5)       # high errors
])

data_viz = np.vstack([data_4d, outliers_4d])             # (1505, 4)

# 2 ─────────────────────────────────────────────────────────────────────
#    Standardize features (recommended for t-SNE)
# ──────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
data_scaled = scaler.fit_transform(data_viz)

# 3 ─────────────────────────────────────────────────────────────────────
#    Run t-SNE to project 4-D → 2-D
# ──────────────────────────────────────────────────────────────────────
tsne = TSNE(
n_components=2,
perplexity=30,
learning_rate='auto',
init='pca',
random_state=0
)
data_2d = tsne.fit_transform(data_scaled)
print("t-SNE output shape:", data_2d.shape)  # (1505, 2)

# 4 ─────────────────────────────────────────────────────────────────────
#    Visualize: normal traffic vs. outliers
# ──────────────────────────────────────────────────────────────────────
plt.figure(figsize=(8, 6))
plt.scatter(
data_2d[:-5, 0], data_2d[:-5, 1],
label="Normal traffic",
alpha=0.6,
s=10
)
plt.scatter(
data_2d[-5:, 0], data_2d[-5:, 1],
label="Outliers / attacks",
alpha=0.9,
s=40,
marker="X",
edgecolor='k'
)

plt.title("t-SNE Projection of Synthetic Network Traffic")
plt.xlabel("t-SNE component 1")
plt.ylabel("t-SNE component 2")
plt.legend()
plt.tight_layout()
plt.show()
```
ここでは、以前の4D normal datasetに、いくつかの極端な外れ値を追加しました（外れ値では、異常なパターンをシミュレートするため、1つのfeature（「duration」）を非常に高く設定するなどしています）。典型的なperplexity 30でt-SNEを実行します。出力データ`data_2d`のshapeは(1505, 2)です。ここでは実際にplotはしませんが、plotした場合、3つのnormal clusterに対応する、おそらく3つの密集したclusterと、それらのclusterから遠く離れた孤立点として現れる5つの外れ値が確認できるでしょう。インタラクティブなworkflowでは、pointをlabel（normalまたはどのclusterに属するか、あるいはanomaly）でcolor分けし、この構造を検証できます。labelがなくても、analystは2D plot上の何もない空間に存在する5つのpointに気付き、flagを立てられる可能性があります。これは、t-SNEがcybersecurity dataにおけるvisual anomaly detectionとcluster inspectionを強力に支援し、上述のautomated algorithmを補完できることを示しています。

</details>


### HDBSCAN（ノイズを含む階層的密度ベース空間クラスタリング）

**HDBSCAN**はDBSCANを拡張したもので、単一のglobalな`eps`値を選択する必要をなくし、density-connected componentのhierarchyを構築してからcondenseすることで、**異なるdensity**のclusterを検出できます。通常のDBSCANと比較すると、通常は次のような特徴があります。

* 一部のclusterがdenseで、その他がsparseな場合でも、より直感的なclusterを抽出する
* 実質的なhyper-parameterは1つ（`min_cluster_size`）だけで、妥当なdefault値がある
* すべてのpointにcluster-membershipの*probability*と**outlier score**（`outlier_scores_`）を付与するため、threat-hunting dashboardに非常に便利である<sup>[[1]](#references)</sup>

> [!TIP]
> *cybersecurityでのユースケース:* HDBSCANはmodernなthreat-hunting pipelineで非常に広く利用されています。commercialなXDR suiteに同梱されたnotebook-based hunting playbookの中で見かけることも多いでしょう。実用的なrecipeの1つは、IR中にHTTP beaconing trafficをcluster化することです。user-agent、interval、URI lengthは、正規のsoftware updaterに対応する複数の密集したgroupを形成する一方、C2 beaconは小規模なlow-density cluster、または純粋なnoiseとして残ることがよくあります。

<details>
<summary>Example – beaconing C2 channelの検出</summary>
```python
import pandas as pd
from hdbscan import HDBSCAN
from sklearn.preprocessing import StandardScaler

# df has features extracted from proxy logs
features = [
"avg_interval",      # seconds between requests
"uri_length_mean",   # average URI length
"user_agent_entropy" # Shannon entropy of UA string
]
X = StandardScaler().fit_transform(df[features])

hdb = HDBSCAN(min_cluster_size=15,  # at least 15 similar beacons to be a group
metric="euclidean",
prediction_data=True)
labels = hdb.fit_predict(X)

df["cluster"] = labels
# Anything with label == -1 is noise → inspect as potential C2
suspects = df[df["cluster"] == -1]
print("Suspect beacon count:", len(suspects))
```
</details>

---

### Robustness and Security Considerations – Poisoning & Adversarial Attacks (2023-2025)

近年の研究により、**unsupervised learner は *active attacker* に対して無防備ではない**ことが明らかになっています。

* **anomaly detector に対する Data-poisoning。** Chen *et al.*（IEEE S&P 2024）は、わずか 3 % の細工した traffic を追加するだけで Isolation Forest と ECOD の decision boundary を移動させ、実際の攻撃を正常に見せられることを実証しました。著者らは、poison point を自動的に合成する open-source PoC（`udo-poison`）を公開しています。<sup>[[2]](#references)</sup>
* **clustering model の Backdooring。** *BadCME* technique（BlackHat EU 2023）は、小さな trigger pattern を埋め込みます。その trigger が現れると、K-Means-based detector はイベントを密かに「benign」cluster 内に配置します。
* **DBSCAN/HDBSCAN の Evasion。** KU Leuven による 2025 年の academic pre-print では、攻撃者が意図的に density gap に入る beaconing pattern を作成し、実質的に *noise* label の中に隠れられることが示されました。

次の Mitigation が注目を集めています。

1. **Model sanitisation / TRIM。** 各 retraining epoch の前に、loss が最も大きい 1–2 % の point を破棄します（trimmed maximum likelihood）。これにより poisoning を大幅に困難にします。
2. **Consensus ensembling。** 複数の heterogeneous detector（例：Isolation Forest + GMM + ECOD）を組み合わせ、いずれかの model が point を flag した場合に alert を発生させます。研究によれば、これにより攻撃者のコストは 10 倍以上に増加します。
3. **clustering 向けの Distance-based defence。** `k` 個の異なる random seed で cluster を再計算し、常に cluster 間を移動する point を無視します。

---

### Modern Open-Source Tooling (2024-2025)

* **PyOD 2.x**（2024 年 5 月リリース）では、*ECOD*、*COPOD*、GPU-accelerated *AutoFormer* detector が追加されました。現在は `benchmark` sub-command が付属しており、次の **one line of code** で dataset 上の 30 種類以上の algorithm を比較できます。
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5**（2025 年 2 月）は vision に重点を置いていますが、generic **PatchCore** implementation も含まれており、screenshot-based phishing page detection に便利です。
* **scikit-learn 1.5**（2024 年 11 月）では、新しい `cluster.HDBSCAN` wrapper を通じて、ついに *HDBSCAN* の `score_samples` が公開されました。そのため、Python 3.12 を使用する場合に外部の contrib package は不要です。

<details>
<summary>Quick PyOD example – ECOD + Isolation Forest ensemble</summary>
```python
from pyod.models import ECOD, IForest
from pyod.utils.data import generate_data, evaluate_print
from pyod.utils.example import visualize

X_train, y_train, X_test, y_test = generate_data(
n_train=5000, n_test=1000, n_features=16,
contamination=0.02, random_state=42)

models = [ECOD(), IForest()]

# majority vote – flag if any model thinks it is anomalous
anomaly_scores = sum(m.fit(X_train).decision_function(X_test) for m in models) / len(models)

evaluate_print("Ensemble", y_test, anomaly_scores)
```
</details>

## 参考文献

- [1] [HDBSCAN - 階層的密度ベースクラスタリング](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* 「教師なし異常検知のデータポイズニングに対する脆弱性について」 *IEEE Symposium on Security and Privacy*, 2024。



{{#include ../banners/hacktricks-training.md}}
