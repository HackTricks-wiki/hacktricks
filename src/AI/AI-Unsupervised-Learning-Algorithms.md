# 비지도 학습 알고리즘

{{#include ../banners/hacktricks-training.md}}

## 비지도 학습

비지도 학습은 레이블이 지정된 응답 없이 데이터로 모델을 학습시키는 machine learning의 한 유형입니다. 목표는 데이터 내의 패턴, 구조 또는 관계를 찾는 것입니다. 모델이 레이블이 지정된 예제에서 학습하는 supervised learning과 달리, unsupervised learning 알고리즘은 레이블이 지정되지 않은 데이터로 작업합니다.
비지도 학습은 clustering, dimensionality reduction, anomaly detection과 같은 작업에 자주 사용됩니다. 데이터에 숨겨진 패턴을 발견하고, 유사한 항목을 함께 그룹화하거나, 핵심 특징을 유지하면서 데이터의 복잡성을 줄이는 데 도움이 될 수 있습니다.


### K-Means Clustering

K-Means는 각 포인트를 가장 가까운 cluster mean에 할당하여 데이터를 K개의 cluster로 나누는 centroid 기반 clustering 알고리즘입니다. 알고리즘은 다음과 같이 작동합니다:
1. **초기화**: K개의 초기 cluster center(centroid)를 선택합니다. 일반적으로 무작위로 선택하거나 k-means++와 같은 더 효율적인 방법을 사용합니다.
2. **할당**: distance metric(예: Euclidean distance)을 기준으로 각 data point를 가장 가까운 centroid에 할당합니다.
3. **업데이트**: 각 cluster에 할당된 모든 data point의 평균을 계산하여 centroid를 다시 계산합니다.
4. **반복**: cluster 할당이 안정화될 때까지(centroid가 더 이상 크게 이동하지 않을 때까지) 2~3단계를 반복합니다.

> [!TIP]
> *사이버 보안에서의 사용 사례:* K-Means는 network event를 clustering하여 intrusion detection에 사용됩니다. 예를 들어, 연구자들은 KDD Cup 99 intrusion dataset에 K-Means를 적용했고, traffic을 normal cluster와 attack cluster로 효과적으로 나눌 수 있음을 확인했습니다. 실제로 security analyst는 log entry 또는 user behavior data를 clustering하여 유사한 activity 그룹을 찾을 수 있습니다. 잘 형성된 cluster에 속하지 않는 포인트는 anomaly를 나타낼 수 있습니다(예: 새로운 malware variant가 자체적으로 작은 cluster를 형성하는 경우). 또한 K-Means는 behavior profile 또는 feature vector를 기반으로 binary를 그룹화하여 malware family classification을 수행하는 데 도움이 될 수 있습니다.

#### K 선택
cluster의 수(K)는 알고리즘을 실행하기 전에 정의해야 하는 hyperparameter입니다. Elbow Method 또는 Silhouette Score와 같은 기법은 clustering performance를 평가하여 적절한 K 값을 결정하는 데 도움이 될 수 있습니다:

- **Elbow Method**: 각 포인트에서 할당된 cluster centroid까지의 squared distance 합계를 K의 함수로 plot합니다. 감소율이 급격히 변하는 "elbow" 지점을 찾으면 적절한 cluster 수를 나타냅니다.
- **Silhouette Score**: 다양한 K 값에 대해 silhouette score를 계산합니다. silhouette score가 높을수록 더 명확하게 정의된 cluster임을 의미합니다.

#### 가정 및 제한 사항

K-Means는 **cluster가 구형이고 크기가 동일하다**고 가정하지만, 이는 모든 dataset에 적용되지 않을 수 있습니다. centroid의 초기 배치에 민감하며 local minima로 수렴할 수 있습니다. 또한 K-Means는 density가 다양하거나 shape이 non-globular인 dataset 및 scale이 서로 다른 feature에는 적합하지 않습니다. 모든 feature가 distance 계산에 동일하게 기여하도록 normalization 또는 standardization과 같은 preprocessing 단계가 필요할 수 있습니다.

<details>
<summary>예시 -- Network Event Clustering
</summary>
아래에서는 network traffic data를 시뮬레이션하고 K-Means를 사용하여 이를 clustering합니다. connection duration 및 byte count와 같은 feature를 포함한 event가 있다고 가정해 보겠습니다. “normal” traffic cluster 3개와 attack pattern을 나타내는 작은 cluster 1개를 생성합니다. 그런 다음 K-Means를 실행하여 이들이 분리되는지 확인합니다.
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
이 예제에서 K-Means는 4개의 클러스터를 찾아야 합니다. 비정상적으로 긴 duration(~200)을 가진 작은 attack 클러스터는 정상 클러스터들과의 거리가 멀기 때문에 이상적으로 자체 클러스터를 형성합니다. 결과를 해석하기 위해 클러스터 크기와 중심을 출력합니다. 실제 시나리오에서는 포인트가 적은 클러스터를 잠재적인 이상으로 분류하거나 해당 멤버를 검사하여 악의적인 활동이 있는지 확인할 수 있습니다.
</details>

### Hierarchical Clustering

Hierarchical clustering은 bottom-up(agglomerative) 또는 top-down(divisive) 접근 방식을 사용하여 클러스터의 계층 구조를 구축합니다:

1. **Agglomerative (Bottom-Up)**: 각 데이터 포인트를 별도의 클러스터로 시작한 다음, 하나의 클러스터만 남거나 중지 기준을 충족할 때까지 가장 가까운 클러스터를 반복적으로 병합합니다.
2. **Divisive (Top-Down)**: 모든 데이터 포인트를 하나의 클러스터로 시작한 다음, 각 데이터 포인트가 자체 클러스터가 되거나 중지 기준을 충족할 때까지 클러스터를 반복적으로 분할합니다.

Agglomerative clustering에서는 클러스터 간 거리를 정의하고 어떤 클러스터를 병합할지 결정하기 위한 linkage criterion이 필요합니다. 일반적인 linkage 방법에는 single linkage(두 클러스터에서 가장 가까운 포인트 간의 거리), complete linkage(가장 먼 포인트 간의 거리), average linkage 등이 있으며, distance metric으로는 Euclidean이 자주 사용됩니다. Linkage의 선택은 생성되는 클러스터의 형태에 영향을 줍니다. 클러스터 수 K를 미리 지정할 필요가 없으며, 원하는 수의 클러스터를 얻기 위해 선택한 수준에서 dendrogram을 “자를” 수 있습니다.

Hierarchical clustering은 서로 다른 세분화 수준에서 클러스터 간 관계를 보여 주는 트리 형태의 구조인 dendrogram을 생성합니다. 원하는 수준에서 dendrogram을 잘라 특정 수의 클러스터를 얻을 수 있습니다.

> [!TIP]
> *사이버보안에서의 사용 사례:* Hierarchical clustering은 이벤트 또는 엔터티를 트리로 구성하여 관계를 파악하는 데 사용할 수 있습니다. 예를 들어 malware analysis에서 agglomerative clustering은 행동 유사성에 따라 샘플을 그룹화하여 malware family 및 variant의 계층 구조를 드러낼 수 있습니다. network security에서는 IP traffic flow를 클러스터링하고 dendrogram을 사용하여 traffic의 하위 그룹(예: protocol별, 이후 behavior별)을 확인할 수 있습니다. K를 미리 선택할 필요가 없으므로 attack category의 수를 알 수 없는 새로운 데이터를 탐색할 때 유용합니다.

#### Assumptions and Limitations

Hierarchical clustering은 특정 클러스터 형태를 가정하지 않으며 nested cluster를 포착할 수 있습니다. taxonomy 또는 그룹 간 관계(예: family subgroup별 malware 그룹화)를 발견하는 데 유용합니다. 또한 deterministic하므로 random initialization 문제가 없습니다. 주요 장점은 모든 규모에서 데이터의 clustering structure를 파악할 수 있는 dendrogram입니다. 이를 통해 security analyst는 의미 있는 클러스터를 식별하기 위한 적절한 cutoff를 결정할 수 있습니다. 그러나 computational cost가 높아(일반적인 naive implementation에서는 일반적으로 $O(n^2)$ 시간 또는 그 이상) 매우 큰 dataset에는 적합하지 않습니다. 또한 greedy procedure이므로 한 번 merge 또는 split이 수행되면 이를 되돌릴 수 없습니다. 따라서 초기에 실수가 발생하면 suboptimal cluster가 생성될 수 있습니다. Outlier는 일부 linkage strategy에도 영향을 줄 수 있습니다(single-link에서는 outlier를 통해 클러스터가 연결되는 “chaining” effect가 발생할 수 있음).

<details>
<summary>Example -- Agglomerative Clustering of Events
</summary>

K-Means 예제의 synthetic data(3개의 normal cluster + 1개의 attack cluster)를 재사용하여 agglomerative clustering을 적용합니다. 그런 다음 dendrogram과 cluster label을 얻는 방법을 설명합니다.
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

DBSCAN은 서로 가까이 밀집된 포인트들을 함께 그룹화하고, 밀도가 낮은 영역의 포인트들을 outlier로 표시하는 density-based clustering algorithm입니다. 다양한 밀도와 비구형 형태를 가진 데이터셋에 특히 유용합니다.

DBSCAN은 다음 두 가지 파라미터를 정의하여 작동합니다:
- **Epsilon (ε)**: 두 포인트가 동일한 cluster의 일부로 간주되기 위한 최대 거리입니다.
- **MinPts**: 밀집 영역(core point)을 형성하는 데 필요한 최소 포인트 수입니다.

DBSCAN은 core point, border point, noise point를 식별합니다:
- **Core Point**: ε 거리 이내에 최소 MinPts개의 neighbor를 가진 포인트입니다.
- **Border Point**: core point에서 ε 거리 이내에 있지만 MinPts개 미만의 neighbor를 가진 포인트입니다.
- **Noise Point**: core point도 border point도 아닌 포인트입니다.

Clustering은 방문하지 않은 core point를 선택하고 이를 새로운 cluster로 표시한 다음, 해당 포인트에서 density-reachable한 모든 포인트(core point와 그 neighbor 등)를 재귀적으로 추가하는 방식으로 진행됩니다. Border point는 근처 core point의 cluster에 추가됩니다. 도달 가능한 모든 포인트의 확장이 완료되면 DBSCAN은 방문하지 않은 다른 core point로 이동하여 새로운 cluster를 시작합니다. 어떤 core point에서도 도달하지 못한 포인트는 noise로 표시된 상태로 남습니다.

> [!TIP]
> *사이버보안에서의 사용 사례:* DBSCAN은 network traffic의 anomaly detection에 유용합니다. 예를 들어 정상적인 user activity는 feature space에서 하나 이상의 밀집 cluster를 형성할 수 있지만, 새로운 attack behavior는 흩어진 포인트로 나타나며 DBSCAN은 이를 noise(outlier)로 표시합니다. DBSCAN은 network flow record를 clustering하는 데 사용되어 왔으며, 희소한 포인트 영역으로 나타나는 port scan이나 denial-of-service traffic을 탐지할 수 있습니다. 또 다른 활용 사례는 malware variant를 그룹화하는 것입니다. 대부분의 sample이 family별로 cluster를 형성하지만 일부가 어느 cluster에도 속하지 않는다면, 해당 sample은 zero-day malware일 가능성이 있습니다. noise를 표시하는 기능을 통해 security team은 이러한 outlier를 조사하는 데 집중할 수 있습니다.

#### Assumptions and Limitations

**Assumptions & Strengths:**: DBSCAN은 구형 cluster를 가정하지 않으므로 chain 형태나 인접한 cluster를 포함한 임의의 형태의 cluster를 찾을 수 있습니다. 데이터 밀도에 따라 cluster 수를 자동으로 결정하며 outlier를 noise로 효과적으로 식별할 수 있습니다. 따라서 불규칙한 형태와 noise가 있는 real-world data에 강력합니다. 또한 outlier에 대해 robust합니다. (outlier를 cluster에 강제로 포함하는 K-Means와 달리) Cluster의 밀도가 대략적으로 균일할 때 잘 작동합니다.

**Limitations**: DBSCAN의 성능은 적절한 ε 및 MinPts 값을 선택하는 데 달려 있습니다. 밀도가 서로 다른 data에서는 하나의 ε 값으로 밀집 cluster와 희소 cluster를 모두 처리할 수 없기 때문에 문제가 발생할 수 있습니다. ε가 너무 작으면 대부분의 포인트가 noise로 표시되고, 너무 크면 cluster가 잘못 병합될 수 있습니다. 또한 DBSCAN은 매우 큰 dataset에서 비효율적일 수 있습니다(naive한 경우 $O(n^2)$이지만 spatial indexing으로 개선할 수 있음). 고차원 feature space에서는 “ε 이내의 거리”라는 개념의 의미가 약해질 수 있으며(the curse of dimensionality), DBSCAN에는 신중한 parameter tuning이 필요하거나 직관적인 cluster를 찾지 못할 수 있습니다. 이러한 문제에도 불구하고 HDBSCAN과 같은 extension은 다양한 밀도와 같은 일부 문제를 해결합니다.

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
이 snippet에서는 데이터 규모에 맞게 `eps`와 `min_samples`를 조정했습니다(특징 단위로 15.0, 클러스터를 형성하려면 5개의 포인트 필요). DBSCAN은 2개의 클러스터(정상 트래픽 클러스터)를 찾고, 주입된 5개의 outlier를 noise로 표시해야 합니다. 이를 검증하기 위해 클러스터 수와 noise 포인트 수를 출력합니다. 실제 환경에서는 안정적인 clustering 결과를 찾기 위해 ε(k-distance graph heuristic을 사용해 ε를 선택)와 MinPts(일반적으로 경험 법칙에 따라 데이터 차원 수 + 1 정도로 설정)를 반복적으로 조정할 수 있습니다. noise를 명시적으로 label할 수 있으므로 잠재적인 attack 데이터를 분리해 추가로 분석하는 데 도움이 됩니다.

</details>

### Principal Component Analysis (PCA)

PCA는 데이터에서 최대 variance를 포착하는 새로운 orthogonal axis 집합(principal component)을 찾아내는 **dimensionality reduction** 기법입니다. 간단히 말하면 PCA는 데이터를 새로운 coordinate system으로 회전하고 projection하여, 첫 번째 principal component(PC1)가 가능한 가장 큰 variance를 설명하고, 두 번째 PC(PC2)가 PC1에 orthogonal한 방향에서 가장 큰 variance를 설명하도록 합니다. 수학적으로 PCA는 데이터의 covariance matrix에 대한 eigenvector를 계산합니다. 이 eigenvector는 principal component의 방향이며, 해당 eigenvalue는 각 component가 설명하는 variance의 양을 나타냅니다. PCA는 feature extraction, visualization, noise reduction에 자주 사용됩니다.

dataset의 차원에 **유의미한 linear dependency 또는 correlation**이 포함되어 있는 경우 유용하다는 점에 유의해야 합니다.

PCA는 데이터의 principal component, 즉 maximum variance 방향을 식별하는 방식으로 동작합니다. PCA에 포함되는 단계는 다음과 같습니다.
1. **Standardization**: 평균을 빼고 unit variance가 되도록 scaling하여 데이터를 center합니다.
2. **Covariance Matrix**: standardized data의 covariance matrix를 계산하여 feature 간 관계를 파악합니다.
3. **Eigenvalue Decomposition**: covariance matrix에 대해 eigenvalue decomposition을 수행하여 eigenvalue와 eigenvector를 얻습니다.
4. **Select Principal Components**: eigenvalue를 내림차순으로 정렬하고, 가장 큰 eigenvalue에 해당하는 상위 K개의 eigenvector를 선택합니다. 이 eigenvector가 새로운 feature space를 구성합니다.
5. **Transform Data**: 선택한 principal component를 사용하여 원본 데이터를 새로운 feature space에 projection합니다.
PCA는 data visualization, noise reduction 및 다른 machine learning algorithm의 preprocessing 단계로 널리 사용됩니다. 데이터의 핵심 구조를 유지하면서 dimensionality를 줄이는 데 도움이 됩니다.

#### Eigenvalues and Eigenvectors

eigenvalue는 해당 eigenvector가 포착하는 variance의 양을 나타내는 scalar입니다. eigenvector는 데이터가 가장 크게 변하는 feature space상의 방향을 나타냅니다.

A가 square matrix이고 v가 다음 조건을 만족하는 0이 아닌 vector라고 가정해 보겠습니다: `A * v = λ * v`
where:
- A는 [ [1, 2], [2, 1]]과 같은 square matrix입니다(예: covariance matrix).
- v는 eigenvector입니다(예: [1, 1]).

그러면 `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`이며, 이는 eigenvalue λ에 eigenvector v를 곱한 값입니다. 따라서 eigenvalue λ = 3입니다.

#### Eigenvalues and Eigenvectors in PCA

예제를 통해 설명해 보겠습니다. 100x100 pixel로 구성된 많은 grayscale 얼굴 사진 dataset이 있다고 가정해 보겠습니다. 각 pixel은 하나의 feature로 간주할 수 있으므로, image당 10,000개의 feature(또는 image당 10000개 component로 구성된 vector)를 갖게 됩니다. PCA를 사용해 이 dataset의 dimensionality를 줄이려면 다음 단계를 따릅니다.

1. **Standardization**: dataset에서 각 feature(pixel)의 평균을 빼 데이터를 center합니다.
2. **Covariance Matrix**: standardized data의 covariance matrix를 계산하여 feature(pixel)가 함께 어떻게 변하는지 포착합니다.
- 두 변수(이 경우 pixel) 간 covariance는 두 변수가 함께 얼마나 변하는지를 나타냅니다. 따라서 여기서는 어떤 pixel이 linear relationship에 따라 함께 증가하거나 감소하는 경향이 있는지 파악하는 것이 목적입니다.
- 예를 들어 pixel 1과 pixel 2가 함께 증가하는 경향이 있다면 두 pixel 간 covariance는 positive가 됩니다.
- covariance matrix는 10,000x10,000 matrix이며, 각 entry는 두 pixel 간 covariance를 나타냅니다.
3. **Solve the The eigenvalue equation**: 풀어야 할 eigenvalue equation은 `C * v = λ * v`이며, 여기서 C는 covariance matrix, v는 eigenvector, λ는 eigenvalue입니다. 다음과 같은 방법으로 풀 수 있습니다.
- **Eigenvalue Decomposition**: covariance matrix에 대해 eigenvalue decomposition을 수행하여 eigenvalue와 eigenvector를 얻습니다.
- **Singular Value Decomposition (SVD)**: 또는 SVD를 사용해 data matrix를 singular value와 vector로 decompose할 수 있으며, 이를 통해 principal component도 얻을 수 있습니다.
4. **Select Principal Components**: eigenvalue를 내림차순으로 정렬하고, 가장 큰 eigenvalue에 해당하는 상위 K개의 eigenvector를 선택합니다. 이 eigenvector는 데이터에서 maximum variance가 발생하는 방향을 나타냅니다.

> [!TIP]
> *Use cases in cybersecurity:* security에서 PCA의 일반적인 사용 사례는 anomaly detection을 위한 feature reduction입니다. 예를 들어 40개가 넘는 network metric(NSL-KDD feature 등)을 사용하는 intrusion detection system은 PCA를 사용해 이를 소수의 component로 줄이고, visualization을 위해 데이터를 요약하거나 clustering algorithm에 입력할 수 있습니다. Analyst는 첫 두 principal component의 space에 network traffic을 plot하여 attack이 normal traffic과 분리되는지 확인할 수 있습니다. PCA는 redundant feature(상관관계가 있는 경우 bytes sent와 bytes received 등)를 제거하여 detection algorithm을 더욱 robust하고 빠르게 만드는 데도 도움이 됩니다.

#### Assumptions and Limitations

PCA는 **principal axis의 variance가 의미가 있다**고 가정합니다. PCA는 linear method이므로 데이터의 linear correlation을 포착합니다. feature covariance만 사용하므로 unsupervised입니다. PCA의 장점에는 noise reduction(variance가 작은 component가 noise에 해당하는 경우가 많음)과 feature decorrelation이 포함됩니다. PCA는 중간 정도로 높은 차원에서 computationally efficient하며, 다른 algorithm의 preprocessing 단계로 자주 사용됩니다(curse of dimensionality 완화). 한 가지 limitation은 PCA가 linear relationship에 한정된다는 점입니다. 따라서 복잡한 nonlinear structure는 포착하지 못합니다(autoencoder나 t-SNE와는 다름). 또한 PCA component는 original feature 관점에서 해석하기 어려울 수 있습니다(original feature의 조합이기 때문입니다). cybersecurity에서는 주의가 필요합니다. low-variance feature에만 미묘한 변화를 일으키는 attack은 top PC에 나타나지 않을 수 있습니다(PCA는 variance를 우선시하며, 반드시 “interestingness”를 우선시하는 것은 아니기 때문입니다).

<details>
<summary>Example -- Reducing Dimensions of Network Data
</summary>

여러 feature(예: duration, bytes, count)를 포함한 network connection log가 있다고 가정해 보겠습니다. 일부 feature 간 correlation이 있는 synthetic 4-dimensional dataset을 생성하고, 이를 visualization 또는 추가 분석을 위해 PCA를 사용해 2 dimensions로 줄입니다.
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
여기서는 앞서 사용한 정상 traffic clusters를 가져와 각 data point에 bytes 및 duration과 상관관계가 있는 두 가지 추가 feature(packets 및 errors)를 더했습니다. 그런 다음 PCA를 사용해 4개의 feature를 2개의 principal component로 압축합니다. 설명된 variance ratio를 출력하면, 예를 들어 2개의 component가 variance의 >95%를 포착한다는 결과가 나올 수 있습니다(즉, 정보 손실이 거의 없음을 의미). 또한 출력에는 data shape가 `(1500, 4)`에서 `(1500, 2)`로 줄어든 결과가 표시됩니다. PCA space에서 처음 몇 개의 point도 예시로 제공됩니다. 실제로는 `data_2d`를 plot하여 clusters가 구분 가능한지 시각적으로 확인할 수 있습니다. anomaly가 존재한다면 PCA-space에서 main cluster에서 멀리 떨어진 point로 나타날 수 있습니다. 따라서 PCA는 복잡한 data를 사람이 해석하거나 다른 algorithm에 입력할 수 있는 관리 가능한 형태로 추출하는 데 도움이 됩니다.

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Model은 data가 **알 수 없는 parameter를 가진 여러 Gaussian(normal) distribution의 mixture**에서 생성된다고 가정합니다. 본질적으로 이는 probabilistic clustering model입니다. 각 point를 K개의 Gaussian component 중 하나에 soft하게 할당하려고 합니다. 각 Gaussian component k에는 mean vector(μ_k), covariance matrix(Σ_k), 그리고 해당 cluster가 얼마나 많이 나타나는지를 나타내는 mixing weight(π_k)가 있습니다. “hard” assignment를 수행하는 K-Means와 달리, GMM은 각 point가 각 cluster에 속할 probability를 제공합니다.

GMM fitting은 일반적으로 Expectation-Maximization(EM) algorithm을 통해 수행됩니다.

- **Initialization**: mean, covariance 및 mixing coefficient에 대한 초기 추정값으로 시작합니다(또는 K-Means 결과를 시작점으로 사용합니다).

- **E-step (Expectation)**: 현재 parameter가 주어졌을 때 각 point에 대한 각 cluster의 responsibility를 계산합니다. 이는 본질적으로 `r_nk = P(z_k | x_n)`이며, 여기서 z_k는 point x_n의 cluster membership를 나타내는 latent variable입니다. 이는 Bayes' theorem을 사용해 수행되며, 현재 parameter를 기반으로 각 point가 각 cluster에 속하는 posterior probability를 계산합니다. Responsibility는 다음과 같이 계산됩니다.
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
여기서:
- \( \pi_k \)는 cluster k의 mixing coefficient입니다(cluster k의 prior probability).
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \)는 mean \( \mu_k \) 및 covariance \( \Sigma_k \)가 주어졌을 때 point \( x_n \)에 대한 Gaussian probability density function입니다.

- **M-step (Maximization)**: E-step에서 계산한 responsibility를 사용해 parameter를 update합니다.
- 각 mean μ_k를 point의 weighted average로 update합니다. 이때 weight는 responsibility입니다.
- 각 covariance Σ_k를 cluster k에 할당된 point의 weighted covariance로 update합니다.
- mixing coefficient π_k를 cluster k에 대한 average responsibility로 update합니다.

- 수렴할 때까지 **E 및 M step을 반복**합니다(parameter가 안정화되거나 likelihood 개선이 threshold보다 낮아질 때까지).

그 결과 전체 data distribution을 함께 model하는 Gaussian distribution 집합을 얻습니다. fitting된 GMM을 사용해 각 point를 probability가 가장 높은 Gaussian에 할당하여 cluster를 구성하거나, uncertainty를 위해 probability를 그대로 유지할 수 있습니다. 또한 새 point의 likelihood를 평가하여 해당 point가 model에 얼마나 잘 맞는지 확인할 수 있습니다(anomaly detection에 유용).

> [!TIP]
> *Cybersecurity에서의 사용 사례:* GMM은 정상 data의 distribution을 model하여 anomaly detection에 사용할 수 있습니다. 학습된 mixture에서 probability가 매우 낮은 point는 anomaly로 flag됩니다. 예를 들어 legitimate network traffic feature로 GMM을 train할 수 있습니다. 학습된 어떤 cluster와도 유사하지 않은 attack connection은 낮은 likelihood를 갖게 됩니다. GMM은 cluster가 서로 다른 shape를 가질 수 있는 activity를 cluster하는 데에도 사용됩니다. 예를 들어 각 profile의 feature가 Gaussian과 유사하지만 고유한 variance structure를 가질 수 있는 경우, behavior profile에 따라 user를 grouping할 수 있습니다. 또 다른 사례로 phishing detection에서는 legitimate email feature가 하나의 Gaussian cluster를 형성하고, known phishing이 또 다른 cluster를 형성하며, 새로운 phishing campaign은 별도의 Gaussian으로 나타나거나 기존 mixture에 비해 likelihood가 낮은 point로 나타날 수 있습니다.

#### Assumptions and Limitations

GMM은 covariance를 포함하는 K-Means의 generalization이므로 cluster가 단순히 spherical한 형태가 아니라 ellipsoidal 형태가 될 수 있습니다. covariance가 full인 경우 서로 다른 size와 shape의 cluster를 처리할 수 있습니다. Soft clustering은 cluster boundary가 모호할 때 유리합니다. 예를 들어 cybersecurity에서 event가 여러 attack type의 특성을 가질 수 있는데, GMM은 probability를 통해 이러한 uncertainty를 반영할 수 있습니다. 또한 GMM은 data에 대한 probabilistic density estimation을 제공하므로 모든 mixture component에서 likelihood가 낮은 outlier를 detection하는 데 유용합니다.

반면 GMM은 component 수 K를 지정해야 합니다(다만 BIC/AIC와 같은 criteria를 사용해 이를 선택할 수 있습니다). EM은 때때로 느리게 수렴하거나 local optimum에 도달할 수 있으므로 initialization이 중요합니다(일반적으로 EM을 여러 번 실행합니다). 실제 data가 Gaussian mixture를 따르지 않는 경우 model이 제대로 fit되지 않을 수 있습니다. 또한 하나의 Gaussian이 outlier 하나만 포함하도록 수축할 위험도 있습니다(regularization 또는 minimum covariance bound를 사용하면 이를 완화할 수 있습니다).


<details>
<summary>예시 -- Soft Clustering 및 Anomaly Scores
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
이 코드에서는 정상 traffic에 대해 3개의 Gaussian을 사용하는 GMM을 학습합니다(정상 traffic의 3가지 profile을 알고 있다고 가정). 출력된 means와 covariances는 이러한 cluster를 설명합니다(예를 들어 하나의 mean은 [50,500] 정도로, 한 cluster의 중심에 해당할 수 있습니다). 그런 다음 의심스러운 connection [duration=200, bytes=800]을 테스트합니다. predict_proba는 이 point가 3개 cluster 각각에 속할 probability를 반환합니다. [200,800]은 정상 cluster에서 멀리 떨어져 있으므로 이 probability들은 매우 낮거나 한쪽으로 크게 치우칠 것으로 예상됩니다. 전체 score_samples(log-likelihood)도 출력되며, 매우 낮은 값은 해당 point가 model에 잘 맞지 않음을 의미하므로 anomaly로 표시할 수 있습니다. 실제로는 log-likelihood(또는 max probability)에 threshold를 설정하여 point가 malicious로 간주될 만큼 충분히 가능성이 낮은지 판단할 수 있습니다. 따라서 GMM은 anomaly detection을 수행하는 체계적인 방법을 제공하는 동시에 uncertainty를 반영하는 soft cluster도 생성합니다.
</details>

### Isolation Forest

**Isolation Forest**는 point를 무작위로 isolate한다는 아이디어에 기반한 ensemble anomaly detection algorithm입니다. 핵심 원리는 anomaly가 적고 서로 다르기 때문에 정상 point보다 더 쉽게 isolate할 수 있다는 것입니다. Isolation Forest는 data를 무작위로 partition하는 여러 개의 binary isolation tree(무작위 decision tree)를 생성합니다. Tree의 각 node에서는 random feature 하나를 선택하고 해당 node의 data에서 그 feature의 min과 max 사이에 있는 random split value를 선택합니다. 이 split은 data를 두 branch로 나눕니다. 각 point가 자체 leaf에서 isolate되거나 최대 tree height에 도달할 때까지 tree를 확장합니다.

Anomaly detection은 이러한 random tree에서 각 point의 path length, 즉 point를 isolate하는 데 필요한 split 수를 관찰하여 수행합니다. 직관적으로 anomaly(outlier)는 sparse region에 있으므로 random split이 dense cluster의 정상 point보다 outlier를 분리할 가능성이 높아 더 빠르게 isolate되는 경향이 있습니다. Isolation Forest는 모든 tree의 average path length로부터 anomaly score를 계산합니다. average path가 짧을수록 더 anomalous합니다. Score는 일반적으로 [0,1]로 normalize되며, 1은 anomaly일 가능성이 매우 높다는 의미입니다.

> [!TIP]
> *Use cases in cybersecurity:* Isolation Forest는 intrusion detection과 fraud detection에 성공적으로 사용되어 왔습니다. 예를 들어 대부분 정상 동작을 포함하는 network traffic log로 Isolation Forest를 train하면, forest는 이상한 traffic(예: 들어본 적 없는 port를 사용하거나 비정상적인 packet size pattern을 보이는 IP)에 대해 짧은 path를 생성하여 검사를 위해 표시합니다. Labeled attack이 필요하지 않으므로 unknown attack type을 탐지하는 데 적합합니다. 또한 user login data에 배포하여 account takeover를 탐지할 수도 있습니다(비정상적인 login time이나 location은 빠르게 isolate됩니다). 한 사용 사례에서 Isolation Forest는 system metrics를 monitoring하고, metrics 조합(CPU, network, file changes)이 historical pattern과 매우 다르게 보일 때(short isolation path) alert를 생성하여 enterprise를 보호할 수 있습니다.

#### Assumptions and Limitations

**Advantages**: Isolation Forest는 distribution assumption이 필요하지 않으며 isolation을 직접 대상으로 합니다. High-dimensional data와 large dataset에서 효율적입니다. 각 tree가 feature의 일부와 split만 사용하여 point를 isolate하므로 forest 구축에 linear complexity $O(n\log n)$가 소요됩니다. Numerical feature를 잘 처리하는 경향이 있으며, $O(n^2)$일 수 있는 distance-based method보다 빠를 수 있습니다. 또한 anomaly score를 자동으로 제공하므로 alert를 위한 threshold를 설정하거나(또는 contamination parameter를 사용하여 예상 anomaly fraction에 기반해 cutoff를 자동으로 결정할 수 있습니다) 활용할 수 있습니다.

**Limitations**: 무작위 특성 때문에 실행마다 결과가 약간 달라질 수 있습니다(다만 tree가 충분히 많으면 그 차이는 작습니다). Data에 irrelevant feature가 많거나 anomaly가 어떤 feature에서도 뚜렷하게 구분되지 않는 경우 isolation이 효과적이지 않을 수 있습니다(random split이 우연히 정상 point를 isolate할 수 있지만, 많은 tree의 averaging으로 완화됩니다). 또한 Isolation Forest는 일반적으로 anomaly가 small minority라고 가정합니다(이는 cybersecurity scenario에서 대체로 사실입니다).

<details>
<summary>Example --  Network Logs에서 Outlier 탐지
</summary>

앞에서 사용한 test dataset(normal point와 일부 attack point를 포함)을 사용하고 Isolation Forest를 실행하여 attack을 분리할 수 있는지 확인합니다. 설명을 위해 data의 약 15%가 anomalous일 것으로 예상한다고 가정합니다.
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
이 코드에서는 100개의 트리를 사용하도록 `IsolationForest`를 인스턴스화하고 `contamination=0.15`로 설정합니다(약 15%가 anomaly일 것으로 예상한다는 의미이며, model은 약 15%의 point가 flagged되도록 score threshold를 설정합니다). 정상 point와 attack point가 섞여 있는 `X_test_if`에 fit합니다(참고로 일반적으로는 training data에 fit한 다음 새로운 data에 predict를 사용하지만, 여기서는 결과를 직접 관찰하기 위해 동일한 set에 fit과 predict를 수행합니다).

출력에는 처음 20개 point에 대한 predicted label이 표시됩니다(`-1`은 anomaly를 나타냅니다). 또한 전체에서 몇 개의 anomaly가 detected되었는지와 일부 example anomaly score도 출력합니다. `contamination`이 15%로 설정되었으므로 대략 120개 point 중 18개가 `-1`로 labeled될 것으로 예상됩니다. 20개의 attack sample이 실제로 가장 outlying한 point라면, 대부분이 해당 `-1` prediction에 포함되어야 합니다. Anomaly score(`Isolation Forest`의 decision function)는 normal point에서 더 높고 anomaly에서는 더 낮으며(더 negative함), separation을 확인하기 위해 일부 값을 출력합니다. 실제로는 score를 기준으로 data를 sort하여 가장 outlying한 point를 확인하고 조사할 수 있습니다. 따라서 `Isolation Forest`는 대규모 unlabeled security data를 효율적으로 선별하여 사람이 분석하거나 추가적인 automated scrutiny를 수행할 가장 irregular한 instance를 찾아내는 방법을 제공합니다.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE**는 high-dimensional data를 2차원 또는 3차원으로 시각화하기 위해 특별히 설계된 nonlinear dimensionality reduction technique입니다. Data point 간의 similarity를 joint probability distribution으로 변환하고, lower-dimensional projection에서 local neighborhood의 structure를 보존하려고 합니다. 간단히 말하면, t-SNE는 (예를 들어) 2D에서 point를 배치하여 original space에서 유사한 point가 서로 가깝게 위치하고, 서로 다른 point는 높은 확률로 멀리 떨어지도록 합니다.

Algorithm에는 세 가지 주요 단계가 있습니다:

1. **Compute pairwise affinities in high-dimensional space:** 각 point pair에 대해 t-SNE는 해당 pair를 neighbor로 선택할 probability를 계산합니다(각 point를 중심으로 Gaussian distribution을 배치하고 거리를 측정하여 수행하며, perplexity parameter는 고려되는 effective neighbor 수에 영향을 줍니다).
2. **Compute pairwise affinities in low-dimensional (e.g. 2D) space:** 처음에는 point를 2D에 random하게 배치합니다. t-SNE는 이 map에서 거리와 관련된 유사한 probability를 정의합니다(Student t-distribution kernel을 사용하며, Gaussian보다 heavier tail을 가지므로 먼 point가 더 자유롭게 배치될 수 있습니다).
3. **Gradient Descent:** 그런 다음 t-SNE는 high-D affinity distribution과 low-D affinity distribution 간의 Kullback–Leibler (KL) divergence를 최소화하도록 2D의 point를 반복적으로 이동합니다. 이 과정에서 2D arrangement가 가능한 한 high-D structure를 반영하게 됩니다. Original space에서 가까웠던 point는 서로 끌어당기고, 멀리 떨어져 있던 point는 서로 밀어내며, 균형이 형성될 때까지 계속됩니다.

그 결과 data의 cluster가 명확하게 드러나는, 시각적으로 의미 있는 scatter plot을 얻는 경우가 많습니다.

> [!TIP]
> *Use cases in cybersecurity:* t-SNE는 **human analysis를 위해 high-dimensional security data를 시각화**하는 데 자주 사용됩니다. 예를 들어 security operations center에서 analyst는 수십 개의 feature(port number, frequency, byte count 등)가 포함된 event dataset을 가져와 t-SNE를 사용하여 2D plot을 생성할 수 있습니다. 이 plot에서 attack이 별도의 cluster를 형성하거나 normal data와 분리되어 더 쉽게 식별될 수 있습니다. Malware family의 grouping을 확인하기 위한 malware dataset이나, 서로 다른 attack type이 뚜렷하게 cluster를 형성하여 추가 조사를 지원하는 network intrusion data에도 적용되어 왔습니다. 본질적으로 t-SNE는 그렇지 않으면 이해하기 어려운 cyber data의 structure를 확인할 수 있는 방법을 제공합니다.

#### Assumptions and Limitations

t-SNE는 pattern을 시각적으로 탐색하는 데 매우 유용합니다. 다른 linear method(예: PCA)가 드러내지 못할 수 있는 cluster, subcluster 및 outlier를 발견할 수 있습니다. Malware behavior profile이나 network traffic pattern과 같은 복잡한 data를 시각화하기 위해 cybersecurity research에서 사용되어 왔습니다. Local structure를 보존하므로 natural grouping을 표시하는 데 적합합니다.

하지만 t-SNE는 computationally heavier(대략 $O(n^2)$)하므로 매우 큰 dataset에서는 sampling이 필요할 수 있습니다. 또한 output에 영향을 줄 수 있는 hyperparameter(perplexity, learning rate, iteration)가 있습니다. 예를 들어 서로 다른 perplexity value는 서로 다른 scale의 cluster를 드러낼 수 있습니다. t-SNE plot은 때때로 잘못 해석될 수 있습니다. Map에서의 거리는 global하게 직접적인 의미를 갖지 않으며(local neighborhood에 초점을 맞추므로 일부 cluster가 인위적으로 매우 잘 분리되어 보일 수 있습니다), t-SNE는 주로 visualization을 위한 방법입니다. Recomputing 없이 새로운 data point를 projection하는 straightforward한 방법을 제공하지 않으며, predictive modeling을 위한 preprocessing으로 사용하도록 설계된 것도 아닙니다(UMAP은 더 빠른 속도로 이러한 문제 중 일부를 해결하는 alternative입니다).

<details>
<summary>Example -- Visualizing Network Connections
</summary>

t-SNE를 사용하여 multi-feature dataset을 2D로 축소합니다. 설명을 위해 앞서 사용한 4D data(정상 traffic의 3개 natural cluster가 있었음)를 가져와 몇 개의 anomaly point를 추가합니다. 그런 다음 t-SNE를 실행하고 결과를 (개념적으로) 시각화합니다.
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
여기서는 이전의 4D normal dataset에 소수의 extreme outlier를 결합했습니다(outlier는 이상한 패턴을 시뮬레이션하기 위해 하나의 feature(“duration”)가 매우 높게 설정되어 있습니다). 일반적인 perplexity 30으로 t-SNE를 실행합니다. 출력 데이터 `data_2d`의 shape은 (1505, 2)입니다. 이 텍스트에서는 실제로 plot을 생성하지 않지만, 생성한다면 3개의 normal cluster에 해당하는 세 개의 조밀한 cluster가 나타나고, 5개의 outlier는 해당 cluster에서 멀리 떨어진 isolated point로 나타날 것으로 예상할 수 있습니다. 대화형 workflow에서는 point를 label(normal 또는 어느 cluster에 속하는지, anomaly인지)에 따라 color를 지정하여 이 구조를 확인할 수 있습니다. label이 없더라도 analyst는 2D plot의 빈 공간에 위치한 이 5개의 point를 발견하고 flag할 수 있습니다. 이는 t-SNE가 cybersecurity data에서 시각적 anomaly detection과 cluster inspection을 지원하는 강력한 도구가 될 수 있으며, 앞서 설명한 automated algorithm을 보완한다는 것을 보여줍니다.

</details>


### HDBSCAN (계층적 밀도 기반 애플리케이션 공간 클러스터링 및 노이즈)

**HDBSCAN**은 단일 global `eps` 값을 선택할 필요를 없애고, density-connected component의 hierarchy를 구축한 다음 이를 압축하여 **서로 다른 density**의 cluster를 찾아낼 수 있도록 DBSCAN을 확장한 알고리즘입니다. 기본 DBSCAN과 비교하면 일반적으로

* 일부 cluster는 dense하고 다른 cluster는 sparse한 경우 더 직관적인 cluster를 추출하고,
* 실제 hyper-parameter가 하나(`min_cluster_size`)뿐이며 합리적인 default를 제공하고,
* 모든 point에 cluster-membership *probability*와 **outlier score**(`outlier_scores_`)를 제공하므로 threat-hunting dashboard에 매우 유용합니다.<sup>[[1]](#references)</sup>

> [!TIP]
> *사이버보안에서의 사용 사례:* HDBSCAN은 최신 threat-hunting pipeline에서 매우 널리 사용되며, 상용 XDR suite와 함께 제공되는 notebook 기반 hunting playbook 내부에서 자주 볼 수 있습니다. 한 가지 실용적인 recipe는 IR 중 HTTP beaconing traffic을 cluster하는 것입니다. user-agent, interval 및 URI length는 합법적인 software updater의 여러 조밀한 group을 형성하는 경우가 많지만, C2 beacon은 작은 low-density cluster 또는 순수한 noise로 남습니다.

<details>
<summary>예제 – beaconing C2 channel 찾기</summary>
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

최근 연구에 따르면 **unsupervised learner는 *active attacker*에 대해 면역성이 없습니다**:

* **Anomaly detector에 대한 Data-poisoning.** Chen *et al.* (IEEE S&P 2024)은 조작된 traffic을 3 %만 추가해도 Isolation Forest와 ECOD의 decision boundary를 변경하여 실제 attack이 정상으로 보이게 할 수 있음을 입증했습니다. 저자들은 poison point를 자동으로 합성하는 open-source PoC(`udo-poison`)를 공개했습니다.<sup>[[2]](#references)</sup>
* **Clustering model Backdooring.** *BadCME* technique (BlackHat EU 2023)은 작은 trigger pattern을 삽입합니다. 해당 trigger가 나타나면 K-Means 기반 detector는 조용히 event를 “benign” cluster 안에 배치합니다.
* **DBSCAN/HDBSCAN Evasion.** KU Leuven의 2025년 academic pre-print는 attacker가 의도적으로 density gap에 들어가도록 beaconing pattern을 조작하여, 사실상 *noise* label 안에 숨을 수 있음을 보였습니다.

다음과 같은 Mitigation이 점점 널리 사용되고 있습니다:

1. **Model sanitisation / TRIM.** 매 retraining epoch 전에 loss가 가장 높은 1–2 %의 point를 폐기합니다(trimmed maximum likelihood). 이를 통해 poisoning을 크게 어렵게 만들 수 있습니다.
2. **Consensus ensembling.** 여러 heterogeneous detector(예: Isolation Forest + GMM + ECOD)를 결합하고, 어느 한 model이라도 point를 flag하면 alert를 발생시킵니다. 연구에 따르면 이 방식은 attacker의 cost를 10배 이상 증가시킵니다.
3. **Clustering을 위한 Distance-based defence.** 서로 다른 `k`개의 random seed로 cluster를 다시 계산하고, 계속해서 cluster 사이를 이동하는 point를 무시합니다.

---

### Modern Open-Source Tooling (2024-2025)

* **PyOD 2.x** (2024년 5월 release)는 *ECOD*, *COPOD* 및 GPU-accelerated *AutoFormer* detector를 추가했습니다. 이제 `benchmark` sub-command를 제공하므로, 다음과 같이 **한 줄의 code**로 dataset에서 30개 이상의 algorithm을 비교할 수 있습니다:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (2025년 2월)는 vision에 중점을 두지만, generic **PatchCore** implementation도 포함합니다. 따라서 screenshot 기반 phishing page detection에 유용합니다.
* **scikit-learn 1.5** (2024년 11월)는 마침내 새로운 `cluster.HDBSCAN` wrapper를 통해 *HDBSCAN*의 `score_samples`를 제공합니다. 따라서 Python 3.12를 사용할 때 external contrib package가 필요하지 않습니다.

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

## 참고 문헌

- [1] [HDBSCAN - 계층적 밀도 기반 클러스터링](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *외.* “비지도 anomaly detection의 data poisoning 취약성.” *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
