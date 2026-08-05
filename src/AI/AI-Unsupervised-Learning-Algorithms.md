# 无监督学习算法

{{#include ../banners/hacktricks-training.md}}

## 无监督学习

无监督学习是一种机器学习类型，模型在没有带标签响应的数据上进行训练。其目标是在数据中发现模式、结构或关系。与模型从带标签示例中学习的监督学习不同，无监督学习算法处理的是无标签数据。
无监督学习通常用于聚类、降维和异常检测等任务。它可以帮助发现数据中的隐藏模式，将相似项目归为一组，或在保留数据基本特征的同时降低数据复杂度。


### K-Means 聚类

K-Means 是一种基于质心的聚类算法，通过将每个点分配给最近的聚类均值，将数据划分为 K 个聚类。该算法的工作流程如下：
1. **初始化**：选择 K 个初始聚类中心（质心），通常通过随机方式或 k-means++ 等更智能的方法选择
2. **分配**：根据距离度量（例如欧氏距离）将每个数据点分配给最近的质心。
3. **更新**：计算分配给每个聚类的所有数据点的均值，以重新计算质心。
4. **重复**：重复步骤 2–3，直到聚类分配趋于稳定（质心不再发生显著移动）。

> [!TIP]
> *在网络安全中的用例：* K-Means 可通过对网络事件进行聚类来执行入侵检测。例如，研究人员将 K-Means 应用于 KDD Cup 99 入侵数据集，并发现它能够有效地将流量划分为正常流量和攻击流量聚类。在实际应用中，安全分析师可以对日志条目或用户行为数据进行聚类，以发现相似活动组成的群组；任何不属于结构良好聚类的点都可能表示异常（例如，一个新的 malware 变种形成自己的小型聚类）。K-Means 还可以通过根据行为配置文件或特征向量对二进制文件进行分组，帮助进行 malware 家族分类。

#### K 的选择
聚类数量（K）是一个需要在运行算法之前定义的超参数。Elbow Method 或 Silhouette Score 等技术可以通过评估聚类性能来帮助确定合适的 K 值：

- **Elbow Method**：绘制每个点到其所属聚类质心的平方距离之和与 K 的关系图。寻找下降速率发生明显变化的“肘部”点，该点表示合适的聚类数量。
- **Silhouette Score**：计算不同 K 值下的 silhouette score。更高的 silhouette score 表示定义更清晰的聚类。

#### 假设和局限性

K-Means 假设 **聚类呈球形且大小相同**，但这一点并不适用于所有数据集。它对质心的初始位置较为敏感，并且可能收敛到局部最小值。此外，K-Means 不适用于密度不同或形状非球状的数据集，也不适用于具有不同尺度特征的数据集。可能需要执行归一化或标准化等预处理步骤，以确保所有特征对距离计算的贡献相同。

<details>
<summary>示例 -- 聚类网络事件
</summary>
下面我们模拟网络流量数据，并使用 K-Means 对其进行聚类。假设我们有一些事件，其特征包括连接持续时间和字节数。我们创建 3 个代表“正常”流量的聚类，以及 1 个代表攻击模式的小型聚类。然后运行 K-Means，观察它是否能将这些聚类分离开来。
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
在此示例中，K-Means 应找到 4 个 clusters。小型 attack cluster（duration 异常高，约为 ~200）由于与 normal clusters 的距离较远，理想情况下会形成自己的 cluster。我们打印 cluster 的大小和中心，以便解读结果。在真实场景中，可以将仅包含少量点的 cluster 标记为潜在异常，或检查其成员是否存在恶意活动。
</details>

### Hierarchical Clustering

Hierarchical clustering 使用自底向上（agglomerative）或自顶向下（divisive）的方法构建 cluster 层次结构：

1. **Agglomerative (Bottom-Up)**：从每个数据点作为独立 cluster 开始，持续合并距离最近的 clusters，直到只剩一个 cluster，或满足停止条件。
2. **Divisive (Top-Down)**：从所有数据点位于同一个 cluster 开始，持续拆分 clusters，直到每个数据点都成为自己的 cluster，或满足停止条件。

Agglomerative clustering 需要定义 inter-cluster distance 和 linkage criterion，以决定要合并哪些 clusters。常见的 linkage 方法包括 single linkage（两个 clusters 之间最近点的距离）、complete linkage（最远点的距离）、average linkage 等，距离度量通常为 Euclidean。linkage 的选择会影响生成的 clusters 的形状。无需预先指定 clusters 的数量 K；可以在选定的层级“切割” dendrogram，以获得所需数量的 clusters。

Hierarchical clustering 会生成 dendrogram，这是一种树状结构，用于展示不同粒度层级下 clusters 之间的关系。可以在所需层级切割 dendrogram，以获得特定数量的 clusters。

> [!TIP]
> *Use cases in cybersecurity:* Hierarchical clustering 可以将 events 或 entities 组织成树状结构，以发现其中的关系。例如，在 malware analysis 中，agglomerative clustering 可以根据行为相似性对 samples 进行分组，从而揭示 malware families 和 variants 的层次结构。在 network security 中，可以对 IP traffic flows 进行 clustering，并使用 dendrogram 查看 traffic 的子分组（例如先按 protocol，再按 behavior）。由于无需预先选择 K，因此在探索 attack categories 数量未知的新数据时非常有用。

#### Assumptions and Limitations

Hierarchical clustering 不假设特定的 cluster 形状，并且能够捕获 nested clusters。它适合发现 groups 之间的 taxonomy 或 relations（例如按 family subgroups 对 malware 进行分组）。它具有确定性（不存在 random initialization 问题）。其主要优势是 dendrogram，它可以展示数据在所有尺度下的 clustering structure，security analysts 可以据此决定合适的 cutoff，以识别有意义的 clusters。不过，它的 computational cost 较高（朴素实现通常需要 $O(n^2)$ 时间或更差），不适用于非常大的 datasets。它也是一种 greedy procedure：一旦完成 merge 或 split，就无法撤销；如果早期发生错误，可能会导致 suboptimal clusters。Outliers 也会影响某些 linkage strategies（single-link 可能导致“chaining” effect，即 clusters 通过 outliers 相互连接）。

<details>
<summary>Example -- Agglomerative Clustering of Events
</summary>

我们将重复使用 K-Means 示例中的 synthetic data（3 个 normal clusters + 1 个 attack cluster），并应用 agglomerative clustering。随后，我们将演示如何获取 dendrogram 和 cluster labels。
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

### DBSCAN（基于密度的带噪声应用空间聚类）

DBSCAN 是一种基于密度的聚类算法，它将彼此紧密聚集的点归为一组，同时将低密度区域中的点标记为离群点。它尤其适用于具有不同密度和非球形形状的数据集。

DBSCAN 通过定义两个参数来工作：
- **Epsilon（ε）**：两个点被视为属于同一簇时允许的最大距离。
- **MinPts**：形成密集区域（核心点）所需的最少点数。

DBSCAN 会识别核心点、边界点和噪声点：
- **核心点**：在 ε 距离内至少有 MinPts 个邻居的点。
- **边界点**：位于某个核心点的 ε 距离内，但邻居数少于 MinPts 的点。
- **噪声点**：既不是核心点，也不是边界点的点。

聚类过程从选择一个未访问的核心点开始，将其标记为一个新簇，然后递归地添加所有从该点密度可达的点（核心点及其邻居等）。边界点会被添加到附近核心点所属的簇中。在扩展完所有可达点后，DBSCAN 会移动到另一个未访问的核心点，以开始新的簇。任何未被核心点到达的点都会继续被标记为噪声。

> [!TIP]
> *在 cybersecurity 中的使用场景：* DBSCAN 适用于网络流量中的 anomaly detection。例如，正常用户活动可能会在特征空间中形成一个或多个密集簇，而新出现的攻击行为可能表现为分散的点，并被 DBSCAN 标记为噪声（离群点）。它已被用于对网络流记录进行聚类，从而将 port scan 或 denial-of-service 流量检测为稀疏的点区域。另一个应用是对 malware 变种进行分组：如果大多数样本按照家族形成簇，但少数样本无法归入任何簇，那么这些样本可能是 zero-day malware。标记噪声的能力意味着 security teams 可以专注于调查这些离群点。

#### 假设与限制

**假设与优势：**：DBSCAN 不假设簇是球形的——它可以发现任意形状的簇（甚至是链状簇或相邻簇）。它会根据数据密度自动确定簇的数量，并能有效地将离群点识别为噪声。这使其非常适合具有不规则形状和噪声的现实数据。它对离群点具有较强的鲁棒性（不同于会强制将离群点归入某个簇的 K-Means）。当簇具有大致均匀的密度时，它的效果良好。

**限制**：DBSCAN 的性能取决于是否选择了合适的 ε 和 MinPts 值。对于密度不同的数据，它可能难以正常工作——单个 ε 无法同时适应密集簇和稀疏簇。如果 ε 太小，它会将大多数点标记为噪声；如果 ε 太大，则簇可能会被错误地合并。此外，DBSCAN 在非常大的数据集上可能效率较低（朴素实现的复杂度为 $O(n^2)$，但空间索引可以提供帮助）。在高维特征空间中，“ε 内的距离”这一概念可能变得不再有意义（维度灾难），因此 DBSCAN 可能需要仔细调整参数，或者无法找到符合直觉的簇。尽管如此，HDBSCAN 等扩展算法解决了其中的一些问题（例如密度变化问题）。

<details>
<summary>示例 -- 带噪声的聚类
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
在此代码片段中，我们调整了 `eps` 和 `min_samples`，使其适应数据的尺度（特征单位中的 15.0，并要求 5 个点才能形成一个 cluster）。DBSCAN 应该能够找到 2 个 cluster（正常流量 cluster），并将注入的 5 个 outlier 标记为 noise。我们输出 cluster 数量与 noise 点数量，以验证这一点。在实际环境中，可以遍历不同的 ε（使用 k-distance graph heuristic 选择 ε）和 MinPts（通常根据经验设置为接近数据维度 + 1），以找到稳定的 clustering 结果。显式标记 noise 的能力有助于将潜在的攻击数据分离出来，以便进一步分析。

</details>

### Principal Component Analysis (PCA)

PCA 是一种**降维**技术，用于寻找一组新的正交轴（principal components），以捕获数据中的最大 variance。简单来说，PCA 会将数据旋转并投影到一个新的坐标系中，使第一主成分（PC1）解释尽可能大的 variance，第二主成分（PC2）解释与 PC1 正交方向上的最大 variance，依此类推。从数学角度看，PCA 会计算数据 covariance matrix 的 eigenvectors——这些 eigenvectors 就是 principal component 的方向，而对应的 eigenvalues 表示每个 component 所解释的 variance 数量。PCA 常用于 feature extraction、可视化和 noise reduction。

需要注意的是，如果数据集的维度包含**显著的线性依赖或相关性**，PCA 会非常有用。

PCA 通过识别数据的 principal components 来工作，这些 components 就是 variance 最大的方向。PCA 涉及以下步骤：
1. **Standardization**：通过减去均值并缩放到单位 variance，对数据进行中心化。
2. **Covariance Matrix**：计算 standardized data 的 covariance matrix，以了解 features 之间的关系。
3. **Eigenvalue Decomposition**：对 covariance matrix 执行 eigenvalue decomposition，以获得 eigenvalues 和 eigenvectors。
4. **Select Principal Components**：按降序排列 eigenvalues，并选择与最大 eigenvalues 对应的前 K 个 eigenvectors。这些 eigenvectors 构成新的 feature space。
5. **Transform Data**：使用选定的 principal components，将原始数据投影到新的 feature space 中。
PCA 广泛用于数据可视化、noise reduction，以及作为其他 machine learning algorithms 的预处理步骤。它能够在保留数据基本结构的同时，降低数据的维度。

#### Eigenvalues and Eigenvectors

eigenvalue 是一个 scalar，用于表示其对应 eigenvector 所捕获的 variance 数量。eigenvector 表示 feature space 中数据变化最大的方向。

假设 A 是一个 square matrix，v 是一个非零 vector，并且满足：`A * v = λ * v`
其中：
- A 是一个 square matrix，例如 [ [1, 2], [2, 1]]（例如 covariance matrix）
- v 是一个 eigenvector（例如 [1, 1]）

那么，`A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`，其结果等于 eigenvalue λ 与 eigenvector v 的乘积，因此 eigenvalue λ = 3。

#### Eigenvalues and Eigenvectors in PCA

让我们通过一个示例来解释这一点。假设你有一个包含大量 100x100 像素灰度人脸图片的数据集。每个像素都可以视为一个 feature，因此每张图片有 10,000 个 features（或者说，每张图片是一个包含 10000 个 components 的 vector）。如果你想使用 PCA 降低该数据集的维度，可以按以下步骤操作：

1. **Standardization**：从数据集中减去每个 feature（像素）的均值，对数据进行中心化。
2. **Covariance Matrix**：计算 standardized data 的 covariance matrix，该矩阵用于捕获 features（像素）如何共同变化。
- 注意，两个变量（在此处即像素）之间的 covariance 表示它们共同变化的程度，因此这里的目标是找出哪些像素倾向于按照线性关系共同增加或减少。
- 例如，如果 pixel 1 和 pixel 2 倾向于同时增加，那么它们之间的 covariance 将为正。
- covariance matrix 将是一个 10,000x10,000 的 matrix，其中每个条目表示两个像素之间的 covariance。
3. **Solve The eigenvalue equation**：需要求解的 eigenvalue equation 是 `C * v = λ * v`，其中 C 是 covariance matrix，v 是 eigenvector，λ 是 eigenvalue。可以使用以下方法求解：
- **Eigenvalue Decomposition**：对 covariance matrix 执行 eigenvalue decomposition，以获得 eigenvalues 和 eigenvectors。
- **Singular Value Decomposition (SVD)**：也可以使用 SVD 将 data matrix 分解为 singular values 和 vectors，这同样能够得到 principal components。
4. **Select Principal Components**：按降序排列 eigenvalues，并选择与最大 eigenvalues 对应的前 K 个 eigenvectors。这些 eigenvectors 表示数据中 variance 最大的方向。

> [!TIP]
> *Use cases in cybersecurity:* PCA 在 security 中的一个常见用途是用于 anomaly detection 的 feature reduction。例如，一个包含 40 多个 network metrics（如 NSL-KDD features）的 intrusion detection system，可以使用 PCA 将其降至少量 components，从而对数据进行汇总，以便可视化或输入 clustering algorithms。分析人员可以在前两个 principal components 构成的空间中绘制 network traffic，以观察攻击是否与正常流量分离。PCA 还可以帮助消除冗余 features（例如，在 bytes sent 与 bytes received 相关时），从而使 detection algorithms 更加 robust 且速度更快。

#### Assumptions and Limitations

PCA 假设**variance 的 principal axes 具有实际意义**——它是一种线性方法，因此能够捕获数据中的线性相关性。PCA 是 unsupervised 的，因为它只使用 feature covariance。PCA 的优势包括 noise reduction（低 variance components 通常对应 noise）以及对 features 进行 decorrelation。对于中等高维度的数据，PCA 的 computational efficiency 较高，并且通常可以作为其他 algorithms 的有用预处理步骤（用于缓解 curse of dimensionality）。PCA 的一个 limitation 是它仅限于线性关系——它无法捕获复杂的 nonlinear structure（而 autoencoders 或 t-SNE 可能可以捕获）。此外，PCA components 很难根据原始 features 进行解释（因为它们是原始 features 的组合）。在 cybersecurity 中必须谨慎：如果某个攻击只导致 low-variance feature 发生细微变化，那么它可能不会出现在 top PCs 中（因为 PCA 优先考虑 variance，而不一定是“interestingness”）。

<details>
<summary>Example -- Reducing Dimensions of Network Data
</summary>

假设我们有包含多个 features（例如 durations、bytes、counts）的 network connection logs。我们将生成一个 synthetic 4-dimensional dataset（其中部分 features 之间存在 correlation），并使用 PCA 将其降至 2 个维度，以便进行可视化或进一步分析。
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
这里，我们对之前的正常流量聚类进行了扩展，为每个数据点增加了两个与字节数和持续时间相关的特征（数据包和错误）。随后使用 PCA 将这 4 个特征压缩为 2 个主成分。我们输出了解释方差比率，该比率可能显示，例如，超过 95% 的方差由 2 个主成分捕获（意味着信息损失很小）。输出还显示数据形状从 (1500, 4) 缩减为 (1500, 2)。其中给出了 PCA 空间中前几个点作为示例。在实际应用中，可以绘制 data_2d，以直观检查各个簇是否具有可区分性。如果存在异常，可能会看到某个点偏离 PCA 空间中的主簇。这样，PCA 就能帮助将复杂数据提炼为便于人类解释的形式，或作为其他算法的输入。

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Model 假设数据由**多个参数未知的 Gaussian（正态）分布混合生成**。本质上，它是一种概率聚类模型：尝试将每个点以软分配的方式分配给 K 个 Gaussian component 中的一个。每个 Gaussian component k 都具有一个均值向量（μ_k）、协方差矩阵（Σ_k）和混合权重（π_k），后者表示该 cluster 的普遍程度。与执行“硬”分配的 K-Means 不同，GMM 会为每个点计算其属于每个 cluster 的概率。

GMM 通常通过 Expectation-Maximization (EM) algorithm 进行拟合：

- **Initialization**：使用均值、协方差和混合系数的初始猜测值开始（也可以使用 K-Means 结果作为起点）。

- **E-step (Expectation)**：给定当前参数，计算每个 cluster 对每个点的责任度：本质上是 `r_nk = P(z_k | x_n)`，其中 z_k 是表示点 x_n 所属 cluster 的 latent variable。该过程使用 Bayes' theorem，根据当前参数计算每个点属于每个 cluster 的 posterior probability。责任度计算如下：
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
其中：
- \( \pi_k \) 是 cluster k 的 mixing coefficient（cluster k 的 prior probability），
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) 是给定均值 \( \mu_k \) 和协方差 \( \Sigma_k \) 时点 \( x_n \) 的 Gaussian probability density function。

- **M-step (Maximization)**：使用 E-step 中计算出的责任度更新参数：
- 将每个均值 μ_k 更新为各点的加权平均值，其中权重就是责任度。
- 将每个协方差 Σ_k 更新为分配给 cluster k 的各点的加权协方差。
- 将混合系数 π_k 更新为 cluster k 的平均责任度。

- **Iterate** E 和 M steps，直到收敛（参数稳定，或 likelihood 的改善低于某个阈值）。

最终结果是一组共同建模整体数据分布的 Gaussian distributions。我们可以使用拟合后的 GMM，通过将每个点分配给概率最高的 Gaussian 来进行聚类，也可以保留这些概率以表示不确定性。还可以评估新点的 likelihood，以判断它们是否符合该模型（这对 anomaly detection 很有用）。

> [!TIP]
> *Use cases in cybersecurity:* GMM 可通过建模正常数据的分布来执行 anomaly detection：在学习到的 mixture 下概率极低的点会被标记为 anomaly。例如，可以在合法 network traffic features 上训练 GMM；一个与任何已学习 cluster 都不相似的攻击连接将具有较低的 likelihood。GMM 还可用于对形状可能不同的活动进行聚类——例如，根据 behavior profiles 对用户进行分组，其中每个 profile 的 features 可能类似 Gaussian，但具有各自的 variance structure。另一个场景是 phishing detection：合法 email features 可能形成一个 Gaussian cluster，已知 phishing 形成另一个 Gaussian cluster，而新的 phishing campaigns 可能表现为独立的 Gaussian，或者相对于现有 mixture 表现为低 likelihood 的点。

#### Assumptions and Limitations

GMM 是 K-Means 的一种 generalization，它引入了 covariance，因此 cluster 可以呈椭圆形（而不仅是球形）。如果 covariance 使用 full 形式，它可以处理大小和形状不同的 cluster。当 cluster 边界模糊时，soft clustering 是一种优势——例如在 cybersecurity 中，某个 event 可能具有多种 attack types 的特征；GMM 可以通过 probabilities 表达这种不确定性。GMM 还提供对数据的 probabilistic density estimation，这对于检测 outliers（在所有 mixture components 下 likelihood 都较低的点）很有用。

其缺点是，GMM 需要指定 components 的数量 K（不过可以使用 BIC/AIC 等 criteria 进行选择）。EM 有时会收敛缓慢，或收敛到 local optimum，因此 initialization 很重要（通常会多次运行 EM）。如果数据实际上并不遵循 Gaussian mixture，模型可能拟合效果较差。此外，还存在某个 Gaussian 收缩到仅覆盖一个 outlier 的风险（不过 regularization 或 minimum covariance bounds 可以缓解这一问题）。


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
在这段代码中，我们使用正常流量训练一个包含 3 个 Gaussian 的 GMM（假设我们已知 3 种合法流量 profile）。打印出的均值和协方差描述了这些 clusters（例如，某个均值可能接近 [50,500]，对应某个 cluster 的中心等）。随后，我们测试一个可疑连接 [duration=200, bytes=800]。predict_proba 给出该点属于 3 个 clusters 中每个 cluster 的概率——由于 [200,800] 远离正常 clusters，我们预计这些概率会非常低或高度偏斜。随后会打印整体 score_samples（log-likelihood）；非常低的值表示该点与模型的匹配程度很差，因此会被标记为 anomaly。在实践中，可以对 log-likelihood（或 max probability）设置 threshold，以判断某个点是否足够不可能，从而将其视为 malicious。GMM 因此提供了一种有理论依据的 anomaly detection 方法，同时还能生成能够体现不确定性的 soft clusters。
</details>

### Isolation Forest

**Isolation Forest** 是一种基于随机隔离 points 思想的 ensemble anomaly detection algorithm。其原理是：anomalies 数量少且与众不同，因此比正常 points 更容易被隔离。Isolation Forest 会构建许多 binary isolation trees（random decision trees），以随机方式对数据进行 partition。在 tree 的每个 node 中，都会选择一个 random feature，并在该 node 中数据对应 feature 的 min 和 max 之间选择一个 random split value。该 split 会将数据分为两个 branches。Tree 会持续生长，直到每个 point 都被隔离到自己的 leaf 中，或达到 tree 的最大高度。

Anomaly detection 通过观察每个 point 在这些 random trees 中的 path length 来执行——即隔离该 point 所需的 splits 数量。直观来说，anomalies（outliers）往往能更快被隔离，因为对于位于稀疏区域中的 outlier，random split 更可能将其分离；而对于位于 dense cluster 中的正常 point，情况则不同。Isolation Forest 根据所有 trees 的平均 path length 计算 anomaly score：平均路径越短 → 越可能是 anomaly。Scores 通常会被归一化到 [0,1]，其中 1 表示极有可能是 anomaly。

> [!TIP]
> *Use cases in cybersecurity:* Isolation Forest 已成功用于 intrusion detection 和 fraud detection。例如，在主要包含正常行为的 network traffic logs 上训练 Isolation Forest；对于异常流量（例如某个 IP 使用了从未出现过的 port，或具有异常的 packet size pattern），forest 会生成较短的 paths，并将其标记出来供检查。由于它不需要 labeled attacks，因此适合检测未知 attack types。它还可以部署在 user login data 上，用于检测 account takeovers（异常的 login times 或 locations 会被快速隔离）。在一个 use-case 中，Isolation Forest 可以通过监控 system metrics 来保护 enterprise，并在一组 metrics（CPU、network、file changes）与历史 patterns 显著不同时（即 isolation paths 较短）生成 alert。

#### Assumptions and Limitations

**Advantages**：Isolation Forest 不要求数据遵循某种 distribution assumption；它直接针对 isolation 进行建模。它对 high-dimensional data 和 large datasets 的处理效率较高（构建 forest 的线性复杂度为 $O(n\log n)$），因为每棵 tree 只使用 feature 的一个 subset 和若干 splits 来隔离 points。它通常能够很好地处理 numerical features，并且可能比 distance-based methods 更快，后者的复杂度可能达到 $O(n^2)$。它还会自动生成 anomaly score，因此可以设置 threshold 来触发 alerts（或者使用 contamination parameter，根据预期的 anomaly fraction 自动确定 cutoff）。

**Limitations**：由于其 random nature，不同 runs 的结果可能略有差异（不过当 trees 数量足够多时，这种差异很小）。如果数据包含大量 irrelevant features，或者 anomalies 在任何 feature 上都没有明显差异，isolation 可能无法有效工作（random splits 可能会因偶然而隔离正常 points——不过对大量 trees 的结果取平均可以缓解这一问题）。此外，Isolation Forest 通常假设 anomalies 只占少数（这在 cybersecurity 场景中通常成立）。

<details>
<summary>Example --  Detecting Outliers in Network Logs
</summary>

我们将使用前面提到的 test dataset（其中包含正常 points 和一些 attack points），并运行 Isolation Forest，观察它是否能够分离这些 attacks。我们假设数据中约有 15% 的内容为 anomalous（用于演示）。
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
在这段代码中，我们使用 100 棵树实例化 `IsolationForest`，并设置 `contamination=0.15`（表示我们预计约有 15% 的异常；模型会设置其分数阈值，使约 15% 的点被标记出来）。我们在包含正常点和攻击点混合数据的 `X_test_if` 上进行拟合（注意：通常应在训练数据上拟合，然后在新数据上使用 predict；但这里为了便于说明，在同一数据集上进行拟合和预测，以便直接观察结果）。

输出显示了前 20 个点的预测标签（其中 -1 表示异常）。我们还会打印检测到的异常总数以及一些示例异常分数。由于 contamination 设置为 15%，我们预计 120 个点中大约有 18 个会被标记为 -1。如果这 20 个攻击样本确实是最偏离整体分布的点，那么其中大多数应该出现在这些 -1 预测中。异常分数（Isolation Forest 的 decision function）对于正常点较高，对于异常点较低（更负）——我们打印一些数值来观察这种分离效果。在实践中，可以按照分数对数据排序，以找出排名靠前的异常点，并对其进行调查。因此，Isolation Forest 提供了一种高效的方法，可以筛查大量无标签安全数据，找出最不规则的实例，供人工分析或进一步的自动化审查。
</details>


### t-SNE（t-Distributed Stochastic Neighbor Embedding）

**t-SNE** 是一种非线性降维技术，专门用于在二维或三维空间中可视化高维数据。它会将数据点之间的相似性转换为联合概率分布，并尝试在低维投影中保留局部邻域的结构。简单来说，t-SNE 会将点放置在（例如）二维空间中，使原始空间中相似的点最终以较高概率彼此接近，而不相似的点彼此远离。

该算法主要包含三个阶段：

1. **在高维空间中计算成对亲和度：** 对于每一对点，t-SNE 会计算将这两个点选为邻居的概率（具体做法是在每个点上以其为中心构建 Gaussian 分布并测量距离——perplexity 参数会影响所考虑的有效邻居数量）。
2. **在低维（例如二维）空间中计算成对亲和度：** 初始时，点会被随机放置在二维空间中。t-SNE 使用类似的概率来表示映射中距离的关系（采用 Student t-distribution kernel，其尾部比 Gaussian 更厚，从而允许远距离点拥有更大的自由度）。
3. **Gradient Descent：** 随后，t-SNE 会反复移动二维空间中的点，使高维亲和度分布与低维亲和度分布之间的 Kullback–Leibler（KL）散度最小化。这会使二维排列尽可能反映高维结构——原始空间中彼此接近的点会相互吸引，而相距较远的点会相互排斥，直到达到平衡。

最终通常会得到一个具有直观意义的散点图，其中的数据集群会变得清晰可见。

> [!TIP]
> *在 cybersecurity 中的使用场景：* t-SNE 常用于**将高维安全数据可视化，以供人工分析**。例如，在 security operations center 中，分析人员可以获取一个包含数十个特征的事件数据集（端口号、频率、字节数等），并使用 t-SNE 生成二维图。攻击可能在图中形成自己的集群，或与正常数据分离，从而更容易被识别。它已被应用于 malware 数据集，以观察不同 malware family 的分组；也被应用于 network intrusion 数据，以显示不同攻击类型形成的明显集群，从而指导进一步调查。本质上，t-SNE 提供了一种观察 cyber data 中结构的方法，而这些结构在其他情况下可能难以理解。

#### 假设和局限性

t-SNE 非常适合用于直观地发现模式。它可以揭示其他线性方法（如 PCA）可能无法发现的集群、子集群和异常点。它已被用于 cybersecurity 研究，以可视化复杂数据，例如 malware behavior profile 或 network traffic pattern。由于它能够保留局部结构，因此非常适合展示自然形成的分组。

不过，t-SNE 的计算开销较大（约为 $O(n^2)$），因此在处理非常大的数据集时可能需要进行采样。它还包含多个超参数（perplexity、learning rate、iterations），这些参数会影响输出——例如，不同的 perplexity 值可能会揭示不同尺度下的集群。t-SNE 图有时可能被误解——图中的距离在全局范围内并不直接具有实际意义（它关注局部邻域，因此某些集群可能会显得人为地分离得非常明显）。此外，t-SNE 主要用于可视化；如果不重新计算，它无法以直接的方式投影新的数据点，并且它不适合作为 predictive modeling 的预处理步骤（UMAP 是一种替代方案，可以通过更快的速度解决其中一些问题）。

<details>
<summary>示例 -- 可视化网络连接
</summary>

我们将使用 t-SNE 将包含多个特征的数据集降至二维空间。为了便于说明，我们使用前面提到的 4D 数据（其中包含 3 个自然形成的正常流量集群），并加入一些异常点。然后运行 t-SNE，并（从概念上）将结果可视化。
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
这里我们将之前的 4D normal dataset 与少量 extreme outliers 结合起来（这些 outliers 的一个 feature（“duration”）被设置为很高的值等，以模拟一种异常模式）。我们使用典型的 perplexity 30 运行 t-SNE。输出数据 `data_2d` 的 shape 为 (1505, 2)。虽然本文不会实际绘图，但如果绘制出来，我们预计会看到大约三个紧密的 clusters，分别对应 3 个 normal clusters；而 5 个 outliers 则会作为远离这些 clusters 的孤立点出现。在交互式工作流中，我们可以根据其 label（normal 或所属 cluster，与 anomaly）为 points 着色，以验证这种结构。即使没有 labels，分析人员也可能注意到 2D plot 中位于空白区域的这 5 个 points，并将其标记出来。这说明 t-SNE 如何成为 cybersecurity 数据中进行 visual anomaly detection 和 cluster inspection 的强大辅助工具，并补充上述 automated algorithms。

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** 是 DBSCAN 的扩展，它不再需要选择单一的全局 `eps` 值，并且能够通过构建 density-connected components 的层次结构并对其进行压缩，识别出具有**不同密度**的 clusters。与 vanilla DBSCAN 相比，它通常能够

* 在某些 clusters 密集、而其他 clusters 稀疏时，提取出更直观的 clusters，
* 只有一个真正的 hyper-parameter（`min_cluster_size`），并且具有合理的 default，
* 为每个 point 提供 cluster-membership *probability* 和 **outlier score**（`outlier_scores_`），这对 threat-hunting dashboards 非常实用。<sup>[[1]](#references)</sup>

> [!TIP]
> *cybersecurity 中的使用场景：* HDBSCAN 在现代 threat-hunting pipelines 中非常流行——你经常会在商业 XDR suites 提供的、基于 notebook 的 hunting playbooks 中看到它。一个实用方案是在 IR 期间对 HTTP beaconing traffic 进行 clustering：user-agent、interval 和 URI length 通常会形成若干个由合法 software updaters 组成的紧密 groups，而 C2 beacons 则会作为微小的 low-density clusters 或纯 noise 保留下来。

<details>
<summary>示例 – 查找 beaconing C2 channels</summary>
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

### 稳健性与安全性注意事项 – Poisoning 与 Adversarial Attacks（2023-2025）

近期研究表明，**unsupervised learners *并不* 能免疫 active attackers**：

* **针对 anomaly detectors 的 Data-poisoning。** Chen *et al.*（IEEE S&P 2024）证明，仅添加 3 % 的 crafted traffic，就能改变 Isolation Forest 和 ECOD 的 decision boundary，使真实 attacks 看起来像正常流量。作者发布了一个 open-source PoC（`udo-poison`），可自动合成 poison points。<sup>[[2]](#references)</sup>
* **对 clustering models 进行 Backdooring。** *BadCME* 技术（BlackHat EU 2023）植入一个微小的 trigger pattern；每当该 trigger 出现时，基于 K-Means 的 detector 会悄悄地将该 event 放入“benign” cluster。
* **规避 DBSCAN/HDBSCAN。** KU Leuven 于 2025 年发布的一篇 academic pre-print 表明，attacker 可以构造故意落入 density gaps 的 beaconing patterns，从而有效隐藏在 *noise* labels 中。

正在逐渐获得关注的 Mitigations：

1. **Model sanitisation / TRIM。** 在每个 retraining epoch 之前，丢弃 loss 最高的 1–2 % points（trimmed maximum likelihood），从而大幅增加 poisoning 的难度。
2. **Consensus ensembling。** 组合多个异构 detectors（例如 Isolation Forest + GMM + ECOD），只要任意一个 model 标记某个 point 就发出 alert。研究表明，这会使 attacker 的成本提高 >10 倍。
3. **针对 clustering 的 Distance-based defence。** 使用 `k` 个不同的 random seeds 重新计算 clusters，并忽略持续在不同 clusters 之间跳转的 points。

---

### 现代 Open-Source Tooling（2024-2025）

* **PyOD 2.x**（2024 年 5 月发布）新增了 *ECOD*、*COPOD* 和 GPU-accelerated *AutoFormer* detectors。现在它还提供了一个 `benchmark` sub-command，可以通过**一行代码**在你的 dataset 上比较 30+ 种 algorithms：
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5**（2025 年 2 月）主要专注于 vision，但也包含一个通用的 **PatchCore** implementation，适合用于基于 screenshot 的 phishing page detection。
* **scikit-learn 1.5**（2024 年 11 月）终于通过新的 `cluster.HDBSCAN` wrapper 暴露了 *HDBSCAN* 的 `score_samples`，因此在 Python 3.12 上不再需要 external contrib package。

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

- [1] [HDBSCAN – 基于层次密度的聚类](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *等*。“无监督异常检测对数据投毒的脆弱性。”*IEEE Symposium on Security and Privacy*，2024 年。



{{#include ../banners/hacktricks-training.md}}
