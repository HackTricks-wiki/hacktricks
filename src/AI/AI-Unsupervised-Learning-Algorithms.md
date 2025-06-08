# 无监督学习算法

{{#include ../banners/hacktricks-training.md}}

## 无监督学习

无监督学习是一种机器学习类型，其中模型在没有标记响应的数据上进行训练。目标是发现数据中的模式、结构或关系。与监督学习不同，监督学习模型从标记示例中学习，而无监督学习算法则处理未标记的数据。
无监督学习通常用于聚类、降维和异常检测等任务。它可以帮助发现数据中的隐藏模式，将相似的项目分组，或在保留数据基本特征的同时减少数据的复杂性。

### K均值聚类

K均值是一种基于质心的聚类算法，通过将每个点分配给最近的聚类均值，将数据划分为K个聚类。该算法的工作流程如下：
1. **初始化**：选择K个初始聚类中心（质心），通常是随机选择或通过更智能的方法如k-means++。
2. **分配**：根据距离度量（例如，欧几里得距离）将每个数据点分配给最近的质心。
3. **更新**：通过取分配给每个聚类的所有数据点的均值重新计算质心。
4. **重复**：重复步骤2-3，直到聚类分配稳定（质心不再显著移动）。

> [!TIP]
> *在网络安全中的用例：* K均值用于通过聚类网络事件进行入侵检测。例如，研究人员将K均值应用于KDD Cup 99入侵数据集，发现它有效地将流量划分为正常与攻击聚类。在实践中，安全分析师可能会聚类日志条目或用户行为数据，以找到相似活动的组；任何不属于良好形成聚类的点可能表明异常（例如，一个新的恶意软件变种形成自己的小聚类）。K均值还可以通过根据行为特征或特征向量对二进制文件进行分组来帮助恶意软件家族分类。

#### K的选择
聚类的数量（K）是一个超参数，需要在运行算法之前定义。像肘部法则或轮廓系数等技术可以通过评估聚类性能来帮助确定K的适当值：

- **肘部法则**：绘制每个点到其分配的聚类质心的平方距离之和与K的关系图。寻找“肘部”点，在该点处，减少的速率急剧变化，指示适合的聚类数量。
- **轮廓系数**：计算不同K值的轮廓系数。较高的轮廓系数表示聚类定义更好。

#### 假设和限制

K均值假设**聚类是球形且大小相等**，这可能并不适用于所有数据集。它对质心的初始位置敏感，并可能收敛到局部最小值。此外，K均值不适合具有不同密度或非球形形状的数据集，以及具有不同尺度的特征。可能需要进行归一化或标准化等预处理步骤，以确保所有特征对距离计算的贡献相等。

<details>
<summary>示例 -- 聚类网络事件
</summary>
下面我们模拟网络流量数据并使用K均值进行聚类。假设我们有连接持续时间和字节计数等特征的事件。我们创建3个“正常”流量的聚类和1个小聚类，代表攻击模式。然后我们运行K均值，看看它是否能将它们分开。
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
在这个例子中，K-Means 应该找到 4 个簇。小型攻击簇（持续时间异常高 ~200）理想情况下会形成自己的簇，因为它与正常簇的距离较远。我们打印簇的大小和中心以解释结果。在实际场景中，可以将少量点的簇标记为潜在异常，或检查其成员是否存在恶意活动。
</details>

### 层次聚类

层次聚类使用自下而上的（聚合）方法或自上而下的（分裂）方法构建簇的层次结构：

1. **聚合（自下而上）**：从每个数据点作为单独的簇开始，迭代地合并最近的簇，直到只剩下一个簇或满足停止标准。
2. **分裂（自上而下）**：从所有数据点在一个簇中开始，迭代地拆分簇，直到每个数据点都是自己的簇或满足停止标准。

聚合聚类需要定义簇间距离和链接标准，以决定合并哪些簇。常见的链接方法包括单链接（两个簇之间最近点的距离）、完全链接（最远点的距离）、平均链接等，距离度量通常是欧几里得距离。链接的选择会影响生成簇的形状。无需预先指定簇的数量 K；可以在所选级别“切割”树状图以获得所需数量的簇。

层次聚类生成一个树状图，显示不同粒度级别的簇之间的关系。可以在所需级别切割树状图以获得特定数量的簇。

> [!TIP]
> *网络安全中的用例：* 层次聚类可以将事件或实体组织成树，以发现关系。例如，在恶意软件分析中，聚合聚类可以根据行为相似性对样本进行分组，揭示恶意软件家族和变种的层次结构。在网络安全中，可以对 IP 流量进行聚类，并使用树状图查看流量的子分组（例如，按协议，然后按行为）。因为不需要提前选择 K，所以在探索未知攻击类别数量的新数据时非常有用。

#### 假设和限制

层次聚类不假设特定的簇形状，可以捕捉嵌套簇。它对于发现分类法或群体之间的关系（例如，根据家族子组对恶意软件进行分组）非常有用。它是确定性的（没有随机初始化问题）。一个关键优势是树状图，它提供了对数据聚类结构在所有尺度上的洞察——安全分析师可以决定适当的截止点以识别有意义的簇。然而，它在计算上是昂贵的（通常对于简单实现是 $O(n^2)$ 时间或更差），并且对于非常大的数据集不可行。它也是一种贪婪过程——一旦合并或拆分完成，就无法撤销，这可能导致早期发生错误时产生次优簇。离群值也可能影响某些链接策略（单链接可能导致“链式”效应，其中簇通过离群值链接）。

<details>
<summary>示例 -- 事件的聚合聚类
</summary>

我们将重用 K-Means 示例中的合成数据（3 个正常簇 + 1 个攻击簇），并应用聚合聚类。然后我们将说明如何获得树状图和簇标签。
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

### DBSCAN（基于密度的噪声应用空间聚类）

DBSCAN 是一种基于密度的聚类算法，它将紧密聚集在一起的点分为一组，同时将低密度区域的点标记为离群点。它特别适用于具有不同密度和非球形形状的数据集。

DBSCAN 通过定义两个参数来工作：
- **Epsilon (ε)**：被视为同一聚类的一部分的两个点之间的最大距离。
- **MinPts**：形成密集区域（核心点）所需的最小点数。

DBSCAN 识别核心点、边界点和噪声点：
- **核心点**：在 ε 距离内至少有 MinPts 邻居的点。
- **边界点**：在 ε 距离内靠近核心点但邻居少于 MinPts 的点。
- **噪声点**：既不是核心点也不是边界点的点。

聚类通过选择一个未访问的核心点开始，将其标记为新聚类，然后递归地添加所有从其密度可达的点（核心点及其邻居等）。边界点被添加到附近核心的聚类中。在扩展所有可达点后，DBSCAN 移动到另一个未访问的核心以开始新的聚类。未被任何核心到达的点仍然标记为噪声。

> [!TIP]
> *在网络安全中的用例：* DBSCAN 对于网络流量中的异常检测非常有用。例如，正常用户活动可能在特征空间中形成一个或多个密集聚类，而新颖的攻击行为则表现为分散的点，DBSCAN 将其标记为噪声（离群点）。它已被用于聚类网络流量记录，可以检测到端口扫描或拒绝服务流量作为稀疏的点区域。另一个应用是对恶意软件变种进行分组：如果大多数样本按家族聚类，但少数样本不适合任何地方，这些少数样本可能是零日恶意软件。标记噪声的能力意味着安全团队可以专注于调查这些离群点。

#### 假设和局限性

**假设与优势：** DBSCAN 不假设球形聚类——它可以找到任意形状的聚类（甚至链状或相邻聚类）。它根据数据密度自动确定聚类数量，并能有效地将离群点识别为噪声。这使得它在具有不规则形状和噪声的真实世界数据中非常强大。它对离群点具有鲁棒性（与 K-Means 不同，后者将其强行归入聚类）。当聚类具有大致均匀的密度时，它表现良好。

**局限性：** DBSCAN 的性能依赖于选择合适的 ε 和 MinPts 值。它可能在具有不同密度的数据上表现不佳——单一的 ε 无法同时适应密集和稀疏的聚类。如果 ε 太小，它会将大多数点标记为噪声；如果太大，聚类可能会错误合并。此外，DBSCAN 在非常大的数据集上可能效率低下（天真地为 $O(n^2)$，尽管空间索引可以有所帮助）。在高维特征空间中，“在 ε 内的距离”概念可能变得不那么有意义（维度诅咒），DBSCAN 可能需要仔细的参数调整，或者可能无法找到直观的聚类。尽管如此，像 HDBSCAN 这样的扩展解决了一些问题（如不同密度）。

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
在这个片段中，我们调整了 `eps` 和 `min_samples` 以适应我们的数据规模（特征单位为 15.0，并且需要 5 个点来形成一个簇）。DBSCAN 应该找到 2 个簇（正常流量簇）并将 5 个注入的异常值标记为噪声。我们输出簇的数量与噪声点的数量以验证这一点。在实际设置中，可以对 ε 进行迭代（使用 k-距离图启发式选择 ε）和 MinPts（通常设置为数据维度 + 1 作为经验法则）以找到稳定的聚类结果。明确标记噪声的能力有助于分离潜在的攻击数据以进行进一步分析。

</details>

### 主成分分析 (PCA)

PCA 是一种 **降维** 技术，它找到一组新的正交轴（主成分），捕捉数据中的最大方差。简单来说，PCA 将数据旋转并投影到一个新的坐标系中，使得第一个主成分 (PC1) 解释最大的方差，第二个主成分 (PC2) 解释与 PC1 正交的最大方差，依此类推。从数学上讲，PCA 计算数据协方差矩阵的特征向量——这些特征向量是主成分方向，相应的特征值指示每个主成分解释的方差量。它通常用于特征提取、可视化和噪声减少。

请注意，如果数据集维度包含 **显著的线性依赖或相关性**，这将是有用的。

PCA 通过识别数据的主成分来工作，这些主成分是最大方差的方向。PCA 涉及的步骤包括：
1. **标准化**：通过减去均值并将其缩放到单位方差来中心化数据。
2. **协方差矩阵**：计算标准化数据的协方差矩阵，以了解特征之间的关系。
3. **特征值分解**：对协方差矩阵进行特征值分解，以获得特征值和特征向量。
4. **选择主成分**：按降序排列特征值，并选择与最大特征值对应的前 K 个特征向量。这些特征向量形成新的特征空间。
5. **转换数据**：使用所选的主成分将原始数据投影到新的特征空间。
PCA 广泛用于数据可视化、噪声减少，以及作为其他机器学习算法的预处理步骤。它有助于在保留数据基本结构的同时减少数据的维度。

#### 特征值和特征向量

特征值是一个标量，指示其对应特征向量捕获的方差量。特征向量表示特征空间中数据变化最大的方向。

假设 A 是一个方阵，v 是一个非零向量，使得： `A * v = λ * v`
其中：
- A 是一个方阵，如 [ [1, 2], [2, 1]]（例如，协方差矩阵）
- v 是一个特征向量（例如，[1, 1]）

那么，`A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`，这将是特征值 λ 乘以特征向量 v，使得特征值 λ = 3。

#### PCA 中的特征值和特征向量

让我们用一个例子来解释这一点。假设你有一个包含大量 100x100 像素灰度图像的数据集。每个像素可以视为一个特征，因此每张图像有 10,000 个特征（或每张图像的 10,000 个分量的向量）。如果你想使用 PCA 降低这个数据集的维度，你将遵循以下步骤：

1. **标准化**：通过从数据集中减去每个特征（像素）的均值来中心化数据。
2. **协方差矩阵**：计算标准化数据的协方差矩阵，捕捉特征（像素）如何共同变化。
- 请注意，两个变量（在这种情况下是像素）之间的协方差指示它们共同变化的程度，因此这里的想法是找出哪些像素倾向于以线性关系一起增加或减少。
- 例如，如果像素 1 和像素 2 倾向于一起增加，它们之间的协方差将是正的。
- 协方差矩阵将是一个 10,000x10,000 的矩阵，其中每个条目表示两个像素之间的协方差。
3. **求解特征值方程**：要解决的特征值方程是 `C * v = λ * v`，其中 C 是协方差矩阵，v 是特征向量，λ 是特征值。可以使用以下方法求解：
- **特征值分解**：对协方差矩阵进行特征值分解，以获得特征值和特征向量。
- **奇异值分解 (SVD)**：或者，你可以使用 SVD 将数据矩阵分解为奇异值和向量，这也可以得到主成分。
4. **选择主成分**：按降序排列特征值，并选择与最大特征值对应的前 K 个特征向量。这些特征向量表示数据中最大方差的方向。

> [!TIP]
> *网络安全中的用例：* PCA 在安全中的一个常见用途是异常检测的特征减少。例如，一个具有 40 多个网络指标（如 NSL-KDD 特征）的入侵检测系统可以使用 PCA 将其减少到少数几个组件，以便于可视化或输入聚类算法。分析师可能会在前两个主成分的空间中绘制网络流量，以查看攻击是否与正常流量分开。PCA 还可以帮助消除冗余特征（如发送的字节与接收的字节如果它们相关）以使检测算法更强大和更快。

#### 假设和限制

PCA 假设 **方差的主轴是有意义的**——这是一种线性方法，因此它捕捉数据中的线性相关性。它是无监督的，因为它仅使用特征协方差。PCA 的优点包括噪声减少（小方差组件通常对应于噪声）和特征的去相关性。对于中等高维度，它在计算上是高效的，并且通常是其他算法的有用预处理步骤（以减轻维度诅咒）。一个限制是 PCA 仅限于线性关系——它不会捕捉复杂的非线性结构（而自编码器或 t-SNE 可能会）。此外，PCA 组件在原始特征方面可能难以解释（它们是原始特征的组合）。在网络安全中，必须谨慎：仅在低方差特征中造成微小变化的攻击可能不会出现在前几个主成分中（因为 PCA 优先考虑方差，而不一定是“有趣性”）。

<details>
<summary>示例 -- 降低网络数据的维度
</summary>

假设我们有多个特征的网络连接日志（例如，持续时间、字节、计数）。我们将生成一个合成的 4 维数据集（特征之间有一些相关性），并使用 PCA 将其降至 2 维以便于可视化或进一步分析。
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
在这里，我们将早期的正常流量聚类扩展，每个数据点增加了两个额外特征（数据包和错误），这些特征与字节和持续时间相关。然后使用PCA将4个特征压缩为2个主成分。我们打印解释的方差比率，这可能显示，例如，>95%的方差由2个成分捕获（意味着信息损失很小）。输出还显示数据形状从(1500, 4)减少到(1500, 2)。PCA空间中的前几个点作为示例给出。在实践中，可以绘制data_2d以直观检查聚类是否可区分。如果存在异常，可能会看到它作为一个位于PCA空间主聚类之外的点。因此，PCA有助于将复杂数据提炼成可供人类解释或作为其他算法输入的可管理形式。

### 高斯混合模型 (GMM)

高斯混合模型假设数据是由**几个具有未知参数的高斯（正态）分布的混合生成的**。本质上，它是一种概率聚类模型：它试图将每个点软性地分配给K个高斯成分之一。每个高斯成分k都有一个均值向量（μ_k）、协方差矩阵（Σ_k）和一个混合权重（π_k），表示该聚类的普遍性。与K-Means进行“硬”分配不同，GMM为每个点提供属于每个聚类的概率。

GMM拟合通常通过期望最大化（EM）算法完成：

- **初始化**：从均值、协方差和混合系数的初始猜测开始（或使用K-Means结果作为起点）。

- **E步（期望）**：给定当前参数，计算每个聚类对每个点的责任：本质上是`r_nk = P(z_k | x_n)`，其中z_k是指示点x_n聚类归属的潜变量。这是使用贝叶斯定理完成的，我们根据当前参数计算每个点属于每个聚类的后验概率。责任的计算如下：
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
其中：
- \( \pi_k \) 是聚类k的混合系数（聚类k的先验概率），
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) 是给定均值\( \mu_k \)和协方差\( \Sigma_k \)的点\( x_n \)的高斯概率密度函数。

- **M步（最大化）**：使用E步中计算的责任更新参数：
- 将每个均值μ_k更新为点的加权平均，其中权重为责任。
- 将每个协方差Σ_k更新为分配给聚类k的点的加权协方差。
- 将混合系数π_k更新为聚类k的平均责任。

- **迭代**E和M步骤，直到收敛（参数稳定或似然改进低于阈值）。

结果是一组高斯分布，共同建模整体数据分布。我们可以使用拟合的GMM通过将每个点分配给具有最高概率的高斯来进行聚类，或者保留概率以表示不确定性。还可以评估新点的似然性，以查看它们是否适合模型（对异常检测有用）。

> [!TIP]
> *网络安全中的用例：* GMM可以通过建模正常数据的分布来用于异常检测：在学习的混合下，任何概率非常低的点都被标记为异常。例如，您可以在合法网络流量特征上训练GMM；一个与任何学习的聚类不相似的攻击连接将具有低似然性。GMM还用于聚类活动，其中聚类可能具有不同的形状——例如，通过行为特征对用户进行分组，其中每个特征的特征可能类似于高斯，但具有自己的方差结构。另一个场景：在钓鱼检测中，合法电子邮件特征可能形成一个高斯聚类，已知的钓鱼形成另一个，而新的钓鱼活动可能显示为单独的高斯或相对于现有混合的低似然点。

#### 假设和限制

GMM是K-Means的推广，结合了协方差，因此聚类可以是椭球形的（不仅仅是球形）。如果协方差是完整的，它可以处理不同大小和形状的聚类。当聚类边界模糊时，软聚类是一个优势——例如，在网络安全中，一个事件可能具有多种攻击类型的特征；GMM可以通过概率反映这种不确定性。GMM还提供了数据的概率密度估计，有助于检测离群值（在所有混合成分下似然性低的点）。

缺点是，GMM需要指定成分数量K（尽管可以使用BIC/AIC等标准来选择）。EM有时可能收敛缓慢或到达局部最优，因此初始化很重要（通常多次运行EM）。如果数据实际上并不遵循高斯混合，模型可能不适合。还有一个风险是一个高斯收缩到仅覆盖一个离群值（尽管正则化或最小协方差界限可以缓解这一点）。

<details>
<summary>示例 -- 软聚类与异常分数
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
在这段代码中，我们使用3个高斯分布训练一个GMM，针对正常流量（假设我们知道3个合法流量的特征）。打印出的均值和协方差描述了这些聚类（例如，一个均值可能在[50,500]附近，对应于一个聚类的中心，等等）。然后我们测试一个可疑连接[duration=200, bytes=800]。predict_proba给出了该点属于这3个聚类的概率——我们预计这些概率会非常低或高度偏斜，因为[200,800]远离正常聚类。打印出整体的score_samples（对数似然）；一个非常低的值表明该点与模型不匹配，将其标记为异常。在实践中，可以在对数似然（或最大概率）上设置阈值，以决定一个点是否足够不可能被视为恶意。因此，GMM提供了一种原则性的方法来进行异常检测，并且还产生了承认不确定性的软聚类。

### 隔离森林

**隔离森林**是一种基于随机隔离点思想的集成异常检测算法。其原理是异常点数量少且不同，因此比正常点更容易被隔离。隔离森林构建许多二叉隔离树（随机决策树），随机划分数据。在树的每个节点，选择一个随机特征，并在该特征的最小值和最大值之间选择一个随机分割值。这个分割将数据分为两个分支。树的生长直到每个点被隔离在自己的叶子中，或者达到最大树高。

通过观察这些随机树中每个点的路径长度来执行异常检测——隔离该点所需的分割次数。直观上，异常（离群点）往往更快被隔离，因为随机分割更可能将离群点（位于稀疏区域）与密集聚类中的正常点分开。隔离森林根据所有树的平均路径长度计算异常分数：平均路径越短→越异常。分数通常归一化到[0,1]，其中1表示非常可能是异常。

> [!TIP]
> *网络安全中的用例：* 隔离森林已成功用于入侵检测和欺诈检测。例如，在主要包含正常行为的网络流量日志上训练一个隔离森林；该森林将为奇怪的流量（如使用不常见端口的IP或不寻常的数据包大小模式）生成短路径，标记其进行检查。因为它不需要标记攻击，所以适合检测未知攻击类型。它还可以部署在用户登录数据上，以检测账户接管（异常的登录时间或地点会迅速被隔离）。在一个用例中，隔离森林可能通过监控系统指标并在一组指标（CPU、网络、文件更改）的组合与历史模式看起来非常不同（短隔离路径）时生成警报，从而保护企业。

#### 假设和局限性

**优点**：隔离森林不需要分布假设；它直接针对隔离。它在高维数据和大数据集上效率高（构建森林的线性复杂度为$O(n\log n)$），因为每棵树仅使用特征的子集和分割来隔离点。它通常能很好地处理数值特征，并且比基于距离的方法更快，后者可能是$O(n^2)$。它还自动给出异常分数，因此您可以设置警报的阈值（或使用污染参数根据预期的异常比例自动决定截止点）。

**局限性**：由于其随机特性，结果在不同运行之间可能略有不同（尽管树的数量足够多时，这种差异很小）。如果数据有很多无关特征，或者异常在任何特征上没有明显区分，隔离可能效果不佳（随机分割可能偶然隔离正常点——然而，平均多棵树可以减轻这一点）。此外，隔离森林通常假设异常是少数（这在网络安全场景中通常是正确的）。

<details>
<summary>示例 -- 检测网络日志中的离群点
</summary>

我们将使用之前的测试数据集（包含正常和一些攻击点），运行一个隔离森林，看看它是否能分离攻击。我们假设我们预计~15%的数据是异常的（用于演示）。
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
在这段代码中，我们用100棵树实例化了`IsolationForest`并设置`contamination=0.15`（这意味着我们预计大约有15%的异常；模型将设置其分数阈值，使得~15%的点被标记）。我们在包含正常和攻击点混合的`X_test_if`上进行拟合（注意：通常你会在训练数据上进行拟合，然后在新数据上使用预测，但这里为了说明我们在同一组上进行拟合和预测，以直接观察结果）。

输出显示了前20个点的预测标签（其中-1表示异常）。我们还打印了总共检测到的异常数量和一些示例异常分数。我们预计大约120个点中有18个会被标记为-1（因为污染率为15%）。如果我们的20个攻击样本确实是最偏离的，大多数应该出现在这些-1预测中。异常分数（Isolation Forest的决策函数）对于正常点较高，对于异常点较低（更负）——我们打印了一些值以查看分离情况。在实践中，人们可能会按分数对数据进行排序，以查看顶级异常并进行调查。因此，Isolation Forest提供了一种有效的方法来筛选大量未标记的安全数据，并挑选出最不规则的实例以供人工分析或进一步的自动审查。

### t-SNE (t-分布随机邻域嵌入)

**t-SNE**是一种非线性降维技术，专门用于在2或3维中可视化高维数据。它将数据点之间的相似性转换为联合概率分布，并试图在低维投影中保留局部邻域的结构。简单来说，t-SNE将点放置在（例如）2D中，使得相似的点（在原始空间中）最终靠近在一起，而不相似的点则以高概率远离。

该算法有两个主要阶段：

1. **计算高维空间中的成对亲和度：** 对于每对点，t-SNE计算选择该对作为邻居的概率（这是通过在每个点上中心化高斯分布并测量距离来完成的——困惑度参数影响考虑的有效邻居数量）。
2. **计算低维（例如2D）空间中的成对亲和度：** 最初，点在2D中随机放置。t-SNE为该图中的距离定义了类似的概率（使用学生t分布核，其尾部比高斯分布更重，以允许远离的点有更多自由）。
3. **梯度下降：** t-SNE然后迭代地在2D中移动点，以最小化高维亲和度分布和低维分布之间的Kullback–Leibler（KL）散度。这使得2D排列尽可能反映高维结构——在原始空间中接近的点将相互吸引，而远离的点将相互排斥，直到找到平衡。

结果通常是一个视觉上有意义的散点图，其中数据中的聚类变得明显。

> [!TIP]
> *在网络安全中的用例：* t-SNE通常用于**可视化高维安全数据以供人工分析**。例如，在安全运营中心，分析师可以使用具有数十个特征（端口号、频率、字节计数等）的事件数据集，并使用t-SNE生成2D图。攻击可能在该图中形成自己的聚类或与正常数据分开，从而更容易识别。它已被应用于恶意软件数据集，以查看恶意软件家族的分组，或在网络入侵数据中，不同攻击类型明显聚类，指导进一步调查。基本上，t-SNE提供了一种查看网络数据结构的方法，否则将难以理解。

#### 假设和局限性

t-SNE非常适合视觉发现模式。它可以揭示其他线性方法（如PCA）可能无法发现的聚类、子聚类和异常值。它已在网络安全研究中用于可视化复杂数据，如恶意软件行为特征或网络流量模式。由于它保留了局部结构，因此在显示自然分组方面表现良好。

然而，t-SNE的计算负担较重（大约为$O(n^2)$），因此对于非常大的数据集可能需要抽样。它还有超参数（困惑度、学习率、迭代次数），这些参数可能会影响输出——例如，不同的困惑度值可能会在不同的尺度上揭示聚类。t-SNE图有时可能被误解——图中的距离在全局上并不直接有意义（它关注局部邻域，有时聚类可能看起来人为地分开）。此外，t-SNE主要用于可视化；它并不提供直接的方法来投影新数据点而无需重新计算，并且不适合用作预测建模的预处理（UMAP是一个解决这些问题并具有更快速度的替代方案）。

<details>
<summary>示例 -- 可视化网络连接
</summary>

我们将使用t-SNE将多特征数据集降维到2D。为了说明，我们取之前的4D数据（其中有3个正常流量的自然聚类）并添加一些异常点。然后我们运行t-SNE并（概念上）可视化结果。
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
在这里，我们将之前的4D正常数据集与少量极端离群值结合在一起（离群值有一个特征（“持续时间”）设置得非常高等，以模拟一种奇怪的模式）。我们以典型的困惑度30运行t-SNE。输出的data_2d形状为(1505, 2)。我们实际上不会在本文中绘图，但如果我们这样做，我们预计会看到大约三个紧密的簇，分别对应于3个正常簇，而5个离群值则作为远离这些簇的孤立点出现。在交互式工作流程中，我们可以根据它们的标签（正常或哪个簇，与异常）为点上色，以验证这种结构。即使没有标签，分析师也可能会注意到这5个点在2D图上处于空白空间中并标记它们。这表明t-SNE可以成为网络安全数据中视觉异常检测和簇检查的强大辅助工具，补充上述自动化算法。

</details>


{{#include ../banners/hacktricks-training.md}}
