# Unsupervised Learning Algorithms

{#include ../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}

## Unsupervised Learning

Unsupervised learning is a type of machine learning where the model is trained on data without labeled responses. The goal is to find patterns, structures, or relationships within the data. Unlike supervised learning, where the model learns from labeled examples, unsupervised learning algorithms work with unlabeled data.
Unsupervised learning is often used for tasks such as clustering, dimensionality reduction, and anomaly detection. It can help discover hidden patterns in data, group similar items together, or reduce the complexity of the data while preserving its essential features.


### K-Means Clustering

K-Means is a centroid-based clustering algorithm that partitions data into K clusters by assigning each point to the nearest cluster mean. The algorithm works as follows:
1. **Initialization**: Choose K initial cluster centers (centroids), often randomly or via smarter methods like k-means++
2. **Assignment**: Assign each data point to the nearest centroid based on a distance metric (e.g., Euclidean distance).
3. **Update**: Recalculate the centroids by taking the mean of all data points assigned to each cluster.
4. **Repeat**: Steps 2–3 are repeated until cluster assignments stabilize (centroids no longer move significantly).

> [!TIP]
> *Use cases in cybersecurity:* K-Means is used for intrusion detection by clustering network events. For example, researchers applied K-Means to the KDD Cup 99 intrusion dataset and found it effectively partitioned traffic into normal vs. attack clusters. In practice, security analysts might cluster log entries or user behavior data to find groups of similar activity; any points that don’t belong to a well-formed cluster might indicate anomalies (e.g. a new malware variant forming its own small cluster). K-Means can also help malware family classification by grouping binaries based on behavior profiles or feature vectors.

#### Selection of K
The number of clusters (K) is a hyperparameter that needs to be defined before running the algorithm. Techniques like the Elbow Method or Silhouette Score can help determine an appropriate value for K by evaluating the clustering performance:

- **Elbow Method**: Plot the sum of squared distances from each point to its assigned cluster centroid as a function of K. Look for an "elbow" point where the rate of decrease sharply changes, indicating a suitable number of clusters.
- **Silhouette Score**: Calculate the silhouette score for different values of K. A higher silhouette score indicates better-defined clusters.

#### Assumptions and Limitations

K-Means assumes that **clusters are spherical and equally sized**, which may not hold true for all datasets. It is sensitive to the initial placement of centroids and can converge to local minima. Additionally, K-Means is not suitable for datasets with varying densities or non-globular shapes and features with different scales. Preprocessing steps like normalization or standardization may be necessary to ensure that all features contribute equally to the distance calculations.

<details>
<summary>Example -- Clustering Network Events
</summary>
Below we simulate network traffic data and use K-Means to cluster it. Suppose we have events with features like connection duration and byte count. We create 3 clusters of “normal” traffic and 1 small cluster representing an attack pattern. Then we run K-Means to see if it separates them.

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

In this example, K-Means should find 4 clusters. The small attack cluster (with unusually high duration ~200) will ideally form its own cluster given its distance from normal clusters. We print the cluster sizes and centers to interpret the results. In a real scenario, one could label the cluster with few points as potential anomalies or inspect its members for malicious activity.
</details>

### Hierarchical Clustering

Hierarchical clustering builds a hierarchy of clusters using either a bottom-up (agglomerative) approach or a top-down (divisive) approach:

1. **Agglomerative (Bottom-Up)**: Start with each data point as a separate cluster and iteratively merge the closest clusters until a single cluster remains or a stopping criterion is met.
2. **Divisive (Top-Down)**: Start with all data points in a single cluster and iteratively split the clusters until each data point is its own cluster or a stopping criterion is met.

Agglomerative clustering requires a definition of inter-cluster distance and a linkage criterion to decide which clusters to merge. Common linkage methods include single linkage (distance of closest points between two clusters), complete linkage (distance of farthest points), average linkage, etc., and the distance metric is often Euclidean. The choice of linkage affects the shape of clusters produced. There is no need to pre-specify the number of clusters K; you can “cut” the dendrogram at a chosen level to get the desired number of clusters.

Hierarchical clustering produces a dendrogram, a tree-like structure that shows the relationships between clusters at different levels of granularity. The dendrogram can be cut at a desired level to obtain a specific number of clusters.

> [!TIP]
> *Use cases in cybersecurity:* Hierarchical clustering can organize events or entities into a tree to spot relationships. For example, in malware analysis, agglomerative clustering could group samples by behavioral similarity, revealing a hierarchy of malware families and variants. In network security, one might cluster IP traffic flows and use the dendrogram to see subgroupings of traffic (e.g., by protocol, then by behavior). Because you don’t need to choose K upfront, it’s useful when exploring new data for which the number of attack categories is unknown.

#### Assumptions and Limitations

Hierarchical clustering does not assume a particular cluster shape and can capture nested clusters. It’s useful for discovering taxonomy or relations among groups (e.g., grouping malware by family subgroups). It’s deterministic (no random initialization issues). A key advantage is the dendrogram, which provides insight into the data’s clustering structure at all scales – security analysts can decide an appropriate cutoff to identify meaningful clusters. However, it is computationally expensive (typically $O(n^2)$ time or worse for naive implementations) and not feasible for very large datasets. It’s also a greedy procedure – once a merge or split is done, it can’t be undone, which may lead to suboptimal clusters if a mistake happens early. Outliers can also affect some linkage strategies (single-link can cause the “chaining” effect where clusters link via outliers).

<details>
<summary>Example -- Agglomerative Clustering of Events
</summary>

We’ll reuse the synthetic data from the K-Means example (3 normal clusters + 1 attack cluster) and apply agglomerative clustering. We then illustrate how to obtain a dendrogram and cluster labels.

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

DBSCAN is a density-based clustering algorithm that groups together points that are closely packed together while marking points in low-density regions as outliers. It is particularly useful for datasets with varying densities and non-spherical shapes.

DBSCAN works by defining two parameters:
- **Epsilon (ε)**: The maximum distance between two points to be considered part of the same cluster.
- **MinPts**: The minimum number of points required to form a dense region (core point).

DBSCAN identifies core points, border points, and noise points:
- **Core Point**: A point with at least MinPts neighbors within ε distance.
- **Border Point**: A point that is within ε distance of a core point but has fewer than MinPts neighbors.
- **Noise Point**: A point that is neither a core point nor a border point.

Clustering proceeds by picking an unvisited core point, marking it as a new cluster, then recursively adding all points density-reachable from it (core points and their neighbors, etc.). Border points get added to the cluster of a nearby core. After expanding all reachable points, DBSCAN moves to another unvisited core to start a new cluster. Points not reached by any core remain labeled as noise.

> [!TIP]
> *Use cases in cybersecurity:* DBSCAN is useful for anomaly detection in network traffic. For instance, normal user activity might form one or more dense clusters in feature space, while novel attack behaviors appear as scattered points that DBSCAN will label as noise (outliers). It has been used to cluster network flow records, where it can detect port scans or denial-of-service traffic as sparse regions of points. Another application is grouping malware variants: if most samples cluster by families but a few don’t fit anywhere, those few could be zero-day malware. The ability to flag noise means security teams can focus on investigating those outliers.

#### Assumptions and Limitations

**Assumptions & Strengths:**: DBSCAN does not assume spherical clusters – it can find arbitrarily shaped clusters (even chain-like or adjacent clusters). It automatically determines the number of clusters based on data density and can effectively identify outliers as noise. This makes it powerful for real-world data with irregular shapes and noise. It’s robust to outliers (unlike K-Means, which forces them into clusters). It works well when clusters have roughly uniform density.

**Limitations**: DBSCAN’s performance depends on choosing appropriate ε and MinPts values. It may struggle with data that has varying densities – a single ε cannot accommodate both dense and sparse clusters. If ε is too small, it labels most points as noise; too large, and clusters may merge incorrectly. Also, DBSCAN can be inefficient on very large datasets (naively $O(n^2)$, though spatial indexing can help). In high-dimensional feature spaces, the concept of “distance within ε” may become less meaningful (the curse of dimensionality), and DBSCAN may need careful parameter tuning or may fail to find intuitive clusters. Despite these, extensions like HDBSCAN address some issues (like varying density).

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

In this snippet, we tuned `eps` and `min_samples` to suit our data scale (15.0 in feature units, and requiring 5 points to form a cluster). DBSCAN should find 2 clusters (the normal traffic clusters) and flag the 5 injected outliers as noise. We output the number of clusters vs. noise points to verify this. In a real setting, one might iterate over ε (using a k-distance graph heuristic to choose ε) and MinPts (often set to around the data dimensionality + 1 as a rule of thumb) to find stable clustering results. The ability to explicitly label noise helps separate potential attack data for further analysis.

</details>

### Principal Component Analysis (PCA)

PCA is a technique for **dimensionality reduction** that finds a new set of orthogonal axes (principal components) which capture the maximum variance in the data. In simple terms, PCA rotates and projects the data onto a new coordinate system such that the first principal component (PC1) explains the largest possible variance, the second PC (PC2) explains the largest variance orthogonal to PC1, and so on. Mathematically, PCA computes the eigenvectors of the data’s covariance matrix – these eigenvectors are the principal component directions, and the corresponding eigenvalues indicate the amount of variance explained by each. It is often used for feature extraction, visualization, and noise reduction.

Note that this is useful if the dataset dimensions contains **significant linear dependencies or correlations**.

PCA works by identifying the principal components of the data, which are the directions of maximum variance. The steps involved in PCA are:
1. **Standardization**: Center the data by subtracting the mean and scaling it to unit variance.
2. **Covariance Matrix**: Compute the covariance matrix of the standardized data to understand the relationships between features.
3. **Eigenvalue Decomposition**: Perform eigenvalue decomposition on the covariance matrix to obtain the eigenvalues and eigenvectors.
4. **Select Principal Components**: Sort the eigenvalues in descending order and select the top K eigenvectors corresponding to the largest eigenvalues. These eigenvectors form the new feature space.
5. **Transform Data**: Project the original data onto the new feature space using the selected principal components.
PCA is widely used for data visualization, noise reduction, and as a preprocessing step for other machine learning algorithms. It helps reduce the dimensionality of the data while retaining its essential structure.

#### Eigenvalues and Eigenvectors

An eigenvalue is a scalar that indicates the amount of variance captured by its corresponding eigenvector. An eigenvector represents a direction in the feature space along which the data varies the most.

Imagine A is a square matrix, and v is a non-zero vector such that: `A * v = λ * v`
where:
- A is a square matrix like [ [1, 2], [2, 1]] (e.g., covariance matrix)
- v is an eigenvector (e.g., [1, 1])

Then, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` which will be the eigenvalue λ multiplied by the eigenvector v, making the eigenvalue λ = 3.

#### Eigenvalues and Eigenvectors in PCA

Let's explain this with an example. Imagine you have a dataset with a lot of grey scale pictures of faces of 100x100 pixels. Each pixel can be considered a feature, so you have 10,000 features per image (or a vector of 10000 components per image). If you want to reduce the dimensionality of this dataset using PCA, you would follow these steps:

1. **Standardization**: Center the data by subtracting the mean of each feature (pixel) from the dataset.
2. **Covariance Matrix**: Compute the covariance matrix of the standardized data, which captures how features (pixels) vary together.
  - Note that the covariance between two variables (pixels in this case) indicates how much they change together so the idea here is to find out which pixels tend to increase or decrease together with a linear relationship.
  - For example, if pixel 1 and pixel 2 tend to increase together, the covariance between them will be positive.
  - The covariance matrix will be a 10,000x10,000 matrix where each entry represents the covariance between two pixels.
3. **Solve the The eigenvalue equation**: The eigenvalue equation to solve is `C * v = λ * v` where C is the covariance matrix, v is the eigenvector, and λ is the eigenvalue. It can be solved using methods like:
  - **Eigenvalue Decomposition**: Perform eigenvalue decomposition on the covariance matrix to obtain the eigenvalues and eigenvectors.
  - **Singular Value Decomposition (SVD)**: Alternatively, you can use SVD to decompose the data matrix into singular values and vectors, which can also yield the principal components.
4. **Select Principal Components**: Sort the eigenvalues in descending order and select the top K eigenvectors corresponding to the largest eigenvalues. These eigenvectors represent the directions of maximum variance in the data.

> [!TIP]
> *Use cases in cybersecurity:* A common use of PCA in security is feature reduction for anomaly detection. For instance, an intrusion detection system with 40+ network metrics (like NSL-KDD features) can use PCA to reduce to a handful of components, summarizing the data for visualization or feeding into clustering algorithms. Analysts might plot network traffic in the space of the first two principal components to see if attacks separate from normal traffic. PCA can also help eliminate redundant features (like bytes sent vs. bytes received if they are correlated) to make detection algorithms more robust and faster.

#### Assumptions and Limitations

PCA assumes that **principal axes of variance are meaningful** – it’s a linear method, so it captures linear correlations in data. It’s unsupervised since it uses only the feature covariance. Advantages of PCA include noise reduction (small-variance components often correspond to noise) and decorrelation of features. It is computationally efficient for moderately high dimensions and often a useful preprocessing step for other algorithms (to mitigate curse of dimensionality). One limitation is that PCA is limited to linear relationships – it won’t capture complex nonlinear structure (whereas autoencoders or t-SNE might). Also, PCA components can be hard to interpret in terms of original features (they are combinations of original features). In cybersecurity, one must be cautious: an attack that only causes a subtle change in a low-variance feature might not show up in top PCs (since PCA prioritizes variance, not necessarily “interestingness”).

<details>
<summary>Example -- Reducing Dimensions of Network Data
</summary>

Suppose we have network connection logs with multiple features (e.g., durations, bytes, counts). We will generate a synthetic 4-dimensional dataset (with some correlation between features) and use PCA to reduce it to 2 dimensions for visualization or further analysis.

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

Here we took the earlier normal traffic clusters and extended each data point with two additional features (packets and errors) that correlate with bytes and duration. PCA is then used to compress the 4 features into 2 principal components. We print the explained variance ratio, which might show that, say, >95% of variance is captured by 2 components (meaning little information loss). The output also shows the data shape reducing from (1500, 4) to (1500, 2). The first few points in PCA space are given as an example. In practice, one could plot data_2d to visually check if the clusters are distinguishable. If an anomaly was present, one might see it as a point lying away from the main cluster in PCA-space. PCA thus helps distill complex data into a manageable form for human interpretation or as input to other algorithms.

</details>


### Gaussian Mixture Models (GMM)

A Gaussian Mixture Model assumes data is generated from a mixture of **several Gaussian (normal) distributions with unknown parameters**. In essence, it is a probabilistic clustering model: it tries to softly assign each point to one of K Gaussian components. Each Gaussian component k has a mean vector (μ_k), covariance matrix (Σ_k), and a mixing weight (π_k) that represents how prevalent that cluster is. Unlike K-Means which does “hard” assignments, GMM gives each point a probability of belonging to each cluster.

GMM fitting is typically done via the Expectation-Maximization (EM) algorithm:

- **Initialization**: Start with initial guesses for the means, covariances, and mixing coefficients (or use K-Means results as a starting point).

- **E-step (Expectation)**: Given current parameters, compute the responsibility of each cluster for each point: essentially `r_nk = P(z_k | x_n)` where z_k is the latent variable indicating cluster membership for point x_n. This is done using Bayes' theorem, where we compute the posterior probability of each point belonging to each cluster based on the current parameters. The responsibilities are computed as:
  ```math
  r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
  ```
  where:
  - \( \pi_k \) is the mixing coefficient for cluster k (prior probability of cluster k),
  - \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) is the Gaussian probability density function for point \( x_n \) given mean \( \mu_k \) and covariance \( \Sigma_k \).

- **M-step (Maximization)**: Update the parameters using the responsibilities computed in the E-step:
  - Update each mean μ_k as the weighted average of points, where weights are the responsibilities.
  - Update each covariance Σ_k as the weighted covariance of points assigned to cluster k.
  - Update mixing coefficients π_k as the average responsibility for cluster k.

- **Iterate** E and M steps until convergence (parameters stabilize or likelihood improvement is below a threshold).

The result is a set of Gaussian distributions that collectively model the overall data distribution. We can use the fitted GMM to cluster by assigning each point to the Gaussian with highest probability, or keep the probabilities for uncertainty. One can also evaluate the likelihood of new points to see if they fit the model (useful for anomaly detection).

> [!TIP]
> *Use cases in cybersecurity:* GMM can be used for anomaly detection by modeling the distribution of normal data: any point with very low probability under the learned mixture is flagged as anomaly. For example, you could train a GMM on legitimate network traffic features; an attack connection that doesn’t resemble any learned cluster would have a low likelihood. GMMs are also used to cluster activities where clusters might have different shapes – e.g., grouping users by behavior profiles, where each profile’s features might be Gaussian-like but with its own variance structure. Another scenario: in phishing detection, legitimate email features might form one Gaussian cluster, known phishing another, and new phishing campaigns might show up as either a separate Gaussian or as low likelihood points relative to the existing mixture.

#### Assumptions and Limitations

GMM is a generalization of K-Means that incorporates covariance, so clusters can be ellipsoidal (not just spherical). It handles clusters of different sizes and shapes if covariance is full. Soft clustering is an advantage when cluster boundaries are fuzzy – e.g., in cybersecurity, an event might have traits of multiple attack types; GMM can reflect that uncertainty with probabilities. GMM also provides a probabilistic density estimation of the data, useful for detecting outliers (points with low likelihood under all mixture components).

On the downside, GMM requires specifying the number of components K (though one can use criteria like BIC/AIC to select it). EM can sometimes converge slowly or to a local optimum, so initialization is important (often run EM multiple times). If the data doesn’t actually follow a mixture of Gaussians, the model may be a poor fit. There’s also a risk of one Gaussian shrinking to cover just an outlier (though regularization or minimum covariance bounds can mitigate that).


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

In this code, we train a GMM with 3 Gaussians on the normal traffic (assuming we know 3 profiles of legitimate traffic). The means and covariances printed describe these clusters (for instance, one mean might be around [50,500] corresponding to one cluster’s center, etc.). We then test a suspicious connection [duration=200, bytes=800]. The predict_proba gives the probability of this point belonging to each of the 3 clusters – we’d expect these probabilities to be very low or highly skewed since [200,800] lies far from the normal clusters. The overall score_samples (log-likelihood) is printed; a very low value indicates the point doesn’t fit the model well, flagging it as an anomaly. In practice, one could set a threshold on the log-likelihood (or on the max probability) to decide if a point is sufficiently unlikely to be considered malicious. GMM thus provides a principled way to do anomaly detection and also yields soft clusters that acknowledge uncertainty.
</details>

### Isolation Forest

**Isolation Forest** is an ensemble anomaly detection algorithm based on the idea of randomly isolating points. The principle is that anomalies are few and different, so they are easier to isolate than normal points. An Isolation Forest builds many binary isolation trees (random decision trees) that partition the data randomly. At each node in a tree, a random feature is selected and a random split value is chosen between the min and max of that feature for the data in that node. This split divides the data into two branches. The tree is grown until each point is isolated in its own leaf or a max tree height is reached.

Anomaly detection is performed by observing the path length of each point in these random trees – the number of splits required to isolate the point. Intuitively, anomalies (outliers) tend to be isolated quicker because a random split is more likely to separate an outlier (which lies in a sparse region) than it would a normal point in a dense cluster. The Isolation Forest computes an anomaly score from the average path length over all trees: shorter average path → more anomalous. Scores are usually normalized to [0,1] where 1 means very likely anomaly.

> [!TIP]
> *Use cases in cybersecurity:* Isolation Forests have been successfully used in intrusion detection and fraud detection. For example, train an Isolation Forest on network traffic logs mostly containing normal behavior; the forest will produce short paths for odd traffic (like an IP that uses an unheard-of port or an unusual packet size pattern), flagging it for inspection. Because it doesn’t require labeled attacks, it’s suitable for detecting unknown attack types. It can also be deployed on user login data to detect account takeovers (the anomalous login times or locations get isolated quickly). In one use-case, an Isolation Forest might protect an enterprise by monitoring system metrics and generating an alert when a combination of metrics (CPU, network, file changes) looks very different (short isolation paths) from historical patterns.

#### Assumptions and Limitations

**Advantages**: Isolation Forest doesn’t require a distribution assumption; it directly targets isolation. It’s efficient on high-dimensional data and large datasets (linear complexity $O(n\log n)$ for building the forest) since each tree isolates points with only a subset of features and splits. It tends to handle numerical features well and can be faster than distance-based methods which might be $O(n^2)$. It also automatically gives an anomaly score, so you can set a threshold for alerts (or use a contamination parameter to automatically decide a cutoff based on an expected anomaly fraction). 

**Limitations**: Because of its random nature, results can vary slightly between runs (though with sufficiently many trees this is minor). If the data has a lot of irrelevant features or if anomalies don’t strongly differentiate in any feature, the isolation might not be effective (random splits could isolate normal points by chance – however averaging many trees mitigates this). Also, Isolation Forest generally assumes anomalies are a small minority (which is usually true in cybersecurity scenarios).

<details>
<summary>Example --  Detecting Outliers in Network Logs
</summary>

We’ll use the earlier test dataset (which contains normal and some attack points) and run an Isolation Forest to see if it can separate the attacks. We’ll assume we expect ~15% of data to be anomalous (for demonstration).

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

In this code, we instantiate `IsolationForest` with 100 trees and set `contamination=0.15` (meaning we expect about 15% anomalies; the model will set its score threshold so that ~15% of points are flagged). We fit it on `X_test_if` which contains a mix of normal and attack points (note: normally you would fit on training data and then use predict on new data, but here for illustration we fit and predict on the same set to directly observe results).

The output shows the predicted labels for the first 20 points (where -1 indicates anomaly). We also print how many anomalies were detected in total and some example anomaly scores. We would expect roughly 18 out of 120 points to be labeled -1 (since contamination was 15%). If our 20 attack samples are truly the most outlying, most of them should appear in those -1 predictions. The anomaly score (Isolation Forest’s decision function) is higher for normal points and lower (more negative) for anomalies – we print a few values to see the separation. In practice, one might sort the data by score to see the top outliers and investigate them. Isolation Forest thus provides an efficient way to sift through large unlabeled security data and pick out the most irregular instances for human analysis or further automated scrutiny.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** is a nonlinear dimensionality reduction technique specifically designed for visualizing high-dimensional data in 2 or 3 dimensions. It converts similarities between data points to joint probability distributions and tries to preserve the structure of local neighborhoods in the lower-dimensional projection. In simpler terms, t-SNE places points in (say) 2D such that similar points (in the original space) end up close together and dissimilar points end up far apart with high probability.

The algorithm has two main stages:

1. **Compute pairwise affinities in high-dimensional space:** For each pair of points, t-SNE computes a probability that one would pick that pair as neighbors (this is done by centering a Gaussian distribution on each point and measuring distances – the perplexity parameter influences the effective number of neighbors considered).
2. **Compute pairwise affinities in low-dimensional (e.g. 2D) space:** Initially, points are placed randomly in 2D. t-SNE defines a similar probability for distances in this map (using a Student t-distribution kernel, which has heavier tails than Gaussian to allow distant points more freedom).
3. **Gradient Descent:** t-SNE then iteratively moves the points in 2D to minimize the Kullback–Leibler (KL) divergence between the high-D affinity distribution and the low-D one. This causes the 2D arrangement to reflect the high-D structure as much as possible – points that were close in original space will attract each other, and those far apart will repel, until a balance is found.

The result is often a visually meaningful scatter plot where clusters in the data become apparent.

> [!TIP]
> *Use cases in cybersecurity:* t-SNE is often used to **visualize high-dimensional security data for human analysis**. For example, in a security operations center, analysts could take an event dataset with dozens of features (port numbers, frequencies, byte counts, etc.) and use t-SNE to produce a 2D plot. Attacks might form their own clusters or separate from normal data in this plot, making them easier to identify. It has been applied to malware datasets to see groupings of malware families or to network intrusion data where different attack types cluster distinctly, guiding further investigation. Essentially, t-SNE provides a way to see structure in cyber data that would otherwise be inscrutable.

#### Assumptions and Limitations

t-SNE is great for visual discovery of patterns. It can reveal clusters, subclusters, and outliers that other linear methods (like PCA) might not. It has been used in cybersecurity research to visualize complex data like malware behavior profiles or network traffic patterns. Because it preserves local structure, it’s good at showing natural groupings.

However, t-SNE is computationally heavier (approximately $O(n^2)$) so it may require sampling for very large datasets. It also has hyperparameters (perplexity, learning rate, iterations) which can affect the output – e.g., different perplexity values might reveal clusters at different scales. t-SNE plots can sometimes be misinterpreted – distances in the map are not directly meaningful globally (it focuses on local neighborhood, sometimes clusters can appear artificially well-separated). Also, t-SNE is mainly for visualization; it doesn’t provide a straightforward way to project new data points without recomputing, and it’s not meant to be used as a preprocessing for predictive modeling (UMAP is an alternative that addresses some of these issues with faster speed).

<details>
<summary>Example -- Visualizing Network Connections
</summary>

We’ll use t-SNE to reduce a multi-feature dataset to 2D. For illustration, let’s take the earlier 4D data (which had 3 natural clusters of normal traffic) and add a few anomaly points. We then run t-SNE and (conceptually) visualize the results.

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

Here we combined our previous 4D normal dataset with a handful of extreme outliers (the outliers have one feature (“duration”) set very high, etc., to simulate an odd pattern). We run t-SNE with a typical perplexity of 30. The output data_2d has shape (1505, 2). We won’t actually plot in this text, but if we did, we’d expect to see perhaps three tight clusters corresponding to the 3 normal clusters, and the 5 outliers appearing as isolated points far from those clusters. In an interactive workflow, we could color the points by their label (normal or which cluster, vs anomaly) to verify this structure. Even without labels, an analyst might notice those 5 points sitting in empty space on the 2D plot and flag them. This shows how t-SNE can be a powerful aid to visual anomaly detection and cluster inspection in cybersecurity data, complementing the automated algorithms above.

</details>


{#include ../../../../../home/runner/work/HackTricks-Feed/HackTricks-Feed/src/banners/hacktricks-training.md}
