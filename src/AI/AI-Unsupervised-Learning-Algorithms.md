# Unsupervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Unsupervised Learning

Unsupervised learning मशीन लर्निंग का एक प्रकार है, जिसमें model को labeled responses के बिना data पर train किया जाता है। इसका लक्ष्य data के भीतर patterns, structures या relationships खोजना है। Supervised learning के विपरीत, जिसमें model labeled examples से सीखता है, unsupervised learning algorithms unlabeled data के साथ काम करते हैं।
Unsupervised learning का उपयोग अक्सर clustering, dimensionality reduction और anomaly detection जैसे tasks के लिए किया जाता है। यह data में छिपे patterns खोजने, समान items को एक साथ group करने या उसकी आवश्यक features को बनाए रखते हुए data की complexity कम करने में सहायता कर सकता है।


### K-Means Clustering

K-Means एक centroid-based clustering algorithm है, जो प्रत्येक point को निकटतम cluster mean को assign करके data को K clusters में विभाजित करता है। यह algorithm इस प्रकार काम करता है:
1. **Initialization**: K initial cluster centers (centroids) चुनें, अक्सर random तरीके से या k-means++ जैसी अधिक smart methods के माध्यम से।
2. **Assignment**: किसी distance metric (जैसे Euclidean distance) के आधार पर प्रत्येक data point को निकटतम centroid को assign करें।
3. **Update**: प्रत्येक cluster को assign किए गए सभी data points का mean लेकर centroids को फिर से calculate करें।
4. **Repeat**: Steps 2–3 को तब तक दोहराएं, जब तक cluster assignments स्थिर न हो जाएं (centroids में महत्वपूर्ण बदलाव न हो)।

> [!TIP]
> *Cybersecurity में उपयोग:* K-Means का उपयोग network events को cluster करके intrusion detection के लिए किया जाता है। उदाहरण के लिए, researchers ने KDD Cup 99 intrusion dataset पर K-Means लागू किया और पाया कि इसने traffic को normal और attack clusters में प्रभावी रूप से विभाजित किया। व्यवहार में, security analysts समान activity के groups खोजने के लिए log entries या user behavior data को cluster कर सकते हैं; जो points किसी अच्छी तरह से बने cluster में शामिल नहीं होते, वे anomalies का संकेत दे सकते हैं (जैसे किसी नए malware variant का अपना छोटा cluster बनाना)। K-Means behavior profiles या feature vectors के आधार पर binaries को group करके malware family classification में भी सहायता कर सकता है।

#### K का Selection
Clusters की संख्या (K) एक hyperparameter है, जिसे algorithm चलाने से पहले define करना आवश्यक है। Elbow Method या Silhouette Score जैसी techniques clustering performance का मूल्यांकन करके K के लिए उपयुक्त value निर्धारित करने में सहायता कर सकती हैं:

- **Elbow Method**: प्रत्येक point से उसके assigned cluster centroid तक की squared distances का sum, K के function के रूप में plot करें। उस "elbow" point को खोजें जहां decrease की rate में तेज बदलाव आता है, जो clusters की उपयुक्त संख्या का संकेत देता है।
- **Silhouette Score**: K की अलग-अलग values के लिए silhouette score calculate करें। अधिक silhouette score बेहतर-defined clusters का संकेत देता है।

#### Assumptions और Limitations

K-Means यह assume करता है कि **clusters spherical और समान आकार के होते हैं**, जो सभी datasets के लिए सही नहीं हो सकता। यह centroids की initial placement के प्रति sensitive है और local minima पर converge कर सकता है। इसके अतिरिक्त, K-Means अलग-अलग densities या non-globular shapes वाले datasets और अलग-अलग scales वाली features के लिए suitable नहीं है। Normalization या standardization जैसे preprocessing steps आवश्यक हो सकते हैं, ताकि सभी features distance calculations में समान रूप से योगदान दें।

<details>
<summary>Example -- Network Events की Clustering
</summary>
नीचे हम network traffic data को simulate करते हैं और उसे cluster करने के लिए K-Means का उपयोग करते हैं। मान लें कि हमारे पास connection duration और byte count जैसी features वाले events हैं। हम “normal” traffic के 3 clusters और attack pattern को दर्शाने वाला 1 छोटा cluster बनाते हैं। फिर हम K-Means चलाकर देखते हैं कि क्या यह उन्हें अलग कर पाता है।
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
इस उदाहरण में, K-Means को 4 clusters खोजने चाहिए। छोटा attack cluster (जिसकी duration असामान्य रूप से अधिक ~200 है) आदर्श रूप से normal clusters से अपनी दूरी के कारण अपना अलग cluster बनाएगा। परिणामों को समझने के लिए हम cluster sizes और centers प्रिंट करते हैं। वास्तविक स्थिति में, कम points वाले cluster को potential anomalies के रूप में label किया जा सकता है या malicious activity के लिए उसके members का निरीक्षण किया जा सकता है।
</details>

### Hierarchical Clustering

Hierarchical clustering bottom-up (agglomerative) approach या top-down (divisive) approach का उपयोग करके clusters की hierarchy बनाता है:

1. **Agglomerative (Bottom-Up)**: प्रत्येक data point को एक अलग cluster से शुरू करें और निकटतम clusters को बार-बार merge करें, जब तक कि एक single cluster शेष न रह जाए या stopping criterion पूरा न हो जाए।
2. **Divisive (Top-Down)**: सभी data points को एक single cluster में रखकर शुरू करें और clusters को बार-बार split करें, जब तक कि प्रत्येक data point अपना अलग cluster न बन जाए या stopping criterion पूरा न हो जाए।

Agglomerative clustering में inter-cluster distance की definition और यह तय करने के लिए linkage criterion आवश्यक होता है कि किन clusters को merge करना है। Common linkage methods में single linkage (दो clusters के बीच closest points की distance), complete linkage (farthest points की distance), average linkage आदि शामिल हैं, और distance metric अक्सर Euclidean होता है। Linkage का चुनाव बनाए गए clusters के आकार को प्रभावित करता है। Clusters की संख्या K को पहले से specify करने की आवश्यकता नहीं होती; desired number of clusters प्राप्त करने के लिए dendrogram को चुने गए level पर “cut” किया जा सकता है।

Hierarchical clustering एक dendrogram बनाता है, जो एक tree-like structure है और granularity के विभिन्न levels पर clusters के बीच संबंध दिखाता है। Specific number of clusters प्राप्त करने के लिए dendrogram को desired level पर cut किया जा सकता है।

> [!TIP]
> *cybersecurity में उपयोग:* Hierarchical clustering events या entities को एक tree में organize करके relationships पहचान सकता है। उदाहरण के लिए, malware analysis में agglomerative clustering behavioral similarity के आधार पर samples को group कर सकता है, जिससे malware families और variants की hierarchy सामने आती है। Network security में, IP traffic flows को cluster करके traffic के subgroupings (जैसे पहले protocol के आधार पर, फिर behavior के आधार पर) देखने के लिए dendrogram का उपयोग किया जा सकता है। चूंकि K को पहले से चुनने की आवश्यकता नहीं होती, इसलिए यह ऐसे नए data की exploration के लिए उपयोगी है जिसमें attack categories की संख्या अज्ञात हो।

#### Assumptions and Limitations

Hierarchical clustering किसी विशेष cluster shape को assume नहीं करता और nested clusters को capture कर सकता है। यह taxonomy या groups के बीच relations खोजने के लिए उपयोगी है (जैसे malware को family subgroups के आधार पर group करना)। यह deterministic है (random initialization से जुड़ी समस्याएं नहीं होतीं)। इसका एक प्रमुख लाभ dendrogram है, जो सभी scales पर data की clustering structure की जानकारी प्रदान करता है – security analysts meaningful clusters की पहचान करने के लिए उचित cutoff तय कर सकते हैं। हालांकि, यह computationally expensive है (naive implementations के लिए सामान्यतः $O(n^2)$ time या उससे अधिक) और बहुत बड़े datasets के लिए feasible नहीं है। यह एक greedy procedure भी है – merge या split हो जाने के बाद उसे undo नहीं किया जा सकता, जिससे शुरुआत में कोई गलती होने पर suboptimal clusters बन सकते हैं। Outliers कुछ linkage strategies को भी प्रभावित कर सकते हैं (single-link “chaining” effect पैदा कर सकता है, जिसमें clusters outliers के माध्यम से जुड़ जाते हैं)।

<details>
<summary>Example -- Agglomerative Clustering of Events
</summary>

हम K-Means example के synthetic data (3 normal clusters + 1 attack cluster) का फिर से उपयोग करेंगे और उस पर agglomerative clustering लागू करेंगे। इसके बाद हम दिखाएंगे कि dendrogram और cluster labels कैसे प्राप्त किए जाते हैं।
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

DBSCAN एक density-based clustering algorithm है, जो एक-दूसरे के बहुत पास स्थित points को एक साथ group करता है और low-density regions में स्थित points को outliers के रूप में चिह्नित करता है। यह विभिन्न densities और non-spherical shapes वाले datasets के लिए विशेष रूप से उपयोगी है।

DBSCAN दो parameters को परिभाषित करके काम करता है:
- **Epsilon (ε)**: दो points के बीच की maximum distance, जिसके आधार पर उन्हें एक ही cluster का हिस्सा माना जाता है।
- **MinPts**: एक dense region (core point) बनाने के लिए आवश्यक points की minimum संख्या।

DBSCAN core points, border points और noise points की पहचान करता है:
- **Core Point**: ऐसा point जिसके ε distance के भीतर कम-से-कम MinPts neighbors हों।
- **Border Point**: ऐसा point जो किसी core point के ε distance के भीतर हो, लेकिन जिसके neighbors की संख्या MinPts से कम हो।
- **Noise Point**: ऐसा point जो न तो core point हो और न ही border point।

Clustering प्रक्रिया में एक unvisited core point चुना जाता है, उसे एक नए cluster के रूप में चिह्नित किया जाता है, फिर उससे density-reachable सभी points (core points और उनके neighbors आदि) को recursively जोड़ा जाता है। Border points को किसी nearby core के cluster में जोड़ा जाता है। सभी reachable points को expand करने के बाद, DBSCAN एक नया cluster शुरू करने के लिए किसी अन्य unvisited core पर जाता है। किसी भी core से न पहुंच पाने वाले points को noise के रूप में label किया जाता है।

> [!TIP]
> *Use cases in cybersecurity:* DBSCAN network traffic में anomaly detection के लिए उपयोगी है। उदाहरण के लिए, सामान्य user activity feature space में एक या अधिक dense clusters बना सकती है, जबकि नए attack behaviors scattered points के रूप में दिखाई दे सकते हैं, जिन्हें DBSCAN noise (outliers) के रूप में label करेगा। इसका उपयोग network flow records को cluster करने के लिए किया गया है, जहां यह port scans या denial-of-service traffic को points के sparse regions के रूप में detect कर सकता है। एक अन्य application malware variants को group करना है: यदि अधिकांश samples families के आधार पर cluster हो जाएं, लेकिन कुछ samples किसी cluster में fit न हों, तो वे few samples zero-day malware हो सकते हैं। Noise को flag करने की क्षमता का अर्थ है कि security teams उन outliers की जांच पर ध्यान केंद्रित कर सकती हैं।

#### Assumptions and Limitations

**Assumptions & Strengths:**: DBSCAN spherical clusters को assume नहीं करता – यह arbitrarily shaped clusters (यहां तक कि chain-like या adjacent clusters) खोज सकता है। यह data density के आधार पर clusters की संख्या automatically निर्धारित करता है और outliers को noise के रूप में effectively identify कर सकता है। इससे यह irregular shapes और noise वाले real-world data के लिए powerful बनता है। यह outliers के प्रति robust है (K-Means के विपरीत, जो उन्हें clusters में force करता है)। यह तब अच्छी तरह काम करता है जब clusters की density लगभग uniform हो।

**Limitations**: DBSCAN का performance appropriate ε और MinPts values चुनने पर निर्भर करता है। अलग-अलग densities वाले data के साथ इसे कठिनाई हो सकती है – एक single ε dense और sparse दोनों clusters को accommodate नहीं कर सकता। यदि ε बहुत छोटा हो, तो यह अधिकांश points को noise के रूप में label कर देता है; बहुत बड़ा होने पर clusters गलत तरीके से merge हो सकते हैं। इसके अलावा, DBSCAN बहुत बड़े datasets पर inefficient हो सकता है (naively $O(n^2)$, हालांकि spatial indexing मदद कर सकता है)। High-dimensional feature spaces में “distance within ε” की concept कम meaningful हो सकती है (curse of dimensionality), और DBSCAN को careful parameter tuning की आवश्यकता हो सकती है या यह intuitive clusters खोजने में fail हो सकता है। इन सीमाओं के बावजूद, HDBSCAN जैसे extensions कुछ समस्याओं (जैसे varying density) को address करते हैं।

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
इस snippet में, हमने अपने data scale के अनुसार `eps` और `min_samples` को tuned किया (feature units में 15.0, और cluster बनाने के लिए 5 points आवश्यक)। DBSCAN को 2 clusters (normal traffic clusters) खोजने चाहिए और injected 5 outliers को noise के रूप में flag करना चाहिए। इसे verify करने के लिए हम clusters की संख्या और noise points की संख्या output करते हैं। वास्तविक setting में, stable clustering results खोजने के लिए कोई ε पर iterate कर सकता है (ε चुनने के लिए k-distance graph heuristic का उपयोग करके) और MinPts पर भी (rule of thumb के रूप में इसे अक्सर data dimensionality + 1 के आसपास set किया जाता है)। Noise को explicitly label करने की क्षमता आगे के analysis के लिए potential attack data को अलग करने में मदद करती है।

</details>

### Principal Component Analysis (PCA)

PCA **dimensionality reduction** की एक technique है, जो orthogonal axes (principal components) का एक नया set खोजती है और data में maximum variance को capture करती है। सरल शब्दों में, PCA data को एक नए coordinate system पर rotate और project करता है, ताकि पहला principal component (PC1) अधिकतम संभव variance को explain करे, दूसरा PC (PC2), PC1 के orthogonal रहते हुए, सबसे अधिक variance को explain करे, और इसी तरह आगे। Mathematical रूप से, PCA data के covariance matrix के eigenvectors compute करता है - ये eigenvectors principal component directions होते हैं, और corresponding eigenvalues प्रत्येक द्वारा explain की गई variance की मात्रा को दर्शाते हैं। इसका उपयोग अक्सर feature extraction, visualization और noise reduction के लिए किया जाता है।

ध्यान दें कि यह तब उपयोगी है जब dataset dimensions में **significant linear dependencies या correlations** हों।

PCA data के principal components की पहचान करके काम करता है, जो maximum variance की directions होती हैं। PCA में शामिल steps हैं:
1. **Standardization**: Mean घटाकर data को center करें और उसे unit variance तक scale करें।
2. **Covariance Matrix**: Features के बीच relationships को समझने के लिए standardized data की covariance matrix compute करें।
3. **Eigenvalue Decomposition**: Eigenvalues और eigenvectors प्राप्त करने के लिए covariance matrix पर eigenvalue decomposition करें।
4. **Select Principal Components**: Eigenvalues को descending order में sort करें और largest eigenvalues से corresponding top K eigenvectors चुनें। ये eigenvectors नया feature space बनाते हैं।
5. **Transform Data**: चुने गए principal components का उपयोग करके original data को नए feature space पर project करें।
PCA का व्यापक रूप से data visualization, noise reduction और अन्य machine learning algorithms के लिए preprocessing step के रूप में उपयोग किया जाता है। यह data की essential structure को बनाए रखते हुए उसकी dimensionality कम करने में मदद करता है।

#### Eigenvalues और Eigenvectors

Eigenvalue एक scalar है, जो अपने corresponding eigenvector द्वारा capture की गई variance की मात्रा दर्शाता है। Eigenvector feature space में उस direction को represent करता है, जिसके along data सबसे अधिक vary करता है।

मान लें कि A एक square matrix है और v एक non-zero vector है, जैसे: `A * v = λ * v`
जहाँ:
- A एक square matrix है, जैसे [ [1, 2], [2, 1]] (उदाहरण के लिए, covariance matrix)
- v एक eigenvector है (जैसे [1, 1])

तब, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` होगा, जो eigenvalue λ को eigenvector v से multiply करने के बराबर है; इसलिए eigenvalue λ = 3 है।

#### PCA में Eigenvalues और Eigenvectors

इसे एक example से समझते हैं। मान लें कि आपके पास 100x100 pixels वाली faces की बहुत-सी grey scale pictures का dataset है। प्रत्येक pixel को एक feature माना जा सकता है, इसलिए आपके पास प्रत्येक image के लिए 10,000 features (या प्रत्येक image के लिए 10000 components का एक vector) हैं। यदि आप PCA का उपयोग करके इस dataset की dimensionality कम करना चाहते हैं, तो आप ये steps follow करेंगे:

1. **Standardization**: Dataset में प्रत्येक feature (pixel) का mean घटाकर data को center करें।
2. **Covariance Matrix**: Standardized data की covariance matrix compute करें, जो यह capture करती है कि features (pixels) साथ-साथ कैसे vary करते हैं।
- ध्यान दें कि दो variables (इस मामले में pixels) के बीच covariance यह दर्शाता है कि वे साथ-साथ कितना change होते हैं; इसलिए यहाँ उद्देश्य यह पता लगाना है कि कौन-से pixels linear relationship के साथ साथ-साथ increase या decrease होते हैं।
- उदाहरण के लिए, यदि pixel 1 और pixel 2 साथ-साथ increase होते हैं, तो उनके बीच covariance positive होगी।
- Covariance matrix एक 10,000x10,000 matrix होगी, जिसमें प्रत्येक entry दो pixels के बीच covariance को represent करेगी।
3. **The eigenvalue equation को solve करें**: Solve की जाने वाली eigenvalue equation `C * v = λ * v` है, जहाँ C covariance matrix है, v eigenvector है और λ eigenvalue है। इसे इन methods का उपयोग करके solve किया जा सकता है:
- **Eigenvalue Decomposition**: Eigenvalues और eigenvectors प्राप्त करने के लिए covariance matrix पर eigenvalue decomposition करें।
- **Singular Value Decomposition (SVD)**: वैकल्पिक रूप से, आप data matrix को singular values और vectors में decompose करने के लिए SVD का उपयोग कर सकते हैं, जिससे principal components भी प्राप्त किए जा सकते हैं।
4. **Select Principal Components**: Eigenvalues को descending order में sort करें और largest eigenvalues से corresponding top K eigenvectors चुनें। ये eigenvectors data में maximum variance की directions को represent करते हैं।

> [!TIP]
> *Cybersecurity में use cases:* Security में PCA का एक common use anomaly detection के लिए feature reduction है। उदाहरण के लिए, 40+ network metrics (जैसे NSL-KDD features) वाले intrusion detection system में PCA का उपयोग करके data को कुछ components तक reduce किया जा सकता है, जिससे visualization के लिए या clustering algorithms में feed करने के लिए data का summary तैयार होता है। Analysts पहले दो principal components के space में network traffic को plot कर सकते हैं, ताकि यह देखा जा सके कि attacks normal traffic से अलग होते हैं या नहीं। PCA redundant features (जैसे bytes sent और bytes received, यदि वे correlated हों) को eliminate करने में भी मदद कर सकता है, जिससे detection algorithms अधिक robust और तेज बनते हैं।

#### Assumptions और Limitations

PCA यह assume करता है कि **principal axes of variance meaningful हैं** - यह एक linear method है, इसलिए data में linear correlations को capture करता है। यह unsupervised है, क्योंकि यह केवल feature covariance का उपयोग करता है। PCA के advantages में noise reduction (small-variance components अक्सर noise से correspond करते हैं) और features का decorrelation शामिल हैं। यह moderately high dimensions के लिए computationally efficient है और अक्सर अन्य algorithms के लिए एक उपयोगी preprocessing step होता है (curse of dimensionality को mitigate करने के लिए)। एक limitation यह है कि PCA linear relationships तक सीमित है - यह complex nonlinear structure को capture नहीं करेगा (जबकि autoencoders या t-SNE ऐसा कर सकते हैं)। इसके अलावा, PCA components को original features के संदर्भ में interpret करना कठिन हो सकता है (वे original features के combinations होते हैं)। Cybersecurity में सावधानी आवश्यक है: low-variance feature में केवल subtle change पैदा करने वाला attack top PCs में दिखाई नहीं दे सकता (क्योंकि PCA variance को prioritize करता है, आवश्यक नहीं कि “interestingness” को)।

<details>
<summary>Example -- Network Data की Dimensions कम करना
</summary>

मान लें कि हमारे पास कई features (जैसे durations, bytes, counts) वाले network connection logs हैं। हम कुछ correlated features के साथ एक synthetic 4-dimensional dataset generate करेंगे और visualization या आगे के analysis के लिए PCA का उपयोग करके इसे 2 dimensions तक reduce करेंगे।
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
यहाँ हमने पहले के सामान्य traffic clusters लिए और प्रत्येक data point में दो अतिरिक्त features (packets और errors) जोड़े, जो bytes और duration से correlate करते हैं। इसके बाद PCA का उपयोग करके 4 features को 2 principal components में compress किया जाता है। हम explained variance ratio print करते हैं, जो यह दिखा सकता है कि, उदाहरण के लिए, 2 components द्वारा >95% variance capture की गई है (अर्थात information loss बहुत कम है)। Output में data shape के (1500, 4) से (1500, 2) तक कम होने को भी दिखाया जाता है। PCA space में शुरुआती कुछ points उदाहरण के रूप में दिए गए हैं। व्यवहार में, clusters अलग-अलग पहचाने जा सकते हैं या नहीं, यह visually check करने के लिए `data_2d` को plot किया जा सकता है। यदि कोई anomaly मौजूद हो, तो वह PCA-space में main cluster से दूर स्थित point के रूप में दिखाई दे सकती है। इस प्रकार PCA complex data को human interpretation या अन्य algorithms के input के लिए manageable form में बदलने में मदद करता है।

</details>


### Gaussian Mixture Models (GMM)

A Gaussian Mixture Model मानता है कि data **unknown parameters वाले कई Gaussian (normal) distributions के mixture** से generate किया गया है। मूल रूप से, यह एक probabilistic clustering model है: यह प्रत्येक point को K Gaussian components में से किसी एक को softly assign करने का प्रयास करता है। प्रत्येक Gaussian component k का एक mean vector (μ_k), covariance matrix (Σ_k), और mixing weight (π_k) होता है, जो यह दर्शाता है कि वह cluster कितना prevalent है। K-Means के विपरीत, जो “hard” assignments करता है, GMM प्रत्येक point के प्रत्येक cluster से संबंधित होने की probability देता है।

GMM fitting आमतौर पर Expectation-Maximization (EM) algorithm के माध्यम से की जाती है:

- **Initialization**: means, covariances और mixing coefficients के लिए initial guesses से शुरुआत करें (या starting point के रूप में K-Means results का उपयोग करें)।

- **E-step (Expectation)**: वर्तमान parameters को देखते हुए, प्रत्येक point के लिए प्रत्येक cluster की responsibility compute करें: मूल रूप से `r_nk = P(z_k | x_n)`, जहाँ z_k वह latent variable है जो point x_n की cluster membership दर्शाता है। यह Bayes' theorem का उपयोग करके किया जाता है, जिसमें वर्तमान parameters के आधार पर प्रत्येक point के प्रत्येक cluster से संबंधित होने की posterior probability compute की जाती है। Responsibilities इस प्रकार compute की जाती हैं:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
जहाँ:
- \( \pi_k \) cluster k का mixing coefficient (cluster k की prior probability) है,
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) mean \( \mu_k \) और covariance \( \Sigma_k \) के आधार पर point \( x_n \) का Gaussian probability density function है।

- **M-step (Maximization)**: E-step में compute की गई responsibilities का उपयोग करके parameters update करें:
- प्रत्येक mean μ_k को points के weighted average के रूप में update करें, जहाँ weights responsibilities हैं।
- प्रत्येक covariance Σ_k को cluster k को assigned points के weighted covariance के रूप में update करें।
- Mixing coefficients π_k को cluster k के लिए average responsibility के रूप में update करें।

- Convergence तक E और M steps को **Iterate** करें (जब parameters stabilize हो जाएँ या likelihood improvement किसी threshold से कम हो जाए)।

इसका परिणाम Gaussian distributions का एक ऐसा set होता है, जो सामूहिक रूप से पूरे data distribution को model करता है। Fitted GMM का उपयोग प्रत्येक point को highest probability वाले Gaussian को assign करके clustering के लिए किया जा सकता है, या uncertainty के लिए probabilities को बनाए रखा जा सकता है। नए points के likelihood का evaluation भी किया जा सकता है, ताकि यह देखा जा सके कि वे model के अनुरूप हैं या नहीं (जो anomaly detection के लिए उपयोगी है)।

> [!TIP]
> *cybersecurity में उपयोग:* GMM का उपयोग normal data के distribution को model करके anomaly detection के लिए किया जा सकता है: learned mixture के अंतर्गत बहुत कम probability वाले किसी भी point को anomaly के रूप में flag किया जाता है। उदाहरण के लिए, आप legitimate network traffic features पर GMM train कर सकते हैं; ऐसा attack connection जो किसी भी learned cluster से resemble नहीं करता, उसका likelihood कम होगा। GMMs का उपयोग ऐसी activities को cluster करने के लिए भी किया जाता है जिनके clusters के shapes अलग-अलग हो सकते हैं – जैसे behavior profiles के आधार पर users को group करना, जहाँ प्रत्येक profile के features Gaussian-like हो सकते हैं, लेकिन उनकी variance structure अलग हो सकती है। एक अन्य scenario phishing detection है: legitimate email features एक Gaussian cluster, known phishing दूसरा cluster बना सकते हैं, और नए phishing campaigns या तो एक separate Gaussian के रूप में दिखाई दे सकते हैं या existing mixture की तुलना में low likelihood points के रूप में।

#### Assumptions and Limitations

GMM K-Means का generalization है, जिसमें covariance शामिल होता है, इसलिए clusters ellipsoidal हो सकते हैं (केवल spherical नहीं)। यदि covariance full हो, तो यह अलग-अलग sizes और shapes वाले clusters को handle कर सकता है। जब cluster boundaries fuzzy हों, तब soft clustering एक advantage है – उदाहरण के लिए, cybersecurity में किसी event में कई attack types के traits हो सकते हैं; GMM probabilities के माध्यम से उस uncertainty को दर्शा सकता है। GMM data का probabilistic density estimation भी प्रदान करता है, जो outliers detect करने के लिए उपयोगी है (ऐसे points जिनका सभी mixture components के अंतर्गत likelihood कम हो)।

दूसरी ओर, GMM में components की संख्या K specify करना आवश्यक है (हालाँकि इसे चुनने के लिए BIC/AIC जैसे criteria का उपयोग किया जा सकता है)। EM कभी-कभी धीरे converge कर सकता है या local optimum तक पहुँच सकता है, इसलिए initialization महत्वपूर्ण है (अक्सर EM को कई बार run किया जाता है)। यदि data वास्तव में Gaussian mixture का पालन नहीं करता, तो model का fit खराब हो सकता है। एक Gaussian के केवल किसी outlier को cover करने के लिए shrink होने का risk भी रहता है (हालाँकि regularization या minimum covariance bounds इसे कम कर सकते हैं)।


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
इस code में, हम normal traffic पर 3 Gaussians वाला एक GMM train करते हैं (यह मानते हुए कि हमें legitimate traffic के 3 profiles पता हैं)। Printed means और covariances इन clusters का वर्णन करते हैं (उदाहरण के लिए, एक mean लगभग [50,500] हो सकता है, जो किसी cluster के center को दर्शाता है)। इसके बाद हम एक suspicious connection [duration=200, bytes=800] को test करते हैं। predict_proba इस point के प्रत्येक 3 clusters से संबंधित होने की probability देता है – हम उम्मीद करेंगे कि ये probabilities बहुत कम या अत्यधिक skewed होंगी, क्योंकि [200,800] normal clusters से काफी दूर है। Overall score_samples (log-likelihood) print किया जाता है; बहुत कम value दर्शाती है कि point model में अच्छी तरह fit नहीं होता, इसलिए इसे anomaly के रूप में flag किया जाता है। व्यवहार में, यह तय करने के लिए log-likelihood (या max probability) पर threshold सेट किया जा सकता है कि कोई point malicious माने जाने के लिए पर्याप्त रूप से unlikely है या नहीं। इसलिए GMM anomaly detection का एक principled तरीका प्रदान करता है और साथ ही soft clusters भी देता है, जो uncertainty को स्वीकार करते हैं।
</details>

### Isolation Forest

**Isolation Forest** randomly points को isolate करने के विचार पर आधारित एक ensemble anomaly detection algorithm है। इसका principle यह है कि anomalies कम संख्या में और अलग-अलग होते हैं, इसलिए उन्हें normal points की तुलना में isolate करना आसान होता है। Isolation Forest कई binary isolation trees (random decision trees) बनाता है, जो data को randomly partition करते हैं। प्रत्येक tree के node पर, एक random feature select किया जाता है और उस node के data में उस feature के min और max के बीच एक random split value चुनी जाती है। यह split data को दो branches में विभाजित करता है। Tree तब तक grow किया जाता है, जब तक प्रत्येक point अपने अलग leaf में isolate न हो जाए या maximum tree height तक न पहुंच जाए।

Anomaly detection इन random trees में प्रत्येक point की path length देखकर किया जाता है – अर्थात point को isolate करने के लिए आवश्यक splits की संख्या। Intuitively, anomalies (outliers) जल्दी isolate हो जाते हैं, क्योंकि random split के लिए sparse region में स्थित outlier को अलग करना dense cluster में स्थित normal point की तुलना में अधिक संभावित होता है। Isolation Forest सभी trees में average path length से anomaly score compute करता है: छोटी average path → अधिक anomalous। Scores आमतौर पर [0,1] में normalized होते हैं, जहां 1 का अर्थ है कि anomaly होने की बहुत अधिक संभावना है।

> [!TIP]
> *cybersecurity में Use cases:* Isolation Forests का intrusion detection और fraud detection में सफलतापूर्वक उपयोग किया गया है। उदाहरण के लिए, ऐसे network traffic logs पर Isolation Forest train करें जिनमें अधिकतर normal behavior हो; forest odd traffic (जैसे ऐसा IP जो किसी unheard-of port का उपयोग करता हो या packet size का unusual pattern दिखाता हो) के लिए short paths बनाएगा और उसे inspection के लिए flag करेगा। क्योंकि इसके लिए labeled attacks की आवश्यकता नहीं होती, यह unknown attack types का पता लगाने के लिए उपयुक्त है। इसे user login data पर भी deploy किया जा सकता है, ताकि account takeovers का पता लगाया जा सके (anomalous login times या locations जल्दी isolate हो जाते हैं)। एक use-case में, Isolation Forest system metrics को monitor करके enterprise की सुरक्षा कर सकता है और तब alert generate कर सकता है जब metrics का कोई combination (CPU, network, file changes) historical patterns से बहुत अलग दिखे (short isolation paths)।

#### Assumptions and Limitations

**Advantages**: Isolation Forest को distribution assumption की आवश्यकता नहीं होती; यह सीधे isolation को target करता है। यह high-dimensional data और large datasets पर efficient है (forest बनाने के लिए linear complexity $O(n\log n)$), क्योंकि प्रत्येक tree points को केवल features के एक subset और splits का उपयोग करके isolate करता है। यह numerical features को अच्छी तरह handle करता है और distance-based methods की तुलना में faster हो सकता है, जिनकी complexity $O(n^2)$ हो सकती है। यह अपने-आप anomaly score भी देता है, इसलिए alerts के लिए threshold सेट किया जा सकता है (या expected anomaly fraction के आधार पर cutoff automatically तय करने के लिए contamination parameter का उपयोग किया जा सकता है)।

**Limitations**: इसकी random nature के कारण, अलग-अलग runs में results थोड़े बदल सकते हैं (हालांकि पर्याप्त trees होने पर यह अंतर मामूली होता है)। यदि data में बहुत-से irrelevant features हों या anomalies किसी भी feature में स्पष्ट रूप से अलग न दिखें, तो isolation प्रभावी नहीं हो सकता (random splits संयोग से normal points को isolate कर सकते हैं – हालांकि कई trees का averaging इस प्रभाव को कम करता है)। इसके अलावा, Isolation Forest आमतौर पर यह assume करता है कि anomalies एक छोटा minority group हैं (जो cybersecurity scenarios में आमतौर पर सही होता है)।

<details>
<summary>Example --  Network Logs में Outliers का पता लगाना
</summary>

हम पहले के test dataset (जिसमें normal और कुछ attack points शामिल हैं) का उपयोग करेंगे और यह देखने के लिए Isolation Forest चलाएंगे कि क्या यह attacks को अलग कर सकता है। हम मानेंगे कि data के लगभग 15% हिस्से के anomalous होने की अपेक्षा है (demonstration के लिए)।
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
इस code में, हम 100 trees के साथ `IsolationForest` को instantiate करते हैं और `contamination=0.15` सेट करते हैं (अर्थात हमें लगभग 15% anomalies की अपेक्षा है; model अपना score threshold इस तरह सेट करेगा कि लगभग 15% points flag हों)। हम इसे `X_test_if` पर fit करते हैं, जिसमें normal और attack points का मिश्रण है (ध्यान दें: सामान्यतः आप training data पर fit करते और फिर नए data पर predict का उपयोग करते, लेकिन यहां illustration के लिए हम सीधे परिणाम देखने हेतु उसी set पर fit और predict कर रहे हैं)।

आउटपुट पहले 20 points के predicted labels दिखाता है (जहां -1 anomaly को दर्शाता है)। हम कुल कितनी anomalies detect हुईं, यह भी print करते हैं और कुछ example anomaly scores भी दिखाते हैं। हम अपेक्षा करेंगे कि 120 points में से लगभग 18 को -1 label मिले (क्योंकि contamination 15% था)। यदि हमारे 20 attack samples वास्तव में सबसे अधिक outlying हैं, तो उनमें से अधिकांश इन -1 predictions में दिखाई देने चाहिए। Anomaly score (Isolation Forest का decision function) normal points के लिए अधिक और anomalies के लिए कम (अधिक negative) होता है - separation देखने के लिए हम कुछ values print करते हैं। व्यवहार में, top outliers देखने और उनकी जांच करने के लिए data को score के आधार पर sort किया जा सकता है। इस प्रकार, Isolation Forest बड़े unlabeled security data को छानने और human analysis या आगे की automated scrutiny के लिए सबसे irregular instances चुनने का एक efficient तरीका प्रदान करता है।
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** एक nonlinear dimensionality reduction technique है, जिसे विशेष रूप से high-dimensional data को 2 या 3 dimensions में visualize करने के लिए design किया गया है। यह data points के बीच की similarities को joint probability distributions में बदलता है और lower-dimensional projection में local neighborhoods की structure को preserve करने का प्रयास करता है। सरल शब्दों में, t-SNE points को (मान लें) 2D में इस तरह रखता है कि original space में similar points high probability के साथ एक-दूसरे के करीब और dissimilar points एक-दूसरे से दूर रहें।

Algorithm के तीन मुख्य stages हैं:

1. **Compute pairwise affinities in high-dimensional space:** प्रत्येक pair of points के लिए, t-SNE एक probability compute करता है कि कोई उस pair को neighbors के रूप में चुनेगा (यह प्रत्येक point पर Gaussian distribution को center करके और distances को measure करके किया जाता है - perplexity parameter considered neighbors की effective संख्या को प्रभावित करता है)।
2. **Compute pairwise affinities in low-dimensional (e.g. 2D) space:** शुरुआत में points को 2D में randomly place किया जाता है। t-SNE इस map में distances के लिए एक similar probability define करता है (Student t-distribution kernel का उपयोग करके, जिसकी tails Gaussian से heavier होती हैं ताकि distant points को अधिक freedom मिल सके)।
3. **Gradient Descent:** इसके बाद t-SNE high-D affinity distribution और low-D distribution के बीच Kullback–Leibler (KL) divergence को minimize करने के लिए 2D में points को iteratively move करता है। इससे 2D arrangement high-D structure को यथासंभव reflect करता है - original space में close points एक-दूसरे को attract करेंगे और दूर points repel करेंगे, जब तक कि एक balance न मिल जाए।

परिणाम अक्सर एक visually meaningful scatter plot होता है, जिसमें data के clusters स्पष्ट दिखाई देने लगते हैं।

> [!TIP]
> *Cybersecurity में use cases:* t-SNE का उपयोग अक्सर **human analysis के लिए high-dimensional security data को visualize करने** में किया जाता है। उदाहरण के लिए, security operations center में analysts dozens of features (port numbers, frequencies, byte counts आदि) वाले event dataset को ले सकते हैं और t-SNE का उपयोग करके 2D plot बना सकते हैं। इस plot में attacks अपने अलग clusters बना सकते हैं या normal data से अलग हो सकते हैं, जिससे उन्हें identify करना आसान हो जाता है। इसका उपयोग malware datasets पर malware families के groupings देखने के लिए या network intrusion data पर किया गया है, जहां different attack types अलग-अलग clusters बनाते हैं और आगे की investigation को guide करते हैं। मूल रूप से, t-SNE cyber data में ऐसी structure देखने का तरीका प्रदान करता है, जो अन्यथा समझना कठिन होता।

#### Assumptions and Limitations

t-SNE patterns की visual discovery के लिए बहुत अच्छा है। यह clusters, subclusters और outliers को reveal कर सकता है, जिन्हें अन्य linear methods (जैसे PCA) शायद न दिखा पाएं। इसका उपयोग cybersecurity research में malware behavior profiles या network traffic patterns जैसे complex data को visualize करने के लिए किया गया है। क्योंकि यह local structure को preserve करता है, इसलिए natural groupings दिखाने में यह उपयोगी है।

हालांकि, t-SNE computationally अधिक heavy है (लगभग $O(n^2)$), इसलिए बहुत बड़े datasets के लिए sampling की आवश्यकता हो सकती है। इसमें hyperparameters (perplexity, learning rate, iterations) भी होते हैं, जो output को प्रभावित कर सकते हैं - उदाहरण के लिए, अलग-अलग perplexity values अलग-अलग scales पर clusters दिखा सकती हैं। t-SNE plots का कभी-कभी गलत अर्थ निकाला जा सकता है - map में distances globally directly meaningful नहीं होते (यह local neighborhood पर focus करता है; कभी-कभी clusters artificially अच्छी तरह separated दिखाई दे सकते हैं)। इसके अलावा, t-SNE मुख्य रूप से visualization के लिए है; यह नए data points को recompute किए बिना project करने का straightforward तरीका प्रदान नहीं करता और predictive modeling के लिए preprocessing के रूप में उपयोग करने के लिए intended नहीं है (UMAP एक alternative है, जो faster speed के साथ इनमें से कुछ issues को address करता है)।

<details>
<summary>Example -- Network Connections को Visualize करना
</summary>

हम t-SNE का उपयोग multi-feature dataset को 2D में reduce करने के लिए करेंगे। Illustration के लिए, पहले के 4D data (जिसमें normal traffic के 3 natural clusters थे) को लेते हैं और उसमें कुछ anomaly points जोड़ते हैं। इसके बाद हम t-SNE run करेंगे और (conceptually) results को visualize करेंगे।
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
यहाँ हमने अपने पिछले 4D normal dataset को कुछ extreme outliers के साथ संयोजित किया है (इन outliers में एक feature (“duration”) को बहुत अधिक मान पर सेट किया गया है, आदि, ताकि एक असामान्य pattern का अनुकरण किया जा सके)। हम t-SNE को 30 की typical perplexity के साथ चलाते हैं। आउटपुट `data_2d` का shape (1505, 2) है। हम इस text में वास्तव में plot नहीं बनाएँगे, लेकिन यदि बनाते, तो हमें संभवतः 3 tight clusters दिखाई देते, जो 3 normal clusters के अनुरूप होते, और 5 outliers इन clusters से दूर isolated points के रूप में दिखाई देते। एक interactive workflow में, हम इस structure को verify करने के लिए points को उनके label (normal या कौन-सा cluster, बनाम anomaly) के आधार पर color कर सकते थे। Labels के बिना भी, कोई analyst 2D plot में empty space पर स्थित उन 5 points को देखकर उन्हें flag कर सकता है। यह दर्शाता है कि t-SNE cybersecurity data में visual anomaly detection और cluster inspection के लिए एक powerful aid हो सकता है और ऊपर दिए गए automated algorithms का complement बन सकता है।

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN**, DBSCAN का एक extension है, जो एक single global `eps` value चुनने की आवश्यकता को समाप्त करता है और density-connected components की hierarchy बनाकर और फिर उसे condense करके **different density** वाले clusters को recover कर सकता है। सामान्य DBSCAN की तुलना में यह आमतौर पर

* ऐसे अधिक intuitive clusters extract करता है, जहाँ कुछ clusters dense और अन्य sparse होते हैं,
* इसमें केवल एक वास्तविक hyper-parameter (`min_cluster_size`) होता है और इसका default sensible होता है,
* प्रत्येक point को cluster-membership *probability* और एक **outlier score** (`outlier_scores_`) देता है, जो threat-hunting dashboards के लिए बेहद उपयोगी है।<sup>[[1]](#references)</sup>

> [!TIP]
> *Cybersecurity में use cases:* HDBSCAN modern threat-hunting pipelines में बहुत popular है - commercial XDR suites के साथ भेजे जाने वाले notebook-based hunting playbooks में यह अक्सर दिखाई देता है। एक practical recipe है कि IR के दौरान HTTP beaconing traffic को cluster किया जाए: user-agent, interval और URI length अक्सर legitimate software updaters के कई tight groups बनाते हैं, जबकि C2 beacons tiny low-density clusters या pure noise के रूप में बने रहते हैं।

<details>
<summary>Example - Beaconing C2 channels ढूँढना</summary>
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

### Robustness और Security Considerations – Poisoning & Adversarial Attacks (2023-2025)

हाल के कार्यों से पता चला है कि **unsupervised learners *active attackers* से immune नहीं होते**:

* **Anomaly detectors के विरुद्ध Data-poisoning।** Chen *et al.* (IEEE S&P 2024) ने प्रदर्शित किया कि केवल 3 % crafted traffic जोड़ने से Isolation Forest और ECOD की decision boundary इस तरह बदल सकती है कि वास्तविक attacks सामान्य दिखाई देने लगें। Authors ने एक open-source PoC (`udo-poison`) जारी किया, जो poison points को automatically synthesise करता है।<sup>[[2]](#references)</sup>
* **Clustering models में Backdooring।** *BadCME* technique (BlackHat EU 2023) एक छोटा trigger pattern implant करती है; जब भी वह trigger दिखाई देता है, K-Means-based detector चुपचाप event को एक “benign” cluster में रख देता है।
* **DBSCAN/HDBSCAN की Evasion।** KU Leuven के एक 2025 academic pre-print ने दिखाया कि attacker ऐसे beaconing patterns बना सकता है जो जानबूझकर density gaps में चले जाते हैं और प्रभावी रूप से *noise* labels के भीतर छिप जाते हैं।

जो Mitigations तेजी से अपनाई जा रही हैं:

1. **Model sanitisation / TRIM।** प्रत्येक retraining epoch से पहले, 1–2 % highest-loss points को discard करें (trimmed maximum likelihood), ताकि poisoning को काफी कठिन बनाया जा सके।
2. **Consensus ensembling।** कई heterogeneous detectors (जैसे, Isolation Forest + GMM + ECOD) को combine करें और यदि *कोई भी* model किसी point को flag करे तो alert जारी करें। Research से संकेत मिलता है कि इससे attacker की लागत 10× से अधिक बढ़ जाती है।
3. **Clustering के लिए Distance-based defence।** `k` अलग-अलग random seeds के साथ clusters को फिर से compute करें और उन points को ignore करें जो लगातार clusters बदलते रहते हैं।

---

### Modern Open-Source Tooling (2024-2025)

* **PyOD 2.x** (May 2024 में released) ने *ECOD*, *COPOD* और GPU-accelerated *AutoFormer* detectors जोड़े। अब इसमें एक `benchmark` sub-command शामिल है, जो आपको **एक line of code** से अपने dataset पर 30+ algorithms की तुलना करने देता है:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (Feb 2025) मुख्यतः vision पर केंद्रित है, लेकिन इसमें एक generic **PatchCore** implementation भी है – screenshot-based phishing page detection के लिए उपयोगी।
* **scikit-learn 1.5** (Nov 2024) अंततः नए `cluster.HDBSCAN` wrapper के माध्यम से *HDBSCAN* के लिए `score_samples` expose करता है, इसलिए Python 3.12 पर external contrib package की आवश्यकता नहीं रहती।

<details>
<summary>त्वरित PyOD उदाहरण – ECOD + Isolation Forest ensemble</summary>
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

## संदर्भ

- [1] [HDBSCAN – पदानुक्रमित density-based clustering](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* “Data Poisoning के प्रति Unsupervised Anomaly Detection की Vulnerability।” *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
