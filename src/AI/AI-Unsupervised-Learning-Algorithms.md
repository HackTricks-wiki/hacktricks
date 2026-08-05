# Algorithms za Unsupervised Learning

{{#include ../banners/hacktricks-training.md}}

## Unsupervised Learning

Unsupervised learning ni aina ya machine learning ambapo model hufunzwa kwa data bila majibu yenye labels. Lengo ni kupata mifumo, miundo, au uhusiano ndani ya data. Tofauti na supervised learning, ambapo model hujifunza kutokana na mifano yenye labels, algorithms za unsupervised learning hufanya kazi na data isiyo na labels.  
Unsupervised learning hutumika mara nyingi kwa kazi kama vile clustering, dimensionality reduction, na anomaly detection. Inaweza kusaidia kugundua mifumo iliyofichika ndani ya data, kuweka pamoja vitu vinavyofanana, au kupunguza uchangamano wa data huku ikihifadhi vipengele vyake muhimu.

### K-Means Clustering

K-Means ni algorithm ya clustering inayotumia centroid, ambayo hugawanya data katika clusters K kwa kumpangia kila pointi wastani wa cluster ulio karibu zaidi. Algorithm hufanya kazi kama ifuatavyo:
1. **Initialization**: Chagua vituo K vya awali vya clusters (centroids), mara nyingi kwa nasibu au kwa kutumia mbinu bora zaidi kama k-means++
2. **Assignment**: Pangia kila pointi ya data centroid iliyo karibu zaidi kulingana na kipimo cha umbali (kwa mfano, Euclidean distance).
3. **Update**: Kokotoa upya centroids kwa kupata wastani wa pointi zote za data zilizopangiwa kila cluster.
4. **Repeat**: Hatua ya 2–3 hurudiwa hadi mgawanyo wa clusters utulie (centroids zisiendelee kusogea kwa kiwango kikubwa).

> [!TIP]
> *Matumizi katika cybersecurity:* K-Means hutumika katika intrusion detection kwa kuweka pamoja matukio ya mtandao. Kwa mfano, watafiti walitumia K-Means kwenye intrusion dataset ya KDD Cup 99 na kugundua kuwa iligawanya traffic kwa ufanisi katika clusters za kawaida dhidi ya mashambulizi. Kwa matumizi ya kawaida, security analysts wanaweza kuweka pamoja log entries au data ya tabia za watumiaji ili kupata makundi ya shughuli zinazofanana; pointi zozote zisizo ndani ya cluster iliyoundwa vizuri zinaweza kuashiria anomalies (kwa mfano, variant mpya ya malware inayounda cluster yake ndogo). K-Means pia inaweza kusaidia katika malware family classification kwa kuweka pamoja binaries kulingana na wasifu wa tabia au feature vectors.

#### Uchaguzi wa K

Idadi ya clusters (K) ni hyperparameter inayohitaji kufafanuliwa kabla ya kuendesha algorithm. Mbinu kama Elbow Method au Silhouette Score zinaweza kusaidia kubaini thamani inayofaa ya K kwa kutathmini utendaji wa clustering:

- **Elbow Method**: Chora jumla ya umbali ulioinuliwa kwa mraba kutoka kwa kila pointi hadi centroid ya cluster iliyopangiwa, kulingana na K. Tafuta pointi ya "elbow" ambapo kasi ya kupungua hubadilika kwa ghafla, ikionyesha idadi inayofaa ya clusters.
- **Silhouette Score**: Kokotoa silhouette score kwa thamani tofauti za K. Silhouette score ya juu huonyesha clusters zilizobainishwa vizuri zaidi.

#### Assumptions na Limitations

K-Means hudhani kuwa **clusters zina umbo la duara na zina ukubwa unaolingana**, jambo ambalo huenda lisiwe kweli kwa datasets zote. Inategemea uwekaji wa awali wa centroids na inaweza kufikia local minima. Zaidi ya hayo, K-Means haifai kwa datasets zenye densities zinazotofautiana au maumbo yasiyo ya globular, pamoja na features zenye scales tofauti. Hatua za preprocessing kama normalization au standardization zinaweza kuhitajika ili kuhakikisha kuwa features zote zinachangia kwa usawa katika ukokotoaji wa umbali.

<details>
<summary>Mfano -- Clustering ya Matukio ya Mtandao
</summary>
Hapa chini tunaiga data ya traffic ya mtandao na kutumia K-Means kuiweka katika clusters. Tuchukulie kuwa tuna matukio yenye features kama muda wa connection na idadi ya bytes. Tunaunda clusters 3 za traffic ya “kawaida” na cluster 1 ndogo inayowakilisha pattern ya shambulio. Kisha tunaendesha K-Means ili kuona kama inazitenganisha.
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
Katika mfano huu, K-Means inapaswa kupata clusters 4. Cluster ndogo ya attack (yenye duration ya juu isivyo kawaida ~200) itaunda cluster yake yenyewe, kutokana na umbali wake kutoka kwenye clusters za kawaida. Tunachapisha ukubwa na centers za clusters ili kutafsiri matokeo. Katika hali halisi, mtu anaweza kuweka label ya cluster yenye points chache kama anomalies zinazowezekana au kukagua washiriki wake kwa ajili ya shughuli hasidi.
</details>

### Hierarchical Clustering

Hierarchical clustering hujenga hierarchy ya clusters kwa kutumia approach ya bottom-up (agglomerative) au top-down (divisive):

1. **Agglomerative (Bottom-Up)**: Anza na kila data point ikiwa cluster tofauti, kisha unganisha clusters zilizo karibu zaidi hatua kwa hatua hadi cluster moja ibaki au stopping criterion ifikiwe.
2. **Divisive (Top-Down)**: Anza na data points zote katika cluster moja, kisha gawa clusters hatua kwa hatua hadi kila data point iwe cluster yake au stopping criterion ifikiwe.

Agglomerative clustering inahitaji definition ya inter-cluster distance na linkage criterion ya kuamua ni clusters zipi ziunganishwe. Linkage methods za kawaida zinajumuisha single linkage (distance ya points zilizo karibu zaidi kati ya clusters mbili), complete linkage (distance ya points zilizo mbali zaidi), average linkage, n.k., na distance metric mara nyingi huwa Euclidean. Chaguo la linkage huathiri shape ya clusters zinazozalishwa. Hakuna haja ya kubainisha mapema idadi ya clusters K; unaweza “kukata” dendrogram katika level iliyochaguliwa ili kupata idadi inayotakiwa ya clusters.

Hierarchical clustering huzalisha dendrogram, muundo unaofanana na mti unaoonyesha mahusiano kati ya clusters katika levels tofauti za granularity. Dendrogram inaweza kukatwa katika level inayotakiwa ili kupata idadi mahususi ya clusters.

> [!TIP]
> *Use cases katika cybersecurity:* Hierarchical clustering inaweza kupanga events au entities katika mti ili kubaini mahusiano. Kwa mfano, katika malware analysis, agglomerative clustering inaweza kupanga samples kulingana na behavioral similarity, na kufichua hierarchy ya malware families na variants. Katika network security, mtu anaweza ku-cluster IP traffic flows na kutumia dendrogram kuona subgroupings za traffic (kwa mfano, kwa protocol, kisha kwa behavior). Kwa kuwa huhitaji kuchagua K mwanzoni, ni muhimu wakati wa kuchunguza data mpya ambayo idadi ya attack categories haijulikani.

#### Assumptions na Limitations

Hierarchical clustering haidhanishii shape mahususi ya cluster na inaweza kutambua nested clusters. Ni muhimu kwa kugundua taxonomy au relations kati ya groups (kwa mfano, kupanga malware kulingana na family subgroups). Ni deterministic (haina matatizo ya random initialization). Faida kuu ni dendrogram, ambayo hutoa ufahamu wa clustering structure ya data katika scales zote – security analysts wanaweza kuamua cutoff inayofaa ili kutambua clusters zenye maana. Hata hivyo, inahitaji computational resources nyingi (kwa kawaida muda wa $O(n^2)$ au zaidi kwa naive implementations) na haifai kwa datasets kubwa sana. Pia ni greedy procedure – merge au split inapofanywa, haiwezi kutenduliwa, jambo ambalo linaweza kusababisha clusters zisizo bora ikiwa kosa litatokea mapema. Outliers pia zinaweza kuathiri baadhi ya linkage strategies (single-link inaweza kusababisha “chaining” effect ambapo clusters huunganishwa kupitia outliers).

<details>
<summary>Example -- Agglomerative Clustering of Events
</summary>

Tutatumia tena synthetic data kutoka kwenye mfano wa K-Means (clusters 3 za kawaida + cluster 1 ya attack) na kutumia agglomerative clustering. Kisha tutaonyesha jinsi ya kupata dendrogram na cluster labels.
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

DBSCAN ni algorithm ya clustering inayotegemea density, ambayo huunganisha pamoja pointi zilizo karibu kwa msongamano mkubwa huku ikiweka alama kwa pointi zilizo katika maeneo yenye msongamano mdogo kama outliers. Inafaa hasa kwa datasets zenye density zinazotofautiana na maumbo yasiyo ya duara.

DBSCAN hufanya kazi kwa kufafanua vigezo viwili:
- **Epsilon (ε)**: Umbali wa juu zaidi kati ya pointi mbili ili zichukuliwe kuwa sehemu ya cluster moja.
- **MinPts**: Idadi ya chini zaidi ya pointi zinazohitajika kuunda eneo lenye msongamano mkubwa (core point).

DBSCAN hutambua core points, border points, na noise points:
- **Core Point**: Pointi yenye angalau majirani wa MinPts ndani ya umbali wa ε.
- **Border Point**: Pointi iliyo ndani ya umbali wa ε kutoka kwa core point lakini ina majirani wasiofikia MinPts.
- **Noise Point**: Pointi ambayo si core point wala border point.

Clustering huanza kwa kuchagua core point ambayo haijatembelewa, kuiwekea alama kama cluster mpya, kisha kuongeza kwa kurudia pointi zote zinazoweza kufikiwa kwa density kutoka kwake (core points na majirani wao, n.k.). Border points huongezwa kwenye cluster ya core point iliyo karibu. Baada ya kupanua pointi zote zinazoweza kufikiwa, DBSCAN huhamia kwenye core point nyingine ambayo haijatembelewa ili kuanzisha cluster mpya. Pointi ambazo hazikufikiwa na core point yoyote hubaki na alama ya noise.

> [!TIP]
> *Matumizi katika cybersecurity:* DBSCAN ni muhimu kwa anomaly detection katika network traffic. Kwa mfano, shughuli za kawaida za mtumiaji zinaweza kuunda cluster moja au zaidi zenye density kubwa katika feature space, huku tabia mpya za mashambulizi zikionekana kama pointi zilizotawanyika ambazo DBSCAN itaziwekea alama ya noise (outliers). Imetumika ku-cluster network flow records, ambapo inaweza kutambua port scans au traffic ya denial-of-service kama maeneo yenye pointi chache. Matumizi mengine ni kuainisha variants za malware: ikiwa samples nyingi zina-cluster kulingana na familia, lakini chache haziendani na kundi lolote, hizo chache zinaweza kuwa zero-day malware. Uwezo wa kuonyesha noise unamaanisha kuwa security teams zinaweza kulenga uchunguzi kwenye outliers hizo.

#### Assumptions and Limitations

**Assumptions & Strengths:**: DBSCAN haidhani kuwa clusters lazima ziwe za duara – inaweza kupata clusters zenye maumbo yoyote (hata zenye umbo la mnyororo au clusters zilizo karibu). Huamua kiotomatiki idadi ya clusters kulingana na density ya data na inaweza kutambua kwa ufanisi outliers kama noise. Hii huifanya iwe yenye nguvu kwa data halisi yenye maumbo yasiyo ya kawaida na noise. Ni thabiti dhidi ya outliers (tofauti na K-Means, ambayo huwalazimisha kuingia kwenye clusters). Hufanya kazi vizuri wakati clusters zina density inayokaribiana.

**Limitations**: Utendaji wa DBSCAN hutegemea kuchagua thamani zinazofaa za ε na MinPts. Inaweza kupata changamoto kwenye data yenye densities zinazotofautiana – ε moja haiwezi kushughulikia clusters zenye density kubwa na ndogo kwa wakati mmoja. Ikiwa ε ni ndogo sana, huweka alama ya noise kwa pointi nyingi; ikiwa ni kubwa sana, clusters zinaweza kuungana kimakosa. Pia, DBSCAN inaweza kuwa isiyofaa kwenye datasets kubwa sana (kwa njia rahisi $O(n^2)$, ingawa spatial indexing inaweza kusaidia). Katika feature spaces zenye dimensions nyingi, dhana ya “distance within ε” inaweza kupoteza maana yake (curse of dimensionality), na DBSCAN inaweza kuhitaji tuning makini ya parameters au kushindwa kupata clusters zenye maana inayotarajiwa. Pamoja na hayo, extensions kama HDBSCAN hushughulikia baadhi ya matatizo (kama density inayotofautiana).

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
Katika kipande hiki, tulirekebisha `eps` na `min_samples` ili zilingane na scale ya data yetu (15.0 katika units za features, na kuhitaji pointi 5 kuunda cluster). DBSCAN inapaswa kupata clusters 2 (clusters za traffic ya kawaida) na kutambua outliers 5 zilizoingizwa kama noise. Tunatoa idadi ya clusters dhidi ya pointi za noise ili kuthibitisha hili. Katika mazingira halisi, mtu anaweza kurudia mchakato kwa kutumia ε (kwa kutumia heuristic ya k-distance graph kuchagua ε) na MinPts (mara nyingi huwekwa karibu na dimensionality ya data + 1 kama kanuni ya jumla) ili kupata matokeo thabiti ya clustering. Uwezo wa kuweka noise lebo wazi husaidia kutenganisha data inayoweza kuwa ya attack kwa ajili ya uchambuzi zaidi.

</details>

### Principal Component Analysis (PCA)

PCA ni technique ya **dimensionality reduction** inayotafuta seti mpya ya axes zilizo orthogonal (principal components) zinazohifadhi variance ya juu zaidi katika data. Kwa maneno rahisi, PCA huzungusha na kuproject data kwenye coordinate system mpya kiasi kwamba principal component ya kwanza (PC1) hueleza variance kubwa iwezekanavyo, PC ya pili (PC2) hueleza variance kubwa zaidi iliyo orthogonal kwa PC1, na kuendelea hivyo. Kihisabati, PCA huhesabu eigenvectors za covariance matrix ya data – eigenvectors hizi ni directions za principal components, na eigenvalues zinazolingana zinaonyesha kiasi cha variance kilichoelezwa na kila moja. Mara nyingi hutumika kwa feature extraction, visualization, na noise reduction.

Kumbuka kuwa hii ni muhimu ikiwa dimensions za dataset zina **linear dependencies au correlations** kubwa.

PCA hufanya kazi kwa kutambua principal components za data, ambazo ni directions za variance ya juu zaidi. Hatua zinazohusika katika PCA ni:
1. **Standardization**: Weka data katikati kwa kutoa mean na kuiscale ifikie unit variance.
2. **Covariance Matrix**: Hesabu covariance matrix ya data iliyostandardize ili kuelewa mahusiano kati ya features.
3. **Eigenvalue Decomposition**: Fanya eigenvalue decomposition kwenye covariance matrix ili kupata eigenvalues na eigenvectors.
4. **Select Principal Components**: Panga eigenvalues kwa mpangilio wa kushuka na uchague eigenvectors K za juu zinazolingana na eigenvalues kubwa zaidi. Eigenvectors hizi huunda feature space mpya.
5. **Transform Data**: Project data ya awali kwenye feature space mpya kwa kutumia principal components zilizochaguliwa.
PCA hutumika sana kwa data visualization, noise reduction, na kama hatua ya preprocessing kwa machine learning algorithms nyingine. Husaidia kupunguza dimensionality ya data huku ikihifadhi muundo wake muhimu.

#### Eigenvalues and Eigenvectors

Eigenvalue ni scalar inayoonyesha kiasi cha variance kilichonaswa na eigenvector inayolingana nayo. Eigenvector inawakilisha direction katika feature space ambayo data hubadilika zaidi.

Fikiria A ni square matrix, na v ni vector isiyo sifuri kiasi kwamba: `A * v = λ * v`
ambapo:
- A ni square matrix kama [ [1, 2], [2, 1]] (kwa mfano, covariance matrix)
- v ni eigenvector (kwa mfano, [1, 1])

Kisha, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, ambayo itakuwa eigenvalue λ iliyozidishwa kwa eigenvector v, hivyo eigenvalue λ = 3.

#### Eigenvalues and Eigenvectors in PCA

Hebu tueleze hili kwa mfano. Fikiria una dataset yenye picha nyingi za nyuso zenye grey scale na pixels 100x100. Kila pixel inaweza kuchukuliwa kuwa feature, hivyo una features 10,000 kwa kila image (au vector yenye components 10000 kwa kila image). Ikiwa unataka kupunguza dimensionality ya dataset hii kwa kutumia PCA, ungefuata hatua hizi:

1. **Standardization**: Weka data katikati kwa kutoa mean ya kila feature (pixel) kutoka kwenye dataset.
2. **Covariance Matrix**: Hesabu covariance matrix ya data iliyostandardize, ambayo hunasa jinsi features (pixels) zinavyobadilika pamoja.
- Kumbuka kuwa covariance kati ya variables mbili (pixels katika hali hii) huonyesha kwa kiasi gani hubadilika pamoja; kwa hiyo, lengo hapa ni kujua ni pixels zipi huwa zinaongezeka au kupungua pamoja katika linear relationship.
- Kwa mfano, ikiwa pixel 1 na pixel 2 huwa zinaongezeka pamoja, covariance kati yao itakuwa positive.
- Covariance matrix itakuwa matrix ya 10,000x10,000 ambapo kila entry inawakilisha covariance kati ya pixels mbili.
3. **Solve the The eigenvalue equation**: Eigenvalue equation ya kutatua ni `C * v = λ * v`, ambapo C ni covariance matrix, v ni eigenvector, na λ ni eigenvalue. Inaweza kutatuliwa kwa kutumia methods kama:
- **Eigenvalue Decomposition**: Fanya eigenvalue decomposition kwenye covariance matrix ili kupata eigenvalues na eigenvectors.
- **Singular Value Decomposition (SVD)**: Vinginevyo, unaweza kutumia SVD ku-decompose data matrix kuwa singular values na vectors, ambazo pia zinaweza kutoa principal components.
4. **Select Principal Components**: Panga eigenvalues kwa mpangilio wa kushuka na uchague eigenvectors K za juu zinazolingana na eigenvalues kubwa zaidi. Eigenvectors hizi zinawakilisha directions za variance ya juu zaidi katika data.

> [!TIP]
> *Use cases in cybersecurity:* Matumizi ya kawaida ya PCA katika security ni feature reduction kwa anomaly detection. Kwa mfano, intrusion detection system yenye network metrics zaidi ya 40 (kama NSL-KDD features) inaweza kutumia PCA kupunguza hadi components chache, ikifupisha data kwa ajili ya visualization au kuingiza kwenye clustering algorithms. Analysts wanaweza kuchora network traffic katika space ya principal components mbili za kwanza ili kuona ikiwa attacks zinajitenga na traffic ya kawaida. PCA pia inaweza kusaidia kuondoa redundant features (kama bytes sent dhidi ya bytes received ikiwa zina correlated) ili kufanya detection algorithms ziwe robust zaidi na za haraka.

#### Assumptions and Limitations

PCA hudhani kuwa **principal axes za variance zina maana** – ni linear method, kwa hiyo hunasa linear correlations katika data. Ni unsupervised kwa sababu hutumia covariance ya features pekee. Faida za PCA ni pamoja na noise reduction (components zenye variance ndogo mara nyingi huhusishwa na noise) na decorrelation ya features. Ni computationally efficient kwa dimensions zilizo juu kwa kiwango cha wastani na mara nyingi huwa preprocessing step yenye manufaa kwa algorithms nyingine (kupunguza curse of dimensionality). Limitation moja ni kwamba PCA inaishia kwenye linear relationships – haitanasa complex nonlinear structure (ambapo autoencoders au t-SNE zinaweza kusaidia). Pia, PCA components zinaweza kuwa ngumu kutafsiri kuhusiana na original features (ni combinations za original features). Katika cybersecurity, mtu lazima awe mwangalifu: attack inayosababisha mabadiliko madogo tu katika feature yenye variance ndogo huenda isionekane katika top PCs (kwa sababu PCA hutanguliza variance, si lazima “interestingness”).

<details>
<summary>Example -- Kupunguza Dimensions za Network Data
</summary>

Tuchukulie tuna network connection logs zenye features nyingi (kwa mfano, durations, bytes, counts). Tutazalisha synthetic 4-dimensional dataset (yenye correlation fulani kati ya features) na kutumia PCA kuipunguza hadi dimensions 2 kwa ajili ya visualization au uchambuzi zaidi.
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
Hapa tulichukua clusters za traffic ya kawaida za awali na tukaongeza kila data point kwa features mbili za ziada (packets na errors) ambazo zina uhusiano na bytes na duration. PCA kisha hutumika kubana features 4 kuwa principal components 2. Tunachapisha explained variance ratio, ambayo inaweza kuonyesha kwamba, kwa mfano, >95% ya variance inawakilishwa na components 2 (ikimaanisha upotevu mdogo wa information). Output pia inaonyesha umbo la data likipungua kutoka (1500, 4) hadi (1500, 2). Points chache za kwanza katika PCA space zimetolewa kama mfano. Kwa matumizi halisi, mtu anaweza kuchora data_2d ili kuangalia kwa macho kama clusters zinaweza kutofautishwa. Ikiwa anomaly ingekuwepo, huenda ingeonekana kama point iliyo mbali na cluster kuu katika PCA-space. Kwa hivyo PCA husaidia kusafisha data changamano kuwa muundo unaoweza kudhibitiwa kwa ajili ya tafsiri ya binadamu au kutumiwa kama input kwa algorithms nyingine.

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Model hudhani kwamba data inatengenezwa kutokana na mchanganyiko wa **Gaussian (normal) distributions kadhaa zenye parameters zisizojulikana**. Kwa msingi, huu ni probabilistic clustering model: hujaribu kumpa kila point kwa njia ya soft assignment mojawapo ya K Gaussian components. Kila Gaussian component k ina mean vector (μ_k), covariance matrix (Σ_k), na mixing weight (π_k) inayowakilisha kiwango ambacho cluster hiyo inapatikana. Tofauti na K-Means inayofanya “hard” assignments, GMM huipa kila point probability ya kuwa katika kila cluster.

GMM fitting kwa kawaida hufanywa kupitia Expectation-Maximization (EM) algorithm:

- **Initialization**: Anza na makadirio ya awali ya means, covariances, na mixing coefficients (au tumia matokeo ya K-Means kama sehemu ya kuanzia).

- **E-step (Expectation)**: Kwa kutumia parameters za sasa, hesabu responsibility ya kila cluster kwa kila point: kimsingi `r_nk = P(z_k | x_n)` ambapo z_k ni latent variable inayoonyesha uanachama wa cluster kwa point x_n. Hii hufanywa kwa kutumia Bayes' theorem, ambapo tunahesabu posterior probability ya kila point kuwa katika kila cluster kulingana na parameters za sasa. Responsibilities huhesabiwa kama:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
ambapo:
- \( \pi_k \) ni mixing coefficient ya cluster k (prior probability ya cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) ni Gaussian probability density function ya point \( x_n \) ikipewa mean \( \mu_k \) na covariance \( \Sigma_k \).

- **M-step (Maximization)**: Sasisha parameters kwa kutumia responsibilities zilizohesabiwa katika E-step:
- Sasisha kila mean μ_k kuwa weighted average ya points, ambapo weights ni responsibilities.
- Sasisha kila covariance Σ_k kuwa weighted covariance ya points zilizopangiwa cluster k.
- Sasisha mixing coefficients π_k kuwa average responsibility ya cluster k.

- **Iterate** E na M steps hadi convergence (parameters zitulie au improvement ya likelihood iwe chini ya threshold).

Matokeo huwa ni seti ya Gaussian distributions ambazo kwa pamoja hu-model overall data distribution. Tunaweza kutumia GMM iliyofit kufanya clustering kwa kumpangia kila point Gaussian yenye probability ya juu zaidi, au kuhifadhi probabilities kwa ajili ya uncertainty. Pia tunaweza kutathmini likelihood ya points mpya ili kuona kama zinaendana na model (jambo linalofaa kwa anomaly detection).

> [!TIP]
> *Use cases katika cybersecurity:* GMM inaweza kutumika kwa anomaly detection kwa ku-model distribution ya data ya kawaida: point yoyote yenye probability ndogo sana chini ya learned mixture huwekwa alama kama anomaly. Kwa mfano, unaweza ku-train GMM kwa features za legitimate network traffic; attack connection isiyofanana na cluster yoyote iliyojifunzwa itakuwa na likelihood ndogo. GMMs pia hutumika ku-cluster activities ambazo clusters zake zinaweza kuwa na shapes tofauti – kwa mfano, kupanga users kulingana na behavior profiles, ambapo features za kila profile zinaweza kuwa Gaussian-like lakini zikiwa na variance structure yake. Mfano mwingine: katika phishing detection, features za legitimate email zinaweza kuunda Gaussian cluster moja, phishing inayojulikana cluster nyingine, na phishing campaigns mpya zinaweza kuonekana kama Gaussian tofauti au points zenye likelihood ndogo ikilinganishwa na mixture iliyopo.

#### Assumptions and Limitations

GMM ni generalization ya K-Means inayojumuisha covariance, hivyo clusters zinaweza kuwa za umbo la ellipsoid (si za spherical pekee). Inaweza kushughulikia clusters zenye sizes na shapes tofauti ikiwa covariance ni full. Soft clustering ni faida wakati mipaka ya clusters haiko wazi – kwa mfano, katika cybersecurity, event inaweza kuwa na traits za attack types nyingi; GMM inaweza kuonyesha uncertainty hiyo kwa kutumia probabilities. GMM pia hutoa probabilistic density estimation ya data, ambayo ni muhimu kwa kugundua outliers (points zenye likelihood ndogo chini ya mixture components zote).

Kwa upande mwingine, GMM inahitaji kutaja idadi ya components K (ingawa mtu anaweza kutumia criteria kama BIC/AIC kuichagua). EM wakati mwingine inaweza ku-converge polepole au kufikia local optimum, hivyo initialization ni muhimu (mara nyingi EM huendeshwa mara nyingi). Ikiwa data haifuati mchanganyiko wa Gaussians kwa kweli, model inaweza kutofit vizuri. Pia kuna hatari ya Gaussian moja kujikunja ili kufunika outlier mmoja tu (ingawa regularization au minimum covariance bounds zinaweza kupunguza tatizo hilo).


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
Katika msimbo huu, tunafunza GMM yenye Gaussian 3 kwenye trafiki ya kawaida (tukidhani tunajua profaili 3 za trafiki halali). Means na covariances zilizochapishwa zinaeleza makundi haya (kwa mfano, mean moja inaweza kuwa karibu na [50,500], inayowakilisha kituo cha kundi moja, n.k.). Kisha tunapima connection yenye kutiliwa shaka [duration=200, bytes=800]. `predict_proba` hutoa probability ya pointi hii kuwa ya kila moja kati ya makundi 3 – tungetarajia probabilities hizi ziwe ndogo sana au zigawanyike kwa upendeleo mkubwa, kwa sababu [200,800] iko mbali na makundi ya kawaida. `score_samples` ya jumla (log-likelihood) inachapishwa; thamani ya chini sana inaonyesha kuwa pointi hiyo haiendani vizuri na model, hivyo kuashiria anomaly. Kwa matumizi halisi, mtu anaweza kuweka threshold kwenye log-likelihood (au kwenye max probability) ili kuamua kama pointi ina uwezekano mdogo kiasi cha kutosha kuhesabiwa kuwa malicious. Kwa hivyo, GMM hutoa njia yenye msingi thabiti ya kufanya anomaly detection na pia hutoa makundi laini yanayotambua kutokuwa na uhakika.
</details>

### Isolation Forest

**Isolation Forest** ni algorithm ya ensemble ya anomaly detection inayotegemea wazo la kutenga pointi kwa njia ya random. Kanuni yake ni kwamba anomalies ni chache na ni tofauti, hivyo ni rahisi zaidi kuzitenga kuliko pointi za kawaida. Isolation Forest hujenga isolation trees nyingi za binary (random decision trees) zinazogawanya data kwa njia ya random. Katika kila node ya tree, feature moja huchaguliwa kwa random na thamani ya random ya split huchaguliwa kati ya min na max ya feature hiyo kwa data iliyo kwenye node hiyo. Split hii hugawanya data kuwa branches mbili. Tree hukuzwa hadi kila pointi itengwe kwenye leaf yake au urefu wa juu wa tree ufikiwe.

Anomaly detection hufanywa kwa kuchunguza path length ya kila pointi kwenye random trees hizi – yaani, idadi ya splits zinazohitajika kuitenga pointi hiyo. Kwa intuition, anomalies (outliers) huwa zinatengwa haraka kwa sababu random split ina uwezekano mkubwa zaidi wa kutenganisha outlier (iliyo katika eneo lenye data chache) kuliko pointi ya kawaida iliyo kwenye cluster yenye msongamano. Isolation Forest hukokotoa anomaly score kutokana na average path length kwenye trees zote: average path fupi → anomaly kubwa zaidi. Scores kwa kawaida hu-normalize kuwa [0,1], ambapo 1 inamaanisha uwezekano mkubwa sana wa anomaly.

> [!TIP]
> *Matumizi katika cybersecurity:* Isolation Forests zimetumika kwa mafanikio katika intrusion detection na fraud detection. Kwa mfano, train Isolation Forest kwenye network traffic logs ambazo kwa kiasi kikubwa zina tabia ya kawaida; forest itatoa paths fupi kwa trafiki isiyo ya kawaida (kama IP inayotumia port ambayo haijawahi kusikika au pattern isiyo ya kawaida ya packet size), na kuiweka alama kwa ajili ya uchunguzi. Kwa kuwa haihitaji labeled attacks, inafaa kwa kugundua aina za mashambulizi zisizojulikana. Pia inaweza kutumika kwenye data ya user login ili kugundua account takeovers (login times au locations zisizo za kawaida hutengwa haraka). Katika use-case moja, Isolation Forest inaweza kulinda enterprise kwa kufuatilia system metrics na kutoa alert wakati mchanganyiko wa metrics (CPU, network, file changes) unaonekana kuwa tofauti sana (short isolation paths) na patterns za kihistoria.

#### Assumptions and Limitations

**Advantages**: Isolation Forest haihitaji assumption kuhusu distribution; inalenga moja kwa moja isolation. Inafanya kazi kwa ufanisi kwenye high-dimensional data na datasets kubwa (linear complexity $O(n\log n)$ ya kujenga forest), kwa kuwa kila tree hutenga pointi kwa kutumia subset tu ya features na splits. Kwa kawaida hushughulikia numerical features vizuri na inaweza kuwa haraka kuliko distance-based methods ambazo zinaweza kuwa $O(n^2)$. Pia hutoa anomaly score moja kwa moja, hivyo unaweza kuweka threshold kwa alerts (au kutumia contamination parameter kuamua cutoff moja kwa moja kulingana na sehemu inayotarajiwa ya anomalies).

**Limitations**: Kwa sababu ya tabia yake ya random, matokeo yanaweza kutofautiana kidogo kati ya runs (ingawa tofauti hii huwa ndogo ikiwa kuna trees za kutosha). Ikiwa data ina features nyingi zisizo muhimu au ikiwa anomalies hazitofautiani sana katika feature yoyote, isolation inaweza kutofanya kazi vizuri (random splits zinaweza kutenga pointi za kawaida kwa bahati – hata hivyo, averaging ya trees nyingi hupunguza tatizo hili). Pia, Isolation Forest kwa ujumla hudhani kuwa anomalies ni minority ndogo (jambo ambalo kwa kawaida ni kweli katika hali za cybersecurity).

<details>
<summary>Example --  Kugundua Outliers katika Network Logs
</summary>

Tutatumia dataset ya majaribio ya awali (iliyo na pointi za kawaida na baadhi ya attack points) na kuendesha Isolation Forest ili kuona kama inaweza kutenganisha mashambulizi. Tutadhani tunatarajia takriban 15% ya data kuwa anomalous (kwa ajili ya demonstration).
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
Katika code hii, tunaunda `IsolationForest` yenye miti 100 na kuweka `contamination=0.15` (ikimaanisha tunatarajia takriban 15% ya data kuwa anomalies; model itaweka threshold ya score yake ili takriban 15% ya pointi ziwekwe alama). Tunai-fit kwenye `X_test_if`, ambayo ina mchanganyiko wa pointi za kawaida na za mashambulizi (kumbuka: kwa kawaida unge-fit kwenye training data kisha utumie predict kwenye data mpya, lakini hapa, kwa madhumuni ya kuonyesha mfano, tuna-fit na predict kwenye seti ileile ili kuona matokeo moja kwa moja).

Output inaonyesha labels zilizotabiriwa kwa pointi 20 za kwanza (ambapo -1 inaonyesha anomaly). Pia tunachapisha jumla ya anomalies zilizogunduliwa na baadhi ya mifano ya anomaly scores. Tungetarajia takriban pointi 18 kati ya 120 ziwekwe alama -1 (kwa kuwa contamination ilikuwa 15%). Ikiwa samples 20 za mashambulizi ndizo zenye kuwa mbali zaidi na data nyingine, nyingi kati yake zinapaswa kuonekana kwenye predictions hizo za -1. Anomaly score (decision function ya Isolation Forest) huwa juu kwa pointi za kawaida na chini (hasi zaidi) kwa anomalies — tunachapisha thamani chache ili kuona utenganisho huo. Kwa matumizi ya vitendo, mtu anaweza kupanga data kwa kutumia score ili kuona outliers zilizo juu zaidi na kuzichunguza. Kwa hivyo, Isolation Forest hutoa njia bora ya kuchuja kiasi kikubwa cha security data isiyo na labels na kubainisha instances zisizo za kawaida zaidi kwa uchambuzi wa binadamu au uchunguzi zaidi wa kiotomatiki.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** ni mbinu ya nonlinear dimensionality reduction iliyoundwa mahsusi kwa ajili ya kuonyesha data yenye vipimo vingi katika vipimo 2 au 3. Inabadilisha similarities kati ya data points kuwa joint probability distributions na hujaribu kuhifadhi muundo wa local neighborhoods katika projection yenye vipimo vichache. Kwa maneno rahisi, t-SNE huweka pointi katika (kwa mfano) 2D kwa namna ambayo pointi zinazofanana katika space ya awali huishia kuwa karibu, na zisizofanana huishia kuwa mbali kwa uwezekano mkubwa.

Algorithm ina hatua kuu tatu:

1. **Compute pairwise affinities in high-dimensional space:** Kwa kila pair ya pointi, t-SNE huhesabu probability kwamba pair hiyo itachaguliwa kuwa neighbors (hili hufanywa kwa kuweka Gaussian distribution iliyowekwa katikati ya kila pointi na kupima distances — parameter ya perplexity huathiri idadi halisi ya neighbors wanaozingatiwa).
2. **Compute pairwise affinities in low-dimensional (e.g. 2D) space:** Mwanzoni, pointi huwekwa kwa random katika 2D. t-SNE hufafanua probability inayofanana kwa distances katika ramani hii (kwa kutumia Student t-distribution kernel, ambayo ina tails nzito zaidi kuliko Gaussian na hivyo kuruhusu pointi za mbali kuwa na uhuru zaidi).
3. **Gradient Descent:** Kisha t-SNE husogeza pointi hizo katika 2D kwa hatua za kurudiwa ili kupunguza Kullback–Leibler (KL) divergence kati ya high-D affinity distribution na low-D distribution. Hii husababisha mpangilio wa 2D kuakisi muundo wa high-D kadiri inavyowezekana — pointi zilizokuwa karibu katika space ya awali huvutana, na zilizokuwa mbali husukumana, hadi usawaziko upatikane.

Matokeo mara nyingi huwa scatter plot yenye maana ya kuonekana, ambapo clusters katika data huwa wazi.

> [!TIP]
> *Matumizi katika cybersecurity:* t-SNE hutumiwa mara nyingi **kuonyesha security data yenye vipimo vingi kwa ajili ya uchambuzi wa binadamu**. Kwa mfano, katika security operations center, analysts wanaweza kuchukua event dataset yenye features kadhaa (port numbers, frequencies, byte counts, na kadhalika) na kutumia t-SNE kutengeneza plot ya 2D. Mashambulizi yanaweza kuunda clusters zao au kujitenga na data ya kawaida katika plot hiyo, hivyo kurahisisha kuyatambua. Imetumika kwenye malware datasets ili kuona makundi ya malware families au kwenye network intrusion data ambapo aina tofauti za mashambulizi huunda clusters zinazotofautiana wazi, na hivyo kusaidia uchunguzi zaidi. Kwa ujumla, t-SNE hutoa njia ya kuona muundo katika cyber data ambao vinginevyo ungekuwa mgumu kueleweka.

#### Assumptions and Limitations

t-SNE ni nzuri kwa ugunduzi wa kuona wa patterns. Inaweza kufichua clusters, subclusters, na outliers ambazo mbinu nyingine za linear (kama PCA) huenda zisionyeshe. Imetumika katika utafiti wa cybersecurity kuonyesha data changamano kama malware behavior profiles au network traffic patterns. Kwa sababu huhifadhi local structure, ni nzuri katika kuonyesha natural groupings.

Hata hivyo, t-SNE ina uzito mkubwa zaidi wa computation (takriban $O(n^2)$), hivyo inaweza kuhitaji sampling kwa datasets kubwa sana. Pia ina hyperparameters (perplexity, learning rate, iterations) ambazo zinaweza kuathiri output — kwa mfano, thamani tofauti za perplexity zinaweza kufichua clusters katika scales tofauti. Wakati mwingine t-SNE plots zinaweza kutafsiriwa vibaya — distances katika ramani si za maana moja kwa moja kwa mtazamo wa global (inalenga local neighborhood, na wakati mwingine clusters zinaweza kuonekana zimetengana vizuri kwa njia isiyo halisi). Pia, t-SNE hutumika hasa kwa visualization; haitoi njia rahisi ya ku-project data points mpya bila kufanya computation upya, na haikusudiwi kutumiwa kama preprocessing ya predictive modeling (UMAP ni alternative inayoshughulikia baadhi ya matatizo haya kwa speed kubwa zaidi).

<details>
<summary>Example -- Kuonyesha Network Connections
</summary>

Tutatumia t-SNE kupunguza dataset yenye features nyingi hadi 2D. Kwa madhumuni ya mfano, tuchukue data ya awali ya 4D (iliyokuwa na clusters 3 za asili za normal traffic) na kuongeza anomaly points chache. Kisha tutaendesha t-SNE na (kwa dhana) kuonyesha matokeo.
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
Hapa tuliunganisha dataset yetu ya kawaida ya 4D ya awali na outliers wachache waliokithiri (outliers wana feature moja (“duration”) iliyowekwa kuwa juu sana, n.k., ili kuiga pattern isiyo ya kawaida). Tunaendesha t-SNE kwa perplexity ya kawaida ya 30. Data ya output `data_2d` ina shape ya (1505, 2). Hatutapiga plot halisi katika maandishi haya, lakini kama tungefanya hivyo, tungetarajia kuona labda clusters tatu zilizobana zinazolingana na clusters tatu za kawaida, na outliers 5 zikitokea kama points zilizojitenga mbali na clusters hizo. Katika workflow ya interactive, tungeweza kupaka rangi points kulingana na label yao (normal au cluster ipi, dhidi ya anomaly) ili kuthibitisha muundo huu. Hata bila labels, analyst anaweza kugundua points hizo 5 zikiwa katika nafasi tupu kwenye plot ya 2D na kuzitia alama. Hii inaonyesha jinsi t-SNE inavyoweza kuwa msaada wenye nguvu kwa visual anomaly detection na ukaguzi wa clusters katika data ya cybersecurity, ikikamilisha algorithms za automated zilizoelezwa hapo juu.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** ni extension ya DBSCAN inayoondoa hitaji la kuchagua value moja ya kimataifa ya `eps` na inaweza kurejesha clusters zenye **density tofauti** kwa kujenga hierarchy ya density-connected components na kisha ku-condense hierarchy hiyo. Ikilinganishwa na vanilla DBSCAN, kwa kawaida

* hutoa clusters zinazoeleweka zaidi wakati baadhi ya clusters ni dense na nyingine ni sparse,
* ina hyper-parameter moja tu halisi (`min_cluster_size`) na default yenye mantiki,
* huipa kila point *probability* ya cluster-membership na **outlier score** (`outlier_scores_`), ambayo ni muhimu sana kwa threat-hunting dashboards.<sup>[[1]](#references)</sup>

> [!TIP]
> *Use cases katika cybersecurity:* HDBSCAN ni maarufu sana katika threat-hunting pipelines za kisasa – mara nyingi utaiona ndani ya playbooks za hunting zinazotegemea notebooks, zinazosambazwa pamoja na commercial XDR suites. Recipe moja ya vitendo ni ku-cluster traffic ya HTTP beaconing wakati wa IR: user-agent, interval na URI length mara nyingi huunda groups kadhaa zilizobana za legitimate software updaters, huku C2 beacons zikibaki kama clusters ndogo zenye low-density au kama noise tupu.

<details>
<summary>Example – Kupata beaconing C2 channels</summary>
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

### Uimara na Mazingatio ya Usalama – Poisoning & Adversarial Attacks (2023-2025)

Utafiti wa hivi karibuni umeonyesha kuwa **unsupervised learners *si* salama dhidi ya attackers wanaofanya mashambulizi ya moja kwa moja**:

* **Data-poisoning dhidi ya anomaly detectors.** Chen *et al.* (IEEE S&P 2024) walionyesha kuwa kuongeza traffic iliyoundwa kwa makusudi kwa kiasi cha chini kama 3% kunaweza kuhamisha decision boundary ya Isolation Forest na ECOD, kiasi kwamba mashambulizi halisi yaonekane kuwa ya kawaida. Waandishi walitoa PoC ya open-source (`udo-poison`) inayotengeneza poison points kiotomatiki.<sup>[[2]](#references)</sup>
* **Backdooring clustering models.** Mbinu ya *BadCME* (BlackHat EU 2023) huingiza trigger pattern ndogo; trigger hiyo inapoonekana, detector inayotumia K-Means huweka tukio hilo kimyakimya ndani ya cluster ya “benign”.
* **Kukwepa DBSCAN/HDBSCAN.** Pre-print ya kitaaluma ya 2025 kutoka KU Leuven ilionyesha kuwa attacker anaweza kuunda beaconing patterns zinazolenga kuingia kwenye density gaps, na hivyo kujificha ndani ya labels za *noise*.

Mitigation zinazozidi kupata matumizi:

1. **Model sanitisation / TRIM.** Kabla ya kila retraining epoch, ondoa points zenye loss kubwa zaidi kwa 1–2% (trimmed maximum likelihood) ili kufanya poisoning kuwa ngumu zaidi kwa kiwango kikubwa.
2. **Consensus ensembling.** Unganisha detectors kadhaa zisizofanana (kwa mfano, Isolation Forest + GMM + ECOD) na toa alert ikiwa model yoyote itatambua point. Utafiti unaonyesha kuwa hii huongeza gharama ya attacker kwa zaidi ya mara 10.
3. **Distance-based defence for clustering.** Kadiria upya clusters kwa kutumia `k` random seeds tofauti na upuuze points zinazohama kutoka cluster moja hadi nyingine kila mara.

---

### Modern Open-Source Tooling (2024-2025)

* **PyOD 2.x** (ilitolewa Mei 2024) iliongeza detectors za *ECOD*, *COPOD* na *AutoFormer* zinazotumia GPU. Sasa inakuja na sub-command ya `benchmark` inayokuruhusu kulinganisha algorithms zaidi ya 30 kwenye dataset yako kwa **mstari mmoja wa code**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (Februari 2025) inalenga vision, lakini pia ina implementation ya jumla ya **PatchCore** – inayofaa kwa detection ya phishing pages inayotegemea screenshots.
* **scikit-learn 1.5** (Novemba 2024) hatimaye imeweka wazi `score_samples` kwa *HDBSCAN* kupitia wrapper mpya ya `cluster.HDBSCAN`, kwa hiyo huhitaji contrib package ya nje unapotumia Python 3.12.

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

## Marejeleo

- [1] [HDBSCAN – clustering ya hierarchical inayotegemea density](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* “Kuhusu Udhaifu wa Unsupervised Anomaly Detection dhidi ya Data Poisoning.” *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
