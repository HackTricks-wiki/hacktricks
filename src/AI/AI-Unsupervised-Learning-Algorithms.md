# Denetimsiz Öğrenme Algoritmaları

{{#include ../banners/hacktricks-training.md}}

## Denetimsiz Öğrenme

Denetimsiz öğrenme, modelin etiketlenmiş yanıtlar içermeyen veriler üzerinde eğitildiği bir makine öğrenmesi türüdür. Amaç, veriler içindeki örüntüleri, yapıları veya ilişkileri bulmaktır. Modelin etiketlenmiş örneklerden öğrendiği supervised learning'in aksine, denetimsiz öğrenme algoritmaları etiketlenmemiş verilerle çalışır.
Denetimsiz öğrenme genellikle clustering, boyut azaltma ve anomaly detection gibi görevlerde kullanılır. Verilerdeki gizli örüntülerin keşfedilmesine, benzer öğelerin birlikte gruplanmasına veya temel özellikleri korunurken verilerin karmaşıklığının azaltılmasına yardımcı olabilir.


### K-Means Clustering

K-Means, verileri her noktayı en yakın küme ortalamasına atayarak K kümeye ayıran, merkez tabanlı bir clustering algoritmasıdır. Algoritma şu şekilde çalışır:
1. **Başlatma**: Genellikle rastgele olarak veya k-means++ gibi daha akıllı yöntemlerle K başlangıç küme merkezi (centroid) seçilir.
2. **Atama**: Her veri noktası, bir mesafe metriğine (ör. Öklid mesafesi) göre en yakın centroid'e atanır.
3. **Güncelleme**: Her kümeye atanmış tüm veri noktalarının ortalaması alınarak centroid'ler yeniden hesaplanır.
4. **Tekrarlama**: Küme atamaları sabitlenene (centroid'ler artık önemli ölçüde hareket etmeyene) kadar 2–3. adımlar tekrarlanır.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* K-Means, ağ olaylarını clustering yöntemiyle gruplandırarak intrusion detection için kullanılır. Örneğin araştırmacılar K-Means'i KDD Cup 99 intrusion veri kümesine uygulamış ve trafiği normal ve saldırı kümelerine etkili bir şekilde ayırdığını bulmuştur. Uygulamada security analyst'leri, benzer etkinlik gruplarını bulmak için log kayıtlarını veya kullanıcı davranışı verilerini kümeleyebilir; iyi biçimlendirilmiş bir kümeye ait olmayan noktalar anomaly'lere işaret edebilir (ör. yeni bir malware varyantının kendine ait küçük bir küme oluşturması). K-Means, davranış profillerine veya feature vector'larına göre binary dosyaları gruplayarak malware family classification işlemine de yardımcı olabilir.

#### K Seçimi
Küme sayısı (K), algoritma çalıştırılmadan önce tanımlanması gereken bir hyperparameter'dır. Elbow Method veya Silhouette Score gibi teknikler, clustering performansını değerlendirerek K için uygun bir değer belirlemeye yardımcı olabilir:

- **Elbow Method**: Her noktadan atandığı küme centroid'ine olan kareli mesafelerin toplamını K'nin bir fonksiyonu olarak çizin. Azalma oranının keskin biçimde değiştiği ve uygun bir küme sayısını gösteren bir "dirsek" noktası arayın.
- **Silhouette Score**: Farklı K değerleri için silhouette score'u hesaplayın. Daha yüksek bir silhouette score, daha iyi tanımlanmış kümelere işaret eder.

#### Varsayımlar ve Sınırlamalar

K-Means, **kümelerin küresel ve eşit boyutlu** olduğunu varsayar; bu durum tüm veri kümeleri için geçerli olmayabilir. Centroid'lerin başlangıçtaki konumlandırılmasına duyarlıdır ve local minima'ya yakınsayabilir. Ayrıca K-Means, yoğunlukları değişen veya küresel olmayan şekillere ve farklı ölçeklere sahip feature'lar içeren veri kümeleri için uygun değildir. Tüm feature'ların mesafe hesaplamalarına eşit katkıda bulunmasını sağlamak için normalization veya standardization gibi preprocessing adımları gerekli olabilir.

<details>
<summary>Örnek -- Ağ Olaylarını Clustering ile Gruplama
</summary>
Aşağıda ağ trafiği verilerini simüle ediyor ve bunları clustering için K-Means kullanıyoruz. Bağlantı süresi ve byte sayısı gibi feature'lara sahip olaylarımız olduğunu varsayalım. "Normal" trafiğe ait 3 küme ve bir saldırı örüntüsünü temsil eden 1 küçük küme oluşturuyoruz. Ardından bunları birbirinden ayırıp ayıramadığını görmek için K-Means'i çalıştırıyoruz.
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
Bu örnekte K-Means 4 küme bulmalıdır. Küçük saldırı kümesi (alışılmadık derecede yüksek ~200 süresine sahip) normal kümelerden uzaklığı göz önüne alındığında ideal olarak kendi kümesini oluşturacaktır. Sonuçları yorumlamak için küme boyutlarını ve merkezlerini yazdırıyoruz. Gerçek bir senaryoda, az sayıda noktaya sahip küme potansiyel anomaliler olarak etiketlenebilir veya üyeleri malicious activity açısından incelenebilir.
</details>

### Hierarchical Clustering

Hierarchical clustering, aşağıdan yukarıya (agglomerative) veya yukarıdan aşağıya (divisive) bir yaklaşım kullanarak bir küme hiyerarşisi oluşturur:

1. **Agglomerative (Bottom-Up)**: Her veri noktası ayrı bir küme olarak başlatılır ve tek bir küme kalana veya bir durdurma kriteri karşılanana kadar en yakın kümeler yinelemeli olarak birleştirilir.
2. **Divisive (Top-Down)**: Tüm veri noktaları tek bir kümede başlatılır ve her veri noktası kendi kümesi olana veya bir durdurma kriteri karşılanana kadar kümeler yinelemeli olarak bölünür.

Agglomerative clustering, kümeler arası mesafenin tanımlanmasını ve hangi kümelerin birleştirileceğine karar vermek için bir linkage kriterini gerektirir. Yaygın linkage yöntemleri arasında single linkage (iki küme arasındaki en yakın noktaların mesafesi), complete linkage (en uzak noktaların mesafesi), average linkage vb. bulunur ve mesafe metriği genellikle Euclidean'dır. Linkage seçimi, oluşturulan kümelerin şeklini etkiler. Küme sayısı K'yi önceden belirtmeye gerek yoktur; istenen sayıda küme elde etmek için dendrogramı seçilen bir seviyede “kesebilirsiniz”.

Hierarchical clustering, farklı ayrıntı düzeylerinde kümeler arasındaki ilişkileri gösteren, ağaç benzeri bir yapı olan dendrogramı oluşturur. Belirli bir sayıda küme elde etmek için dendrogram istenen seviyede kesilebilir.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Hierarchical clustering, ilişkileri tespit etmek için event'leri veya entity'leri bir ağaç yapısında düzenleyebilir. Örneğin malware analizinde agglomerative clustering, sample'ları davranışsal benzerliklerine göre gruplandırarak malware family'leri ve variant'ları arasındaki hiyerarşiyi ortaya çıkarabilir. Network security'de IP traffic flow'ları cluster'lamak ve traffic'in alt gruplarını (ör. önce protocol'e, ardından behavior'a göre) görmek için dendrogram kullanılabilir. K'yi başlangıçta seçmeniz gerekmediğinden, attack category'lerinin sayısının bilinmediği yeni verileri keşfederken kullanışlıdır.

#### Assumptions and Limitations

Hierarchical clustering belirli bir küme şeklini varsaymaz ve iç içe kümeleri yakalayabilir. Taxonomy'yi veya gruplar arasındaki ilişkileri keşfetmek için kullanışlıdır (ör. malware'ı family alt gruplarına göre gruplandırmak). Deterministic'tir (random initialization sorunları yoktur). Önemli bir avantajı, tüm ölçeklerde verilerin kümeleme yapısı hakkında içgörü sağlayan dendrogramdır – security analyst'ler anlamlı kümeleri belirlemek için uygun cutoff seviyesine karar verebilir. Ancak hesaplama açısından maliyetlidir (naive implementation'larda genellikle $O(n^2)$ zaman veya daha kötüsü) ve çok büyük dataset'ler için uygun değildir. Ayrıca greedy bir prosedürdür – bir merge veya split işlemi yapıldıktan sonra geri alınamaz; bu da erken bir hata gerçekleşirse suboptimal kümelere yol açabilir. Outlier'lar bazı linkage stratejilerini de etkileyebilir (single-link, kümelerin outlier'lar üzerinden birbirine bağlandığı “chaining” etkisine neden olabilir).

<details>
<summary>Example -- Events'in Agglomerative Clustering'i
</summary>

K-Means örneğindeki sentetik verileri (3 normal küme + 1 attack cluster) yeniden kullanacak ve agglomerative clustering uygulayacağız. Ardından dendrogram ve küme label'larının nasıl elde edileceğini göstereceğiz.
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

DBSCAN, birbirine yakın noktaları birlikte gruplayan ve düşük yoğunluklu bölgelerdeki noktaları outlier olarak işaretleyen density-based bir clustering algorithm'dır. Farklı yoğunluklara ve spherical olmayan şekillere sahip dataset'ler için özellikle kullanışlıdır.

DBSCAN iki parametre tanımlayarak çalışır:
- **Epsilon (ε)**: İki noktanın aynı cluster'ın parçası sayılması için aralarındaki maksimum mesafe.
- **MinPts**: Yoğun bir bölge (core point) oluşturmak için gereken minimum nokta sayısı.

DBSCAN; core point, border point ve noise point'leri tanımlar:
- **Core Point**: ε mesafesi içinde en az MinPts komşusu bulunan nokta.
- **Border Point**: Bir core point'in ε mesafesi içinde bulunan ancak MinPts'ten daha az komşusu olan nokta.
- **Noise Point**: Ne core point ne de border point olan nokta.

Clustering, ziyaret edilmemiş bir core point seçilerek ve bunun yeni bir cluster olduğu işaretlenerek ilerler; ardından bu noktadan density-reachable olan tüm noktalar (core point'ler ve bunların komşuları vb.) recursive olarak eklenir. Border point'ler yakındaki bir core point'in cluster'ına eklenir. Ulaşılabilir tüm noktalar genişletildikten sonra DBSCAN, yeni bir cluster başlatmak için başka bir ziyaret edilmemiş core point'e geçer. Herhangi bir core point tarafından ulaşılamayan noktalar noise olarak etiketlenir.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* DBSCAN, network traffic'te anomaly detection için kullanışlıdır. Örneğin normal user activity, feature space içinde bir veya daha fazla yoğun cluster oluşturabilirken yeni attack behavior'ları, DBSCAN'in noise (outlier) olarak etiketleyeceği dağınık noktalar şeklinde görünebilir. Network flow record'larını cluster'lamak için kullanılmıştır; burada port scan'leri veya denial-of-service traffic'i seyrek nokta bölgeleri olarak tespit edebilir. Başka bir uygulama malware variant'larını gruplamaktır: örneklerin çoğu family'lere göre cluster'lanırken birkaç örnek hiçbir yere uymuyorsa, bu örnekler zero-day malware olabilir. Noise'u işaretleme yeteneği, security team'lerinin bu outlier'ları incelemeye odaklanmasını sağlar.

#### Varsayımlar ve Sınırlamalar

**Varsayımlar ve Güçlü Yönler:**: DBSCAN, spherical cluster'lar varsaymaz; keyfi şekillere sahip cluster'ları (hatta chain-like veya bitişik cluster'ları) bulabilir. Data density'ye göre cluster sayısını otomatik olarak belirler ve outlier'ları noise olarak etkili şekilde tespit edebilir. Bu, onu düzensiz şekillere ve noise'a sahip gerçek dünya dataları için güçlü hale getirir. Outlier'lara karşı dayanıklıdır (bunları cluster'lara zorlayan K-Means'in aksine). Cluster'ların yaklaşık olarak uniform density'ye sahip olduğu durumlarda iyi çalışır.

**Sınırlamalar**: DBSCAN'in performansı uygun ε ve MinPts değerlerinin seçilmesine bağlıdır. Farklı density'lere sahip datalarda zorlanabilir; tek bir ε hem yoğun hem de seyrek cluster'lara uyum sağlayamaz. ε çok küçükse çoğu noktayı noise olarak etiketler; çok büyükse cluster'lar hatalı şekilde birleşebilir. Ayrıca DBSCAN, çok büyük dataset'lerde verimsiz olabilir (naive durumda $O(n^2)$; ancak spatial indexing yardımcı olabilir). High-dimensional feature space'lerde “ε içindeki mesafe” kavramı daha az anlamlı hale gelebilir (curse of dimensionality) ve DBSCAN'in dikkatli parameter tuning'e ihtiyacı olabilir veya sezgisel cluster'ları bulamayabilir. Bunlara rağmen HDBSCAN gibi extension'lar bazı sorunları (varying density gibi) ele alır.

<details>
<summary>Örnek -- Noise ile Clustering
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
Bu snippet'te `eps` ve `min_samples` değerlerini veri ölçeğimize uyacak şekilde ayarladık (feature birimlerinde 15.0 ve bir cluster oluşturmak için 5 nokta gerekecek şekilde). DBSCAN 2 cluster (normal traffic cluster'ları) bulmalı ve enjekte edilen 5 outlier'ı noise olarak işaretlemelidir. Bunu doğrulamak için cluster sayısını ve noise noktalarının sayısını output olarak veriyoruz. Gerçek bir ortamda, kararlı clustering sonuçları bulmak için ε (ε değerini seçmek üzere k-distance graph heuristic kullanılarak) ve MinPts (genellikle pratik bir kural olarak data dimensionality + 1 civarında ayarlanır) üzerinde iterasyon yapılabilir. Noise'u açıkça label'lama yeteneği, olası attack data'sını daha ileri analiz için ayırmaya yardımcı olur.

</details>

### Principal Component Analysis (PCA)

PCA, datadaki maksimum varyansı yakalayan yeni bir orthogonal axis (principal component) kümesi bulan bir **dimensionality reduction** tekniğidir. Basitçe ifade etmek gerekirse PCA, datayı yeni bir coordinate system'e rotate eder ve project eder; böylece ilk principal component (PC1) mümkün olan en büyük varyansı, ikinci PC (PC2) PC1'e orthogonal olan en büyük varyansı açıklar ve bu şekilde devam eder. Matematiksel olarak PCA, datanın covariance matrix'inin eigenvector'larını hesaplar; bu eigenvector'lar principal component direction'larını, karşılık gelen eigenvalue'lar ise açıklanan varyans miktarını gösterir. Genellikle feature extraction, visualization ve noise reduction için kullanılır.

Dataset boyutlarının **önemli linear dependency veya correlation** içermesi durumunda bunun kullanışlı olduğunu unutmayın.

PCA, maksimum varyans yönleri olan datanın principal component'lerini tanımlayarak çalışır. PCA'de yer alan adımlar şunlardır:
1. **Standardization**: Mean'i çıkararak datayı center edin ve unit variance olacak şekilde scale edin.
2. **Covariance Matrix**: Feature'lar arasındaki ilişkileri anlamak için standardized datanın covariance matrix'ini hesaplayın.
3. **Eigenvalue Decomposition**: Eigenvalue ve eigenvector'ları elde etmek için covariance matrix üzerinde eigenvalue decomposition gerçekleştirin.
4. **Select Principal Components**: Eigenvalue'ları azalan sırada sıralayın ve en büyük eigenvalue'lara karşılık gelen ilk K eigenvector'ı seçin. Bu eigenvector'lar yeni feature space'i oluşturur.
5. **Transform Data**: Seçilen principal component'leri kullanarak original datayı yeni feature space üzerine project edin.
PCA, data visualization, noise reduction ve diğer machine learning algorithm'leri için preprocessing step olarak yaygın şekilde kullanılır. Temel yapısını korurken datanın dimensionality'sini azaltmaya yardımcı olur.

#### Eigenvalues and Eigenvectors

Bir eigenvalue, karşılık gelen eigenvector tarafından yakalanan varyans miktarını gösteren bir scalar'dır. Bir eigenvector, datanın en fazla değiştiği feature space içindeki yönü temsil eder.

A'nın square matrix ve v'nin şu koşulu sağlayan non-zero vector olduğunu düşünün: `A * v = λ * v`
burada:
- A, [ [1, 2], [2, 1]] gibi bir square matrix'tir (ör. covariance matrix)
- v, bir eigenvector'dır (ör. [1, 1])

Ardından `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` olur. Bu değer, eigenvalue λ ile eigenvector v'nin çarpımıdır ve eigenvalue λ = 3 olur.

#### Eigenvalues and Eigenvectors in PCA

Bunu bir örnekle açıklayalım. 100x100 pixel boyutunda çok sayıda grayscale yüz görseli içeren bir dataset'iniz olduğunu düşünün. Her pixel bir feature olarak kabul edilebilir; bu nedenle image başına 10.000 feature'a (veya image başına 10000 component içeren bir vector'e) sahip olursunuz. Bu dataset'in dimensionality'sini PCA kullanarak azaltmak istiyorsanız şu adımları izlersiniz:

1. **Standardization**: Her feature'ın (pixel'in) mean'ini dataset'ten çıkararak datayı center edin.
2. **Covariance Matrix**: Feature'ların (pixel'lerin) birlikte nasıl değiştiğini yakalayan standardized datanın covariance matrix'ini hesaplayın.
- İki variable (bu durumda pixel) arasındaki covariance'ın, birlikte ne kadar değiştiklerini gösterdiğini unutmayın; dolayısıyla buradaki fikir, hangi pixel'lerin linear bir ilişkiyle birlikte artma veya azalma eğiliminde olduğunu bulmaktır.
- Örneğin pixel 1 ve pixel 2 birlikte artma eğilimindeyse aralarındaki covariance positive olacaktır.
- Covariance matrix, her entry'nin iki pixel arasındaki covariance'ı temsil ettiği 10,000x10,000 boyutunda bir matrix olacaktır.
3. **Solve the The eigenvalue equation**: Çözülecek eigenvalue equation `C * v = λ * v` şeklindedir; burada C covariance matrix, v eigenvector ve λ eigenvalue'dur. Şu method'lar kullanılarak çözülebilir:
- **Eigenvalue Decomposition**: Eigenvalue ve eigenvector'ları elde etmek için covariance matrix üzerinde eigenvalue decomposition gerçekleştirin.
- **Singular Value Decomposition (SVD)**: Alternatif olarak data matrix'ini singular value ve vector'lara ayırmak için SVD kullanabilirsiniz; bu işlem de principal component'leri sağlayabilir.
4. **Select Principal Components**: Eigenvalue'ları azalan sırada sıralayın ve en büyük eigenvalue'lara karşılık gelen ilk K eigenvector'ı seçin. Bu eigenvector'lar datadaki maksimum varyans yönlerini temsil eder.

> [!TIP]
> *Use cases in cybersecurity:* Security'de PCA'nın yaygın bir kullanımı anomaly detection için feature reduction'dır. Örneğin 40'tan fazla network metric'i (NSL-KDD feature'ları gibi) içeren bir intrusion detection system, visualization için datayı özetlemek veya clustering algorithm'lerine beslemek amacıyla PCA kullanarak birkaç component'e indirgenebilir. Analyst'ler attack'ların normal traffic'ten ayrılıp ayrılmadığını görmek için network traffic'i ilk iki principal component'in space'inde plot edebilir. PCA, detection algorithm'lerini daha robust ve hızlı hale getirmek için redundant feature'ları (correlated olmaları durumunda bytes sent ve bytes received gibi) ortadan kaldırmaya da yardımcı olabilir.

#### Assumptions and Limitations

PCA, **principal axes of variance'ın anlamlı olduğunu** varsayar; bu bir linear method'dur ve dolayısıyla datadaki linear correlation'ları yakalar. Yalnızca feature covariance'ını kullandığı için unsupervised'dır. PCA'nın avantajları arasında noise reduction (small-variance component'ler çoğu zaman noise'a karşılık gelir) ve feature'ların decorrelation'ı bulunur. Orta derecede yüksek dimensionality için computationally efficient'tir ve diğer algorithm'ler için sıklıkla kullanışlı bir preprocessing step'tir (curse of dimensionality'yi azaltmak için). Bir limitation, PCA'nın linear relationship'lerle sınırlı olmasıdır; karmaşık nonlinear structure'ı yakalayamaz (autoencoder veya t-SNE ise yakalayabilir). Ayrıca PCA component'lerini original feature'lar açısından yorumlamak zor olabilir (bunlar original feature'ların combination'larıdır). Cybersecurity'de dikkatli olunmalıdır: yalnızca low-variance bir feature'da subtle bir değişikliğe neden olan bir attack, top PC'lerde görünmeyebilir (çünkü PCA varyansa öncelik verir; bunun mutlaka “interestingness” anlamına gelmesi gerekmez).

<details>
<summary>Example -- Reducing Dimensions of Network Data
</summary>

Birden fazla feature'a (ör. duration, bytes, count) sahip network connection log'larına sahip olduğumuzu varsayalım. Sentetik bir 4-dimensional dataset (feature'lar arasında bir miktar correlation ile) oluşturacağız ve visualization veya ileri analiz için PCA kullanarak bunu 2 dimension'a indirgeyeceğiz.
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
Burada daha önceki normal traffic cluster'larını aldık ve her data point'i bytes ve duration ile korelasyon gösteren iki ek feature (packets ve errors) ile genişlettik. Ardından PCA, 4 feature'ı 2 principal component'e sıkıştırmak için kullanılır. Açıklanan variance ratio'yu yazdırırız; bu, örneğin variance'ın >%95'inin 2 component tarafından yakalandığını gösterebilir (yani bilgi kaybı azdır). Çıktı ayrıca data shape'inin (1500, 4)'ten (1500, 2)'ye düştüğünü gösterir. PCA space'teki ilk birkaç point örnek olarak verilir. Uygulamada, cluster'ların ayırt edilip edilemediğini görsel olarak kontrol etmek için data_2d plot edilebilir. Bir anomaly mevcutsa, PCA-space'te ana cluster'dan uzakta bulunan bir point olarak görülebilir. Bu nedenle PCA, karmaşık datayı insan yorumlaması veya diğer algorithm'lere input olarak kullanması için yönetilebilir bir forma indirgemeye yardımcı olur.

</details>


### Gaussian Mixture Models (GMM)

Bir Gaussian Mixture Model, datanın **parametreleri bilinmeyen birkaç Gaussian (normal) distribution'ın karışımından üretildiğini** varsayar. Esasen bu, probabilistic bir clustering modelidir: her point'i K Gaussian component'ten birine soft olarak atamaya çalışır. Her Gaussian component k; bir mean vector'üne (μ_k), covariance matrix'ine (Σ_k) ve ilgili cluster'ın ne kadar yaygın olduğunu gösteren bir mixing weight'e (π_k) sahiptir. “Hard” assignment yapan K-Means'in aksine GMM, her point için her cluster'a ait olma probability'sini verir.

GMM fitting işlemi genellikle Expectation-Maximization (EM) algorithm'ı kullanılarak yapılır:

- **Initialization**: Mean'ler, covariance'lar ve mixing coefficient'lar için başlangıç tahminleriyle başlanır (veya başlangıç point'i olarak K-Means sonuçları kullanılır).

- **E-step (Expectation)**: Mevcut parametreler verildiğinde, her point için her cluster'ın responsibility'si hesaplanır: temel olarak `r_nk = P(z_k | x_n)`; burada z_k, x_n point'i için cluster membership'ı gösteren latent variable'dır. Bu işlem, mevcut parametrelere göre her point'in her cluster'a ait olmasının posterior probability'sini hesapladığımız Bayes' theorem kullanılarak yapılır. Responsibility'ler şu şekilde hesaplanır:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
burada:
- \( \pi_k \), k cluster'ı için mixing coefficient'tır (k cluster'ının prior probability'si),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \), mean'i \( \mu_k \) ve covariance'ı \( \Sigma_k \) olan k dağılımına göre \( x_n \) point'inin Gaussian probability density function'ıdır.

- **M-step (Maximization)**: Parametreler, E-step'te hesaplanan responsibility'ler kullanılarak güncellenir:
- Her mean μ_k, responsibility'lerin weight olarak kullanıldığı point'lerin weighted average'ı şeklinde güncellenir.
- Her covariance Σ_k, k cluster'ına atanan point'lerin weighted covariance'ı olarak güncellenir.
- Mixing coefficient π_k, k cluster'ı için average responsibility olarak güncellenir.

- Convergence sağlanana kadar **E ve M step'leri tekrarlanır** (parametreler stabilize olur veya likelihood improvement belirli bir threshold'un altına iner).

Sonuç, genel data distribution'ını birlikte modelleyen bir Gaussian distribution set'idir. Fitted GMM'i, her point'i probability'si en yüksek olan Gaussian'a atayarak clustering yapmak için kullanabilir veya uncertainty için probability'leri koruyabiliriz. Ayrıca yeni point'lerin likelihood'ı değerlendirilerek modele uyup uymadıkları görülebilir (anomaly detection için faydalıdır).

> [!TIP]
> *Cybersecurity'deki kullanım alanları:* GMM, normal datanın distribution'ını modelleyerek anomaly detection için kullanılabilir: öğrenilen mixture altında probability'si çok düşük olan her point anomaly olarak işaretlenir. Örneğin, legitimate network traffic feature'ları üzerinde bir GMM train edilebilir; öğrenilen cluster'ların hiçbirine benzemeyen bir attack connection düşük likelihood'a sahip olur. GMM'ler, cluster'ların farklı şekillere sahip olabileceği aktiviteleri cluster'lamak için de kullanılır – örneğin, kullanıcıları behavior profile'larına göre gruplandırmak; her profile'ın feature'ları Gaussian-like olabilir, ancak kendine ait bir variance structure'a sahip olabilir. Başka bir senaryo phishing detection'dır: legitimate email feature'ları bir Gaussian cluster, bilinen phishing'ler başka bir cluster oluşturabilir ve yeni phishing campaign'leri ayrı bir Gaussian olarak veya mevcut mixture'a göre düşük likelihood'lı point'ler şeklinde ortaya çıkabilir.

#### Assumptions and Limitations

GMM, covariance'ı dahil eden bir K-Means generalization'ıdır; bu nedenle cluster'lar yalnızca spherical değil, ellipsoidal da olabilir. Covariance full olduğunda farklı boyut ve şekillerdeki cluster'ları handle eder. Soft clustering, cluster boundary'lerinin belirsiz olduğu durumlarda avantajlıdır – örneğin cybersecurity'de bir event birden fazla attack type'ın özelliklerine sahip olabilir; GMM bu uncertainty'yi probability'lerle yansıtabilir. GMM ayrıca datanın probabilistic density estimation'ını sağlar; bu, tüm mixture component'leri altında likelihood'ı düşük olan outlier'ları tespit etmek için faydalıdır.

Olumsuz tarafı, GMM'in component sayısı K'nın belirtilmesini gerektirmesidir (ancak seçmek için BIC/AIC gibi criteria kullanılabilir). EM bazen yavaş convergence sağlayabilir veya local optimum'a ulaşabilir; bu nedenle initialization önemlidir (EM genellikle birden fazla kez çalıştırılır). Data aslında Gaussian mixture'ını takip etmiyorsa model kötü bir fit sağlayabilir. Ayrıca bir Gaussian'ın yalnızca bir outlier'ı kapsayacak şekilde küçülmesi riski vardır (ancak regularization veya minimum covariance bounds bunu azaltabilir).


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
Bu kodda, normal trafik üzerinde 3 Gaussian ile bir GMM eğitiyoruz (meşru trafiğin 3 profilini bildiğimizi varsayarak). Yazdırılan ortalamalar ve kovaryanslar bu kümeleri tanımlar (örneğin, bir ortalama [50,500] civarında olabilir ve bu da kümelerden birinin merkezine karşılık gelir). Ardından şüpheli bir bağlantıyı [duration=200, bytes=800] test ediyoruz. predict_proba, bu noktanın 3 kümenin her birine ait olma olasılığını verir – [200,800] normal kümelerden uzakta bulunduğu için bu olasılıkların çok düşük veya oldukça çarpık olmasını bekleriz. Genel score_samples (log-likelihood) yazdırılır; çok düşük bir değer, noktanın modele iyi uymadığını gösterir ve bu da bir anomali olarak işaretlenmesini sağlar. Uygulamada, bir noktanın malicious kabul edilemeyecek kadar olasılık dışı olup olmadığına karar vermek için log-likelihood (veya maksimum olasılık) üzerinde bir eşik belirlenebilir. GMM böylece anomaly detection için ilkeli bir yöntem sunar ve ayrıca belirsizliği kabul eden soft clusters üretir.
</details>

### Isolation Forest

**Isolation Forest**, noktaları rastgele izole etme fikrine dayanan bir ensemble anomaly detection algoritmasıdır. Temel ilke, anomalilerin az sayıda ve farklı olması nedeniyle normal noktalara kıyasla daha kolay izole edilebilmeleridir. Bir Isolation Forest, verileri rastgele bölümlere ayıran çok sayıda binary isolation tree (random decision tree) oluşturur. Bir ağaçtaki her düğümde, rastgele bir feature seçilir ve o düğümdeki veriler için bu feature'ın minimum ve maksimum değerleri arasında rastgele bir bölme değeri belirlenir. Bu bölme, verileri iki dala ayırır. Ağaç, her nokta kendi leaf'inde izole edilene veya maksimum ağaç yüksekliğine ulaşılana kadar büyütülür.

Anomaly detection, bu random tree'lerde her noktanın path length'ini – noktayı izole etmek için gereken bölme sayısını – gözlemleyerek gerçekleştirilir. Sezgisel olarak, anomalies (outlier'lar), yoğun bir cluster'daki normal bir noktaya kıyasla seyrek bir bölgede bulunan bir outlier'ı random split'in ayırma olasılığı daha yüksek olduğundan daha hızlı izole edilme eğilimindedir. Isolation Forest, tüm ağaçlardaki ortalama path length'ten bir anomaly score hesaplar: daha kısa ortalama path → daha anomalous. Score'lar genellikle [0,1] aralığında normalize edilir; burada 1, anomaly olasılığının çok yüksek olduğu anlamına gelir.

> [!TIP]
> *Siber güvenlikte kullanım alanları:* Isolation Forest'lar intrusion detection ve fraud detection'da başarıyla kullanılmıştır. Örneğin, çoğunlukla normal davranış içeren network traffic log'ları üzerinde bir Isolation Forest eğitin; forest, sıra dışı traffic için (örneğin daha önce görülmemiş bir port kullanan veya alışılmadık bir packet size pattern'ine sahip bir IP) kısa path'ler üreterek bu trafiği inceleme için işaretler. Labeled attack'ler gerektirmediğinden, bilinmeyen attack türlerini tespit etmek için uygundur. Ayrıca account takeover'ları tespit etmek amacıyla user login data üzerinde de deploy edilebilir (anomalous login time'lar veya location'lar hızlıca izole edilir). Bir kullanım alanında Isolation Forest, system metrics'i izleyerek ve bir metrics kombinasyonu (CPU, network, file changes) historical pattern'lerden çok farklı göründüğünde (kısa isolation path'ler) alert oluşturarak bir enterprise'ı koruyabilir.

#### Assumptions and Limitations

**Advantages**: Isolation Forest bir distribution assumption gerektirmez; doğrudan isolation'ı hedefler. High-dimensional data ve large dataset'lerde etkilidir (forest oluşturmanın linear complexity'si $O(n\log n)$'dir); çünkü her tree, yalnızca feature'ların bir subset'ini ve split'leri kullanarak noktaları izole eder. Numerical feature'ları iyi ele alma eğilimindedir ve $O(n^2)$ olabilen distance-based method'lardan daha hızlı olabilir. Ayrıca otomatik olarak bir anomaly score sağlar; böylece alert'ler için bir threshold belirleyebilir (veya beklenen anomaly fraction'a göre bir cutoff'ı otomatik olarak belirlemek için contamination parameter'ı kullanabilirsiniz).

**Limitations**: Random yapısı nedeniyle sonuçlar run'lar arasında biraz değişebilir (ancak yeterli sayıda tree ile bu fark önemsizdir). Data'da çok sayıda ilgisiz feature varsa veya anomalies herhangi bir feature'da güçlü biçimde farklılaşmıyorsa isolation etkili olmayabilir (random split'ler normal noktaları şans eseri izole edebilir – ancak çok sayıda tree'nin average edilmesi bu durumu azaltır). Ayrıca Isolation Forest genellikle anomalies'in küçük bir minority olduğunu varsayar (bu, siber güvenlik senaryolarında genellikle doğrudur).

<details>
<summary>Example --  Detecting Outliers in Network Logs
</summary>

Daha önceki test dataset'ini (normal ve bazı attack noktalarını içeren) kullanacağız ve attack'leri ayırıp ayıramadığını görmek için bir Isolation Forest çalıştıracağız. Gösterim amacıyla, data'nın yaklaşık %15'inin anomalous olmasını beklediğimizi varsayacağız.
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
Bu kodda, `IsolationForest` öğesini 100 ağaçla başlatıyor ve `contamination=0.15` olarak ayarlıyoruz (yani yaklaşık %15 anomaly bekliyoruz; model, noktaların yaklaşık %15'inin işaretlenmesi için skor eşiğini belirleyecek). Modeli, normal ve attack noktalarının bir karışımını içeren `X_test_if` üzerinde eğitiyoruz (not: normalde training data üzerinde eğitir ve ardından yeni veriler üzerinde `predict` kullanırdınız; ancak burada sonuçları doğrudan gözlemlemek için örnek olarak aynı veri kümesi üzerinde hem eğitim hem de tahmin yapıyoruz).

Çıktı, ilk 20 nokta için tahmin edilen etiketleri gösterir (`-1` anomaly olduğunu belirtir). Ayrıca toplamda kaç anomaly tespit edildiğini ve bazı örnek anomaly skorlarını yazdırıyoruz. `contamination` %15 olarak ayarlandığından yaklaşık 120 noktanın 18'inin `-1` olarak etiketlenmesini bekleriz. 20 attack örneğimiz gerçekten en aykırı örneklerse bunların çoğu `-1` tahminleri arasında görünmelidir. Anomaly skoru (Isolation Forest'ın decision function değeri) normal noktalar için daha yüksek, anomaly noktaları içinse daha düşük (daha negatif) olur; ayrımı görmek için birkaç değeri yazdırıyoruz. Uygulamada, en aykırı noktaları görmek ve bunları incelemek için veriler skorlarına göre sıralanabilir. Isolation Forest böylece büyük ve labelsız security verilerini taramak ve en düzensiz örnekleri insan analizi veya daha ileri otomatik inceleme için seçmek üzere verimli bir yöntem sunar.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE**, yüksek boyutlu verileri 2 veya 3 boyutta görselleştirmek için özel olarak tasarlanmış doğrusal olmayan bir boyut indirgeme tekniğidir. Veri noktaları arasındaki benzerlikleri ortak olasılık dağılımlarına dönüştürür ve düşük boyutlu projeksiyonda yerel komşulukların yapısını korumaya çalışır. Daha basit ifadeyle t-SNE, (örneğin) 2D'de noktaları, orijinal uzayda benzer olan noktalar birbirine yakın, farklı olan noktalar ise yüksek olasılıkla birbirinden uzak olacak şekilde yerleştirir.

Algoritmanın üç ana aşaması vardır:

1. **Yüksek boyutlu uzayda ikili yakınlıkları hesaplama:** Her nokta çifti için t-SNE, bu çiftin komşu olarak seçilme olasılığını hesaplar (bu işlem her noktanın merkezine bir Gaussian dağılımı yerleştirilerek ve mesafeler ölçülerek yapılır; perplexity parametresi dikkate alınan etkin komşu sayısını etkiler).
2. **Düşük boyutlu (ör. 2D) uzayda ikili yakınlıkları hesaplama:** Başlangıçta noktalar 2D'ye rastgele yerleştirilir. t-SNE, bu haritadaki mesafeler için benzer bir olasılık tanımlar (uzak noktalara daha fazla hareket özgürlüğü sağlamak amacıyla Gaussian'dan daha ağır kuyruklara sahip bir Student t-distribution kernel kullanır).
3. **Gradient Descent:** t-SNE daha sonra, yüksek boyutlu affinity dağılımı ile düşük boyutlu dağılım arasındaki Kullback–Leibler (KL) divergence değerini en aza indirmek için 2D'deki noktaları yinelemeli olarak hareket ettirir. Bu işlem, 2D düzenlemesinin yüksek boyutlu yapıyı mümkün olduğunca yansıtmasını sağlar; orijinal uzayda birbirine yakın olan noktalar birbirini çeker, uzak olanlar ise bir denge sağlanana kadar birbirini iter.

Sonuç genellikle, veri kümelerindeki cluster'ların görünür hâle geldiği, görsel açıdan anlamlı bir scatter plot olur.

> [!TIP]
> *Cybersecurity kullanım alanları:* t-SNE, genellikle **yüksek boyutlu security verilerini insan analizi için görselleştirmek** amacıyla kullanılır. Örneğin bir security operations center'daki analistler, düzinelerce feature (port numaraları, frekanslar, byte sayıları vb.) içeren bir event veri kümesini alıp t-SNE ile 2D bir plot oluşturabilir. Attack'lar bu plot'ta kendi cluster'larını oluşturabilir veya normal verilerden ayrılabilir; bu da onların tanımlanmasını kolaylaştırır. t-SNE, malware family'lerinin gruplandırılmasını görmek için malware veri kümelerine veya farklı attack türlerinin belirgin biçimde cluster oluşturduğu network intrusion verilerine uygulanmış ve daha ileri incelemelere yön vermiştir. Esasen t-SNE, aksi hâlde anlaşılması zor olacak cyber verilerindeki yapıyı görmeyi sağlar.

#### Varsayımlar ve Sınırlamalar

t-SNE, pattern'lerin görsel olarak keşfedilmesi için oldukça iyidir. Diğer doğrusal yöntemlerin (PCA gibi) ortaya çıkaramayabileceği cluster'ları, alt cluster'ları ve outlier'ları gösterebilir. Malware davranış profilleri veya network traffic pattern'leri gibi karmaşık verileri görselleştirmek için cybersecurity araştırmalarında kullanılmıştır. Yerel yapıyı koruduğu için doğal gruplandırmaları göstermek konusunda başarılıdır.

Ancak t-SNE hesaplama açısından daha ağırdır (yaklaşık $O(n^2)$); bu nedenle çok büyük veri kümelerinde sampling gerekebilir. Ayrıca çıktıyı etkileyebilen hyperparameter'lara (perplexity, learning rate, iterations) sahiptir; örneğin farklı perplexity değerleri, farklı ölçeklerdeki cluster'ları ortaya çıkarabilir. t-SNE plot'ları bazen yanlış yorumlanabilir; haritadaki mesafeler global ölçekte doğrudan anlamlı değildir (yerel komşuluğa odaklanır ve bazen cluster'lar yapay olarak birbirinden çok iyi ayrılmış görünebilir). Ayrıca t-SNE esas olarak görselleştirme içindir; yeni veri noktalarını yeniden hesaplama yapmadan project etmek için basit bir yöntem sunmaz ve predictive modeling için preprocessing olarak kullanılmak üzere tasarlanmamıştır (UMAP, daha yüksek hızla bu sorunların bazılarını ele alan bir alternatiftir).

<details>
<summary>Örnek -- Network Connections Görselleştirme
</summary>

Çok feature'lı bir veri kümesini 2D'ye indirgemek için t-SNE kullanacağız. Örnek olarak, önceki 4D verilerini (normal traffic'in 3 doğal cluster'ını içeren) alıp birkaç anomaly noktası ekleyelim. Ardından t-SNE'yi çalıştırıp sonuçları (kavramsal olarak) görselleştireceğiz.
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
Burada önceki 4D normal veri setimizi, birkaç uç aykırı değerle birleştirdik (aykırı değerlerin bir özelliği (“duration”) olağandışı bir paterni simüle etmek için çok yüksek bir değere ayarlanmıştır vb.). t-SNE'yi 30 gibi tipik bir perplexity değeriyle çalıştırıyoruz. `data_2d` çıktısının şekli (1505, 2) olur. Bu metinde gerçekten bir grafik oluşturmayacağız; oluştursaydık, 3 normal kümeye karşılık gelen muhtemelen üç sıkı küme ve bu kümelerden uzakta izole noktalar olarak görünen 5 aykırı değer beklerdik. Etkileşimli bir iş akışında, bu yapıyı doğrulamak için noktaları etiketlerine göre (normal veya hangi kümede oldukları ya da anomaly) renklendirebilirdik. Etiketler olmasa bile bir analist, 2D grafikte boş bir alanda duran bu 5 noktayı fark edip işaretleyebilirdi. Bu, t-SNE'nin siber güvenlik verilerinde görsel anomaly detection ve küme incelemesine nasıl güçlü bir yardımcı olabileceğini ve yukarıdaki otomatik algoritmaları nasıl tamamladığını gösterir.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN**, tek bir global `eps` değeri seçme gereksinimini ortadan kaldıran ve yoğunluğa bağlı bileşenlerden oluşan bir hiyerarşi kurup bunu yoğunlaştırarak **farklı yoğunluklara** sahip kümeleri ortaya çıkarabilen bir DBSCAN uzantısıdır. Vanilla DBSCAN ile karşılaştırıldığında genellikle

* bazı kümeler yoğun, diğerleri seyrek olduğunda daha sezgisel kümeler çıkarır,
* yalnızca bir gerçek hyper-parameter'a (`min_cluster_size`) sahiptir ve makul bir varsayılan değer sunar,
* her noktaya bir küme üyeliği *olasılığı* ve threat-hunting dashboard'ları için son derece kullanışlı olan bir **outlier score** (`outlier_scores_`) verir.<sup>[[1]](#references)</sup>

> [!TIP]
> *Siber güvenlikte kullanım alanları:* HDBSCAN, modern threat-hunting pipeline'larında oldukça popülerdir; ticari XDR suite'leriyle birlikte sunulan notebook tabanlı hunting playbook'larında sıklıkla kullanıldığını görürsünüz. Pratik bir yöntem, IR sırasında HTTP beaconing trafiğini kümelendirmektir: user-agent, interval ve URI length genellikle meşru software updater'lara ait birkaç sıkı grup oluştururken C2 beacon'ları küçük, düşük yoğunluklu kümeler veya tamamen noise olarak kalır.

<details>
<summary>Örnek – Beaconing C2 kanallarını bulma</summary>
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

### Dayanıklılık ve Security Considerations – Poisoning & Adversarial Attacks (2023-2025)

Son çalışmalar, **unsupervised learner'ların *active attacker'lara karşı bağışık olmadığını*** göstermiştir:

* **Anomaly detector'lara karşı Data-poisoning.** Chen *et al.* (IEEE S&P 2024), yalnızca %3 oranında hazırlanmış traffic eklemenin Isolation Forest ve ECOD'un decision boundary'sini değiştirerek gerçek attack'ların normal görünmesini sağlayabildiğini gösterdi. Yazarlar, poison point'leri otomatik olarak sentezleyen open-source bir PoC (`udo-poison`) yayınladı.<sup>[[2]](#references)</sup>
* **Clustering model'larına Backdooring.** *BadCME* tekniği (BlackHat EU 2023), küçük bir trigger pattern yerleştirir; bu trigger ortaya çıktığında K-Means tabanlı detector, event'i sessizce “benign” cluster'ın içine yerleştirir.
* **DBSCAN/HDBSCAN Evasion.** KU Leuven'den 2025 tarihli bir academic pre-print, attacker'ın bilerek density gap'lerine düşen beaconing pattern'leri hazırlayarak *noise* label'larının içinde etkili biçimde gizlenebileceğini gösterdi.

Giderek daha fazla benimsenen mitigation'lar:

1. **Model sanitisation / TRIM.** Her retraining epoch'undan önce, poisoning'i önemli ölçüde zorlaştırmak için en yüksek loss değerine sahip %1–2 oranındaki point'leri atın (trimmed maximum likelihood).
2. **Consensus ensembling.** Birkaç farklı detector'ı (ör. Isolation Forest + GMM + ECOD) birleştirin ve herhangi bir model bir point'i işaretlerse alert oluşturun. Araştırmalar bunun attacker'ın maliyetini 10×'dan fazla artırdığını gösteriyor.
3. **Clustering için Distance-based defence.** Cluster'ları `k` farklı random seed ile yeniden hesaplayın ve sürekli cluster değiştiren point'leri yok sayın.

---

### Modern Open-Source Tooling (2024-2025)

* **PyOD 2.x** (Mayıs 2024'te yayınlandı), *ECOD*, *COPOD* ve GPU-accelerated *AutoFormer* detector'larını ekledi. Artık dataset'inizde 30'dan fazla algorithm'i **tek satır kodla** karşılaştırmanıza olanak tanıyan bir `benchmark` sub-command'i içeriyor:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (Şubat 2025), vision'a odaklanır ancak screenshot tabanlı phishing page detection için kullanışlı olan generic bir **PatchCore** implementation'ı da içerir.
* **scikit-learn 1.5** (Kasım 2024), yeni `cluster.HDBSCAN` wrapper'ı aracılığıyla nihayet *HDBSCAN* için `score_samples` özelliğini kullanıma sundu; böylece Python 3.12 kullanırken external contrib package'e ihtiyaç duymazsınız.

<details>
<summary>Hızlı PyOD örneği – ECOD + Isolation Forest ensemble</summary>
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

## Referanslar

- [1] [HDBSCAN – Hiyerarşik yoğunluk tabanlı kümeleme](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *ve diğerleri* “Denetimsiz Anomali Tespitinin Veri Zehirlemeye Karşı Savunmasızlığı.” *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
