# Gözetimsiz Öğrenme Algoritmaları

{{#include ../banners/hacktricks-training.md}}

## Gözetimsiz Öğrenme

Gözetimsiz öğrenme, modelin etiketlenmiş yanıtlar olmadan veriler üzerinde eğitildiği bir makine öğrenimi türüdür. Amaç, veriler içinde desenler, yapılar veya ilişkiler bulmaktır. Etiketlenmiş örneklerden öğrenen gözetimli öğrenmenin aksine, gözetimsiz öğrenme algoritmaları etiketlenmemiş verilerle çalışır. Gözetimsiz öğrenme genellikle kümeleme, boyut azaltma ve anomali tespiti gibi görevler için kullanılır. Verilerde gizli desenleri keşfetmeye, benzer öğeleri bir araya getirmeye veya verinin temel özelliklerini korurken karmaşıklığını azaltmaya yardımcı olabilir.

### K-Ortalamalar Kümeleme

K-Ortalamalar, verileri en yakın küme ortalamasına atayarak K kümeye ayıran merkez tabanlı bir kümeleme algoritmasıdır. Algoritma şu şekilde çalışır:
1. **Başlatma**: Genellikle rastgele veya k-means++ gibi daha akıllı yöntemlerle K başlangıç küme merkezleri (merkezler) seçin.
2. **Atama**: Her veri noktasını bir mesafe metriğine (örneğin, Öklid mesafesi) dayanarak en yakın merkeze atayın.
3. **Güncelleme**: Her kümeye atanan tüm veri noktalarının ortalamasını alarak merkezleri yeniden hesaplayın.
4. **Tekrarla**: Küme atamaları istikrara kavuşana kadar (merkezler artık önemli ölçüde hareket etmediğinde) Adım 2-3'ü tekrarlayın.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* K-Ortalamalar, ağ olaylarını kümeleyerek saldırı tespiti için kullanılır. Örneğin, araştırmacılar KDD Cup 99 saldırı veri kümesine K-Ortalamalar uyguladılar ve bunun trafiği normal ve saldırı kümelerine etkili bir şekilde ayırdığını buldular. Pratikte, güvenlik analistleri benzer etkinlik gruplarını bulmak için günlük girişlerini veya kullanıcı davranış verilerini kümeleyebilir; iyi biçimlenmiş bir kümeye ait olmayan herhangi bir nokta anomali gösterebilir (örneğin, kendi küçük kümesini oluşturan yeni bir kötü amaçlı yazılım varyantı). K-Ortalamalar, davranış profilleri veya özellik vektörlerine dayalı olarak ikili dosyaları gruplandırarak kötü amaçlı yazılım aile sınıflandırmasına da yardımcı olabilir.

#### K'nın Seçimi
Kümelerin sayısı (K), algoritmayı çalıştırmadan önce tanımlanması gereken bir hiperparametredir. Elbow Yöntemi veya Silhouette Skoru gibi teknikler, kümeleme performansını değerlendirerek K için uygun bir değer belirlemeye yardımcı olabilir:

- **Elbow Yöntemi**: Her noktanın atandığı küme merkezine olan kare mesafelerinin toplamını K'nin bir fonksiyonu olarak çizin. Uygun bir küme sayısını gösteren, azalma oranının keskin bir şekilde değiştiği "dirsek" noktasını arayın.
- **Silhouette Skoru**: Farklı K değerleri için siluet skorunu hesaplayın. Daha yüksek bir siluet skoru, daha iyi tanımlanmış kümeleri gösterir.

#### Varsayımlar ve Sınırlamalar

K-Ortalamalar, **kümelerin küresel ve eşit boyutlu olduğu** varsayımında bulunur; bu, tüm veri setleri için geçerli olmayabilir. Merkezlerin başlangıç yerleştirmesine duyarlıdır ve yerel minimumlara yakınsama gösterebilir. Ayrıca, K-Ortalamalar, farklı yoğunluklara veya küresel olmayan şekillere sahip veri setleri ve farklı ölçeklere sahip özellikler için uygun değildir. Tüm özelliklerin mesafe hesaplamalarına eşit şekilde katkıda bulunmasını sağlamak için normalizasyon veya standartlaştırma gibi ön işleme adımları gerekli olabilir.

<details>
<summary>Örnek -- Ağ Olaylarını Kümeleme
</summary>
Ağ trafiği verilerini simüle ediyoruz ve K-Ortalamalar kullanarak bunları kümelemeye çalışıyoruz. Bağlantı süresi ve bayt sayısı gibi özelliklere sahip olaylarımız olduğunu varsayalım. "Normal" trafiğin 3 kümesini ve bir saldırı desenini temsil eden 1 küçük küme oluşturuyoruz. Ardından, bunları ayırıp ayıramadığını görmek için K-Ortalamalar çalıştırıyoruz.
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
Bu örnekte, K-Means 4 küme bulmalıdır. Küçük saldırı kümesi (olağanüstü yüksek süre ~200) normal kümelerden uzaklığı nedeniyle ideal olarak kendi kümesini oluşturacaktır. Sonuçları yorumlamak için küme boyutlarını ve merkezlerini yazdırıyoruz. Gerçek bir senaryoda, birkaç noktadan oluşan kümeyi potansiyel anormallikler olarak etiketlemek veya üyelerini kötü niyetli etkinlik açısından incelemek mümkündür.

### Hiyerarşik Kümeleme

Hiyerarşik kümeleme, ya aşağıdan yukarı (agglomeratif) bir yaklaşım ya da yukarıdan aşağı (bölücü) bir yaklaşım kullanarak kümelerin bir hiyerarşisini oluşturur:

1. **Agglomeratif (Aşağıdan Yukarı)**: Her veri noktasını ayrı bir küme olarak başlatın ve en yakın kümeleri tekrarlayarak birleştirin, ta ki tek bir küme kalana veya bir durdurma kriteri karşılanana kadar.
2. **Bölücü (Yukarıdan Aşağı)**: Tüm veri noktalarını tek bir kümede başlatın ve her veri noktası kendi kümesi olana veya bir durdurma kriteri karşılanana kadar kümeleri tekrarlayarak bölün.

Agglomeratif kümeleme, kümeler arası mesafenin tanımını ve hangi kümelerin birleştirileceğini belirlemek için bir bağlantı kriteri gerektirir. Yaygın bağlantı yöntemleri arasında tek bağlantı (iki küme arasındaki en yakın noktaların mesafesi), tam bağlantı (en uzak noktaların mesafesi), ortalama bağlantı vb. bulunur ve mesafe metriği genellikle Öklidyen'dir. Bağlantı seçimi, üretilen kümelerin şeklini etkiler. Kümelerin sayısını K önceden belirtmeye gerek yoktur; istenen sayıda küme elde etmek için dendrogramı seçilen bir seviyede "kesebilirsiniz".

Hiyerarşik kümeleme, farklı granülarite seviyelerinde kümeler arasındaki ilişkileri gösteren ağaç benzeri bir yapı olan bir dendrogram üretir. Dendrogram, belirli bir sayıda küme elde etmek için istenen seviyede kesilebilir.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* Hiyerarşik kümeleme, olayları veya varlıkları bir ağaç yapısında organize ederek ilişkileri tespit edebilir. Örneğin, kötü amaçlı yazılım analizinde, agglomeratif kümeleme örnekleri davranışsal benzerliğe göre gruplandırabilir ve kötü amaçlı yazılım aileleri ve varyantları hiyerarşisini ortaya çıkarabilir. Ağ güvenliğinde, IP trafik akışlarını kümeleyebilir ve dendrogramı kullanarak trafiğin alt gruplarını görebilirsiniz (örneğin, protokole göre, ardından davranışa göre). K'yi önceden seçmenize gerek olmadığından, saldırı kategorilerinin sayısının bilinmediği yeni verileri keşfederken faydalıdır.

#### Varsayımlar ve Sınırlamalar

Hiyerarşik kümeleme belirli bir küme şekli varsaymaz ve iç içe geçmiş kümeleri yakalayabilir. Gruplar arasında taksonomi veya ilişkileri keşfetmek için faydalıdır (örneğin, kötü amaçlı yazılımları aile alt gruplarına göre gruplamak). Deterministiktir (rastgele başlatma sorunları yoktur). Ana avantajı, verinin kümeleme yapısını tüm ölçeklerde anlamaya yardımcı olan dendrogramdır – güvenlik analistleri anlamlı kümeleri tanımlamak için uygun bir kesim noktası belirleyebilir. Ancak, hesaplama açısından pahalıdır (genellikle $O(n^2)$ zaman veya daha kötü, basit uygulamalar için) ve çok büyük veri setleri için uygulanabilir değildir. Ayrıca, açgözlü bir prosedürdür – bir birleştirme veya bölme yapıldığında, geri alınamaz, bu da erken bir hata olursa alt optimal kümelere yol açabilir. Aykırı değerler de bazı bağlantı stratejilerini etkileyebilir (tek bağlantı, kümelerin aykırı değerler aracılığıyla bağlandığı "zincirleme" etkisini yaratabilir).

<details>
<summary>Örnek -- Olayların Agglomeratif Kümeleme
</summary>

K-Means örneğinden (3 normal küme + 1 saldırı kümesi) sentetik verileri yeniden kullanacağız ve agglomeratif kümelemeyi uygulayacağız. Ardından, bir dendrogram ve küme etiketleri elde etmenin nasıl olduğunu göstereceğiz.
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

### DBSCAN (Gürültü ile Uygulamaların Yoğunluk Tabanlı Uzamsal Kümeleme)

DBSCAN, yakın bir şekilde paketlenmiş noktaları bir araya getiren ve düşük yoğunluklu bölgelerdeki noktaları aykırı değer olarak işaretleyen yoğunluk tabanlı bir kümeleme algoritmasıdır. Farklı yoğunluklara ve küresel olmayan şekillere sahip veri setleri için özellikle yararlıdır.

DBSCAN, iki parametre tanımlayarak çalışır:
- **Epsilon (ε)**: Aynı kümeye ait olarak kabul edilecek iki nokta arasındaki maksimum mesafe.
- **MinPts**: Yoğun bir bölge (çekirdek nokta) oluşturmak için gereken minimum nokta sayısı.

DBSCAN, çekirdek noktaları, sınır noktaları ve gürültü noktalarını tanımlar:
- **Çekirdek Nokta**: ε mesafesi içinde en az MinPts komşusu olan bir nokta.
- **Sınır Noktası**: Bir çekirdek noktasının ε mesafesi içinde olan ancak MinPts'ten daha az komşusu olan bir nokta.
- **Gürültü Noktası**: Ne bir çekirdek nokta ne de bir sınır noktası olan bir nokta.

Kümeleme, ziyaret edilmemiş bir çekirdek noktasını seçerek, onu yeni bir küme olarak işaretleyerek ve ardından ondan yoğunlukla ulaşılabilir tüm noktaları (çekirdek noktalar ve komşuları vb.) özyinelemeli olarak ekleyerek devam eder. Sınır noktaları, yakın bir çekirdeğin kümesine eklenir. Tüm ulaşılabilir noktalar genişletildikten sonra, DBSCAN yeni bir küme başlatmak için başka bir ziyaret edilmemiş çekirdek noktasına geçer. Hiçbir çekirdek tarafından ulaşılmayan noktalar gürültü olarak etiketlenmeye devam eder.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* DBSCAN, ağ trafiğinde anomali tespiti için yararlıdır. Örneğin, normal kullanıcı etkinliği, özellik alanında bir veya daha fazla yoğun küme oluşturabilirken, yeni saldırı davranışları DBSCAN'ın gürültü (aykırı değerler) olarak etiketleyeceği dağınık noktalar olarak görünebilir. Ağ akış kayıtlarını kümelemek için kullanılmıştır; burada port taramaları veya hizmet reddi trafiğini nokta kümelerinin seyrek bölgeleri olarak tespit edebilir. Bir diğer uygulama, kötü amaçlı yazılım varyantlarını gruplamaktır: çoğu örnek aileler tarafından kümelenirken, birkaçının hiçbir yere uymadığı durumlarda, o birkaç örnek sıfır-gün kötü amaçlı yazılım olabilir. Gürültüyü işaretleme yeteneği, güvenlik ekiplerinin bu aykırı değerleri araştırmaya odaklanmasını sağlar.

#### Varsayımlar ve Sınırlamalar

**Varsayımlar & Güçlü Yönler:** DBSCAN, küresel kümeler varsaymaz – keyfi şekilli kümeleri (hatta zincir benzeri veya bitişik kümeleri) bulabilir. Veri yoğunluğuna dayalı olarak küme sayısını otomatik olarak belirler ve aykırı değerleri gürültü olarak etkili bir şekilde tanımlayabilir. Bu, düzensiz şekiller ve gürültü içeren gerçek dünya verileri için güçlü kılar. Aykırı değerlere karşı dayanıklıdır (K-Means'in aksine, onları kümelere zorlamaz). Kümeler yaklaşık olarak eşit yoğunlukta olduğunda iyi çalışır.

**Sınırlamalar:** DBSCAN'ın performansı uygun ε ve MinPts değerlerini seçmeye bağlıdır. Farklı yoğunluklara sahip verilerle zorlanabilir – tek bir ε, hem yoğun hem de seyrek kümeleri karşılayamaz. Eğer ε çok küçükse, çoğu noktayı gürültü olarak etiketler; çok büyükse, kümeler yanlış bir şekilde birleşebilir. Ayrıca, DBSCAN çok büyük veri setlerinde verimsiz olabilir (naif olarak $O(n^2)$, ancak mekansal indeksleme yardımcı olabilir). Yüksek boyutlu özellik alanlarında, “ε içindeki mesafe” kavramı daha az anlamlı hale gelebilir (boyutlanma laneti) ve DBSCAN dikkatli parametre ayarlamaları gerektirebilir veya sezgisel kümeleri bulmakta başarısız olabilir. Tüm bunlara rağmen, HDBSCAN gibi uzantılar bazı sorunları (farklı yoğunluk gibi) ele alır.

<details>
<summary>Örnek -- Gürültü ile Kümeleme
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
Bu kesitte, `eps` ve `min_samples` değerlerini verilerimizin ölçeğine uygun hale getirdik (özellik birimlerinde 15.0 ve bir küme oluşturmak için 5 nokta gerektiriyor). DBSCAN, 2 küme (normal trafik kümeleri) bulmalı ve 5 enjekte edilmiş aykırı noktayı gürültü olarak işaretlemelidir. Bunu doğrulamak için kümelerin sayısını gürültü noktaları ile karşılaştırıyoruz. Gerçek bir ortamda, ε üzerinde yineleme yapılabilir (ε'yi seçmek için bir k-uzaklık grafiği sezgisi kullanarak) ve MinPts (genellikle veri boyutunun +1 kadar bir kural olarak ayarlanır) ile kararlı kümeleme sonuçları bulmak için. Gürültüyü açıkça etiketleme yeteneği, potansiyel saldırı verilerini daha fazla analiz için ayırmaya yardımcı olur.

</details>

### Temel Bileşen Analizi (PCA)

PCA, verilerdeki maksimum varyansı yakalayan yeni bir ortogonal eksen seti (temel bileşenler) bulan **boyut azaltma** tekniğidir. Basit terimlerle, PCA verileri yeni bir koordinat sistemine döndürür ve projekte eder, böylece birinci temel bileşen (PC1) mümkün olan en büyük varyansı açıklar, ikinci PC (PC2) PC1'e dik en büyük varyansı açıklar ve bu şekilde devam eder. Matematiksel olarak, PCA verilerin kovaryans matrisinin özvektörlerini hesaplar - bu özvektörler temel bileşen yönleridir ve karşılık gelen özdeğerler her birinin açıkladığı varyans miktarını gösterir. Genellikle özellik çıkarımı, görselleştirme ve gürültü azaltma için kullanılır.

Bu, veri kümesi boyutlarının **önemli lineer bağımlılıklar veya korelasyonlar** içeriyorsa faydalıdır.

PCA, verilerin temel bileşenlerini tanımlayarak çalışır; bu, maksimum varyans yönleridir. PCA'da yer alan adımlar şunlardır:
1. **Standartlaştırma**: Verileri ortalamayı çıkararak merkezleme ve birim varyansa ölçekleme.
2. **Kovaryans Matrisi**: Özellikler arasındaki ilişkileri anlamak için standartlaştırılmış verilerin kovaryans matrisini hesaplama.
3. **Özdeğer Ayrıştırması**: Özdeğerleri ve özvektörleri elde etmek için kovaryans matrisinde özdeğer ayrıştırması yapma.
4. **Temel Bileşenleri Seçme**: Özdeğerleri azalan sırayla sıralayın ve en büyük özdeğerlere karşılık gelen en üst K özvektörünü seçin. Bu özvektörler yeni özellik alanını oluşturur.
5. **Veriyi Dönüştürme**: Seçilen temel bileşenleri kullanarak orijinal veriyi yeni özellik alanına projekte etme.
PCA, veri görselleştirme, gürültü azaltma ve diğer makine öğrenimi algoritmaları için bir ön işleme adımı olarak yaygın olarak kullanılır. Verinin boyutunu azaltırken temel yapısını korumaya yardımcı olur.

#### Özdeğerler ve Özvektörler

Bir özdeğer, karşılık gelen özvektörü tarafından yakalanan varyans miktarını gösteren bir skalar değerdir. Bir özvektör, veri setinin en fazla değiştiği yönü temsil eder.

A'nın bir kare matris olduğunu ve v'nin sıfırdan farklı bir vektör olduğunu varsayalım: `A * v = λ * v`
burada:
- A, [ [1, 2], [2, 1]] gibi bir kare matristir (örneğin, kovaryans matrisi)
- v bir özvektördür (örneğin, [1, 1])

O zaman, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` olacaktır; bu, özdeğer λ'nın özvektör v ile çarpılmasıdır ve özdeğer λ = 3 olur.

#### PCA'daki Özdeğerler ve Özvektörler

Bunu bir örnekle açıklayalım. 100x100 piksel boyutunda birçok gri tonlamalı yüz resmi içeren bir veri setiniz olduğunu hayal edin. Her piksel bir özellik olarak kabul edilebilir, bu nedenle her resim için 10.000 özellik (veya her resim için 10000 bileşenden oluşan bir vektör) vardır. Bu veri setinin boyutunu PCA kullanarak azaltmak istiyorsanız, şu adımları izlersiniz:

1. **Standartlaştırma**: Her özelliğin (pikselin) ortalamasını veri setinden çıkararak verileri merkezleme.
2. **Kovaryans Matrisi**: Özelliklerin (piksellerin) birlikte nasıl değiştiğini yakalayan standartlaştırılmış verilerin kovaryans matrisini hesaplama.
- İki değişken (bu durumda pikseller) arasındaki kovaryans, birlikte ne kadar değiştiklerini gösterir; bu nedenle burada amaç, hangi piksellerin lineer bir ilişki ile birlikte artma veya azalma eğiliminde olduğunu bulmaktır.
- Örneğin, piksel 1 ve piksel 2 birlikte artma eğilimindeyse, aralarındaki kovaryans pozitif olacaktır.
- Kovaryans matrisi, her bir girişin iki piksel arasındaki kovaryansı temsil ettiği 10.000x10.000 boyutunda bir matris olacaktır.
3. **Özdeğer denklemini çözme**: Çözülmesi gereken özdeğer denklemi `C * v = λ * v` şeklindedir; burada C kovaryans matrisidir, v özvektördür ve λ özdeğerdir. Şu yöntemlerle çözülebilir:
- **Özdeğer Ayrıştırması**: Özdeğerleri ve özvektörleri elde etmek için kovaryans matrisinde özdeğer ayrıştırması yapma.
- **Tekil Değer Ayrıştırması (SVD)**: Alternatif olarak, verileri tekil değerler ve vektörler olarak ayrıştırmak için SVD kullanabilirsiniz; bu da temel bileşenleri elde edebilir.
4. **Temel Bileşenleri Seçme**: Özdeğerleri azalan sırayla sıralayın ve en büyük özdeğerlere karşılık gelen en üst K özvektörünü seçin. Bu özvektörler, verilerdeki maksimum varyans yönlerini temsil eder.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* Güvenlikte PCA'nın yaygın bir kullanımı, anomali tespiti için özellik azaltmadır. Örneğin, 40'tan fazla ağ metriği (NSL-KDD özellikleri gibi) içeren bir saldırı tespit sistemi, verileri görselleştirmek veya kümeleme algoritmalarına beslemek için PCA kullanarak birkaç bileşene indirgemeyi tercih edebilir. Analistler, saldırıların normal trafikten ayrılıp ayrılmadığını görmek için ilk iki temel bileşen alanında ağ trafiğini çizebilir. PCA ayrıca, tespit algoritmalarını daha sağlam ve hızlı hale getirmek için (korelasyonlu istenen baytlar gönderilen ve alınan baytlar gibi) gereksiz özellikleri ortadan kaldırmaya da yardımcı olabilir.

#### Varsayımlar ve Sınırlamalar

PCA, **temel varyans eksenlerinin anlamlı olduğunu varsayar** - bu, lineer bir yöntemdir, bu nedenle verilerdeki lineer korelasyonları yakalar. Sadece özellik kovaryansını kullandığı için denetimsizdir. PCA'nın avantajları arasında gürültü azaltma (küçük varyans bileşenleri genellikle gürültü ile ilişkilidir) ve özelliklerin dekorrelasyonu bulunur. Orta derecede yüksek boyutlar için hesaplama açısından verimlidir ve genellikle diğer algoritmalar için yararlı bir ön işleme adımıdır (boyut lanetini azaltmak için). Bir sınırlama, PCA'nın yalnızca lineer ilişkilerle sınırlı olmasıdır - karmaşık doğrusal olmayan yapıları yakalayamaz (oysa otomatik kodlayıcılar veya t-SNE bunu yapabilir). Ayrıca, PCA bileşenleri orijinal özellikler açısından yorumlanması zor olabilir (orijinal özelliklerin kombinasyonlarıdır). Siber güvenlikte, dikkatli olunmalıdır: düşük varyanslı bir özellikte yalnızca hafif bir değişiklik yaratan bir saldırı, en üst PC'lerde görünmeyebilir (çünkü PCA varyansı önceliklendirir, mutlaka "ilginçliği" değil).

<details>
<summary>Örnek -- Ağ Verilerinin Boyutunu Azaltma
</summary>

Birden fazla özelliğe (örneğin, süreler, baytlar, sayılar) sahip ağ bağlantı günlüklerimiz olduğunu varsayalım. Özellikler arasında bazı korelasyonlar olan sentetik 4 boyutlu bir veri seti oluşturacağız ve bunu görselleştirme veya daha fazla analiz için 2 boyuta indirmek için PCA kullanacağız.
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
Burada daha önceki normal trafik kümelerini aldık ve her veri noktasını baytlar ve süre ile ilişkili iki ek özellik (paketler ve hatalar) ile genişlettik. PCA, ardından 4 özelliği 2 ana bileşene sıkıştırmak için kullanılır. Açıklanan varyans oranını yazdırıyoruz; bu, örneğin, %95'ten fazla varyansın 2 bileşen tarafından yakalandığını gösterebilir (yani az bilgi kaybı). Çıktı ayrıca veri şeklinin (1500, 4) den (1500, 2) düştüğünü gösterir. PCA alanındaki ilk birkaç nokta bir örnek olarak verilmiştir. Pratikte, veri_2d'yi görsel olarak kontrol etmek için çizmek mümkündür; eğer bir anomali varsa, bunu PCA alanındaki ana kümeden uzakta bir nokta olarak görebiliriz. Bu nedenle, PCA karmaşık verileri insan yorumlaması için yönetilebilir bir forma veya diğer algoritmalara girdi olarak damıtmaya yardımcı olur.

</details>


### Gaussian Karışım Modelleri (GMM)

Bir Gaussian Karışım Modeli, verilerin **bilinmeyen parametrelerle birkaç Gaussian (normal) dağılımının karışımından üretildiğini** varsayar. Özünde, bu olasılıksal bir kümeleme modelidir: her noktayı K Gaussian bileşeninden birine yumuşak bir şekilde atamaya çalışır. Her Gaussian bileşeni k'nin bir ortalama vektörü (μ_k), bir kovaryans matrisine (Σ_k) ve o kümenin ne kadar yaygın olduğunu temsil eden bir karışım ağırlığı (π_k) vardır. K-Means'in "sert" atamalar yaptığı yerlerde, GMM her noktaya her küme için bir ait olma olasılığı verir.

GMM uyumu genellikle Beklenti-Maksimizasyon (EM) algoritması aracılığıyla yapılır:

- **Başlatma**: Ortalama, kovaryans ve karışım katsayıları için başlangıç tahminleri ile başlayın (veya başlangıç noktası olarak K-Means sonuçlarını kullanın).

- **E-adımı (Beklenti)**: Mevcut parametreler verildiğinde, her nokta için her kümenin sorumluluğunu hesaplayın: esasen `r_nk = P(z_k | x_n)` burada z_k, x_n noktasının küme üyeliğini gösteren gizli değişkendir. Bu, Bayes teoremi kullanılarak yapılır; burada her noktanın mevcut parametrelere dayanarak her kümeye ait olma posterior olasılığını hesaplarız. Sorumluluklar şu şekilde hesaplanır:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
burada:
- \( \pi_k \) küme k için karışım katsayısıdır (küme k'nin öncel olasılığı),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) ortalama \( \mu_k \) ve kovaryans \( \Sigma_k \) verildiğinde nokta \( x_n \) için Gaussian olasılık yoğunluk fonksiyonudur.

- **M-adımı (Maksimizasyon)**: E-adımında hesaplanan sorumlulukları kullanarak parametreleri güncelleyin:
- Her ortalamayı μ_k, noktaların ağırlıklı ortalaması olarak güncelleyin; burada ağırlıklar sorumluluklardır.
- Her kovaryansı Σ_k, küme k'ye atanan noktaların ağırlıklı kovaryansı olarak güncelleyin.
- Karışım katsayılarını π_k, küme k için ortalama sorumluluk olarak güncelleyin.

- **E ve M adımlarını** yakınsama sağlanana kadar yineleyin (parametreler stabilize olana veya olasılık iyileşmesi bir eşik altına düşene kadar).

Sonuç, genel veri dağılımını topluca modelleyen bir dizi Gaussian dağılımıdır. Uyumlu GMM'yi, her noktayı en yüksek olasılığa sahip Gaussian'a atayarak kümelemek için kullanabiliriz veya belirsizlik için olasılıkları saklayabiliriz. Yeni noktaların modele uyup uymadığını görmek için olasılıklarını da değerlendirebiliriz (anomali tespiti için yararlıdır).

> [!TIP]
> *Siber güvenlikte kullanım durumları:* GMM, normal verilerin dağılımını modelleyerek anomali tespiti için kullanılabilir: öğrenilen karışım altında çok düşük olasılığa sahip herhangi bir nokta anomali olarak işaretlenir. Örneğin, meşru ağ trafiği özellikleri üzerinde bir GMM eğitebilirsiniz; herhangi bir öğrenilen kümeye benzemeyen bir saldırı bağlantısı düşük bir olasılığa sahip olacaktır. GMM'ler ayrıca kümelerin farklı şekillere sahip olabileceği aktiviteleri kümelemek için de kullanılır – örneğin, kullanıcıları davranış profillerine göre gruplamak, burada her profilin özellikleri Gaussian benzeri olabilir ancak kendi varyans yapısına sahip olabilir. Başka bir senaryo: oltalama tespitinde, meşru e-posta özellikleri bir Gaussian kümesi oluşturabilir, bilinen oltalama başka bir küme oluşturabilir ve yeni oltalama kampanyaları ya ayrı bir Gaussian olarak ya da mevcut karışıma göre düşük olasılıklı noktalar olarak ortaya çıkabilir.

#### Varsayımlar ve Sınırlamalar

GMM, kovaryansı içeren K-Means'in bir genellemesidir, böylece kümeler elipsoidal olabilir (sadece küresel değil). Kovaryans tam olduğunda farklı boyut ve şekillerdeki kümeleri işleyebilir. Yumuşak kümeleme, küme sınırları belirsiz olduğunda bir avantajdır – örneğin, siber güvenlikte bir olay birden fazla saldırı türünün özelliklerini taşıyabilir; GMM bu belirsizliği olasılıklarla yansıtabilir. GMM ayrıca verinin olasılıksal yoğunluk tahminini sağlar, bu da aykırı değerleri (tüm karışım bileşenleri altında düşük olasılığa sahip noktalar) tespit etmek için yararlıdır.

Diğer yandan, GMM, bileşen sayısı K'nın belirtilmesini gerektirir (bunu seçmek için BIC/AIC gibi kriterler kullanılabilir). EM bazen yavaş yakınsama sağlayabilir veya yerel bir optimuma ulaşabilir, bu nedenle başlatma önemlidir (genellikle EM'yi birden fazla kez çalıştırmak gerekir). Veriler aslında Gaussian karışımını takip etmiyorsa, model kötü bir uyum sağlayabilir. Ayrıca, bir Gaussian'ın yalnızca bir aykırı değeri kapsayacak şekilde küçülme riski vardır (ancak düzenleme veya minimum kovaryans sınırları bunu hafifletebilir).

<details>
<summary>Örnek -- Yumuşak Kümeleme & Anomali Puanları
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
Bu kodda, normal trafiğe (meşru trafiğin 3 profilini bildiğimizi varsayarak) 3 Gauss ile bir GMM eğitiyoruz. Yazdırılan ortalamalar ve kovaryanslar bu kümeleri tanımlar (örneğin, bir ortalama [50,500] civarında olabilir ve bu bir kümenin merkezi ile ilişkilidir, vb.). Daha sonra şüpheli bir bağlantıyı [duration=200, bytes=800] test ediyoruz. predict_proba, bu noktanın 3 kümeden her birine ait olma olasılığını verir - [200,800] normal kümelerden uzak olduğu için bu olasılıkların çok düşük veya oldukça çarpık olmasını bekleriz. Genel score_samples (log-likelihood) yazdırılır; çok düşük bir değer, noktanın modeli iyi bir şekilde uymadığını gösterir ve onu bir anomali olarak işaretler. Pratikte, bir noktanın kötü niyetli olarak kabul edilemeyecek kadar olasılıksız olup olmadığını belirlemek için log-likelihood (veya maksimum olasılık) üzerinde bir eşik belirlenebilir. Bu nedenle GMM, anomali tespiti için prensipli bir yol sağlar ve belirsizliği kabul eden yumuşak kümeler de üretir.

### Isolation Forest

**Isolation Forest**, noktaları rastgele izole etme fikrine dayanan bir topluluk anomali tespit algoritmasıdır. İlkeler, anomallerin az ve farklı olmasıdır, bu nedenle normal noktalardan daha kolay izole edilirler. Bir Isolation Forest, verileri rastgele bölümlere ayıran birçok ikili izolasyon ağacı (rastgele karar ağaçları) oluşturur. Bir ağacın her düğümünde, rastgele bir özellik seçilir ve o düğümdeki veriler için o özelliğin minimum ve maksimumu arasında rastgele bir bölünme değeri seçilir. Bu bölünme verileri iki dala ayırır. Ağaç, her nokta kendi yaprağında izole edilene veya maksimum ağaç yüksekliğine ulaşılana kadar büyütülür.

Anomali tespiti, bu rastgele ağaçlardaki her noktanın yol uzunluğunu gözlemleyerek gerçekleştirilir - noktayı izole etmek için gereken bölünme sayısı. Sezgisel olarak, anomaller (aykırı değerler) daha hızlı izole olma eğilimindedir çünkü rastgele bir bölünme, yoğun bir kümedeki normal bir noktayı ayırmaktan çok, seyrek bir bölgede bulunan bir aykırı değeri ayırma olasılığı daha yüksektir. Isolation Forest, tüm ağaçlar üzerindeki ortalama yol uzunluğundan bir anomali skoru hesaplar: daha kısa ortalama yol → daha anormal. Skorlar genellikle [0,1] aralığında normalize edilir; burada 1, çok olası bir anomali anlamına gelir.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* Isolation Forest'lar, saldırı tespiti ve dolandırıcılık tespiti gibi alanlarda başarıyla kullanılmıştır. Örneğin, çoğunlukla normal davranış içeren ağ trafiği günlükleri üzerinde bir Isolation Forest eğitmek; orman, garip trafik (duyulmamış bir port kullanan bir IP veya alışılmadık bir paket boyutu deseni gibi) için kısa yollar üretecek ve bunu inceleme için işaretleyecektir. Etiketlenmiş saldırılara ihtiyaç duymadığı için, bilinmeyen saldırı türlerini tespit etmek için uygundur. Ayrıca, kullanıcı giriş verileri üzerinde hesap ele geçirmelerini tespit etmek için de kullanılabilir (anomalik giriş zamanları veya konumları hızlı bir şekilde izole edilir). Bir kullanım durumunda, bir Isolation Forest, sistem metriklerini izleyerek ve bir dizi metrik (CPU, ağ, dosya değişiklikleri) tarihsel desenlerden çok farklı göründüğünde (kısa izolasyon yolları) bir uyarı üreterek bir işletmeyi koruyabilir.

#### Varsayımlar ve Sınırlamalar

**Avantajlar**: Isolation Forest, bir dağılım varsayımına ihtiyaç duymaz; doğrudan izolasyonu hedefler. Yüksek boyutlu veriler ve büyük veri setleri üzerinde etkilidir (ormanı oluşturmak için lineer karmaşıklık $O(n\log n)$) çünkü her ağaç, yalnızca bir alt küme özellik ve bölünme ile noktaları izole eder. Sayısal özellikleri iyi bir şekilde işleme eğilimindedir ve $O(n^2)$ olabilecek mesafe tabanlı yöntemlerden daha hızlı olabilir. Ayrıca otomatik olarak bir anomali skoru verir, böylece uyarılar için bir eşik belirleyebilir (veya beklenen anomali oranına dayalı olarak otomatik bir kesim noktası belirlemek için bir kontaminasyon parametresi kullanabilirsiniz).

**Sınırlamalar**: Rastgele doğası nedeniyle, sonuçlar çalıştırmalar arasında biraz değişiklik gösterebilir (ancak yeterince çok ağaç varsa bu önemsizdir). Veriler çok sayıda alakasız özellik içeriyorsa veya anomaller herhangi bir özellikte güçlü bir şekilde farklılaşmıyorsa, izolasyon etkili olmayabilir (rastgele bölünmeler normal noktaları şans eseri izole edebilir - ancak birçok ağacın ortalaması bunu hafifletir). Ayrıca, Isolation Forest genellikle anomallerin küçük bir azınlık olduğunu varsayar (bu genellikle siber güvenlik senaryolarında doğrudur).

<details>
<summary>Örnek -- Ağ Günlüklerinde Aykırı Değerleri Tespit Etme
</summary>

Daha önceki test veri setini (normal ve bazı saldırı noktalarını içeren) kullanacağız ve saldırıları ayırıp ayıramayacağını görmek için bir Isolation Forest çalıştıracağız. Anomali olarak ~%15 veri beklediğimizi varsayacağız.
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
Bu kodda, `IsolationForest`'u 100 ağaç ile başlatıyoruz ve `contamination=0.15` olarak ayarlıyoruz (bu, yaklaşık %15 anomali beklediğimiz anlamına gelir; model, ~%15'lik noktaların işaretlenmesi için puan eşiğini ayarlayacaktır). Bunu, normal ve saldırı noktalarının bir karışımını içeren `X_test_if` üzerinde uyarlıyoruz (not: normalde eğitim verileri üzerinde uyarlayıp yeni verilerde tahmin yaparsınız, ancak burada örnekleme amacıyla aynı set üzerinde uyarlayıp tahmin yapıyoruz). 

Çıktı, ilk 20 nokta için tahmin edilen etiketleri gösterir (burada -1 anomaliyi belirtir). Ayrıca toplamda kaç anomali tespit edildiğini ve bazı örnek anomali puanlarını yazdırıyoruz. 120 noktadan yaklaşık 18'inin -1 olarak etiketlenmesini bekleriz (çünkü kontaminasyon %15'ti). Eğer 20 saldırı örneğimiz gerçekten en uç noktalar ise, bunların çoğu o -1 tahminlerinde görünmelidir. Anomali puanı (Isolation Forest’ün karar fonksiyonu) normal noktalar için daha yüksek ve anomali için daha düşük (daha negatif) olacaktır – ayrımı görmek için birkaç değeri yazdırıyoruz. Pratikte, verileri puana göre sıralamak, en uç noktaları görmek ve incelemek için yararlı olabilir. Isolation Forest, böylece büyük etiketlenmemiş güvenlik verilerini taramak ve insan analizi veya daha fazla otomatik inceleme için en düzensiz örnekleri seçmek için etkili bir yol sağlar.

### t-SNE (t-Dağıtılmış Stokastik Komşu Gömme)

**t-SNE**, yüksek boyutlu verileri 2 veya 3 boyutta görselleştirmek için özel olarak tasarlanmış bir doğrusal olmayan boyut azaltma tekniğidir. Veri noktaları arasındaki benzerlikleri ortak olasılık dağılımlarına dönüştürür ve yerel komşulukların yapısını daha düşük boyutlu projeksiyonda korumaya çalışır. Daha basit bir ifadeyle, t-SNE, benzer noktaları (orijinal alanda) birbirine yakın ve benzer olmayan noktaları yüksek olasılıkla uzak yerleştirir.

Algoritmanın iki ana aşaması vardır:

1. **Yüksek boyutlu alanda çiftler arası benzerlikleri hesapla:** Her nokta çifti için, t-SNE, o çifti komşu olarak seçme olasılığını hesaplar (bu, her noktanın etrafında bir Gauss dağılımı merkezleyerek ve mesafeleri ölçerek yapılır – karmaşıklık parametresi, dikkate alınan etkili komşu sayısını etkiler).
2. **Düşük boyutlu (örneğin 2D) alanda çiftler arası benzerlikleri hesapla:** Başlangıçta, noktalar 2D'de rastgele yerleştirilir. t-SNE, bu haritadaki mesafeler için benzer bir olasılık tanımlar (uzak noktaların daha fazla özgürlük tanıması için Gauss'tan daha ağır kuyruklara sahip bir Student t-dağılımı çekirdeği kullanarak).
3. **Gradyan İnişi:** t-SNE, ardından yüksek-D benzerlik dağılımı ile düşük-D olan arasındaki Kullback–Leibler (KL) ayrımını minimize etmek için noktaları 2D'de iteratif olarak hareket ettirir. Bu, 2D düzeninin yüksek-D yapısını mümkün olduğunca yansıtmasını sağlar – orijinal alanda yakın olan noktalar birbirini çeker, uzak olanlar ise itilir, ta ki bir denge bulunana kadar.

Sonuç genellikle verilerdeki kümelerin belirgin hale geldiği görsel olarak anlamlı bir dağılım grafiğidir.

> [!TIP]
> *Siber güvenlikte kullanım durumları:* t-SNE, genellikle **insan analizi için yüksek boyutlu güvenlik verilerini görselleştirmek** için kullanılır. Örneğin, bir güvenlik operasyon merkezi içinde, analistler, birçok özelliğe sahip bir olay veri setini (port numaraları, frekanslar, bayt sayıları vb.) alabilir ve t-SNE kullanarak 2D bir grafik üretebilir. Saldırılar, bu grafikte kendi kümelerini oluşturabilir veya normal verilerden ayrılabilir, bu da onları tanımlamayı kolaylaştırır. Kötü amaçlı yazılım ailelerinin gruplarını görmek için kötü amaçlı yazılım veri setlerine veya farklı saldırı türlerinin belirgin şekilde kümelendiği ağ ihlali verilerine uygulanmıştır ve daha fazla araştırmayı yönlendirmiştir. Temelde, t-SNE, aksi takdirde anlaşılmaz olan siber verilerde yapı görmenin bir yolunu sağlar.

#### Varsayımlar ve Sınırlamalar

t-SNE, desenlerin görsel keşfi için harikadır. Diğer doğrusal yöntemlerin (PCA gibi) göremeyebileceği kümeleri, alt kümeleri ve uç noktaları ortaya çıkarabilir. Kötü amaçlı yazılım davranış profilleri veya ağ trafiği desenleri gibi karmaşık verileri görselleştirmek için siber güvenlik araştırmalarında kullanılmıştır. Yerel yapıyı koruduğu için doğal gruplamaları göstermede iyidir.

Ancak, t-SNE hesaplama açısından daha ağırdır (yaklaşık $O(n^2)$) bu nedenle çok büyük veri setleri için örnekleme gerektirebilir. Ayrıca, çıktıyı etkileyebilecek hiperparametreleri (karmaşıklık, öğrenme oranı, iterasyonlar) vardır – örneğin, farklı karmaşıklık değerleri farklı ölçeklerde kümeleri ortaya çıkarabilir. t-SNE grafikleri bazen yanlış yorumlanabilir – haritadaki mesafeler küresel olarak doğrudan anlamlı değildir (yerel komşuluğa odaklanır, bazen kümeler yapay olarak iyi ayrılmış görünebilir). Ayrıca, t-SNE esasen görselleştirme içindir; yeni veri noktalarını yeniden hesaplamadan projekte etmek için doğrudan bir yol sağlamaz ve tahmin modellemesi için ön işleme olarak kullanılmak üzere tasarlanmamıştır (UMAP, bu sorunların bazılarını daha hızlı hızla ele alan bir alternatiftir).

<details>
<summary>Örnek -- Ağ Bağlantılarını Görselleştirme
</summary>

t-SNE'yi çok özellikli bir veri setini 2D'ye indirmek için kullanacağız. Örnekleme amacıyla, daha önceki 4D verileri (normal trafiğin 3 doğal kümesine sahip olan) alalım ve birkaç anomali noktası ekleyelim. Ardından t-SNE'yi çalıştırıyoruz ve (kavram olarak) sonuçları görselleştiriyoruz.
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
Burada önceki 4D normal veri setimizi birkaç aşırı uç ile birleştirdik (aşırı uçların bir özelliği (“süre”) çok yüksek ayarlanmış vb., garip bir deseni simüle etmek için). t-SNE'yi 30'luk tipik bir karmaşıklık ile çalıştırıyoruz. Çıktı data_2d'nin şekli (1505, 2) dir. Bu metinde aslında bir grafik çizmeyeceğiz, ama çizersek, muhtemelen 3 normal kümeye karşılık gelen üç sıkı küme ve bu kümelerden uzakta izole noktalar olarak görünen 5 aşırı ucu göreceğiz. Etkileşimli bir iş akışında, bu yapıyı doğrulamak için noktaları etiketlerine (normal veya hangi küme, anomaliye karşı) göre renklendirebiliriz. Etiketler olmadan bile, bir analist bu 5 noktanın 2D grafikte boş alanda durduğunu fark edebilir ve bunları işaretleyebilir. Bu, t-SNE'nin siber güvenlik verilerinde görsel anomali tespiti ve küme incelemesi için güçlü bir yardımcı olabileceğini, yukarıdaki otomatik algoritmaları tamamladığını göstermektedir.

</details>


{{#include ../banners/hacktricks-training.md}}
