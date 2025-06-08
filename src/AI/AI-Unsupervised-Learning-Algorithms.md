# Unsupervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Unsupervised Learning

Kujifunza bila usimamizi ni aina ya kujifunza kwa mashine ambapo mfano unafundishwa kwa data bila majibu yaliyoandikwa. Lengo ni kutafuta mifumo, muundo, au uhusiano ndani ya data. Tofauti na kujifunza kwa usimamizi, ambapo mfano unajifunza kutoka kwa mifano iliyoandikwa, algorithimu za kujifunza bila usimamizi hufanya kazi na data isiyo na lebo.
Kujifunza bila usimamizi mara nyingi hutumika kwa kazi kama vile kuunganisha, kupunguza vipimo, na kugundua anomali. Inaweza kusaidia kugundua mifumo iliyofichika katika data, kuunganisha vitu vinavyofanana pamoja, au kupunguza ugumu wa data huku ikihifadhi sifa zake muhimu.

### K-Means Clustering

K-Means ni algorithimu ya kuunganisha inayotegemea centroid ambayo inagawanya data katika makundi K kwa kupeana kila nukta kwa maana ya kundi iliyo karibu zaidi. Algorithimu inafanya kazi kama ifuatavyo:
1. **Initialization**: Chagua K vitu vya kuanzia vya kundi (centroids), mara nyingi kwa bahati nasibu au kupitia mbinu bora kama k-means++
2. **Assignment**: Peana kila nukta ya data kwa centroid iliyo karibu zaidi kulingana na kipimo cha umbali (mfano, umbali wa Euclidean).
3. **Update**: Hesabu upya centroids kwa kuchukua maana ya nukta zote za data zilizopewa kila kundi.
4. **Repeat**: Hatua za 2–3 zinarudiwa hadi ugawaji wa makundi uwe thabiti (centroids hazihamishwi kwa kiasi kikubwa).

> [!TIP]
> *Matumizi katika usalama wa mtandao:* K-Means inatumika kwa kugundua uvamizi kwa kuunganisha matukio ya mtandao. Kwa mfano, watafiti walitumia K-Means kwenye seti ya data ya uvamizi ya KDD Cup 99 na kugundua kuwa iligawanya trafiki kwa ufanisi katika makundi ya kawaida dhidi ya mashambulizi. Katika mazoezi, wachambuzi wa usalama wanaweza kuunganisha entries za logi au data ya tabia ya mtumiaji ili kupata makundi ya shughuli zinazofanana; nukta zozote ambazo hazihusiani na kundi lililo na muundo mzuri zinaweza kuashiria anomali (mfano, toleo jipya la malware linalounda kundi lake dogo). K-Means pia inaweza kusaidia katika uainishaji wa familia za malware kwa kuunganisha binaries kulingana na profaili za tabia au vektori vya sifa.

#### Selection of K
Idadi ya makundi (K) ni hyperparameter ambayo inahitaji kufafanuliwa kabla ya kuendesha algorithimu. Mbinu kama vile Njia ya Elbow au Alama ya Silhouette zinaweza kusaidia kubaini thamani inayofaa kwa K kwa kutathmini utendaji wa kuunganisha:

- **Elbow Method**: Piga picha ya jumla ya umbali wa mraba kutoka kila nukta hadi centroid ya kundi lake kama kazi ya K. Tafuta nukta ya "elbow" ambapo kiwango cha kupungua kinabadilika kwa haraka, ikionyesha idadi inayofaa ya makundi.
- **Silhouette Score**: Hesabu alama ya silhouette kwa thamani tofauti za K. Alama ya silhouette ya juu inaonyesha makundi yaliyoainishwa vizuri zaidi.

#### Assumptions and Limitations

K-Means inadhani kwamba **makundi ni ya mviringo na yana ukubwa sawa**, ambayo huenda isiwe kweli kwa seti zote za data. Inahisi mabadiliko ya awali ya centroids na inaweza kuishia kwenye minima za ndani. Zaidi ya hayo, K-Means si sahihi kwa seti za data zenye wiani tofauti au sura zisizo za globular na sifa zenye viwango tofauti. Hatua za preprocessing kama vile normalization au standardization zinaweza kuwa muhimu ili kuhakikisha kwamba sifa zote zinachangia sawa katika hesabu za umbali.

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
Katika mfano huu, K-Means inapaswa kupata makundi 4. Kundi dogo la shambulio (lenye muda wa kawaida wa ~200) litaunda kundi lake mwenyewe kutokana na umbali wake kutoka kwa makundi ya kawaida. Tunachapisha saizi za makundi na vituo ili kutafsiri matokeo. Katika hali halisi, mtu anaweza kuweka lebo kundi lenye alama chache kama anomali zinazoweza kutokea au kuchunguza wanachama wake kwa shughuli mbaya.

### Kundi la Kihierarchiki

Kundi la kihierarchiki linaunda hierarchi ya makundi kwa kutumia njia ya chini-kuenda (agglomerative) au juu-kushuka (divisive):

1. **Agglomerative (Chini-Kuenda)**: Anza na kila kipengele cha data kama kundi tofauti na kuunganishwa kwa makundi ya karibu hadi kundi moja linabaki au kigezo cha kusimamisha kinatimizwa.
2. **Divisive (Juu-Kushuka)**: Anza na vipengele vyote vya data katika kundi moja na kugawanya makundi hadi kila kipengele cha data kiwe kundi lake mwenyewe au kigezo cha kusimamisha kinatimizwa.

Kundi la agglomerative linahitaji ufafanuzi wa umbali kati ya makundi na kigezo cha kuunganisha ili kuamua ni makundi gani ya kuunganisha. Njia za kawaida za kuunganisha ni pamoja na kuunganisha moja (umbali wa alama za karibu zaidi kati ya makundi mawili), kuunganisha kamili (umbali wa alama za mbali zaidi), kuunganisha wastani, n.k., na kipimo cha umbali mara nyingi ni Euclidean. Chaguo la kuunganisha linaathiri umbo la makundi yanayozalishwa. Hakuna haja ya kuweka idadi ya makundi K mapema; unaweza "kukata" dendrogram katika kiwango kilichochaguliwa ili kupata idadi inayotakiwa ya makundi.

Kundi la kihierarchiki linaweza kutoa dendrogram, muundo kama mti unaoonyesha uhusiano kati ya makundi katika viwango tofauti vya undani. Dendrogram inaweza kukatwa katika kiwango kinachotakiwa ili kupata idadi maalum ya makundi.

> [!TIP]
> *Matumizi katika usalama wa mtandao:* Kundi la kihierarchiki linaweza kuandaa matukio au vitu katika mti ili kubaini uhusiano. Kwa mfano, katika uchambuzi wa malware, kundi la agglomerative linaweza kuunganisha sampuli kwa kufanana kwa tabia, kuonyesha hierarchi ya familia za malware na toleo. Katika usalama wa mtandao, mtu anaweza kuunganisha mtiririko wa trafiki ya IP na kutumia dendrogram kuona makundi ya trafiki (kwa mfano, kwa itifaki, kisha kwa tabia). Kwa sababu huwezi kuchagua K mapema, ni muhimu unapochunguza data mpya ambayo idadi ya makundi ya shambulio haijulikani.

#### Dhana na Mipaka

Kundi la kihierarchiki halikubali umbo fulani la kundi na linaweza kunasa makundi yaliyo ndani. Ni muhimu kwa kugundua taxonomy au uhusiano kati ya vikundi (kwa mfano, kuunganisha malware kwa familia za makundi). Ni ya kutabirika (hakuna masuala ya kuanzisha kwa bahati nasibu). Faida kuu ni dendrogram, ambayo inatoa mwanga juu ya muundo wa kundi wa data katika viwango vyote – wachambuzi wa usalama wanaweza kuamua kiwango sahihi cha kukata ili kubaini makundi yenye maana. Hata hivyo, ni ghali kwa hesabu (kawaida $O(n^2)$ muda au mbaya zaidi kwa utekelezaji wa kawaida) na si rahisi kwa seti kubwa za data. Pia ni utaratibu wa greedy – mara tu muungano au kugawanya kumefanyika, haiwezi kubadilishwa, ambayo inaweza kusababisha makundi yasiyo bora ikiwa kosa litafanyika mapema. Vitu vya nje pia vinaweza kuathiri baadhi ya mikakati ya kuunganisha (kuunganisha moja kunaweza kusababisha athari ya "mnyororo" ambapo makundi yanaunganishwa kupitia vitu vya nje).

<details>
<summary>Mfano -- Kundi la Agglomerative la Matukio
</summary>

Tutatumia tena data ya bandia kutoka kwa mfano wa K-Means (makundi 3 ya kawaida + kundi 1 la shambulio) na kutumia kundi la agglomerative. Kisha tunaonyesha jinsi ya kupata dendrogram na lebo za kundi.
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

### DBSCAN (Kikundi cha Kitaalamu cha Maombi kwa Msaada wa Kelele)

DBSCAN ni algorithimu ya kukusanya inayotegemea wingi ambayo inakusanya pamoja pointi ambazo zimejipanga kwa karibu huku ikitambua pointi katika maeneo ya wingi mdogo kama nje ya kawaida. Inatumika hasa kwa seti za data zenye wingi tofauti na sura zisizo za mpira.

DBSCAN inafanya kazi kwa kufafanua vigezo viwili:
- **Epsilon (ε)**: Umbali wa juu kati ya pointi mbili ili kuzingatiwa kama sehemu ya kundi moja.
- **MinPts**: Idadi ya chini ya pointi zinazohitajika kuunda eneo lenye wingi (pointi kuu).

DBSCAN inatambua pointi kuu, pointi za mpaka, na pointi za kelele:
- **Pointi Kuu**: Pointi yenye angalau majirani wa MinPts ndani ya umbali wa ε.
- **Pointi za Mpakani**: Pointi ambayo iko ndani ya umbali wa ε wa pointi kuu lakini ina majirani wachache kuliko MinPts.
- **Pointi za Kelele**: Pointi ambayo si pointi kuu wala pointi za mpaka.

Kukusanya kunendelea kwa kuchagua pointi kuu ambazo hazijatembelewa, kuziita kama kundi jipya, kisha kuongeza pointi zote zinazoweza kufikiwa kwa wingi kutoka kwake (pointi kuu na majirani zao, nk). Pointi za mpaka zinaongezwa kwenye kundi la pointi kuu zilizo karibu. Baada ya kupanua pointi zote zinazoweza kufikiwa, DBSCAN inahamia kwenye pointi kuu nyingine ambayo haijatembelewa ili kuanza kundi jipya. Pointi ambazo hazijafikiwa na pointi kuu yoyote zinabaki zikitambulika kama kelele.

> [!TIP]
> *Matumizi katika usalama wa mtandao:* DBSCAN ni muhimu kwa kugundua anomali katika trafiki ya mtandao. Kwa mfano, shughuli za kawaida za mtumiaji zinaweza kuunda kundi moja au zaidi zenye wingi katika nafasi ya sifa, wakati tabia mpya za shambulio zinaonekana kama pointi zilizotawanyika ambazo DBSCAN itazitambulisha kama kelele (nje ya kawaida). Imekuwa ikitumika kukusanya rekodi za mtiririko wa mtandao, ambapo inaweza kugundua skana za bandari au trafiki ya kukatiza huduma kama maeneo ya pointi zisizo na wingi. Maombi mengine ni kuunganisha aina za malware: ikiwa sampuli nyingi zinakusanyika kwa familia lakini chache hazifai mahali popote, hizo chache zinaweza kuwa malware ya siku sifuri. Uwezo wa kutambua kelele unamaanisha timu za usalama zinaweza kuzingatia kuchunguza hizo nje ya kawaida.

#### Dhana na Mipaka

**Dhana & Nguvu:** DBSCAN haidhani makundi ya mpira – inaweza kupata makundi yenye sura yoyote (hata makundi ya mnyororo au jirani). Inajitenga kiotomatiki idadi ya makundi kulingana na wingi wa data na inaweza kutambua kwa ufanisi nje ya kawaida kama kelele. Hii inafanya kuwa na nguvu kwa data halisi zenye sura zisizo za kawaida na kelele. Ni thabiti kwa nje ya kawaida (kinyume na K-Means, ambayo inawalazimisha kuwa katika makundi). Inafanya kazi vizuri wakati makundi yana wingi sawa.

**Mipaka**: Utendaji wa DBSCAN unategemea kuchagua thamani sahihi za ε na MinPts. Inaweza kuwa na shida na data yenye wingi tofauti – ε moja haiwezi kukidhi makundi yenye wingi na yasiyo na wingi. Ikiwa ε ni ndogo sana, inatambua pointi nyingi kama kelele; ikiwa ni kubwa sana, makundi yanaweza kuungana vibaya. Pia, DBSCAN inaweza kuwa na ufanisi mdogo kwenye seti kubwa za data (kwa urahisi $O(n^2)$, ingawa uainishaji wa nafasi unaweza kusaidia). Katika nafasi za sifa zenye vipimo vingi, dhana ya "umbali ndani ya ε" inaweza kuwa na maana kidogo (laana ya vipimo), na DBSCAN inaweza kuhitaji urekebishaji wa vigezo kwa makini au inaweza kushindwa kupata makundi ya kueleweka. Licha ya haya, nyongeza kama HDBSCAN zinashughulikia baadhi ya masuala (kama vile wingi tofauti).

<details>
<summary>Mfano -- Kukusanya na Kelele
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
Katika kipande hiki, tulirekebisha `eps` na `min_samples` ili kuendana na kiwango chetu cha data (15.0 katika vitengo vya kipengele, na inahitaji pointi 5 kuunda kundi). DBSCAN inapaswa kupata makundi 2 (makundi ya trafiki ya kawaida) na kuashiria 5 ya nje iliyoongezwa kama kelele. Tunatoa idadi ya makundi dhidi ya pointi za kelele ili kuthibitisha hili. Katika mazingira halisi, mtu anaweza kurudia ε (akitumika mbinu ya grafu ya k-distance kuchagua ε) na MinPts (ambayo mara nyingi huwekwa karibu na ukubwa wa data + 1 kama kanuni ya kidole) ili kupata matokeo ya makundi thabiti. Uwezo wa kuweka wazi lebo za kelele husaidia kutenganisha data za mashambulizi zinazoweza kuwa kwa uchambuzi zaidi.

### Uchambuzi wa Vipengele Msingi (PCA)

PCA ni mbinu ya **kupunguza vipimo** inayopata seti mpya ya axisi za orthogonal (vipengele vya msingi) ambavyo vinakamata tofauti kubwa zaidi katika data. Kwa maneno rahisi, PCA inageuza na kupeleka data kwenye mfumo mpya wa kuratibu ili vipengele vya msingi vya kwanza (PC1) viweze kuelezea tofauti kubwa zaidi, PC ya pili (PC2) inaelezea tofauti kubwa zaidi isiyo ya orthogonal kwa PC1, na kadhalika. Kihesabu, PCA inakadiria eigenvectors ya matrix ya covariance ya data – hizi eigenvectors ni mwelekeo wa vipengele vya msingi, na eigenvalues zinazohusiana zinaonyesha kiasi cha tofauti kinachofafanuliwa na kila moja. Mara nyingi hutumiwa kwa uchimbaji wa vipengele, uonyeshaji, na kupunguza kelele.

Kumbuka kwamba hii ni muhimu ikiwa vipimo vya dataset vina **mategemeo au uhusiano wa moja kwa moja**.

PCA inafanya kazi kwa kutambua vipengele vya msingi vya data, ambavyo ni mwelekeo wa tofauti kubwa zaidi. Hatua zinazohusika katika PCA ni:
1. **Kiwango**: Kituo cha data kwa kupunguza wastani na kuipima kwa tofauti ya kitengo.
2. **Matrix ya Covariance**: Kadiria matrix ya covariance ya data iliyopimwa ili kuelewa uhusiano kati ya vipengele.
3. **Ufunguo wa Eigenvalue**: Fanya ufunguo wa eigenvalue kwenye matrix ya covariance ili kupata eigenvalues na eigenvectors.
4. **Chagua Vipengele Msingi**: Panga eigenvalues kwa mpangilio wa kushuka na uchague eigenvectors bora K zinazohusiana na eigenvalues kubwa zaidi. Hizi eigenvectors zinaunda nafasi mpya ya vipengele.
5. **Badilisha Data**: Peleka data ya asili kwenye nafasi mpya ya vipengele kwa kutumia vipengele vya msingi vilivyochaguliwa.
PCA inatumika sana kwa uonyeshaji wa data, kupunguza kelele, na kama hatua ya awali kwa algorithimu nyingine za kujifunza mashine. Inasaidia kupunguza vipimo vya data huku ikihifadhi muundo wake muhimu.

#### Eigenvalues na Eigenvectors

Eigenvalue ni scalar inayonyesha kiasi cha tofauti kinachokamatwa na eigenvector yake inayohusiana. Eigenvector inawakilisha mwelekeo katika nafasi ya vipengele ambapo data inabadilika zaidi.

Fikiria A ni matrix ya mraba, na v ni vector isiyo na sifuri kama ifuatavyo: `A * v = λ * v`
ambapo:
- A ni matrix ya mraba kama [ [1, 2], [2, 1]] (mfano, matrix ya covariance)
- v ni eigenvector (mfano, [1, 1])

Basi, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` ambayo itakuwa eigenvalue λ iliyozidishwa na eigenvector v, ikifanya eigenvalue λ = 3.

#### Eigenvalues na Eigenvectors katika PCA

Hebu tueleze hii kwa mfano. Fikiria una dataset yenye picha nyingi za rangi ya kijivu za nyuso za 100x100 pixels. Kila pixel inaweza kuonekana kama kipengele, hivyo una vipengele 10,000 kwa picha (au vector ya vipengele 10000 kwa picha). Ikiwa unataka kupunguza vipimo vya dataset hii kwa kutumia PCA, ungetakiwa kufuata hatua hizi:

1. **Kiwango**: Kituo cha data kwa kupunguza wastani wa kila kipengele (pixel) kutoka kwenye dataset.
2. **Matrix ya Covariance**: Kadiria matrix ya covariance ya data iliyopimwa, ambayo inakamata jinsi vipengele (pixels) vinavyobadilika pamoja.
- Kumbuka kwamba covariance kati ya variables mbili (pixels katika kesi hii) inaonyesha jinsi zinavyobadilika pamoja hivyo wazo hapa ni kugundua ni pixels zipi zinaweza kuongezeka au kupungua pamoja kwa uhusiano wa moja kwa moja.
- Kwa mfano, ikiwa pixel 1 na pixel 2 zinaweza kuongezeka pamoja, covariance kati yao itakuwa chanya.
- Matrix ya covariance itakuwa matrix ya 10,000x10,000 ambapo kila ingizo linawakilisha covariance kati ya pixels mbili.
3. **Suluisha Msingi wa Eigenvalue**: Msingi wa eigenvalue wa kutatua ni `C * v = λ * v` ambapo C ni matrix ya covariance, v ni eigenvector, na λ ni eigenvalue. Inaweza kutatuliwa kwa kutumia mbinu kama:
- **Ufunguo wa Eigenvalue**: Fanya ufunguo wa eigenvalue kwenye matrix ya covariance ili kupata eigenvalues na eigenvectors.
- **Ufunguo wa Thamani ya Kipekee (SVD)**: Vinginevyo, unaweza kutumia SVD kutenganisha matrix ya data katika thamani za kipekee na vectors, ambazo pia zinaweza kutoa vipengele vya msingi.
4. **Chagua Vipengele Msingi**: Panga eigenvalues kwa mpangilio wa kushuka na uchague eigenvectors bora K zinazohusiana na eigenvalues kubwa zaidi. Hizi eigenvectors zinawakilisha mwelekeo wa tofauti kubwa zaidi katika data.

> [!TIP]
> *Matumizi katika usalama wa mtandao:* Matumizi ya kawaida ya PCA katika usalama ni kupunguza vipengele kwa ajili ya kugundua anomali. Kwa mfano, mfumo wa kugundua uvamizi wenye metriki 40+ za mtandao (kama vile vipengele vya NSL-KDD) unaweza kutumia PCA kupunguza hadi vipengele vichache, kujumlisha data kwa ajili ya uonyeshaji au kupeleka kwenye algorithimu za makundi. Wachambuzi wanaweza kuchora trafiki ya mtandao katika nafasi ya vipengele viwili vya msingi vya kwanza ili kuona ikiwa mashambulizi yanatenganishwa na trafiki ya kawaida. PCA inaweza pia kusaidia kuondoa vipengele vya ziada (kama vile bytes zilizotumwa dhidi ya bytes zilizopokelewa ikiwa zina uhusiano) ili kufanya algorithimu za kugundua kuwa thabiti zaidi na haraka.

#### Matarajio na Mipaka

PCA inatarajia kwamba **mifumo ya msingi ya tofauti ni ya maana** – ni mbinu ya moja kwa moja, hivyo inakamata uhusiano wa moja kwa moja katika data. Ni isiyo na uangalizi kwani inatumia tu covariance ya vipengele. Faida za PCA ni pamoja na kupunguza kelele (vipengele vya tofauti ndogo mara nyingi vinahusiana na kelele) na kupunguza uhusiano wa vipengele. Ni yenye ufanisi wa hesabu kwa vipimo vya kati na mara nyingi ni hatua ya awali inayofaa kwa algorithimu nyingine (ili kupunguza laana ya vipimo). Mipaka moja ni kwamba PCA inategemea uhusiano wa moja kwa moja – haitakamata muundo mgumu wa kisasa (ambapo autoencoders au t-SNE inaweza). Pia, vipengele vya PCA vinaweza kuwa vigumu kufasiri kwa kuzingatia vipengele vya asili (ni mchanganyiko wa vipengele vya asili). Katika usalama wa mtandao, mtu anapaswa kuwa makini: shambulizi ambalo linaweza kusababisha mabadiliko madogo katika kipengele chenye tofauti ndogo linaweza kutokuwepo katika PCs za juu (kwa kuwa PCA inapa kipaumbele tofauti, si lazima "kuvutia").

<details>
<summary>Mfano -- Kupunguza Vipimo vya Data ya Mtandao
</summary>

Kufikiria tuna kumbukumbu za muunganisho wa mtandao zenye vipengele vingi (mfano, muda, bytes, hesabu). Tutaunda dataset ya bandia ya vipimo 4 (ikiwa na uhusiano kati ya vipengele) na kutumia PCA kupunguza hadi vipimo 2 kwa ajili ya uonyeshaji au uchambuzi zaidi.
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
Hapa tulichukua makundi ya awali ya trafiki ya kawaida na kupanua kila kipengele cha data kwa vipengele viwili vya ziada (pakiti na makosa) vinavyohusiana na bytes na muda. PCA inatumika kubana vipengele 4 kuwa vipengele 2 vya msingi. Tunachapisha uwiano wa tofauti iliyoelezewa, ambayo inaweza kuonyesha kwamba, sema, >95% ya tofauti inakamatwa na vipengele 2 (kumanisha kupoteza kwa habari kidogo). Matokeo pia yanaonyesha umbo la data likipungua kutoka (1500, 4) hadi (1500, 2). Pointi chache za kwanza katika nafasi ya PCA zinatolewa kama mfano. Katika mazoezi, mtu anaweza kuchora data_2d ili kuangalia kwa kuona kama makundi yanaweza kutofautishwa. Ikiwa kasoro ilikuwa ipo, mtu anaweza kuiona kama pointi iliyoko mbali na kundi kuu katika nafasi ya PCA. Hivyo, PCA inasaidia kuondoa data ngumu kuwa mfumo unaoweza kudhibitiwa kwa tafsiri ya kibinadamu au kama ingizo kwa algorithimu nyingine.

### Gaussian Mixture Models (GMM)

Mfano wa Mchanganyiko wa Gaussian unadhani data inazalishwa kutoka mchanganyiko wa **usambazaji kadhaa wa Gaussian (kawaida) wenye vigezo visivyojulikana**. Kwa msingi, ni mfano wa makundi ya uwezekano: inajaribu kwa upole kupeana kila pointi kwa moja ya vipengele K vya Gaussian. Kila kipengele cha Gaussian k kina vector ya wastani (μ_k), matrix ya covariance (Σ_k), na uzito wa mchanganyiko (π_k) unaowrepresenta jinsi kundi hilo lilivyo maarufu. Tofauti na K-Means ambayo inafanya "ugawaji" mgumu, GMM inampa kila pointi uwezekano wa kuwa katika kila kundi.

Ulinganifu wa GMM kawaida hufanywa kupitia algorithm ya Expectation-Maximization (EM):

- **Kuanza**: Anza na makadirio ya awali ya wastani, covariances, na coefficients za mchanganyiko (au tumia matokeo ya K-Means kama hatua ya mwanzo).

- **E-step (Matarajio)**: Iwapo vigezo vya sasa, hesabu jukumu la kila kundi kwa kila pointi: kimsingi `r_nk = P(z_k | x_n)` ambapo z_k ni variable ya siri inayoashiria uanachama wa kundi kwa pointi x_n. Hii inafanywa kwa kutumia nadharia ya Bayes, ambapo tunahesabu uwezekano wa nyuma wa kila pointi kuwa katika kila kundi kulingana na vigezo vya sasa. Majukumu yanahesabiwa kama:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
ambapo:
- \( \pi_k \) ni coefficient ya mchanganyiko kwa kundi k (uwezekano wa awali wa kundi k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) ni kazi ya uwezekano wa density ya Gaussian kwa pointi \( x_n \) ikizingatia wastani \( \mu_k \) na covariance \( \Sigma_k \).

- **M-step (Uboreshaji)**: Sasisha vigezo kwa kutumia majukumu yaliyohesabiwa katika hatua ya E:
- Sasisha kila wastani μ_k kama wastani wa uzito wa pointi, ambapo uzito ni majukumu.
- Sasisha kila covariance Σ_k kama covariance ya uzito wa pointi zilizotengwa kwa kundi k.
- Sasisha coefficients za mchanganyiko π_k kama wastani wa jukumu kwa kundi k.

- **Rudia** hatua za E na M hadi kufikia muafaka (vigezo vinapojisimamia au kuboresha uwezekano uko chini ya kigezo).

Matokeo ni seti ya usambazaji wa Gaussian ambayo kwa pamoja inasimamia usambazaji wa data kwa ujumla. Tunaweza kutumia GMM iliyofanywa kuunda makundi kwa kupeana kila pointi kwa Gaussian yenye uwezekano mkubwa, au kuweka uwezekano kwa ajili ya kutokuwa na uhakika. Mtu anaweza pia kutathmini uwezekano wa pointi mpya ili kuona kama zinafaa katika mfano (inayofaa kwa kugundua kasoro).

> [!TIP]
> *Matumizi katika usalama wa mtandao:* GMM inaweza kutumika kwa kugundua kasoro kwa kuunda mfano wa usambazaji wa data ya kawaida: pointi yoyote yenye uwezekano mdogo sana chini ya mchanganyiko uliojifunza inatambuliwa kama kasoro. Kwa mfano, unaweza kufundisha GMM juu ya vipengele vya trafiki halali ya mtandao; muunganisho wa shambulio ambao haufanani na kundi lolote lililojifunzwa utakuwa na uwezekano mdogo. GMM pia hutumiwa kuunda makundi ya shughuli ambapo makundi yanaweza kuwa na sura tofauti – e.g., kuunganisha watumiaji kwa wasifu wa tabia, ambapo vipengele vya kila wasifu vinaweza kuwa kama Gaussian lakini na muundo wake wa tofauti. Hali nyingine: katika kugundua ulaghai, vipengele halali vya barua pepe vinaweza kuunda kundi moja la Gaussian, ulaghai unaojulikana mwingine, na kampeni mpya za ulaghai zinaweza kuonekana kama Gaussian tofauti au kama pointi zenye uwezekano mdogo kulingana na mchanganyiko uliopo.

#### Dhana na Mipaka

GMM ni jumla ya K-Means ambayo inajumuisha covariance, hivyo makundi yanaweza kuwa ya ellipsoidal (siyo tu ya mpira). Inashughulikia makundi ya ukubwa na sura tofauti ikiwa covariance ni kamili. Kugawanya kwa upole ni faida wakati mipaka ya kundi ni fuzzy – e.g., katika usalama wa mtandao, tukio linaweza kuwa na sifa za aina kadhaa za shambulio; GMM inaweza kuonyesha kutokuwa na uhakika hiyo kwa uwezekano. GMM pia inatoa tathmini ya density ya uwezekano wa data, inayofaa kwa kugundua nje (pointi zenye uwezekano mdogo chini ya vipengele vyote vya mchanganyiko).

Kwa upande wa hasara, GMM inahitaji kufafanua idadi ya vipengele K (ingawa mtu anaweza kutumia vigezo kama BIC/AIC kuichagua). EM inaweza wakati mwingine kuja kwa muafaka polepole au kwa muafaka wa ndani, hivyo kuanzisha ni muhimu (mara nyingi inafanya EM mara kadhaa). Ikiwa data haifuati mchanganyiko wa Gaussians, mfano unaweza kuwa na ufanisi duni. Pia kuna hatari ya Gaussian mmoja kupungua ili kufunika tu nje (ingawa udhibiti au mipaka ya chini ya covariance inaweza kupunguza hiyo).
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
Katika msimbo huu, tunafundisha GMM na Gaussians 3 kwenye trafiki ya kawaida (tukidhani tunajua wasifu 3 wa trafiki halali). Maana na covariances zilizochapishwa zinaelezea makundi haya (kwa mfano, maana moja inaweza kuwa karibu [50,500] inayohusiana na kituo cha kundi moja, n.k.). Kisha tunajaribu muunganisho wa kutatanisha [duration=200, bytes=800]. predict_proba inatoa uwezekano wa pointi hii kuhusika na kila moja ya makundi 3 – tungeweza kutarajia uwezekano huu kuwa wa chini sana au kupindishwa sana kwani [200,800] iko mbali na makundi ya kawaida. Alama ya jumla ya score_samples (log-likelihood) inachapishwa; thamani ya chini sana inaonyesha kuwa pointi hiyo haifai vizuri kwenye mfano, ikionyesha kama anomalous. Katika mazoezi, mtu anaweza kuweka kigezo kwenye log-likelihood (au kwenye uwezekano wa juu) ili kuamua ikiwa pointi ni ya kutosha kutokuwa na hatari. GMM hivyo hutoa njia iliyo na kanuni ya kufanya ugunduzi wa anomalies na pia inatoa makundi laini yanayotambua kutokuwa na uhakika.

### Isolation Forest

**Isolation Forest** ni algorithm ya ugunduzi wa anomalies ya kundi inayotegemea wazo la kutenga pointi kwa bahati nasibu. Kanuni ni kwamba anomalies ni chache na tofauti, hivyo ni rahisi kuzitenga kuliko pointi za kawaida. Isolation Forest inajenga miti nyingi za kutenga binary (miti ya maamuzi ya bahati nasibu) ambazo zinagawanya data kwa bahati nasibu. Kila node kwenye mti, kipengele cha bahati nasibu kinachaguliwa na thamani ya kugawanya ya bahati nasibu inachaguliwa kati ya min na max ya kipengele hicho kwa data katika node hiyo. Kugawanya hii kunagawanya data katika matawi mawili. Mti unakua hadi kila pointi itengwe katika jani lake mwenyewe au urefu wa juu wa mti unafikiwa.

Ugunduzi wa anomalies unafanywa kwa kuangalia urefu wa njia ya kila pointi katika miti hii ya bahati nasibu – idadi ya kugawanya inayohitajika kutenga pointi hiyo. Kwa njia ya kawaida, anomalies (outliers) huwa zinatengwa haraka zaidi kwa sababu kugawanya kwa bahati nasibu kuna uwezekano mkubwa wa kutenganisha outlier (ambaye yuko katika eneo la sparse) kuliko pointi za kawaida katika kundi lenye msongamano. Isolation Forest inakadiria alama ya anomaly kutoka kwa urefu wa wastani wa njia juu ya miti zote: urefu wa njia ya wastani mfupi → zaidi ya anomalous. Alama kawaida huwekwa sawa kwa [0,1] ambapo 1 inamaanisha uwezekano mkubwa wa anomaly.

> [!TIP]
> *Matumizi katika usalama wa mtandao:* Isolation Forests zimekuwa zikitumika kwa mafanikio katika ugunduzi wa uvamizi na ugunduzi wa udanganyifu. Kwa mfano, fundisha Isolation Forest kwenye kumbukumbu za trafiki ya mtandao ambazo kwa kiasi kikubwa zina tabia ya kawaida; msitu utaweza kutoa njia fupi kwa trafiki isiyo ya kawaida (kama IP inayotumia bandari isiyojulikana au muundo wa ukubwa wa pakiti usio wa kawaida), ikionyesha kwa ukaguzi. Kwa sababu haitaji mashambulizi yaliyoandikwa, inafaa kwa kugundua aina za mashambulizi zisizojulikana. Inaweza pia kutumika kwenye data za kuingia kwa mtumiaji kugundua kuchukuliwa kwa akaunti (nyakati au maeneo ya kuingia yasiyo ya kawaida yanatengwa haraka). Katika matumizi moja, Isolation Forest inaweza kulinda biashara kwa kufuatilia metriki za mfumo na kutoa tahadhari wakati mchanganyiko wa metriki (CPU, mtandao, mabadiliko ya faili) unaonekana kuwa tofauti sana (njia fupi za kutengwa) kutoka kwa mifumo ya kihistoria.

#### Dhana na Mipaka

**Faida**: Isolation Forest haitaji dhana ya usambazaji; inashughulikia moja kwa moja kutengwa. Ni bora kwenye data zenye vipimo vingi na seti kubwa za data (ugumu wa moja kwa moja $O(n\log n)$ kwa kujenga msitu) kwani kila mti unategemea pointi na vipengele na kugawanya tu. Inashughulikia vizuri vipengele vya nambari na inaweza kuwa haraka zaidi kuliko mbinu zinazotegemea umbali ambazo zinaweza kuwa $O(n^2)$. Pia inatoa moja kwa moja alama ya anomaly, hivyo unaweza kuweka kigezo cha tahadhari (au kutumia kipimo cha uchafuzi kuamua kiotomatiki kikomo kulingana na sehemu inayotarajiwa ya anomaly).

**Mipaka**: Kwa sababu ya asili yake ya bahati nasibu, matokeo yanaweza kutofautiana kidogo kati ya mbio (ingawa kwa miti nyingi hii ni ndogo). Ikiwa data ina vipengele vingi visivyo na maana au ikiwa anomalies hazitofautiani kwa nguvu katika kipengele chochote, kutengwa kunaweza kutokuwa na ufanisi (kugawanya kwa bahati nasibu kunaweza kutenga pointi za kawaida kwa bahati – hata hivyo, kuhesabu miti mingi hupunguza hili). Pia, Isolation Forest kwa ujumla inadhani kuwa anomalies ni wachache (ambayo mara nyingi ni kweli katika hali za usalama wa mtandao).

<details>
<summary>Mfano -- Kugundua Outliers katika Kumbukumbu za Mtandao
</summary>

Tutatumia seti ya data ya mtihani ya awali (ambayo ina pointi za kawaida na baadhi ya mashambulizi) na kuendesha Isolation Forest ili kuona ikiwa inaweza kutenga mashambulizi. Tutadhani tunatarajia ~15% ya data kuwa ya kutatanisha (kwa maonyesho).
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
Katika msimbo huu, tunaunda `IsolationForest` na miti 100 na kuweka `contamination=0.15` (kumanisha tunatarajia karibu 15% ya anomalies; mfano utaweka kigezo chake cha alama ili ~15% ya alama zifanywe alama). Tunafaa kwenye `X_test_if` ambayo ina mchanganyiko wa alama za kawaida na za shambulio (kumbuka: kawaida ungetumia data ya mafunzo na kisha kutumia predict kwenye data mpya, lakini hapa kwa mfano tunafaa na kutabiri kwenye seti moja ili kuona matokeo moja kwa moja).

Matokeo yanaonyesha lebo zilizotabiriwa kwa alama 20 za kwanza (ambapo -1 inaashiria anomaly). Pia tunachapisha ni anomalies ngapi zimegundulika kwa jumla na baadhi ya alama za mfano za anomaly. Tunatarajia takriban 18 kati ya alama 120 kupewa lebo -1 (kwa kuwa contamination ilikuwa 15%). Ikiwa sampuli zetu 20 za shambulio ni kweli ziko mbali zaidi, nyingi yao zinapaswa kuonekana katika hizo -1 predictions. Alama ya anomaly (kazi ya uamuzi ya Isolation Forest) ni kubwa kwa alama za kawaida na ndogo (mbaya zaidi) kwa anomalies – tunachapisha baadhi ya thamani ili kuona utofauti. Katika mazoezi, mtu anaweza kupanga data kwa alama ili kuona waandishi wakuu na kuichunguza. Isolation Forest hivyo inatoa njia bora ya kuchambua data kubwa zisizo na lebo za usalama na kuchagua matukio yasiyo ya kawaida kwa uchambuzi wa kibinadamu au uchunguzi wa kiotomatiki zaidi.

### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** ni mbinu ya kupunguza vipimo isiyo ya laini iliyoundwa mahsusi kwa ajili ya kuonyesha data yenye vipimo vingi katika vipimo 2 au 3. Inabadilisha ufanisi kati ya alama za data kuwa usambazaji wa uwezekano wa pamoja na kujaribu kuhifadhi muundo wa majirani wa ndani katika uwasilishaji wa chini wa vipimo. Kwa maneno rahisi, t-SNE inaweka alama katika (sema) 2D kwa namna ambayo alama zinazofanana (katika nafasi ya asili) zinaishia karibu pamoja na alama zisizofanana zinaishia mbali na kila mmoja kwa uwezekano mkubwa.

Algorithimu ina hatua mbili kuu:

1. **Hesabu uhusiano wa pande mbili katika nafasi ya vipimo vingi:** Kwa kila jozi ya alama, t-SNE inahesabu uwezekano kwamba mtu angechagua jozi hiyo kama majirani (hii inafanywa kwa kuzingatia usambazaji wa Gaussian kwenye kila alama na kupima umbali – kigezo cha perplexity kinaathiri idadi halisi ya majirani wanaozingatiwa).
2. **Hesabu uhusiano wa pande mbili katika nafasi ya chini ya vipimo (mfano 2D):** Kwanza, alama zinawekwa kwa bahati nasibu katika 2D. t-SNE in定义 uwezekano sawa kwa umbali katika ramani hii (ikitumia kiini cha usambazaji wa Student t, ambacho kina ncha nzito zaidi kuliko Gaussian ili kuruhusu alama za mbali uhuru zaidi).
3. **Gradient Descent:** t-SNE kisha inahamisha alama kwa hatua kwa hatua katika 2D ili kupunguza tofauti ya Kullback–Leibler (KL) kati ya usambazaji wa uhusiano wa juu-D na wa chini-D. Hii inasababisha mpangilio wa 2D kuakisi muundo wa juu-D kadri iwezekanavyo – alama ambazo zilikuwa karibu katika nafasi ya asili zitavutia kila mmoja, na zile ziko mbali zitakataa, hadi usawa upatikane.

Matokeo mara nyingi ni mchoro wa kusambaza wenye maana ya kuona ambapo makundi katika data yanakuwa dhahiri.

> [!TIP]
> *Matumizi katika usalama wa mtandao:* t-SNE mara nyingi hutumiwa ku **onyesha data ya usalama yenye vipimo vingi kwa uchambuzi wa kibinadamu**. Kwa mfano, katika kituo cha operesheni za usalama, wachambuzi wanaweza kuchukua seti ya matukio yenye vipengele vingi (nambari za bandari, mara kwa mara, idadi ya byte, nk) na kutumia t-SNE kutoa mchoro wa 2D. Mashambulizi yanaweza kuunda makundi yao wenyewe au kutengwa na data ya kawaida katika mchoro huu, na kuifanya iwe rahisi kuwatambua. Imetumika kwenye seti za data za malware kuona makundi ya familia za malware au kwenye data ya uvunjaji wa mtandao ambapo aina tofauti za mashambulizi zinakusanyika kwa tofauti, ikiongoza uchunguzi zaidi. Kimsingi, t-SNE inatoa njia ya kuona muundo katika data za cyber ambazo vinginevyo zingekuwa ngumu kueleweka.

#### Dhana na Mipaka

t-SNE ni nzuri kwa kugundua mifumo kwa kuona. Inaweza kufichua makundi, makundi madogo, na waandishi wa mbali ambao mbinu nyingine za laini (kama PCA) zinaweza kutokuwepo. Imetumika katika utafiti wa usalama wa mtandao kuonyesha data ngumu kama vile profaili za tabia za malware au mifumo ya trafiki ya mtandao. Kwa sababu inahifadhi muundo wa ndani, ni nzuri katika kuonyesha makundi ya asili.

Hata hivyo, t-SNE ni nzito kwa kompyuta (takriban $O(n^2)$) hivyo inaweza kuhitaji sampuli kwa seti kubwa sana za data. Pia ina vigezo vya hyper (perplexity, kiwango cha kujifunza, mizunguko) ambavyo vinaweza kuathiri matokeo – mfano, thamani tofauti za perplexity zinaweza kufichua makundi katika viwango tofauti. Mchoro wa t-SNE wakati mwingine unaweza kutafsiriwa vibaya – umbali katika ramani si wa maana moja kwa moja kimataifa (inazingatia jirani wa ndani, wakati mwingine makundi yanaweza kuonekana kuwa mbali sana kwa bandia). Pia, t-SNE ni hasa kwa ajili ya uonyeshaji; haipati njia rahisi ya kuhamasisha alama mpya bila kuhesabu tena, na haikusudiwi kutumika kama maandalizi kwa ajili ya uundaji wa utabiri (UMAP ni mbadala inayoshughulikia baadhi ya masuala haya kwa kasi ya haraka).

<details>
<summary>Mfano -- Kuonyesha Mifumo ya Mtandao
</summary>

Tutatumia t-SNE kupunguza seti ya data yenye vipengele vingi hadi 2D. Kwa mfano, hebu tuchukue data ya awali ya 4D (ambayo ilikuwa na makundi 3 ya asili ya trafiki ya kawaida) na kuongeza alama chache za anomaly. Kisha tunakimbia t-SNE na (kimsingi) kuonyesha matokeo.
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
Hapa tumekusanya dataset yetu ya kawaida ya 4D na kundi dogo la outliers kali (outliers zina kipengele kimoja (“duration”) kilichowekwa juu sana, nk, ili kuiga muundo wa ajabu). Tunakimbia t-SNE na perplexity ya kawaida ya 30. Data ya output_2d ina umbo (1505, 2). Hatuwezi kweli kuchora katika maandiko haya, lakini kama tungeweza, tungeweza kutarajia kuona labda makundi matatu yaliyofungwa yanayolingana na makundi 3 ya kawaida, na outliers 5 zikionekana kama pointi zilizotengwa mbali na makundi hayo. Katika mchakato wa mwingiliano, tunaweza kubadilisha rangi za pointi kulingana na lebo zao (kawaida au kundi gani, dhidi ya anomaly) ili kuthibitisha muundo huu. Hata bila lebo, mchambuzi anaweza kugundua zile pointi 5 zikiwa katika nafasi tupu kwenye mchoro wa 2D na kuziangazia. Hii inaonyesha jinsi t-SNE inaweza kuwa msaada mzuri katika kugundua anomalies kwa njia ya kuona na ukaguzi wa makundi katika data ya cybersecurity, ikikamilisha algorithimu za kiotomatiki zilizo juu.

</details>


{{#include ../banners/hacktricks-training.md}}
