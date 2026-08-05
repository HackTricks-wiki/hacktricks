# Ongesuperviseerde Leeralgoritmes

{{#include ../banners/hacktricks-training.md}}

## Ongesuperviseerde Leer

Ongesuperviseerde leer is ’n tipe masjienleer waarin die model opgelei word op data sonder benoemde antwoorde. Die doel is om patrone, strukture of verhoudings binne die data te vind. Anders as gesuperviseerde leer, waar die model uit benoemde voorbeelde leer, werk ongesuperviseerde leeralgoritmes met onbenoemde data.
Ongesuperviseerde leer word dikwels gebruik vir take soos clustering, dimensionaliteitsvermindering en anomaly detection. Dit kan help om versteekte patrone in data te ontdek, soortgelyke items saam te groepeer of die kompleksiteit van die data te verminder terwyl die noodsaaklike kenmerke daarvan behoue bly.


### K-Means Clustering

K-Means is ’n centroid-gebaseerde clustering-algoritme wat data in K clusters verdeel deur elke punt aan die naaste cluster-gemiddelde toe te ken. Die algoritme werk soos volg:
1. **Initialisering**: Kies K aanvanklike cluster-sentrums (centroids), dikwels lukraak of deur slimmer metodes soos k-means++ te gebruik
2. **Toewysing**: Ken elke datapunt aan die naaste centroid toe op grond van ’n afstandsmetriek (bv. Euclidiese afstand).
3. **Opdatering**: Bereken die centroids herhaaldelik deur die gemiddelde te neem van alle datapunte wat aan elke cluster toegewys is.
4. **Herhaal**: Stappe 2–3 word herhaal totdat die cluster-toewysings stabiliseer (centroids beweeg nie meer beduidend nie).

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* K-Means word vir intrusion detection gebruik deur network events te cluster. Navorsers het byvoorbeeld K-Means op die KDD Cup 99 intrusion-dataset toegepas en gevind dat dit traffic effektief in normale versus attack-clusters verdeel het. In die praktyk kan security analysts log entries of user behavior-data cluster om groepe soortgelyke aktiwiteit te vind; enige punte wat nie aan ’n goedgevormde cluster behoort nie, kan anomalies aandui (bv. ’n nuwe malware-variant wat sy eie klein cluster vorm). K-Means kan ook help met malware family classification deur binaries volgens behavior profiles of feature vectors te groepeer.

#### Keuse van K
Die aantal clusters (K) is ’n hyperparameter wat gedefinieer moet word voordat die algoritme uitgevoer word. Tegnieke soos die Elbow Method of Silhouette Score kan help om ’n geskikte waarde vir K te bepaal deur die clustering-prestasie te evalueer:

- **Elbow Method**: Teken die som van die kwadraatafstande vanaf elke punt tot sy toegewysde cluster-centroid as ’n funksie van K. Soek ’n "elmboog"-punt waar die afnametempo skerp verander, wat ’n geskikte aantal clusters aandui.
- **Silhouette Score**: Bereken die silhouette score vir verskillende waardes van K. ’n Hoër silhouette score dui op beter gedefinieerde clusters.

#### Aannames en Beperkings

K-Means neem aan dat **clusters sferies en ewe groot is**, wat moontlik nie vir alle datasets waar is nie. Dit is sensitief vir die aanvanklike plasing van centroids en kan na plaaslike minima konvergeer. Daarbenewens is K-Means nie geskik vir datasets met wisselende digthede of nie-globulêre vorms en features met verskillende skale nie. Voorverwerkingstappe soos normalisering of standaardisering mag nodig wees om te verseker dat alle features ewe veel tot die afstandsberekeninge bydra.

<details>
<summary>Voorbeeld -- Clustering van Network Events
</summary>
Hieronder simuleer ons network traffic-data en gebruik ons K-Means om dit te cluster. Gestel ons het events met features soos connection duration en byte count. Ons skep 3 clusters van “normale” traffic en 1 klein cluster wat ’n attack pattern verteenwoordig. Dan voer ons K-Means uit om te sien of dit hulle skei.
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
In hierdie voorbeeld behoort K-Means 4 clusters te vind. Die klein attack-cluster (met ’n buitengewoon hoë duur van ongeveer 200) sal ideaal gesproke sy eie cluster vorm, gegewe die afstand daarvan vanaf normale clusters. Ons druk die clustergroottes en -sentrums uit om die resultate te interpreteer. In ’n werklike scenario kan ’n mens die cluster met min punte as moontlike anomalieë etiketteer of die lede daarvan vir kwaadwillige aktiwiteit ondersoek.
</details>

### Hiërargiese Clustering

Hiërargiese clustering bou ’n hiërargie van clusters deur óf ’n bottom-up (agglomeratiewe) benadering óf ’n top-down (divisiewe) benadering te gebruik:

1. **Agglomeratief (Bottom-Up)**: Begin met elke datapunt as ’n afsonderlike cluster en voeg die naaste clusters iteratief saam totdat ’n enkele cluster oorbly of ’n stopkriterium bereik word.
2. **Divisief (Top-Down)**: Begin met alle datapunte in ’n enkele cluster en verdeel die clusters iteratief totdat elke datapunt sy eie cluster is of ’n stopkriterium bereik word.

Agglomeratiewe clustering vereis ’n definisie van inter-cluster-afstand en ’n linkage-kriterium om te besluit watter clusters saamgevoeg moet word. Algemene linkage-metodes sluit single linkage (afstand van die naaste punte tussen twee clusters), complete linkage (afstand van die verste punte), average linkage, ensovoorts in, en die afstandsmetriek is dikwels Euklidies. Die keuse van linkage beïnvloed die vorm van die clusters wat geproduseer word. Dit is nie nodig om vooraf die aantal clusters K te spesifiseer nie; jy kan die dendrogram op ’n gekose vlak “sny” om die gewenste aantal clusters te verkry.

Hiërargiese clustering produseer ’n dendrogram, ’n boomagtige struktuur wat die verhoudings tussen clusters op verskillende vlakke van granulariteit toon. Die dendrogram kan op ’n gewenste vlak gesny word om ’n spesifieke aantal clusters te verkry.

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* Hiërargiese clustering kan gebeurtenisse of entiteite in ’n boom organiseer om verhoudings raak te sien. In malware-analise kan agglomeratiewe clustering byvoorbeeld samples volgens gedragsooreenkoms groepeer, wat ’n hiërargie van malware-families en -variante blootlê. In netwerksekuriteit kan ’n mens IP-verkeersvloeie groepeer en die dendrogram gebruik om subgroeperings van verkeer te sien (byvoorbeeld volgens protokol en daarna volgens gedrag). Omdat jy nie K vooraf hoef te kies nie, is dit nuttig wanneer jy nuwe data verken waarvoor die aantal aanvalskategorieë onbekend is.

#### Aannames en Beperkings

Hiërargiese clustering neem nie ’n spesifieke clusters-vorm aan nie en kan geneste clusters vasvang. Dit is nuttig om taksonomie of verhoudings tussen groepe te ontdek (byvoorbeeld om malware volgens famil­ie-subgroepe te groepeer). Dit is deterministies (geen probleme met ewekansige initialisering nie). ’n Belangrike voordeel is die dendrogram, wat insig in die data se clustering-struktuur op alle skale bied – sekuriteitsontleders kan ’n toepaslike afsnypunt bepaal om betekenisvolle clusters te identifiseer. Dit is egter rekenaarmatig duur (tipies $O(n^2)$ tyd of erger vir naïewe implementerings) en nie haalbaar vir baie groot datastelle nie. Dit is ook ’n gulsige prosedure – sodra ’n samesmelting of verdeling gedoen is, kan dit nie ongedaan gemaak word nie, wat tot suboptimale clusters kan lei indien ’n fout vroeg voorkom. Uitskieters kan ook sommige linkage-strategieë beïnvloed (single-link kan die “ketting”-effek veroorsaak waar clusters via uitskieters aan mekaar verbind word).

<details>
<summary>Voorbeeld -- Agglomeratiewe Clustering van Gebeurtenisse
</summary>

Ons sal die sintetiese data uit die K-Means-voorbeeld hergebruik (3 normale clusters + 1 attack-cluster) en agglomeratiewe clustering toepas. Ons illustreer vervolgens hoe om ’n dendrogram en cluster-etikette te verkry.
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

DBSCAN is ’n digtheidsgebaseerde klusteringsalgoritme wat punte wat naby aan mekaar gepak is, saamgroepeer terwyl dit punte in laedigtheidsgebiede as uitskieters merk. Dit is besonder nuttig vir datastelle met wisselende digthede en nie-sferiese vorms.

DBSCAN werk deur twee parameters te definieer:
- **Epsilon (ε)**: Die maksimum afstand tussen twee punte om as deel van dieselfde kluster beskou te word.
- **MinPts**: Die minimum aantal punte wat benodig word om ’n digte gebied (kernpunt) te vorm.

DBSCAN identifiseer kernpunte, grenspunte en ruispunte:
- **Kernpunt**: ’n Punt met minstens MinPts bure binne ε-afstand.
- **Grenspunt**: ’n Punt wat binne ε-afstand van ’n kernpunt is, maar minder as MinPts bure het.
- **Ruispunt**: ’n Punt wat nie ’n kernpunt of ’n grenspunt is nie.

Klusterverwerking begin deur ’n onbesoekte kernpunt te kies, dit as ’n nuwe kluster te merk en daarna rekursief alle punte wat digtheidsbereikbaar daarvan is, by te voeg (kernpunte en hul bure, ensovoorts). Grenspunte word by die kluster van ’n nabygeleë kernpunt gevoeg. Nadat alle bereikbare punte uitgebrei is, beweeg DBSCAN na ’n ander onbesoekte kernpunt om ’n nuwe kluster te begin. Punte wat deur geen kernpunt bereik word nie, bly as ruis gemerk.

> [!TIP]
> *Gebruikgevalle in kuberveiligheid:* DBSCAN is nuttig vir anomalie-opsporing in netwerkverkeer. Normale gebruikersaktiwiteit kan byvoorbeeld een of meer digte klusters in die kenmerkruimte vorm, terwyl nuwe aanvalgedrag as verspreide punte verskyn wat DBSCAN as ruis (uitskieters) sal merk. Dit is gebruik om netwerkvloei-rekords te kluster, waar dit poortskanderings of denial-of-service-verkeer as yl gebiede van punte kan opspoor. Nog ’n toepassing is om malware-variante te groepeer: as die meeste monsters volgens families kluster, maar ’n paar nêrens pas nie, kan daardie paar zero-day-malware wees. Die vermoë om ruis te merk, beteken dat sekuriteitspanne daarop kan fokus om daardie uitskieters te ondersoek.

#### Aannames en Beperkings

**Aannames & Sterkpunte:**: DBSCAN neem nie sferiese klusters aan nie – dit kan klusters met arbitrêre vorms vind (selfs kettingagtige of aangrensende klusters). Dit bepaal outomaties die aantal klusters op grond van datadigtheid en kan uitskieters doeltreffend as ruis identifiseer. Dit maak dit kragtig vir werklike data met onreëlmatige vorms en ruis. Dit is bestand teen uitskieters (anders as K-Means, wat hulle in klusters forseer). Dit werk goed wanneer klusters ongeveer eenvormige digtheid het.

**Beperkings**: DBSCAN se werkverrigting hang af van die keuse van toepaslike ε- en MinPts-waardes. Dit kan probleme ondervind met data met wisselende digthede – ’n enkele ε kan nie digte en yl klusters albei akkommodeer nie. As ε te klein is, merk dit die meeste punte as ruis; as dit te groot is, kan klusters verkeerdelik saamsmelt. DBSCAN kan ook ondoeltreffend wees op baie groot datastelle (naïefweg $O(n^2)$, hoewel ruimtelike indeksering kan help). In hoëdimensiekenmerkruimtes kan die konsep van “afstand binne ε” minder betekenisvol word (die dimensionaliteitsvloek), en DBSCAN kan noukeurige parameterinstelling vereis of dalk nie intuïtiewe klusters vind nie. Ten spyte hiervan spreek uitbreidings soos HDBSCAN sommige probleme aan (soos wisselende digtheid).

<details>
<summary>Voorbeeld -- Klustering met Ruis
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
In hierdie brokkie het ons `eps` en `min_samples` aangepas om by ons dataskaal te pas (15.0 in kenmerkeenhede, en 5 punte word vereis om ’n cluster te vorm). DBSCAN behoort 2 clusters (die normale verkeersclusters) te vind en die 5 ingevoegde uitskieters as geraas te merk. Ons voer die aantal clusters teenoor geraaspunte uit om dit te verifieer. In ’n werklike situasie kan ’n mens oor ε (met behulp van ’n k-distance-grafiekheuristiek om ε te kies) en MinPts iter eer (dikwels gestel op ongeveer die datadimensionaliteit + 1 as ’n duimreël) om stabiele clustering-resultate te vind. Die vermoë om geraas uitdruklik te benoem, help om potensiële aanvaldata vir verdere ontleding te skei.

</details>

### Principal Component Analysis (PCA)

PCA is ’n tegniek vir **dimensionaliteitsvermindering** wat ’n nuwe stel ortogonale asse (principal components) vind wat die maksimum variansie in die data vasvang. In eenvoudige terme roteer en projekteer PCA die data op ’n nuwe koordinatestelsel sodat die eerste principal component (PC1) die grootste moontlike variansie verklaar, die tweede PC (PC2) die grootste variansie ortogonaal tot PC1 verklaar, ensovoorts. Wiskundig bereken PCA die eigenvektore van die data se kovariansiematriks – hierdie eigenvektore is die rigtings van die principal components, en die ooreenstemmende eigenwaardes dui die hoeveelheid variansie aan wat deur elkeen verklaar word. Dit word dikwels vir kenmerkekstraksie, visualisering en geraasvermindering gebruik.

Let daarop dat dit nuttig is indien die datastel se dimensies **beduidende lineêre afhanklikhede of korrelasies** bevat.

PCA werk deur die data se principal components te identifiseer, wat die rigtings van maksimum variansie is. Die stappe wat by PCA betrokke is:
1. **Standaardisering**: Sentreer die data deur die gemiddelde af te trek en dit na eenheidsvariansie te skaleer.
2. **Kovariansiematriks**: Bereken die gestandaardiseerde data se kovariansiematriks om die verwantskappe tussen kenmerke te verstaan.
3. **Eigenwaarde-ontbinding**: Voer eigenwaarde-ontbinding op die kovariansiematriks uit om die eigenwaardes en eigenvektore te verkry.
4. **Kies Principal Components**: Sorteer die eigenwaardes in dalende volgorde en kies die top K-eigenvektore wat met die grootste eigenwaardes ooreenstem. Hierdie eigenvektore vorm die nuwe kenmerkruimte.
5. **Transformeer data**: Projekteer die oorspronklike data op die nuwe kenmerkruimte deur die gekose principal components te gebruik.
PCA word wyd gebruik vir datavisualisering, geraasvermindering en as ’n voorverwerkingstap vir ander machine learning-algoritmes. Dit help om die dimensionaliteit van die data te verminder terwyl die noodsaaklike struktuur daarvan behoue bly.

#### Eigenwaardes en Eigenvektore

’n Eigenwaarde is ’n skalaar wat die hoeveelheid variansie aandui wat deur sy ooreenstemmende eigenvektor vasgevang word. ’n Eigenvektor verteenwoordig ’n rigting in die kenmerkruimte waarin die data die meeste varieer.

Stel jou voor A is ’n vierkantige matriks, en v is ’n nie-nul-vektor sodat: `A * v = λ * v`
waar:
- A ’n vierkantige matriks is soos [ [1, 2], [2, 1]] (bv. kovariansiematriks)
- v ’n eigenvektor is (bv. [1, 1])

Dan is `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, wat die eigenwaarde λ vermenigvuldig met die eigenvektor v sal wees, sodat die eigenwaarde λ = 3 is.

#### Eigenwaardes en Eigenvektore in PCA

Kom ons verduidelik dit met ’n voorbeeld. Stel jou voor jy het ’n datastel met baie grysskaalfoto’s van gesigte met 100x100 pixels. Elke pixel kan as ’n kenmerk beskou word, dus het jy 10 000 kenmerke per beeld (of ’n vektor met 10000 komponente per beeld). Indien jy die dimensionaliteit van hierdie datastel met PCA wil verminder, sal jy die volgende stappe volg:

1. **Standaardisering**: Sentreer die data deur die gemiddelde van elke kenmerk (pixel) van die datastel af te trek.
2. **Kovariansiematriks**: Bereken die gestandaardiseerde data se kovariansiematriks, wat vasvang hoe kenmerke (pixels) saam varieer.
- Let daarop dat die kovariansie tussen twee veranderlikes (pixels in hierdie geval) aandui in watter mate hulle saam verander; die idee hier is dus om uit te vind watter pixels geneig is om saam met ’n lineêre verwantskap toe of af te neem.
- Byvoorbeeld, indien pixel 1 en pixel 2 geneig is om saam toe te neem, sal die kovariansie tussen hulle positief wees.
- Die kovariansiematriks sal ’n 10,000x10,000-matriks wees waar elke inskrywing die kovariansie tussen twee pixels verteenwoordig.
3. **Los die eigenwaardevergelyking op**: Die eigenwaardevergelyking wat opgelos moet word, is `C * v = λ * v`, waar C die kovariansiematriks is, v die eigenvektor is en λ die eigenwaarde is. Dit kan opgelos word met metodes soos:
- **Eigenwaarde-ontbinding**: Voer eigenwaarde-ontbinding op die kovariansiematriks uit om die eigenwaardes en eigenvektore te verkry.
- **Singular Value Decomposition (SVD)**: Alternatiewelik kan jy SVD gebruik om die datamatriks in singuliere waardes en vektore te ontbind, wat ook die principal components kan oplewer.
4. **Kies Principal Components**: Sorteer die eigenwaardes in dalende volgorde en kies die top K-eigenvektore wat met die grootste eigenwaardes ooreenstem. Hierdie eigenvektore verteenwoordig die rigtings van maksimum variansie in die data.

> [!TIP]
> *Gebruiksscenario’s in cybersecurity:* ’n Algemene gebruik van PCA in security is kenmerkvermindering vir anomalie-opsporing. Byvoorbeeld, ’n intrusion detection system met meer as 40 network metrics (soos NSL-KDD-kenmerke) kan PCA gebruik om dit tot ’n handvol components te verminder, wat die data vir visualisering opsom of dit aan clustering-algoritmes voer. Analiste kan network traffic in die ruimte van die eerste twee principal components plot om te sien of attacks van normale traffic skei. PCA kan ook help om redundante kenmerke uit te skakel (soos bytes sent teenoor bytes received indien hulle gekorreleer is), wat detection-algoritmes meer robuust en vinniger maak.

#### Aannames en Beperkings

PCA neem aan dat **principal axes of variance betekenisvol is** – dit is ’n lineêre metode, dus vang dit lineêre korrelasies in data vas. Dit is unsupervised omdat dit slegs die kenmerkkovariansie gebruik. Voordele van PCA sluit geraasvermindering in (komponente met klein variansie stem dikwels met geraas ooreen) sowel as die dekorrelering van kenmerke. Dit is berekeningsdoeltreffend vir matig hoë dimensies en is dikwels ’n nuttige voorverwerkingstap vir ander algoritmes (om die curse of dimensionality te versag). Een beperking is dat PCA tot lineêre verwantskappe beperk is – dit sal nie komplekse nie-lineêre strukture vasvang nie (terwyl autoencoders of t-SNE dalk wel kan). PCA-komponente kan ook moeilik wees om in terme van die oorspronklike kenmerke te interpreteer (hulle is kombinasies van oorspronklike kenmerke). In cybersecurity moet ’n mens versigtig wees: ’n aanval wat slegs ’n subtiele verandering in ’n lae-variansie-kenmerk veroorsaak, sal dalk nie in die top PCs verskyn nie (omdat PCA variansie prioritiseer en nie noodwendig “interessantheid” nie).

<details>
<summary>Voorbeeld -- Vermindering van die Dimensionaliteit van Network Data
</summary>

Gestel ons het network connection logs met verskeie kenmerke (bv. durations, bytes, counts). Ons sal ’n sintetiese 4-dimensionele datastel (met ’n mate van korrelasie tussen kenmerke) genereer en PCA gebruik om dit tot 2 dimensies te verminder vir visualisering of verdere ontleding.
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
Hier het ons die vroeëre normale verkeersclusters geneem en elke datapunt uitgebrei met twee bykomende kenmerke (packets en errors) wat met bytes en duration korreleer. PCA word vervolgens gebruik om die 4 kenmerke tot 2 hoofkomponente saam te pers. Ons druk die explained variance ratio, wat kan toon dat byvoorbeeld >95% van die variansie deur 2 komponente vasgevang word (wat min inligtingsverlies beteken). Die uitvoer toon ook dat die datavorm van (1500, 4) na (1500, 2) verminder. Die eerste paar punte in PCA-ruimte word as ’n voorbeeld gegee. In die praktyk kan ’n mens data_2d plot om visueel te kontroleer of die clusters onderskeibaar is. Indien ’n anomalie teenwoordig was, sou ’n mens dit moontlik sien as ’n punt wat weg van die hoofcluster in PCA-ruimte lê. PCA help dus om komplekse data tot ’n hanteerbare vorm te distilleer vir menslike interpretasie of as toevoer tot ander algoritmes.

</details>


### Gaussian Mixture Models (GMM)

’n Gaussian Mixture Model neem aan dat data gegenereer word uit ’n mengsel van **verskeie Gaussian (normale) distribusies met onbekende parameters**. In wese is dit ’n probabilistiese clustering-model: dit probeer om elke punt sagkens aan een van K Gaussian-komponente toe te ken. Elke Gaussian-komponent k het ’n gemiddeldevektor (μ_k), kovariansiematriks (Σ_k) en ’n menggewig (π_k) wat aandui hoe algemeen daardie cluster is. Anders as K-Means, wat “harde” toewysings doen, gee GMM aan elke punt ’n waarskynlikheid om aan elke cluster te behoort.

GMM-fitting word tipies deur die Expectation-Maximization (EM)-algoritme gedoen:

- **Initialisering**: Begin met aanvanklike skattings vir die gemiddeldes, kovariansies en mengkoëffisiënte (of gebruik K-Means-resultate as ’n beginpunt).

- **E-stap (Expectation)**: Gegee die huidige parameters, bereken die verantwoordelikheid van elke cluster vir elke punt: in wese `r_nk = P(z_k | x_n)` waar z_k die latente veranderlike is wat clusteraardelidmaatskap vir punt x_n aandui. Dit word met Bayes se stelling gedoen, waar die posterior-waarskynlikheid bereken word dat elke punt aan elke cluster behoort, gebaseer op die huidige parameters. Die verantwoordelikhede word soos volg bereken:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
waar:
- \( \pi_k \) die mengkoëffisiënt vir cluster k is (die voorafwaarskynlikheid van cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) die Gaussian-waarskynlikheidsdigtheidsfunksie vir punt \( x_n \) is, gegewe die gemiddelde \( \mu_k \) en kovariansie \( \Sigma_k \).

- **M-stap (Maximization)**: Werk die parameters by deur die verantwoordelikhede te gebruik wat in die E-stap bereken is:
- Werk elke gemiddelde μ_k by as die geweegde gemiddelde van die punte, waar die gewigte die verantwoordelikhede is.
- Werk elke kovariansie Σ_k by as die geweegde kovariansie van punte wat aan cluster k toegewys is.
- Werk mengkoëffisiënte π_k by as die gemiddelde verantwoordelikheid vir cluster k.

- **Herhaal** die E- en M-stappe totdat konvergensie bereik word (die parameters stabiliseer of die verbetering in waarskynlikheid onder ’n drempel val).

Die resultaat is ’n stel Gaussian-distribusies wat gesamentlik die algehele datadistribusie modelleer. Ons kan die aangeleerde GMM gebruik om te cluster deur elke punt aan die Gaussian met die hoogste waarskynlikheid toe te wys, of die waarskynlikhede vir onsekerheid behou. ’n Mens kan ook die waarskynlikheid van nuwe punte evalueer om te sien of hulle by die model pas (nuttig vir anomalie-opsporing).

> [!TIP]
> *Gebruiksgevalle in kuberveiligheid:* GMM kan vir anomalie-opsporing gebruik word deur die distribusie van normale data te modelleer: enige punt met ’n baie lae waarskynlikheid onder die aangeleerde mengsel word as ’n anomalie gemerk. Jy kan byvoorbeeld ’n GMM op wettige netwerkverkeerkenmerke oplei; ’n aanvalverbinding wat nie soos enige aangeleerde cluster lyk nie, sou ’n lae waarskynlikheid hê. GMMs word ook gebruik om aktiwiteite te cluster waar clusters verskillende vorms kan hê – byvoorbeeld om gebruikers volgens gedragprofiele te groepeer, waar elke profiel se kenmerke moontlik Gaussian-agtig kan wees, maar met sy eie variansiestruktuur. Nog ’n scenario is phishing-opsporing: kenmerke van wettige e-posse kan een Gaussian-cluster vorm, bekende phishing ’n ander, en nuwe phishing-veldtogte kan óf as ’n afsonderlike Gaussian óf as punte met ’n lae waarskynlikheid relatief tot die bestaande mengsel verskyn.

#### Aannames en Beperkings

GMM is ’n veralgemening van K-Means wat kovariansie insluit, sodat clusters ellipsoïdaal kan wees (nie net sferies nie). Dit hanteer clusters van verskillende groottes en vorms indien kovariansie volledig is. Sagte clustering is ’n voordeel wanneer clustergrense vaag is – byvoorbeeld in kuberveiligheid, waar ’n gebeurtenis eienskappe van verskeie aanvalstipes kan hê; GMM kan daardie onsekerheid met waarskynlikhede weerspieël. GMM verskaf ook ’n probabilistiese digtheidskatting van die data, wat nuttig is om uitskieters op te spoor (punte met ’n lae waarskynlikheid onder alle mengselkomponente).

Aan die negatiewe kant vereis GMM dat die aantal komponente K gespesifiseer word (hoewel ’n mens kriteria soos BIC/AIC kan gebruik om dit te kies). EM kan soms stadig konvergeer of na ’n plaaslike optimum konvergeer, dus is initialisering belangrik (EM word dikwels verskeie kere uitgevoer). Indien die data nie werklik ’n mengsel van Gaussians volg nie, kan die model swak pas. Daar is ook ’n risiko dat een Gaussian krimp om slegs ’n uitskieter te dek (hoewel regularisering of minimum kovariansiegrense dit kan beperk).


<details>
<summary>Voorbeeld -- Sagte Clustering en Anomalietellings
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
In hierdie kode lei ons ’n GMM met 3 Gaussians op die normale verkeer op (met die aanname dat ons 3 profiele van wettige verkeer ken). Die gemiddeldes en kovariansies wat gedruk word, beskryf hierdie groepe (byvoorbeeld, een gemiddelde kan ongeveer [50,500] wees, wat met die middelpunt van een groep ooreenstem, ens.). Ons toets dan ’n verdagte verbinding [duration=200, bytes=800]. Die predict_proba gee die waarskynlikheid dat hierdie punt aan elk van die 3 groepe behoort – ons sou verwag dat hierdie waarskynlikhede baie laag of sterk skeefgetrek sal wees, aangesien [200,800] ver van die normale groepe lê. Die algehele score_samples (log-likelihood) word gedruk; ’n baie lae waarde dui aan dat die punt nie goed by die model pas nie, wat dit as ’n anomalie merk. In die praktyk kan ’n drempel op die log-likelihood (of op die maksimum waarskynlikheid) gestel word om te besluit of ’n punt onwaarskynlik genoeg is om as kwaadwillig beskou te word. GMM bied dus ’n gegronde manier om anomaly detection uit te voer en lewer ook sagte groepe wat onsekerheid erken.
</details>

### Isolation Forest

**Isolation Forest** is ’n ensemble-algoritme vir anomaly detection wat gebaseer is op die idee om punte lukraak te isoleer. Die beginsel is dat anomalieë min is en verskillend is, en dus makliker geïsoleer kan word as normale punte. ’n Isolation Forest bou baie binêre isolasie-bome (lukrake besluitnemingsbome) wat die data lukraak partisioneer. By elke node in ’n boom word ’n lukrake kenmerk gekies en ’n lukrake skeidingswaarde tussen die minimum en maksimum van daardie kenmerk vir die data in daardie node bepaal. Hierdie skeiding verdeel die data in twee vertakkings. Die boom groei totdat elke punt in sy eie blaar geïsoleer is of ’n maksimum boomhoogte bereik word.

Anomaly detection word uitgevoer deur die padlengte van elke punt in hierdie lukrake bome waar te neem – die aantal skeidings wat nodig is om die punt te isoleer. Intuïtief word anomalieë (uitskieters) geneig om vinniger geïsoleer te word, omdat ’n lukrake skeiding meer waarskynlik ’n uitskieter (wat in ’n yl gebied lê) sal skei as ’n normale punt in ’n digte groep. Die Isolation Forest bereken ’n anomaliescore uit die gemiddelde padlengte oor al die bome: korter gemiddelde pad → meer anomalie. Tellings word gewoonlik na [0,1] genormaliseer, waar 1 ’n baie waarskynlike anomalie beteken.

> [!TIP]
> *Gebruiksgevalle in cybersecurity:* Isolation Forests is suksesvol gebruik in intrusion detection en fraud detection. Lei byvoorbeeld ’n Isolation Forest op netwerkverkeerslogboeke op wat hoofsaaklik normale gedrag bevat; die bos sal kort paaie vir vreemde verkeer produseer (soos ’n IP wat ’n ongekende poort gebruik of ’n ongewone pakkiegroottepatroon het), en dit vir inspeksie merk. Omdat dit nie gemerkte aanvalle vereis nie, is dit geskik om onbekende aanvalstipes op te spoor. Dit kan ook op gebruikersaanmeldingsdata ontplooi word om account takeovers op te spoor (die abnormale aanmeldingstye of -liggings word vinnig geïsoleer). In een gebruiksgeval kan ’n Isolation Forest ’n onderneming beskerm deur stelselmaatstawwe te monitor en ’n waarskuwing te genereer wanneer ’n kombinasie van maatstawwe (CPU, netwerk, lêerveranderinge) baie anders as historiese patrone lyk (kort isolasiepaaie).

#### Aannames en Beperkings

**Voordele**: Isolation Forest vereis nie ’n verspreidingsaanname nie; dit fokus direk op isolasie. Dit is doeltreffend met hoëdimensionele data en groot datastelle (lineêre kompleksiteit $O(n\log n)$ vir die bou van die bos), aangesien elke boom punte met slegs ’n deelversameling van die kenmerke en skeidings isoleer. Dit hanteer numeriese kenmerke gewoonlik goed en kan vinniger wees as afstandgebaseerde metodes wat moontlik $O(n^2)$ is. Dit verskaf ook outomaties ’n anomaliescore, sodat jy ’n drempel vir waarskuwings kan stel (of ’n contamination-parameter kan gebruik om outomaties ’n afsnypunt te bepaal gebaseer op ’n verwagte anomaliefraksie).

**Beperkings**: Weens die lukrake aard daarvan kan resultate effens tussen lopies verskil (hoewel dit met genoeg bome gering is). As die data baie irrelevante kenmerke bevat of as anomalieë nie sterk op enige kenmerk onderskei nie, is die isolasie moontlik nie doeltreffend nie (lukrake skeidings kan normale punte toevallig isoleer – die gemiddelde van baie bome verminder egter hierdie effek). Isolation Forest neem ook oor die algemeen aan dat anomalieë ’n klein minderheid is (wat gewoonlik in cybersecurity-scenario’s waar is).

<details>
<summary>Voorbeeld -- Opsporing van Uitskieters in Netwerklogboeke
</summary>

Ons sal die vorige toetsdatastel gebruik (wat normale en sommige aanvalspunte bevat) en ’n Isolation Forest uitvoer om te sien of dit die aanvalle kan skei. Ons sal aanneem dat ons verwag dat ongeveer 15% van die data anomalieë is (vir demonstrasiedoeleindes).
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
In hierdie kode instansieer ons `IsolationForest` met 100 bome en stel ons `contamination=0.15` in (wat beteken dat ons ongeveer 15% anomalies verwag; die model sal sy tellingdrempel instel sodat ongeveer 15% van die punte gemerk word). Ons pas dit op `X_test_if` toe, wat 'n mengsel van normale en aanvalspunte bevat (let wel: normaalweg sou jy op opleidingsdata pas en dan `predict` op nuwe data gebruik, maar hier pas en voorspel ons ter illustrasie op dieselfde stel om die resultate direk waar te neem).

Die afvoer wys die voorspelde etikette vir die eerste 20 punte (waar -1 'n anomaly aandui). Ons druk ook hoeveel anomalies in totaal opgespoor is en enkele voorbeeld-anomalietellings. Ons sou ongeveer 18 uit 120 punte verwag om as -1 gemerk te word (omdat contamination 15% was). As ons 20 aanvalmonsters werklik die mees uitsonderlike is, behoort die meeste van hulle in daardie -1-voorspellings te verskyn. Die anomalietelling (Isolation Forest se besluitfunksie) is hoër vir normale punte en laer (meer negatief) vir anomalies – ons druk 'n paar waardes om die skeiding te sien. In die praktyk kan 'n mens die data volgens telling sorteer om die mees uitsonderlike punte te sien en dit te ondersoek. Isolation Forest bied dus 'n doeltreffende manier om deur groot, ongemerkte sekuriteitsdata te sif en die mees onreëlmatige gevalle vir menslike ontleding of verdere geoutomatiseerde ondersoek uit te sonder.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** is 'n nie-lineêre dimensionaliteitsreduksietegniek wat spesifiek ontwerp is om hoëdimensionele data in 2 of 3 dimensies te visualiseer. Dit omskep ooreenkomste tussen datapunte in gesamentlike waarskynlikheidsverdelings en probeer om die struktuur van plaaslike bure in die laerdimensionele projeksie te behou. In eenvoudiger terme plaas t-SNE punte in (byvoorbeeld) 2D sodat soortgelyke punte (in die oorspronklike ruimte) naby mekaar beland en ongelyksoortige punte met 'n hoë waarskynlikheid ver van mekaar beland.

Die algoritme het drie hoofstadia:

1. **Bereken paargewyse affiniteite in hoëdimensionele ruimte:** Vir elke paar punte bereken t-SNE 'n waarskynlikheid dat 'n mens daardie paar as bure sou kies (dit word gedoen deur 'n Gaussiese verdeling op elke punt te sentreer en afstande te meet – die perplexity-parameter beïnvloed die effektiewe aantal bure wat oorweeg word).
2. **Bereken paargewyse affiniteite in laerdimensionele (byvoorbeeld 2D-)ruimte:** Aanvanklik word punte lukraak in 2D geplaas. t-SNE definieer 'n soortgelyke waarskynlikheid vir afstande in hierdie kaart (deur 'n Student t-verdelingskern te gebruik, wat swaarder sterte as Gaussies het om verafgeleë punte meer vryheid te gee).
3. **Gradient Descent:** t-SNE verskuif dan die punte iteratief in 2D om die Kullback–Leibler- (KL-)divergensie tussen die hoë-D-affiniteitsverdeling en die lae-D-verdeling te minimaliseer. Dit veroorsaak dat die 2D-rangskikking die hoë-D-struktuur so goed moontlik weerspieël – punte wat in die oorspronklike ruimte naby was, trek mekaar aan, en dié wat ver van mekaar was, stoot mekaar af totdat 'n balans gevind word.

Die resultaat is dikwels 'n visueel betekenisvolle spreidiagram waarin clusters in die data sigbaar word.

> [!TIP]
> *Gebruikgevalle in kuberveiligheid:* t-SNE word dikwels gebruik om **hoëdimensionele sekuriteitsdata vir menslike ontleding te visualiseer**. In 'n sekuriteitsbedryfsentrum kan ontleders byvoorbeeld 'n gebeurtenisdatastel met dosyne kenmerke (poortnommers, frekwensies, greep-tellings, ensovoorts) neem en t-SNE gebruik om 'n 2D-grafiek te skep. Aanvalle kan hul eie clusters vorm of in hierdie grafiek van normale data skei, wat dit makliker maak om hulle te identifiseer. Dit is op malware-datastelle toegepas om groeperings van malware-families te sien, of op netwerkindringingsdata waar verskillende aanvalsoorte duidelike clusters vorm, wat verdere ondersoek rig. In wese bied t-SNE 'n manier om struktuur in kuberdata te sien wat andersins ondeurgrondelik sou wees.

#### Aannames en Beperkings

t-SNE is uitstekend vir die visuele ontdekking van patrone. Dit kan clusters, subclusters en uitskieters onthul wat ander lineêre metodes (soos PCA) dalk nie kan nie. Dit is in kuberveiligheidsnavorsing gebruik om komplekse data soos malware-gedragsprofiele of netwerkverkeerpatrone te visualiseer. Omdat dit plaaslike struktuur behou, is dit goed daarmee om natuurlike groeperings te wys.

t-SNE is egter rekenaarmatig swaarder (ongeveer $O(n^2)$), en daarom kan steekproefneming vir baie groot datastelle nodig wees. Dit het ook hiperparameters (perplexity, learning rate, iterations) wat die afvoer kan beïnvloed – verskillende perplexity-waardes kan byvoorbeeld clusters op verskillende skale onthul. t-SNE-grafieke kan soms verkeerd geïnterpreteer word – afstande in die kaart is nie wêreldwyd direk betekenisvol nie (dit fokus op plaaslike bure; soms kan clusters kunsmatig goed geskei voorkom). t-SNE is ook hoofsaaklik vir visualisering; dit bied nie 'n eenvoudige manier om nuwe datapunte te projekteer sonder om die berekening te herhaal nie, en dit is nie bedoel om as 'n voorverwerkingsstap vir voorspellende modellering gebruik te word nie (UMAP is 'n alternatief wat sommige van hierdie probleme met groter spoed aanspreek).

<details>
<summary>Voorbeeld -- Visualisering van netwerkverbindings
</summary>

Ons sal t-SNE gebruik om 'n datastel met veelvuldige kenmerke na 2D te reduseer. Ter illustrasie neem ons die vroeëre 4D-data (wat 3 natuurlike clusters van normale verkeer gehad het) en voeg ons 'n paar anomaliepunte by. Ons voer dan t-SNE uit en visualiseer (konseptueel) die resultate.
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
Hier het ons ons vorige 4D-normale datastel gekombineer met ’n handvol ekstreme uitskieters (die uitskieters het een kenmerk (“duration”) baie hoog gestel, ens., om ’n ongewone patroon te simuleer). Ons voer t-SNE uit met ’n tipiese perplexity van 30. Die uitvoer `data_2d` het die vorm (1505, 2). Ons sal nie werklik in hierdie teks plot nie, maar indien ons dit sou doen, sou ons verwag om moontlik drie digte clusters te sien wat met die 3 normale clusters ooreenstem, terwyl die 5 uitskieters as geïsoleerde punte ver van daardie clusters verskyn. In ’n interaktiewe workflow kon ons die punte volgens hul label kleur (normaal of watter cluster, teenoor anomaly) om hierdie struktuur te verifieer. Selfs sonder labels kan ’n analyst daardie 5 punte in leë ruimte op die 2D-plot opmerk en dit vlag. Dit wys hoe t-SNE ’n kragtige hulpmiddel vir visuele anomaly detection en cluster-inspeksie in kuberveiligheidsdata kan wees, as aanvulling tot die geoutomatiseerde algorithms hierbo.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** is ’n uitbreiding van DBSCAN wat die behoefte uitskakel om ’n enkele globale `eps`-waarde te kies, en wat clusters met **verskillende digthede** kan herwin deur ’n hiërargie van digtheidsverbinde komponente te bou en dit dan te kondenseer. In vergelyking met vanilla DBSCAN

* onttrek dit gewoonlik meer intuïtiewe clusters wanneer sommige clusters dig is en ander yl is,
* het dit slegs een werklike hyper-parameter (`min_cluster_size`) en ’n sinvolle verstekwaarde,
* gee dit aan elke punt ’n cluster-membership *probability* en ’n **outlier score** (`outlier_scores_`), wat uiters nuttig is vir threat-hunting dashboards.<sup>[[1]](#references)</sup>

> [!TIP]
> *Gebruikgevalle in kuberveiligheid:* HDBSCAN is baie gewild in moderne threat-hunting pipelines – jy sal dit dikwels sien binne notebook-gebaseerde hunting playbooks wat saam met kommersiële XDR-suites gelewer word. Een praktiese resep is om HTTP-beaconing-verkeer tydens IR te cluster: user-agent, interval en URI-lengte vorm dikwels verskeie digte groepe van wettige software updaters, terwyl C2-beacons as klein clusters met lae digtheid of as suiwer noise oorbly.

<details>
<summary>Voorbeeld – Finding beaconing C2 channels</summary>
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

### Robustheid en sekuriteitsoorwegings – Poisoning & Adversarial Attacks (2023-2025)

Onlangse werk het getoon dat **unsupervised learners *nie* immuun teen aktiewe aanvallers is nie**:

* **Data-poisoning teen anomaly detectors.** Chen *et al.* (IEEE S&P 2024) het gedemonstreer dat die toevoeging van slegs 3 % spesiaal vervaardigde traffic die decision boundary van Isolation Forest en ECOD kan verskuif, sodat werklike attacks normaal lyk. Die outeurs het ’n open-source PoC (`udo-poison`) vrygestel wat poison points outomaties sintetiseer.<sup>[[2]](#references)</sup>
* **Backdooring clustering models.** Die *BadCME*-tegniek (BlackHat EU 2023) plaas ’n klein trigger pattern; wanneer daardie trigger verskyn, plaas ’n K-Means-gebaseerde detector die event stilweg binne ’n “benign” cluster.
* **Evasion van DBSCAN/HDBSCAN.** ’n Akademiese pre-print van KU Leuven uit 2025 het getoon dat ’n aanvaller beaconing patterns kan vervaardig wat doelbewus in density gaps val, en sodoende effektief binne *noise*-labels wegkruip.

Mitigations wat toenemend gebruik word:

1. **Model sanitisation / TRIM.** Voor elke retraining epoch word die 1–2 % punte met die hoogste loss weggegooi (trimmed maximum likelihood) om poisoning aansienlik moeiliker te maak.
2. **Consensus ensembling.** Kombineer verskeie heterogene detectors (bv. Isolation Forest + GMM + ECOD) en genereer ’n alert indien *enige* model ’n punt flag. Navorsing dui daarop dat dit die aanvaller se koste met >10× verhoog.
3. **Distance-based defence for clustering.** Bereken clusters opnuut met `k` verskillende random seeds en ignoreer punte wat voortdurend tussen clusters beweeg.

---

### Moderne Open-Source Tooling (2024-2025)

* **PyOD 2.x** (vrygestel Mei 2024) het *ECOD*, *COPOD* en GPU-versnelde *AutoFormer*-detectors bygevoeg. Dit bevat nou ’n `benchmark`-subcommand waarmee jy 30+ algorithms op jou dataset kan vergelyk met **een reël kode**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (Feb 2025) fokus op vision, maar bevat ook ’n generiese **PatchCore**-implementering – nuttig vir screenshot-gebaseerde phishing page-detection.
* **scikit-learn 1.5** (Nov 2024) stel uiteindelik `score_samples` vir *HDBSCAN* beskikbaar via die nuwe `cluster.HDBSCAN`-wrapper, sodat jy nie die eksterne contrib-package nodig het wanneer jy Python 3.12 gebruik nie.

<details>
<summary>Vinnige PyOD-voorbeeld – ECOD + Isolation Forest-ensemble</summary>
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

## Verwysings

- [1] [HDBSCAN – Hiërargiese digtheidsgebaseerde groepering](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* “Oor die kwesbaarheid van ongesuperviseerde anomalie-opsporing vir datavergiftiging.” *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
