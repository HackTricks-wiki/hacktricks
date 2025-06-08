# Ongehoorde Leer Algoritmes

{{#include ../banners/hacktricks-training.md}}

## Ongehoorde Leer

Ongehoorde leer is 'n tipe masjienleer waar die model op data sonder gelabelde antwoorde opgelei word. Die doel is om patrone, strukture of verhoudings binne die data te vind. Anders as gesuperviseerde leer, waar die model van gelabelde voorbeelde leer, werk ongehoorde leer algoritmes met ongelabelde data. 
Ongehoorde leer word dikwels gebruik vir take soos groepering, dimensie vermindering en anomalie opsporing. Dit kan help om versteekte patrone in data te ontdek, soortgelyke items saam te groepeer, of die kompleksiteit van die data te verminder terwyl die essensiële kenmerke behou word.

### K-Means Groepering

K-Means is 'n sentroid-gebaseerde groeperingsalgoritme wat data in K groepe verdeel deur elke punt aan die naaste groep gemiddelde toe te ken. Die algoritme werk soos volg:
1. **Inisialisering**: Kies K aanvanklike groep sentrums (sentroïede), dikwels ewekansig of via slimmer metodes soos k-means++
2. **Toekenning**: Ken elke datapunt aan die naaste sentroid toe op grond van 'n afstandsmetrie (bv. Euclidiese afstand).
3. **Opdatering**: Herbereken die sentroïede deur die gemiddelde van alle datapunte wat aan elke groep toegeken is, te neem.
4. **Herhaal**: Stappe 2–3 word herhaal totdat die groep toekennings stabiliseer (sentroïede beweeg nie meer beduidend nie).

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* K-Means word gebruik vir indringing opsporing deur netwerkgebeurtenisse te groepeer. Byvoorbeeld, navorsers het K-Means toegepas op die KDD Cup 99 indringingsdataset en gevind dat dit effektief verkeer in normale teenoor aanval groepe verdeel. In praktyk kan sekuriteitsontleders loginskrywings of gebruikersgedragdata groepeer om groepe van soortgelyke aktiwiteit te vind; enige punte wat nie aan 'n goed gevormde groep behoort nie, kan anomalieë aandui (bv. 'n nuwe malware variasie wat sy eie klein groep vorm). K-Means kan ook help met malware familie klassifikasie deur binaire lêers op grond van gedragsprofiele of kenmerk vektore te groepeer.

#### Keuse van K
Die aantal groepe (K) is 'n hiperparameter wat gedefinieer moet word voordat die algoritme uitgevoer word. Tegnieke soos die Elbow Metode of Silhouette Punt kan help om 'n toepaslike waarde vir K te bepaal deur die groepering prestasie te evalueer:

- **Elbow Metode**: Plot die som van die kwadratiese afstande van elke punt na sy toegekenne groep sentroid as 'n funksie van K. Soek 'n "elboog" punt waar die tempo van afname skerp verander, wat 'n geskikte aantal groepe aandui.
- **Silhouette Punt**: Bereken die silhouette punt vir verskillende waardes van K. 'n Hoër silhouette punt dui op beter gedefinieerde groepe aan.

#### Aannames en Beperkings

K-Means neem aan dat **groepe sferies en gelyk groot is**, wat dalk nie vir alle datasets waar is nie. Dit is sensitief vir die aanvanklike plasing van sentroïede en kan na plaaslike minima konvergeer. Boonop is K-Means nie geskik vir datasets met verskillende digthede of nie-globulêre vorms en kenmerke met verskillende skale nie. Voorverwerkingsstappe soos normalisering of standaardisering mag nodig wees om te verseker dat alle kenmerke gelyk bydra tot die afstandsberekeninge.

<details>
<summary>Voorbeeld -- Groepering van Netwerk Gebeurtenisse
</summary>
Hieronder simuleer ons netwerkverkeer data en gebruik K-Means om dit te groepeer. Neem aan ons het gebeurtenisse met kenmerke soos verbinding duur en byte telling. Ons skep 3 groepe van “normale” verkeer en 1 klein groep wat 'n aanvalspatroon verteenwoordig. Dan voer ons K-Means uit om te sien of dit hulle skei.
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
In hierdie voorbeeld moet K-Means 4 groepe vind. Die klein aanvalsgroep (met ongewone hoë duur ~200) sal idealiter sy eie groep vorm gegewe sy afstand van normale groepe. Ons druk die grootte en sentrums van die groepe uit om die resultate te interpreteer. In 'n werklike scenario kan 'n mens die groep met 'n paar punte as potensiële anomalieë etiketteer of sy lede ondersoek vir kwaadwillige aktiwiteit.

### Hiërargiese Groepering

Hiërargiese groepering bou 'n hiërargie van groepe op deur óf 'n onder-na-bo (agglomeratiewe) benadering óf 'n bo-na-onder (divisiewe) benadering te gebruik:

1. **Agglomeratiewe (Onder-Na-Bo)**: Begin met elke datapunt as 'n aparte groep en kombineer herhaaldelik die naaste groepe totdat 'n enkele groep oorbly of 'n stopkriterium bereik word.
2. **Divisiewe (Bo-Na-Onder)**: Begin met alle datapunte in 'n enkele groep en verdeel herhaaldelik die groepe totdat elke datapunt sy eie groep is of 'n stopkriterium bereik word.

Agglomeratiewe groepering vereis 'n definisie van inter-groep afstand en 'n skakelingskriterium om te besluit watter groepe om te kombineer. Algemene skakelingsmetodes sluit enkele skakeling (afstand van die naaste punte tussen twee groepe), volledige skakeling (afstand van die verste punte), gemiddelde skakeling, ensovoorts in, en die afstandsmetrieks is dikwels Euclidies. Die keuse van skakeling beïnvloed die vorm van die geproduceerde groepe. Daar is geen behoefte om die aantal groepe K vooraf te spesifiseer nie; jy kan die dendrogram op 'n gekose vlak "sny" om die gewenste aantal groepe te verkry.

Hiërargiese groepering produseer 'n dendrogram, 'n boomagtige struktuur wat die verhoudings tussen groepe op verskillende vlakke van granulariteit toon. Die dendrogram kan op 'n gewenste vlak gesny word om 'n spesifieke aantal groepe te verkry.

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* Hiërargiese groepering kan gebeurtenisse of entiteite in 'n boom organiseer om verhoudings te identifiseer. Byvoorbeeld, in kwaadwillige sagteware analise kan agglomeratiewe groepering monsters volgens gedragsgelykheid groepeer, wat 'n hiërargie van kwaadwillige sagteware families en variasies onthul. In netwerkveiligheid kan 'n mens IP-verkeerstrome groepeer en die dendrogram gebruik om subgroeperings van verkeer te sien (bv. volgens protokol, dan volgens gedrag). Omdat jy nie K vooraf hoef te kies nie, is dit nuttig wanneer jy nuwe data verken waarvoor die aantal aanvalkategorieë onbekend is.

#### Aannames en Beperkings

Hiërargiese groepering neem nie 'n spesifieke groepvorm aan nie en kan geneste groepe vasvang. Dit is nuttig om taksonomie of verhoudings tussen groepe te ontdek (bv. om kwaadwillige sagteware volgens familie subgroepe te groepeer). Dit is deterministies (geen random inisialisasie probleme nie). 'n Sleutelvoordeel is die dendrogram, wat insig bied in die data se groeperingsstruktuur op alle skale – sekuriteitsontleders kan 'n toepaslike afsnit besluit om betekenisvolle groepe te identifiseer. Dit is egter rekenaarintensief (tipies $O(n^2)$ tyd of erger vir naïewe implementasies) en nie haalbaar vir baie groot datastelle nie. Dit is ook 'n gulsige prosedure – sodra 'n kombinasie of splitsing gedoen is, kan dit nie ongedaan gemaak word nie, wat tot suboptimale groepe kan lei as 'n fout vroeg gebeur. Uitskieters kan ook sommige skakelingsstrategieë beïnvloed (enkele skakeling kan die "ketting" effek veroorsaak waar groepe via uitskieters skakel).

<details>
<summary>Voorbeeld -- Agglomeratiewe Groepering van Gebeurtenisse
</summary>

Ons sal die sintetiese data van die K-Means voorbeeld (3 normale groepe + 1 aanvalsgroep) hergebruik en agglomeratiewe groepering toepas. Ons illustreer dan hoe om 'n dendrogram en groep etikette te verkry.
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

### DBSCAN (Digtheid-gebaseerde Ruimtelike Groepering van Toepassings met Ruis)

DBSCAN is 'n digtheid-gebaseerde groeperingsalgoritme wat punte wat naby mekaar gepak is, saamgroepeer terwyl dit punte in lae-digtheid gebiede as uitskieters merk. Dit is veral nuttig vir datastelle met verskillende digthede en nie-sferiese vorms.

DBSCAN werk deur twee parameters te definieer:
- **Epsilon (ε)**: Die maksimum afstand tussen twee punte om as deel van dieselfde groep beskou te word.
- **MinPts**: Die minimum aantal punte wat benodig word om 'n digte gebied (kernpunt) te vorm.

DBSCAN identifiseer kernpunte, grenspunte en ruispunte:
- **Kernpunt**: 'n Punt met ten minste MinPts bure binne ε afstand.
- **Grenspunt**: 'n Punt wat binne ε afstand van 'n kernpunt is, maar minder as MinPts bure het.
- **Ruispunt**: 'n Punt wat nie 'n kernpunt of 'n grenspunt is nie.

Groepering vorder deur 'n onbesoekte kernpunt te kies, dit as 'n nuwe groep te merk, en dan alle punte wat digtheid-bereikbaar is daarvan (kernpunte en hul bure, ens.) rekursief by te voeg. Grenspunte word by die groep van 'n nabye kern gevoeg. Nadat alle bereikbare punte uitgebrei is, beweeg DBSCAN na 'n ander onbesoekte kern om 'n nuwe groep te begin. Punte wat nie deur enige kern bereik is nie, bly as ruis gemerk.

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* DBSCAN is nuttig vir anomaliedetektering in netwerkverkeer. Byvoorbeeld, normale gebruikersaktiwiteit kan een of meer digte groepe in kenmerkruimte vorm, terwyl nuut aanvalsgedrag as verspreide punte verskyn wat DBSCAN as ruis (uitskieters) sal merk. Dit is gebruik om netwerkvloei-rekords te groepeer, waar dit poortskandering of ontkenning-van-diens verkeer as dun gebiede van punte kan opspoor. 'n Ander toepassing is die groepering van malware-variante: as die meeste monsters volgens families groepeer, maar 'n paar nêrens pas nie, kan daardie paar nul-dag malware wees. Die vermoë om ruis te merk beteken dat sekuriteitspanne op die ondersoek van daardie uitskieters kan fokus.

#### Aannames en Beperkings

**Aannames & Sterkte:**: DBSCAN neem nie sferiese groepe aan nie – dit kan arbitrêr gevormde groepe vind (selfs ketting-agtige of aangrensende groepe). Dit bepaal outomaties die aantal groepe op grond van datadigtheid en kan effektief uitskieters as ruis identifiseer. Dit maak dit kragtig vir werklike data met onreëlmatige vorms en ruis. Dit is robuust teen uitskieters (in teenstelling met K-Means, wat hulle in groepe dwing). Dit werk goed wanneer groepe ongeveer uniforme digtheid het.

**Beperkings**: DBSCAN se prestasie hang af van die keuse van toepaslike ε en MinPts waardes. Dit kan sukkel met data wat verskillende digthede het – 'n enkele ε kan nie sowel digte as dun groepe akkommodeer nie. As ε te klein is, merk dit die meeste punte as ruis; te groot, en groepe kan verkeerd saamvloei. Ook, DBSCAN kan ondoeltreffend wees op baie groot datastelle (naïef $O(n^2)$, hoewel ruimtelike indeksering kan help). In hoë-dimensionele kenmerkruimtes kan die konsep van “afstand binne ε” minder betekenisvol word (die vloek van dimensionaliteit), en DBSCAN mag versigtige parameterafstemming benodig of mag misluk om intuïtiewe groepe te vind. Ten spyte hiervan, adresseer uitbreidings soos HDBSCAN sommige probleme (soos verskillende digtheid).

<details>
<summary>Voorbeeld -- Groepering met Ruis
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
In hierdie snit het ons `eps` en `min_samples` aangepas om by ons dataskaal te pas (15.0 in kenmerk eenhede, en vereis 5 punte om 'n kluster te vorm). DBSCAN behoort 2 klusters te vind (die normale verkeer klusters) en die 5 ingespuite uitskieters as geraas te merk. Ons voer die aantal klusters teenoor geraaspunte uit om dit te verifieer. In 'n werklike omgewing kan 'n mens oor ε iterasie doen (met 'n k-afstand grafiek heuristiek om ε te kies) en MinPts (dikwels rondom die datadimensie + 1 as 'n reël van duim) om stabiele klusteringresultate te vind. Die vermoë om geraas eksplisiet te merk help om potensiële aanvaldata vir verdere analise te skei.

</details>

### Hoofkomponentanalise (PCA)

PCA is 'n tegniek vir **dimensionaliteitsvermindering** wat 'n nuwe stel ortogonale as (hoofkomponente) vind wat die maksimum variansie in die data vasvang. In eenvoudige terme draai PCA die data en projekteer dit op 'n nuwe koördinaatstelsel sodat die eerste hoofkomponent (PC1) die grootste moontlike variansie verduidelik, die tweede PC (PC2) die grootste variansie ortogonaal tot PC1 verduidelik, en so aan. Wiskundig bereken PCA die eie vektore van die data se kovariansiematrix – hierdie eie vektore is die richtings van die hoofkomponente, en die ooreenstemmende eie waardes dui die hoeveelheid variansie aan wat deur elkeen verduidelik word. Dit word dikwels gebruik vir kenmerk ekstraksie, visualisering, en geraasvermindering.

Let daarop dat dit nuttig is as die dataset dimensies **beduidende lineêre afhanklikhede of korrelasies** bevat.

PCA werk deur die hoofkomponente van die data te identifiseer, wat die richtings van maksimum variansie is. Die stappe wat betrokke is by PCA is:
1. **Standaardisering**: Sentraal die data deur die gemiddelde af te trek en dit na eenheidsvariansie te skaal.
2. **Kovariansiematrix**: Bereken die kovariansiematrix van die gestandaardiseerde data om die verhoudings tussen kenmerke te verstaan.
3. **Eie waarde ontbinding**: Voer eie waarde ontbinding op die kovariansiematrix uit om die eie waardes en eie vektore te verkry.
4. **Kies Hoofkomponente**: Sorteer die eie waardes in aflopende volgorde en kies die top K eie vektore wat ooreenstem met die grootste eie waardes. Hierdie eie vektore vorm die nuwe kenmerkruimte.
5. **Transformeer Data**: Projekteer die oorspronklike data op die nuwe kenmerkruimte met behulp van die geselekteerde hoofkomponente.
PCA word wyd gebruik vir data visualisering, geraasvermindering, en as 'n voorverwerkings stap vir ander masjienleer algoritmes. Dit help om die dimensionaliteit van die data te verminder terwyl dit sy essensiële struktuur behou.

#### Eie waardes en Eie vektore

'n Eie waarde is 'n skaal wat die hoeveelheid variansie aandui wat deur sy ooreenstemmende eie vektor vasgevang word. 'n Eie vektor verteenwoordig 'n rigting in die kenmerkruimte waarlangs die data die meeste varieer.

Stel jou voor A is 'n vierkantige matriks, en v is 'n nie-nul vektor sodat: `A * v = λ * v`
waar:
- A is 'n vierkantige matriks soos [ [1, 2], [2, 1]] (bv. kovariansiematrix)
- v is 'n eie vektor (bv. [1, 1])

Dan, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` wat die eie waarde λ vermenigvuldig met die eie vektor v sal wees, wat die eie waarde λ = 3 maak.

#### Eie waardes en Eie vektore in PCA

Kom ons verduidelik dit met 'n voorbeeld. Stel jou voor jy het 'n dataset met baie grys skaal prente van gesigte van 100x100 pixels. Elke pixel kan as 'n kenmerk beskou word, so jy het 10,000 kenmerke per beeld (of 'n vektor van 10000 komponente per beeld). As jy die dimensionaliteit van hierdie dataset met PCA wil verminder, sal jy hierdie stappe volg:

1. **Standaardisering**: Sentraal die data deur die gemiddelde van elke kenmerk (pixel) van die dataset af te trek.
2. **Kovariansiematrix**: Bereken die kovariansiematrix van die gestandaardiseerde data, wat vasvang hoe kenmerke (pixels) saam varieer.
- Let daarop dat die kovariansie tussen twee veranderlikes (pixels in hierdie geval) aandui hoe baie hulle saam verander, so die idee hier is om uit te vind watter pixels geneig is om saam te verhoog of te verlaag met 'n lineêre verhouding.
- Byvoorbeeld, as pixel 1 en pixel 2 geneig is om saam te verhoog, sal die kovariansie tussen hulle positief wees.
- Die kovariansiematrix sal 'n 10,000x10,000 matriks wees waar elke inskrywing die kovariansie tussen twee pixels verteenwoordig.
3. **Los die eie waarde vergelyking op**: Die eie waarde vergelyking om op te los is `C * v = λ * v` waar C die kovariansiematrix is, v die eie vektor is, en λ die eie waarde is. Dit kan opgelos word met metodes soos:
- **Eie waarde ontbinding**: Voer eie waarde ontbinding op die kovariansiematrix uit om die eie waardes en eie vektore te verkry.
- **Singuliere Waarde Ontbinding (SVD)**: Alternatiewelik kan jy SVD gebruik om die datamatris in singuliere waardes en vektore te ontbind, wat ook die hoofkomponente kan oplewer.
4. **Kies Hoofkomponente**: Sorteer die eie waardes in aflopende volgorde en kies die top K eie vektore wat ooreenstem met die grootste eie waardes. Hierdie eie vektore verteenwoordig die richtings van maksimum variansie in die data.

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* 'n Algemene gebruik van PCA in sekuriteit is kenmerkvermindering vir anomaliedetektering. Byvoorbeeld, 'n indringingdeteksiesisteem met 40+ netwerkmetrieke (soos NSL-KDD kenmerke) kan PCA gebruik om tot 'n handjievol komponente te verminder, wat die data opsom vir visualisering of om in klustering algoritmes te voer. Analiste kan netwerkverkeer in die ruimte van die eerste twee hoofkomponente plot om te sien of aanvalle van normale verkeer skei. PCA kan ook help om oorvloedige kenmerke te elimineer (soos bytes gestuur teenoor bytes ontvang as hulle korreleer) om deteksie algoritmes meer robuust en vinniger te maak.

#### Aannames en Beperkings

PCA neem aan dat **hoofasse van variansie betekenisvol is** – dit is 'n lineêre metode, so dit vang lineêre korrelasies in data vas. Dit is nie-beheerde leer aangesien dit slegs die kenmerk kovariansie gebruik. Voordele van PCA sluit geraasvermindering in (klein-variansie komponente stem dikwels ooreen met geraas) en dekorelasi van kenmerke. Dit is berekeningsmatig doeltreffend vir matig hoë dimensies en dikwels 'n nuttige voorverwerkings stap vir ander algoritmes (om die vloek van dimensionaliteit te verminder). Een beperking is dat PCA beperk is tot lineêre verhoudings – dit sal nie komplekse nie-lineêre struktuur vasvang nie (terwyl outokoders of t-SNE dit mag). Ook kan PCA komponente moeilik wees om te interpreteer in terme van oorspronklike kenmerke (dit is kombinasies van oorspronklike kenmerke). In kuberveiligheid moet 'n mens versigtig wees: 'n aanval wat net 'n subtiele verandering in 'n lae-variansie kenmerk veroorsaak, mag nie in die top PC's verskyn nie (aangesien PCA variansie prioritiseer, nie noodwendig "interessantheid" nie).

<details>
<summary>Voorbeeld -- Vermindering van Dimensies van Netwerkdata
</summary>

Stel ons het netwerkverbinding logs met verskeie kenmerke (bv. duur, bytes, tellings). Ons sal 'n sintetiese 4-dimensionele dataset genereer (met 'n paar korrelasie tussen kenmerke) en PCA gebruik om dit tot 2 dimensies te verminder vir visualisering of verdere analise.
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
Hier het ons die vroeëre normale verkeersklusters geneem en elke datapunt uitgebrei met twee bykomende kenmerke (pakkette en foute) wat met bytes en duur korreleer. PCA word dan gebruik om die 4 kenmerke in 2 hoofkomponente te komprimeer. Ons druk die verduidelikte variantieverhouding, wat mag wys dat, sê, >95% van die variasie deur 2 komponente vasgevang word (wat min inligtingverlies beteken). Die uitvoer toon ook dat die datavorm verminder van (1500, 4) na (1500, 2). Die eerste paar punte in die PCA-ruimte word as 'n voorbeeld gegee. In praktyk kan 'n mens data_2d plot om visueel te kontroleer of die klusters onderskeibaar is. As 'n anomalie teenwoordig was, kan 'n mens dit sien as 'n punt wat weg van die hoofkluster in PCA-ruimte lê. PCA help dus om komplekse data in 'n hanteerbare vorm vir menslike interpretasie of as inset vir ander algoritmes te distilleer.

</details>


### Gaussian Mixture Models (GMM)

'n Gaussian Mixture Model neem aan dat data gegenereer word uit 'n mengsel van **verskeie Gaussian (normale) verspreidings met onbekende parameters**. In wese is dit 'n probabilistiese klusteringmodel: dit probeer om elke punt sagkens aan een van K Gaussian komponente toe te ken. Elke Gaussian komponent k het 'n gemiddelde vektor (μ_k), kovariansiematrix (Σ_k), en 'n menggewig (π_k) wat verteenwoordig hoe algemeen daardie kluster is. Anders as K-Means wat "harde" toewysings doen, gee GMM elke punt 'n waarskynlikheid om tot elke kluster te behoort.

GMM-aanpassing word tipies gedoen via die Verwachting-Maximisering (EM) algoritme:

- **Inisialisering**: Begin met aanvanklike raaiskote vir die gemiddeldes, kovariansies, en mengkoëffisiënte (of gebruik K-Means resultate as 'n beginpunt).

- **E-stap (Verwachting)**: Gegewe huidige parameters, bereken die verantwoordelikheid van elke kluster vir elke punt: essensieel `r_nk = P(z_k | x_n)` waar z_k die latente veranderlike is wat klusterlidmaatskap vir punt x_n aandui. Dit word gedoen met behulp van Bayes se stelling, waar ons die posterior waarskynlikheid van elke punt wat tot elke kluster behoort, gebaseer op die huidige parameters, bereken. Die verantwoordelikhede word bereken as:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
waar:
- \( \pi_k \) is die mengkoëffisiënt vir kluster k (vooraf waarskynlikheid van kluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) is die Gaussian waarskynlikheiddigtheidsfunksie vir punt \( x_n \) gegewe gemiddelde \( \mu_k \) en kovariansie \( \Sigma_k \).

- **M-stap (Maximisering)**: Werk die parameters op met behulp van die verantwoordelikhede wat in die E-stap bereken is:
- Werk elke gemiddelde μ_k op as die gewogen gemiddelde van punte, waar gewigte die verantwoordelikhede is.
- Werk elke kovariansie Σ_k op as die gewogen kovariansie van punte wat aan kluster k toegeken is.
- Werk mengkoëffisiënte π_k op as die gemiddelde verantwoordelikheid vir kluster k.

- **Herhaal** E- en M-stappe totdat konvergensie plaasvind (parameters stabiliseer of waarskynlikheidsverbetering onder 'n drempel is).

Die resultaat is 'n stel Gaussian verspreidings wat saam die algehele dataverspreiding modelleer. Ons kan die aangepaste GMM gebruik om te kluster deur elke punt aan die Gaussian met die hoogste waarskynlikheid toe te ken, of die waarskynlikhede vir onsekerheid te behou. 'n Mens kan ook die waarskynlikheid van nuwe punte evalueer om te sien of hulle by die model pas (nuttig vir anomaliedetektering).

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* GMM kan gebruik word vir anomaliedetektering deur die verspreiding van normale data te modelleer: enige punt met 'n baie lae waarskynlikheid onder die geleerde mengsel word as anomalie gemerk. Byvoorbeeld, jy kan 'n GMM op wettige netwerkverkeerskenmerke oplei; 'n aanvalskonneksie wat nie enige geleerde kluster herinner nie, sou 'n lae waarskynlikheid hê. GMM's word ook gebruik om aktiwiteite te kluster waar klusters verskillende vorms kan hê – byvoorbeeld, om gebruikers volgens gedragprofiele te groepeer, waar elke profiel se kenmerke dalk Gaussian-agtig is, maar met sy eie variantiestruktuur. 'n Ander scenario: in phishing-detektering kan wettige e-poskenmerke een Gaussian kluster vorm, bekende phishing 'n ander, en nuwe phishingveldtogte kan verskyn as 'n aparte Gaussian of as lae waarskynlikheid punte relatief tot die bestaande mengsel.

#### Aannames en Beperkings

GMM is 'n generalisering van K-Means wat kovariansie inkorporeer, sodat klusters ellipsoïdaal kan wees (nie net sferies nie). Dit hanteer klusters van verskillende groottes en vorms as die kovariansie vol is. Sagte klustering is 'n voordeel wanneer klustergrense vaag is – byvoorbeeld, in kuberveiligheid kan 'n gebeurtenis eienskappe van verskeie aanvalstipes hê; GMM kan daardie onsekerheid met waarskynlikhede weerspieël. GMM bied ook 'n probabilistiese digtheidskattings van die data, nuttig vir die opsporing van uitskieters (punte met lae waarskynlikheid onder al die mengkomponente).

Aan die ander kant vereis GMM die spesifisering van die aantal komponente K (alhoewel 'n mens kriteria soos BIC/AIC kan gebruik om dit te kies). EM kan soms stadig konvergeer of na 'n plaaslike optimum, so inisialisering is belangrik (dikwels EM verskeie kere gedoen). As die data nie werklik 'n mengsel van Gaussians volg nie, kan die model 'n swak pas wees. Daar is ook 'n risiko dat een Gaussian krimp om net 'n uitskieter te dek (alhoewel regularisering of minimum kovariansie grense dit kan verminder).

<details>
<summary>Voorbeeld --  Sagte Klustering & Anomalie Punte
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
In hierdie kode, oplei ons 'n GMM met 3 Gaussiese op die normale verkeer (aannemende ons ken 3 profiele van wettige verkeer). Die gemiddeldes en kovariansies wat gedruk word, beskryf hierdie klusters (byvoorbeeld, een gemiddelde mag rondom [50,500] wees wat ooreenstem met een kluster se sentrum, ens.). Ons toets dan 'n verdagte verbinding [duur=200, bytes=800]. Die predict_proba gee die waarskynlikheid dat hierdie punt aan elkeen van die 3 klusters behoort – ons sou verwag dat hierdie waarskynlikhede baie laag of hoogskew sou wees aangesien [200,800] ver van die normale klusters lê. Die algehele score_samples (log-likelihood) word gedruk; 'n baie lae waarde dui aan dat die punt nie goed by die model pas nie, wat dit as 'n anomalie merk. In praktyk kan 'n mens 'n drempel op die log-likelihood (of op die maksimum waarskynlikheid) stel om te besluit of 'n punt voldoende onwaarskynlik is om as kwaadwillig beskou te word. GMM bied dus 'n prinsipiële manier om anomaliedetectie te doen en lewer ook sagte klusters wat onsekerheid erken.

### Isolation Forest

**Isolation Forest** is 'n ensemble anomaliedetectie-algoritme gebaseer op die idee om punte ewekansig te isoleer. Die beginsel is dat anomalieë min en anders is, so hulle is makliker om te isoleer as normale punte. 'n Isolation Forest bou baie binêre isolasiebome (ewekansige besluitbome) wat die data ewekansig partitioneer. By elke knoop in 'n boom, word 'n ewekansige kenmerk gekies en 'n ewekansige splitsingswaarde tussen die minimum en maksimum van daardie kenmerk vir die data in daardie knoop gekies. Hierdie splitsing verdeel die data in twee takke. Die boom word gegroei totdat elke punt in sy eie bladsy geisoleer is of 'n maksimum boomhoogte bereik is.

Anomaliedetectie word uitgevoer deur die padlengte van elke punt in hierdie ewekansige bome te observeer – die aantal splitsings wat benodig word om die punt te isoleer. Intuïtief, anomalieë (uitvallers) geneig om vinniger geisoleer te word omdat 'n ewekansige splitsing meer waarskynlik is om 'n uitvaller te skei (wat in 'n spars gebied lê) as wat dit 'n normale punt in 'n digte kluster sou doen. Die Isolation Forest bereken 'n anomalie telling vanaf die gemiddelde padlengte oor alle bome: korter gemiddelde pad → meer anomalies. Tellings word gewoonlik genormaliseer tot [0,1] waar 1 baie waarskynlik anomalie beteken.

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* Isolation Forests is suksesvol gebruik in indringingdetectie en bedrogdetectie. Byvoorbeeld, oplei 'n Isolation Forest op netwerkverkeer logs wat meestal normale gedrag bevat; die woud sal kort paaie vir vreemde verkeer produseer (soos 'n IP wat 'n onbekende poort gebruik of 'n ongewone pakketgrootte patroon), wat dit vir inspeksie merk. Omdat dit nie gelabelde aanvalle vereis nie, is dit geskik om onbekende aanvalstipes te detecteer. Dit kan ook op gebruikersaanmelddata ontplooi word om rekeningoorname te detecteer (die anomaliese aanmeldtye of plekke word vinnig geisoleer). In een gebruiksgeval kan 'n Isolation Forest 'n onderneming beskerm deur stelselsmetrieke te monitor en 'n waarskuwing te genereer wanneer 'n kombinasie van metrieke (CPU, netwerk, lêer veranderinge) baie anders lyk (korte isolasiepaaie) van historiese patrone.

#### Aannames en Beperkings

**Voordele**: Isolation Forest vereis nie 'n verspreidingsaannames nie; dit teiken direk isolasie. Dit is doeltreffend op hoë-dimensionele data en groot datastelle (lineêre kompleksiteit $O(n\log n)$ vir die bou van die woud) aangesien elke boom punte met slegs 'n subset van kenmerke en splitsings isoleer. Dit hanteer geneig numeriese kenmerke goed en kan vinniger wees as afstand-gebaseerde metodes wat $O(n^2)$ mag wees. Dit gee ook outomaties 'n anomalie telling, sodat jy 'n drempel vir waarskuwings kan stel (of 'n kontaminasieparameter kan gebruik om outomaties 'n afsnit te besluit gebaseer op 'n verwagte anomaliefraksie).

**Beperkings**: Vanweë sy ewekansige aard, kan resultate effens verskil tussen lopies (alhoewel dit met voldoende bome gering is). As die data baie irrelevante kenmerke het of as anomalieë nie sterk in enige kenmerk onderskei nie, mag die isolasie nie effektief wees nie (ewkansige splitsings kan normale punte per toeval isoleer – egter, die gemiddelde van baie bome verlig dit). Ook, Isolation Forest neem oor die algemeen aan dat anomalieë 'n klein minderheid is (wat gewoonlik waar is in kuberveiligheid scenario's).

<details>
<summary>Voorbeeld --  Detectie van Uitvallers in Netwerk Logs
</summary>

Ons sal die vroeëre toetsdatastel gebruik (wat normale en sommige aanvalspunte bevat) en 'n Isolation Forest uitvoer om te sien of dit die aanvalle kan skei. Ons sal aannem dat ons verwag ~15% van die data anomalies is (vir demonstrasie).
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
In hierdie kode, instantiate ons `IsolationForest` met 100 bome en stel `contamination=0.15` (wat beteken ons verwag ongeveer 15% anomalieë; die model sal sy tellingdrempel stel sodat ~15% van die punte geflag word). Ons pas dit toe op `X_test_if` wat 'n mengsel van normale en aanvalspunte bevat (let wel: normaalweg sou jy op opleidingsdata pas en dan voorspel op nuwe data, maar hier ter illustrasie pas ons toe en voorspel op dieselfde stel om die resultate direk waar te neem).

Die uitvoer toon die voorspelde etikette vir die eerste 20 punte (waar -1 anomalie aandui). Ons druk ook uit hoeveel anomalieë in totaal opgespoor is en 'n paar voorbeeld anomalie tellinge. Ons sou verwag dat ongeveer 18 uit 120 punte geëtiketteer word as -1 (aangesien kontaminasie 15% was). As ons 20 aanval monsters werklik die mees uitspringende is, behoort die meeste daarvan in daardie -1 voorspellings te verskyn. Die anomalie telling (Isolation Forest se besluit funksie) is hoër vir normale punte en laer (meer negatief) vir anomalieë – ons druk 'n paar waardes uit om die skeiding te sien. In praktyk kan 'n mens die data volgens telling sorteer om die top uitspringers te sien en hulle te ondersoek. Isolation Forest bied dus 'n doeltreffende manier om deur groot ongetekende sekuriteitsdata te sift en die mees onreëlmatige voorbeelde vir menslike analise of verdere geoutomatiseerde ondersoek uit te kies.

### t-SNE (t-Gedistribueerde Stogastiese Buren Inbed)

**t-SNE** is 'n nie-lineêre dimensie verminderings tegniek spesifiek ontwerp om hoë-dimensionele data in 2 of 3 dimensies te visualiseer. Dit omskep ooreenkomste tussen datapunte na gesamentlike waarskynlikheidsverdelings en probeer om die struktuur van plaaslike buurtes in die laer-dimensionele projek te behou. In eenvoudiger terme plaas t-SNE punte in (sê) 2D sodat soortgelyke punte (in die oorspronklike ruimte) naby mekaar eindig en onsimilar punte ver van mekaar met 'n hoë waarskynlikheid eindig.

Die algoritme het twee hoof fases:

1. **Bereken paargewys affiniteit in hoë-dimensionele ruimte:** Vir elke paar punte, bereken t-SNE 'n waarskynlikheid dat 'n mens daardie paar as bure sou kies (dit word gedoen deur 'n Gaussiese verdeling op elke punt te sentreer en afstande te meet – die perplexity parameter beïnvloed die effektiewe aantal bure wat oorweeg word).
2. **Bereken paargewys affiniteit in lae-dimensionele (bv. 2D) ruimte:** Aanvanklik word punte ewekansig in 2D geplaas. t-SNE definieer 'n soortgelyke waarskynlikheid vir afstande in hierdie kaart (met 'n Student t-verdeling kern, wat swaarder sterte het as Gaussies om veraf punte meer vryheid te gee).
3. **Gradiënt Afdaling:** t-SNE beweeg dan iteratief die punte in 2D om die Kullback–Leibler (KL) divergensie tussen die hoë-D affiniteit verdeling en die lae-D een te minimaliseer. Dit veroorsaak dat die 2D rangskikking die hoë-D struktuur soveel as moontlik weerspieël – punte wat naby was in die oorspronklike ruimte sal mekaar aantrek, en diegene wat ver van mekaar is sal afstoot, totdat 'n balans gevind word.

Die resultaat is dikwels 'n visueel betekenisvolle verspreidingsgrafiek waar klusters in die data duidelik word.

> [!TIP]
> *Gebruik gevalle in kuberveiligheid:* t-SNE word dikwels gebruik om **hoë-dimensionele sekuriteitsdata vir menslike analise te visualiseer**. Byvoorbeeld, in 'n sekuriteitsbedrywigheidsentrum kan analiste 'n gebeurtenisdatastel met dosyne kenmerke (poortnommers, frekwensies, byte tellings, ens.) neem en t-SNE gebruik om 'n 2D-grafiek te produseer. Aanvalle kan hul eie klusters vorm of van normale data in hierdie grafiek skei, wat dit makliker maak om te identifiseer. Dit is toegepas op malware datastelle om groepe van malware families te sien of op netwerk indringing data waar verskillende aanval tipe duidelik groepeer, wat verdere ondersoek lei. Essensieel bied t-SNE 'n manier om struktuur in kuberdata te sien wat andersins onduidelik sou wees.

#### Aannames en Beperkings

t-SNE is uitstekend vir visuele ontdekking van patrone. Dit kan klusters, subklusters, en uitspringers onthul wat ander lineêre metodes (soos PCA) dalk nie kan nie. Dit is gebruik in kuberveiligheid navorsing om komplekse data soos malware gedrag profiele of netwerkverkeer patrone te visualiseer. Omdat dit plaaslike struktuur behou, is dit goed om natuurlike groepe te toon.

Echter, t-SNE is rekenaarintensief (ongeveer $O(n^2)$) so dit mag steekproefneming vereis vir baie groot datastelle. Dit het ook hiperparameters (perplexity, leer tempo, iterasies) wat die uitvoer kan beïnvloed – bv., verskillende perplexity waardes kan klusters op verskillende skale onthul. t-SNE grafieke kan soms verkeerd geïnterpreteer word – afstande in die kaart is nie direk betekenisvol globaal nie (dit fokus op plaaslike buurtes, soms kan klusters kunsmatig goed geskei voorkom). Ook, t-SNE is hoofsaaklik vir visualisering; dit bied nie 'n regstreekse manier om nuwe datapunte te projekteer sonder om weer te bereken nie, en dit is nie bedoel om as 'n voorverwerking vir voorspellende modellering gebruik te word nie (UMAP is 'n alternatief wat sommige van hierdie probleme met vinniger spoed aanspreek).

<details>
<summary>Voorbeeld -- Visualisering van Netwerkverbindinge
</summary>

Ons sal t-SNE gebruik om 'n multi-kenmerk datastel na 2D te verminder. Ter illustrasie, kom ons neem die vroeëre 4D data (wat 3 natuurlike klusters van normale verkeer gehad het) en voeg 'n paar anomalie punte by. Ons voer dan t-SNE uit en (konseptueel) visualiseer die resultate.
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
Hier het ons ons vorige 4D normale dataset gekombineer met 'n handvol ekstreme uitskieters (die uitskieters het een kenmerk (“duur”) baie hoog gestel, ens., om 'n vreemde patroon na te boots). Ons loop t-SNE met 'n tipiese perplexity van 30. Die uitvoer data_2d het 'n vorm van (1505, 2). Ons sal eintlik nie in hierdie teks plot nie, maar as ons dit sou doen, sou ons verwag om dalk drie stywe klusters te sien wat ooreenstem met die 3 normale klusters, en die 5 uitskieters wat as geïsoleerde punte ver van daardie klusters verskyn. In 'n interaktiewe werksvloei, kan ons die punte kleur volgens hul etiket (normaal of watter kluster, teenoor anomalie) om hierdie struktuur te verifieer. Selfs sonder etikette, mag 'n ontleder daardie 5 punte in leë ruimte op die 2D plot opgemerk het en dit merk. Dit toon hoe t-SNE 'n kragtige hulp kan wees vir visuele anomaliedetektering en klusterinspeksie in kuberveiligheidsdata, wat die geoutomatiseerde algoritmes hierbo aanvul.

</details>


{{#include ../banners/hacktricks-training.md}}
