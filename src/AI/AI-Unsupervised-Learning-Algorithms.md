# Algoritmi nenadgledanog učenja

{{#include ../banners/hacktricks-training.md}}

## Nenadgledano učenje

Nenadgledano učenje je vrsta mašinskog učenja u kojoj se model trenira na podacima bez označenih odgovora. Cilj je pronalaženje obrazaca, struktura ili odnosa unutar podataka. Za razliku od nadgledanog učenja, gde model uči na osnovu označenih primera, algoritmi nenadgledanog učenja rade sa neoznačenim podacima.
Nenadgledano učenje se često koristi za zadatke kao što su grupisanje, smanjenje dimenzionalnosti i detekcija anomalija. Može pomoći u otkrivanju skrivenih obrazaca u podacima, grupisanju sličnih stavki ili smanjenju složenosti podataka uz očuvanje njihovih ključnih karakteristika.


### K-Means grupisanje

K-Means je algoritam za grupisanje zasnovan na centroidima koji deli podatke u K grupa tako što svaku tačku dodeljuje najbližoj srednjoj vrednosti grupe. Algoritam funkcioniše na sledeći način:
1. **Inicijalizacija**: Izaberite K početnih centara grupa (centroida), često nasumično ili pomoću naprednijih metoda kao što je k-means++
2. **Dodeljivanje**: Dodelite svaku tačku podataka najbližem centroidu na osnovu metrike udaljenosti (npr. Euklidske udaljenosti).
3. **Ažuriranje**: Ponovo izračunajte centroide tako što ćete izračunati srednju vrednost svih tačaka podataka dodeljenih svakoj grupi.
4. **Ponavljanje**: Koraci 2–3 se ponavljaju dok se dodeljivanje grupa ne stabilizuje (centroidi se više značajno ne pomeraju).

> [!TIP]
> *Slučajevi upotrebe u cybersecurity-u:* K-Means se koristi za detekciju upada grupisanjem mrežnih događaja. Na primer, istraživači su primenili K-Means na skup podataka za detekciju upada KDD Cup 99 i ustanovili da efikasno deli saobraćaj na grupe normalnog saobraćaja i napada. U praksi, security analitičari mogu grupisati unose u logovima ili podatke o ponašanju korisnika kako bi pronašli grupe sličnih aktivnosti; tačke koje ne pripadaju dobro formiranoj grupi mogu ukazivati na anomalije (npr. nova varijanta malware-a koja formira sopstvenu malu grupu). K-Means takođe može pomoći u klasifikaciji malware familija grupisanjem binarnih datoteka na osnovu profila ponašanja ili vektora karakteristika.

#### Izbor vrednosti K
Broj grupa (K) je hiperparametar koji treba definisati pre pokretanja algoritma. Tehnike kao što su Elbow Method ili Silhouette Score mogu pomoći u određivanju odgovarajuće vrednosti za K procenom uspešnosti grupisanja:

- **Elbow Method**: Nacrtajte zbir kvadrata udaljenosti od svake tačke do dodeljenog centroida grupe u funkciji vrednosti K. Potražite tačku „lakta“, gde se stopa smanjenja naglo menja, što ukazuje na odgovarajući broj grupa.
- **Silhouette Score**: Izračunajte silhouette score za različite vrednosti K. Viši silhouette score ukazuje na bolje definisane grupe.

#### Pretpostavke i ograničenja

K-Means pretpostavlja da su **grupe sferične i jednake veličine**, što ne mora važiti za sve skupove podataka. Osetljiv je na početni položaj centroida i može konvergirati ka lokalnim minimumima. Pored toga, K-Means nije pogodan za skupove podataka sa promenljivim gustinama ili neglobularnim oblicima, kao ni za karakteristike različitih razmera. Koraci pretprocesiranja, kao što su normalizacija ili standardizacija, mogu biti neophodni kako bi sve karakteristike jednako doprinosile izračunavanju udaljenosti.

<details>
<summary>Primer -- Grupisanje mrežnih događaja
</summary>
U nastavku simuliramo podatke o mrežnom saobraćaju i koristimo K-Means za njihovo grupisanje. Pretpostavimo da imamo događaje sa karakteristikama kao što su trajanje konekcije i broj bajtova. Kreiramo 3 grupe „normalnog“ saobraćaja i 1 malu grupu koja predstavlja obrazac napada. Zatim pokrećemo K-Means da proverimo da li će ih razdvojiti.
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
U ovom primeru, K-Means bi trebalo da pronađe 4 klastera. Mali attack klaster (sa neuobičajeno velikim trajanjem ~200) idealno će formirati sopstveni klaster zbog svoje udaljenosti od normalnih klastera. Ispisujemo veličine i centre klastera kako bismo protumačili rezultate. U stvarnom scenariju, klaster sa malo tačaka mogao bi se označiti kao potencijalne anomalije ili bi se njegovi članovi mogli pregledati radi otkrivanja zlonamerne aktivnosti.
</details>

### Hijerarhijsko klasterovanje

Hijerarhijsko klasterovanje gradi hijerarhiju klastera koristeći pristup odozdo-nagore (agglomerative) ili odozgo-nadole (divisive):

1. **Agglomerative (odozdo-nagore)**: Počinje tako što je svaka tačka podataka zaseban klaster i iterativno spaja najbliže klastere dok ne ostane jedan klaster ili dok se ne ispuni kriterijum zaustavljanja.
2. **Divisive (odozgo-nadole)**: Počinje tako što su sve tačke podataka u jednom klasteru i iterativno deli klastere dok svaka tačka podataka ne postane sopstveni klaster ili dok se ne ispuni kriterijum zaustavljanja.

Agglomerative klasterovanje zahteva definiciju udaljenosti između klastera i kriterijum povezivanja kojim se odlučuje koje klastere treba spojiti. Uobičajene metode povezivanja uključuju single linkage (udaljenost najbližih tačaka između dva klastera), complete linkage (udaljenost najudaljenijih tačaka), average linkage itd., dok je metrika udaljenosti često Euklidska. Izbor povezivanja utiče na oblik proizvedenih klastera. Nije potrebno unapred navesti broj klastera K; dendrogram možete „preseći“ na izabranom nivou da biste dobili željeni broj klastera.

Hijerarhijsko klasterovanje proizvodi dendrogram, strukturu nalik stablu koja prikazuje odnose između klastera na različitim nivoima granularnosti. Dendrogram se može preseći na željenom nivou kako bi se dobio određeni broj klastera.

> [!TIP]
> *Primene u cybersecurity-u:* Hijerarhijsko klasterovanje može organizovati događaje ili entitete u stablo kako bi se uočili odnosi. Na primer, u analizi malware-a, agglomerative klasterovanje može grupisati uzorke prema sličnosti ponašanja, otkrivajući hijerarhiju malware porodica i varijanti. U network security-ju, saobraćajni tokovi IP adresa mogu se grupisati, a dendrogram koristiti za uočavanje podgrupa saobraćaja (npr. prema protokolu, a zatim prema ponašanju). Pošto nije potrebno unapred izabrati K, ovo je korisno pri istraživanju novih podataka kod kojih je broj kategorija napada nepoznat.

#### Pretpostavke i ograničenja

Hijerarhijsko klasterovanje ne pretpostavlja određeni oblik klastera i može obuhvatiti ugnježdene klastere. Korisno je za otkrivanje taksonomije ili odnosa između grupa (npr. grupisanje malware-a prema podgrupama porodica). Determinističko je (nema problema sa slučajnom inicijalizacijom). Ključna prednost je dendrogram, koji pruža uvid u strukturu klasterovanja podataka na svim nivoima – security analitičari mogu odrediti odgovarajući prag kako bi identifikovali smislene klastere. Međutim, računski je zahtevno (obično $O(n^2)$ vremena ili više za naivne implementacije) i nije praktično za veoma velike skupove podataka. Takođe je greedy procedura – kada se spajanje ili deljenje izvrši, ne može se poništiti, što može dovesti do suboptimalnih klastera ako se greška dogodi u ranoj fazi. Outlieri takođe mogu uticati na neke strategije povezivanja (single-link može izazvati efekat „lančanja“, pri kojem se klasteri povezuju preko outliera).

<details>
<summary>Primer -- Agglomerative klasterovanja događaja
</summary>

Ponovo ćemo koristiti sintetičke podatke iz primera sa K-Means-om (3 normalna klastera + 1 attack klaster) i primeniti agglomerative klasterovanje. Zatim ćemo prikazati kako dobiti dendrogram i oznake klastera.
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

DBSCAN je algoritam za klasterovanje zasnovan na gustini koji grupiše tačke koje su međusobno blisko raspoređene, dok tačke u regionima male gustine označava kao outliers. Posebno je koristan za skupove podataka sa različitim gustinama i nesferičnim oblicima.

DBSCAN radi definisanjem dva parametra:
- **Epsilon (ε)**: Maksimalno rastojanje između dve tačke da bi se smatrale delom istog klastera.
- **MinPts**: Minimalan broj tačaka potreban za formiranje gustog regiona (core point).

DBSCAN identifikuje core points, border points i noise points:
- **Core Point**: Tačka koja ima najmanje MinPts suseda unutar rastojanja ε.
- **Border Point**: Tačka koja se nalazi unutar rastojanja ε od core point-a, ali ima manje od MinPts suseda.
- **Noise Point**: Tačka koja nije ni core point ni border point.

Klasterovanje počinje izborom neposjećene core point tačke, njenim označavanjem kao novog klastera, a zatim se rekurzivno dodaju sve tačke koje su iz nje dostupne na osnovu gustine (core points i njihovi susedi itd.). Border points se dodaju klasteru obližnje core point tačke. Nakon proširivanja na sve dostupne tačke, DBSCAN prelazi na drugu neposjećenu core point tačku da bi započeo novi klaster. Tačke do kojih nijedna core point tačka nije došla ostaju označene kao noise.

> [!TIP]
> *Primene u cybersecurity:* DBSCAN je koristan za detekciju anomalija u mrežnom saobraćaju. Na primer, normalna aktivnost korisnika može formirati jedan ili više gustih klastera u prostoru karakteristika, dok se nova ponašanja napada pojavljuju kao rasute tačke koje će DBSCAN označiti kao noise (outliers). Koristi se za klasterovanje zapisa o mrežnim tokovima, gde može detektovati port scans ili denial-of-service saobraćaj kao retke regione tačaka. Druga primena je grupisanje malware varijanti: ako se većina uzoraka grupiše po familijama, ali se nekoliko njih ne uklapa nigde, ti uzorci bi mogli biti zero-day malware. Mogućnost označavanja noise tačaka omogućava security timovima da se usredsrede na istraživanje tih outliers.

#### Pretpostavke i ograničenja

**Pretpostavke i prednosti:**: DBSCAN ne pretpostavlja sferne klastere – može pronaći klastere proizvoljnih oblika (čak i klastere u obliku lanaca ili susedne klastere). Automatski određuje broj klastera na osnovu gustine podataka i može efikasno identifikovati outliers kao noise. Zbog toga je moćan za realne podatke sa nepravilnim oblicima i noise tačkama. Otporan je na outliers (za razliku od K-Means, koji ih primorava da budu deo klastera). Dobro funkcioniše kada klasteri imaju približno ujednačenu gustinu.

**Ograničenja**: Performanse DBSCAN-a zavise od izbora odgovarajućih vrednosti ε i MinPts. Može imati poteškoća sa podacima koji imaju različite gustine – jedna vrednost ε ne može istovremeno obuhvatiti guste i retke klastere. Ako je ε premalo, većinu tačaka označava kao noise; ako je preveliko, klasteri se mogu neispravno spojiti. Takođe, DBSCAN može biti neefikasan na veoma velikim skupovima podataka (naivan pristup ima složenost $O(n^2)$, mada prostorno indeksiranje može pomoći). U visokodimenzionalnim prostorima karakteristika koncept „rastojanja unutar ε“ može postati manje smislen (prokletstvo dimenzionalnosti), pa DBSCAN može zahtevati pažljivo podešavanje parametara ili ne uspeti da pronađe intuitivne klastere. Uprkos tome, ekstenzije kao što je HDBSCAN rešavaju neke od ovih problema (kao što je promenljiva gustina).

<details>
<summary>Primer -- Klasterovanje sa šumom
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
U ovom isečku, podesili smo `eps` i `min_samples` tako da odgovaraju skali naših podataka (15.0 u jedinicama karakteristika i zahtev da 5 tačaka formira klaster). DBSCAN bi trebalo da pronađe 2 klastera (klastere normalnog saobraćaja) i označi 5 ubačenih outlier-a kao šum. Ispisujemo broj klastera naspram broja tačaka šuma kako bismo to proverili. U realnom okruženju, mogle bi se iterativno isprobavati vrednosti za ε (korišćenjem heuristike k-distance grafa za izbor vrednosti ε) i MinPts (često se okvirno postavlja na dimenzionalnost podataka + 1) kako bi se pronašli stabilni rezultati klasterovanja. Mogućnost eksplicitnog označavanja šuma pomaže u odvajanju potencijalnih attack podataka radi dalje analize.

</details>

### Principal Component Analysis (PCA)

PCA je tehnika za **smanjenje dimenzionalnosti** koja pronalazi novi skup ortogonalnih osa (glavne komponente) koje obuhvataju maksimalnu varijansu u podacima. Jednostavno rečeno, PCA rotira i projektuje podatke na novi koordinatni sistem tako da prva glavna komponenta (PC1) objašnjava najveću moguću varijansu, druga glavna komponenta (PC2) objašnjava najveću varijansu ortogonalnu na PC1, i tako dalje. Matematički, PCA izračunava svojstvene vektore kovarijacione matrice podataka - ti svojstveni vektori predstavljaju pravce glavnih komponenti, a odgovarajuće svojstvene vrednosti ukazuju na količinu objašnjene varijanse. Često se koristi za izdvajanje karakteristika, vizuelizaciju i smanjenje šuma.

Imajte na umu da je ovo korisno ako dimenzije skupa podataka sadrže **značajne linearne zavisnosti ili korelacije**.

PCA funkcioniše tako što identifikuje glavne komponente podataka, odnosno pravce maksimalne varijanse. Koraci u PCA su:
1. **Standardizacija**: Centrirajte podatke oduzimanjem srednje vrednosti i skaliranjem na jediničnu varijansu.
2. **Kovarijaciona matrica**: Izračunajte kovarijacionu matricu standardizovanih podataka da biste razumeli odnose između karakteristika.
3. **Dekompozicija svojstvenih vrednosti**: Izvršite dekompoziciju svojstvenih vrednosti kovarijacione matrice da biste dobili svojstvene vrednosti i svojstvene vektore.
4. **Izbor glavnih komponenti**: Sortirajte svojstvene vrednosti u opadajućem redosledu i izaberite prvih K svojstvenih vektora koji odgovaraju najvećim svojstvenim vrednostima. Ovi svojstveni vektori formiraju novi prostor karakteristika.
5. **Transformacija podataka**: Projektujte originalne podatke na novi prostor karakteristika koristeći izabrane glavne komponente.
PCA se široko koristi za vizuelizaciju podataka, smanjenje šuma i kao korak pretprocesiranja za druge algoritme mašinskog učenja. Pomaže u smanjenju dimenzionalnosti podataka uz očuvanje njihove suštinske strukture.

#### Svojstvene vrednosti i svojstveni vektori

Svojstvena vrednost je skalar koji ukazuje na količinu varijanse obuhvaćene odgovarajućim svojstvenim vektorom. Svojstveni vektor predstavlja pravac u prostoru karakteristika duž kojeg podaci najviše variraju.

Zamislite da je A kvadratna matrica, a v vektor različit od nule, tako da važi: `A * v = λ * v`
gde je:
- A kvadratna matrica kao što je [ [1, 2], [2, 1]] (npr. kovarijaciona matrica)
- v svojstveni vektor (npr. [1, 1])

Tada je `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, što će biti svojstvena vrednost λ pomnožena svojstvenim vektorom v, čime se dobija svojstvena vrednost λ = 3.

#### Svojstvene vrednosti i svojstveni vektori u PCA

Objasnimo ovo na primeru. Zamislite da imate skup podataka sa velikim brojem sivih slika lica rezolucije 100x100 piksela. Svaki piksel može da se posmatra kao karakteristika, tako da imate 10.000 karakteristika po slici (odnosno vektor sa 10000 komponenti po slici). Ako želite da smanjite dimenzionalnost ovog skupa podataka koristeći PCA, pratili biste sledeće korake:

1. **Standardizacija**: Centrirajte podatke oduzimanjem srednje vrednosti svake karakteristike (piksela) od skupa podataka.
2. **Kovarijaciona matrica**: Izračunajte kovarijacionu matricu standardizovanih podataka, koja obuhvata način na koji karakteristike (pikseli) variraju zajedno.
- Imajte na umu da kovarijacija između dve promenljive (u ovom slučaju piksela) ukazuje na to koliko se one menjaju zajedno, pa je cilj ovde utvrditi koji pikseli imaju tendenciju da se povećavaju ili smanjuju zajedno u okviru linearne veze.
- Na primer, ako piksel 1 i piksel 2 imaju tendenciju da se povećavaju zajedno, kovarijacija između njih biće pozitivna.
- Kovarijaciona matrica biće matrica dimenzija 10,000x10,000, gde svaki element predstavlja kovarijaciju između dva piksela.
3. **Rešavanje jednačine svojstvenih vrednosti**: Jednačina svojstvenih vrednosti koju treba rešiti jeste `C * v = λ * v`, gde je C kovarijaciona matrica, v svojstveni vektor, a λ svojstvena vrednost. Može se rešiti metodama kao što su:
- **Dekompozicija svojstvenih vrednosti**: Izvršite dekompoziciju svojstvenih vrednosti kovarijacione matrice da biste dobili svojstvene vrednosti i svojstvene vektore.
- **Singular Value Decomposition (SVD)**: Alternativno, možete koristiti SVD za dekomponovanje matrice podataka na singularne vrednosti i vektore, čime se takođe mogu dobiti glavne komponente.
4. **Izbor glavnih komponenti**: Sortirajte svojstvene vrednosti u opadajućem redosledu i izaberite prvih K svojstvenih vektora koji odgovaraju najvećim svojstvenim vrednostima. Ovi svojstveni vektori predstavljaju pravce maksimalne varijanse u podacima.

> [!TIP]
> *Primene u cybersecurity-u:* Uobičajena upotreba PCA u bezbednosti jeste smanjenje broja karakteristika za anomaly detection. Na primer, intrusion detection system sa više od 40 mrežnih metrika (kao što su NSL-KDD karakteristike) može koristiti PCA za smanjenje na nekoliko komponenti, čime se podaci sažimaju radi vizuelizacije ili prosleđivanja algoritmima za klasterovanje. Analitičari mogu prikazati mrežni saobraćaj u prostoru prve dve glavne komponente kako bi utvrdili da li se attack-i odvajaju od normalnog saobraćaja. PCA takođe može pomoći u uklanjanju redundantnih karakteristika (kao što su poslati i primljeni bajtovi ako su korelisani), čime algoritmi za detekciju postaju robusniji i brži.

#### Pretpostavke i ograničenja

PCA pretpostavlja da su **glavne ose varijanse značajne** - to je linearna metoda, pa obuhvata linearne korelacije u podacima. Neusmerena je jer koristi samo kovarijaciju karakteristika. Prednosti PCA uključuju smanjenje šuma (komponente male varijanse često odgovaraju šumu) i dekorelaciju karakteristika. Računarski je efikasna za umereno velike dimenzionalnosti i često predstavlja koristan korak pretprocesiranja za druge algoritme (radi ublažavanja curse of dimensionality). Jedno ograničenje jeste to što je PCA ograničen na linearne odnose - ne obuhvata složenu nelinearnu strukturu (za razliku od autoencoders ili t-SNE). Takođe, PCA komponente mogu biti teške za tumačenje u smislu originalnih karakteristika (one predstavljaju kombinacije originalnih karakteristika). U cybersecurity-u treba biti oprezan: attack koji izaziva samo suptilnu promenu karakteristike male varijanse možda se neće pojaviti u najvažnijim PC-ovima (jer PCA daje prioritet varijansi, a ne nužno „zanimljivosti“).

<details>
<summary>Primer -- Smanjenje dimenzionalnosti mrežnih podataka
</summary>

Pretpostavimo da imamo logove mrežnih konekcija sa više karakteristika (npr. trajanja, bajtove, brojače). Generisaćemo sintetički skup podataka sa 4 dimenzije (sa određenom korelacijom između karakteristika) i koristićemo PCA za njegovo smanjenje na 2 dimenzije radi vizuelizacije ili dalje analize.
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
Ovde smo uzeli ranije klastere normalnog saobraćaja i proširili svaku tačku podataka sa dve dodatne karakteristike (packets i errors) koje koreliraju sa bytes i duration. PCA se zatim koristi za kompresovanje 4 karakteristike u 2 glavne komponente. Ispisujemo odnos objašnjene varijanse, koji može pokazati da je, na primer, >95% varijanse obuhvaćeno sa 2 komponente (što znači mali gubitak informacija). Izlaz takođe prikazuje smanjenje oblika podataka sa (1500, 4) na (1500, 2). Prvih nekoliko tačaka u PCA prostoru dato je kao primer. U praksi, data_2d se može prikazati kako bi se vizuelno proverilo da li se klasteri mogu razlikovati. Ako je prisutna anomalija, mogla bi se uočiti kao tačka udaljena od glavnog klastera u PCA prostoru. PCA tako pomaže da se složeni podaci svedu na oblik kojim se može lakše upravljati, za ljudsko tumačenje ili kao ulaz za druge algoritme.

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Model pretpostavlja da se podaci generišu iz mešavine **nekoliko Gaussian (normalnih) distribucija sa nepoznatim parametrima**. U suštini, to je probabilistički model klasterovanja: pokušava da svaku tačku softverski dodeli jednoj od K Gaussian komponenti. Svaka Gaussian komponenta k ima vektorsku sredinu (μ_k), kovarijacionu matricu (Σ_k) i težinu mešanja (π_k), koja predstavlja zastupljenost tog klastera. Za razliku od K-Means-a, koji vrši „hard“ dodeljivanja, GMM svakoj tački daje verovatnoću pripadanja svakom klasteru.

GMM fitting se obično obavlja pomoću algoritma Expectation-Maximization (EM):

- **Initialization**: Početi sa početnim procenama sredina, kovarijacija i koeficijenata mešanja (ili koristiti rezultate K-Means-a kao početnu tačku).

- **E-step (Expectation)**: Na osnovu trenutnih parametara izračunati odgovornost svakog klastera za svaku tačku: u suštini `r_nk = P(z_k | x_n)`, gde je z_k latentna promenljiva koja označava pripadnost klasteru za tačku x_n. Ovo se radi pomoću Bayesove teoreme, pri čemu se računa posteriorna verovatnoća pripadanja svake tačke svakom klasteru na osnovu trenutnih parametara. Odgovornosti se računaju na sledeći način:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
gde:
- \( \pi_k \) predstavlja koeficijent mešanja za klaster k (prior verovatnoću klastera k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) predstavlja Gaussian funkciju gustine verovatnoće za tačku \( x_n \), sa sredinom \( \mu_k \) i kovarijacijom \( \Sigma_k \).

- **M-step (Maximization)**: Ažurirati parametre pomoću odgovornosti izračunatih u E-step-u:
- Ažurirati svaku sredinu μ_k kao ponderisani prosek tačaka, pri čemu su težine odgovornosti.
- Ažurirati svaku kovarijaciju Σ_k kao ponderisanu kovarijaciju tačaka dodeljenih klasteru k.
- Ažurirati koeficijente mešanja π_k kao prosečnu odgovornost za klaster k.

- **Iterate** E i M korake dok se ne postigne konvergencija (parametri se stabilizuju ili je poboljšanje verovatnoće manje od praga).

Rezultat je skup Gaussian distribucija koje zajedno modeluju ukupnu distribuciju podataka. Fitted GMM možemo koristiti za klasterovanje tako što svaku tačku dodeljujemo Gaussian distribuciji sa najvećom verovatnoćom, ili možemo zadržati verovatnoće radi procene neizvesnosti. Takođe se može proceniti verovatnoća novih tačaka kako bi se proverilo da li odgovaraju modelu (što je korisno za anomaly detection).

> [!TIP]
> *Upotreba u cybersecurity-ju:* GMM se može koristiti za anomaly detection modelovanjem distribucije normalnih podataka: svaka tačka sa veoma malom verovatnoćom u okviru naučene mešavine označava se kao anomalija. Na primer, GMM možete trenirati na karakteristikama legitimnog network traffic-a; attack konekcija koja ne liči ni na jedan naučeni klaster imala bi malu verovatnoću. GMM-ovi se takođe koriste za klasterovanje aktivnosti kod kojih klasteri mogu imati različite oblike – na primer, za grupisanje korisnika prema profilima ponašanja, gde karakteristike svakog profila mogu biti nalik Gaussian distribuciji, ali sa sopstvenom strukturom varijanse. Drugi scenario je phishing detection: karakteristike legitimnih email poruka mogu formirati jedan Gaussian klaster, poznati phishing drugi, dok se nove phishing kampanje mogu pojaviti kao zaseban Gaussian klaster ili kao tačke sa malom verovatnoćom u odnosu na postojeću mešavinu.

#### Pretpostavke i ograničenja

GMM je generalizacija K-Means-a koja uključuje kovarijaciju, pa klasteri mogu biti elipsoidni (a ne samo sferični). Ako je kovarijacija puna, može da obrađuje klastere različitih veličina i oblika. Soft klasterovanje je prednost kada su granice klastera nejasne – na primer, u cybersecurity-ju događaj može imati osobine više tipova napada; GMM tu neizvesnost može prikazati pomoću verovatnoća. GMM takođe obezbeđuje probabilističku procenu gustine podataka, što je korisno za otkrivanje outlier-a (tačaka sa malom verovatnoćom u okviru svih komponenti mešavine).

Sa druge strane, GMM zahteva navođenje broja komponenti K (mada se za njegov izbor mogu koristiti kriterijumi poput BIC/AIC). EM ponekad može sporo da konvergira ili da konvergira ka lokalnom optimumu, pa je initialization važan (EM se često pokreće više puta). Ako podaci zapravo ne prate mešavinu Gaussian distribucija, model može biti lošeg kvaliteta. Takođe postoji rizik da se jedan Gaussian smanji tako da obuhvati samo jedan outlier (mada regularizacija ili ograničenja minimalne kovarijacije mogu ublažiti taj problem).


<details>
<summary>Primer --  Soft Clustering & Anomaly Scores
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
U ovom kodu treniramo GMM sa 3 Gaussian komponente na normalnom saobraćaju (pod pretpostavkom da poznajemo 3 profila legitimnog saobraćaja). Odštampane sredine i kovarijanse opisuju ove klastere (na primer, jedna sredina može biti približno [50,500], što odgovara centru jednog klastera itd.). Zatim testiramo sumnjivu konekciju [duration=200, bytes=800]. Funkcija predict_proba daje verovatnoću da ova tačka pripada svakom od 3 klastera – očekivali bismo da ove verovatnoće budu veoma niske ili izrazito asimetrične, pošto se [200,800] nalazi daleko od normalnih klastera. Ukupni score_samples (log-likelihood) se ispisuje; veoma niska vrednost ukazuje na to da se tačka ne uklapa dobro u model, čime se označava kao anomalija. U praksi se može postaviti prag na log-likelihood (ili na maksimalnu verovatnoću) kako bi se odlučilo da li je tačka dovoljno malo verovatna da bi se smatrala malicious. GMM tako pruža principijelan način za detekciju anomalija i istovremeno generiše soft klastere koji uzimaju u obzir neizvesnost.
</details>

### Isolation Forest

**Isolation Forest** je ensemble algoritam za detekciju anomalija zasnovan na ideji nasumičnog izolovanja tačaka. Princip je da su anomalije malobrojne i različite, pa ih je lakše izolovati nego normalne tačke. Isolation Forest gradi mnogo binarnih isolation stabala (nasumičnih stabala odlučivanja) koja nasumično particionišu podatke. Na svakom čvoru stabla bira se nasumična feature i nasumična vrednost za podelu između minimuma i maksimuma te feature za podatke u tom čvoru. Ova podela deli podatke na dve grane. Stablo se gradi sve dok svaka tačka ne bude izolovana u sopstvenom leaf-u ili dok se ne dostigne maksimalna visina stabla.

Detekcija anomalija se vrši posmatranjem dužine putanje svake tačke u ovim nasumičnim stablima – broja podela potrebnih da se tačka izoluje. Intuitivno, anomalije (outliers) obično se brže izoluju jer je verovatnije da će nasumična podela razdvojiti outlier (koji se nalazi u retkom regionu) nego normalnu tačku u gustom klasteru. Isolation Forest izračunava anomaly score na osnovu prosečne dužine putanje kroz sva stabla: kraća prosečna putanja → veća verovatnoća anomalije. Score vrednosti se obično normalizuju na [0,1], gde 1 znači da je anomalija veoma verovatna.

> [!TIP]
> *Use cases in cybersecurity:* Isolation Forest se uspešno koristi u intrusion detection i fraud detection sistemima. Na primer, trenirajte Isolation Forest na network traffic logovima koji uglavnom sadrže normalno ponašanje; forest će generisati kratke putanje za neuobičajen saobraćaj (kao što je IP koji koristi do tada neviđen port ili neuobičajen obrazac veličine paketa), označavajući ga za proveru. Pošto ne zahteva labeled attacks, pogodan je za detekciju nepoznatih tipova napada. Takođe se može primeniti na podatke o user login-ima radi detekcije account takeover-a (neuobičajena vremena ili lokacije login-a brzo se izoluju). U jednom slučaju upotrebe, Isolation Forest bi mogao da zaštiti enterprise nadgledanjem system metrics i generisanjem alerta kada kombinacija metrika (CPU, network, file changes) izgleda veoma različito (kratke isolation putanje) u odnosu na istorijske obrasce.

#### Assumptions and Limitations

**Advantages**: Isolation Forest ne zahteva pretpostavku o distribuciji; direktno cilja izolaciju. Efikasan je na high-dimensional podacima i velikim dataset-ovima (linearna složenost $O(n\log n)$ za izgradnju forest-a), jer svako stablo izoluju tačke koristeći samo podskup features i podela. Obično dobro obrađuje numeričke features i može biti brži od distance-based metoda koje mogu imati složenost $O(n^2)$. Takođe automatski daje anomaly score, pa možete postaviti prag za alerte (ili koristiti contamination parametar da automatski odredite cutoff na osnovu očekivanog udela anomalija).

**Limitations**: Zbog svoje nasumične prirode, rezultati se mogu neznatno razlikovati između pokretanja (mada je to zanemarljivo uz dovoljno veliki broj stabala). Ako podaci sadrže mnogo irelevantnih features ili se anomalije ni po jednoj feature-i značajno ne razlikuju, izolacija možda neće biti efikasna (nasumične podele bi slučajno mogle izolovati normalne tačke – međutim, usrednjavanje kroz mnogo stabala ublažava ovaj problem). Takođe, Isolation Forest uglavnom pretpostavlja da su anomalije mala manjina (što je obično tačno u cybersecurity scenarijima).

<details>
<summary>Example --  Detecting Outliers in Network Logs
</summary>

Koristićemo raniji test dataset (koji sadrži normalne i neke attack tačke) i pokrenuti Isolation Forest da bismo proverili da li može da razdvoji napade. Pretpostavićemo da očekujemo da će ~15% podataka biti anomalno (u demonstracione svrhe).
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
U ovom kodu instanciramo `IsolationForest` sa 100 stabala i postavljamo `contamination=0.15` (što znači da očekujemo oko 15% anomalija; model će postaviti prag rezultata tako da približno 15% tačaka bude označeno). Primenjujemo ga na `X_test_if`, koji sadrži kombinaciju normalnih i attack tačaka (napomena: uobičajeno je da se model trenira na training podacima, a zatim da se `predict` koristi na novim podacima, ali ovde, radi ilustracije, model treniramo i predviđamo na istom skupu kako bismo direktno videli rezultate).

Izlaz prikazuje predviđene oznake za prvih 20 tačaka (gde `-1` označava anomaliju). Takođe ispisujemo ukupan broj detektovanih anomalija i nekoliko primera anomaly score vrednosti. Očekivali bismo da približno 18 od 120 tačaka bude označeno kao `-1` (pošto je `contamination` postavljen na 15%). Ako je naših 20 attack uzoraka zaista najviše izdvojeno, većina njih bi trebalo da se pojavi među tim `-1` predviđanjima. Anomaly score (`decision function` funkcija Isolation Forest-a) viši je za normalne tačke, a niži (negativniji) za anomalije – ispisujemo nekoliko vrednosti kako bismo videli razdvajanje. U praksi se podaci mogu sortirati prema score vrednosti kako bi se pronašli najizraženiji outlier-i i istražili. Isolation Forest na taj način pruža efikasan način za pregled velikih unlabeled security skupova podataka i izdvajanje najnepravilnijih instanci za ljudsku analizu ili dalju automatizovanu proveru.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** je nelinearna tehnika smanjenja dimenzionalnosti posebno osmišljena za vizuelizaciju visokodimenzionalnih podataka u 2 ili 3 dimenzije. Ona pretvara sličnosti između tačaka podataka u zajedničke distribucije verovatnoće i pokušava da očuva strukturu lokalnih susedstava u projekciji niže dimenzionalnosti. Jednostavnije rečeno, t-SNE raspoređuje tačke u (recimo) 2D prostoru tako da se slične tačke (u originalnom prostoru) sa velikom verovatnoćom nađu blizu jedna drugoj, dok se različite tačke nađu daleko jedna od druge.

Algoritam ima tri glavne faze:

1. **Izračunavanje afiniteta između parova tačaka u visokodimenzionalnom prostoru:** Za svaki par tačaka, t-SNE izračunava verovatnoću da bi taj par bio izabran kao susedni (to se radi centriranjem Gaussian distribucije oko svake tačke i merenjem rastojanja – parametar perplexity utiče na efektivni broj posmatranih suseda).
2. **Izračunavanje afiniteta između parova tačaka u niskodimenzionalnom (npr. 2D) prostoru:** Na početku se tačke nasumično raspoređuju u 2D prostoru. t-SNE definiše sličnu verovatnoću za rastojanja na ovoj mapi (koristeći Student t-distribution kernel, koji ima šire repove od Gaussian distribucije i time udaljenim tačkama omogućava veću slobodu).
3. **Gradient Descent:** t-SNE zatim iterativno pomera tačke u 2D prostoru kako bi minimizovao Kullback–Leibler (KL) divergenciju između affinity distribucije u visoko-D prostoru i one u nisko-D prostoru. Na taj način 2D raspored u najvećoj mogućoj meri odražava strukturu visoko-D prostora – tačke koje su bile blizu u originalnom prostoru privlače jedna drugu, dok se one koje su bile udaljene međusobno odbijaju, sve dok se ne pronađe ravnoteža.

Rezultat je često vizuelno značajan scatter plot u kojem klasteri podataka postaju uočljivi.

> [!TIP]
> *Upotreba u cybersecurity-u:* t-SNE se često koristi za **vizuelizaciju visokodimenzionalnih security podataka radi ljudske analize**. Na primer, u security operations centru analitičari mogu uzeti skup event podataka sa desetinama karakteristika (brojevi portova, učestalosti, broj bajtova itd.) i koristiti t-SNE za izradu 2D grafikona. Attack-i bi na tom grafikonu mogli formirati sopstvene klastere ili se odvojiti od normalnih podataka, što bi olakšalo njihovu identifikaciju. Tehnika je primenjena na malware skupove podataka radi uočavanja grupisanja malware family-ja, kao i na network intrusion podatke, gde se različiti tipovi attack-a jasno grupišu, čime se usmerava dalja istraga. U suštini, t-SNE pruža način da se uoči struktura u cyber podacima koja bi inače bila teško razumljiva.

#### Pretpostavke i ograničenja

t-SNE je odličan za vizuelno otkrivanje obrazaca. Može otkriti klastere, podklastere i outlier-e koje druge linearne metode (kao što je PCA) možda ne bi uočile. Koristi se u cybersecurity istraživanjima za vizuelizaciju složenih podataka, kao što su profili ponašanja malware-a ili obrasci network saobraćaja. Pošto čuva lokalnu strukturu, dobar je u prikazivanju prirodnih grupisanja.

Međutim, t-SNE je računarski zahtevniji (približno $O(n^2)$), pa za veoma velike skupove podataka može biti potrebno sampling-ovanje. Takođe ima hyperparameter-e (perplexity, learning rate, iterations) koji mogu uticati na izlaz – na primer, različite vrednosti perplexity-ja mogu otkriti klastere na različitim skalama. t-SNE grafikoni ponekad mogu biti pogrešno protumačeni – rastojanja na mapi nisu direktno globalno značajna (metoda se fokusira na lokalno susedstvo, pa se klasteri ponekad mogu učiniti veštački dobro razdvojenim). Osim toga, t-SNE je prvenstveno namenjen vizuelizaciji; ne pruža jednostavan način za projekciju novih tačaka podataka bez ponovnog izračunavanja i nije namenjen korišćenju kao preprocessing za predictive modeling (UMAP je alternativa koja neke od ovih problema rešava većom brzinom).

<details>
<summary>Primer -- Vizuelizacija Network Connections
</summary>

Koristićemo t-SNE za smanjenje skupa podataka sa više karakteristika na 2D prostor. Radi ilustracije, uzećemo ranije pomenute 4D podatke (koji su sadržali 3 prirodna klastera normalnog saobraćaja) i dodaćemo nekoliko anomaly tačaka. Zatim ćemo pokrenuti t-SNE i (konceptualno) vizuelizovati rezultate.
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
Ovde smo kombinovali naš prethodni 4D normalni skup podataka sa nekolicinom ekstremnih outlier-a (kod outlier-a je jedna karakteristika („duration“) podešena na veoma visoku vrednost itd., kako bi se simulirao neobičan obrazac). Pokrećemo t-SNE sa uobičajenom vrednošću perplexity od 30. Izlazni podaci `data_2d` imaju oblik (1505, 2). U ovom tekstu ih zapravo nećemo prikazati, ali kada bismo to uradili, očekivali bismo da vidimo možda tri kompaktna klastera koja odgovaraju 3 normalna klastera, dok bi se 5 outlier-a pojavilo kao izolovane tačke udaljene od tih klastera. U interaktivnom workflow-u mogli bismo da obojimo tačke prema njihovoj oznaci (normalne ili pripadajuće određenom klasteru, naspram anomalije) kako bismo proverili ovu strukturu. Čak i bez oznaka, analitičar bi mogao da primeti tih 5 tačaka u praznom prostoru na 2D prikazu i označi ih. Ovo pokazuje kako t-SNE može biti moćna pomoć za vizuelnu detekciju anomalija i ispitivanje klastera u cybersecurity podacima, dopunjujući prethodno navedene automated algorithms.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** je proširenje algoritma DBSCAN koje uklanja potrebu za izborom jedne globalne vrednosti `eps` i može da pronađe klastere **različite gustine** tako što gradi hijerarhiju density-connected komponenti, a zatim je kondenzuje. U poređenju sa standardnim DBSCAN-om, obično

* izdvaja intuitivnije klastere kada su neki klasteri gusti, a drugi retki,
* ima samo jedan stvarni hyper-parameter (`min_cluster_size`) i razumnu podrazumevanu vrednost,
* svakoj tački dodeljuje *probability* pripadnosti klasteru i **outlier score** (`outlier_scores_`), što je izuzetno korisno za threat-hunting dashboard-e.<sup>[[1]](#references)</sup>

> [!TIP]
> *Use cases u cybersecurity-u:* HDBSCAN je veoma popularan u modernim threat-hunting pipeline-ovima – često ćete ga videti unutar notebook-based hunting playbook-ova koji se isporučuju sa komercijalnim XDR paketima. Jedan praktičan recept jeste klasterovanje HTTP beaconing saobraćaja tokom IR-a: user-agent, interval i dužina URI-ja često formiraju nekoliko kompaktnih grupa legitimnih software updater-a, dok C2 beacon-i ostaju kao mali klasteri niske gustine ili kao čisti noise.

<details>
<summary>Primer – Pronalaženje beaconing C2 kanala</summary>
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

### Razmatranja robusnosti i bezbednosti – Poisoning i Adversarial Attacks (2023-2025)

Nedavna istraživanja pokazala su da **unsupervised learners *nisu* imuni na aktivne napadače**:

* **Data-poisoning protiv anomaly detektora.** Chen *et al.* (IEEE S&P 2024) pokazali su da dodavanje samo 3 % posebno kreiranog saobraćaja može da pomeri decision boundary algoritama Isolation Forest i ECOD, tako da stvarni napadi izgledaju normalno. Autori su objavili open-source PoC (`udo-poison`) koji automatski sintetiše poison points.<sup>[[2]](#references)</sup>
* **Backdooring clustering modela.** Tehnika *BadCME* (BlackHat EU 2023) ubacuje mali trigger pattern; kad god se taj trigger pojavi, K-Means-based detector neprimetno smešta događaj u „benign“ cluster.
* **Evasion DBSCAN/HDBSCAN algoritama.** Akademski pre-print sa KU Leuven iz 2025. godine pokazao je da napadač može da kreira beaconing patterns koji namerno upadaju u density gaps, efektivno se skrivajući unutar *noise* labels.

Mitigacije koje dobijaju sve veću primenu:

1. **Model sanitisation / TRIM.** Pre svakog retraining epoch-a odbaciti 1–2 % tačaka sa najvećim loss-om (trimmed maximum likelihood), čime se poisoning značajno otežava.
2. **Consensus ensembling.** Kombinovati nekoliko heterogenih detektora (npr. Isolation Forest + GMM + ECOD) i podići alert ako *bilo koji* model označi tačku. Istraživanja pokazuju da ovo povećava trošak napadača za više od 10×.
3. **Distance-based defence za clustering.** Ponovo izračunati klastere koristeći `k` različitih random seed-ova i ignorisati tačke koje neprestano menjaju klastere.

---

### Moderni Open-Source alati (2024-2025)

* **PyOD 2.x** (objavljen u maju 2024) dodao je *ECOD*, *COPOD* i GPU-accelerated *AutoFormer* detektore. Sada dolazi sa `benchmark` sub-command-om koji vam omogućava da uporedite više od 30 algoritama na svom dataset-u pomoću **jedne linije koda**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (februar 2025) fokusira se na vision, ali sadrži i generičku implementaciju **PatchCore** – korisnu za screenshot-based phishing page detection.
* **scikit-learn 1.5** (novembar 2024) konačno izlaže `score_samples` za *HDBSCAN* preko novog `cluster.HDBSCAN` wrapper-a, tako da vam nije potreban eksterni contrib package kada koristite Python 3.12.

<details>
<summary>Brz PyOD primer – ECOD + Isolation Forest ensemble</summary>
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

## Reference

- [1] [HDBSCAN – Hijerarhijsko klasterovanje zasnovano na gustini](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* „O ranjivosti nenadgledanog otkrivanja anomalija na trovanje podataka.“ *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
