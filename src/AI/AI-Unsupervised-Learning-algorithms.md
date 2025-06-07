# Algoritmi nesupervizovanog učenja

{{#include ../banners/hacktricks-training.md}}

## Nesupervizovano učenje

Nesupervizovano učenje je vrsta mašinskog učenja gde se model obučava na podacima bez označenih odgovora. Cilj je pronaći obrasce, strukture ili odnose unutar podataka. Za razliku od supervizovanog učenja, gde model uči iz označenih primera, algoritmi nesupervizovanog učenja rade sa neoznačenim podacima. 
Nesupervizovano učenje se često koristi za zadatke kao što su klasterizacija, smanjenje dimenzionalnosti i detekcija anomalija. Može pomoći u otkrivanju skrivenih obrazaca u podacima, grupisanju sličnih stavki ili smanjenju složenosti podataka uz očuvanje njihovih suštinskih karakteristika.

### K-Means klasterizacija

K-Means je algoritam klasterizacije zasnovan na centroidima koji deli podatke u K klastera dodeljujući svaku tačku najbližem srednjem klasteru. Algoritam funkcioniše na sledeći način:
1. **Inicijalizacija**: Izaberite K početnih centara klastera (centroida), često nasumično ili putem pametnijih metoda kao što je k-means++
2. **Dodeljivanje**: Dodelite svaku tačku podataka najbližem centroidu na osnovu metričke udaljenosti (npr. Euklidska udaljenost).
3. **Ažuriranje**: Ponovo izračunajte centre uzimajući prosek svih tačaka podataka dodeljenih svakom klasteru.
4. **Ponoviti**: Koraci 2–3 se ponavljaju dok se dodeljivanje klastera ne stabilizuje (centroidi se više ne pomeraju značajno).

> [!TIP]
> *Upotreba u sajber bezbednosti:* K-Means se koristi za detekciju upada klasterizacijom mrežnih događaja. Na primer, istraživači su primenili K-Means na KDD Cup 99 skupu podataka o upadima i otkrili da efikasno deli saobraćaj na normalne i napadačke klastere. U praksi, analitičari bezbednosti mogu klasterizovati unose logova ili podatke o ponašanju korisnika kako bi pronašli grupe sličnih aktivnosti; bilo koje tačke koje ne pripadaju dobro formiranom klasteru mogu ukazivati na anomalije (npr. nova varijanta malvera koja formira svoj mali klaster). K-Means takođe može pomoći u klasifikaciji porodica malvera grupisanjem binarnih datoteka na osnovu profila ponašanja ili vektora karakteristika.

#### Odabir K
Broj klastera (K) je hiperparametar koji treba definisati pre pokretanja algoritma. Tehnike poput Elbow metode ili Silhouette skora mogu pomoći u određivanju odgovarajuće vrednosti za K procenom performansi klasterizacije:

- **Elbow metoda**: Prikazivanje sume kvadratnih udaljenosti svake tačke do njenog dodeljenog centroida klastera kao funkcije K. Potražite "laktasti" tačku gde se brzina opadanja naglo menja, što ukazuje na odgovarajući broj klastera.
- **Silhouette skor**: Izračunajte silhouette skor za različite vrednosti K. Viši silhouette skor ukazuje na bolje definisane klastere.

#### Pretpostavke i ograničenja

K-Means pretpostavlja da su **klasteri sferni i jednake veličine**, što možda nije tačno za sve skupove podataka. Osetljiv je na početno postavljanje centroida i može konvergirati ka lokalnim minimumima. Pored toga, K-Means nije pogodan za skupove podataka sa različitim gustinama ili neglobularnim oblicima i karakteristikama različitih razmera. Koraci predobrada poput normalizacije ili standardizacije mogu biti neophodni kako bi se osiguralo da sve karakteristike ravnomerno doprinose izračunavanju udaljenosti.

<details>
<summary>Primer -- Klasterizacija mrežnih događaja
</summary>
Ispod simuliramo podatke o mrežnom saobraćaju i koristimo K-Means za njihovu klasterizaciju. Pretpostavimo da imamo događaje sa karakteristikama kao što su trajanje veze i broj bajtova. Kreiramo 3 klastera "normalnog" saobraćaja i 1 mali klaster koji predstavlja obrazac napada. Zatim pokrećemo K-Means da vidimo da li ih razdvaja.
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
U ovom primeru, K-Means bi trebao da pronađe 4 klastera. Mali klaster napada (sa neobično visokim trajanjem ~200) će idealno formirati svoj vlastiti klaster s obzirom na svoju udaljenost od normalnih klastera. Štampamo veličine klastera i centre kako bismo interpretirali rezultate. U stvarnom scenariju, moglo bi se označiti klaster sa nekoliko tačaka kao potencijalne anomalije ili pregledati njegove članove zbog malicioznih aktivnosti.
</details>

### Hijerarhijsko Klasterovanje

Hijerarhijsko klasterovanje gradi hijerarhiju klastera koristeći ili pristup odozdo prema gore (aglomerativni) ili pristup odozgo prema dole (divizivni):

1. **Aglomerativno (odozdo prema gore)**: Počnite sa svakom tačkom podataka kao posebnim klasterom i iterativno spajajte najbliže klastere dok ne ostane jedan klaster ili se ne ispuni kriterijum zaustavljanja.
2. **Divizivno (odozgo prema dole)**: Počnite sa svim tačkama podataka u jednom klasteru i iterativno delite klastere dok svaka tačka podataka ne postane svoj vlastiti klaster ili se ne ispuni kriterijum zaustavljanja.

Aglomerativno klasterovanje zahteva definiciju međuklaster udaljenosti i kriterijum povezivanja da bi se odlučilo koji klasteri će se spojiti. Uobičajene metode povezivanja uključuju pojedinačno povezivanje (udaljenost najbližih tačaka između dva klastera), potpuno povezivanje (udaljenost najdaljih tačaka), prosečno povezivanje itd., a metrička udaljenost je često euklidska. Izbor povezivanja utiče na oblik klastera koji se proizvode. Nema potrebe da se unapred definiše broj klastera K; možete "prerezati" dendrogram na odabranom nivou da biste dobili željeni broj klastera.

Hijerarhijsko klasterovanje proizvodi dendrogram, strukturu nalik drvetu koja prikazuje odnose između klastera na različitim nivoima granularnosti. Dendrogram se može prerezati na željenom nivou da bi se dobio specifičan broj klastera.

> [!TIP]
> *Upotrebe u sajber bezbednosti:* Hijerarhijsko klasterovanje može organizovati događaje ili entitete u drvo kako bi se uočili odnosi. Na primer, u analizi malvera, aglomerativno klasterovanje bi moglo grupisati uzorke prema ponašanju, otkrivajući hijerarhiju porodica i varijanti malvera. U mrežnoj bezbednosti, moglo bi se klasterovati IP saobraćaj i koristiti dendrogram da se vide podgrupe saobraćaja (npr. prema protokolu, zatim prema ponašanju). Pošto ne morate unapred odabrati K, korisno je kada istražujete nove podatke za koje je broj kategorija napada nepoznat.

#### Pretpostavke i Ograničenja

Hijerarhijsko klasterovanje ne pretpostavlja određeni oblik klastera i može uhvatiti ugnježdene klastere. Korisno je za otkrivanje taksonomije ili odnosa među grupama (npr. grupisanje malvera prema porodicama). Determinističko je (nema problema sa slučajnom inicijalizacijom). Ključna prednost je dendrogram, koji pruža uvid u strukturu klasterovanja podataka na svim razmerama – analitičari bezbednosti mogu odlučiti o odgovarajućem preseku da identifikuju značajne klastere. Međutim, računski je skup (tipično $O(n^2)$ vremena ili gore za naivne implementacije) i nije izvodljiv za veoma velike skupove podataka. Takođe je pohlepna procedura – jednom kada se spajanje ili deljenje izvrši, ne može se poništiti, što može dovesti do suboptimalnih klastera ako se greška dogodi rano. Izuzeci takođe mogu uticati na neke strategije povezivanja (jednostavno povezivanje može izazvati efekat "lančanja" gde se klasteri povezuju putem izuzetaka).

<details>
<summary>Primer -- Aglomerativno Klasterovanje Događaja
</summary>

Ponovo ćemo koristiti sintetičke podatke iz K-Means primera (3 normalna klastera + 1 klaster napada) i primeniti aglomerativno klasterovanje. Zatim ilustrujemo kako dobiti dendrogram i oznake klastera.
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

### DBSCAN (Klasterovanje na bazi gustine sa šumom)

DBSCAN je algoritam klasterovanja zasnovan na gustini koji grupiše tačke koje su blisko smeštene zajedno, dok označava tačke u oblastima niske gustine kao izuzetke. Posebno je koristan za skupove podataka sa različitim gustinama i nesfernim oblicima.

DBSCAN funkcioniše definisanjem dva parametra:
- **Epsilon (ε)**: Maksimalna udaljenost između dve tačke da bi se smatrale delom istog klastera.
- **MinPts**: Minimalan broj tačaka potrebnih za formiranje guste oblasti (glavna tačka).

DBSCAN identifikuje glavne tačke, tačke na granici i tačke šuma:
- **Glavna tačka**: Tačka sa najmanje MinPts suseda unutar ε udaljenosti.
- **Tačka na granici**: Tačka koja se nalazi unutar ε udaljenosti od glavne tačke, ali ima manje od MinPts suseda.
- **Tačka šuma**: Tačka koja nije ni glavna tačka ni tačka na granici.

Klasterovanje se nastavlja biranjem neposećene glavne tačke, označavanjem kao novog klastera, a zatim rekurzivnim dodavanjem svih tačaka koje su dostupne po gustini (glavne tačke i njihovi susedi, itd.). Tačke na granici se dodaju klasteru obližnje glavne tačke. Nakon proširenja svih dostupnih tačaka, DBSCAN prelazi na drugu neposećenu glavnu tačku da započne novi klaster. Tačke koje nisu dostignute od strane nijedne glavne tačke ostaju označene kao šum.

> [!TIP]
> *Upotreba u sajber bezbednosti:* DBSCAN je koristan za detekciju anomalija u mrežnom saobraćaju. Na primer, normalna aktivnost korisnika može formirati jedan ili više gustih klastera u prostoru karakteristika, dok se nove napadačke ponašanja pojavljuju kao rasute tačke koje će DBSCAN označiti kao šum (izuzetke). Koristi se za klasterovanje zapisa mrežnog toka, gde može detektovati skeniranja portova ili saobraćaj usluge uskraćivanja kao retke oblasti tačaka. Druga primena je grupisanje varijanti malvera: ako se većina uzoraka grupiše po porodicama, ali se nekoliko ne uklapa nigde, tih nekoliko bi moglo biti zero-day malver. Sposobnost označavanja šuma znači da se timovi za bezbednost mogu fokusirati na istraživanje tih izuzetaka.

#### Pretpostavke i Ograničenja

**Pretpostavke i Snage:** DBSCAN ne pretpostavlja sferne klastere – može pronaći klastere proizvoljnog oblika (čak i lančaste ili susedne klastere). Automatski određuje broj klastera na osnovu gustine podataka i može efikasno identifikovati izuzetke kao šum. Ovo ga čini moćnim za stvarne podatke sa nepravilnim oblicima i šumom. Otporan je na izuzetke (za razliku od K-Means, koji ih prisiljava u klastere). Dobro funkcioniše kada klasteri imaju otprilike uniformnu gustinu.

**Ograničenja:** Performanse DBSCAN-a zavise od izbora odgovarajućih ε i MinPts vrednosti. Može imati problema sa podacima koji imaju različite gustine – jedna ε ne može obuhvatiti i guste i retke klastere. Ako je ε previše mala, označava većinu tačaka kao šum; prevelika, i klasteri se mogu pogrešno spojiti. Takođe, DBSCAN može biti neefikasan na veoma velikim skupovima podataka (naivno $O(n^2)$, iako prostorno indeksiranje može pomoći). U visokodimenzionalnim prostorima karakteristika, koncept "udaljenosti unutar ε" može postati manje značajan (prokletstvo dimenzionalnosti), i DBSCAN može zahtevati pažljivo podešavanje parametara ili može propasti u pronalaženju intuitivnih klastera. I pored ovoga, proširenja poput HDBSCAN rešavaju neka pitanja (poput varijabilne gustine).

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
U ovom isječku, prilagodili smo `eps` i `min_samples` da odgovaraju našoj skali podataka (15.0 u jedinicama karakteristika, i zahtevajući 5 tačaka za formiranje klastera). DBSCAN bi trebao pronaći 2 klastera (klastere normalnog saobraćaja) i označiti 5 ubačenih izuzetaka kao šum. Izlazimo broj klastera u odnosu na tačke šuma kako bismo to potvrdili. U stvarnom okruženju, može se iterirati preko ε (koristeći heuristiku grafika k-udaljenosti za odabir ε) i MinPts (često postavljenih na oko dimenzionalnosti podataka + 1 kao pravilo prsta) kako bi se pronašli stabilni rezultati klasterisanja. Sposobnost da se eksplicitno označi šum pomaže u oddvajanju potencijalnih podataka o napadima za dalju analizu.

</details>

### Analiza glavnih komponenti (PCA)

PCA je tehnika za **smanjenje dimenzionalnosti** koja pronalazi novi skup ortogonalnih osa (glavnih komponenti) koje hvataju maksimalnu varijansu u podacima. U jednostavnim terminima, PCA rotira i projektuje podatke na novi koordinatni sistem tako da prva glavna komponenta (PC1) objašnjava najveću moguću varijansu, druga PC (PC2) objašnjava najveću varijansu ortogonalnu na PC1, i tako dalje. Matematički, PCA izračunava sopstvene vektore kovarijantne matrice podataka – ovi sopstveni vektori su pravci glavnih komponenti, a odgovarajući sopstveni vrednosti ukazuju na količinu varijanse koju objašnjava svaka. Često se koristi za ekstrakciju karakteristika, vizualizaciju i smanjenje šuma.

Napomena da je ovo korisno ako dimenzije skupa podataka sadrže **značajne linearne zavisnosti ili korelacije**.

PCA funkcioniše identifikovanjem glavnih komponenti podataka, koje su pravci maksimalne varijanse. Koraci uključeni u PCA su:
1. **Standardizacija**: Centriranje podataka oduzimanjem proseka i skaliranjem na jediničnu varijansu.
2. **Kovarijantna matrica**: Izračunavanje kovarijantne matrice standardizovanih podataka kako bi se razumele veze između karakteristika.
3. **Dezintegracija sopstvenih vrednosti**: Izvršavanje dezintegracije sopstvenih vrednosti na kovarijantnoj matrici kako bi se dobile sopstvene vrednosti i sopstveni vektori.
4. **Odabir glavnih komponenti**: Sortiranje sopstvenih vrednosti u opadajućem redosledu i odabir vrhunskih K sopstvenih vektora koji odgovaraju najvećim sopstvenim vrednostima. Ovi sopstveni vektori formiraju novi prostor karakteristika.
5. **Transformacija podataka**: Projekcija originalnih podataka na novi prostor karakteristika koristeći odabrane glavne komponente.
PCA se široko koristi za vizualizaciju podataka, smanjenje šuma i kao korak predobrada za druge algoritme mašinskog učenja. Pomaže u smanjenju dimenzionalnosti podataka dok zadržava njegovu suštinsku strukturu.

#### Sopstvene vrednosti i sopstveni vektori

Sopstvena vrednost je skalar koji ukazuje na količinu varijanse koju hvata njen odgovarajući sopstveni vektor. Sopstveni vektor predstavlja pravac u prostoru karakteristika duž kojeg se podaci najviše menjaju.

Zamislite da je A kvadratna matrica, a v nenulti vektor takav da: `A * v = λ * v`
gde:
- A je kvadratna matrica poput [ [1, 2], [2, 1]] (npr. kovarijantna matrica)
- v je sopstveni vektor (npr. [1, 1])

Tada, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` što će biti sopstvena vrednost λ pomnožena sa sopstvenim vektorom v, čineći sopstvenu vrednost λ = 3.

#### Sopstvene vrednosti i sopstveni vektori u PCA

Objasnimo ovo sa primerom. Zamislite da imate skup podataka sa puno slika lica u sivim tonovima dimenzija 100x100 piksela. Svaki piksel se može smatrati karakteristikom, tako da imate 10,000 karakteristika po slici (ili vektor od 10,000 komponenti po slici). Ako želite da smanjite dimenzionalnost ovog skupa podataka koristeći PCA, pratili biste ove korake:

1. **Standardizacija**: Centriranje podataka oduzimanjem proseka svake karakteristike (piksela) iz skupa podataka.
2. **Kovarijantna matrica**: Izračunavanje kovarijantne matrice standardizovanih podataka, koja hvata kako se karakteristike (pikseli) zajedno menjaju.
- Napomena da kovarijansa između dve varijable (piksela u ovom slučaju) ukazuje na to koliko se zajedno menjaju, tako da je ideja ovde da se otkrije koji piksela imaju tendenciju da se povećavaju ili smanjuju zajedno sa linearnom vezom.
- Na primer, ako piksel 1 i piksel 2 imaju tendenciju da se zajedno povećavaju, kovarijansa između njih će biti pozitivna.
- Kovarijantna matrica će biti 10,000x10,000 matrica gde svaki unos predstavlja kovarijansu između dva piksela.
3. **Rešavanje sopstvene vrednosti**: Sopstvena vrednost koju treba rešiti je `C * v = λ * v` gde je C kovarijantna matrica, v sopstveni vektor, a λ sopstvena vrednost. Može se rešiti korišćenjem metoda kao što su:
- **Dezintegracija sopstvenih vrednosti**: Izvršavanje dezintegracije sopstvenih vrednosti na kovarijantnoj matrici kako bi se dobile sopstvene vrednosti i sopstveni vektori.
- **Dezintegracija singularnih vrednosti (SVD)**: Alternativno, možete koristiti SVD za dezintegraciju matrice podataka u singularne vrednosti i vektore, što takođe može dati glavne komponente.
4. **Odabir glavnih komponenti**: Sortiranje sopstvenih vrednosti u opadajućem redosledu i odabir vrhunskih K sopstvenih vektora koji odgovaraju najvećim sopstvenim vrednostima. Ovi sopstveni vektori predstavljaju pravce maksimalne varijanse u podacima.

> [!TIP]
> *Upotrebe u sajber bezbednosti:* Uobičajena upotreba PCA u bezbednosti je smanjenje karakteristika za otkrivanje anomalija. Na primer, sistem za otkrivanje upada sa 40+ mrežnih metrika (poput NSL-KDD karakteristika) može koristiti PCA da smanji na nekoliko komponenti, sumirajući podatke za vizualizaciju ili unošenje u algoritme klasterisanja. Analitičari mogu prikazati mrežni saobraćaj u prostoru prvih dve glavne komponente kako bi videli da li se napadi odvajaju od normalnog saobraćaja. PCA takođe može pomoći u eliminaciji redundantnih karakteristika (poput poslatih bajtova u odnosu na primljene bajtove ako su korelisani) kako bi se algoritmi detekcije učinili robusnijim i bržim.

#### Pretpostavke i ograničenja

PCA pretpostavlja da su **glavne ose varijanse značajne** – to je linearna metoda, pa hvata linearne korelacije u podacima. To je nesupervizovana metoda jer koristi samo kovarijansu karakteristika. Prednosti PCA uključuju smanjenje šuma (komponente male varijanse često odgovaraju šumu) i dekorelaciju karakteristika. Efikasna je u računski za umereno visoke dimenzije i često je koristan korak predobrada za druge algoritme (da ublaži prokletstvo dimenzionalnosti). Jedno ograničenje je to što je PCA ograničen na linearne odnose – neće uhvatiti složenu nelinearnu strukturu (dok autoenkoderi ili t-SNE mogu). Takođe, komponente PCA mogu biti teške za interpretaciju u smislu originalnih karakteristika (one su kombinacije originalnih karakteristika). U sajber bezbednosti, treba biti oprezan: napad koji uzrokuje samo suptilnu promenu u karakteristici male varijanse možda se neće pojaviti u vrhunskim PC-ima (pošto PCA prioritizuje varijansu, a ne nužno "zanimljivost").

<details>
<summary>Primer -- Smanjenje dimenzija mrežnih podataka
</summary>

Pretpostavimo da imamo logove mrežnih konekcija sa više karakteristika (npr. trajanja, bajtova, brojeva). Generisaćemo sintetički 4-dimenzionalni skup podataka (sa nekim korelacijama između karakteristika) i koristiti PCA da ga smanjimo na 2 dimenzije za vizualizaciju ili dalju analizu.
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
Ovde smo uzeli ranije normalne klastere saobraćaja i proširili svaku tačku podacima sa dve dodatne karakteristike (paketi i greške) koje su u korelaciji sa bajtovima i trajanjem. PCA se zatim koristi za kompresiju 4 karakteristike u 2 glavne komponente. Štampamo odnos objašnjene varijanse, koji može pokazati da, recimo, >95% varijanse pokriva 2 komponente (što znači malo gubitka informacija). Izlaz takođe pokazuje da se oblik podataka smanjuje sa (1500, 4) na (1500, 2). Prvih nekoliko tačaka u PCA prostoru je dato kao primer. U praksi, moglo bi se prikazati data_2d da se vizuelno proveri da li su klasteri prepoznatljivi. Ako je postojala anomalija, moglo bi se videti kao tačka koja leži daleko od glavnog klastera u PCA-prostoru. PCA tako pomaže da se složeni podaci destiluju u upravljiv oblik za ljudsku interpretaciju ili kao ulaz za druge algoritme.

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Model pretpostavlja da su podaci generisani iz mešavine **several Gaussian (normal) distributions with unknown parameters**. U suštini, to je probabilistički model klasterovanja: pokušava da blago dodeli svaku tačku jednom od K Gaussian komponenti. Svaka Gaussian komponenta k ima vektor srednje vrednosti (μ_k), kovarijantnu matricu (Σ_k) i težinu mešanja (π_k) koja predstavlja koliko je taj klaster prisutan. Za razliku od K-Means koji vrši "tvrde" dodeljivanje, GMM daje svakoj tački verovatnoću pripadnosti svakom klasteru.

GMM prilagođavanje se obično vrši putem algoritma Expectation-Maximization (EM):

- **Inicijalizacija**: Počnite sa početnim pretpostavkama za srednje vrednosti, kovarijanse i koeficijente mešanja (ili koristite rezultate K-Means kao početnu tačku).

- **E-korak (Očekivanje)**: S obzirom na trenutne parametre, izračunajte odgovornost svakog klastera za svaku tačku: suštinski `r_nk = P(z_k | x_n)` gde je z_k latentna varijabla koja ukazuje na članstvo u klasteru za tačku x_n. Ovo se radi koristeći Bayesovu teoremu, gde izračunavamo posteriornu verovatnoću svake tačke da pripada svakom klasteru na osnovu trenutnih parametara. Odgovornosti se izračunavaju kao:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
gde:
- \( \pi_k \) je koeficijent mešanja za klaster k (prior verovatnoća klastera k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) je Gaussian funkcija gustine verovatnoće za tačku \( x_n \) s obzirom na srednju vrednost \( \mu_k \) i kovarijansu \( \Sigma_k \).

- **M-korak (Maksimizacija)**: Ažurirajte parametre koristeći odgovornosti izračunate u E-koraku:
- Ažurirajte svaku srednju vrednost μ_k kao ponderisanu srednju vrednost tačaka, gde su težine odgovornosti.
- Ažurirajte svaku kovarijansu Σ_k kao ponderisanu kovarijansu tačaka dodeljenih klasteru k.
- Ažurirajte koeficijente mešanja π_k kao prosečnu odgovornost za klaster k.

- **Iterirajte** E i M korake dok ne dođe do konvergencije (parametri se stabilizuju ili poboljšanje verovatnoće je ispod praga).

Rezultat je skup Gaussian distribucija koje kolektivno modeliraju ukupnu distribuciju podataka. Možemo koristiti prilagođeni GMM za klasterovanje dodeljivanjem svake tačke Gaussian-u sa najvišom verovatnoćom, ili zadržati verovatnoće za nesigurnost. Takođe se može proceniti verovatnoća novih tačaka da vide da li se uklapaju u model (korisno za otkrivanje anomalija).

> [!TIP]
> *Upotrebe u sajber bezbednosti:* GMM se može koristiti za otkrivanje anomalija modelovanjem distribucije normalnih podataka: svaka tačka sa vrlo niskom verovatnoćom pod naučenom mešavinom se označava kao anomalija. Na primer, mogli biste obučiti GMM na karakteristikama legitimnog mrežnog saobraćaja; napadna veza koja se ne sliči nijednom naučenom klasteru imala bi nisku verovatnoću. GMM-ovi se takođe koriste za klasterovanje aktivnosti gde klasteri mogu imati različite oblike – npr., grupisanje korisnika prema profilima ponašanja, gde karakteristike svakog profila mogu biti slične Gaussian-u, ali sa sopstvenom strukturom varijanse. Drugi scenario: u otkrivanju phishing-a, legitimne karakteristike e-pošte mogu formirati jedan Gaussian klaster, poznati phishing drugi, a nove phishing kampanje mogu se pojaviti kao ili odvojeni Gaussian ili kao tačke sa niskom verovatnoćom u odnosu na postojeću mešavinu.

#### Pretpostavke i Ograničenja

GMM je generalizacija K-Means koja uključuje kovarijansu, tako da klasteri mogu biti elipsoidni (ne samo sferni). Rukuje klasterima različitih veličina i oblika ako je kovarijansa puna. Mekano klasterovanje je prednost kada su granice klastera nejasne – npr., u sajber bezbednosti, događaj može imati osobine više tipova napada; GMM može odražavati tu nesigurnost sa verovatnoćama. GMM takođe pruža procenu gustine verovatnoće podataka, korisnu za otkrivanje outliera (tačaka sa niskom verovatnoćom pod svim komponentama mešavine).

S druge strane, GMM zahteva da se specificira broj komponenti K (iako se mogu koristiti kriterijumi poput BIC/AIC za njegovu selekciju). EM ponekad može sporo konvergirati ili do lokalnog optimuma, tako da je inicijalizacija važna (često se EM pokreće više puta). Ako podaci zapravo ne prate mešavinu Gaussian-a, model može biti loše prilagođen. Takođe postoji rizik da jedan Gaussian smanji da pokrije samo outlier (iako regularizacija ili minimalne granice kovarijanse mogu to ublažiti).


<details>
<summary>Primer --  Mekano Klasterovanje & Anomalijske Ocene
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
U ovom kodu, obučavamo GMM sa 3 Gaussiana na normalnom saobraćaju (pretpostavljajući da znamo 3 profila legitimnog saobraćaja). Srednje vrednosti i kovarijanse koje se ispisuju opisuju ove klastere (na primer, jedna srednja vrednost može biti oko [50,500] koja odgovara centru jednog klastera, itd.). Zatim testiramo sumnjivu vezu [duration=200, bytes=800]. predict_proba daje verovatnoću da ova tačka pripada svakom od 3 klastera – očekivali bismo da su ove verovatnoće vrlo niske ili veoma iskrivljene, pošto [200,800] leži daleko od normalnih klastera. Ukupni score_samples (log-verovatnoća) se ispisuje; vrlo niska vrednost ukazuje na to da tačka ne odgovara modelu dobro, označavajući je kao anomaliju. U praksi, može se postaviti prag na log-verovatnoću (ili na maksimalnu verovatnoću) da se odluči da li je tačka dovoljno malo verovatna da se smatra malicioznom. GMM tako pruža principijelan način za detekciju anomalija i takođe daje meke klastere koji priznaju nesigurnost.
</details>

### Isolation Forest

**Isolation Forest** je ansambl algoritam za detekciju anomalija zasnovan na ideji nasumičnog izolovanja tačaka. Princip je da su anomalije retke i različite, pa ih je lakše izolovati nego normalne tačke. Isolation Forest gradi mnogo binarnih izolacionih stabala (nasumična odlučujuća stabla) koja nasumično dele podatke. Na svakom čvoru u stablu, nasumična karakteristika se bira i nasumična vrednost razdvajanja se bira između minimuma i maksimuma te karakteristike za podatke u tom čvoru. Ovo razdvajanje deli podatke na dve grane. Stablo se razvija sve dok svaka tačka nije izolovana u svom listu ili dok se ne dostigne maksimalna visina stabla.

Detekcija anomalija se vrši posmatranjem dužine puta svake tačke u ovim nasumičnim stablima – broj razdvajanja potrebnih za izolaciju tačke. Intuitivno, anomalije (izuzeci) se obično brže izoluju jer je nasumično razdvajanje verovatnije da će odvojiti izuzetak (koji se nalazi u retkoj oblasti) nego normalnu tačku u gustoj grupi. Isolation Forest izračunava skor anomalije na osnovu prosečne dužine puta preko svih stabala: kraća prosečna dužina puta → više anomalno. Skorovi se obično normalizuju na [0,1] gde 1 znači vrlo verovatna anomalija.

> [!TIP]
> *Upotrebe u sajber bezbednosti:* Isolation Forests su uspešno korišćeni u detekciji upada i detekciji prevara. Na primer, obučite Isolation Forest na logovima mrežnog saobraćaja koji većinom sadrže normalno ponašanje; šuma će proizvesti kratke puteve za čudan saobraćaj (kao što je IP koji koristi nečuvenu portu ili neobičan obrazac veličine paketa), označavajući ga za inspekciju. Pošto ne zahteva označene napade, pogodna je za detekciju nepoznatih tipova napada. Takođe se može primeniti na podatke o prijavljivanju korisnika za detekciju preuzimanja naloga (anomalna vremena ili lokacije prijavljivanja se brzo izoluju). U jednom slučaju upotrebe, Isolation Forest može zaštititi preduzeće praćenjem sistemskih metrika i generisanjem upozorenja kada kombinacija metrika (CPU, mreža, promene fajlova) izgleda veoma drugačije (kratki putevi izolacije) od istorijskih obrazaca.

#### Pretpostavke i Ograničenja

**Prednosti**: Isolation Forest ne zahteva pretpostavku o distribuciji; direktno cilja izolaciju. Efikasan je na podacima visoke dimenzionalnosti i velikim skupovima podataka (linearna složenost $O(n\log n)$ za izgradnju šume) pošto svako stablo izoluje tačke samo sa podskupom karakteristika i razdvajanja. Obično dobro obrađuje numeričke karakteristike i može biti brži od metoda zasnovanih na udaljenosti koje mogu biti $O(n^2)$. Takođe automatski daje skor anomalije, tako da možete postaviti prag za upozorenja (ili koristiti parametar kontaminacije da automatski odlučite o prekidu na osnovu očekivane frakcije anomalija).

**Ograničenja**: Zbog svoje nasumične prirode, rezultati se mogu malo razlikovati između pokretanja (iako je to minorno sa dovoljno mnogo stabala). Ako podaci imaju mnogo irelevantnih karakteristika ili ako se anomalije ne razlikuju snažno u bilo kojoj karakteristici, izolacija možda neće biti efikasna (nasumična razdvajanja bi mogla izolovati normalne tačke slučajno – međutim, prosečno uzimanje mnogih stabala ublažava ovo). Takođe, Isolation Forest obično pretpostavlja da su anomalije mala manjina (što je obično tačno u scenarijima sajber bezbednosti).

<details>
<summary>Primer -- Detekcija Izuzetaka u Mrežnim Logovima
</summary>

Koristićemo raniji test skup podataka (koji sadrži normalne i neke tačke napada) i pokrenuti Isolation Forest da vidimo da li može da razdvoji napade. Pretpostavićemo da očekujemo ~15% podataka da bude anomalno (za demonstraciju).
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
U ovom kodu, instanciramo `IsolationForest` sa 100 stabala i postavljamo `contamination=0.15` (što znači da očekujemo oko 15% anomalija; model će postaviti svoj prag rezultata tako da ~15% tačaka bude označeno). Prilagođavamo ga na `X_test_if` koji sadrži mešavinu normalnih i napadnih tačaka (napomena: obično biste prilagodili na podacima za obuku, a zatim koristili predikciju na novim podacima, ali ovde, radi ilustracije, prilagođavamo i predviđamo na istom skupu kako bismo direktno posmatrali rezultate).

Izlaz prikazuje predviđene oznake za prvih 20 tačaka (gde -1 označava anomaliju). Takođe štampamo koliko je anomalija ukupno otkriveno i neke primerke anomalijskih rezultata. Očekivali bismo otprilike 18 od 120 tačaka da budu označene sa -1 (pošto je kontaminacija bila 15%). Ako su naših 20 uzoraka napada zaista najizolovaniji, većina njih bi trebala da se pojavi u tim -1 predikcijama. Anomalijski rezultat (odluka funkcije Isolation Forest-a) je viši za normalne tačke i niži (više negativan) za anomalije – štampamo nekoliko vrednosti da bismo videli razdvajanje. U praksi, neko bi mogao da sortira podatke po rezultatu da vidi najistaknutije izuzetke i istraži ih. Isolation Forest tako pruža efikasan način da se pretražuju veliki neoznačeni bezbednosni podaci i izdvoje najnepravilnije instance za ljudsku analizu ili dalju automatsku proveru.

### t-SNE (t-Distribuirano Stohastičko Uključivanje Suseda)

**t-SNE** je nelinearna tehnika smanjenja dimenzionalnosti posebno dizajnirana za vizualizaciju podataka visoke dimenzionalnosti u 2 ili 3 dimenzije. Ona pretvara sličnosti između tačaka podataka u zajedničke verovatnoće i pokušava da sačuva strukturu lokalnih komšiluka u projekciji sa nižom dimenzionalnošću. Jednostavnije rečeno, t-SNE postavlja tačke u (recimo) 2D tako da slične tačke (u originalnom prostoru) završe blizu jedna druge, a neslične tačke daleko jedna od druge sa visokom verovatnoćom.

Algoritam ima dve glavne faze:

1. **Izračunavanje parnih afiniteta u prostoru visoke dimenzionalnosti:** Za svaki par tačaka, t-SNE izračunava verovatnoću da bi neko izabrao taj par kao komšije (to se radi centriranjem Gaussove distribucije na svakoj tački i merenjem udaljenosti – parametar perplexity utiče na efektivan broj komšija koje se razmatraju).
2. **Izračunavanje parnih afiniteta u prostoru sa niskom dimenzionalnošću (npr. 2D):** U početku, tačke se nasumično postavljaju u 2D. t-SNE definiše sličnu verovatnoću za udaljenosti na ovoj mapi (koristeći Studentovu t-distribuciju, koja ima teže repove od Gaussove kako bi omogućila udaljenim tačkama više slobode).
3. **Gradientni spust:** t-SNE zatim iterativno pomera tačke u 2D kako bi minimizirao Kullback–Leibler (KL) divergenciju između visoko-D afinitetske distribucije i nisko-D one. To uzrokuje da raspored u 2D odražava strukturu visoke dimenzionalnosti koliko god je to moguće – tačke koje su bile blizu u originalnom prostoru će se privlačiti, a one daleko će se odbijati, sve dok se ne pronađe ravnoteža.

Rezultat je često vizuelno značajan dijagram raspršenja gde klasteri u podacima postaju očigledni.

> [!TIP]
> *Upotrebe u sajber bezbednosti:* t-SNE se često koristi za **vizualizaciju podataka visoke dimenzionalnosti za ljudsku analizu**. Na primer, u centru za operacije bezbednosti, analitičari bi mogli uzeti skup podataka o događajima sa desetinama karakteristika (brojevi portova, frekvencije, brojevi bajtova itd.) i koristiti t-SNE da proizvedu 2D dijagram. Napadi bi mogli formirati svoje klastere ili se odvojiti od normalnih podataka u ovom dijagramu, čineći ih lakšim za identifikaciju. Primena je bila na skupovima podataka o malveru da se vide grupisanja porodica malvera ili na podacima o mrežnim upadima gde se različite vrste napada jasno grupišu, usmeravajući dalju istragu. Suštinski, t-SNE pruža način da se vidi struktura u sajber podacima koja bi inače bila nejasna.

#### Pretpostavke i Ograničenja

t-SNE je odličan za vizuelno otkrivanje obrazaca. Može otkriti klastere, subklastere i izuzetke koje druge linearne metode (kao što je PCA) možda ne bi mogle. Koristi se u istraživanju sajber bezbednosti za vizualizaciju složenih podataka kao što su profili ponašanja malvera ili obrasci mrežnog saobraćaja. Pošto čuva lokalnu strukturu, dobar je za prikazivanje prirodnih grupisanja.

Međutim, t-SNE je računski zahtevniji (približno $O(n^2)$) pa može zahtevati uzorkovanje za veoma velike skupove podataka. Takođe ima hiperparametre (perplexity, brzina učenja, iteracije) koji mogu uticati na izlaz – npr., različite vrednosti perplexity mogu otkriti klastere na različitim skalama. t-SNE dijagrami se ponekad mogu pogrešno interpretirati – udaljenosti na mapi nisu direktno značajne globalno (fokusira se na lokalno komšiluko, ponekad klasteri mogu izgledati veštački dobro odvojeni). Takođe, t-SNE je uglavnom za vizualizaciju; ne pruža jednostavan način za projektovanje novih tačaka podataka bez ponovnog izračunavanja, i nije namenjen da se koristi kao predobrada za prediktivno modelovanje (UMAP je alternativa koja rešava neka od ovih problema bržom brzinom).

<details>
<summary>Primer -- Vizualizacija Mrežnih Veza
</summary>

Koristićemo t-SNE da smanjimo skup podataka sa više karakteristika na 2D. Za ilustraciju, uzmimo ranije 4D podatke (koji su imali 3 prirodna klastera normalnog saobraćaja) i dodajmo nekoliko tačaka anomalija. Zatim pokrećemo t-SNE i (konceptualno) vizualizujemo rezultate.
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
Ovde smo kombinovali naš prethodni 4D normalni skup podataka sa nekoliko ekstremnih outliera (outlieri imaju jednu karakteristiku (“trajanje”) postavljenu veoma visoko, itd., da simuliraju neobičan obrazac). Pokrećemo t-SNE sa tipičnom perplexity od 30. Izlazni data_2d ima oblik (1505, 2). U ovom tekstu zapravo nećemo praviti grafikon, ali ako bismo to uradili, očekivali bismo da vidimo možda tri uska klastera koja odgovaraju 3 normalna klastera, a 5 outliera se pojavljuje kao izolovane tačke daleko od tih klastera. U interaktivnom radnom toku, mogli bismo obojiti tačke prema njihovoj oznaci (normalno ili koji klaster, naspram anomalije) da bismo potvrdili ovu strukturu. Čak i bez oznaka, analitičar bi mogao primetiti tih 5 tačaka koje se nalaze u praznom prostoru na 2D grafiku i označiti ih. Ovo pokazuje kako t-SNE može biti moćna pomoć u vizuelnoj detekciji anomalija i inspekciji klastera u podacima o sajber bezbednosti, dopunjujući automatizovane algoritme iznad.

</details>


{{#include ../banners/hacktricks-training.md}}
