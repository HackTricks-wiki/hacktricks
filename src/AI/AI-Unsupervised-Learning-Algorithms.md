# Algorytmy uczenia nienadzorowanego

{{#include ../banners/hacktricks-training.md}}

## Uczenie nienadzorowane

Uczenie nienadzorowane to rodzaj machine learning, w którym model jest trenowany na danych bez oznaczonych odpowiedzi. Celem jest znalezienie wzorców, struktur lub zależności w danych. W przeciwieństwie do uczenia nadzorowanego, w którym model uczy się na oznaczonych przykładach, algorytmy uczenia nienadzorowanego pracują z nieoznaczonymi danymi.
Uczenie nienadzorowane jest często używane do takich zadań jak klasteryzacja, redukcja wymiarowości i wykrywanie anomalii. Może pomóc odkrywać ukryte wzorce w danych, grupować podobne elementy lub zmniejszać złożoność danych przy zachowaniu ich najważniejszych cech.


### Klasteryzacja K-Means

K-Means to algorytm klasteryzacji oparty na centroidach, który dzieli dane na K klastrów, przypisując każdy punkt do najbliższej średniej klastra. Algorytm działa następująco:
1. **Inicjalizacja**: Wybierz K początkowych centrów klastrów (centroidów), często losowo lub za pomocą bardziej zaawansowanych metod, takich jak k-means++
2. **Przypisanie**: Przypisz każdy punkt danych do najbliższego centroidu na podstawie metryki odległości (np. odległości euklidesowej).
3. **Aktualizacja**: Przelicz centroidy, wyznaczając średnią ze wszystkich punktów danych przypisanych do każdego klastra.
4. **Powtórzenie**: Kroki 2–3 są powtarzane do momentu ustabilizowania się przypisań do klastrów (centroidy przestają znacząco się przemieszczać).

> [!TIP]
> *Zastosowania w cyberbezpieczeństwie:* K-Means jest używany do wykrywania włamań poprzez klasteryzację zdarzeń sieciowych. Przykładowo badacze zastosowali K-Means do zbioru danych dotyczących włamań KDD Cup 99 i stwierdzili, że skutecznie dzielił ruch na klastry normalnego ruchu i ataków. W praktyce analitycy bezpieczeństwa mogą klasteryzować wpisy dzienników lub dane dotyczące zachowania użytkowników, aby znaleźć grupy podobnej aktywności; punkty, które nie należą do dobrze uformowanego klastra, mogą wskazywać anomalie (np. nowy wariant malware tworzący własny mały klaster). K-Means może również pomóc w klasyfikacji rodzin malware poprzez grupowanie plików binarnych na podstawie profili zachowania lub wektorów cech.

#### Wybór K
Liczba klastrów (K) to hiperparametr, który należy zdefiniować przed uruchomieniem algorytmu. Techniki takie jak metoda łokcia (Elbow Method) lub Silhouette Score mogą pomóc określić odpowiednią wartość K poprzez ocenę jakości klasteryzacji:

- **Metoda łokcia (Elbow Method)**: Narysuj wykres sumy kwadratów odległości każdego punktu od przypisanego mu centroidu klastra w funkcji K. Poszukaj punktu „łokcia”, w którym tempo spadku gwałtownie się zmienia, co wskazuje odpowiednią liczbę klastrów.
- **Silhouette Score**: Oblicz silhouette score dla różnych wartości K. Wyższy silhouette score wskazuje lepiej zdefiniowane klastry.

#### Założenia i ograniczenia

K-Means zakłada, że **klastry są sferyczne i mają jednakowy rozmiar**, co może nie być prawdą dla wszystkich zbiorów danych. Jest wrażliwy na początkowe rozmieszczenie centroidów i może zbiegać do minimów lokalnych. Ponadto K-Means nie nadaje się do zbiorów danych o różnej gęstości lub nieglobularnych kształtach oraz cechach o różnych skalach. Kroki wstępnego przetwarzania, takie jak normalizacja lub standaryzacja, mogą być konieczne, aby zapewnić równy udział wszystkich cech w obliczeniach odległości.

<details>
<summary>Przykład -- Klasteryzacja zdarzeń sieciowych
</summary>
Poniżej symulujemy dane dotyczące ruchu sieciowego i używamy K-Means do ich klasteryzacji. Załóżmy, że mamy zdarzenia z cechami takimi jak czas trwania połączenia i liczba bajtów. Tworzymy 3 klastry „normalnego” ruchu oraz 1 mały klaster reprezentujący wzorzec ataku. Następnie uruchamiamy K-Means, aby sprawdzić, czy rozdzieli te grupy.
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
W tym przykładzie K-Means powinien znaleźć 4 klastry. Mały klaster ataków (z nietypowo wysokim czasem trwania ~200) powinien idealnie utworzyć własny klaster ze względu na odległość od normalnych klastrów. Wypisujemy rozmiary i środki klastrów, aby zinterpretować wyniki. W rzeczywistym scenariuszu można oznaczyć klaster z niewielką liczbą punktów jako potencjalne anomalie lub przeanalizować jego elementy pod kątem złośliwej aktywności.
</details>

### Klasteryzacja hierarchiczna

Klasteryzacja hierarchiczna tworzy hierarchię klastrów, wykorzystując podejście oddolne (agglomerative) lub odgórne (divisive):

1. **Agglomerative (Bottom-Up)**: Rozpocznij od potraktowania każdego punktu danych jako osobnego klastra i iteracyjnie łącz najbliższe klastry, aż pozostanie jeden klaster lub zostanie spełnione kryterium zatrzymania.
2. **Divisive (Top-Down)**: Rozpocznij od umieszczenia wszystkich punktów danych w jednym klastrze i iteracyjnie dziel klastry, aż każdy punkt danych będzie własnym klastrem lub zostanie spełnione kryterium zatrzymania.

Klasteryzacja agglomerative wymaga zdefiniowania odległości między klastrami oraz kryterium linkage, które decyduje o tym, które klastry należy połączyć. Typowe metody linkage obejmują single linkage (odległość między najbliższymi punktami dwóch klastrów), complete linkage (odległość między najbardziej oddalonymi punktami), average linkage itd., a metryką odległości jest często odległość euklidesowa. Wybór linkage wpływa na kształt tworzonych klastrów. Nie ma potrzeby wcześniejszego określania liczby klastrów K; można „przeciąć” dendrogram na wybranym poziomie, aby uzyskać żądaną liczbę klastrów.

Klasteryzacja hierarchiczna tworzy dendrogram, czyli strukturę przypominającą drzewo, która pokazuje relacje między klastrami na różnych poziomach szczegółowości. Dendrogram można przeciąć na wybranym poziomie, aby uzyskać określoną liczbę klastrów.

> [!TIP]
> *Przypadki użycia w cybersecurity:* Klasteryzacja hierarchiczna może uporządkować zdarzenia lub encje w drzewie, aby ułatwić wykrywanie relacji. Na przykład w analizie malware klasteryzacja agglomerative może grupować próbki według podobieństwa zachowania, ujawniając hierarchię rodzin i wariantów malware. W network security można grupować przepływy ruchu IP i używać dendrogramu do obserwowania podgrup ruchu (np. najpierw według protokołu, a następnie według zachowania). Ponieważ nie trzeba z góry wybierać K, rozwiązanie to jest przydatne podczas analizowania nowych danych, dla których liczba kategorii ataków jest nieznana.

#### Założenia i ograniczenia

Klasteryzacja hierarchiczna nie zakłada określonego kształtu klastra i może wykrywać klastry zagnieżdżone. Jest przydatna do odkrywania taksonomii lub relacji między grupami (np. grupowania malware według podgrup rodzin). Jest deterministyczna, więc nie występują problemy związane z losową inicjalizacją. Kluczową zaletą jest dendrogram, który zapewnia wgląd w strukturę klasteryzacji danych na wszystkich poziomach — analitycy security mogą określić odpowiedni punkt odcięcia w celu zidentyfikowania znaczących klastrów. Jednak rozwiązanie to jest kosztowne obliczeniowo (zwykle $O(n^2)$ lub gorzej w przypadku naiwnych implementacji) i nie nadaje się do bardzo dużych zbiorów danych. Jest również procedurą zachłanną — po wykonaniu połączenia lub podziału nie można go cofnąć, co może prowadzić do suboptymalnych klastrów, jeśli błąd wystąpi na wczesnym etapie. Outliery mogą także wpływać na niektóre strategie linkage (single-link może powodować efekt „łańcucha”, w którym klastry łączą się za pośrednictwem outlierów).

<details>
<summary>Przykład -- Agglomerative Clustering zdarzeń
</summary>

Ponownie wykorzystamy syntetyczne dane z przykładu K-Means (3 normalne klastry + 1 klaster ataków) i zastosujemy klasteryzację agglomerative. Następnie pokażemy, jak uzyskać dendrogram i etykiety klastrów.
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

DBSCAN to algorytm klasteryzacji oparty na gęstości, który grupuje punkty znajdujące się blisko siebie, oznaczając jednocześnie punkty w obszarach o małej gęstości jako wartości odstające. Jest szczególnie przydatny w przypadku zbiorów danych o różnej gęstości i niesferycznych kształtach.

DBSCAN działa poprzez zdefiniowanie dwóch parametrów:
- **Epsilon (ε)**: Maksymalna odległość między dwoma punktami, aby mogły zostać uznane za należące do tego samego klastra.
- **MinPts**: Minimalna liczba punktów wymagana do utworzenia gęstego obszaru (punktu rdzeniowego).

DBSCAN identyfikuje punkty rdzeniowe, punkty brzegowe i punkty szumu:
- **Punkt rdzeniowy**: Punkt mający co najmniej MinPts sąsiadów w odległości ε.
- **Punkt brzegowy**: Punkt znajdujący się w odległości ε od punktu rdzeniowego, ale mający mniej niż MinPts sąsiadów.
- **Punkt szumu**: Punkt, który nie jest ani punktem rdzeniowym, ani punktem brzegowym.

Klasteryzacja rozpoczyna się od wybrania nieodwiedzonego punktu rdzeniowego i oznaczenia go jako nowego klastra, a następnie rekurencyjnego dodawania wszystkich punktów osiągalnych z niego pod względem gęstości (punktów rdzeniowych i ich sąsiadów itd.). Punkty brzegowe są dodawane do klastra pobliskiego punktu rdzeniowego. Po rozszerzeniu klastra o wszystkie osiągalne punkty DBSCAN przechodzi do kolejnego nieodwiedzonego punktu rdzeniowego, aby rozpocząć nowy klaster. Punkty, do których nie dotarł żaden punkt rdzeniowy, pozostają oznaczone jako szum.

> [!TIP]
> *Zastosowania w cyberbezpieczeństwie:* DBSCAN jest przydatny do wykrywania anomalii w ruchu sieciowym. Na przykład normalna aktywność użytkowników może tworzyć jeden lub więcej gęstych klastrów w przestrzeni cech, podczas gdy nowe zachowania atakujących pojawiają się jako rozproszone punkty, które DBSCAN oznaczy jako szum (wartości odstające). Algorytm ten był używany do klasteryzacji rekordów przepływów sieciowych, gdzie może wykrywać skanowanie portów lub ruch związany z denial-of-service jako rzadkie obszary punktów. Innym zastosowaniem jest grupowanie wariantów malware: jeśli większość próbek tworzy klastry według rodzin, ale kilka nie pasuje do żadnego z nich, mogą to być malware typu zero-day. Możliwość oznaczania szumu pozwala zespołom bezpieczeństwa skupić się na analizie tych wartości odstających.

#### Założenia i ograniczenia

**Założenia i zalety:** DBSCAN nie zakłada sferycznego kształtu klastrów – może znajdować klastry o dowolnych kształtach (nawet przypominające łańcuchy lub sąsiadujące ze sobą). Automatycznie określa liczbę klastrów na podstawie gęstości danych i skutecznie identyfikuje wartości odstające jako szum. Dzięki temu dobrze sprawdza się w przypadku rzeczywistych danych o nieregularnych kształtach i zawierających szum. Jest odporny na wartości odstające (w przeciwieństwie do K-Means, który wymusza przypisanie ich do klastrów). Działa dobrze, gdy klastry mają w przybliżeniu równomierną gęstość.

**Ograniczenia**: Wydajność DBSCAN zależy od dobrania odpowiednich wartości ε i MinPts. Algorytm może mieć problemy z danymi o różnej gęstości – pojedyncza wartość ε nie jest w stanie obsłużyć jednocześnie gęstych i rzadkich klastrów. Jeśli ε jest zbyt małe, większość punktów zostanie oznaczona jako szum; jeśli jest zbyt duże, klastry mogą zostać nieprawidłowo połączone. Ponadto DBSCAN może być nieefektywny w przypadku bardzo dużych zbiorów danych (naiwnie $O(n^2)$, choć indeksowanie przestrzenne może pomóc). W przestrzeniach cech o wysokim wymiarze koncepcja „odległości w granicach ε” może mieć mniejsze znaczenie (klątwa wymiarowości), a DBSCAN może wymagać starannego dostrojenia parametrów lub może nie znajdować intuicyjnych klastrów. Mimo to rozszerzenia takie jak HDBSCAN rozwiązują niektóre problemy (np. różną gęstość).

<details>
<summary>Przykład -- Klasteryzacja z szumem
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
W tym fragmencie dostosowaliśmy `eps` i `min_samples` do skali naszych danych (15.0 w jednostkach cech oraz wymaganie 5 punktów do utworzenia klastra). DBSCAN powinien znaleźć 2 klastry (klastry normalnego ruchu) i oznaczyć 5 wstrzykniętych wartości odstających jako szum. Wyświetlamy liczbę klastrów i punktów szumu, aby to zweryfikować. W rzeczywistym środowisku można iterować po ε (wykorzystując heurystykę wykresu k-distance do wyboru ε) i MinPts (często przyjmowane jako około wymiarowość danych + 1, zgodnie z praktyczną regułą), aby znaleźć stabilne wyniki klasteryzacji. Możliwość jawnego oznaczania szumu pomaga oddzielić potencjalne dane związane z atakiem do dalszej analizy.

</details>

### Principal Component Analysis (PCA)

PCA to technika **redukcji wymiarowości**, która znajduje nowy zestaw ortogonalnych osi (głównych składowych) przechwytujących maksymalną wariancję w danych. Mówiąc prościej, PCA obraca i rzutuje dane na nowy układ współrzędnych w taki sposób, że pierwsza główna składowa (PC1) wyjaśnia największą możliwą wariancję, druga składowa (PC2) wyjaśnia największą wariancję ortogonalną względem PC1 itd. Matematycznie PCA oblicza wektory własne macierzy kowariancji danych – wektory te są kierunkami głównych składowych, a odpowiadające im wartości własne wskazują ilość wariancji wyjaśnianej przez każdą z nich. PCA jest często używane do ekstrakcji cech, wizualizacji i redukcji szumu.

Należy zauważyć, że jest to przydatne, jeśli wymiary zbioru danych zawierają **znaczące zależności liniowe lub korelacje**.

PCA działa poprzez identyfikację głównych składowych danych, czyli kierunków maksymalnej wariancji. Etapy PCA obejmują:
1. **Standaryzacja**: Wycentruj dane, odejmując średnią, i przeskaluj je do wariancji równej jeden.
2. **Macierz kowariancji**: Oblicz macierz kowariancji standaryzowanych danych, aby zrozumieć zależności między cechami.
3. **Rozkład według wartości własnych**: Wykonaj rozkład według wartości własnych na macierzy kowariancji, aby uzyskać wartości własne i wektory własne.
4. **Wybór głównych składowych**: Posortuj wartości własne malejąco i wybierz K najważniejszych wektorów własnych odpowiadających największym wartościom własnym. Wektory te tworzą nową przestrzeń cech.
5. **Transformacja danych**: Zrzutuj oryginalne dane na nową przestrzeń cech, używając wybranych głównych składowych.
PCA jest szeroko stosowane do wizualizacji danych, redukcji szumu oraz jako etap wstępnego przetwarzania dla innych algorytmów machine learning. Pomaga zmniejszyć wymiarowość danych przy jednoczesnym zachowaniu ich istotnej struktury.

#### Wartości własne i wektory własne

Wartość własna jest skalarem wskazującym ilość wariancji przechwyconej przez odpowiadający jej wektor własny. Wektor własny reprezentuje kierunek w przestrzeni cech, wzdłuż którego dane zmieniają się najbardziej.

Wyobraźmy sobie, że A jest macierzą kwadratową, a v jest niezerowym wektorem spełniającym: `A * v = λ * v`
gdzie:
- A jest macierzą kwadratową, taką jak [ [1, 2], [2, 1]] (np. macierzą kowariancji)
- v jest wektorem własnym (np. [1, 1])

Wtedy `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, co będzie wartością własną λ pomnożoną przez wektor własny v, dlatego wartość własna λ = 3.

#### Wartości własne i wektory własne w PCA

Wyjaśnijmy to na przykładzie. Wyobraźmy sobie, że mamy zbiór danych zawierający wiele obrazów twarzy w odcieniach szarości o rozmiarze 100x100 pikseli. Każdy piksel można uznać za cechę, więc mamy 10 000 cech na obraz (lub wektor 10000 składowych na obraz). Jeśli chcemy zmniejszyć wymiarowość tego zbioru danych za pomocą PCA, wykonamy następujące kroki:

1. **Standaryzacja**: Wycentruj dane, odejmując od zbioru danych średnią każdej cechy (piksela).
2. **Macierz kowariancji**: Oblicz macierz kowariancji standaryzowanych danych, która pokazuje, jak cechy (piksele) zmieniają się wspólnie.
- Należy zauważyć, że kowariancja między dwiema zmiennymi (w tym przypadku pikselami) wskazuje, w jakim stopniu zmieniają się one razem, więc chodzi tutaj o ustalenie, które piksele mają tendencję do wspólnego zwiększania lub zmniejszania się w ramach zależności liniowej.
- Na przykład jeśli piksel 1 i piksel 2 mają tendencję do wspólnego zwiększania się, kowariancja między nimi będzie dodatnia.
- Macierz kowariancji będzie macierzą 10,000x10,000, w której każdy wpis reprezentuje kowariancję między dwiema pikselami.
3. **Rozwiązanie równania wartości własnych**: Równanie wartości własnych do rozwiązania to `C * v = λ * v`, gdzie C jest macierzą kowariancji, v jest wektorem własnym, a λ jest wartością własną. Można je rozwiązać za pomocą metod takich jak:
- **Rozkład według wartości własnych**: Wykonaj rozkład według wartości własnych na macierzy kowariancji, aby uzyskać wartości własne i wektory własne.
- **Singular Value Decomposition (SVD)**: Alternatywnie można użyć SVD do rozłożenia macierzy danych na wartości i wektory singularne, co również może doprowadzić do uzyskania głównych składowych.
4. **Wybór głównych składowych**: Posortuj wartości własne malejąco i wybierz K najważniejszych wektorów własnych odpowiadających największym wartościom własnym. Wektory te reprezentują kierunki maksymalnej wariancji w danych.

> [!TIP]
> *Przypadki użycia w cyberbezpieczeństwie:* Częstym zastosowaniem PCA w security jest redukcja cech na potrzeby wykrywania anomalii. Na przykład system intrusion detection zawierający ponad 40 metryk sieciowych (takich jak cechy NSL-KDD) może użyć PCA do zredukowania ich do kilku składowych, podsumowując dane na potrzeby wizualizacji lub przekazania do algorytmów klasteryzacji. Analitycy mogą wykreślić ruch sieciowy w przestrzeni dwóch pierwszych głównych składowych, aby sprawdzić, czy ataki oddzielają się od normalnego ruchu. PCA może również pomóc wyeliminować redundantne cechy (takie jak liczba wysłanych i odebranych bajtów, jeśli są skorelowane), dzięki czemu algorytmy wykrywania będą bardziej odporne i szybsze.

#### Założenia i ograniczenia

PCA zakłada, że **główne osie wariancji mają znaczenie** – jest to metoda liniowa, więc przechwytuje liniowe korelacje w danych. Jest nienadzorowane, ponieważ wykorzystuje wyłącznie kowariancję cech. Zalety PCA obejmują redukcję szumu (składowe o małej wariancji często odpowiadają szumowi) oraz decorrelation cech. Jest wydajne obliczeniowo dla umiarkowanie dużych wymiarów i często stanowi przydatny etap wstępnego przetwarzania dla innych algorytmów (pozwalający ograniczyć curse of dimensionality). Jednym z ograniczeń jest to, że PCA jest ograniczone do zależności liniowych – nie przechwytuje złożonej struktury nieliniowej (w przeciwieństwie do autoenkoderów lub t-SNE). Ponadto składowe PCA mogą być trudne do zinterpretowania w kontekście oryginalnych cech (są kombinacjami cech oryginalnych). W cyberbezpieczeństwie należy zachować ostrożność: atak powodujący jedynie subtelną zmianę cechy o małej wariancji może nie pojawić się w najważniejszych składowych głównych (ponieważ PCA priorytetyzuje wariancję, a niekoniecznie „interesującość”).

<details>
<summary>Przykład -- Redukcja wymiarów danych sieciowych
</summary>

Załóżmy, że mamy logi połączeń sieciowych zawierające wiele cech (np. czasy trwania, liczbę bajtów i liczniki). Wygenerujemy syntetyczny zbiór danych o 4 wymiarach (z pewną korelacją między cechami) i użyjemy PCA do zredukowania go do 2 wymiarów na potrzeby wizualizacji lub dalszej analizy.
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
Tutaj wzięliśmy wcześniejsze klastry normalnego ruchu i rozszerzyliśmy każdy punkt danych o dwie dodatkowe cechy (pakiety i błędy), które korelują z liczbą bajtów i czasem trwania. Następnie PCA służy do skompresowania 4 cech do 2 głównych składowych. Wyświetlamy stosunek wyjaśnionej wariancji, który może pokazać, że na przykład >95% wariancji jest uchwycone przez 2 składowe (co oznacza niewielką utratę informacji). Wynik pokazuje również zmniejszenie kształtu danych z (1500, 4) do (1500, 2). Pierwsze kilka punktów w przestrzeni PCA podano jako przykład. W praktyce można narysować data_2d, aby wizualnie sprawdzić, czy klastry są rozróżnialne. Jeśli występowałaby anomalia, można byłoby zobaczyć ją jako punkt oddalony od głównego klastra w przestrzeni PCA. PCA pomaga więc sprowadzić złożone dane do formy łatwiejszej do interpretacji przez człowieka lub wykorzystania jako dane wejściowe dla innych algorytmów.

</details>


### Gaussian Mixture Models (GMM)

Gaussian Mixture Model zakłada, że dane są generowane przez mieszaninę **kilku rozkładów Gaussa (normalnych) o nieznanych parametrach**. W istocie jest to probabilistyczny model klasteryzacji: próbuje on w sposób miękki przypisać każdy punkt do jednego z K komponentów gaussowskich. Każdy komponent gaussowski k ma wektor średniej (μ_k), macierz kowariancji (Σ_k) oraz wagę mieszania (π_k), która określa, jak liczny jest dany klaster. W przeciwieństwie do K-Means, który wykonuje przypisania „twarde”, GMM przypisuje każdemu punktowi prawdopodobieństwo przynależności do każdego klastra.

Dopasowanie GMM zazwyczaj odbywa się za pomocą algorytmu Expectation-Maximization (EM):

- **Inicjalizacja**: Rozpocznij od początkowych wartości średnich, macierzy kowariancji i współczynników mieszania (lub użyj wyników K-Means jako punktu wyjścia).

- **E-step (Expectation)**: Dla bieżących parametrów oblicz odpowiedzialność każdego klastra za każdy punkt: zasadniczo `r_nk = P(z_k | x_n)`, gdzie z_k to zmienna ukryta wskazująca przynależność do klastra dla punktu x_n. Odbywa się to z użyciem twierdzenia Bayesa, za pomocą obliczenia posteriorowego prawdopodobieństwa przynależności każdego punktu do każdego klastra na podstawie bieżących parametrów. Odpowiedzialności są obliczane następująco:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
gdzie:
- \( \pi_k \) to współczynnik mieszania dla klastra k (a priori prawdopodobieństwo klastra k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) to funkcja gęstości prawdopodobieństwa Gaussa dla punktu \( x_n \) przy średniej \( \mu_k \) i kowariancji \( \Sigma_k \).

- **M-step (Maximization)**: Zaktualizuj parametry, korzystając z odpowiedzialności obliczonych w E-step:
- Zaktualizuj każdą średnią μ_k jako średnią ważoną punktów, gdzie wagami są odpowiedzialności.
- Zaktualizuj każdą kowariancję Σ_k jako ważoną kowariancję punktów przypisanych do klastra k.
- Zaktualizuj współczynniki mieszania π_k jako średnią odpowiedzialność dla klastra k.

- **Iteruj** kroki E i M do momentu osiągnięcia zbieżności (ustabilizowania parametrów lub spadku poprawy wiarygodności poniżej określonego progu).

Wynikiem jest zestaw rozkładów Gaussa, które wspólnie modelują ogólny rozkład danych. Dopasowanego GMM można użyć do klasteryzacji, przypisując każdy punkt do Gaussa o najwyższym prawdopodobieństwie, albo zachować prawdopodobieństwa w celu uwzględnienia niepewności. Można również oceniać wiarygodność nowych punktów, aby sprawdzić, czy pasują do modelu (co jest przydatne w anomaly detection).

> [!TIP]
> *Przypadki użycia w cybersecurity:* GMM może być używany do anomaly detection poprzez modelowanie rozkładu normalnych danych: każdy punkt o bardzo niskim prawdopodobieństwie w ramach wyuczonej mieszaniny jest oznaczany jako anomalia. Można na przykład wytrenować GMM na cechach prawidłowego ruchu sieciowego; połączenie będące częścią ataku, które nie przypomina żadnego wyuczonego klastra, miałoby niską wiarygodność. GMM są również używane do klasteryzacji aktywności, w przypadku których klastry mogą mieć różne kształty — np. do grupowania użytkowników według profili zachowań, gdzie cechy każdego profilu mogą mieć charakter zbliżony do gaussowskiego, ale własną strukturę wariancji. Inny scenariusz: w phishing detection cechy prawidłowych wiadomości e-mail mogą tworzyć jeden klaster gaussowski, znany phishing drugi, a nowe kampanie phishingowe mogą pojawić się jako osobny Gauss lub jako punkty o niskiej wiarygodności względem istniejącej mieszaniny.

#### Założenia i ograniczenia

GMM jest uogólnieniem K-Means, które uwzględnia kowariancję, dzięki czemu klastry mogą być elipsoidalne (a nie tylko sferyczne). Przy pełnej kowariancji obsługuje klastry o różnych rozmiarach i kształtach. Miękka klasteryzacja jest zaletą, gdy granice klastrów są niejednoznaczne — np. w cybersecurity zdarzenie może mieć cechy kilku typów ataków; GMM może odzwierciedlać tę niepewność za pomocą prawdopodobieństw. GMM zapewnia również probabilistyczne modelowanie gęstości danych, przydatne do wykrywania wartości odstających (punktów o niskiej wiarygodności względem wszystkich komponentów mieszaniny).

Z drugiej strony GMM wymaga określenia liczby komponentów K (można jednak użyć kryteriów takich jak BIC/AIC do jej wyboru). EM może czasami zbiegać powoli lub do optimum lokalnego, dlatego inicjalizacja jest istotna (często EM uruchamia się wielokrotnie). Jeśli dane w rzeczywistości nie są zgodne z mieszaniną rozkładów Gaussa, model może być słabo dopasowany. Istnieje również ryzyko, że jeden Gauss skurczy się, aby obejmować tylko wartość odstającą (można temu przeciwdziałać przez regularyzację lub ograniczenia minimalnej kowariancji).


<details>
<summary>Przykład -- Miękka klasteryzacja i wyniki anomalii
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
W tym kodzie trenujemy GMM z 3 rozkładami Gaussa na normalnym ruchu (zakładając, że znamy 3 profile legalnego ruchu). Wydrukowane średnie i macierze kowariancji opisują te klastry (na przykład jedna średnia może wynosić około [50,500], co odpowiada centrum jednego z klastrów itd.). Następnie testujemy podejrzane połączenie [duration=200, bytes=800]. Funkcja predict_proba zwraca prawdopodobieństwo przynależności tego punktu do każdego z 3 klastrów – oczekiwalibyśmy, że prawdopodobieństwa te będą bardzo niskie lub silnie niezrównoważone, ponieważ [200,800] leży daleko od normalnych klastrów. Wyświetlany jest również ogólny score_samples (log-likelihood); bardzo niska wartość wskazuje, że punkt słabo pasuje do modelu, co pozwala oznaczyć go jako anomalię. W praktyce można ustawić próg dla log-likelihood (lub maksymalnego prawdopodobieństwa), aby zdecydować, czy punkt jest wystarczająco mało prawdopodobny, by uznać go za malicious. GMM zapewnia więc uzasadniony sposób przeprowadzania anomaly detection, a także tworzy miękkie klastry uwzględniające niepewność.
</details>

### Isolation Forest

**Isolation Forest** to ensemble anomaly detection algorithm oparty na idei losowego izolowania punktów. Zasada jest taka, że anomalie są nieliczne i różnią się od pozostałych, dlatego można je łatwiej izolować niż normalne punkty. Isolation Forest tworzy wiele binarnych drzew izolacji (losowych drzew decyzyjnych), które losowo dzielą dane. W każdym węźle drzewa wybierana jest losowa cecha oraz losowa wartość podziału znajdująca się między minimum a maksimum tej cechy dla danych w danym węźle. Podział dzieli dane na dwie gałęzie. Drzewo jest rozbudowywane do momentu, gdy każdy punkt zostanie odizolowany we własnym liściu lub osiągnięta zostanie maksymalna wysokość drzewa.

Anomaly detection odbywa się poprzez obserwowanie długości ścieżki każdego punktu w tych losowych drzewach – liczby podziałów wymaganych do odizolowania punktu. Intuicyjnie anomalie (outliers) są zwykle izolowane szybciej, ponieważ losowy podział z większym prawdopodobieństwem oddzieli outliera (znajdującego się w rzadkim regionie) niż normalny punkt należący do gęstego klastra. Isolation Forest oblicza anomaly score na podstawie średniej długości ścieżki ze wszystkich drzew: krótsza średnia ścieżka → większe prawdopodobieństwo anomalii. Wyniki są zwykle normalizowane do zakresu [0,1], gdzie 1 oznacza bardzo prawdopodobną anomalię.

> [!TIP]
> *Use cases w cybersecurity:* Isolation Forests są z powodzeniem wykorzystywane w intrusion detection i fraud detection. Na przykład można wytrenować Isolation Forest na logach ruchu sieciowego zawierających głównie normalne zachowanie; forest utworzy krótkie ścieżki dla nietypowego ruchu (takiego jak adres IP używający niespotykanego portu lub nietypowego wzorca rozmiarów pakietów), oznaczając go do dalszej analizy. Ponieważ nie wymaga oznaczonych ataków, nadaje się do wykrywania nieznanych typów ataków. Można go również wdrożyć na danych dotyczących logowań użytkowników w celu wykrywania przejęć kont (nietypowe godziny lub lokalizacje logowań są szybko izolowane). W jednym z zastosowań Isolation Forest może chronić przedsiębiorstwo poprzez monitorowanie metryk systemowych i generowanie alertu, gdy kombinacja metryk (CPU, sieć, zmiany plików) znacznie różni się od historycznych wzorców (krótkie ścieżki izolacji).

#### Założenia i ograniczenia

**Zalety**: Isolation Forest nie wymaga przyjmowania założeń dotyczących rozkładu; bezpośrednio koncentruje się na izolowaniu punktów. Jest wydajny dla danych o dużej liczbie wymiarów i dużych zbiorów danych (złożoność liniowa $O(n\log n)$ podczas budowania forest), ponieważ każde drzewo izoluje punkty, używając tylko podzbioru cech i podziałów. Zwykle dobrze radzi sobie z cechami numerycznymi i może być szybszy niż metody oparte na odległości, które mogą mieć złożoność $O(n^2)$. Automatycznie generuje również anomaly score, dzięki czemu można ustawić próg dla alertów (lub użyć parametru contamination, aby automatycznie określić cutoff na podstawie oczekiwanego odsetka anomalii).

**Ograniczenia**: Ze względu na losowy charakter wyniki mogą nieznacznie różnić się między uruchomieniami (choć przy wystarczającej liczbie drzew różnica ta jest niewielka). Jeśli dane zawierają wiele nieistotnych cech lub anomalie nie różnią się wyraźnie pod względem żadnej cechy, izolowanie może nie być skuteczne (losowe podziały mogą przypadkowo izolować normalne punkty – jednak uśrednianie wyników z wielu drzew ogranicza ten problem). Ponadto Isolation Forest zazwyczaj zakłada, że anomalie stanowią niewielką mniejszość (co zwykle jest prawdą w scenariuszach cybersecurity).

<details>
<summary>Przykład -- Wykrywanie wartości odstających w logach sieciowych
</summary>

Użyjemy wcześniejszego testowego zbioru danych (zawierającego normalne punkty oraz niektóre punkty reprezentujące ataki) i uruchomimy Isolation Forest, aby sprawdzić, czy potrafi oddzielić ataki. Założymy, że około 15% danych powinno być anomalne (na potrzeby demonstracji).
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
W tym kodzie tworzymy instancję `IsolationForest` ze 100 drzewami i ustawiamy `contamination=0.15` (co oznacza, że oczekujemy około 15% anomalii; model ustawi próg wyniku tak, aby oznaczyć około 15% punktów). Dopasowujemy ją do `X_test_if`, które zawiera mieszankę punktów normalnych i punktów reprezentujących ataki (uwaga: zwykle model byłby dopasowywany do danych treningowych, a następnie używany za pomocą `predict` na nowych danych, ale tutaj, dla ilustracji, dopasowujemy go i wykonujemy predykcję na tym samym zbiorze, aby bezpośrednio zaobserwować wyniki).

Dane wyjściowe pokazują przewidywane etykiety dla pierwszych 20 punktów (gdzie `-1` oznacza anomalię). Wypisujemy również całkowitą liczbę wykrytych anomalii oraz przykładowe wyniki anomalii. Oczekiwalibyśmy, że około 18 ze 120 punktów zostanie oznaczonych jako `-1` (ponieważ `contamination` wynosiło 15%). Jeśli 20 próbek ataków rzeczywiście znajduje się najbardziej poza rozkładem, większość z nich powinna pojawić się wśród tych predykcji `-1`. Wynik anomalii (funkcja `decision function` algorytmu Isolation Forest) jest wyższy dla punktów normalnych i niższy (bardziej ujemny) dla anomalii — wypisujemy kilka wartości, aby zobaczyć separację. W praktyce można posortować dane według wyniku, aby znaleźć najbardziej odstające punkty i je zbadać. Isolation Forest zapewnia zatem wydajny sposób przesiewania dużych, nieetykietowanych zbiorów danych związanych z bezpieczeństwem oraz wybierania najbardziej nieregularnych przypadków do analizy przez człowieka lub dalszej automatycznej kontroli.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** to nieliniowa technika redukcji wymiarów, zaprojektowana specjalnie do wizualizacji danych wielowymiarowych w 2 lub 3 wymiarach. Przekształca podobieństwa między punktami danych w łączne rozkłady prawdopodobieństwa i stara się zachować strukturę lokalnych sąsiedztw w projekcji o mniejszej liczbie wymiarów. Mówiąc prościej, t-SNE rozmieszcza punkty (na przykład) w 2D w taki sposób, aby podobne punkty (w przestrzeni oryginalnej) znalazły się blisko siebie, a różne punkty z dużym prawdopodobieństwem znalazły się daleko od siebie.

Algorytm składa się z głównych etapów:

1. **Obliczanie podobieństw par punktów w przestrzeni wielowymiarowej:** Dla każdej pary punktów t-SNE oblicza prawdopodobieństwo, że jeden punkt zostanie wybrany jako sąsiad drugiego (odbywa się to przez wyśrodkowanie rozkładu Gaussa na każdym punkcie i pomiar odległości — parametr perplexity wpływa na efektywną liczbę uwzględnianych sąsiadów).
2. **Obliczanie podobieństw par punktów w przestrzeni o mniejszej liczbie wymiarów (np. 2D):** Początkowo punkty są rozmieszczane losowo w 2D. t-SNE definiuje podobne prawdopodobieństwo dla odległości na tej mapie (używając jądra opartego na rozkładzie t-Studenta, który ma cięższe ogony niż rozkład Gaussa, dzięki czemu odległe punkty mają większą swobodę).
3. **Gradient Descent:** Następnie t-SNE iteracyjnie przesuwa punkty w 2D, aby zminimalizować dywergencję Kullbacka-Leiblera (KL) między rozkładem podobieństw w przestrzeni wielowymiarowej a rozkładem w przestrzeni o mniejszej liczbie wymiarów. Dzięki temu układ 2D możliwie wiernie odzwierciedla strukturę wielowymiarową — punkty, które były blisko siebie w przestrzeni oryginalnej, przyciągają się, a punkty odległe od siebie odpychają się, aż zostanie osiągnięta równowaga.

Rezultatem jest często wizualnie znaczący wykres punktowy, na którym widoczne stają się klastry danych.

> [!TIP]
> *Zastosowania w cybersecurity:* t-SNE jest często używane do **wizualizacji wielowymiarowych danych związanych z bezpieczeństwem na potrzeby analizy przez człowieka**. Na przykład w security operations center analitycy mogą pobrać zbiór zdarzeń zawierający dziesiątki cech (numery portów, częstotliwości, liczby bajtów itd.) i użyć t-SNE do utworzenia wykresu 2D. Ataki mogą tworzyć na tym wykresie własne klastry lub oddzielać się od normalnych danych, dzięki czemu łatwiej je zidentyfikować. t-SNE stosowano do zbiorów danych dotyczących malware w celu wykrywania grup rodzin malware lub do danych o intruzjach sieciowych, gdzie różne typy ataków tworzą wyraźnie odrębne klastry, ułatwiając dalsze badanie. Zasadniczo t-SNE umożliwia dostrzeżenie struktury w danych cyber, która w innym przypadku byłaby nieczytelna.

#### Założenia i ograniczenia

t-SNE świetnie sprawdza się w wizualnym odkrywaniu wzorców. Może ujawnić klastry, podklastry i wartości odstające, których inne metody liniowe (takie jak PCA) mogą nie wykryć. Jest używane w badaniach nad cybersecurity do wizualizacji złożonych danych, takich jak profile zachowania malware lub wzorce ruchu sieciowego. Ponieważ zachowuje strukturę lokalną, dobrze pokazuje naturalne grupowania.

Jednak t-SNE wymaga większych zasobów obliczeniowych (w przybliżeniu $O(n^2)$), dlatego w przypadku bardzo dużych zbiorów danych może wymagać próbkowania. Ma również hiperparametry (perplexity, learning rate, iterations), które mogą wpływać na wynik — na przykład różne wartości perplexity mogą ujawniać klastry w różnych skalach. Wykresy t-SNE mogą być czasami błędnie interpretowane — odległości na mapie nie mają bezpośredniego znaczenia globalnego (metoda skupia się na lokalnym sąsiedztwie, przez co niektóre klastry mogą wydawać się sztucznie dobrze odseparowane). Ponadto t-SNE służy głównie do wizualizacji; nie zapewnia prostego sposobu rzutowania nowych punktów danych bez ponownego obliczania i nie jest przeznaczone do używania jako etap preprocessing w modelowaniu predykcyjnym (UMAP jest alternatywą, która rozwiązuje niektóre z tych problemów dzięki większej szybkości).

<details>
<summary>Przykład -- Wizualizacja połączeń sieciowych
</summary>

Użyjemy t-SNE do zredukowania wielocechowego zbioru danych do 2D. Dla ilustracji weźmy wcześniejsze dane 4D (zawierające 3 naturalne klastry normalnego ruchu) i dodajmy kilka punktów anomalii. Następnie uruchomimy t-SNE i (koncepcyjnie) zwizualizujemy wyniki.
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
Tutaj połączyliśmy nasz wcześniejszy normalny zbiór danych 4D z garścią wartości odstających (w wartościach odstających jedna cecha („duration”) jest ustawiona na bardzo wysoką wartość itd., aby zasymulować nietypowy wzorzec). Uruchamiamy t-SNE z typową wartością perplexity równą 30. Dane wyjściowe `data_2d` mają kształt (1505, 2). W tym tekście faktycznie nie utworzymy wykresu, ale gdybyśmy to zrobili, spodziewalibyśmy się zobaczyć być może trzy zwarte klastry odpowiadające 3 normalnym klastrom oraz 5 wartości odstających występujących jako izolowane punkty, daleko od tych klastrów. W interaktywnym workflow moglibyśmy pokolorować punkty według ich etykiety (normalne lub należące do konkretnego klastra albo anomalia), aby zweryfikować tę strukturę. Nawet bez etykiet analityk mógłby zauważyć te 5 punktów znajdujących się w pustej przestrzeni na wykresie 2D i oznaczyć je do dalszej analizy. Pokazuje to, jak t-SNE może być potężnym wsparciem w wizualnym wykrywaniu anomalii i analizie klastrów w danych cybersecurity, uzupełniając opisane wyżej algorytmy automatyczne.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** to rozszerzenie DBSCAN, które eliminuje potrzebę wyboru jednej globalnej wartości `eps` i umożliwia wykrywanie klastrów o **różnej gęstości** poprzez zbudowanie hierarchii komponentów połączonych gęstościowo, a następnie jej kondensację. W porównaniu ze standardowym DBSCAN zazwyczaj

* wyodrębnia bardziej intuicyjne klastry, gdy niektóre klastry są gęste, a inne rzadkie,
* ma tylko jeden rzeczywisty hyper-parameter (`min_cluster_size`) oraz rozsądną wartość domyślną,
* przypisuje każdemu punktowi *prawdopodobieństwo* przynależności do klastra oraz **outlier score** (`outlier_scores_`), co jest niezwykle przydatne w dashboardach threat-hunting.<sup>[[1]](#references)</sup>

> [!TIP]
> *Zastosowania w cybersecurity:* HDBSCAN jest bardzo popularny we współczesnych pipeline'ach threat-hunting — często można go znaleźć w playbookach huntingowych opartych na notebookach, dostarczanych wraz z komercyjnymi pakietami XDR. Jednym z praktycznych zastosowań jest klastrowanie ruchu HTTP beaconing podczas IR: user-agent, interval i URI length często tworzą kilka zwartych grup legalnych updaterów oprogramowania, podczas gdy beacony C2 pozostają małymi klastrami o niskiej gęstości albo czystym szumem.

<details>
<summary>Przykład – wykrywanie kanałów beaconing C2</summary>
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

### Kwestie odporności i bezpieczeństwa – Poisoning i Adversarial Attacks (2023-2025)

Najnowsze badania wykazały, że **unsupervised learners *nie są* odporne na aktywnych attackerów**:

* **Data-poisoning przeciwko anomaly detectors.** Chen *et al.* (IEEE S&P 2024) wykazali, że dodanie zaledwie 3 % spreparowanego trafficu może przesunąć granicę decyzyjną Isolation Forest i ECOD, przez co rzeczywiste ataki wyglądają jak normalny traffic. Autorzy udostępnili open-source PoC (`udo-poison`), który automatycznie syntetyzuje poison points.<sup>[[2]](#references)</sup>
* **Backdooring clustering models.** Technika *BadCME* (BlackHat EU 2023) wszczepia niewielki trigger pattern; gdy tylko ten trigger się pojawi, detector oparty na K-Means po cichu umieszcza zdarzenie w klastrze „benign”.
* **Evasion DBSCAN/HDBSCAN.** Opublikowany w 2025 r. academic pre-print z KU Leuven wykazał, że attacker może spreparować beaconing patterns, które celowo trafiają w luki gęstości, skutecznie ukrywając się w etykietach *noise*.

Zyskujące popularność mitigations:

1. **Model sanitisation / TRIM.** Przed każdą epoką retrainingu odrzucaj 1–2 % punktów o najwyższym lossie (trimmed maximum likelihood), aby znacząco utrudnić poisoning.
2. **Consensus ensembling.** Połącz kilka heterogenicznych detectorów (np. Isolation Forest + GMM + ECOD) i generuj alert, jeśli *dowolny* model oznaczy punkt. Badania wskazują, że zwiększa to koszt attackera ponad 10-krotnie.
3. **Distance-based defence for clustering.** Przeliczaj klastry z użyciem `k` różnych random seeds i ignoruj punkty, które nieustannie zmieniają klastry.

---

### Nowoczesne Open-Source Tooling (2024-2025)

* **PyOD 2.x** (wydany w maju 2024 r.) dodał detektory *ECOD*, *COPOD* oraz akcelerowany przez GPU *AutoFormer*. Obecnie zawiera sub-command `benchmark`, który pozwala porównać ponad 30 algorytmów na Twoim datasecie za pomocą **jednej linii kodu**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (luty 2025 r.) koncentruje się na vision, ale zawiera również generyczną implementację **PatchCore** – przydatną do wykrywania phishing pages na podstawie screenshotów.
* **scikit-learn 1.5** (listopad 2024 r.) w końcu udostępnia `score_samples` dla *HDBSCAN* za pośrednictwem nowego wrappera `cluster.HDBSCAN`, dzięki czemu podczas korzystania z Python 3.12 nie potrzebujesz zewnętrznego contrib package.

<details>
<summary>Szybki przykład PyOD – ensemble ECOD + Isolation Forest</summary>
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

## Referencje

- [1] [HDBSCAN – Klastrowanie hierarchiczne oparte na gęstości](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* „Podatność nienadzorowanego wykrywania anomalii na zatruwanie danych”. *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
