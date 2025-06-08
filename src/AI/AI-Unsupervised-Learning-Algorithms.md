# Algorytmy Uczenia Nienadzorowanego

{{#include ../banners/hacktricks-training.md}}

## Uczenie Nienadzorowane

Uczenie nienadzorowane to rodzaj uczenia maszynowego, w którym model jest trenowany na danych bez oznaczonych odpowiedzi. Celem jest znalezienie wzorców, struktur lub relacji w danych. W przeciwieństwie do uczenia nadzorowanego, w którym model uczy się na podstawie oznaczonych przykładów, algorytmy uczenia nienadzorowanego pracują z danymi nieoznaczonymi. 
Uczenie nienadzorowane jest często wykorzystywane do zadań takich jak klasteryzacja, redukcja wymiarów i wykrywanie anomalii. Może pomóc w odkrywaniu ukrytych wzorców w danych, grupowaniu podobnych elementów lub redukcji złożoności danych przy jednoczesnym zachowaniu ich istotnych cech.

### Klasteryzacja K-Średnich

K-Średnich to algorytm klasteryzacji oparty na centroidach, który dzieli dane na K klastrów, przypisując każdy punkt do najbliższego średniego klastra. Algorytm działa w następujący sposób:
1. **Inicjalizacja**: Wybierz K początkowych centrów klastrów (centroidów), często losowo lub za pomocą inteligentniejszych metod, takich jak k-średnie++.
2. **Przypisanie**: Przypisz każdy punkt danych do najbliższego centroidu na podstawie metryki odległości (np. odległość euklidesowa).
3. **Aktualizacja**: Przelicz centroidy, biorąc średnią ze wszystkich punktów danych przypisanych do każdego klastra.
4. **Powtórz**: Kroki 2–3 są powtarzane, aż przypisania klastrów się ustabilizują (centroidy przestają się znacząco poruszać).

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* K-Średnich jest używane do wykrywania intruzji poprzez klasteryzację zdarzeń sieciowych. Na przykład, badacze zastosowali K-Średnich do zestawu danych o intruzjach KDD Cup 99 i stwierdzili, że skutecznie podzielił ruch na klastry normalne i atakujące. W praktyce analitycy bezpieczeństwa mogą klasteryzować wpisy dzienników lub dane o zachowaniu użytkowników, aby znaleźć grupy podobnej aktywności; wszelkie punkty, które nie należą do dobrze uformowanego klastra, mogą wskazywać na anomalie (np. nowa odmiana złośliwego oprogramowania tworząca własny mały klaster). K-Średnich może również pomóc w klasyfikacji rodzin złośliwego oprogramowania poprzez grupowanie plików binarnych na podstawie profili zachowań lub wektorów cech.

#### Wybór K
Liczba klastrów (K) jest hiperparametrem, który należy zdefiniować przed uruchomieniem algorytmu. Techniki takie jak Metoda Łokcia lub Wskaźnik Silhouette mogą pomóc w określeniu odpowiedniej wartości dla K, oceniając wydajność klasteryzacji:

- **Metoda Łokcia**: Narysuj sumę kwadratów odległości od każdego punktu do przypisanego centroidu klastra w funkcji K. Szukaj punktu "łokcia", w którym tempo spadku gwałtownie się zmienia, co wskazuje na odpowiednią liczbę klastrów.
- **Wskaźnik Silhouette**: Oblicz wskaźnik silhouette dla różnych wartości K. Wyższy wskaźnik silhouette wskazuje na lepiej zdefiniowane klastry.

#### Założenia i Ograniczenia

K-Średnich zakłada, że **klastry są sferyczne i mają równą wielkość**, co może nie być prawdą dla wszystkich zestawów danych. Jest wrażliwy na początkowe umiejscowienie centroidów i może zbiegać do lokalnych minimów. Dodatkowo, K-Średnich nie jest odpowiedni dla zestawów danych o zmiennej gęstości lub nienałogowych kształtach oraz cechach o różnych skalach. Kroki wstępne, takie jak normalizacja lub standaryzacja, mogą być konieczne, aby zapewnić, że wszystkie cechy przyczyniają się równo do obliczeń odległości.

<details>
<summary>Przykład -- Klasteryzacja Zdarzeń Sieciowych
</summary>
Poniżej symulujemy dane ruchu sieciowego i używamy K-Średnich do ich klasteryzacji. Załóżmy, że mamy zdarzenia z cechami takimi jak czas trwania połączenia i liczba bajtów. Tworzymy 3 klastry "normalnego" ruchu i 1 mały klaster reprezentujący wzór ataku. Następnie uruchamiamy K-Średnich, aby sprawdzić, czy je rozdzieli.
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
W tym przykładzie K-Means powinien znaleźć 4 klastry. Mały klaster ataku (o niezwykle wysokim czasie trwania ~200) idealnie utworzy własny klaster, biorąc pod uwagę jego odległość od normalnych klastrów. Drukujemy rozmiary klastrów i centra, aby zinterpretować wyniki. W rzeczywistym scenariuszu można oznaczyć klaster z kilkoma punktami jako potencjalne anomalie lub zbadać jego członków pod kątem złośliwej aktywności.
</details>

### Klasteryzacja Hierarchiczna

Klasteryzacja hierarchiczna buduje hierarchię klastrów, używając podejścia od dołu do góry (agglomeratywnego) lub od góry do dołu (dzielącego):

1. **Agglomeratywne (Od Dołu do Góry)**: Rozpocznij od każdego punktu danych jako osobnego klastra i iteracyjnie łącz najbliższe klastry, aż pozostanie jeden klaster lub zostanie spełniony kryterium zatrzymania.
2. **Dzielące (Od Góry do Dołu)**: Rozpocznij od wszystkich punktów danych w jednym klastrze i iteracyjnie dziel klastry, aż każdy punkt danych stanie się swoim własnym klastrem lub zostanie spełniony kryterium zatrzymania.

Klasteryzacja agglomeratywna wymaga zdefiniowania odległości między klastrami oraz kryterium łączenia, aby zdecydować, które klastry połączyć. Powszechne metody łączenia obejmują pojedyncze łączenie (odległość najbliższych punktów między dwoma klastrami), pełne łączenie (odległość najdalszych punktów), średnie łączenie itp., a metryka odległości często jest euklidesowa. Wybór metody łączenia wpływa na kształt produkowanych klastrów. Nie ma potrzeby wstępnego określania liczby klastrów K; można "przeciąć" dendrogram na wybranym poziomie, aby uzyskać pożądaną liczbę klastrów.

Klasteryzacja hierarchiczna produkuje dendrogram, strukturę przypominającą drzewo, która pokazuje relacje między klastrami na różnych poziomach szczegółowości. Dendrogram można przeciąć na pożądanym poziomie, aby uzyskać określoną liczbę klastrów.

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Klasteryzacja hierarchiczna może organizować zdarzenia lub podmioty w drzewo, aby dostrzegać relacje. Na przykład w analizie złośliwego oprogramowania klasteryzacja agglomeratywna mogłaby grupować próbki według podobieństwa behawioralnego, ujawniając hierarchię rodzin i wariantów złośliwego oprogramowania. W bezpieczeństwie sieci można klasteryzować przepływy ruchu IP i używać dendrogramu do zobaczenia podgrup ruchu (np. według protokołu, a następnie według zachowania). Ponieważ nie trzeba wybierać K z góry, jest to przydatne podczas eksploracji nowych danych, dla których liczba kategorii ataków jest nieznana.

#### Założenia i Ograniczenia

Klasteryzacja hierarchiczna nie zakłada konkretnego kształtu klastra i może uchwycić zagnieżdżone klastry. Jest przydatna do odkrywania taksonomii lub relacji między grupami (np. grupowanie złośliwego oprogramowania według podgrup rodzinnych). Jest deterministyczna (brak problemów z losową inicjalizacją). Kluczową zaletą jest dendrogram, który dostarcza wglądu w strukturę klasteryzacji danych na wszystkich poziomach – analitycy bezpieczeństwa mogą zdecydować o odpowiednim poziomie odcięcia, aby zidentyfikować znaczące klastry. Jednak jest to kosztowne obliczeniowo (zwykle czas $O(n^2)$ lub gorszy dla naiwnej implementacji) i niepraktyczne dla bardzo dużych zbiorów danych. Jest to również procedura zachłanna – po wykonaniu połączenia lub podziału nie można tego cofnąć, co może prowadzić do suboptymalnych klastrów, jeśli błąd wystąpi wcześnie. Odstające punkty mogą również wpływać na niektóre strategie łączenia (pojedyncze łączenie może powodować efekt "łańcuchowy", gdzie klastry łączą się przez odstające punkty).

<details>
<summary>Przykład -- Klasteryzacja Agglomeratywna Zdarzeń
</summary>

Ponownie wykorzystamy syntetyczne dane z przykładu K-Means (3 normalne klastry + 1 klaster ataku) i zastosujemy klasteryzację agglomeratywną. Następnie ilustrujemy, jak uzyskać dendrogram i etykiety klastrów.
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

### DBSCAN (Gęstościowe Grupowanie Przestrzenne Aplikacji z Szumem)

DBSCAN to algorytm grupowania oparty na gęstości, który łączy punkty blisko siebie, jednocześnie oznaczając punkty w obszarach o niskiej gęstości jako odstające. Jest szczególnie przydatny w przypadku zbiorów danych o zmiennej gęstości i nienormalnych kształtach.

DBSCAN działa, definiując dwa parametry:
- **Epsilon (ε)**: Maksymalna odległość między dwoma punktami, aby mogły być uznane za część tej samej grupy.
- **MinPts**: Minimalna liczba punktów wymagana do utworzenia gęstego obszaru (punkt rdzeniowy).

DBSCAN identyfikuje punkty rdzeniowe, punkty brzegowe i punkty szumowe:
- **Punkt Rdzeniowy**: Punkt z co najmniej MinPts sąsiadami w odległości ε.
- **Punkt Brzegowy**: Punkt, który znajduje się w odległości ε od punktu rdzeniowego, ale ma mniej niż MinPts sąsiadów.
- **Punkt Szumowy**: Punkt, który nie jest ani punktem rdzeniowym, ani punktem brzegowym.

Grupowanie przebiega poprzez wybranie nieodwiedzonego punktu rdzeniowego, oznaczenie go jako nowej grupy, a następnie rekurencyjne dodawanie wszystkich punktów osiągalnych gęstościowo z niego (punkty rdzeniowe i ich sąsiedzi itp.). Punkty brzegowe są dodawane do grupy pobliskiego punktu rdzeniowego. Po rozszerzeniu wszystkich osiągalnych punktów, DBSCAN przechodzi do innego nieodwiedzonego punktu rdzeniowego, aby rozpocząć nową grupę. Punkty, które nie zostały osiągnięte przez żaden punkt rdzeniowy, pozostają oznaczone jako szum.

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* DBSCAN jest przydatny do wykrywania anomalii w ruchu sieciowym. Na przykład normalna aktywność użytkowników może tworzyć jedną lub więcej gęstych grup w przestrzeni cech, podczas gdy nowe zachowania ataków pojawiają się jako rozproszone punkty, które DBSCAN oznaczy jako szum (odstające). Został użyty do grupowania rekordów przepływu sieciowego, gdzie może wykrywać skany portów lub ruch typu denial-of-service jako rzadkie obszary punktów. Innym zastosowaniem jest grupowanie wariantów złośliwego oprogramowania: jeśli większość próbek grupuje się według rodzin, ale kilka nie pasuje nigdzie, te kilka może być złośliwym oprogramowaniem zero-day. Możliwość oznaczania szumu oznacza, że zespoły bezpieczeństwa mogą skupić się na badaniu tych odstających.

#### Założenia i Ograniczenia

**Założenia i Mocne Strony:** DBSCAN nie zakłada sferycznych grup – może znajdować grupy o dowolnych kształtach (nawet łańcuchowych lub sąsiadujących). Automatycznie określa liczbę grup na podstawie gęstości danych i skutecznie identyfikuje odstające jako szum. To czyni go potężnym narzędziem dla danych rzeczywistych o nieregularnych kształtach i szumie. Jest odporny na odstające (w przeciwieństwie do K-Means, który zmusza je do grup). Działa dobrze, gdy grupy mają mniej więcej jednolitą gęstość.

**Ograniczenia:** Wydajność DBSCAN zależy od wyboru odpowiednich wartości ε i MinPts. Może mieć trudności z danymi o zmiennej gęstości – pojedyncze ε nie może pomieścić zarówno gęstych, jak i rzadkich grup. Jeśli ε jest zbyt małe, oznacza większość punktów jako szum; zbyt duże, a grupy mogą się niepoprawnie łączyć. Ponadto DBSCAN może być nieefektywny na bardzo dużych zbiorach danych (naiwnie $O(n^2)$, chociaż indeksowanie przestrzenne może pomóc). W przestrzeniach cech o wysokiej wymiarowości pojęcie „odległości w ε” może stać się mniej znaczące (klątwa wymiarowości), a DBSCAN może wymagać starannego dostrajania parametrów lub może nie znaleźć intuicyjnych grup. Mimo to, rozszerzenia takie jak HDBSCAN rozwiązują niektóre problemy (jak zmienna gęstość).

<details>
<summary>Przykład -- Grupowanie z Szumem
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
W tym fragmencie dostosowaliśmy `eps` i `min_samples` do skali naszych danych (15.0 w jednostkach cech i wymagając 5 punktów do utworzenia klastra). DBSCAN powinien znaleźć 2 klastry (klastry normalnego ruchu) i oznaczyć 5 wstrzykniętych wartości odstających jako szum. Wyprowadzamy liczbę klastrów w porównaniu do punktów szumowych, aby to zweryfikować. W rzeczywistym ustawieniu można iterować po ε (używając heurystyki grafu odległości k, aby wybrać ε) i MinPts (często ustawianym na około wymiarowości danych + 1 jako zasada ogólna), aby znaleźć stabilne wyniki klastrowania. Możliwość wyraźnego oznaczania szumu pomaga oddzielić potencjalne dane ataku do dalszej analizy.

</details>

### Analiza Głównych Składników (PCA)

PCA to technika **redukcji wymiarowości**, która znajduje nowy zestaw ortogonalnych osi (głównych składników), które uchwycają maksymalną wariancję w danych. Mówiąc prosto, PCA obraca i projektuje dane na nowy układ współrzędnych, tak aby pierwszy główny składnik (PC1) wyjaśniał możliwie największą wariancję, drugi PC (PC2) wyjaśniał największą wariancję ortogonalną do PC1, i tak dalej. Matematycznie, PCA oblicza wektory własne macierzy kowariancji danych – te wektory własne to kierunki głównych składników, a odpowiadające im wartości własne wskazują ilość wariancji wyjaśnianej przez każdy z nich. Często jest używane do ekstrakcji cech, wizualizacji i redukcji szumów.

Należy zauważyć, że jest to przydatne, jeśli wymiary zbioru danych zawierają **znaczące zależności liniowe lub korelacje**.

PCA działa poprzez identyfikację głównych składników danych, którymi są kierunki maksymalnej wariancji. Kroki zaangażowane w PCA to:
1. **Standaryzacja**: Wyśrodkowanie danych poprzez odjęcie średniej i skalowanie do jednostkowej wariancji.
2. **Macierz Kowariancji**: Obliczenie macierzy kowariancji ustandaryzowanych danych, aby zrozumieć relacje między cechami.
3. **Rozkład Wartości Własnych**: Wykonanie rozkładu wartości własnych na macierzy kowariancji, aby uzyskać wartości własne i wektory własne.
4. **Wybór Głównych Składników**: Posortowanie wartości własnych w porządku malejącym i wybór najlepszych K wektorów własnych odpowiadających największym wartościom własnym. Te wektory własne tworzą nową przestrzeń cech.
5. **Transformacja Danych**: Projekcja oryginalnych danych na nową przestrzeń cech przy użyciu wybranych głównych składników.
PCA jest szeroko stosowane do wizualizacji danych, redukcji szumów i jako krok wstępny dla innych algorytmów uczenia maszynowego. Pomaga zmniejszyć wymiarowość danych, zachowując ich istotną strukturę.

#### Wartości Własne i Wektory Własne

Wartość własna to skalar, który wskazuje ilość wariancji uchwyconej przez odpowiadający jej wektor własny. Wektor własny reprezentuje kierunek w przestrzeni cech, wzdłuż którego dane zmieniają się najbardziej.

Wyobraź sobie, że A jest macierzą kwadratową, a v jest wektorem różnym od zera, tak że: `A * v = λ * v`
gdzie:
- A to macierz kwadratowa, jak [ [1, 2], [2, 1]] (np. macierz kowariancji)
- v to wektor własny (np. [1, 1])

Wtedy `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, co będzie wartością własną λ pomnożoną przez wektor własny v, co daje wartość własną λ = 3.

#### Wartości Własne i Wektory Własne w PCA

Wyjaśnijmy to na przykładzie. Wyobraź sobie, że masz zbiór danych z wieloma zdjęciami w odcieniach szarości twarzy o rozmiarze 100x100 pikseli. Każdy piksel można uznać za cechę, więc masz 10 000 cech na obraz (lub wektor 10000 komponentów na obraz). Jeśli chcesz zmniejszyć wymiarowość tego zbioru danych za pomocą PCA, powinieneś postępować zgodnie z tymi krokami:

1. **Standaryzacja**: Wyśrodkowanie danych poprzez odjęcie średniej każdej cechy (piksela) z zestawu danych.
2. **Macierz Kowariancji**: Obliczenie macierzy kowariancji ustandaryzowanych danych, która uchwyca, jak cechy (piksele) zmieniają się razem.
- Należy zauważyć, że kowariancja między dwiema zmiennymi (pikselami w tym przypadku) wskazuje, jak bardzo zmieniają się razem, więc pomysł polega na odkryciu, które piksele mają tendencję do wzrostu lub spadku razem w relacji liniowej.
- Na przykład, jeśli piksel 1 i piksel 2 mają tendencję do wzrostu razem, kowariancja między nimi będzie dodatnia.
- Macierz kowariancji będzie macierzą 10 000x10 000, gdzie każdy wpis reprezentuje kowariancję między dwoma pikselami.
3. **Rozwiąż równanie wartości własnych**: Równanie wartości własnych do rozwiązania to `C * v = λ * v`, gdzie C to macierz kowariancji, v to wektor własny, a λ to wartość własna. Można je rozwiązać za pomocą metod takich jak:
- **Rozkład Wartości Własnych**: Wykonanie rozkładu wartości własnych na macierzy kowariancji, aby uzyskać wartości własne i wektory własne.
- **Rozkład Wartości Singularnych (SVD)**: Alternatywnie, można użyć SVD do rozkładu macierzy danych na wartości i wektory singularne, co również może dać główne składniki.
4. **Wybór Głównych Składników**: Posortowanie wartości własnych w porządku malejącym i wybór najlepszych K wektorów własnych odpowiadających największym wartościom własnym. Te wektory własne reprezentują kierunki maksymalnej wariancji w danych.

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Powszechnym zastosowaniem PCA w bezpieczeństwie jest redukcja cech do wykrywania anomalii. Na przykład, system wykrywania intruzów z ponad 40 metrykami sieciowymi (takimi jak cechy NSL-KDD) może użyć PCA do redukcji do kilku składników, podsumowując dane do wizualizacji lub wprowadzenia do algorytmów klastrowania. Analitycy mogą rysować ruch sieciowy w przestrzeni pierwszych dwóch głównych składników, aby zobaczyć, czy ataki oddzielają się od normalnego ruchu. PCA może również pomóc w eliminacji zbędnych cech (jak bajty wysłane w porównaniu do bajtów odebranych, jeśli są skorelowane), aby uczynić algorytmy wykrywania bardziej odpornymi i szybszymi.

#### Założenia i Ograniczenia

PCA zakłada, że **główne osie wariancji są znaczące** – jest to metoda liniowa, więc uchwyca liniowe korelacje w danych. Jest nienadzorowana, ponieważ wykorzystuje tylko kowariancję cech. Zalety PCA obejmują redukcję szumów (małe składniki wariancji często odpowiadają szumowi) i dekorelację cech. Jest obliczeniowo wydajne dla umiarkowanie wysokich wymiarów i często jest używane jako krok wstępny dla innych algorytmów (aby złagodzić przekleństwo wymiarowości). Jednym z ograniczeń jest to, że PCA jest ograniczone do relacji liniowych – nie uchwyci złożonej nieliniowej struktury (podczas gdy autoenkodery lub t-SNE mogą). Ponadto składniki PCA mogą być trudne do interpretacji w kontekście oryginalnych cech (są kombinacjami oryginalnych cech). W cyberbezpieczeństwie należy być ostrożnym: atak, który powoduje tylko subtelną zmianę w cechach o niskiej wariancji, może nie pojawić się w głównych składnikach (ponieważ PCA priorytetowo traktuje wariancję, a niekoniecznie „interesującość”).

<details>
<summary>Przykład -- Redukcja Wymiarów Danych Sieciowych
</summary>

Załóżmy, że mamy logi połączeń sieciowych z wieloma cechami (np. czasy trwania, bajty, liczby). Wygenerujemy syntetyczny zbiór danych o wymiarach 4 (z pewną korelacją między cechami) i użyjemy PCA, aby zredukować go do 2 wymiarów do wizualizacji lub dalszej analizy.
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
Tutaj wzięliśmy wcześniejsze klastry normalnego ruchu i rozszerzyliśmy każdy punkt danych o dwie dodatkowe cechy (pakiety i błędy), które korelują z bajtami i czasem trwania. Następnie używamy PCA do skompresowania 4 cech do 2 głównych komponentów. Drukujemy współczynnik wyjaśnionej wariancji, który może pokazać, że na przykład >95% wariancji jest uchwycone przez 2 komponenty (co oznacza niewielką utratę informacji). Wynik pokazuje również, że kształt danych zmienia się z (1500, 4) na (1500, 2). Pierwsze kilka punktów w przestrzeni PCA podano jako przykład. W praktyce można by narysować data_2d, aby wizualnie sprawdzić, czy klastry są rozróżnialne. Jeśli występowałaby anomalia, można by ją zobaczyć jako punkt leżący z dala od głównego klastra w przestrzeni PCA. PCA w ten sposób pomaga destylować złożone dane do zarządzalnej formy dla ludzkiej interpretacji lub jako wejście do innych algorytmów.

</details>


### Modele Mieszanek Gaussowskich (GMM)

Model Mieszanek Gaussowskich zakłada, że dane są generowane z mieszanki **kilku rozkładów Gaussowskich (normalnych) o nieznanych parametrach**. W istocie jest to probabilistyczny model klastrowania: stara się łagodnie przypisać każdy punkt do jednego z K komponentów Gaussowskich. Każdy komponent Gaussowski k ma wektor średni (μ_k), macierz kowariancji (Σ_k) oraz wagę mieszania (π_k), która reprezentuje, jak powszechny jest ten klaster. W przeciwieństwie do K-Means, który dokonuje "twardych" przypisań, GMM nadaje każdemu punktowi prawdopodobieństwo przynależności do każdego klastra.

Dopasowanie GMM zazwyczaj odbywa się za pomocą algorytmu Oczekiwania-Maksymalizacji (EM):

- **Inicjalizacja**: Rozpocznij od początkowych oszacowań dla średnich, kowariancji i współczynników mieszania (lub użyj wyników K-Means jako punktu wyjścia).

- **E-krok (Oczekiwanie)**: Mając obecne parametry, oblicz odpowiedzialność każdego klastra dla każdego punktu: zasadniczo `r_nk = P(z_k | x_n)`, gdzie z_k to zmienna utajona wskazująca przynależność do klastra dla punktu x_n. To jest robione za pomocą twierdzenia Bayesa, gdzie obliczamy prawdopodobieństwo a posteriori każdego punktu przynależności do każdego klastra na podstawie obecnych parametrów. Odpowiedzialności oblicza się jako:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
gdzie:
- \( \pi_k \) to współczynnik mieszania dla klastra k (prawdopodobieństwo a priori klastra k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) to funkcja gęstości prawdopodobieństwa Gaussa dla punktu \( x_n \) przy danej średniej \( \mu_k \) i kowariancji \( \Sigma_k \).

- **M-krok (Maksymalizacja)**: Zaktualizuj parametry, używając odpowiedzialności obliczonych w kroku E:
- Zaktualizuj każdą średnią μ_k jako ważoną średnią punktów, gdzie wagi to odpowiedzialności.
- Zaktualizuj każdą kowariancję Σ_k jako ważoną kowariancję punktów przypisanych do klastra k.
- Zaktualizuj współczynniki mieszania π_k jako średnią odpowiedzialność dla klastra k.

- **Iteruj** kroki E i M, aż do zbieżności (parametry stabilizują się lub poprawa prawdopodobieństwa jest poniżej progu).

Wynikiem jest zestaw rozkładów Gaussowskich, które wspólnie modelują ogólny rozkład danych. Możemy użyć dopasowanego GMM do klastrowania, przypisując każdy punkt do Gaussa o najwyższym prawdopodobieństwie, lub zachować prawdopodobieństwa dla niepewności. Można również ocenić prawdopodobieństwo nowych punktów, aby sprawdzić, czy pasują do modelu (przydatne w wykrywaniu anomalii).

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* GMM można wykorzystać do wykrywania anomalii, modelując rozkład normalnych danych: każdy punkt o bardzo niskim prawdopodobieństwie w ramach wyuczonej mieszanki jest oznaczany jako anomalia. Na przykład, można by wytrenować GMM na cechach legalnego ruchu sieciowego; połączenie atakujące, które nie przypomina żadnego wyuczonego klastra, miałoby niskie prawdopodobieństwo. GMM są również używane do klastrowania działań, gdzie klastry mogą mieć różne kształty – np. grupowanie użytkowników według profili zachowań, gdzie cechy każdego profilu mogą być podobne do Gaussa, ale z własną strukturą wariancji. Inny scenariusz: w wykrywaniu phishingu, cechy legalnych e-maili mogą tworzyć jeden klaster Gaussowski, znane phishingi inny, a nowe kampanie phishingowe mogą pojawić się jako oddzielny Gauss lub jako punkty o niskim prawdopodobieństwie w stosunku do istniejącej mieszanki.

#### Założenia i ograniczenia

GMM jest uogólnieniem K-Means, które uwzględnia kowariancję, dzięki czemu klastry mogą być elipsoidalne (nie tylko sferyczne). Radzi sobie z klastrami o różnych rozmiarach i kształtach, jeśli kowariancja jest pełna. Miękkie klastrowanie jest zaletą, gdy granice klastrów są nieostre – np. w cyberbezpieczeństwie, zdarzenie może mieć cechy wielu typów ataków; GMM może odzwierciedlać tę niepewność za pomocą prawdopodobieństw. GMM dostarcza również probabilistycznej estymacji gęstości danych, co jest przydatne do wykrywania wartości odstających (punktów o niskim prawdopodobieństwie w ramach wszystkich komponentów mieszanki).

Z drugiej strony, GMM wymaga określenia liczby komponentów K (choć można użyć kryteriów takich jak BIC/AIC do jej wyboru). EM czasami może zbiegać się wolno lub do lokalnego optimum, więc inicjalizacja jest ważna (często uruchamia się EM wiele razy). Jeśli dane w rzeczywistości nie podążają za mieszanką Gaussów, model może być słabo dopasowany. Istnieje również ryzyko, że jeden Gauss skurczy się, aby pokryć tylko wartość odstającą (choć regularizacja lub minimalne ograniczenia kowariancji mogą to złagodzić).


<details>
<summary>Przykład --  Miękkie klastrowanie i wyniki anomalii
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
W tym kodzie trenujemy GMM z 3 Gaussami na normalnym ruchu (zakładając, że znamy 3 profile legalnego ruchu). Średnie i kowariancje wydrukowane opisują te klastry (na przykład, jedna średnia może wynosić około [50,500], co odpowiada centrum jednego klastra itd.). Następnie testujemy podejrzane połączenie [duration=200, bytes=800]. predict_proba podaje prawdopodobieństwo, że ten punkt należy do każdego z 3 klastrów – spodziewalibyśmy się, że te prawdopodobieństwa będą bardzo niskie lub mocno zniekształcone, ponieważ [200,800] leży daleko od normalnych klastrów. Całkowity score_samples (log-likelihood) jest wydrukowany; bardzo niska wartość wskazuje, że punkt nie pasuje dobrze do modelu, oznaczając go jako anomalię. W praktyce można ustawić próg na log-likelihood (lub na maksymalne prawdopodobieństwo), aby zdecydować, czy punkt jest wystarczająco mało prawdopodobny, aby uznać go za złośliwy. GMM w ten sposób zapewnia zasadniczy sposób wykrywania anomalii i również generuje miękkie klastry, które uwzględniają niepewność.

### Isolation Forest

**Isolation Forest** to algorytm detekcji anomalii oparty na idei losowego izolowania punktów. Zasada polega na tym, że anomalie są nieliczne i różne, więc łatwiej je izolować niż normalne punkty. Isolation Forest buduje wiele binarnych drzew izolacyjnych (losowych drzew decyzyjnych), które losowo dzielą dane. W każdym węźle drzewa wybierana jest losowa cecha, a losowa wartość podziału jest wybierana pomiędzy min i max tej cechy dla danych w tym węźle. Ten podział dzieli dane na dwie gałęzie. Drzewo rośnie, aż każdy punkt zostanie izolowany w swoim własnym liściu lub osiągnięta zostanie maksymalna wysokość drzewa.

Wykrywanie anomalii odbywa się poprzez obserwację długości ścieżki każdego punktu w tych losowych drzewach – liczby podziałów wymaganych do izolacji punktu. Intuicyjnie, anomalie (odstające wartości) mają tendencję do szybszej izolacji, ponieważ losowy podział jest bardziej prawdopodobny, aby oddzielić odstającą wartość (która znajduje się w rzadkim obszarze) niż normalny punkt w gęstym klastrze. Isolation Forest oblicza wynik anomalii na podstawie średniej długości ścieżki we wszystkich drzewach: krótsza średnia ścieżka → bardziej anomalny. Wyniki są zazwyczaj normalizowane do [0,1], gdzie 1 oznacza bardzo prawdopodobną anomalię.

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Isolation Forests były z powodzeniem używane w wykrywaniu intruzji i wykrywaniu oszustw. Na przykład, trenuj Isolation Forest na logach ruchu sieciowego, które głównie zawierają normalne zachowanie; las wygeneruje krótkie ścieżki dla dziwnego ruchu (jak IP, które używa nieznanego portu lub nietypowego wzoru rozmiaru pakietu), flagując go do inspekcji. Ponieważ nie wymaga oznaczonych ataków, nadaje się do wykrywania nieznanych typów ataków. Może być również wdrażany na danych logowania użytkowników w celu wykrywania przejęć kont (anomalia w czasach logowania lub lokalizacjach są szybko izolowane). W jednym przypadku użycia, Isolation Forest może chronić przedsiębiorstwo, monitorując metryki systemowe i generując alert, gdy kombinacja metryk (CPU, sieć, zmiany plików) wygląda bardzo inaczej (krótkie ścieżki izolacji) niż wzory historyczne.

#### Założenia i ograniczenia

**Zalety**: Isolation Forest nie wymaga założenia o rozkładzie; bezpośrednio celuje w izolację. Jest wydajny w przypadku danych o wysokiej wymiarowości i dużych zbiorów danych (złożoność liniowa $O(n\log n)$ przy budowie lasu), ponieważ każde drzewo izoluje punkty tylko z podzbioru cech i podziałów. Zwykle dobrze radzi sobie z cechami numerycznymi i może być szybszy niż metody oparte na odległości, które mogą mieć złożoność $O(n^2)$. Automatycznie również daje wynik anomalii, więc można ustawić próg dla alertów (lub użyć parametru zanieczyszczenia, aby automatycznie zdecydować o odcięciu na podstawie oczekiwanej frakcji anomalii).

**Ograniczenia**: Z powodu swojej losowej natury wyniki mogą się nieznacznie różnić między uruchomieniami (choć przy wystarczającej liczbie drzew jest to niewielkie). Jeśli dane mają wiele nieistotnych cech lub jeśli anomalie nie różnią się wyraźnie w żadnej cechie, izolacja może nie być skuteczna (losowe podziały mogą przypadkowo izolować normalne punkty – jednak uśrednianie wielu drzew łagodzi to). Ponadto, Isolation Forest zazwyczaj zakłada, że anomalie są małą mniejszością (co zazwyczaj jest prawdą w scenariuszach cyberbezpieczeństwa).

<details>
<summary>Przykład -- Wykrywanie odstających wartości w logach sieciowych
</summary>

Użyjemy wcześniejszego zestawu danych testowych (który zawiera normalne i niektóre punkty ataku) i uruchomimy Isolation Forest, aby zobaczyć, czy może oddzielić ataki. Zakładamy, że oczekujemy, że ~15% danych będzie anomaliami (dla demonstracji).
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
W tym kodzie instancjonujemy `IsolationForest` z 100 drzewami i ustawiamy `contamination=0.15` (co oznacza, że oczekujemy około 15% anomalii; model ustawi próg punktacji tak, aby ~15% punktów zostało oznaczonych). Dopasowujemy go do `X_test_if`, który zawiera mieszankę normalnych punktów i punktów ataku (uwaga: zazwyczaj dopasowujesz do danych treningowych, a następnie używasz predict na nowych danych, ale tutaj dla ilustracji dopasowujemy i przewidujemy na tym samym zbiorze, aby bezpośrednio zaobserwować wyniki).

Wynik pokazuje przewidywane etykiety dla pierwszych 20 punktów (gdzie -1 oznacza anomalię). Drukujemy również, ile anomalii zostało wykrytych w sumie oraz kilka przykładowych punktów anomalii. Oczekiwalibyśmy, że około 18 z 120 punktów zostanie oznaczonych jako -1 (ponieważ zanieczyszczenie wynosiło 15%). Jeśli nasze 20 próbek ataku jest rzeczywiście najbardziej odstającymi, większość z nich powinna pojawić się w tych przewidywaniach -1. Punktacja anomalii (funkcja decyzyjna Isolation Forest) jest wyższa dla normalnych punktów i niższa (bardziej negatywna) dla anomalii – drukujemy kilka wartości, aby zobaczyć separację. W praktyce można by posortować dane według punktacji, aby zobaczyć najlepsze odstające i je zbadać. Isolation Forest zapewnia zatem efektywny sposób przeszukiwania dużych, nieoznakowanych danych bezpieczeństwa i wyodrębniania najbardziej nieregularnych przypadków do analizy przez ludzi lub dalszej automatycznej analizy.

### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** to nieliniowa technika redukcji wymiarów, zaprojektowana specjalnie do wizualizacji danych o wysokiej wymiarowości w 2 lub 3 wymiarach. Przekształca podobieństwa między punktami danych w wspólne rozkłady prawdopodobieństwa i stara się zachować strukturę lokalnych sąsiedztw w projekcji o niższej wymiarowości. Mówiąc prościej, t-SNE umieszcza punkty w (powiedzmy) 2D w taki sposób, że podobne punkty (w oryginalnej przestrzeni) znajdują się blisko siebie, a różne punkty są oddalone od siebie z dużym prawdopodobieństwem.

Algorytm ma dwa główne etapy:

1. **Obliczanie parowych afinitetów w przestrzeni o wysokiej wymiarowości:** Dla każdej pary punktów t-SNE oblicza prawdopodobieństwo, że wybierze tę parę jako sąsiadów (to jest realizowane przez centrowanie rozkładu Gaussa na każdym punkcie i mierzenie odległości – parametr złożoności wpływa na efektywną liczbę sąsiadów, które są brane pod uwagę).
2. **Obliczanie parowych afinitetów w przestrzeni o niskiej wymiarowości (np. 2D):** Początkowo punkty są losowo umieszczane w 2D. t-SNE definiuje podobne prawdopodobieństwo dla odległości w tej mapie (używając jądra rozkładu t Studenta, które ma cięższe ogony niż Gauss, aby umożliwić dalszym punktom większą swobodę).
3. **Spadek gradientu:** t-SNE następnie iteracyjnie przemieszcza punkty w 2D, aby zminimalizować rozbieżność Kullbacka-Leiblera (KL) między rozkładem afinitetów w wysokiej wymiarowości a tym w niskiej wymiarowości. Powoduje to, że układ 2D odzwierciedla strukturę w wysokiej wymiarowości tak bardzo, jak to możliwe – punkty, które były blisko w oryginalnej przestrzeni, będą się przyciągać, a te oddalone będą się odpychać, aż znajdzie się równowaga.

Wynik często stanowi wizualnie znaczący wykres punktowy, na którym klastry w danych stają się oczywiste.

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* t-SNE jest często używane do **wizualizacji danych o wysokiej wymiarowości w celu analizy przez ludzi**. Na przykład, w centrum operacyjnym bezpieczeństwa, analitycy mogą wziąć zbiór danych zdarzeń z dziesiątkami cech (numery portów, częstotliwości, liczby bajtów itp.) i użyć t-SNE do wygenerowania wykresu 2D. Ataki mogą tworzyć własne klastry lub oddzielać się od normalnych danych na tym wykresie, co ułatwia ich identyfikację. Zostało to zastosowane do zbiorów danych złośliwego oprogramowania, aby zobaczyć grupy rodzin złośliwego oprogramowania lub do danych o włamaniu do sieci, gdzie różne typy ataków wyraźnie się grupują, co prowadzi do dalszego dochodzenia. W zasadzie t-SNE zapewnia sposób na zobaczenie struktury w danych cybernetycznych, które w przeciwnym razie byłyby nieczytelne.

#### Założenia i ograniczenia

t-SNE jest świetne do wizualnego odkrywania wzorców. Może ujawniać klastry, podklastry i odstające punkty, które inne metody liniowe (jak PCA) mogą przeoczyć. Zostało użyte w badaniach nad cyberbezpieczeństwem do wizualizacji złożonych danych, takich jak profile zachowań złośliwego oprogramowania lub wzorce ruchu sieciowego. Ponieważ zachowuje lokalną strukturę, dobrze pokazuje naturalne grupowania.

Jednak t-SNE jest obliczeniowo cięższe (około $O(n^2)$), więc może wymagać próbkowania dla bardzo dużych zbiorów danych. Ma również hiperparametry (złożoność, współczynnik uczenia, iteracje), które mogą wpływać na wynik – np. różne wartości złożoności mogą ujawniać klastry w różnych skalach. Wykresy t-SNE mogą czasami być błędnie interpretowane – odległości na mapie nie mają bezpośredniego znaczenia globalnego (koncentruje się na lokalnym sąsiedztwie, czasami klastry mogą wydawać się sztucznie dobrze oddzielone). Ponadto t-SNE jest głównie do wizualizacji; nie zapewnia prostego sposobu na projekcję nowych punktów danych bez ponownego obliczania i nie jest przeznaczone do użycia jako wstępne przetwarzanie dla modelowania predykcyjnego (UMAP jest alternatywą, która rozwiązuje niektóre z tych problemów z szybszą prędkością).

<details>
<summary>Przykład -- Wizualizacja połączeń sieciowych
</summary>

Użyjemy t-SNE, aby zredukować zbiór danych z wieloma cechami do 2D. Dla ilustracji weźmy wcześniejsze dane 4D (które miały 3 naturalne klastry normalnego ruchu) i dodajmy kilka punktów anomalii. Następnie uruchamiamy t-SNE i (koncepcyjnie) wizualizujemy wyniki.
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
Tutaj połączyliśmy nasz wcześniejszy zbiór danych 4D normalnych z garstką ekstremalnych wartości odstających (wartości odstające mają jedną cechę (“duration”) ustawioną bardzo wysoko, itd., aby zasymulować dziwny wzór). Uruchamiamy t-SNE z typową złożonością 30. Wyjściowe data_2d ma kształt (1505, 2). W tym tekście nie będziemy faktycznie rysować, ale gdybyśmy to zrobili, spodziewalibyśmy się zobaczyć może trzy zwarte klastry odpowiadające 3 normalnym klastrom, a 5 wartości odstających pojawiających się jako izolowane punkty daleko od tych klastrów. W interaktywnym przepływie pracy moglibyśmy pokolorować punkty według ich etykiety (normalne lub który klaster, w porównaniu do anomalii), aby zweryfikować tę strukturę. Nawet bez etykiet analityk mógłby zauważyć te 5 punktów siedzących w pustej przestrzeni na wykresie 2D i oznaczyć je. To pokazuje, jak t-SNE może być potężnym narzędziem do wizualnej detekcji anomalii i inspekcji klastrów w danych z cyberbezpieczeństwa, uzupełniając powyższe zautomatyzowane algorytmy.

</details>


{{#include ../banners/hacktricks-training.md}}
