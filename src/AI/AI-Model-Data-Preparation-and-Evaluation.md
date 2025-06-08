# Przygotowanie danych modelu i ocena

{{#include ../banners/hacktricks-training.md}}

Przygotowanie danych modelu jest kluczowym krokiem w procesie uczenia maszynowego, ponieważ polega na przekształceniu surowych danych w format odpowiedni do trenowania modeli uczenia maszynowego. Proces ten obejmuje kilka kluczowych kroków:

1. **Zbieranie danych**: Gromadzenie danych z różnych źródeł, takich jak bazy danych, API lub pliki. Dane mogą być strukturalne (np. tabele) lub niestrukturalne (np. tekst, obrazy).
2. **Czyszczenie danych**: Usuwanie lub korygowanie błędnych, niekompletnych lub nieistotnych punktów danych. Ten krok może obejmować radzenie sobie z brakującymi wartościami, usuwanie duplikatów i filtrowanie wartości odstających.
3. **Przekształcanie danych**: Konwertowanie danych w odpowiedni format do modelowania. Może to obejmować normalizację, skalowanie, kodowanie zmiennych kategorycznych oraz tworzenie nowych cech za pomocą technik takich jak inżynieria cech.
4. **Podział danych**: Dzielnie zbioru danych na zestawy treningowe, walidacyjne i testowe, aby zapewnić, że model będzie dobrze generalizował na nieznanych danych.

## Zbieranie danych

Zbieranie danych polega na gromadzeniu danych z różnych źródeł, które mogą obejmować:
- **Bazy danych**: Ekstrakcja danych z relacyjnych baz danych (np. bazy danych SQL) lub baz danych NoSQL (np. MongoDB).
- **API**: Pobieranie danych z interfejsów API, które mogą dostarczać dane w czasie rzeczywistym lub historyczne.
- **Pliki**: Odczytywanie danych z plików w formatach takich jak CSV, JSON lub XML.
- **Web Scraping**: Gromadzenie danych z witryn internetowych za pomocą technik web scrapingu.

W zależności od celu projektu uczenia maszynowego, dane będą ekstraktowane i zbierane z odpowiednich źródeł, aby zapewnić, że są reprezentatywne dla obszaru problemowego.

## Czyszczenie danych

Czyszczenie danych to proces identyfikacji i korygowania błędów lub niespójności w zbiorze danych. Krok ten jest niezbędny, aby zapewnić jakość danych używanych do trenowania modeli uczenia maszynowego. Kluczowe zadania w czyszczeniu danych obejmują:
- **Radzenie sobie z brakującymi wartościami**: Identyfikacja i rozwiązywanie problemów z brakującymi punktami danych. Powszechne strategie obejmują:
- Usuwanie wierszy lub kolumn z brakującymi wartościami.
- Uzupełnianie brakujących wartości za pomocą technik takich jak imputacja średniej, mediany lub trybu.
- Używanie zaawansowanych metod, takich jak imputacja K-najbliższych sąsiadów (KNN) lub imputacja regresyjna.
- **Usuwanie duplikatów**: Identyfikacja i usuwanie zduplikowanych rekordów, aby zapewnić, że każdy punkt danych jest unikalny.
- **Filtrowanie wartości odstających**: Wykrywanie i usuwanie wartości odstających, które mogą zniekształcać wydajność modelu. Techniki takie jak Z-score, IQR (zakres międzykwartylowy) lub wizualizacje (np. wykresy pudełkowe) mogą być używane do identyfikacji wartości odstających.

### Przykład czyszczenia danych
```python
import pandas as pd
# Load the dataset
data = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_possitive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = data[~data['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
data = data.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
data['days'] = pd.to_numeric(data['days'], errors='coerce')

## For example, set "NaN" to not ips
def is_valid_ip(ip):
pattern = re.compile(r'^((25[0-5]|2[0-4][0-9]|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$')
if pd.isna(ip) or not pattern.match(str(ip)):
return np.nan
return ip
df['ip'] = df['ip'].apply(is_valid_ip)

# Filling missing values based on different strategies
numeric_cols = ["days", "hours", "minutes"]
categorical_cols = ["ip", "status"]

## Filling missing values in numeric columns with the median
num_imputer = SimpleImputer(strategy='median')
df[numeric_cols] = num_imputer.fit_transform(df[numeric_cols])

## Filling missing values in categorical columns with the most frequent value
cat_imputer = SimpleImputer(strategy='most_frequent')
df[categorical_cols] = cat_imputer.fit_transform(df[categorical_cols])

## Filling missing values in numeric columns using KNN imputation
knn_imputer = KNNImputer(n_neighbors=5)
df[numeric_cols] = knn_imputer.fit_transform(df[numeric_cols])



# Filling missing values
data.fillna(data.mean(), inplace=True)

# Removing duplicates
data.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = stats.zscore(data.select_dtypes(include=['float64', 'int64']))
data = data[(z_scores < 3).all(axis=1)]
```
## Transformacja Danych

Transformacja danych polega na konwersji danych do formatu odpowiedniego do modelowania. Ten krok może obejmować:
- **Normalizacja i Standaryzacja**: Skalowanie cech numerycznych do wspólnego zakresu, zazwyczaj [0, 1] lub [-1, 1]. Pomaga to poprawić zbieżność algorytmów optymalizacji.
- **Skalowanie Min-Max**: Przeskalowanie cech do ustalonego zakresu, zazwyczaj [0, 1]. Robi się to za pomocą wzoru: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalizacja Z-Score**: Standaryzacja cech poprzez odjęcie średniej i podzielenie przez odchylenie standardowe, co skutkuje rozkładem o średniej 0 i odchyleniu standardowym 1. Robi się to za pomocą wzoru: `X' = (X - μ) / σ`, gdzie μ to średnia, a σ to odchylenie standardowe.
- **Skrzywienie i Kurtoza**: Dostosowanie rozkładu cech w celu zmniejszenia skrzywienia (asymetrii) i kurtozy (spiczastości). Można to zrobić za pomocą transformacji takich jak logarytmiczne, pierwiastek kwadratowy lub transformacje Box-Cox. Na przykład, jeśli cecha ma skrzywiony rozkład, zastosowanie transformacji logarytmicznej może pomóc w jej normalizacji.
- **Normalizacja Łańcuchów**: Konwersja łańcuchów do spójnego formatu, takiego jak:
- Zmiana na małe litery
- Usuwanie znaków specjalnych (zachowując te istotne)
- Usuwanie słów stop (powszechnych słów, które nie przyczyniają się do znaczenia, takich jak "the", "is", "and")
- Usuwanie zbyt częstych i zbyt rzadkich słów (np. słów, które pojawiają się w więcej niż 90% dokumentów lub mniej niż 5 razy w korpusie)
- Przycinanie białych znaków
- Stemming/Lematyzacja: Redukcja słów do ich podstawowej lub rdzennej formy (np. "running" do "run").

- **Kodowanie Zmiennych Kategorycznych**: Konwersja zmiennych kategorycznych na reprezentacje numeryczne. Powszechne techniki obejmują:
- **Kodowanie One-Hot**: Tworzenie binarnych kolumn dla każdej kategorii.
- Na przykład, jeśli cecha ma kategorie "czerwony", "zielony" i "niebieski", zostanie przekształcona w trzy binarne kolumny: `is_red`(100), `is_green`(010) i `is_blue`(001).
- **Kodowanie Etykiet**: Przypisywanie unikalnej liczby całkowitej każdej kategorii.
- Na przykład, "czerwony" = 0, "zielony" = 1, "niebieski" = 2.
- **Kodowanie Ordynalne**: Przypisywanie liczb całkowitych na podstawie kolejności kategorii.
- Na przykład, jeśli kategorie to "niski", "średni" i "wysoki", mogą być zakodowane jako 0, 1 i 2, odpowiednio.
- **Kodowanie Hashingowe**: Użycie funkcji haszującej do konwersji kategorii na wektory o stałej wielkości, co może być przydatne dla zmiennych kategorycznych o wysokiej kardynalności.
- Na przykład, jeśli cecha ma wiele unikalnych kategorii, haszowanie może zmniejszyć wymiarowość, zachowując jednocześnie pewne informacje o kategoriach.
- **Bag of Words (BoW)**: Reprezentowanie danych tekstowych jako macierzy zliczeń słów lub częstotliwości, gdzie każdy wiersz odpowiada dokumentowi, a każda kolumna odpowiada unikalnemu słowu w korpusie.
- Na przykład, jeśli korpus zawiera słowa "kot", "pies" i "ryba", dokument zawierający "kot" i "pies" byłby reprezentowany jako [1, 1, 0]. Ta konkretna reprezentacja nazywa się "unigram" i nie uchwyca kolejności słów, więc traci informacje semantyczne.
- **Bigram/Trigram**: Rozszerzenie BoW w celu uchwycenia sekwencji słów (bigramów lub trigramów), aby zachować pewien kontekst. Na przykład, "kot i pies" byłoby reprezentowane jako bigram [1, 1] dla "kot i" i [1, 1] dla "i pies". W tych przypadkach zbierane są dodatkowe informacje semantyczne (zwiększając wymiarowość reprezentacji), ale tylko dla 2 lub 3 słów na raz.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Statystyczna miara, która ocenia znaczenie słowa w dokumencie w odniesieniu do zbioru dokumentów (korpusu). Łączy częstotliwość terminu (jak często słowo pojawia się w dokumencie) i odwrotną częstotliwość dokumentu (jak rzadkie jest słowo w całym zbiorze dokumentów).
- Na przykład, jeśli słowo "kot" pojawia się często w dokumencie, ale jest rzadkie w całym korpusie, będzie miało wysoką wartość TF-IDF, co wskazuje na jego znaczenie w tym dokumencie.

- **Inżynieria Cech**: Tworzenie nowych cech z istniejących, aby zwiększyć moc predykcyjną modelu. Może to obejmować łączenie cech, wydobywanie komponentów daty/czasu lub stosowanie transformacji specyficznych dla danej dziedziny.

## Podział Danych

Podział danych polega na podzieleniu zbioru danych na oddzielne podzbiory do treningu, walidacji i testowania. Jest to niezbędne do oceny wydajności modelu na nieznanych danych i zapobiegania przeuczeniu. Powszechne strategie obejmują:
- **Podział na Zbiór Treningowy i Testowy**: Podział zbioru danych na zbiór treningowy (zazwyczaj 60-80% danych), zbiór walidacyjny (10-15% danych) do dostrajania hiperparametrów oraz zbiór testowy (10-15% danych). Model jest trenowany na zbiorze treningowym i oceniany na zbiorze testowym.
- Na przykład, jeśli masz zbiór danych z 1000 próbek, możesz użyć 700 próbek do treningu, 150 do walidacji i 150 do testowania.
- **Próbkowanie Stratifikowane**: Zapewnienie, że rozkład klas w zbiorach treningowych i testowych jest podobny do ogólnego zbioru danych. Jest to szczególnie ważne dla niezrównoważonych zbiorów danych, gdzie niektóre klasy mogą mieć znacznie mniej próbek niż inne.
- **Podział na Szereg Czasowy**: Dla danych szeregów czasowych zbiór danych jest dzielony na podstawie czasu, zapewniając, że zbiór treningowy zawiera dane z wcześniejszych okresów, a zbiór testowy zawiera dane z późniejszych okresów. Pomaga to ocenić wydajność modelu na przyszłych danych.
- **K-Fold Cross-Validation**: Podział zbioru danych na K podzbiorów (foldów) i trenowanie modelu K razy, za każdym razem używając innego folda jako zbioru testowego, a pozostałych foldów jako zbioru treningowego. Pomaga to zapewnić, że model jest oceniany na różnych podzbiorach danych, co daje bardziej solidny oszacowanie jego wydajności.

## Ocena Modelu

Ocena modelu to proces oceny wydajności modelu uczenia maszynowego na nieznanych danych. Obejmuje użycie różnych metryk do ilościowego określenia, jak dobrze model generalizuje na nowe dane. Powszechne metryki oceny obejmują:

### Dokładność

Dokładność to proporcja poprawnie przewidzianych przypadków do całkowitej liczby przypadków. Oblicza się ją jako:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Dokładność jest prostą i intuicyjną miarą, ale może nie być odpowiednia dla niezrównoważonych zbiorów danych, w których jedna klasa dominuje nad innymi, ponieważ może dawać mylące wrażenie wydajności modelu. Na przykład, jeśli 90% danych należy do klasy A, a model przewiduje wszystkie przypadki jako klasę A, osiągnie 90% dokładności, ale nie będzie przydatny do przewidywania klasy B.

### Precyzja

Precyzja to proporcja prawdziwych pozytywnych przewidywań w stosunku do wszystkich pozytywnych przewidywań dokonanych przez model. Oblicza się ją jako:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Precyzja jest szczególnie ważna w scenariuszach, w których fałszywe pozytywy są kosztowne lub niepożądane, takich jak diagnozy medyczne czy wykrywanie oszustw. Na przykład, jeśli model przewiduje 100 przypadków jako pozytywne, ale tylko 80 z nich jest rzeczywiście pozytywnych, precyzja wynosiłaby 0,8 (80%).

### Recall (Czułość)

Recall, znany również jako czułość lub wskaźnik prawdziwych pozytywów, to proporcja prawdziwych pozytywnych prognoz w stosunku do wszystkich rzeczywistych pozytywnych przypadków. Oblicza się go jako:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Przypomnienie jest kluczowe w scenariuszach, w których fałszywe negatywy są kosztowne lub niepożądane, takich jak wykrywanie chorób czy filtrowanie spamu. Na przykład, jeśli model identyfikuje 80 z 100 rzeczywistych pozytywnych przypadków, przypomnienie wynosi 0,8 (80%).

### F1 Score

Wynik F1 to średnia harmoniczna precyzji i przypomnienia, zapewniająca równowagę między tymi dwoma metrykami. Oblicza się go jako:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Wskaźnik F1 jest szczególnie przydatny w przypadku niezrównoważonych zbiorów danych, ponieważ uwzględnia zarówno fałszywe pozytywy, jak i fałszywe negatywy. Zapewnia pojedynczy wskaźnik, który uchwyca kompromis między precyzją a czułością. Na przykład, jeśli model ma precyzję 0.8 i czułość 0.6, wskaźnik F1 wynosiłby około 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

Wskaźnik ROC-AUC ocenia zdolność modelu do rozróżniania klas, rysując krzywą rzeczywistej stopy pozytywnej (czułość) w stosunku do stopy fałszywych pozytywów przy różnych ustawieniach progowych. Powierzchnia pod krzywą ROC (AUC) kwantyfikuje wydajność modelu, przy czym wartość 1 oznacza doskonałą klasyfikację, a wartość 0.5 oznacza losowe zgadywanie.

> [!TIP]
> ROC-AUC jest szczególnie przydatny w problemach klasyfikacji binarnej i zapewnia kompleksowy widok wydajności modelu w różnych progach. Jest mniej wrażliwy na niezrównoważenie klas w porównaniu do dokładności. Na przykład model z AUC równym 0.9 wskazuje, że ma wysoką zdolność do rozróżniania między pozytywnymi a negatywnymi przypadkami.

### Specyficzność

Specyficzność, znana również jako rzeczywista stopa negatywna, to proporcja rzeczywistych negatywnych prognoz w stosunku do wszystkich rzeczywistych negatywnych przypadków. Oblicza się ją jako:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Specyficzność jest ważna w scenariuszach, w których fałszywe pozytywy są kosztowne lub niepożądane, takich jak testy medyczne czy wykrywanie oszustw. Pomaga ocenić, jak dobrze model identyfikuje negatywne przypadki. Na przykład, jeśli model poprawnie identyfikuje 90 z 100 rzeczywistych negatywnych przypadków, specyficzność wynosi 0,9 (90%).

### Współczynnik korelacji Matthewsa (MCC)
Współczynnik korelacji Matthewsa (MCC) jest miarą jakości klasyfikacji binarnych. Uwzględnia prawdziwe i fałszywe pozytywy oraz negatywy, zapewniając zrównoważony obraz wydajności modelu. MCC oblicza się jako:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
gdzie:
- **TP**: Prawdziwe Pozytywy
- **TN**: Prawdziwe Negatywy
- **FP**: Fałszywe Pozytywy
- **FN**: Fałszywe Negatywy

> [!TIP]
> MCC waha się od -1 do 1, gdzie 1 oznacza doskonałą klasyfikację, 0 oznacza losowe zgadywanie, a -1 oznacza całkowitą niezgodność między prognozą a obserwacją. Jest szczególnie przydatny w przypadku niezrównoważonych zbiorów danych, ponieważ uwzględnia wszystkie cztery komponenty macierzy pomyłek.

### Średni Błąd Bezwzględny (MAE)
Średni Błąd Bezwzględny (MAE) to miara regresji, która mierzy średnią bezwzględną różnicę między wartościami prognozowanymi a rzeczywistymi. Oblicza się go jako:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
gdzie:
- **n**: Liczba instancji
- **y_i**: Rzeczywista wartość dla instancji i
- **ŷ_i**: Przewidywana wartość dla instancji i

> [!TIP]
> MAE zapewnia proste zrozumienie średniego błędu w prognozach, co ułatwia jego interpretację. Jest mniej wrażliwy na wartości odstające w porównaniu do innych metryk, takich jak Mean Squared Error (MSE). Na przykład, jeśli model ma MAE równą 5, oznacza to, że średnio prognozy modelu odbiegają od rzeczywistych wartości o 5 jednostek.

### Macierz pomyłek

Macierz pomyłek to tabela, która podsumowuje wydajność modelu klasyfikacyjnego, pokazując liczby prawdziwych pozytywnych, prawdziwych negatywnych, fałszywych pozytywnych i fałszywych negatywnych prognoz. Zapewnia szczegółowy widok na to, jak dobrze model radzi sobie w każdej klasie.

|               | Przewidywana pozytywna | Przewidywana negatywna |
|---------------|-------------------------|-------------------------|
| Rzeczywista pozytywna| Prawdziwy pozytywny (TP)  | Fałszywy negatywny (FN)  |
| Rzeczywista negatywna| Fałszywy pozytywny (FP) | Prawdziwy negatywny (TN)   |

- **Prawdziwy pozytywny (TP)**: Model poprawnie przewidział klasę pozytywną.
- **Prawdziwy negatywny (TN)**: Model poprawnie przewidział klasę negatywną.
- **Fałszywy pozytywny (FP)**: Model błędnie przewidział klasę pozytywną (błąd typu I).
- **Fałszywy negatywny (FN)**: Model błędnie przewidział klasę negatywną (błąd typu II).

Macierz pomyłek może być używana do obliczania różnych metryk oceny, takich jak dokładność, precyzja, czułość i wynik F1.


{{#include ../banners/hacktricks-training.md}}
