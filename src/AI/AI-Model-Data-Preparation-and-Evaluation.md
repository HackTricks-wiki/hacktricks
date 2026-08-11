# Przygotowanie i ocena danych modelu

{{#include ../banners/hacktricks-training.md}}

Przygotowanie danych modelu to kluczowy etap w pipeline machine learning, ponieważ obejmuje przekształcanie surowych danych do formatu odpowiedniego do trenowania modeli machine learning. Proces ten obejmuje kilka kluczowych etapów:

1. **Zbieranie danych**: Gromadzenie danych z różnych źródeł, takich jak bazy danych, API lub pliki. Dane mogą być ustrukturyzowane (np. tabele) lub nieustrukturyzowane (np. tekst, obrazy).
2. **Czyszczenie danych**: Usuwanie lub poprawianie błędnych, niekompletnych lub nieistotnych punktów danych. Ten etap może obejmować obsługę brakujących wartości, usuwanie duplikatów i filtrowanie wartości odstających.
3. **Transformacja danych**: Konwertowanie danych do formatu odpowiedniego do modelowania. Może to obejmować normalizację, skalowanie, kodowanie zmiennych kategorycznych oraz tworzenie nowych cech za pomocą technik takich jak feature engineering.
4. **Podział danych**: Dzielenie datasetu na zbiory treningowy, walidacyjny i testowy, aby zapewnić, że model będzie dobrze generalizować na nieznane dane.

## Zbieranie danych

Zbieranie danych obejmuje gromadzenie danych z różnych źródeł, w tym:
- **Bazy danych**: Wyodrębnianie danych z relacyjnych baz danych (np. baz danych SQL) lub baz danych NoSQL (np. MongoDB).
- **API**: Pobieranie danych z webowych API, które mogą dostarczać dane w czasie rzeczywistym lub dane historyczne.
- **Pliki**: Odczytywanie danych z plików w formatach takich jak CSV, JSON lub XML.
- **Web Scraping**: Zbieranie danych ze stron internetowych przy użyciu technik web scraping.

W zależności od celu projektu machine learning dane zostaną wyodrębnione i zebrane z odpowiednich źródeł, aby zapewnić ich reprezentatywność dla domeny problemu.

## Czyszczenie danych <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Czyszczenie danych to proces identyfikowania i korygowania błędów lub niespójności w datasecie. Ten etap jest niezbędny do zapewnienia jakości danych używanych do trenowania modeli machine learning. Kluczowe zadania związane z czyszczeniem danych obejmują:
- **Obsługa brakujących wartości**: Identyfikowanie i rozwiązywanie problemu brakujących punktów danych. Typowe strategie obejmują:
- Usuwanie wierszy lub kolumn zawierających brakujące wartości.
- Uzupełnianie brakujących wartości za pomocą technik takich jak imputacja średnią, medianą lub dominantą.
- Używanie zaawansowanych metod, takich jak imputacja K-nearest neighbors (KNN) lub imputacja regresyjna.
- **Usuwanie duplikatów**: Identyfikowanie i usuwanie zduplikowanych rekordów w celu zapewnienia unikalności każdego punktu danych.
- **Filtrowanie wartości odstających**: Wykrywanie i usuwanie wartości odstających, które mogą zniekształcać wydajność modelu. Do identyfikowania wartości odstających można używać technik takich jak Z-score, IQR (Interquartile Range) lub wizualizacji (np. wykresów pudełkowych).

### Przykład czyszczenia danych
```python
import re

import numpy as np
import pandas as pd
from sklearn.impute import KNNImputer, SimpleImputer

# Load the dataset
df = pd.read_csv('data.csv')

# Finding invalid values based on a specific function
def is_valid_positive_int(num):
try:
num = int(num)
return 1 <= num <= 31
except ValueError:
return False

invalid_days = df[~df['days'].astype(str).apply(is_valid_positive_int)]

## Dropping rows with invalid days
df = df.drop(invalid_days.index, errors='ignore')



# Set "NaN" values to a specific value
## For example, setting NaN values in the 'days' column to 0
df['days'] = pd.to_numeric(df['days'], errors='coerce')

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
df.fillna(df.mean(numeric_only=True), inplace=True)

# Removing duplicates
df.drop_duplicates(inplace=True)
# Filtering outliers using Z-score
from scipy import stats
z_scores = np.abs(stats.zscore(df.select_dtypes(include=['float64', 'int64']), nan_policy='omit'))
df = df[(z_scores < 3).all(axis=1)]
```
## Transformacja danych <sup>[[1]](#references)</sup>

Transformacja danych polega na konwersji danych do formatu odpowiedniego do modelowania. Ten etap może obejmować:
- **Normalizacja i standaryzacja**: Skalowanie cech numerycznych do wspólnego zakresu, zazwyczaj [0, 1] lub [-1, 1]. Może to poprawić zbieżność algorytmów optymalizacji.
- **Min-Max Scaling**: Przeskalowanie cech do ustalonego zakresu, zwykle [0, 1]. Wykorzystuje się do tego wzór: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score Normalization**: Standaryzacja cech przez odjęcie średniej i podzielenie przez odchylenie standardowe, co daje rozkład ze średnią równą 0 i odchyleniem standardowym równym 1. Wykorzystuje się do tego wzór: `X' = (X - μ) / σ`, gdzie μ to średnia, a σ to odchylenie standardowe.
- **Skośność i kurtoza**: Dostosowywanie rozkładów cech za pomocą transformacji, takich jak logarytm, pierwiastek kwadratowy lub Box-Cox. Na przykład transformacja logarytmiczna może zmniejszyć dodatnią skośność.
- **String Normalization**: Konwersja ciągów znaków do spójnego formatu, na przykład:
- Zamiana na małe litery
- Usuwanie znaków specjalnych (z zachowaniem istotnych znaków)
- Usuwanie stop words (częstych słów, które nie wpływają na znaczenie, takich jak "the", "is", "and")
- Usuwanie zbyt częstych i zbyt rzadkich słów (np. słów występujących w ponad 90% dokumentów lub mniej niż 5 razy w korpusie)
- Usuwanie początkowych i końcowych białych znaków
- Stemming/Lemmatization: Redukowanie słów do ich podstawowej lub źródłowej formy (np. "running" do "run").

- **Encoding Categorical Variables**: Konwersja zmiennych kategorycznych na reprezentacje numeryczne. Typowe techniki obejmują:
- **One-Hot Encoding**: Tworzenie kolumn binarnych dla każdej kategorii.
- Na przykład, jeśli cecha ma kategorie "red", "green" i "blue", zostanie przekształcona w trzy kolumny binarne: `is_red`(100), `is_green`(010) i `is_blue`(001).
- **Label Encoding**: Przypisywanie unikalnej liczby całkowitej do każdej kategorii.
- Na przykład: "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Przypisywanie liczb całkowitych na podstawie kolejności kategorii.
- Na przykład, jeśli kategorie to "low", "medium" i "high", można je zakodować odpowiednio jako 0, 1 i 2.
- **Hashing Encoding**: Używanie funkcji hashującej do konwersji kategorii na wektory o stałym rozmiarze, co może być przydatne w przypadku zmiennych kategorycznych o dużej liczbie unikalnych wartości.
- Na przykład, jeśli cecha ma wiele unikalnych kategorii, hashing może zmniejszyć wymiarowość, zachowując część informacji o kategoriach.
- **Bag of Words (BoW)**: Reprezentowanie danych tekstowych jako macierzy liczby lub częstotliwości wystąpień słów, gdzie każdy wiersz odpowiada dokumentowi, a każda kolumna — unikalnemu słowu w korpusie.
- Na przykład, jeśli korpus zawiera słowa "cat", "dog" i "fish", dokument zawierający "cat" i "dog" zostanie przedstawiony jako [1, 1, 0]. Ta konkretna reprezentacja nazywa się "unigram" i nie uwzględnia kolejności słów, przez co traci informacje semantyczne.
- **Bigram/Trigram**: Rozszerzenie BoW o uwzględnianie sekwencji słów (bigramów lub trigramów) w celu zachowania części kontekstu. Na przykład "cat and dog" zostanie przedstawione jako bigram [1, 1] dla "cat and" oraz [1, 1] dla "and dog". W tym przypadku gromadzona jest większa ilość informacji semantycznych (zwiększa się wymiarowość reprezentacji), ale tylko dla 2 lub 3 słów jednocześnie.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Miara statystyczna oceniająca znaczenie słowa w dokumencie względem zbioru dokumentów (korpusu). Łączy częstotliwość terminu (jak często słowo występuje w dokumencie) oraz odwrotną częstotliwość dokumentową (jak rzadkie jest słowo we wszystkich dokumentach).
- Na przykład, jeśli słowo "cat" często występuje w dokumencie, ale jest rzadkie w całym korpusie, uzyska wysoki wynik TF-IDF, wskazujący na jego znaczenie w tym dokumencie.

- **Feature Engineering**: Tworzenie nowych cech na podstawie istniejących w celu zwiększenia mocy predykcyjnej modelu. Może to obejmować łączenie cech, wyodrębnianie składników daty/czasu lub stosowanie transformacji specyficznych dla danej dziedziny.

## Podział danych <sup>[[3]](#references)</sup>

Podział danych polega na podzieleniu zbioru danych na oddzielne podzbiory do trenowania, walidacji i testowania. Jest to niezbędne do oceny wydajności modelu na nieznanych danych i zapobiegania przeuczeniu. Typowe strategie obejmują:
- **Train-Test Split**: Podział zbioru danych na zbiór treningowy (zazwyczaj 60–80% danych), zbiór walidacyjny (10–15% danych) do dostrajania hiperparametrów oraz zbiór testowy (10–15% danych). Model jest trenowany na zbiorze treningowym i oceniany na zbiorze testowym.
- Na przykład, jeśli masz zbiór danych zawierający 1000 próbek, możesz użyć 700 próbek do trenowania, 150 do walidacji i 150 do testowania.
- **Stratified Sampling**: Zapewnienie, że rozkład klas w zbiorach treningowym i testowym jest podobny do rozkładu w całym zbiorze danych. Jest to szczególnie ważne w przypadku niezbalansowanych zbiorów danych, w których niektóre klasy mogą mieć znacznie mniej próbek niż inne.
- **Time Series Split**: W przypadku danych szeregów czasowych zbiór danych jest dzielony według czasu, tak aby zbiór treningowy zawierał dane z wcześniejszych okresów, a zbiór testowy dane z późniejszych okresów. Pomaga to ocenić wydajność modelu na przyszłych danych.
- **K-Fold Cross-Validation**: Podział zbioru danych na K podzbiorów (foldów) i trenowanie modelu K razy, za każdym razem z użyciem innego foldu jako zbioru testowego, a pozostałych foldów jako zbioru treningowego. Pomaga to zapewnić ocenę modelu na różnych podzbiorach danych, dostarczając bardziej wiarygodnego oszacowania jego wydajności.

## Ocena modelu <sup>[[4]](#references)</sup>

Ocena modelu to proces analizowania wydajności modelu machine learning na nieznanych danych. Obejmuje użycie różnych metryk do określenia, jak dobrze model uogólnia się na nowe dane. Typowe metryki oceny obejmują:

### Accuracy

Accuracy to odsetek poprawnie przewidzianych przypadków w stosunku do wszystkich przypadków. Oblicza się ją według wzoru:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Accuracy to prosta i intuicyjna metryka, ale może nie być odpowiednia dla niezrównoważonych zbiorów danych, w których jedna klasa dominuje nad pozostałymi, ponieważ może dawać mylące wyobrażenie o skuteczności modelu. Na przykład jeśli 90% danych należy do klasy A, a model przewiduje klasę A dla wszystkich przypadków, osiągnie 90% accuracy, ale nie będzie przydatny do przewidywania klasy B.

### Precision

Precision to odsetek prawdziwie pozytywnych predykcji spośród wszystkich pozytywnych predykcji dokonanych przez model. Oblicza się ją następująco:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Precyzja jest szczególnie ważna w sytuacjach, w których wyniki fałszywie dodatnie są kosztowne lub niepożądane, takich jak diagnozy medyczne lub wykrywanie oszustw. Na przykład jeśli model przewiduje 100 przypadków jako pozytywne, ale tylko 80 z nich jest faktycznie pozytywnych, precyzja wynosiłaby 0,8 (80%).

### Czułość (Recall)

Czułość, znana również jako odsetek prawdziwie pozytywnych, to stosunek prawdziwie pozytywnych predykcji do wszystkich faktycznie pozytywnych przypadków. Oblicza się ją następująco:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Recall ma kluczowe znaczenie w scenariuszach, w których wyniki fałszywie ujemne są kosztowne lub niepożądane, takich jak wykrywanie chorób lub filtrowanie spamu. Na przykład, jeśli model identyfikuje 80 ze 100 rzeczywistych przypadków pozytywnych, recall wynosiłby 0,8 (80%).

### F1 Score

F1 score to średnia harmoniczna precision i recall, zapewniająca równowagę między tymi dwiema metrykami. Oblicza się go następująco:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Wynik F1 jest szczególnie przydatny w przypadku niezrównoważonych zbiorów danych, ponieważ uwzględnia zarówno false positives, jak i false negatives. Zapewnia pojedynczą metrykę odzwierciedlającą kompromis między precision a recall. Na przykład, jeśli model ma precision na poziomie 0.8 i recall na poziomie 0.6, wynik F1 wyniesie około 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

Metryka ROC-AUC ocenia zdolność modelu do rozróżniania klas, przedstawiając true positive rate (czułość) względem false positive rate przy różnych ustawieniach progu. Pole pod krzywą ROC (AUC) określa wydajność modelu, przy czym wartość 1 oznacza idealną klasyfikację, a wartość 0.5 oznacza losowe zgadywanie.

> [!TIP]
> ROC-AUC jest szczególnie przydatne w problemach klasyfikacji binarnej i zapewnia kompleksowy obraz wydajności modelu przy różnych progach. Jest mniej wrażliwe na niezrównoważenie klas w porównaniu z accuracy. Na przykład model z AUC wynoszącym 0.9 ma wysoką zdolność do rozróżniania instancji pozytywnych i negatywnych.

### Specificity

Specificity, znane również jako true negative rate, to odsetek poprawnych przewidywań negatywnych spośród wszystkich rzeczywistych instancji negatywnych. Oblicza się je jako:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Specyficzność jest ważna w scenariuszach, w których wyniki fałszywie dodatnie są kosztowne lub niepożądane, takich jak badania medyczne lub wykrywanie oszustw. Pomaga ocenić, jak dobrze model identyfikuje przypadki negatywne. Na przykład jeśli model prawidłowo identyfikuje 90 ze 100 rzeczywistych przypadków negatywnych, specyficzność wynosiłaby 0,9 (90%).

### Współczynnik korelacji Matthewsa (MCC)
Współczynnik korelacji Matthewsa (MCC) jest miarą jakości klasyfikacji binarnej. Uwzględnia prawdziwie i fałszywie dodatnie oraz prawdziwie i fałszywie ujemne wyniki, zapewniając zrównoważony obraz skuteczności modelu. MCC oblicza się następująco:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
gdzie:
- **TP**: True Positives
- **TN**: True Negatives
- **FP**: False Positives
- **FN**: False Negatives

> [!TIP]
> MCC mieści się w zakresie od -1 do 1, gdzie 1 oznacza idealną klasyfikację, 0 oznacza losowe zgadywanie, a -1 oznacza całkowitą niezgodność między predykcją a obserwacją. Jest szczególnie przydatny w przypadku niezrównoważonych zbiorów danych, ponieważ uwzględnia wszystkie cztery elementy macierzy pomyłek.

### Mean Absolute Error (MAE)
Mean Absolute Error (MAE) to metryka regresji mierząca średnią bezwzględną różnicę między wartościami przewidywanymi a rzeczywistymi. Oblicza się ją następująco:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
gdzie:
- **n**: Liczba instancji
- **y_i**: Rzeczywista wartość dla instancji i
- **ŷ_i**: Przewidywana wartość dla instancji i

> [!TIP]
> MAE zapewnia prostą interpretację średniego błędu predykcji, dzięki czemu jest łatwy do zrozumienia. Jest mniej wrażliwy na wartości odstające w porównaniu z innymi metrykami, takimi jak Mean Squared Error (MSE). Na przykład jeśli model ma MAE równe 5, oznacza to, że średnio predykcje modelu różnią się od rzeczywistych wartości o 5 jednostek.

### Macierz pomyłek

Macierz pomyłek to tabela podsumowująca wydajność modelu klasyfikacyjnego poprzez przedstawienie liczby predykcji: true positive, true negative, false positive i false negative. Zapewnia szczegółowy obraz tego, jak dobrze model działa dla każdej klasy.

|               | Przewidziana klasa pozytywna | Przewidziana klasa negatywna |
|---------------|---------------------|---------------------|
| Rzeczywista klasa pozytywna| True Positive (TP)  | False Negative (FN)  |
| Rzeczywista klasa negatywna| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Model poprawnie przewidział klasę pozytywną.
- **True Negative (TN)**: Model poprawnie przewidział klasę negatywną.
- **False Positive (FP)**: Model niepoprawnie przewidział klasę pozytywną (błąd typu I).
- **False Negative (FN)**: Model niepoprawnie przewidział klasę negatywną (błąd typu II).

Macierz pomyłek może służyć do obliczania metryk ewaluacyjnych, takich jak accuracy, precision, recall i F1 score.

## References

- [1] [scikit-learn - Wstępne przetwarzanie danych](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Uzupełnianie brakujących wartości](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Walidacja krzyżowa: ocena wydajności estymatora](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metryki i scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
