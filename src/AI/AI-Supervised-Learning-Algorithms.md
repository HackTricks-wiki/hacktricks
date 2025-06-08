# Algorytmy Uczenia Nadzorowanego

{{#include ../banners/hacktricks-training.md}}

## Podstawowe Informacje

Uczenie nadzorowane wykorzystuje oznaczone dane do trenowania modeli, które mogą dokonywać prognoz na nowych, nieznanych danych wejściowych. W cyberbezpieczeństwie, uczenie maszynowe nadzorowane jest szeroko stosowane w zadaniach takich jak wykrywanie intruzji (klasyfikacja ruchu sieciowego jako *normalny* lub *atak*), wykrywanie złośliwego oprogramowania (rozróżnianie złośliwego oprogramowania od łagodnego), wykrywanie phishingu (identyfikacja oszukańczych stron internetowych lub e-maili) oraz filtrowanie spamu, między innymi. Każdy algorytm ma swoje mocne strony i jest odpowiedni do różnych typów problemów (klasyfikacja lub regresja). Poniżej przeglądamy kluczowe algorytmy uczenia nadzorowanego, wyjaśniamy, jak działają, i demonstrujemy ich zastosowanie na rzeczywistych zbiorach danych dotyczących cyberbezpieczeństwa. Dyskutujemy również, jak łączenie modeli (uczenie zespołowe) może często poprawić wydajność predykcyjną.

## Algorytmy

-   **Regresja Liniowa:** Podstawowy algorytm regresji do przewidywania wyników numerycznych poprzez dopasowanie równania liniowego do danych.

-   **Regresja Logistyczna:** Algorytm klasyfikacji (pomimo swojej nazwy), który wykorzystuje funkcję logistyczną do modelowania prawdopodobieństwa wyniku binarnego.

-   **Drzewa Decyzyjne:** Modele o strukturze drzewiastej, które dzielą dane według cech, aby dokonywać prognoz; często używane ze względu na ich interpretowalność.

-   **Las Losowy:** Zespół drzew decyzyjnych (poprzez bagging), który poprawia dokładność i redukuje przeuczenie.

-   **Maszyny Wektorów Wsparcia (SVM):** Klasyfikatory maksymalnej marginesu, które znajdują optymalną hiperpłaszczyznę separującą; mogą używać jąder dla danych nieliniowych.

-   **Naive Bayes:** Klasyfikator probabilistyczny oparty na twierdzeniu Bayesa z założeniem niezależności cech, znany z zastosowania w filtrowaniu spamu.

-   **k-Najbliżsi Sąsiedzi (k-NN):** Prosty klasyfikator "oparty na instancji", który etykietuje próbkę na podstawie większościowej klasy jej najbliższych sąsiadów.

-   **Maszyny Wzmacniające Gradientowo:** Modele zespołowe (np. XGBoost, LightGBM), które budują silny predyktor, dodając sekwencyjnie słabsze uczące się (zwykle drzewa decyzyjne).

Każda sekcja poniżej dostarcza ulepszony opis algorytmu oraz **przykład kodu w Pythonie** z użyciem bibliotek takich jak `pandas` i `scikit-learn` (oraz `PyTorch` dla przykładu sieci neuronowej). Przykłady wykorzystują publicznie dostępne zbiory danych dotyczących cyberbezpieczeństwa (takie jak NSL-KDD do wykrywania intruzji oraz zbiór danych o stronach phishingowych) i mają spójną strukturę:

1.  **Załaduj zbiór danych** (pobierz przez URL, jeśli dostępny).

2.  **Wstępnie przetwórz dane** (np. zakoduj cechy kategoryczne, skaluj wartości, podziel na zbiory treningowe/testowe).

3.  **Wytrenuj model** na danych treningowych.

4.  **Oceń** na zbiorze testowym przy użyciu metryk: dokładność, precyzja, czułość, F1-score i ROC AUC dla klasyfikacji (oraz średni błąd kwadratowy dla regresji).

Zanurzmy się w każdy algorytm:

### Regresja Liniowa

Regresja liniowa to **algorytm regresji** używany do przewidywania ciągłych wartości numerycznych. Zakłada liniową zależność między cechami wejściowymi (zmiennymi niezależnymi) a wynikiem (zmienną zależną). Model stara się dopasować prostą linię (lub hiperpłaszczyznę w wyższych wymiarach), która najlepiej opisuje zależność między cechami a celem. Zwykle odbywa się to poprzez minimalizację sumy kwadratów błędów między wartościami przewidywanymi a rzeczywistymi (metoda najmniejszych kwadratów). 

Najprostsza forma reprezentacji regresji liniowej to linia:
```plaintext
y = mx + b
```
Gdzie:

- `y` to przewidywana wartość (wyjście)
- `m` to nachylenie linii (współczynnik)
- `x` to cecha wejściowa
- `b` to punkt przecięcia z osią y

Celem regresji liniowej jest znalezienie najlepiej dopasowanej linii, która minimalizuje różnicę między przewidywanymi wartościami a rzeczywistymi wartościami w zbiorze danych. Oczywiście, jest to bardzo proste, byłaby to prosta linia oddzielająca 2 kategorie, ale jeśli dodane zostaną dodatkowe wymiary, linia staje się bardziej złożona:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Regresja liniowa sama w sobie jest mniej powszechna w podstawowych zadaniach związanych z bezpieczeństwem (które często są klasyfikacją), ale może być stosowana do przewidywania wyników liczbowych. Na przykład, można użyć regresji liniowej do **przewidywania wolumenu ruchu sieciowego** lub **oszacowania liczby ataków w danym okresie** na podstawie danych historycznych. Może również przewidywać wskaźnik ryzyka lub oczekiwany czas do wykrycia ataku, biorąc pod uwagę określone metryki systemowe. W praktyce algorytmy klasyfikacji (takie jak regresja logistyczna lub drzewa) są częściej używane do wykrywania intruzji lub złośliwego oprogramowania, ale regresja liniowa stanowi fundament i jest przydatna w analizach ukierunkowanych na regresję.

#### **Kluczowe cechy regresji liniowej:**

-   **Rodzaj problemu:** Regresja (przewidywanie wartości ciągłych). Nie nadaje się do bezpośredniej klasyfikacji, chyba że zastosuje się próg do wyjścia.

-   **Interpretowalność:** Wysoka -- współczynniki są łatwe do interpretacji, pokazując liniowy wpływ każdej cechy.

-   **Zalety:** Prosta i szybka; dobry punkt odniesienia dla zadań regresyjnych; dobrze działa, gdy prawdziwy związek jest w przybliżeniu liniowy.

-   **Ograniczenia:** Nie może uchwycić złożonych lub nieliniowych relacji (bez ręcznego inżynierii cech); podatna na nieddopasowanie, jeśli relacje są nieliniowe; wrażliwa na wartości odstające, które mogą zniekształcać wyniki.

-   **Znajdowanie najlepszego dopasowania:** Aby znaleźć najlepszą linię dopasowania, która oddziela możliwe kategorie, używamy metody zwanej **Zwykłymi Najmniejszymi Kwadratami (OLS)**. Metoda ta minimalizuje sumę kwadratów różnic między wartościami obserwowanymi a wartościami przewidywanymi przez model liniowy.

<details>
<summary>Przykład -- Przewidywanie Czasu Połączenia (Regresja) w Zestawie Danych o Intruzjach
</summary>
Poniżej demonstrujemy regresję liniową, używając zestawu danych NSL-KDD w dziedzinie cyberbezpieczeństwa. Traktujemy to jako problem regresji, przewidując `czas trwania` połączeń sieciowych na podstawie innych cech. (W rzeczywistości `czas trwania` jest jedną cechą NSL-KDD; używamy go tutaj tylko w celu zilustrowania regresji.) Ładujemy zestaw danych, przetwarzamy go (kodujemy cechy kategoryczne), trenujemy model regresji liniowej i oceniamy błąd średniokwadratowy (MSE) oraz wynik R² na zbiorze testowym.
```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_squared_error, r2_score

# ── 1. Column names taken from the NSL‑KDD documentation ──────────────
col_names = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root",
"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login","count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

# ── 2. Load data *without* header row ─────────────────────────────────
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ── 3. Encode the 3 nominal features ─────────────────────────────────
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# ── 4. Prepare features / target ─────────────────────────────────────
X_train = df_train.drop(columns=['class', 'difficulty_level', 'duration'])
y_train = df_train['duration']

X_test  = df_test.drop(columns=['class', 'difficulty_level', 'duration'])
y_test  = df_test['duration']

# ── 5. Train & evaluate simple Linear Regression ─────────────────────
model = LinearRegression().fit(X_train, y_train)
y_pred = model.predict(X_test)

print(f"Test MSE: {mean_squared_error(y_test, y_pred):.2f}")
print(f"Test R² : {r2_score(y_test, y_pred):.3f}")

"""
Test MSE: 3021333.56
Test R² : -0.526
"""
```
W tym przykładzie model regresji liniowej próbuje przewidzieć `duration` połączenia na podstawie innych cech sieciowych. Mierzymy wydajność za pomocą średniego błędu kwadratowego (MSE) i R². Wartość R² bliska 1.0 wskazywałaby, że model wyjaśnia większość wariancji w `duration`, podczas gdy niska lub ujemna wartość R² wskazuje na słabe dopasowanie. (Nie bądź zaskoczony, jeśli R² jest tutaj niskie -- przewidywanie `duration` może być trudne na podstawie podanych cech, a regresja liniowa może nie uchwycić wzorców, jeśli są one złożone.)

### Regresja logistyczna

Regresja logistyczna to algorytm **klasyfikacji**, który modeluje prawdopodobieństwo, że dany przypadek należy do określonej klasy (zwykle klasy "pozytywnej"). Pomimo swojej nazwy, *regresja* logistyczna jest używana do wyników dyskretnych (w przeciwieństwie do regresji liniowej, która jest dla wyników ciągłych). Jest szczególnie używana do **klasyfikacji binarnej** (dwie klasy, np. złośliwe vs. łagodne), ale może być rozszerzona na problemy wieloklasowe (przy użyciu podejść softmax lub one-vs-rest).

Regresja logistyczna wykorzystuje funkcję logistyczną (znaną również jako funkcja sigmoidalna) do mapowania przewidywanych wartości na prawdopodobieństwa. Należy zauważyć, że funkcja sigmoidalna jest funkcją o wartościach między 0 a 1, która rośnie w kształcie litery S zgodnie z potrzebami klasyfikacji, co jest przydatne w zadaniach klasyfikacji binarnej. Dlatego każda cecha każdego wejścia jest mnożona przez przypisaną wagę, a wynik jest przekazywany przez funkcję sigmoidalną, aby uzyskać prawdopodobieństwo:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gdzie:

- `p(y=1|x)` to prawdopodobieństwo, że wynik `y` wynosi 1, biorąc pod uwagę wejście `x`
- `e` to podstawa logarytmu naturalnego
- `z` to liniowa kombinacja cech wejściowych, zazwyczaj reprezentowana jako `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Zauważ, że w najprostszej formie jest to linia prosta, ale w bardziej złożonych przypadkach staje się hiperpłaszczyzną z wieloma wymiarami (po jednym na cechę).

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Ponieważ wiele problemów związanych z bezpieczeństwem to zasadniczo decyzje tak/nie, regresja logistyczna jest szeroko stosowana. Na przykład system wykrywania włamań może używać regresji logistycznej do decydowania, czy połączenie sieciowe jest atakiem na podstawie cech tego połączenia. W wykrywaniu phishingu regresja logistyczna może łączyć cechy strony internetowej (długość URL, obecność symbolu "@", itp.) w prawdopodobieństwo bycia phishingiem. Była używana w filtrach spamowych pierwszej generacji i pozostaje silną bazą dla wielu zadań klasyfikacyjnych.

#### Regresja logistyczna dla klasyfikacji wieloklasowej

Regresja logistyczna jest zaprojektowana do klasyfikacji binarnej, ale może być rozszerzona, aby obsługiwać problemy wieloklasowe, stosując techniki takie jak **one-vs-rest** (OvR) lub **regresja softmax**. W OvR dla każdej klasy trenowany jest osobny model regresji logistycznej, traktując ją jako klasę pozytywną w porównaniu do wszystkich innych. Klasa z najwyższym przewidywanym prawdopodobieństwem jest wybierana jako ostateczna prognoza. Regresja softmax uogólnia regresję logistyczną na wiele klas, stosując funkcję softmax do warstwy wyjściowej, produkując rozkład prawdopodobieństwa dla wszystkich klas.

#### **Kluczowe cechy regresji logistycznej:**

-   **Rodzaj problemu:** Klasyfikacja (zwykle binarna). Przewiduje prawdopodobieństwo klasy pozytywnej.

-   **Interpretowalność:** Wysoka -- podobnie jak w regresji liniowej, współczynniki cech mogą wskazywać, jak każda cecha wpływa na log-odds wyniku. Ta przejrzystość jest często doceniana w bezpieczeństwie, aby zrozumieć, które czynniki przyczyniają się do alertu.

-   **Zalety:** Prosta i szybka w trenowaniu; dobrze działa, gdy związek między cechami a log-odds wyniku jest liniowy. Generuje prawdopodobieństwa, umożliwiając ocenę ryzyka. Przy odpowiedniej regularizacji dobrze się generalizuje i lepiej radzi sobie z multikolinearnością niż zwykła regresja liniowa.

-   **Ograniczenia:** Zakłada liniową granicę decyzyjną w przestrzeni cech (nie udaje się, jeśli prawdziwa granica jest złożona/nieliniowa). Może działać gorzej w problemach, gdzie interakcje lub efekty nieliniowe są krytyczne, chyba że ręcznie dodasz cechy wielomianowe lub interakcyjne. Ponadto regresja logistyczna jest mniej skuteczna, jeśli klasy nie są łatwo separowalne przez liniową kombinację cech.

<details>
<summary>Przykład -- Wykrywanie stron phishingowych z użyciem regresji logistycznej:</summary>

Użyjemy **Zestawu Danych Stron Phishingowych** (z repozytorium UCI), który zawiera wyodrębnione cechy stron internetowych (takie jak to, czy URL ma adres IP, wiek domeny, obecność podejrzanych elementów w HTML, itp.) oraz etykietę wskazującą, czy strona jest phishingowa, czy legalna. Trenujemy model regresji logistycznej do klasyfikacji stron internetowych, a następnie oceniamy jego dokładność, precyzję, czułość, F1-score i ROC AUC na zbiorze testowym.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load dataset
data = fetch_openml(data_id=4534, as_frame=True)  # PhishingWebsites
df   = data.frame
print(df.head())

# 2. Target mapping ─ legitimate (1) → 0, everything else → 1
df['Result'] = df['Result'].astype(int)
y = (df['Result'] != 1).astype(int)

# 3. Features
X = df.drop(columns=['Result'])

# 4. Train/test split with stratify
## Stratify ensures balanced classes in train/test sets
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# 5. Scale
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 6. Logistic Regression
## L‑BFGS is a modern, memory‑efficient “quasi‑Newton” algorithm that works well for medium/large datasets and supports multiclass natively.
## Upper bound on how many optimization steps the solver may take before it gives up.	Not all steps are guaranteed to be taken, but would be the maximum before a "failed to converge" error.
clf = LogisticRegression(max_iter=1000, solver='lbfgs', random_state=42)
clf.fit(X_train, y_train)

# 7. Evaluation
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1-score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.928
Precision: 0.934
Recall   : 0.901
F1-score : 0.917
ROC AUC  : 0.979
"""
```
W tym przykładzie wykrywania phishingu, regresja logistyczna produkuje prawdopodobieństwo dla każdej strony internetowej, że jest phishingowa. Oceniając dokładność, precyzję, czułość i F1, uzyskujemy poczucie wydajności modelu. Na przykład, wysoka czułość oznacza, że wychwytuje większość stron phishingowych (ważne dla bezpieczeństwa, aby zminimalizować pominięte ataki), podczas gdy wysoka precyzja oznacza, że ma niewiele fałszywych alarmów (ważne, aby uniknąć zmęczenia analityków). ROC AUC (Area Under the ROC Curve) daje miarę wydajności niezależną od progu (1.0 jest idealne, 0.5 nie lepsze niż przypadek). Regresja logistyczna często dobrze sprawdza się w takich zadaniach, ale jeśli granica decyzyjna między stronami phishingowymi a legalnymi jest złożona, mogą być potrzebne bardziej zaawansowane modele nieliniowe.

</details>

### Drzewa Decyzyjne

Drzewo decyzyjne to wszechstronny **algorytm uczenia nadzorowanego**, który może być używany zarówno do zadań klasyfikacyjnych, jak i regresyjnych. Uczy się hierarchicznego modelu decyzji w formie drzewa na podstawie cech danych. Każdy węzeł wewnętrzny drzewa reprezentuje test na konkretnej cesze, każda gałąź reprezentuje wynik tego testu, a każdy węzeł liściasty reprezentuje przewidywaną klasę (dla klasyfikacji) lub wartość (dla regresji).

Aby zbudować drzewo, algorytmy takie jak CART (Classification and Regression Tree) używają miar takich jak **impurty Gini** lub **zysk informacyjny (entropia)**, aby wybrać najlepszą cechę i próg do podziału danych na każdym kroku. Celem przy każdym podziale jest podział danych w celu zwiększenia jednorodności zmiennej docelowej w wynikowych podzbiorach (dla klasyfikacji, każdy węzeł dąży do tego, aby był jak najczystszy, zawierając głównie jedną klasę).

Drzewa decyzyjne są **wysoce interpretowalne** -- można śledzić ścieżkę od korzenia do liścia, aby zrozumieć logikę stojącą za przewidywaniem (np. *"JEŚLI `service = telnet` I `src_bytes > 1000` I `failed_logins > 3` TO klasyfikuj jako atak"*). To jest cenne w cyberbezpieczeństwie, aby wyjaśnić, dlaczego dany alert został zgłoszony. Drzewa mogą naturalnie obsługiwać zarówno dane numeryczne, jak i kategoryczne i wymagają niewielkiego wstępnego przetwarzania (np. skalowanie cech nie jest potrzebne).

Jednak pojedyncze drzewo decyzyjne może łatwo dopasować się do danych treningowych, szczególnie jeśli jest głęboko rozwinięte (wiele podziałów). Techniki takie jak przycinanie (ograniczanie głębokości drzewa lub wymaganie minimalnej liczby próbek na liść) są często stosowane, aby zapobiec przeuczeniu.

Istnieją 3 główne komponenty drzewa decyzyjnego:
- **Węzeł Korzeniowy**: Górny węzeł drzewa, reprezentujący cały zbiór danych.
- **Węzły Wewnętrzne**: Węzły, które reprezentują cechy i decyzje na podstawie tych cech.
- **Węzły Liściaste**: Węzły, które reprezentują ostateczny wynik lub przewidywanie.

Drzewo może wyglądać tak:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Drzewa decyzyjne były używane w systemach wykrywania włamań do wyprowadzania **reguł** identyfikujących ataki. Na przykład, wczesne IDS, takie jak systemy oparte na ID3/C4.5, generowały reguły czytelne dla ludzi, aby odróżnić ruch normalny od złośliwego. Są również używane w analizie złośliwego oprogramowania do decydowania, czy plik jest złośliwy na podstawie jego atrybutów (rozmiar pliku, entropia sekcji, wywołania API itp.). Przejrzystość drzew decyzyjnych sprawia, że są one przydatne, gdy potrzebna jest transparentność -- analityk może zbadać drzewo, aby zweryfikować logikę detekcji.

#### **Kluczowe cechy drzew decyzyjnych:**

-   **Rodzaj problemu:** Klasyfikacja i regresja. Powszechnie używane do klasyfikacji ataków w porównaniu do ruchu normalnego itp.

-   **Interpretowalność:** Bardzo wysoka -- decyzje modelu można wizualizować i rozumieć jako zestaw reguł if-then. To jest główna zaleta w bezpieczeństwie dla zaufania i weryfikacji zachowania modelu.

-   **Zalety:** Mogą uchwycić nieliniowe relacje i interakcje między cechami (każde podział można postrzegać jako interakcję). Nie ma potrzeby skalowania cech ani kodowania one-hot zmiennych kategorycznych -- drzewa obsługują to natywnie. Szybkie wnioskowanie (predykcja to tylko podążanie ścieżką w drzewie).

-   **Ograniczenia:** Skłonność do przeuczenia, jeśli nie jest kontrolowane (głębokie drzewo może zapamiętać zestaw treningowy). Mogą być niestabilne -- małe zmiany w danych mogą prowadzić do innej struktury drzewa. Jako pojedyncze modele, ich dokładność może nie dorównywać bardziej zaawansowanym metodom (zespoły, takie jak Random Forests, zazwyczaj działają lepiej, redukując wariancję).

-   **Znajdowanie najlepszego podziału:**
- **Zanieczyszczenie Gini:** Mierzy zanieczyszczenie węzła. Niższe zanieczyszczenie Gini wskazuje na lepszy podział. Wzór to:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Gdzie `p_i` to proporcja instancji w klasie `i`.

- **Entropia:** Mierzy niepewność w zbiorze danych. Niższa entropia wskazuje na lepszy podział. Wzór to:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Gdzie `p_i` to proporcja instancji w klasie `i`.

- **Zysk informacyjny:** Redukcja entropii lub zanieczyszczenia Gini po podziale. Im wyższy zysk informacyjny, tym lepszy podział. Oblicza się go jako:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ponadto, drzewo kończy się, gdy:
- Wszystkie instancje w węźle należą do tej samej klasy. Może to prowadzić do przeuczenia.
- Osiągnięto maksymalną głębokość (hardcodowaną) drzewa. To jest sposób na zapobieganie przeuczeniu.
- Liczba instancji w węźle jest poniżej określonego progu. To również jest sposób na zapobieganie przeuczeniu.
- Zysk informacyjny z dalszych podziałów jest poniżej określonego progu. To również jest sposób na zapobieganie przeuczeniu.

<details>
<summary>Przykład -- Drzewo decyzyjne do wykrywania włamań:</summary>
Wytrenujemy drzewo decyzyjne na zbiorze danych NSL-KDD, aby klasyfikować połączenia sieciowe jako *normalne* lub *atak*. NSL-KDD to ulepszona wersja klasycznego zbioru danych KDD Cup 1999, z cechami takimi jak typ protokołu, usługa, czas trwania, liczba nieudanych logowań itp., oraz etykietą wskazującą typ ataku lub "normalny". Wszystkie typy ataków przypiszemy do klasy "anomalia" (klasyfikacja binarna: normalny vs anomalia). Po treningu ocenimy wydajność drzewa na zbiorze testowym.
```python
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣  NSL‑KDD column names (41 features + class + difficulty)
col_names = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised",
"root_shell","su_attempted","num_root","num_file_creations","num_shells",
"num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count",
"srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
"same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate",
"dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate",
"class","difficulty_level"
]

# 2️⃣  Load data ➜ *headerless* CSV
train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 3️⃣  Encode the 3 nominal features
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# 4️⃣  Prepare X / y   (binary: 0 = normal, 1 = attack)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
y_train = (df_train['class'].str.lower() != 'normal').astype(int)

X_test  = df_test.drop(columns=['class', 'difficulty_level'])
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# 5️⃣  Train Decision‑Tree
clf = DecisionTreeClassifier(max_depth=10, random_state=42)
clf.fit(X_train, y_train)

# 6️⃣  Evaluate
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")


"""
Accuracy : 0.772
Precision: 0.967
Recall   : 0.621
F1‑score : 0.756
ROC AUC  : 0.758
"""
```
W tym przykładzie drzewa decyzyjnego ograniczyliśmy głębokość drzewa do 10, aby uniknąć ekstremalnego przeuczenia (parametr `max_depth=10`). Metryki pokazują, jak dobrze drzewo rozróżnia ruch normalny od ataków. Wysoki recall oznacza, że wychwytuje większość ataków (ważne dla IDS), podczas gdy wysoka precyzja oznacza niewiele fałszywych alarmów. Drzewa decyzyjne często osiągają przyzwoitą dokładność na danych strukturalnych, ale pojedyncze drzewo może nie osiągnąć najlepszej możliwej wydajności. Niemniej jednak, *interpretowalność* modelu to duży plus - możemy zbadać podziały drzewa, aby zobaczyć, które cechy (np. `service`, `src_bytes` itd.) mają największy wpływ na oznaczanie połączenia jako złośliwego.

</details>

### Random Forests

Random Forest to metoda **uczenia zespołowego**, która opiera się na drzewach decyzyjnych, aby poprawić wydajność. Random forest trenuje wiele drzew decyzyjnych (stąd "las") i łączy ich wyniki, aby dokonać ostatecznej predykcji (w przypadku klasyfikacji, zazwyczaj przez głosowanie większościowe). Dwie główne idee w random forest to **bagging** (bootstrap aggregating) i **losowość cech**:

-   **Bagging:** Każde drzewo jest trenowane na losowej próbce bootstrap z danych treningowych (próbkowane z wymianą). To wprowadza różnorodność między drzewami.

-   **Losowość cech:** Przy każdym podziale w drzewie rozważana jest losowa podgrupa cech do podziału (zamiast wszystkich cech). To dodatkowo de-korelatuje drzewa.

Poprzez uśrednianie wyników wielu drzew, random forest redukuje wariancję, którą może mieć pojedyncze drzewo decyzyjne. Mówiąc prosto, poszczególne drzewa mogą być przeuczone lub hałaśliwe, ale duża liczba różnorodnych drzew głosujących razem wygładza te błędy. Wynikiem jest często model o **wyższej dokładności** i lepszej generalizacji niż pojedyncze drzewo decyzyjne. Dodatkowo, random forests mogą dostarczyć oszacowanie ważności cech (patrząc na to, jak bardzo każdy podział cechy redukuje nieczystość w średniej).

Random forests stały się **koniecznością w cyberbezpieczeństwie** w zadaniach takich jak wykrywanie intruzji, klasyfikacja złośliwego oprogramowania i wykrywanie spamu. Często działają dobrze od razu po uruchomieniu z minimalnym dostosowaniem i mogą obsługiwać duże zestawy cech. Na przykład, w wykrywaniu intruzji, random forest może przewyższać pojedyncze drzewo decyzyjne, wychwytując subtelniejsze wzorce ataków z mniejszą liczbą fałszywych alarmów. Badania wykazały, że random forests wypadają korzystnie w porównaniu do innych algorytmów w klasyfikacji ataków w zbiorach danych takich jak NSL-KDD i UNSW-NB15.

#### **Kluczowe cechy Random Forests:**

-   **Typ problemu:** Głównie klasyfikacja (używane również do regresji). Bardzo dobrze nadaje się do wysokowymiarowych danych strukturalnych, które są powszechne w logach bezpieczeństwa.

-   **Interpretowalność:** Niższa niż w przypadku pojedynczego drzewa decyzyjnego - nie można łatwo wizualizować ani wyjaśnić setek drzew jednocześnie. Jednak wyniki ważności cech dostarczają pewnych informacji na temat tego, które atrybuty są najbardziej wpływowe.

-   **Zalety:** Zazwyczaj wyższa dokładność niż modele pojedynczego drzewa dzięki efektowi zespołowemu. Odporność na przeuczenie - nawet jeśli poszczególne drzewa są przeuczone, zespół generalizuje lepiej. Obsługuje zarówno cechy numeryczne, jak i kategoryczne oraz może w pewnym stopniu zarządzać brakującymi danymi. Jest również stosunkowo odporny na wartości odstające.

-   **Ograniczenia:** Rozmiar modelu może być duży (wiele drzew, z których każde może być głębokie). Prognozy są wolniejsze niż w przypadku pojedynczego drzewa (ponieważ musisz agregować wyniki z wielu drzew). Mniej interpretowalne - chociaż znasz ważne cechy, dokładna logika nie jest łatwo śledzona jako prosta zasada. Jeśli zbiór danych jest ekstremalnie wysokowymiarowy i rzadki, trenowanie bardzo dużego lasu może być obciążające obliczeniowo.

-   **Proces treningowy:**
1. **Próbkowanie Bootstrap:** Losowo próbkuj dane treningowe z wymianą, aby stworzyć wiele podzbiorów (próbki bootstrap).
2. **Budowa drzewa:** Dla każdej próbki bootstrap zbuduj drzewo decyzyjne, używając losowej podgrupy cech przy każdym podziale. To wprowadza różnorodność między drzewami.
3. **Agregacja:** W przypadku zadań klasyfikacyjnych, ostateczna predykcja jest dokonywana przez głosowanie większościowe wśród prognoz wszystkich drzew. W przypadku zadań regresyjnych, ostateczna prognoza to średnia prognoz ze wszystkich drzew.

<details>
<summary>Przykład -- Random Forest do wykrywania intruzji (NSL-KDD):</summary>
Użyjemy tego samego zbioru danych NSL-KDD (etykietowanego binarnie jako normalne vs anomalia) i wytrenujemy klasyfikator Random Forest. Oczekujemy, że random forest będzie działał tak samo dobrze lub lepiej niż pojedyncze drzewo decyzyjne, dzięki uśrednianiu zespołowemu redukującemu wariancję. Ocenimy go tymi samymi metrykami.
```python
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1. LOAD DATA  ➜  files have **no header row**, so we
#                 pass `header=None` and give our own column names.
# ──────────────────────────────────────────────
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# ──────────────────────────────────────────────
# 2. PRE‑PROCESSING
# ──────────────────────────────────────────────
# 2‑a) Encode the three categorical columns so that the model
#      receives integers instead of strings.
#      LabelEncoder gives an int to each unique value in the column: {'icmp':0, 'tcp':1, 'udp':2}
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder().fit(pd.concat([df_train[col], df_test[col]]))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])

# 2‑b) Build feature matrix X  (drop target & difficulty)
X_train = df_train.drop(columns=['class', 'difficulty_level'])
X_test  = df_test.drop(columns=['class', 'difficulty_level'])

# 2‑c) Convert multi‑class labels to binary
#      label 0 → 'normal' traffic, label 1 → any attack
y_train = (df_train['class'].str.lower() != 'normal').astype(int)
y_test  = (df_test['class'].str.lower() != 'normal').astype(int)

# ──────────────────────────────────────────────
# 3. MODEL: RANDOM FOREST
# ──────────────────────────────────────────────
# • n_estimators = 100 ➜ build 100 different decision‑trees.
# • max_depth=None  ➜ let each tree grow until pure leaves
#                    (or until it hits other stopping criteria).
# • random_state=42 ➜ reproducible randomness.
model = RandomForestClassifier(
n_estimators=100,
max_depth=None,
random_state=42,
bootstrap=True          # default: each tree is trained on a
# bootstrap sample the same size as
# the original training set.
# max_samples           # ← you can set this (float or int) to
#     use a smaller % of samples per tree.
)

model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4. EVALUATION
# ──────────────────────────────────────────────
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.770
Precision: 0.966
Recall:    0.618
F1-score:  0.754
ROC AUC:   0.962
"""
```
Las random forest zazwyczaj osiąga silne wyniki w tym zadaniu wykrywania intruzji. Możemy zaobserwować poprawę w metrykach takich jak F1 lub AUC w porównaniu do pojedynczego drzewa decyzyjnego, szczególnie w zakresie recall lub precision, w zależności od danych. To jest zgodne z rozumieniem, że *"Random Forest (RF) jest klasyfikatorem zespołowym i wypada dobrze w porównaniu do innych tradycyjnych klasyfikatorów w skutecznej klasyfikacji ataków."*. W kontekście operacji bezpieczeństwa model random forest może bardziej niezawodnie oznaczać ataki, jednocześnie redukując fałszywe alarmy, dzięki uśrednianiu wielu reguł decyzyjnych. Ważność cech z lasu może powiedzieć nam, które cechy sieciowe są najbardziej wskazujące na ataki (np. pewne usługi sieciowe lub nietypowe liczby pakietów).

</details>

### Support Vector Machines (SVM)

Support Vector Machines to potężne modele uczenia nadzorowanego, używane głównie do klasyfikacji (a także regresji jako SVR). SVM stara się znaleźć **optymalną hiperpowierzchnię separującą**, która maksymalizuje margines między dwiema klasami. Tylko podzbiór punktów treningowych (tzw. "wektory wsparcia" najbliższe granicy) określa położenie tej hiperpowierzchni. Maksymalizując margines (odległość między wektorami wsparcia a hiperpowierzchnią), SVM-y zazwyczaj osiągają dobrą generalizację.

Kluczową cechą mocy SVM jest zdolność do używania **funkcji jądrowych** do obsługi nieliniowych relacji. Dane mogą być implicitnie przekształcane w wyższy wymiar przestrzeni cech, gdzie może istnieć liniowy separator. Powszechne jądra to wielomianowe, funkcja bazowa radialna (RBF) i sigmoidalna. Na przykład, jeśli klasy ruchu sieciowego nie są liniowo separowalne w surowej przestrzeni cech, jądro RBF może je odwzorować w wyższy wymiar, gdzie SVM znajduje liniowy podział (co odpowiada nieliniowej granicy w oryginalnej przestrzeni). Elastyczność wyboru jąder pozwala SVM-om radzić sobie z różnorodnymi problemami.

SVM-y są znane z dobrej wydajności w sytuacjach z przestrzeniami cech o wysokiej wymiarowości (jak dane tekstowe lub sekwencje opcode złośliwego oprogramowania) oraz w przypadkach, gdy liczba cech jest duża w porównaniu do liczby próbek. Były popularne w wielu wczesnych zastosowaniach cyberbezpieczeństwa, takich jak klasyfikacja złośliwego oprogramowania i wykrywanie intruzji oparte na anomaliach w latach 2000, często wykazując wysoką dokładność.

Jednak SVM-y nie skalują się łatwo do bardzo dużych zbiorów danych (złożoność treningu jest super-liniowa w liczbie próbek, a zużycie pamięci może być wysokie, ponieważ może być konieczne przechowywanie wielu wektorów wsparcia). W praktyce, w przypadku zadań takich jak wykrywanie intruzji w sieci z milionami rekordów, SVM może być zbyt wolny bez starannego podpróbkowania lub użycia metod przybliżonych.

#### **Kluczowe cechy SVM:**

-   **Typ problemu:** Klasyfikacja (binarna lub wieloklasowa przez one-vs-one/one-vs-rest) oraz warianty regresji. Często używane w klasyfikacji binarnej z wyraźnym oddzieleniem marginesu.

-   **Interpretowalność:** Średnia -- SVM-y nie są tak interpretowalne jak drzewa decyzyjne czy regresja logistyczna. Chociaż można zidentyfikować, które punkty danych są wektorami wsparcia i uzyskać pewne pojęcie o tym, które cechy mogą być wpływowe (poprzez wagi w przypadku liniowego jądra), w praktyce SVM-y (szczególnie z nieliniowymi jądrami) są traktowane jako klasyfikatory czarnej skrzynki.

-   **Zalety:** Skuteczne w przestrzeniach o wysokiej wymiarowości; mogą modelować złożone granice decyzyjne dzięki sztuczce jądrowej; odporne na przeuczenie, jeśli margines jest maksymalizowany (szczególnie z odpowiednim parametrem regularyzacji C); dobrze działają nawet gdy klasy nie są oddzielone dużą odległością (znajdują najlepszą granicę kompromisową).

-   **Ograniczenia:** **Intensywne obliczeniowo** dla dużych zbiorów danych (zarówno trening, jak i prognozowanie źle skalują się w miarę wzrostu danych). Wymaga starannego dostrojenia parametrów jądra i regularyzacji (C, typ jądra, gamma dla RBF itp.). Nie dostarcza bezpośrednio probabilistycznych wyników (choć można użyć skalowania Platta, aby uzyskać prawdopodobieństwa). Ponadto, SVM-y mogą być wrażliwe na wybór parametrów jądra --- zły wybór może prowadzić do niedopasowania lub przeuczenia.

*Przykłady zastosowań w cyberbezpieczeństwie:* SVM-y były używane w **wykrywaniu złośliwego oprogramowania** (np. klasyfikacja plików na podstawie wyodrębnionych cech lub sekwencji opcode), **wykrywaniu anomalii w sieci** (klasyfikacja ruchu jako normalny vs złośliwy) oraz **wykrywaniu phishingu** (używając cech URL). Na przykład, SVM mógłby wziąć cechy e-maila (liczby określonych słów kluczowych, oceny reputacji nadawcy itp.) i sklasyfikować go jako phishing lub legalny. Zostały również zastosowane do **wykrywania intruzji** na zestawach cech takich jak KDD, często osiągając wysoką dokładność kosztem obliczeń.

<details>
<summary>Przykład -- SVM do klasyfikacji złośliwego oprogramowania:</summary>
Ponownie użyjemy zestawu danych o stronach phishingowych, tym razem z SVM. Ponieważ SVM-y mogą być wolne, użyjemy podzbioru danych do treningu, jeśli to konieczne (zestaw danych ma około 11k instancji, co SVM może obsłużyć w rozsądny sposób). Użyjemy jądra RBF, które jest powszechnym wyborem dla danych nieliniowych, i włączymy szacowanie prawdopodobieństwa, aby obliczyć ROC AUC.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ─────────────────────────────────────────────────────────────
# 1️⃣  LOAD DATASET   (OpenML id 4534: “PhishingWebsites”)
#     • as_frame=True  ➜  returns a pandas DataFrame
# ─────────────────────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame
print(df.head())          # quick sanity‑check

# ─────────────────────────────────────────────────────────────
# 2️⃣  TARGET: 0 = legitimate, 1 = phishing
#     The raw column has values {1, 0, -1}:
#       1  → legitimate   → 0
#       0  &  -1          → phishing    → 1
# ─────────────────────────────────────────────────────────────
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split  (stratified keeps class proportions)
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# ─────────────────────────────────────────────────────────────
# 3️⃣  PRE‑PROCESS: Standardize features (mean‑0 / std‑1)
# ─────────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# ─────────────────────────────────────────────────────────────
# 4️⃣  MODEL: RBF‑kernel SVM
#     • C=1.0         (regularization strength)
#     • gamma='scale' (1 / [n_features × var(X)])
#     • probability=True  → enable predict_proba for ROC‑AUC
# ─────────────────────────────────────────────────────────────
clf = SVC(kernel="rbf", C=1.0, gamma="scale",
probability=True, random_state=42)
clf.fit(X_train, y_train)

# ─────────────────────────────────────────────────────────────
# 5️⃣  EVALUATION
# ─────────────────────────────────────────────────────────────
y_pred = clf.predict(X_test)
y_prob = clf.predict_proba(X_test)[:, 1]   # P(class 1)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.956
Precision: 0.963
Recall   : 0.937
F1‑score : 0.950
ROC AUC  : 0.989
"""
```
Model SVM wygeneruje metryki, które możemy porównać z regresją logistyczną w tym samym zadaniu. Możemy stwierdzić, że SVM osiąga wysoką dokładność i AUC, jeśli dane są dobrze oddzielone przez cechy. Z drugiej strony, jeśli zbiór danych zawiera dużo szumów lub nakładające się klasy, SVM może nieznacznie przewyższać regresję logistyczną. W praktyce, SVM mogą dać impuls, gdy istnieją złożone, nieliniowe relacje między cechami a klasą – jądro RBF może uchwycić zakrzywione granice decyzyjne, które regresja logistyczna by przeoczyła. Jak w przypadku wszystkich modeli, konieczne jest staranne dostrojenie parametrów `C` (regularyzacja) i parametrów jądra (jak `gamma` dla RBF), aby zrównoważyć bias i wariancję.

</details>

#### Różnice między regresją logistyczną a SVM

| Aspekt | **Regresja Logistyczna** | **Maszyny Wektorów Wsparcia** |
|---|---|---|
| **Funkcja celu** | Minimalizuje **log‑loss** (entropia krzyżowa). | Maksymalizuje **margines** przy minimalizacji **hinge‑loss**. |
| **Granica decyzyjna** | Znajduje **najlepiej dopasowaną hiperpłaszczyznę**, która modeluje _P(y\|x)_. | Znajduje **hiperpłaszczyznę o maksymalnym marginesie** (największa przerwa do najbliższych punktów). |
| **Wynik** | **Probabilistyczny** – podaje skalibrowane prawdopodobieństwa klas za pomocą σ(w·x + b). | **Deterministyczny** – zwraca etykiety klas; prawdopodobieństwa wymagają dodatkowej pracy (np. skalowanie Platta). |
| **Regularyzacja** | L2 (domyślnie) lub L1, bezpośrednio równoważy niedopasowanie/przeuczenie. | Parametr C równoważy szerokość marginesu w stosunku do błędnych klasyfikacji; parametry jądra dodają złożoności. |
| **Jądra / Nieliniowe** | Forma natywna jest **liniowa**; nieliniowość dodawana przez inżynierię cech. | Wbudowany **trik jądra** (RBF, poly, itp.) pozwala modelować złożone granice w przestrzeni o wysokim wymiarze. |
| **Skalowalność** | Rozwiązuje optymalizację wypukłą w **O(nd)**; dobrze radzi sobie z bardzo dużym n. | Trening może być **O(n²–n³)** pod względem pamięci/czasu bez wyspecjalizowanych rozwiązań; mniej przyjazny dla ogromnego n. |
| **Interpretowalność** | **Wysoka** – wagi pokazują wpływ cech; stosunek szans intuicyjny. | **Niska** dla nieliniowych jąder; wektory wsparcia są rzadkie, ale trudne do wyjaśnienia. |
| **Wrażliwość na wartości odstające** | Używa gładkiego log‑loss → mniej wrażliwy. | Hinge‑loss z twardym marginesem może być **wrażliwy**; miękki margines (C) łagodzi. |
| **Typowe przypadki użycia** | Ocena kredytowa, ryzyko medyczne, testy A/B – gdzie **prawdopodobieństwa i wyjaśnialność** mają znaczenie. | Klasyfikacja obrazów/tekstów, bioinformatyka – gdzie **złożone granice** i **dane o wysokim wymiarze** mają znaczenie. |

* **Jeśli potrzebujesz skalibrowanych prawdopodobieństw, interpretowalności lub pracujesz na ogromnych zbiorach danych — wybierz regresję logistyczną.**
* **Jeśli potrzebujesz elastycznego modelu, który może uchwycić nieliniowe relacje bez ręcznej inżynierii cech — wybierz SVM (z jądrami).**
* Oba optymalizują cele wypukłe, więc **globalne minima są gwarantowane**, ale jądra SVM dodają hiperparametry i koszty obliczeniowe.

### Naive Bayes

Naive Bayes to rodzina **klasyfikatorów probabilistycznych** opartych na zastosowaniu twierdzenia Bayesa z silnym założeniem o niezależności między cechami. Pomimo tego "naiwnego" założenia, Naive Bayes często działa zaskakująco dobrze w niektórych zastosowaniach, szczególnie tych związanych z danymi tekstowymi lub kategorycznymi, takimi jak wykrywanie spamu.

#### Twierdzenie Bayesa

Twierdzenie Bayesa jest podstawą klasyfikatorów Naive Bayes. Łączy warunkowe i marginalne prawdopodobieństwa zdarzeń losowych. Wzór to:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gdzie:
- `P(A|B)` to prawdopodobieństwo posteriori klasy `A` biorąc pod uwagę cechę `B`.
- `P(B|A)` to prawdopodobieństwo cechy `B` biorąc pod uwagę klasę `A`.
- `P(A)` to prawdopodobieństwo a priori klasy `A`.
- `P(B)` to prawdopodobieństwo a priori cechy `B`.

Na przykład, jeśli chcemy sklasyfikować, czy tekst jest napisany przez dziecko czy dorosłego, możemy użyć słów w tekście jako cech. Na podstawie pewnych początkowych danych, klasyfikator Naive Bayes wcześniej obliczy prawdopodobieństwa każdego słowa w każdej potencjalnej klasie (dziecko lub dorosły). Gdy podany zostanie nowy tekst, obliczy prawdopodobieństwo każdej potencjalnej klasy biorąc pod uwagę słowa w tekście i wybierze klasę z najwyższym prawdopodobieństwem.

Jak widać w tym przykładzie, klasyfikator Naive Bayes jest bardzo prosty i szybki, ale zakłada, że cechy są niezależne, co nie zawsze ma miejsce w danych rzeczywistych.


#### Typy klasyfikatorów Naive Bayes

Istnieje kilka typów klasyfikatorów Naive Bayes, w zależności od rodzaju danych i rozkładu cech:
- **Gaussian Naive Bayes**: Zakłada, że cechy mają rozkład Gaussa (normalny). Jest odpowiedni dla danych ciągłych.
- **Multinomial Naive Bayes**: Zakłada, że cechy mają rozkład wielomianowy. Jest odpowiedni dla danych dyskretnych, takich jak liczba słów w klasyfikacji tekstu.
- **Bernoulli Naive Bayes**: Zakłada, że cechy są binarne (0 lub 1). Jest odpowiedni dla danych binarnych, takich jak obecność lub brak słów w klasyfikacji tekstu.
- **Categorical Naive Bayes**: Zakłada, że cechy są zmiennymi kategorycznymi. Jest odpowiedni dla danych kategorycznych, takich jak klasyfikacja owoców na podstawie ich koloru i kształtu.


#### **Kluczowe cechy Naive Bayes:**

-   **Rodzaj problemu:** Klasyfikacja (binarny lub wieloklasowy). Często używany do zadań klasyfikacji tekstu w cyberbezpieczeństwie (spam, phishing itp.).

-   **Interpretowalność:** Średnia -- nie jest tak bezpośrednio interpretowalny jak drzewo decyzyjne, ale można zbadać wyuczone prawdopodobieństwa (np. które słowa są najbardziej prawdopodobne w spamie w porównaniu do wiadomości ham). Forma modelu (prawdopodobieństwa dla każdej cechy biorąc pod uwagę klasę) może być zrozumiana, jeśli zajdzie taka potrzeba.

-   **Zalety:** **Bardzo szybkie** uczenie i przewidywanie, nawet na dużych zbiorach danych (liniowe w liczbie instancji * liczba cech). Wymaga stosunkowo małej ilości danych do wiarygodnego oszacowania prawdopodobieństw, szczególnie przy odpowiednim wygładzaniu. Często jest zaskakująco dokładny jako punkt odniesienia, szczególnie gdy cechy niezależnie przyczyniają się do dowodów na klasę. Dobrze działa z danymi o wysokiej wymiarowości (np. tysiące cech z tekstu). Nie wymaga skomplikowanego dostrajania poza ustawieniem parametru wygładzania.

-   **Ograniczenia:** Założenie niezależności może ograniczać dokładność, jeśli cechy są silnie skorelowane. Na przykład, w danych sieciowych, cechy takie jak `src_bytes` i `dst_bytes` mogą być skorelowane; Naive Bayes nie uchwyci tej interakcji. W miarę jak rozmiar danych staje się bardzo duży, bardziej ekspresywne modele (takie jak zespoły lub sieci neuronowe) mogą przewyższyć NB, ucząc się zależności cech. Ponadto, jeśli do identyfikacji ataku potrzebna jest określona kombinacja cech (a nie tylko pojedyncze cechy niezależnie), NB będzie miał trudności.

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Klasycznym zastosowaniem jest **wykrywanie spamu** -- Naive Bayes był rdzeniem wczesnych filtrów spamowych, wykorzystując częstotliwości niektórych tokenów (słów, fraz, adresów IP) do obliczenia prawdopodobieństwa, że e-mail jest spamem. Jest również używany w **wykrywaniu e-maili phishingowych** i **klasyfikacji URL**, gdzie obecność określonych słów kluczowych lub cech (takich jak "login.php" w URL, lub `@` w ścieżce URL) przyczynia się do prawdopodobieństwa phishingu. W analizie złośliwego oprogramowania można sobie wyobrazić klasyfikator Naive Bayes, który wykorzystuje obecność określonych wywołań API lub uprawnień w oprogramowaniu do przewidywania, czy jest to złośliwe oprogramowanie. Chociaż bardziej zaawansowane algorytmy często działają lepiej, Naive Bayes pozostaje dobrym punktem odniesienia ze względu na swoją szybkość i prostotę.

<details>
<summary>Przykład -- Naive Bayes do wykrywania phishingu:</summary>
Aby zademonstrować Naive Bayes, użyjemy Gaussian Naive Bayes na zbiorze danych NSL-KDD dotyczących intruzji (z etykietami binarnymi). Gaussian NB potraktuje każdą cechę jako podlegającą normalnemu rozkładowi dla każdej klasy. To jest szorstki wybór, ponieważ wiele cech sieciowych jest dyskretnych lub silnie skośnych, ale pokazuje, jak można zastosować NB do danych cech ciągłych. Możemy również wybrać Bernoulli NB na zbiorze danych z cechami binarnymi (takimi jak zestaw wyzwolonych alertów), ale tutaj pozostaniemy przy NSL-KDD dla ciągłości.
```python
import pandas as pd
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD data
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

# 2. Preprocess (encode categorical features, prepare binary labels)
from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])
X_train = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_train = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
X_test  = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test  = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 3. Train Gaussian Naive Bayes
model = GaussianNB()
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
# For ROC AUC, need probability of class 1:
y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, "predict_proba") else y_pred
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.450
Precision: 0.937
Recall:    0.037
F1-score:  0.071
ROC AUC:   0.867
"""
```
Ten kod trenuje klasyfikator Naive Bayes do wykrywania ataków. Naive Bayes obliczy takie rzeczy jak `P(service=http | Attack)` i `P(Service=http | Normal)` na podstawie danych treningowych, zakładając niezależność między cechami. Następnie wykorzysta te prawdopodobieństwa do klasyfikacji nowych połączeń jako normalne lub atak na podstawie zaobserwowanych cech. Wydajność NB na NSL-KDD może nie być tak wysoka jak w przypadku bardziej zaawansowanych modeli (ponieważ niezależność cech jest naruszona), ale często jest przyzwoita i charakteryzuje się ekstremalną szybkością. W scenariuszach takich jak filtrowanie e-maili w czasie rzeczywistym lub wstępna triage URL-i, model Naive Bayes może szybko oznaczyć oczywiście złośliwe przypadki przy niskim zużyciu zasobów.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors to jeden z najprostszych algorytmów uczenia maszynowego. To **metoda nieparametryczna, oparta na instancjach**, która dokonuje prognoz na podstawie podobieństwa do przykładów w zbiorze treningowym. Idea klasyfikacji jest następująca: aby sklasyfikować nowy punkt danych, należy znaleźć **k** najbliższych punktów w danych treningowych (jego "najbliżsi sąsiedzi") i przypisać klasę większości wśród tych sąsiadów. "Bliskość" definiuje się za pomocą metryki odległości, zazwyczaj odległości euklidesowej dla danych numerycznych (inne odległości mogą być używane dla różnych typów cech lub problemów).

K-NN nie wymaga *żadnego wyraźnego treningu* -- faza "treningu" polega jedynie na przechowywaniu zbioru danych. Cała praca odbywa się podczas zapytania (prognozy): algorytm musi obliczyć odległości od punktu zapytania do wszystkich punktów treningowych, aby znaleźć najbliższe. To sprawia, że czas prognozy jest **liniowy w liczbie próbek treningowych**, co może być kosztowne dla dużych zbiorów danych. Z tego powodu k-NN najlepiej nadaje się do mniejszych zbiorów danych lub scenariuszy, w których można wymienić pamięć i szybkość na prostotę.

Pomimo swojej prostoty, k-NN może modelować bardzo złożone granice decyzyjne (ponieważ efektywnie granica decyzyjna może mieć dowolny kształt dyktowany przez rozkład przykładów). Zazwyczaj radzi sobie dobrze, gdy granica decyzyjna jest bardzo nieregularna i masz dużo danych -- zasadniczo pozwalając danym "mówić same za siebie". Jednak w wysokich wymiarach metryki odległości mogą stać się mniej znaczące (klątwa wymiarowości), a metoda może mieć trudności, chyba że masz ogromną liczbę próbek.

*Przykłady zastosowań w cyberbezpieczeństwie:* k-NN został zastosowany do wykrywania anomalii -- na przykład system wykrywania włamań może oznaczyć zdarzenie sieciowe jako złośliwe, jeśli większość jego najbliższych sąsiadów (poprzednich zdarzeń) była złośliwa. Jeśli normalny ruch tworzy klastry, a ataki są wartościami odstającymi, podejście K-NN (z k=1 lub małym k) zasadniczo wykonuje **wykrywanie anomalii najbliższego sąsiada**. K-NN był również używany do klasyfikacji rodzin złośliwego oprogramowania na podstawie binarnych wektorów cech: nowy plik może być sklasyfikowany jako określona rodzina złośliwego oprogramowania, jeśli jest bardzo bliski (w przestrzeni cech) znanym przypadkom tej rodziny. W praktyce k-NN nie jest tak powszechny jak bardziej skalowalne algorytmy, ale jest koncepcyjnie prosty i czasami używany jako punkt odniesienia lub do problemów w małej skali.

#### **Kluczowe cechy k-NN:**

-   **Rodzaj problemu:** Klasyfikacja (istnieją również warianty regresji). To *metoda leniwego uczenia* -- brak wyraźnego dopasowania modelu.

-   **Interpretowalność:** Niska do średniej -- nie ma globalnego modelu ani zwięzłego wyjaśnienia, ale można interpretować wyniki, patrząc na najbliższych sąsiadów, którzy wpłynęli na decyzję (np. "ten ruch sieciowy został sklasyfikowany jako złośliwy, ponieważ jest podobny do tych 3 znanych złośliwych ruchów"). Tak więc, wyjaśnienia mogą być oparte na przykładach.

-   **Zalety:** Bardzo proste do wdrożenia i zrozumienia. Nie zakłada żadnych założeń dotyczących rozkładu danych (nieparametryczne). Może naturalnie obsługiwać problemy wieloklasowe. Jest **adaptacyjne** w tym sensie, że granice decyzyjne mogą być bardzo złożone, kształtowane przez rozkład danych.

-   **Ograniczenia:** Prognozowanie może być wolne dla dużych zbiorów danych (musi obliczyć wiele odległości). Intensywne pamięciowo -- przechowuje wszystkie dane treningowe. Wydajność pogarsza się w wysokowymiarowych przestrzeniach cech, ponieważ wszystkie punkty mają tendencję do stawania się prawie równoodległe (co sprawia, że koncepcja "najbliższego" staje się mniej znacząca). Należy odpowiednio dobrać *k* (liczbę sąsiadów) -- zbyt małe k może być hałaśliwe, zbyt duże k może obejmować nieistotne punkty z innych klas. Ponadto cechy powinny być odpowiednio skalowane, ponieważ obliczenia odległości są wrażliwe na skalę.

<details>
<summary>Przykład -- k-NN do wykrywania phishingu:</summary>

Ponownie użyjemy NSL-KDD (klasyfikacja binarna). Ponieważ k-NN jest obliczeniowo intensywny, użyjemy podzbioru danych treningowych, aby utrzymać to w zasięgu w tej demonstracji. Wybierzemy, powiedzmy, 20 000 próbek treningowych z pełnych 125k i użyjemy k=5 sąsiadów. Po treningu (naprawdę tylko przechowywaniu danych) ocenimy na zbiorze testowym. Również skalujemy cechy do obliczeń odległości, aby zapewnić, że żadna pojedyncza cecha nie dominuje z powodu skali.
```python
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1. Load NSL-KDD and preprocess similarly
col_names = [                       # 41 features + 2 targets
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root","num_file_creations",
"num_shells","num_access_files","num_outbound_cmds","is_host_login",
"is_guest_login","count","srv_count","serror_rate","srv_serror_rate",
"rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate",
"srv_diff_host_rate","dst_host_count","dst_host_srv_count",
"dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate",
"dst_host_srv_rerror_rate","class","difficulty_level"
]

train_url = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Train.csv"
test_url  = "https://raw.githubusercontent.com/Mamcose/NSL-KDD-Network-Intrusion-Detection/master/NSL_KDD_Test.csv"

df_train = pd.read_csv(train_url, header=None, names=col_names)
df_test  = pd.read_csv(test_url,  header=None, names=col_names)

from sklearn.preprocessing import LabelEncoder
for col in ['protocol_type', 'service', 'flag']:
le = LabelEncoder()
le.fit(pd.concat([df_train[col], df_test[col]], axis=0))
df_train[col] = le.transform(df_train[col])
df_test[col]  = le.transform(df_test[col])
X = df_train.drop(columns=['class', 'difficulty_level'], errors='ignore')
y = df_train['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)
# Use a random subset of the training data for K-NN (to reduce computation)
X_train = X.sample(n=20000, random_state=42)
y_train = y[X_train.index]
# Use the full test set for evaluation
X_test = df_test.drop(columns=['class', 'difficulty_level'], errors='ignore')
y_test = df_test['class'].apply(lambda x: 0 if x.strip().lower() == 'normal' else 1)

# 2. Feature scaling for distance-based model
from sklearn.preprocessing import StandardScaler
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test  = scaler.transform(X_test)

# 3. Train k-NN classifier (store data)
model = KNeighborsClassifier(n_neighbors=5, n_jobs=-1)
model.fit(X_train, y_train)

# 4. Evaluate on test set
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]
print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1-score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.780
Precision: 0.972
Recall:    0.632
F1-score:  0.766
ROC AUC:   0.837
"""
```
Model k-NN sklasyfikuje połączenie, analizując 5 najbliższych połączeń w podzbiorze zbioru treningowego. Jeśli na przykład 4 z tych sąsiadów to ataki (anomalia), a 1 jest normalne, nowe połączenie zostanie sklasyfikowane jako atak. Wydajność może być rozsądna, chociaż często nie tak wysoka jak w przypadku dobrze dostrojonego Random Forest lub SVM na tych samych danych. Jednak k-NN może czasami błyszczeć, gdy rozkłady klas są bardzo nieregularne i złożone - skutecznie wykorzystując wyszukiwanie oparte na pamięci. W cyberbezpieczeństwie k-NN (z k=1 lub małym k) może być używane do wykrywania znanych wzorców ataków na podstawie przykładów lub jako komponent w bardziej złożonych systemach (np. do klasteryzacji, a następnie klasyfikacji na podstawie przynależności do klastra).

### Gradient Boosting Machines (np. XGBoost)

Gradient Boosting Machines należą do najpotężniejszych algorytmów dla danych strukturalnych. **Gradient boosting** odnosi się do techniki budowania zespołu słabych uczniów (często drzew decyzyjnych) w sposób sekwencyjny, gdzie każdy nowy model koryguje błędy poprzedniego zespołu. W przeciwieństwie do baggingu (Random Forest), który buduje drzewa równolegle i je uśrednia, boosting buduje drzewa *jedno po drugim*, każde koncentrując się bardziej na instancjach, które poprzednie drzewa źle przewidziały.

Najpopularniejsze implementacje w ostatnich latach to **XGBoost**, **LightGBM** i **CatBoost**, które są bibliotekami drzew decyzyjnych z gradientowym boostingiem (GBDT). Odniosły one ogromny sukces w konkursach i zastosowaniach uczenia maszynowego, często **osiągając wyniki na poziomie stanu techniki na zbiorach danych tabelarycznych**. W cyberbezpieczeństwie badacze i praktycy używali drzew z gradientowym boostingiem do zadań takich jak **wykrywanie złośliwego oprogramowania** (używając cech wyodrębnionych z plików lub zachowania w czasie rzeczywistym) oraz **wykrywanie intruzji w sieci**. Na przykład model gradient boosting może łączyć wiele słabych reguł (drzew) takich jak "jeśli wiele pakietów SYN i nietypowy port -> prawdopodobnie skanowanie" w silny detektor kompozytowy, który uwzględnia wiele subtelnych wzorców.

Dlaczego drzewa z boostingiem są tak skuteczne? Każde drzewo w sekwencji jest trenowane na *resztkowych błędach* (gradientach) prognoz obecnego zespołu. W ten sposób model stopniowo **"wzmacnia"** obszary, w których jest słaby. Użycie drzew decyzyjnych jako podstawowych uczniów oznacza, że końcowy model może uchwycić złożone interakcje i nieliniowe relacje. Ponadto boosting ma wbudowaną formę regularizacji: dodając wiele małych drzew (i używając współczynnika uczenia do skalowania ich wkładów), często dobrze generalizuje bez dużego przeuczenia, pod warunkiem, że wybrane są odpowiednie parametry.

#### **Kluczowe cechy Gradient Boosting:**

-   **Typ problemu:** Głównie klasyfikacja i regresja. W bezpieczeństwie zazwyczaj klasyfikacja (np. binarna klasyfikacja połączenia lub pliku). Obsługuje problemy binarne, wieloklasowe (z odpowiednią stratą) i nawet problemy rankingowe.

-   **Interpretowalność:** Niska do średniej. Chociaż pojedyncze drzewo z boostingiem jest małe, pełny model może mieć setki drzew, co nie jest interpretowalne dla ludzi jako całość. Jednak, podobnie jak Random Forest, może dostarczać oceny ważności cech, a narzędzia takie jak SHAP (SHapley Additive exPlanations) mogą być używane do interpretacji indywidualnych prognoz w pewnym zakresie.

-   **Zalety:** Często **najlepiej działający** algorytm dla danych strukturalnych/tabelarycznych. Może wykrywać złożone wzorce i interakcje. Ma wiele pokręteł do strojenia (liczba drzew, głębokość drzew, współczynnik uczenia, terminy regularizacji), aby dostosować złożoność modelu i zapobiec przeuczeniu. Nowoczesne implementacje są zoptymalizowane pod kątem szybkości (np. XGBoost używa informacji o gradientach drugiego rzędu i efektywnych struktur danych). Zwykle lepiej radzi sobie z niezrównoważonymi danymi, gdy jest połączony z odpowiednimi funkcjami straty lub przez dostosowanie wag próbek.

-   **Ograniczenia:** Bardziej skomplikowane do strojenia niż prostsze modele; trening może być wolny, jeśli drzewa są głębokie lub liczba drzew jest duża (choć nadal zazwyczaj szybszy niż trening porównywalnej głębokiej sieci neuronowej na tych samych danych). Model może przeuczyć się, jeśli nie jest dostrojony (np. zbyt wiele głębokich drzew przy niewystarczającej regularizacji). Z powodu wielu hiperparametrów, skuteczne użycie gradient boosting może wymagać większej wiedzy lub eksperymentowania. Ponadto, podobnie jak metody oparte na drzewach, nie radzi sobie z bardzo rzadkimi danymi o wysokiej wymiarowości tak efektywnie jak modele liniowe lub Naive Bayes (choć nadal może być stosowane, np. w klasyfikacji tekstu, ale może nie być pierwszym wyborem bez inżynierii cech).

> [!TIP]
> *Przykłady zastosowań w cyberbezpieczeństwie:* Prawie wszędzie tam, gdzie można użyć drzewa decyzyjnego lub lasu losowego, model gradient boosting może osiągnąć lepszą dokładność. Na przykład, **konkursy wykrywania złośliwego oprogramowania** firmy Microsoft widziały intensywne wykorzystanie XGBoost na inżynierowanych cechach z plików binarnych. Badania nad **wykrywaniem intruzji w sieci** często raportują najlepsze wyniki z GBDT (np. XGBoost na zbiorach danych CIC-IDS2017 lub UNSW-NB15). Modele te mogą przyjmować szeroki zakres cech (typy protokołów, częstotliwość określonych zdarzeń, cechy statystyczne ruchu itp.) i łączyć je w celu wykrywania zagrożeń. W wykrywaniu phishingu, gradient boosting może łączyć cechy leksykalne URL, cechy reputacji domeny i cechy treści stron, aby osiągnąć bardzo wysoką dokładność. Podejście zespołowe pomaga pokryć wiele przypadków brzegowych i subtelności w danych.

<details>
<summary>Przykład -- XGBoost do wykrywania phishingu:</summary>
Użyjemy klasyfikatora gradient boosting na zbiorze danych o phishingu. Aby uprościć sprawy i uczynić je samodzielnymi, użyjemy `sklearn.ensemble.GradientBoostingClassifier` (który jest wolniejszą, ale prostą implementacją). Zwykle można by użyć bibliotek `xgboost` lub `lightgbm` dla lepszej wydajności i dodatkowych funkcji. Wytrenujemy model i ocenimy go podobnie jak wcześniej.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

# 1️⃣ Load the “Phishing Websites” data directly from OpenML
data = fetch_openml(data_id=4534, as_frame=True)   # or data_name="PhishingWebsites"
df   = data.frame

# 2️⃣ Separate features/target & make sure everything is numeric
X = df.drop(columns=["Result"])
y = df["Result"].astype(int).apply(lambda v: 1 if v == 1 else 0)  # map {-1,1} → {0,1}

# (If any column is still object‑typed, coerce it to numeric.)
X = X.apply(pd.to_numeric, errors="coerce").fillna(0)

# 3️⃣ Train/test split
X_train, X_test, y_train, y_test = train_test_split(
X.values, y, test_size=0.20, random_state=42
)

# 4️⃣ Gradient Boosting model
model = GradientBoostingClassifier(
n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42
)
model.fit(X_train, y_train)

# 5️⃣ Evaluation
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print(f"Accuracy:  {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall:    {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score:  {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC:   {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy:  0.951
Precision: 0.949
Recall:    0.965
F1‑score:  0.957
ROC AUC:   0.990
"""
```
Model gradient boosting prawdopodobnie osiągnie bardzo wysoką dokładność i AUC na tym zbiorze danych dotyczących phishingu (często te modele mogą przekraczać 95% dokładności przy odpowiednim dostrojeniu na takich danych, co widać w literaturze. To pokazuje, dlaczego GBDT są uważane za *"najnowocześniejszy model dla zbiorów danych tabelarycznych"* -- często przewyższają prostsze algorytmy, uchwycając złożone wzorce. W kontekście cyberbezpieczeństwa może to oznaczać wychwytywanie większej liczby stron phishingowych lub ataków przy mniejszej liczbie pominięć. Oczywiście, należy być ostrożnym w kwestii nadmiernego dopasowania -- zazwyczaj stosujemy techniki takie jak walidacja krzyżowa i monitorujemy wydajność na zbiorze walidacyjnym podczas opracowywania takiego modelu do wdrożenia.

</details>

### Łączenie modeli: Uczenie zespołowe i Stacking

Uczenie zespołowe to strategia **łączenia wielu modeli** w celu poprawy ogólnej wydajności. Już widzieliśmy konkretne metody zespołowe: Random Forest (zespół drzew za pomocą baggingu) i Gradient Boosting (zespół drzew za pomocą sekwencyjnego boosting). Ale zespoły można tworzyć także w inny sposób, na przykład **zespoły głosujące** lub **stacked generalization (stacking)**. Główna idea polega na tym, że różne modele mogą uchwycić różne wzorce lub mieć różne słabości; łącząc je, możemy **zrekompensować błędy każdego modelu mocnymi stronami innych**.

-   **Zespół głosujący:** W prostym klasyfikatorze głosującym trenujemy wiele różnorodnych modeli (powiedzmy, regresję logistyczną, drzewo decyzyjne i SVM) i pozwalamy im głosować na ostateczną prognozę (głos większościowy dla klasyfikacji). Jeśli ważymy głosy (np. wyższa waga dla dokładniejszych modeli), to jest to ważony schemat głosowania. Zazwyczaj poprawia to wydajność, gdy poszczególne modele są wystarczająco dobre i niezależne -- zespół zmniejsza ryzyko błędu pojedynczego modelu, ponieważ inne mogą go skorygować. To jak posiadanie panelu ekspertów zamiast jednej opinii.

-   **Stacking (Zespół Stacked):** Stacking idzie o krok dalej. Zamiast prostego głosowania, trenuje **meta-model**, aby **nauczyć się, jak najlepiej łączyć prognozy** modeli bazowych. Na przykład, trenujesz 3 różne klasyfikatory (uczniowie bazowi), a następnie przekazujesz ich wyniki (lub prawdopodobieństwa) jako cechy do meta-klasyfikatora (często prostego modelu, takiego jak regresja logistyczna), który uczy się optymalnego sposobu ich mieszania. Meta-model jest trenowany na zbiorze walidacyjnym lub za pomocą walidacji krzyżowej, aby uniknąć nadmiernego dopasowania. Stacking często może przewyższyć proste głosowanie, ucząc się *które modele bardziej ufać w jakich okolicznościach*. W cyberbezpieczeństwie jeden model może być lepszy w wychwytywaniu skanów sieciowych, podczas gdy inny lepiej wychwytuje sygnalizację złośliwego oprogramowania; model stacking mógłby nauczyć się polegać na każdym z nich w odpowiedni sposób.

Zespoły, niezależnie od tego, czy przez głosowanie, czy stacking, mają tendencję do **zwiększania dokładności** i odporności. Wadą jest zwiększona złożoność i czasami zmniejszona interpretowalność (choć niektóre podejścia zespołowe, takie jak średnia drzew decyzyjnych, mogą nadal dostarczać pewnych informacji, np. o ważności cech). W praktyce, jeśli ograniczenia operacyjne na to pozwalają, użycie zespołu może prowadzić do wyższych wskaźników wykrywania. Wiele zwycięskich rozwiązań w wyzwaniach związanych z cyberbezpieczeństwem (i ogólnie w konkursach Kaggle) wykorzystuje techniki zespołowe, aby wydobyć ostatni kawałek wydajności.

<details>
<summary>Przykład -- Zespół głosujący do wykrywania phishingu:</summary>
Aby zilustrować stacking modeli, połączmy kilka modeli, które omówiliśmy na zbiorze danych dotyczących phishingu. Użyjemy regresji logistycznej, drzewa decyzyjnego i k-NN jako uczniów bazowych, a Random Forest jako meta-ucznia do agregacji ich prognoz. Meta-uczeń będzie trenowany na wynikach uczniów bazowych (używając walidacji krzyżowej na zbiorze treningowym). Oczekujemy, że model stacking będzie działał tak samo dobrze lub nieco lepiej niż poszczególne modele.
```python
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import StackingClassifier, RandomForestClassifier
from sklearn.metrics import (accuracy_score, precision_score,
recall_score, f1_score, roc_auc_score)

# ──────────────────────────────────────────────
# 1️⃣  LOAD DATASET (OpenML id 4534)
# ──────────────────────────────────────────────
data = fetch_openml(data_id=4534, as_frame=True)     # “PhishingWebsites”
df   = data.frame

# Target mapping:  1 → legitimate (0),   0/‑1 → phishing (1)
y = (df["Result"].astype(int) != 1).astype(int)
X = df.drop(columns=["Result"])

# Train / test split (stratified to keep class balance)
X_train, X_test, y_train, y_test = train_test_split(
X, y, test_size=0.20, random_state=42, stratify=y)

# ──────────────────────────────────────────────
# 2️⃣  DEFINE BASE LEARNERS
#     • LogisticRegression and k‑NN need scaling ➜ wrap them
#       in a Pipeline(StandardScaler → model) so that scaling
#       happens inside each CV fold of StackingClassifier.
# ──────────────────────────────────────────────
base_learners = [
('lr',  make_pipeline(StandardScaler(),
LogisticRegression(max_iter=1000,
solver='lbfgs',
random_state=42))),
('dt',  DecisionTreeClassifier(max_depth=5, random_state=42)),
('knn', make_pipeline(StandardScaler(),
KNeighborsClassifier(n_neighbors=5)))
]

# Meta‑learner (level‑2 model)
meta_learner = RandomForestClassifier(n_estimators=50, random_state=42)

stack_model = StackingClassifier(
estimators      = base_learners,
final_estimator = meta_learner,
cv              = 5,        # 5‑fold CV to create meta‑features
passthrough     = False     # only base learners’ predictions go to meta‑learner
)

# ──────────────────────────────────────────────
# 3️⃣  TRAIN ENSEMBLE
# ──────────────────────────────────────────────
stack_model.fit(X_train, y_train)

# ──────────────────────────────────────────────
# 4️⃣  EVALUATE
# ──────────────────────────────────────────────
y_pred = stack_model.predict(X_test)
y_prob = stack_model.predict_proba(X_test)[:, 1]   # P(phishing)

print(f"Accuracy : {accuracy_score(y_test, y_pred):.3f}")
print(f"Precision: {precision_score(y_test, y_pred):.3f}")
print(f"Recall   : {recall_score(y_test, y_pred):.3f}")
print(f"F1‑score : {f1_score(y_test, y_pred):.3f}")
print(f"ROC AUC  : {roc_auc_score(y_test, y_prob):.3f}")

"""
Accuracy : 0.954
Precision: 0.951
Recall   : 0.946
F1‑score : 0.948
ROC AUC  : 0.992
"""
```
Zespół składający się z modeli korzysta z komplementarnych mocnych stron modeli bazowych. Na przykład, regresja logistyczna może radzić sobie z liniowymi aspektami danych, drzewo decyzyjne może uchwycić specyficzne interakcje przypominające reguły, a k-NN może doskonale sprawdzać się w lokalnych sąsiedztwach przestrzeni cech. Model meta (tutaj las losowy) może nauczyć się, jak ważyć te wejścia. Ostateczne metryki często pokazują poprawę (nawet jeśli niewielką) w porównaniu do metryk pojedynczego modelu. W naszym przykładzie phishingu, jeśli regresja logistyczna miała F1 na poziomie 0.95, a drzewo 0.94, zespół może osiągnąć 0.96, wykorzystując miejsca, w których każdy model się myli.

Metody zespołowe, takie jak ta, demonstrują zasadę, że *"łączenie wielu modeli zazwyczaj prowadzi do lepszej generalizacji"*. W cyberbezpieczeństwie można to wdrożyć, mając wiele silników detekcji (jeden może być oparty na regułach, jeden na uczeniu maszynowym, jeden oparty na anomaliach) i następnie warstwę, która agreguje ich alerty -- efektywnie forma zespołu -- aby podjąć ostateczną decyzję z wyższą pewnością. Przy wdrażaniu takich systemów należy wziąć pod uwagę dodatkową złożoność i upewnić się, że zespół nie staje się zbyt trudny do zarządzania lub wyjaśnienia. Jednak z punktu widzenia dokładności, zespoły i stosowanie modeli to potężne narzędzia do poprawy wydajności modeli.

</details>


## References

- [https://madhuramiah.medium.com/logistic-regression-6e55553cc003](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [https://www.geeksforgeeks.org/decision-tree-introduction-example/](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [https://www.ibm.com/think/topics/support-vector-machine](https://www.ibm.com/think/topics/support-vector-machine)
- [https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [https://zvelo.com/ai-and-machine-learning-in-cybersecurity/](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://www.ibm.com/think/topics/knn](https://www.ibm.com/think/topics/knn)
- [https://arxiv.org/pdf/2101.02552](https://arxiv.org/pdf/2101.02552)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
