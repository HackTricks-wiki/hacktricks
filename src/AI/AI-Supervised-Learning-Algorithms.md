# Algorytmy uczenia nadzorowanego

{{#include ../banners/hacktricks-training.md}}

## Podstawowe informacje

Uczenie nadzorowane wykorzystuje oznaczone dane do trenowania modeli, które mogą dokonywać predykcji na podstawie nowych, wcześniej niewidzianych danych wejściowych. W cyberbezpieczeństwie nadzorowane uczenie maszynowe jest szeroko stosowane do zadań takich jak wykrywanie włamań (klasyfikowanie ruchu sieciowego jako *normalnego* lub *ataku*), wykrywanie malware (odróżnianie złośliwego oprogramowania od nieszkodliwego), wykrywanie phishingu (identyfikowanie fałszywych stron internetowych lub wiadomości e-mail) oraz filtrowanie spamu.<sup>[[1]](#references)</sup> Każdy algorytm ma swoje mocne strony i nadaje się do różnych typów problemów (klasyfikacji lub regresji). Poniżej omawiamy najważniejsze algorytmy uczenia nadzorowanego, wyjaśniamy, jak działają, i pokazujemy ich użycie na rzeczywistych zbiorach danych związanych z cyberbezpieczeństwem. Omawiamy również, jak łączenie modeli (uczenie zespołowe) może często poprawić skuteczność predykcji.

## Algorytmy

-   **Regresja liniowa:** Podstawowy algorytm regresji służący do przewidywania wartości liczbowych poprzez dopasowanie do danych równania liniowego.

-   **Regresja logistyczna:** Algorytm klasyfikacji (pomimo swojej nazwy), który wykorzystuje funkcję logistyczną do modelowania prawdopodobieństwa wyniku binarnego.

-   **Drzewa decyzyjne:** Modele o strukturze drzewa, które dzielą dane na podstawie cech w celu dokonywania predykcji; często stosowane ze względu na ich interpretowalność.

-   **Lasy losowe:** Zespół drzew decyzyjnych (za pomocą baggingu), który poprawia dokładność i ogranicza przeuczenie.

-   **Support Vector Machines (SVM):** Klasyfikatory maksymalnego marginesu, które znajdują optymalną hiperpłaszczyznę rozdzielającą; mogą wykorzystywać jądra dla danych nieliniowych.

-   **Naive Bayes:** Klasyfikator probabilistyczny oparty na twierdzeniu Bayesa i założeniu niezależności cech, powszechnie stosowany do filtrowania spamu.

-   **k-Nearest Neighbors (k-NN):** Prosty klasyfikator „oparty na instancjach”, który przypisuje próbkę do klasy na podstawie klasy większościowej jej najbliższych sąsiadów.

-   **Gradient Boosting Machines:** Modele zespołowe (np. XGBoost, LightGBM), które tworzą silny predyktor poprzez sekwencyjne dodawanie słabszych predyktorów (zwykle drzew decyzyjnych).

Każda z poniższych sekcji zawiera ulepszony opis algorytmu oraz **przykład kodu w Pythonie** z wykorzystaniem bibliotek takich jak `pandas` i `scikit-learn` (oraz `PyTorch` w przykładzie sieci neuronowej). Przykłady korzystają z publicznie dostępnych zbiorów danych związanych z cyberbezpieczeństwem (takich jak NSL-KDD do wykrywania włamań oraz zbiór danych Phishing Websites) i mają spójną strukturę:

1.  **Wczytanie zbioru danych** (pobranie za pomocą URL, jeśli jest dostępny).

2.  **Wstępne przetworzenie danych** (np. zakodowanie cech kategorycznych, przeskalowanie wartości, podział na zbiory treningowe i testowe).

3.  **Wytrenowanie modelu** na danych treningowych.

4.  **Ocena** na zbiorze testowym za pomocą metryk: accuracy, precision, recall, F1-score i ROC AUC dla klasyfikacji (oraz mean squared error dla regresji).

Przejdźmy do omówienia poszczególnych algorytmów:

### Regresja liniowa

Regresja liniowa to algorytm **regresji** używany do przewidywania ciągłych wartości liczbowych. Zakłada on liniową zależność między cechami wejściowymi (zmiennymi niezależnymi) a wyjściem (zmienną zależną). Model próbuje dopasować prostą (lub hiperpłaszczyznę w wyższych wymiarach), która najlepiej opisuje zależność między cechami a zmienną docelową. Zwykle odbywa się to poprzez minimalizowanie sumy kwadratów błędów między wartościami przewidywanymi a rzeczywistymi (metoda Ordinary Least Squares).<sup>[[2]](#references)</sup>

Najprościej przedstawić regresję liniową za pomocą prostej:
```plaintext
y = mx + b
```
Gdzie:

- `y` to przewidywana wartość (wynik)
- `m` to nachylenie linii (współczynnik)
- `x` to cecha wejściowa
- `b` to punkt przecięcia z osią y

Celem regresji liniowej jest znalezienie najlepiej dopasowanej linii, która minimalizuje różnicę między przewidywanymi wartościami a rzeczywistymi wartościami w zbiorze danych. Oczywiście jest to bardzo proste — byłaby to prosta oddzielająca 2 kategorie, ale jeśli dodanych zostanie więcej wymiarów, linia staje się bardziej złożona:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Przypadki użycia w cyberbezpieczeństwie:* Linear regression sama w sobie jest rzadziej stosowana w podstawowych zadaniach związanych z bezpieczeństwem (które często są zadaniami klasyfikacji), ale można jej używać do przewidywania wyników liczbowych. Można na przykład wykorzystać linear regression do **przewidywania natężenia ruchu sieciowego** lub **szacowania liczby ataków w danym okresie** na podstawie danych historycznych. Może także przewidywać wynik ryzyka lub oczekiwany czas do wykrycia ataku na podstawie określonych metryk systemu. W praktyce algorytmy klasyfikacji (takie jak logistic regression lub drzewa) są częściej używane do wykrywania intruzji lub malware, ale linear regression stanowi podstawę i jest przydatna w analizach ukierunkowanych na regression.

#### **Kluczowe cechy Linear Regression:**

-   **Typ problemu:** Regression (przewidywanie wartości ciągłych). Nie nadaje się do bezpośredniej klasyfikacji, chyba że do wyniku zostanie zastosowany próg.

-   **Interpretowalność:** Wysoka -- współczynniki są proste do interpretacji i pokazują liniowy wpływ każdej cechy.

-   **Zalety:** Prosta i szybka; stanowi dobry punkt odniesienia dla zadań regression; działa dobrze, gdy rzeczywista zależność jest w przybliżeniu liniowa.

-   **Ograniczenia:** Nie potrafi uchwycić złożonych lub nieliniowych zależności (bez ręcznego engineeringu cech); może prowadzić do underfittingu, jeśli zależności są nieliniowe; jest wrażliwa na wartości odstające, które mogą zniekształcać wyniki.

-   **Wyznaczanie najlepszego dopasowania:** Aby znaleźć najlepiej dopasowaną linię, która rozdziela możliwe kategorie, używamy metody nazywanej **Ordinary Least Squares (OLS)**. Metoda ta minimalizuje sumę kwadratów różnic między zaobserwowanymi wartościami a wartościami przewidywanymi przez model liniowy.

<details>
<summary>Przykład -- Przewidywanie czasu trwania połączenia (Regression) w zbiorze danych dotyczących intruzji
</summary>
Poniżej demonstrujemy użycie linear regression z wykorzystaniem datasetu cyberbezpieczeństwa NSL-KDD. Potraktujemy to jako problem regression, przewidując `duration` połączeń sieciowych na podstawie innych cech. (W rzeczywistości `duration` jest jedną z cech NSL-KDD; używamy jej tutaj wyłącznie do zilustrowania regression.) Wczytujemy dataset, przetwarzamy go wstępnie (kodując cechy kategoryczne), trenujemy model linear regression i oceniamy Mean Squared Error (MSE) oraz wynik R² na zbiorze testowym.
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
W tym przykładzie model regresji liniowej próbuje przewidzieć `duration` połączenia na podstawie innych cech sieciowych. Wydajność mierzymy za pomocą Mean Squared Error (MSE) i R². Wartość R² bliska 1.0 wskazywałaby, że model wyjaśnia większość wariancji `duration`, natomiast niska lub ujemna wartość R² wskazuje na słabe dopasowanie. (Nie zdziw się, jeśli wartość R² będzie tutaj niska -- przewidywanie `duration` na podstawie podanych cech może być trudne, a regresja liniowa może nie wychwytywać wzorców, jeśli są one złożone.)
</details>

### Logistic Regression

Logistic regression to algorytm **classification**, który modeluje prawdopodobieństwo, że instancja należy do określonej klasy (zwykle klasy „positive”). Pomimo swojej nazwy *logistic* regression jest używana dla wyników dyskretnych (w przeciwieństwie do linear regression, która służy do wyników ciągłych). Jest używana szczególnie do **binary classification** (dwóch klas, np. malicious i benign), ale można ją rozszerzyć na problemy wieloklasowe (z użyciem podejścia softmax lub one-vs-rest).<sup>[[3]](#references)</sup>

Logistic regression wykorzystuje funkcję logistyczną (znaną również jako funkcja sigmoid) do mapowania przewidywanych wartości na prawdopodobieństwa. Należy zauważyć, że funkcja sigmoid przyjmuje wartości od 0 do 1 i rośnie po krzywej w kształcie litery S zgodnie z wymaganiami classification, co jest przydatne w zadaniach binary classification. Dlatego każda cecha każdego wejścia jest mnożona przez przypisaną jej wagę, a wynik jest przekazywany przez funkcję sigmoid w celu uzyskania prawdopodobieństwa:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gdzie:

- `p(y=1|x)` to prawdopodobieństwo, że wynik `y` wynosi 1 przy danym wejściu `x`
- `e` to podstawa logarytmu naturalnego
- `z` to liniowa kombinacja cech wejściowych, zazwyczaj przedstawiana jako `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Zauważ, że również w najprostszym przypadku jest to linia prosta, ale w bardziej złożonych przypadkach staje się hiperpłaszczyzną z kilkoma wymiarami (po jednym na każdą cechę).

> [!TIP]
> *Zastosowania w cyberbezpieczeństwie:* Ponieważ wiele problemów związanych z bezpieczeństwem sprowadza się zasadniczo do decyzji tak/nie, regresja logistyczna jest szeroko stosowana. Na przykład system wykrywania włamań może używać regresji logistycznej do określenia, czy połączenie sieciowe jest atakiem, na podstawie cech tego połączenia. W wykrywaniu phishingu regresja logistyczna może łączyć cechy witryny (długość URL, obecność symbolu "@” itd.) w prawdopodobieństwo, że jest ona phishingowa. Była stosowana we wczesnych filtrach spamu i nadal pozostaje dobrym rozwiązaniem bazowym dla wielu zadań klasyfikacji.

#### Regresja logistyczna dla klasyfikacji niebinarnej

Regresja logistyczna jest przeznaczona do klasyfikacji binarnej, ale można ją rozszerzyć, aby obsługiwała problemy wieloklasowe, przy użyciu technik takich jak **one-vs-rest** (OvR) lub **softmax regression**. W OvR dla każdej klasy trenuje się osobny model regresji logistycznej, traktując ją jako klasę pozytywną, a wszystkie pozostałe jako przeciwne. Jako ostateczną predykcję wybiera się klasę z najwyższym przewidywanym prawdopodobieństwem. Softmax regression uogólnia regresję logistyczną na wiele klas poprzez zastosowanie funkcji softmax do warstwy wyjściowej, co pozwala uzyskać rozkład prawdopodobieństwa dla wszystkich klas.

#### **Kluczowe cechy regresji logistycznej:**

-   **Typ problemu:** Klasyfikacja (zwykle binarna). Przewiduje prawdopodobieństwo klasy pozytywnej.

-   **Interpretowalność:** Wysoka -- podobnie jak w regresji liniowej, współczynniki cech mogą wskazywać, jak każda cecha wpływa na logarytm szans wystąpienia wyniku. Ta przejrzystość jest często ceniona w bezpieczeństwie, ponieważ ułatwia zrozumienie, które czynniki przyczyniają się do wygenerowania alertu.

-   **Zalety:** Prosta i szybka w trenowaniu; dobrze działa, gdy zależność między cechami a logarytmem szans wystąpienia wyniku jest liniowa. Zwraca prawdopodobieństwa, umożliwiając ocenę ryzyka. Przy odpowiedniej regularyzacji dobrze generalizuje i lepiej radzi sobie ze współliniowością niż zwykła regresja liniowa.

-   **Ograniczenia:** Zakłada liniową granicę decyzyjną w przestrzeni cech (zawodzi, jeśli rzeczywista granica jest złożona/nieliniowa). Może działać słabiej w problemach, w których kluczowe są interakcje lub efekty nieliniowe, chyba że ręcznie dodasz cechy wielomianowe lub cechy interakcji. Ponadto regresja logistyczna jest mniej skuteczna, jeśli klas nie można łatwo rozdzielić za pomocą liniowej kombinacji cech.


<details>
<summary>Przykład -- Wykrywanie witryn phishingowych za pomocą regresji logistycznej:</summary>

Użyjemy **Phishing Websites Dataset** (z repozytorium UCI), który zawiera wyodrębnione cechy witryn (takie jak informacja, czy URL zawiera adres IP, wiek domeny, obecność podejrzanych elementów w kodzie HTML itd.) oraz etykietę wskazującą, czy witryna jest phishingowa, czy legalna.<sup>[[4]](#references)</sup> Trenujemy model regresji logistycznej do klasyfikowania witryn, a następnie oceniamy jego accuracy, precision, recall, F1-score i ROC AUC na wydzielonym zbiorze testowym.
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
W tym przykładzie wykrywania phishingu regresja logistyczna generuje prawdopodobieństwo, że każda witryna jest phishingiem. Oceniając accuracy, precision, recall i F1, uzyskujemy obraz skuteczności modelu. Na przykład wysoki recall oznaczałby, że model wykrywa większość witryn phishingowych (co jest ważne dla bezpieczeństwa, aby zminimalizować liczbę przeoczonych ataków), natomiast wysoki precision oznacza, że generuje niewiele fałszywych alarmów (co pomaga uniknąć zmęczenia analityków). ROC AUC (Area Under the ROC Curve) zapewnia niezależną od progu miarę skuteczności (1.0 oznacza wynik idealny, a 0.5 — wynik nielepszy od losowego). Regresja logistyczna często dobrze sprawdza się w takich zadaniach, ale jeśli granica decyzyjna między witrynami phishingowymi a legalnymi jest złożona, mogą być potrzebne bardziej zaawansowane modele nieliniowe.

</details>

### Drzewa decyzyjne

Drzewo decyzyjne to wszechstronny **algorytm uczenia nadzorowanego**, który może być używany zarówno do zadań klasyfikacji, jak i regresji. Uczy się hierarchicznego modelu decyzji o strukturze przypominającej drzewo, opartego na cechach danych. Każdy węzeł wewnętrzny drzewa reprezentuje test określonej cechy, każda gałąź reprezentuje wynik tego testu, a każdy węzeł liścia reprezentuje przewidywaną klasę (w przypadku klasyfikacji) lub wartość (w przypadku regresji).<sup>[[5]](#references)</sup>

Aby zbudować drzewo, algorytmy takie jak CART (Classification and Regression Tree) używają miar, takich jak **Gini impurity** lub **information gain (entropy)**, aby na każdym etapie wybrać najlepszą cechę i próg podziału danych. Celem każdego podziału jest podzielenie danych w taki sposób, aby zwiększyć jednorodność zmiennej docelowej w wynikowych podzbiorach (w przypadku klasyfikacji każdy węzeł powinien być możliwie czysty i zawierać głównie jedną klasę).

Drzewa decyzyjne są **wysoce interpretowalne** -- można prześledzić ścieżkę od korzenia do liścia, aby zrozumieć logikę stojącą za predykcją (np. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Jest to cenne w cybersecurity, ponieważ pozwala wyjaśnić, dlaczego wygenerowano określony alert. Drzewa mogą naturalnie obsługiwać zarówno dane numeryczne, jak i kategoryczne, a także wymagają niewielkiego wstępnego przetwarzania (np. skalowanie cech nie jest potrzebne).

Pojedyncze drzewo decyzyjne może jednak łatwo dopasować się nadmiernie do danych treningowych, szczególnie jeśli jest głęboko rozbudowane (ma wiele podziałów). Aby zapobiegać overfittingowi, często stosuje się techniki takie jak przycinanie (ograniczanie głębokości drzewa lub wymaganie minimalnej liczby próbek w każdym liściu).

Drzewo decyzyjne składa się z 3 głównych elementów:
- **Root Node**: Górny węzeł drzewa reprezentujący cały zbiór danych.
- **Internal Nodes**: Węzły reprezentujące cechy i decyzje oparte na tych cechach.
- **Leaf Nodes**: Węzły reprezentujące końcowy wynik lub predykcję.

Drzewo może ostatecznie wyglądać tak:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Przypadki użycia w cyberbezpieczeństwie:* Drzewa decyzyjne były używane w systemach intrusion detection do wyprowadzania **reguł** identyfikujących ataki. Na przykład wczesne systemy IDS oparte na ID3/C4.5 generowały czytelne dla człowieka reguły odróżniające normalny od złośliwego ruchu. Są również używane w analizie malware do określania, czy plik jest złośliwy na podstawie jego atrybutów (rozmiar pliku, entropia sekcji, wywołania API itp.). Przejrzystość drzew decyzyjnych sprawia, że są użyteczne, gdy wymagana jest transparentność -- analityk może sprawdzić drzewo, aby zweryfikować logikę detekcji.

#### **Kluczowe cechy drzew decyzyjnych:**

-   **Typ problemu:** Zarówno klasyfikacja, jak i regresja. Często używane do klasyfikacji ataków i normalnego ruchu itp.

-   **Interpretowalność:** Bardzo wysoka -- decyzje modelu można wizualizować i rozumieć jako zestaw reguł if-then. Jest to istotna zaleta w security, jeśli chodzi o zaufanie i weryfikację działania modelu.

-   **Zalety:** Mogą uchwycić nieliniowe zależności i interakcje między cechami (każdy podział można postrzegać jako interakcję). Nie ma potrzeby skalowania cech ani kodowania one-hot zmiennych kategorycznych -- drzewa obsługują je natywnie. Szybkie wnioskowanie (predykcja polega po prostu na przejściu ścieżką w drzewie).

-   **Ograniczenia:** Są podatne na overfitting, jeśli nie są kontrolowane (głębokie drzewo może zapamiętać zbiór treningowy). Mogą być niestabilne -- niewielkie zmiany w danych mogą prowadzić do powstania innej struktury drzewa. Jako pojedyncze modele ich dokładność może nie dorównywać bardziej zaawansowanym metodom (ensembles, takie jak Random Forests, zwykle działają lepiej dzięki redukcji wariancji).

-   **Znajdowanie najlepszego podziału:**
- **Gini Impurity**: Mierzy nieczystość węzła. Niższa wartość Gini impurity oznacza lepszy podział. Wzór:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Gdzie `p_i` oznacza proporcję instancji należących do klasy `i`.

- **Entropy**: Mierzy niepewność w zbiorze danych. Niższa entropy oznacza lepszy podział. Wzór:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Gdzie `p_i` oznacza proporcję instancji należących do klasy `i`.

- **Information Gain**: Redukcja entropy lub Gini impurity po podziale. Im większy information gain, tym lepszy podział. Oblicza się go następująco:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ponadto drzewo zostaje zakończone, gdy:
- Wszystkie instancje w węźle należą do tej samej klasy. Może to prowadzić do overfittingu.
- Osiągnięta zostanie maksymalna (hardcoded) głębokość drzewa. Jest to sposób zapobiegania overfittingowi.
- Liczba instancji w węźle spadnie poniżej określonego progu. Jest to również sposób zapobiegania overfittingowi.
- Information gain z kolejnych podziałów spadnie poniżej określonego progu. Jest to również sposób zapobiegania overfittingowi.

<details>
<summary>Przykład -- Drzewo decyzyjne do Intrusion Detection:</summary>
Wytrenujemy drzewo decyzyjne na zbiorze danych NSL-KDD, aby sklasyfikować połączenia sieciowe jako *normalne* lub *atak*. NSL-KDD to ulepszona wersja klasycznego zbioru danych KDD Cup 1999, zawierająca takie cechy jak typ protokołu, usługa, czas trwania, liczba nieudanych logowań itp., oraz etykietę wskazującą typ ataku lub wartość "normal". Zmapujemy wszystkie typy ataków na klasę "anomaly" (klasyfikacja binarna: normal vs anomaly). Po wytrenowaniu ocenimy skuteczność drzewa na zbiorze testowym.
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
W tym przykładzie drzewa decyzyjnego ograniczyliśmy głębokość drzewa do 10, aby uniknąć nadmiernego overfittingu (parametr `max_depth=10`). Metryki pokazują, jak dobrze drzewo rozróżnia normalny ruch od ruchu będącego atakiem. Wysoki recall oznaczałby wykrywanie większości ataków (co jest ważne dla systemu IDS), natomiast wysoki precision oznacza niewiele fałszywych alarmów. Drzewa decyzyjne często osiągają przyzwoitą accuracy na danych strukturalnych, ale pojedyncze drzewo może nie zapewniać najlepszej możliwej wydajności. Niemniej jednak dużą zaletą jest *interpretowalność* modelu -- możemy przeanalizować podziały drzewa, aby zobaczyć na przykład, które cechy (np. `service`, `src_bytes` itd.) mają największy wpływ na oznaczenie połączenia jako złośliwego.

</details>

### Random Forests

Random Forest to metoda **ensemble learning**, która bazuje na drzewach decyzyjnych w celu poprawy wydajności. Random forest trenuje wiele drzew decyzyjnych (stąd określenie „forest”) i łączy ich wyniki, aby uzyskać końcową predykcję (w przypadku klasyfikacji zwykle poprzez głosowanie większościowe). Dwie główne idee stojące za random forest to **bagging** (bootstrap aggregating) oraz **losowość cech**:

-   **Bagging:** Każde drzewo jest trenowane na losowej bootstrapowej próbce danych treningowych (pobieranej ze zwracaniem). Wprowadza to różnorodność między drzewami.

-   **Losowość cech:** Przy każdym podziale drzewa brany jest pod uwagę losowy podzbiór cech (zamiast wszystkich cech). Dodatkowo zmniejsza to korelację między drzewami.

Uśrednianie wyników wielu drzew zmniejsza wariancję, którą może mieć pojedyncze drzewo decyzyjne. Mówiąc prościej, pojedyncze drzewa mogą nadmiernie dopasowywać się do danych lub generować szum, ale duża liczba różnorodnych drzew głosujących wspólnie wygładza te błędy. Rezultatem jest często model o **wyższej accuracy** i lepszej generalizacji niż w przypadku pojedynczego drzewa decyzyjnego. Ponadto random forests mogą dostarczać oszacowanie ważności cech (poprzez sprawdzenie, w jakim stopniu każdy podział na cesze średnio zmniejsza nieczystość).

Random forests stały się **workhorse w cybersecurity** w zadaniach takich jak intrusion detection, klasyfikacja malware i wykrywanie spamu. Często dobrze działają bezpośrednio po uruchomieniu, przy minimalnym dostrajaniu, i mogą obsługiwać duże zestawy cech. Na przykład w intrusion detection random forest może przewyższać pojedyncze drzewo decyzyjne, wykrywając bardziej subtelne wzorce ataków przy mniejszej liczbie false positives. Badania wykazały, że random forests wypadają korzystnie w porównaniu z innymi algorytmami podczas klasyfikowania ataków w zbiorach danych takich jak NSL-KDD i UNSW-NB15.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Najważniejsze cechy Random Forests:**

-   **Rodzaj problemu:** Przede wszystkim klasyfikacja (stosowane również do regresji). Bardzo dobrze nadają się do wielowymiarowych danych strukturalnych typowych dla security logs.

-   **Interpretowalność:** Niższa niż w przypadku pojedynczego drzewa decyzyjnego -- nie można łatwo zwizualizować ani wyjaśnić jednocześnie setek drzew. Jednak wartości ważności cech dostarczają pewnych informacji o tym, które atrybuty mają największy wpływ.

-   **Zalety:** Zwykle wyższa accuracy niż w modelach opartych na pojedynczym drzewie dzięki efektowi ensemble. Odporność na overfitting -- nawet jeśli pojedyncze drzewa nadmiernie dopasują się do danych, ensemble lepiej generalizuje. Obsługuje zarówno cechy numeryczne, jak i kategoryczne, a także w pewnym zakresie radzi sobie z brakującymi danymi. Jest również stosunkowo odporny na outliers.

-   **Ograniczenia:** Rozmiar modelu może być duży (wiele drzew, z których każde może być głębokie). Predykcje są wolniejsze niż w przypadku pojedynczego drzewa (ponieważ należy agregować wyniki wielu drzew). Mniejsza interpretowalność -- wiadomo, które cechy są ważne, ale dokładna logika nie jest łatwa do prześledzenia tak jak w przypadku prostej reguły. Jeśli dataset jest wyjątkowo wielowymiarowy i rzadki, trenowanie bardzo dużego forest może być wymagające obliczeniowo.

-   **Proces trenowania:**
1. **Bootstrap Sampling**: Losowo pobierz ze zwracaniem próbki danych treningowych, aby utworzyć wiele podzbiorów (bootstrap samples).
2. **Tree Construction**: Dla każdej bootstrap sample zbuduj drzewo decyzyjne, używając losowego podzbioru cech przy każdym podziale. Wprowadza to różnorodność między drzewami.
3. **Aggregation**: W zadaniach klasyfikacyjnych końcowa predykcja jest uzyskiwana poprzez głosowanie większościowe na podstawie predykcji wszystkich drzew. W zadaniach regresji końcowa predykcja jest średnią predykcji ze wszystkich drzew.

<details>
<summary>Przykład -- Random Forest do Intrusion Detection (NSL-KDD):</summary>
Użyjemy tego samego datasetu NSL-KDD (z etykietami binarnymi: normalny lub anomaly) i wytrenujemy classifier Random Forest. Oczekujemy, że random forest osiągnie wyniki co najmniej tak dobre jak pojedyncze drzewo decyzyjne lub lepsze, ponieważ uśrednianie wyników ensemble zmniejsza wariancję. Ocenimy go za pomocą tych samych metryk.
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
Model random forest zazwyczaj osiąga dobre wyniki w tym zadaniu wykrywania włamań. Możemy zaobserwować poprawę takich metryk jak F1 lub AUC w porównaniu z pojedynczym drzewem decyzyjnym, szczególnie w zakresie recall lub precision, zależnie od danych. Jest to zgodne z obserwacją, że *„Random Forest (RF) jest klasyfikatorem zespołowym i w porównaniu z innymi tradycyjnymi klasyfikatorami dobrze sprawdza się w skutecznej klasyfikacji ataków.”*.<sup>[[6]](#references)</sup> W kontekście operacji bezpieczeństwa model random forest może bardziej niezawodnie wykrywać ataki, jednocześnie ograniczając liczbę fałszywych alarmów dzięki uśrednianiu wielu reguł decyzyjnych. Ważność cech obliczona przez forest może wskazać, które cechy sieciowe najlepiej sygnalizują ataki, np. określone usługi sieciowe lub nietypową liczbę pakietów.

</details>

### Support Vector Machines (SVM)

Support Vector Machines to zaawansowane modele supervised learning używane głównie do klasyfikacji, a także do regresji jako SVR. SVM próbuje znaleźć **optymalną hiperpłaszczyznę rozdzielającą**, która maksymalizuje margines między dwiema klasami. Tylko podzbiór punktów treningowych, czyli „wektory nośne” znajdujące się najbliżej granicy, określa położenie tej hiperpłaszczyzny. Maksymalizowanie marginesu, czyli odległości między wektorami nośnymi a hiperpłaszczyzną, zazwyczaj pozwala modelom SVM osiągać dobre uogólnianie.<sup>[[8]](#references)</sup>

Kluczową zaletą SVM jest możliwość używania **funkcji kernel** do obsługi nieliniowych zależności. Dane mogą być niejawnie przekształcone do wielowymiarowej przestrzeni cech, w której może istnieć liniowy separator. Typowe kernele obejmują wielomianowy, radial basis function (RBF) oraz sigmoid. Na przykład, jeśli klasy ruchu sieciowego nie są liniowo separowalne w surowej przestrzeni cech, kernel RBF może odwzorować je do przestrzeni o większym wymiarze, w której SVM znajdzie liniowy podział, odpowiadający nieliniowej granicy w przestrzeni oryginalnej. Elastyczność wyboru kerneli pozwala modelom SVM rozwiązywać różnorodne problemy.

Modele SVM są znane z dobrego działania w sytuacjach obejmujących wielowymiarowe przestrzenie cech, takich jak dane tekstowe lub sekwencje opcode malware, oraz w przypadkach, gdy liczba cech jest duża w porównaniu z liczbą próbek. Były popularne w wielu pierwszych zastosowaniach cybersecurity, takich jak klasyfikacja malware i wykrywanie włamań oparte na anomaliach w latach 2000., często osiągając wysoką accuracy.

SVM nie skaluje się jednak łatwo do bardzo dużych zbiorów danych. Złożoność treningu jest superliniowa względem liczby próbek, a zużycie pamięci może być wysokie, ponieważ model może wymagać przechowywania wielu wektorów nośnych. W praktyce, w zadaniach takich jak wykrywanie włamań sieciowych obejmujących miliony rekordów, SVM może działać zbyt wolno bez starannego subsamplingu lub zastosowania metod przybliżonych.

#### **Najważniejsze cechy SVM:**

-   **Typ problemu:** Klasyfikacja, binarna lub wieloklasowa za pomocą one-vs-one/one-vs-rest, oraz warianty regresji. Często używany w klasyfikacji binarnej z wyraźnym rozdzieleniem marginesem.

-   **Interpretowalność:** Średnia -- SVM nie są tak łatwe do interpretacji jak drzewa decyzyjne lub regresja logistyczna. Chociaż można określić, które punkty danych są wektorami nośnymi, i uzyskać pewne informacje o tym, które cechy mogą mieć wpływ, analizując wagi w przypadku liniowego kernela, w praktyce SVM, szczególnie z nieliniowymi kernelami, traktuje się jako klasyfikatory black-box.

-   **Zalety:** Skuteczność w wielowymiarowych przestrzeniach; możliwość modelowania złożonych granic decyzyjnych dzięki kernel trick; odporność na overfitting, jeśli margines jest maksymalizowany, szczególnie przy prawidłowym parametrze regularyzacji C; dobre działanie nawet wtedy, gdy klasy nie są oddzielone dużą odległością, ponieważ model znajduje najlepszy kompromis między granicami.

-   **Ograniczenia:** **Duże wymagania obliczeniowe** dla dużych zbiorów danych, ponieważ zarówno trening, jak i predykcja słabo skalują się wraz ze wzrostem ilości danych. Wymaga starannego dostrojenia parametrów kernela i regularyzacji, takich jak C, typ kernela oraz gamma dla RBF. Nie dostarcza bezpośrednio wyników probabilistycznych, choć można użyć Platt scaling do uzyskania prawdopodobieństw. Ponadto SVM może być wrażliwy na wybór parametrów kernela --- niewłaściwy wybór może prowadzić do underfittingu lub overfittingu.

*Przypadki użycia w cybersecurity:* SVM były używane do **wykrywania malware**, np. klasyfikowania plików na podstawie wyodrębnionych cech lub sekwencji opcode, **wykrywania anomalii sieciowych**, czyli klasyfikowania ruchu jako normalnego lub złośliwego, oraz **wykrywania phishingu** z wykorzystaniem cech URL-i. Na przykład SVM może przyjąć cechy wiadomości e-mail, takie jak liczba wystąpień określonych słów kluczowych, oceny reputacji nadawcy itp., i sklasyfikować ją jako phishing lub wiadomość wiarygodną. Modele te stosowano również do **wykrywania włamań** na zbiorach cech takich jak KDD, często osiągając wysoką accuracy kosztem większych wymagań obliczeniowych.

<details>
<summary>Przykład -- SVM do klasyfikacji malware:</summary>
Ponownie użyjemy zbioru danych dotyczącego stron phishingowych, tym razem z modelem SVM. Ponieważ SVM może działać wolno, w razie potrzeby użyjemy podzbioru danych do treningu. Zbiór zawiera około 11 tys. instancji, które SVM może obsłużyć bez większych problemów. Użyjemy kernela RBF, będącego częstym wyborem dla danych nieliniowych, oraz włączymy estymację prawdopodobieństwa, aby obliczyć ROC AUC.
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
Model SVM będzie zwracał metryki, które możemy porównać z Logistic Regression dla tego samego zadania. Możemy stwierdzić, że SVM osiąga wysoką accuracy i AUC, jeśli dane są dobrze rozdzielone przez cechy. Z drugiej strony, jeśli dataset zawiera dużo szumu lub nakładające się klasy, SVM może nie przewyższać znacząco Logistic Regression. W praktyce SVM może zapewnić poprawę, gdy między cechami a klasą występują złożone, nieliniowe zależności — kernel RBF potrafi odwzorować zakrzywione granice decyzyjne, których Logistic Regression nie wykryje. Podobnie jak w przypadku wszystkich modeli, konieczne jest staranne dostrojenie parametru `C` (regularyzacja) oraz parametrów kernela (takich jak `gamma` dla RBF), aby zachować równowagę między obciążeniem a wariancją.

</details>

#### Różnice między Logistic Regression a SVM

| Aspekt | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Funkcja celu** | Minimalizuje **log‑loss** (entropię krzyżową). | Maksymalizuje **margines**, jednocześnie minimalizując **hinge‑loss**. |
| **Granica decyzyjna** | Znajduje **najlepiej dopasowaną hiperpłaszczyznę**, która modeluje _P(y\|x)_. | Znajduje **hiperpłaszczyznę o maksymalnym marginesie** (z największym odstępem od najbliższych punktów). |
| **Wyjście** | **Probabilistyczne** – zwraca skalibrowane prawdopodobieństwa klas za pomocą σ(w·x + b). | **Deterministyczne** – zwraca etykiety klas; prawdopodobieństwa wymagają dodatkowego przetwarzania (np. Platt scaling). |
| **Regularyzacja** | L2 (domyślnie) lub L1, bezpośrednio równoważy underfitting i overfitting. | Parametr C stanowi kompromis między szerokością marginesu a błędnymi klasyfikacjami; parametry kernela zwiększają złożoność. |
| **Kernele / Nieliniowość** | Wbudowana forma jest **liniowa**; nieliniowość dodaje się przez feature engineering. | Wbudowany **kernel trick** (RBF, poly itd.) pozwala modelować złożone granice w przestrzeni o wysokim wymiarze. |
| **Skalowalność** | Rozwiązuje wypukłą optymalizację w **O(nd)**; dobrze obsługuje bardzo duże n. | Bez wyspecjalizowanych solverów trenowanie może wymagać **O(n²–n³)** pamięci/czasu; gorzej nadaje się do ogromnych wartości n. |
| **Interpretowalność** | **Wysoka** – wagi pokazują wpływ cech; iloraz szans jest intuicyjny. | **Niska** dla nieliniowych kerneli; support vectors są rzadkie, ale trudne do wyjaśnienia. |
| **Wrażliwość na wartości odstające** | Wykorzystuje gładką funkcję log‑loss → jest mniej wrażliwy. | Hinge‑loss z hard margin może być **wrażliwy**; soft-margin (C) łagodzi ten problem. |
| **Typowe zastosowania** | Scoring kredytowy, ryzyko medyczne, testy A/B — gdy istotne są **prawdopodobieństwa i wyjaśnialność**. | Klasyfikacja obrazów/tekstu, bioinformatyka — gdy istotne są **złożone granice** i **dane o wysokim wymiarze**. |

* **Jeśli potrzebujesz skalibrowanych prawdopodobieństw, interpretowalności lub pracy na ogromnych datasetach — wybierz Logistic Regression.**
* **Jeśli potrzebujesz elastycznego modelu, który potrafi uchwycić nieliniowe zależności bez ręcznego feature engineering — wybierz SVM (z kernelami).**
* Oba modele optymalizują funkcje wypukłe, więc **globalne minima są gwarantowane**, ale kernele SVM dodają hiperparametry i koszt obliczeniowy.

### Naive Bayes

Naive Bayes to rodzina **klasyfikatorów probabilistycznych** opartych na zastosowaniu twierdzenia Bayesa przy silnym założeniu niezależności między cechami. Pomimo tego „naiwnego” założenia Naive Bayes często działa zaskakująco dobrze w określonych zastosowaniach, szczególnie obejmujących tekst lub dane kategoryczne, takich jak wykrywanie spamu.<sup>[[9]](#references)</sup>


#### Twierdzenie Bayesa

Twierdzenie Bayesa stanowi podstawę klasyfikatorów Naive Bayes. Łączy prawdopodobieństwa warunkowe i brzegowe zdarzeń losowych. Wzór przedstawia się następująco:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gdzie:
- `P(A|B)` to prawdopodobieństwo a posteriori klasy `A` przy danej cesze `B`.
- `P(B|A)` to wiarygodność cechy `B` przy danej klasie `A`.
- `P(A)` to prawdopodobieństwo a priori klasy `A`.
- `P(B)` to prawdopodobieństwo a priori cechy `B`.

Na przykład, jeśli chcemy sklasyfikować, czy tekst został napisany przez dziecko czy osobę dorosłą, możemy użyć słów w tekście jako cech. Na podstawie początkowych danych klasyfikator Naive Bayes wcześniej obliczy prawdopodobieństwa wystąpienia każdego słowa w każdej potencjalnej klasie (dziecko lub osoba dorosła). Po podaniu nowego tekstu obliczy prawdopodobieństwo każdej potencjalnej klasy na podstawie słów w tekście i wybierze klasę o najwyższym prawdopodobieństwie.

Jak widać na tym przykładzie, klasyfikator Naive Bayes jest bardzo prosty i szybki, ale zakłada, że cechy są niezależne, co nie zawsze ma miejsce w rzeczywistych danych.


#### Typy klasyfikatorów Naive Bayes

Istnieje kilka typów klasyfikatorów Naive Bayes, zależnie od rodzaju danych i rozkładu cech:
- **Gaussian Naive Bayes**: Zakłada, że cechy mają rozkład Gaussa (normalny). Jest odpowiedni dla danych ciągłych.
- **Multinomial Naive Bayes**: Zakłada, że cechy mają rozkład wielomianowy. Jest odpowiedni dla danych dyskretnych, takich jak liczba wystąpień słów w klasyfikacji tekstu.
- **Bernoulli Naive Bayes**: Zakłada, że cechy są binarne (0 lub 1). Jest odpowiedni dla danych binarnych, takich jak obecność lub brak słów w klasyfikacji tekstu.
- **Categorical Naive Bayes**: Zakłada, że cechy są zmiennymi kategorycznymi. Jest odpowiedni dla danych kategorycznych, takich jak klasyfikowanie owoców na podstawie ich koloru i kształtu.


#### **Kluczowe cechy Naive Bayes:**

-   **Rodzaj problemu:** Klasyfikacja (binarna lub wieloklasowa). Często używany do zadań klasyfikacji tekstu w cybersecurity (spam, phishing itp.).

-   **Interpretowalność:** Średnia -- nie jest tak bezpośrednio interpretowalny jak drzewo decyzyjne, ale można sprawdzić wyuczone prawdopodobieństwa (np. które słowa najczęściej występują w wiadomościach spamowych, a które w wiadomościach ham). Postać modelu (prawdopodobieństwa każdej cechy przy danej klasie) może być w razie potrzeby zrozumiała.

-   **Zalety:** **Bardzo szybkie** uczenie i predykcja, nawet w przypadku dużych zbiorów danych (liniowa zależność od liczby instancji * liczby cech). Wymaga stosunkowo niewielkiej ilości danych do wiarygodnego oszacowania prawdopodobieństw, szczególnie przy prawidłowym wygładzaniu. Często jest zaskakująco dokładny jako model bazowy, zwłaszcza gdy cechy niezależnie dostarczają informacji wskazujących klasę. Dobrze działa z danymi wysokowymiarowymi (np. tysiącami cech pochodzących z tekstu). Nie wymaga złożonego dostrajania poza ustawieniem parametru wygładzania.

-   **Ograniczenia:** Założenie niezależności może ograniczać dokładność, jeśli cechy są silnie skorelowane. Na przykład w danych sieciowych cechy takie jak `src_bytes` i `dst_bytes` mogą być skorelowane; Naive Bayes nie uchwyci tej zależności. Wraz z bardzo dużym wzrostem rozmiaru danych bardziej ekspresywne modele (takie jak zespoły modeli lub sieci neuronowe) mogą przewyższyć NB, ucząc się zależności między cechami. Ponadto, jeśli do identyfikacji ataku potrzebna jest określona kombinacja cech (a nie tylko niezależny wkład poszczególnych cech), NB będzie mieć problemy.

> [!TIP]
> *Zastosowania w cybersecurity:* Klasycznym zastosowaniem jest **spam detection** -- Naive Bayes stanowił podstawę wczesnych filtrów antyspamowych, wykorzystujących częstotliwość określonych tokenów (słów, fraz, adresów IP) do obliczania prawdopodobieństwa, że wiadomość e-mail jest spamem. Jest również używany do **phishing email detection** i **URL classification**, gdzie obecność określonych słów kluczowych lub charakterystyk (takich jak "login.php" w adresie URL lub `@` w ścieżce URL) wpływa na prawdopodobieństwo phishingu. W analizie malware można wyobrazić sobie klasyfikator Naive Bayes wykorzystujący obecność określonych wywołań API lub uprawnień w oprogramowaniu do przewidywania, czy jest ono malware. Chociaż bardziej zaawansowane algorytmy często działają lepiej, Naive Bayes pozostaje dobrym modelem bazowym ze względu na szybkość i prostotę.

<details>
<summary>Przykład -- Naive Bayes do wykrywania phishingu:</summary>
Aby zademonstrować działanie Naive Bayes, użyjemy Gaussian Naive Bayes na zbiorze danych dotyczących włamań NSL-KDD (z etykietami binarnymi). Gaussian NB potraktuje każdą cechę jako mającą rozkład normalny w obrębie danej klasy. Jest to przybliżony wybór, ponieważ wiele cech sieciowych ma charakter dyskretny lub jest silnie skośnych, ale pokazuje, jak zastosować NB do danych cech ciągłych. Moglibyśmy również wybrać Bernoulli NB dla zbioru danych zawierającego cechy binarne (takiego jak zestaw wyzwolonych alertów), ale dla zachowania ciągłości pozostaniemy tutaj przy NSL-KDD.
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
Ten kod trenuje klasyfikator Naive Bayes do wykrywania ataków. Naive Bayes obliczy takie wartości jak `P(service=http | Attack)` i `P(Service=http | Normal)` na podstawie danych treningowych, zakładając niezależność cech. Następnie użyje tych prawdopodobieństw do klasyfikowania nowych połączeń jako normalnych lub będących atakiem na podstawie zaobserwowanych cech. Wydajność NB na NSL-KDD może nie być tak wysoka jak w przypadku bardziej zaawansowanych modeli (ponieważ założenie niezależności cech nie jest spełnione), ale często jest przyzwoita i zapewnia korzyść w postaci wyjątkowo dużej szybkości. W scenariuszach takich jak filtrowanie wiadomości e-mail w czasie rzeczywistym lub wstępna analiza URL-i model Naive Bayes może szybko oznaczać oczywiście złośliwe przypadki przy niewielkim zużyciu zasobów.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors to jeden z najprostszych algorytmów machine learning. Jest to **non-parametric, instance-based** metoda, która tworzy predykcje na podstawie podobieństwa do przykładów ze zbioru treningowego. Idea klasyfikacji jest następująca: aby sklasyfikować nowy punkt danych, należy znaleźć **k** najbliższych punktów w danych treningowych (jego „nearest neighbors”) i przypisać mu klasę większościową spośród tych sąsiadów. „Bliskość” jest definiowana za pomocą metryki odległości, zazwyczaj odległości euklidesowej dla danych numerycznych (dla różnych typów cech lub problemów można używać innych odległości).<sup>[[10]](#references)</sup>

K-NN nie wymaga *jawnego treningu* — faza „treningu” polega jedynie na przechowywaniu zbioru danych. Cała praca odbywa się podczas zapytania (predykcji): algorytm musi obliczyć odległości od punktu zapytania do wszystkich punktów treningowych, aby znaleźć najbliższe z nich. Sprawia to, że czas predykcji jest **liniowy względem liczby próbek treningowych**, co może być kosztowne w przypadku dużych zbiorów danych. Z tego powodu k-NN najlepiej nadaje się do mniejszych zbiorów danych lub scenariuszy, w których można poświęcić pamięć i szybkość na rzecz prostoty.

Pomimo prostoty k-NN może modelować bardzo złożone granice decyzyjne (ponieważ granica decyzyjna może w praktyce przyjmować dowolny kształt wyznaczony przez rozkład przykładów). Algorytm zwykle dobrze działa, gdy granica decyzyjna jest bardzo nieregularna i dostępna jest duża ilość danych — zasadniczo pozwalając, aby dane „same przemówiły”. Jednak w przestrzeniach o wysokim wymiarze metryki odległości mogą stawać się mniej znaczące (curse of dimensionality), a metoda może mieć problemy, chyba że dostępna jest bardzo duża liczba próbek.

*Zastosowania w cybersecurity:* k-NN był stosowany do anomaly detection — na przykład intrusion detection system może oznaczyć zdarzenie sieciowe jako złośliwe, jeśli większość jego najbliższych sąsiadów (wcześniejszych zdarzeń) była złośliwa. Jeśli normalny ruch tworzy klastry, a ataki są outlierami, podejście K-NN (z k=1 lub małym k) zasadniczo działa jako **nearest-neighbor anomaly detection**. K-NN był również używany do klasyfikowania rodzin malware na podstawie binary feature vectors: nowy plik może zostać sklasyfikowany jako należący do określonej rodziny malware, jeśli w przestrzeni cech jest bardzo podobny do znanych instancji tej rodziny. W praktyce k-NN nie jest tak powszechny jak bardziej skalowalne algorytmy, ale jest prosty w koncepcji i czasami służy jako baseline lub do problemów na małą skalę.

#### **Key characteristics of k-NN:**

-   **Type of Problem:** Klasyfikacja (istnieją również warianty regresji). Jest to metoda *lazy learning* — bez jawnego dopasowywania modelu.

-   **Interpretability:** Niska do średniej — nie ma globalnego modelu ani zwięzłego wyjaśnienia, ale wyniki można interpretować, analizując najbliższych sąsiadów, którzy wpłynęli na decyzję (np. „ten network flow został sklasyfikowany jako złośliwy, ponieważ jest podobny do tych 3 znanych złośliwych network flows”). Wyjaśnienia mogą więc opierać się na przykładach.

-   **Advantages:** Bardzo prosty we wdrożeniu i zrozumieniu. Nie przyjmuje żadnych założeń dotyczących rozkładu danych (non-parametric). Może naturalnie obsługiwać problemy wieloklasowe. Jest **adaptacyjny** w tym sensie, że granice decyzyjne mogą być bardzo złożone i kształtowane przez rozkład danych.

-   **Limitations:** Predykcja może być powolna w przypadku dużych zbiorów danych (konieczne jest obliczenie wielu odległości). Wymaga dużej ilości pamięci — przechowuje wszystkie dane treningowe. Wydajność spada w przestrzeniach cech o wysokim wymiarze, ponieważ wszystkie punkty stają się zazwyczaj niemal równoodległe (przez co pojęcie „najbliższego” staje się mniej znaczące). Należy odpowiednio wybrać *k* (liczbę sąsiadów) — zbyt małe k może powodować szum, a zbyt duże k może uwzględniać nieistotne punkty z innych klas. Cechy należy również odpowiednio skalować, ponieważ obliczenia odległości są wrażliwe na skalę.

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

Ponownie użyjemy NSL-KDD (klasyfikacja binarna). Ponieważ k-NN jest kosztowny obliczeniowo, w tym przykładzie użyjemy podzbioru danych treningowych, aby zachować wykonalność obliczeń. Wybierzemy na przykład 20 000 próbek treningowych z pełnego zbioru liczącego 125 tys. próbek i użyjemy 5 sąsiadów k=5. Po treningu (który w praktyce polega jedynie na przechowywaniu danych) przeprowadzimy ocenę na zbiorze testowym. Przeskalujemy również cechy na potrzeby obliczania odległości, aby żadna pojedyncza cecha nie dominowała z powodu swojej skali.
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
Model k-NN sklasyfikuje połączenie, sprawdzając 5 najbliższych połączeń w podzbiorze zbioru treningowego. Jeśli na przykład 4 z tych sąsiadów to ataki (anomalie), a 1 jest normalny, nowe połączenie zostanie sklasyfikowane jako atak. Wydajność może być zadowalająca, choć często nie jest tak wysoka jak w przypadku dobrze dostrojonego Random Forest lub SVM na tych samych danych. Jednak k-NN może czasami sprawdzać się wyjątkowo dobrze, gdy rozkłady klas są bardzo nieregularne i złożone — skutecznie działając jako wyszukiwanie oparte na pamięci. W cybersecurity k-NN (z k=1 lub małym k) może być używany do wykrywania znanych wzorców ataków na podstawie przykładów albo jako komponent bardziej złożonych systemów (np. do grupowania, a następnie klasyfikowania na podstawie przynależności do klastra).
</details>

### Gradient Boosting Machines (np. XGBoost)

Gradient Boosting Machines należą do najpotężniejszych algorytmów dla danych strukturalnych. **Gradient boosting** odnosi się do techniki budowania zespołu słabych learnerów (często drzew decyzyjnych) sekwencyjnie, gdzie każdy nowy model koryguje błędy poprzedniego zespołu. W przeciwieństwie do baggingu (Random Forest), który buduje drzewa równolegle i uśrednia ich wyniki, boosting buduje drzewa *jedno po drugim*, przy czym każde z nich koncentruje się bardziej na przypadkach, które poprzednie drzewa sklasyfikowały błędnie.<sup>[[11]](#references)</sup>

Najpopularniejsze implementacje w ostatnich latach to **XGBoost**, **LightGBM** i **CatBoost** — wszystkie są bibliotekami gradient boosting decision tree (GBDT). Odniosły one ogromny sukces w konkursach i zastosowaniach machine learning, często **osiągając najwyższą jakość wyników na zbiorach danych tabelarycznych**. W cybersecurity badacze i praktycy używali gradient boosted trees do zadań takich jak **wykrywanie malware** (z wykorzystaniem cech wyodrębnionych z plików lub zachowania w czasie wykonywania) oraz **network intrusion detection**. Na przykład model gradient boosting może połączyć wiele słabych reguł (drzew), takich jak „jeśli występuje wiele pakietów SYN i nietypowy port -> prawdopodobny skan”, w silny detektor złożony, który uwzględnia wiele subtelnych wzorców.

Dlaczego boosted trees są tak skuteczne? Każde drzewo w sekwencji jest trenowane na *resztowych błędach* (gradientach) predykcji bieżącego zespołu. Dzięki temu model stopniowo **„wzmacnia”** obszary, w których jest słaby. Wykorzystanie drzew decyzyjnych jako bazowych learnerów oznacza, że model końcowy może przechwytywać złożone zależności i nieliniowe relacje. Ponadto boosting z natury ma formę wbudowanej regularyzacji: poprzez dodawanie wielu małych drzew (i użycie learning rate do skalowania ich udziału) często dobrze generalizuje bez znacznego overfittingu, pod warunkiem dobrania odpowiednich parametrów.

#### **Najważniejsze cechy Gradient Boosting:**

-   **Typ problemu:** Głównie klasyfikacja i regresja. W security zwykle klasyfikacja (np. binarne klasyfikowanie połączenia lub pliku). Obsługuje problemy binarne, wieloklasowe (z odpowiednią funkcją straty), a nawet problemy rankingowe.

-   **Interpretowalność:** Niska do średniej. Chociaż pojedyncze boosted tree jest małe, pełny model może zawierać setki drzew, przez co jako całość nie jest interpretowalny dla człowieka. Jednak podobnie jak Random Forest może dostarczać wartości ważności cech, a narzędzia takie jak SHAP (SHapley Additive exPlanations) mogą być używane do pewnego stopnia interpretowania indywidualnych predykcji.

-   **Zalety:** Często **najlepiej działający** algorytm dla danych strukturalnych/tabelarycznych. Może wykrywać złożone wzorce i zależności. Ma wiele parametrów do dostrajania (liczba drzew, głębokość drzew, learning rate, parametry regularyzacji), które pozwalają dopasować złożoność modelu i zapobiegać overfittingowi. Nowoczesne implementacje są zoptymalizowane pod kątem szybkości (np. XGBoost używa informacji o gradientach drugiego rzędu i wydajnych struktur danych). Zwykle lepiej radzi sobie z niezbalansowanymi danymi, gdy jest połączony z odpowiednimi funkcjami straty lub gdy dostosuje się wagi próbek.

-   **Ograniczenia:** Jest trudniejszy do dostrojenia niż prostsze modele; trenowanie może być powolne, jeśli drzewa są głębokie lub ich liczba jest duża (choć nadal zwykle jest szybsze niż trenowanie porównywalnej deep neural network na tych samych danych). Model może ulec overfittingowi, jeśli nie zostanie dostrojony (np. zbyt wiele głębokich drzew przy niewystarczającej regularyzacji). Ze względu na dużą liczbę hyperparameters skuteczne wykorzystanie gradient boosting może wymagać większej wiedzy lub eksperymentowania. Ponadto, podobnie jak metody oparte na drzewach, nie obsługuje z natury bardzo rzadkich danych o wysokiej liczbie wymiarów tak wydajnie jak modele liniowe lub Naive Bayes (choć nadal można go stosować, np. w klasyfikacji tekstu, ale bez feature engineering może nie być pierwszym wyborem).

> [!TIP]
> *Zastosowania w cybersecurity:* Niemal wszędzie tam, gdzie można użyć drzewa decyzyjnego lub random forest, model gradient boosting może zapewnić lepszą accuracy. Na przykład w konkursach dotyczących **wykrywania malware firmy Microsoft** powszechnie używano XGBoost na cechach przygotowanych na podstawie plików binarnych. Badania nad **network intrusion detection** często wskazują najlepsze wyniki uzyskiwane przez GBDT (np. XGBoost na zbiorach danych CIC-IDS2017 lub UNSW-NB15). Modele te mogą przyjmować szeroki zakres cech (typy protokołów, częstotliwość określonych zdarzeń, cechy statystyczne ruchu itd.) i łączyć je w celu wykrywania zagrożeń. W wykrywaniu phishingu gradient boosting może łączyć cechy leksykalne URL-i, cechy reputacji domen i cechy zawartości stron, aby osiągnąć bardzo wysoką accuracy. Podejście zespołowe pomaga uwzględniać wiele przypadków brzegowych i subtelności w danych.

<details>
<summary>Przykład -- XGBoost do wykrywania phishingu:</summary>
Użyjemy klasyfikatora gradient boosting na zbiorze danych dotyczącym phishingu. Aby zachować prostotę i samowystarczalność przykładu, użyjemy `sklearn.ensemble.GradientBoostingClassifier` (czyli wolniejszej, ale prostej implementacji). Zwykle można użyć bibliotek `xgboost` lub `lightgbm`, aby uzyskać lepszą wydajność i dodatkowe funkcje. Wytrenujemy model i ocenimy go podobnie jak wcześniej.
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
Model gradient boosting prawdopodobnie osiągnie bardzo wysoką dokładność i wartość AUC na tym zbiorze danych dotyczącym phishingu (często modele te, po odpowiednim dostrojeniu, mogą osiągać ponad 95% dokładności na takich danych, jak pokazują publikacje naukowe. Pokazuje to, dlaczego GBDT są uznawane za *„state of the art model for tabular dataset”* — często przewyższają prostsze algorytmy, ponieważ wykrywają złożone wzorce.<sup>[[11]](#references)</sup> W kontekście cybersecurity może to oznaczać wykrywanie większej liczby stron phishingowych lub ataków przy mniejszej liczbie przeoczeń. Oczywiście należy uważać na overfitting — podczas tworzenia takiego modelu do wdrożenia zazwyczaj stosuje się techniki takie jak cross-validation oraz monitoruje wydajność na zbiorze walidacyjnym.

</details>

### Łączenie modeli: Ensemble Learning i Stacking

Ensemble learning to strategia **łączenia wielu modeli** w celu poprawy ogólnej wydajności. Poznaliśmy już konkretne metody ensemble: Random Forest (ensemble drzew za pomocą baggingu) oraz Gradient Boosting (ensemble drzew za pomocą sekwencyjnego boostingu). Ensemble można jednak tworzyć również na inne sposoby, takie jak **voting ensembles** lub **stacked generalization (stacking)**. Główna idea polega na tym, że różne modele mogą wykrywać różne wzorce lub mieć różne słabości; łącząc je, możemy **kompensować błędy każdego modelu mocnymi stronami innego**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** W prostym klasyfikatorze voting trenujemy wiele zróżnicowanych modeli (na przykład regresję logistyczną, drzewo decyzyjne i SVM), a następnie pozwalamy im głosować nad końcową predykcją (w przypadku klasyfikacji obowiązuje większość głosów). Jeśli przypiszemy głosom różne wagi (np. większą wagę dokładniejszym modelom), otrzymamy schemat weighted voting. Zazwyczaj poprawia to wydajność, gdy poszczególne modele są wystarczająco dobre i niezależne — ensemble zmniejsza ryzyko błędu pojedynczego modelu, ponieważ inne modele mogą go skorygować. To jak posiadanie panelu ekspertów zamiast pojedynczej opinii.

-   **Stacking (Stacked Ensemble):** Stacking idzie o krok dalej. Zamiast prostego głosowania trenuje **meta-model**, aby **nauczył się, jak najlepiej łączyć predykcje** modeli bazowych. Na przykład trenujemy 3 różne klasyfikatory (base learners), a następnie przekazujemy ich wyniki (lub prawdopodobieństwa) jako cechy do meta-klasyfikatora (często prostego modelu, takiego jak regresja logistyczna), który uczy się optymalnego sposobu ich łączenia. Meta-model jest trenowany na zbiorze walidacyjnym lub za pomocą cross-validation, aby uniknąć overfittingu. Stacking często może przewyższać proste voting, ponieważ uczy się *którym modelom bardziej ufać w określonych okolicznościach*. W cybersecurity jeden model może lepiej wykrywać skanowanie sieci, podczas gdy inny lepiej wykrywa malware beaconing; model stacking może nauczyć się odpowiednio polegać na każdym z nich.

Ensemble, niezależnie od tego, czy wykorzystuje voting, czy stacking, zazwyczaj **zwiększa dokładność** i odporność. Wadą jest większa złożoność oraz czasami mniejsza interpretowalność (choć niektóre podejścia ensemble, takie jak uśrednianie drzew decyzyjnych, nadal mogą dostarczać pewnych informacji, np. o ważności cech). W praktyce, jeśli ograniczenia operacyjne na to pozwalają, wykorzystanie ensemble może prowadzić do wyższych wskaźników wykrywania. Wiele zwycięskich rozwiązań w wyzwaniach cybersecurity (a także w konkursach Kaggle ogólnie) korzysta z technik ensemble, aby uzyskać ostatni wzrost wydajności.

<details>
<summary>Przykład -- Voting Ensemble do wykrywania phishingu:</summary>
Aby zilustrować model stacking, połączmy kilka modeli omówionych wcześniej na zbiorze danych dotyczącym phishingu. Użyjemy regresji logistycznej, drzewa decyzyjnego i k-NN jako base learners, a Random Forest jako meta-learnera agregującego ich predykcje. Meta-learner będzie trenowany na wynikach base learners (z wykorzystaniem cross-validation na zbiorze treningowym). Oczekujemy, że model stacked osiągnie wydajność porównywalną z modelami indywidualnymi lub nieco od nich lepszą.
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
Stakowany ensemble wykorzystuje uzupełniające się zalety modeli bazowych. Na przykład regresja logistyczna może obsługiwać liniowe aspekty danych, drzewo decyzyjne może wychwytywać określone interakcje przypominające reguły, a k-NN może doskonale działać w lokalnych obszarach przestrzeni cech. Meta-model (w tym przypadku random forest) może nauczyć się, jak ważyć te dane wejściowe. Uzyskane metryki często wskazują na poprawę (nawet niewielką) względem metryk dowolnego pojedynczego modelu. W naszym przykładzie phishingu, jeśli sam model logistyczny miałby F1 na poziomie, powiedzmy, 0,95, a drzewo 0,94, stack mógłby osiągnąć 0,96, uzupełniając braki każdego z modeli.

Metody ensemble, takie jak ta, demonstrują zasadę, że *„łączenie wielu modeli zazwyczaj prowadzi do lepszej generalizacji”*.<sup>[[12]](#references)</sup> W cybersecurity można to zrealizować poprzez zastosowanie wielu silników detekcji (jeden może być oparty na regułach, drugi na machine learning, a trzeci na wykrywaniu anomalii), a następnie warstwy agregującej ich alerty -- skutecznie tworząc formę ensemble -- w celu podjęcia ostatecznej decyzji z większą pewnością. Podczas wdrażania takich systemów należy uwzględnić dodatkową złożoność i zadbać o to, aby ensemble nie stał się zbyt trudny w zarządzaniu lub wyjaśnianiu. Jednak z punktu widzenia dokładności ensemble i stacking są potężnymi narzędziami poprawy wydajności modelu.

</details>

Podejścia oparte na sieciach neuronowych opisane na [stronie deep learning](AI-Deep-Learning.md) mogą uzupełniać te klasyczne modele w wykrywaniu intrusion, gdy zbiór danych i budżet obliczeniowy uzasadniają dodatkową złożoność.<sup>[[13]](#references)</sup>

## References

- [1] [AI i machine learning w cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Regresja liniowa - wyjaśnienie - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Regresja logistyczna - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Klasyfikacja ataków phishingowych i stron internetowych za pomocą machine learning i wielu zbiorów danych (analiza porównawcza)"](https://arxiv.org/pdf/2101.02552)
- [5] [Drzewo decyzyjne - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Wykrywanie ataków typu Denial of Services za pomocą klasyfikatora random forest z information gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Analiza wydajności modeli machine learning dla systemu wykrywania intrusion z wykorzystaniem techniki selekcji cech Gini Impurity-based Weighted Random Forest (GIWRF)"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Czym jest Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Filtrowanie spamu za pomocą Naive Bayes - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [Czym jest k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT bez tajemnic: jak działają LightGBM, XGBoost i CatBoost - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble learning: poprawa wydajności modeli poprzez łączenie ich zalet - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Jak deep learning usprawnia systemy wykrywania intrusion](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
