# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Podstawowe informacje

Supervised learning wykorzystuje oznaczone dane do trenowania modeli, które mogą tworzyć predykcje na podstawie nowych, wcześniej niewidzianych danych wejściowych. W cyberbezpieczeństwie supervised machine learning jest szeroko stosowane w zadaniach takich jak intrusion detection (klasyfikowanie ruchu sieciowego jako *normalnego* lub *ataku*), malware detection (rozróżnianie złośliwego oprogramowania od nieszkodliwego), phishing detection (identyfikowanie fałszywych stron internetowych lub wiadomości e-mail) oraz filtrowanie spamu. Każdy algorytm ma swoje mocne strony i jest przeznaczony do różnych typów problemów (klasyfikacji lub regresji). Poniżej omawiamy najważniejsze supervised learning algorithms, wyjaśniamy, jak działają, i pokazujemy ich zastosowanie na rzeczywistych datasetach związanych z cyberbezpieczeństwem. Omawiamy również, jak łączenie modeli (ensemble learning) może często poprawić skuteczność predykcji.

## Algorytmy

-   **Linear Regression:** Podstawowy algorytm regresji służący do przewidywania wartości liczbowych poprzez dopasowanie równania liniowego do danych.

-   **Logistic Regression:** Algorytm klasyfikacji (pomimo swojej nazwy), który wykorzystuje funkcję logistyczną do modelowania prawdopodobieństwa wystąpienia wyniku binarnego.

-   **Decision Trees:** Modele o strukturze drzewa, które dzielą dane według cech w celu tworzenia predykcji; często stosowane ze względu na ich interpretowalność.

-   **Random Forests:** Ensemble złożony z decision trees (za pomocą bagging), który poprawia dokładność i ogranicza overfitting.

-   **Support Vector Machines (SVM):** Klasyfikatory maksymalizujące margines, które znajdują optymalną hiperpłaszczyznę rozdzielającą; mogą używać kernels dla danych nieliniowych.

-   **Naive Bayes:** Klasyfikator probabilistyczny oparty na twierdzeniu Bayesa i założeniu niezależności cech, powszechnie stosowany w filtrowaniu spamu.

-   **k-Nearest Neighbors (k-NN):** Prosty klasyfikator „instance-based”, który przypisuje próbkę do klasy na podstawie większościowej klasy jej najbliższych sąsiadów.

-   **Gradient Boosting Machines:** Modele ensemble (np. XGBoost, LightGBM), które tworzą silny predyktor poprzez sekwencyjne dodawanie słabszych learnerów (zazwyczaj decision trees).

Każda z poniższych sekcji zawiera ulepszony opis algorytmu oraz **przykład kodu w Pythonie** z użyciem bibliotek takich jak `pandas` i `scikit-learn` (oraz `PyTorch` w przykładzie sieci neuronowej). Przykłady wykorzystują publicznie dostępne datasety związane z cyberbezpieczeństwem (takie jak NSL-KDD do intrusion detection oraz Phishing Websites dataset) i mają spójną strukturę:

1.  **Wczytanie datasetu** (pobranie za pomocą URL, jeśli jest dostępny).

2.  **Wstępne przetworzenie danych** (np. zakodowanie cech kategorycznych, przeskalowanie wartości, podział na zbiory treningowy i testowy).

3.  **Wytrenowanie modelu** na danych treningowych.

4.  **Ewaluacja** na zbiorze testowym z użyciem metryk: accuracy, precision, recall, F1-score oraz ROC AUC dla klasyfikacji (i mean squared error dla regresji).

Przejdźmy do omówienia poszczególnych algorytmów:

### Linear Regression

Linear regression to algorytm **regresji** używany do przewidywania ciągłych wartości liczbowych. Zakłada liniową zależność między cechami wejściowymi (zmiennymi niezależnymi) a wynikiem (zmienną zależną). Model próbuje dopasować prostą (lub hiperpłaszczyznę w wyższych wymiarach), która najlepiej opisuje zależność między cechami a wartością docelową. Zazwyczaj odbywa się to poprzez minimalizację sumy kwadratów błędów między wartościami przewidywanymi i rzeczywistymi (metoda Ordinary Least Squares).<sup>[[8]](#references)</sup>

Najprościej jest przedstawić regresję liniową za pomocą prostej:
```plaintext
y = mx + b
```
Gdzie:

- `y` to przewidywana wartość (wynik)
- `m` to nachylenie linii (współczynnik)
- `x` to cecha wejściowa
- `b` to punkt przecięcia z osią y

Celem regresji liniowej jest znalezienie najlepiej dopasowanej linii, która minimalizuje różnicę między przewidywanymi wartościami a rzeczywistymi wartościami w zbiorze danych. Oczywiście jest to bardzo proste — byłaby to prosta linia oddzielająca 2 kategorie, ale jeśli doda się więcej wymiarów, linia staje się bardziej złożona:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Przypadki użycia w cyberbezpieczeństwie:* Sama regresja liniowa jest rzadziej stosowana do podstawowych zadań związanych z bezpieczeństwem (które często obejmują klasyfikację), ale można jej używać do przewidywania wartości liczbowych. Na przykład regresja liniowa może służyć do **przewidywania natężenia ruchu sieciowego** lub **szacowania liczby ataków w określonym przedziale czasu** na podstawie danych historycznych. Może również przewidywać poziom ryzyka albo przewidywany czas do wykrycia ataku na podstawie określonych metryk systemowych. W praktyce algorytmy klasyfikacji (takie jak regresja logistyczna lub drzewa) są częściej używane do wykrywania włamań lub malware, ale regresja liniowa stanowi podstawę i jest przydatna w analizach ukierunkowanych na regresję.

#### **Najważniejsze cechy regresji liniowej:**

-   **Typ problemu:** Regresja (przewidywanie wartości ciągłych). Nie nadaje się do bezpośredniej klasyfikacji, chyba że do wyniku zostanie zastosowany próg.

-   **Interpretowalność:** Wysoka -- współczynniki są łatwe do interpretacji i pokazują liniowy wpływ każdej cechy.

-   **Zalety:** Prosta i szybka; stanowi dobry model bazowy dla zadań regresji; działa dobrze, gdy rzeczywista zależność jest w przybliżeniu liniowa.

-   **Ograniczenia:** Nie potrafi uchwycić złożonych ani nieliniowych zależności (bez ręcznego tworzenia cech); może prowadzić do niedouczenia, jeśli zależności są nieliniowe; jest podatna na wartości odstające, które mogą zniekształcać wyniki.

-   **Wyznaczanie najlepszego dopasowania:** Aby znaleźć najlepiej dopasowaną linię, która rozdziela możliwe kategorie, używamy metody nazywanej **Ordinary Least Squares (OLS)**. Metoda ta minimalizuje sumę kwadratów różnic między zaobserwowanymi wartościami a wartościami przewidywanymi przez model liniowy.

<details>
<summary>Przykład -- Przewidywanie czasu trwania połączenia (regresja) w zbiorze danych dotyczących włamań
</summary>
Poniżej demonstrujemy regresję liniową z użyciem zbioru danych NSL-KDD dotyczącego cyberbezpieczeństwa. Potraktujemy to jako problem regresji, przewidując `duration` połączeń sieciowych na podstawie innych cech. (W rzeczywistości `duration` jest jedną z cech NSL-KDD; używamy jej tutaj wyłącznie do zilustrowania regresji). Wczytujemy zbiór danych, wstępnie go przetwarzamy (kodując cechy kategoryczne), trenujemy model regresji liniowej i oceniamy Mean Squared Error (MSE) oraz wynik R² na zbiorze testowym.
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
W tym przykładzie model regresji liniowej próbuje przewidzieć `duration` połączenia na podstawie innych cech sieciowych. Wydajność mierzymy za pomocą Mean Squared Error (MSE) oraz R². Wartość R² bliska 1.0 oznaczałaby, że model wyjaśnia większość zmienności `duration`, natomiast niska lub ujemna wartość R² wskazuje na słabe dopasowanie. (Nie zdziw się, jeśli wartość R² będzie tutaj niska -- przewidywanie `duration` na podstawie podanych cech może być trudne, a regresja liniowa może nie uchwycić złożonych wzorców.)
</details>

### Regresja logistyczna

Regresja logistyczna to algorytm **klasyfikacji**, który modeluje prawdopodobieństwo, że dana instancja należy do określonej klasy (zwykle do klasy „pozytywnej”). Pomimo swojej nazwy regresja *logistyczna* jest używana dla wyników dyskretnych (w przeciwieństwie do regresji liniowej, która służy do wyników ciągłych). Jest szczególnie użyteczna w **klasyfikacji binarnej** (dwie klasy, np. malicious i benign), ale można ją rozszerzyć na problemy wieloklasowe (z użyciem podejścia softmax lub one-vs-rest).<sup>[[1]](#references)</sup>

Regresja logistyczna wykorzystuje funkcję logistyczną (znaną również jako funkcja sigmoid) do mapowania przewidywanych wartości na prawdopodobieństwa. Należy zauważyć, że funkcja sigmoid przyjmuje wartości od 0 do 1 i rośnie po krzywej w kształcie litery S, zgodnie z wymaganiami klasyfikacji, co jest przydatne w zadaniach klasyfikacji binarnej. Dlatego każda cecha każdego wejścia jest mnożona przez przypisaną jej wagę, a wynik jest przekazywany przez funkcję sigmoid w celu uzyskania prawdopodobieństwa:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gdzie:

- `p(y=1|x)` to prawdopodobieństwo, że wynik `y` wynosi 1 przy danym wejściu `x`
- `e` to podstawa logarytmu naturalnego
- `z` to liniowa kombinacja cech wejściowych, zwykle przedstawiana jako `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Zauważ, że w najprostszej postaci jest to ponownie linia prosta, ale w bardziej złożonych przypadkach staje się hiperpłaszczyzną o kilku wymiarach (po jednym na każdą cechę).

> [!TIP]
> *Zastosowania w cyberbezpieczeństwie:* Ponieważ wiele problemów związanych z bezpieczeństwem sprowadza się zasadniczo do decyzji tak/nie, logistic regression jest szeroko stosowana. Na przykład system wykrywania włamań może używać logistic regression do określenia, czy połączenie sieciowe jest atakiem, na podstawie jego cech. W wykrywaniu phishingu logistic regression może łączyć cechy witryny (długość URL, obecność symbolu "@", itp.) w prawdopodobieństwo, że jest to phishing. Była używana we wczesnych filtrach antyspamowych i nadal stanowi silny model bazowy dla wielu zadań klasyfikacyjnych.

#### Logistic Regression dla klasyfikacji wieloklasowej

Logistic regression jest przeznaczona do klasyfikacji binarnej, ale można ją rozszerzyć, aby obsługiwała problemy wieloklasowe, za pomocą technik takich jak **one-vs-rest** (OvR) lub **softmax regression**. W OvR dla każdej klasy trenuje się osobny model logistic regression, traktując ją jako klasę pozytywną, a wszystkie pozostałe jako przeciwne. Jako ostateczną predykcję wybiera się klasę z najwyższym przewidywanym prawdopodobieństwem. Softmax regression uogólnia logistic regression na wiele klas, stosując funkcję softmax do warstwy wyjściowej i generując rozkład prawdopodobieństwa dla wszystkich klas.

#### **Kluczowe cechy Logistic Regression:**

-   **Typ problemu:** Klasyfikacja (zwykle binarna). Przewiduje prawdopodobieństwo klasy pozytywnej.

-   **Interpretowalność:** Wysoka -- podobnie jak w linear regression, współczynniki cech mogą wskazywać, jak każda cecha wpływa na logarytm ilorazu szans wyniku. Ta przejrzystość jest często ceniona w bezpieczeństwie, ponieważ pomaga zrozumieć, które czynniki przyczyniają się do wygenerowania alertu.

-   **Zalety:** Prosta i szybka w trenowaniu; dobrze działa, gdy zależność między cechami a logarytmem ilorazu szans wyniku jest liniowa. Generuje prawdopodobieństwa, umożliwiając ocenę ryzyka. Przy odpowiedniej regularyzacji dobrze generalizuje i lepiej radzi sobie ze współliniowością niż zwykła linear regression.

-   **Ograniczenia:** Zakłada liniową granicę decyzyjną w przestrzeni cech (zawodzi, jeśli rzeczywista granica jest złożona/nieliniowa). Może osiągać gorsze wyniki w problemach, w których kluczowe są interakcje lub efekty nieliniowe, chyba że ręcznie dodasz cechy wielomianowe lub interakcyjne. Logistic regression jest również mniej skuteczna, jeśli klas nie można łatwo rozdzielić za pomocą liniowej kombinacji cech.


<details>
<summary>Przykład -- wykrywanie phishingowych witryn za pomocą Logistic Regression:</summary>

Użyjemy **Phishing Websites Dataset** (z repozytorium UCI), który zawiera wyodrębnione cechy witryn (takie jak informacja, czy URL zawiera adres IP, wiek domeny, obecność podejrzanych elementów w HTML itp.) oraz etykietę wskazującą, czy witryna jest phishingowa, czy legalna. Wytrenujemy model logistic regression do klasyfikowania witryn, a następnie ocenimy jego accuracy, precision, recall, F1-score i ROC AUC na wydzielonym zbiorze testowym.
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
W tym przykładzie wykrywania phishingu regresja logistyczna generuje prawdopodobieństwo, że każda witryna jest phishingiem. Oceniając accuracy, precision, recall i F1, uzyskujemy obraz wydajności modelu. Na przykład wysoki recall oznaczałby, że model wykrywa większość witryn phishingowych (co jest ważne z punktu widzenia bezpieczeństwa, aby zminimalizować liczbę przeoczonych ataków), podczas gdy wysoki precision oznacza niewielką liczbę fałszywych alarmów (co pomaga zapobiegać zmęczeniu analityków). ROC AUC (Area Under the ROC Curve) zapewnia niezależną od progu miarę wydajności (1.0 oznacza wynik idealny, a 0.5 — wynik nielepszy niż losowy). Regresja logistyczna często dobrze sprawdza się w takich zadaniach, ale jeśli granica decyzyjna między witrynami phishingowymi a legalnymi jest złożona, mogą być potrzebne bardziej zaawansowane modele nieliniowe.

</details>

### Drzewa decyzyjne

Drzewo decyzyjne to wszechstronny **algorytm uczenia nadzorowanego**, który może być wykorzystywany zarówno do zadań klasyfikacji, jak i regresji. Uczy się hierarchicznego modelu decyzji przypominającego drzewo, opartego na cechach danych. Każdy węzeł wewnętrzny drzewa reprezentuje test określonej cechy, każda gałąź reprezentuje wynik tego testu, a każdy węzeł liścia reprezentuje przewidywaną klasę (w przypadku klasyfikacji) lub wartość (w przypadku regresji).<sup>[[2]](#references)</sup>

Do budowy drzewa algorytmy takie jak CART (Classification and Regression Tree) wykorzystują miary, takie jak **nieczystość Giniego** lub **przyrost informacji (entropia)**, aby na każdym etapie wybrać najlepszą cechę i próg podziału danych. Celem każdego podziału jest rozdzielenie danych w taki sposób, aby zwiększyć jednorodność zmiennej docelowej w powstałych podzbiorach (w przypadku klasyfikacji każdy węzeł powinien być możliwie czysty i zawierać głównie jedną klasę).

Drzewa decyzyjne są **wysoce interpretowalne** -- można prześledzić ścieżkę od korzenia do liścia, aby zrozumieć logikę stojącą za przewidywaniem (np. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Jest to cenne w cybersecurity, ponieważ pozwala wyjaśnić, dlaczego wygenerowano konkretny alert. Drzewa mogą naturalnie obsługiwać zarówno dane numeryczne, jak i kategoryczne, a ponadto wymagają niewielkiego wstępnego przetwarzania (np. skalowanie cech nie jest potrzebne).

Pojedyncze drzewo decyzyjne może jednak łatwo przeuczyć się na danych treningowych, szczególnie jeśli zostanie rozbudowane do dużej głębokości (wiele podziałów). Aby zapobiec przeuczeniu, często stosuje się techniki takie jak przycinanie (ograniczenie głębokości drzewa lub wymaganie minimalnej liczby próbek w liściu).

Drzewo decyzyjne ma 3 główne komponenty:
- **Węzeł korzenia**: Najwyższy węzeł drzewa, reprezentujący cały zbiór danych.
- **Węzły wewnętrzne**: Węzły reprezentujące cechy i decyzje oparte na tych cechach.
- **Węzły liści**: Węzły reprezentujące końcowy wynik lub przewidywanie.

Drzewo może ostatecznie wyglądać tak:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Zastosowania w cyberbezpieczeństwie:* Drzewa decyzyjne były używane w systemach wykrywania włamań do wyprowadzania **reguł** służących do identyfikowania ataków. Na przykład wczesne IDS oparte na ID3/C4.5 generowały czytelne dla człowieka reguły pozwalające odróżniać normalny ruch od złośliwego. Są również używane w analizie malware do określania, czy plik jest złośliwy na podstawie jego atrybutów (rozmiar pliku, entropia sekcji, wywołania API itd.). Przejrzystość drzew decyzyjnych sprawia, że są przydatne, gdy wymagana jest transparentność -- analityk może sprawdzić drzewo w celu zweryfikowania logiki wykrywania.

#### **Kluczowe cechy drzew decyzyjnych:**

-   **Typ problemu:** Zarówno klasyfikacja, jak i regresja. Są powszechnie używane do klasyfikowania ataków i normalnego ruchu itd.

-   **Interpretowalność:** Bardzo wysoka -- decyzje modelu można wizualizować i rozumieć jako zestaw reguł if-then. Jest to istotna zaleta w bezpieczeństwie, ponieważ zapewnia zaufanie i możliwość weryfikacji działania modelu.

-   **Zalety:** Mogą odwzorowywać nieliniowe zależności i interakcje między cechami (każdy podział można postrzegać jako interakcję). Nie ma potrzeby skalowania cech ani kodowania one-hot zmiennych kategorycznych -- drzewa obsługują je natywnie. Szybkie wnioskowanie (predykcja polega jedynie na przejściu ścieżką w drzewie).

-   **Ograniczenia:** Są podatne na overfitting, jeśli nie są kontrolowane (głębokie drzewo może zapamiętać zbiór treningowy). Mogą być niestabilne -- niewielkie zmiany w danych mogą prowadzić do powstania innej struktury drzewa. Jako pojedyncze modele ich dokładność może nie dorównywać bardziej zaawansowanym metodom (ensembles, takie jak Random Forests, zwykle osiągają lepsze wyniki dzięki redukcji wariancji).

-   **Znajdowanie najlepszego podziału:**
- **Gini Impurity**: Mierzy nieczystość węzła. Niższa wartość Gini impurity oznacza lepszy podział. Wzór wygląda następująco:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Gdzie `p_i` oznacza udział instancji należących do klasy `i`.

- **Entropy**: Mierzy niepewność w zbiorze danych. Niższa entropy oznacza lepszy podział. Wzór wygląda następująco:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Gdzie `p_i` oznacza udział instancji należących do klasy `i`.

- **Information Gain**: Redukcja entropy lub Gini impurity po wykonaniu podziału. Im wyższy information gain, tym lepszy podział. Jest obliczany następująco:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ponadto drzewo zostaje zakończone, gdy:
- Wszystkie instancje w węźle należą do tej samej klasy. Może to prowadzić do overfittingu.
- Osiągnięta zostanie maksymalna głębokość drzewa (hardcoded). Jest to sposób zapobiegania overfittingowi.
- Liczba instancji w węźle spadnie poniżej określonego progu. Jest to również sposób zapobiegania overfittingowi.
- Information gain z kolejnych podziałów spadnie poniżej określonego progu. Jest to również sposób zapobiegania overfittingowi.

<details>
<summary>Przykład -- drzewo decyzyjne do wykrywania włamań:</summary>
Wytrenujemy drzewo decyzyjne na zbiorze danych NSL-KDD w celu klasyfikowania połączeń sieciowych jako *normalne* lub *atak*. NSL-KDD to ulepszona wersja klasycznego zbioru danych KDD Cup 1999, zawierającego cechy takie jak typ protokołu, usługa, czas trwania, liczba nieudanych logowań itd., oraz etykietę wskazującą typ ataku lub wartość "normal". Wszystkie typy ataków zmapujemy do klasy "anomaly" (klasyfikacja binarna: normal vs anomaly). Po zakończeniu trenowania ocenimy wydajność drzewa na zbiorze testowym.
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
W tym przykładzie drzewa decyzyjnego ograniczyliśmy głębokość drzewa do 10, aby uniknąć nadmiernego overfittingu (parametr `max_depth=10`). Metryki pokazują, jak dobrze drzewo rozróżnia normalny ruch od ruchu będącego atakiem. Wysoki recall oznaczałby, że wykrywa większość ataków (co jest ważne dla IDS), natomiast wysoki precision oznacza niewiele fałszywych alarmów. Drzewa decyzyjne często osiągają przyzwoitą accuracy na danych strukturalnych, ale pojedyncze drzewo może nie zapewnić najlepszej możliwej wydajności. Niemniej jednak *interpretowalność* modelu jest dużą zaletą -- możemy przeanalizować podziały drzewa, aby sprawdzić na przykład, które features (np. `service`, `src_bytes` itd.) mają największy wpływ na oznaczenie połączenia jako złośliwego.

</details>

### Random Forests

Random Forest to metoda **ensemble learning**, która bazuje na drzewach decyzyjnych w celu poprawy wydajności. Random forest trenuje wiele drzew decyzyjnych (stąd określenie „forest”) i łączy ich wyniki, aby uzyskać końcową predykcję (w przypadku klasyfikacji zazwyczaj za pomocą głosowania większościowego). Dwie główne idee Random Forest to **bagging** (bootstrap aggregating) oraz **feature randomness**:

-   **Bagging:** Każde drzewo jest trenowane na losowej bootstrap sample danych treningowych (próbkowanej ze zwracaniem). Wprowadza to różnorodność między drzewami.

-   **Feature Randomness:** Przy każdym podziale drzewa rozważany jest losowy podzbiór features (zamiast wszystkich features). Dodatkowo zmniejsza to korelację między drzewami.

Uśrednianie wyników wielu drzew zmniejsza variance, którą może wykazywać pojedyncze drzewo decyzyjne. Mówiąc prościej, poszczególne drzewa mogą być nadmiernie dopasowane lub generować szum, ale duża liczba różnorodnych drzew głosujących wspólnie wygładza te błędy. Rezultatem jest często model o **wyższej accuracy** i lepszej generalizacji niż w przypadku pojedynczego drzewa decyzyjnego. Ponadto Random Forests mogą dostarczać estymację feature importance (na podstawie tego, o ile każdy podział według feature średnio zmniejsza impurity).

Random Forests stały się **workhorse w cyberbezpieczeństwie** w zadaniach takich jak intrusion detection, malware classification i spam detection. Często dobrze działają out-of-the-box przy minimalnym tuningu i mogą obsługiwać duże zbiory features. Na przykład w intrusion detection Random Forest może przewyższać pojedyncze drzewo decyzyjne, wykrywając bardziej subtelne wzorce ataków przy mniejszej liczbie false positives. Badania wykazały, że Random Forests wypadają korzystnie w porównaniu z innymi algorytmami podczas klasyfikowania ataków w datasetach takich jak NSL-KDD i UNSW-NB15.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** Przede wszystkim klasyfikacja (stosowane również do regresji). Bardzo dobrze nadają się do wysokowymiarowych danych strukturalnych typowych dla security logs.

-   **Interpretability:** Niższa niż w przypadku pojedynczego drzewa decyzyjnego -- nie można łatwo zwizualizować ani wyjaśnić jednocześnie setek drzew. Jednak feature importance scores dostarczają pewnego wglądu w to, które attributes mają największy wpływ.

-   **Advantages:** Zazwyczaj wyższa accuracy niż w przypadku modeli opartych na pojedynczym drzewie dzięki efektowi ensemble. Odporność na overfitting -- nawet jeśli poszczególne drzewa są nadmiernie dopasowane, ensemble lepiej się generalizuje. Obsługuje zarówno features numeryczne, jak i kategoryczne, a także w pewnym stopniu radzi sobie z brakującymi danymi. Jest również stosunkowo odporny na outliers.

-   **Limitations:** Rozmiar modelu może być duży (wiele drzew, z których każde może być głębokie). Predykcje są wolniejsze niż w przypadku pojedynczego drzewa (ponieważ trzeba agregować wyniki wielu drzew). Mniejsza interpretowalność -- choć wiadomo, które features są ważne, dokładna logika nie jest łatwa do prześledzenia tak jak w przypadku prostej reguły. Jeśli dataset jest skrajnie wysokowymiarowy i sparse, trenowanie bardzo dużego forest może być wymagające obliczeniowo.

-   **Training Process:**
1. **Bootstrap Sampling**: Losowo próbkuj dane treningowe ze zwracaniem, aby utworzyć wiele podzbiorów (bootstrap samples).
2. **Tree Construction**: Dla każdej bootstrap sample zbuduj drzewo decyzyjne, używając losowego podzbioru features przy każdym podziale. Wprowadza to różnorodność między drzewami.
3. **Aggregation**: W zadaniach klasyfikacyjnych końcowa predykcja jest tworzona poprzez głosowanie większościowe na podstawie predykcji wszystkich drzew. W zadaniach regresyjnych końcowa predykcja jest średnią predykcji ze wszystkich drzew.

<details>
<summary>Example -- Random Forest for Intrusion Detection (NSL-KDD):</summary>
Użyjemy tego samego datasetu NSL-KDD (z etykietami binarnymi: normalny ruch lub anomalia) i wytrenujemy classifier Random Forest. Oczekujemy, że Random Forest osiągnie wyniki porównywalne z pojedynczym drzewem decyzyjnym lub lepsze, dzięki temu, że ensemble averaging zmniejsza variance. Ocenimy go za pomocą tych samych metryk.
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
Las losowy zazwyczaj osiąga dobre wyniki w tym zadaniu wykrywania intruzji. Możemy zaobserwować poprawę wskaźników, takich jak F1 lub AUC, w porównaniu z pojedynczym drzewem decyzyjnym, szczególnie w zakresie recall lub precision, zależnie od danych. Jest to zgodne ze stwierdzeniem, że *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*. W kontekście security operations model random forest może bardziej niezawodnie oznaczać ataki, jednocześnie ograniczając liczbę false alarms, dzięki uśrednianiu wielu reguł decyzyjnych. Feature importance z forest może wskazać, które cechy sieciowe najlepiej sygnalizują ataki (np. określone usługi sieciowe lub nietypowe liczby pakietów).

</details>

### Support Vector Machines (SVM)

Support Vector Machines to potężne modele supervised learning używane głównie do classification (a także do regression jako SVR). SVM próbuje znaleźć **optymalną hiperpłaszczyznę separującą**, która maksymalizuje margines między dwiema klasami. Tylko podzbiór punktów treningowych (tzw. "support vectors", znajdujące się najbliżej granicy) określa położenie tej hiperpłaszczyzny. Dzięki maksymalizacji marginesu (odległości między support vectors a hiperpłaszczyzną) SVM zwykle zapewnia dobrą generalizację.<sup>[[4]](#references)</sup>

Kluczową cechą SVM jest możliwość używania **kernel functions** do obsługi nieliniowych zależności. Dane mogą być niejawnie przekształcane do wielowymiarowej przestrzeni cech, w której może istnieć liniowy separator. Popularne kernels obejmują polynomial, radial basis function (RBF) i sigmoid. Na przykład jeśli klasy ruchu sieciowego nie są liniowo separowalne w surowej przestrzeni cech, kernel RBF może odwzorować je do wyższego wymiaru, w którym SVM znajdzie liniowy podział (odpowiadający nieliniowej granicy w przestrzeni oryginalnej). Elastyczność wyboru kernels pozwala SVM rozwiązywać różnorodne problemy.

SVM są znane z dobrego działania w sytuacjach, w których przestrzeń cech ma wysoki wymiar (np. dane tekstowe lub sekwencje opcode malware) oraz gdy liczba cech jest duża w porównaniu z liczbą próbek. Były popularne we wczesnych zastosowaniach cybersecurity, takich jak klasyfikacja malware i anomaly-based intrusion detection w latach 2000., często zapewniając wysoką accuracy.

SVM nie skalują się jednak łatwo do bardzo dużych datasets (złożoność treningu jest super-liniowa względem liczby próbek, a zużycie pamięci może być wysokie, ponieważ konieczne może być przechowywanie wielu support vectors). W praktyce, w zadaniach takich jak network intrusion detection obejmujących miliony rekordów, SVM może działać zbyt wolno bez starannego subsamplingu lub użycia metod przybliżonych.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (binary lub multiclass za pomocą one-vs-one/one-vs-rest) oraz warianty regression. Często używany w binary classification z wyraźną separacją marginesem.

-   **Interpretability:** Średnia -- SVM nie są tak łatwe do interpretacji jak decision trees lub logistic regression. Chociaż można określić, które punkty danych są support vectors, i uzyskać pewne pojęcie o tym, które cechy mogą mieć znaczenie (na podstawie weights w przypadku linear kernel), w praktyce SVM (szczególnie z non-linear kernels) traktuje się jako black-box classifiers.

-   **Advantages:** Skuteczne w high-dimensional spaces; mogą modelować złożone granice decyzyjne za pomocą kernel trick; odporne na overfitting, jeśli margines jest maksymalizowany (szczególnie przy właściwym parametrze regularization C); działają dobrze nawet wtedy, gdy klasy nie są oddzielone dużą odległością (znajdują najlepszy kompromis między granicami).

-   **Limitations:** **Computationally intensive** dla dużych datasets (zarówno training, jak i prediction słabo skalują się wraz ze wzrostem ilości danych). Wymagają starannego dostrojenia parametrów kernel i regularization (C, typ kernel, gamma dla RBF itd.). Nie dostarczają bezpośrednio probabilistic outputs (choć można użyć Platt scaling do uzyskania probabilities). SVM mogą być również wrażliwe na wybór parametrów kernel --- niewłaściwy wybór może prowadzić do underfit lub overfit.

*Use cases in cybersecurity:* SVM były używane do **malware detection** (np. klasyfikowania plików na podstawie wyodrębnionych cech lub sekwencji opcode), **network anomaly detection** (klasyfikowania ruchu jako normalnego lub malicious) oraz **phishing detection** (z użyciem cech URLs). Na przykład SVM może przyjąć cechy wiadomości e-mail (liczby wystąpień określonych keywords, scores reputacji nadawcy itd.) i sklasyfikować ją jako phishing lub legitimate. Stosowano je również do **intrusion detection** na datasets cech, takich jak KDD, często osiągając wysoką accuracy kosztem obliczeń.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Ponownie użyjemy phishing website dataset, tym razem z SVM. Ponieważ SVM mogą działać wolno, w razie potrzeby użyjemy podzbioru danych do trainingu (dataset obejmuje około 11 tys. instances, które SVM może obsłużyć w rozsądnym czasie). Użyjemy kernel RBF, który jest częstym wyborem dla danych nieliniowych, i włączymy probability estimates, aby obliczyć ROC AUC.
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
Model SVM będzie zwracał metryki, które możemy porównać z Logistic Regression dla tego samego zadania. Możemy odkryć, że SVM osiąga wysoką accuracy i AUC, jeśli dane są dobrze rozdzielone za pomocą cech. Z drugiej strony, jeśli dataset zawierałby dużo szumu lub nakładające się klasy, SVM może nie przewyższać znacząco Logistic Regression. W praktyce SVM może zapewnić poprawę, gdy między cechami a klasą występują złożone, nieliniowe zależności — kernel RBF może uchwycić zakrzywione granice decyzyjne, których Logistic Regression by nie wykrył. Tak jak w przypadku wszystkich modeli, konieczne jest staranne dostrojenie `C` (regularization) oraz parametrów kernela (takich jak `gamma` dla RBF), aby zachować równowagę między bias i variance.

</details>

#### Różnica między Logistic Regression a SVM

| Aspect | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Objective function** | Minimalizuje **log-loss** (cross-entropy). | Maksymalizuje **margin**, jednocześnie minimalizując **hinge-loss**. |
| **Decision boundary** | Znajduje **najlepiej dopasowaną hiperpłaszczyznę**, która modeluje _P(y\|x)_. | Znajduje **hiperpłaszczyznę o maksymalnym marginesie** (największy odstęp od najbliższych punktów). |
| **Output** | **Probabilistyczny** – zwraca skalibrowane prawdopodobieństwa klas za pomocą σ(w·x + b). | **Deterministyczny** – zwraca etykiety klas; prawdopodobieństwa wymagają dodatkowego przetwarzania (np. Platt scaling). |
| **Regularisation** | L2 (domyślna) lub L1, bezpośrednio równoważy underfitting i overfitting. | Parametr C stanowi kompromis między szerokością marginesu a błędnymi klasyfikacjami; parametry kernela zwiększają złożoność. |
| **Kernels / Non‑linear** | Natywna postać jest **liniowa**; nieliniowość dodaje się przez feature engineering. | Wbudowany **kernel trick** (RBF, poly itd.) pozwala modelować złożone granice w przestrzeni o wysokim wymiarze. |
| **Scalability** | Rozwiązuje wypukłą optymalizację w **O(nd)**; dobrze obsługuje bardzo duże n. | Trenowanie może wymagać **O(n²–n³)** pamięci/czasu bez wyspecjalizowanych solverów; gorzej sprawdza się przy ogromnych n. |
| **Interpretability** | **Wysoka** – wagi pokazują wpływ cech; odds ratio jest intuicyjne. | **Niska** dla nieliniowych kerneli; support vectors są rzadkie, ale trudne do wyjaśnienia. |
| **Sensitivity to outliers** | Wykorzystuje gładką funkcję log-loss → jest mniej wrażliwy. | **Hinge-loss** z hard margin może być **wrażliwy**; soft-margin (C) łagodzi ten problem. |
| **Typical use cases** | Scoring kredytowy, ryzyko medyczne, testy A/B – gdy istotne są **prawdopodobieństwa i explainability**. | Klasyfikacja obrazów/tekstu, bio-informatyka – gdy znaczenie mają **złożone granice** i **dane wielowymiarowe**. |

* **Jeśli potrzebujesz skalibrowanych prawdopodobieństw, interpretowalności lub pracy na ogromnych datasetach — wybierz Logistic Regression.**
* **Jeśli potrzebujesz elastycznego modelu, który może uchwycić nieliniowe zależności bez ręcznego feature engineering — wybierz SVM (z kernelami).**
* Oba modele optymalizują funkcje wypukłe, dlatego **gwarantowane są minima globalne**, ale kernele SVM dodają hiperparametry i zwiększają koszt obliczeniowy.

### Naive Bayes

Naive Bayes to rodzina **klasyfikatorów probabilistycznych** opartych na zastosowaniu twierdzenia Bayesa przy silnym założeniu niezależności między cechami. Pomimo tego „naiwnego” założenia Naive Bayes często działa zaskakująco dobrze w określonych zastosowaniach, zwłaszcza obejmujących dane tekstowe lub kategoryczne, takich jak wykrywanie spamu.<sup>[[5]](#references)</sup>


#### Twierdzenie Bayesa

Twierdzenie Bayesa stanowi podstawę klasyfikatorów Naive Bayes. Łączy prawdopodobieństwa warunkowe i brzegowe zdarzeń losowych. Wzór wygląda następująco:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gdzie:
- `P(A|B)` to prawdopodobieństwo a posteriori klasy `A` przy danej cesze `B`.
- `P(B|A)` to likelihood cechy `B` przy danej klasie `A`.
- `P(A)` to prawdopodobieństwo a priori klasy `A`.
- `P(B)` to prawdopodobieństwo a priori cechy `B`.

Na przykład, jeśli chcemy sklasyfikować, czy tekst został napisany przez dziecko czy osobę dorosłą, możemy użyć słów w tekście jako cech. Na podstawie początkowych danych klasyfikator Naive Bayes wcześniej obliczy prawdopodobieństwa wystąpienia każdego słowa w każdej potencjalnej klasie (dziecko lub dorosły). Gdy zostanie podany nowy tekst, obliczy prawdopodobieństwo każdej potencjalnej klasy na podstawie słów w tekście i wybierze klasę o najwyższym prawdopodobieństwie.

Jak widać na tym przykładzie, klasyfikator Naive Bayes jest bardzo prosty i szybki, ale zakłada, że cechy są niezależne, co nie zawsze ma miejsce w danych ze świata rzeczywistego.


#### Typy klasyfikatorów Naive Bayes

Istnieje kilka typów klasyfikatorów Naive Bayes, zależnie od rodzaju danych i rozkładu cech:
- **Gaussian Naive Bayes**: Zakłada, że cechy mają rozkład Gaussa (normalny). Jest odpowiedni dla danych ciągłych.
- **Multinomial Naive Bayes**: Zakłada, że cechy mają rozkład wielomianowy. Jest odpowiedni dla danych dyskretnych, takich jak liczba wystąpień słów w klasyfikacji tekstu.
- **Bernoulli Naive Bayes**: Zakłada, że cechy są binarne (0 lub 1). Jest odpowiedni dla danych binarnych, takich jak obecność lub brak słów w klasyfikacji tekstu.
- **Categorical Naive Bayes**: Zakłada, że cechy są zmiennymi kategorialnymi. Jest odpowiedni dla danych kategorialnych, takich jak klasyfikowanie owoców na podstawie ich koloru i kształtu.


#### **Kluczowe cechy Naive Bayes:**

-   **Rodzaj problemu:** Klasyfikacja (binarna lub wieloklasowa). Powszechnie używany do zadań klasyfikacji tekstu w cybersecurity (spam, phishing itd.).

-   **Interpretowalność:** Średnia -- nie jest tak bezpośrednio interpretowalny jak drzewo decyzyjne, ale można analizować wyuczone prawdopodobieństwa (np. które słowa najczęściej występują w wiadomościach spamowych w porównaniu z wiadomościami ham). Postać modelu (prawdopodobieństwa każdej cechy przy danej klasie) może być w razie potrzeby zrozumiana.

-   **Zalety:** **Bardzo szybkie** trenowanie i predykcja, nawet w przypadku dużych zbiorów danych (liniowe względem liczby instancji * liczby cech). Wymaga stosunkowo niewielkiej ilości danych do wiarygodnego oszacowania prawdopodobieństw, szczególnie przy zastosowaniu odpowiedniego smoothing. Często jest zaskakująco dokładny jako baseline, zwłaszcza gdy cechy niezależnie dostarczają dowodów na przynależność do klasy. Dobrze działa z danymi o dużej liczbie wymiarów (np. tysiącami cech pochodzących z tekstu). Nie wymaga złożonego dostrajania poza ustawieniem parametru smoothing.

-   **Ograniczenia:** Założenie niezależności może ograniczać dokładność, jeśli cechy są silnie skorelowane. Na przykład w danych sieciowych cechy takie jak `src_bytes` i `dst_bytes` mogą być skorelowane; Naive Bayes nie uchwyci tej interakcji. Wraz ze znacznym wzrostem rozmiaru danych bardziej ekspresyjne modele (takie jak ensembles lub neural nets) mogą przewyższyć NB, ucząc się zależności między cechami. Ponadto, jeśli do identyfikacji ataku potrzebna jest określona kombinacja cech (a nie tylko pojedyncze cechy niezależnie), NB będzie mieć trudności.

> [!TIP]
> *Zastosowania w cybersecurity:* Klasycznym zastosowaniem jest **spam detection** -- Naive Bayes stanowił podstawę wczesnych filtrów antyspamowych, wykorzystujących częstotliwość występowania określonych tokenów (słów, fraz, adresów IP) do obliczenia prawdopodobieństwa, że wiadomość e-mail jest spamem. Jest również używany w **phishing email detection** i **URL classification**, gdzie obecność określonych słów kluczowych lub cech (takich jak "login.php" w adresie URL lub `@` w ścieżce adresu URL) wpływa na prawdopodobieństwo phishingu. W analizie malware można wyobrazić sobie klasyfikator Naive Bayes, który wykorzystuje obecność określonych wywołań API lub uprawnień w oprogramowaniu do przewidywania, czy jest ono malware. Chociaż bardziej zaawansowane algorytmy często zapewniają lepsze wyniki, Naive Bayes pozostaje dobrym baseline ze względu na szybkość i prostotę.

<details>
<summary>Przykład -- Naive Bayes do wykrywania phishingu:</summary>
Aby zademonstrować działanie Naive Bayes, użyjemy Gaussian Naive Bayes na zbiorze danych dotyczących intrusion NSL-KDD (z etykietami binarnymi). Gaussian NB potraktuje każdą cechę jako mającą rozkład normalny dla każdej klasy. Jest to przybliżony wybór, ponieważ wiele cech sieciowych jest dyskretnych lub ma silnie skośny rozkład, ale pokazuje, jak zastosować NB do danych cech ciągłych. Moglibyśmy również wybrać Bernoulli NB dla zbioru danych zawierającego cechy binarne (takiego jak zestaw wyzwolonych alertów), ale w tym przypadku pozostaniemy przy NSL-KDD dla zachowania spójności.
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
Ten kod trenuje klasyfikator Naive Bayes do wykrywania ataków. Naive Bayes obliczy wartości takie jak `P(service=http | Attack)` i `P(Service=http | Normal)` na podstawie danych treningowych, zakładając niezależność cech. Następnie użyje tych prawdopodobieństw do klasyfikowania nowych połączeń jako normalnych lub będących atakiem na podstawie zaobserwowanych cech. Skuteczność NB na NSL-KDD może nie być tak wysoka jak w przypadku bardziej zaawansowanych modeli (ponieważ założenie niezależności cech jest naruszone), ale często jest przyzwoita i zapewnia korzyść w postaci wyjątkowo dużej szybkości. W scenariuszach takich jak filtrowanie wiadomości e-mail w czasie rzeczywistym lub wstępna triage adresów URL model Naive Bayes może szybko oznaczać oczywiście złośliwe przypadki przy niewielkim zużyciu zasobów.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors to jeden z najprostszych algorytmów machine learning. Jest to **nieparametryczna metoda oparta na instancjach**, która dokonuje predykcji na podstawie podobieństwa do przykładów ze zbioru treningowego. W przypadku klasyfikacji idea jest następująca: aby sklasyfikować nowy punkt danych, należy znaleźć **k** najbliższych punktów w danych treningowych (jego „nearest neighbors”), a następnie przypisać mu klasę występującą najczęściej wśród tych sąsiadów. „Bliskość” jest definiowana przez metrykę odległości, zazwyczaj odległość euklidesową dla danych numerycznych (dla różnych typów cech lub problemów można używać innych odległości).<sup>[[10]](#references)</sup>

K-NN nie wymaga *jawnego treningu* -- faza „treningu” polega jedynie na zapisaniu zbioru danych. Cała praca odbywa się podczas zapytania (predykcji): algorytm musi obliczyć odległości od punktu zapytania do wszystkich punktów treningowych, aby znaleźć te najbliższe. Sprawia to, że czas predykcji jest **liniowy względem liczby próbek treningowych**, co może być kosztowne w przypadku dużych zbiorów danych. Z tego powodu k-NN najlepiej nadaje się do mniejszych zbiorów danych lub scenariuszy, w których można poświęcić pamięć i szybkość na rzecz prostoty.

Pomimo swojej prostoty k-NN może modelować bardzo złożone granice decyzyjne (ponieważ granica decyzyjna może w praktyce mieć dowolny kształt wyznaczony przez rozmieszczenie przykładów). Sprawdza się szczególnie dobrze, gdy granica decyzyjna jest bardzo nieregularna i dostępna jest duża ilość danych -- zasadniczo pozwalając, aby dane „mówiły same za siebie”. Jednak w przestrzeniach o wysokiej liczbie wymiarów metryki odległości mogą stać się mniej miarodajne (curse of dimensionality), a metoda może mieć trudności, chyba że dysponuje się ogromną liczbą próbek.

*Zastosowania w cybersecurity:* k-NN stosowano do anomaly detection -- na przykład intrusion detection system może oznaczyć zdarzenie sieciowe jako złośliwe, jeśli większość jego najbliższych sąsiadów (wcześniejszych zdarzeń) była złośliwa. Jeśli normalny ruch tworzy klastry, a ataki są wartościami odstającymi, podejście K-NN (z k=1 lub małym k) działa zasadniczo jako **nearest-neighbor anomaly detection**. K-NN wykorzystywano również do klasyfikowania rodzin malware na podstawie binarnych wektorów cech: nowy plik może zostać sklasyfikowany jako należący do określonej rodziny malware, jeśli w przestrzeni cech jest bardzo podobny do znanych instancji tej rodziny. W praktyce k-NN nie jest tak powszechny jak bardziej skalowalne algorytmy, ale jest koncepcyjnie prosty i czasami używa się go jako baseline lub w problemach na małą skalę.

#### **Najważniejsze cechy k-NN:**

-   **Typ problemu:** Classification (istnieją również warianty regression). Jest to metoda *lazy learning* -- nie wykonuje jawnego dopasowania modelu.

-   **Interpretowalność:** Niska do średniej -- nie istnieje globalny model ani zwięzłe wyjaśnienie, ale wyniki można interpretować, analizując najbliższych sąsiadów, którzy wpłynęli na decyzję (np. „ten network flow został sklasyfikowany jako złośliwy, ponieważ jest podobny do tych 3 znanych złośliwych network flows”). Wyjaśnienia mogą więc opierać się na przykładach.

-   **Zalety:** Bardzo prosty we wdrożeniu i zrozumieniu. Nie wymaga założeń dotyczących rozkładu danych (non-parametric). Może naturalnie obsługiwać problemy multi-class. Jest **adaptacyjny** w tym sensie, że granice decyzyjne mogą być bardzo złożone i kształtowane przez rozkład danych.

-   **Ograniczenia:** Predykcja może być powolna w przypadku dużych zbiorów danych (trzeba obliczyć wiele odległości). Wymaga dużo pamięci -- przechowuje wszystkie dane treningowe. Wydajność pogarsza się w przestrzeniach cech o wysokiej liczbie wymiarów, ponieważ wszystkie punkty mają tendencję do stawania się niemal równoodległymi (przez co pojęcie „najbliższego” staje się mniej miarodajne). Należy odpowiednio wybrać *k* (liczbę sąsiadów) -- zbyt małe k może powodować szum, a zbyt duże k może uwzględniać nieistotne punkty z innych klas. Cechy powinny być również odpowiednio skalowane, ponieważ obliczenia odległości są wrażliwe na skalę.

<details>
<summary>Przykład -- k-NN do wykrywania Phishing:</summary>

Ponownie użyjemy NSL-KDD (klasyfikacja binarna). Ponieważ k-NN jest obciążony obliczeniowo, w tej demonstracji użyjemy podzbioru danych treningowych, aby zachować wykonalność obliczeń. Wybierzemy na przykład 20 000 próbek treningowych z pełnego zbioru liczącego 125 tys. próbek i użyjemy 5 sąsiadów, czyli k=5. Po treningu (który w rzeczywistości polega jedynie na zapisaniu danych) przeprowadzimy ewaluację na zbiorze testowym. Przeskalujemy również cechy na potrzeby obliczania odległości, aby żadna pojedyncza cecha nie dominowała z powodu swojej skali.
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
Model k-NN sklasyfikuje połączenie, sprawdzając 5 najbliższych połączeń w podzbiorze zbioru treningowego. Jeśli na przykład 4 z tych sąsiadów to ataki (anomalie), a 1 jest normalny, nowe połączenie zostanie sklasyfikowane jako atak. Wydajność może być rozsądna, choć często nie jest tak wysoka jak w przypadku dobrze dostrojonego Random Forest lub SVM na tych samych danych. k-NN może jednak czasami sprawdzać się bardzo dobrze, gdy rozkłady klas są bardzo nieregularne i złożone -- skutecznie wykorzystując wyszukiwanie oparte na pamięci. W cybersecurity k-NN (z k=1 lub małym k) można używać do wykrywania znanych wzorców ataków na podstawie przykładów albo jako komponentu bardziej złożonych systemów (np. do klasteryzacji, a następnie klasyfikowania na podstawie przynależności do klastra).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines należą do najpotężniejszych algorytmów dla danych strukturalnych. **Gradient boosting** odnosi się do techniki budowania zespołu słabych learnerów (często drzew decyzyjnych) sekwencyjnie, gdzie każdy nowy model koryguje błędy poprzedniego zespołu. W przeciwieństwie do baggingu (Random Forest), który buduje drzewa równolegle i uśrednia ich wyniki, boosting buduje drzewa *jedno po drugim*, przy czym każde z nich koncentruje się bardziej na instancjach, które poprzednie drzewa sklasyfikowały niepoprawnie.

Najpopularniejsze implementacje w ostatnich latach to **XGBoost**, **LightGBM** i **CatBoost** - wszystkie są bibliotekami gradient boosting decision tree (GBDT). Odniosły ogromny sukces w zawodach i zastosowaniach machine learning, często **osiągając wyniki na poziomie state-of-the-art na zbiorach danych tabelarycznych**. W cybersecurity badacze i praktycy używali gradient boosted trees do zadań takich jak **malware detection** (z wykorzystaniem cech wyodrębnionych z plików lub zachowania podczas działania) oraz **network intrusion detection**. Na przykład model gradient boosting może połączyć wiele słabych reguł (drzew), takich jak „jeśli występuje wiele pakietów SYN i nietypowy port -> prawdopodobnie skanowanie”, w silny złożony detektor uwzględniający wiele subtelnych wzorców.<sup>[[6]](#references)</sup>

Dlaczego boosted trees są tak skuteczne? Każde drzewo w sekwencji jest trenowane na *resztowych błędach* (gradientach) predykcji bieżącego zespołu. Dzięki temu model stopniowo **„wzmacnia”** obszary, w których jest słaby. Wykorzystanie drzew decyzyjnych jako bazowych learnerów oznacza, że końcowy model może wychwytywać złożone interakcje i nieliniowe zależności. Boosting ma również formę wbudowanej regularyzacji: przez dodawanie wielu małych drzew (i użycie learning rate do skalowania ich udziału) często dobrze generalizuje bez nadmiernego overfittingu, o ile zostaną dobrane odpowiednie parametry.

#### **Key characteristics of Gradient Boosting:**

-   **Type of Problem:** Przede wszystkim klasyfikacja i regresja. W security zazwyczaj klasyfikacja (np. binarne klasyfikowanie połączenia lub pliku). Obsługuje problemy binarne, wieloklasowe (z odpowiednią funkcją straty), a nawet problemy rankingowe.

-   **Interpretability:** Niska do średniej. Chociaż pojedyncze boosted tree jest małe, pełny model może zawierać setki drzew, przez co jako całość nie jest zrozumiały dla człowieka. Jednak podobnie jak Random Forest może dostarczać wyniki ważności cech, a narzędzia takie jak SHAP (SHapley Additive exPlanations) mogą do pewnego stopnia służyć do interpretowania poszczególnych predykcji.

-   **Advantages:** Często **algorytm osiągający najlepsze wyniki** dla danych strukturalnych/tabelarycznych. Może wykrywać złożone wzorce i interakcje. Ma wiele parametrów do dostrajania (liczba drzew, głębokość drzew, learning rate, terminy regularyzacji), co pozwala dopasować złożoność modelu i zapobiegać overfittingowi. Nowoczesne implementacje są zoptymalizowane pod kątem szybkości (np. XGBoost używa informacji o gradientach drugiego rzędu i wydajnych struktur danych). Zwykle lepiej radzi sobie z niezbalansowanymi danymi, gdy jest połączony z odpowiednimi funkcjami straty lub gdy dostosuje się wagi próbek.

-   **Limitations:** Jest trudniejszy do dostrojenia niż prostsze modele; trenowanie może być powolne, jeśli drzewa są głębokie lub ich liczba jest duża (choć zwykle i tak jest szybsze niż trenowanie porównywalnej deep neural network na tych samych danych). Model może ulec overfittingowi, jeśli nie zostanie odpowiednio dostrojony (np. zbyt wiele głębokich drzew przy niewystarczającej regularyzacji). Ze względu na dużą liczbę hyperparameters skuteczne wykorzystanie gradient boosting może wymagać większego doświadczenia lub eksperymentowania. Ponadto, podobnie jak metody oparte na drzewach, nie obsługuje z natury bardzo rzadkich danych wysoko wymiarowych tak wydajnie jak modele liniowe lub Naive Bayes (choć nadal można go stosować, np. w klasyfikacji tekstu, ale bez feature engineering może nie być pierwszym wyborem).

> [!TIP]
> *Use cases in cybersecurity:* Niemal wszędzie tam, gdzie można użyć drzewa decyzyjnego lub random forest, model gradient boosting może osiągnąć lepszą dokładność. Na przykład w zawodach **Microsoft's malware detection** intensywnie wykorzystywano XGBoost na cechach przygotowanych z plików binarnych. Badania nad **Network intrusion detection** często wskazują najlepsze wyniki uzyskiwane za pomocą GBDT (np. XGBoost na zbiorach danych CIC-IDS2017 lub UNSW-NB15). Modele te mogą przyjmować szeroki zakres cech (typy protokołów, częstotliwość określonych zdarzeń, cechy statystyczne ruchu itd.) i łączyć je w celu wykrywania zagrożeń. W phishing detection gradient boosting może łączyć cechy leksykalne URL, cechy reputacji domeny i cechy zawartości strony, aby osiągnąć bardzo wysoką dokładność. Podejście zespołowe pomaga uwzględnić wiele przypadków brzegowych i subtelności w danych.

<details>
<summary>Przykład -- XGBoost for Phishing Detection:</summary>
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
Model gradient boosting prawdopodobnie osiągnie bardzo wysoką accuracy i AUC na tym zbiorze danych dotyczącym phishingu (często modele te mogą, przy odpowiednim dostrojeniu, przekraczać 95% accuracy na takich danych, jak pokazują publikacje naukowe). Pokazuje to, dlaczego GBDT są uznawane za *„state of the art model for tabular dataset”* -- często przewyższają prostsze algorytmy, wykrywając złożone wzorce. W kontekście cybersecurity może to oznaczać wykrywanie większej liczby stron phishingowych lub ataków przy mniejszej liczbie przeoczeń. Oczywiście należy uważać na overfitting -- podczas tworzenia takiego modelu do wdrożenia zazwyczaj stosuje się techniki takie jak cross-validation i monitoruje wydajność na zbiorze walidacyjnym.

</details>

### Łączenie modeli: Ensemble Learning i Stacking

Ensemble learning to strategia **łączenia wielu modeli** w celu poprawy ogólnej wydajności. Poznaliśmy już konkretne metody ensemble: Random Forest (ensemble drzew wykorzystujący bagging) oraz Gradient Boosting (ensemble drzew wykorzystujący sekwencyjny boosting). Ensemble można jednak tworzyć także na inne sposoby, na przykład jako **voting ensembles** lub **stacked generalization (stacking)**. Główna idea polega na tym, że różne modele mogą wykrywać różne wzorce lub mieć różne słabości; łącząc je, możemy **kompensować błędy jednego modelu mocnymi stronami innego**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** W prostym voting classifier trenujemy wiele zróżnicowanych modeli (na przykład regresję logistyczną, drzewo decyzyjne i SVM), a następnie pozwalamy im głosować nad końcową predykcją (w przypadku klasyfikacji stosuje się głosowanie większościowe). Jeśli przypiszemy głosom wagi (na przykład większą wagę dokładniejszym modelom), otrzymamy weighted voting scheme. Zwykle poprawia to wydajność, gdy poszczególne modele są odpowiednio dobre i niezależne -- ensemble zmniejsza ryzyko błędu pojedynczego modelu, ponieważ pozostałe mogą go skorygować. To tak, jakby korzystać z panelu ekspertów zamiast pojedynczej opinii.

-   **Stacking (Stacked Ensemble):** Stacking idzie o krok dalej. Zamiast prostego głosowania trenuje **meta-model**, który ma **nauczyć się, jak najlepiej łączyć predykcje** modeli bazowych. Na przykład trenujemy 3 różne klasyfikatory (base learners), a następnie przekazujemy ich wyniki (lub prawdopodobieństwa) jako features do meta-classifiera (często prostego modelu, takiego jak regresja logistyczna), który uczy się optymalnego sposobu ich łączenia. Meta-model jest trenowany na zbiorze walidacyjnym lub za pomocą cross-validation, aby uniknąć overfittingu. Stacking często przewyższa proste głosowanie, ponieważ uczy się, *którym modelom bardziej ufać w określonych sytuacjach*. W cybersecurity jeden model może lepiej wykrywać skanowanie sieci, a inny beaconing malware; model stacking może nauczyć się odpowiednio polegać na każdym z nich.

Ensemble, niezależnie od tego, czy wykorzystuje głosowanie, czy stacking, zwykle **zwiększa accuracy** i odporność. Wadą jest większa złożoność oraz czasami mniejsza interpretowalność (choć niektóre podejścia ensemble, takie jak uśrednianie drzew decyzyjnych, nadal mogą dostarczać pewnych informacji, na przykład o feature importance). W praktyce, jeśli pozwalają na to ograniczenia operacyjne, użycie ensemble może prowadzić do wyższych detection rates. Wiele zwycięskich rozwiązań w wyzwaniach cybersecurity (a także w konkursach Kaggle ogólnie) wykorzystuje techniki ensemble, aby wycisnąć ostatnie ułamki wydajności.

<details>
<summary>Przykład -- Voting Ensemble do wykrywania phishingu:</summary>
Aby zilustrować model stacking, połączmy kilka modeli, które omawialiśmy, na zbiorze danych dotyczącym phishingu. Użyjemy regresji logistycznej, drzewa decyzyjnego i k-NN jako base learners, a Random Forest jako meta-learnera do agregowania ich predykcji. Meta-learner będzie trenowany na wynikach base learners (z wykorzystaniem cross-validation na zbiorze treningowym). Oczekujemy, że model stacked osiągnie wydajność porównywalną z poszczególnymi modelami lub nieco od nich lepszą.
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
Stacked ensemble wykorzystuje uzupełniające się mocne strony modeli bazowych. Na przykład regresja logistyczna może obsługiwać liniowe aspekty danych, drzewo decyzyjne może wychwytywać określone interakcje przypominające reguły, a k-NN może doskonale sprawdzać się w lokalnych sąsiedztwach przestrzeni cech. Meta-model (w tym przypadku random forest) może nauczyć się, jak ważyć te dane wejściowe. Uzyskane metryki często pokazują poprawę (nawet jeśli niewielką) w porównaniu z metrykami dowolnego pojedynczego modelu. W naszym przykładzie phishingu, jeśli sama regresja logistyczna miałaby wartość F1 wynoszącą na przykład 0,95, a drzewo 0,94, stack mógłby osiągnąć 0,96, uzupełniając obszary, w których poszczególne modele się mylą.

Metody ensemble, takie jak ta, ilustrują zasadę, że *„łączenie wielu modeli zazwyczaj prowadzi do lepszej generalizacji”*. W cyberbezpieczeństwie można to wdrożyć, wykorzystując wiele silników detekcji (jeden może być oparty na regułach, drugi na machine learning, a trzeci na wykrywaniu anomalii), a następnie warstwę agregującą ich alerty -- co stanowi w praktyce formę ensemble -- w celu podjęcia ostatecznej decyzji z większą pewnością. Podczas wdrażania takich systemów należy uwzględnić dodatkową złożoność i zadbać o to, aby ensemble nie stał się zbyt trudny w zarządzaniu lub wyjaśnianiu. Jednak z punktu widzenia dokładności ensemble i stacking są potężnymi narzędziami poprawiającymi wydajność modeli.

</details>


## References

- [1] [Regresja logistyczna](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Drzewo decyzyjne - wprowadzenie z przykładem](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Wykrywanie Denial of Services Attack za pomocą klasyfikatora Random Forest z Information Gain](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [Czym są Support Vector Machines (SVM)? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Filtrowanie spamu za pomocą Naive Bayes (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT wyjaśnione: jak działają LightGBM, XGBoost i CatBoost](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI i machine learning w cyberbezpieczeństwie (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Regresja liniowa wyjaśniona](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Analiza wydajności modeli machine learning dla systemu wykrywania włamań z wykorzystaniem techniki selekcji cech Gini Impurity-based Weighted Random Forest (GIWRF)](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [Czym jest algorytm k-nearest neighbors (KNN)? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Klasyfikacja ataków phishingowych i stron internetowych z wykorzystaniem machine learning i wielu zbiorów danych (analiza porównawcza)](https://arxiv.org/pdf/2101.02552)
- [12] [Jak deep learning usprawnia systemy wykrywania włamań](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble learning: zwiększanie wydajności modeli przez łączenie ich mocnych stron](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
