# Algorytmy uczenia nadzorowanego

{{#include ../banners/hacktricks-training.md}}

## Podstawowe informacje

Uczenie nadzorowane wykorzystuje oznaczone dane do trenowania modeli, które mogą generować predykcje dla nowych, niewidzianych wcześniej danych wejściowych. W cyberbezpieczeństwie supervised machine learning jest szeroko stosowane w zadaniach takich jak wykrywanie intruzji (klasyfikowanie ruchu sieciowego jako *normalnego* lub *ataku*), wykrywanie malware (rozróżnianie złośliwego oprogramowania od nieszkodliwego), wykrywanie phishingu (identyfikowanie fałszywych stron internetowych lub wiadomości e-mail), filtrowanie spamu oraz wielu innych.<sup>[[1]](#references)</sup> Każdy algorytm ma swoje mocne strony i nadaje się do różnych typów problemów (klasyfikacji lub regresji). Poniżej omawiamy najważniejsze algorytmy uczenia nadzorowanego, wyjaśniamy, jak działają, oraz pokazujemy ich zastosowanie na rzeczywistych datasetach związanych z cyberbezpieczeństwem. Omawiamy również, jak łączenie modeli (ensemble learning) może często poprawić wydajność predykcyjną.

## Algorytmy

-   **Regresja liniowa:** Podstawowy algorytm regresji służący do przewidywania wartości liczbowych poprzez dopasowanie równania liniowego do danych.

-   **Regresja logistyczna:** Algorytm klasyfikacji (pomimo swojej nazwy), który wykorzystuje funkcję logistyczną do modelowania prawdopodobieństwa wyniku binarnego.

-   **Drzewa decyzyjne:** Modele o strukturze drzewa, które dzielą dane na podstawie cech w celu generowania predykcji; często wykorzystywane ze względu na ich interpretowalność.

-   **Lasy losowe:** Ensemble drzew decyzyjnych (za pomocą baggingu), które poprawiają dokładność i ograniczają overfitting.

-   **Support Vector Machines (SVM):** Klasyfikatory maksymalnego marginesu, które znajdują optymalną hiperpłaszczyznę rozdzielającą; mogą wykorzystywać kernele dla danych nieliniowych.

-   **Naive Bayes:** Klasyfikator probabilistyczny oparty na twierdzeniu Bayesa i założeniu niezależności cech, powszechnie wykorzystywany w filtrowaniu spamu.

-   **k-Nearest Neighbors (k-NN):** Prosty klasyfikator „instance-based”, który przypisuje próbce etykietę na podstawie najliczniejszej klasy wśród jej najbliższych sąsiadów.

-   **Gradient Boosting Machines:** Modele ensemble (np. XGBoost, LightGBM), które budują silny predyktor poprzez sekwencyjne dodawanie słabszych modeli (zazwyczaj drzew decyzyjnych).

Każda z poniższych sekcji zawiera ulepszony opis algorytmu oraz **przykład kodu w Pythonie** wykorzystujący biblioteki takie jak `pandas` i `scikit-learn` (oraz `PyTorch` w przykładzie sieci neuronowej). Przykłady korzystają z publicznie dostępnych datasetów związanych z cyberbezpieczeństwem (takich jak NSL-KDD do wykrywania intruzji oraz Phishing Websites dataset) i mają spójną strukturę:

1.  **Wczytanie datasetu** (pobranie za pomocą URL, jeśli jest dostępny).

2.  **Wstępne przetworzenie danych** (np. zakodowanie cech kategorycznych, przeskalowanie wartości, podział na zbiory treningowy i testowy).

3.  **Wytrenowanie modelu** na danych treningowych.

4.  **Ewaluacja** na zbiorze testowym z użyciem metryk: accuracy, precision, recall, F1-score i ROC AUC dla klasyfikacji (oraz mean squared error dla regresji).

Przejdźmy do omówienia poszczególnych algorytmów:

### Regresja liniowa

Regresja liniowa jest algorytmem **regresji** używanym do przewidywania ciągłych wartości liczbowych. Zakłada liniową zależność między cechami wejściowymi (zmiennymi niezależnymi) a wyjściem (zmienną zależną). Model próbuje dopasować prostą linię (lub hiperpłaszczyznę w wyższych wymiarach), która najlepiej opisuje zależność między cechami a wartością docelową. Zwykle osiąga się to poprzez minimalizację sumy kwadratów błędów między wartościami przewidywanymi a rzeczywistymi (metoda Ordinary Least Squares).<sup>[[2]](#references)</sup>

Najprostszy sposób przedstawienia regresji liniowej to linia:
```plaintext
y = mx + b
```
Gdzie:

- `y` to przewidywana wartość (wynik)
- `m` to nachylenie linii (współczynnik)
- `x` to cecha wejściowa
- `b` to punkt przecięcia z osią y

Celem regresji liniowej jest znalezienie najlepiej dopasowanej linii, która minimalizuje różnicę między przewidywanymi wartościami a rzeczywistymi wartościami w zbiorze danych. Oczywiście jest to bardzo proste — byłaby to prosta linia oddzielająca 2 kategorie, ale po dodaniu większej liczby wymiarów linia staje się bardziej złożona:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Zastosowania w cyberbezpieczeństwie:* Sama regresja liniowa jest rzadziej stosowana w podstawowych zadaniach bezpieczeństwa (które często są zadaniami klasyfikacji), ale można jej używać do przewidywania wartości liczbowych. Na przykład regresja liniowa może służyć do **przewidywania natężenia ruchu sieciowego** lub **szacowania liczby ataków w określonym przedziale czasu** na podstawie danych historycznych. Może również przewidywać wynik ryzyka lub oczekiwany czas do wykrycia ataku na podstawie określonych metryk systemowych. W praktyce algorytmy klasyfikacji (takie jak regresja logistyczna lub drzewa) są częściej używane do wykrywania włamań lub malware, ale regresja liniowa stanowi podstawę i jest przydatna w analizach ukierunkowanych na regresję.

#### **Najważniejsze cechy regresji liniowej:**

-   **Typ problemu:** Regresja (przewidywanie wartości ciągłych). Nie nadaje się do bezpośredniej klasyfikacji, chyba że do wyniku zostanie zastosowany próg.

-   **Interpretowalność:** Wysoka -- współczynniki są łatwe do interpretacji i pokazują liniowy wpływ każdej cechy.

-   **Zalety:** Prosta i szybka; stanowi dobry punkt odniesienia dla zadań regresji; działa dobrze, gdy rzeczywista zależność jest w przybliżeniu liniowa.

-   **Ograniczenia:** Nie potrafi uchwycić złożonych lub nieliniowych zależności (bez ręcznego konstruowania cech); jest podatna na niedouczenie, jeśli zależności są nieliniowe; jest wrażliwa na wartości odstające, które mogą zniekształcać wyniki.

-   **Wyznaczanie najlepszego dopasowania:** Aby znaleźć linię najlepszego dopasowania, która rozdziela możliwe kategorie, używamy metody zwanej **zwykłą metodą najmniejszych kwadratów (OLS)**. Metoda ta minimalizuje sumę kwadratów różnic między zaobserwowanymi wartościami a wartościami przewidywanymi przez model liniowy.

<details>
<summary>Przykład -- Przewidywanie czasu trwania połączenia (regresja) w zbiorze danych dotyczących włamań
</summary>
Poniżej demonstrujemy regresję liniową z użyciem zbioru danych dotyczących cyberbezpieczeństwa NSL-KDD. Potraktujemy to jako problem regresji, przewidując `duration` połączeń sieciowych na podstawie innych cech. (W rzeczywistości `duration` jest jedną z cech NSL-KDD; używamy jej tutaj wyłącznie w celu zilustrowania regresji). Wczytujemy zbiór danych, wstępnie go przetwarzamy (kodując cechy kategoryczne), uczymy model regresji liniowej oraz oceniamy błąd średniokwadratowy (MSE) i wynik R² na zbiorze testowym.
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
W tym przykładzie model regresji liniowej próbuje przewidzieć `duration` połączenia na podstawie innych cech sieci. Wydajność mierzymy za pomocą Mean Squared Error (MSE) i R². Wartość R² bliska 1.0 wskazywałaby, że model wyjaśnia większość wariancji `duration`, natomiast niska lub ujemna wartość R² wskazuje na słabe dopasowanie. (Nie zdziw się, jeśli R² będzie tutaj niskie -- przewidywanie `duration` na podstawie podanych cech może być trudne, a regresja liniowa może nie uchwycić wzorców, jeśli są one złożone.)
</details>

### Regresja logistyczna

Regresja logistyczna to algorytm **classification**, który modeluje prawdopodobieństwo, że dana instancja należy do określonej klasy (zazwyczaj klasy „pozytywnej”). Pomimo swojej nazwy regresja *logistic* jest używana dla wyników dyskretnych (w przeciwieństwie do regresji liniowej, która służy do wyników ciągłych). Jest szczególnie użyteczna w przypadku **binary classification** (dwóch klas, np. malicious i benign), ale można ją rozszerzyć na problemy wieloklasowe (przy użyciu podejść softmax lub one-vs-rest).<sup>[[3]](#references)</sup>

Regresja logistyczna wykorzystuje funkcję logistyczną (znaną również jako funkcja sigmoid) do mapowania przewidywanych wartości na prawdopodobieństwa. Należy zauważyć, że funkcja sigmoid to funkcja o wartościach od 0 do 1, która zgodnie z potrzebami klasyfikacji rośnie po krzywej w kształcie litery S, co jest przydatne w zadaniach binary classification. Dlatego każda cecha każdego wejścia jest mnożona przez przypisaną jej wagę, a wynik jest przekazywany przez funkcję sigmoid w celu uzyskania prawdopodobieństwa:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Gdzie:

- `p(y=1|x)` to prawdopodobieństwo, że wyjście `y` wynosi 1 przy wejściu `x`
- `e` to podstawa logarytmu naturalnego
- `z` to kombinacja liniowa cech wejściowych, zazwyczaj przedstawiana jako `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Zauważ, że ponownie w najprostszej postaci jest to linia prosta, ale w bardziej złożonych przypadkach staje się hiperpłaszczyzną o wielu wymiarach (po jednym na każdą cechę).

> [!TIP]
> *Zastosowania w cyberbezpieczeństwie:* Ponieważ wiele problemów związanych z bezpieczeństwem sprowadza się zasadniczo do decyzji typu tak/nie, Logistic Regression jest szeroko stosowana. Na przykład system wykrywania włamań może używać Logistic Regression do określenia, czy połączenie sieciowe jest atakiem, na podstawie cech tego połączenia. W wykrywaniu phishingu Logistic Regression może połączyć cechy witryny (długość adresu URL, obecność symbolu "@", itp.) w prawdopodobieństwo, że jest to phishing. Była stosowana we wczesnych generacjach filtrów antyspamowych i nadal stanowi silny punkt odniesienia dla wielu zadań klasyfikacji.

#### Logistic Regression dla klasyfikacji niebinarnej

Logistic Regression została zaprojektowana do klasyfikacji binarnej, ale można ją rozszerzyć, aby obsługiwała problemy wieloklasowe, wykorzystując techniki takie jak **one-vs-rest** (OvR) lub **softmax regression**. W OvR dla każdej klasy trenuje się osobny model Logistic Regression, traktując ją jako klasę pozytywną, a wszystkie pozostałe jako negatywne. Klasa z najwyższym przewidywanym prawdopodobieństwem jest wybierana jako ostateczna predykcja. Softmax regression uogólnia Logistic Regression na wiele klas, stosując funkcję softmax do warstwy wyjściowej i generując rozkład prawdopodobieństwa dla wszystkich klas.

#### **Kluczowe cechy Logistic Regression:**

-   **Typ problemu:** Klasyfikacja (zwykle binarna). Przewiduje prawdopodobieństwo klasy pozytywnej.

-   **Interpretowalność:** Wysoka -- podobnie jak w przypadku regresji liniowej, współczynniki cech mogą wskazywać, jak każda cecha wpływa na logarytm ilorazu szans wyniku. Ta przejrzystość jest często ceniona w obszarze bezpieczeństwa, ponieważ pomaga zrozumieć, które czynniki przyczyniają się do wygenerowania alertu.

-   **Zalety:** Prosta i szybka w trenowaniu; dobrze działa, gdy zależność między cechami a logarytmem ilorazu szans wyniku jest liniowa. Zwraca prawdopodobieństwa, umożliwiając ocenę ryzyka. Przy odpowiedniej regularyzacji dobrze uogólnia i lepiej radzi sobie ze współliniowością niż zwykła regresja liniowa.

-   **Ograniczenia:** Zakłada liniową granicę decyzyjną w przestrzeni cech (zawodzi, jeśli rzeczywista granica jest złożona/nieliniowa). Może osiągać gorsze wyniki w problemach, w których interakcje lub efekty nieliniowe mają kluczowe znaczenie, chyba że ręcznie doda się cechy wielomianowe lub cechy interakcji. Ponadto Logistic Regression jest mniej skuteczna, jeśli klas nie można łatwo rozdzielić za pomocą liniowej kombinacji cech.


<details>
<summary>Przykład -- wykrywanie phishingowych witryn za pomocą Logistic Regression:</summary>

Użyjemy **Phishing Websites Dataset** (z repozytorium UCI), który zawiera wyodrębnione cechy witryn (takie jak informacja, czy adres URL zawiera adres IP, wiek domeny, obecność podejrzanych elementów w HTML itp.) oraz etykietę wskazującą, czy witryna jest phishingowa, czy legalna.<sup>[[4]](#references)</sup> Wytrenujemy model Logistic Regression do klasyfikowania witryn, a następnie ocenimy jego accuracy, precision, recall, F1-score i ROC AUC na wydzielonym zbiorze testowym.
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
W tym przykładzie wykrywania phishingu regresja logistyczna generuje prawdopodobieństwo, że każda witryna jest phishingiem. Oceniając accuracy, precision, recall i F1, uzyskujemy obraz wydajności modelu. Na przykład wysoki recall oznaczałby, że model wykrywa większość witryn phishingowych (co jest ważne dla bezpieczeństwa, aby zminimalizować liczbę pominiętych ataków), podczas gdy wysoka precision oznacza, że generuje niewiele fałszywych alarmów (co jest istotne, aby uniknąć zmęczenia analityków). ROC AUC (Area Under the ROC Curve) zapewnia niezależną od progu miarę wydajności (1.0 oznacza wynik idealny, a 0.5 — wynik nielepszy niż losowy). Regresja logistyczna często dobrze sprawdza się w takich zadaniach, ale jeśli granica decyzyjna między witrynami phishingowymi a legalnymi jest złożona, mogą być potrzebne bardziej zaawansowane modele nieliniowe.

</details>

### Drzewa decyzyjne

Drzewo decyzyjne to wszechstronny **algorytm uczenia nadzorowanego**, który może być używany zarówno do zadań klasyfikacji, jak i regresji. Uczy się hierarchicznego modelu decyzji przypominającego drzewo, bazując na cechach danych. Każdy węzeł wewnętrzny drzewa reprezentuje test określonej cechy, każda gałąź reprezentuje wynik tego testu, a każdy węzeł liścia reprezentuje przewidywaną klasę (w przypadku klasyfikacji) lub wartość (w przypadku regresji).<sup>[[5]](#references)</sup>

Do budowy drzewa algorytmy takie jak CART (Classification and Regression Tree) wykorzystują miary, takie jak **nieczystość Giniego** lub **information gain (entropia)**, aby na każdym etapie wybrać najlepszą cechę i próg podziału danych. Celem każdego podziału jest zwiększenie jednorodności zmiennej docelowej w powstałych podzbiorach (w przypadku klasyfikacji każdy węzeł powinien być możliwie czysty i zawierać głównie jedną klasę).

Drzewa decyzyjne są **wysoce interpretowalne** -- można prześledzić ścieżkę od korzenia do liścia, aby zrozumieć logikę stojącą za predykcją (np. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Jest to cenne w cybersecurity, ponieważ pozwala wyjaśnić, dlaczego wygenerowano określony alert. Drzewa mogą naturalnie obsługiwać zarówno dane numeryczne, jak i kategoryczne, a także wymagają niewielkiego wstępnego przetwarzania (np. skalowanie cech nie jest potrzebne).

Pojedyncze drzewo decyzyjne może jednak łatwo dopasować się nadmiernie do danych treningowych, szczególnie jeśli jest rozbudowane (ma wiele podziałów). Aby zapobiec overfittingowi, często stosuje się techniki takie jak przycinanie (ograniczenie głębokości drzewa lub wymaganie minimalnej liczby próbek w każdym liściu).

Drzewo decyzyjne ma 3 główne komponenty:
- **Węzeł korzenia**: Najwyższy węzeł drzewa, reprezentujący cały zbiór danych.
- **Węzły wewnętrzne**: Węzły reprezentujące cechy i decyzje oparte na tych cechach.
- **Węzły liści**: Węzły reprezentujące końcowy rezultat lub predykcję.

Drzewo może ostatecznie wyglądać tak:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Zastosowania w cybersecurity:* Drzewa decyzyjne były używane w systemach wykrywania włamań do tworzenia **reguł** identyfikujących ataki. Na przykład wczesne systemy IDS oparte na ID3/C4.5 generowały czytelne dla człowieka reguły pozwalające odróżnić normalny od złośliwego ruchu. Są również używane w analizie malware do określania, czy plik jest złośliwy na podstawie jego atrybutów (rozmiaru pliku, entropii sekcji, wywołań API itp.). Przejrzystość drzew decyzyjnych sprawia, że są przydatne, gdy wymagana jest transparentność -- analityk może przeanalizować drzewo, aby zweryfikować logikę wykrywania.

#### **Kluczowe cechy drzew decyzyjnych:**

-   **Typ problemu:** Zarówno klasyfikacja, jak i regresja. Powszechnie używane do klasyfikowania ataków i normalnego ruchu itp.

-   **Interpretowalność:** Bardzo wysoka -- decyzje modelu można wizualizować i rozumieć jako zestaw reguł if-then. Jest to istotna zaleta w security, jeśli chodzi o zaufanie do modelu i weryfikację jego działania.

-   **Zalety:** Mogą odwzorowywać nieliniowe zależności i interakcje między cechami (każdy podział można postrzegać jako interakcję). Nie ma potrzeby skalowania cech ani stosowania one-hot encodingu dla zmiennych kategorycznych -- drzewa obsługują je natywnie. Szybkie wnioskowanie (predykcja polega jedynie na przejściu ścieżką w drzewie).

-   **Ograniczenia:** Są podatne na overfitting, jeśli nie są kontrolowane (głębokie drzewo może zapamiętać zbiór treningowy). Mogą być niestabilne -- niewielkie zmiany w danych mogą prowadzić do powstania innej struktury drzewa. Jako pojedyncze modele ich dokładność może nie dorównywać bardziej zaawansowanym metodom (ensembles, takim jak Random Forests, zazwyczaj osiągają lepsze wyniki dzięki redukcji wariancji).

-   **Wybór najlepszego podziału:**
- **Gini Impurity**: Mierzy niejednorodność węzła. Niższa wartość Gini impurity oznacza lepszy podział. Wzór:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Gdzie `p_i` to udział instancji należących do klasy `i`.

- **Entropy**: Mierzy niepewność w zbiorze danych. Niższa entropia oznacza lepszy podział. Wzór:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Gdzie `p_i` to udział instancji należących do klasy `i`.

- **Information Gain**: Redukcja entropii lub Gini impurity po podziale. Im większy information gain, tym lepszy podział. Oblicza się go następująco:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Ponadto drzewo zostaje zakończone, gdy:
- Wszystkie instancje w węźle należą do tej samej klasy. Może to prowadzić do overfittingu.
- Osiągnięta zostanie maksymalna (hardcoded) głębokość drzewa. Jest to sposób zapobiegania overfittingowi.
- Liczba instancji w węźle spadnie poniżej określonego progu. Jest to również sposób zapobiegania overfittingowi.
- Information gain wynikający z kolejnych podziałów spadnie poniżej określonego progu. Jest to również sposób zapobiegania overfittingowi.

<details>
<summary>Przykład -- Drzewo decyzyjne do wykrywania włamań:</summary>
Wytrenujemy drzewo decyzyjne na zbiorze danych NSL-KDD, aby klasyfikować połączenia sieciowe jako *normal* lub *attack*. NSL-KDD to ulepszona wersja klasycznego zbioru danych KDD Cup 1999, zawierająca cechy takie jak typ protokołu, usługa, czas trwania, liczba nieudanych logowań itp. oraz etykietę wskazującą typ ataku lub „normal”. Zmapujemy wszystkie typy ataków na klasę „anomaly” (klasyfikacja binarna: normal vs anomaly). Po treningu ocenimy działanie drzewa na zbiorze testowym.
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
W tym przykładzie drzewa decyzyjnego ograniczyliśmy głębokość drzewa do 10, aby uniknąć skrajnego overfittingu (parametr `max_depth=10`). Metryki pokazują, jak dobrze drzewo rozróżnia normalny ruch od ruchu będącego atakiem. Wysoki recall oznaczałby wykrywanie większości ataków (co jest ważne dla IDS), natomiast wysoki precision oznacza niewiele fałszywych alarmów. Drzewa decyzyjne często osiągają przyzwoitą dokładność na danych ustrukturyzowanych, ale pojedyncze drzewo może nie zapewniać najlepszej możliwej wydajności. Niemniej jednak *interpretowalność* modelu jest dużą zaletą -- możemy przeanalizować podziały w drzewie, aby zobaczyć na przykład, które cechy (np. `service`, `src_bytes` itd.) mają największy wpływ na oznaczenie połączenia jako złośliwego.

</details>

### Random Forests

Random Forest to metoda **uczenia zespołowego**, która bazuje na drzewach decyzyjnych w celu poprawy wydajności. Random Forest trenuje wiele drzew decyzyjnych (stąd określenie „forest”) i łączy ich wyniki, aby utworzyć końcową predykcję (w przypadku klasyfikacji zazwyczaj poprzez głosowanie większościowe). Dwie główne idee w Random Forest to **bagging** (bootstrap aggregating) oraz **losowość cech**:

-   **Bagging:** Każde drzewo jest trenowane na losowej próbie bootstrapowej danych treningowych (losowanie ze zwracaniem). Wprowadza to różnorodność między drzewami.

-   **Losowość cech:** Przy każdym podziale drzewa do podziału brany jest pod uwagę losowy podzbiór cech (zamiast wszystkich cech). Dodatkowo zmniejsza to korelację między drzewami.

Uśrednianie wyników wielu drzew pozwala Random Forest zmniejszyć wariancję, którą może wykazywać pojedyncze drzewo decyzyjne. Mówiąc prościej, pojedyncze drzewa mogą overfitować lub generować zaszumione wyniki, ale duża liczba różnorodnych drzew głosujących wspólnie wygładza te błędy. Rezultatem jest często model o **wyższej dokładności** i lepszej generalizacji niż w przypadku pojedynczego drzewa decyzyjnego. Ponadto Random Forest może dostarczać ocenę ważności cech (poprzez analizę średniego stopnia, w jakim każdy podział według cechy zmniejsza nieczystość).

Random Forest stał się **workhorse w cybersecurity** w zadaniach takich jak intrusion detection, klasyfikacja malware oraz wykrywanie spamu. Często działa dobrze od razu, przy minimalnym dostrajaniu, i może obsługiwać duże zbiory cech. Na przykład w intrusion detection Random Forest może przewyższać pojedyncze drzewo decyzyjne, wykrywając bardziej subtelne wzorce ataków przy mniejszej liczbie false positives. Badania wykazały, że Random Forest osiąga korzystne wyniki w porównaniu z innymi algorytmami podczas klasyfikowania ataków w zbiorach danych takich jak NSL-KDD i UNSW-NB15.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Key characteristics of Random Forests:**

-   **Type of Problem:** Przede wszystkim klasyfikacja (stosowany również do regresji). Bardzo dobrze nadaje się do wielowymiarowych danych ustrukturyzowanych, typowych dla security logs.

-   **Interpretability:** Niższa niż w przypadku pojedynczego drzewa decyzyjnego -- nie można łatwo zwizualizować ani wyjaśnić setek drzew jednocześnie. Wyniki dotyczące ważności cech dostarczają jednak pewnych informacji o tym, które atrybuty mają największy wpływ.

-   **Advantages:** Zazwyczaj wyższa dokładność niż w modelach opartych na pojedynczym drzewie dzięki efektowi zespołowemu. Odporność na overfitting -- nawet jeśli pojedyncze drzewa overfitują, zespół lepiej generalizuje. Obsługuje zarówno cechy numeryczne, jak i kategoryczne, a także w pewnym stopniu radzi sobie z brakującymi danymi. Jest również stosunkowo odporny na outliers.

-   **Limitations:** Rozmiar modelu może być duży (wiele drzew, z których każde może być głębokie). Predykcje są wolniejsze niż w przypadku pojedynczego drzewa (ponieważ trzeba agregować wyniki wielu drzew). Mniejsza interpretowalność -- choć wiadomo, które cechy są ważne, dokładna logika nie jest łatwa do prześledzenia tak jak w przypadku prostej reguły. Jeśli zbiór danych jest bardzo wysokowymiarowy i rzadki, trenowanie bardzo dużego forest może być wymagające obliczeniowo.

-   **Training Process:**
1. **Bootstrap Sampling**: Losowo próbkuj dane treningowe ze zwracaniem, aby utworzyć wiele podzbiorów (prób bootstrapowych).
2. **Tree Construction**: Dla każdej próby bootstrapowej zbuduj drzewo decyzyjne, używając losowego podzbioru cech przy każdym podziale. Wprowadza to różnorodność między drzewami.
3. **Aggregation**: W zadaniach klasyfikacyjnych końcowa predykcja jest tworzona poprzez głosowanie większościowe na podstawie predykcji wszystkich drzew. W zadaniach regresyjnych końcowa predykcja jest średnią predykcji wszystkich drzew.

<details>
<summary>Przykład -- Random Forest do Intrusion Detection (NSL-KDD):</summary>
Użyjemy tego samego zbioru danych NSL-KDD (z etykietami binarnymi: normalny ruch lub anomaly) i wytrenujemy klasyfikator Random Forest. Oczekujemy, że Random Forest osiągnie wyniki co najmniej tak dobre jak pojedyncze drzewo decyzyjne lub lepsze, ponieważ uśrednianie zespołowe zmniejsza wariancję. Ocenimy go za pomocą tych samych metryk.
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
Los losowy zazwyczaj osiąga dobre wyniki w tym zadaniu wykrywania intruzji. Możemy zaobserwować poprawę metryk, takich jak F1 lub AUC, w porównaniu z pojedynczym drzewem decyzyjnym, zwłaszcza w zakresie recall lub precision, zależnie od danych. Jest to zgodne ze stwierdzeniem, że *„Random Forest (RF) jest klasyfikatorem zespołowym i skutecznie klasyfikuje ataki w porównaniu z innymi tradycyjnymi klasyfikatorami.”*<sup>[[6]](#references)</sup> W kontekście security operations model random forest może bardziej niezawodnie wykrywać ataki, jednocześnie ograniczając liczbę fałszywych alarmów dzięki uśrednianiu wielu reguł decyzyjnych. Znaczenie cech obliczone przez forest może wskazać, które cechy sieciowe najlepiej sygnalizują ataki (np. określone usługi sieciowe lub nietypowe liczby pakietów).

</details>

### Support Vector Machines (SVM)

Support Vector Machines to zaawansowane modele supervised learning używane głównie do klasyfikacji (a także do regresji jako SVR). SVM próbuje znaleźć **optymalną hiperpłaszczyznę rozdzielającą**, która maksymalizuje margines między dwiema klasami. Tylko podzbiór punktów treningowych („support vectors” znajdujące się najbliżej granicy) określa położenie tej hiperpłaszczyzny. Maksymalizując margines (odległość między support vectors a hiperpłaszczyzną), SVM zwykle osiąga dobrą generalizację.<sup>[[8]](#references)</sup>

Kluczową cechą SVM jest możliwość używania **funkcji kernel** do obsługi nieliniowych zależności. Dane mogą być niejawnie przekształcane do wielowymiarowej przestrzeni cech, w której może istnieć liniowy separator. Popularne kernele obejmują wielomianowy, radial basis function (RBF) oraz sigmoid. Jeśli na przykład klasy ruchu sieciowego nie są liniowo separowalne w surowej przestrzeni cech, kernel RBF może odwzorować je w przestrzeni o wyższym wymiarze, w której SVM znajdzie liniowy podział (odpowiadający nieliniowej granicy w przestrzeni oryginalnej). Elastyczność wyboru kernela pozwala SVM rozwiązywać różnorodne problemy.

SVM są znane z dobrego działania w sytuacjach obejmujących wielowymiarowe przestrzenie cech (takie jak dane tekstowe lub sekwencje opcode malware) oraz wtedy, gdy liczba cech jest duża w stosunku do liczby próbek. Były popularne w wielu wczesnych zastosowaniach cybersecurity, takich jak klasyfikacja malware i wykrywanie intruzji oparte na anomaliach w latach 2000., często osiągając wysoką accuracy.

SVM nie skalują się jednak łatwo do bardzo dużych zbiorów danych (złożoność treningu rośnie ponadliniowo wraz z liczbą próbek, a użycie pamięci może być wysokie, ponieważ konieczne może być przechowywanie wielu support vectors). W praktyce, w zadaniach takich jak wykrywanie intruzji w sieci obejmujących miliony rekordów, SVM może działać zbyt wolno bez starannego subsamplingu lub użycia metod przybliżonych.

#### **Kluczowe cechy SVM:**

-   **Typ problemu:** Klasyfikacja (binarna lub multiclass za pomocą one-vs-one/one-vs-rest) oraz warianty regresji. Często używane w klasyfikacji binarnej z wyraźnym rozdzieleniem marginesem.

-   **Interpretowalność:** Średnia -- SVM nie są tak interpretowalne jak drzewa decyzyjne lub regresja logistyczna. Chociaż można zidentyfikować punkty danych będące support vectors i uzyskać pewne pojęcie o tym, które cechy mogą mieć wpływ (na podstawie wag w przypadku linear kernel), w praktyce SVM (zwłaszcza z nieliniowymi kernelami) traktuje się jako klasyfikatory black-box.

-   **Zalety:** Skuteczne w wielowymiarowych przestrzeniach; mogą modelować złożone granice decyzyjne dzięki kernel trick; odporne na overfitting, jeśli margines jest maksymalizowany (szczególnie przy właściwie dobranym parametrze regularyzacji C); dobrze działają nawet wtedy, gdy klasy nie są rozdzielone dużą odległością (znajdują najlepszy kompromis między granicami).

-   **Ograniczenia:** **Wymagające obliczeniowo** w przypadku dużych zbiorów danych (zarówno trening, jak i predykcja słabo skalują się wraz ze wzrostem danych). Wymagają starannego dostrajania parametrów kernela i regularyzacji (C, typ kernela, gamma dla RBF itd.). Nie dostarczają bezpośrednio wyników probabilistycznych (choć można użyć Platt scaling, aby uzyskać prawdopodobieństwa). SVM mogą być również wrażliwe na wybór parametrów kernela --- niewłaściwy wybór może prowadzić do underfittingu lub overfittingu.

*Zastosowania w cybersecurity:* SVM były używane do **wykrywania malware** (np. klasyfikowania plików na podstawie wyekstrahowanych cech lub sekwencji opcode), **wykrywania anomalii w sieci** (klasyfikowania ruchu jako normalnego lub złośliwego) oraz **wykrywania phishingu** (z wykorzystaniem cech URL). Na przykład SVM może przyjąć cechy wiadomości e-mail (liczby określonych słów kluczowych, wyniki reputacji nadawcy itd.) i sklasyfikować ją jako phishingową lub legalną. SVM stosowano również do **wykrywania intruzji** na zbiorach cech takich jak KDD, często osiągając wysoką accuracy kosztem obliczeń.

<details>
<summary>Przykład -- SVM do klasyfikacji malware:</summary>
Ponownie użyjemy zbioru danych dotyczącego phishing websites, tym razem z SVM. Ponieważ SVM mogą działać wolno, w razie potrzeby użyjemy podzbioru danych do treningu (zbiór zawiera około 11 tys. instancji, z którymi SVM powinien sobie rozsądnie poradzić). Użyjemy kernela RBF, który jest częstym wyborem dla danych nieliniowych, oraz włączymy estymację prawdopodobieństwa, aby obliczyć ROC AUC.
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
Model SVM zwróci metryki, które możemy porównać z wynikami Logistic Regression dla tego samego zadania. Możemy odkryć, że SVM osiąga wysoką accuracy i AUC, jeśli dane są dobrze rozdzielone przez cechy. Z drugiej strony, jeśli dataset zawiera dużo szumu lub nakładające się klasy, SVM może nie przewyższać znacząco Logistic Regression. W praktyce SVM może zapewnić poprawę, gdy między cechami a klasą występują złożone, nieliniowe zależności -- kernel RBF potrafi odwzorować zakrzywione granice decyzyjne, których Logistic Regression nie byłby w stanie uchwycić. Podobnie jak w przypadku wszystkich modeli, konieczne jest staranne dostrojenie parametru `C` (regularyzacja) oraz parametrów kernela (takich jak `gamma` dla RBF), aby zachować równowagę między bias a wariancją.

</details>

#### Różnica między Logistic Regression a SVM

| Aspekt | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Funkcja celu** | Minimalizuje **log-loss** (cross-entropy). | Maksymalizuje **margin**, jednocześnie minimalizując **hinge-loss**. |
| **Granica decyzyjna** | Znajduje **najlepiej dopasowaną hiperpłaszczyznę**, która modeluje _P(y\|x)_. | Znajduje **hiperpłaszczyznę o maksymalnym marginie** (największej odległości od najbliższych punktów). |
| **Wynik** | **Probabilistyczny** -- zwraca skalibrowane prawdopodobieństwa klas za pomocą σ(w·x + b). | **Deterministyczny** -- zwraca etykiety klas; prawdopodobieństwa wymagają dodatkowego przetwarzania (np. Platt scaling). |
| **Regularyzacja** | L2 (domyślna) lub L1, bezpośrednio równoważy underfitting i overfitting. | Parametr C stanowi kompromis między szerokością marginesu a błędnymi klasyfikacjami; parametry kernela zwiększają złożoność. |
| **Kernele / Nieliniowość** | Natywna forma jest **liniowa**; nieliniowość można dodać poprzez feature engineering. | Wbudowany **kernel trick** (RBF, poly itd.) pozwala modelować złożone granice w przestrzeni o wysokim wymiarze. |
| **Skalowalność** | Rozwiązuje wypukłą optymalizację w **O(nd)**; dobrze obsługuje bardzo duże n. | Trenowanie może wymagać **O(n²–n³)** pamięci/czasu bez wyspecjalizowanych solverów; gorzej nadaje się do ogromnych wartości n. |
| **Interpretowalność** | **Wysoka** -- wagi pokazują wpływ cech; iloraz szans jest intuicyjny. | **Niska** dla nieliniowych kerneli; support vectors są rzadkie, ale trudne do wyjaśnienia. |
| **Wrażliwość na wartości odstające** | Wykorzystuje gładką funkcję log-loss, więc jest mniej wrażliwy. | **Hinge-loss** z hard marginem może być **wrażliwy**; soft margin (C) łagodzi ten problem. |
| **Typowe zastosowania** | Scoring kredytowy, ryzyko medyczne, testy A/B -- tam, gdzie ważne są **prawdopodobieństwa i wyjaśnialność**. | Klasyfikacja obrazów/tekstu, bioinformatyka -- tam, gdzie znaczenie mają **złożone granice** i **dane o wysokim wymiarze**. |

* **Jeśli potrzebujesz skalibrowanych prawdopodobieństw, interpretowalności lub pracy na ogromnych datasetach -- wybierz Logistic Regression.**
* **Jeśli potrzebujesz elastycznego modelu, który potrafi uchwycić nieliniowe zależności bez ręcznego feature engineering -- wybierz SVM (z kernelami).**
* Oba modele optymalizują wypukłe funkcje celu, więc **zagwarantowane są minima globalne**, ale kernele SVM dodają hiperparametry i zwiększają koszt obliczeniowy.

### Naive Bayes

Naive Bayes to rodzina **klasyfikatorów probabilistycznych** opartych na zastosowaniu twierdzenia Bayesa wraz z silnym założeniem niezależności między cechami. Pomimo tego „naiwnego” założenia Naive Bayes często działa zaskakująco dobrze w określonych zastosowaniach, szczególnie tych obejmujących tekst lub dane kategoryczne, takich jak wykrywanie spamu.<sup>[[9]](#references)</sup>


#### Twierdzenie Bayesa

Twierdzenie Bayesa stanowi podstawę klasyfikatorów Naive Bayes. Łączy prawdopodobieństwa warunkowe i brzegowe zdarzeń losowych. Wzór wygląda następująco:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Gdzie:
- `P(A|B)` to prawdopodobieństwo a posteriori klasy `A` przy danej cesze `B`.
- `P(B|A)` to wiarygodność cechy `B` przy danej klasie `A`.
- `P(A)` to prawdopodobieństwo a priori klasy `A`.
- `P(B)` to prawdopodobieństwo a priori cechy `B`.

Na przykład, jeśli chcemy sklasyfikować, czy tekst został napisany przez dziecko czy osobę dorosłą, możemy użyć słów w tekście jako cech. Na podstawie początkowych danych classifier Naive Bayes wcześniej obliczy prawdopodobieństwa wystąpienia każdego słowa w każdej potencjalnej klasie (dziecko lub osoba dorosła). Po otrzymaniu nowego tekstu obliczy prawdopodobieństwo każdej potencjalnej klasy na podstawie słów w tekście i wybierze klasę o najwyższym prawdopodobieństwie.

Jak widać na tym przykładzie, classifier Naive Bayes jest bardzo prosty i szybki, ale zakłada, że cechy są niezależne, co nie zawsze ma miejsce w danych ze świata rzeczywistego.


#### Typy classifierów Naive Bayes

Istnieje kilka typów classifierów Naive Bayes, zależnie od rodzaju danych i rozkładu cech:
- **Gaussian Naive Bayes**: Zakłada, że cechy mają rozkład Gaussa (normalny). Nadaje się do danych ciągłych.
- **Multinomial Naive Bayes**: Zakłada, że cechy mają rozkład wielomianowy. Nadaje się do danych dyskretnych, takich jak liczba wystąpień słów w klasyfikacji tekstu.
- **Bernoulli Naive Bayes**: Zakłada, że cechy są binarne (0 lub 1). Nadaje się do danych binarnych, takich jak obecność lub brak słów w klasyfikacji tekstu.
- **Categorical Naive Bayes**: Zakłada, że cechy są zmiennymi kategorycznymi. Nadaje się do danych kategorycznych, takich jak klasyfikowanie owoców na podstawie ich koloru i kształtu.


#### **Najważniejsze cechy Naive Bayes:**

-   **Typ problemu:** Klasyfikacja (binarna lub wieloklasowa). Często używany do zadań klasyfikacji tekstu w cybersecurity (spam, phishing itp.).

-   **Interpretowalność:** Średnia -- nie jest tak bezpośrednio interpretowalny jak drzewo decyzyjne, ale można analizować wyuczone prawdopodobieństwa (np. które słowa najczęściej występują w wiadomościach spamowych w porównaniu z wiadomościami ham). Forma modelu (prawdopodobieństwa każdej cechy przy danej klasie) może być w razie potrzeby zrozumiana.

-   **Zalety:** **Bardzo szybkie** trenowanie i predykcja, nawet dla dużych zbiorów danych (liniowa względem liczby instancji * liczby cech). Wymaga stosunkowo niewielkiej ilości danych do wiarygodnego oszacowania prawdopodobieństw, szczególnie przy użyciu odpowiedniego wygładzania. Często jest zaskakująco dokładny jako baseline, zwłaszcza gdy cechy niezależnie dostarczają informacji o klasie. Dobrze działa z danymi o wysokim wymiarze (np. tysiące cech pochodzących z tekstu). Nie wymaga złożonego dostrajania poza ustawieniem parametru wygładzania.

-   **Ograniczenia:** Założenie niezależności może ograniczać dokładność, jeśli cechy są silnie skorelowane. Na przykład w danych sieciowych cechy takie jak `src_bytes` i `dst_bytes` mogą być skorelowane; Naive Bayes nie uchwyci tej zależności. Gdy rozmiar danych staje się bardzo duży, bardziej ekspresywne modele (takie jak ensembles lub neural nets) mogą przewyższyć NB, ucząc się zależności między cechami. Ponadto jeśli do identyfikacji ataku potrzebna jest określona kombinacja cech (a nie tylko niezależny wkład poszczególnych cech), NB będzie mieć trudności.

> [!TIP]
> *Przypadki użycia w cybersecurity:* Klasycznym zastosowaniem jest **wykrywanie spamu** -- Naive Bayes stanowił podstawę wczesnych filtrów antyspamowych, wykorzystujących częstotliwość określonych tokenów (słów, fraz, adresów IP) do obliczania prawdopodobieństwa, że wiadomość e-mail jest spamem. Jest również używany do **wykrywania phishingowych wiadomości e-mail** i **klasyfikacji URL**, gdzie obecność określonych słów kluczowych lub cech (takich jak "login.php" w URL albo `@` w ścieżce URL) wpływa na prawdopodobieństwo phishingu. W analizie malware można wyobrazić sobie classifier Naive Bayes wykorzystujący obecność określonych wywołań API lub uprawnień w oprogramowaniu do przewidywania, czy jest ono malware. Chociaż bardziej zaawansowane algorytmy często zapewniają lepsze wyniki, Naive Bayes pozostaje dobrym baseline'em ze względu na szybkość i prostotę.

<details>
<summary>Przykład -- Naive Bayes do wykrywania phishingu:</summary>
Aby zademonstrować działanie Naive Bayes, użyjemy Gaussian Naive Bayes na zbiorze danych o włamaniach NSL-KDD (z etykietami binarnymi). Gaussian NB potraktuje każdą cechę jako cechę mającą rozkład normalny w obrębie każdej klasy. Jest to przybliżony wybór, ponieważ wiele cech sieciowych ma charakter dyskretny lub cechuje się silną skośnością, ale pokazuje, jak zastosować NB do danych cech ciągłych. Moglibyśmy również wybrać Bernoulli NB dla zbioru danych z cechami binarnymi (takiego jak zestaw wyzwolonych alertów), ale dla zachowania ciągłości pozostaniemy tutaj przy NSL-KDD.
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
Ten kod szkoli classifier Naive Bayes do wykrywania ataków. Naive Bayes obliczy wartości takie jak `P(service=http | Attack)` i `P(Service=http | Normal)` na podstawie danych treningowych, zakładając niezależność cech. Następnie użyje tych prawdopodobieństw do klasyfikowania nowych połączeń jako normalnych lub będących atakiem, na podstawie zaobserwowanych cech. Wydajność NB na NSL-KDD może nie być tak wysoka jak w przypadku bardziej zaawansowanych modeli (ponieważ założenie o niezależności cech jest naruszone), ale często jest przyzwoita, a dodatkową zaletą jest wyjątkowo duża szybkość. W scenariuszach takich jak filtrowanie wiadomości e-mail w czasie rzeczywistym lub wstępna triage adresów URL model Naive Bayes może szybko oznaczać przypadki ewidentnie złośliwe przy niskim użyciu zasobów.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors to jeden z najprostszych algorytmów machine learning. Jest to **nieparametryczna, oparta na instancjach** metoda, która dokonuje predykcji na podstawie podobieństwa do przykładów w zbiorze treningowym. Idea klasyfikacji jest następująca: aby sklasyfikować nowy punkt danych, należy znaleźć **k** najbliższych punktów w danych treningowych (jego „najbliższych sąsiadów”), a następnie przypisać większościową klasę spośród tych sąsiadów. „Bliskość” definiuje się za pomocą metryki odległości, zwykle odległości euklidesowej dla danych numerycznych (w przypadku różnych typów cech lub problemów można używać innych odległości).<sup>[[10]](#references)</sup>

K-NN nie wymaga *jawnego treningu* -- faza „treningu” polega wyłącznie na przechowywaniu zbioru danych. Cała praca odbywa się podczas zapytania (predykcji): algorytm musi obliczyć odległości od punktu zapytania do wszystkich punktów treningowych, aby znaleźć najbliższe z nich. Oznacza to, że czas predykcji jest **liniowy względem liczby próbek treningowych**, co może być kosztowne w przypadku dużych zbiorów danych. Z tego powodu k-NN najlepiej sprawdza się w przypadku mniejszych zbiorów danych lub w scenariuszach, w których można poświęcić pamięć i szybkość na rzecz prostoty.

Pomimo swojej prostoty k-NN może modelować bardzo złożone granice decyzyjne (ponieważ granica decyzyjna może w praktyce mieć dowolny kształt wynikający z rozkładu przykładów). Metoda ta zwykle dobrze działa, gdy granica decyzyjna jest bardzo nieregularna i dostępna jest duża ilość danych -- zasadniczo pozwalając, aby dane „mówiły same za siebie”. Jednak w przestrzeniach o dużej liczbie wymiarów metryki odległości mogą stawać się mniej użyteczne (przekleństwo wymiarowości), a metoda może mieć problemy, chyba że dostępna jest ogromna liczba próbek.

*Przypadki użycia w cybersecurity:* k-NN stosowano do wykrywania anomalii -- na przykład system intrusion detection może oznaczyć zdarzenie sieciowe jako złośliwe, jeśli większość jego najbliższych sąsiadów (wcześniejszych zdarzeń) była złośliwa. Jeśli normalny ruch tworzy klastry, a ataki są wartościami odstającymi, podejście K-NN (z k=1 lub małym k) działa zasadniczo jako **wykrywanie anomalii na podstawie najbliższego sąsiada**. K-NN stosowano również do klasyfikowania rodzin malware na podstawie binarnych wektorów cech: nowy plik może zostać sklasyfikowany jako należący do określonej rodziny malware, jeśli jest bardzo podobny (w przestrzeni cech) do znanych instancji tej rodziny. W praktyce k-NN nie jest tak powszechny jak bardziej skalowalne algorytmy, ale jest koncepcyjnie prosty i czasami używa się go jako baseline'u lub w problemach na małą skalę.

#### **Najważniejsze cechy k-NN:**

-   **Typ problemu:** Klasyfikacja (istnieją również warianty regresyjne). Jest to metoda *lazy learning* -- nie dochodzi do jawnego dopasowania modelu.

-   **Interpretowalność:** Niska do średniej -- nie istnieje globalny model ani zwięzłe wyjaśnienie, ale wyniki można interpretować, analizując najbliższych sąsiadów, którzy wpłynęli na decyzję (np. „ten przepływ sieciowy został sklasyfikowany jako złośliwy, ponieważ jest podobny do tych 3 znanych złośliwych przepływów”). Wyjaśnienia mogą więc opierać się na przykładach.

-   **Zalety:** Bardzo prosty we wdrożeniu i zrozumieniu. Nie wymaga żadnych założeń dotyczących rozkładu danych (jest nieparametryczny). Może naturalnie obsługiwać problemy wieloklasowe. Jest **adaptacyjny** w tym sensie, że granice decyzyjne mogą być bardzo złożone i kształtowane przez rozkład danych.

-   **Ograniczenia:** Predykcja może być powolna w przypadku dużych zbiorów danych (konieczne jest obliczenie wielu odległości). Wymaga dużej ilości pamięci -- przechowuje wszystkie dane treningowe. Wydajność spada w przestrzeniach cech o dużej liczbie wymiarów, ponieważ wszystkie punkty stają się niemal jednakowo odległe (przez co pojęcie „najbliższego” ma mniejsze znaczenie). Należy odpowiednio wybrać *k* (liczbę sąsiadów) -- zbyt małe k może powodować szum, a zbyt duże k może uwzględniać nieistotne punkty z innych klas. Cechy powinny być również odpowiednio skalowane, ponieważ obliczenia odległości są wrażliwe na skalę.

<details>
<summary>Przykład -- k-NN do wykrywania phishingu:</summary>

Ponownie użyjemy NSL-KDD (klasyfikacja binarna). Ponieważ k-NN jest kosztowny obliczeniowo, w tej demonstracji użyjemy podzbioru danych treningowych, aby zachować akceptowalny czas działania. Wybierzemy na przykład 20 000 próbek treningowych z pełnego zbioru liczącego 125 tys. próbek i użyjemy 5 sąsiadów, czyli k=5. Po treningu (który w rzeczywistości polega wyłącznie na przechowywaniu danych) przeprowadzimy ewaluację na zbiorze testowym. Przeskalujemy również cechy na potrzeby obliczania odległości, aby żadna pojedyncza cecha nie dominowała z powodu skali.
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
Model k-NN sklasyfikuje połączenie, analizując 5 najbliższych połączeń w podzbiorze zbioru treningowego. Jeśli na przykład 4 z tych sąsiadów to ataki (anomalie), a 1 jest normalny, nowe połączenie zostanie sklasyfikowane jako atak. Wydajność może być zadowalająca, choć często nie tak wysoka jak w przypadku dobrze dostrojonego Random Forest lub SVM na tych samych danych. k-NN może jednak czasami sprawdzać się wyjątkowo dobrze, gdy rozkłady klas są bardzo nieregularne i złożone — faktycznie wykorzystując wyszukiwanie oparte na pamięci. W cybersecurity k-NN (z k=1 lub małą wartością k) może służyć do wykrywania znanych wzorców ataków na podstawie przykładów albo jako komponent bardziej złożonych systemów (np. do klastrowania, a następnie klasyfikowania na podstawie przynależności do klastra).
</details>

### Gradient Boosting Machines (np. XGBoost)

Gradient Boosting Machines należą do najpotężniejszych algorytmów dla danych strukturalnych. **Gradient boosting** odnosi się do techniki budowania ensemble słabych modeli (często drzew decyzyjnych) w sposób sekwencyjny, gdzie każdy nowy model koryguje błędy poprzedniego ensemble. W przeciwieństwie do baggingu (Random Forest), który buduje drzewa równolegle i uśrednia ich wyniki, boosting buduje drzewa *jedno po drugim*, przy czym każde z nich skupia się bardziej na instancjach, które poprzednie drzewa sklasyfikowały niepoprawnie.<sup>[[11]](#references)</sup>

Najpopularniejszymi implementacjami w ostatnich latach są **XGBoost**, **LightGBM** i **CatBoost** — wszystkie są bibliotekami gradient boosting decision tree (GBDT). Odniosły one ogromny sukces w konkursach machine learning i praktycznych zastosowaniach, często **osiągając najlepszą dostępną wydajność na zbiorach danych tabelarycznych**. W cybersecurity badacze i praktycy wykorzystują drzewa ze wzmocnieniem gradientowym do zadań takich jak **wykrywanie malware** (z użyciem cech wyodrębnionych z plików lub zachowania podczas działania) oraz **wykrywanie network intrusion**. Przykładowo model gradient boosting może połączyć wiele słabych reguł (drzew), takich jak „jeśli występuje wiele pakietów SYN i nietypowy port -> prawdopodobny scan”, w silny detektor złożony, który uwzględnia wiele subtelnych wzorców.

Dlaczego boosted trees są tak skuteczne? Każde drzewo w sekwencji jest trenowane na *resztowych błędach* (gradientach) predykcji bieżącego ensemble. Dzięki temu model stopniowo **„wzmacnia”** obszary, w których jest słaby. Wykorzystanie drzew decyzyjnych jako modeli bazowych oznacza, że model końcowy może uchwycić złożone interakcje i nieliniowe zależności. Boosting ma również wbudowaną formę regularizacji: dzięki dodawaniu wielu małych drzew (i użyciu learning rate do skalowania ich udziału) często dobrze generalizuje bez znacznego overfittingu, pod warunkiem dobrania odpowiednich parametrów.

#### **Najważniejsze cechy Gradient Boosting:**

-   **Typ problemu:** Przede wszystkim klasyfikacja i regresja. W security zwykle stosuje się klasyfikację (np. binarne sklasyfikowanie połączenia lub pliku). Obsługuje problemy binarne, wieloklasowe (z odpowiednią funkcją straty), a nawet problemy rankingowe.

-   **Interpretowalność:** Niska do średniej. Chociaż pojedyncze boosted tree jest małe, pełny model może zawierać setki drzew, przez co jako całość nie jest interpretowalny dla człowieka. Jednak podobnie jak Random Forest może dostarczać wyniki ważności cech, a narzędzia takie jak SHAP (SHapley Additive exPlanations) mogą do pewnego stopnia służyć do interpretowania poszczególnych predykcji.

-   **Zalety:** Często **najlepiej działający** algorytm dla danych strukturalnych/tabelarycznych. Może wykrywać złożone wzorce i interakcje. Oferuje wiele parametrów dostrajania (liczba drzew, głębokość drzew, learning rate, terminy regularizacji), które pozwalają dopasować złożoność modelu i zapobiegać overfittingowi. Nowoczesne implementacje są zoptymalizowane pod kątem szybkości (np. XGBoost wykorzystuje informacje o gradientzie drugiego rzędu oraz wydajne struktury danych). Zwykle lepiej radzi sobie z niezbalansowanymi danymi po połączeniu z odpowiednimi funkcjami straty lub dostosowaniu wag próbek.

-   **Ograniczenia:** Jest trudniejszy do dostrojenia niż prostsze modele; trenowanie może być powolne, jeśli drzewa są głębokie lub ich liczba jest duża (choć zazwyczaj nadal jest szybsze niż trenowanie porównywalnej deep neural network na tych samych danych). Model może ulec overfittingowi, jeśli nie zostanie odpowiednio dostrojony (np. zbyt wiele głębokich drzew przy niewystarczającej regularizacji). Ze względu na dużą liczbę hyperparameters skuteczne wykorzystanie gradient boosting może wymagać większej wiedzy lub eksperymentowania. Ponadto, podobnie jak metody oparte na drzewach, nie obsługuje natywnie bardzo rzadkich danych o wysokim wymiarze tak wydajnie jak modele liniowe lub Naive Bayes (choć nadal można go stosować, np. w klasyfikacji tekstu, ale bez feature engineering może nie być pierwszym wyborem).

> [!TIP]
> *Zastosowania w cybersecurity:* Niemal wszędzie tam, gdzie można użyć drzewa decyzyjnego lub random forest, model gradient boosting może osiągnąć lepszą accuracy. Przykładowo w konkursach dotyczących **wykrywania malware przez Microsoft** powszechnie wykorzystywano XGBoost na cechach przygotowanych z plików binarnych. Badania nad **network intrusion detection** często wskazują najlepsze wyniki dla GBDT (np. XGBoost na zbiorach danych CIC-IDS2017 lub UNSW-NB15). Modele te mogą przyjmować szeroki zakres cech (typy protokołów, częstotliwość określonych zdarzeń, cechy statystyczne ruchu itd.) i łączyć je w celu wykrywania zagrożeń. W wykrywaniu phishingu gradient boosting może łączyć cechy leksykalne URL-i, cechy reputacji domen oraz cechy zawartości stron, aby osiągnąć bardzo wysoką accuracy. Podejście ensemble pomaga uwzględnić wiele przypadków brzegowych i subtelności w danych.

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
Model Gradient Boosting prawdopodobnie osiągnie bardzo wysoką accuracy i AUC na tym phishing dataset (często po odpowiednim dostrojeniu takie modele mogą przekraczać 95% accuracy na tego typu danych, co pokazuje literatura. Demonstruje to, dlaczego GBDT są uznawane za *„state of the art model for tabular dataset”* -- często przewyższają prostsze algorytmy, wychwytując złożone wzorce.<sup>[[11]](#references)</sup> W kontekście cyberbezpieczeństwa może to oznaczać wykrywanie większej liczby phishing sites lub ataków przy mniejszej liczbie przeoczeń. Oczywiście należy zachować ostrożność w kwestii overfittingu -- podczas tworzenia takiego modelu do wdrożenia zazwyczaj stosowalibyśmy techniki takie jak cross-validation i monitorowalibyśmy wydajność na validation set.

</details>

### Łączenie modeli: Ensemble Learning i Stacking

Ensemble learning to strategia **łączenia wielu modeli** w celu poprawy ogólnej wydajności. Widzieliśmy już konkretne metody ensemble: Random Forest (ensemble drzew za pomocą baggingu) oraz Gradient Boosting (ensemble drzew za pomocą sekwencyjnego boostingu). Ensembles można jednak tworzyć również na inne sposoby, takie jak **voting ensembles** lub **stacked generalization (stacking)**. Główna idea polega na tym, że różne modele mogą wychwytywać różne wzorce lub mieć różne słabości; łącząc je, możemy **kompensować błędy każdego modelu mocnymi stronami innego modelu**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** W prostym voting classifier trenujemy wiele zróżnicowanych modeli (na przykład regresję logistyczną, drzewo decyzyjne i SVM), a następnie pozwalamy im głosować nad końcową predykcją (większość głosów w przypadku klasyfikacji). Jeśli przypiszemy głosom wagi (np. większą wagę dokładniejszym modelom), otrzymamy weighted voting scheme. Zwykle poprawia to wydajność, gdy poszczególne modele są odpowiednio dobre i niezależne -- ensemble zmniejsza ryzyko błędu pojedynczego modelu, ponieważ pozostałe mogą go skorygować. To tak, jak posiadanie panelu ekspertów zamiast pojedynczej opinii.

-   **Stacking (Stacked Ensemble):** Stacking idzie o krok dalej. Zamiast prostego głosowania trenuje **meta-model**, aby **nauczył się, jak najlepiej łączyć predykcje** modeli bazowych. Na przykład trenujesz 3 różne klasyfikatory (base learners), a następnie przekazujesz ich wyniki (lub prawdopodobieństwa) jako features do meta-classifier (często prostego modelu, takiego jak regresja logistyczna), który uczy się optymalnego sposobu ich łączenia. Meta-model jest trenowany na validation set lub za pomocą cross-validation, aby uniknąć overfittingu. Stacking często może przewyższać proste voting, ponieważ uczy się *którym modelom bardziej ufać w określonych sytuacjach*. W cyberbezpieczeństwie jeden model może lepiej wykrywać network scans, podczas gdy inny lepiej wykrywa malware beaconing; model stacking może nauczyć się odpowiednio polegać na każdym z nich.

Ensembles, niezależnie od tego, czy wykorzystują voting, czy stacking, zwykle **zwiększają accuracy** i odporność. Wadą jest większa złożoność oraz czasami mniejsza interpretowalność (choć niektóre podejścia ensemble, takie jak uśrednianie drzew decyzyjnych, nadal mogą dostarczać pewnych informacji, np. feature importance). W praktyce, jeśli ograniczenia operacyjne na to pozwalają, użycie ensemble może prowadzić do wyższych detection rates. Wiele zwycięskich rozwiązań w wyzwaniach związanych z cyberbezpieczeństwem (oraz ogólnie w konkursach Kaggle) wykorzystuje techniki ensemble, aby wycisnąć ostatnie ułamki wydajności.

<details>
<summary>Przykład -- Voting Ensemble do wykrywania phishingu:</summary>
Aby zilustrować model stacking, połączmy kilka modeli, które omówiliśmy na phishing dataset. Użyjemy regresji logistycznej, drzewa decyzyjnego i k-NN jako base learners, a Random Forest jako meta-learnera do agregowania ich predykcji. Meta-learner będzie trenowany na wynikach base learners (z użyciem cross-validation na training set). Oczekujemy, że model stacked osiągnie wydajność porównywalną z poszczególnymi modelami lub nieco od nich lepszą.
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
Stackowany ensemble korzysta z uzupełniających się mocnych stron modeli bazowych. Na przykład regresja logistyczna może obsługiwać liniowe aspekty danych, drzewo decyzyjne może wychwytywać określone interakcje przypominające reguły, a k-NN może sprawdzać się w lokalnych sąsiedztwach przestrzeni cech. Meta-model (w tym przypadku random forest) może nauczyć się, jak ważyć te dane wejściowe. Uzyskane metryki często pokazują poprawę (nawet niewielką) w porównaniu z metrykami dowolnego pojedynczego modelu. W naszym przykładzie phishingu, jeśli sam model logistyczny miałby F1 na poziomie powiedzmy 0.95, a drzewo 0.94, stack mógłby osiągnąć 0.96, wykorzystując obszary, w których poszczególne modele popełniają błędy.

Metody ensemble, takie jak ta, ilustrują zasadę, że *„łączenie wielu modeli zazwyczaj prowadzi do lepszej generalizacji”*.<sup>[[12]](#references)</sup> W cyberbezpieczeństwie można to wdrożyć, wykorzystując wiele silników detekcji (jeden może być oparty na regułach, drugi na machine learning, a trzeci na wykrywaniu anomalii), a następnie warstwę agregującą ich alerty -- skutecznie tworzącą formę ensemble -- aby podjąć ostateczną decyzję z większą pewnością. Podczas wdrażania takich systemów należy uwzględnić dodatkową złożoność i upewnić się, że ensemble nie stanie się zbyt trudny w zarządzaniu lub wyjaśnianiu. Jednak z punktu widzenia dokładności ensembles i stacking są potężnymi narzędziami poprawiającymi wydajność modeli.

</details>

## Referencje

- [1] [AI and Machine Learning in Cybersecurity - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Linear Regression, Explained - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistic Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - "Phishing Attacks and Websites Classification Using Machine Learning and Multiple Datasets (A Comparative Analysis)"](https://arxiv.org/pdf/2101.02552)
- [5] [Decision Tree - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - "Denial of Services Attack Detection using Random Forest Classifier with Information Gain"](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - "Performance analysis of machine learning models for intrusion detection system using Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique"](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [What is a Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive Bayes spam filtering - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [What is k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT Demystified: How LightGBM, XGBoost and CatBoost Work - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Boosting Model Performance by Combining Strengths - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [How Deep Learning Enhances Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)

{{#include ../banners/hacktricks-training.md}}
