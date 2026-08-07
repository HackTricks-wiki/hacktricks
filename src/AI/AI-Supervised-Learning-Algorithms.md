# Algorithmen des Supervised Learning

{{#include ../banners/hacktricks-training.md}}

## Grundlegende Informationen

Supervised Learning verwendet gelabelte Daten, um Modelle zu trainieren, die Vorhersagen für neue, bisher unbekannte Eingaben treffen können. In der Cybersicherheit wird Supervised Machine Learning häufig für Aufgaben wie Intrusion Detection (Klassifizierung von Netzwerkverkehr als *normal* oder *Angriff*), Malware Detection (Unterscheidung zwischen schädlicher und gutartiger Software), Phishing Detection (Erkennung betrügerischer Websites oder E-Mails) und Spam Filtering eingesetzt, neben vielen anderen Anwendungsfällen.<sup>[[1]](#references)</sup> Jeder Algorithmus hat seine Stärken und eignet sich für unterschiedliche Problemtypen (Klassifikation oder Regression). Im Folgenden betrachten wir wichtige Algorithmen des Supervised Learning, erklären ihre Funktionsweise und demonstrieren ihre Verwendung mit realen Cybersecurity-Datasets. Außerdem besprechen wir, wie die Kombination von Modellen (Ensemble Learning) häufig die Vorhersageleistung verbessern kann.

## Algorithmen

-   **Linear Regression:** Ein grundlegender Regressionsalgorithmus zur Vorhersage numerischer Ergebnisse durch Anpassung einer linearen Gleichung an Daten.

-   **Logistic Regression:** Ein Klassifikationsalgorithmus (trotz seines Namens), der eine logistische Funktion verwendet, um die Wahrscheinlichkeit eines binären Ergebnisses zu modellieren.

-   **Decision Trees:** Baumstrukturierte Modelle, die Daten anhand von Features aufteilen, um Vorhersagen zu treffen; sie werden häufig wegen ihrer Interpretierbarkeit eingesetzt.

-   **Random Forests:** Ein Ensemble aus Decision Trees (mittels Bagging), das die Genauigkeit verbessert und Overfitting reduziert.

-   **Support Vector Machines (SVM):** Classifier mit maximalem Rand, die die optimale trennende Hyperebene finden; für nichtlineare Daten können Kernel verwendet werden.

-   **Naive Bayes:** Ein probabilistischer Classifier, der auf dem Satz von Bayes und der Annahme unabhängiger Features basiert und bekannt für seine Verwendung beim Spam Filtering ist.

-   **k-Nearest Neighbors (k-NN):** Ein einfacher „instanzbasierter“ Classifier, der einer Stichprobe anhand der Mehrheitsklasse ihrer nächsten Nachbarn ein Label zuweist.

-   **Gradient Boosting Machines:** Ensemble-Modelle (z. B. XGBoost, LightGBM), die durch das sequenzielle Hinzufügen schwächerer Learner (typischerweise Decision Trees) einen starken Prädiktor aufbauen.

Jeder Abschnitt weiter unten enthält eine verbesserte Beschreibung des Algorithmus sowie ein **Python code example**, das Bibliotheken wie `pandas` und `scikit-learn` (und `PyTorch` für das Beispiel mit dem neuronalen Netzwerk) verwendet. Die Beispiele nutzen öffentlich verfügbare Cybersecurity-Datasets (wie NSL-KDD für Intrusion Detection und ein Phishing Websites Dataset) und folgen einer einheitlichen Struktur:

1.  **Dataset laden** (falls verfügbar per URL herunterladen).

2.  **Daten vorverarbeiten** (z. B. kategorische Features codieren, Werte skalieren und die Daten in Trainings- und Testsets aufteilen).

3.  **Modell** anhand der Trainingsdaten **trainieren**.

4.  **Mit Metriken evaluieren** auf einem Testset: Accuracy, Precision, Recall, F1-Score und ROC AUC für die Klassifikation (sowie Mean Squared Error für die Regression).

Sehen wir uns die einzelnen Algorithmen an:

### Linear Regression

Linear Regression ist ein **Regressions**algorithmus, der zur Vorhersage kontinuierlicher numerischer Werte verwendet wird. Er setzt eine lineare Beziehung zwischen den Eingabe-Features (unabhängigen Variablen) und der Ausgabe (abhängigen Variable) voraus. Das Modell versucht, eine gerade Linie (oder in höheren Dimensionen eine Hyperebene) anzupassen, die die Beziehung zwischen den Features und dem Zielwert bestmöglich beschreibt. Dies geschieht typischerweise durch die Minimierung der Summe der quadrierten Fehler zwischen den vorhergesagten und den tatsächlichen Werten (Ordinary Least Squares method).<sup>[[2]](#references)</sup>

Die einfachste Form zur Darstellung von Linear Regression ist eine Linie:
```plaintext
y = mx + b
```
Dabei gilt:

- `y` ist der vorhergesagte Wert (Output)
- `m` ist die Steigung der Gerade (Koeffizient)
- `x` ist das Eingabemerkmal
- `b` ist der y-Achsenabschnitt

Das Ziel der linearen Regression besteht darin, die am besten passende Gerade zu finden, die den Unterschied zwischen den vorhergesagten Werten und den tatsächlichen Werten im Datensatz minimiert. Natürlich ist dies sehr einfach: Es wäre eine gerade Linie, die 2 Kategorien voneinander trennt. Wenn jedoch weitere Dimensionen hinzugefügt werden, wird die Linie komplexer:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Die lineare Regression selbst wird seltener für zentrale Security-Aufgaben eingesetzt (bei denen es sich häufig um Klassifikation handelt), kann jedoch zur Vorhersage numerischer Ergebnisse verwendet werden. Beispielsweise könnte man mithilfe der linearen Regression das **Volumen des Netzwerkverkehrs vorhersagen** oder **die Anzahl der Angriffe in einem bestimmten Zeitraum schätzen**, basierend auf historischen Daten. Sie könnte auch einen Risiko-Score oder die erwartete Zeit bis zur Erkennung eines Angriffs vorhersagen, wenn bestimmte Systemmetriken gegeben sind. In der Praxis werden Klassifikationsalgorithmen (wie die logistische Regression oder Bäume) häufiger zur Erkennung von Intrusionen oder Malware eingesetzt, aber die lineare Regression dient als Grundlage und ist für regressionsorientierte Analysen nützlich.

#### **Wichtige Merkmale der linearen Regression:**

-   **Problemtyp:** Regression (Vorhersage kontinuierlicher Werte). Ohne Anwendung eines Schwellenwerts auf die Ausgabe nicht für die direkte Klassifikation geeignet.

-   **Interpretierbarkeit:** Hoch -- Koeffizienten sind einfach zu interpretieren und zeigen den linearen Effekt jedes Features.

-   **Vorteile:** Einfach und schnell; eine gute Basis für Regressionsaufgaben; funktioniert gut, wenn der tatsächliche Zusammenhang annähernd linear ist.

-   **Einschränkungen:** Kann komplexe oder nichtlineare Zusammenhänge nicht erfassen (ohne manuelles Feature Engineering); neigt bei nichtlinearen Zusammenhängen zu Underfitting; anfällig für Ausreißer, die die Ergebnisse verfälschen können.

-   **Ermittlung der besten Anpassung:** Um die am besten passende Gerade zu finden, die die möglichen Kategorien trennt, verwenden wir eine Methode namens **Ordinary Least Squares (OLS)**. Diese Methode minimiert die Summe der quadrierten Differenzen zwischen den beobachteten Werten und den vom linearen Modell vorhergesagten Werten.

<details>
<summary>Beispiel -- Vorhersage der Verbindungsdauer (Regression) in einem Intrusion-Datensatz
</summary>
Im Folgenden demonstrieren wir die lineare Regression mithilfe des NSL-KDD-Cybersicherheitsdatensatzes. Wir behandeln dies als Regressionsproblem, indem wir die `duration` von Netzwerkverbindungen basierend auf anderen Features vorhersagen. (In der Realität ist `duration` ein Feature von NSL-KDD; wir verwenden es hier lediglich zur Veranschaulichung der Regression.) Wir laden den Datensatz, bereiten ihn vor (indem wir kategoriale Features codieren), trainieren ein lineares Regressionsmodell und bewerten den Mean Squared Error (MSE) sowie den R²-Score anhand eines Testdatensatzes.
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
In diesem Beispiel versucht das lineare Regressionsmodell, die Verbindungs-`duration` anhand anderer Netzwerkmerkmale vorherzusagen. Wir messen die Leistung mit dem Mean Squared Error (MSE) und R². Ein R² nahe 1,0 würde darauf hindeuten, dass das Modell den größten Teil der Varianz von `duration` erklärt, während ein niedriges oder negatives R² auf eine schlechte Anpassung hinweist. (Seien Sie nicht überrascht, wenn das R² hier niedrig ist – die Vorhersage von `duration` anhand der gegebenen Merkmale könnte schwierig sein, und die lineare Regression kann die Muster möglicherweise nicht erfassen, wenn sie komplex sind.)
</details>

### Logistische Regression

Die logistische Regression ist ein **Klassifikations**algorithmus, der die Wahrscheinlichkeit modelliert, dass eine Instanz zu einer bestimmten Klasse gehört (typischerweise zur „positiven“ Klasse). Trotz ihres Namens wird die *logistische* Regression für diskrete Ergebnisse verwendet (im Gegensatz zur linearen Regression, die für kontinuierliche Ergebnisse eingesetzt wird). Sie wird insbesondere für die **binäre Klassifikation** verwendet (zwei Klassen, z. B. malicious und benign), kann jedoch auf Multi-Class-Probleme erweitert werden (mit softmax- oder One-vs-Rest-Ansätzen).<sup>[[3]](#references)</sup>

Die logistische Regression verwendet die logistische Funktion (auch Sigmoid-Funktion genannt), um vorhergesagte Werte auf Wahrscheinlichkeiten abzubilden. Beachten Sie, dass die Sigmoid-Funktion eine Funktion mit Werten zwischen 0 und 1 ist, die je nach den Anforderungen der Klassifikation in einer S-förmigen Kurve ansteigt. Dies ist für Aufgaben der binären Klassifikation nützlich. Daher wird jedes Merkmal jeder Eingabe mit seinem zugewiesenen Gewicht multipliziert, und das Ergebnis wird durch die Sigmoid-Funktion geleitet, um eine Wahrscheinlichkeit zu erzeugen:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` ist die Wahrscheinlichkeit, dass die Ausgabe `y` bei der Eingabe `x` den Wert 1 hat
- `e` ist die Basis des natürlichen Logarithmus
- `z` ist eine lineare Kombination der Eingabemerkmale, typischerweise dargestellt als `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Beachte, dass es auch hier in seiner einfachsten Form eine gerade Linie ist, in komplexeren Fällen jedoch zu einer Hyperebene mit mehreren Dimensionen wird (eine pro Merkmal).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Da viele Sicherheitsprobleme im Wesentlichen Ja/Nein-Entscheidungen sind, wird Logistic Regression häufig eingesetzt. Beispielsweise könnte ein Intrusion-Detection-System Logistic Regression verwenden, um anhand der Merkmale einer Netzwerkverbindung zu entscheiden, ob es sich um einen Angriff handelt. Bei der Phishing-Erkennung kann Logistic Regression Merkmale einer Website (URL-Länge, Vorhandensein des Symbols "@", usw.) zu einer Wahrscheinlichkeit kombinieren, dass es sich um Phishing handelt. Logistic Regression wurde in Spam-Filtern der frühen Generation eingesetzt und ist weiterhin eine starke Baseline für viele Klassifizierungsaufgaben.

#### Logistic Regression für nicht-binäre Klassifikation

Logistic Regression ist für die binäre Klassifikation ausgelegt, kann aber mithilfe von Verfahren wie **one-vs-rest** (OvR) oder **softmax regression** auf Multi-Class-Probleme erweitert werden. Bei OvR wird für jede Klasse ein separates Logistic-Regression-Modell trainiert, wobei diese Klasse als positive Klasse gegenüber allen anderen behandelt wird. Die Klasse mit der höchsten vorhergesagten Wahrscheinlichkeit wird als endgültige Vorhersage ausgewählt. Softmax regression verallgemeinert Logistic Regression auf mehrere Klassen, indem die Softmax-Funktion auf die Ausgabeschicht angewendet wird und eine Wahrscheinlichkeitsverteilung über alle Klassen erzeugt.

#### **Wichtige Merkmale von Logistic Regression:**

-   **Art des Problems:** Klassifikation (normalerweise binär). Das Modell sagt die Wahrscheinlichkeit der positiven Klasse voraus.

-   **Interpretierbarkeit:** Hoch -- wie bei der linearen Regression können die Merkmalskoeffizienten angeben, wie jedes Merkmal die Log-Odds des Ergebnisses beeinflusst. Diese Transparenz wird in der Sicherheit häufig geschätzt, um zu verstehen, welche Faktoren zu einem Alert beitragen.

-   **Vorteile:** Einfach und schnell zu trainieren; funktioniert gut, wenn die Beziehung zwischen den Merkmalen und den Log-Odds des Ergebnisses linear ist. Gibt Wahrscheinlichkeiten aus und ermöglicht dadurch eine Risikobewertung. Mit geeigneter Regularisierung generalisiert das Modell gut und kann Multikollinearität besser verarbeiten als eine einfache lineare Regression.

-   **Einschränkungen:** Geht von einer linearen Entscheidungsgrenze im Merkmalsraum aus (versagt, wenn die tatsächliche Grenze komplex/nicht linear ist). Bei Problemen, bei denen Interaktionen oder nicht-lineare Effekte entscheidend sind, kann die Leistung geringer ausfallen, sofern nicht manuell polynomiale Merkmale oder Interaktionsmerkmale hinzugefügt werden. Außerdem ist Logistic Regression weniger effektiv, wenn die Klassen nicht leicht durch eine lineare Kombination der Merkmale trennbar sind.


<details>
<summary>Beispiel -- Erkennung von Phishing-Websites mit Logistic Regression:</summary>

Wir verwenden ein **Phishing Websites Dataset** (aus dem UCI-Repository), das extrahierte Merkmale von Websites enthält (z. B. ob die URL eine IP-Adresse enthält, das Alter der Domain, das Vorhandensein verdächtiger Elemente im HTML usw.) sowie ein Label, das angibt, ob die Website Phishing betreibt oder legitim ist.<sup>[[4]](#references)</sup> Wir trainieren ein Logistic-Regression-Modell, um Websites zu klassifizieren, und bewerten anschließend seine Accuracy, Precision, Recall, den F1-Score und die ROC AUC anhand einer Testaufteilung.
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
In diesem Beispiel zur Erkennung von Phishing erzeugt die logistische Regression für jede Website eine Wahrscheinlichkeit dafür, dass es sich um eine Phishing-Website handelt. Durch die Bewertung von Accuracy, Precision, Recall und F1 erhalten wir einen Eindruck von der Leistung des Modells. Ein hoher Recall würde beispielsweise bedeuten, dass die meisten Phishing-Websites erkannt werden (wichtig für die Sicherheit, um möglichst wenige Angriffe zu übersehen), während eine hohe Precision bedeutet, dass es nur wenige Fehlalarme gibt (wichtig, um eine Ermüdung der Analysten zu vermeiden). Die ROC AUC (Area Under the ROC Curve) liefert ein schwellenwertunabhängiges Maß für die Leistung (1,0 ist ideal, 0,5 ist nicht besser als Zufall). Die logistische Regression erzielt bei solchen Aufgaben häufig gute Ergebnisse. Wenn die Entscheidungsgrenze zwischen Phishing- und legitimen Websites jedoch komplex ist, werden möglicherweise leistungsfähigere nichtlineare Modelle benötigt.

</details>

### Entscheidungsbäume

Ein Entscheidungsbaum ist ein vielseitiger **Algorithmus für überwachtes Lernen**, der sowohl für Klassifizierungs- als auch für Regressionsaufgaben verwendet werden kann. Er lernt ein hierarchisches, baumartiges Entscheidungsmodell auf Grundlage der Merkmale der Daten. Jeder interne Knoten des Baums stellt einen Test für ein bestimmtes Merkmal dar, jeder Zweig repräsentiert ein Ergebnis dieses Tests und jedes Blatt stellt eine vorhergesagte Klasse (bei der Klassifizierung) oder einen Wert (bei der Regression) dar.<sup>[[5]](#references)</sup>

Zum Erstellen eines Baums verwenden Algorithmen wie CART (Classification and Regression Tree) Maße wie **Gini impurity** oder **information gain (entropy)**, um bei jedem Schritt das beste Merkmal und den besten Schwellenwert für die Aufteilung der Daten auszuwählen. Das Ziel jeder Aufteilung besteht darin, die Homogenität der Zielvariable in den resultierenden Teilmengen zu erhöhen (bei der Klassifizierung soll jeder Knoten möglichst rein sein und überwiegend nur eine Klasse enthalten).

Entscheidungsbäume sind **sehr gut interpretierbar** -- man kann den Pfad von der Wurzel bis zum Blatt verfolgen, um die Logik hinter einer Vorhersage zu verstehen (z. B. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Dies ist in der Cybersicherheit hilfreich, um zu erklären, warum eine bestimmte Warnung ausgelöst wurde. Bäume können sowohl numerische als auch kategoriale Daten auf natürliche Weise verarbeiten und erfordern nur wenig Vorverarbeitung (z. B. ist keine Skalierung der Merkmale erforderlich).

Ein einzelner Entscheidungsbaum kann die Trainingsdaten jedoch leicht überanpassen, insbesondere wenn er sehr tief aufgebaut wird (mit vielen Aufteilungen). Techniken wie das Pruning (Begrenzung der Baumtiefe oder Festlegung einer Mindestanzahl von Stichproben pro Blatt) werden häufig eingesetzt, um eine Überanpassung zu verhindern.

Ein Entscheidungsbaum besteht aus 3 Hauptkomponenten:
- **Root Node**: Der oberste Knoten des Baums, der den gesamten Datensatz repräsentiert.
- **Internal Nodes**: Knoten, die Merkmale und auf diesen Merkmalen basierende Entscheidungen repräsentieren.
- **Leaf Nodes**: Knoten, die das endgültige Ergebnis oder die Vorhersage repräsentieren.

Ein Baum könnte schließlich folgendermaßen aussehen:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Entscheidungsbäume werden in Intrusion Detection Systems verwendet, um **Regeln** zur Identifizierung von Angriffen abzuleiten. Beispielsweise erzeugten frühe IDS auf Basis von ID3/C4.5 menschenlesbare Regeln, um normalen von bösartigem Traffic zu unterscheiden. Sie werden auch bei der Malware-Analyse eingesetzt, um anhand ihrer Attribute (Dateigröße, Abschnittsentropie, API-Aufrufe usw.) zu entscheiden, ob eine Datei bösartig ist. Die Klarheit von Entscheidungsbäumen macht sie nützlich, wenn Transparenz erforderlich ist -- ein Analyst kann den Baum überprüfen, um die Erkennungslogik zu validieren.

#### **Wichtige Merkmale von Entscheidungsbäumen:**

-   **Problemtyp:** Sowohl Klassifikation als auch Regression. Häufig für die Klassifikation von Angriffen gegenüber normalem Traffic usw. verwendet.

-   **Interpretierbarkeit:** Sehr hoch -- die Entscheidungen des Modells können visualisiert und als eine Reihe von Wenn-dann-Regeln verstanden werden. Dies ist ein großer Vorteil in der Security, wenn Vertrauen und die Überprüfung des Modellverhaltens wichtig sind.

-   **Vorteile:** Können nichtlineare Beziehungen und Interaktionen zwischen Features erfassen (jeder Split kann als Interaktion betrachtet werden). Features müssen nicht skaliert und kategoriale Variablen nicht One-Hot-encodiert werden -- Bäume verarbeiten diese nativ. Schnelle Inferenz (die Vorhersage besteht lediglich darin, einem Pfad im Baum zu folgen).

-   **Einschränkungen:** Neigen zu Overfitting, wenn sie nicht kontrolliert werden (ein tiefer Baum kann den Trainingsdatensatz auswendig lernen). Sie können instabil sein -- kleine Änderungen an den Daten können zu einer anderen Baumstruktur führen. Als einzelne Modelle erreicht ihre Genauigkeit möglicherweise nicht das Niveau fortschrittlicherer Methoden (Ensembles wie Random Forests schneiden typischerweise besser ab, da sie die Varianz reduzieren).

-   **Ermittlung des besten Splits:**
- **Gini Impurity**: Misst die Unreinheit eines Knotens. Eine niedrigere Gini Impurity weist auf einen besseren Split hin. Die Formel lautet:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Dabei ist `p_i` der Anteil der Instanzen in Klasse `i`.

- **Entropy**: Misst die Unsicherheit im Datensatz. Eine niedrigere Entropy weist auf einen besseren Split hin. Die Formel lautet:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Dabei ist `p_i` der Anteil der Instanzen in Klasse `i`.

- **Information Gain**: Die Verringerung der Entropy oder Gini Impurity nach einem Split. Je höher der Information Gain, desto besser der Split. Er wird wie folgt berechnet:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Außerdem wird ein Baum beendet, wenn:
- Alle Instanzen in einem Knoten derselben Klasse angehören. Dies kann zu Overfitting führen.
- Die maximale Tiefe (hartcodiert) des Baums erreicht ist. Dies ist eine Möglichkeit, Overfitting zu verhindern.
- Die Anzahl der Instanzen in einem Knoten unter einem bestimmten Schwellenwert liegt. Dies ist ebenfalls eine Möglichkeit, Overfitting zu verhindern.
- Der Information Gain weiterer Splits unter einem bestimmten Schwellenwert liegt. Dies ist ebenfalls eine Möglichkeit, Overfitting zu verhindern.

<details>
<summary>Beispiel -- Entscheidungsbaum für Intrusion Detection:</summary>
Wir trainieren einen Entscheidungsbaum mit dem NSL-KDD-Datensatz, um Netzwerkverbindungen entweder als *normal* oder als *Angriff* zu klassifizieren. NSL-KDD ist eine verbesserte Version des klassischen KDD-Cup-1999-Datensatzes mit Features wie Protokolltyp, Service, Dauer, Anzahl fehlgeschlagener Logins usw. sowie einem Label, das den Angriffstyp oder „normal“ angibt. Wir ordnen alle Angriffstypen der Klasse „Anomalie“ zu (binäre Klassifikation: normal gegenüber Anomalie). Nach dem Training bewerten wir die Performance des Baums auf dem Testdatensatz.
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
In diesem Beispiel eines Entscheidungsbaums haben wir die Baumtiefe auf 10 begrenzt, um extremes Overfitting zu vermeiden (der Parameter `max_depth=10`). Die Metriken zeigen, wie gut der Baum normalen von Angriffsverkehr unterscheidet. Ein hoher Recall würde bedeuten, dass die meisten Angriffe erkannt werden (wichtig für ein IDS), während eine hohe Precision wenige Fehlalarme bedeutet. Entscheidungsbäume erreichen bei strukturierten Daten oft eine ordentliche Genauigkeit, aber ein einzelner Baum erzielt möglicherweise nicht die bestmögliche Performance. Dennoch ist die *Interpretierbarkeit* des Modells ein großer Vorteil -- wir könnten die Splits des Baums untersuchen, um beispielsweise festzustellen, welche Features (z. B. `service`, `src_bytes` usw.) am stärksten dazu beitragen, eine Verbindung als bösartig einzustufen.

</details>

### Random Forests

Random Forest ist eine **Ensemble-Learning**-Methode, die auf Entscheidungsbäumen aufbaut, um die Performance zu verbessern. Ein Random Forest trainiert mehrere Entscheidungsbäume (daher „forest“) und kombiniert deren Ausgaben, um eine abschließende Vorhersage zu treffen (bei der Klassifikation typischerweise durch Mehrheitsentscheidung). Die beiden Hauptideen eines Random Forests sind **Bagging** (Bootstrap Aggregating) und **Feature Randomness**:

-   **Bagging:** Jeder Baum wird mit einer zufälligen Bootstrap-Stichprobe der Trainingsdaten trainiert (mit Zurücklegen gezogen). Dadurch entsteht Diversität zwischen den Bäumen.

-   **Feature Randomness:** Bei jedem Split in einem Baum wird eine zufällige Teilmenge der Features für den Split berücksichtigt (statt aller Features). Dadurch werden die Bäume zusätzlich voneinander entkoppelt.

Durch die Mittelung der Ergebnisse vieler Bäume reduziert der Random Forest die Varianz, die ein einzelner Entscheidungsbaum aufweisen kann. Vereinfacht gesagt können einzelne Bäume Overfitting betreiben oder verrauscht sein, aber eine große Anzahl diverser Bäume, die gemeinsam abstimmen, gleicht diese Fehler aus. Das Ergebnis ist häufig ein Modell mit **höherer Genauigkeit** und besserer Generalisierung als ein einzelner Entscheidungsbaum. Zusätzlich können Random Forests eine Schätzung der Feature Importance liefern (indem betrachtet wird, wie stark jeder Feature-Split die Unreinheit im Durchschnitt reduziert).

Random Forests haben sich in der **Cybersecurity** für Aufgaben wie Intrusion Detection, Malware-Klassifikation und Spam-Erkennung zu einem **Arbeitspferd** entwickelt. Sie erzielen oft direkt ohne umfangreiches Tuning gute Ergebnisse und können große Feature-Mengen verarbeiten. Bei der Intrusion Detection kann ein Random Forest beispielsweise einen einzelnen Entscheidungsbaum übertreffen, indem er subtilere Angriffsmuster mit weniger False Positives erkennt. Untersuchungen haben gezeigt, dass Random Forests bei der Klassifikation von Angriffen in Datensätzen wie NSL-KDD und UNSW-NB15 im Vergleich zu anderen Algorithmen gute Ergebnisse erzielen.<sup>[[6]](#references)[[7]](#references)</sup>

#### **Wichtige Eigenschaften von Random Forests:**

-   **Problemtyp:** Primär Klassifikation (wird auch für Regression verwendet). Sehr gut für hochdimensionale strukturierte Daten geeignet, wie sie häufig in Security-Logs vorkommen.

-   **Interpretierbarkeit:** Geringer als bei einem einzelnen Entscheidungsbaum -- Hunderte von Bäumen lassen sich nicht einfach gleichzeitig visualisieren oder erklären. Feature-Importance-Scores liefern jedoch gewisse Einblicke darin, welche Attribute den größten Einfluss haben.

-   **Vorteile:** Im Allgemeinen höhere Genauigkeit als Single-Tree-Modelle aufgrund des Ensemble-Effekts. Robust gegenüber Overfitting -- selbst wenn einzelne Bäume Overfitting betreiben, generalisiert das Ensemble besser. Verarbeitet sowohl numerische als auch kategoriale Features und kann fehlende Daten bis zu einem gewissen Grad handhaben. Außerdem ist es relativ robust gegenüber Ausreißern.

-   **Einschränkungen:** Die Modellgröße kann groß sein (viele Bäume, die jeweils potenziell tief sein können). Vorhersagen sind langsamer als bei einem einzelnen Baum (da die Ergebnisse vieler Bäume aggregiert werden müssen). Geringere Interpretierbarkeit -- zwar sind wichtige Features bekannt, aber die genaue Logik lässt sich nicht so einfach wie eine einfache Regel nachvollziehen. Wenn der Datensatz extrem hochdimensional und dünn besetzt ist, kann das Training eines sehr großen Forests rechenintensiv sein.

-   **Trainingsprozess:**
1. **Bootstrap Sampling**: Ziehe zufällig Trainingsdaten mit Zurücklegen, um mehrere Teilmengen (Bootstrap-Stichproben) zu erstellen.
2. **Tree Construction**: Erstelle für jede Bootstrap-Stichprobe einen Entscheidungsbaum und verwende bei jedem Split eine zufällige Teilmenge der Features. Dadurch entsteht Diversität zwischen den Bäumen.
3. **Aggregation**: Bei Klassifikationsaufgaben wird die abschließende Vorhersage durch eine Mehrheitsentscheidung unter den Vorhersagen aller Bäume getroffen. Bei Regressionsaufgaben ist die abschließende Vorhersage der Durchschnitt der Vorhersagen aller Bäume.

<details>
<summary>Beispiel -- Random Forest für Intrusion Detection (NSL-KDD):</summary>
Wir verwenden denselben NSL-KDD-Datensatz (binär als normal oder Anomalie gelabelt) und trainieren einen Random-Forest-Klassifikator. Wir erwarten, dass der Random Forest dank der Varianzreduzierung durch die Ensemble-Mittelung genauso gut oder besser als der einzelne Entscheidungsbaum abschneidet. Wir evaluieren ihn mit denselben Metriken.
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
Der Random Forest erzielt bei dieser Aufgabe zur Intrusion Detection typischerweise starke Ergebnisse. Im Vergleich zu einem einzelnen Entscheidungsbaum könnten wir eine Verbesserung bei Metriken wie F1 oder AUC beobachten, insbesondere bei Recall oder Precision, abhängig von den Daten. Dies stimmt mit der Erkenntnis überein, dass *"Random Forest (RF) ein Ensemble-Klassifikator ist und im Vergleich zu anderen traditionellen Klassifikatoren eine effektive Klassifizierung von Angriffen ermöglicht."*.<sup>[[6]](#references)</sup> Im Kontext von Security Operations könnte ein Random-Forest-Modell Angriffe dank der Mittelung vieler Entscheidungsregeln zuverlässiger erkennen und gleichzeitig Fehlalarme reduzieren. Die Feature Importance des Forests könnte uns zeigen, welche Netzwerk-Features am stärksten auf Angriffe hindeuten (z. B. bestimmte Netzwerkdienste oder ungewöhnliche Paketanzahlen).

</details>

### Support Vector Machines (SVM)

Support Vector Machines sind leistungsstarke überwachte Lernmodelle, die hauptsächlich zur Klassifizierung (und auch zur Regression als SVR) eingesetzt werden. Eine SVM versucht, die **optimale trennende Hyperebene** zu finden, welche den Abstand zwischen zwei Klassen maximiert. Nur eine Teilmenge der Trainingspunkte (die der Grenze am nächsten liegenden „Support Vectors“) bestimmt die Position dieser Hyperebene. Durch die Maximierung des Abstands (der Distanz zwischen den Support Vectors und der Hyperebene) erreichen SVMs typischerweise eine gute Generalisierung.<sup>[[8]](#references)</sup>

Ein wesentlicher Bestandteil der Leistungsfähigkeit von SVMs ist die Möglichkeit, **Kernel-Funktionen** zu verwenden, um nichtlineare Zusammenhänge zu verarbeiten. Die Daten können implizit in einen höherdimensionalen Feature-Raum transformiert werden, in dem möglicherweise ein linearer Trenner existiert. Zu den gängigen Kernels gehören Polynomial-, Radial-Basis-Function- (RBF-) und Sigmoid-Kernels. Wenn beispielsweise Netzwerkverkehrsklassen im ursprünglichen Feature-Raum nicht linear trennbar sind, kann ein RBF-Kernel sie in einen höherdimensionalen Raum abbilden, in dem die SVM eine lineare Trennung findet (was im ursprünglichen Raum einer nichtlinearen Grenze entspricht). Die Möglichkeit, zwischen verschiedenen Kernels zu wählen, erlaubt es SVMs, eine Vielzahl von Problemen zu bewältigen.

SVMs funktionieren bekanntermaßen gut in Situationen mit hochdimensionalen Feature-Räumen (wie Textdaten oder Malware-Opcode-Sequenzen) und in Fällen, in denen die Anzahl der Features im Verhältnis zur Anzahl der Samples groß ist. Sie waren in vielen frühen Cybersecurity-Anwendungen beliebt, etwa bei der Malware-Klassifizierung und der anomaliebasierten Intrusion Detection in den 2000er-Jahren, und erzielten oft eine hohe Genauigkeit.

SVMs lassen sich jedoch nur schwer auf sehr große Datensätze skalieren (die Trainingskomplexität ist hinsichtlich der Anzahl der Samples superlinear, und der Speicherbedarf kann hoch sein, da möglicherweise viele Support Vectors gespeichert werden müssen). In der Praxis könnte eine SVM für Aufgaben wie Network Intrusion Detection mit Millionen von Datensätzen ohne sorgfältiges Subsampling oder die Verwendung approximativer Methoden zu langsam sein.

#### **Wichtige Eigenschaften von SVM:**

-   **Problemtyp:** Klassifizierung (binär oder multiklassig über One-vs-One/One-vs-Rest) sowie Regressionsvarianten. Wird häufig zur binären Klassifizierung mit klarer Abstandstrennung eingesetzt.

-   **Interpretierbarkeit:** Mittel -- SVMs sind nicht so interpretierbar wie Entscheidungsbäume oder die logistische Regression. Zwar kann man erkennen, welche Datenpunkte Support Vectors sind, und ein gewisses Verständnis dafür gewinnen, welche Features einflussreich sein könnten (über die Gewichte im Fall eines linearen Kernels), in der Praxis werden SVMs (insbesondere mit nichtlinearen Kernels) jedoch als Black-Box-Klassifikatoren behandelt.

-   **Vorteile:** Effektiv in hochdimensionalen Räumen; kann mit dem Kernel-Trick komplexe Entscheidungsgrenzen modellieren; robust gegenüber Overfitting, wenn der Abstand maximiert wird (insbesondere mit einem geeigneten Regularisierungsparameter C); funktioniert auch dann gut, wenn die Klassen nicht durch eine große Distanz getrennt sind (findet eine bestmögliche Kompromissgrenze).

-   **Einschränkungen:** **Rechenintensiv** bei großen Datensätzen (sowohl Training als auch Vorhersage skalieren bei wachsender Datenmenge schlecht). Erfordert eine sorgfältige Abstimmung der Kernel- und Regularisierungsparameter (C, Kernel-Typ, Gamma für RBF usw.). Liefert nicht direkt probabilistische Ausgaben (mit Platt Scaling können jedoch Wahrscheinlichkeiten erzeugt werden). Außerdem können SVMs empfindlich auf die Wahl der Kernel-Parameter reagieren --- eine schlechte Wahl kann zu Underfitting oder Overfitting führen.

*Einsatzbereiche in der Cybersecurity:* SVMs wurden zur **Malware-Erkennung** (z. B. zur Klassifizierung von Dateien anhand extrahierter Features oder Opcode-Sequenzen), zur **Netzwerk-Anomalieerkennung** (Klassifizierung von Datenverkehr als normal oder bösartig) und zur **Phishing-Erkennung** (anhand von URL-Features) eingesetzt. Beispielsweise könnte eine SVM Features einer E-Mail (Anzahl bestimmter Schlüsselwörter, Reputation des Absenders usw.) verarbeiten und sie als Phishing oder legitim klassifizieren. Sie wurden auch zur **Intrusion Detection** auf Feature-Sets wie KDD eingesetzt und erzielten häufig eine hohe Genauigkeit, allerdings auf Kosten des Rechenaufwands.

<details>
<summary>Beispiel -- SVM zur Malware-Klassifizierung:</summary>
Wir verwenden erneut den Phishing-Website-Datensatz, diesmal mit einer SVM. Da SVMs langsam sein können, verwenden wir bei Bedarf eine Teilmenge der Daten zum Training (der Datensatz umfasst etwa 11.000 Instanzen, was eine SVM noch problemlos verarbeiten kann). Wir verwenden einen RBF-Kernel, der eine gängige Wahl für nichtlineare Daten ist, und aktivieren Wahrscheinlichkeitsschätzungen zur Berechnung der ROC AUC.
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
Das SVM-Modell gibt Metriken aus, die wir mit der logistischen Regression für dieselbe Aufgabe vergleichen können. Wir könnten feststellen, dass SVM eine hohe Accuracy und AUC erreicht, wenn die Daten anhand der Features gut getrennt sind. Umgekehrt könnte SVM die logistische Regression nicht wesentlich übertreffen, wenn der Datensatz viel Rauschen oder überlappende Klassen enthält. In der Praxis können SVMs einen Vorteil bieten, wenn komplexe, nichtlineare Beziehungen zwischen Features und Klassen bestehen -- der RBF-Kernel kann gekrümmte Entscheidungsgrenzen erfassen, die die logistische Regression übersehen würde. Wie bei allen Modellen ist eine sorgfältige Abstimmung von `C` (Regularisierung) und den Kernel-Parametern (wie `gamma` für RBF) erforderlich, um Bias und Varianz auszubalancieren.

</details>

#### Unterschiede zwischen logistischer Regression und SVM

| Aspekt | **Logistische Regression** | **Support Vector Machines** |
|---|---|---|
| **Zielfunktion** | Minimiert **Log-Loss** (Kreuzentropie). | Maximiert den **Margin**, während **Hinge-Loss** minimiert wird. |
| **Entscheidungsgrenze** | Ermittelt die **am besten passende Hyperebene**, die _P(y\|x)_ modelliert. | Ermittelt die **Hyperebene mit maximalem Margin** (größter Abstand zu den nächstgelegenen Punkten). |
| **Ausgabe** | **Probabilistisch** – liefert kalibrierte Klassenwahrscheinlichkeiten über σ(w·x + b). | **Deterministisch** – gibt Klassenlabels zurück; Wahrscheinlichkeiten erfordern zusätzliche Verarbeitung (z. B. Platt Scaling). |
| **Regularisierung** | L2 (Standard) oder L1, gleicht Underfitting und Overfitting direkt aus. | Der Parameter C stellt einen Kompromiss zwischen der Breite des Margins und Fehlklassifikationen dar; Kernel-Parameter erhöhen die Komplexität. |
| **Kernels / Nichtlinearität** | Die native Form ist **linear**; Nichtlinearität wird durch Feature Engineering hinzugefügt. | Der integrierte **Kernel-Trick** (RBF, poly usw.) ermöglicht die Modellierung komplexer Grenzen in hochdimensionalen Räumen. |
| **Skalierbarkeit** | Löst eine konvexe Optimierung in **O(nd)**; verarbeitet sehr große n gut. | Das Training kann ohne spezialisierte Solver **O(n²–n³)** an Speicher/Zeit benötigen; weniger geeignet für sehr große n. |
| **Interpretierbarkeit** | **Hoch** – Gewichte zeigen den Einfluss der Features; das Odds Ratio ist intuitiv verständlich. | **Gering** bei nichtlinearen Kernels; Support Vectors sind sparsam, aber nicht leicht zu erklären. |
| **Empfindlichkeit gegenüber Ausreißern** | Verwendet einen glatten Log-Loss und ist daher weniger empfindlich. | Hinge-Loss mit hartem Margin kann **empfindlich** sein; ein Soft-Margin (C) wirkt dem entgegen. |
| **Typische Anwendungsfälle** | Kreditbewertung, medizinische Risikobewertung, A/B-Testing – wenn **Wahrscheinlichkeiten und Erklärbarkeit** wichtig sind. | Bild-/Textklassifikation, Bioinformatik – wenn **komplexe Grenzen** und **hochdimensionale Daten** wichtig sind. |

* **Wenn du kalibrierte Wahrscheinlichkeiten, Interpretierbarkeit oder die Verarbeitung sehr großer Datensätze benötigst – wähle die logistische Regression.**
* **Wenn du ein flexibles Modell benötigst, das nichtlineare Beziehungen ohne manuelles Feature Engineering erfassen kann – wähle SVM (mit Kernels).**
* Beide optimieren konvexe Zielfunktionen, daher sind **globale Minima garantiert**. Die Kernels von SVM fügen jedoch Hyperparameter und zusätzlichen Rechenaufwand hinzu.

### Naive Bayes

Naive Bayes ist eine Familie **probabilistischer Klassifikatoren**, die auf der Anwendung des Satzes von Bayes mit einer starken Unabhängigkeitsannahme zwischen den Features basiert. Trotz dieser „naiven“ Annahme funktioniert Naive Bayes bei bestimmten Anwendungen oft überraschend gut, insbesondere bei Texten oder kategorialen Daten, beispielsweise bei der Spam-Erkennung.<sup>[[9]](#references)</sup>


#### Satz von Bayes

Der Satz von Bayes bildet die Grundlage von Naive-Bayes-Klassifikatoren. Er setzt die bedingten und marginalen Wahrscheinlichkeiten zufälliger Ereignisse in Beziehung. Die Formel lautet:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Wo:
- `P(A|B)` ist die posteriori-Wahrscheinlichkeit der Klasse `A` gegeben das Merkmal `B`.
- `P(B|A)` ist die Likelihood des Merkmals `B` gegeben die Klasse `A`.
- `P(A)` ist die a-priori-Wahrscheinlichkeit der Klasse `A`.
- `P(B)` ist die a-priori-Wahrscheinlichkeit des Merkmals `B`.

Wenn wir beispielsweise klassifizieren möchten, ob ein Text von einem Kind oder einem Erwachsenen geschrieben wurde, können wir die Wörter im Text als Merkmale verwenden. Auf Grundlage einiger initialer Daten berechnet der Naive-Bayes-Klassifikator im Voraus die Wahrscheinlichkeiten dafür, dass jedes Wort zu jeder möglichen Klasse (Kind oder Erwachsener) gehört. Wenn ein neuer Text bereitgestellt wird, berechnet er die Wahrscheinlichkeit jeder möglichen Klasse anhand der Wörter im Text und wählt die Klasse mit der höchsten Wahrscheinlichkeit aus.

Wie Sie an diesem Beispiel sehen können, ist der Naive-Bayes-Klassifikator sehr einfach und schnell. Er nimmt jedoch an, dass die Merkmale unabhängig sind, was bei realen Daten nicht immer der Fall ist.


#### Typen von Naive-Bayes-Klassifikatoren

Es gibt mehrere Typen von Naive-Bayes-Klassifikatoren, abhängig vom Datentyp und der Verteilung der Merkmale:
- **Gaussian Naive Bayes**: Nimmt an, dass die Merkmale einer Gaußschen (Normal-)Verteilung folgen. Geeignet für kontinuierliche Daten.
- **Multinomial Naive Bayes**: Nimmt an, dass die Merkmale einer Multinomialverteilung folgen. Geeignet für diskrete Daten, beispielsweise Wortanzahlen bei der Textklassifizierung.
- **Bernoulli Naive Bayes**: Nimmt an, dass die Merkmale binär (0 oder 1) sind. Geeignet für binäre Daten, beispielsweise das Vorhandensein oder Fehlen von Wörtern bei der Textklassifizierung.
- **Categorical Naive Bayes**: Nimmt an, dass die Merkmale kategoriale Variablen sind. Geeignet für kategoriale Daten, beispielsweise die Klassifizierung von Früchten anhand ihrer Farbe und Form.


#### **Wichtige Merkmale von Naive Bayes:**

-   **Art des Problems:** Klassifizierung (binär oder mehrere Klassen). Wird häufig für Textklassifizierungsaufgaben in der Cybersicherheit eingesetzt (Spam, Phishing usw.).

-   **Interpretierbarkeit:** Mittel -- nicht so direkt interpretierbar wie ein Entscheidungsbaum, aber man kann die gelernten Wahrscheinlichkeiten untersuchen (z. B. welche Wörter am wahrscheinlichsten in Spam- bzw. Ham-E-Mails vorkommen). Die Struktur des Modells (Wahrscheinlichkeiten für jedes Merkmal gegeben die Klasse) kann bei Bedarf verstanden werden.

-   **Vorteile:** **Sehr schnelles** Training und schnelle Vorhersagen, auch bei großen Datensätzen (linear zur Anzahl der Instanzen * Anzahl der Merkmale). Erfordert relativ wenige Daten, um Wahrscheinlichkeiten zuverlässig zu schätzen, insbesondere bei geeigneter Glättung. Als Baseline ist der Algorithmus oft überraschend genau, vor allem wenn Merkmale unabhängig voneinander zur Evidenz für eine Klasse beitragen. Funktioniert gut mit hochdimensionalen Daten (z. B. Tausenden von Merkmalen aus Texten). Außer der Festlegung eines Glättungsparameters ist keine komplexe Abstimmung erforderlich.

-   **Einschränkungen:** Die Unabhängigkeitsannahme kann die Genauigkeit einschränken, wenn Merkmale stark korreliert sind. Beispielsweise können in Netzwerkdaten Merkmale wie `src_bytes` und `dst_bytes` korreliert sein; Naive Bayes erfasst diese Wechselwirkung nicht. Wenn die Datenmenge sehr groß wird, können ausdrucksstärkere Modelle (wie Ensembles oder neuronale Netze) NB übertreffen, da sie Merkmalsabhängigkeiten lernen. Wenn außerdem eine bestimmte Kombination von Merkmalen erforderlich ist, um einen Angriff zu identifizieren (und nicht nur einzelne Merkmale unabhängig voneinander), wird NB Schwierigkeiten haben.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Der klassische Anwendungsfall ist die **Spam-Erkennung** -- Naive Bayes bildete den Kern früher Spamfilter. Dabei wurden die Häufigkeiten bestimmter Tokens (Wörter, Phrasen, IP-Adressen) verwendet, um die Wahrscheinlichkeit zu berechnen, dass eine E-Mail Spam ist. Der Algorithmus wird außerdem bei der **Erkennung von Phishing-E-Mails** und der **URL-Klassifizierung** eingesetzt, bei denen das Vorhandensein bestimmter Schlüsselwörter oder Merkmale (wie "login.php" in einer URL oder `@` in einem URL-Pfad) zur Phishing-Wahrscheinlichkeit beitragen. Bei der Malware-Analyse könnte man sich einen Naive-Bayes-Klassifikator vorstellen, der das Vorhandensein bestimmter API-Aufrufe oder Berechtigungen in Software verwendet, um vorherzusagen, ob es sich um Malware handelt. Obwohl fortschrittlichere Algorithmen häufig bessere Ergebnisse liefern, bleibt Naive Bayes aufgrund seiner Geschwindigkeit und Einfachheit eine gute Baseline.

<details>
<summary>Beispiel -- Naive Bayes zur Phishing-Erkennung:</summary>
Zur Demonstration von Naive Bayes verwenden wir Gaussian Naive Bayes für den NSL-KDD-Intrusion-Datensatz (mit binären Labels). Gaussian NB behandelt jedes Merkmal so, als würde es pro Klasse einer Normalverteilung folgen. Dies ist eine grobe Wahl, da viele Netzwerkmerkmale diskret oder stark verzerrt sind, zeigt aber, wie NB auf kontinuierliche Merkmalsdaten angewendet werden kann. Wir könnten auch Bernoulli NB für einen Datensatz mit binären Merkmalen auswählen (beispielsweise eine Menge ausgelöster Alerts), bleiben hier zur besseren Kontinuität jedoch bei NSL-KDD.
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
Dieser Code trainiert einen Naive-Bayes-Klassifikator zur Erkennung von Angriffen. Naive Bayes berechnet anhand der Trainingsdaten Werte wie `P(service=http | Attack)` und `P(Service=http | Normal)` und nimmt dabei die Unabhängigkeit der Merkmale an. Anschließend verwendet er diese Wahrscheinlichkeiten, um neue Verbindungen anhand der beobachteten Merkmale entweder als normal oder als Angriff zu klassifizieren. Die Leistung von NB auf NSL-KDD ist möglicherweise nicht so hoch wie die fortgeschrittenerer Modelle (da die Merkmalsunabhängigkeit verletzt wird), ist aber oft dennoch ordentlich und bietet den Vorteil extremer Geschwindigkeit. In Szenarien wie der Echtzeit-E-Mail-Filterung oder der ersten Triage von URLs kann ein Naive-Bayes-Modell offensichtlich bösartige Fälle schnell und mit geringem Ressourcenverbrauch markieren.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ist einer der einfachsten Machine-Learning-Algorithmen. Es handelt sich um eine **nichtparametrische, instanzbasierte** Methode, die Vorhersagen anhand der Ähnlichkeit zu Beispielen aus dem Trainingsdatensatz trifft. Die Idee bei der Klassifizierung lautet: Um einen neuen Datenpunkt zu klassifizieren, werden die **k** nächstgelegenen Punkte in den Trainingsdaten (seine „nächsten Nachbarn“) gefunden und die Mehrheitsklasse unter diesen Nachbarn zugewiesen. Die „Nähe“ wird durch eine Distanzmetrik definiert, typischerweise die euklidische Distanz für numerische Daten (für unterschiedliche Merkmalstypen oder Problemstellungen können andere Distanzen verwendet werden).<sup>[[10]](#references)</sup>

K-NN benötigt *kein explizites Training* -- die „Trainingsphase“ besteht lediglich darin, den Datensatz zu speichern. Die gesamte Arbeit findet während der Abfrage (Vorhersage) statt: Der Algorithmus muss die Distanzen vom Abfragepunkt zu allen Trainingspunkten berechnen, um die nächstgelegenen Punkte zu finden. Dadurch ist die Vorhersagezeit **linear zur Anzahl der Trainingsbeispiele**, was bei großen Datensätzen kostspielig sein kann. Aus diesem Grund eignet sich k-NN am besten für kleinere Datensätze oder Szenarien, in denen man zugunsten von Einfachheit einen höheren Speicherbedarf und eine geringere Geschwindigkeit in Kauf nehmen kann.

Trotz seiner Einfachheit kann k-NN sehr komplexe Entscheidungsgrenzen modellieren (da die Entscheidungsgrenze effektiv jede durch die Verteilung der Beispiele vorgegebene Form annehmen kann). Die Methode funktioniert tendenziell gut, wenn die Entscheidungsgrenze sehr unregelmäßig ist und viele Daten vorhanden sind -- im Wesentlichen lässt sie die Daten „für sich selbst sprechen“. In hohen Dimensionen können Distanzmetriken jedoch an Aussagekraft verlieren (Fluch der Dimensionalität), und die Methode kann Schwierigkeiten bekommen, sofern nicht eine sehr große Anzahl an Beispielen vorhanden ist.

*Einsatzbereiche in der Cybersicherheit:* k-NN wurde bei der Anomalieerkennung eingesetzt -- beispielsweise könnte ein Intrusion-Detection-System ein Netzwerkereignis als bösartig markieren, wenn die meisten seiner nächsten Nachbarn (frühere Ereignisse) bösartig waren. Wenn normaler Traffic Cluster bildet und Angriffe Ausreißer sind, entspricht ein K-NN-Ansatz (mit k=1 oder einem kleinen k) im Wesentlichen einer **Anomalieerkennung durch den nächsten Nachbarn**. K-NN wurde auch zur Klassifizierung von Malware-Familien anhand binärer Merkmalsvektoren verwendet: Eine neue Datei könnte als Mitglied einer bestimmten Malware-Familie klassifiziert werden, wenn sie im Merkmalsraum bekannten Instanzen dieser Familie sehr ähnlich ist. In der Praxis ist k-NN nicht so verbreitet wie besser skalierbare Algorithmen, wird aber aufgrund seiner konzeptionellen Einfachheit gelegentlich als Baseline oder für Probleme kleineren Umfangs eingesetzt.

#### **Wichtige Eigenschaften von k-NN:**

-   **Art des Problems:** Klassifizierung (Varianten für Regression existieren ebenfalls). Es handelt sich um eine *Lazy-Learning*-Methode -- es findet keine explizite Modellanpassung statt.

-   **Interpretierbarkeit:** Niedrig bis mittel -- es gibt kein globales Modell und keine prägnante Erklärung, aber die Ergebnisse können durch Betrachtung der nächsten Nachbarn interpretiert werden, die eine Entscheidung beeinflusst haben (z. B. „Dieser Netzwerkfluss wurde als bösartig klassifiziert, weil er diesen 3 bekannten bösartigen Netzwerkflüssen ähnelt“). Erklärungen können somit beispielbasiert sein.

-   **Vorteile:** Sehr einfach zu implementieren und zu verstehen. Macht keine Annahmen über die Datenverteilung (nichtparametrisch). Kann Mehrklassenprobleme auf natürliche Weise verarbeiten. Ist insofern **adaptiv**, als die Entscheidungsgrenzen sehr komplex sein und durch die Datenverteilung geformt werden können.

-   **Einschränkungen:** Die Vorhersage kann bei großen Datensätzen langsam sein (es müssen viele Distanzen berechnet werden). Hoher Speicherbedarf -- alle Trainingsdaten werden gespeichert. Die Leistung nimmt in hochdimensionalen Merkmalsräumen ab, da alle Punkte tendenziell nahezu gleich weit voneinander entfernt sind (wodurch das Konzept des „nächsten“ Punkts an Bedeutung verliert). *k* (die Anzahl der Nachbarn) muss passend gewählt werden -- ein zu kleines k kann zu verrauschten Ergebnissen führen, ein zu großes k kann irrelevante Punkte aus anderen Klassen einbeziehen. Außerdem sollten die Merkmale angemessen skaliert werden, da Distanzberechnungen empfindlich auf unterschiedliche Skalierungen reagieren.

<details>
<summary>Beispiel -- k-NN zur Phishing-Erkennung:</summary>

Wir werden erneut NSL-KDD verwenden (binäre Klassifizierung). Da k-NN rechenintensiv ist, verwenden wir eine Teilmenge der Trainingsdaten, damit die Demonstration praktikabel bleibt. Wir wählen beispielsweise 20.000 Trainingsbeispiele aus den insgesamt 125.000 aus und verwenden k=5 Nachbarn. Nach dem Training (das tatsächlich nur im Speichern der Daten besteht) evaluieren wir das Modell anhand des Testdatensatzes. Außerdem skalieren wir die Merkmale für die Distanzberechnung, um sicherzustellen, dass aufgrund unterschiedlicher Skalierungen kein einzelnes Merkmal dominiert.
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
Das k-NN-Modell klassifiziert eine Verbindung, indem es die 5 nächstgelegenen Verbindungen in der Teilmenge des Trainingssatzes betrachtet. Wenn beispielsweise 4 dieser Nachbarn Angriffe (Anomalien) und 1 normal ist, wird die neue Verbindung als Angriff klassifiziert. Die Leistung kann angemessen sein, liegt jedoch häufig nicht so hoch wie bei einem gut abgestimmten Random Forest oder SVM auf denselben Daten. Allerdings kann k-NN manchmal bei sehr unregelmäßigen und komplexen Klassenverteilungen glänzen -- es verwendet effektiv eine speicherbasierte Suche. In der cybersecurity könnte k-NN (mit k=1 oder einem kleinen k) zur Erkennung bekannter Angriffsmuster anhand von Beispielen oder als Komponente komplexerer Systeme eingesetzt werden (z. B. zum Clustering und anschließenden Klassifizieren anhand der Clusterzugehörigkeit).
</details>

### Gradient Boosting Machines (z. B. XGBoost)

Gradient Boosting Machines gehören zu den leistungsfähigsten Algorithmen für strukturierte Daten. **Gradient boosting** bezeichnet die Technik, ein Ensemble schwacher Lerner (häufig Entscheidungsbäume) sequenziell aufzubauen, wobei jedes neue Modell die Fehler des vorherigen Ensembles korrigiert. Im Gegensatz zu Bagging (Random Forests), bei dem Bäume parallel erstellt und anschließend gemittelt werden, baut Boosting die Bäume *einen nach dem anderen* auf, wobei sich jeder stärker auf die Instanzen konzentriert, die von den vorherigen Bäumen falsch vorhergesagt wurden.<sup>[[11]](#references)</sup>

Die beliebtesten Implementierungen der letzten Jahre sind **XGBoost**, **LightGBM** und **CatBoost**; bei allen handelt es sich um Bibliotheken für Gradient Boosting Decision Trees (GBDT). Sie waren bei Machine-Learning-Wettbewerben und in praktischen Anwendungen äußerst erfolgreich und **erreichen bei tabellarischen Datensätzen häufig eine Leistung auf dem neuesten Stand der Technik**. In der cybersecurity haben Forscher und Praktiker Gradient-Boosted Trees für Aufgaben wie **malware detection** (unter Verwendung aus Dateien oder Laufzeitverhalten extrahierter Merkmale) und **network intrusion detection** eingesetzt. Beispielsweise kann ein Gradient-Boosting-Modell viele schwache Regeln (Bäume) wie „wenn viele SYN-Pakete und ein ungewöhnlicher Port -> wahrscheinlich Scan“ zu einem starken kombinierten Detektor verbinden, der zahlreiche subtile Muster berücksichtigt.

Warum sind Boosted Trees so effektiv? Jeder Baum in der Sequenz wird anhand der *residual errors* (Gradienten) der aktuellen Vorhersagen des Ensembles trainiert. Auf diese Weise **„boostet“** das Modell schrittweise die Bereiche, in denen es schwach ist. Durch die Verwendung von Entscheidungsbäumen als Basislerner kann das endgültige Modell komplexe Wechselwirkungen und nichtlineare Beziehungen erfassen. Außerdem beinhaltet Boosting von Natur aus eine Form der integrierten Regularisierung: Durch das Hinzufügen vieler kleiner Bäume (und die Verwendung einer Lernrate zur Skalierung ihrer Beiträge) generalisiert es häufig gut, ohne starkes Overfitting, sofern geeignete Parameter gewählt werden.

#### **Wichtige Eigenschaften von Gradient Boosting:**

-   **Problemtyp:** Primär Klassifikation und Regression. In der security meist Klassifikation (z. B. binäre Klassifizierung einer Verbindung oder Datei). Es verarbeitet binäre und Multi-Class-Probleme (mit entsprechendem Loss) sowie Ranking-Probleme.

-   **Interpretierbarkeit:** Niedrig bis mittel. Während ein einzelner Boosted Tree klein ist, kann ein vollständiges Modell Hunderte von Bäumen enthalten und ist als Ganzes nicht für Menschen interpretierbar. Wie Random Forest kann es jedoch Feature-Importance-Werte bereitstellen, und Tools wie SHAP (SHapley Additive exPlanations) können verwendet werden, um einzelne Vorhersagen bis zu einem gewissen Grad zu interpretieren.

-   **Vorteile:** Häufig der **leistungsstärkste** Algorithmus für strukturierte/tabellarische Daten. Kann komplexe Muster und Wechselwirkungen erkennen. Verfügt über viele Stellschrauben (Anzahl der Bäume, Tiefe der Bäume, Lernrate, Regularisierungsterme), um die Modellkomplexität anzupassen und Overfitting zu verhindern. Moderne Implementierungen sind auf Geschwindigkeit optimiert (z. B. verwendet XGBoost Informationen über Gradienten zweiter Ordnung und effiziente Datenstrukturen). Bewältigt unausgeglichene Daten tendenziell besser, wenn geeignete Loss-Funktionen verwendet oder die Sample-Gewichte angepasst werden.

-   **Einschränkungen:** Schwieriger abzustimmen als einfachere Modelle; das Training kann langsam sein, wenn die Bäume tief sind oder die Anzahl der Bäume groß ist (obwohl es in der Regel immer noch schneller ist als das Training eines vergleichbaren Deep Neural Network auf denselben Daten). Das Modell kann Overfitting verursachen, wenn es nicht abgestimmt wird (z. B. zu viele tiefe Bäume bei unzureichender Regularisierung). Aufgrund der vielen Hyperparameter kann die effektive Verwendung von Gradient Boosting mehr Fachwissen oder Experimente erfordern. Außerdem verarbeitet es wie baumbasierte Methoden sehr spärliche, hochdimensionale Daten nicht von sich aus so effizient wie lineare Modelle oder Naive Bayes (obwohl es weiterhin eingesetzt werden kann, z. B. bei der Textklassifikation, aber ohne Feature Engineering möglicherweise nicht die erste Wahl ist).

> [!TIP]
> *Einsatzmöglichkeiten in der cybersecurity:* Nahezu überall dort, wo ein Entscheidungsbaum oder Random Forest eingesetzt werden könnte, kann ein Gradient-Boosting-Modell eine bessere Genauigkeit erreichen. Beispielsweise wurde bei **Microsofts malware detection**-Wettbewerben XGBoost häufig auf entwickelten Merkmalen aus Binärdateien eingesetzt. Die Forschung zu **network intrusion detection** berichtet häufig über Spitzenresultate mit GBDTs (z. B. XGBoost auf den Datensätzen CIC-IDS2017 oder UNSW-NB15). Diese Modelle können eine große Bandbreite an Merkmalen (Protokolltypen, Häufigkeit bestimmter Ereignisse, statistische Merkmale des Datenverkehrs usw.) verarbeiten und zu deren Erkennung kombinieren. Bei der Phishing-Erkennung kann Gradient Boosting lexikalische Merkmale von URLs, Merkmale der Domain-Reputation und Merkmale des Seiteninhalts kombinieren, um eine sehr hohe Genauigkeit zu erreichen. Der Ensemble-Ansatz hilft dabei, viele Sonderfälle und Feinheiten in den Daten abzudecken.

<details>
<summary>Beispiel -- XGBoost zur Phishing-Erkennung:</summary>
Wir verwenden einen Gradient-Boosting-Klassifikator für den Phishing-Datensatz. Um die Dinge einfach und eigenständig zu halten, verwenden wir `sklearn.ensemble.GradientBoostingClassifier` (eine langsamere, aber unkomplizierte Implementierung). Normalerweise könnte man die Bibliotheken `xgboost` oder `lightgbm` für eine bessere Leistung und zusätzliche Funktionen verwenden. Wir trainieren das Modell und bewerten es ähnlich wie zuvor.
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
Das Gradient-Boosting-Modell wird auf diesem Phishing-Datensatz wahrscheinlich eine sehr hohe Accuracy und AUC erreichen (solche Modelle können bei geeigneter Abstimmung auf derartigen Daten oft eine Accuracy von über 95 % erzielen, wie es in der Literatur zu sehen ist). Dies zeigt, warum GBDTs als *„the state of the art model for tabular dataset“* gelten -- sie übertreffen häufig einfachere Algorithmen, da sie komplexe Muster erfassen.<sup>[[11]](#references)</sup> Im Bereich der Cybersicherheit könnte dies bedeuten, mehr Phishing-Seiten oder Angriffe zu erkennen und gleichzeitig weniger Treffer zu übersehen. Natürlich muss man sich vor Overfitting in Acht nehmen -- bei der Entwicklung eines solchen Modells für den produktiven Einsatz würden wir typischerweise Techniken wie Cross-Validation verwenden und die Leistung auf einem Validation Set überwachen.

</details>

### Modelle kombinieren: Ensemble Learning und Stacking

Ensemble Learning ist eine Strategie zur **Kombination mehrerer Modelle**, um die Gesamtleistung zu verbessern. Wir haben bereits spezifische Ensemble-Methoden kennengelernt: Random Forest (ein Ensemble aus Bäumen mittels Bagging) und Gradient Boosting (ein Ensemble aus Bäumen mittels sequenziellem Boosting). Ensembles können jedoch auch auf andere Weise erstellt werden, etwa als **Voting Ensembles** oder mittels **Stacked Generalization (Stacking)**. Die Grundidee besteht darin, dass verschiedene Modelle unterschiedliche Muster erfassen oder unterschiedliche Schwächen haben können; durch ihre Kombination können wir **die Fehler eines einzelnen Modells durch die Stärken eines anderen ausgleichen**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble:** Bei einem einfachen Voting Classifier trainieren wir mehrere unterschiedliche Modelle (zum Beispiel eine logistische Regression, einen Decision Tree und einen SVM) und lassen sie über die endgültige Prediction abstimmen (bei Classification entscheidet die Mehrheit). Wenn wir die Stimmen gewichten (zum Beispiel genaueren Modellen ein höheres Gewicht geben), handelt es sich um ein gewichtetes Voting-Verfahren. Dies verbessert die Leistung typischerweise, wenn die einzelnen Modelle ausreichend gut und unabhängig sind -- das Ensemble verringert das Risiko eines Fehlers durch ein einzelnes Modell, da andere Modelle diesen möglicherweise korrigieren. Es ist vergleichbar mit einem Expertengremium statt einer einzigen Meinung.

-   **Stacking (Stacked Ensemble):** Stacking geht einen Schritt weiter. Statt einer einfachen Abstimmung trainiert es ein **Meta-Modell**, um zu **lernen, wie die Predictions der Basismodelle am besten kombiniert werden**. Zum Beispiel trainiert man 3 verschiedene Classifier (Base Learner) und übergibt deren Ausgaben (oder Wahrscheinlichkeiten) als Features an einen Meta-Classifier (häufig ein einfaches Modell wie eine logistische Regression), der die optimale Kombination erlernt. Das Meta-Modell wird auf einem Validation Set oder mittels Cross-Validation trainiert, um Overfitting zu vermeiden. Stacking kann ein einfaches Voting oft übertreffen, da es lernt, *welchen Modellen unter welchen Umständen stärker vertraut werden sollte*. In der Cybersicherheit könnte ein Modell besser darin sein, Network Scans zu erkennen, während ein anderes Malware Beaconing besser erkennt; ein Stacking-Modell könnte lernen, sich jeweils angemessen auf das entsprechende Modell zu stützen.

Ensembles, ob durch Voting oder Stacking, neigen dazu, **Accuracy** und Robustheit zu verbessern. Der Nachteil besteht in der höheren Komplexität und manchmal geringeren Interpretierbarkeit (obwohl einige Ensemble-Ansätze, etwa ein Durchschnitt aus Decision Trees, weiterhin gewisse Einblicke ermöglichen können, zum Beispiel durch Feature Importance). In der Praxis kann der Einsatz eines Ensembles zu höheren Detection-Raten führen, sofern die betrieblichen Rahmenbedingungen dies erlauben. Viele erfolgreiche Lösungen bei Cybersecurity-Challenges (und allgemein bei Kaggle-Wettbewerben) verwenden Ensemble-Techniken, um auch die letzten Leistungsreserven auszuschöpfen.

<details>
<summary>Beispiel -- Voting Ensemble zur Phishing-Erkennung:</summary>
Um Model Stacking zu veranschaulichen, kombinieren wir einige der Modelle, die wir für den Phishing-Datensatz besprochen haben. Wir verwenden eine logistische Regression, einen Decision Tree und ein k-NN als Base Learner und einen Random Forest als Meta-Learner, um ihre Predictions zu aggregieren. Der Meta-Learner wird anhand der Ausgaben der Base Learner trainiert (unter Verwendung von Cross-Validation auf dem Trainingset). Wir erwarten, dass das Stacked-Modell genauso gut oder geringfügig besser abschneidet als die einzelnen Modelle.
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
Das gestapelte Ensemble nutzt die komplementären Stärken der Basismodelle. Beispielsweise könnte die logistische Regression lineare Aspekte der Daten verarbeiten, der Entscheidungsbaum spezifische regelähnliche Interaktionen erfassen und k-NN in lokalen Bereichen des Merkmalsraums besonders leistungsfähig sein. Das Meta-Modell (hier ein Random Forest) kann lernen, wie diese Eingaben gewichtet werden sollen. Die resultierenden Metriken zeigen häufig eine Verbesserung (auch wenn sie gering ausfällt) gegenüber den Metriken jedes einzelnen Modells. In unserem Phishing-Beispiel könnte die logistische Regression allein beispielsweise einen F1-Wert von 0.95 und der Baum einen Wert von 0.94 erreichen, während das Stack-Modell durch die Kombination der jeweiligen Stärken einen Wert von 0.96 erzielt.

Ensemble-Methoden wie diese veranschaulichen das Prinzip, dass *„die Kombination mehrerer Modelle typischerweise zu einer besseren Generalisierung führt“*.<sup>[[12]](#references)</sup> In der Cybersecurity kann dies umgesetzt werden, indem mehrere Detection Engines eingesetzt werden (eine könnte regelbasiert, eine auf Machine Learning und eine anomaliebasiert sein) und anschließend eine weitere Ebene deren Alerts aggregiert -- effektiv eine Form eines Ensembles --, um eine endgültige Entscheidung mit höherer Konfidenz zu treffen. Bei der Bereitstellung solcher Systeme müssen die zusätzliche Komplexität berücksichtigt und Maßnahmen getroffen werden, damit das Ensemble nicht zu schwierig zu verwalten oder zu erklären wird. Aus Sicht der Genauigkeit sind Ensembles und Stacking jedoch leistungsfähige Werkzeuge zur Verbesserung der Modellleistung.

</details>

## Referenzen

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
