# Algorithmen des überwachten Lernens

{{#include ../banners/hacktricks-training.md}}

## Grundlegende Informationen

Beim überwachten Lernen werden gelabelte Daten verwendet, um Modelle zu trainieren, die Vorhersagen für neue, bisher unbekannte Eingaben treffen können. In der Cybersicherheit wird überwachtes Machine Learning häufig für Aufgaben wie Intrusion Detection (Klassifizierung des Netzwerkverkehrs als *normal* oder *Angriff*), Malware-Erkennung (Unterscheidung zwischen bösartiger und gutartiger Software), Phishing-Erkennung (Identifizierung betrügerischer Websites oder E-Mails) und Spam-Filterung eingesetzt.<sup>[[1]](#references)</sup> Jeder Algorithmus hat seine Stärken und eignet sich für unterschiedliche Problemtypen (Klassifikation oder Regression). Im Folgenden betrachten wir wichtige Algorithmen des überwachten Lernens, erklären ihre Funktionsweise und demonstrieren ihre Anwendung auf realen Cybersecurity-Datensätzen. Außerdem zeigen wir, wie die Kombination von Modellen (Ensemble Learning) die Vorhersageleistung häufig verbessern kann.

## Algorithmen

-   **Lineare Regression:** Ein grundlegender Regressionsalgorithmus zur Vorhersage numerischer Ergebnisse durch Anpassung einer linearen Gleichung an Daten.

-   **Logistische Regression:** Ein Klassifikationsalgorithmus (trotz seines Namens), der eine logistische Funktion verwendet, um die Wahrscheinlichkeit eines binären Ergebnisses zu modellieren.

-   **Entscheidungsbäume:** Baumstrukturierte Modelle, die Daten anhand von Merkmalen aufteilen, um Vorhersagen zu treffen; sie werden häufig wegen ihrer Interpretierbarkeit eingesetzt.

-   **Random Forests:** Ein Ensemble aus Entscheidungsbäumen (mittels Bagging), das die Genauigkeit verbessert und Overfitting reduziert.

-   **Support Vector Machines (SVM):** Klassifikatoren mit maximalem Rand, die die optimale trennende Hyperebene bestimmen; für nichtlineare Daten können Kernel verwendet werden.

-   **Naive Bayes:** Ein probabilistischer Klassifikator auf Grundlage des Satzes von Bayes mit der Annahme unabhängiger Merkmale, der bekanntermaßen bei der Spam-Filterung eingesetzt wird.

-   **k-Nearest Neighbors (k-NN):** Ein einfacher „instanzbasierter“ Klassifikator, der einem Sample die Mehrheitsklasse seiner nächsten Nachbarn zuweist.

-   **Gradient Boosting Machines:** Ensemble-Modelle (z. B. XGBoost, LightGBM), die durch das schrittweise Hinzufügen schwächerer Lerner (typischerweise Entscheidungsbäume) einen starken Prädiktor erstellen.

Jeder folgende Abschnitt enthält eine verbesserte Beschreibung des Algorithmus sowie ein **Python-Codebeispiel**, das Bibliotheken wie `pandas` und `scikit-learn` (und `PyTorch` für das Beispiel mit dem neuronalen Netzwerk) verwendet. Die Beispiele nutzen öffentlich verfügbare Cybersecurity-Datensätze (wie NSL-KDD für Intrusion Detection und einen Phishing-Websites-Datensatz) und folgen einer einheitlichen Struktur:

1.  **Datensatz laden** (falls verfügbar per URL herunterladen).

2.  **Daten vorverarbeiten** (z. B. kategoriale Merkmale codieren, Werte skalieren, Daten in Trainings- und Testmengen aufteilen).

3.  **Modell** mit den Trainingsdaten trainieren.

4.  **Auf einem Testsatz evaluieren** unter Verwendung der Metriken Accuracy, Precision, Recall, F1-Score und ROC AUC für die Klassifikation (sowie des mittleren quadratischen Fehlers für die Regression).

Sehen wir uns die einzelnen Algorithmen an:

### Lineare Regression

Die lineare Regression ist ein **Regressionsalgorithmus**, der zur Vorhersage kontinuierlicher numerischer Werte verwendet wird. Sie nimmt eine lineare Beziehung zwischen den Eingabemerkmalen (unabhängigen Variablen) und der Ausgabe (abhängigen Variable) an. Das Modell versucht, eine gerade Linie (oder in höheren Dimensionen eine Hyperebene) anzupassen, die die Beziehung zwischen den Merkmalen und dem Zielwert am besten beschreibt. Dies geschieht typischerweise durch die Minimierung der Summe der quadrierten Fehler zwischen den vorhergesagten und den tatsächlichen Werten (Ordinary-Least-Squares-Methode).<sup>[[2]](#references)</sup>

Die einfachste Form, lineare Regression darzustellen, ist eine Linie:
```plaintext
y = mx + b
```
Dabei gilt:

- `y` ist der vorhergesagte Wert (Ausgabe)
- `m` ist die Steigung der Linie (Koeffizient)
- `x` ist das Eingabemerkmal
- `b` ist der y-Achsenabschnitt

Das Ziel der linearen Regression besteht darin, die am besten passende Linie zu finden, die den Unterschied zwischen den vorhergesagten Werten und den tatsächlichen Werten im Datensatz minimiert. Natürlich ist dies sehr einfach: Es wäre eine gerade Linie, die 2 Kategorien voneinander trennt. Wenn jedoch weitere Dimensionen hinzugefügt werden, wird die Linie komplexer:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Lineare Regression ist für zentrale Security-Aufgaben weniger verbreitet (bei denen es sich häufig um Klassifikation handelt), kann aber zur Vorhersage numerischer Ergebnisse eingesetzt werden. Beispielsweise kann man lineare Regression verwenden, um **das Volumen des Netzwerkverkehrs vorherzusagen** oder **die Anzahl der Angriffe in einem bestimmten Zeitraum zu schätzen**, basierend auf historischen Daten. Sie kann außerdem einen Risiko-Score oder die erwartete Zeit bis zur Erkennung eines Angriffs anhand bestimmter Systemmetriken vorhersagen. In der Praxis werden Klassifikationsalgorithmen (wie logistische Regression oder Bäume) häufiger zur Erkennung von Intrusionen oder Malware eingesetzt, aber lineare Regression dient als Grundlage und ist für regressionsorientierte Analysen nützlich.

#### **Wichtige Merkmale der linearen Regression:**

-   **Problemtyp:** Regression (Vorhersage kontinuierlicher Werte). Für die direkte Klassifikation nicht geeignet, sofern nicht ein Schwellenwert auf die Ausgabe angewendet wird.

-   **Interpretierbarkeit:** Hoch -- Koeffizienten sind einfach zu interpretieren und zeigen den linearen Effekt jedes Features.

-   **Vorteile:** Einfach und schnell; eine gute Baseline für Regressionsaufgaben; funktioniert gut, wenn die tatsächliche Beziehung ungefähr linear ist.

-   **Einschränkungen:** Kann komplexe oder nichtlineare Beziehungen nicht erfassen (ohne manuelles Feature Engineering); neigt bei nichtlinearen Beziehungen zu Underfitting; empfindlich gegenüber Ausreißern, die die Ergebnisse verzerren können.

-   **Best Fit finden:** Um die Best-Fit-Linie zu finden, die die möglichen Kategorien trennt, verwenden wir eine Methode namens **Ordinary Least Squares (OLS)**. Diese Methode minimiert die Summe der quadrierten Differenzen zwischen den beobachteten Werten und den vom linearen Modell vorhergesagten Werten.

<details>
<summary>Beispiel -- Vorhersage der Verbindungsdauer (Regression) in einem Intrusion-Datensatz
</summary>
Im Folgenden demonstrieren wir lineare Regression anhand des NSL-KDD-Cybersecurity-Datensatzes. Wir behandeln dies als Regressionsproblem, indem wir die `duration` von Netzwerkverbindungen anhand anderer Features vorhersagen. (In der Realität ist `duration` ein Feature von NSL-KDD; hier verwenden wir es lediglich zur Veranschaulichung von Regression.) Wir laden den Datensatz, führen eine Vorverarbeitung durch (Kodierung kategorialer Features), trainieren ein lineares Regressionsmodell und bewerten den Mean Squared Error (MSE) sowie den R²-Score anhand eines Testdatensatzes.
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
In diesem Beispiel versucht das lineare Regressionsmodell, die Verbindungs-`duration` anhand anderer Netzwerkmerkmale vorherzusagen. Wir messen die Leistung mit dem Mean Squared Error (MSE) und R². Ein R²-Wert nahe 1,0 würde darauf hindeuten, dass das Modell den Großteil der Varianz von `duration` erklärt, während ein niedriger oder negativer R²-Wert auf eine schlechte Anpassung hindeutet. (Es ist nicht überraschend, wenn der R²-Wert hier niedrig ist -- die Vorhersage von `duration` anhand der gegebenen Merkmale könnte schwierig sein, und die lineare Regression kann die Muster möglicherweise nicht erfassen, wenn diese komplex sind.)
</details>

### Logistische Regression

Die logistische Regression ist ein **Klassifikationsalgorithmus**, der die Wahrscheinlichkeit modelliert, dass eine Instanz zu einer bestimmten Klasse gehört (typischerweise zur „positiven“ Klasse). Trotz ihres Namens wird die *logistische* Regression für diskrete Ergebnisse verwendet (im Gegensatz zur linearen Regression, die für kontinuierliche Ergebnisse eingesetzt wird). Sie wird insbesondere für die **binäre Klassifikation** verwendet (zwei Klassen, z. B. bösartig vs. harmlos), kann jedoch auf Probleme mit mehreren Klassen erweitert werden (mithilfe von softmax- oder One-vs-Rest-Ansätzen).<sup>[[3]](#references)</sup>

Die logistische Regression verwendet die logistische Funktion (auch als Sigmoidfunktion bezeichnet), um vorhergesagte Werte auf Wahrscheinlichkeiten abzubilden. Beachte, dass die Sigmoidfunktion eine Funktion mit Werten zwischen 0 und 1 ist, die je nach den Anforderungen der Klassifikation in einer S-förmigen Kurve ansteigt, was für Aufgaben der binären Klassifikation nützlich ist. Daher wird jedes Merkmal jeder Eingabe mit seinem zugewiesenen Gewicht multipliziert, und das Ergebnis wird durch die Sigmoidfunktion geleitet, um eine Wahrscheinlichkeit zu erzeugen:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Wo:

- `p(y=1|x)` ist die Wahrscheinlichkeit, dass die Ausgabe `y` bei der Eingabe `x` den Wert 1 hat
- `e` ist die Basis des natürlichen Logarithmus
- `z` ist eine lineare Kombination der Eingabemerkmale, typischerweise dargestellt als `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Beachte, dass es auch hier in seiner einfachsten Form eine gerade Linie ist, in komplexeren Fällen jedoch zu einer Hyperebene mit mehreren Dimensionen wird (eine pro Merkmal).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Da viele Sicherheitsprobleme im Wesentlichen Ja/Nein-Entscheidungen sind, wird Logistic Regression häufig eingesetzt. Beispielsweise könnte ein Intrusion-Detection-System Logistic Regression verwenden, um anhand der Merkmale einer Netzwerkverbindung zu entscheiden, ob es sich um einen Angriff handelt. Bei der Phishing-Erkennung kann Logistic Regression Merkmale einer Website (URL-Länge, Vorhandensein des Symbols „@“ usw.) zu einer Wahrscheinlichkeit zusammenfassen, dass es sich um Phishing handelt. Sie wurde in Spam-Filtern der frühen Generation eingesetzt und ist weiterhin eine starke Baseline für viele Classification-Aufgaben.

#### Logistic Regression für nicht binäre Classification

Logistic Regression ist für binäre Classification konzipiert, kann aber mithilfe von Techniken wie **one-vs-rest** (OvR) oder **softmax regression** auf Multi-Class-Probleme erweitert werden. Bei OvR wird für jede Klasse ein separates Logistic-Regression-Modell trainiert, wobei diese Klasse als positive Klasse gegenüber allen anderen behandelt wird. Die Klasse mit der höchsten vorhergesagten Wahrscheinlichkeit wird als endgültige Vorhersage ausgewählt. Softmax regression verallgemeinert Logistic Regression auf mehrere Klassen, indem die Softmax-Funktion auf die Ausgabeschicht angewendet wird und eine Wahrscheinlichkeitsverteilung über alle Klassen erzeugt wird.

#### **Wichtige Eigenschaften von Logistic Regression:**

-   **Art des Problems:** Classification (gewöhnlich binär). Es wird die Wahrscheinlichkeit der positiven Klasse vorhergesagt.

-   **Interpretierbarkeit:** Hoch -- wie bei Linear Regression können die Merkmalskoeffizienten anzeigen, wie jedes Merkmal die Log-Odds des Ergebnisses beeinflusst. Diese Transparenz wird in der Security häufig geschätzt, um zu verstehen, welche Faktoren zu einem Alert beitragen.

-   **Vorteile:** Einfach und schnell zu trainieren; funktioniert gut, wenn die Beziehung zwischen den Merkmalen und den Log-Odds des Ergebnisses linear ist. Gibt Wahrscheinlichkeiten aus und ermöglicht dadurch ein Risk Scoring. Mit geeigneter Regularisierung generalisiert das Modell gut und kann Multikollinearität besser handhaben als eine einfache Linear Regression.

-   **Einschränkungen:** Nimmt eine lineare Entscheidungsgrenze im Merkmalsraum an (versagt, wenn die tatsächliche Grenze komplex/nicht linear ist). Bei Problemen, bei denen Interaktionen oder nicht lineare Effekte entscheidend sind, kann die Leistung geringer sein, sofern nicht manuell polynomiale oder Interaktionsmerkmale hinzugefügt werden. Außerdem ist Logistic Regression weniger effektiv, wenn Klassen nicht leicht durch eine lineare Kombination von Merkmalen separiert werden können.


<details>
<summary>Beispiel -- Erkennung von Phishing-Websites mit Logistic Regression:</summary>

Wir verwenden einen **Phishing Websites Dataset** (aus dem UCI-Repository), der extrahierte Merkmale von Websites enthält (z. B. ob die URL eine IP-Adresse enthält, das Alter der Domain, das Vorhandensein verdächtiger Elemente im HTML usw.) sowie ein Label, das angibt, ob die Website Phishing ist oder legitim.<sup>[[4]](#references)</sup> Wir trainieren ein Logistic-Regression-Modell, um Websites zu klassifizieren, und bewerten anschließend dessen Accuracy, Precision, Recall, F1-Score und ROC AUC anhand einer Testaufteilung.
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
In diesem Phishing-Erkennungsbeispiel erzeugt die logistische Regression für jede Website eine Wahrscheinlichkeit dafür, dass es sich um eine Phishing-Website handelt. Durch die Bewertung von Genauigkeit, Präzision, Recall und F1 erhalten wir einen Eindruck von der Leistung des Modells. Ein hoher Recall würde beispielsweise bedeuten, dass die meisten Phishing-Websites erkannt werden (wichtig für die Sicherheit, um übersehene Angriffe zu minimieren), während eine hohe Präzision bedeutet, dass es nur wenige Fehlalarme gibt (wichtig, um die Ermüdung der Analysten zu vermeiden). Die ROC-AUC (Area Under the ROC Curve) liefert ein schwellenwertunabhängiges Maß für die Leistung (1,0 ist ideal, 0,5 ist nicht besser als Zufall). Die logistische Regression erzielt bei solchen Aufgaben häufig gute Ergebnisse. Wenn die Entscheidungsgrenze zwischen Phishing- und legitimen Websites jedoch komplex ist, können leistungsfähigere nichtlineare Modelle erforderlich sein.

</details>

### Entscheidungsbäume

Ein Entscheidungsbaum ist ein vielseitiger **Algorithmus des überwachten Lernens**, der sowohl für Klassifizierungs- als auch für Regressionsaufgaben verwendet werden kann. Er erlernt ein hierarchisches, baumähnliches Entscheidungsmodell auf Grundlage der Merkmale der Daten. Jeder interne Knoten des Baums stellt einen Test zu einem bestimmten Merkmal dar, jeder Zweig repräsentiert ein Ergebnis dieses Tests und jeder Blattknoten steht für eine vorhergesagte Klasse (bei der Klassifizierung) oder einen Wert (bei der Regression).<sup>[[5]](#references)</sup>

Zum Erstellen eines Baums verwenden Algorithmen wie CART (Classification and Regression Tree) Maße wie **Gini-Unreinheit** oder **Informationsgewinn (Entropie)**, um bei jedem Schritt das beste Merkmal und den besten Schwellenwert für die Aufteilung der Daten auszuwählen. Das Ziel jeder Aufteilung besteht darin, die Homogenität der Zielvariablen in den resultierenden Teilmengen zu erhöhen (bei der Klassifizierung soll jeder Knoten möglichst rein sein und überwiegend eine einzige Klasse enthalten).

Entscheidungsbäume sind **sehr gut interpretierbar** -- man kann den Pfad von der Wurzel bis zum Blatt verfolgen, um die Logik hinter einer Vorhersage zu verstehen (z. B. *"WENN `service = telnet` UND `src_bytes > 1000` UND `failed_logins > 3`, DANN als Angriff klassifizieren"*). Dies ist in der Cybersicherheit wertvoll, um zu erklären, warum ein bestimmter Alarm ausgelöst wurde. Bäume können sowohl numerische als auch kategoriale Daten auf natürliche Weise verarbeiten und erfordern nur wenig Vorverarbeitung (z. B. ist keine Skalierung der Merkmale erforderlich).

Ein einzelner Entscheidungsbaum kann die Trainingsdaten jedoch leicht überanpassen, insbesondere wenn er tief aufgebaut wird (mit vielen Aufteilungen). Techniken wie das Beschneiden (Begrenzung der Baumtiefe oder Festlegung einer Mindestanzahl von Stichproben pro Blatt) werden häufig eingesetzt, um eine Überanpassung zu verhindern.

Es gibt 3 Hauptkomponenten eines Entscheidungsbaums:
- **Wurzelknoten**: Der oberste Knoten des Baums, der den gesamten Datensatz repräsentiert.
- **Interne Knoten**: Knoten, die Merkmale und auf diesen Merkmalen basierende Entscheidungen repräsentieren.
- **Blattknoten**: Knoten, die das endgültige Ergebnis oder die Vorhersage darstellen.

Ein Baum könnte letztendlich so aussehen:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Entscheidungsbäume wurden in Intrusion-Detection-Systemen verwendet, um **Regeln** zur Identifizierung von Angriffen abzuleiten. Beispielsweise erzeugten frühe IDS auf Basis von ID3/C4.5 menschenlesbare Regeln, um normalen von bösartigem Traffic zu unterscheiden. Sie werden auch bei der Malware-Analyse eingesetzt, um anhand ihrer Attribute (Dateigröße, Abschnittsentropie, API-Aufrufe usw.) zu entscheiden, ob eine Datei bösartig ist. Die Klarheit von Entscheidungsbäumen macht sie nützlich, wenn Transparenz erforderlich ist -- ein Analyst kann den Baum überprüfen, um die Erkennungslogik zu validieren.

#### **Wichtige Merkmale von Entscheidungsbäumen:**

-   **Problemtyp:** Sowohl Klassifikation als auch Regression. Wird häufig zur Klassifikation von Angriffen gegenüber normalem Traffic usw. verwendet.

-   **Interpretierbarkeit:** Sehr hoch -- die Entscheidungen des Modells können visualisiert und als eine Reihe von Wenn-dann-Regeln verstanden werden. Dies ist ein großer Vorteil in der Security, wenn Vertrauen und die Überprüfung des Modellverhaltens wichtig sind.

-   **Vorteile:** Kann nichtlineare Beziehungen und Interaktionen zwischen Features erfassen (jede Aufteilung kann als Interaktion betrachtet werden). Features müssen nicht skaliert und kategoriale Variablen nicht One-Hot-encoded werden -- Bäume verarbeiten diese nativ. Schnelle Inferenz (die Vorhersage folgt einfach einem Pfad im Baum).

-   **Einschränkungen:** Anfällig für Overfitting, wenn keine Kontrolle erfolgt (ein tiefer Baum kann den Trainingsdatensatz auswendig lernen). Sie können instabil sein -- kleine Änderungen an den Daten können zu einer anderen Baumstruktur führen. Als einzelne Modelle erreichen sie möglicherweise nicht die Genauigkeit fortschrittlicherer Methoden (Ensembles wie Random Forests liefern typischerweise bessere Ergebnisse, da sie die Varianz reduzieren).

-   **Ermittlung der besten Aufteilung:**
- **Gini-Impurity**: Misst die Unreinheit eines Knotens. Eine niedrigere Gini-Impurity weist auf eine bessere Aufteilung hin. Die Formel lautet:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Dabei ist `p_i` der Anteil der Instanzen in Klasse `i`.

- **Entropie**: Misst die Unsicherheit im Datensatz. Eine niedrigere Entropie weist auf eine bessere Aufteilung hin. Die Formel lautet:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Dabei ist `p_i` der Anteil der Instanzen in Klasse `i`.

- **Informationsgewinn**: Die Verringerung der Entropie oder Gini-Impurity nach einer Aufteilung. Je höher der Informationsgewinn, desto besser die Aufteilung. Er wird wie folgt berechnet:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Außerdem wird ein Baum beendet, wenn:
- Alle Instanzen in einem Knoten derselben Klasse angehören. Dies kann zu Overfitting führen.
- Die (hartcodierte) maximale Tiefe des Baums erreicht ist. Dies verhindert Overfitting.
- Die Anzahl der Instanzen in einem Knoten unter einem bestimmten Schwellenwert liegt. Auch dies verhindert Overfitting.
- Der Informationsgewinn durch weitere Aufteilungen unter einem bestimmten Schwellenwert liegt. Auch dies verhindert Overfitting.

<details>
<summary>Beispiel -- Entscheidungsbaum zur Intrusion Detection:</summary>
Wir trainieren einen Entscheidungsbaum mit dem NSL-KDD-Datensatz, um Netzwerkverbindungen entweder als *normal* oder *Angriff* zu klassifizieren. NSL-KDD ist eine verbesserte Version des klassischen KDD-Cup-1999-Datensatzes mit Features wie Protokolltyp, Service, Dauer, Anzahl fehlgeschlagener Anmeldungen usw. sowie einem Label, das den Angriffstyp oder „normal“ angibt. Wir ordnen alle Angriffstypen einer „Anomalie“-Klasse zu (binäre Klassifikation: normal gegenüber Anomalie). Nach dem Training bewerten wir die Leistung des Baums anhand des Testdatensatzes.
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
In diesem Entscheidungsbaum-Beispiel haben wir die Baumtiefe auf 10 begrenzt, um extremes Overfitting zu vermeiden (der Parameter `max_depth=10`). Die Metriken zeigen, wie gut der Baum normalen und attack traffic unterscheidet. Ein hoher Recall würde bedeuten, dass die meisten Angriffe erkannt werden (wichtig für ein IDS), während eine hohe Precision wenige Fehlalarme bedeutet. Entscheidungsbäume erreichen bei strukturierten Daten häufig eine anständige Genauigkeit, aber ein einzelner Baum erreicht möglicherweise nicht die bestmögliche Performance. Dennoch ist die *Interpretierbarkeit* des Modells ein großer Vorteil -- wir könnten die Splits des Baums untersuchen, um beispielsweise zu sehen, welche Features (z. B. `service`, `src_bytes` usw.) den größten Einfluss darauf haben, eine Verbindung als malicious zu markieren.

</details>

### Random Forests

Random Forest ist eine **Ensemble-Learning**-Methode, die auf Entscheidungsbäumen aufbaut, um die Performance zu verbessern. Ein Random Forest trainiert mehrere Entscheidungsbäume (daher „forest“) und kombiniert deren Ausgaben, um eine endgültige Vorhersage zu treffen (bei Classification typischerweise durch Mehrheitsentscheidung). Die beiden Hauptideen eines Random Forest sind **Bagging** (Bootstrap Aggregating) und **Feature Randomness**:

-   **Bagging:** Jeder Baum wird auf einer zufälligen Bootstrap-Stichprobe der Trainingsdaten trainiert (mit Zurücklegen gezogen). Dadurch entsteht Vielfalt zwischen den Bäumen.

-   **Feature Randomness:** Bei jedem Split in einem Baum wird eine zufällige Teilmenge der Features für den Split berücksichtigt (statt aller Features). Dadurch werden die Bäume zusätzlich voneinander entkoppelt.

Durch die Mittelung der Ergebnisse vieler Bäume reduziert der Random Forest die Varianz, die ein einzelner Entscheidungsbaum aufweisen kann. Einfach ausgedrückt können einzelne Bäume overfitten oder verrauscht sein, aber eine große Anzahl vielfältiger Bäume, die gemeinsam abstimmen, glättet diese Fehler. Das Ergebnis ist häufig ein Modell mit **höherer Genauigkeit** und besserer Generalisierung als ein einzelner Entscheidungsbaum. Außerdem können Random Forests eine Schätzung der Feature Importance liefern (indem betrachtet wird, wie stark jeder Feature-Split die Unreinheit im Durchschnitt reduziert).

Random Forests sind zu einem **Arbeitspferd in der Cybersicherheit** für Aufgaben wie Intrusion Detection, Malware-Klassifizierung und Spam-Erkennung geworden. Sie liefern häufig ohne zusätzliche Konfiguration eine gute Performance und können große Feature-Mengen verarbeiten. Bei der Intrusion Detection kann ein Random Forest beispielsweise einen einzelnen Entscheidungsbaum übertreffen, indem er subtilere Angriffsmuster mit weniger False Positives erkennt. Untersuchungen haben gezeigt, dass Random Forests bei der Klassifizierung von Angriffen in Datensätzen wie NSL-KDD und UNSW-NB15 im Vergleich zu anderen Algorithmen gute Ergebnisse erzielen.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Wichtige Merkmale von Random Forests:**

-   **Problemtyp:** Primär Classification (wird auch für Regression verwendet). Sehr gut geeignet für hochdimensionale strukturierte Daten, wie sie häufig in Security-Logs vorkommen.

-   **Interpretierbarkeit:** Geringer als bei einem einzelnen Entscheidungsbaum -- Hunderte von Bäumen lassen sich nicht einfach gleichzeitig visualisieren oder erklären. Feature-Importance-Scores liefern jedoch gewisse Einblicke darin, welche Attribute den größten Einfluss haben.

-   **Vorteile:** Aufgrund des Ensemble-Effekts im Allgemeinen höhere Genauigkeit als Single-Tree-Modelle. Robust gegenüber Overfitting -- selbst wenn einzelne Bäume overfitten, generalisiert das Ensemble besser. Verarbeitet sowohl numerische als auch kategorische Features und kann fehlende Daten bis zu einem gewissen Grad handhaben. Außerdem ist es relativ robust gegenüber Ausreißern.

-   **Einschränkungen:** Die Modellgröße kann umfangreich sein (viele Bäume, von denen jeder potenziell tief sein kann). Vorhersagen sind langsamer als bei einem einzelnen Baum (da über viele Bäume aggregiert werden muss). Weniger interpretierbar -- obwohl wichtige Features bekannt sind, lässt sich die genaue Logik nicht so einfach wie eine einzelne Regel nachvollziehen. Wenn der Datensatz extrem hochdimensional und spärlich besetzt ist, kann das Training eines sehr großen Forests rechenintensiv sein.

-   **Trainingsprozess:**
1. **Bootstrap Sampling**: Die Trainingsdaten werden zufällig mit Zurücklegen gezogen, um mehrere Teilmengen (Bootstrap-Stichproben) zu erstellen.
2. **Baumkonstruktion**: Für jede Bootstrap-Stichprobe wird ein Entscheidungsbaum erstellt, wobei bei jedem Split eine zufällige Teilmenge der Features verwendet wird. Dadurch entsteht Vielfalt zwischen den Bäumen.
3. **Aggregation**: Bei Classification-Aufgaben wird die endgültige Vorhersage durch eine Mehrheitsentscheidung zwischen den Vorhersagen aller Bäume getroffen. Bei Regression-Aufgaben ist die endgültige Vorhersage der Durchschnitt der Vorhersagen aller Bäume.

<details>
<summary>Beispiel -- Random Forest für Intrusion Detection (NSL-KDD):</summary>
Wir verwenden denselben NSL-KDD-Datensatz (binär als normal oder anomaly gekennzeichnet) und trainieren einen Random-Forest-Klassifikator. Wir erwarten, dass der Random Forest dank der durch Ensemble-Mittelung reduzierten Varianz genauso gut oder besser als der einzelne Entscheidungsbaum abschneidet. Wir bewerten ihn anhand derselben Metriken.
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
Der Random Forest erzielt bei dieser Aufgabe zur Intrusion Detection typischerweise starke Ergebnisse. Im Vergleich zum einzelnen Decision Tree könnten wir eine Verbesserung bei Metriken wie F1 oder AUC beobachten, insbesondere bei Recall oder Precision, abhängig von den Daten. Dies entspricht der Erkenntnis, dass *„Random Forest (RF) ein Ensemble-Klassifikator ist und im Vergleich zu anderen traditionellen Klassifikatoren eine effektive Klassifizierung von Angriffen ermöglicht.“*.<sup>[[6]](#references)</sup> Im Kontext von Security Operations könnte ein Random-Forest-Modell Angriffe zuverlässiger erkennen und gleichzeitig Fehlalarme reduzieren, da es viele Entscheidungsregeln mittelt. Die Feature Importance des Forests könnte uns zeigen, welche Netzwerk-Features am stärksten auf Angriffe hindeuten (z. B. bestimmte Netzwerkdienste oder ungewöhnliche Paketanzahlen).

</details>

### Support Vector Machines (SVM)

Support Vector Machines sind leistungsfähige Modelle des überwachten Lernens, die hauptsächlich für die Klassifizierung (und auch für Regression als SVR) eingesetzt werden. Eine SVM versucht, die **optimale trennende Hyperebene** zu finden, die den Abstand zwischen zwei Klassen maximiert. Nur eine Teilmenge der Trainingspunkte (die der Grenze am nächsten liegenden „Support Vectors“) bestimmt die Position dieser Hyperebene. Durch die Maximierung des Abstands (der Distanz zwischen den Support Vectors und der Hyperebene) erzielen SVMs tendenziell eine gute Generalisierung.<sup>[[8]](#references)</sup>

Ein wesentlicher Faktor für die Leistungsfähigkeit von SVMs ist die Möglichkeit, **Kernel-Funktionen** zu verwenden, um nichtlineare Zusammenhänge zu verarbeiten. Die Daten können implizit in einen höherdimensionalen Feature-Raum transformiert werden, in dem möglicherweise ein linearer Trenner existiert. Zu den verbreiteten Kernels gehören Polynomial-, Radial-Basis-Function-(RBF)- und Sigmoid-Kernels. Wenn Netzwerkverkehrsklassen beispielsweise im ursprünglichen Feature-Raum nicht linear separierbar sind, kann ein RBF-Kernel sie in eine höhere Dimension abbilden, in der die SVM eine lineare Trennung findet (die im ursprünglichen Raum einer nichtlinearen Grenze entspricht). Die Möglichkeit, verschiedene Kernels auszuwählen, erlaubt es SVMs, eine Vielzahl von Problemen zu bewältigen.

SVMs liefern bekanntermaßen gute Ergebnisse in Situationen mit hochdimensionalen Feature-Räumen (z. B. bei Textdaten oder Malware-Opcode-Sequenzen) sowie in Fällen, in denen die Anzahl der Features im Verhältnis zur Anzahl der Samples groß ist. In vielen frühen Cybersecurity-Anwendungen wie der Malware-Klassifizierung und der anomaliebasierten Intrusion Detection der 2000er-Jahre waren sie beliebt und erzielten häufig eine hohe Genauigkeit.

SVMs lassen sich jedoch nicht problemlos auf sehr große Datensätze skalieren (die Trainingskomplexität ist bezüglich der Anzahl der Samples superlinear, und der Speicherbedarf kann hoch sein, da möglicherweise viele Support Vectors gespeichert werden müssen). In der Praxis könnte eine SVM bei Aufgaben wie der Network Intrusion Detection mit Millionen von Datensätzen ohne sorgfältiges Subsampling oder approximative Methoden zu langsam sein.

#### **Wichtige Merkmale von SVM:**

-   **Problemtyp:** Klassifizierung (binär oder multiklassig über One-vs-One/One-vs-Rest) und Regressionsvarianten. Wird häufig für die binäre Klassifizierung mit klarer Abstandstrennung eingesetzt.

-   **Interpretierbarkeit:** Mittel -- SVMs sind weniger interpretierbar als Decision Trees oder die logistische Regression. Zwar kann man erkennen, welche Datenpunkte Support Vectors sind, und einen gewissen Eindruck davon gewinnen, welche Features einflussreich sein könnten (über die Gewichte im Fall eines linearen Kernels), in der Praxis werden SVMs (insbesondere mit nichtlinearen Kernels) jedoch als Black-Box-Klassifikatoren behandelt.

-   **Vorteile:** Effektiv in hochdimensionalen Räumen; kann mit dem Kernel-Trick komplexe Entscheidungsgrenzen modellieren; robust gegenüber Overfitting, wenn der Abstand maximiert wird (insbesondere mit einem geeigneten Regularisierungsparameter C); funktioniert auch dann gut, wenn die Klassen nicht durch eine große Distanz getrennt sind (findet eine bestmögliche Kompromissgrenze).

-   **Einschränkungen:** **Rechenintensiv** bei großen Datensätzen (sowohl Training als auch Vorhersage skalieren schlecht, wenn die Datenmenge wächst). Erfordert eine sorgfältige Abstimmung der Kernel- und Regularisierungsparameter (C, Kernel-Typ, Gamma für RBF usw.). Liefert nicht direkt probabilistische Ausgaben (allerdings kann man Platt Scaling verwenden, um Wahrscheinlichkeiten zu erhalten). Außerdem können SVMs empfindlich auf die Wahl der Kernelparameter reagieren --- eine schlechte Wahl kann zu Underfitting oder Overfitting führen.

*Anwendungsfälle in der Cybersecurity:* SVMs wurden zur **Malware Detection** (z. B. zur Klassifizierung von Dateien anhand extrahierter Features oder Opcode-Sequenzen), zur **Network Anomaly Detection** (Klassifizierung von Datenverkehr als normal oder schädlich) und zur **Phishing Detection** (anhand von URL-Features) eingesetzt. Eine SVM könnte beispielsweise Features einer E-Mail (Anzahl bestimmter Schlüsselwörter, Reputation Scores des Absenders usw.) verarbeiten und sie als Phishing oder legitim klassifizieren. Sie wurden außerdem für die **Intrusion Detection** mit Feature-Sets wie KDD eingesetzt und erzielten häufig eine hohe Genauigkeit auf Kosten des Rechenaufwands.

<details>
<summary>Beispiel -- SVM zur Malware-Klassifizierung:</summary>
Wir verwenden erneut den Phishing-Website-Datensatz, diesmal mit einer SVM. Da SVMs langsam sein können, verwenden wir bei Bedarf eine Teilmenge der Daten zum Training (der Datensatz umfasst etwa 11.000 Instanzen, die eine SVM noch angemessen verarbeiten kann). Wir verwenden einen RBF-Kernel, der häufig für nichtlineare Daten eingesetzt wird, und aktivieren Wahrscheinlichkeitsschätzungen zur Berechnung der ROC AUC.
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
Das SVM-Modell gibt Metriken aus, die wir bei derselben Aufgabe mit der logistischen Regression vergleichen können. Wir könnten feststellen, dass SVM eine hohe Accuracy und AUC erreicht, wenn die Daten anhand der Features gut getrennt sind. Umgekehrt könnte SVM die logistische Regression nicht deutlich übertreffen, wenn der Datensatz viel Rauschen oder überlappende Klassen enthält. In der Praxis können SVMs einen Leistungsschub bieten, wenn komplexe, nichtlineare Beziehungen zwischen Features und Klassen bestehen – der RBF-Kernel kann gekrümmte Entscheidungsgrenzen erfassen, die die logistische Regression übersehen würde. Wie bei allen Modellen ist eine sorgfältige Abstimmung von `C` (Regularisierung) und den Kernel-Parametern (wie `gamma` für RBF) erforderlich, um Bias und Varianz auszubalancieren.

</details>

#### Unterschiede zwischen logistischer Regression und SVM

| Aspekt | **Logistische Regression** | **Support Vector Machines** |
|---|---|---|
| **Zielfunktion** | Minimiert den **log-loss** (Kreuzentropie). | Maximiert den **Abstand** und minimiert gleichzeitig den **hinge-loss**. |
| **Entscheidungsgrenze** | Ermittelt die **bestmögliche Hyperebene**, die _P(y\|x)_ modelliert. | Ermittelt die **Hyperebene mit maximalem Abstand** (größter Abstand zu den nächstgelegenen Punkten). |
| **Ausgabe** | **Probabilistisch** – liefert kalibrierte Klassenwahrscheinlichkeiten über σ(w·x + b). | **Deterministisch** – gibt Klassenlabels zurück; Wahrscheinlichkeiten erfordern zusätzliche Verarbeitung (z. B. Platt scaling). |
| **Regularisierung** | L2 (Standard) oder L1 gleicht Underfitting und Overfitting direkt aus. | Der C-Parameter stellt einen Kompromiss zwischen der Breite des Abstands und Fehlklassifikationen dar; Kernel-Parameter erhöhen die Komplexität. |
| **Kernels / Nichtlinearität** | Die native Form ist **linear**; Nichtlinearität wird durch Feature Engineering hinzugefügt. | Der integrierte **kernel trick** (RBF, poly usw.) ermöglicht die Modellierung komplexer Grenzen in hochdimensionalen Räumen. |
| **Skalierbarkeit** | Löst eine konvexe Optimierung in **O(nd)**; verarbeitet sehr große n gut. | Das Training kann ohne spezialisierte Solver **O(n²–n³)** an Speicher und Zeit benötigen; weniger geeignet für sehr große n. |
| **Interpretierbarkeit** | **Hoch** – Gewichte zeigen den Einfluss von Features; die Odds Ratio ist intuitiv verständlich. | **Gering** bei nichtlinearen Kernels; Support Vectors sind zwar sparsam, aber nicht leicht zu erklären. |
| **Empfindlichkeit gegenüber Ausreißern** | Verwendet einen glatten log-loss und ist dadurch weniger empfindlich. | Hinge-loss mit hartem Margin kann **empfindlich** sein; ein Soft-Margin (`C`) wirkt dem entgegen. |
| **Typische Anwendungsfälle** | Kreditbewertung, medizinische Risiken, A/B-Testing – wenn **Wahrscheinlichkeiten und Erklärbarkeit** wichtig sind. | Bild-/Textklassifikation, Bioinformatik – wenn **komplexe Grenzen** und **hochdimensionale Daten** wichtig sind. |

* **Wenn du kalibrierte Wahrscheinlichkeiten und Interpretierbarkeit benötigst oder mit sehr großen Datensätzen arbeitest – wähle die logistische Regression.**
* **Wenn du ein flexibles Modell benötigst, das nichtlineare Beziehungen ohne manuelles Feature Engineering erfassen kann – wähle SVM (mit Kernels).**
* Beide optimieren konvexe Zielfunktionen, daher sind **globale Minima garantiert**; die Kernel von SVM fügen jedoch Hyperparameter und zusätzliche Rechenkosten hinzu.

### Naive Bayes

Naive Bayes ist eine Familie **probabilistischer Klassifikatoren**, die auf der Anwendung des Satzes von Bayes mit einer starken Unabhängigkeitsannahme zwischen den Features basiert. Trotz dieser „naiven“ Annahme funktioniert Naive Bayes bei bestimmten Anwendungen oft erstaunlich gut, insbesondere bei Texten oder kategorialen Daten, etwa bei der Spam-Erkennung.<sup>[[9]](#references)</sup>


#### Satz von Bayes

Der Satz von Bayes bildet die Grundlage von Naive-Bayes-Klassifikatoren. Er stellt eine Beziehung zwischen den bedingten und marginalen Wahrscheinlichkeiten zufälliger Ereignisse her. Die Formel lautet:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Wo:
- `P(A|B)` ist die posteriore Wahrscheinlichkeit der Klasse `A` bei gegebenem Feature `B`.
- `P(B|A)` ist die Likelihood des Features `B` bei gegebener Klasse `A`.
- `P(A)` ist die a-priori-Wahrscheinlichkeit der Klasse `A`.
- `P(B)` ist die a-priori-Wahrscheinlichkeit des Features `B`.

Wenn wir beispielsweise klassifizieren möchten, ob ein Text von einem Kind oder einem Erwachsenen geschrieben wurde, können wir die Wörter im Text als Features verwenden. Basierend auf einigen Ausgangsdaten berechnet der Naive-Bayes-Klassifikator zunächst die Wahrscheinlichkeiten dafür, dass jedes Wort zu jeder potenziellen Klasse (Kind oder Erwachsener) gehört. Wenn ein neuer Text übergeben wird, berechnet er die Wahrscheinlichkeit jeder potenziellen Klasse anhand der Wörter im Text und wählt die Klasse mit der höchsten Wahrscheinlichkeit.

Wie Sie an diesem Beispiel sehen können, ist der Naive-Bayes-Klassifikator sehr einfach und schnell. Er nimmt jedoch an, dass die Features unabhängig sind, was bei realen Daten nicht immer der Fall ist.


#### Typen von Naive-Bayes-Klassifikatoren

Es gibt mehrere Typen von Naive-Bayes-Klassifikatoren, abhängig von der Art der Daten und der Verteilung der Features:
- **Gaussian Naive Bayes**: Nimmt an, dass die Features einer Gaußschen (Normal-)Verteilung folgen. Geeignet für kontinuierliche Daten.
- **Multinomial Naive Bayes**: Nimmt an, dass die Features einer multinomialen Verteilung folgen. Geeignet für diskrete Daten, beispielsweise Worthäufigkeiten bei der Textklassifizierung.
- **Bernoulli Naive Bayes**: Nimmt an, dass die Features binär sind (0 oder 1). Geeignet für binäre Daten, beispielsweise das Vorhandensein oder Fehlen von Wörtern bei der Textklassifizierung.
- **Categorical Naive Bayes**: Nimmt an, dass die Features kategoriale Variablen sind. Geeignet für kategoriale Daten, beispielsweise zur Klassifizierung von Früchten anhand ihrer Farbe und Form.


#### **Wichtige Eigenschaften von Naive Bayes:**

-   **Art des Problems:** Klassifizierung (binär oder mehrere Klassen). Wird häufig für Textklassifizierungsaufgaben in der Cybersecurity verwendet (Spam, Phishing usw.).

-   **Interpretierbarkeit:** Mittel -- nicht so direkt interpretierbar wie ein Entscheidungsbaum, aber die gelernten Wahrscheinlichkeiten können untersucht werden (z. B. welche Wörter am wahrscheinlichsten in Spam- bzw. Ham-E-Mails vorkommen). Die Form des Modells (Wahrscheinlichkeiten für jedes Feature bei gegebener Klasse) kann bei Bedarf verstanden werden.

-   **Vorteile:** **Sehr schnelles** Training und schnelle Vorhersagen, selbst bei großen Datensätzen (linear in der Anzahl der Instanzen * Anzahl der Features). Benötigt relativ wenige Daten, um Wahrscheinlichkeiten zuverlässig zu schätzen, insbesondere bei geeigneter Glättung. Als Baseline ist es oft überraschend genau, insbesondere wenn Features unabhängig voneinander Evidenz für die Klasse liefern. Funktioniert gut mit hochdimensionalen Daten (z. B. Tausenden von Features aus Texten). Außer dem Festlegen eines Glättungsparameters ist keine komplexe Abstimmung erforderlich.

-   **Einschränkungen:** Die Unabhängigkeitsannahme kann die Genauigkeit einschränken, wenn Features stark miteinander korreliert sind. In Netzwerkdaten könnten beispielsweise Features wie `src_bytes` und `dst_bytes` korreliert sein; Naive Bayes erfasst diese Interaktion nicht. Wenn die Datenmenge sehr groß wird, können ausdrucksstärkere Modelle (wie Ensembles oder neuronale Netze) NB übertreffen, da sie Abhängigkeiten zwischen Features lernen. Wenn außerdem eine bestimmte Kombination von Features erforderlich ist, um einen Angriff zu identifizieren (und nicht nur einzelne Features unabhängig voneinander), wird NB Schwierigkeiten haben.

> [!TIP]
> *Einsatzbereiche in der Cybersecurity:* Der klassische Einsatzbereich ist die **Spam-Erkennung** -- Naive Bayes bildete den Kern früher Spamfilter. Dabei wurden die Häufigkeiten bestimmter Tokens (Wörter, Phrasen, IP-Adressen) verwendet, um die Wahrscheinlichkeit zu berechnen, dass eine E-Mail Spam ist. Außerdem wird es bei der **Erkennung von Phishing-E-Mails** und der **URL-Klassifizierung** eingesetzt, wobei das Vorhandensein bestimmter Schlüsselwörter oder Merkmale (wie "login.php" in einer URL oder `@` in einem URL-Pfad) zur Phishing-Wahrscheinlichkeit beiträgt. Bei der Malware-Analyse könnte man sich einen Naive-Bayes-Klassifikator vorstellen, der das Vorhandensein bestimmter API-Aufrufe oder Berechtigungen in Software verwendet, um vorherzusagen, ob es sich um Malware handelt. Obwohl fortgeschrittenere Algorithmen häufig bessere Ergebnisse erzielen, bleibt Naive Bayes aufgrund seiner Geschwindigkeit und Einfachheit eine gute Baseline.

<details>
<summary>Beispiel -- Naive Bayes zur Phishing-Erkennung:</summary>
Zur Demonstration von Naive Bayes verwenden wir Gaussian Naive Bayes auf dem NSL-KDD-Intrusion-Datensatz (mit binären Labels). Gaussian NB behandelt jedes Feature so, als würde es pro Klasse einer Normalverteilung folgen. Dies ist eine grobe Wahl, da viele Netzwerk-Features diskret oder stark verzerrt sind, aber es zeigt, wie NB auf kontinuierliche Feature-Daten angewendet werden kann. Wir könnten auch Bernoulli NB auf einem Datensatz mit binären Features auswählen (beispielsweise einer Sammlung ausgelöster Alerts), bleiben hier aber der Kontinuität halber bei NSL-KDD.
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
Dieser Code trainiert einen Naive-Bayes-Klassifikator zur Erkennung von Angriffen. Naive Bayes berechnet anhand der Trainingsdaten Werte wie `P(service=http | Attack)` und `P(Service=http | Normal)` und nimmt dabei die Unabhängigkeit der Features an. Anschließend verwendet das Verfahren diese Wahrscheinlichkeiten, um neue Verbindungen anhand der beobachteten Features entweder als normal oder als Angriff zu klassifizieren. Die Leistung von NB auf NSL-KDD ist möglicherweise nicht so hoch wie die fortgeschrittenerer Modelle (da die Unabhängigkeit der Features verletzt wird), aber sie ist oft ordentlich und bietet den Vorteil einer extrem hohen Geschwindigkeit. In Szenarien wie der Echtzeit-E-Mail-Filterung oder einer ersten Triage von URLs kann ein Naive-Bayes-Modell offensichtlich bösartige Fälle schnell erkennen und dabei nur wenige Ressourcen benötigen.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ist einer der einfachsten Machine-Learning-Algorithmen. Es handelt sich um ein **nichtparametrisches, instanzbasiertes** Verfahren, das Vorhersagen anhand der Ähnlichkeit zu Beispielen im Trainingsdatensatz trifft. Die Idee bei der Klassifizierung lautet: Um einen neuen Datenpunkt zu klassifizieren, werden die **k** nächstgelegenen Punkte in den Trainingsdaten (seine „nearest neighbors“) ermittelt und die Mehrheitsklasse dieser Nachbarn zugewiesen. Die „Nähe“ wird durch eine Distanzmetrik definiert, typischerweise die euklidische Distanz bei numerischen Daten (für verschiedene Feature- oder Problemtypen können andere Distanzen verwendet werden).<sup>[[10]](#references)</sup>

K-NN benötigt *kein explizites Training* -- die „Trainingsphase“ besteht lediglich darin, den Datensatz zu speichern. Die gesamte Arbeit findet während der Abfrage (Vorhersage) statt: Der Algorithmus muss die Distanzen vom Abfragepunkt zu allen Trainingspunkten berechnen, um die nächstgelegenen Punkte zu finden. Dadurch ist die Vorhersagezeit **linear in der Anzahl der Trainingssamples**, was bei großen Datensätzen kostspielig sein kann. Daher eignet sich k-NN am besten für kleinere Datensätze oder Szenarien, in denen man zugunsten der Einfachheit Speicher und Geschwindigkeit gegeneinander abwägen kann.

Trotz seiner Einfachheit kann k-NN sehr komplexe Entscheidungsgrenzen modellieren (da die Entscheidungsgrenze effektiv jede Form annehmen kann, die durch die Verteilung der Beispiele vorgegeben wird). Das Verfahren funktioniert tendenziell gut, wenn die Entscheidungsgrenze sehr unregelmäßig ist und viele Daten vorhanden sind -- im Wesentlichen lässt es die Daten „für sich selbst sprechen“. In hohen Dimensionen können Distanzmetriken jedoch weniger aussagekräftig werden (Fluch der Dimensionalität), und das Verfahren kann Schwierigkeiten bekommen, sofern nicht eine sehr große Anzahl von Samples vorhanden ist.

*Anwendungsfälle in der Cybersicherheit:* k-NN wurde bei der Anomalieerkennung eingesetzt -- beispielsweise könnte ein Intrusion-Detection-System ein Netzwerkereignis als bösartig markieren, wenn die meisten seiner nearest neighbors (vorherige Ereignisse) bösartig waren. Wenn normaler Traffic Cluster bildet und Angriffe Ausreißer sind, entspricht ein K-NN-Ansatz (mit k=1 oder einem kleinen k) im Wesentlichen einer **Anomalieerkennung durch nearest neighbors**. K-NN wurde außerdem zur Klassifizierung von Malware-Familien anhand binärer Feature-Vektoren eingesetzt: Eine neue Datei könnte als Mitglied einer bestimmten Malware-Familie klassifiziert werden, wenn sie im Feature-Raum bekannten Instanzen dieser Familie sehr ähnlich ist. In der Praxis wird k-NN nicht so häufig eingesetzt wie besser skalierbare Algorithmen, ist aber konzeptionell unkompliziert und wird gelegentlich als Baseline oder für Probleme mit kleinem Umfang verwendet.

#### **Wichtige Merkmale von k-NN:**

-   **Problemtyp:** Klassifizierung (und Varianten für Regression sind vorhanden). Es handelt sich um ein Verfahren des *lazy learning* -- es wird kein explizites Modell erstellt.

-   **Interpretierbarkeit:** Niedrig bis mittel -- es gibt kein globales Modell und keine kompakte Erklärung, aber die Ergebnisse können interpretiert werden, indem man die nearest neighbors betrachtet, die eine Entscheidung beeinflusst haben (z. B. „Dieser Netzwerkfluss wurde als bösartig klassifiziert, weil er diesen 3 bekannten bösartigen Netzwerkflüssen ähnelt“). Erklärungen können somit beispielbasiert sein.

-   **Vorteile:** Sehr einfach zu implementieren und zu verstehen. Macht keine Annahmen über die Datenverteilung (nichtparametrisch). Kann Mehrklassenprobleme auf natürliche Weise verarbeiten. Ist insofern **adaptiv**, als Entscheidungsgrenzen sehr komplex sein und durch die Datenverteilung geformt werden können.

-   **Einschränkungen:** Die Vorhersage kann bei großen Datensätzen langsam sein (es müssen viele Distanzen berechnet werden). Speicherintensiv -- alle Trainingsdaten werden gespeichert. Die Leistung nimmt in hochdimensionalen Feature-Räumen ab, da alle Punkte tendenziell nahezu gleich weit voneinander entfernt sind (wodurch das Konzept des „Nächsten“ weniger aussagekräftig wird). *k* (die Anzahl der Nachbarn) muss passend gewählt werden -- ein zu kleines k kann zu verrauschten Ergebnissen führen, während ein zu großes k irrelevante Punkte aus anderen Klassen einbeziehen kann. Außerdem sollten Features angemessen skaliert werden, da Distanzberechnungen empfindlich auf unterschiedliche Skalierungen reagieren.

<details>
<summary>Beispiel -- k-NN zur Phishing-Erkennung:</summary>

Wir werden erneut NSL-KDD verwenden (binäre Klassifizierung). Da k-NN rechenintensiv ist, verwenden wir in dieser Demonstration eine Teilmenge der Trainingsdaten, damit die Berechnung praktikabel bleibt. Wir wählen beispielsweise 20.000 Trainingssamples aus den insgesamt 125.000 Samples und verwenden k=5 Nachbarn. Nach dem Training (also eigentlich nur dem Speichern der Daten) evaluieren wir das Verfahren anhand des Testdatensatzes. Außerdem skalieren wir die Features für die Distanzberechnung, damit kein einzelnes Feature aufgrund seiner Skalierung dominiert.
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
Das k-NN-Modell klassifiziert eine Verbindung, indem es die 5 nächstgelegenen Verbindungen in der Teilmenge des Trainingsdatensatzes betrachtet. Wenn beispielsweise 4 dieser Nachbarn Angriffe (Anomalien) und 1 normal ist, wird die neue Verbindung als Angriff klassifiziert. Die Leistung kann angemessen sein, liegt jedoch oft nicht so hoch wie bei einem gut abgestimmten Random Forest oder SVM auf denselben Daten. k-NN kann jedoch manchmal überzeugen, wenn die Klassenverteilungen sehr unregelmäßig und komplex sind -- im Grunde durch eine speicherbasierte Suche. In der Cybersicherheit könnte k-NN (mit k=1 oder einem kleinen k) zur Erkennung bekannter Angriffsmuster anhand von Beispielen oder als Komponente in komplexeren Systemen eingesetzt werden (z. B. zum Clustering und anschließenden Klassifizieren anhand der Clusterzugehörigkeit).
</details>

### Gradient Boosting Machines (z. B. XGBoost)

Gradient Boosting Machines gehören zu den leistungsfähigsten Algorithmen für strukturierte Daten. **Gradient boosting** bezeichnet die Technik, ein Ensemble schwacher Lerner (häufig Entscheidungsbäume) sequenziell aufzubauen, wobei jedes neue Modell die Fehler des vorherigen Ensembles korrigiert. Im Gegensatz zu Bagging (Random Forests), bei dem Bäume parallel erstellt und gemittelt werden, baut Boosting die Bäume *nacheinander* auf, wobei jeder Baum sich stärker auf die Instanzen konzentriert, die von den vorherigen Bäumen falsch vorhergesagt wurden.<sup>[[11]](#references)</sup>

Die beliebtesten Implementierungen der letzten Jahre sind **XGBoost**, **LightGBM** und **CatBoost**, die allesamt Bibliotheken für Gradient Boosting Decision Trees (GBDT) sind. Sie waren bei Machine-Learning-Wettbewerben und in verschiedenen Anwendungen äußerst erfolgreich und **erreichen bei tabellarischen Datensätzen häufig eine State-of-the-Art-Leistung**. In der Cybersicherheit haben Forscher und Praktiker Gradient-Boosted Trees für Aufgaben wie **Malware-Erkennung** (unter Verwendung aus Dateien oder Laufzeitverhalten extrahierter Merkmale) und **Network Intrusion Detection** eingesetzt. Beispielsweise kann ein Gradient-Boosting-Modell viele schwache Regeln (Bäume) wie „wenn viele SYN-Pakete und ein ungewöhnlicher Port -> wahrscheinlich Scan“ zu einem starken kombinierten Detektor verbinden, der viele subtile Muster berücksichtigt.

Warum sind Boosted Trees so effektiv? Jeder Baum in der Sequenz wird anhand der *residualen Fehler* (Gradienten) der Vorhersagen des aktuellen Ensembles trainiert. Auf diese Weise **„boostet“** das Modell schrittweise die Bereiche, in denen es schwach ist. Die Verwendung von Entscheidungsbäumen als Basislerner ermöglicht es dem finalen Modell, komplexe Wechselwirkungen und nichtlineare Beziehungen zu erfassen. Außerdem verfügt Boosting grundsätzlich über eine Form integrierter Regularisierung: Durch das Hinzufügen vieler kleiner Bäume (und die Verwendung einer Lernrate zur Skalierung ihrer Beiträge) generalisiert es häufig gut, ohne stark zu überfitten, sofern geeignete Parameter gewählt werden.

#### **Wichtige Merkmale von Gradient Boosting:**

-   **Problemtyp:** Hauptsächlich Klassifikation und Regression. In der Security normalerweise Klassifikation (z. B. binäre Klassifizierung einer Verbindung oder Datei). Es verarbeitet binäre und Multiclass-Probleme (mit einem geeigneten Loss) sowie Ranking-Probleme.

-   **Interpretierbarkeit:** Niedrig bis mittel. Während ein einzelner Boosted Tree klein ist, kann ein vollständiges Modell aus Hunderten von Bäumen bestehen und ist als Ganzes nicht für Menschen interpretierbar. Wie Random Forest kann es jedoch Feature-Importance-Scores bereitstellen, und Tools wie SHAP (SHapley Additive exPlanations) können verwendet werden, um einzelne Vorhersagen bis zu einem gewissen Grad zu interpretieren.

-   **Vorteile:** Häufig der **leistungsstärkste** Algorithmus für strukturierte/tabellarische Daten. Kann komplexe Muster und Wechselwirkungen erkennen. Bietet viele Stellschrauben (Anzahl der Bäume, Baumtiefe, Lernrate, Regularisierungsterme), um die Modellkomplexität anzupassen und Overfitting zu verhindern. Moderne Implementierungen sind auf Geschwindigkeit optimiert (z. B. verwendet XGBoost Gradienteninformationen zweiter Ordnung und effiziente Datenstrukturen). Kann unausgeglichene Daten tendenziell besser verarbeiten, wenn geeignete Loss-Funktionen verwendet oder Sample-Gewichte angepasst werden.

-   **Einschränkungen:** Komplexer zu optimieren als einfachere Modelle; das Training kann langsam sein, wenn die Bäume tief sind oder die Anzahl der Bäume groß ist (obwohl es in der Regel immer noch schneller ist als das Training eines vergleichbaren Deep Neural Network auf denselben Daten). Das Modell kann überfitten, wenn es nicht richtig abgestimmt wird (z. B. zu viele tiefe Bäume mit unzureichender Regularisierung). Aufgrund der vielen Hyperparameter kann der effektive Einsatz von Gradient Boosting mehr Erfahrung oder Experimente erfordern. Wie baumbasierte Methoden verarbeitet es außerdem sehr spärliche, hochdimensionale Daten nicht grundsätzlich so effizient wie lineare Modelle oder Naive Bayes (obwohl es beispielsweise bei Textklassifikation eingesetzt werden kann, ohne Feature Engineering jedoch möglicherweise nicht die erste Wahl ist).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Fast überall dort, wo ein Entscheidungsbaum oder Random Forest eingesetzt werden könnte, kann ein Gradient-Boosting-Modell eine bessere Genauigkeit erreichen. Beispielsweise wurde bei **Microsofts Malware-Erkennungs**-Wettbewerben häufig XGBoost auf aus Binärdateien extrahierten und aufbereiteten Merkmalen eingesetzt. Die Forschung zu **Network Intrusion Detection** berichtet häufig Spitzenresultate mit GBDTs (z. B. XGBoost auf den Datensätzen CIC-IDS2017 oder UNSW-NB15). Diese Modelle können eine große Bandbreite an Merkmalen (Protokolltypen, Häufigkeit bestimmter Ereignisse, statistische Merkmale des Datenverkehrs usw.) verarbeiten und kombinieren, um Bedrohungen zu erkennen. Bei der Phishing-Erkennung kann Gradient Boosting lexikalische Merkmale von URLs, Merkmale zur Domain-Reputation und Merkmale des Seiteninhalts kombinieren und dadurch eine sehr hohe Genauigkeit erreichen. Der Ensemble-Ansatz hilft dabei, viele Sonderfälle und Feinheiten in den Daten abzudecken.

<details>
<summary>Beispiel -- XGBoost zur Phishing-Erkennung:</summary>
Wir verwenden einen Gradient-Boosting-Klassifikator auf dem Phishing-Datensatz. Um die Dinge einfach und eigenständig zu halten, verwenden wir `sklearn.ensemble.GradientBoostingClassifier` (eine langsamere, aber unkomplizierte Implementierung). Normalerweise könnte man die Bibliotheken `xgboost` oder `lightgbm` verwenden, um eine bessere Leistung und zusätzliche Funktionen zu erhalten. Wir werden das Modell trainieren und es ähnlich wie zuvor evaluieren.
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
Das Gradient-Boosting-Modell wird auf diesem Phishing-Datensatz wahrscheinlich eine sehr hohe Genauigkeit und AUC erreichen (solche Modelle können bei korrektem Tuning auf derartigen Daten oft eine Genauigkeit von über 95 % erzielen, wie in der Literatur zu sehen ist. Dies zeigt, warum GBDTs als *„the state of the art model for tabular dataset“* gelten -- sie übertreffen häufig einfachere Algorithmen, indem sie komplexe Muster erfassen.<sup>[[11]](#references)</sup> Im Kontext der Cybersicherheit könnte dies bedeuten, mehr Phishing-Websites oder Angriffe zu erkennen und zugleich weniger zu übersehen. Natürlich muss man sich vor Overfitting hüten -- bei der Entwicklung eines solchen Modells für den Einsatz würden wir normalerweise Techniken wie Cross-Validation verwenden und die Leistung auf einem Validierungsdatensatz überwachen.

</details>

### Modelle kombinieren: Ensemble Learning und Stacking

Ensemble Learning ist eine Strategie zum **Kombinieren mehrerer Modelle**, um die Gesamtleistung zu verbessern. Wir haben bereits spezifische Ensemble-Methoden gesehen: Random Forest (ein Ensemble von Bäumen durch Bagging) und Gradient Boosting (ein Ensemble von Bäumen durch sequenzielles Boosting). Ensembles können jedoch auch auf andere Weise erstellt werden, etwa als **Voting-Ensembles** oder durch **Stacked Generalization (Stacking)**. Die Grundidee besteht darin, dass verschiedene Modelle unterschiedliche Muster erfassen oder verschiedene Schwächen haben können; durch ihre Kombination können wir **die Fehler jedes Modells durch die Stärken eines anderen ausgleichen**.<sup>[[12]](#references)</sup>

-   **Voting-Ensemble:** Bei einem einfachen Voting-Klassifikator trainieren wir mehrere unterschiedliche Modelle (beispielsweise eine logistische Regression, einen Entscheidungsbaum und eine SVM) und lassen sie über die endgültige Vorhersage abstimmen (bei der Klassifikation durch Mehrheitsentscheidung). Wenn wir die Stimmen gewichten (beispielsweise genaueren Modellen ein höheres Gewicht geben), handelt es sich um ein gewichtetes Voting-Verfahren. Dies verbessert typischerweise die Leistung, wenn die einzelnen Modelle ausreichend gut und unabhängig sind -- das Ensemble reduziert das Risiko eines Fehlers eines einzelnen Modells, da andere Modelle ihn möglicherweise korrigieren. Es ist, als hätte man ein Expertengremium statt nur einer einzigen Meinung.

-   **Stacking (Stacked Ensemble):** Stacking geht einen Schritt weiter. Statt einer einfachen Abstimmung wird ein **Meta-Modell** trainiert, das **lernt, wie die Vorhersagen der Basismodelle am besten kombiniert werden**. Beispielsweise trainiert man drei verschiedene Klassifikatoren (Base Learners) und übergibt ihre Ausgaben (oder Wahrscheinlichkeiten) als Features an einen Meta-Klassifikator (häufig ein einfaches Modell wie eine logistische Regression), der die optimale Methode zu ihrer Kombination erlernt. Das Meta-Modell wird auf einem Validierungsdatensatz oder mittels Cross-Validation trainiert, um Overfitting zu vermeiden. Stacking kann einfache Voting-Verfahren häufig übertreffen, da es lernt, *welchen Modellen unter welchen Umständen stärker vertraut werden sollte*. In der Cybersicherheit könnte ein Modell besser darin sein, Network Scans zu erkennen, während ein anderes Malware-Beaconing besser erkennt; ein Stacking-Modell könnte lernen, sich jeweils angemessen auf das passende Modell zu stützen.

Ensembles, ob durch Voting oder Stacking, neigen dazu, **Genauigkeit** und Robustheit zu **steigern**. Der Nachteil besteht in der höheren Komplexität und der manchmal geringeren Interpretierbarkeit (obwohl einige Ensemble-Ansätze, wie ein Durchschnitt von Entscheidungsbäumen, weiterhin gewisse Einblicke liefern können, etwa durch Feature Importance). Wenn die betrieblichen Einschränkungen es zulassen, kann der Einsatz eines Ensembles in der Praxis zu höheren Erkennungsraten führen. Viele erfolgreiche Lösungen bei Cybersicherheits-Herausforderungen (und allgemein bei Kaggle-Wettbewerben) verwenden Ensemble-Techniken, um das letzte bisschen Leistung herauszuholen.

<details>
<summary>Beispiel -- Voting-Ensemble zur Phishing-Erkennung:</summary>
Um Model Stacking zu veranschaulichen, kombinieren wir einige der Modelle, die wir im Phishing-Datensatz besprochen haben. Wir verwenden eine logistische Regression, einen Entscheidungsbaum und ein k-NN als Base Learners und setzen einen Random Forest als Meta-Learner ein, um ihre Vorhersagen zu aggregieren. Der Meta-Learner wird auf den Ausgaben der Base Learners trainiert (unter Verwendung von Cross-Validation auf dem Trainingsdatensatz). Wir erwarten, dass das gestackte Modell genauso gut oder geringfügig besser als die einzelnen Modelle abschneidet.
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
Das Stacked Ensemble nutzt die komplementären Stärken der Basismodelle. Beispielsweise könnte die logistische Regression lineare Aspekte der Daten verarbeiten, der Entscheidungsbaum bestimmte regelartige Interaktionen erfassen und k-NN in lokalen Bereichen des Merkmalsraums besonders gut abschneiden. Das Meta-Modell (hier ein Random Forest) kann lernen, wie diese Eingaben zu gewichten sind. Die resultierenden Metriken zeigen häufig eine Verbesserung (wenn auch nur geringfügig) gegenüber den Metriken jedes einzelnen Modells. In unserem Phishing-Beispiel könnte die logistische Regression allein beispielsweise einen F1-Wert von 0,95 und der Baum einen Wert von 0,94 erreichen, während das Stacking einen Wert von 0,96 erzielt, indem es die Fehlerbereiche der einzelnen Modelle ausgleicht.

Ensemble-Methoden wie diese veranschaulichen das Prinzip, dass *„die Kombination mehrerer Modelle typischerweise zu einer besseren Generalisierung führt“*.<sup>[[12]](#references)</sup> In der Cybersicherheit kann dies umgesetzt werden, indem mehrere Detection Engines verwendet werden (eine könnte regelbasiert, eine auf Machine Learning und eine auf Anomalieerkennung basieren) und anschließend eine Schicht ihre Alerts aggregiert -- im Grunde eine Form von Ensemble --, um mit höherer Sicherheit eine endgültige Entscheidung zu treffen. Beim Einsatz solcher Systeme muss die zusätzliche Komplexität berücksichtigt und sichergestellt werden, dass das Ensemble nicht zu schwierig zu verwalten oder zu erklären wird. Aus Sicht der Genauigkeit sind Ensembles und Stacking jedoch leistungsstarke Werkzeuge zur Verbesserung der Modellleistung.

</details>

Die auf der [Deep-Learning-Seite](AI-Deep-Learning.md) beschriebenen neuronalen Netzwerkansätze können diese klassischen Modelle bei der Intrusion Detection ergänzen, wenn der Datensatz und das verfügbare Compute-Budget die zusätzliche Komplexität rechtfertigen.<sup>[[13]](#references)</sup>

## References

- [1] [KI und Machine Learning in der Cybersicherheit - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [Lineare Regression erklärt - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Logistische Regression - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - „Klassifizierung von Phishing-Angriffen und Websites mithilfe von Machine Learning und mehreren Datensätzen (eine vergleichende Analyse)“](https://arxiv.org/pdf/2101.02552)
- [5] [Entscheidungsbaum - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - „Erkennung von Denial-of-Service-Angriffen mithilfe eines Random-Forest-Klassifikators mit Informationsgewinn“](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - „Leistungsanalyse von Machine-Learning-Modellen für Intrusion-Detection-Systeme mithilfe einer Gini-Imurity-basierten gewichteten Random-Forest-Technik zur Merkmalsauswahl (GIWRF)“](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Was ist eine Support Vector Machine? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Naive-Bayes-Spamfilterung - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [Was ist k-Nearest Neighbors (KNN)? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT entschlüsselt: So funktionieren LightGBM, XGBoost und CatBoost - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble Learning: Verbesserung der Modellleistung durch die Kombination von Stärken - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Wie Deep Learning Intrusion-Detection-Systeme verbessert](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
