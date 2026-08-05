# Überwachte Lernalgorithmen

{{#include ../banners/hacktricks-training.md}}

## Grundlegende Informationen

Überwachtes Lernen verwendet gelabelte Daten, um Modelle zu trainieren, die Vorhersagen zu neuen, bisher unbekannten Eingaben treffen können. In der Cybersicherheit wird überwachtes Machine Learning häufig für Aufgaben wie Intrusion Detection (Klassifizierung des Netzwerkverkehrs als *normal* oder *Angriff*), Malware-Erkennung (Unterscheidung zwischen schädlicher und gutartiger Software), Phishing-Erkennung (Identifizierung betrügerischer Websites oder E-Mails) und Spam-Filterung eingesetzt. Jeder Algorithmus hat seine Stärken und eignet sich für unterschiedliche Problemtypen (Klassifizierung oder Regression). Im Folgenden betrachten wir wichtige Algorithmen des überwachten Lernens, erklären ihre Funktionsweise und zeigen ihre Anwendung auf realen Cybersicherheitsdatensätzen. Außerdem wird erläutert, wie die Kombination von Modellen (Ensemble Learning) die Vorhersageleistung häufig verbessern kann.

## Algorithmen

-   **Linear Regression:** Ein grundlegender Regressionsalgorithmus zur Vorhersage numerischer Ergebnisse durch Anpassung einer linearen Gleichung an Daten.

-   **Logistic Regression:** Ein Klassifizierungsalgorithmus (trotz seines Namens), der eine logistische Funktion verwendet, um die Wahrscheinlichkeit eines binären Ergebnisses zu modellieren.

-   **Decision Trees:** Baumstrukturierte Modelle, die Daten anhand von Merkmalen aufteilen, um Vorhersagen zu treffen; sie werden häufig wegen ihrer Interpretierbarkeit eingesetzt.

-   **Random Forests:** Ein Ensemble aus Decision Trees (mittels Bagging), das die Genauigkeit verbessert und Overfitting reduziert.

-   **Support Vector Machines (SVM):** Klassifikatoren mit maximalem Abstand, die die optimale trennende Hyperebene bestimmen; für nichtlineare Daten können Kernel verwendet werden.

-   **Naive Bayes:** Ein probabilistischer Klassifikator, der auf dem Satz von Bayes und der Annahme unabhängiger Merkmale basiert und bekanntlich zur Spam-Filterung eingesetzt wird.

-   **k-Nearest Neighbors (k-NN):** Ein einfacher „instanzbasierter“ Klassifikator, der ein Sample anhand der Mehrheitsklasse seiner nächsten Nachbarn klassifiziert.

-   **Gradient Boosting Machines:** Ensemble-Modelle (z. B. XGBoost, LightGBM), die einen leistungsfähigen Prädiktor erstellen, indem sie sequenziell schwächere Lerner hinzufügen (typischerweise Decision Trees).

Jeder folgende Abschnitt enthält eine verbesserte Beschreibung des Algorithmus sowie ein **Python-Codebeispiel**, das Bibliotheken wie `pandas` und `scikit-learn` (und `PyTorch` für das Beispiel mit dem neuronalen Netzwerk) verwendet. Die Beispiele nutzen öffentlich verfügbare Cybersicherheitsdatensätze (wie NSL-KDD zur Intrusion Detection und einen Datensatz zu Phishing-Websites) und folgen einer einheitlichen Struktur:

1.  **Datensatz laden** (Download über eine URL, falls verfügbar).

2.  **Daten vorverarbeiten** (z. B. kategorische Merkmale codieren, Werte skalieren und die Daten in Trainings- und Testdatensätze aufteilen).

3.  **Modell** anhand der Trainingsdaten trainieren.

4.  **Auf einem Testsatz evaluieren** mithilfe der Metriken Accuracy, Precision, Recall, F1-Score und ROC AUC für Klassifizierungsaufgaben (sowie Mean Squared Error für Regression).

Sehen wir uns die einzelnen Algorithmen an:

### Linear Regression

Linear Regression ist ein **Regressionsalgorithmus**, der zur Vorhersage kontinuierlicher numerischer Werte verwendet wird. Er nimmt eine lineare Beziehung zwischen den Eingabemerkmalen (unabhängigen Variablen) und der Ausgabe (abhängigen Variable) an. Das Modell versucht, eine gerade Linie (oder in höheren Dimensionen eine Hyperebene) anzupassen, die die Beziehung zwischen den Merkmalen und dem Zielwert bestmöglich beschreibt. Dies geschieht typischerweise durch Minimierung der Summe der quadrierten Fehler zwischen den vorhergesagten und den tatsächlichen Werten (Methode der kleinsten Quadrate).<sup>[[8]](#references)</sup>

Die einfachste Form zur Darstellung der Linear Regression ist eine Gerade:
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
> *Anwendungsfälle in der Cybersicherheit:* Die lineare Regression selbst wird für zentrale Sicherheitsaufgaben, bei denen es sich häufig um Klassifikation handelt, seltener eingesetzt. Sie kann jedoch zur Vorhersage numerischer Ergebnisse verwendet werden. Beispielsweise kann man mithilfe der linearen Regression das **Volumen des Netzwerkverkehrs vorhersagen** oder **die Anzahl der Angriffe in einem bestimmten Zeitraum schätzen**, basierend auf historischen Daten. Sie kann auch einen Risikowert oder die erwartete Zeit bis zur Erkennung eines Angriffs anhand bestimmter Systemmetriken vorhersagen. In der Praxis werden Klassifikationsalgorithmen (wie die logistische Regression oder Bäume) häufiger zur Erkennung von Intrusionen oder Malware verwendet, aber die lineare Regression dient als Grundlage und ist für regressionsorientierte Analysen nützlich.

#### **Wichtige Merkmale der linearen Regression:**

-   **Problemtyp:** Regression (Vorhersage kontinuierlicher Werte). Für eine direkte Klassifikation nicht geeignet, außer es wird ein Schwellenwert auf die Ausgabe angewendet.

-   **Interpretierbarkeit:** Hoch -- Koeffizienten sind einfach zu interpretieren und zeigen den linearen Einfluss jedes Features.

-   **Vorteile:** Einfach und schnell; eine gute Baseline für Regressionsaufgaben; funktioniert gut, wenn der tatsächliche Zusammenhang näherungsweise linear ist.

-   **Einschränkungen:** Kann komplexe oder nichtlineare Zusammenhänge nicht erfassen (ohne manuelles Feature Engineering); neigt bei nichtlinearen Zusammenhängen zu Underfitting; ist empfindlich gegenüber Ausreißern, die die Ergebnisse verfälschen können.

-   **Ermittlung der besten Anpassung:** Um die Linie mit der besten Anpassung zu finden, die die möglichen Kategorien voneinander trennt, verwenden wir eine Methode namens **Ordinary Least Squares (OLS)**. Diese Methode minimiert die Summe der quadrierten Differenzen zwischen den beobachteten Werten und den vom linearen Modell vorhergesagten Werten.

<details>
<summary>Beispiel -- Vorhersage der Verbindungsdauer (Regression) in einem Intrusion-Datensatz
</summary>
Im Folgenden demonstrieren wir die lineare Regression anhand des NSL-KDD-Cybersicherheitsdatensatzes. Wir behandeln dies als Regressionsproblem, indem wir die `duration` von Netzwerkverbindungen anhand anderer Features vorhersagen. (In Wirklichkeit ist `duration` ein Feature von NSL-KDD; wir verwenden es hier lediglich zur Veranschaulichung der Regression.) Wir laden den Datensatz, verarbeiten ihn vor (einschließlich der Kodierung kategorischer Features), trainieren ein lineares Regressionsmodell und bewerten den Mean Squared Error (MSE) sowie den R²-Score anhand eines Testdatensatzes.
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
In diesem Beispiel versucht das lineare Regressionsmodell, die Verbindungs-`duration` anhand anderer Netzwerkmerkmale vorherzusagen. Wir messen die Leistung mit dem Mean Squared Error (MSE) und R². Ein R²-Wert nahe 1,0 würde darauf hindeuten, dass das Modell den größten Teil der Varianz von `duration` erklärt, während ein niedriger oder negativer R²-Wert auf eine schlechte Anpassung hinweist. (Seien Sie nicht überrascht, wenn der R²-Wert hier niedrig ist -- die Vorhersage von `duration` anhand der gegebenen Merkmale kann schwierig sein, und die lineare Regression erfasst möglicherweise keine komplexen Muster.)
</details>

### Logistische Regression

Die logistische Regression ist ein **Klassifikations**algorithmus, der die Wahrscheinlichkeit modelliert, dass eine Instanz zu einer bestimmten Klasse gehört (typischerweise zur „positiven“ Klasse). Trotz ihres Namens wird die *logistische* Regression für diskrete Ergebnisse verwendet (im Gegensatz zur linearen Regression, die für kontinuierliche Ergebnisse eingesetzt wird). Sie wird insbesondere für die **binäre Klassifikation** verwendet (zwei Klassen, z. B. bösartig vs. harmlos), kann aber auf Multi-Class-Probleme erweitert werden (mithilfe von Softmax- oder One-vs-Rest-Ansätzen).<sup>[[1]](#references)</sup>

Die logistische Regression verwendet die logistische Funktion (auch als Sigmoidfunktion bekannt), um vorhergesagte Werte auf Wahrscheinlichkeiten abzubilden. Beachten Sie, dass die Sigmoidfunktion eine Funktion mit Werten zwischen 0 und 1 ist, die je nach den Anforderungen der Klassifikation in einer S-förmigen Kurve ansteigt. Dies ist für Aufgaben der binären Klassifikation nützlich. Daher wird jedes Merkmal jeder Eingabe mit seinem zugewiesenen Gewicht multipliziert, und das Ergebnis wird durch die Sigmoidfunktion geleitet, um eine Wahrscheinlichkeit zu erzeugen:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` ist die Wahrscheinlichkeit, dass die Ausgabe `y` bei der Eingabe `x` den Wert 1 hat
- `e` ist die Basis des natürlichen Logarithmus
- `z` ist eine lineare Kombination der Eingabemerkmale, typischerweise dargestellt als `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Beachte, dass es sich auch hier in der einfachsten Form um eine gerade Linie handelt, in komplexeren Fällen jedoch um eine Hyperebene mit mehreren Dimensionen (eine pro Merkmal).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Da viele Sicherheitsprobleme im Wesentlichen Ja/Nein-Entscheidungen sind, wird Logistic Regression häufig eingesetzt. Beispielsweise könnte ein Intrusion-Detection-System Logistic Regression verwenden, um anhand der Merkmale einer Netzwerkverbindung zu entscheiden, ob es sich um einen Angriff handelt. Bei der Phishing-Erkennung kann Logistic Regression Merkmale einer Website (URL-Länge, Vorhandensein des Symbols "@", usw.) zu einer Wahrscheinlichkeit dafür kombinieren, dass es sich um Phishing handelt. Logistic Regression wurde in Spam-Filtern der frühen Generation eingesetzt und ist nach wie vor eine starke Baseline für viele Klassifizierungsaufgaben.

#### Logistic Regression für nicht binäre Klassifizierung

Logistic Regression ist für die binäre Klassifizierung ausgelegt, kann jedoch mithilfe von Techniken wie **one-vs-rest** (OvR) oder **softmax regression** auf Probleme mit mehreren Klassen erweitert werden. Bei OvR wird für jede Klasse ein separates Logistic-Regression-Modell trainiert, wobei diese als positive Klasse gegenüber allen anderen behandelt wird. Die Klasse mit der höchsten vorhergesagten Wahrscheinlichkeit wird als endgültige Vorhersage ausgewählt. Softmax regression verallgemeinert Logistic Regression auf mehrere Klassen, indem die Softmax-Funktion auf die Ausgabeschicht angewendet wird und eine Wahrscheinlichkeitsverteilung über alle Klassen erzeugt wird.

#### **Wichtige Merkmale von Logistic Regression:**

-   **Problemtyp:** Klassifizierung (normalerweise binär). Das Modell sagt die Wahrscheinlichkeit der positiven Klasse voraus.

-   **Interpretierbarkeit:** Hoch -- wie bei der linearen Regression können die Merkmalskoeffizienten anzeigen, wie jedes Merkmal die Log-Odds des Ergebnisses beeinflusst. Diese Transparenz wird im Sicherheitsbereich häufig geschätzt, um zu verstehen, welche Faktoren zu einem Alert beitragen.

-   **Vorteile:** Einfach und schnell zu trainieren; funktioniert gut, wenn die Beziehung zwischen den Merkmalen und den Log-Odds des Ergebnisses linear ist. Gibt Wahrscheinlichkeiten aus und ermöglicht dadurch eine Risikobewertung. Bei geeigneter Regularisierung generalisiert das Modell gut und kann Multikollinearität besser bewältigen als eine einfache lineare Regression.

-   **Einschränkungen:** Nimmt eine lineare Entscheidungsgrenze im Merkmalsraum an (versagt, wenn die tatsächliche Grenze komplex/nichtlinear ist). Bei Problemen, bei denen Interaktionen oder nichtlineare Effekte entscheidend sind, kann das Modell schlechter abschneiden, sofern nicht manuell polynomiale Merkmale oder Interaktionsmerkmale hinzugefügt werden. Logistic Regression ist außerdem weniger effektiv, wenn sich die Klassen nicht leicht durch eine lineare Kombination von Merkmalen trennen lassen.


<details>
<summary>Beispiel -- Erkennung von Phishing-Websites mit Logistic Regression:</summary>

Wir verwenden ein **Phishing Websites Dataset** (aus dem UCI-Repository), das extrahierte Merkmale von Websites enthält (z. B. ob die URL eine IP-Adresse enthält, das Alter der Domain, das Vorhandensein verdächtiger Elemente im HTML usw.) sowie ein Label, das angibt, ob die Website Phishing oder legitim ist. Wir trainieren ein Logistic-Regression-Modell, um Websites zu klassifizieren, und bewerten anschließend seine Accuracy, Precision, Recall, seinen F1-Score und seine ROC AUC anhand einer Testaufteilung.
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
In diesem Beispiel zur Erkennung von phishing erzeugt die logistische Regression für jede Website eine Wahrscheinlichkeit, dass es sich um eine phishing-Website handelt. Durch die Bewertung von Accuracy, Precision, Recall und F1 erhalten wir einen Eindruck von der Leistung des Modells. Ein hoher Recall würde beispielsweise bedeuten, dass die meisten phishing-Websites erkannt werden (wichtig für die Sicherheit, um möglichst wenige Angriffe zu übersehen), während eine hohe Precision bedeutet, dass es nur wenige Fehlalarme gibt (wichtig, um eine Ermüdung der Analysten zu vermeiden). Die ROC AUC (Area Under the ROC Curve) liefert ein schwellenwertunabhängiges Maß für die Leistung (1,0 ist ideal, 0,5 ist nicht besser als Zufall). Die logistische Regression erzielt bei solchen Aufgaben häufig gute Ergebnisse. Wenn die Entscheidungsgrenze zwischen phishing- und legitimen Websites jedoch komplex ist, werden möglicherweise leistungsfähigere nichtlineare Modelle benötigt.

</details>

### Entscheidungsbäume

Ein Entscheidungsbaum ist ein vielseitiger **Algorithmus für überwachtes Lernen**, der sowohl für Klassifikations- als auch für Regressionsaufgaben verwendet werden kann. Er lernt ein hierarchisches, baumähnliches Entscheidungsmodell auf Grundlage der Merkmale der Daten. Jeder interne Knoten des Baums stellt einen Test auf ein bestimmtes Merkmal dar, jeder Zweig repräsentiert ein Ergebnis dieses Tests, und jeder Blattknoten stellt eine vorhergesagte Klasse (bei der Klassifikation) oder einen Wert (bei der Regression) dar.<sup>[[2]](#references)</sup>

Zum Erstellen eines Baums verwenden Algorithmen wie CART (Classification and Regression Tree) Maße wie **Gini impurity** oder **information gain (entropy)**, um bei jedem Schritt das beste Merkmal und den besten Schwellenwert für die Aufteilung der Daten auszuwählen. Das Ziel jeder Aufteilung besteht darin, die Homogenität der Zielvariablen in den daraus entstehenden Teilmengen zu erhöhen (bei der Klassifikation soll jeder Knoten möglichst rein sein und überwiegend nur eine Klasse enthalten).

Entscheidungsbäume sind **sehr gut interpretierbar** -- man kann den Pfad von der Wurzel bis zum Blatt verfolgen, um die Logik hinter einer Vorhersage zu verstehen (z. B. *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Dies ist in der Cybersicherheit wertvoll, um zu erklären, warum ein bestimmter Alarm ausgelöst wurde. Bäume können sowohl numerische als auch kategoriale Daten natürlich verarbeiten und erfordern nur wenig Vorverarbeitung (z. B. ist eine Skalierung der Merkmale nicht erforderlich).

Ein einzelner Entscheidungsbaum kann die Trainingsdaten jedoch leicht überanpassen, insbesondere wenn er sehr tief aufgebaut wird (mit vielen Aufteilungen). Techniken wie Pruning (Begrenzung der Baumtiefe oder Festlegung einer Mindestanzahl von Stichproben pro Blatt) werden häufig eingesetzt, um Overfitting zu verhindern.

Ein Entscheidungsbaum besteht aus 3 Hauptkomponenten:
- **Root Node**: Der oberste Knoten des Baums, der den gesamten Datensatz repräsentiert.
- **Internal Nodes**: Knoten, die Merkmale und auf diesen Merkmalen basierende Entscheidungen repräsentieren.
- **Leaf Nodes**: Knoten, die das endgültige Ergebnis oder die Vorhersage repräsentieren.

Ein Baum könnte schließlich so aussehen:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Entscheidungsbäume werden in Intrusion-Detection-Systemen verwendet, um **Regeln** zur Identifizierung von Angriffen abzuleiten. Beispielsweise erzeugten frühe IDS auf Basis von ID3/C4.5 menschenlesbare Regeln, um normalen von bösartigem Datenverkehr zu unterscheiden. Sie werden auch bei der Malware-Analyse eingesetzt, um anhand ihrer Attribute (Dateigröße, Abschnittsentropie, API-Aufrufe usw.) zu entscheiden, ob eine Datei bösartig ist. Die Klarheit von Entscheidungsbäumen macht sie nützlich, wenn Transparenz erforderlich ist -- ein Analyst kann den Baum überprüfen, um die Erkennungslogik zu validieren.

#### **Wichtige Merkmale von Entscheidungsbäumen:**

-   **Problemtyp:** Sowohl Klassifikation als auch Regression. Häufig zur Klassifikation von Angriffen gegenüber normalem Datenverkehr usw. verwendet.

-   **Interpretierbarkeit:** Sehr hoch -- die Entscheidungen des Modells können visualisiert und als eine Reihe von Wenn-dann-Regeln verstanden werden. Dies ist ein wesentlicher Vorteil in der Sicherheit, da es Vertrauen und die Überprüfung des Modellverhaltens ermöglicht.

-   **Vorteile:** Kann nichtlineare Beziehungen und Interaktionen zwischen Merkmalen erfassen (jede Aufteilung kann als Interaktion betrachtet werden). Merkmale müssen nicht skaliert oder kategoriale Variablen per One-Hot-Encoding codiert werden -- Bäume verarbeiten diese nativ. Schnelle Inferenz (eine Vorhersage besteht lediglich darin, einem Pfad im Baum zu folgen).

-   **Einschränkungen:** Neigt zu Overfitting, wenn keine Kontrollmaßnahmen getroffen werden (ein tiefer Baum kann den Trainingsdatensatz auswendig lernen). Entscheidungsbäume können instabil sein -- kleine Änderungen an den Daten können zu einer anderen Baumstruktur führen. Als einzelne Modelle entspricht ihre Genauigkeit möglicherweise nicht der fortschrittlicherer Methoden (Ensembles wie Random Forests erzielen durch die Verringerung der Varianz typischerweise bessere Ergebnisse).

-   **Ermittlung der besten Aufteilung:**
- **Gini Impurity**: Misst die Unreinheit eines Knotens. Eine niedrigere Gini Impurity weist auf eine bessere Aufteilung hin. Die Formel lautet:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Dabei ist `p_i` der Anteil der Instanzen in Klasse `i`.

- **Entropy**: Misst die Unsicherheit im Datensatz. Eine niedrigere Entropy weist auf eine bessere Aufteilung hin. Die Formel lautet:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Dabei ist `p_i` der Anteil der Instanzen in Klasse `i`.

- **Information Gain**: Die Verringerung der Entropy oder Gini Impurity nach einer Aufteilung. Je höher der Information Gain, desto besser die Aufteilung. Er wird wie folgt berechnet:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Außerdem wird ein Baum beendet, wenn:
- Alle Instanzen in einem Knoten derselben Klasse angehören. Dies kann zu Overfitting führen.
- Die maximale Tiefe (hardcodiert) des Baums erreicht ist. Dies ist eine Möglichkeit, Overfitting zu verhindern.
- Die Anzahl der Instanzen in einem Knoten unter einem bestimmten Schwellenwert liegt. Dies ist ebenfalls eine Möglichkeit, Overfitting zu verhindern.
- Der Information Gain durch weitere Aufteilungen unter einem bestimmten Schwellenwert liegt. Dies ist ebenfalls eine Möglichkeit, Overfitting zu verhindern.

<details>
<summary>Beispiel -- Entscheidungsbaum zur Intrusion Detection:</summary>
Wir trainieren einen Entscheidungsbaum mit dem NSL-KDD-Datensatz, um Netzwerkverbindungen entweder als *normal* oder als *attack* zu klassifizieren. NSL-KDD ist eine verbesserte Version des klassischen KDD-Cup-1999-Datensatzes mit Merkmalen wie Protokolltyp, Dienst, Dauer, Anzahl fehlgeschlagener Anmeldungen usw. sowie einer Kennzeichnung, die den Angriffstyp oder „normal“ angibt. Wir ordnen alle Angriffstypen der Klasse „anomaly“ zu (binäre Klassifikation: normal gegenüber anomaly). Nach dem Training bewerten wir die Leistung des Baums anhand des Testdatensatzes.
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
In diesem Beispiel für einen Entscheidungsbaum haben wir die Baumtiefe auf 10 begrenzt, um extremes Overfitting zu vermeiden (der Parameter `max_depth=10`). Die Metriken zeigen, wie gut der Baum normalen Datenverkehr von Angriffsverkehr unterscheidet. Ein hoher Recall würde bedeuten, dass die meisten Angriffe erkannt werden (wichtig für ein IDS), während eine hohe Precision wenige Fehlalarme bedeutet. Entscheidungsbäume erreichen bei strukturierten Daten oft eine ordentliche Genauigkeit, aber ein einzelner Baum erzielt möglicherweise nicht die bestmögliche Performance. Dennoch ist die *Interpretierbarkeit* des Modells ein großer Vorteil -- wir könnten die Splits des Baums untersuchen, um beispielsweise zu sehen, welche Features (z. B. `service`, `src_bytes` usw.) den größten Einfluss darauf haben, eine Verbindung als bösartig zu kennzeichnen.

</details>

### Random Forests

Random Forest ist eine **Ensemble-Learning**-Methode, die auf Entscheidungsbäumen aufbaut, um die Performance zu verbessern. Ein Random Forest trainiert mehrere Entscheidungsbäume (daher „Forest“) und kombiniert deren Ausgaben, um eine endgültige Vorhersage zu treffen (bei der Klassifizierung typischerweise durch Mehrheitsentscheidung). Die beiden wichtigsten Konzepte in einem Random Forest sind **Bagging** (Bootstrap Aggregating) und **Feature Randomness**:

-   **Bagging:** Jeder Baum wird mit einer zufälligen Bootstrap-Stichprobe der Trainingsdaten trainiert (mit Zurücklegen gezogen). Dadurch entsteht Vielfalt zwischen den Bäumen.

-   **Feature Randomness:** Bei jedem Split in einem Baum wird eine zufällige Teilmenge der Features für den Split berücksichtigt (statt aller Features). Dadurch werden die Bäume zusätzlich voneinander entkoppelt.

Durch die Mittelung der Ergebnisse vieler Bäume reduziert der Random Forest die Varianz, die ein einzelner Entscheidungsbaum aufweisen kann. Vereinfacht gesagt können einzelne Bäume overfitten oder verrauscht sein, aber eine große Anzahl vielfältiger Bäume, die gemeinsam abstimmen, gleicht diese Fehler aus. Das Ergebnis ist oft ein Modell mit **höherer Genauigkeit** und besserer Generalisierung als bei einem einzelnen Entscheidungsbaum. Außerdem können Random Forests eine Schätzung der Feature Importance liefern (indem betrachtet wird, wie stark jeder Feature-Split die Unreinheit im Durchschnitt reduziert).

Random Forests haben sich in der **Cybersecurity** bei Aufgaben wie Intrusion Detection, Malware-Klassifizierung und Spam-Erkennung zu einem **Arbeitspferd** entwickelt. Sie liefern oft ohne umfangreiches Tuning gute Ergebnisse und können große Feature-Mengen verarbeiten. Bei der Intrusion Detection kann ein Random Forest beispielsweise einen einzelnen Entscheidungsbaum übertreffen, indem er subtilere Angriffsmuster mit weniger False Positives erkennt. Untersuchungen haben gezeigt, dass Random Forests bei der Klassifizierung von Angriffen in Datensätzen wie NSL-KDD und UNSW-NB15 im Vergleich zu anderen Algorithmen gut abschneiden.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Wichtige Eigenschaften von Random Forests:**

-   **Problemtyp:** Primär Klassifizierung (wird auch für Regression verwendet). Sehr gut für hochdimensionale strukturierte Daten geeignet, wie sie häufig in Security-Logs vorkommen.

-   **Interpretierbarkeit:** Geringer als bei einem einzelnen Entscheidungsbaum -- Hunderte von Bäumen lassen sich nicht ohne Weiteres gleichzeitig visualisieren oder erklären. Feature-Importance-Werte geben jedoch einen gewissen Einblick darin, welche Attribute den größten Einfluss haben.

-   **Vorteile:** Aufgrund des Ensemble-Effekts im Allgemeinen höhere Genauigkeit als Single-Tree-Modelle. Robust gegenüber Overfitting -- selbst wenn einzelne Bäume overfitten, generalisiert das Ensemble besser. Verarbeitet sowohl numerische als auch kategorische Features und kann fehlende Daten bis zu einem gewissen Grad verwalten. Außerdem ist es relativ robust gegenüber Ausreißern.

-   **Einschränkungen:** Die Modellgröße kann beträchtlich sein (viele Bäume, von denen jeder potenziell tief sein kann). Vorhersagen sind langsamer als bei einem einzelnen Baum (da die Ergebnisse vieler Bäume aggregiert werden müssen). Geringere Interpretierbarkeit -- obwohl wichtige Features bekannt sind, lässt sich die genaue Logik nicht ohne Weiteres wie eine einfache Regel nachvollziehen. Wenn der Datensatz extrem hochdimensional und dünn besetzt ist, kann das Training eines sehr großen Forests rechenintensiv sein.

-   **Trainingsprozess:**
1. **Bootstrap Sampling**: Ziehe zufällig Trainingsdaten mit Zurücklegen, um mehrere Teilmengen (Bootstrap-Stichproben) zu erstellen.
2. **Baumkonstruktion**: Erstelle für jede Bootstrap-Stichprobe einen Entscheidungsbaum und verwende bei jedem Split eine zufällige Teilmenge der Features. Dadurch entsteht Vielfalt zwischen den Bäumen.
3. **Aggregation**: Bei Klassifizierungsaufgaben wird die endgültige Vorhersage durch eine Mehrheitsentscheidung unter den Vorhersagen aller Bäume getroffen. Bei Regressionsaufgaben ist die endgültige Vorhersage der Durchschnitt der Vorhersagen aller Bäume.

<details>
<summary>Beispiel -- Random Forest für Intrusion Detection (NSL-KDD):</summary>
Wir verwenden denselben NSL-KDD-Datensatz (binär als normal oder Anomalie gekennzeichnet) und trainieren einen Random-Forest-Klassifikator. Wir erwarten, dass der Random Forest dank der Varianzreduzierung durch die Mittelung im Ensemble genauso gut oder besser abschneidet als der einzelne Entscheidungsbaum. Wir bewerten ihn anhand derselben Metriken.
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
Der Random Forest erzielt bei dieser Aufgabe zur Intrusion Detection typischerweise starke Ergebnisse. Im Vergleich zum einzelnen Entscheidungsbaum könnten wir eine Verbesserung bei Metriken wie F1 oder AUC beobachten, insbesondere bei Recall oder Precision, abhängig von den Daten. Dies entspricht der Erkenntnis, dass *„Random Forest (RF) ein Ensemble-Klassifikator ist und im Vergleich zu anderen traditionellen Klassifikatoren eine effektive Klassifizierung von Angriffen ermöglicht.“* Im Kontext von Security Operations könnte ein Random-Forest-Modell Angriffe zuverlässiger erkennen und gleichzeitig Fehlalarme reduzieren, da es viele Entscheidungsregeln mittelt. Die Feature Importance des Forests könnte uns zeigen, welche Netzwerk-Features am stärksten auf Angriffe hindeuten, z. B. bestimmte Netzwerkdienste oder ungewöhnliche Paketanzahlen.

</details>

### Support Vector Machines (SVM)

Support Vector Machines sind leistungsfähige Modelle des überwachten Lernens, die hauptsächlich zur Klassifizierung verwendet werden, aber auch für Regression als SVR. Eine SVM versucht, die **optimale trennende Hyperebene** zu finden, die den Margin zwischen zwei Klassen maximiert. Nur eine Teilmenge der Trainingspunkte, die sogenannten „Support Vectors“, die der Grenze am nächsten liegen, bestimmt die Position dieser Hyperebene. Durch die Maximierung des Margins, also des Abstands zwischen den Support Vectors und der Hyperebene, erreichen SVMs tendenziell eine gute Generalisierung.<sup>[[4]](#references)</sup>

Ein wesentlicher Grund für die Leistungsfähigkeit von SVMs ist die Möglichkeit, **Kernel-Funktionen** zu verwenden, um nichtlineare Zusammenhänge zu verarbeiten. Die Daten können implizit in einen höherdimensionalen Feature-Raum transformiert werden, in dem möglicherweise ein linearer Trenner existiert. Zu den verbreiteten Kernels gehören polynomial, radial basis function (RBF) und sigmoid. Wenn Netzwerk-Traffic-Klassen beispielsweise im ursprünglichen Feature-Raum nicht linear trennbar sind, kann ein RBF-Kernel sie in eine höhere Dimension abbilden, in der die SVM eine lineare Trennung findet, die im ursprünglichen Raum einer nichtlinearen Grenze entspricht. Die Möglichkeit, verschiedene Kernels auszuwählen, erlaubt es SVMs, eine Vielzahl von Problemen zu bearbeiten.

SVMs erzielen bekanntermaßen gute Ergebnisse in Situationen mit hochdimensionalen Feature-Räumen, etwa bei Textdaten oder Malware-Opcode-Sequenzen, sowie in Fällen, in denen die Anzahl der Features im Verhältnis zur Anzahl der Samples groß ist. In vielen frühen Cybersecurity-Anwendungen wie der Malware-Klassifizierung und der anomaliebasierten Intrusion Detection in den 2000er-Jahren waren sie beliebt und erzielten häufig eine hohe Accuracy.

SVMs lassen sich jedoch nicht einfach auf sehr große Datensätze skalieren, da die Trainingskomplexität superlinear mit der Anzahl der Samples steigt und der Speicherverbrauch hoch sein kann, weil möglicherweise viele Support Vectors gespeichert werden müssen. In der Praxis könnte eine SVM bei Aufgaben wie der Network Intrusion Detection mit Millionen von Datensätzen ohne sorgfältiges Subsampling oder approximative Methoden zu langsam sein.

#### **Wichtige Merkmale von SVM:**

-   **Problemtyp:** Klassifizierung, binär oder multiklassig über one-vs-one/one-vs-rest, sowie Regressionsvarianten. Wird häufig für die binäre Klassifizierung mit klarer Margin-Trennung verwendet.

-   **Interpretierbarkeit:** Mittel -- SVMs sind nicht so interpretierbar wie Entscheidungsbäume oder die logistische Regression. Zwar kann man feststellen, welche Datenpunkte Support Vectors sind, und anhand der Gewichte im Fall eines linearen Kernels ein gewisses Verständnis dafür gewinnen, welche Features möglicherweise einflussreich sind; in der Praxis werden SVMs, insbesondere mit nichtlinearen Kernels, jedoch als Black-Box-Klassifikatoren behandelt.

-   **Vorteile:** Effektiv in hochdimensionalen Räumen; kann mithilfe des Kernel-Tricks komplexe Entscheidungsgrenzen modellieren; robust gegenüber Overfitting, wenn der Margin maximiert wird, insbesondere mit einem geeigneten Regularisierungsparameter C; funktioniert auch dann gut, wenn die Klassen nicht durch einen großen Abstand getrennt sind, da die bestmögliche Kompromissgrenze gefunden wird.

-   **Einschränkungen:** **Rechenintensiv** bei großen Datensätzen, da sowohl Training als auch Prediction mit zunehmender Datenmenge schlecht skalieren. Erfordert eine sorgfältige Abstimmung der Kernel- und Regularisierungsparameter, etwa C, Kernel-Typ und Gamma für RBF. Liefert nicht direkt probabilistische Ausgaben, wobei sich mithilfe von Platt Scaling Wahrscheinlichkeiten berechnen lassen. Außerdem können SVMs empfindlich auf die Wahl der Kernel-Parameter reagieren -- eine schlechte Wahl kann zu Underfitting oder Overfitting führen.

*Einsatzbereiche in der Cybersecurity:* SVMs wurden bei der **Malware Detection**, etwa zur Klassifizierung von Dateien anhand extrahierter Features oder Opcode-Sequenzen, bei der **Network Anomaly Detection**, also der Klassifizierung von Traffic als normal oder bösartig, sowie bei der **Phishing Detection** anhand von URL-Features eingesetzt. Eine SVM könnte beispielsweise Features einer E-Mail, etwa die Anzahl bestimmter Keywords oder Sender-Reputationswerte, verarbeiten und sie als Phishing oder legitim klassifizieren. Sie wurden auch bei der **Intrusion Detection** mit Feature-Sets wie KDD eingesetzt und erzielten häufig eine hohe Accuracy, allerdings auf Kosten des Rechenaufwands.

<details>
<summary>Beispiel -- SVM zur Malware-Klassifizierung:</summary>
Wir verwenden erneut den Datensatz zu Phishing-Websites, diesmal mit einer SVM. Da SVMs langsam sein können, verwenden wir bei Bedarf eine Teilmenge der Daten für das Training. Der Datensatz umfasst etwa 11.000 Instanzen, die eine SVM noch angemessen verarbeiten kann. Wir verwenden einen RBF-Kernel, der häufig für nichtlineare Daten eingesetzt wird, und aktivieren Wahrscheinlichkeitsschätzungen, um ROC AUC zu berechnen.
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
Das SVM-Modell wird Metriken ausgeben, die wir mit der logistischen Regression bei derselben Aufgabe vergleichen können. Wir könnten feststellen, dass SVM eine hohe Genauigkeit und AUC erreicht, wenn die Daten anhand der Features gut getrennt sind. Wenn der Datensatz hingegen viel Rauschen oder überlappende Klassen enthält, übertrifft SVM die logistische Regression möglicherweise nicht deutlich. In der Praxis können SVMs einen Vorteil bieten, wenn komplexe, nichtlineare Beziehungen zwischen Features und Klassen bestehen – der RBF-Kernel kann gekrümmte Entscheidungsgrenzen erfassen, die die logistische Regression übersehen würde. Wie bei allen Modellen ist eine sorgfältige Abstimmung von `C` (Regularisierung) und den Kernel-Parametern (z. B. `gamma` für RBF) erforderlich, um Bias und Varianz auszugleichen.

</details>

#### Unterschiede zwischen logistischer Regression und SVM

| Aspekt | **Logistische Regression** | **Support Vector Machines** |
|---|---|---|
| **Zielfunktion** | Minimiert den **Log-Loss** (Cross-Entropy). | Maximiert den **Margin**, während der **Hinge-Loss** minimiert wird. |
| **Entscheidungsgrenze** | Findet die **Best-Fit-Hyperebene**, die _P(y\|x)_ modelliert. | Findet die **Hyperebene mit maximalem Margin** (größter Abstand zu den nächstgelegenen Punkten). |
| **Ausgabe** | **Probabilistisch** – liefert kalibrierte Klassenwahrscheinlichkeiten über σ(w·x + b). | **Deterministisch** – gibt Klassenlabels zurück; Wahrscheinlichkeiten erfordern zusätzliche Verarbeitung (z. B. Platt Scaling). |
| **Regularisierung** | L2 (Standard) oder L1; gleicht Underfitting und Overfitting direkt aus. | Der C-Parameter stellt einen Kompromiss zwischen der Breite des Margins und Fehlklassifikationen dar; Kernel-Parameter erhöhen die Komplexität. |
| **Kernels / Nichtlinearität** | Die native Form ist **linear**; Nichtlinearität wird durch Feature Engineering hinzugefügt. | Der integrierte **Kernel Trick** (RBF, Polynom usw.) ermöglicht die Modellierung komplexer Grenzen in hochdimensionalen Räumen. |
| **Skalierbarkeit** | Löst eine konvexe Optimierung in **O(nd)**; geeignet für sehr große n. | Das Training kann ohne spezialisierte Solver **O(n²–n³)** Speicher/Zeit benötigen; weniger geeignet für sehr große n. |
| **Interpretierbarkeit** | **Hoch** – Gewichte zeigen den Einfluss der Features; das Odds Ratio ist intuitiv verständlich. | **Niedrig** bei nichtlinearen Kernels; Support Vectors sind zwar dünn besetzt, aber schwer zu erklären. |
| **Empfindlichkeit gegenüber Ausreißern** | Verwendet einen glatten Log-Loss → weniger empfindlich. | Hinge-Loss mit Hard Margin kann **empfindlich** sein; ein Soft Margin (C) wirkt dem entgegen. |
| **Typische Anwendungsfälle** | Kreditbewertung, medizinische Risiken, A/B-Tests – wenn **Wahrscheinlichkeiten und Erklärbarkeit** wichtig sind. | Bild-/Textklassifikation, Bioinformatik – wenn **komplexe Grenzen** und **hochdimensionale Daten** wichtig sind. |

* **Wenn du kalibrierte Wahrscheinlichkeiten und Interpretierbarkeit benötigst oder mit riesigen Datensätzen arbeitest – wähle die logistische Regression.**
* **Wenn du ein flexibles Modell benötigst, das nichtlineare Beziehungen ohne manuelles Feature Engineering erfassen kann – wähle SVM (mit Kernels).**
* Beide optimieren konvexe Zielfunktionen, daher sind **globale Minima garantiert**. Die Kernels von SVM fügen jedoch Hyperparameter und zusätzlichen Rechenaufwand hinzu.

### Naive Bayes

Naive Bayes ist eine Gruppe **probabilistischer Klassifikatoren**, die auf der Anwendung des Satzes von Bayes mit einer starken Unabhängigkeitsannahme zwischen den Features basiert. Trotz dieser „naiven“ Annahme funktioniert Naive Bayes in bestimmten Anwendungen oft überraschend gut, insbesondere bei Texten oder kategorialen Daten, beispielsweise bei der Spam-Erkennung.<sup>[[5]](#references)</sup>


#### Satz von Bayes

Der Satz von Bayes bildet die Grundlage der Naive-Bayes-Klassifikatoren. Er stellt einen Zusammenhang zwischen den bedingten und den marginalen Wahrscheinlichkeiten zufälliger Ereignisse her. Die Formel lautet:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Wo:
- `P(A|B)` ist die a-posteriori-Wahrscheinlichkeit der Klasse `A` bei gegebenem Merkmal `B`.
- `P(B|A)` ist die Wahrscheinlichkeit des Merkmals `B` bei gegebener Klasse `A`.
- `P(A)` ist die a-priori-Wahrscheinlichkeit der Klasse `A`.
- `P(B)` ist die a-priori-Wahrscheinlichkeit des Merkmals `B`.

Wenn wir beispielsweise klassifizieren möchten, ob ein Text von einem Kind oder einem Erwachsenen geschrieben wurde, können wir die Wörter im Text als Merkmale verwenden. Basierend auf einigen anfänglichen Daten berechnet der Naive-Bayes-Klassifikator zunächst die Wahrscheinlichkeiten dafür, dass jedes Wort zu jeder möglichen Klasse (Kind oder Erwachsener) gehört. Wenn ein neuer Text eingegeben wird, berechnet er die Wahrscheinlichkeit jeder möglichen Klasse anhand der Wörter im Text und wählt die Klasse mit der höchsten Wahrscheinlichkeit.

Wie Sie in diesem Beispiel sehen können, ist der Naive-Bayes-Klassifikator sehr einfach und schnell. Er nimmt jedoch an, dass die Merkmale unabhängig sind, was bei realen Daten nicht immer der Fall ist.


#### **Wichtige Merkmale von Naive Bayes:**

-   **Problemtyp:** Klassifikation (binär oder mehrklassig). Häufig für Textklassifikationsaufgaben in der Cybersicherheit verwendet (Spam, Phishing usw.).

-   **Interpretierbarkeit:** Mittel -- der Algorithmus ist nicht so direkt interpretierbar wie ein Entscheidungsbaum, aber man kann die erlernten Wahrscheinlichkeiten untersuchen (z. B. welche Wörter am wahrscheinlichsten in Spam- bzw. Ham-E-Mails vorkommen). Die Form des Modells (Wahrscheinlichkeiten für jedes Merkmal bei gegebener Klasse) kann bei Bedarf verstanden werden.

-   **Vorteile:** **Sehr schnelles** Training und sehr schnelle Vorhersagen, selbst bei großen Datensätzen (linear zur Anzahl der Instanzen * Anzahl der Merkmale). Benötigt relativ wenige Daten, um Wahrscheinlichkeiten zuverlässig zu schätzen, insbesondere bei geeigneter Glättung. Als Baseline ist der Algorithmus oft überraschend genau, besonders wenn Merkmale unabhängig voneinander Hinweise auf die Klasse liefern. Funktioniert gut mit hochdimensionalen Daten (z. B. Tausenden von Merkmalen aus Texten). Außer dem Festlegen eines Glättungsparameters ist keine komplexe Abstimmung erforderlich.

-   **Einschränkungen:** Die Unabhängigkeitsannahme kann die Genauigkeit begrenzen, wenn Merkmale stark miteinander korreliert sind. In Netzwerkdaten könnten beispielsweise Merkmale wie `src_bytes` und `dst_bytes` korreliert sein; Naive Bayes erfasst diese Wechselwirkung nicht. Wenn die Datenmenge sehr groß wird, können ausdrucksstärkere Modelle (wie Ensembles oder neuronale Netze) NB übertreffen, da sie Abhängigkeiten zwischen Merkmalen erlernen. Wenn außerdem eine bestimmte Kombination von Merkmalen erforderlich ist, um einen Angriff zu erkennen, und nicht nur einzelne Merkmale unabhängig voneinander betrachtet werden können, wird NB Schwierigkeiten haben.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Der klassische Einsatz ist die **Spam-Erkennung** -- Naive Bayes bildete den Kern früher Spam-Filter. Dabei wurden die Häufigkeiten bestimmter Tokens (Wörter, Ausdrücke, IP-Adressen) verwendet, um die Wahrscheinlichkeit zu berechnen, dass eine E-Mail Spam ist. Der Algorithmus wird auch bei der **Erkennung von Phishing-E-Mails** und der **URL-Klassifikation** eingesetzt, wobei das Vorhandensein bestimmter Schlüsselwörter oder Merkmale (wie „login.php“ in einer URL oder `@` in einem URL-Pfad) zur Phishing-Wahrscheinlichkeit beitragen. Bei der Malware-Analyse könnte man sich einen Naive-Bayes-Klassifikator vorstellen, der das Vorhandensein bestimmter API-Aufrufe oder Berechtigungen in Software verwendet, um vorherzusagen, ob es sich um Malware handelt. Obwohl fortgeschrittenere Algorithmen häufig bessere Ergebnisse erzielen, bleibt Naive Bayes aufgrund seiner Geschwindigkeit und Einfachheit eine gute Baseline.

<details>
<summary>Beispiel -- Naive Bayes zur Phishing-Erkennung:</summary>
Um Naive Bayes zu demonstrieren, verwenden wir Gaussian Naive Bayes für den NSL-KDD-Intrusion-Datensatz (mit binären Labels). Gaussian NB behandelt jedes Merkmal pro Klasse so, als würde es einer Normalverteilung folgen. Dies ist eine grobe Wahl, da viele Netzwerkmerkmale diskret oder stark verzerrt sind, aber es zeigt, wie NB auf kontinuierliche Merkmalsdaten angewendet werden kann. Wir könnten auch Bernoulli NB auf einem Datensatz mit binären Merkmalen verwenden (z. B. einer Sammlung ausgelöster Alerts), bleiben hier zur Kontinuität jedoch bei NSL-KDD.
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
Dieser Code trainiert einen Naive-Bayes-Klassifikator, um Angriffe zu erkennen. Naive Bayes berechnet anhand der Trainingsdaten Größen wie `P(service=http | Attack)` und `P(Service=http | Normal)` und nimmt dabei die Unabhängigkeit der Features an. Anschließend verwendet er diese Wahrscheinlichkeiten, um neue Verbindungen anhand der beobachteten Features entweder als normal oder als Angriff zu klassifizieren. Die Leistung von NB auf NSL-KDD ist möglicherweise nicht so hoch wie bei fortgeschritteneren Modellen (da die Unabhängigkeit der Features verletzt wird), ist aber oft ordentlich und bietet den Vorteil extremer Geschwindigkeit. In Szenarien wie der E-Mail-Filterung in Echtzeit oder der ersten Triage von URLs kann ein Naive-Bayes-Modell offensichtlich bösartige Fälle bei geringem Ressourcenverbrauch schnell markieren.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ist einer der einfachsten Machine-Learning-Algorithmen. Es handelt sich um eine **nichtparametrische, instanzbasierte** Methode, die Vorhersagen anhand der Ähnlichkeit zu Beispielen im Trainingsdatensatz trifft. Die Idee bei der Klassifizierung lautet: Um einen neuen Datenpunkt zu klassifizieren, werden die **k** nächstgelegenen Punkte in den Trainingsdaten (seine „nächsten Nachbarn“) gefunden und die Mehrheitsklasse unter diesen Nachbarn zugewiesen. Die „Nähe“ wird durch eine Distanzmetrik definiert, typischerweise durch die euklidische Distanz bei numerischen Daten (für verschiedene Arten von Features oder Problemen können andere Distanzen verwendet werden).<sup>[[10]](#references)</sup>

K-NN benötigt *kein explizites Training* -- die „Trainingsphase“ besteht lediglich darin, den Datensatz zu speichern. Die gesamte Arbeit findet während der Abfrage (Vorhersage) statt: Der Algorithmus muss die Distanzen vom Abfragepunkt zu allen Trainingspunkten berechnen, um die nächstgelegenen Punkte zu finden. Dadurch ist die Vorhersagezeit **linear zur Anzahl der Trainingsbeispiele**, was bei großen Datensätzen kostspielig sein kann. Daher eignet sich k-NN am besten für kleinere Datensätze oder Szenarien, in denen man für Einfachheit einen Kompromiss bei Speicherbedarf und Geschwindigkeit eingehen kann.

Trotz seiner Einfachheit kann k-NN sehr komplexe Entscheidungsgrenzen modellieren (da die Entscheidungsgrenze effektiv jede Form annehmen kann, die durch die Verteilung der Beispiele vorgegeben wird). Es funktioniert tendenziell gut, wenn die Entscheidungsgrenze sehr unregelmäßig ist und viele Daten vorhanden sind -- im Wesentlichen lässt es die Daten „für sich selbst sprechen“. In hohen Dimensionen können Distanzmetriken jedoch weniger aussagekräftig werden (Fluch der Dimensionalität), und die Methode kann Schwierigkeiten bekommen, sofern nicht eine sehr große Anzahl an Beispielen vorhanden ist.

*Anwendungsfälle in der Cybersecurity:* k-NN wurde bei der Anomalieerkennung eingesetzt -- beispielsweise könnte ein Intrusion-Detection-System ein Netzwerkereignis als bösartig markieren, wenn die meisten seiner nächsten Nachbarn (vorherige Ereignisse) bösartig waren. Wenn normaler Traffic Cluster bildet und Angriffe Ausreißer sind, entspricht ein K-NN-Ansatz (mit k=1 oder einem kleinen k) im Wesentlichen einer **Nearest-Neighbor-Anomalieerkennung**. K-NN wurde außerdem zur Klassifizierung von Malware-Familien anhand binärer Feature-Vektoren verwendet: Eine neue Datei könnte als eine bestimmte Malware-Familie klassifiziert werden, wenn sie im Feature-Raum bekannten Instanzen dieser Familie sehr nahekommt. In der Praxis ist k-NN nicht so verbreitet wie besser skalierbare Algorithmen, aber es ist konzeptionell unkompliziert und wird manchmal als Baseline oder für Probleme kleinen Umfangs eingesetzt.

#### **Wichtige Eigenschaften von k-NN:**

-   **Problemtyp:** Klassifizierung (Varianten für Regression existieren ebenfalls). Es handelt sich um eine *Lazy-Learning*-Methode -- es findet keine explizite Modellanpassung statt.

-   **Interpretierbarkeit:** Niedrig bis mittel -- es gibt kein globales Modell und keine prägnante Erklärung, aber die Ergebnisse können durch Betrachtung der nächsten Nachbarn interpretiert werden, die eine Entscheidung beeinflusst haben (z. B. „Dieser Netzwerkdatenfluss wurde als bösartig klassifiziert, weil er diesen 3 bekannten bösartigen Datenflüssen ähnelt“). Erklärungen können somit beispielbasiert sein.

-   **Vorteile:** Sehr einfach zu implementieren und zu verstehen. Macht keine Annahmen über die Datenverteilung (nichtparametrisch). Kann Mehrklassenprobleme von Natur aus verarbeiten. Es ist **adaptiv**, da Entscheidungsgrenzen sehr komplex sein und durch die Datenverteilung geprägt werden können.

-   **Einschränkungen:** Die Vorhersage kann bei großen Datensätzen langsam sein (es müssen viele Distanzen berechnet werden). Hoher Speicherbedarf -- der gesamte Trainingsdatensatz wird gespeichert. Die Leistung nimmt in hochdimensionalen Feature-Räumen ab, da alle Punkte tendenziell nahezu gleich weit voneinander entfernt sind (wodurch das Konzept des „nächsten“ Punkts weniger aussagekräftig wird). *k* (die Anzahl der Nachbarn) muss passend gewählt werden -- ein zu kleines k kann verrauscht sein, ein zu großes k kann irrelevante Punkte aus anderen Klassen einbeziehen. Außerdem sollten Features angemessen skaliert werden, da Distanzberechnungen empfindlich auf unterschiedliche Maßstäbe reagieren.

<details>
<summary>Beispiel -- k-NN zur Phishing-Erkennung:</summary>

Wir verwenden erneut NSL-KDD (binäre Klassifizierung). Da k-NN rechenintensiv ist, verwenden wir eine Teilmenge der Trainingsdaten, damit die Demonstration praktikabel bleibt. Wir wählen beispielsweise 20.000 Trainingsbeispiele aus den vollständigen 125.000 aus und verwenden k=5 Nachbarn. Nach dem Training (bei dem die Daten eigentlich nur gespeichert werden) evaluieren wir das Modell anhand des Testdatensatzes. Außerdem skalieren wir die Features für die Distanzberechnung, um sicherzustellen, dass aufgrund unterschiedlicher Maßstäbe kein einzelnes Feature dominiert.
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
Das k-NN-Modell klassifiziert eine Verbindung, indem es die 5 nächstgelegenen Verbindungen in der Teilmenge des Trainingsdatensatzes betrachtet. Wenn beispielsweise 4 dieser Nachbarn Angriffe (Anomalien) und 1 normal ist, wird die neue Verbindung als Angriff klassifiziert. Die Leistung kann akzeptabel sein, liegt jedoch oft nicht so hoch wie bei einem gut abgestimmten Random Forest oder SVM auf denselben Daten. k-NN kann jedoch manchmal glänzen, wenn die Klassenverteilungen sehr unregelmäßig und komplex sind – da es effektiv eine speicherbasierte Suche verwendet. In der Cybersicherheit könnte k-NN (mit k=1 oder einem kleinen k) zur Erkennung bekannter Angriffsmuster anhand von Beispielen oder als Komponente komplexerer Systeme eingesetzt werden (z. B. zum Clustering und anschließenden Klassifizieren anhand der Clusterzugehörigkeit).
</details>

### Gradient Boosting Machines (z. B. XGBoost)

Gradient Boosting Machines gehören zu den leistungsfähigsten Algorithmen für strukturierte Daten. **Gradient boosting** bezeichnet die Technik, ein Ensemble schwacher Lerner (häufig Entscheidungsbäume) sequenziell aufzubauen, wobei jedes neue Modell die Fehler des vorherigen Ensembles korrigiert. Im Gegensatz zu Bagging (Random Forests), bei dem Bäume parallel erstellt und anschließend gemittelt werden, erstellt Boosting die Bäume *nacheinander*, wobei sich jeder stärker auf die Instanzen konzentriert, die von den vorherigen Bäumen falsch vorhergesagt wurden.

Die beliebtesten Implementierungen der letzten Jahre sind **XGBoost**, **LightGBM** und **CatBoost**. Alle sind Bibliotheken für Gradient Boosting Decision Trees (GBDT). Sie waren bei Machine-Learning-Wettbewerben und in praktischen Anwendungen äußerst erfolgreich und erzielen häufig **State-of-the-Art-Leistung bei tabellarischen Datensätzen**. In der Cybersicherheit haben Forscher und Praktiker Gradient-Boosted Trees für Aufgaben wie **Malware-Erkennung** (unter Verwendung aus Dateien oder Laufzeitverhalten extrahierter Merkmale) und **Network Intrusion Detection** eingesetzt. Beispielsweise kann ein Gradient-Boosting-Modell viele schwache Regeln (Bäume) wie „wenn viele SYN-Pakete und ein ungewöhnlicher Port -> wahrscheinlich Scan“ zu einem starken kombinierten Detektor verbinden, der viele subtile Muster berücksichtigt.<sup>[[6]](#references)</sup>

Warum sind Boosted Trees so effektiv? Jeder Baum in der Sequenz wird auf den *Residuenfehlern* (Gradienten) der Vorhersagen des aktuellen Ensembles trainiert. Auf diese Weise **„boostet“** das Modell schrittweise die Bereiche, in denen es schwach ist. Die Verwendung von Entscheidungsbäumen als Basismodellen ermöglicht es dem finalen Modell, komplexe Wechselwirkungen und nichtlineare Beziehungen zu erfassen. Außerdem verfügt Boosting über eine Form integrierter Regularisierung: Durch das Hinzufügen vieler kleiner Bäume (und die Verwendung einer Lernrate zur Skalierung ihrer Beiträge) generalisiert es häufig gut, ohne starkes Overfitting, vorausgesetzt, die richtigen Parameter werden gewählt.

#### **Wichtige Merkmale von Gradient Boosting:**

-   **Problemtyp:** Hauptsächlich Klassifikation und Regression. In der Sicherheit meist Klassifikation (z. B. binäre Klassifikation einer Verbindung oder Datei). Es unterstützt binäre und Multi-Class-Probleme (mit geeigneter Loss-Funktion) sowie Ranking-Probleme.

-   **Interpretierbarkeit:** Gering bis mittel. Während ein einzelner Boosted Tree klein ist, kann ein vollständiges Modell Hunderte von Bäumen enthalten und ist als Ganzes nicht für Menschen interpretierbar. Wie ein Random Forest kann es jedoch Feature-Importance-Werte liefern, und Tools wie SHAP (SHapley Additive exPlanations) können verwendet werden, um einzelne Vorhersagen bis zu einem gewissen Grad zu interpretieren.

-   **Vorteile:** Häufig der **leistungsstärkste** Algorithmus für strukturierte/tabellarische Daten. Kann komplexe Muster und Wechselwirkungen erkennen. Verfügt über zahlreiche Stellschrauben (Anzahl der Bäume, Baumtiefe, Lernrate, Regularisierungsterme), mit denen sich die Modellkomplexität anpassen und Overfitting verhindern lässt. Moderne Implementierungen sind auf Geschwindigkeit optimiert (XGBoost verwendet beispielsweise Gradienteninformationen zweiter Ordnung und effiziente Datenstrukturen). Bei Kombination mit geeigneten Loss-Funktionen oder durch Anpassung der Sample-Gewichte kann es unausgeglichene Daten tendenziell besser verarbeiten.

-   **Einschränkungen:** Schwieriger abzustimmen als einfachere Modelle; das Training kann langsam sein, wenn die Bäume tief sind oder die Anzahl der Bäume groß ist (obwohl es in der Regel immer noch schneller ist als das Training eines vergleichbaren Deep Neural Networks auf denselben Daten). Das Modell kann overfitten, wenn es nicht abgestimmt wird (z. B. bei zu vielen tiefen Bäumen mit unzureichender Regularisierung). Aufgrund der vielen Hyperparameter erfordert die effektive Verwendung von Gradient Boosting möglicherweise mehr Fachwissen oder Experimente. Wie baumbasierte Methoden verarbeitet es außerdem sehr sparse, hochdimensionale Daten nicht grundsätzlich so effizient wie lineare Modelle oder Naive Bayes (obwohl es beispielsweise bei Textklassifikation eingesetzt werden kann, ohne Feature Engineering jedoch möglicherweise nicht die erste Wahl ist).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Fast überall dort, wo ein Entscheidungsbaum oder Random Forest eingesetzt werden könnte, kann ein Gradient-Boosting-Modell eine höhere Genauigkeit erreichen. Beispielsweise wurde bei **Microsofts Malware-Erkennungs**-Wettbewerben XGBoost intensiv auf entwickelten Merkmalen aus Binärdateien eingesetzt. Die Forschung zu **Network Intrusion Detection** berichtet häufig über Spitzenresultate mit GBDTs (z. B. XGBoost auf den Datensätzen CIC-IDS2017 oder UNSW-NB15). Diese Modelle können eine große Bandbreite an Merkmalen (Protokolltypen, Häufigkeit bestimmter Ereignisse, statistische Merkmale des Datenverkehrs usw.) aufnehmen und kombinieren, um Bedrohungen zu erkennen. Bei der Phishing-Erkennung kann Gradient Boosting lexikalische Merkmale von URLs, Merkmale zur Domain-Reputation und Merkmale des Seiteninhalts kombinieren, um eine sehr hohe Genauigkeit zu erreichen. Der Ensemble-Ansatz hilft dabei, viele Sonderfälle und Feinheiten in den Daten abzudecken.

<details>
<summary>Beispiel -- XGBoost zur Phishing-Erkennung:</summary>
Wir verwenden einen Gradient-Boosting-Klassifikator auf dem Phishing-Datensatz. Um die Sache einfach und eigenständig zu halten, verwenden wir `sklearn.ensemble.GradientBoostingClassifier` (eine langsamere, aber unkomplizierte Implementierung). Normalerweise würde man für eine bessere Leistung und zusätzliche Funktionen die Bibliotheken `xgboost` oder `lightgbm` verwenden. Wir werden das Modell trainieren und es ähnlich wie zuvor evaluieren.
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
Das Gradient-Boosting-Modell wird bei diesem Phishing-Datensatz wahrscheinlich eine sehr hohe Genauigkeit und AUC erreichen (mit der richtigen Abstimmung können solche Modelle bei diesen Daten oft eine Genauigkeit von über 95 % erzielen, wie es auch in der Literatur zu sehen ist). Dies zeigt, warum GBDTs als *„das State-of-the-Art-Modell für tabellarische Datensätze“* gelten -- sie übertreffen häufig einfachere Algorithmen, da sie komplexe Muster erfassen. Im Kontext der Cybersicherheit könnte dies bedeuten, dass mehr Phishing-Seiten oder Angriffe erkannt werden und weniger übersehen werden. Natürlich muss man sich vor Overfitting hüten -- bei der Entwicklung eines solchen Modells für den Einsatz würden wir typischerweise Techniken wie Cross-Validation verwenden und die Leistung auf einem Validierungsdatensatz überwachen.

</details>

### Modelle kombinieren: Ensemble Learning und Stacking

Ensemble Learning ist eine Strategie zur **Kombination mehrerer Modelle**, um die Gesamtleistung zu verbessern. Wir haben bereits spezifische Ensemble-Methoden gesehen: Random Forest (ein Ensemble von Bäumen mittels Bagging) und Gradient Boosting (ein Ensemble von Bäumen mittels sequenziellem Boosting). Ensembles können jedoch auch auf andere Weise erstellt werden, etwa als **Voting-Ensembles** oder durch **Stacked Generalization (Stacking)**. Die Grundidee besteht darin, dass verschiedene Modelle unterschiedliche Muster erfassen oder unterschiedliche Schwächen haben können; durch ihre Kombination können wir **die Fehler jedes Modells durch die Stärken eines anderen ausgleichen**.<sup>[[13]](#references)</sup>

-   **Voting-Ensemble:** Bei einem einfachen Voting-Klassifikator trainieren wir mehrere unterschiedliche Modelle (etwa eine logistische Regression, einen Entscheidungsbaum und einen SVM) und lassen sie über die endgültige Vorhersage abstimmen (bei der Klassifikation durch Mehrheitsentscheidung). Wenn wir die Stimmen gewichten (z. B. genaueren Modellen ein höheres Gewicht geben), handelt es sich um ein gewichtetes Voting-Verfahren. Dies verbessert die Leistung typischerweise, wenn die einzelnen Modelle ausreichend gut und unabhängig sind -- das Ensemble verringert das Risiko eines Fehlers eines einzelnen Modells, da andere Modelle ihn möglicherweise korrigieren. Es ist vergleichbar mit einem Expertengremium statt einer einzelnen Meinung.

-   **Stacking (Stacked Ensemble):** Stacking geht noch einen Schritt weiter. Anstatt einfach abzustimmen, trainiert es ein **Meta-Modell**, das **lernt, wie die Vorhersagen der Basismodelle am besten kombiniert werden**. Beispielsweise trainiert man drei verschiedene Klassifikatoren (Basis-Lerner) und verwendet anschließend deren Ausgaben (oder Wahrscheinlichkeiten) als Features für einen Meta-Klassifikator (häufig ein einfaches Modell wie eine logistische Regression), der die optimale Art ihrer Kombination lernt. Das Meta-Modell wird auf einem Validierungsdatensatz oder mittels Cross-Validation trainiert, um Overfitting zu vermeiden. Stacking kann einfaches Voting häufig übertreffen, da es lernt, *welchen Modellen unter welchen Umständen mehr vertraut werden sollte*. In der Cybersicherheit könnte ein Modell besser darin sein, Network Scans zu erkennen, während ein anderes Malware-Beaconing besser erkennt; ein Stacking-Modell könnte lernen, sich jeweils angemessen auf das passende Modell zu verlassen.

Ensembles, ob durch Voting oder Stacking, **erhöhen tendenziell die Genauigkeit** und Robustheit. Der Nachteil sind die höhere Komplexität und manchmal die geringere Interpretierbarkeit (obwohl einige Ensemble-Ansätze, etwa ein Durchschnitt von Entscheidungsbäumen, weiterhin gewisse Einblicke ermöglichen können, z. B. durch Feature Importance). In der Praxis kann der Einsatz eines Ensembles zu höheren Erkennungsraten führen, sofern es die betrieblichen Rahmenbedingungen erlauben. Viele erfolgreiche Lösungen bei Cybersecurity-Herausforderungen (und allgemein bei Kaggle-Wettbewerben) verwenden Ensemble-Techniken, um auch noch das letzte bisschen Leistung herauszuholen.

<details>
<summary>Beispiel -- Voting-Ensemble zur Phishing-Erkennung:</summary>
Um Model Stacking zu veranschaulichen, kombinieren wir einige der Modelle, die wir beim Phishing-Datensatz besprochen haben. Wir verwenden eine logistische Regression, einen Entscheidungsbaum und ein k-NN als Basis-Lerner und einen Random Forest als Meta-Lerner, um ihre Vorhersagen zu aggregieren. Der Meta-Lerner wird anhand der Ausgaben der Basis-Lerner trainiert (unter Verwendung von Cross-Validation auf dem Trainingsdatensatz). Wir erwarten, dass das gestapelte Modell mindestens so gut oder geringfügig besser abschneidet als die einzelnen Modelle.
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
Das gestapelte Ensemble nutzt die sich ergänzenden Stärken der Basismodelle. Beispielsweise könnte die logistische Regression lineare Aspekte der Daten verarbeiten, der Entscheidungsbaum bestimmte regelähnliche Wechselwirkungen erfassen und k-NN in lokalen Nachbarschaften des Merkmalsraums besonders gut funktionieren. Das Meta-Modell (hier ein random forest) kann lernen, wie diese Eingaben gewichtet werden. Die resultierenden Metriken zeigen häufig eine Verbesserung (auch wenn sie geringfügig ist) gegenüber den Metriken jedes einzelnen Modells. In unserem Phishing-Beispiel könnte die logistische Regression allein beispielsweise einen F1-Wert von 0,95 und der Baum einen Wert von 0,94 erreichen, während der Stack durch das Ausgleichen der Fehler der einzelnen Modelle 0,96 erzielen könnte.

Ensemble-Methoden wie diese veranschaulichen das Prinzip, dass *„die Kombination mehrerer Modelle typischerweise zu einer besseren Generalisierung führt“*. In der Cybersicherheit kann dies umgesetzt werden, indem mehrere Detection Engines eingesetzt werden (eine könnte regelbasiert, eine auf Machine Learning und eine anomaliebasiert sein) und anschließend eine Schicht ihre Alerts aggregiert -- effektiv eine Form eines Ensembles --, um eine endgültige Entscheidung mit höherer Konfidenz zu treffen. Beim Deployment solcher Systeme muss die zusätzliche Komplexität berücksichtigt und sichergestellt werden, dass das Ensemble nicht zu schwierig zu verwalten oder zu erklären ist. Aus Sicht der Genauigkeit sind Ensembles und Stacking jedoch leistungsstarke Werkzeuge zur Verbesserung der Modellleistung.

</details>


## Referenzen

- [1] [Logistische Regression](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Entscheidungsbaum – Einführung mit Beispiel](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Erkennung von Denial of Services Attack mit einem Random Forest Classifier und Information Gain](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [Was sind Support Vector Machines (SVMs)? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Naive-Bayes-Spamfilterung (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT entschlüsselt: Funktionsweise von LightGBM, XGBoost und CatBoost](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI und Machine Learning in der Cybersicherheit (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Lineare Regression erklärt](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Leistungsanalyse von Machine-Learning-Modellen für Intrusion-Detection-Systeme mit der Gini-Impuity-basierten Weighted-Random-Forest-(GIWRF)-Merkmalsauswahltechnik](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [Was ist der k-nearest-neighbors-(KNN)-Algorithmus? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Klassifizierung von Phishing-Angriffen und -Websites mit Machine Learning und mehreren Datensätzen (eine vergleichende Analyse)](https://arxiv.org/pdf/2101.02552)
- [12] [Wie Deep Learning Intrusion-Detection-Systeme verbessert](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning: Verbesserung der Modellleistung durch die Kombination von Stärken](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
