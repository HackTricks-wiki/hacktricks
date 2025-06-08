# Überwachungslernen-Algorithmen

{{#include ../banners/hacktricks-training.md}}

## Grundinformationen

Überwachtes Lernen verwendet beschriftete Daten, um Modelle zu trainieren, die Vorhersagen für neue, unbekannte Eingaben treffen können. In der Cybersicherheit wird maschinelles Lernen mit Aufsicht häufig für Aufgaben wie Intrusionserkennung (Klassifizierung von Netzwerkverkehr als *normal* oder *Angriff*), Malware-Erkennung (Unterscheidung zwischen bösartiger und harmloser Software), Phishing-Erkennung (Identifizierung von betrügerischen Websites oder E-Mails) und Spam-Filterung eingesetzt, unter anderem. Jeder Algorithmus hat seine Stärken und ist für verschiedene Arten von Problemen (Klassifikation oder Regression) geeignet. Im Folgenden überprüfen wir wichtige Algorithmen des überwachten Lernens, erklären, wie sie funktionieren, und demonstrieren ihre Verwendung an realen Cybersicherheitsdatensätzen. Wir diskutieren auch, wie die Kombination von Modellen (Ensemble-Lernen) oft die Vorhersageleistung verbessern kann.

## Algorithmen

-   **Lineare Regression:** Ein grundlegender Regressionsalgorithmus zur Vorhersage numerischer Ergebnisse durch Anpassung einer linearen Gleichung an Daten.

-   **Logistische Regression:** Ein Klassifikationsalgorithmus (trotz seines Namens), der eine logistische Funktion verwendet, um die Wahrscheinlichkeit eines binären Ergebnisses zu modellieren.

-   **Entscheidungsbäume:** Baumstrukturierte Modelle, die Daten nach Merkmalen aufteilen, um Vorhersagen zu treffen; oft wegen ihrer Interpretierbarkeit verwendet.

-   **Zufallswälder:** Ein Ensemble von Entscheidungsbäumen (durch Bagging), das die Genauigkeit verbessert und Überanpassung reduziert.

-   **Support Vector Machines (SVM):** Maximalrand-Klassifizierer, die die optimale trennende Hyperfläche finden; können Kerne für nichtlineare Daten verwenden.

-   **Naive Bayes:** Ein probabilistischer Klassifizierer, der auf dem Satz von Bayes basiert und eine Annahme der Merkmalsunabhängigkeit hat, berühmt in der Spam-Filterung verwendet.

-   **k-nächste Nachbarn (k-NN):** Ein einfacher "instanzbasierter" Klassifizierer, der eine Probe basierend auf der Mehrheitsklasse ihrer nächsten Nachbarn kennzeichnet.

-   **Gradient Boosting Machines:** Ensemble-Modelle (z. B. XGBoost, LightGBM), die einen starken Prädiktor aufbauen, indem sie schwächere Lernende (typischerweise Entscheidungsbäume) sequenziell hinzufügen.

Jeder Abschnitt unten bietet eine verbesserte Beschreibung des Algorithmus und ein **Python-Codebeispiel** unter Verwendung von Bibliotheken wie `pandas` und `scikit-learn` (und `PyTorch` für das Beispiel mit neuronalen Netzen). Die Beispiele verwenden öffentlich verfügbare Cybersicherheitsdatensätze (wie NSL-KDD für die Intrusionserkennung und einen Datensatz über Phishing-Websites) und folgen einer konsistenten Struktur:

1.  **Laden Sie den Datensatz** (herunterladen über URL, wenn verfügbar).

2.  **Vorverarbeiten der Daten** (z. B. kategorische Merkmale kodieren, Werte skalieren, in Trainings-/Testsets aufteilen).

3.  **Trainieren Sie das Modell** mit den Trainingsdaten.

4.  **Bewerten** Sie es auf einem Testset mit Metriken: Genauigkeit, Präzision, Rückruf, F1-Score und ROC AUC für die Klassifikation (und mittlerer quadratischer Fehler für die Regression).

Lassen Sie uns in jeden Algorithmus eintauchen:

### Lineare Regression

Die lineare Regression ist ein **Regressions**algorithmus, der verwendet wird, um kontinuierliche numerische Werte vorherzusagen. Sie geht von einer linearen Beziehung zwischen den Eingabemerkmalen (unabhängige Variablen) und dem Ergebnis (abhängige Variable) aus. Das Modell versucht, eine gerade Linie (oder Hyperfläche in höheren Dimensionen) anzupassen, die die Beziehung zwischen Merkmalen und dem Ziel am besten beschreibt. Dies geschieht typischerweise durch Minimierung der Summe der quadrierten Fehler zwischen vorhergesagten und tatsächlichen Werten (Ordinary Least Squares-Methode).

Die einfachste Form, die lineare Regression darzustellen, ist mit einer Linie:
```plaintext
y = mx + b
```
Wo:

- `y` ist der vorhergesagte Wert (Ausgabe)
- `m` ist die Steigung der Linie (Koeffizient)
- `x` ist das Eingangsmerkmal
- `b` ist der y-Achsenabschnitt

Das Ziel der linearen Regression ist es, die am besten passende Linie zu finden, die den Unterschied zwischen den vorhergesagten Werten und den tatsächlichen Werten im Datensatz minimiert. Natürlich ist das sehr einfach, es wäre eine gerade Linie, die 2 Kategorien trennt, aber wenn mehr Dimensionen hinzugefügt werden, wird die Linie komplexer:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Lineare Regression selbst ist weniger häufig für zentrale Sicherheitsaufgaben (die oft Klassifikation sind), kann jedoch angewendet werden, um numerische Ergebnisse vorherzusagen. Zum Beispiel könnte man lineare Regression verwenden, um **das Volumen des Netzwerkverkehrs** vorherzusagen oder **die Anzahl der Angriffe in einem Zeitraum** basierend auf historischen Daten zu schätzen. Es könnte auch einen Risikowert oder die erwartete Zeit bis zur Erkennung eines Angriffs vorhersagen, gegeben bestimmte Systemmetriken. In der Praxis werden Klassifikationsalgorithmen (wie logistische Regression oder Bäume) häufiger zur Erkennung von Eindringlingen oder Malware verwendet, aber lineare Regression dient als Grundlage und ist nützlich für regressionsorientierte Analysen.

#### **Schlüsselkriterien der linearen Regression:**

-   **Art des Problems:** Regression (Vorhersage kontinuierlicher Werte). Nicht geeignet für direkte Klassifikation, es sei denn, es wird ein Schwellenwert auf die Ausgabe angewendet.

-   **Interpretierbarkeit:** Hoch -- Koeffizienten sind einfach zu interpretieren und zeigen den linearen Effekt jedes Merkmals.

-   **Vorteile:** Einfach und schnell; eine gute Basislinie für Regressionsaufgaben; funktioniert gut, wenn die wahre Beziehung ungefähr linear ist.

-   **Einschränkungen:** Kann komplexe oder nicht-lineare Beziehungen nicht erfassen (ohne manuelle Merkmalsengineering); anfällig für Underfitting, wenn Beziehungen nicht linear sind; empfindlich gegenüber Ausreißern, die die Ergebnisse verzerren können.

-   **Best Fit finden:** Um die beste Anpassungslinie zu finden, die die möglichen Kategorien trennt, verwenden wir eine Methode namens **Ordinary Least Squares (OLS)**. Diese Methode minimiert die Summe der quadrierten Unterschiede zwischen den beobachteten Werten und den Werten, die vom linearen Modell vorhergesagt werden.

<details>
<summary>Beispiel -- Vorhersage der Verbindungsdauer (Regression) in einem Eindringdatensatz
</summary>
Unten demonstrieren wir die lineare Regression mit dem NSL-KDD-Cybersicherheitsdatensatz. Wir behandeln dies als ein Regressionsproblem, indem wir die `duration` von Netzwerkverbindungen basierend auf anderen Merkmalen vorhersagen. (In Wirklichkeit ist `duration` ein Merkmal von NSL-KDD; wir verwenden es hier nur zur Veranschaulichung der Regression.) Wir laden den Datensatz, verarbeiten ihn vor (kodieren kategorische Merkmale), trainieren ein lineares Regressionsmodell und bewerten den mittleren quadratischen Fehler (MSE) und den R²-Wert auf einem Testdatensatz.
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
In diesem Beispiel versucht das lineare Regressionsmodell, die Verbindungsdauer (`duration`) aus anderen Netzwerkmerkmalen vorherzusagen. Wir messen die Leistung mit dem mittleren quadratischen Fehler (MSE) und R². Ein R² nahe 1,0 würde darauf hindeuten, dass das Modell die meiste Varianz in der `duration` erklärt, während ein niedriges oder negatives R² auf eine schlechte Anpassung hinweist. (Seien Sie nicht überrascht, wenn das R² hier niedrig ist – die Vorhersage der `duration` könnte aus den gegebenen Merkmalen schwierig sein, und die lineare Regression erfasst möglicherweise die Muster nicht, wenn sie komplex sind.)
</details>

### Logistische Regression

Die logistische Regression ist ein **Klassifikations**algorithmus, der die Wahrscheinlichkeit modelliert, dass eine Instanz zu einer bestimmten Klasse gehört (typischerweise der "positiven" Klasse). Trotz ihres Namens wird die *logistische* Regression für diskrete Ergebnisse verwendet (im Gegensatz zur linearen Regression, die für kontinuierliche Ergebnisse gedacht ist). Sie wird insbesondere für **binäre Klassifikation** (zwei Klassen, z.B. bösartig vs. gutartig) verwendet, kann jedoch auf Mehrklassenprobleme (unter Verwendung von Softmax- oder One-vs-Rest-Ansätzen) erweitert werden.

Die logistische Regression verwendet die logistische Funktion (auch bekannt als Sigmoidfunktion), um vorhergesagte Werte in Wahrscheinlichkeiten zu überführen. Beachten Sie, dass die Sigmoidfunktion eine Funktion mit Werten zwischen 0 und 1 ist, die in einer S-förmigen Kurve wächst, je nach den Anforderungen der Klassifikation, was für binäre Klassifikationsaufgaben nützlich ist. Daher wird jedes Merkmal jedes Eingangs mit seinem zugewiesenen Gewicht multipliziert, und das Ergebnis wird durch die Sigmoidfunktion geleitet, um eine Wahrscheinlichkeit zu erzeugen:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Wo:

- `p(y=1|x)` ist die Wahrscheinlichkeit, dass die Ausgabe `y` 1 ist, gegeben die Eingabe `x`
- `e` ist die Basis des natürlichen Logarithmus
- `z` ist eine lineare Kombination der Eingabefunktionen, typischerweise dargestellt als `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Beachten Sie, dass es in seiner einfachsten Form eine gerade Linie ist, aber in komplexeren Fällen wird es zu einer Hyperfläche mit mehreren Dimensionen (eine pro Funktion).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Da viele Sicherheitsprobleme im Wesentlichen Ja/Nein-Entscheidungen sind, wird die logistische Regression häufig verwendet. Zum Beispiel könnte ein Intrusion Detection System die logistische Regression verwenden, um zu entscheiden, ob eine Netzwerkverbindung ein Angriff ist, basierend auf Merkmalen dieser Verbindung. Bei der Phishing-Erkennung kann die logistische Regression Merkmale einer Website (URL-Länge, Vorhandensein des "@"-Symbols usw.) in eine Wahrscheinlichkeit umwandeln, dass es sich um Phishing handelt. Sie wurde in frühen Spam-Filtern verwendet und bleibt eine starke Basislinie für viele Klassifikationsaufgaben.

#### Logistische Regression für nicht-binäre Klassifikation

Die logistische Regression ist für die binäre Klassifikation konzipiert, kann jedoch erweitert werden, um Mehrklassenprobleme mit Techniken wie **one-vs-rest** (OvR) oder **softmax regression** zu behandeln. Bei OvR wird für jede Klasse ein separates logistische Regressionsmodell trainiert, das sie als positive Klasse gegen alle anderen behandelt. Die Klasse mit der höchsten vorhergesagten Wahrscheinlichkeit wird als endgültige Vorhersage ausgewählt. Die Softmax-Regression verallgemeinert die logistische Regression auf mehrere Klassen, indem sie die Softmax-Funktion auf die Ausgabeschicht anwendet und eine Wahrscheinlichkeitsverteilung über alle Klassen erzeugt.

#### **Hauptmerkmale der logistischen Regression:**

-   **Art des Problems:** Klassifikation (normalerweise binär). Sie sagt die Wahrscheinlichkeit der positiven Klasse voraus.

-   **Interpretierbarkeit:** Hoch -- wie bei der linearen Regression können die Merkmalskoeffizienten anzeigen, wie jedes Merkmal die Log-Odds des Ergebnisses beeinflusst. Diese Transparenz wird in der Sicherheit oft geschätzt, um zu verstehen, welche Faktoren zu einem Alarm beitragen.

-   **Vorteile:** Einfach und schnell zu trainieren; funktioniert gut, wenn die Beziehung zwischen Merkmalen und Log-Odds des Ergebnisses linear ist. Gibt Wahrscheinlichkeiten aus, die eine Risikobewertung ermöglichen. Mit geeigneter Regularisierung generalisiert sie gut und kann Multikollinearität besser handhaben als die einfache lineare Regression.

-   **Einschränkungen:** Geht von einer linearen Entscheidungsgrenze im Merkmalsraum aus (versagt, wenn die wahre Grenze komplex/nicht-linear ist). Sie kann bei Problemen, bei denen Interaktionen oder nicht-lineare Effekte entscheidend sind, unterperformen, es sei denn, Sie fügen manuell polynomiale oder Interaktionsmerkmale hinzu. Außerdem ist die logistische Regression weniger effektiv, wenn Klassen nicht leicht durch eine lineare Kombination von Merkmalen trennbar sind.

<details>
<summary>Beispiel -- Phishing-Website-Erkennung mit logistischer Regression:</summary>

Wir verwenden einen **Phishing Websites Dataset** (aus dem UCI-Repository), der extrahierte Merkmale von Websites enthält (wie ob die URL eine IP-Adresse hat, das Alter der Domain, das Vorhandensein verdächtiger Elemente im HTML usw.) und ein Label, das angibt, ob die Seite Phishing oder legitim ist. Wir trainieren ein logistische Regressionsmodell, um Websites zu klassifizieren, und bewerten dann seine Genauigkeit, Präzision, Recall, F1-Score und ROC AUC auf einem Testsplit.
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
In diesem Beispiel zur Phishing-Erkennung erzeugt die logistische Regression eine Wahrscheinlichkeit dafür, dass jede Website Phishing ist. Durch die Bewertung von Genauigkeit, Präzision, Recall und F1 erhalten wir ein Gefühl für die Leistung des Modells. Ein hoher Recall würde beispielsweise bedeuten, dass die meisten Phishing-Seiten erkannt werden (wichtig für die Sicherheit, um verpasste Angriffe zu minimieren), während eine hohe Präzision bedeutet, dass es wenige Fehlalarme gibt (wichtig, um Analystenmüdigkeit zu vermeiden). Der ROC AUC (Area Under the ROC Curve) bietet ein schwellenunabhängiges Maß für die Leistung (1.0 ist ideal, 0.5 ist nicht besser als Zufall). Die logistische Regression schneidet bei solchen Aufgaben oft gut ab, aber wenn die Entscheidungsgrenze zwischen Phishing- und legitimen Seiten komplex ist, könnten leistungsfähigere nichtlineare Modelle erforderlich sein.

</details>

### Entscheidungsbäume

Ein Entscheidungsbaum ist ein vielseitiger **überwachter Lernalgorithmus**, der sowohl für Klassifikations- als auch für Regressionsaufgaben verwendet werden kann. Er lernt ein hierarchisches, baumähnliches Modell von Entscheidungen basierend auf den Merkmalen der Daten. Jeder interne Knoten des Baums repräsentiert einen Test auf ein bestimmtes Merkmal, jeder Zweig repräsentiert ein Ergebnis dieses Tests, und jeder Blattknoten repräsentiert eine vorhergesagte Klasse (für die Klassifikation) oder einen Wert (für die Regression).

Um einen Baum zu erstellen, verwenden Algorithmen wie CART (Classification and Regression Tree) Maße wie **Gini-Unreinheit** oder **Informationsgewinn (Entropie)**, um das beste Merkmal und den besten Schwellenwert auszuwählen, um die Daten bei jedem Schritt zu teilen. Das Ziel bei jedem Split ist es, die Daten zu partitionieren, um die Homogenität der Zielvariablen in den resultierenden Teilmengen zu erhöhen (für die Klassifikation zielt jeder Knoten darauf ab, so rein wie möglich zu sein, wobei überwiegend eine einzige Klasse enthalten ist).

Entscheidungsbäume sind **hochgradig interpretierbar** – man kann den Pfad vom Wurzel- zum Blattknoten verfolgen, um die Logik hinter einer Vorhersage zu verstehen (z. B. *"WENN `service = telnet` UND `src_bytes > 1000` UND `failed_logins > 3` DANN klassifizieren als Angriff"*). Dies ist in der Cybersicherheit wertvoll, um zu erklären, warum ein bestimmter Alarm ausgelöst wurde. Bäume können sowohl numerische als auch kategoriale Daten natürlich verarbeiten und erfordern wenig Vorverarbeitung (z. B. ist eine Merkmalsnormierung nicht erforderlich).

Ein einzelner Entscheidungsbaum kann jedoch leicht die Trainingsdaten überanpassen, insbesondere wenn er tief gewachsen ist (viele Splits). Techniken wie das Beschneiden (Begrenzung der Baumtiefe oder Erfordernis einer Mindestanzahl von Proben pro Blatt) werden häufig verwendet, um Überanpassung zu verhindern.

Es gibt 3 Hauptkomponenten eines Entscheidungsbaums:
- **Wurzelknoten**: Der oberste Knoten des Baums, der den gesamten Datensatz repräsentiert.
- **Interne Knoten**: Knoten, die Merkmale und Entscheidungen basierend auf diesen Merkmalen repräsentieren.
- **Blattknoten**: Knoten, die das endgültige Ergebnis oder die Vorhersage repräsentieren.

Ein Baum könnte so aussehen:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Entscheidungsbäume wurden in Intrusion Detection Systemen verwendet, um **Regeln** zur Identifizierung von Angriffen abzuleiten. Zum Beispiel würden frühe IDS wie ID3/C4.5-basierte Systeme menschenlesbare Regeln generieren, um normalen von bösartigem Verkehr zu unterscheiden. Sie werden auch in der Malware-Analyse verwendet, um zu entscheiden, ob eine Datei bösartig ist, basierend auf ihren Attributen (Dateigröße, Abschnittsentropie, API-Aufrufe usw.). Die Klarheit von Entscheidungsbäumen macht sie nützlich, wenn Transparenz erforderlich ist – ein Analyst kann den Baum inspizieren, um die Erkennungslogik zu validieren.

#### **Schlüsselkriterien von Entscheidungsbäumen:**

-   **Art des Problems:** Sowohl Klassifikation als auch Regression. Häufig verwendet zur Klassifikation von Angriffen vs. normalem Verkehr usw.

-   **Interpretierbarkeit:** Sehr hoch – die Entscheidungen des Modells können visualisiert und als eine Reihe von Wenn-Dann-Regeln verstanden werden. Dies ist ein großer Vorteil in der Sicherheit für Vertrauen und Verifizierung des Modellverhaltens.

-   **Vorteile:** Kann nicht-lineare Beziehungen und Interaktionen zwischen Merkmalen erfassen (jeder Split kann als Interaktion betrachtet werden). Keine Notwendigkeit, Merkmale zu skalieren oder kategorische Variablen one-hot zu kodieren – Bäume behandeln diese nativ. Schnelle Inferenz (Vorhersage erfolgt einfach durch das Folgen eines Pfades im Baum).

-   **Einschränkungen:** Anfällig für Überanpassung, wenn nicht kontrolliert (ein tiefer Baum kann den Trainingssatz auswendig lernen). Sie können instabil sein – kleine Änderungen in den Daten können zu einer anderen Baumstruktur führen. Als Einzelmodelle könnte ihre Genauigkeit nicht mit fortgeschritteneren Methoden übereinstimmen (Ensembles wie Random Forests schneiden typischerweise besser ab, indem sie die Varianz reduzieren).

-   **Den besten Split finden:**
- **Gini-Unreinheit**: Misst die Unreinheit eines Knotens. Eine niedrigere Gini-Unreinheit zeigt einen besseren Split an. Die Formel lautet:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Wobei `p_i` der Anteil der Instanzen in der Klasse `i` ist.

- **Entropie**: Misst die Unsicherheit im Datensatz. Eine niedrigere Entropie zeigt einen besseren Split an. Die Formel lautet:

```plaintext
Entropie = -Σ(p_i * log2(p_i))
```

Wobei `p_i` der Anteil der Instanzen in der Klasse `i` ist.

- **Informationsgewinn**: Die Reduktion der Entropie oder Gini-Unreinheit nach einem Split. Je höher der Informationsgewinn, desto besser der Split. Er wird berechnet als:

```plaintext
Informationsgewinn = Entropie(eltern) - (Gewichteter Durchschnitt der Entropie(Kinder))
```

Darüber hinaus endet ein Baum, wenn:
- Alle Instanzen in einem Knoten zur gleichen Klasse gehören. Dies kann zu Überanpassung führen.
- Die maximale Tiefe (fest codiert) des Baums erreicht ist. Dies ist eine Möglichkeit, Überanpassung zu verhindern.
- Die Anzahl der Instanzen in einem Knoten unter einem bestimmten Schwellenwert liegt. Dies ist ebenfalls eine Möglichkeit, Überanpassung zu verhindern.
- Der Informationsgewinn aus weiteren Splits unter einem bestimmten Schwellenwert liegt. Dies ist auch eine Möglichkeit, Überanpassung zu verhindern.

<details>
<summary>Beispiel -- Entscheidungsbaum für Intrusion Detection:</summary>
Wir werden einen Entscheidungsbaum auf dem NSL-KDD-Datensatz trainieren, um Netzwerkverbindungen als *normal* oder *Angriff* zu klassifizieren. NSL-KDD ist eine verbesserte Version des klassischen KDD Cup 1999-Datensatzes, mit Merkmalen wie Protokolltyp, Dienst, Dauer, Anzahl fehlgeschlagener Anmeldungen usw. und einem Label, das den Angriffstyp oder "normal" angibt. Wir werden alle Angriffstypen einer "Anomalie"-Klasse zuordnen (binäre Klassifikation: normal vs. Anomalie). Nach dem Training werden wir die Leistung des Baums im Testdatensatz bewerten.
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
In diesem Entscheidungsbaumbeispiel haben wir die Baumtiefe auf 10 begrenzt, um extremes Overfitting zu vermeiden (der Parameter `max_depth=10`). Die Metriken zeigen, wie gut der Baum normalen Verkehr von Angriffstraffic unterscheidet. Ein hoher Recall würde bedeuten, dass die meisten Angriffe erfasst werden (wichtig für ein IDS), während eine hohe Präzision bedeutet, dass es wenige Fehlalarme gibt. Entscheidungsbäume erreichen oft eine anständige Genauigkeit bei strukturierten Daten, aber ein einzelner Baum könnte nicht die beste mögliche Leistung erreichen. Dennoch ist die *Interpretierbarkeit* des Modells ein großer Vorteil – wir könnten die Splits des Baums untersuchen, um zu sehen, welche Merkmale (z. B. `service`, `src_bytes` usw.) am einflussreichsten sind, um eine Verbindung als bösartig zu kennzeichnen.

</details>

### Random Forests

Random Forest ist eine **Ensemble-Lernmethode**, die auf Entscheidungsbäumen aufbaut, um die Leistung zu verbessern. Ein Random Forest trainiert mehrere Entscheidungsbäume (daher "Wald") und kombiniert deren Ausgaben, um eine endgültige Vorhersage zu treffen (bei Klassifikationen typischerweise durch Mehrheitsvotum). Die beiden Hauptideen in einem Random Forest sind **Bagging** (Bootstrap-Aggregation) und **Merkmalszufälligkeit**:

-   **Bagging:** Jeder Baum wird auf einer zufälligen Bootstrap-Stichprobe der Trainingsdaten trainiert (mit Zurücklegen ausgewählt). Dies führt zu Vielfalt unter den Bäumen.

-   **Merkmalszufälligkeit:** Bei jedem Split in einem Baum wird eine zufällige Teilmenge von Merkmalen für den Split in Betracht gezogen (anstatt aller Merkmale). Dies korreliert die Bäume weiter.

Durch das Mittelwerten der Ergebnisse vieler Bäume reduziert der Random Forest die Varianz, die ein einzelner Entscheidungsbaum haben könnte. Einfach ausgedrückt, könnten einzelne Bäume überanpassen oder rauschig sein, aber eine große Anzahl von vielfältigen Bäumen, die zusammen abstimmen, glättet diese Fehler. Das Ergebnis ist oft ein Modell mit **höherer Genauigkeit** und besserer Generalisierung als ein einzelner Entscheidungsbaum. Darüber hinaus können Random Forests eine Schätzung der Merkmalsbedeutung liefern (indem sie betrachten, wie viel jedes Merkmal im Durchschnitt die Unreinheit reduziert).

Random Forests sind zu einem **Arbeitspferd in der Cybersicherheit** für Aufgaben wie Intrusion Detection, Malware-Klassifikation und Spam-Erkennung geworden. Sie schneiden oft gut ohne große Anpassungen ab und können große Merkmalsmengen verarbeiten. Zum Beispiel kann ein Random Forest in der Intrusion Detection einen einzelnen Entscheidungsbaum übertreffen, indem er subtilere Angriffsmuster mit weniger Fehlalarmen erfasst. Forschungen haben gezeigt, dass Random Forests im Vergleich zu anderen Algorithmen bei der Klassifizierung von Angriffen in Datensätzen wie NSL-KDD und UNSW-NB15 günstig abschneiden.

#### **Hauptmerkmale von Random Forests:**

-   **Art des Problems:** Primär Klassifikation (auch für Regression verwendet). Sehr gut geeignet für hochdimensionale strukturierte Daten, die in Sicherheitsprotokollen häufig vorkommen.

-   **Interpretierbarkeit:** Geringer als bei einem einzelnen Entscheidungsbaum – man kann nicht einfach Hunderte von Bäumen gleichzeitig visualisieren oder erklären. Allerdings bieten Merkmalsbedeutungsscores einige Einblicke, welche Attribute am einflussreichsten sind.

-   **Vorteile:** Allgemein höhere Genauigkeit als Einzelbaum-Modelle aufgrund des Ensemble-Effekts. Robust gegenüber Overfitting – selbst wenn einzelne Bäume überanpassen, generalisiert das Ensemble besser. Verarbeitet sowohl numerische als auch kategoriale Merkmale und kann fehlende Daten bis zu einem gewissen Grad verwalten. Es ist auch relativ robust gegenüber Ausreißern.

-   **Einschränkungen:** Die Modellgröße kann groß sein (viele Bäume, jeder potenziell tief). Vorhersagen sind langsamer als bei einem einzelnen Baum (da man über viele Bäume aggregieren muss). Weniger interpretierbar – während man wichtige Merkmale kennt, ist die genaue Logik nicht leicht als einfache Regel nachzuvollziehen. Wenn der Datensatz extrem hochdimensional und spärlich ist, kann das Training eines sehr großen Waldes rechnerisch aufwendig sein.

-   **Trainingsprozess:**
1. **Bootstrap-Sampling**: Zufällige Stichprobe der Trainingsdaten mit Zurücklegen, um mehrere Teilmengen (Bootstrap-Stichproben) zu erstellen.
2. **Baumkonstruktion**: Für jede Bootstrap-Stichprobe wird ein Entscheidungsbaum unter Verwendung einer zufälligen Teilmenge von Merkmalen bei jedem Split erstellt. Dies führt zu Vielfalt unter den Bäumen.
3. **Aggregation**: Bei Klassifikationsaufgaben wird die endgültige Vorhersage durch Mehrheitsvotum unter den Vorhersagen aller Bäume getroffen. Bei Regressionsaufgaben ist die endgültige Vorhersage der Durchschnitt der Vorhersagen aller Bäume.

<details>
<summary>Beispiel -- Random Forest für Intrusion Detection (NSL-KDD):</summary>
Wir werden dasselbe NSL-KDD-Dataset (binär gekennzeichnet als normal vs. Anomalie) verwenden und einen Random Forest-Klassifikator trainieren. Wir erwarten, dass der Random Forest genauso gut oder besser abschneidet als der einzelne Entscheidungsbaum, da die Ensemble-Mittelung die Varianz reduziert. Wir werden es mit denselben Metriken bewerten.
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
Der Random Forest erzielt typischerweise starke Ergebnisse bei dieser Intrusion Detection-Aufgabe. Wir könnten eine Verbesserung in Metriken wie F1 oder AUC im Vergleich zum einzelnen Entscheidungsbaum beobachten, insbesondere in Bezug auf Recall oder Precision, abhängig von den Daten. Dies steht im Einklang mit dem Verständnis, dass *"Random Forest (RF) ein Ensemble-Klassifikator ist und im Vergleich zu anderen traditionellen Klassifikatoren gut für die effektive Klassifizierung von Angriffen abschneidet."*. In einem Kontext der Sicherheitsoperationen könnte ein Random Forest-Modell Angriffe zuverlässiger kennzeichnen und gleichzeitig Fehlalarme reduzieren, dank der Durchschnittsbildung vieler Entscheidungsregeln. Die Feature-Wichtigkeit aus dem Wald könnte uns sagen, welche Netzwerkmerkmale am aussagekräftigsten für Angriffe sind (z. B. bestimmte Netzwerkdienste oder ungewöhnliche Paketanzahlen).

</details>

### Support Vector Machines (SVM)

Support Vector Machines sind leistungsstarke überwachte Lernmodelle, die hauptsächlich für die Klassifikation (und auch Regression als SVR) verwendet werden. Eine SVM versucht, die **optimale trennende Hyperfläche** zu finden, die den Abstand zwischen zwei Klassen maximiert. Nur eine Teilmenge der Trainingspunkte (die "Support Vectors", die am nächsten an der Grenze liegen) bestimmt die Position dieser Hyperfläche. Durch die Maximierung des Abstands (der Abstand zwischen den Support Vectors und der Hyperfläche) erreichen SVMs in der Regel eine gute Generalisierung.

Der Schlüssel zur Stärke der SVM ist die Fähigkeit, **Kernel-Funktionen** zu verwenden, um nicht-lineare Beziehungen zu behandeln. Die Daten können implizit in einen höherdimensionalen Merkmalsraum transformiert werden, in dem ein linearer Separator existieren könnte. Häufige Kerne sind polynomial, radiale Basisfunktion (RBF) und Sigmoid. Wenn beispielsweise Netzwerkverkehrsklassen im ursprünglichen Merkmalsraum nicht linear trennbar sind, kann ein RBF-Kernel sie in eine höhere Dimension abbilden, in der die SVM einen linearen Schnitt findet (der einer nicht-linearen Grenze im ursprünglichen Raum entspricht). Die Flexibilität bei der Wahl der Kerne ermöglicht es SVMs, eine Vielzahl von Problemen zu bewältigen.

SVMs sind bekannt dafür, in Situationen mit hochdimensionalen Merkmalsräumen (wie Textdaten oder Malware-Opcode-Sequenzen) und in Fällen, in denen die Anzahl der Merkmale im Verhältnis zur Anzahl der Proben groß ist, gut abzuschneiden. Sie waren in vielen frühen Cybersecurity-Anwendungen wie Malware-Klassifikation und anomaliemäßiger Intrusion Detection in den 2000er Jahren beliebt und zeigten oft eine hohe Genauigkeit.

Allerdings skalieren SVMs nicht leicht auf sehr große Datensätze (die Trainingskomplexität ist superlinear in der Anzahl der Proben, und der Speicherbedarf kann hoch sein, da viele Support Vectors gespeichert werden müssen). In der Praxis könnte eine SVM für Aufgaben wie die Netzwerk-Intrusionserkennung mit Millionen von Datensätzen zu langsam sein, ohne sorgfältiges Subsampling oder die Verwendung approximativer Methoden.

#### **Schlüsselkriterien der SVM:**

-   **Art des Problems:** Klassifikation (binär oder mehrklassig über one-vs-one/one-vs-rest) und Regressionsvarianten. Oft in der binären Klassifikation mit klarer Margen-Trennung verwendet.

-   **Interpretierbarkeit:** Mittel -- SVMs sind nicht so interpretierbar wie Entscheidungsbäume oder logistische Regression. Während man identifizieren kann, welche Datenpunkte Support Vectors sind und ein gewisses Gefühl dafür bekommt, welche Merkmale einflussreich sein könnten (durch die Gewichte im Fall des linearen Kernels), werden SVMs in der Praxis (insbesondere mit nicht-linearen Kernen) als Black-Box-Klassifikatoren behandelt.

-   **Vorteile:** Effektiv in hochdimensionalen Räumen; kann komplexe Entscheidungsgrenzen mit dem Kernel-Trick modellieren; robust gegen Überanpassung, wenn der Abstand maximiert wird (insbesondere mit einem geeigneten Regularisierungsparameter C); funktioniert gut, selbst wenn Klassen nicht durch einen großen Abstand getrennt sind (findet die beste Kompromissgrenze).

-   **Einschränkungen:** **Rechenintensiv** für große Datensätze (sowohl Training als auch Vorhersage skalieren schlecht, wenn die Daten wachsen). Erfordert sorgfältige Abstimmung der Kernel- und Regularisierungsparameter (C, Kerneltyp, Gamma für RBF usw.). Bietet keine direkten probabilistischen Ausgaben (obwohl man Platt-Skalierung verwenden kann, um Wahrscheinlichkeiten zu erhalten). Außerdem können SVMs empfindlich auf die Wahl der Kernelparameter sein --- eine schlechte Wahl kann zu Unteranpassung oder Überanpassung führen.

*Anwendungsfälle in der Cybersicherheit:* SVMs wurden in der **Malware-Erkennung** (z. B. Klassifizierung von Dateien basierend auf extrahierten Merkmalen oder Opcode-Sequenzen), **Netzwerkanomalieerkennung** (Klassifizierung von Verkehr als normal oder bösartig) und **Phishing-Erkennung** (unter Verwendung von Merkmalen von URLs) eingesetzt. Beispielsweise könnte eine SVM Merkmale einer E-Mail (Anzahlen bestimmter Schlüsselwörter, Sender-Reputationswerte usw.) verwenden und sie als Phishing oder legitim klassifizieren. Sie wurden auch auf **Intrusion Detection** bei Merkmalsätzen wie KDD angewendet und erzielten oft eine hohe Genauigkeit auf Kosten der Berechnung.

<details>
<summary>Beispiel -- SVM zur Malware-Klassifikation:</summary>
Wir werden erneut den Datensatz von Phishing-Websites verwenden, diesmal mit einer SVM. Da SVMs langsam sein können, verwenden wir eine Teilmenge der Daten für das Training, falls erforderlich (der Datensatz umfasst etwa 11.000 Instanzen, die eine SVM vernünftig verarbeiten kann). Wir verwenden einen RBF-Kernel, der eine gängige Wahl für nicht-lineare Daten ist, und aktivieren Wahrscheinlichkeitsabschätzungen, um ROC AUC zu berechnen.
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
Das SVM-Modell gibt Metriken aus, die wir mit der logistischen Regression bei derselben Aufgabe vergleichen können. Wir könnten feststellen, dass SVM eine hohe Genauigkeit und AUC erreicht, wenn die Daten gut durch die Merkmale getrennt sind. Umgekehrt, wenn der Datensatz viel Rauschen oder überlappende Klassen hatte, könnte SVM die logistische Regression nicht signifikant übertreffen. In der Praxis können SVMs einen Schub geben, wenn es komplexe, nicht-lineare Beziehungen zwischen Merkmalen und Klassen gibt – der RBF-Kernel kann gekrümmte Entscheidungsgrenzen erfassen, die die logistische Regression übersehen würde. Wie bei allen Modellen ist eine sorgfältige Abstimmung der `C` (Regularisierung) und der Kernel-Parameter (wie `gamma` für RBF) erforderlich, um Bias und Varianz auszubalancieren.

</details>

#### Unterschied zwischen logistischer Regression und SVM

| Aspekt | **Logistische Regression** | **Support Vector Machines** |
|---|---|---|
| **Ziel-Funktion** | Minimiert **log‑loss** (Kreuzentropie). | Maximiert den **Margin** bei gleichzeitiger Minimierung des **hinge‑loss**. |
| **Entscheidungsgrenze** | Findet die **beste Hyperplane**, die _P(y\|x)_ modelliert. | Findet die **maximale Margin-Hyperplane** (größter Abstand zu den nächsten Punkten). |
| **Ausgabe** | **Probabilistisch** – gibt kalibrierte Klassenwahrscheinlichkeiten über σ(w·x + b) aus. | **Deterministisch** – gibt Klassenlabels zurück; Wahrscheinlichkeiten benötigen zusätzliche Arbeit (z.B. Platt-Skalierung). |
| **Regularisierung** | L2 (Standard) oder L1, balanciert direkt Unter-/Überanpassung. | Der C-Parameter tauscht die Breite des Margins gegen Fehlklassifikationen; Kernel-Parameter erhöhen die Komplexität. |
| **Kerne / Nicht-linear** | Native Form ist **linear**; Nicht-Linearität wird durch Merkmalsengineering hinzugefügt. | Eingebauter **Kernel-Trick** (RBF, poly usw.) ermöglicht es, komplexe Grenzen im hochdimensionalen Raum zu modellieren. |
| **Skalierbarkeit** | Löst eine konvexe Optimierung in **O(nd)**; bewältigt sehr große n gut. | Training kann **O(n²–n³)** Speicher/Zeit ohne spezialisierte Solver sein; weniger freundlich zu riesigem n. |
| **Interpretierbarkeit** | **Hoch** – Gewichte zeigen den Einfluss der Merkmale; Odds-Ratio intuitiv. | **Niedrig** für nicht-lineare Kerne; Stützvektoren sind spärlich, aber nicht leicht zu erklären. |
| **Empfindlichkeit gegenüber Ausreißern** | Verwendet glatten log‑loss → weniger empfindlich. | Hinge‑loss mit hartem Margin kann **empfindlich** sein; weicher Margin (C) mildert dies. |
| **Typische Anwendungsfälle** | Kreditbewertung, medizinisches Risiko, A/B-Tests – wo **Wahrscheinlichkeiten & Erklärbarkeit** wichtig sind. | Bild-/Textklassifikation, Bioinformatik – wo **komplexe Grenzen** und **hochdimensionale Daten** wichtig sind. |

* **Wenn Sie kalibrierte Wahrscheinlichkeiten, Interpretierbarkeit benötigen oder mit riesigen Datensätzen arbeiten — wählen Sie die logistische Regression.**
* **Wenn Sie ein flexibles Modell benötigen, das nicht-lineare Beziehungen ohne manuelles Merkmalsengineering erfassen kann — wählen Sie SVM (mit Kernen).**
* Beide optimieren konvexe Ziele, daher sind **globale Minima garantiert**, aber die Kerne von SVM fügen Hyperparameter und Rechenkosten hinzu.

### Naive Bayes

Naive Bayes ist eine Familie von **probabilistischen Klassifikatoren**, die auf der Anwendung des Bayes-Theorems mit einer starken Unabhängigkeitsannahme zwischen den Merkmalen basieren. Trotz dieser "naiven" Annahme funktioniert Naive Bayes oft überraschend gut für bestimmte Anwendungen, insbesondere solche, die Text- oder kategoriale Daten betreffen, wie z.B. Spam-Erkennung.

#### Bayes' Theorem

Das Bayes-Theorem ist die Grundlage der Naive Bayes-Klassifikatoren. Es verbindet die bedingten und marginalen Wahrscheinlichkeiten zufälliger Ereignisse. Die Formel lautet:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Wo:
- `P(A|B)` ist die posteriori Wahrscheinlichkeit der Klasse `A` gegeben das Merkmal `B`.
- `P(B|A)` ist die Wahrscheinlichkeit des Merkmals `B` gegeben die Klasse `A`.
- `P(A)` ist die apriorische Wahrscheinlichkeit der Klasse `A`.
- `P(B)` ist die apriorische Wahrscheinlichkeit des Merkmals `B`.

Wenn wir beispielsweise klassifizieren möchten, ob ein Text von einem Kind oder einem Erwachsenen geschrieben wurde, können wir die Wörter im Text als Merkmale verwenden. Basierend auf einigen Anfangsdaten wird der Naive Bayes-Klassifikator zuvor die Wahrscheinlichkeiten jedes Wortes für jede potenzielle Klasse (Kind oder Erwachsener) berechnen. Wenn ein neuer Text gegeben wird, berechnet er die Wahrscheinlichkeit jeder potenziellen Klasse basierend auf den Wörtern im Text und wählt die Klasse mit der höchsten Wahrscheinlichkeit aus.

Wie Sie in diesem Beispiel sehen können, ist der Naive Bayes-Klassifikator sehr einfach und schnell, geht jedoch davon aus, dass die Merkmale unabhängig sind, was in realen Daten nicht immer der Fall ist.

#### Arten von Naive Bayes-Klassifikatoren

Es gibt mehrere Arten von Naive Bayes-Klassifikatoren, abhängig von der Art der Daten und der Verteilung der Merkmale:
- **Gaussian Naive Bayes**: Geht davon aus, dass die Merkmale einer Gaussian (normalen) Verteilung folgen. Es ist geeignet für kontinuierliche Daten.
- **Multinomial Naive Bayes**: Geht davon aus, dass die Merkmale einer multinomialen Verteilung folgen. Es ist geeignet für diskrete Daten, wie z.B. Wortzählungen in der Textklassifikation.
- **Bernoulli Naive Bayes**: Geht davon aus, dass die Merkmale binär (0 oder 1) sind. Es ist geeignet für binäre Daten, wie z.B. das Vorhandensein oder Fehlen von Wörtern in der Textklassifikation.
- **Categorical Naive Bayes**: Geht davon aus, dass die Merkmale kategoriale Variablen sind. Es ist geeignet für kategoriale Daten, wie z.B. die Klassifizierung von Früchten basierend auf ihrer Farbe und Form.

#### **Schlüsselkriterien von Naive Bayes:**

-   **Art des Problems:** Klassifikation (binär oder mehrklassig). Häufig verwendet für Textklassifikationsaufgaben in der Cybersicherheit (Spam, Phishing usw.).

-   **Interpretierbarkeit:** Mittel -- es ist nicht so direkt interpretierbar wie ein Entscheidungsbaum, aber man kann die gelernten Wahrscheinlichkeiten inspizieren (z.B. welche Wörter am wahrscheinlichsten in Spam- vs. Ham-E-Mails vorkommen). Die Form des Modells (Wahrscheinlichkeiten für jedes Merkmal gegeben die Klasse) kann bei Bedarf verstanden werden.

-   **Vorteile:** **Sehr schnelle** Ausbildung und Vorhersage, selbst bei großen Datensätzen (linear in der Anzahl der Instanzen * Anzahl der Merkmale). Erfordert relativ kleine Datenmengen, um Wahrscheinlichkeiten zuverlässig zu schätzen, insbesondere mit ordnungsgemäßer Glättung. Es ist oft überraschend genau als Basislinie, insbesondere wenn Merkmale unabhängig Beweise für die Klasse beitragen. Funktioniert gut mit hochdimensionalen Daten (z.B. Tausende von Merkmalen aus Text). Keine komplexe Feinabstimmung erforderlich, außer das Setzen eines Glättungsparameters.

-   **Einschränkungen:** Die Unabhängigkeitsannahme kann die Genauigkeit einschränken, wenn Merkmale stark korreliert sind. Zum Beispiel könnten in Netzwerkdaten Merkmale wie `src_bytes` und `dst_bytes` korreliert sein; Naive Bayes wird diese Interaktion nicht erfassen. Wenn die Datengröße sehr groß wird, können ausdrucksstärkere Modelle (wie Ensembles oder neuronale Netze) Naive Bayes übertreffen, indem sie Merkmalsabhängigkeiten lernen. Auch wenn eine bestimmte Kombination von Merkmalen erforderlich ist, um einen Angriff zu identifizieren (nicht nur einzelne Merkmale unabhängig), wird Naive Bayes Schwierigkeiten haben.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Der klassische Anwendungsfall ist **Spam-Erkennung** -- Naive Bayes war der Kern früherer Spam-Filter, die die Häufigkeiten bestimmter Tokens (Wörter, Phrasen, IP-Adressen) verwendeten, um die Wahrscheinlichkeit zu berechnen, dass eine E-Mail Spam ist. Es wird auch in der **Phishing-E-Mail-Erkennung** und **URL-Klassifikation** verwendet, wo das Vorhandensein bestimmter Schlüsselwörter oder Merkmale (wie "login.php" in einer URL oder `@` in einem URL-Pfad) zur Phishing-Wahrscheinlichkeit beiträgt. In der Malware-Analyse könnte man sich einen Naive Bayes-Klassifikator vorstellen, der das Vorhandensein bestimmter API-Aufrufe oder Berechtigungen in Software verwendet, um vorherzusagen, ob es sich um Malware handelt. Während fortschrittlichere Algorithmen oft besser abschneiden, bleibt Naive Bayes aufgrund seiner Geschwindigkeit und Einfachheit eine gute Basislinie.

<details>
<summary>Beispiel -- Naive Bayes zur Phishing-Erkennung:</summary>
Um Naive Bayes zu demonstrieren, verwenden wir Gaussian Naive Bayes auf dem NSL-KDD-Intrusionsdatensatz (mit binären Labels). Gaussian NB behandelt jedes Merkmal als einer normalen Verteilung pro Klasse folgend. Dies ist eine grobe Wahl, da viele Netzwerkmerkmale diskret oder stark schief verteilt sind, aber es zeigt, wie man Naive Bayes auf kontinuierliche Merkmalsdaten anwenden würde. Wir könnten auch Bernoulli NB auf einem Datensatz von binären Merkmalen (wie einer Reihe von ausgelösten Warnungen) wählen, aber wir bleiben hier für die Kontinuität bei NSL-KDD.
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
Dieser Code trainiert einen Naive Bayes-Klassifikator zur Erkennung von Angriffen. Naive Bayes berechnet Dinge wie `P(service=http | Attack)` und `P(Service=http | Normal)` basierend auf den Trainingsdaten, wobei Unabhängigkeit zwischen den Merkmalen angenommen wird. Anschließend verwendet es diese Wahrscheinlichkeiten, um neue Verbindungen als normal oder Angriff basierend auf den beobachteten Merkmalen zu klassifizieren. Die Leistung von NB auf NSL-KDD ist möglicherweise nicht so hoch wie bei fortgeschritteneren Modellen (da die Unabhängigkeit der Merkmale verletzt wird), aber sie ist oft anständig und bietet den Vorteil extremer Geschwindigkeit. In Szenarien wie der Echtzeit-E-Mail-Filterung oder der ersten Triage von URLs kann ein Naive Bayes-Modell offensichtlich bösartige Fälle schnell mit geringem Ressourcenverbrauch kennzeichnen.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors ist einer der einfachsten Machine-Learning-Algorithmen. Es ist eine **nicht-parametrische, instanzbasierte** Methode, die Vorhersagen basierend auf der Ähnlichkeit zu Beispielen im Trainingssatz trifft. Die Idee zur Klassifizierung ist: Um einen neuen Datenpunkt zu klassifizieren, finden Sie die **k** nächsten Punkte in den Trainingsdaten (seine "nächsten Nachbarn") und weisen Sie die Mehrheitsklasse unter diesen Nachbarn zu. "Nähe" wird durch eine Distanzmetrik definiert, typischerweise die euklidische Distanz für numerische Daten (andere Distanzen können für verschiedene Arten von Merkmalen oder Problemen verwendet werden).

K-NN erfordert *kein explizites Training* -- die "Trainings"-Phase besteht nur darin, den Datensatz zu speichern. Die gesamte Arbeit erfolgt während der Abfrage (Vorhersage): Der Algorithmus muss die Distanzen vom Abfragepunkt zu allen Trainingspunkten berechnen, um die nächsten zu finden. Dies macht die Vorhersagezeit **linear in der Anzahl der Trainingsproben**, was bei großen Datensätzen kostspielig sein kann. Daher ist k-NN am besten für kleinere Datensätze oder Szenarien geeignet, in denen Sie Speicher und Geschwindigkeit gegen Einfachheit eintauschen können.

Trotz seiner Einfachheit kann k-NN sehr komplexe Entscheidungsgrenzen modellieren (da die Entscheidungsgrenze effektiv jede Form annehmen kann, die durch die Verteilung der Beispiele diktiert wird). Es tendiert dazu, gut abzuschneiden, wenn die Entscheidungsgrenze sehr unregelmäßig ist und Sie viele Daten haben -- im Wesentlichen lässt es die Daten "für sich selbst sprechen". In hohen Dimensionen können Distanzmetriken jedoch weniger aussagekräftig werden (Fluch der Dimensionalität), und die Methode kann Schwierigkeiten haben, es sei denn, Sie haben eine große Anzahl von Proben.

*Anwendungsfälle in der Cybersicherheit:* k-NN wurde auf Anomalieerkennung angewendet -- zum Beispiel könnte ein Intrusion Detection System ein Netzwerkereignis als bösartig kennzeichnen, wenn die meisten seiner nächsten Nachbarn (frühere Ereignisse) bösartig waren. Wenn normaler Verkehr Cluster bildet und Angriffe Ausreißer sind, führt ein K-NN-Ansatz (mit k=1 oder kleinem k) im Wesentlichen eine **nächster-Nachbar-Anomalieerkennung** durch. K-NN wurde auch zur Klassifizierung von Malware-Familien durch binäre Merkmalsvektoren verwendet: Eine neue Datei könnte als eine bestimmte Malware-Familie klassifiziert werden, wenn sie sehr nah (im Merkmalsraum) an bekannten Instanzen dieser Familie ist. In der Praxis ist k-NN nicht so verbreitet wie skalierbarere Algorithmen, aber es ist konzeptionell einfach und wird manchmal als Basislinie oder für kleinere Probleme verwendet.

#### **Schlüsselkriterien von k-NN:**

-   **Art des Problems:** Klassifikation (und es gibt Regressionsvarianten). Es ist eine *lazy learning*-Methode -- kein explizites Modellanpassung.

-   **Interpretierbarkeit:** Niedrig bis mittel -- es gibt kein globales Modell oder prägnante Erklärung, aber man kann Ergebnisse interpretieren, indem man sich die nächsten Nachbarn ansieht, die eine Entscheidung beeinflusst haben (z. B. "Dieser Netzwerkfluss wurde als bösartig klassifiziert, weil er ähnlich zu diesen 3 bekannten bösartigen Flüssen ist"). Erklärungen können also beispielbasiert sein.

-   **Vorteile:** Sehr einfach zu implementieren und zu verstehen. Macht keine Annahmen über die Datenverteilung (nicht-parametrisch). Kann natürlich mit Mehrklassenproblemen umgehen. Es ist **adaptiv** in dem Sinne, dass Entscheidungsgrenzen sehr komplex sein können, geformt durch die Datenverteilung.

-   **Einschränkungen:** Die Vorhersage kann bei großen Datensätzen langsam sein (muss viele Distanzen berechnen). Speicherintensiv -- es speichert alle Trainingsdaten. Die Leistung verschlechtert sich in hochdimensionalen Merkmalsräumen, da alle Punkte dazu tendieren, nahezu äquidistant zu werden (was das Konzept von "nächster" weniger aussagekräftig macht). Es muss *k* (Anzahl der Nachbarn) angemessen gewählt werden -- zu kleines k kann laut sein, zu großes k kann irrelevante Punkte aus anderen Klassen einbeziehen. Außerdem sollten Merkmale angemessen skaliert werden, da Distanzberechnungen empfindlich auf die Skalierung reagieren.

<details>
<summary>Beispiel -- k-NN zur Phishing-Erkennung:</summary>

Wir werden erneut NSL-KDD verwenden (binäre Klassifikation). Da k-NN rechenintensiv ist, verwenden wir eine Teilmenge der Trainingsdaten, um es in dieser Demonstration handhabbar zu halten. Wir wählen beispielsweise 20.000 Trainingsproben aus den insgesamt 125k aus und verwenden k=5 Nachbarn. Nach dem Training (das wirklich nur das Speichern der Daten ist) werden wir auf dem Testset evaluieren. Wir werden auch Merkmale für die Distanzberechnung skalieren, um sicherzustellen, dass kein einzelnes Merkmal aufgrund der Skalierung dominiert.
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
Das k-NN-Modell klassifiziert eine Verbindung, indem es die 5 nächsten Verbindungen im Trainingsdatensatz betrachtet. Wenn beispielsweise 4 dieser Nachbarn Angriffe (Anomalien) und 1 normal ist, wird die neue Verbindung als Angriff klassifiziert. Die Leistung könnte angemessen sein, ist jedoch oft nicht so hoch wie bei einem gut abgestimmten Random Forest oder SVM mit denselben Daten. k-NN kann jedoch manchmal glänzen, wenn die Klassendistributionen sehr unregelmäßig und komplex sind – effektiv durch die Verwendung einer speicherbasierten Suche. In der Cybersicherheit könnte k-NN (mit k=1 oder kleinem k) zur Erkennung bekannter Angriffsmuster durch Beispiele oder als Bestandteil komplexerer Systeme (z. B. zur Clusterbildung und anschließenden Klassifizierung basierend auf der Clusterzugehörigkeit) verwendet werden.

### Gradient Boosting Machines (z. B. XGBoost)

Gradient Boosting Machines gehören zu den leistungsstärksten Algorithmen für strukturierte Daten. **Gradient Boosting** bezieht sich auf die Technik, ein Ensemble von schwachen Lernmodellen (häufig Entscheidungsbäume) sequenziell aufzubauen, wobei jedes neue Modell die Fehler des vorherigen Ensembles korrigiert. Im Gegensatz zu Bagging (Random Forests), das Bäume parallel erstellt und diese mittelt, baut Boosting Bäume *einen nach dem anderen*, wobei jeder mehr auf die Instanzen fokussiert, die vorherige Bäume falsch vorhergesagt haben.

Die beliebtesten Implementierungen in den letzten Jahren sind **XGBoost**, **LightGBM** und **CatBoost**, die alle Bibliotheken für gradient boosting decision trees (GBDT) sind. Sie waren in Wettbewerben und Anwendungen im maschinellen Lernen äußerst erfolgreich und erreichen oft **state-of-the-art Leistung auf tabellarischen Datensätzen**. In der Cybersicherheit haben Forscher und Praktiker gradient boosted trees für Aufgaben wie **Malware-Erkennung** (unter Verwendung von Merkmalen, die aus Dateien oder dem Laufverhalten extrahiert wurden) und **Netzwerk-Eindringungserkennung** verwendet. Ein Gradient-Boosting-Modell kann beispielsweise viele schwache Regeln (Bäume) wie "wenn viele SYN-Pakete und ungewöhnlicher Port -> wahrscheinlich Scan" in einen starken zusammengesetzten Detektor kombinieren, der viele subtile Muster berücksichtigt.

Warum sind Boosted Trees so effektiv? Jeder Baum in der Sequenz wird auf den *Residualfehlern* (Gradienten) der Vorhersagen des aktuellen Ensembles trainiert. Auf diese Weise **"verstärkt"** das Modell allmählich die Bereiche, in denen es schwach ist. Die Verwendung von Entscheidungsbäumen als Basislerner bedeutet, dass das endgültige Modell komplexe Interaktionen und nichtlineare Beziehungen erfassen kann. Außerdem hat Boosting von Natur aus eine Form der eingebauten Regularisierung: Durch das Hinzufügen vieler kleiner Bäume (und die Verwendung einer Lernrate zur Skalierung ihrer Beiträge) generalisiert es oft gut, ohne große Überanpassung, vorausgesetzt, es werden geeignete Parameter gewählt.

#### **Wesentliche Merkmale von Gradient Boosting:**

-   **Art des Problems:** Primär Klassifikation und Regression. In der Sicherheit normalerweise Klassifikation (z. B. binäre Klassifizierung einer Verbindung oder Datei). Es behandelt binäre, mehrklassige (mit geeigneten Verlusten) und sogar Ranking-Probleme.

-   **Interpretierbarkeit:** Niedrig bis mittel. Während ein einzelner Boosted Tree klein ist, kann ein vollständiges Modell Hunderte von Bäumen enthalten, was als Ganzes nicht menschlich interpretierbar ist. Wie bei Random Forest kann es jedoch Merkmalswichtigkeitswerte bereitstellen, und Werkzeuge wie SHAP (SHapley Additive exPlanations) können verwendet werden, um individuelle Vorhersagen bis zu einem gewissen Grad zu interpretieren.

-   **Vorteile:** Oft der **beste Algorithmus** für strukturierte/tabellarische Daten. Kann komplexe Muster und Interaktionen erkennen. Hat viele Abstimmungsparameter (Anzahl der Bäume, Tiefe der Bäume, Lernrate, Regularisierungsparameter), um die Modellkomplexität anzupassen und Überanpassung zu verhindern. Moderne Implementierungen sind auf Geschwindigkeit optimiert (z. B. verwendet XGBoost Informationen über den zweiten Grad und effiziente Datenstrukturen). Tendenziell besser im Umgang mit unausgewogenen Daten, wenn sie mit geeigneten Verlustfunktionen kombiniert oder die Stichprobengewichte angepasst werden.

-   **Einschränkungen:** Komplexer zu optimieren als einfachere Modelle; das Training kann langsam sein, wenn die Bäume tief sind oder die Anzahl der Bäume groß ist (obwohl es in der Regel immer noch schneller ist als das Training eines vergleichbaren tiefen neuronalen Netzwerks mit denselben Daten). Das Modell kann überanpassen, wenn es nicht abgestimmt ist (z. B. zu viele tiefe Bäume mit unzureichender Regularisierung). Aufgrund der vielen Hyperparameter kann die effektive Nutzung von Gradient Boosting mehr Fachwissen oder Experimentieren erfordern. Außerdem behandelt es, wie baumbasierte Methoden, sehr spärliche hochdimensionale Daten nicht so effizient wie lineare Modelle oder Naive Bayes (obwohl es immer noch angewendet werden kann, z. B. in der Textklassifizierung, aber möglicherweise nicht die erste Wahl ohne Merkmalsengineering ist).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Fast überall, wo ein Entscheidungsbaum oder Random Forest verwendet werden könnte, könnte ein Gradient-Boosting-Modell eine bessere Genauigkeit erzielen. Zum Beispiel haben **Microsofts Malware-Erkennungs**-Wettbewerbe eine intensive Nutzung von XGBoost auf entwickelten Merkmalen aus Binärdateien gesehen. Die Forschung zur **Netzwerk-Eindringungserkennung** berichtet oft von Spitzenleistungen mit GBDTs (z. B. XGBoost auf den Datensätzen CIC-IDS2017 oder UNSW-NB15). Diese Modelle können eine Vielzahl von Merkmalen (Protokolltypen, Häufigkeit bestimmter Ereignisse, statistische Merkmale des Verkehrs usw.) erfassen und kombinieren, um Bedrohungen zu erkennen. Bei der Phishing-Erkennung kann Gradient Boosting lexikalische Merkmale von URLs, Merkmale der Domainreputation und Merkmale des Seiteninhalts kombinieren, um eine sehr hohe Genauigkeit zu erreichen. Der Ensemble-Ansatz hilft, viele Randfälle und Feinheiten in den Daten abzudecken.

<details>
<summary>Beispiel -- XGBoost zur Phishing-Erkennung:</summary>
Wir werden einen Gradient-Boosting-Klassifikator auf dem Phishing-Datensatz verwenden. Um die Dinge einfach und eigenständig zu halten, verwenden wir `sklearn.ensemble.GradientBoostingClassifier` (was eine langsamere, aber unkomplizierte Implementierung ist). Normalerweise könnte man die Bibliotheken `xgboost` oder `lightgbm` für bessere Leistung und zusätzliche Funktionen verwenden. Wir werden das Modell trainieren und es ähnlich wie zuvor bewerten.
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
Das Gradient-Boosting-Modell wird wahrscheinlich eine sehr hohe Genauigkeit und AUC auf diesem Phishing-Datensatz erreichen (oft können diese Modelle mit entsprechender Feinabstimmung auf solchen Daten über 95 % Genauigkeit erreichen, wie in der Literatur zu sehen ist. Dies zeigt, warum GBDTs als *"das State-of-the-Art-Modell für tabellarische Datensätze"* gelten -- sie übertreffen oft einfachere Algorithmen, indem sie komplexe Muster erfassen. Im Kontext der Cybersicherheit könnte dies bedeuten, dass mehr Phishing-Websites oder Angriffe mit weniger Fehlalarmen erkannt werden. Natürlich muss man vorsichtig mit Overfitting sein -- wir würden typischerweise Techniken wie Kreuzvalidierung verwenden und die Leistung auf einem Validierungsdatensatz überwachen, wenn wir ein solches Modell für den Einsatz entwickeln.

</details>

### Modelle kombinieren: Ensemble-Lernen und Stacking

Ensemble-Lernen ist eine Strategie zur **Kombination mehrerer Modelle**, um die Gesamtleistung zu verbessern. Wir haben bereits spezifische Ensemble-Methoden gesehen: Random Forest (ein Ensemble von Bäumen über Bagging) und Gradient Boosting (ein Ensemble von Bäumen über sequenzielles Boosting). Aber Ensembles können auch auf andere Weise erstellt werden, wie z.B. **Voting-Ensembles** oder **Stacked Generalization (Stacking)**. Die Hauptidee ist, dass verschiedene Modelle unterschiedliche Muster erfassen oder unterschiedliche Schwächen haben können; durch ihre Kombination können wir **die Fehler jedes Modells mit den Stärken eines anderen ausgleichen**.

-   **Voting Ensemble:** In einem einfachen Abstimmungs-Klassifikator trainieren wir mehrere unterschiedliche Modelle (sagen wir, eine logistische Regression, einen Entscheidungsbaum und ein SVM) und lassen sie über die endgültige Vorhersage abstimmen (Mehrheitsabstimmung für die Klassifikation). Wenn wir die Stimmen gewichten (z.B. höhere Gewichtung für genauere Modelle), handelt es sich um ein gewichtetes Abstimmungsschema. Dies verbessert typischerweise die Leistung, wenn die einzelnen Modelle vernünftig gut und unabhängig sind -- das Ensemble verringert das Risiko eines Fehlers eines einzelnen Modells, da andere es möglicherweise korrigieren. Es ist wie ein Gremium von Experten anstelle einer einzelnen Meinung.

-   **Stacking (Stacked Ensemble):** Stacking geht einen Schritt weiter. Anstatt einfach abzustimmen, trainiert es ein **Meta-Modell**, um **zu lernen, wie man die Vorhersagen der Basis-Modelle am besten kombiniert**. Zum Beispiel trainierst du 3 verschiedene Klassifikatoren (Basislerner) und speist deren Ausgaben (oder Wahrscheinlichkeiten) als Merkmale in einen Meta-Klassifikator (oft ein einfaches Modell wie logistische Regression) ein, der lernt, wie man sie optimal mischt. Das Meta-Modell wird auf einem Validierungsdatensatz oder durch Kreuzvalidierung trainiert, um Overfitting zu vermeiden. Stacking kann oft einfacher Abstimmungen übertreffen, indem es *lernt, welchen Modellen man in welchen Umständen mehr vertrauen kann*. In der Cybersicherheit könnte ein Modell besser darin sein, Netzwerkscans zu erkennen, während ein anderes besser darin ist, Malware-Beaconing zu erkennen; ein Stacking-Modell könnte lernen, sich jeweils angemessen auf jedes zu verlassen.

Ensembles, ob durch Abstimmung oder Stacking, neigen dazu, **die Genauigkeit** und Robustheit zu **steigern**. Der Nachteil ist eine erhöhte Komplexität und manchmal reduzierte Interpretierbarkeit (obwohl einige Ensemble-Ansätze wie der Durchschnitt von Entscheidungsbäumen immer noch einige Einblicke bieten können, z.B. die Wichtigkeit von Merkmalen). In der Praxis kann die Verwendung eines Ensembles, wenn operationale Einschränkungen es zulassen, zu höheren Erkennungsraten führen. Viele erfolgreiche Lösungen in Cybersicherheitsherausforderungen (und Kaggle-Wettbewerben im Allgemeinen) verwenden Ensemble-Techniken, um das letzte bisschen Leistung herauszuholen.

<details>
<summary>Beispiel -- Voting Ensemble zur Phishing-Erkennung:</summary>
Um das Modell-Stacking zu veranschaulichen, lassen Sie uns einige der Modelle kombinieren, die wir im Phishing-Datensatz besprochen haben. Wir verwenden eine logistische Regression, einen Entscheidungsbaum und ein k-NN als Basislerner und verwenden einen Random Forest als Meta-Lerner, um deren Vorhersagen zu aggregieren. Der Meta-Lerner wird auf den Ausgaben der Basislerner trainiert (unter Verwendung von Kreuzvalidierung auf dem Trainingsdatensatz). Wir erwarten, dass das gestapelte Modell genauso gut oder leicht besser abschneidet als die einzelnen Modelle.
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
Das gestapelte Ensemble nutzt die komplementären Stärken der Basis-Modelle. Zum Beispiel könnte die logistische Regression die linearen Aspekte der Daten behandeln, der Entscheidungsbaum könnte spezifische regelartige Interaktionen erfassen, und k-NN könnte in lokalen Nachbarschaften des Merkmalsraums glänzen. Das Meta-Modell (hier ein Random Forest) kann lernen, wie man diese Eingaben gewichtet. Die resultierenden Metriken zeigen oft eine Verbesserung (auch wenn geringfügig) gegenüber den Metriken eines einzelnen Modells. In unserem Phishing-Beispiel, wenn die logistische Regression allein einen F1 von sagen wir 0,95 und der Baum 0,94 hatte, könnte das Ensemble 0,96 erreichen, indem es dort ansetzt, wo jedes Modell Fehler macht.

Ensemble-Methoden wie diese demonstrieren das Prinzip, dass *"die Kombination mehrerer Modelle in der Regel zu einer besseren Generalisierung führt"*. In der Cybersicherheit kann dies umgesetzt werden, indem mehrere Erkennungs-Engines (eine könnte regelbasiert, eine maschinelles Lernen, eine anomaliebasiert sein) und dann eine Schicht, die ihre Warnungen aggregiert – effektiv eine Form von Ensemble – um eine endgültige Entscheidung mit höherer Zuversicht zu treffen. Bei der Bereitstellung solcher Systeme muss man die zusätzliche Komplexität berücksichtigen und sicherstellen, dass das Ensemble nicht zu schwer zu verwalten oder zu erklären wird. Aber aus der Sicht der Genauigkeit sind Ensembles und Stacking leistungsstarke Werkzeuge zur Verbesserung der Modellleistung.

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
