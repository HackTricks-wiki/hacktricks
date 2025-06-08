# Modell-Datenvorbereitung & -Bewertung

{{#include ../banners/hacktricks-training.md}}

Die Modell-Datenvorbereitung ist ein entscheidender Schritt in der Pipeline des maschinellen Lernens, da sie die Umwandlung von Rohdaten in ein Format umfasst, das für das Training von Modellen des maschinellen Lernens geeignet ist. Dieser Prozess umfasst mehrere wichtige Schritte:

1. **Datensammlung**: Daten aus verschiedenen Quellen sammeln, wie z.B. Datenbanken, APIs oder Dateien. Die Daten können strukturiert (z.B. Tabellen) oder unstrukturiert (z.B. Text, Bilder) sein.
2. **Datenbereinigung**: Entfernen oder Korrigieren fehlerhafter, unvollständiger oder irrelevanter Datenpunkte. Dieser Schritt kann den Umgang mit fehlenden Werten, das Entfernen von Duplikaten und das Filtern von Ausreißern umfassen.
3. **Datenumwandlung**: Umwandeln der Daten in ein geeignetes Format für das Modellieren. Dies kann Normalisierung, Skalierung, Kodierung kategorialer Variablen und das Erstellen neuer Merkmale durch Techniken wie Feature Engineering umfassen.
4. **Datenteilung**: Aufteilen des Datensatzes in Trainings-, Validierungs- und Testsets, um sicherzustellen, dass das Modell gut auf unbekannte Daten verallgemeinern kann.

## Datensammlung

Die Datensammlung umfasst das Sammeln von Daten aus verschiedenen Quellen, die Folgendes umfassen können:
- **Datenbanken**: Extrahieren von Daten aus relationalen Datenbanken (z.B. SQL-Datenbanken) oder NoSQL-Datenbanken (z.B. MongoDB).
- **APIs**: Abrufen von Daten aus Web-APIs, die Echtzeit- oder historische Daten bereitstellen können.
- **Dateien**: Lesen von Daten aus Dateien in Formaten wie CSV, JSON oder XML.
- **Web Scraping**: Sammeln von Daten von Websites mithilfe von Web-Scraping-Techniken.

Je nach Ziel des Projekts im Bereich des maschinellen Lernens werden die Daten aus relevanten Quellen extrahiert und gesammelt, um sicherzustellen, dass sie repräsentativ für das Problemfeld sind.

## Datenbereinigung

Die Datenbereinigung ist der Prozess der Identifizierung und Korrektur von Fehlern oder Inkonsistenzen im Datensatz. Dieser Schritt ist entscheidend, um die Qualität der Daten sicherzustellen, die für das Training von Modellen des maschinellen Lernens verwendet werden. Wichtige Aufgaben in der Datenbereinigung umfassen:
- **Umgang mit fehlenden Werten**: Identifizieren und Ansprechen fehlender Datenpunkte. Häufige Strategien umfassen:
- Entfernen von Zeilen oder Spalten mit fehlenden Werten.
- Imputieren fehlender Werte mit Techniken wie Mittelwert-, Median- oder Modus-Imputation.
- Verwenden fortgeschrittener Methoden wie K-nearest neighbors (KNN) Imputation oder Regressionsimputation.
- **Entfernen von Duplikaten**: Identifizieren und Entfernen von doppelten Datensätzen, um sicherzustellen, dass jeder Datenpunkt einzigartig ist.
- **Filtern von Ausreißern**: Erkennen und Entfernen von Ausreißern, die die Leistung des Modells verzerren könnten. Techniken wie Z-Score, IQR (Interquartilsbereich) oder Visualisierungen (z.B. Boxplots) können verwendet werden, um Ausreißer zu identifizieren.

### Beispiel für Datenbereinigung
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
## Datenumwandlung

Die Datenumwandlung umfasst die Konvertierung der Daten in ein für das Modellieren geeignetes Format. Dieser Schritt kann Folgendes umfassen:
- **Normalisierung & Standardisierung**: Skalierung numerischer Merkmale auf einen gemeinsamen Bereich, typischerweise [0, 1] oder [-1, 1]. Dies hilft, die Konvergenz von Optimierungsalgorithmen zu verbessern.
- **Min-Max-Skalierung**: Reskalierung von Merkmalen auf einen festen Bereich, normalerweise [0, 1]. Dies erfolgt mit der Formel: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score-Normalisierung**: Standardisierung von Merkmalen durch Subtraktion des Mittelwerts und Division durch die Standardabweichung, was zu einer Verteilung mit einem Mittelwert von 0 und einer Standardabweichung von 1 führt. Dies erfolgt mit der Formel: `X' = (X - μ) / σ`, wobei μ der Mittelwert und σ die Standardabweichung ist.
- **Schiefe und Kurtosis**: Anpassung der Verteilung von Merkmalen zur Reduzierung der Schiefe (Asymmetrie) und Kurtosis (Spitzigkeit). Dies kann durch Transformationen wie logarithmische, Quadratwurzel- oder Box-Cox-Transformationen erfolgen. Wenn ein Merkmal beispielsweise eine schiefe Verteilung hat, kann die Anwendung einer logarithmischen Transformation helfen, es zu normalisieren.
- **String-Normalisierung**: Konvertierung von Strings in ein konsistentes Format, wie z.B.:
  - Kleinschreibung
  - Entfernen von Sonderzeichen (beibehalten der relevanten)
  - Entfernen von Stoppwörtern (häufige Wörter, die nicht zur Bedeutung beitragen, wie "der", "ist", "und")
  - Entfernen von zu häufigen und zu seltenen Wörtern (z.B. Wörter, die in mehr als 90 % der Dokumente oder weniger als 5 Mal im Korpus erscheinen)
  - Trimmen von Leerzeichen
  - Stemming/Lemmatisierung: Reduzierung von Wörtern auf ihre Basis- oder Stammform (z.B. "laufen" zu "lauf").

- **Kodierung kategorialer Variablen**: Umwandlung kategorialer Variablen in numerische Darstellungen. Häufige Techniken sind:
  - **One-Hot-Kodierung**: Erstellen von binären Spalten für jede Kategorie.
  - Wenn ein Merkmal beispielsweise die Kategorien "rot", "grün" und "blau" hat, wird es in drei binäre Spalten umgewandelt: `is_red`(100), `is_green`(010) und `is_blue`(001).
  - **Label-Kodierung**: Zuweisung einer eindeutigen Ganzzahl zu jeder Kategorie.
  - Zum Beispiel, "rot" = 0, "grün" = 1, "blau" = 2.
  - **Ordinal-Kodierung**: Zuweisung von Ganzzahlen basierend auf der Reihenfolge der Kategorien.
  - Wenn die Kategorien beispielsweise "niedrig", "mittel" und "hoch" sind, können sie als 0, 1 und 2 kodiert werden.
  - **Hashing-Kodierung**: Verwendung einer Hash-Funktion zur Umwandlung von Kategorien in Vektoren fester Größe, was für kategoriale Variablen mit hoher Kardinalität nützlich sein kann.
  - Wenn ein Merkmal viele einzigartige Kategorien hat, kann Hashing die Dimensionalität reduzieren und gleichzeitig einige Informationen über die Kategorien bewahren.
  - **Bag of Words (BoW)**: Darstellung von Textdaten als Matrix von Wortanzahlen oder -häufigkeiten, wobei jede Zeile einem Dokument und jede Spalte einem einzigartigen Wort im Korpus entspricht.
  - Wenn der Korpus beispielsweise die Wörter "Katze", "Hund" und "Fisch" enthält, würde ein Dokument, das "Katze" und "Hund" enthält, als [1, 1, 0] dargestellt. Diese spezifische Darstellung wird als "unigram" bezeichnet und erfasst nicht die Reihenfolge der Wörter, sodass sie semantische Informationen verliert.
  - **Bigram/Trigram**: Erweiterung von BoW zur Erfassung von Wortfolgen (Bigrams oder Trigrams), um etwas Kontext zu bewahren. Zum Beispiel würde "Katze und Hund" als Bigram [1, 1] für "Katze und" und [1, 1] für "und Hund" dargestellt. In diesen Fällen werden mehr semantische Informationen gesammelt (was die Dimensionalität der Darstellung erhöht), jedoch nur für 2 oder 3 Wörter gleichzeitig.
  - **TF-IDF (Term Frequency-Inverse Document Frequency)**: Ein statistisches Maß, das die Bedeutung eines Wortes in einem Dokument im Verhältnis zu einer Sammlung von Dokumenten (Korpus) bewertet. Es kombiniert die Termfrequenz (wie oft ein Wort in einem Dokument erscheint) und die inverse Dokumentfrequenz (wie selten ein Wort in allen Dokumenten ist).
  - Wenn das Wort "Katze" beispielsweise häufig in einem Dokument erscheint, aber im gesamten Korpus selten ist, hat es einen hohen TF-IDF-Wert, was auf seine Bedeutung in diesem Dokument hinweist.

- **Feature Engineering**: Erstellung neuer Merkmale aus bestehenden, um die Vorhersagekraft des Modells zu verbessern. Dies kann das Kombinieren von Merkmalen, das Extrahieren von Datum/Uhrzeit-Komponenten oder die Anwendung domänenspezifischer Transformationen umfassen.

## Datenaufteilung

Die Datenaufteilung umfasst die Unterteilung des Datensatzes in separate Teilmengen für Training, Validierung und Test. Dies ist entscheidend, um die Leistung des Modells auf ungesehenen Daten zu bewerten und Überanpassung zu verhindern. Häufige Strategien sind:
- **Train-Test-Split**: Aufteilung des Datensatzes in einen Trainingssatz (typischerweise 60-80 % der Daten), einen Validierungssatz (10-15 % der Daten) zur Feinabstimmung der Hyperparameter und einen Testsatz (10-15 % der Daten). Das Modell wird am Trainingssatz trainiert und am Testsatz bewertet.
- Wenn Sie beispielsweise einen Datensatz mit 1000 Proben haben, könnten Sie 700 Proben für das Training, 150 für die Validierung und 150 für den Test verwenden.
- **Stratifizierte Stichprobe**: Sicherstellung, dass die Verteilung der Klassen in den Trainings- und Testsätzen der Gesamtverteilung des Datensatzes ähnelt. Dies ist besonders wichtig für unausgeglichene Datensätze, bei denen einige Klassen möglicherweise deutlich weniger Proben haben als andere.
- **Zeitreihenaufteilung**: Bei Zeitreihendaten wird der Datensatz basierend auf der Zeit aufgeteilt, wobei sichergestellt wird, dass der Trainingssatz Daten aus früheren Zeiträumen und der Testsatz Daten aus späteren Zeiträumen enthält. Dies hilft, die Leistung des Modells auf zukünftigen Daten zu bewerten.
- **K-Fold-Kreuzvalidierung**: Aufteilung des Datensatzes in K Teilmengen (Folds) und Training des Modells K Mal, wobei jedes Mal ein anderer Fold als Testsatz und die verbleibenden Folds als Trainingssatz verwendet werden. Dies hilft sicherzustellen, dass das Modell auf verschiedenen Teilmengen von Daten bewertet wird, was eine robustere Schätzung seiner Leistung bietet.

## Modellevaluation

Die Modellevaluation ist der Prozess der Bewertung der Leistung eines maschinellen Lernmodells auf ungesehenen Daten. Sie umfasst die Verwendung verschiedener Metriken, um zu quantifizieren, wie gut das Modell auf neue Daten generalisiert. Häufige Evaluationsmetriken sind:

### Genauigkeit

Die Genauigkeit ist der Anteil der korrekt vorhergesagten Instanzen an der Gesamtanzahl der Instanzen. Sie wird berechnet als:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Genauigkeit ist eine einfache und intuitive Metrik, aber sie ist möglicherweise nicht geeignet für unausgeglichene Datensätze, in denen eine Klasse die anderen dominiert, da sie einen irreführenden Eindruck von der Modellleistung vermitteln kann. Wenn beispielsweise 90 % der Daten zur Klasse A gehören und das Modell alle Instanzen als Klasse A vorhersagt, erreicht es eine Genauigkeit von 90 %, ist jedoch nicht nützlich für die Vorhersage der Klasse B.

### Präzision

Präzision ist der Anteil der wahren positiven Vorhersagen an allen positiven Vorhersagen, die vom Modell gemacht wurden. Sie wird wie folgt berechnet:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Präzision ist besonders wichtig in Szenarien, in denen falsch-positive Ergebnisse kostspielig oder unerwünscht sind, wie z.B. bei medizinischen Diagnosen oder Betrugserkennung. Wenn ein Modell beispielsweise 100 Instanzen als positiv vorhersagt, aber nur 80 davon tatsächlich positiv sind, wäre die Präzision 0,8 (80%).

### Recall (Sensitivität)

Recall, auch bekannt als Sensitivität oder wahre positive Rate, ist der Anteil der wahren positiven Vorhersagen an allen tatsächlichen positiven Instanzen. Er wird wie folgt berechnet:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Der Rückruf ist entscheidend in Szenarien, in denen falsch-negative Ergebnisse kostspielig oder unerwünscht sind, wie z.B. bei der Krankheitsdiagnose oder der Spam-Filterung. Wenn ein Modell beispielsweise 80 von 100 tatsächlichen positiven Instanzen identifiziert, wäre der Rückruf 0,8 (80%).

### F1-Score

Der F1-Score ist das harmonische Mittel von Präzision und Rückruf und bietet ein Gleichgewicht zwischen den beiden Metriken. Er wird wie folgt berechnet:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Der F1-Score ist besonders nützlich, wenn man es mit unausgewogenen Datensätzen zu tun hat, da er sowohl falsche Positive als auch falsche Negative berücksichtigt. Er bietet eine einzelne Kennzahl, die den Kompromiss zwischen Präzision und Rückruf erfasst. Wenn ein Modell beispielsweise eine Präzision von 0,8 und einen Rückruf von 0,6 hat, wäre der F1-Score ungefähr 0,69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

Die ROC-AUC-Kennzahl bewertet die Fähigkeit des Modells, zwischen Klassen zu unterscheiden, indem die wahre positive Rate (Sensitivität) gegen die falsche positive Rate bei verschiedenen Schwellenwert-Einstellungen geplottet wird. Die Fläche unter der ROC-Kurve (AUC) quantifiziert die Leistung des Modells, wobei ein Wert von 1 perfekte Klassifizierung und ein Wert von 0,5 zufälliges Raten anzeigt.

> [!TIP]
> ROC-AUC ist besonders nützlich für binäre Klassifikationsprobleme und bietet einen umfassenden Überblick über die Leistung des Modells bei verschiedenen Schwellenwerten. Es ist weniger empfindlich gegenüber Klassenungleichgewicht im Vergleich zur Genauigkeit. Ein Modell mit einer AUC von 0,9 zeigt beispielsweise, dass es eine hohe Fähigkeit hat, zwischen positiven und negativen Instanzen zu unterscheiden.

### Spezifität

Die Spezifität, auch bekannt als wahre negative Rate, ist der Anteil der wahren negativen Vorhersagen an allen tatsächlichen negativen Instanzen. Sie wird wie folgt berechnet:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Spezifität ist wichtig in Szenarien, in denen falsch-positive Ergebnisse kostspielig oder unerwünscht sind, wie z.B. bei medizinischen Tests oder Betrugserkennung. Sie hilft zu bewerten, wie gut das Modell negative Instanzen identifiziert. Wenn ein Modell beispielsweise 90 von 100 tatsächlichen negativen Instanzen korrekt identifiziert, wäre die Spezifität 0,9 (90%).

### Matthews-Korrelationskoeffizient (MCC)
Der Matthews-Korrelationskoeffizient (MCC) ist ein Maß für die Qualität binärer Klassifikationen. Er berücksichtigt wahre und falsche Positive sowie Negative und bietet eine ausgewogene Sicht auf die Leistung des Modells. Der MCC wird wie folgt berechnet:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
wo:
- **TP**: Wahre Positives
- **TN**: Wahre Negatives
- **FP**: Falsche Positives
- **FN**: Falsche Negatives

> [!TIP]
> Der MCC reicht von -1 bis 1, wobei 1 perfekte Klassifikation anzeigt, 0 zufälliges Raten und -1 totale Uneinigkeit zwischen Vorhersage und Beobachtung. Er ist besonders nützlich für unausgeglichene Datensätze, da er alle vier Komponenten der Verwirrungsmatrix berücksichtigt.

### Mittlerer Absoluter Fehler (MAE)
Der Mittlere Absolute Fehler (MAE) ist eine Regressionsmetrik, die den durchschnittlichen absoluten Unterschied zwischen vorhergesagten und tatsächlichen Werten misst. Er wird berechnet als:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
wo:
- **n**: Anzahl der Instanzen
- **y_i**: Tatsächlicher Wert für Instanz i
- **ŷ_i**: Vorhergesagter Wert für Instanz i

> [!TIP]
> MAE bietet eine einfache Interpretation des durchschnittlichen Fehlers in den Vorhersagen, was das Verständnis erleichtert. Es ist weniger empfindlich gegenüber Ausreißern im Vergleich zu anderen Metriken wie dem mittleren quadratischen Fehler (MSE). Wenn ein Modell beispielsweise eine MAE von 5 hat, bedeutet das, dass die Vorhersagen des Modells im Durchschnitt um 5 Einheiten von den tatsächlichen Werten abweichen.

### Verwirrungsmatrix

Die Verwirrungsmatrix ist eine Tabelle, die die Leistung eines Klassifikationsmodells zusammenfasst, indem sie die Anzahl der wahren Positiven, wahren Negativen, falschen Positiven und falschen Negativen Vorhersagen zeigt. Sie bietet einen detaillierten Überblick darüber, wie gut das Modell in jeder Klasse abschneidet.

|               | Vorhergesagt Positiv | Vorhergesagt Negativ |
|---------------|---------------------|---------------------|
| Tatsächlich Positiv| Wahre Positive (TP)  | Falsche Negative (FN)  |
| Tatsächlich Negativ| Falsche Positive (FP) | Wahre Negative (TN)   |

- **Wahre Positive (TP)**: Das Modell hat die positive Klasse korrekt vorhergesagt.
- **Wahre Negative (TN)**: Das Modell hat die negative Klasse korrekt vorhergesagt.
- **Falsche Positive (FP)**: Das Modell hat die positive Klasse fälschlicherweise vorhergesagt (Typ-I-Fehler).
- **Falsche Negative (FN)**: Das Modell hat die negative Klasse fälschlicherweise vorhergesagt (Typ-II-Fehler).

Die Verwirrungsmatrix kann verwendet werden, um verschiedene Bewertungsmetriken wie Genauigkeit, Präzision, Recall und F1-Score zu berechnen.

{{#include ../banners/hacktricks-training.md}}
