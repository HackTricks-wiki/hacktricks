# Datenvorbereitung und -evaluierung von Modellen

{{#include ../banners/hacktricks-training.md}}

Die Datenvorbereitung von Modellen ist ein entscheidender Schritt in der Machine-Learning-Pipeline, da dabei Rohdaten in ein für das Training von Machine-Learning-Modellen geeignetes Format umgewandelt werden. Dieser Prozess umfasst mehrere wichtige Schritte:

1. **Datensammlung**: Sammeln von Daten aus verschiedenen Quellen wie Datenbanken, APIs oder Dateien. Die Daten können strukturiert (z. B. Tabellen) oder unstrukturiert (z. B. Text, Bilder) sein.
2. **Datenbereinigung**: Entfernen oder Korrigieren fehlerhafter, unvollständiger oder irrelevanter Datenpunkte. Dieser Schritt kann den Umgang mit fehlenden Werten, das Entfernen von Duplikaten und das Herausfiltern von Ausreißern umfassen.
3. **Datentransformation**: Umwandeln der Daten in ein für die Modellierung geeignetes Format. Dies kann Normalisierung, Skalierung, Kodierung kategorialer Variablen und das Erstellen neuer Features durch Techniken wie feature engineering umfassen.
4. **Aufteilung der Daten**: Aufteilen des Datensatzes in Trainings-, Validierungs- und Testmengen, um sicherzustellen, dass das Modell gut auf unbekannte Daten generalisieren kann.

## Datensammlung

Die Datensammlung umfasst das Erfassen von Daten aus verschiedenen Quellen, darunter:
- **Datenbanken**: Extrahieren von Daten aus relationalen Datenbanken (z. B. SQL-Datenbanken) oder NoSQL-Datenbanken (z. B. MongoDB).
- **APIs**: Abrufen von Daten über Web-APIs, die Echtzeit- oder historische Daten bereitstellen können.
- **Dateien**: Lesen von Daten aus Dateien in Formaten wie CSV, JSON oder XML.
- **Web Scraping**: Sammeln von Daten von Websites mithilfe von Web-Scraping-Techniken.

Abhängig vom Ziel des Machine-Learning-Projekts werden die Daten aus relevanten Quellen extrahiert und gesammelt, um sicherzustellen, dass sie den Problembereich repräsentativ abbilden.

## Datenbereinigung <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Datenbereinigung ist der Prozess, Fehler oder Inkonsistenzen im Datensatz zu identifizieren und zu korrigieren. Dieser Schritt ist entscheidend, um die Qualität der für das Training von Machine-Learning-Modellen verwendeten Daten sicherzustellen. Zu den wichtigsten Aufgaben bei der Datenbereinigung gehören:
- **Umgang mit fehlenden Werten**: Identifizieren und Bearbeiten fehlender Datenpunkte. Zu den gängigen Strategien gehören:
- Entfernen von Zeilen oder Spalten mit fehlenden Werten.
- Ersetzen fehlender Werte mithilfe von Techniken wie Mittelwert-, Median- oder Modus-Imputation.
- Verwendung fortgeschrittener Methoden wie der K-nearest neighbors (KNN)-Imputation oder der Regressions-Imputation.
- **Entfernen von Duplikaten**: Identifizieren und Entfernen doppelter Datensätze, um sicherzustellen, dass jeder Datenpunkt eindeutig ist.
- **Filtern von Ausreißern**: Erkennen und Entfernen von Ausreißern, die die Leistung des Modells verzerren können. Zur Identifizierung von Ausreißern können Techniken wie Z-Score, IQR (Interquartilsabstand) oder Visualisierungen (z. B. Boxplots) verwendet werden.

### Beispiel einer Datenbereinigung
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
## Datentransformation <sup>[[1]](#references)</sup>

Datentransformation umfasst die Umwandlung der Daten in ein für die Modellierung geeignetes Format. Dieser Schritt kann Folgendes umfassen:
- **Normalisierung und Standardisierung**: Skalierung numerischer Merkmale auf einen gemeinsamen Wertebereich, typischerweise [0, 1] oder [-1, 1]. Dies kann die Konvergenz von Optimierungsalgorithmen verbessern.
- **Min-Max-Skalierung**: Neuskalierung von Merkmalen auf einen festen Wertebereich, normalerweise [0, 1]. Dies erfolgt anhand der Formel: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Z-Score-Normalisierung**: Standardisierung von Merkmalen durch Subtraktion des Mittelwerts und Division durch die Standardabweichung, wodurch eine Verteilung mit einem Mittelwert von 0 und einer Standardabweichung von 1 entsteht. Dies erfolgt anhand der Formel: `X' = (X - μ) / σ`, wobei μ der Mittelwert und σ die Standardabweichung ist.
- **Schiefe und Kurtosis**: Anpassung von Merkmalsverteilungen durch Transformationen wie Logarithmus, Quadratwurzel oder Box-Cox. Beispielsweise kann eine logarithmische Transformation eine positive Schiefe reduzieren.
- **String-Normalisierung**: Umwandlung von Strings in ein einheitliches Format, beispielsweise:
- Umwandlung in Kleinbuchstaben
- Entfernen von Sonderzeichen (wobei relevante Zeichen beibehalten werden)
- Entfernen von Stoppwörtern (häufige Wörter, die nicht zur Bedeutung beitragen, wie „the“, „is“ und „and“)
- Entfernen zu häufiger und zu seltener Wörter (z. B. Wörter, die in mehr als 90 % der Dokumente oder weniger als 5 Mal im Korpus vorkommen)
- Entfernen von Leerzeichen am Anfang und Ende
- Stemming/Lemmatisierung: Reduzierung von Wörtern auf ihre Grund- oder Stammform (z. B. „running“ zu „run“).

- **Kodierung kategorialer Variablen**: Umwandlung kategorialer Variablen in numerische Darstellungen. Zu den gängigen Verfahren gehören:
- **One-Hot Encoding**: Erstellung binärer Spalten für jede Kategorie.
- Wenn ein Merkmal beispielsweise die Kategorien „red“, „green“ und „blue“ enthält, wird es in drei binäre Spalten umgewandelt: `is_red`(100), `is_green`(010) und `is_blue`(001).
- **Label Encoding**: Zuweisung einer eindeutigen Ganzzahl zu jeder Kategorie.
- Beispielsweise „red“ = 0, „green“ = 1, „blue“ = 2.
- **Ordinal Encoding**: Zuweisung von Ganzzahlen auf Grundlage der Reihenfolge der Kategorien.
- Wenn die Kategorien beispielsweise „low“, „medium“ und „high“ lauten, können sie jeweils als 0, 1 und 2 kodiert werden.
- **Hashing Encoding**: Verwendung einer Hash-Funktion zur Umwandlung von Kategorien in Vektoren fester Größe, was für kategoriale Variablen mit hoher Kardinalität nützlich sein kann.
- Wenn ein Merkmal beispielsweise viele eindeutige Kategorien enthält, kann Hashing die Dimensionalität reduzieren und dabei einige Informationen über die Kategorien bewahren.
- **Bag of Words (BoW)**: Darstellung von Textdaten als Matrix von Wortanzahlen oder -häufigkeiten, wobei jede Zeile einem Dokument und jede Spalte einem eindeutigen Wort im Korpus entspricht.
- Wenn der Korpus beispielsweise die Wörter „cat“, „dog“ und „fish“ enthält, würde ein Dokument mit „cat“ und „dog“ als [1, 1, 0] dargestellt. Diese spezifische Darstellung wird „unigram“ genannt und erfasst nicht die Reihenfolge der Wörter, wodurch semantische Informationen verloren gehen.
- **Bigram/Trigram**: Erweiterung von BoW zur Erfassung von Wortfolgen (Bigrams oder Trigrams), um einen Teil des Kontexts zu erhalten. Beispielsweise würde „cat and dog“ als Bigram [1, 1] für „cat and“ und [1, 1] für „and dog“ dargestellt. In diesem Fall werden mehr semantische Informationen erfasst (wodurch die Dimensionalität der Darstellung steigt), jedoch nur für jeweils 2 oder 3 Wörter.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Ein statistisches Maß, das die Bedeutung eines Wortes in einem Dokument im Verhältnis zu einer Sammlung von Dokumenten (Korpus) bewertet. Es kombiniert die Termhäufigkeit (wie oft ein Wort in einem Dokument vorkommt) und die inverse Dokumenthäufigkeit (wie selten ein Wort in allen Dokumenten ist).
- Wenn das Wort „cat“ beispielsweise häufig in einem Dokument vorkommt, im gesamten Korpus jedoch selten ist, erhält es einen hohen TF-IDF-Wert, der seine Bedeutung in diesem Dokument anzeigt.

- **Feature Engineering**: Erstellung neuer Merkmale aus vorhandenen Merkmalen, um die Vorhersagekraft des Modells zu verbessern. Dies kann das Kombinieren von Merkmalen, das Extrahieren von Datums-/Zeitkomponenten oder das Anwenden domänenspezifischer Transformationen umfassen.

## Aufteilung der Daten <sup>[[3]](#references)</sup>

Die Aufteilung der Daten umfasst die Unterteilung des Datensatzes in separate Teilmengen für Training, Validierung und Tests. Dies ist wichtig, um die Leistung des Modells anhand unbekannter Daten zu bewerten und Overfitting zu verhindern. Zu den gängigen Strategien gehören:
- **Train-Test-Split**: Aufteilung des Datensatzes in einen Trainingsdatensatz (typischerweise 60–80 % der Daten), einen Validierungsdatensatz (10–15 % der Daten) zur Abstimmung der Hyperparameter und einen Testdatensatz (10–15 % der Daten). Das Modell wird anhand des Trainingsdatensatzes trainiert und anhand des Testdatensatzes bewertet.
- Wenn du beispielsweise einen Datensatz mit 1000 Stichproben hast, könntest du 700 Stichproben für das Training, 150 für die Validierung und 150 für die Tests verwenden.
- **Stratifiziertes Sampling**: Sicherstellung, dass die Klassenverteilung in den Trainings- und Testdatensätzen der Verteilung im Gesamtdatensatz ähnelt. Dies ist besonders für unausgeglichene Datensätze wichtig, bei denen einige Klassen deutlich weniger Stichproben als andere enthalten können.
- **Time-Series-Split**: Bei Zeitreihendaten wird der Datensatz nach Zeit aufgeteilt, wobei sichergestellt wird, dass der Trainingsdatensatz Daten aus früheren Zeiträumen und der Testdatensatz Daten aus späteren Zeiträumen enthält. Dies hilft bei der Bewertung der Leistung des Modells anhand zukünftiger Daten.
- **K-Fold-Cross-Validation**: Aufteilung des Datensatzes in K Teilmengen (Folds) und K-maliges Training des Modells, wobei jedes Mal ein anderer Fold als Testdatensatz und die übrigen Folds als Trainingsdatensatz verwendet werden. Dies hilft sicherzustellen, dass das Modell anhand verschiedener Teilmengen der Daten bewertet wird, und liefert eine robustere Schätzung seiner Leistung.

## Modellevaluierung <sup>[[4]](#references)</sup>

Modellevaluierung ist der Prozess zur Bewertung der Leistung eines Machine-Learning-Modells anhand unbekannter Daten. Dabei werden verschiedene Metriken verwendet, um zu quantifizieren, wie gut das Modell auf neue Daten generalisiert. Zu den gängigen Bewertungsmetriken gehören:

### Genauigkeit

Die Genauigkeit ist der Anteil der korrekt vorhergesagten Instanzen an allen Instanzen. Sie wird folgendermaßen berechnet:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> Accuracy ist eine einfache und intuitive Metrik, eignet sich jedoch möglicherweise nicht für unausgeglichene Datensätze, bei denen eine Klasse gegenüber den anderen dominiert, da sie einen irreführenden Eindruck von der Modellleistung vermitteln kann. Wenn beispielsweise 90 % der Daten zu Klasse A gehören und das Modell alle Instanzen als Klasse A vorhersagt, erreicht es eine Accuracy von 90 %, ist aber für die Vorhersage von Klasse B nicht nützlich.

### Precision

Precision ist der Anteil der True-Positive-Vorhersagen an allen vom Modell getroffenen positiven Vorhersagen. Sie wird wie folgt berechnet:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> Präzision ist besonders in Szenarien wichtig, in denen False Positives kostspielig oder unerwünscht sind, beispielsweise bei medizinischen Diagnosen oder der Betrugserkennung. Wenn ein Modell beispielsweise 100 Instanzen als positiv vorhersagt, aber nur 80 davon tatsächlich positiv sind, beträgt die Präzision 0,8 (80 %).

### Recall (Sensitivität)

Recall, auch als Sensitivität oder True-Positive-Rate bezeichnet, ist der Anteil der True-Positive-Vorhersagen an allen tatsächlich positiven Instanzen. Er wird wie folgt berechnet:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Der Recall ist in Szenarien entscheidend, in denen False Negatives kostspielig oder unerwünscht sind, beispielsweise bei der Erkennung von Krankheiten oder der Spam-Filterung. Wenn ein Modell beispielsweise 80 von 100 tatsächlich positiven Instanzen identifiziert, würde der Recall 0,8 (80 %) betragen.

### F1 Score

Der F1 Score ist das harmonische Mittel aus Precision und Recall und stellt ein Gleichgewicht zwischen den beiden Metriken her. Er wird wie folgt berechnet:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Der F1-Score ist besonders nützlich beim Umgang mit unausgeglichenen Datensätzen, da er sowohl False Positives als auch False Negatives berücksichtigt. Er liefert eine einzelne Metrik, die den Kompromiss zwischen Precision und Recall erfasst. Wenn ein Modell beispielsweise eine Precision von 0.8 und einen Recall von 0.6 aufweist, läge der F1-Score bei ungefähr 0.69.

### ROC-AUC (Receiver Operating Characteristic – Fläche unter der Kurve)

Die ROC-AUC-Metrik bewertet die Fähigkeit des Modells, zwischen Klassen zu unterscheiden, indem sie die True-Positive-Rate (Sensitivität) gegenüber der False-Positive-Rate bei verschiedenen Schwellenwerten aufträgt. Die Fläche unter der ROC-Kurve (AUC) quantifiziert die Leistung des Modells, wobei ein Wert von 1 eine perfekte Klassifizierung und ein Wert von 0.5 zufälliges Raten bedeutet.

> [!TIP]
> ROC-AUC ist besonders nützlich für binäre Klassifizierungsprobleme und bietet einen umfassenden Überblick über die Leistung des Modells bei verschiedenen Schwellenwerten. Im Vergleich zur Accuracy reagiert sie weniger empfindlich auf ein Klassenungleichgewicht. Ein Modell mit einer AUC von 0.9 weist beispielsweise darauf hin, dass es eine hohe Fähigkeit besitzt, zwischen positiven und negativen Instanzen zu unterscheiden.

### Spezifität

Die Spezifität, auch True-Negative-Rate genannt, ist der Anteil der True-Negative-Vorhersagen an allen tatsächlich negativen Instanzen. Sie wird wie folgt berechnet:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> Spezifität ist in Szenarien wichtig, in denen falsch positive Ergebnisse kostspielig oder unerwünscht sind, beispielsweise bei medizinischen Tests oder der Betrugserkennung. Sie hilft dabei zu beurteilen, wie gut das Modell negative Instanzen identifiziert. Wenn ein Modell beispielsweise 90 von 100 tatsächlich negativen Instanzen korrekt identifiziert, beträgt die Spezifität 0,9 (90 %).

### Matthews-Korrelationskoeffizient (MCC)
Der Matthews-Korrelationskoeffizient (MCC) ist ein Maß für die Qualität binärer Klassifikationen. Er berücksichtigt echte und falsche positive sowie negative Ergebnisse und bietet dadurch eine ausgewogene Bewertung der Modellleistung. Der MCC wird wie folgt berechnet:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
wobei:
- **TP**: Richtig-Positive
- **TN**: Richtig-Negative
- **FP**: Falsch-Positive
- **FN**: Falsch-Negative

> [!TIP]
> Der MCC reicht von -1 bis 1, wobei 1 eine perfekte Klassifizierung, 0 zufälliges Raten und -1 eine vollständige Abweichung zwischen Vorhersage und Beobachtung bedeutet. Er ist besonders nützlich für unausgeglichene Datensätze, da er alle vier Komponenten der Konfusionsmatrix berücksichtigt.

### Mean Absolute Error (MAE)
Der Mean Absolute Error (MAE) ist eine Regressionsmetrik, die die durchschnittliche absolute Differenz zwischen vorhergesagten und tatsächlichen Werten misst. Er wird wie folgt berechnet:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
wobei:
- **n**: Anzahl der Instanzen
- **y_i**: Tatsächlicher Wert für Instanz i
- **ŷ_i**: Vorhergesagter Wert für Instanz i

> [!TIP]
> MAE bietet eine unkomplizierte Interpretation des durchschnittlichen Fehlers bei Vorhersagen und ist dadurch leicht verständlich. Im Vergleich zu anderen Metriken wie dem Mean Squared Error (MSE) ist es weniger empfindlich gegenüber Ausreißern. Wenn ein Modell beispielsweise einen MAE von 5 aufweist, bedeutet dies, dass die Vorhersagen des Modells im Durchschnitt um 5 Einheiten von den tatsächlichen Werten abweichen.

### Konfusionsmatrix

Die Konfusionsmatrix ist eine Tabelle, die die Leistung eines classification-Modells zusammenfasst, indem sie die Anzahl der True-Positive-, True-Negative-, False-Positive- und False-Negative-Vorhersagen darstellt. Sie bietet eine detaillierte Übersicht darüber, wie gut das Modell bei jeder Klasse abschneidet.

|               | Positive Vorhersage | Negative Vorhersage |
|---------------|---------------------|---------------------|
| Tatsächlich positiv| True Positive (TP)  | False Negative (FN)  |
| Tatsächlich negativ| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: Das Modell hat die positive Klasse korrekt vorhergesagt.
- **True Negative (TN)**: Das Modell hat die negative Klasse korrekt vorhergesagt.
- **False Positive (FP)**: Das Modell hat fälschlicherweise die positive Klasse vorhergesagt (Fehler Typ I).
- **False Negative (FN)**: Das Modell hat fälschlicherweise die negative Klasse vorhergesagt (Fehler Typ II).

Die Konfusionsmatrix kann zur Berechnung von Evaluationsmetriken wie Accuracy, Precision, Recall und F1 score verwendet werden.

## References

- [1] [scikit-learn - Datenvorverarbeitung](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputation fehlender Werte](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Cross-Validation: Bewertung der Estimator-Leistung](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Metriken und Scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
