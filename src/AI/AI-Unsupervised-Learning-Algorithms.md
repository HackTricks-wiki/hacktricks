# Unsupervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Unsupervised Learning

Unsupervised Learning ist eine Art des maschinellen Lernens, bei der das Modell mit Daten ohne beschriftete Antworten trainiert wird. Das Ziel ist es, Muster, Strukturen oder Beziehungen innerhalb der Daten zu finden. Im Gegensatz zum überwachten Lernen, bei dem das Modell aus beschrifteten Beispielen lernt, arbeiten unüberwachte Lernalgorithmen mit unbeschrifteten Daten. 
Unsupervised Learning wird häufig für Aufgaben wie Clustering, Dimensionsreduktion und Anomalieerkennung verwendet. Es kann helfen, verborgene Muster in Daten zu entdecken, ähnliche Elemente zu gruppieren oder die Komplexität der Daten zu reduzieren, während die wesentlichen Merkmale erhalten bleiben.

### K-Means Clustering

K-Means ist ein zentroidbasierter Clustering-Algorithmus, der Daten in K Cluster partitioniert, indem jeder Punkt dem nächstgelegenen Cluster-Mittelwert zugewiesen wird. Der Algorithmus funktioniert wie folgt:
1. **Initialisierung**: Wählen Sie K anfängliche Clusterzentren (Zentroiden), oft zufällig oder durch intelligentere Methoden wie k-means++.
2. **Zuweisung**: Weisen Sie jeden Datenpunkt dem nächstgelegenen Zentroiden basierend auf einer Distanzmetrik (z. B. euklidische Distanz) zu.
3. **Aktualisierung**: Berechnen Sie die Zentroiden neu, indem Sie den Mittelwert aller Datenpunkte, die jedem Cluster zugewiesen sind, nehmen.
4. **Wiederholen**: Schritte 2–3 werden wiederholt, bis die Clusterzuweisungen stabil sind (Zentroiden sich nicht mehr signifikant bewegen).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* K-Means wird zur Intrusionserkennung verwendet, indem Netzwerkereignisse geclustert werden. Zum Beispiel haben Forscher K-Means auf den KDD Cup 99 Intrusionsdatensatz angewendet und festgestellt, dass es den Datenverkehr effektiv in normale und Angriffscluster partitionierte. In der Praxis könnten Sicherheitsanalysten Protokolleinträge oder Benutzerdaten clustern, um Gruppen ähnlicher Aktivitäten zu finden; Punkte, die nicht zu einem gut geformten Cluster gehören, könnten Anomalien anzeigen (z. B. eine neue Malware-Variante, die ihr eigenes kleines Cluster bildet). K-Means kann auch bei der Klassifizierung von Malware-Familien helfen, indem Binärdateien basierend auf Verhaltensprofilen oder Merkmalsvektoren gruppiert werden.

#### Auswahl von K
Die Anzahl der Cluster (K) ist ein Hyperparameter, der vor dem Ausführen des Algorithmus definiert werden muss. Techniken wie die Elbow-Methode oder der Silhouette-Score können helfen, einen geeigneten Wert für K zu bestimmen, indem die Clustering-Leistung bewertet wird:

- **Elbow-Methode**: Zeichnen Sie die Summe der quadrierten Abstände von jedem Punkt zu seinem zugewiesenen Clusterzentroiden als Funktion von K. Suchen Sie nach einem "Ellbogen"-Punkt, an dem sich die Abnahmerate scharf ändert, was auf eine geeignete Anzahl von Clustern hinweist.
- **Silhouette-Score**: Berechnen Sie den Silhouette-Score für verschiedene Werte von K. Ein höherer Silhouette-Score weist auf besser definierte Cluster hin.

#### Annahmen und Einschränkungen

K-Means geht davon aus, dass **Cluster sphärisch und gleich groß** sind, was nicht für alle Datensätze zutreffen muss. Es ist empfindlich gegenüber der anfänglichen Platzierung der Zentroiden und kann zu lokalen Minima konvergieren. Darüber hinaus ist K-Means nicht für Datensätze mit variierenden Dichten oder nicht-globulären Formen sowie für Merkmale mit unterschiedlichen Skalen geeignet. Vorverarbeitungsschritte wie Normalisierung oder Standardisierung können erforderlich sein, um sicherzustellen, dass alle Merkmale gleichmäßig zu den Distanzberechnungen beitragen.

<details>
<summary>Beispiel -- Clustering von Netzwerkereignissen
</summary>
Im Folgenden simulieren wir Netzwerkverkehrsdaten und verwenden K-Means, um sie zu clustern. Angenommen, wir haben Ereignisse mit Merkmalen wie Verbindungsdauer und Byte-Anzahl. Wir erstellen 3 Cluster von "normalem" Verkehr und 1 kleines Cluster, das ein Angriffsmuster darstellt. Dann führen wir K-Means aus, um zu sehen, ob es sie trennt.
```python
import numpy as np
from sklearn.cluster import KMeans

# Simulate synthetic network traffic data (e.g., [duration, bytes]).
# Three normal clusters and one small attack cluster.
rng = np.random.RandomState(42)
normal1 = rng.normal(loc=[50, 500], scale=[10, 100], size=(500, 2))   # Cluster 1
normal2 = rng.normal(loc=[60, 1500], scale=[8, 200], size=(500, 2))   # Cluster 2
normal3 = rng.normal(loc=[70, 3000], scale=[5, 300], size=(500, 2))   # Cluster 3
attack = rng.normal(loc=[200, 800], scale=[5, 50], size=(50, 2))      # Small attack cluster

X = np.vstack([normal1, normal2, normal3, attack])
# Run K-Means clustering into 4 clusters (we expect it to find the 4 groups)
kmeans = KMeans(n_clusters=4, random_state=0, n_init=10)
labels = kmeans.fit_predict(X)

# Analyze resulting clusters
clusters, counts = np.unique(labels, return_counts=True)
print(f"Cluster labels: {clusters}")
print(f"Cluster sizes: {counts}")
print("Cluster centers (duration, bytes):")
for idx, center in enumerate(kmeans.cluster_centers_):
print(f"  Cluster {idx}: {center}")
```
In diesem Beispiel sollte K-Means 4 Cluster finden. Der kleine Angriffscluster (mit ungewöhnlich hoher Dauer ~200) wird idealerweise seinen eigenen Cluster bilden, gegeben seiner Distanz zu normalen Clustern. Wir drucken die Clustergrößen und -zentren aus, um die Ergebnisse zu interpretieren. In einem realen Szenario könnte man den Cluster mit wenigen Punkten als potenzielle Anomalien kennzeichnen oder seine Mitglieder auf bösartige Aktivitäten untersuchen.
</details>

### Hierarchisches Clustering

Hierarchisches Clustering erstellt eine Hierarchie von Clustern, entweder mit einem Bottom-Up (agglomerativen) Ansatz oder einem Top-Down (divisiven) Ansatz:

1. **Agglomerativ (Bottom-Up)**: Beginnen Sie mit jedem Datenpunkt als separatem Cluster und fügen Sie iterativ die nächstgelegenen Cluster zusammen, bis nur noch ein einzelner Cluster übrig bleibt oder ein Abbruchkriterium erfüllt ist.
2. **Divisiv (Top-Down)**: Beginnen Sie mit allen Datenpunkten in einem einzigen Cluster und teilen Sie die Cluster iterativ, bis jeder Datenpunkt sein eigener Cluster ist oder ein Abbruchkriterium erfüllt ist.

Agglomeratives Clustering erfordert eine Definition der Inter-Cluster-Distanz und ein Verknüpfungskriterium, um zu entscheiden, welche Cluster zusammengeführt werden sollen. Zu den gängigen Verknüpfungsmethoden gehören die Einzelverknüpfung (Abstand der nächstgelegenen Punkte zwischen zwei Clustern), die vollständige Verknüpfung (Abstand der entferntesten Punkte), die durchschnittliche Verknüpfung usw., und die Distanzmetrik ist oft euklidisch. Die Wahl der Verknüpfung beeinflusst die Form der produzierten Cluster. Es ist nicht notwendig, die Anzahl der Cluster K im Voraus festzulegen; Sie können das Dendrogramm auf einem gewählten Niveau "schneiden", um die gewünschte Anzahl von Clustern zu erhalten.

Hierarchisches Clustering erzeugt ein Dendrogramm, eine baumartige Struktur, die die Beziehungen zwischen Clustern auf verschiedenen Granularitätsebenen zeigt. Das Dendrogramm kann auf einem gewünschten Niveau geschnitten werden, um eine bestimmte Anzahl von Clustern zu erhalten.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Hierarchisches Clustering kann Ereignisse oder Entitäten in einen Baum organisieren, um Beziehungen zu erkennen. Zum Beispiel könnte im Malware-Analyse agglomeratives Clustering Proben nach Verhaltensähnlichkeit gruppieren und eine Hierarchie von Malware-Familien und -Varianten offenbaren. In der Netzwerksicherheit könnte man IP-Verkehrsflüsse clustern und das Dendrogramm verwenden, um Untergruppen des Verkehrs zu sehen (z. B. nach Protokoll, dann nach Verhalten). Da Sie K nicht im Voraus wählen müssen, ist es nützlich, wenn Sie neue Daten erkunden, für die die Anzahl der Angriffskategorien unbekannt ist.

#### Annahmen und Einschränkungen

Hierarchisches Clustering geht nicht von einer bestimmten Clusterform aus und kann geschachtelte Cluster erfassen. Es ist nützlich, um Taxonomien oder Beziehungen zwischen Gruppen zu entdecken (z. B. Gruppierung von Malware nach Familienuntergruppen). Es ist deterministisch (keine Probleme mit zufälliger Initialisierung). Ein wesentlicher Vorteil ist das Dendrogramm, das Einblicke in die Clusterstruktur der Daten auf allen Ebenen bietet – Sicherheitsanalysten können einen geeigneten Schnittpunkt wählen, um bedeutungsvolle Cluster zu identifizieren. Es ist jedoch rechenintensiv (typischerweise $O(n^2)$ Zeit oder schlechter für naive Implementierungen) und nicht praktikabel für sehr große Datensätze. Es ist auch ein gieriges Verfahren – einmal durchgeführte Zusammenführungen oder Teilungen können nicht rückgängig gemacht werden, was zu suboptimalen Clustern führen kann, wenn ein Fehler früh auftritt. Ausreißer können auch einige Verknüpfungsstrategien beeinflussen (Einzelverknüpfung kann den "Verkettungseffekt" verursachen, bei dem Cluster über Ausreißer verbunden werden).

<details>
<summary>Beispiel -- Agglomeratives Clustering von Ereignissen
</summary>

Wir werden die synthetischen Daten aus dem K-Means-Beispiel (3 normale Cluster + 1 Angriffscluster) wiederverwenden und agglomeratives Clustering anwenden. Wir veranschaulichen dann, wie man ein Dendrogramm und Clusterbezeichnungen erhält.
```python
from sklearn.cluster import AgglomerativeClustering
from scipy.cluster.hierarchy import linkage, dendrogram

# Perform agglomerative clustering (bottom-up) on the data
agg = AgglomerativeClustering(n_clusters=None, distance_threshold=0, linkage='ward')
# distance_threshold=0 gives the full tree without cutting (we can cut manually)
agg.fit(X)

print(f"Number of merge steps: {agg.n_clusters_ - 1}")  # should equal number of points - 1
# Create a dendrogram using SciPy for visualization (optional)
Z = linkage(X, method='ward')
# Normally, you would plot the dendrogram. Here we'll just compute cluster labels for a chosen cut:
clusters_3 = AgglomerativeClustering(n_clusters=3, linkage='ward').fit_predict(X)
print(f"Labels with 3 clusters: {np.unique(clusters_3)}")
print(f"Cluster sizes for 3 clusters: {np.bincount(clusters_3)}")
```
</details>

### DBSCAN (Dichtebasiertes räumliches Clustering von Anwendungen mit Rauschen)

DBSCAN ist ein dichtebasiierter Clustering-Algorithmus, der Punkte gruppiert, die eng beieinander liegen, während Punkte in Regionen mit niedriger Dichte als Ausreißer markiert werden. Es ist besonders nützlich für Datensätze mit variierenden Dichten und nicht-sphärischen Formen.

DBSCAN funktioniert, indem es zwei Parameter definiert:
- **Epsilon (ε)**: Die maximale Entfernung zwischen zwei Punkten, um als Teil desselben Clusters betrachtet zu werden.
- **MinPts**: Die minimale Anzahl von Punkten, die erforderlich ist, um eine dichte Region (Kernpunkt) zu bilden.

DBSCAN identifiziert Kernpunkte, Randpunkte und Rauschpunkte:
- **Kernpunkt**: Ein Punkt mit mindestens MinPts Nachbarn innerhalb der ε-Distanz.
- **Randpunkt**: Ein Punkt, der sich innerhalb der ε-Distanz eines Kernpunkts befindet, aber weniger als MinPts Nachbarn hat.
- **Rauschpunkt**: Ein Punkt, der weder ein Kernpunkt noch ein Randpunkt ist.

Das Clustering erfolgt, indem ein unbesuchter Kernpunkt ausgewählt, als neues Cluster markiert und dann rekursiv alle Punkte hinzugefügt werden, die von ihm aus dichte-erreichbar sind (Kernpunkte und deren Nachbarn usw.). Randpunkte werden dem Cluster eines nahegelegenen Kerns hinzugefügt. Nachdem alle erreichbaren Punkte erweitert wurden, wechselt DBSCAN zu einem anderen unbesuchten Kern, um ein neues Cluster zu starten. Punkte, die von keinem Kern erreicht werden, bleiben als Rauschen gekennzeichnet.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* DBSCAN ist nützlich zur Anomalieerkennung im Netzwerkverkehr. Beispielsweise könnte die normale Benutzeraktivität ein oder mehrere dichte Cluster im Merkmalsraum bilden, während neuartige Angriffsverhalten als verstreute Punkte erscheinen, die DBSCAN als Rauschen (Ausreißer) kennzeichnen wird. Es wurde verwendet, um Netzwerkflussaufzeichnungen zu clustern, wo es Portscans oder Denial-of-Service-Verkehr als spärliche Regionen von Punkten erkennen kann. Eine weitere Anwendung ist das Gruppieren von Malware-Varianten: Wenn die meisten Proben nach Familien gruppiert sind, aber einige nirgendwo passen, könnten diese wenigen Zero-Day-Malware sein. Die Fähigkeit, Rauschen zu kennzeichnen, bedeutet, dass Sicherheitsteams sich auf die Untersuchung dieser Ausreißer konzentrieren können.

#### Annahmen und Einschränkungen

**Annahmen & Stärken:** DBSCAN geht nicht von sphärischen Clustern aus – es kann beliebig geformte Cluster finden (sogar kettenartige oder benachbarte Cluster). Es bestimmt automatisch die Anzahl der Cluster basierend auf der Datendichte und kann Ausreißer effektiv als Rauschen identifizieren. Dies macht es leistungsstark für reale Daten mit unregelmäßigen Formen und Rauschen. Es ist robust gegenüber Ausreißern (im Gegensatz zu K-Means, das sie in Cluster zwingt). Es funktioniert gut, wenn Cluster ungefähr eine einheitliche Dichte haben.

**Einschränkungen:** Die Leistung von DBSCAN hängt von der Wahl geeigneter ε- und MinPts-Werte ab. Es kann Schwierigkeiten mit Daten haben, die unterschiedliche Dichten aufweisen – ein einzelnes ε kann sowohl dichte als auch spärliche Cluster nicht berücksichtigen. Wenn ε zu klein ist, kennzeichnet es die meisten Punkte als Rauschen; zu groß, und Cluster können fälschlicherweise zusammengeführt werden. Außerdem kann DBSCAN bei sehr großen Datensätzen ineffizient sein (naiv $O(n^2)$, obwohl räumliche Indizierung helfen kann). In hochdimensionalen Merkmalsräumen kann das Konzept der „Entfernung innerhalb von ε“ weniger sinnvoll werden (der Fluch der Dimensionalität), und DBSCAN benötigt möglicherweise eine sorgfältige Parameteranpassung oder kann scheitern, intuitive Cluster zu finden. Trotz dieser Einschränkungen adressieren Erweiterungen wie HDBSCAN einige Probleme (wie variierende Dichte).

<details>
<summary>Beispiel -- Clustering mit Rauschen
</summary>
```python
from sklearn.cluster import DBSCAN

# Generate synthetic data: 2 normal clusters and 5 outlier points
cluster1 = rng.normal(loc=[100, 1000], scale=[5, 100], size=(100, 2))
cluster2 = rng.normal(loc=[120, 2000], scale=[5, 100], size=(100, 2))
outliers = rng.uniform(low=[50, 50], high=[180, 3000], size=(5, 2))  # scattered anomalies
data = np.vstack([cluster1, cluster2, outliers])

# Run DBSCAN with chosen eps and MinPts
eps = 15.0   # radius for neighborhood
min_pts = 5  # minimum neighbors to form a dense region
db = DBSCAN(eps=eps, min_samples=min_pts).fit(data)
labels = db.labels_  # cluster labels (-1 for noise)

# Analyze clusters and noise
num_clusters = len(set(labels) - {-1})
num_noise = np.sum(labels == -1)
print(f"DBSCAN found {num_clusters} clusters and {num_noise} noise points")
print("Cluster labels for first 10 points:", labels[:10])
```
In diesem Abschnitt haben wir `eps` und `min_samples` angepasst, um unserem Datenskalierung (15.0 in Merkmals-Einheiten und erfordert 5 Punkte, um einen Cluster zu bilden) gerecht zu werden. DBSCAN sollte 2 Cluster (die Cluster des normalen Verkehrs) finden und die 5 injizierten Ausreißer als Rauschen kennzeichnen. Wir geben die Anzahl der Cluster im Vergleich zu Rauschpunkten aus, um dies zu überprüfen. In einer realen Umgebung könnte man über ε iterieren (unter Verwendung einer k-Abstandsgraph-Heuristik zur Auswahl von ε) und MinPts (oft auf etwa die Daten-Dimensionalität + 1 als Faustregel gesetzt), um stabile Clusterergebnisse zu finden. Die Fähigkeit, Rauschen explizit zu kennzeichnen, hilft, potenzielle Angriffsdatensätze für eine weitere Analyse zu trennen.

</details>

### Hauptkomponentenanalyse (PCA)

PCA ist eine Technik zur **Dimensionsreduktion**, die eine neue Menge orthogonaler Achsen (Hauptkomponenten) findet, die die maximale Varianz in den Daten erfassen. Einfach ausgedrückt, rotiert und projiziert PCA die Daten auf ein neues Koordinatensystem, sodass die erste Hauptkomponente (PC1) die größtmögliche Varianz erklärt, die zweite PC (PC2) die größte Varianz, die orthogonal zu PC1 ist, und so weiter. Mathematisch berechnet PCA die Eigenvektoren der Kovarianzmatrix der Daten – diese Eigenvektoren sind die Richtungen der Hauptkomponenten, und die entsprechenden Eigenwerte geben die Menge der von jeder erklärten Varianz an. Es wird häufig zur Merkmalsextraktion, Visualisierung und Rauschreduzierung verwendet.

Beachten Sie, dass dies nützlich ist, wenn die Dimensionen des Datensatzes **signifikante lineare Abhängigkeiten oder Korrelationen** enthalten.

PCA funktioniert, indem es die Hauptkomponenten der Daten identifiziert, die die Richtungen der maximalen Varianz sind. Die Schritte, die an PCA beteiligt sind, sind:
1. **Standardisierung**: Zentrieren Sie die Daten, indem Sie den Mittelwert subtrahieren und sie auf eine Einheitliche Varianz skalieren.
2. **Kovarianzmatrix**: Berechnen Sie die Kovarianzmatrix der standardisierten Daten, um die Beziehungen zwischen den Merkmalen zu verstehen.
3. **Eigenwertzerlegung**: Führen Sie eine Eigenwertzerlegung der Kovarianzmatrix durch, um die Eigenwerte und Eigenvektoren zu erhalten.
4. **Hauptkomponenten auswählen**: Sortieren Sie die Eigenwerte in absteigender Reihenfolge und wählen Sie die obersten K Eigenvektoren aus, die den größten Eigenwerten entsprechen. Diese Eigenvektoren bilden den neuen Merkmalsraum.
5. **Daten transformieren**: Projizieren Sie die ursprünglichen Daten auf den neuen Merkmalsraum unter Verwendung der ausgewählten Hauptkomponenten.
PCA wird häufig für die Datenvisualisierung, Rauschreduzierung und als Vorverarbeitungsschritt für andere maschinelle Lernalgorithmen verwendet. Es hilft, die Dimensionalität der Daten zu reduzieren, während die wesentliche Struktur erhalten bleibt.

#### Eigenwerte und Eigenvektoren

Ein Eigenwert ist ein Skalar, der die Menge der Varianz angibt, die durch seinen entsprechenden Eigenvektor erfasst wird. Ein Eigenvektor stellt eine Richtung im Merkmalsraum dar, entlang derer sich die Daten am meisten ändern.

Stellen Sie sich vor, A ist eine quadratische Matrix, und v ist ein nicht-null Vektor, sodass: `A * v = λ * v`
wobei:
- A eine quadratische Matrix wie [ [1, 2], [2, 1]] (z.B. Kovarianzmatrix) ist
- v ein Eigenvektor ist (z.B. [1, 1])

Dann ist `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, was der Eigenwert λ multipliziert mit dem Eigenvektor v sein wird, sodass der Eigenwert λ = 3 ist.

#### Eigenwerte und Eigenvektoren in PCA

Lassen Sie uns dies mit einem Beispiel erklären. Stellen Sie sich vor, Sie haben einen Datensatz mit vielen Graustufenbildern von Gesichtern mit 100x100 Pixeln. Jedes Pixel kann als Merkmal betrachtet werden, sodass Sie 10.000 Merkmale pro Bild haben (oder einen Vektor von 10.000 Komponenten pro Bild). Wenn Sie die Dimensionalität dieses Datensatzes mit PCA reduzieren möchten, würden Sie die folgenden Schritte ausführen:

1. **Standardisierung**: Zentrieren Sie die Daten, indem Sie den Mittelwert jedes Merkmals (Pixels) vom Datensatz abziehen.
2. **Kovarianzmatrix**: Berechnen Sie die Kovarianzmatrix der standardisierten Daten, die erfasst, wie Merkmale (Pixel) zusammen variieren.
- Beachten Sie, dass die Kovarianz zwischen zwei Variablen (in diesem Fall Pixel) angibt, wie sehr sie sich gemeinsam ändern, sodass die Idee hier darin besteht, herauszufinden, welche Pixel dazu neigen, gemeinsam mit einer linearen Beziehung zu steigen oder zu fallen.
- Wenn beispielsweise Pixel 1 und Pixel 2 dazu neigen, gemeinsam zu steigen, wird die Kovarianz zwischen ihnen positiv sein.
- Die Kovarianzmatrix wird eine 10.000x10.000-Matrix sein, in der jeder Eintrag die Kovarianz zwischen zwei Pixeln darstellt.
3. **Lösen Sie die Eigenwertgleichung**: Die zu lösende Eigenwertgleichung ist `C * v = λ * v`, wobei C die Kovarianzmatrix, v der Eigenvektor und λ der Eigenwert ist. Sie kann mit Methoden wie:
- **Eigenwertzerlegung**: Führen Sie eine Eigenwertzerlegung der Kovarianzmatrix durch, um die Eigenwerte und Eigenvektoren zu erhalten.
- **Singulärwertzerlegung (SVD)**: Alternativ können Sie SVD verwenden, um die Datenmatrix in singuläre Werte und Vektoren zu zerlegen, die ebenfalls die Hauptkomponenten liefern können.
4. **Hauptkomponenten auswählen**: Sortieren Sie die Eigenwerte in absteigender Reihenfolge und wählen Sie die obersten K Eigenvektoren aus, die den größten Eigenwerten entsprechen. Diese Eigenvektoren repräsentieren die Richtungen der maximalen Varianz in den Daten.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Ein häufiger Einsatz von PCA in der Sicherheit ist die Merkmalsreduktion zur Anomalieerkennung. Beispielsweise kann ein Intrusion-Detection-System mit über 40 Netzwerkmetriken (wie NSL-KDD-Merkmalen) PCA verwenden, um auf eine Handvoll Komponenten zu reduzieren, die Daten für die Visualisierung oder zur Einspeisung in Clusteralgorithmen zusammenfassen. Analysten könnten den Netzwerkverkehr im Raum der ersten beiden Hauptkomponenten darstellen, um zu sehen, ob Angriffe sich vom normalen Verkehr trennen. PCA kann auch helfen, redundante Merkmale (wie gesendete Bytes vs. empfangene Bytes, wenn sie korreliert sind) zu eliminieren, um die Erkennungsalgorithmen robuster und schneller zu machen.

#### Annahmen und Einschränkungen

PCA geht davon aus, dass **Hauptachsen der Varianz sinnvoll sind** – es ist eine lineare Methode, daher erfasst sie lineare Korrelationen in den Daten. Es ist unüberwacht, da es nur die Merkmalskovarianz verwendet. Zu den Vorteilen von PCA gehören Rauschreduzierung (kleinere Varianzkomponenten entsprechen oft Rauschen) und Dekorrelation der Merkmale. Es ist rechnerisch effizient für mäßig hohe Dimensionen und oft ein nützlicher Vorverarbeitungsschritt für andere Algorithmen (um den Fluch der Dimensionalität zu mildern). Eine Einschränkung ist, dass PCA auf lineare Beziehungen beschränkt ist – es erfasst keine komplexen nichtlinearen Strukturen (während Autoencoder oder t-SNE dies tun könnten). Außerdem können PCA-Komponenten schwer zu interpretieren sein in Bezug auf die ursprünglichen Merkmale (sie sind Kombinationen der ursprünglichen Merkmale). In der Cybersicherheit muss man vorsichtig sein: Ein Angriff, der nur eine subtile Veränderung in einem Merkmal mit niedriger Varianz verursacht, könnte in den obersten PCs nicht sichtbar sein (da PCA die Varianz priorisiert, nicht unbedingt die „Interessantheit“).

<details>
<summary>Beispiel -- Reduzierung der Dimensionen von Netzwerkdaten
</summary>

Angenommen, wir haben Netzwerkverbindungsprotokolle mit mehreren Merkmalen (z.B. Dauer, Bytes, Zählungen). Wir werden einen synthetischen 4-dimensionalen Datensatz generieren (mit einer gewissen Korrelation zwischen den Merkmalen) und PCA verwenden, um ihn auf 2 Dimensionen für die Visualisierung oder weitere Analysen zu reduzieren.
```python
from sklearn.decomposition import PCA

# Create synthetic 4D data (3 clusters similar to before, but add correlated features)
# Base features: duration, bytes (as before)
base_data = np.vstack([normal1, normal2, normal3])  # 1500 points from earlier normal clusters
# Add two more features correlated with existing ones, e.g. packets = bytes/50 + noise, errors = duration/10 + noise
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))
data_4d = np.column_stack([base_data[:, 0], base_data[:, 1], packets, errors])

# Apply PCA to reduce 4D data to 2D
pca = PCA(n_components=2)
data_2d = pca.fit_transform(data_4d)
print("Explained variance ratio of 2 components:", pca.explained_variance_ratio_)
print("Original shape:", data_4d.shape, "Reduced shape:", data_2d.shape)
# We can examine a few transformed points
print("First 5 data points in PCA space:\n", data_2d[:5])
```
Hier haben wir die früheren normalen Verkehrscluster genommen und jeden Datenpunkt um zwei zusätzliche Merkmale (Pakete und Fehler) erweitert, die mit Bytes und Dauer korrelieren. PCA wird dann verwendet, um die 4 Merkmale in 2 Hauptkomponenten zu komprimieren. Wir drucken das erklärte Varianzverhältnis aus, das zeigen könnte, dass beispielsweise >95% der Varianz von 2 Komponenten erfasst werden (was wenig Informationsverlust bedeutet). Die Ausgabe zeigt auch, dass die Datenform von (1500, 4) auf (1500, 2) reduziert wird. Die ersten paar Punkte im PCA-Raum werden als Beispiel angegeben. In der Praxis könnte man data_2d plotten, um visuell zu überprüfen, ob die Cluster unterscheidbar sind. Wenn eine Anomalie vorhanden war, könnte man sie als einen Punkt sehen, der sich im PCA-Raum vom Hauptcluster entfernt. PCA hilft somit, komplexe Daten in eine handhabbare Form für die menschliche Interpretation oder als Eingabe für andere Algorithmen zu destillieren.

</details>


### Gaussian Mixture Models (GMM)

Ein Gaussian Mixture Model geht davon aus, dass Daten aus einer Mischung von **mehreren Gaussian (normalen) Verteilungen mit unbekannten Parametern** generiert werden. Im Wesentlichen handelt es sich um ein probabilistisches Clustering-Modell: Es versucht, jeden Punkt sanft einem der K Gaussian-Komponenten zuzuordnen. Jede Gaussian-Komponente k hat einen Mittelwertvektor (μ_k), eine Kovarianzmatrix (Σ_k) und ein Mischgewicht (π_k), das darstellt, wie verbreitet dieser Cluster ist. Im Gegensatz zu K-Means, das „harte“ Zuordnungen vornimmt, gibt GMM jedem Punkt eine Wahrscheinlichkeit, zu jedem Cluster zu gehören.

Das Anpassen von GMM erfolgt typischerweise über den Expectation-Maximization (EM)-Algorithmus:

- **Initialisierung**: Beginnen Sie mit anfänglichen Schätzungen für die Mittelwerte, Kovarianzen und Mischkoeffizienten (oder verwenden Sie die Ergebnisse von K-Means als Ausgangspunkt).

- **E-Schritt (Erwartung)**: Berechnen Sie die Verantwortung jedes Clusters für jeden Punkt anhand der aktuellen Parameter: im Wesentlichen `r_nk = P(z_k | x_n)`, wobei z_k die latente Variable ist, die die Clusterzugehörigkeit für den Punkt x_n angibt. Dies geschieht unter Verwendung des Satzes von Bayes, wobei wir die posteriori Wahrscheinlichkeit jedes Punktes berechnen, zu jedem Cluster basierend auf den aktuellen Parametern zu gehören. Die Verantwortlichkeiten werden wie folgt berechnet:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
wobei:
- \( \pi_k \) der Mischkoeffizient für Cluster k (priori Wahrscheinlichkeit von Cluster k) ist,
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) die Gaussian-Wahrscheinlichkeitsdichtefunktion für den Punkt \( x_n \) gegeben den Mittelwert \( \mu_k \) und die Kovarianz \( \Sigma_k \) ist.

- **M-Schritt (Maximierung)**: Aktualisieren Sie die Parameter unter Verwendung der im E-Schritt berechneten Verantwortlichkeiten:
- Aktualisieren Sie jeden Mittelwert μ_k als den gewichteten Durchschnitt der Punkte, wobei die Gewichte die Verantwortlichkeiten sind.
- Aktualisieren Sie jede Kovarianz Σ_k als die gewichtete Kovarianz der Punkte, die dem Cluster k zugeordnet sind.
- Aktualisieren Sie die Mischkoeffizienten π_k als den durchschnittlichen Verantwortungswert für Cluster k.

- **Iterieren** Sie E- und M-Schritte, bis die Konvergenz erreicht ist (Parameter stabilisieren sich oder die Verbesserung der Wahrscheinlichkeit liegt unter einem Schwellenwert).

Das Ergebnis ist eine Menge von Gaussian-Verteilungen, die gemeinsam die gesamte Datenverteilung modellieren. Wir können das angepasste GMM verwenden, um zu clustern, indem wir jeden Punkt dem Gaussian mit der höchsten Wahrscheinlichkeit zuordnen oder die Wahrscheinlichkeiten für Unsicherheit beibehalten. Man kann auch die Wahrscheinlichkeit neuer Punkte bewerten, um zu sehen, ob sie zum Modell passen (nützlich für die Anomalieerkennung).

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* GMM kann zur Anomalieerkennung verwendet werden, indem die Verteilung normaler Daten modelliert wird: Jeder Punkt mit sehr niedriger Wahrscheinlichkeit unter der gelernten Mischung wird als Anomalie markiert. Zum Beispiel könnten Sie ein GMM auf legitimen Netzwerkverkehrsmerkmalen trainieren; eine Angriffsverbindung, die keinem gelernten Cluster ähnelt, hätte eine niedrige Wahrscheinlichkeit. GMMs werden auch verwendet, um Aktivitäten zu clustern, bei denen Cluster unterschiedliche Formen haben könnten – z.B. Benutzer nach Verhaltensprofilen zu gruppieren, wobei die Merkmale jedes Profils Gaussian-ähnlich, aber mit eigener Varianzstruktur sein könnten. Ein weiteres Szenario: Bei der Phishing-Erkennung könnten legitime E-Mail-Merkmale einen Gaussian-Cluster bilden, bekanntes Phishing einen anderen, und neue Phishing-Kampagnen könnten entweder als separater Gaussian oder als Punkte mit niedriger Wahrscheinlichkeit im Verhältnis zur bestehenden Mischung erscheinen.

#### Annahmen und Einschränkungen

GMM ist eine Verallgemeinerung von K-Means, die Kovarianz einbezieht, sodass Cluster ellipsoid sein können (nicht nur sphärisch). Es verarbeitet Cluster unterschiedlicher Größen und Formen, wenn die Kovarianz vollständig ist. Weiches Clustering ist ein Vorteil, wenn die Clustergrenzen unscharf sind – z.B. in der Cybersicherheit könnte ein Ereignis Merkmale mehrerer Angriffsarten aufweisen; GMM kann diese Unsicherheit mit Wahrscheinlichkeiten widerspiegeln. GMM bietet auch eine probabilistische Dichteschätzung der Daten, die nützlich ist, um Ausreißer (Punkte mit niedriger Wahrscheinlichkeit unter allen Mischkomponenten) zu erkennen.

Auf der negativen Seite erfordert GMM die Angabe der Anzahl der Komponenten K (obwohl man Kriterien wie BIC/AIC verwenden kann, um sie auszuwählen). EM kann manchmal langsam konvergieren oder zu einem lokalen Optimum führen, daher ist die Initialisierung wichtig (oft wird EM mehrfach ausgeführt). Wenn die Daten tatsächlich keiner Mischung von Gaussians folgen, kann das Modell schlecht passen. Es besteht auch das Risiko, dass ein Gaussian schrumpft, um nur einen Ausreißer abzudecken (obwohl Regularisierung oder Mindestkovarianzgrenzen dies mildern können).


<details>
<summary>Beispiel --  Weiches Clustering & Anomaliewerte
</summary>
```python
from sklearn.mixture import GaussianMixture

# Fit a GMM with 3 components to the normal traffic data
gmm = GaussianMixture(n_components=3, covariance_type='full', random_state=0)
gmm.fit(base_data)  # using the 1500 normal data points from PCA example

# Print the learned Gaussian parameters
print("GMM means:\n", gmm.means_)
print("GMM covariance matrices:\n", gmm.covariances_)

# Take a sample attack-like point and evaluate it
sample_attack = np.array([[200, 800]])  # an outlier similar to earlier attack cluster
probs = gmm.predict_proba(sample_attack)
log_likelihood = gmm.score_samples(sample_attack)
print("Cluster membership probabilities for sample attack:", probs)
print("Log-likelihood of sample attack under GMM:", log_likelihood)
```
In diesem Code trainieren wir ein GMM mit 3 Gaussischen auf dem normalen Verkehr (vorausgesetzt, wir kennen 3 Profile von legitimem Verkehr). Die ausgegebenen Mittelwerte und Kovarianzen beschreiben diese Cluster (zum Beispiel könnte ein Mittelwert etwa [50,500] entsprechen, was dem Zentrum eines Clusters entspricht, usw.). Wir testen dann eine verdächtige Verbindung [duration=200, bytes=800]. Die predict_proba gibt die Wahrscheinlichkeit an, dass dieser Punkt zu jedem der 3 Cluster gehört – wir würden erwarten, dass diese Wahrscheinlichkeiten sehr niedrig oder stark verzerrt sind, da [200,800] weit von den normalen Clustern entfernt liegt. Der gesamte score_samples (Log-Likelihood) wird ausgegeben; ein sehr niedriger Wert zeigt an, dass der Punkt nicht gut zum Modell passt, was ihn als Anomalie kennzeichnet. In der Praxis könnte man einen Schwellenwert für die Log-Likelihood (oder für die maximale Wahrscheinlichkeit) festlegen, um zu entscheiden, ob ein Punkt ausreichend unwahrscheinlich ist, um als bösartig betrachtet zu werden. GMM bietet somit eine fundierte Methode zur Anomalieerkennung und liefert auch weiche Cluster, die Unsicherheit anerkennen.

### Isolation Forest

**Isolation Forest** ist ein Ensemble-Anomalieerkennungsalgorithmus, der auf der Idee basiert, Punkte zufällig zu isolieren. Das Prinzip ist, dass Anomalien selten und unterschiedlich sind, sodass sie leichter zu isolieren sind als normale Punkte. Ein Isolation Forest baut viele binäre Isolationsbäume (zufällige Entscheidungsbäume), die die Daten zufällig partitionieren. An jedem Knoten in einem Baum wird ein zufälliges Merkmal ausgewählt und ein zufälliger Split-Wert zwischen dem Minimum und Maximum dieses Merkmals für die Daten in diesem Knoten gewählt. Dieser Split teilt die Daten in zwei Zweige. Der Baum wird so lange gewachsen, bis jeder Punkt in seinem eigenen Blatt isoliert ist oder eine maximale Baumhöhe erreicht ist.

Die Anomalieerkennung erfolgt durch Beobachtung der Pfadlänge jedes Punktes in diesen zufälligen Bäumen – die Anzahl der Splits, die erforderlich sind, um den Punkt zu isolieren. Intuitiv neigen Anomalien (Ausreißer) dazu, schneller isoliert zu werden, da ein zufälliger Split eher einen Ausreißer (der sich in einer spärlichen Region befindet) trennt als einen normalen Punkt in einem dichten Cluster. Der Isolation Forest berechnet einen Anomaliewert aus der durchschnittlichen Pfadlänge über alle Bäume: kürzere durchschnittliche Pfadlänge → anomalere Punkte. Die Werte werden normalerweise auf [0,1] normalisiert, wobei 1 sehr wahrscheinlich eine Anomalie bedeutet.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Isolation Forests wurden erfolgreich in der Eindringungserkennung und Betrugserkennung eingesetzt. Zum Beispiel trainieren Sie einen Isolation Forest auf Netzwerkverkehrsprotokollen, die hauptsächlich normales Verhalten enthalten; der Wald wird kurze Pfade für seltsamen Verkehr erzeugen (wie eine IP, die einen unbekannten Port verwendet oder ein ungewöhnliches Paketgrößenmuster aufweist), und ihn zur Inspektion kennzeichnen. Da er keine gekennzeichneten Angriffe erfordert, ist er geeignet, unbekannte Angriffstypen zu erkennen. Er kann auch auf Benutzerdaten zu Anmeldungen eingesetzt werden, um Kontoübernahmen zu erkennen (die anomalen Anmeldezeiten oder -orte werden schnell isoliert). In einem Anwendungsfall könnte ein Isolation Forest ein Unternehmen schützen, indem er Systemmetriken überwacht und eine Warnung generiert, wenn eine Kombination von Metriken (CPU, Netzwerk, Dateiänderungen) sehr unterschiedlich (kurze Isolationspfade) von historischen Mustern aussieht.

#### Annahmen und Einschränkungen

**Vorteile**: Isolation Forest erfordert keine Verteilungsannahme; er zielt direkt auf Isolation ab. Er ist effizient bei hochdimensionalen Daten und großen Datensätzen (lineare Komplexität $O(n\log n)$ für den Aufbau des Waldes), da jeder Baum Punkte nur mit einer Teilmenge von Merkmalen und Splits isoliert. Er neigt dazu, numerische Merkmale gut zu behandeln und kann schneller sein als distanzbasierte Methoden, die $O(n^2)$ sein könnten. Er gibt auch automatisch einen Anomaliewert aus, sodass Sie einen Schwellenwert für Warnungen festlegen können (oder einen Kontaminationsparameter verwenden, um automatisch einen Cutoff basierend auf einem erwarteten Anomalieanteil zu entscheiden).

**Einschränkungen**: Aufgrund seiner zufälligen Natur können die Ergebnisse zwischen den Durchläufen leicht variieren (obwohl dies bei ausreichend vielen Bäumen geringfügig ist). Wenn die Daten viele irrelevante Merkmale enthalten oder wenn Anomalien sich in keinem Merkmal stark unterscheiden, könnte die Isolation nicht effektiv sein (zufällige Splits könnten normale Punkte zufällig isolieren – jedoch mildert das Durchschnittt vieler Bäume dies). Außerdem geht der Isolation Forest im Allgemeinen davon aus, dass Anomalien eine kleine Minderheit sind (was in der Regel in Cybersicherheitsszenarien zutrifft).

<details>
<summary>Beispiel -- Ausreißer in Netzwerkprotokollen erkennen
</summary>

Wir werden den früheren Testdatensatz verwenden (der normalen und einige Angriffs-Punkte enthält) und einen Isolation Forest ausführen, um zu sehen, ob er die Angriffe trennen kann. Wir gehen davon aus, dass wir erwarten, dass ~15% der Daten anomale sind (zur Demonstration).
```python
from sklearn.ensemble import IsolationForest

# Combine normal and attack test data from autoencoder example
X_test_if = test_data  # (120 x 2 array with 100 normal and 20 attack points)
# Train Isolation Forest (unsupervised) on the test set itself for demo (in practice train on known normal)
iso_forest = IsolationForest(n_estimators=100, contamination=0.15, random_state=0)
iso_forest.fit(X_test_if)
# Predict anomalies (-1 for anomaly, 1 for normal)
preds = iso_forest.predict(X_test_if)
anomaly_scores = iso_forest.decision_function(X_test_if)  # the higher, the more normal
print("Isolation Forest predicted labels (first 20):", preds[:20])
print("Number of anomalies detected:", np.sum(preds == -1))
print("Example anomaly scores (lower means more anomalous):", anomaly_scores[:5])
```
In diesem Code instanziieren wir `IsolationForest` mit 100 Bäumen und setzen `contamination=0.15` (was bedeutet, dass wir etwa 15% Anomalien erwarten; das Modell wird seine Schwelle so setzen, dass ~15% der Punkte markiert werden). Wir passen es an `X_test_if` an, das eine Mischung aus normalen und Angriffs-Punkten enthält (Hinweis: Normalerweise würden Sie es auf Trainingsdaten anpassen und dann `predict` auf neuen Daten verwenden, aber hier zur Veranschaulichung passen wir es an und sagen auf demselben Satz Vorhersagen, um die Ergebnisse direkt zu beobachten).

Die Ausgabe zeigt die vorhergesagten Labels für die ersten 20 Punkte (wobei -1 Anomalie anzeigt). Wir drucken auch, wie viele Anomalien insgesamt erkannt wurden, und einige Beispiel-Anomaliewerte. Wir würden erwarten, dass ungefähr 18 von 120 Punkten mit -1 gekennzeichnet werden (da die Kontamination 15% betrug). Wenn unsere 20 Angriffsmuster tatsächlich die auffälligsten sind, sollten die meisten von ihnen in diesen -1-Vorhersagen erscheinen. Der Anomaliewert (die Entscheidungsfunktion des Isolation Forest) ist höher für normale Punkte und niedriger (negativer) für Anomalien – wir drucken einige Werte aus, um die Trennung zu sehen. In der Praxis könnte man die Daten nach Wert sortieren, um die auffälligsten Ausreißer zu sehen und sie zu untersuchen. Isolation Forest bietet somit eine effiziente Möglichkeit, große unbeschriftete Sicherheitsdaten zu durchsuchen und die unregelmäßigsten Instanzen für die menschliche Analyse oder weitere automatisierte Überprüfung herauszufiltern.

### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** ist eine nichtlineare Dimensionsreduktionsmethode, die speziell für die Visualisierung hochdimensionaler Daten in 2 oder 3 Dimensionen entwickelt wurde. Es wandelt Ähnlichkeiten zwischen Datenpunkten in gemeinsame Wahrscheinlichkeitsverteilungen um und versucht, die Struktur lokaler Nachbarschaften in der niederdimensionalen Projektion zu bewahren. Einfacher ausgedrückt platziert t-SNE Punkte in (sagen wir) 2D, sodass ähnliche Punkte (im ursprünglichen Raum) nahe beieinander und unähnliche Punkte mit hoher Wahrscheinlichkeit weit auseinander liegen.

Der Algorithmus hat zwei Hauptphasen:

1. **Berechnung paarweiser Affinitäten im hochdimensionalen Raum:** Für jedes Punktpaar berechnet t-SNE eine Wahrscheinlichkeit, dass man dieses Paar als Nachbarn auswählen würde (dies geschieht, indem eine Gaußsche Verteilung auf jeden Punkt zentriert und Abstände gemessen werden – der Perplexitätsparameter beeinflusst die effektive Anzahl der berücksichtigten Nachbarn).
2. **Berechnung paarweiser Affinitäten im niederdimensionalen (z.B. 2D) Raum:** Zunächst werden die Punkte zufällig in 2D platziert. t-SNE definiert eine ähnliche Wahrscheinlichkeit für Abstände in dieser Karte (unter Verwendung eines Student-t-Verteilungskernels, der schwerere Schwänze als Gaußsche Verteilungen hat, um entfernten Punkten mehr Freiheit zu geben).
3. **Gradientenabstieg:** t-SNE bewegt dann iterativ die Punkte in 2D, um die Kullback-Leibler (KL) Divergenz zwischen der hochdimensionalen Affinitätsverteilung und der niederdimensionalen zu minimieren. Dies bewirkt, dass die 2D-Anordnung die hochdimensionale Struktur so gut wie möglich widerspiegelt – Punkte, die im ursprünglichen Raum nahe beieinander lagen, ziehen sich an, und solche, die weit auseinander liegen, stoßen sich ab, bis ein Gleichgewicht gefunden ist.

Das Ergebnis ist oft ein visuell bedeutungsvolles Streudiagramm, in dem Cluster in den Daten offensichtlich werden.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* t-SNE wird häufig verwendet, um **hochdimensionale Sicherheitsdaten für die menschliche Analyse zu visualisieren**. Zum Beispiel könnten Analysten in einem Sicherheitsoperationszentrum einen Ereignisdatenbestand mit Dutzenden von Merkmalen (Portnummern, Frequenzen, Byte-Zahlen usw.) nehmen und t-SNE verwenden, um ein 2D-Diagramm zu erstellen. Angriffe könnten in diesem Diagramm ihre eigenen Cluster bilden oder sich von normalen Daten trennen, was sie leichter identifizierbar macht. Es wurde auf Malware-Datensätze angewendet, um Gruppierungen von Malware-Familien zu sehen, oder auf Daten zu Netzwerkangriffen, bei denen sich verschiedene Angriffsarten deutlich gruppieren, was weitere Untersuchungen leitet. Im Wesentlichen bietet t-SNE eine Möglichkeit, Strukturen in Cyberdaten zu sehen, die sonst unverständlich wären.

#### Annahmen und Einschränkungen

t-SNE ist großartig für die visuelle Entdeckung von Mustern. Es kann Cluster, Untercluster und Ausreißer aufdecken, die andere lineare Methoden (wie PCA) möglicherweise nicht erkennen. Es wurde in der Cybersicherheitsforschung verwendet, um komplexe Daten wie Malware-Verhaltensprofile oder Muster im Netzwerkverkehr zu visualisieren. Da es die lokale Struktur bewahrt, ist es gut darin, natürliche Gruppierungen zu zeigen.

Allerdings ist t-SNE rechnerisch aufwendiger (ungefähr $O(n^2)$), sodass es für sehr große Datensätze möglicherweise eine Stichprobe erfordert. Es hat auch Hyperparameter (Perplexität, Lernrate, Iterationen), die die Ausgabe beeinflussen können – z.B. könnten unterschiedliche Perplexitätswerte Cluster in unterschiedlichen Maßstäben offenbaren. t-SNE-Diagramme können manchmal falsch interpretiert werden – Abstände in der Karte sind global nicht direkt bedeutungsvoll (es konzentriert sich auf lokale Nachbarschaften, manchmal können Cluster künstlich gut getrennt erscheinen). Außerdem ist t-SNE hauptsächlich für die Visualisierung gedacht; es bietet keinen direkten Weg, neue Datenpunkte zu projizieren, ohne neu zu berechnen, und es ist nicht dafür gedacht, als Vorverarbeitung für prädiktive Modellierung verwendet zu werden (UMAP ist eine Alternative, die einige dieser Probleme mit schnellerer Geschwindigkeit angeht).

<details>
<summary>Beispiel -- Visualisierung von Netzwerkverbindungen
</summary>

Wir werden t-SNE verwenden, um einen Datensatz mit mehreren Merkmalen auf 2D zu reduzieren. Zur Veranschaulichung nehmen wir die früheren 4D-Daten (die 3 natürliche Cluster normalen Verkehrs hatten) und fügen einige Anomaliepunkte hinzu. Dann führen wir t-SNE aus und visualisieren (konzeptionell) die Ergebnisse.
```python
# 1 ─────────────────────────────────────────────────────────────────────
#    Create synthetic 4-D dataset
#      • Three clusters of “normal” traffic (duration, bytes)
#      • Two correlated features: packets & errors
#      • Five outlier points to simulate suspicious traffic
# ──────────────────────────────────────────────────────────────────────
import numpy as np
import matplotlib.pyplot as plt
from sklearn.manifold import TSNE
from sklearn.preprocessing import StandardScaler

rng = np.random.RandomState(42)

# Base (duration, bytes) clusters
normal1 = rng.normal(loc=[50, 500],  scale=[10, 100], size=(500, 2))
normal2 = rng.normal(loc=[60, 1500], scale=[8,  200], size=(500, 2))
normal3 = rng.normal(loc=[70, 3000], scale=[5,  300], size=(500, 2))

base_data = np.vstack([normal1, normal2, normal3])       # (1500, 2)

# Correlated features
packets = base_data[:, 1] / 50 + rng.normal(scale=0.5, size=len(base_data))
errors  = base_data[:, 0] / 10 + rng.normal(scale=0.5, size=len(base_data))

data_4d = np.column_stack([base_data, packets, errors])  # (1500, 4)

# Outlier / attack points
outliers_4d = np.column_stack([
rng.normal(250, 1, size=5),     # extreme duration
rng.normal(1000, 1, size=5),    # moderate bytes
rng.normal(5, 1, size=5),       # very low packets
rng.normal(25, 1, size=5)       # high errors
])

data_viz = np.vstack([data_4d, outliers_4d])             # (1505, 4)

# 2 ─────────────────────────────────────────────────────────────────────
#    Standardize features (recommended for t-SNE)
# ──────────────────────────────────────────────────────────────────────
scaler = StandardScaler()
data_scaled = scaler.fit_transform(data_viz)

# 3 ─────────────────────────────────────────────────────────────────────
#    Run t-SNE to project 4-D → 2-D
# ──────────────────────────────────────────────────────────────────────
tsne = TSNE(
n_components=2,
perplexity=30,
learning_rate='auto',
init='pca',
random_state=0
)
data_2d = tsne.fit_transform(data_scaled)
print("t-SNE output shape:", data_2d.shape)  # (1505, 2)

# 4 ─────────────────────────────────────────────────────────────────────
#    Visualize: normal traffic vs. outliers
# ──────────────────────────────────────────────────────────────────────
plt.figure(figsize=(8, 6))
plt.scatter(
data_2d[:-5, 0], data_2d[:-5, 1],
label="Normal traffic",
alpha=0.6,
s=10
)
plt.scatter(
data_2d[-5:, 0], data_2d[-5:, 1],
label="Outliers / attacks",
alpha=0.9,
s=40,
marker="X",
edgecolor='k'
)

plt.title("t-SNE Projection of Synthetic Network Traffic")
plt.xlabel("t-SNE component 1")
plt.ylabel("t-SNE component 2")
plt.legend()
plt.tight_layout()
plt.show()
```
Hier haben wir unser vorheriges 4D-Normaldatenset mit einer Handvoll extremer Ausreißer kombiniert (die Ausreißer haben ein Merkmal (“Dauer”), das sehr hoch eingestellt ist, um ein ungewöhnliches Muster zu simulieren). Wir führen t-SNE mit einer typischen Perplexität von 30 aus. Die Ausgabedaten data_2d haben die Form (1505, 2). Wir werden in diesem Text tatsächlich nicht plotten, aber wenn wir es tun würden, würden wir erwarten, vielleicht drei enge Cluster zu sehen, die den 3 normalen Clustern entsprechen, und die 5 Ausreißer erscheinen als isolierte Punkte weit entfernt von diesen Clustern. In einem interaktiven Workflow könnten wir die Punkte nach ihrem Label (normal oder welcher Cluster, vs Anomalie) einfärben, um diese Struktur zu überprüfen. Selbst ohne Labels könnte ein Analyst diese 5 Punkte im leeren Raum im 2D-Plot bemerken und sie markieren. Dies zeigt, wie t-SNE eine leistungsstarke Hilfe zur visuellen Anomalieerkennung und Clusterinspektion in Cybersecurity-Daten sein kann, die die oben genannten automatisierten Algorithmen ergänzt.

</details>


{{#include ../banners/hacktricks-training.md}}
