# Unüberwachte Lernalgorithmen

{{#include ../banners/hacktricks-training.md}}

## Unüberwachtes Lernen

Unüberwachtes Lernen ist eine Art des maschinellen Lernens, bei der das Modell anhand von Daten ohne gekennzeichnete Antworten trainiert wird. Ziel ist es, Muster, Strukturen oder Beziehungen innerhalb der Daten zu finden. Im Gegensatz zum überwachten Lernen, bei dem das Modell aus gekennzeichneten Beispielen lernt, arbeiten Algorithmen des unüberwachten Lernens mit nicht gekennzeichneten Daten.
Unüberwachtes Lernen wird häufig für Aufgaben wie Clustering, Dimensionsreduktion und Anomalieerkennung eingesetzt. Es kann dabei helfen, verborgene Muster in Daten zu entdecken, ähnliche Elemente zu gruppieren oder die Komplexität der Daten zu reduzieren und dabei ihre wesentlichen Merkmale zu bewahren.


### K-Means-Clustering

K-Means ist ein zentroidbasiertes Clustering-Verfahren, das Daten in K Cluster aufteilt, indem jeder Punkt dem nächstgelegenen Clustermittelwert zugewiesen wird. Der Algorithmus funktioniert wie folgt:
1. **Initialisierung**: Wähle K anfängliche Clusterzentren (Zentroide), häufig zufällig oder mithilfe intelligenterer Verfahren wie k-means++
2. **Zuweisung**: Weise jeden Datenpunkt anhand eines Distanzmaßes (z. B. der euklidischen Distanz) dem nächstgelegenen Zentroiden zu.
3. **Aktualisierung**: Berechne die Zentroide neu, indem der Mittelwert aller Datenpunkte gebildet wird, die jedem Cluster zugewiesen wurden.
4. **Wiederholung**: Wiederhole die Schritte 2–3, bis sich die Clusterzuweisungen stabilisieren (die Zentroide sich nicht mehr wesentlich bewegen).

> [!TIP]
> *Anwendungsfälle in der Cybersecurity:* K-Means wird zur Intrusion Detection eingesetzt, indem Netzwerkereignisse geclustert werden. Beispielsweise wendeten Forscher K-Means auf den KDD-Cup-99-Intrusion-Datensatz an und stellten fest, dass der Datenverkehr damit effektiv in Cluster für normalen Datenverkehr und Angriffe aufgeteilt werden konnte. In der Praxis können Security-Analysten Logeinträge oder Daten zum Benutzerverhalten clustern, um Gruppen ähnlicher Aktivitäten zu finden. Punkte, die zu keinem gut ausgeprägten Cluster gehören, können auf Anomalien hindeuten (z. B. eine neue Malware-Variante, die einen eigenen kleinen Cluster bildet). K-Means kann außerdem bei der Klassifizierung von Malware-Familien helfen, indem Binärdateien anhand von Verhaltensprofilen oder Feature-Vektoren gruppiert werden.

#### Auswahl von K
Die Anzahl der Cluster (K) ist ein Hyperparameter, der vor der Ausführung des Algorithmus festgelegt werden muss. Verfahren wie die Elbow-Methode oder der Silhouettenkoeffizient können dabei helfen, einen geeigneten Wert für K zu bestimmen, indem sie die Clustering-Leistung bewerten:

- **Elbow-Methode**: Trage die Summe der quadrierten Distanzen jedes Punkts zu seinem zugewiesenen Clusterzentroiden als Funktion von K auf. Suche nach einem „Ellbogen“-Punkt, an dem sich die Abnahmerate stark verändert, was auf eine geeignete Anzahl von Clustern hinweist.
- **Silhouettenkoeffizient**: Berechne den Silhouettenkoeffizienten für verschiedene K-Werte. Ein höherer Silhouettenkoeffizient weist auf besser definierte Cluster hin.

#### Annahmen und Einschränkungen

K-Means setzt voraus, dass **Cluster kugelförmig und gleich groß** sind, was nicht für alle Datensätze zutreffen muss. Das Verfahren reagiert empfindlich auf die anfängliche Positionierung der Zentroide und kann in lokalen Minima konvergieren. Außerdem eignet sich K-Means nicht für Datensätze mit unterschiedlicher Dichte oder nicht kugelförmigen Formen sowie für Features mit unterschiedlichen Maßstäben. Vorverarbeitungsschritte wie Normalisierung oder Standardisierung können erforderlich sein, damit alle Features gleichermaßen zu den Distanzberechnungen beitragen.

<details>
<summary>Beispiel -- Clustering von Netzwerkereignissen
</summary>
Im Folgenden simulieren wir Netzwerkverkehrsdaten und verwenden K-Means, um sie zu clustern. Angenommen, wir haben Ereignisse mit Features wie Verbindungsdauer und Byte-Anzahl. Wir erstellen 3 Cluster für „normalen“ Datenverkehr und 1 kleines Cluster, das ein Angriffsmuster darstellt. Anschließend führen wir K-Means aus, um zu prüfen, ob die Cluster voneinander getrennt werden.
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
In diesem Beispiel sollte K-Means 4 Cluster finden. Das kleine Attack-Cluster (mit einer ungewöhnlich hohen Dauer von etwa 200) wird sich aufgrund seiner Entfernung zu den normalen Clustern idealerweise zu einem eigenen Cluster formen. Wir geben die Clustergrößen und -zentren aus, um die Ergebnisse zu interpretieren. In einem realen Szenario könnte man das Cluster mit wenigen Punkten als potenzielle Anomalien kennzeichnen oder seine Mitglieder auf bösartige Aktivitäten untersuchen.
</details>

### Hierarchisches Clustering

Hierarchisches Clustering erstellt mithilfe eines Bottom-up- (agglomerativen) oder Top-down- (divisiven) Ansatzes eine Hierarchie von Clustern:

1. **Agglomerativ (Bottom-up)**: Mit jedem Datenpunkt als eigenständigem Cluster beginnen und die nächstgelegenen Cluster iterativ zusammenführen, bis ein einzelnes Cluster übrig bleibt oder ein Abbruchkriterium erreicht ist.
2. **Divisiv (Top-down)**: Mit allen Datenpunkten in einem einzelnen Cluster beginnen und die Cluster iterativ aufteilen, bis jeder Datenpunkt sein eigenes Cluster bildet oder ein Abbruchkriterium erreicht ist.

Agglomeratives Clustering erfordert eine Definition der Inter-Cluster-Distanz und ein Linkage-Kriterium, um zu bestimmen, welche Cluster zusammengeführt werden. Zu den gängigen Linkage-Methoden gehören Single Linkage (Distanz der nächstgelegenen Punkte zwischen zwei Clustern), Complete Linkage (Distanz der am weitesten voneinander entfernten Punkte), Average Linkage usw.; als Distanzmetrik wird häufig die euklidische Distanz verwendet. Die Wahl der Linkage-Methode beeinflusst die Form der erzeugten Cluster. Die Anzahl der Cluster K muss nicht im Voraus festgelegt werden; man kann das Dendrogramm auf einer ausgewählten Ebene „schneiden“, um die gewünschte Anzahl von Clustern zu erhalten.

Hierarchisches Clustering erzeugt ein Dendrogramm, eine baumartige Struktur, die die Beziehungen zwischen Clustern auf verschiedenen Granularitätsebenen darstellt. Das Dendrogramm kann auf einer gewünschten Ebene geschnitten werden, um eine bestimmte Anzahl von Clustern zu erhalten.

> [!TIP]
> *Anwendungsfälle in der Cybersecurity:* Hierarchisches Clustering kann Ereignisse oder Entitäten in einem Baum organisieren, um Beziehungen zu erkennen. In der Malware-Analyse könnte agglomeratives Clustering beispielsweise Samples anhand ihrer Verhaltensähnlichkeit gruppieren und dadurch eine Hierarchie von Malware-Familien und -Varianten sichtbar machen. In der Netzwerksicherheit könnte man IP-Datenverkehrsströme clustern und das Dendrogramm verwenden, um Untergruppen des Datenverkehrs zu erkennen (z. B. zunächst nach Protokoll und anschließend nach Verhalten). Da K nicht im Voraus ausgewählt werden muss, ist diese Methode nützlich, wenn man neue Daten untersucht und die Anzahl der Angriffskategorien unbekannt ist.

#### Annahmen und Einschränkungen

Hierarchisches Clustering setzt keine bestimmte Clusterform voraus und kann verschachtelte Cluster erfassen. Es eignet sich zum Erkennen von Taxonomien oder Beziehungen zwischen Gruppen (z. B. zum Gruppieren von Malware nach Untergruppen einer Familie). Es ist deterministisch, sodass keine Probleme durch zufällige Initialisierungen entstehen. Ein wesentlicher Vorteil ist das Dendrogramm, das Einblicke in die Clusterstruktur der Daten auf allen Maßstabsebenen bietet – Security-Analysten können einen geeigneten Schwellenwert festlegen, um aussagekräftige Cluster zu identifizieren. Allerdings ist das Verfahren rechenintensiv (bei naiven Implementierungen typischerweise $O(n^2)$ oder schlechter) und für sehr große Datensätze nicht praktikabel. Außerdem handelt es sich um ein gieriges Verfahren: Sobald eine Zusammenführung oder Aufteilung erfolgt ist, kann sie nicht rückgängig gemacht werden. Dies kann zu suboptimalen Clustern führen, wenn früh ein Fehler passiert. Ausreißer können ebenfalls einige Linkage-Strategien beeinflussen (Single Linkage kann den „Chaining“-Effekt verursachen, bei dem Cluster über Ausreißer miteinander verbunden werden).

<details>
<summary>Beispiel -- Agglomeratives Clustering von Ereignissen
</summary>

Wir verwenden erneut die synthetischen Daten aus dem K-Means-Beispiel (3 normale Cluster + 1 Attack-Cluster) und wenden agglomeratives Clustering an. Anschließend veranschaulichen wir, wie man ein Dendrogramm und Cluster-Labels erstellt.
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

### DBSCAN (Density-Based Spatial Clustering of Applications with Noise)

DBSCAN ist ein dichtebasierter Clustering-Algorithmus, der eng beieinander liegende Punkte gruppiert und Punkte in Bereichen mit geringer Dichte als Ausreißer markiert. Er eignet sich besonders für Datensätze mit unterschiedlichen Dichten und nicht-sphärischen Formen.

DBSCAN arbeitet mit zwei Parametern:
- **Epsilon (ε)**: Der maximale Abstand zwischen zwei Punkten, damit sie als Teil desselben Clusters betrachtet werden.
- **MinPts**: Die Mindestanzahl an Punkten, die erforderlich ist, um eine dichte Region zu bilden (Kernpunkt).

DBSCAN identifiziert Kernpunkte, Randpunkte und Rauschpunkte:
- **Kernpunkt**: Ein Punkt mit mindestens MinPts Nachbarn innerhalb eines Abstands von ε.
- **Randpunkt**: Ein Punkt, der sich innerhalb eines Abstands von ε zu einem Kernpunkt befindet, aber weniger als MinPts Nachbarn hat.
- **Rauschpunkt**: Ein Punkt, der weder ein Kernpunkt noch ein Randpunkt ist.

Das Clustering beginnt, indem ein nicht besuchter Kernpunkt ausgewählt und als neuer Cluster markiert wird. Anschließend werden rekursiv alle von ihm aus dichte-erreichbaren Punkte hinzugefügt (Kernpunkte und deren Nachbarn usw.). Randpunkte werden dem Cluster eines nahe gelegenen Kernpunkts hinzugefügt. Nachdem alle erreichbaren Punkte erweitert wurden, wechselt DBSCAN zu einem anderen nicht besuchten Kernpunkt, um einen neuen Cluster zu starten. Punkte, die von keinem Kernpunkt erreicht werden, bleiben als Rauschen markiert.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* DBSCAN eignet sich zur Anomalieerkennung in Netzwerkverkehr. Beispielsweise kann normale Benutzeraktivität einen oder mehrere dichte Cluster im Merkmalsraum bilden, während neuartige Angriffsverhalten als verstreute Punkte erscheinen, die DBSCAN als Rauschen (Ausreißer) markiert. Der Algorithmus wurde zum Clustering von Netzwerkflussdatensätzen eingesetzt, wobei er Port-Scans oder Denial-of-Service-Datenverkehr als dünn besetzte Punktbereiche erkennen kann. Eine weitere Anwendung ist die Gruppierung von Malware-Varianten: Wenn sich die meisten Samples nach Familien gruppieren lassen, einige jedoch in keinen Cluster passen, könnte es sich bei diesen wenigen um Zero-Day-Malware handeln. Die Fähigkeit, Rauschen zu kennzeichnen, ermöglicht es Security-Teams, sich auf die Untersuchung dieser Ausreißer zu konzentrieren.

#### Annahmen und Einschränkungen

**Annahmen & Stärken:**: DBSCAN setzt keine sphärischen Cluster voraus – es kann Cluster mit beliebigen Formen finden (einschließlich kettenförmiger oder benachbarter Cluster). Die Anzahl der Cluster wird automatisch anhand der Datendichte bestimmt, und Ausreißer können effektiv als Rauschen identifiziert werden. Dadurch eignet sich der Algorithmus gut für reale Daten mit unregelmäßigen Formen und Rauschen. Er ist robust gegenüber Ausreißern (im Gegensatz zu K-Means, das sie zwangsweise Clustern zuordnet). DBSCAN funktioniert gut, wenn Cluster ungefähr eine einheitliche Dichte aufweisen.

**Einschränkungen**: Die Leistung von DBSCAN hängt von der Wahl geeigneter Werte für ε und MinPts ab. Bei Daten mit unterschiedlichen Dichten kann es zu Problemen kommen – ein einzelner ε-Wert kann nicht gleichzeitig dichte und dünn besetzte Cluster berücksichtigen. Ist ε zu klein, werden die meisten Punkte als Rauschen markiert; ist er zu groß, können Cluster fälschlicherweise zusammengeführt werden. Außerdem kann DBSCAN bei sehr großen Datensätzen ineffizient sein (naiv $O(n^2)$, wobei räumliche Indizierung helfen kann). In hochdimensionalen Merkmalsräumen kann das Konzept des „Abstands innerhalb von ε“ an Bedeutung verlieren (Fluch der Dimensionalität). DBSCAN benötigt dann möglicherweise eine sorgfältige Parametrierung oder findet möglicherweise keine intuitiven Cluster. Trotz dieser Einschränkungen behandeln Erweiterungen wie HDBSCAN einige der Probleme (z. B. unterschiedliche Dichten).

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
In diesem Snippet haben wir `eps` und `min_samples` an die Skalierung unserer Daten angepasst (15.0 in Feature-Einheiten und mindestens 5 Punkte zur Bildung eines Clusters). DBSCAN sollte 2 Cluster (die Cluster des normalen Traffics) finden und die 5 eingefügten Ausreißer als Rauschen markieren. Wir geben die Anzahl der Cluster und der Rauschpunkte aus, um dies zu überprüfen. In einer realen Umgebung könnte man ε (mithilfe einer k-distance graph-Heuristik zur Auswahl von ε) und MinPts iterativ variieren, um stabile Clustering-Ergebnisse zu finden. Die Möglichkeit, Rauschen explizit zu markieren, hilft dabei, potenzielle Angriffs-Daten zur weiteren Analyse abzugrenzen.

</details>

### Principal Component Analysis (PCA)

PCA ist eine Technik zur **Dimensionsreduktion**, die eine neue Menge orthogonaler Achsen (Hauptkomponenten) findet, welche die maximale Varianz in den Daten erfassen. Vereinfacht gesagt dreht und projiziert PCA die Daten auf ein neues Koordinatensystem, sodass die erste Hauptkomponente (PC1) die größtmögliche Varianz erklärt, die zweite Hauptkomponente (PC2) die größtmögliche Varianz orthogonal zu PC1 erklärt und so weiter. Mathematisch berechnet PCA die Eigenvektoren der Kovarianzmatrix der Daten – diese Eigenvektoren sind die Richtungen der Hauptkomponenten, und die zugehörigen Eigenwerte geben die durch jede Komponente erklärte Varianz an. PCA wird häufig zur Feature-Extraktion, Visualisierung und Rauschreduzierung verwendet.

Beachte, dass dies nützlich ist, wenn die Dimensionen des Datensatzes **signifikante lineare Abhängigkeiten oder Korrelationen** enthalten.

PCA funktioniert, indem die Hauptkomponenten der Daten identifiziert werden, also die Richtungen mit maximaler Varianz. Die Schritte bei PCA sind:
1. **Standardisierung**: Zentriere die Daten, indem du den Mittelwert subtrahierst, und skaliere sie auf eine Varianz von eins.
2. **Kovarianzmatrix**: Berechne die Kovarianzmatrix der standardisierten Daten, um die Beziehungen zwischen den Features zu verstehen.
3. **Eigenwertzerlegung**: Führe eine Eigenwertzerlegung der Kovarianzmatrix durch, um die Eigenwerte und Eigenvektoren zu erhalten.
4. **Hauptkomponenten auswählen**: Sortiere die Eigenwerte absteigend und wähle die obersten K Eigenvektoren aus, die den größten Eigenwerten entsprechen. Diese Eigenvektoren bilden den neuen Feature-Raum.
5. **Daten transformieren**: Projiziere die ursprünglichen Daten mithilfe der ausgewählten Hauptkomponenten auf den neuen Feature-Raum.
PCA wird häufig zur Datenvisualisierung, Rauschreduzierung und als Vorverarbeitungsschritt für andere Machine-Learning-Algorithmen verwendet. Sie hilft dabei, die Dimensionalität der Daten zu reduzieren und gleichzeitig ihre wesentliche Struktur zu erhalten.

#### Eigenwerte und Eigenvektoren

Ein Eigenwert ist ein Skalar, der angibt, wie viel Varianz durch den zugehörigen Eigenvektor erfasst wird. Ein Eigenvektor stellt eine Richtung im Feature-Raum dar, entlang derer die Daten am stärksten variieren.

Stell dir vor, A ist eine quadratische Matrix und v ein Vektor ungleich null, sodass gilt: `A * v = λ * v`
wobei:
- A eine quadratische Matrix ist, etwa [ [1, 2], [2, 1]] (z. B. eine Kovarianzmatrix)
- v ein Eigenvektor ist (z. B. [1, 1])

Dann gilt `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`. Dies ist der mit dem Eigenwert λ multiplizierte Eigenvektor v, wodurch der Eigenwert λ = 3 ist.

#### Eigenwerte und Eigenvektoren in PCA

Erklären wir dies anhand eines Beispiels. Stell dir vor, du hast einen Datensatz mit vielen Graustufenbildern von Gesichtern mit einer Größe von 100x100 Pixeln. Jedes Pixel kann als ein Feature betrachtet werden, sodass du 10.000 Features pro Bild hast (oder einen Vektor mit 10000 Komponenten pro Bild). Wenn du die Dimensionalität dieses Datensatzes mithilfe von PCA reduzieren möchtest, würdest du folgende Schritte durchführen:

1. **Standardisierung**: Zentriere die Daten, indem du den Mittelwert jedes Features (Pixels) vom Datensatz subtrahierst.
2. **Kovarianzmatrix**: Berechne die Kovarianzmatrix der standardisierten Daten. Sie erfasst, wie sich Features (Pixel) gemeinsam verändern.
- Beachte, dass die Kovarianz zwischen zwei Variablen (in diesem Fall Pixeln) angibt, wie stark sie sich gemeinsam verändern. Die Idee besteht also darin herauszufinden, welche Pixel dazu neigen, sich in einer linearen Beziehung gemeinsam zu erhöhen oder zu verringern.
- Wenn beispielsweise Pixel 1 und Pixel 2 dazu neigen, sich gemeinsam zu erhöhen, ist die Kovarianz zwischen ihnen positiv.
- Die Kovarianzmatrix ist eine 10.000x10.000-Matrix, wobei jeder Eintrag die Kovarianz zwischen zwei Pixeln darstellt.
3. **Löse die Eigenwertgleichung**: Die zu lösende Eigenwertgleichung lautet `C * v = λ * v`, wobei C die Kovarianzmatrix, v der Eigenvektor und λ der Eigenwert ist. Sie kann mithilfe von Methoden wie den folgenden gelöst werden:
- **Eigenwertzerlegung**: Führe eine Eigenwertzerlegung der Kovarianzmatrix durch, um die Eigenwerte und Eigenvektoren zu erhalten.
- **Singular Value Decomposition (SVD)**: Alternativ kannst du SVD verwenden, um die Datenmatrix in Singulärwerte und Vektoren zu zerlegen, wodurch ebenfalls die Hauptkomponenten bestimmt werden können.
4. **Hauptkomponenten auswählen**: Sortiere die Eigenwerte absteigend und wähle die obersten K Eigenvektoren aus, die den größten Eigenwerten entsprechen. Diese Eigenvektoren stellen die Richtungen maximaler Varianz in den Daten dar.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Eine häufige Verwendung von PCA in der Sicherheit ist die Feature-Reduktion zur Anomalieerkennung. Beispielsweise kann ein Intrusion Detection System mit mehr als 40 Netzwerkmetriken (etwa NSL-KDD-Features) PCA verwenden, um die Daten auf eine Handvoll Komponenten zu reduzieren und sie für die Visualisierung zusammenzufassen oder in Clustering-Algorithmen einzuspeisen. Analysten könnten den Netzwerk-Traffic im Raum der ersten beiden Hauptkomponenten darstellen, um zu sehen, ob sich Angriffe vom normalen Traffic trennen. PCA kann außerdem dabei helfen, redundante Features zu entfernen (etwa gesendete und empfangene Bytes, wenn diese korreliert sind), damit Detection-Algorithmen robuster und schneller werden.

#### Annahmen und Einschränkungen

PCA geht davon aus, dass **die Hauptachsen der Varianz aussagekräftig sind** – es handelt sich um eine lineare Methode, die daher lineare Korrelationen in den Daten erfasst. Sie ist unüberwacht, da sie nur die Feature-Kovarianz verwendet. Zu den Vorteilen von PCA gehören die Rauschreduzierung (Komponenten mit geringer Varianz entsprechen häufig Rauschen) und die Dekorrelation von Features. PCA ist für mäßig hohe Dimensionen recheneffizient und oft ein nützlicher Vorverarbeitungsschritt für andere Algorithmen (um den Fluch der Dimensionalität abzuschwächen). Eine Einschränkung besteht darin, dass PCA auf lineare Beziehungen beschränkt ist – komplexe nichtlineare Strukturen werden nicht erfasst (während Autoencoder oder t-SNE dies möglicherweise können). Außerdem können PCA-Komponenten im Hinblick auf die ursprünglichen Features schwer zu interpretieren sein (sie sind Kombinationen der ursprünglichen Features). In der Cybersicherheit ist Vorsicht geboten: Ein Angriff, der nur eine subtile Änderung in einem Feature mit geringer Varianz verursacht, taucht möglicherweise nicht in den wichtigsten PCs auf (da PCA die Varianz priorisiert und nicht unbedingt die „Interessantheit“).

<details>
<summary>Beispiel -- Reduzierung der Dimensionen von Netzwerkdaten
</summary>

Angenommen, wir haben Netzwerkverbindungs-Logs mit mehreren Features (z. B. Dauer, Bytes und Zählwerte). Wir werden einen synthetischen vierdimensionalen Datensatz (mit einer gewissen Korrelation zwischen den Features) erzeugen und PCA verwenden, um ihn für die Visualisierung oder weitere Analyse auf 2 Dimensionen zu reduzieren.
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
Hier haben wir die zuvor erstellten Cluster des normalen Datenverkehrs genommen und jeden Datenpunkt um zwei zusätzliche Features (Pakete und Fehler) erweitert, die mit Bytes und Dauer korrelieren. Anschließend wird PCA verwendet, um die 4 Features in 2 Hauptkomponenten zu komprimieren. Wir geben das Verhältnis der erklärten Varianz aus, das beispielsweise zeigen könnte, dass >95 % der Varianz durch 2 Komponenten erfasst werden (also nur ein geringer Informationsverlust entsteht). Die Ausgabe zeigt außerdem, dass sich die Datenform von (1500, 4) auf (1500, 2) reduziert. Die ersten Punkte im PCA-Raum werden als Beispiel ausgegeben. In der Praxis könnte man `data_2d` plotten, um visuell zu prüfen, ob die Cluster unterscheidbar sind. Falls eine Anomalie vorhanden wäre, könnte sie als Punkt erscheinen, der im PCA-Raum vom Hauptcluster entfernt liegt. PCA hilft somit dabei, komplexe Daten in eine überschaubare Form zu bringen, die von Menschen interpretiert oder als Eingabe für andere Algorithmen verwendet werden kann.

</details>


### Gaussian Mixture Models (GMM)

Ein Gaussian Mixture Model geht davon aus, dass Daten aus einer Mischung aus **mehreren Gaußschen (normalverteilten) Verteilungen mit unbekannten Parametern** erzeugt werden. Im Wesentlichen handelt es sich um ein probabilistisches Clustering-Modell: Es versucht, jeden Punkt anhand von Wahrscheinlichkeiten einer von K Gauß-Komponenten zuzuordnen. Jede Gauß-Komponente k verfügt über einen Mittelwertvektor (μ_k), eine Kovarianzmatrix (Σ_k) und ein Mischgewicht (π_k), das angibt, wie häufig dieses Cluster vorkommt. Im Gegensatz zu K-Means, das „harte“ Zuordnungen vornimmt, weist GMM jedem Punkt eine Wahrscheinlichkeit für die Zugehörigkeit zu jedem Cluster zu.

Das Fitting eines GMM erfolgt typischerweise mit dem Expectation-Maximization-(EM-)Algorithmus:

- **Initialisierung**: Mit anfänglichen Schätzungen für Mittelwerte, Kovarianzen und Mischkoeffizienten beginnen (oder die Ergebnisse von K-Means als Ausgangspunkt verwenden).

- **E-Schritt (Expectation)**: Mit den aktuellen Parametern die Verantwortung jedes Clusters für jeden Punkt berechnen: im Wesentlichen `r_nk = P(z_k | x_n)`, wobei z_k die latente Variable ist, die die Clusterzugehörigkeit für den Punkt x_n angibt. Dies erfolgt mithilfe des Satzes von Bayes. Dabei wird anhand der aktuellen Parameter die Posterior-Wahrscheinlichkeit berechnet, dass jeder Punkt zu jedem Cluster gehört. Die Verantwortlichkeiten werden wie folgt berechnet:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
wobei:
- \( \pi_k \) der Mischkoeffizient für Cluster k (die a-priori-Wahrscheinlichkeit von Cluster k) ist,
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) die Gaußsche Wahrscheinlichkeitsdichtefunktion für den Punkt \( x_n \) bei gegebenem Mittelwert \( \mu_k \) und gegebener Kovarianz \( \Sigma_k \) ist.

- **M-Schritt (Maximization)**: Die Parameter anhand der im E-Schritt berechneten Verantwortlichkeiten aktualisieren:
- Jeden Mittelwert μ_k als gewichteten Durchschnitt der Punkte aktualisieren, wobei die Verantwortlichkeiten als Gewichte dienen.
- Jede Kovarianz Σ_k als gewichtete Kovarianz der Punkte aktualisieren, die Cluster k zugeordnet sind.
- Die Mischkoeffizienten π_k als durchschnittliche Verantwortlichkeit für Cluster k aktualisieren.

- Die E- und M-Schritte **wiederholen**, bis Konvergenz erreicht ist (die Parameter stabil bleiben oder die Verbesserung der Likelihood unter einem Schwellenwert liegt).

Das Ergebnis ist eine Gruppe von Gauß-Verteilungen, die gemeinsam die gesamte Datenverteilung modellieren. Wir können das gefittete GMM zum Clustering verwenden, indem wir jeden Punkt der Gauß-Verteilung mit der höchsten Wahrscheinlichkeit zuweisen, oder die Wahrscheinlichkeiten zur Darstellung der Unsicherheit beibehalten. Außerdem kann man die Likelihood neuer Punkte bewerten, um festzustellen, ob sie zum Modell passen (nützlich für die Anomalieerkennung).

> [!TIP]
> *Anwendungsfälle in der Cybersecurity:* GMM kann zur Anomalieerkennung verwendet werden, indem die Verteilung normaler Daten modelliert wird: Jeder Punkt mit einer sehr niedrigen Wahrscheinlichkeit unter der erlernten Mischung wird als Anomalie markiert. Beispielsweise könnte man ein GMM anhand von Features legitimen Netzwerkverkehrs trainieren; eine Angriffverbindung, die keinem erlernten Cluster ähnelt, hätte eine geringe Likelihood. GMMs werden außerdem verwendet, um Aktivitäten zu clustern, bei denen Cluster unterschiedliche Formen haben können – etwa zur Gruppierung von Benutzern anhand von Verhaltensprofilen, bei denen die Features jedes Profils Gauß-ähnlich sein können, jedoch jeweils eine eigene Varianzstruktur besitzen. Ein weiteres Szenario ist die Phishing-Erkennung: Die Features legitimer E-Mails könnten ein Gauß-Cluster bilden, bekannte Phishing-E-Mails ein weiteres, und neue Phishing-Kampagnen könnten entweder als separate Gauß-Verteilung oder als Punkte mit geringer Likelihood relativ zur bestehenden Mischung erscheinen.

#### Annahmen und Einschränkungen

GMM ist eine Verallgemeinerung von K-Means, die Kovarianz berücksichtigt, sodass Cluster ellipsenförmig sein können (nicht nur kugelförmig). Bei voller Kovarianz kann es Cluster unterschiedlicher Größe und Form verarbeiten. Soft Clustering ist von Vorteil, wenn Clustergrenzen unscharf sind – beispielsweise in der Cybersecurity, wenn ein Ereignis Merkmale mehrerer Angriffstypen aufweisen kann; GMM kann diese Unsicherheit durch Wahrscheinlichkeiten abbilden. GMM bietet außerdem eine probabilistische Dichteschätzung der Daten, die zum Erkennen von Ausreißern nützlich ist (Punkte mit geringer Likelihood unter allen Mischungskomponenten).

Nachteilig ist, dass GMM die Anzahl der Komponenten K voraussetzt (wobei man Kriterien wie BIC/AIC zu ihrer Auswahl verwenden kann). EM kann manchmal langsam konvergieren oder in einem lokalen Optimum enden, weshalb die Initialisierung wichtig ist (häufig wird EM mehrmals ausgeführt). Wenn die Daten tatsächlich nicht einer Mischung aus Gauß-Verteilungen folgen, kann das Modell schlecht passen. Außerdem besteht das Risiko, dass eine Gauß-Verteilung so stark schrumpft, dass sie nur einen Ausreißer abdeckt (Regularisierung oder Mindestgrenzen für Kovarianzen können dies jedoch abmildern).


<details>
<summary>Beispiel --  Soft Clustering & Anomalie-Scores
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
In diesem Code trainieren wir ein GMM mit 3 Gauß-Verteilungen auf dem normalen Datenverkehr (unter der Annahme, dass wir 3 Profile des legitimen Datenverkehrs kennen). Die ausgegebenen Mittelwerte und Kovarianzen beschreiben diese Cluster (beispielsweise könnte ein Mittelwert ungefähr bei [50,500] liegen und damit das Zentrum eines Clusters darstellen usw.). Anschließend testen wir eine verdächtige Verbindung [duration=200, bytes=800]. `predict_proba` liefert die Wahrscheinlichkeit, dass dieser Punkt zu jedem der 3 Cluster gehört – wir würden erwarten, dass diese Wahrscheinlichkeiten sehr niedrig oder stark unausgewogen sind, da [200,800] weit von den normalen Clustern entfernt liegt. Der gesamte `score_samples`-Wert (Log-Likelihood) wird ausgegeben; ein sehr niedriger Wert deutet darauf hin, dass der Punkt schlecht zum Modell passt, und markiert ihn als Anomalie. In der Praxis könnte man einen Schwellenwert für die Log-Likelihood (oder für die maximale Wahrscheinlichkeit) festlegen, um zu entscheiden, ob ein Punkt ausreichend unwahrscheinlich ist, um als malicious betrachtet zu werden. GMM bietet somit eine fundierte Methode zur Anomalieerkennung und liefert außerdem weiche Cluster, die Unsicherheit berücksichtigen.
</details>

### Isolation Forest

**Isolation Forest** ist ein Ensemble-Algorithmus zur Anomalieerkennung, der auf der Idee beruht, Punkte zufällig zu isolieren. Das Prinzip lautet, dass Anomalien selten und unterschiedlich sind und sich daher leichter isolieren lassen als normale Punkte. Ein Isolation Forest erstellt viele binäre Isolation Trees (zufällige Entscheidungsbäume), die die Daten zufällig partitionieren. In jedem Knoten eines Baums wird ein zufälliges Feature ausgewählt und ein zufälliger Split-Wert zwischen dem Minimum und Maximum dieses Features für die Daten in diesem Knoten bestimmt. Dieser Split teilt die Daten in zwei Zweige auf. Der Baum wird so lange erweitert, bis jeder Punkt in einem eigenen Blatt isoliert ist oder die maximale Baumhöhe erreicht wurde.

Die Anomalieerkennung erfolgt durch die Beobachtung der Pfadlänge jedes Punkts in diesen zufälligen Bäumen – also der Anzahl der Splits, die erforderlich sind, um den Punkt zu isolieren. Intuitiv werden Anomalien (Ausreißer) schneller isoliert, da ein zufälliger Split einen Ausreißer (der in einer dünn besetzten Region liegt) mit höherer Wahrscheinlichkeit abtrennt als einen normalen Punkt in einem dichten Cluster. Der Isolation Forest berechnet einen Anomalie-Score aus der durchschnittlichen Pfadlänge über alle Bäume: kürzerer durchschnittlicher Pfad → anomalischer. Die Scores werden normalerweise auf [0,1] normalisiert, wobei 1 eine sehr wahrscheinliche Anomalie bedeutet.

> [!TIP]
> *Anwendungsfälle in der Cybersicherheit:* Isolation Forests wurden erfolgreich bei der Intrusion Detection und Fraud Detection eingesetzt. Trainieren Sie beispielsweise einen Isolation Forest mit Network-Traffic-Logs, die größtenteils normales Verhalten enthalten; der Forest erzeugt kurze Pfade für ungewöhnlichen Datenverkehr (etwa für eine IP, die einen unbekannten Port verwendet, oder für ein ungewöhnliches Muster der Paketgrößen) und markiert ihn zur Untersuchung. Da keine gelabelten Angriffe erforderlich sind, eignet sich das Verfahren zur Erkennung unbekannter Angriffstypen. Es kann auch auf Benutzer-Login-Daten eingesetzt werden, um Account Takeovers zu erkennen (die ungewöhnlichen Login-Zeitpunkte oder -Orte werden schnell isoliert). In einem Anwendungsfall könnte ein Isolation Forest ein Unternehmen schützen, indem er Systemmetriken überwacht und einen Alert erzeugt, wenn eine Kombination von Metriken (CPU, Netzwerk, Dateiänderungen) im Vergleich zu historischen Mustern sehr unterschiedlich aussieht (kurze Isolationspfade).

#### Annahmen und Einschränkungen

**Vorteile**: Isolation Forest erfordert keine Annahme über eine Verteilung, sondern zielt direkt auf die Isolation ab. Er ist bei hochdimensionalen Daten und großen Datensätzen effizient (lineare Komplexität $O(n\log n)$ beim Erstellen des Forests), da jeder Baum Punkte nur anhand einer Teilmenge der Features und Splits isoliert. Er verarbeitet numerische Features in der Regel gut und kann schneller sein als distanzbasierte Verfahren, deren Komplexität bei $O(n^2)$ liegen kann. Außerdem liefert er automatisch einen Anomalie-Score, sodass Sie einen Schwellenwert für Alerts festlegen können (oder einen Contamination-Parameter verwenden können, um anhand eines erwarteten Anomalieanteils automatisch einen Grenzwert zu bestimmen).

**Einschränkungen**: Aufgrund seiner zufälligen Natur können die Ergebnisse zwischen den Ausführungen leicht variieren (bei einer ausreichend großen Anzahl von Bäumen ist dieser Effekt jedoch gering). Wenn die Daten viele irrelevante Features enthalten oder sich Anomalien in keinem Feature deutlich unterscheiden, ist die Isolation möglicherweise nicht effektiv (zufällige Splits könnten normale Punkte zufällig isolieren – die Mittelung über viele Bäume wirkt dem jedoch entgegen). Außerdem geht Isolation Forest im Allgemeinen davon aus, dass Anomalien eine kleine Minderheit darstellen (was in Cybersicherheits-Szenarien normalerweise zutrifft).

<details>
<summary>Beispiel -- Erkennen von Ausreißern in Network-Logs
</summary>

Wir verwenden den zuvor erstellten Testdatensatz (der normale und einige Angriffspunkte enthält) und führen einen Isolation Forest aus, um zu sehen, ob er die Angriffe trennen kann. Wir nehmen an, dass ungefähr 15 % der Daten anomal sind (zu Demonstrationszwecken).
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
In diesem Code instanziieren wir `IsolationForest` mit 100 Bäumen und setzen `contamination=0.15` (das bedeutet, dass wir etwa 15 % Anomalien erwarten; das Modell legt seinen Score-Schwellenwert so fest, dass ungefähr 15 % der Punkte markiert werden). Wir trainieren es mit `X_test_if`, das eine Mischung aus normalen und Angriffspunkten enthält (Hinweis: Normalerweise würde man mit Trainingsdaten trainieren und anschließend `predict` auf neuen Daten verwenden; zur Veranschaulichung trainieren wir hier jedoch auf derselben Menge und führen darauf Vorhersagen durch, um die Ergebnisse direkt zu beobachten).

Die Ausgabe zeigt die vorhergesagten Labels für die ersten 20 Punkte (wobei -1 eine Anomalie kennzeichnet). Außerdem geben wir aus, wie viele Anomalien insgesamt erkannt wurden, sowie einige Beispiele für Anomalie-Scores. Wir würden erwarten, dass ungefähr 18 von 120 Punkten als -1 markiert werden (da `contamination` auf 15 % gesetzt wurde). Wenn unsere 20 Angriffssamples tatsächlich die am weitesten abweichenden Punkte sind, sollten die meisten davon in diesen -1-Vorhersagen erscheinen. Der Anomalie-Score (die `decision function` des Isolation Forest) ist für normale Punkte höher und für Anomalien niedriger (stärker negativ) – wir geben einige Werte aus, um die Trennung zu sehen. In der Praxis könnte man die Daten nach dem Score sortieren, um die auffälligsten Ausreißer zu sehen und zu untersuchen. Isolation Forest bietet somit eine effiziente Möglichkeit, große Mengen nicht gelabelter Security-Daten zu durchsuchen und die unregelmäßigsten Instanzen für die manuelle Analyse oder weitere automatisierte Prüfungen herauszufiltern.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** ist eine nichtlineare Technik zur Dimensionsreduktion, die speziell für die Visualisierung hochdimensionaler Daten in 2 oder 3 Dimensionen entwickelt wurde. Sie wandelt Ähnlichkeiten zwischen Datenpunkten in gemeinsame Wahrscheinlichkeitsverteilungen um und versucht, die Struktur lokaler Nachbarschaften in der Projektion mit niedrigerer Dimension zu bewahren. Einfacher ausgedrückt platziert t-SNE Punkte in (beispielsweise) 2D so, dass ähnliche Punkte im ursprünglichen Raum mit hoher Wahrscheinlichkeit nahe beieinander liegen und unähnliche Punkte weit voneinander entfernt liegen.

Der Algorithmus besteht aus drei Hauptphasen:

1. **Berechnung paarweiser Affinitäten im hochdimensionalen Raum:** Für jedes Punktepaar berechnet t-SNE die Wahrscheinlichkeit, dass man dieses Paar als Nachbarn auswählen würde (dazu wird eine Gaußverteilung auf jeden Punkt zentriert und es werden Distanzen gemessen – der Perplexity-Parameter beeinflusst die effektive Anzahl der berücksichtigten Nachbarn).
2. **Berechnung paarweiser Affinitäten im niedrigdimensionalen (z. B. 2D-)Raum:** Zu Beginn werden die Punkte zufällig in 2D platziert. t-SNE definiert eine ähnliche Wahrscheinlichkeit für Distanzen in dieser Karte (unter Verwendung eines Student-t-Verteilungs-Kernels, dessen Verteilungsschwänze schwerer sind als die einer Gaußverteilung, sodass entfernte Punkte mehr Bewegungsfreiheit haben).
3. **Gradient Descent:** Anschließend verschiebt t-SNE die Punkte in 2D iterativ, um die Kullback-Leibler-(KL-)Divergenz zwischen der Affinitätsverteilung im hochdimensionalen Raum und derjenigen im niedrigdimensionalen Raum zu minimieren. Dadurch soll die 2D-Anordnung die Struktur des hochdimensionalen Raums möglichst gut widerspiegeln – Punkte, die im ursprünglichen Raum nahe beieinander lagen, ziehen sich an, während weit voneinander entfernte Punkte sich abstoßen, bis ein Gleichgewicht erreicht ist.

Das Ergebnis ist häufig ein visuell aussagekräftiges Streudiagramm, in dem Cluster in den Daten sichtbar werden.

> [!TIP]
> *Anwendungsfälle in der Cybersecurity:* t-SNE wird häufig verwendet, um **hochdimensionale Security-Daten für die manuelle Analyse zu visualisieren**. Beispielsweise könnten Analysten in einem Security Operations Center einen Event-Datensatz mit Dutzenden von Features (Portnummern, Häufigkeiten, Byte-Anzahlen usw.) verwenden und t-SNE einsetzen, um ein 2D-Diagramm zu erzeugen. Angriffe könnten in diesem Diagramm eigene Cluster bilden oder sich von normalen Daten abgrenzen, wodurch sie leichter zu erkennen wären. t-SNE wurde auf Malware-Datensätze angewendet, um Gruppierungen von Malware-Familien sichtbar zu machen, oder auf Netzwerk-Intrusion-Daten, bei denen sich verschiedene Angriffstypen deutlich clustern, was weitere Untersuchungen unterstützt. Im Wesentlichen bietet t-SNE eine Möglichkeit, Strukturen in Cyber-Daten sichtbar zu machen, die andernfalls nur schwer zu erkennen wären.

#### Annahmen und Einschränkungen

t-SNE eignet sich hervorragend für die visuelle Entdeckung von Mustern. Es kann Cluster, Subcluster und Ausreißer aufdecken, die andere lineare Methoden (wie PCA) möglicherweise nicht erkennen. In der Cybersecurity-Forschung wurde es verwendet, um komplexe Daten wie Malware-Verhaltensprofile oder Netzwerkverkehrsmuster zu visualisieren. Da es die lokale Struktur bewahrt, eignet es sich gut zur Darstellung natürlicher Gruppierungen.

t-SNE ist jedoch rechenintensiver (ungefähr $O(n^2)$), weshalb bei sehr großen Datensätzen möglicherweise Sampling erforderlich ist. Außerdem verfügt es über Hyperparameter (Perplexity, Lernrate, Iterationen), die die Ausgabe beeinflussen können – unterschiedliche Perplexity-Werte können beispielsweise Cluster auf unterschiedlichen Skalen sichtbar machen. t-SNE-Diagramme können manchmal falsch interpretiert werden – Distanzen in der Karte sind global nicht direkt aussagekräftig (der Fokus liegt auf lokalen Nachbarschaften; dadurch können Cluster gelegentlich künstlich stark voneinander getrennt erscheinen). Außerdem dient t-SNE hauptsächlich der Visualisierung; es bietet keine unkomplizierte Möglichkeit, neue Datenpunkte ohne Neuberechnung zu projizieren, und ist nicht als Preprocessing für Predictive Modeling gedacht (UMAP ist eine Alternative, die einige dieser Probleme durch höhere Geschwindigkeit adressiert).

<details>
<summary>Beispiel -- Visualisierung von Netzwerkverbindungen
</summary>

Wir verwenden t-SNE, um einen Datensatz mit mehreren Features auf 2D zu reduzieren. Zur Veranschaulichung nehmen wir die zuvor verwendeten 4D-Daten (die 3 natürliche Cluster normalen Datenverkehrs enthielten) und fügen einige Anomaliepunkte hinzu. Anschließend führen wir t-SNE aus und visualisieren die Ergebnisse (konzeptionell).
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
Hier haben wir unseren vorherigen normalen 4D-Datensatz mit einer Handvoll extremer Ausreißer kombiniert (bei den Ausreißern wurde ein Feature („duration“) sehr hoch gesetzt usw., um ein ungewöhnliches Muster zu simulieren). Wir führen t-SNE mit einer typischen Perplexität von 30 aus. Die Ausgabedaten `data_2d` haben die Form (1505, 2). Wir werden in diesem Text tatsächlich keinen Plot erstellen, aber wenn wir dies täten, würden wir vermutlich drei enge Cluster erwarten, die den drei normalen Clustern entsprechen, wobei die fünf Ausreißer als isolierte Punkte weit von diesen Clustern entfernt erscheinen. In einem interaktiven Workflow könnten wir die Punkte anhand ihrer Bezeichnung einfärben (normal oder zu welchem Cluster gehörend bzw. Anomalie), um diese Struktur zu überprüfen. Auch ohne Bezeichnungen könnte ein Analyst bemerken, dass diese fünf Punkte im 2D-Plot in einem leeren Bereich liegen, und sie markieren. Dies zeigt, wie t-SNE eine leistungsfähige Unterstützung bei der visuellen Anomalieerkennung und Clusterinspektion in Cybersecurity-Daten sein kann und die oben beschriebenen automatisierten Algorithmen ergänzt.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** ist eine Erweiterung von DBSCAN, die es überflüssig macht, einen einzelnen globalen `eps`-Wert festzulegen, und durch den Aufbau einer Hierarchie dichteverbundener Komponenten und deren anschließende Verdichtung Cluster mit **unterschiedlicher Dichte** erkennen kann. Im Vergleich zu Vanilla-DBSCAN

* extrahiert es intuitivere Cluster, wenn einige Cluster dicht und andere dünn besiedelt sind,
* besitzt es nur einen echten Hyperparameter (`min_cluster_size`) und einen sinnvollen Standardwert,
* weist es jedem Punkt eine Wahrscheinlichkeit der Clusterzugehörigkeit und einen **Ausreißerscore** (`outlier_scores_`) zu, was für Threat-Hunting-Dashboards äußerst praktisch ist.<sup>[[1]](#references)</sup>

> [!TIP]
> *Einsatzmöglichkeiten in der Cybersecurity:* HDBSCAN ist in modernen Threat-Hunting-Pipelines sehr beliebt – häufig findet man es in notebookbasierten Hunting-Playbooks, die mit kommerziellen XDR-Suites ausgeliefert werden. Ein praktisches Vorgehen besteht darin, während der IR den HTTP-Beaconing-Datenverkehr zu clustern: User-Agent, Intervall und URI-Länge bilden häufig mehrere enge Gruppen legitimer Software-Updater, während C2-Beacons als winzige Cluster mit niedriger Dichte oder als reine Noise verbleiben.

<details>
<summary>Beispiel – Beaconing-C2-Kanäle finden</summary>
```python
import pandas as pd
from hdbscan import HDBSCAN
from sklearn.preprocessing import StandardScaler

# df has features extracted from proxy logs
features = [
"avg_interval",      # seconds between requests
"uri_length_mean",   # average URI length
"user_agent_entropy" # Shannon entropy of UA string
]
X = StandardScaler().fit_transform(df[features])

hdb = HDBSCAN(min_cluster_size=15,  # at least 15 similar beacons to be a group
metric="euclidean",
prediction_data=True)
labels = hdb.fit_predict(X)

df["cluster"] = labels
# Anything with label == -1 is noise → inspect as potential C2
suspects = df[df["cluster"] == -1]
print("Suspect beacon count:", len(suspects))
```
</details>

---

### Robustheit und Sicherheitsüberlegungen – Poisoning- und Adversarial-Angriffe (2023-2025)

Neuere Arbeiten haben gezeigt, dass **unüberwachte Lernverfahren *nicht* gegen aktive Angreifer immun sind**:

* **Data-poisoning gegen Anomalie-Detektoren.** Chen *et al.* (IEEE S&P 2024) zeigten, dass bereits 3 % gezielt erstellter Traffic die Entscheidungsgrenze von Isolation Forest und ECOD so verschieben können, dass echte Angriffe normal aussehen. Die Autoren veröffentlichten einen Open-Source-PoC (`udo-poison`), der automatisch Poisoning-Punkte synthetisiert.<sup>[[2]](#references)</sup>
* **Backdooring von Clustering-Modellen.** Die Technik *BadCME* (BlackHat EU 2023) platziert ein winziges Trigger-Muster; sobald dieses Trigger-Muster erscheint, platziert ein auf K-Means basierender Detektor das Ereignis unauffällig in einem „benignen“ Cluster.
* **Evasion von DBSCAN/HDBSCAN.** Ein akademisches Preprint der KU Leuven aus dem Jahr 2025 zeigte, dass ein Angreifer Beaconing-Muster erstellen kann, die absichtlich in Dichte-Lücken fallen und sich effektiv innerhalb von *Noise*-Labels verstecken.

Folgende Mitigations setzen sich zunehmend durch:

1. **Model-Sanitisierung / TRIM.** Vor jeder Retraining-Epoche werden die 1–2 % der Punkte mit dem höchsten Loss verworfen (Trimmed Maximum Likelihood), um Poisoning deutlich zu erschweren.
2. **Consensus-Ensembling.** Mehrere heterogene Detektoren (z. B. Isolation Forest + GMM + ECOD) werden kombiniert, und es wird ein Alert ausgelöst, wenn *irgendein* Modell einen Punkt markiert. Untersuchungen zeigen, dass dies die Kosten für den Angreifer um mehr als das Zehnfache erhöht.
3. **Distanzbasierte Abwehr für Clustering.** Cluster werden mit `k` verschiedenen zufälligen Seeds neu berechnet, und Punkte, die ständig zwischen Clustern wechseln, werden ignoriert.

---

### Moderne Open-Source-Tools (2024-2025)

* **PyOD 2.x** (veröffentlicht im Mai 2024) fügte *ECOD*, *COPOD* und GPU-beschleunigte *AutoFormer*-Detektoren hinzu. Es enthält nun einen `benchmark`-Subcommand, mit dem du mehr als 30 Algorithmen auf deinem Dataset mit **einer Codezeile** vergleichen kannst:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (Februar 2025) konzentriert sich auf Vision, enthält aber auch eine generische **PatchCore**-Implementierung – praktisch für die Erkennung von Phishing-Seiten auf Basis von Screenshots.
* **scikit-learn 1.5** (November 2024) stellt über den neuen `cluster.HDBSCAN`-Wrapper endlich `score_samples` für *HDBSCAN* bereit, sodass du bei Python 3.12 nicht das externe Contrib-Paket benötigst.

<details>
<summary>Schnelles PyOD-Beispiel – ECOD- und Isolation-Forest-Ensemble</summary>
```python
from pyod.models import ECOD, IForest
from pyod.utils.data import generate_data, evaluate_print
from pyod.utils.example import visualize

X_train, y_train, X_test, y_test = generate_data(
n_train=5000, n_test=1000, n_features=16,
contamination=0.02, random_state=42)

models = [ECOD(), IForest()]

# majority vote – flag if any model thinks it is anomalous
anomaly_scores = sum(m.fit(X_train).decision_function(X_test) for m in models) / len(models)

evaluate_print("Ensemble", y_test, anomaly_scores)
```
</details>

## Referenzen

- [1] [HDBSCAN – Hierarchisches dichtebasiertes Clustering](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* „Zur Anfälligkeit von unüberwachter Anomalieerkennung gegenüber Data Poisoning.“ *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
