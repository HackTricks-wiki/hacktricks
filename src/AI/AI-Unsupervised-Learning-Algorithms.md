# Algorithmes d'apprentissage non supervisé

{{#include ../banners/hacktricks-training.md}}

## Apprentissage non supervisé

L'apprentissage non supervisé est un type d'apprentissage automatique dans lequel le modèle est entraîné sur des données sans réponses étiquetées. L'objectif est de trouver des motifs, des structures ou des relations au sein des données. Contrairement à l'apprentissage supervisé, où le modèle apprend à partir d'exemples étiquetés, les algorithmes d'apprentissage non supervisé fonctionnent avec des données non étiquetées.
L'apprentissage non supervisé est souvent utilisé pour des tâches telles que le clustering, la réduction de dimensionnalité et la détection d'anomalies. Il peut aider à découvrir des motifs cachés dans les données, à regrouper des éléments similaires ou à réduire la complexité des données tout en préservant leurs caractéristiques essentielles.


### Clustering K-Means

K-Means est un algorithme de clustering basé sur les centroïdes qui partitionne les données en K clusters en assignant chaque point à la moyenne du cluster la plus proche. L'algorithme fonctionne comme suit :
1. **Initialisation** : Choisir K centres de clusters initiaux (centroïdes), souvent de manière aléatoire ou à l'aide de méthodes plus avancées comme k-means++
2. **Assignation** : Assigner chaque point de données au centroïde le plus proche en fonction d'une métrique de distance (par exemple, la distance euclidienne).
3. **Mise à jour** : Recalculer les centroïdes en prenant la moyenne de tous les points de données assignés à chaque cluster.
4. **Répétition** : Les étapes 2–3 sont répétées jusqu'à ce que les assignations des clusters se stabilisent (les centroïdes ne se déplacent plus de manière significative).

> [!TIP]
> *Cas d'utilisation en cybersécurité :* K-Means est utilisé pour la détection d'intrusions en regroupant les événements réseau. Par exemple, des chercheurs ont appliqué K-Means au dataset d'intrusion KDD Cup 99 et ont constaté qu'il partitionnait efficacement le trafic en clusters correspondant au trafic normal et aux attaques. En pratique, les analystes de sécurité peuvent regrouper les entrées de journaux ou les données de comportement des utilisateurs afin de trouver des groupes d'activités similaires ; les points qui n'appartiennent pas à un cluster bien défini peuvent indiquer des anomalies (par exemple, une nouvelle variante de malware formant son propre petit cluster). K-Means peut également aider à classifier les familles de malware en regroupant les binaires selon leurs profils de comportement ou leurs vecteurs de caractéristiques.

#### Sélection de K
Le nombre de clusters (K) est un hyperparamètre qui doit être défini avant l'exécution de l'algorithme. Des techniques comme la méthode du coude ou le score de silhouette peuvent aider à déterminer une valeur appropriée pour K en évaluant les performances du clustering :

- **Méthode du coude** : Tracer la somme des distances au carré entre chaque point et le centroïde du cluster qui lui est assigné en fonction de K. Rechercher un point en forme de « coude » où le taux de diminution change brusquement, ce qui indique un nombre approprié de clusters.
- **Score de silhouette** : Calculer le score de silhouette pour différentes valeurs de K. Un score de silhouette plus élevé indique des clusters mieux définis.

#### Hypothèses et limitations

K-Means suppose que les **clusters sont sphériques et de taille similaire**, ce qui peut ne pas être vrai pour tous les datasets. Il est sensible au placement initial des centroïdes et peut converger vers des minima locaux. De plus, K-Means n'est pas adapté aux datasets présentant des densités variables, des formes non globulaires ou des caractéristiques à différentes échelles. Des étapes de prétraitement comme la normalisation ou la standardisation peuvent être nécessaires pour garantir que toutes les caractéristiques contribuent de manière égale aux calculs de distance.

<details>
<summary>Exemple -- Clustering d'événements réseau
</summary>
Ci-dessous, nous simulons des données de trafic réseau et utilisons K-Means pour les regrouper. Supposons que nous ayons des événements avec des caractéristiques telles que la durée de connexion et le nombre d'octets. Nous créons 3 clusters de trafic « normal » et 1 petit cluster représentant un schéma d'attaque. Nous exécutons ensuite K-Means pour vérifier s'il les sépare.
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
Dans cet exemple, K-Means devrait trouver 4 clusters. Le petit cluster d’attaque (avec une durée exceptionnellement élevée, d’environ 200) constituera idéalement son propre cluster, compte tenu de sa distance par rapport aux clusters normaux. Nous affichons les tailles et les centres des clusters afin d’interpréter les résultats. Dans un scénario réel, on pourrait étiqueter le cluster contenant peu de points comme une anomalie potentielle ou examiner ses membres à la recherche d’une activité malveillante.
</details>

### Regroupement hiérarchique

Le regroupement hiérarchique construit une hiérarchie de clusters en utilisant soit une approche ascendante (agglomérative), soit une approche descendante (divisive) :

1. **Agglomérative (ascendante)** : Commencer avec chaque point de données comme un cluster distinct, puis fusionner itérativement les clusters les plus proches jusqu’à ce qu’il ne reste qu’un seul cluster ou qu’un critère d’arrêt soit atteint.
2. **Divisive (descendante)** : Commencer avec tous les points de données dans un seul cluster, puis diviser itérativement les clusters jusqu’à ce que chaque point de données constitue son propre cluster ou qu’un critère d’arrêt soit atteint.

Le regroupement agglomératif nécessite une définition de la distance inter-clusters et un critère de liaison pour déterminer quels clusters fusionner. Les méthodes de liaison courantes comprennent la liaison simple (distance entre les points les plus proches de deux clusters), la liaison complète (distance entre les points les plus éloignés), la liaison moyenne, etc. La métrique de distance est souvent euclidienne. Le choix de la liaison influence la forme des clusters produits. Il n’est pas nécessaire de spécifier à l’avance le nombre de clusters K ; on peut « couper » le dendrogramme à un niveau choisi pour obtenir le nombre de clusters souhaité.

Le regroupement hiérarchique produit un dendrogramme, une structure arborescente qui montre les relations entre les clusters à différents niveaux de granularité. Le dendrogramme peut être coupé au niveau souhaité afin d’obtenir un nombre spécifique de clusters.

> [!TIP]
> *Cas d’utilisation en cybersécurité :* Le regroupement hiérarchique peut organiser des événements ou des entités dans un arbre afin de repérer les relations. Par exemple, dans l’analyse de malware, le regroupement agglomératif peut regrouper les échantillons selon leur similarité comportementale, révélant une hiérarchie de familles et de variantes de malware. Dans la sécurité réseau, on peut regrouper les flux de trafic IP et utiliser le dendrogramme pour observer les sous-groupes de trafic (par exemple, d’abord par protocole, puis par comportement). Comme il n’est pas nécessaire de choisir K à l’avance, cette méthode est utile lors de l’exploration de nouvelles données pour lesquelles le nombre de catégories d’attaques est inconnu.

#### Hypothèses et limitations

Le regroupement hiérarchique ne suppose pas une forme particulière de cluster et peut prendre en compte des clusters imbriqués. Il est utile pour découvrir une taxonomie ou les relations entre des groupes (par exemple, regrouper les malwares par sous-groupes de familles). Il est déterministe (sans problèmes liés à l’initialisation aléatoire). L’un de ses principaux avantages est le dendrogramme, qui fournit une vision de la structure de regroupement des données à toutes les échelles – les analystes de sécurité peuvent ainsi décider d’un seuil approprié pour identifier des clusters pertinents. Cependant, il est coûteux en ressources (généralement un temps d’exécution de $O(n^2)$ ou plus avec les implémentations naïves) et n’est pas adapté aux jeux de données très volumineux. Il s’agit également d’une procédure gloutonne : une fois qu’une fusion ou une division a été effectuée, elle ne peut pas être annulée, ce qui peut conduire à des clusters sous-optimaux si une erreur survient au début. Les valeurs aberrantes peuvent également affecter certaines stratégies de liaison (la liaison simple peut provoquer un effet de « chaînage », où les clusters sont reliés par l’intermédiaire de valeurs aberrantes).

<details>
<summary>Exemple -- Regroupement agglomératif d’événements
</summary>

Nous allons réutiliser les données synthétiques de l’exemple K-Means (3 clusters normaux + 1 cluster d’attaque) et appliquer un regroupement agglomératif. Nous montrerons ensuite comment obtenir un dendrogramme et les étiquettes des clusters.
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

DBSCAN est un algorithme de clustering basé sur la densité qui regroupe les points étroitement regroupés, tout en marquant les points situés dans des régions de faible densité comme des valeurs aberrantes. Il est particulièrement utile pour les jeux de données présentant des densités variables et des formes non sphériques.

DBSCAN fonctionne en définissant deux paramètres :
- **Epsilon (ε)** : La distance maximale entre deux points pour qu’ils soient considérés comme appartenant au même cluster.
- **MinPts** : Le nombre minimal de points requis pour former une région dense (point central).

DBSCAN identifie les points centraux, les points frontières et les points de bruit :
- **Point central** : Un point ayant au moins MinPts voisins dans un rayon de distance ε.
- **Point frontière** : Un point situé dans un rayon de distance ε d’un point central, mais ayant moins de MinPts voisins.
- **Point de bruit** : Un point qui n’est ni un point central ni un point frontière.

Le clustering commence par sélectionner un point central non visité, à le marquer comme un nouveau cluster, puis à ajouter récursivement tous les points qui sont accessibles par densité depuis celui-ci (les points centraux et leurs voisins, etc.). Les points frontières sont ajoutés au cluster d’un point central proche. Après avoir étendu tous les points accessibles, DBSCAN passe à un autre point central non visité pour commencer un nouveau cluster. Les points qui n’ont été atteints par aucun point central restent marqués comme du bruit.

> [!TIP]
> *Cas d’utilisation en cybersécurité :* DBSCAN est utile pour la détection d’anomalies dans le trafic réseau. Par exemple, l’activité normale des utilisateurs peut former un ou plusieurs clusters denses dans l’espace des caractéristiques, tandis que de nouveaux comportements d’attaque apparaissent comme des points dispersés que DBSCAN marquera comme du bruit (valeurs aberrantes). Il a été utilisé pour regrouper des enregistrements de flux réseau, où il peut détecter les scans de ports ou le trafic de déni de service sous forme de régions clairsemées de points. Une autre application consiste à regrouper des variantes de malware : si la plupart des échantillons se regroupent par familles, mais que quelques-uns ne correspondent à aucune famille, ces derniers pourraient être des malwares zero-day. La capacité à signaler le bruit permet aux équipes de sécurité de se concentrer sur l’analyse de ces valeurs aberrantes.

#### Hypothèses et limitations

**Hypothèses et points forts :** DBSCAN ne suppose pas que les clusters sont sphériques – il peut détecter des clusters de formes arbitraires (même en forme de chaîne ou adjacents). Il détermine automatiquement le nombre de clusters en fonction de la densité des données et peut identifier efficacement les valeurs aberrantes comme du bruit. Cela le rend puissant pour les données réelles présentant des formes irrégulières et du bruit. Il résiste aux valeurs aberrantes (contrairement à K-Means, qui les force à rejoindre des clusters). Il fonctionne bien lorsque les clusters ont une densité relativement uniforme.

**Limitations** : Les performances de DBSCAN dépendent du choix de valeurs appropriées pour ε et MinPts. Il peut rencontrer des difficultés avec les données présentant des densités variables – une seule valeur de ε ne peut pas prendre en charge à la fois les clusters denses et clairsemés. Si ε est trop faible, il marque la plupart des points comme du bruit ; s’il est trop élevé, les clusters peuvent fusionner de manière incorrecte. De plus, DBSCAN peut être inefficace sur de très grands jeux de données (naïvement $O(n^2)$, bien que l’indexation spatiale puisse aider). Dans les espaces de caractéristiques de grande dimension, le concept de « distance inférieure à ε » peut devenir moins pertinent (la malédiction de la dimensionnalité), et DBSCAN peut nécessiter un réglage minutieux des paramètres ou ne pas parvenir à trouver des clusters intuitifs. Malgré cela, des extensions comme HDBSCAN répondent à certains problèmes (notamment les densités variables).

<details>
<summary>Exemple -- Clustering avec du bruit
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
Dans cet extrait, nous avons ajusté `eps` et `min_samples` pour les adapter à l’échelle de nos données (15.0 dans les unités des caractéristiques, et 5 points requis pour former un cluster). DBSCAN devrait trouver 2 clusters (les clusters de trafic normal) et signaler les 5 outliers injectés comme du bruit. Nous affichons le nombre de clusters par rapport au nombre de points de bruit afin de vérifier cela. Dans un contexte réel, on pourrait itérer sur ε (en utilisant une heuristique basée sur un graphique des k-distances pour choisir ε) et sur MinPts (souvent défini à environ la dimension des données + 1 comme règle empirique) afin d’obtenir des résultats de clustering stables. La possibilité d’étiqueter explicitement le bruit aide à isoler les données potentiellement liées à une attaque pour une analyse approfondie.

</details>

### Analyse en composantes principales (PCA)

La PCA est une technique de **réduction de la dimensionnalité** qui recherche un nouvel ensemble d’axes orthogonaux (les composantes principales) capturant la variance maximale des données. En termes simples, la PCA fait pivoter et projette les données sur un nouveau système de coordonnées, de sorte que la première composante principale (PC1) explique la plus grande variance possible, que la deuxième composante (PC2) explique la plus grande variance orthogonale à PC1, et ainsi de suite. Mathématiquement, la PCA calcule les vecteurs propres de la matrice de covariance des données : ces vecteurs propres sont les directions des composantes principales, et les valeurs propres correspondantes indiquent la quantité de variance expliquée par chacune d’elles. Elle est souvent utilisée pour l’extraction de caractéristiques, la visualisation et la réduction du bruit.

Notez que cette technique est utile si les dimensions de l’ensemble de données contiennent des **dépendances linéaires ou des corrélations significatives**.

La PCA fonctionne en identifiant les composantes principales des données, qui sont les directions de variance maximale. Les étapes de la PCA sont les suivantes :
1. **Standardisation** : Centrer les données en soustrayant la moyenne et les mettre à l’échelle pour obtenir une variance unitaire.
2. **Matrice de covariance** : Calculer la matrice de covariance des données standardisées afin de comprendre les relations entre les caractéristiques.
3. **Décomposition en valeurs propres** : Effectuer une décomposition en valeurs propres de la matrice de covariance afin d’obtenir les valeurs propres et les vecteurs propres.
4. **Sélection des composantes principales** : Trier les valeurs propres par ordre décroissant et sélectionner les K premiers vecteurs propres correspondant aux plus grandes valeurs propres. Ces vecteurs propres forment le nouvel espace des caractéristiques.
5. **Transformation des données** : Projeter les données d’origine dans le nouvel espace des caractéristiques à l’aide des composantes principales sélectionnées.
La PCA est largement utilisée pour la visualisation des données, la réduction du bruit et comme étape de prétraitement pour d’autres algorithmes de machine learning. Elle contribue à réduire la dimensionnalité des données tout en conservant leur structure essentielle.

#### Valeurs propres et vecteurs propres

Une valeur propre est un scalaire qui indique la quantité de variance capturée par le vecteur propre correspondant. Un vecteur propre représente une direction dans l’espace des caractéristiques le long de laquelle les données varient le plus.

Imaginons que A soit une matrice carrée et que v soit un vecteur non nul tel que : `A * v = λ * v`
où :
- A est une matrice carrée telle que [ [1, 2], [2, 1]] (par exemple, une matrice de covariance)
- v est un vecteur propre (par exemple, [1, 1])

Alors, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, ce qui correspondra à la valeur propre λ multipliée par le vecteur propre v, donnant ainsi une valeur propre λ = 3.

#### Valeurs propres et vecteurs propres dans la PCA

Expliquons cela à l’aide d’un exemple. Imaginez que vous disposez d’un ensemble de données contenant de nombreuses images en niveaux de gris de visages de 100x100 pixels. Chaque pixel peut être considéré comme une caractéristique ; vous disposez donc de 10 000 caractéristiques par image (ou d’un vecteur de 10 000 composantes par image). Si vous souhaitez réduire la dimensionnalité de cet ensemble de données à l’aide de la PCA, vous suivriez les étapes suivantes :

1. **Standardisation** : Centrer les données en soustrayant de l’ensemble de données la moyenne de chaque caractéristique (pixel).
2. **Matrice de covariance** : Calculer la matrice de covariance des données standardisées, qui capture la manière dont les caractéristiques (pixels) varient ensemble.
- Notez que la covariance entre deux variables (les pixels dans ce cas) indique dans quelle mesure elles évoluent ensemble ; l’objectif est donc de déterminer quels pixels ont tendance à augmenter ou à diminuer ensemble selon une relation linéaire.
- Par exemple, si les pixels 1 et 2 ont tendance à augmenter ensemble, la covariance entre eux sera positive.
- La matrice de covariance sera une matrice de 10 000x10 000, où chaque entrée représente la covariance entre deux pixels.
3. **Résoudre l’équation en valeurs propres** : L’équation en valeurs propres à résoudre est `C * v = λ * v`, où C est la matrice de covariance, v est le vecteur propre et λ est la valeur propre. Elle peut être résolue à l’aide de méthodes telles que :
- **Décomposition en valeurs propres** : Effectuer une décomposition en valeurs propres de la matrice de covariance afin d’obtenir les valeurs propres et les vecteurs propres.
- **Décomposition en valeurs singulières (SVD)** : Vous pouvez également utiliser la SVD pour décomposer la matrice de données en valeurs singulières et en vecteurs, ce qui peut aussi produire les composantes principales.
4. **Sélection des composantes principales** : Trier les valeurs propres par ordre décroissant et sélectionner les K premiers vecteurs propres correspondant aux plus grandes valeurs propres. Ces vecteurs propres représentent les directions de variance maximale dans les données.

> [!TIP]
> *Cas d’utilisation en cybersécurité :* Une utilisation courante de la PCA en sécurité consiste à réduire les caractéristiques pour la détection d’anomalies. Par exemple, un système de détection d’intrusion disposant de plus de 40 métriques réseau (comme les caractéristiques de NSL-KDD) peut utiliser la PCA pour les réduire à quelques composantes, en résumant les données pour la visualisation ou en les transmettant à des algorithmes de clustering. Les analystes peuvent représenter le trafic réseau dans l’espace des deux premières composantes principales afin de voir si les attaques se distinguent du trafic normal. La PCA peut également contribuer à éliminer les caractéristiques redondantes (comme les octets envoyés et les octets reçus lorsqu’ils sont corrélés), afin de rendre les algorithmes de détection plus robustes et plus rapides.

#### Hypothèses et limites

La PCA suppose que les **axes principaux de variance sont pertinents** : il s’agit d’une méthode linéaire, qui capture donc les corrélations linéaires dans les données. Elle est non supervisée, car elle utilise uniquement la covariance des caractéristiques. Les avantages de la PCA comprennent la réduction du bruit (les composantes à faible variance correspondent souvent au bruit) et la décorrélation des caractéristiques. Elle est efficace sur le plan computationnel pour des dimensions modérément élevées et constitue souvent une étape de prétraitement utile pour d’autres algorithmes (afin d’atténuer la malédiction de la dimensionnalité). L’une de ses limites est que la PCA se limite aux relations linéaires : elle ne capture pas les structures non linéaires complexes (contrairement aux autoencodeurs ou à t-SNE, par exemple). De plus, les composantes de la PCA peuvent être difficiles à interpréter par rapport aux caractéristiques d’origine (il s’agit de combinaisons de caractéristiques d’origine). En cybersécurité, il faut être prudent : une attaque qui ne provoque qu’une modification subtile d’une caractéristique à faible variance peut ne pas apparaître dans les principales composantes (car la PCA privilégie la variance et pas nécessairement ce qui est « intéressant »).

<details>
<summary>Exemple -- Réduction de la dimensionnalité de données réseau
</summary>

Supposons que nous disposions de journaux de connexions réseau contenant plusieurs caractéristiques (par exemple, les durées, les octets et les compteurs). Nous allons générer un ensemble de données synthétiques à 4 dimensions (avec une certaine corrélation entre les caractéristiques) et utiliser la PCA pour le réduire à 2 dimensions à des fins de visualisation ou d’analyse complémentaire.
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
Ici, nous avons repris les clusters de trafic normal précédents et étendu chaque point de données avec deux caractéristiques supplémentaires (paquets et erreurs) corrélées aux octets et à la durée. La PCA est ensuite utilisée pour compresser les 4 caractéristiques en 2 composantes principales. Nous affichons le ratio de variance expliquée, qui peut montrer que, par exemple, >95 % de la variance est capturée par 2 composantes (ce qui signifie une faible perte d’information). La sortie montre également que la forme des données passe de (1500, 4) à (1500, 2). Les premiers points dans l’espace PCA sont fournis à titre d’exemple. En pratique, on pourrait représenter `data_2d` pour vérifier visuellement si les clusters sont distinguables. Si une anomalie était présente, on pourrait la voir sous la forme d’un point éloigné du cluster principal dans l’espace PCA. La PCA aide ainsi à condenser des données complexes sous une forme exploitable par l’humain ou utilisable en entrée d’autres algorithmes.

</details>


### Modèles de mélange gaussien (GMM)

Un modèle de mélange gaussien suppose que les données sont générées à partir d’un mélange de **plusieurs distributions gaussiennes (normales) dont les paramètres sont inconnus**. Il s’agit essentiellement d’un modèle de clustering probabiliste : il tente d’attribuer chaque point, de manière souple, à l’une des K composantes gaussiennes. Chaque composante gaussienne k possède un vecteur moyen (μ_k), une matrice de covariance (Σ_k) et un poids de mélange (π_k), qui représente la prévalence de ce cluster. Contrairement à K-Means, qui effectue des affectations « strictes », le GMM attribue à chaque point une probabilité d’appartenance à chaque cluster.

L’ajustement d’un GMM est généralement effectué à l’aide de l’algorithme Expectation-Maximization (EM) :

- **Initialisation** : Commencer avec des estimations initiales des moyennes, des covariances et des coefficients de mélange (ou utiliser les résultats de K-Means comme point de départ).

- **Étape E (Expectation)** : Avec les paramètres actuels, calculer la responsabilité de chaque cluster pour chaque point : essentiellement `r_nk = P(z_k | x_n)`, où z_k est la variable latente indiquant l’appartenance au cluster du point x_n. Cela se fait à l’aide du théorème de Bayes, en calculant la probabilité a posteriori de l’appartenance de chaque point à chaque cluster à partir des paramètres actuels. Les responsabilités sont calculées comme suit :
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
où :
- \( \pi_k \) est le coefficient de mélange du cluster k (probabilité a priori du cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) est la fonction de densité de probabilité gaussienne du point \( x_n \), avec une moyenne \( \mu_k \) et une covariance \( \Sigma_k \).

- **Étape M (Maximization)** : Mettre à jour les paramètres à l’aide des responsabilités calculées lors de l’étape E :
- Mettre à jour chaque moyenne μ_k comme la moyenne pondérée des points, les poids correspondant aux responsabilités.
- Mettre à jour chaque covariance Σ_k comme la covariance pondérée des points affectés au cluster k.
- Mettre à jour les coefficients de mélange π_k comme la responsabilité moyenne du cluster k.

- **Répéter** les étapes E et M jusqu’à convergence (stabilisation des paramètres ou amélioration de la vraisemblance inférieure à un seuil).

Le résultat est un ensemble de distributions gaussiennes qui modélisent collectivement la distribution globale des données. Nous pouvons utiliser le GMM ajusté pour effectuer un clustering en affectant chaque point à la gaussienne ayant la probabilité la plus élevée, ou conserver les probabilités afin de représenter l’incertitude. Il est également possible d’évaluer la vraisemblance de nouveaux points afin de vérifier s’ils correspondent au modèle (ce qui est utile pour la détection d’anomalies).

> [!TIP]
> *Cas d’utilisation en cybersécurité :* Le GMM peut être utilisé pour la détection d’anomalies en modélisant la distribution des données normales : tout point ayant une très faible probabilité selon le mélange appris est signalé comme une anomalie. Par exemple, on pourrait entraîner un GMM sur les caractéristiques d’un trafic réseau légitime ; une connexion d’attaque qui ne ressemble à aucun cluster appris aurait une faible vraisemblance. Les GMM sont également utilisés pour regrouper des activités lorsque les clusters peuvent avoir des formes différentes – par exemple, pour regrouper des utilisateurs selon leurs profils comportementaux, où les caractéristiques de chaque profil pourraient suivre une forme gaussienne, mais avec leur propre structure de variance. Autre scénario : dans la détection du phishing, les caractéristiques des e-mails légitimes pourraient former un cluster gaussien, les e-mails de phishing connus un autre, et les nouvelles campagnes de phishing pourraient apparaître soit comme une gaussienne distincte, soit comme des points à faible vraisemblance par rapport au mélange existant.

#### Hypothèses et limites

Le GMM est une généralisation de K-Means qui intègre la covariance ; les clusters peuvent donc être ellipsoïdaux (et pas uniquement sphériques). Il gère les clusters de tailles et de formes différentes lorsque la covariance est complète. Le clustering souple est un avantage lorsque les limites entre les clusters sont floues – par exemple, en cybersécurité, un événement peut présenter les caractéristiques de plusieurs types d’attaques ; le GMM peut représenter cette incertitude au moyen de probabilités. Le GMM fournit également une estimation probabiliste de la densité des données, utile pour détecter les valeurs aberrantes (points ayant une faible vraisemblance selon toutes les composantes du mélange).

En revanche, le GMM nécessite de spécifier le nombre de composantes K (bien que des critères tels que BIC/AIC puissent être utilisés pour le sélectionner). L’algorithme EM peut parfois converger lentement ou vers un optimum local ; l’initialisation est donc importante (on exécute souvent EM plusieurs fois). Si les données ne suivent pas réellement un mélange de distributions gaussiennes, le modèle peut être mal adapté. Il existe également un risque qu’une gaussienne se contracte pour ne couvrir qu’une seule valeur aberrante (bien qu’une régularisation ou des limites minimales de covariance puissent atténuer ce problème).


<details>
<summary>Exemple --  Clustering souple et scores d’anomalie
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
Dans ce code, nous entraînons un GMM avec 3 distributions gaussiennes sur le trafic normal (en supposant que nous connaissons 3 profils de trafic légitime). Les moyennes et les covariances affichées décrivent ces clusters (par exemple, une moyenne peut être autour de [50,500], correspondant au centre d’un cluster, etc.). Nous testons ensuite une connexion suspecte [duration=200, bytes=800]. La fonction predict_proba fournit la probabilité que ce point appartienne à chacun des 3 clusters — on s’attend à ce que ces probabilités soient très faibles ou fortement déséquilibrées, puisque [200,800] est éloigné des clusters normaux. Le score_samples global (log-vraisemblance) est affiché ; une valeur très faible indique que le point correspond mal au modèle, ce qui permet de le signaler comme anomalie. En pratique, on peut définir un seuil sur la log-vraisemblance (ou sur la probabilité maximale) afin de décider si un point est suffisamment improbable pour être considéré comme malveillant. Le GMM fournit ainsi une méthode fondée sur des principes solides pour la détection d’anomalies et produit également des clusters souples qui prennent en compte l’incertitude.
</details>

### Isolation Forest

**Isolation Forest** est un algorithme de détection d’anomalies en ensemble, fondé sur l’idée d’isoler aléatoirement les points. Le principe est que les anomalies sont peu nombreuses et différentes ; elles sont donc plus faciles à isoler que les points normaux. Un Isolation Forest construit de nombreux arbres d’isolation binaires (arbres de décision aléatoires) qui partitionnent aléatoirement les données. À chaque nœud d’un arbre, une feature aléatoire est sélectionnée et une valeur de séparation aléatoire est choisie entre le minimum et le maximum de cette feature pour les données du nœud. Cette séparation divise les données en deux branches. L’arbre est développé jusqu’à ce que chaque point soit isolé dans sa propre feuille ou qu’une hauteur maximale soit atteinte.

La détection d’anomalies s’effectue en observant la longueur du chemin de chaque point dans ces arbres aléatoires — c’est-à-dire le nombre de séparations nécessaires pour isoler le point. Intuitivement, les anomalies (outliers) ont tendance à être isolées plus rapidement, car une séparation aléatoire a davantage de chances de séparer un outlier (situé dans une région peu dense) qu’un point normal situé dans un cluster dense. L’Isolation Forest calcule un score d’anomalie à partir de la longueur moyenne du chemin sur l’ensemble des arbres : chemin moyen plus court → anomalie plus probable. Les scores sont généralement normalisés dans l’intervalle [0,1], où 1 signifie qu’il s’agit très probablement d’une anomalie.

> [!TIP]
> *Cas d’utilisation en cybersécurité :* les Isolation Forests ont été utilisées avec succès pour la détection d’intrusions et la détection de fraudes. Par exemple, entraînez un Isolation Forest sur des logs de trafic réseau contenant principalement un comportement normal ; la forêt produira des chemins courts pour les trafics inhabituels (comme une IP qui utilise un port jamais observé ou un schéma de taille de paquets inhabituel), et les signalera pour inspection. Comme il ne nécessite pas d’attaques labellisées, cet algorithme convient à la détection de types d’attaques inconnus. Il peut également être déployé sur des données de connexion utilisateur afin de détecter les prises de contrôle de comptes (les heures ou emplacements de connexion anormaux sont isolés rapidement). Dans un cas d’utilisation, un Isolation Forest pourrait protéger une entreprise en surveillant les métriques système et en générant une alerte lorsqu’une combinaison de métriques (CPU, réseau, changements de fichiers) semble très différente (chemins d’isolation courts) des schémas historiques.

#### Hypothèses et limitations

**Avantages** : l’Isolation Forest ne nécessite aucune hypothèse de distribution ; il cible directement l’isolation. Il est efficace sur les données à haute dimension et les grands jeux de données (complexité linéaire $O(n\log n)$ pour construire la forêt), car chaque arbre isole les points en utilisant seulement un sous-ensemble de features et de séparations. Il tend à bien gérer les features numériques et peut être plus rapide que les méthodes fondées sur la distance, qui peuvent être en $O(n^2)$. Il fournit également automatiquement un score d’anomalie ; vous pouvez donc définir un seuil pour les alertes (ou utiliser un paramètre de contamination afin de déterminer automatiquement une limite à partir d’une fraction d’anomalies attendue).

**Limitations** : en raison de sa nature aléatoire, les résultats peuvent légèrement varier d’une exécution à l’autre (bien que cette variation soit faible avec un nombre suffisamment élevé d’arbres). Si les données contiennent beaucoup de features non pertinentes ou si les anomalies ne se distinguent fortement dans aucune feature, l’isolation peut être inefficace (des séparations aléatoires peuvent isoler des points normaux par hasard ; toutefois, la moyenne calculée sur de nombreux arbres réduit cet effet). De plus, l’Isolation Forest suppose généralement que les anomalies constituent une petite minorité (ce qui est habituellement le cas dans les scénarios de cybersécurité).

<details>
<summary>Exemple --  Détection d’outliers dans des logs réseau
</summary>

Nous utiliserons le jeu de données de test précédent (qui contient des points normaux et quelques points d’attaque) et exécuterons un Isolation Forest pour voir s’il peut séparer les attaques. Nous supposerons qu’environ 15 % des données sont anormales (à des fins de démonstration).
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
Dans ce code, nous instancions `IsolationForest` avec 100 arbres et définissons `contamination=0.15` (ce qui signifie que nous nous attendons à environ 15 % d’anomalies ; le modèle définira son seuil de score de manière à ce qu’environ 15 % des points soient signalés). Nous l’entraînons sur `X_test_if`, qui contient un mélange de points normaux et de points d’attaque (remarque : normalement, vous l’entraîneriez sur des données d’entraînement, puis utiliseriez predict sur de nouvelles données, mais ici, à titre d’illustration, nous l’entraînons et effectuons les prédictions sur le même ensemble afin d’observer directement les résultats).

La sortie affiche les labels prédits pour les 20 premiers points (où -1 indique une anomalie). Nous affichons également le nombre total d’anomalies détectées ainsi que quelques exemples de scores d’anomalie. Nous nous attendrions à ce qu’environ 18 points sur 120 soient étiquetés -1 (puisque la contamination était de 15 %). Si nos 20 échantillons d’attaque sont réellement les plus éloignés, la plupart d’entre eux devraient apparaître dans ces prédictions -1. Le score d’anomalie (la decision function d’Isolation Forest) est plus élevé pour les points normaux et plus faible (plus négatif) pour les anomalies ; nous affichons quelques valeurs afin d’observer la séparation. En pratique, on pourrait trier les données selon le score afin d’afficher les principales valeurs aberrantes et de les examiner. Isolation Forest fournit ainsi un moyen efficace de parcourir de grandes quantités de données de sécurité non étiquetées et d’identifier les instances les plus irrégulières pour une analyse humaine ou un examen automatisé supplémentaire.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** est une technique non linéaire de réduction de dimensionnalité conçue spécifiquement pour visualiser des données de grande dimension en 2 ou 3 dimensions. Elle convertit les similarités entre les points de données en distributions de probabilités conjointes et tente de préserver la structure des voisinages locaux dans la projection de dimension inférieure. En termes plus simples, t-SNE place les points en (par exemple) 2D de sorte que les points similaires dans l’espace d’origine se retrouvent proches les uns des autres, tandis que les points dissemblables se retrouvent éloignés avec une probabilité élevée.

L’algorithme comporte trois étapes principales :

1. **Calculer les affinités par paire dans l’espace de grande dimension :** Pour chaque paire de points, t-SNE calcule la probabilité que cette paire soit choisie comme voisine (cela se fait en centrant une distribution gaussienne sur chaque point et en mesurant les distances – le paramètre de perplexité influence le nombre effectif de voisins pris en compte).
2. **Calculer les affinités par paire dans l’espace de faible dimension (par exemple en 2D) :** Initialement, les points sont placés aléatoirement en 2D. t-SNE définit une probabilité similaire pour les distances sur cette carte (en utilisant un noyau fondé sur une distribution t de Student, dont les queues sont plus lourdes que celles d’une distribution gaussienne, afin d’offrir davantage de liberté aux points éloignés).
3. **Descente de gradient :** t-SNE déplace ensuite itérativement les points en 2D afin de minimiser la divergence de Kullback–Leibler (KL) entre la distribution des affinités en haute dimension et celle en basse dimension. La disposition en 2D reflète ainsi autant que possible la structure en haute dimension : les points proches dans l’espace d’origine s’attirent, tandis que les points éloignés se repoussent, jusqu’à ce qu’un équilibre soit atteint.

Le résultat est souvent un nuage de points visuellement pertinent, dans lequel les clusters des données deviennent apparents.

> [!TIP]
> *Cas d’utilisation en cybersécurité :* t-SNE est souvent utilisé pour **visualiser des données de sécurité de grande dimension à des fins d’analyse humaine**. Par exemple, dans un centre des opérations de sécurité, les analystes pourraient prendre un jeu de données d’événements comportant des dizaines de caractéristiques (numéros de port, fréquences, quantités d’octets, etc.) et utiliser t-SNE pour produire un graphique en 2D. Les attaques pourraient former leurs propres clusters ou se séparer des données normales sur ce graphique, ce qui les rendrait plus faciles à identifier. Cette technique a été appliquée à des jeux de données de malware pour visualiser les regroupements de familles de malware, ainsi qu’à des données d’intrusion réseau où différents types d’attaques forment des clusters distincts, facilitant ainsi les investigations. En substance, t-SNE permet d’observer la structure de données cyber qui serait autrement difficile à interpréter.

#### Hypothèses et limitations

t-SNE est excellent pour la découverte visuelle de patterns. Il peut révéler des clusters, des sous-clusters et des valeurs aberrantes que d’autres méthodes linéaires (comme PCA) ne mettent pas nécessairement en évidence. Il a été utilisé dans des recherches en cybersécurité pour visualiser des données complexes, telles que des profils de comportement de malware ou des patterns de trafic réseau. Comme il préserve la structure locale, il est efficace pour représenter les regroupements naturels.

Cependant, t-SNE est plus exigeant sur le plan computationnel (environ $O(n^2)$), et peut donc nécessiter un échantillonnage pour les jeux de données très volumineux. Il comporte également des hyperparamètres (perplexité, taux d’apprentissage, nombre d’itérations) qui peuvent influencer la sortie – par exemple, différentes valeurs de perplexité peuvent révéler des clusters à différentes échelles. Les graphiques t-SNE peuvent parfois être mal interprétés : les distances sur la carte n’ont pas directement de signification globale (la méthode se concentre sur le voisinage local, et certains clusters peuvent sembler artificiellement bien séparés). De plus, t-SNE sert principalement à la visualisation ; il ne fournit pas de méthode simple pour projeter de nouveaux points de données sans recalcul, et n’est pas destiné à être utilisé comme étape de prétraitement pour la modélisation prédictive (UMAP est une alternative qui corrige certains de ces problèmes avec une vitesse supérieure).

<details>
<summary>Exemple -- Visualisation de connexions réseau
</summary>

Nous allons utiliser t-SNE pour réduire un jeu de données comportant plusieurs caractéristiques en 2D. À titre d’illustration, prenons les données 4D précédentes (qui comportaient 3 clusters naturels de trafic normal) et ajoutons quelques points d’anomalie. Nous exécuterons ensuite t-SNE et visualiserons (conceptuellement) les résultats.
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
Ici, nous avons combiné notre précédent dataset normal en 4D avec quelques outliers extrêmes (les outliers ont une feature (« duration ») définie à une valeur très élevée, etc., afin de simuler un comportement inhabituel). Nous exécutons t-SNE avec une perplexité typique de 30. La sortie `data_2d` a la forme (1505, 2). Nous n’allons pas réellement produire de graphique dans ce texte, mais si nous le faisions, nous nous attendrions à voir peut-être trois clusters très compacts correspondant aux 3 clusters normaux, ainsi que les 5 outliers apparaissant comme des points isolés, éloignés de ces clusters. Dans un workflow interactif, nous pourrions colorer les points selon leur label (normal ou correspondant à un cluster, par opposition aux anomalies) afin de vérifier cette structure. Même sans labels, un analyste pourrait remarquer ces 5 points situés dans une zone vide du graphique 2D et les signaler. Cela montre comment t-SNE peut être une aide puissante pour la détection visuelle des anomalies et l’inspection des clusters dans les données de cybersécurité, en complément des algorithmes automatisés présentés précédemment.

</details>


### HDBSCAN (Hierarchical Density-Based Spatial Clustering of Applications with Noise)

**HDBSCAN** est une extension de DBSCAN qui élimine la nécessité de choisir une valeur globale unique pour `eps` et qui est capable de retrouver des clusters de **densités différentes** en construisant une hiérarchie de composants connectés par densité, puis en la condensant. Comparé à DBSCAN vanilla, il

* extrait généralement des clusters plus intuitifs lorsque certains clusters sont denses et que d’autres sont dispersés ;
* ne possède qu’un seul hyperparamètre réel (`min_cluster_size`) et une valeur par défaut pertinente ;
* attribue à chaque point une *probabilité* d’appartenance à un cluster ainsi qu’un **score d’outlier** (`outlier_scores_`), ce qui est extrêmement pratique pour les dashboards de threat-hunting.<sup>[[1]](#references)</sup>

> [!TIP]
> *Cas d’utilisation en cybersécurité :* HDBSCAN est très populaire dans les pipelines modernes de threat-hunting : on le retrouve souvent dans des playbooks de hunting basés sur des notebooks, fournis avec les suites XDR commerciales. Une recette pratique consiste à clusteriser le trafic de beaconing HTTP pendant une réponse à incident (IR) : le user-agent, l’intervalle et la longueur de l’URI forment souvent plusieurs groupes compacts correspondant à des logiciels légitimes de mise à jour, tandis que les beacons C2 restent sous la forme de minuscules clusters à faible densité ou de pur bruit.

<details>
<summary>Exemple – Détection des canaux C2 de beaconing</summary>
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

### Considérations de robustesse et de sécurité – Poisoning et attaques adversariales (2023-2025)

Des travaux récents ont montré que les **algorithmes unsupervised ne sont *pas* immunisés contre les attaquants actifs** :

* **Data-poisoning contre les anomaly detectors.** Chen *et al.* (IEEE S&P 2024) ont démontré que l’ajout de seulement 3 % de trafic élaboré peut déplacer la frontière de décision d’Isolation Forest et d’ECOD, de sorte que de véritables attaques semblent normales. Les auteurs ont publié un PoC open source (`udo-poison`) qui synthétise automatiquement des points de poison.<sup>[[2]](#references)</sup>
* **Backdooring des modèles de clustering.** La technique *BadCME* (BlackHat EU 2023) implante un minuscule trigger ; chaque fois que ce trigger apparaît, un detector basé sur K-Means place discrètement l’événement dans un cluster « bénin ».
* **Evasion de DBSCAN/HDBSCAN.** Un pre-print académique de 2025 de la KU Leuven a montré qu’un attaquant peut élaborer des patterns de beaconing qui tombent délibérément dans des gaps de densité, se cachant ainsi efficacement parmi les labels *noise*.

Les mesures d’atténuation qui gagnent du terrain :

1. **Model sanitisation / TRIM.** Avant chaque epoch de retraining, supprimer les 1 à 2 % de points présentant la loss la plus élevée (maximum likelihood tronquée) afin de rendre le poisoning beaucoup plus difficile.
2. **Consensus ensembling.** Combiner plusieurs detectors hétérogènes (par exemple Isolation Forest + GMM + ECOD) et déclencher une alerte si *au moins un* modèle signale un point. Les recherches indiquent que cela augmente le coût pour l’attaquant de plus de 10×.
3. **Distance-based defence pour le clustering.** Recalculer les clusters avec `k` seeds aléatoires différentes et ignorer les points qui changent constamment de cluster.

---

### Outils Open Source modernes (2024-2025)

* **PyOD 2.x** (publié en mai 2024) a ajouté les detectors *ECOD*, *COPOD* et *AutoFormer* accélérés par GPU. Il fournit désormais une sous-commande `benchmark` qui permet de comparer plus de 30 algorithmes sur votre dataset avec **une seule ligne de code** :
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (février 2025) se concentre sur la vision, mais contient également une implémentation générique de **PatchCore**, pratique pour la détection de pages de phishing à partir de screenshots.
* **scikit-learn 1.5** (novembre 2024) expose enfin `score_samples` pour *HDBSCAN* via le nouveau wrapper `cluster.HDBSCAN`, ce qui évite d’avoir besoin du package contrib externe avec Python 3.12.

<details>
<summary>Exemple PyOD rapide – ensemble ECOD + Isolation Forest</summary>
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

## Références

- [1] [HDBSCAN – Clustering hiérarchique basé sur la densité](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* « Vulnérabilité de la détection d’anomalies non supervisée face au data poisoning. » *IEEE Symposium on Security and Privacy*, 2024.



{{#include ../banners/hacktricks-training.md}}
