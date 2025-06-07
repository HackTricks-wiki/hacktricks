# Algorithmes d'apprentissage non supervisé

{{#include ../banners/hacktricks-training.md}}

## Apprentissage non supervisé

L'apprentissage non supervisé est un type d'apprentissage automatique où le modèle est entraîné sur des données sans réponses étiquetées. L'objectif est de trouver des motifs, des structures ou des relations au sein des données. Contrairement à l'apprentissage supervisé, où le modèle apprend à partir d'exemples étiquetés, les algorithmes d'apprentissage non supervisé travaillent avec des données non étiquetées. L'apprentissage non supervisé est souvent utilisé pour des tâches telles que le regroupement, la réduction de dimensionnalité et la détection d'anomalies. Il peut aider à découvrir des motifs cachés dans les données, à regrouper des éléments similaires ou à réduire la complexité des données tout en préservant ses caractéristiques essentielles.

### Regroupement K-Means

K-Means est un algorithme de regroupement basé sur les centroïdes qui partitionne les données en K clusters en assignant chaque point au centre de cluster le plus proche. L'algorithme fonctionne comme suit :
1. **Initialisation** : Choisir K centres de cluster initiaux (centroïdes), souvent aléatoirement ou via des méthodes plus intelligentes comme k-means++
2. **Affectation** : Assigner chaque point de données au centroïde le plus proche en fonction d'une métrique de distance (par exemple, distance euclidienne).
3. **Mise à jour** : Recalculer les centroïdes en prenant la moyenne de tous les points de données assignés à chaque cluster.
4. **Répéter** : Les étapes 2–3 sont répétées jusqu'à ce que les affectations de cluster se stabilisent (les centroïdes ne se déplacent plus de manière significative).

> [!TIP]
> *Cas d'utilisation en cybersécurité :* K-Means est utilisé pour la détection d'intrusions en regroupant les événements réseau. Par exemple, des chercheurs ont appliqué K-Means au jeu de données d'intrusion KDD Cup 99 et ont constaté qu'il partitionnait efficacement le trafic en clusters normaux et d'attaque. En pratique, les analystes de sécurité peuvent regrouper les entrées de journal ou les données de comportement des utilisateurs pour trouver des groupes d'activités similaires ; tout point qui n'appartient pas à un cluster bien formé pourrait indiquer des anomalies (par exemple, une nouvelle variante de malware formant son propre petit cluster). K-Means peut également aider à la classification des familles de malware en regroupant des binaires en fonction de profils de comportement ou de vecteurs de caractéristiques.

#### Sélection de K
Le nombre de clusters (K) est un hyperparamètre qui doit être défini avant d'exécuter l'algorithme. Des techniques comme la méthode du coude ou le score de silhouette peuvent aider à déterminer une valeur appropriée pour K en évaluant la performance du regroupement :

- **Méthode du coude** : Tracer la somme des distances au carré de chaque point à son centroïde de cluster assigné en fonction de K. Rechercher un point de "coude" où le taux de diminution change brusquement, indiquant un nombre de clusters approprié.
- **Score de silhouette** : Calculer le score de silhouette pour différentes valeurs de K. Un score de silhouette plus élevé indique des clusters mieux définis.

#### Hypothèses et limitations

K-Means suppose que **les clusters sont sphériques et de taille égale**, ce qui peut ne pas être vrai pour tous les ensembles de données. Il est sensible à l'emplacement initial des centroïdes et peut converger vers des minima locaux. De plus, K-Means n'est pas adapté aux ensembles de données avec des densités variables ou des formes non globulaires et des caractéristiques avec des échelles différentes. Des étapes de prétraitement comme la normalisation ou la standardisation peuvent être nécessaires pour garantir que toutes les caractéristiques contribuent également aux calculs de distance.

<details>
<summary>Exemple -- Regroupement d'événements réseau
</summary>
Ci-dessous, nous simulons des données de trafic réseau et utilisons K-Means pour les regrouper. Supposons que nous ayons des événements avec des caractéristiques telles que la durée de connexion et le nombre d'octets. Nous créons 3 clusters de trafic "normal" et 1 petit cluster représentant un modèle d'attaque. Ensuite, nous exécutons K-Means pour voir s'il les sépare.
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
Dans cet exemple, K-Means devrait trouver 4 clusters. Le petit cluster d'attaque (avec une durée anormalement élevée ~200) formera idéalement son propre cluster étant donné sa distance par rapport aux clusters normaux. Nous imprimons les tailles et les centres des clusters pour interpréter les résultats. Dans un scénario réel, on pourrait étiqueter le cluster avec peu de points comme des anomalies potentielles ou inspecter ses membres pour une activité malveillante.

### Clustering Hiérarchique

Le clustering hiérarchique construit une hiérarchie de clusters en utilisant soit une approche ascendante (agglomérative) soit une approche descendante (divisive) :

1. **Agglomératif (Ascendant)** : Commencez avec chaque point de données comme un cluster séparé et fusionnez itérativement les clusters les plus proches jusqu'à ce qu'il ne reste qu'un seul cluster ou qu'un critère d'arrêt soit atteint.
2. **Divisif (Descendant)** : Commencez avec tous les points de données dans un seul cluster et divisez itérativement les clusters jusqu'à ce que chaque point de données soit son propre cluster ou qu'un critère d'arrêt soit atteint.

Le clustering agglomératif nécessite une définition de la distance inter-cluster et un critère de liaison pour décider quels clusters fusionner. Les méthodes de liaison courantes incluent la liaison simple (distance des points les plus proches entre deux clusters), la liaison complète (distance des points les plus éloignés), la liaison moyenne, etc., et la métrique de distance est souvent euclidienne. Le choix de la liaison affecte la forme des clusters produits. Il n'est pas nécessaire de spécifier à l'avance le nombre de clusters K ; vous pouvez "couper" le dendrogramme à un niveau choisi pour obtenir le nombre de clusters souhaité.

Le clustering hiérarchique produit un dendrogramme, une structure en arbre qui montre les relations entre les clusters à différents niveaux de granularité. Le dendrogramme peut être coupé à un niveau souhaité pour obtenir un nombre spécifique de clusters.

> [!TIP]
> *Cas d'utilisation en cybersécurité :* Le clustering hiérarchique peut organiser des événements ou des entités en un arbre pour repérer des relations. Par exemple, dans l'analyse de logiciels malveillants, le clustering agglomératif pourrait regrouper des échantillons par similarité comportementale, révélant une hiérarchie de familles et de variantes de logiciels malveillants. En sécurité réseau, on pourrait regrouper les flux de trafic IP et utiliser le dendrogramme pour voir les sous-groupes de trafic (par exemple, par protocole, puis par comportement). Comme vous n'avez pas besoin de choisir K à l'avance, c'est utile lors de l'exploration de nouvelles données pour lesquelles le nombre de catégories d'attaques est inconnu.

#### Hypothèses et Limitations

Le clustering hiérarchique ne suppose pas une forme de cluster particulière et peut capturer des clusters imbriqués. Il est utile pour découvrir la taxonomie ou les relations entre les groupes (par exemple, regrouper les logiciels malveillants par sous-groupes familiaux). Il est déterministe (pas de problèmes d'initialisation aléatoire). Un avantage clé est le dendrogramme, qui fournit un aperçu de la structure de clustering des données à toutes les échelles – les analystes en sécurité peuvent décider d'un seuil approprié pour identifier des clusters significatifs. Cependant, il est coûteux en calcul (typiquement $O(n^2)$ ou pire pour des implémentations naïves) et n'est pas faisable pour des ensembles de données très volumineux. C'est aussi une procédure avide – une fois qu'une fusion ou une division est effectuée, elle ne peut pas être annulée, ce qui peut conduire à des clusters sous-optimaux si une erreur se produit tôt. Les valeurs aberrantes peuvent également affecter certaines stratégies de liaison (la liaison simple peut provoquer l'effet de "chaînage" où les clusters se lient via des valeurs aberrantes).

<details>
<summary>Exemple -- Clustering Agglomératif d'Événements
</summary>

Nous allons réutiliser les données synthétiques de l'exemple K-Means (3 clusters normaux + 1 cluster d'attaque) et appliquer le clustering agglomératif. Nous illustrons ensuite comment obtenir un dendrogramme et des étiquettes de clusters.
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

### DBSCAN (Clustering spatial basé sur la densité des applications avec bruit)

DBSCAN est un algorithme de clustering basé sur la densité qui regroupe ensemble des points étroitement regroupés tout en marquant les points dans des régions de faible densité comme des valeurs aberrantes. Il est particulièrement utile pour les ensembles de données avec des densités variables et des formes non sphériques.

DBSCAN fonctionne en définissant deux paramètres :
- **Epsilon (ε)** : La distance maximale entre deux points pour être considérés comme faisant partie du même cluster.
- **MinPts** : Le nombre minimum de points requis pour former une région dense (point central).

DBSCAN identifie les points centraux, les points de bord et les points de bruit :
- **Point central** : Un point ayant au moins MinPts voisins dans une distance ε.
- **Point de bord** : Un point qui est à une distance ε d'un point central mais a moins de MinPts voisins.
- **Point de bruit** : Un point qui n'est ni un point central ni un point de bord.

Le clustering se poursuit en choisissant un point central non visité, en le marquant comme un nouveau cluster, puis en ajoutant récursivement tous les points accessibles par densité à partir de celui-ci (points centraux et leurs voisins, etc.). Les points de bord sont ajoutés au cluster d'un point central voisin. Après avoir étendu tous les points accessibles, DBSCAN passe à un autre point central non visité pour commencer un nouveau cluster. Les points non atteints par aucun point central restent étiquetés comme bruit.

> [!TIP]
> *Cas d'utilisation en cybersécurité :* DBSCAN est utile pour la détection d'anomalies dans le trafic réseau. Par exemple, l'activité normale des utilisateurs pourrait former un ou plusieurs clusters denses dans l'espace des caractéristiques, tandis que les comportements d'attaque nouveaux apparaissent comme des points dispersés que DBSCAN étiquetera comme bruit (valeurs aberrantes). Il a été utilisé pour regrouper des enregistrements de flux réseau, où il peut détecter des analyses de ports ou du trafic de déni de service comme des régions de points rares. Une autre application est le regroupement de variantes de logiciels malveillants : si la plupart des échantillons se regroupent par familles mais que quelques-uns ne s'intègrent nulle part, ces quelques-uns pourraient être des logiciels malveillants de type zero-day. La capacité à signaler le bruit signifie que les équipes de sécurité peuvent se concentrer sur l'investigation de ces valeurs aberrantes.

#### Hypothèses et limitations

**Hypothèses et forces :** DBSCAN ne suppose pas des clusters sphériques – il peut trouver des clusters de forme arbitraire (même des clusters en chaîne ou adjacents). Il détermine automatiquement le nombre de clusters en fonction de la densité des données et peut identifier efficacement les valeurs aberrantes comme bruit. Cela le rend puissant pour les données du monde réel avec des formes irrégulières et du bruit. Il est robuste aux valeurs aberrantes (contrairement à K-Means, qui les force dans des clusters). Il fonctionne bien lorsque les clusters ont une densité à peu près uniforme.

**Limitations :** La performance de DBSCAN dépend du choix des valeurs appropriées pour ε et MinPts. Il peut avoir des difficultés avec des données ayant des densités variables – un seul ε ne peut pas accommoder à la fois des clusters denses et rares. Si ε est trop petit, il étiquette la plupart des points comme bruit ; trop grand, et les clusters peuvent fusionner incorrectement. De plus, DBSCAN peut être inefficace sur des ensembles de données très volumineux (naïvement $O(n^2)$, bien que l'indexation spatiale puisse aider). Dans des espaces de caractéristiques de haute dimension, le concept de "distance dans ε" peut devenir moins significatif (la malédiction de la dimensionnalité), et DBSCAN peut nécessiter un réglage minutieux des paramètres ou peut échouer à trouver des clusters intuitifs. Malgré cela, des extensions comme HDBSCAN abordent certains problèmes (comme la densité variable).

<details>
<summary>Exemple -- Clustering avec bruit
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
Dans cet extrait, nous avons ajusté `eps` et `min_samples` pour convenir à notre échelle de données (15,0 en unités de caractéristiques, et nécessitant 5 points pour former un cluster). DBSCAN devrait trouver 2 clusters (les clusters de trafic normal) et signaler les 5 valeurs aberrantes injectées comme bruit. Nous affichons le nombre de clusters par rapport aux points de bruit pour vérifier cela. Dans un cadre réel, on pourrait itérer sur ε (en utilisant une heuristique de graphique de distance k pour choisir ε) et MinPts (souvent fixé autour de la dimensionnalité des données + 1 comme règle générale) pour trouver des résultats de clustering stables. La capacité à étiqueter explicitement le bruit aide à séparer les données d'attaque potentielles pour une analyse plus approfondie.

</details>

### Analyse en Composantes Principales (ACP)

L'ACP est une technique de **réduction de dimensionnalité** qui trouve un nouvel ensemble d'axes orthogonaux (composantes principales) qui capturent la variance maximale dans les données. En termes simples, l'ACP fait pivoter et projette les données sur un nouveau système de coordonnées de sorte que la première composante principale (PC1) explique la plus grande variance possible, la deuxième PC (PC2) explique la plus grande variance orthogonale à PC1, et ainsi de suite. Mathématiquement, l'ACP calcule les vecteurs propres de la matrice de covariance des données – ces vecteurs propres sont les directions des composantes principales, et les valeurs propres correspondantes indiquent la quantité de variance expliquée par chacune. Elle est souvent utilisée pour l'extraction de caractéristiques, la visualisation et la réduction du bruit.

Notez que cela est utile si les dimensions du jeu de données contiennent **des dépendances ou des corrélations linéaires significatives**.

L'ACP fonctionne en identifiant les composantes principales des données, qui sont les directions de variance maximale. Les étapes impliquées dans l'ACP sont :
1. **Standardisation** : Centrer les données en soustrayant la moyenne et en les mettant à l'échelle pour obtenir une variance unitaire.
2. **Matrice de Covariance** : Calculer la matrice de covariance des données standardisées pour comprendre les relations entre les caractéristiques.
3. **Décomposition en Valeurs Propres** : Effectuer une décomposition en valeurs propres sur la matrice de covariance pour obtenir les valeurs propres et les vecteurs propres.
4. **Sélection des Composantes Principales** : Trier les valeurs propres par ordre décroissant et sélectionner les K vecteurs propres correspondants aux plus grandes valeurs propres. Ces vecteurs propres forment le nouvel espace de caractéristiques.
5. **Transformer les Données** : Projeter les données originales sur le nouvel espace de caractéristiques en utilisant les composantes principales sélectionnées.
L'ACP est largement utilisée pour la visualisation des données, la réduction du bruit et comme étape de prétraitement pour d'autres algorithmes d'apprentissage automatique. Elle aide à réduire la dimensionnalité des données tout en conservant sa structure essentielle.

#### Valeurs Propres et Vecteurs Propres

Une valeur propre est un scalaire qui indique la quantité de variance capturée par son vecteur propre correspondant. Un vecteur propre représente une direction dans l'espace des caractéristiques le long de laquelle les données varient le plus.

Imaginez qu'A est une matrice carrée, et v est un vecteur non nul tel que : `A * v = λ * v`
où :
- A est une matrice carrée comme [ [1, 2], [2, 1]] (par exemple, matrice de covariance)
- v est un vecteur propre (par exemple, [1, 1])

Alors, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` ce qui sera la valeur propre λ multipliée par le vecteur propre v, rendant la valeur propre λ = 3.

#### Valeurs Propres et Vecteurs Propres dans l'ACP

Expliquons cela avec un exemple. Imaginez que vous avez un ensemble de données avec beaucoup d'images en niveaux de gris de visages de 100x100 pixels. Chaque pixel peut être considéré comme une caractéristique, donc vous avez 10 000 caractéristiques par image (ou un vecteur de 10 000 composants par image). Si vous souhaitez réduire la dimensionnalité de cet ensemble de données en utilisant l'ACP, vous suivriez ces étapes :

1. **Standardisation** : Centrer les données en soustrayant la moyenne de chaque caractéristique (pixel) de l'ensemble de données.
2. **Matrice de Covariance** : Calculer la matrice de covariance des données standardisées, qui capture comment les caractéristiques (pixels) varient ensemble.
- Notez que la covariance entre deux variables (pixels dans ce cas) indique combien elles changent ensemble, donc l'idée ici est de découvrir quels pixels ont tendance à augmenter ou diminuer ensemble avec une relation linéaire.
- Par exemple, si le pixel 1 et le pixel 2 ont tendance à augmenter ensemble, la covariance entre eux sera positive.
- La matrice de covariance sera une matrice de 10 000x10 000 où chaque entrée représente la covariance entre deux pixels.
3. **Résoudre l'équation des valeurs propres** : L'équation des valeurs propres à résoudre est `C * v = λ * v` où C est la matrice de covariance, v est le vecteur propre, et λ est la valeur propre. Elle peut être résolue en utilisant des méthodes comme :
- **Décomposition en Valeurs Propres** : Effectuer une décomposition en valeurs propres sur la matrice de covariance pour obtenir les valeurs propres et les vecteurs propres.
- **Décomposition en Valeurs Singulières (SVD)** : Alternativement, vous pouvez utiliser la SVD pour décomposer la matrice de données en valeurs et vecteurs singuliers, ce qui peut également donner les composantes principales.
4. **Sélection des Composantes Principales** : Trier les valeurs propres par ordre décroissant et sélectionner les K vecteurs propres correspondants aux plus grandes valeurs propres. Ces vecteurs propres représentent les directions de variance maximale dans les données.

> [!TIP]
> *Cas d'utilisation en cybersécurité :* Un usage courant de l'ACP en sécurité est la réduction de caractéristiques pour la détection d'anomalies. Par exemple, un système de détection d'intrusions avec plus de 40 métriques réseau (comme les caractéristiques NSL-KDD) peut utiliser l'ACP pour réduire à quelques composants, résumant les données pour la visualisation ou l'alimentation dans des algorithmes de clustering. Les analystes pourraient tracer le trafic réseau dans l'espace des deux premières composantes principales pour voir si les attaques se séparent du trafic normal. L'ACP peut également aider à éliminer les caractéristiques redondantes (comme les octets envoyés par rapport aux octets reçus s'ils sont corrélés) pour rendre les algorithmes de détection plus robustes et plus rapides.

#### Hypothèses et Limitations

L'ACP suppose que **les axes principaux de variance sont significatifs** – c'est une méthode linéaire, donc elle capture les corrélations linéaires dans les données. Elle est non supervisée car elle utilise uniquement la covariance des caractéristiques. Les avantages de l'ACP incluent la réduction du bruit (les composants de petite variance correspondent souvent au bruit) et la décorrélation des caractéristiques. Elle est efficace sur le plan computationnel pour des dimensions modérément élevées et souvent une étape de prétraitement utile pour d'autres algorithmes (pour atténuer le fléau de la dimensionnalité). Une limitation est que l'ACP est limitée aux relations linéaires – elle ne capturera pas de structures non linéaires complexes (tandis que les autoencodeurs ou t-SNE pourraient le faire). De plus, les composants de l'ACP peuvent être difficiles à interpréter en termes de caractéristiques originales (ce sont des combinaisons de caractéristiques originales). En cybersécurité, il faut être prudent : une attaque qui ne cause qu'un changement subtil dans une caractéristique à faible variance pourrait ne pas apparaître dans les principales PC (puisque l'ACP priorise la variance, pas nécessairement l'« intérêt »).

<details>
<summary>Exemple -- Réduction des Dimensions des Données Réseau
</summary>

Supposons que nous ayons des journaux de connexion réseau avec plusieurs caractéristiques (par exemple, durées, octets, comptes). Nous allons générer un ensemble de données synthétique à 4 dimensions (avec une certaine corrélation entre les caractéristiques) et utiliser l'ACP pour le réduire à 2 dimensions pour la visualisation ou une analyse plus approfondie.
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
Ici, nous avons pris les clusters de trafic normal précédents et avons étendu chaque point de données avec deux caractéristiques supplémentaires (paquets et erreurs) qui sont corrélées avec les octets et la durée. PCA est ensuite utilisé pour compresser les 4 caractéristiques en 2 composants principaux. Nous imprimons le ratio de variance expliquée, qui pourrait montrer que, par exemple, >95% de la variance est capturée par 2 composants (ce qui signifie peu de perte d'information). La sortie montre également que la forme des données passe de (1500, 4) à (1500, 2). Les premiers points dans l'espace PCA sont donnés comme exemple. En pratique, on pourrait tracer data_2d pour vérifier visuellement si les clusters sont distinguables. Si une anomalie était présente, on pourrait la voir comme un point éloigné du cluster principal dans l'espace PCA. PCA aide donc à distiller des données complexes en une forme gérable pour l'interprétation humaine ou comme entrée pour d'autres algorithmes.

</details>


### Modèles de Mélange Gaussien (GMM)

Un Modèle de Mélange Gaussien suppose que les données sont générées à partir d'un mélange de **plusieurs distributions gaussiennes (normales) avec des paramètres inconnus**. En essence, c'est un modèle de clustering probabiliste : il essaie d'assigner en douceur chaque point à l'un des K composants gaussiens. Chaque composant gaussien k a un vecteur moyen (μ_k), une matrice de covariance (Σ_k) et un poids de mélange (π_k) qui représente la prévalence de ce cluster. Contrairement à K-Means qui fait des assignations "dures", GMM donne à chaque point une probabilité d'appartenir à chaque cluster.

L'ajustement de GMM se fait généralement via l'algorithme d'Expectation-Maximization (EM) :

- **Initialisation** : Commencer avec des estimations initiales pour les moyennes, les covariances et les coefficients de mélange (ou utiliser les résultats de K-Means comme point de départ).

- **Étape E (Expectation)** : Étant donné les paramètres actuels, calculer la responsabilité de chaque cluster pour chaque point : essentiellement `r_nk = P(z_k | x_n)` où z_k est la variable latente indiquant l'appartenance au cluster pour le point x_n. Cela se fait en utilisant le théorème de Bayes, où nous calculons la probabilité a posteriori de chaque point appartenant à chaque cluster en fonction des paramètres actuels. Les responsabilités sont calculées comme :
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
où :
- \( \pi_k \) est le coefficient de mélange pour le cluster k (probabilité a priori du cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) est la fonction de densité de probabilité gaussienne pour le point \( x_n \) donné la moyenne \( \mu_k \) et la covariance \( \Sigma_k \).

- **Étape M (Maximization)** : Mettre à jour les paramètres en utilisant les responsabilités calculées dans l'étape E :
- Mettre à jour chaque moyenne μ_k comme la moyenne pondérée des points, où les poids sont les responsabilités.
- Mettre à jour chaque covariance Σ_k comme la covariance pondérée des points assignés au cluster k.
- Mettre à jour les coefficients de mélange π_k comme la responsabilité moyenne pour le cluster k.

- **Itérer** les étapes E et M jusqu'à convergence (les paramètres se stabilisent ou l'amélioration de la vraisemblance est inférieure à un seuil).

Le résultat est un ensemble de distributions gaussiennes qui modélisent collectivement la distribution globale des données. Nous pouvons utiliser le GMM ajusté pour le clustering en assignant chaque point au gaussien avec la plus haute probabilité, ou conserver les probabilités pour l'incertitude. On peut également évaluer la vraisemblance de nouveaux points pour voir s'ils s'intègrent dans le modèle (utile pour la détection d'anomalies).

> [!TIP]
> *Cas d'utilisation en cybersécurité :* GMM peut être utilisé pour la détection d'anomalies en modélisant la distribution des données normales : tout point avec une probabilité très faible sous le mélange appris est signalé comme une anomalie. Par exemple, vous pourriez entraîner un GMM sur des caractéristiques de trafic réseau légitime ; une connexion d'attaque qui ne ressemble à aucun cluster appris aurait une faible vraisemblance. Les GMM sont également utilisés pour regrouper des activités où les clusters pourraient avoir des formes différentes – par exemple, regrouper les utilisateurs par profils de comportement, où les caractéristiques de chaque profil pourraient être de type gaussien mais avec leur propre structure de variance. Un autre scénario : dans la détection de phishing, les caractéristiques des e-mails légitimes pourraient former un cluster gaussien, le phishing connu un autre, et de nouvelles campagnes de phishing pourraient apparaître soit comme un gaussien séparé soit comme des points de faible vraisemblance par rapport au mélange existant.

#### Hypothèses et Limitations

GMM est une généralisation de K-Means qui incorpore la covariance, de sorte que les clusters peuvent être ellipsoïdaux (pas seulement sphériques). Il gère des clusters de tailles et de formes différentes si la covariance est complète. Le clustering doux est un avantage lorsque les frontières des clusters sont floues – par exemple, en cybersécurité, un événement pourrait avoir des traits de plusieurs types d'attaques ; GMM peut refléter cette incertitude avec des probabilités. GMM fournit également une estimation de densité probabiliste des données, utile pour détecter des valeurs aberrantes (points avec une faible vraisemblance sous tous les composants du mélange).

En revanche, GMM nécessite de spécifier le nombre de composants K (bien qu'on puisse utiliser des critères comme BIC/AIC pour le sélectionner). EM peut parfois converger lentement ou vers un optimum local, donc l'initialisation est importante (souvent, on exécute EM plusieurs fois). Si les données ne suivent pas réellement un mélange de gaussiennes, le modèle peut être un mauvais ajustement. Il y a aussi un risque qu'une gaussienne se rétrécisse pour ne couvrir qu'une valeur aberrante (bien que la régularisation ou les limites de covariance minimales puissent atténuer cela).


<details>
<summary>Exemple --  Clustering Doux & Scores d'Anomalie
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
Dans ce code, nous entraînons un GMM avec 3 Gaussiennes sur le trafic normal (en supposant que nous connaissons 3 profils de trafic légitime). Les moyennes et les covariances imprimées décrivent ces clusters (par exemple, une moyenne pourrait être autour de [50,500] correspondant au centre d'un cluster, etc.). Nous testons ensuite une connexion suspecte [duration=200, bytes=800]. Le predict_proba donne la probabilité que ce point appartienne à chacun des 3 clusters – nous nous attendrions à ce que ces probabilités soient très faibles ou fortement biaisées puisque [200,800] se situe loin des clusters normaux. Le score global score_samples (log-vraisemblance) est imprimé ; une valeur très basse indique que le point ne s'adapte pas bien au modèle, le signalant comme une anomalie. En pratique, on pourrait définir un seuil sur la log-vraisemblance (ou sur la probabilité maximale) pour décider si un point est suffisamment peu probable pour être considéré comme malveillant. GMM fournit donc une méthode fondée pour faire de la détection d'anomalies et produit également des clusters souples qui reconnaissent l'incertitude.

### Isolation Forest

**Isolation Forest** est un algorithme d'anomalie basé sur l'idée d'isoler aléatoirement des points. Le principe est que les anomalies sont rares et différentes, donc elles sont plus faciles à isoler que les points normaux. Un Isolation Forest construit de nombreux arbres d'isolation binaires (arbres de décision aléatoires) qui partitionnent les données de manière aléatoire. À chaque nœud d'un arbre, une caractéristique aléatoire est sélectionnée et une valeur de séparation aléatoire est choisie entre le min et le max de cette caractéristique pour les données dans ce nœud. Cette séparation divise les données en deux branches. L'arbre est développé jusqu'à ce que chaque point soit isolé dans sa propre feuille ou qu'une hauteur d'arbre maximale soit atteinte.

La détection d'anomalies est effectuée en observant la longueur du chemin de chaque point dans ces arbres aléatoires – le nombre de séparations nécessaires pour isoler le point. Intuitivement, les anomalies (valeurs aberrantes) tendent à être isolées plus rapidement car une séparation aléatoire est plus susceptible de séparer une valeur aberrante (qui se trouve dans une région sparse) qu'un point normal dans un cluster dense. L'Isolation Forest calcule un score d'anomalie à partir de la longueur moyenne du chemin sur tous les arbres : chemin moyen plus court → plus anormal. Les scores sont généralement normalisés entre [0,1] où 1 signifie très probablement une anomalie.

> [!TIP]
> *Cas d'utilisation en cybersécurité :* Les Isolation Forests ont été utilisés avec succès dans la détection d'intrusions et la détection de fraudes. Par exemple, entraînez un Isolation Forest sur des journaux de trafic réseau contenant principalement un comportement normal ; la forêt produira des chemins courts pour un trafic étrange (comme une IP utilisant un port inconnu ou un modèle de taille de paquet inhabituel), le signalant pour inspection. Comme il ne nécessite pas d'attaques étiquetées, il est adapté pour détecter des types d'attaques inconnus. Il peut également être déployé sur des données de connexion utilisateur pour détecter des prises de contrôle de compte (les heures ou emplacements de connexion anormaux sont rapidement isolés). Dans un cas d'utilisation, un Isolation Forest pourrait protéger une entreprise en surveillant les métriques système et en générant une alerte lorsqu'une combinaison de métriques (CPU, réseau, changements de fichiers) semble très différente (chemins d'isolement courts) des modèles historiques.

#### Hypothèses et Limitations

**Avantages** : L'Isolation Forest ne nécessite pas d'hypothèse de distribution ; il cible directement l'isolement. Il est efficace sur des données de haute dimension et de grands ensembles de données (complexité linéaire $O(n\log n)$ pour construire la forêt) puisque chaque arbre isole des points avec seulement un sous-ensemble de caractéristiques et de séparations. Il tend à bien gérer les caractéristiques numériques et peut être plus rapide que les méthodes basées sur la distance qui pourraient être $O(n^2)$. Il donne également automatiquement un score d'anomalie, vous pouvez donc définir un seuil pour les alertes (ou utiliser un paramètre de contamination pour décider automatiquement d'un seuil basé sur une fraction d'anomalie attendue).

**Limitations** : En raison de sa nature aléatoire, les résultats peuvent varier légèrement entre les exécutions (bien qu'avec suffisamment d'arbres, cela soit mineur). Si les données contiennent beaucoup de caractéristiques non pertinentes ou si les anomalies ne se différencient pas fortement dans une caractéristique, l'isolement pourrait ne pas être efficace (des séparations aléatoires pourraient isoler des points normaux par chance – cependant, la moyenne de nombreux arbres atténue cela). De plus, l'Isolation Forest suppose généralement que les anomalies sont une petite minorité (ce qui est généralement vrai dans les scénarios de cybersécurité).

<details>
<summary>Exemple -- Détection des valeurs aberrantes dans les journaux réseau
</summary>

Nous utiliserons l'ensemble de données de test précédent (qui contient des points normaux et quelques points d'attaque) et exécuterons un Isolation Forest pour voir s'il peut séparer les attaques. Nous supposerons que nous nous attendons à ce que ~15 % des données soient anormales (à des fins de démonstration).
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
Dans ce code, nous instancions `IsolationForest` avec 100 arbres et définissons `contamination=0.15` (ce qui signifie que nous nous attendons à environ 15 % d'anomalies ; le modèle fixera son seuil de score de sorte qu'environ 15 % des points soient signalés). Nous l'ajustons sur `X_test_if` qui contient un mélange de points normaux et d'attaques (note : normalement, vous ajusteriez sur des données d'entraînement et utiliseriez ensuite predict sur de nouvelles données, mais ici, à des fins d'illustration, nous ajustons et prédisons sur le même ensemble pour observer directement les résultats).

La sortie montre les étiquettes prédites pour les 20 premiers points (où -1 indique une anomalie). Nous imprimons également combien d'anomalies ont été détectées au total et quelques exemples de scores d'anomalie. Nous nous attendrions à ce qu'environ 18 des 120 points soient étiquetés -1 (puisque la contamination était de 15 %). Si nos 20 échantillons d'attaque sont vraiment les plus éloignés, la plupart d'entre eux devraient apparaître dans ces prédictions -1. Le score d'anomalie (la fonction de décision de l'Isolation Forest) est plus élevé pour les points normaux et plus bas (plus négatif) pour les anomalies – nous imprimons quelques valeurs pour voir la séparation. En pratique, on pourrait trier les données par score pour voir les principaux points aberrants et les examiner. L'Isolation Forest fournit donc un moyen efficace de filtrer de grandes données de sécurité non étiquetées et de sélectionner les instances les plus irrégulières pour une analyse humaine ou un examen automatisé supplémentaire.

### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** est une technique de réduction de dimensionnalité non linéaire spécifiquement conçue pour visualiser des données de haute dimension dans 2 ou 3 dimensions. Elle convertit les similarités entre les points de données en distributions de probabilité conjointe et essaie de préserver la structure des voisinages locaux dans la projection de dimension inférieure. En termes plus simples, t-SNE place des points dans (disons) 2D de sorte que des points similaires (dans l'espace original) se retrouvent proches les uns des autres et des points dissemblables se retrouvent éloignés avec une forte probabilité.

L'algorithme a deux étapes principales :

1. **Calculer les affinités par paires dans l'espace de haute dimension :** Pour chaque paire de points, t-SNE calcule une probabilité que l'on choisirait cette paire comme voisins (cela se fait en centrant une distribution gaussienne sur chaque point et en mesurant les distances – le paramètre de perplexité influence le nombre effectif de voisins considérés).
2. **Calculer les affinités par paires dans l'espace de basse dimension (par exemple, 2D) :** Initialement, les points sont placés aléatoirement en 2D. t-SNE définit une probabilité similaire pour les distances dans cette carte (en utilisant un noyau de distribution t de Student, qui a des queues plus lourdes que la gaussienne pour permettre aux points éloignés plus de liberté).
3. **Descente de gradient :** t-SNE déplace ensuite itérativement les points en 2D pour minimiser la divergence de Kullback–Leibler (KL) entre la distribution d'affinité en haute dimension et celle en basse dimension. Cela fait en sorte que l'agencement en 2D reflète autant que possible la structure en haute dimension – les points qui étaient proches dans l'espace original s'attireront, et ceux éloignés se repousseront, jusqu'à ce qu'un équilibre soit trouvé.

Le résultat est souvent un nuage de points visuellement significatif où les clusters dans les données deviennent apparents.

> [!TIP]
> *Cas d'utilisation en cybersécurité :* t-SNE est souvent utilisé pour **visualiser des données de sécurité de haute dimension pour une analyse humaine**. Par exemple, dans un centre d'opérations de sécurité, les analystes pourraient prendre un ensemble de données d'événements avec des dizaines de caractéristiques (numéros de port, fréquences, comptes d'octets, etc.) et utiliser t-SNE pour produire un graphique en 2D. Les attaques pourraient former leurs propres clusters ou se séparer des données normales dans ce graphique, les rendant plus faciles à identifier. Il a été appliqué à des ensembles de données de logiciels malveillants pour voir les regroupements de familles de logiciels malveillants ou à des données d'intrusion réseau où différents types d'attaques se regroupent distinctement, guidant une enquête plus approfondie. Essentiellement, t-SNE fournit un moyen de voir la structure dans les données cybernétiques qui serait autrement incompréhensible.

#### Hypothèses et limitations

t-SNE est excellent pour la découverte visuelle de motifs. Il peut révéler des clusters, des sous-clusters et des points aberrants que d'autres méthodes linéaires (comme PCA) pourraient ne pas détecter. Il a été utilisé dans la recherche en cybersécurité pour visualiser des données complexes comme les profils de comportement des logiciels malveillants ou les modèles de trafic réseau. Parce qu'il préserve la structure locale, il est bon pour montrer des regroupements naturels.

Cependant, t-SNE est computationnellement plus lourd (environ $O(n^2)$) donc il peut nécessiter un échantillonnage pour des ensembles de données très volumineux. Il a également des hyperparamètres (perplexité, taux d'apprentissage, itérations) qui peuvent affecter la sortie – par exemple, différentes valeurs de perplexité pourraient révéler des clusters à différentes échelles. Les graphiques t-SNE peuvent parfois être mal interprétés – les distances dans la carte ne sont pas directement significatives globalement (il se concentre sur le voisinage local, parfois les clusters peuvent apparaître artificiellement bien séparés). De plus, t-SNE est principalement destiné à la visualisation ; il ne fournit pas un moyen simple de projeter de nouveaux points de données sans recomputation, et il n'est pas destiné à être utilisé comme prétraitement pour la modélisation prédictive (UMAP est une alternative qui aborde certains de ces problèmes avec une vitesse plus rapide).

<details>
<summary>Exemple -- Visualisation des connexions réseau
</summary>

Nous allons utiliser t-SNE pour réduire un ensemble de données multi-caractéristiques à 2D. À titre d'illustration, prenons les données 4D précédentes (qui avaient 3 clusters naturels de trafic normal) et ajoutons quelques points d'anomalie. Nous exécutons ensuite t-SNE et (conceptuellement) visualisons les résultats.
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
Ici, nous avons combiné notre précédent ensemble de données normal en 4D avec une poignée de valeurs aberrantes extrêmes (les valeurs aberrantes ont une caractéristique (“durée”) définie très haut, etc., pour simuler un modèle étrange). Nous exécutons t-SNE avec une perplexité typique de 30. Les données de sortie data_2d ont une forme (1505, 2). Nous ne tracerons en fait pas dans ce texte, mais si nous le faisions, nous nous attendrions à voir peut-être trois clusters serrés correspondant aux 3 clusters normaux, et les 5 valeurs aberrantes apparaissant comme des points isolés loin de ces clusters. Dans un flux de travail interactif, nous pourrions colorer les points par leur étiquette (normal ou quel cluster, contre anomalie) pour vérifier cette structure. Même sans étiquettes, un analyste pourrait remarquer ces 5 points se trouvant dans un espace vide sur le graphique 2D et les signaler. Cela montre comment t-SNE peut être un puissant outil d'aide à la détection visuelle d'anomalies et à l'inspection des clusters dans les données de cybersécurité, complétant les algorithmes automatisés ci-dessus.

</details>


{{#include ../banners/hacktricks-training.md}}
