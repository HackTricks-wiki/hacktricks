# Préparation et évaluation des données du modèle

{{#include ../banners/hacktricks-training.md}}

La préparation des données du modèle est une étape cruciale dans le pipeline d'apprentissage automatique, car elle consiste à transformer des données brutes en un format adapté à l'entraînement des modèles d'apprentissage automatique. Ce processus comprend plusieurs étapes clés :

1. **Collecte de données** : Rassembler des données provenant de diverses sources, telles que des bases de données, des API ou des fichiers. Les données peuvent être structurées (par exemple, des tables) ou non structurées (par exemple, du texte, des images).
2. **Nettoyage des données** : Supprimer ou corriger les points de données erronés, incomplets ou non pertinents. Cette étape peut impliquer la gestion des valeurs manquantes, la suppression des doublons et le filtrage des valeurs aberrantes.
3. **Transformation des données** : Convertir les données en un format approprié pour la modélisation. Cela peut inclure la normalisation, l'échelle, l'encodage des variables catégorielles et la création de nouvelles caractéristiques par des techniques comme l'ingénierie des caractéristiques.
4. **Division des données** : Diviser l'ensemble de données en ensembles d'entraînement, de validation et de test pour s'assurer que le modèle peut bien se généraliser à des données non vues.

## Collecte de données

La collecte de données implique de rassembler des données provenant de diverses sources, qui peuvent inclure :
- **Bases de données** : Extraire des données de bases de données relationnelles (par exemple, des bases de données SQL) ou de bases de données NoSQL (par exemple, MongoDB).
- **APIs** : Récupérer des données à partir d'APIs web, qui peuvent fournir des données en temps réel ou historiques.
- **Fichiers** : Lire des données à partir de fichiers dans des formats comme CSV, JSON ou XML.
- **Web Scraping** : Collecter des données à partir de sites web en utilisant des techniques de web scraping.

Selon l'objectif du projet d'apprentissage automatique, les données seront extraites et collectées à partir de sources pertinentes pour s'assurer qu'elles sont représentatives du domaine du problème.

## Nettoyage des données

Le nettoyage des données est le processus d'identification et de correction des erreurs ou des incohérences dans l'ensemble de données. Cette étape est essentielle pour garantir la qualité des données utilisées pour l'entraînement des modèles d'apprentissage automatique. Les tâches clés dans le nettoyage des données incluent :
- **Gestion des valeurs manquantes** : Identifier et traiter les points de données manquants. Les stratégies courantes incluent :
- Supprimer les lignes ou colonnes avec des valeurs manquantes.
- Imputer les valeurs manquantes en utilisant des techniques comme l'imputation par la moyenne, la médiane ou le mode.
- Utiliser des méthodes avancées comme l'imputation par K-plus proches voisins (KNN) ou l'imputation par régression.
- **Suppression des doublons** : Identifier et supprimer les enregistrements en double pour garantir que chaque point de données est unique.
- **Filtrage des valeurs aberrantes** : Détecter et supprimer les valeurs aberrantes qui peuvent fausser les performances du modèle. Des techniques comme le Z-score, l'IQR (intervalle interquartile) ou des visualisations (par exemple, des diagrammes en boîte) peuvent être utilisées pour identifier les valeurs aberrantes.

### Exemple de nettoyage des données
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
## Transformation des données

La transformation des données implique de convertir les données dans un format adapté à la modélisation. Cette étape peut inclure :
- **Normalisation & Standardisation** : Mise à l'échelle des caractéristiques numériques dans une plage commune, généralement [0, 1] ou [-1, 1]. Cela aide à améliorer la convergence des algorithmes d'optimisation.
- **Mise à l'échelle Min-Max** : Redimensionnement des caractéristiques dans une plage fixe, généralement [0, 1]. Cela se fait en utilisant la formule : `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalisation Z-Score** : Standardisation des caractéristiques en soustrayant la moyenne et en divisant par l'écart type, ce qui donne une distribution avec une moyenne de 0 et un écart type de 1. Cela se fait en utilisant la formule : `X' = (X - μ) / σ`, où μ est la moyenne et σ est l'écart type.
- **Asymétrie et Kurtosis** : Ajustement de la distribution des caractéristiques pour réduire l'asymétrie (asymétrie) et la kurtosis (pic). Cela peut être fait en utilisant des transformations comme logarithmique, racine carrée ou transformations de Box-Cox. Par exemple, si une caractéristique a une distribution asymétrique, l'application d'une transformation logarithmique peut aider à la normaliser.
- **Normalisation des chaînes** : Conversion des chaînes dans un format cohérent, tel que :
- Mise en minuscules
- Suppression des caractères spéciaux (en gardant ceux qui sont pertinents)
- Suppression des mots vides (mots courants qui ne contribuent pas au sens, comme "le", "est", "et")
- Suppression des mots trop fréquents et trop rares (par exemple, des mots qui apparaissent dans plus de 90 % des documents ou moins de 5 fois dans le corpus)
- Suppression des espaces
- Stemming/Lemmatisation : Réduction des mots à leur forme de base ou racine (par exemple, "courant" à "courir").

- **Encodage des variables catégorielles** : Conversion des variables catégorielles en représentations numériques. Les techniques courantes incluent :
- **Encodage One-Hot** : Création de colonnes binaires pour chaque catégorie.
- Par exemple, si une caractéristique a les catégories "rouge", "vert" et "bleu", elle sera transformée en trois colonnes binaires : `is_red`(100), `is_green`(010), et `is_blue`(001).
- **Encodage par étiquette** : Attribution d'un entier unique à chaque catégorie.
- Par exemple, "rouge" = 0, "vert" = 1, "bleu" = 2.
- **Encodage ordinal** : Attribution d'entiers en fonction de l'ordre des catégories.
- Par exemple, si les catégories sont "bas", "moyen" et "élevé", elles peuvent être encodées comme 0, 1 et 2, respectivement.
- **Encodage par hachage** : Utilisation d'une fonction de hachage pour convertir les catégories en vecteurs de taille fixe, ce qui peut être utile pour les variables catégorielles à haute cardinalité.
- Par exemple, si une caractéristique a de nombreuses catégories uniques, le hachage peut réduire la dimensionnalité tout en préservant certaines informations sur les catégories.
- **Sac de mots (BoW)** : Représentation des données textuelles sous forme de matrice de comptes ou de fréquences de mots, où chaque ligne correspond à un document et chaque colonne correspond à un mot unique dans le corpus.
- Par exemple, si le corpus contient les mots "chat", "chien" et "poisson", un document contenant "chat" et "chien" serait représenté comme [1, 1, 0]. Cette représentation spécifique est appelée "unigramme" et ne capture pas l'ordre des mots, donc elle perd des informations sémantiques.
- **Bigramme/Trigramme** : Extension de BoW pour capturer des séquences de mots (bigrams ou trigrams) afin de conserver un certain contexte. Par exemple, "chat et chien" serait représenté comme un bigramme [1, 1] pour "chat et" et [1, 1] pour "et chien". Dans ces cas, plus d'informations sémantiques sont recueillies (augmentant la dimensionnalité de la représentation) mais seulement pour 2 ou 3 mots à la fois.
- **TF-IDF (Fréquence de terme-Fréquence inverse de document)** : Une mesure statistique qui évalue l'importance d'un mot dans un document par rapport à une collection de documents (corpus). Elle combine la fréquence des termes (à quelle fréquence un mot apparaît dans un document) et la fréquence inverse des documents (à quel point un mot est rare dans tous les documents).
- Par exemple, si le mot "chat" apparaît fréquemment dans un document mais est rare dans l'ensemble du corpus, il aura un score TF-IDF élevé, indiquant son importance dans ce document.

- **Ingénierie des caractéristiques** : Création de nouvelles caractéristiques à partir de celles existantes pour améliorer le pouvoir prédictif du modèle. Cela peut impliquer la combinaison de caractéristiques, l'extraction de composants date/heure ou l'application de transformations spécifiques au domaine.

## Division des données

La division des données implique de diviser l'ensemble de données en sous-ensembles distincts pour l'entraînement, la validation et le test. Cela est essentiel pour évaluer la performance du modèle sur des données non vues et prévenir le surapprentissage. Les stratégies courantes incluent :
- **Division Train-Test** : Division de l'ensemble de données en un ensemble d'entraînement (généralement 60-80 % des données), un ensemble de validation (10-15 % des données) pour ajuster les hyperparamètres, et un ensemble de test (10-15 % des données). Le modèle est entraîné sur l'ensemble d'entraînement et évalué sur l'ensemble de test.
- Par exemple, si vous avez un ensemble de données de 1000 échantillons, vous pourriez utiliser 700 échantillons pour l'entraînement, 150 pour la validation et 150 pour le test.
- **Échantillonnage stratifié** : S'assurer que la distribution des classes dans les ensembles d'entraînement et de test est similaire à l'ensemble de données global. Cela est particulièrement important pour les ensembles de données déséquilibrés, où certaines classes peuvent avoir significativement moins d'échantillons que d'autres.
- **Division par séries temporelles** : Pour les données de séries temporelles, l'ensemble de données est divisé en fonction du temps, en veillant à ce que l'ensemble d'entraînement contienne des données de périodes antérieures et l'ensemble de test contienne des données de périodes ultérieures. Cela aide à évaluer la performance du modèle sur des données futures.
- **Validation croisée K-Fold** : Division de l'ensemble de données en K sous-ensembles (pli) et entraînement du modèle K fois, chaque fois en utilisant un pli différent comme ensemble de test et les plis restants comme ensemble d'entraînement. Cela aide à s'assurer que le modèle est évalué sur différents sous-ensembles de données, fournissant une estimation plus robuste de sa performance.

## Évaluation du modèle

L'évaluation du modèle est le processus d'évaluation de la performance d'un modèle d'apprentissage automatique sur des données non vues. Elle implique l'utilisation de diverses métriques pour quantifier à quel point le modèle se généralise à de nouvelles données. Les métriques d'évaluation courantes incluent :

### Précision

La précision est la proportion d'instances correctement prédites par rapport au nombre total d'instances. Elle est calculée comme :
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> La précision est une métrique simple et intuitive, mais elle peut ne pas être adaptée aux ensembles de données déséquilibrés où une classe domine les autres, car elle peut donner une impression trompeuse de la performance du modèle. Par exemple, si 90 % des données appartiennent à la classe A et que le modèle prédit toutes les instances comme classe A, il atteindra une précision de 90 %, mais cela ne sera pas utile pour prédire la classe B.

### Précision

La précision est la proportion de prédictions positives vraies par rapport à toutes les prédictions positives faites par le modèle. Elle est calculée comme :
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> La précision est particulièrement importante dans des scénarios où les faux positifs sont coûteux ou indésirables, comme dans les diagnostics médicaux ou la détection de fraude. Par exemple, si un modèle prédit 100 instances comme positives, mais que seulement 80 d'entre elles sont réellement positives, la précision serait de 0,8 (80 %).

### Rappel (Sensibilité)

Le rappel, également connu sous le nom de sensibilité ou taux de vrais positifs, est la proportion de prédictions vraies positives par rapport à toutes les instances positives réelles. Il est calculé comme :
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Le rappel est crucial dans les scénarios où les faux négatifs sont coûteux ou indésirables, comme dans la détection de maladies ou le filtrage de spam. Par exemple, si un modèle identifie 80 des 100 instances positives réelles, le rappel serait de 0,8 (80 %).

### F1 Score

Le score F1 est la moyenne harmonique de la précision et du rappel, fournissant un équilibre entre les deux métriques. Il est calculé comme :
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Le score F1 est particulièrement utile lorsqu'on traite des ensembles de données déséquilibrés, car il prend en compte à la fois les faux positifs et les faux négatifs. Il fournit une métrique unique qui capture le compromis entre la précision et le rappel. Par exemple, si un modèle a une précision de 0.8 et un rappel de 0.6, le score F1 serait d'environ 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

La métrique ROC-AUC évalue la capacité du modèle à distinguer entre les classes en traçant le taux de vrais positifs (sensibilité) par rapport au taux de faux positifs à divers réglages de seuil. L'aire sous la courbe ROC (AUC) quantifie la performance du modèle, avec une valeur de 1 indiquant une classification parfaite et une valeur de 0.5 indiquant un tirage aléatoire.

> [!TIP]
> ROC-AUC est particulièrement utile pour les problèmes de classification binaire et fournit une vue d'ensemble complète de la performance du modèle à travers différents seuils. Il est moins sensible au déséquilibre des classes par rapport à la précision. Par exemple, un modèle avec un AUC de 0.9 indique qu'il a une grande capacité à distinguer entre les instances positives et négatives.

### Spécificité

La spécificité, également connue sous le nom de taux de vrais négatifs, est la proportion de prédictions de vrais négatifs par rapport à toutes les instances négatives réelles. Elle est calculée comme :
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> La spécificité est importante dans les scénarios où les faux positifs sont coûteux ou indésirables, comme dans les tests médicaux ou la détection de fraude. Elle aide à évaluer dans quelle mesure le modèle identifie les instances négatives. Par exemple, si un modèle identifie correctement 90 des 100 instances négatives réelles, la spécificité serait de 0,9 (90 %).

### Matthews Correlation Coefficient (MCC)
Le Matthews Correlation Coefficient (MCC) est une mesure de la qualité des classifications binaires. Il prend en compte les vrais et faux positifs et négatifs, fournissant une vue équilibrée de la performance du modèle. Le MCC est calculé comme :
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
où :
- **TP** : Vrais Positifs
- **TN** : Vrais Négatifs
- **FP** : Faux Positifs
- **FN** : Faux Négatifs

> [!TIP]
> Le MCC varie de -1 à 1, où 1 indique une classification parfaite, 0 indique une supposition aléatoire, et -1 indique un désaccord total entre la prédiction et l'observation. Il est particulièrement utile pour les ensembles de données déséquilibrés, car il prend en compte les quatre composants de la matrice de confusion.

### Erreur Absolue Moyenne (MAE)
L'Erreur Absolue Moyenne (MAE) est une métrique de régression qui mesure la différence absolue moyenne entre les valeurs prédites et les valeurs réelles. Elle est calculée comme :
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
où :
- **n** : Nombre d'instances
- **y_i** : Valeur réelle pour l'instance i
- **ŷ_i** : Valeur prédite pour l'instance i

> [!TIP]
> MAE fournit une interprétation simple de l'erreur moyenne dans les prédictions, ce qui la rend facile à comprendre. Elle est moins sensible aux valeurs aberrantes par rapport à d'autres métriques comme l'erreur quadratique moyenne (MSE). Par exemple, si un modèle a un MAE de 5, cela signifie qu'en moyenne, les prédictions du modèle s'écartent des valeurs réelles de 5 unités.

### Matrice de confusion

La matrice de confusion est un tableau qui résume la performance d'un modèle de classification en montrant les comptes de vraies positives, vraies négatives, fausses positives et fausses négatives. Elle fournit une vue détaillée de la performance du modèle sur chaque classe.

|               | Prédit Positif     | Prédit Négatif     |
|---------------|---------------------|---------------------|
| Réel Positif  | Vrai Positif (TP)   | Fausse Négative (FN)|
| Réel Négatif  | Fausse Positive (FP) | Vrai Négatif (TN)  |

- **Vrai Positif (TP)** : Le modèle a correctement prédit la classe positive.
- **Vrai Négatif (TN)** : Le modèle a correctement prédit la classe négative.
- **Fausse Positive (FP)** : Le modèle a incorrectement prédit la classe positive (erreur de type I).
- **Fausse Négative (FN)** : Le modèle a incorrectement prédit la classe négative (erreur de type II).

La matrice de confusion peut être utilisée pour calculer diverses métriques d'évaluation, telles que la précision, le rappel et le score F1.

{{#include ../banners/hacktricks-training.md}}
