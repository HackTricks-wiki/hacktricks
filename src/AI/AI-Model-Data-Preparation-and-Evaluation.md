# Préparation et évaluation des données du modèle

{{#include ../banners/hacktricks-training.md}}

La préparation des données du modèle est une étape cruciale du pipeline de machine learning, car elle consiste à transformer les données brutes dans un format adapté à l'entraînement des modèles de machine learning. Ce processus comprend plusieurs étapes clés :

1. **Collecte des données** : Rassembler des données provenant de diverses sources, telles que des bases de données, des APIs ou des fichiers. Les données peuvent être structurées (par ex., des tableaux) ou non structurées (par ex., du texte ou des images).
2. **Nettoyage des données** : Supprimer ou corriger les points de données erronés, incomplets ou non pertinents. Cette étape peut impliquer la gestion des valeurs manquantes, la suppression des doublons et le filtrage des valeurs aberrantes.
3. **Transformation des données** : Convertir les données dans un format adapté à la modélisation. Cela peut inclure la normalisation, la mise à l'échelle, l'encodage des variables catégorielles et la création de nouvelles caractéristiques à l'aide de techniques telles que le feature engineering.
4. **Séparation des données** : Diviser le jeu de données en ensembles d'entraînement, de validation et de test afin de garantir que le modèle puisse bien se généraliser à des données inconnues.

## Collecte des données

La collecte des données consiste à rassembler des données provenant de diverses sources, notamment :
- **Bases de données** : Extraire des données de bases de données relationnelles (par ex., des bases de données SQL) ou de bases de données NoSQL (par ex., MongoDB).
- **APIs** : Récupérer des données depuis des APIs web, qui peuvent fournir des données en temps réel ou historiques.
- **Fichiers** : Lire des données depuis des fichiers dans des formats tels que CSV, JSON ou XML.
- **Web Scraping** : Collecter des données depuis des sites web à l'aide de techniques de web scraping.

Selon l'objectif du projet de machine learning, les données seront extraites et collectées depuis des sources pertinentes afin de garantir qu'elles soient représentatives du domaine du problème.

## Nettoyage des données <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

Le nettoyage des données est le processus d'identification et de correction des erreurs ou des incohérences dans le jeu de données. Cette étape est essentielle pour garantir la qualité des données utilisées lors de l'entraînement des modèles de machine learning. Les principales tâches de nettoyage des données comprennent :
- **Gestion des valeurs manquantes** : Identifier et traiter les points de données manquants. Les stratégies courantes comprennent :
- Supprimer les lignes ou les colonnes contenant des valeurs manquantes.
- Imputer les valeurs manquantes à l'aide de techniques telles que l'imputation par la moyenne, la médiane ou le mode.
- Utiliser des méthodes avancées telles que l'imputation par les K plus proches voisins (KNN) ou l'imputation par régression.
- **Suppression des doublons** : Identifier et supprimer les enregistrements en double afin de garantir l'unicité de chaque point de données.
- **Filtrage des valeurs aberrantes** : Détecter et supprimer les valeurs aberrantes susceptibles de fausser les performances du modèle. Des techniques telles que le Z-score, l'IQR (écart interquartile) ou les visualisations (par ex., les diagrammes en boîte) peuvent être utilisées pour identifier les valeurs aberrantes.

### Exemple de nettoyage des données
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
## Transformation des données <sup>[[1]](#references)</sup>

La transformation des données consiste à convertir les données dans un format adapté à la modélisation. Cette étape peut inclure :
- **Normalisation et standardisation** : mise à l'échelle des caractéristiques numériques dans une plage commune, généralement [0, 1] ou [-1, 1]. Cela peut améliorer la convergence des algorithmes d'optimisation.
- **Mise à l'échelle Min-Max** : redimensionnement des caractéristiques dans une plage fixe, généralement [0, 1]. Cela s'effectue à l'aide de la formule : `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalisation Z-Score** : standardisation des caractéristiques en soustrayant la moyenne et en divisant par l'écart type, ce qui produit une distribution avec une moyenne de 0 et un écart type de 1. Cela s'effectue à l'aide de la formule : `X' = (X - μ) / σ`, où μ est la moyenne et σ l'écart type.
- **Asymétrie et aplatissement** : ajustement des distributions des caractéristiques à l'aide de transformations telles que le logarithme, la racine carrée ou Box-Cox. Par exemple, une transformation logarithmique peut réduire l'asymétrie positive.
- **Normalisation des chaînes de caractères** : conversion des chaînes dans un format cohérent, par exemple :
- Conversion en minuscules
- Suppression des caractères spéciaux (en conservant ceux qui sont pertinents)
- Suppression des mots vides (mots courants qui ne contribuent pas au sens, tels que "the", "is" et "and")
- Suppression des mots trop fréquents et des mots trop rares (par exemple, les mots qui apparaissent dans plus de 90 % des documents ou moins de 5 fois dans le corpus)
- Suppression des espaces superflus
- Stemming/Lemmatisation : réduction des mots à leur forme de base ou racine (par exemple, "running" devient "run").

- **Encodage des variables catégorielles** : conversion des variables catégorielles en représentations numériques. Les techniques courantes incluent :
- **One-Hot Encoding** : création de colonnes binaires pour chaque catégorie.
- Par exemple, si une caractéristique possède les catégories "red", "green" et "blue", elle sera transformée en trois colonnes binaires : `is_red`(100), `is_green`(010) et `is_blue`(001).
- **Label Encoding** : attribution d'un entier unique à chaque catégorie.
- Par exemple, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding** : attribution d'entiers en fonction de l'ordre des catégories.
- Par exemple, si les catégories sont "low", "medium" et "high", elles peuvent être encodées respectivement par 0, 1 et 2.
- **Hashing Encoding** : utilisation d'une fonction de hachage pour convertir les catégories en vecteurs de taille fixe, ce qui peut être utile pour les variables catégorielles à forte cardinalité.
- Par exemple, si une caractéristique possède de nombreuses catégories uniques, le hashing peut réduire la dimensionnalité tout en préservant certaines informations sur les catégories.
- **Bag of Words (BoW)** : représentation des données textuelles sous forme de matrice de nombres ou de fréquences de mots, où chaque ligne correspond à un document et chaque colonne correspond à un mot unique du corpus.
- Par exemple, si le corpus contient les mots "cat", "dog" et "fish", un document contenant "cat" et "dog" serait représenté par [1, 1, 0]. Cette représentation spécifique est appelée "unigram" et ne capture pas l'ordre des mots ; elle perd donc les informations sémantiques.
- **Bigram/Trigram** : extension de BoW pour capturer des séquences de mots (bigrammes ou trigrammes) afin de conserver une partie du contexte. Par exemple, "cat and dog" serait représenté par un bigramme [1, 1] pour "cat and" et [1, 1] pour "and dog". Dans ce cas, davantage d'informations sémantiques sont recueillies (ce qui augmente la dimensionnalité de la représentation), mais uniquement pour 2 ou 3 mots à la fois.
- **TF-IDF (Term Frequency-Inverse Document Frequency)** : mesure statistique qui évalue l'importance d'un mot dans un document par rapport à une collection de documents (corpus). Elle combine la fréquence du terme (la fréquence d'apparition d'un mot dans un document) et la fréquence inverse du document (la rareté d'un mot dans l'ensemble des documents).
- Par exemple, si le mot "cat" apparaît fréquemment dans un document mais est rare dans l'ensemble du corpus, il aura un score TF-IDF élevé, indiquant son importance dans ce document.

- **Feature Engineering** : création de nouvelles caractéristiques à partir de caractéristiques existantes afin d'améliorer le pouvoir prédictif du modèle. Cela peut impliquer la combinaison de caractéristiques, l'extraction de composants de date/heure ou l'application de transformations spécifiques au domaine.

## Séparation des données <sup>[[3]](#references)</sup>

La séparation des données consiste à diviser le jeu de données en sous-ensembles distincts pour l'entraînement, la validation et les tests. Cette étape est essentielle pour évaluer les performances du modèle sur des données inédites et éviter le surapprentissage. Les stratégies courantes incluent :
- **Train-Test Split** : division du jeu de données en un ensemble d'entraînement (généralement 60 à 80 % des données), un ensemble de validation (10 à 15 % des données) pour ajuster les hyperparamètres, et un ensemble de test (10 à 15 % des données). Le modèle est entraîné sur l'ensemble d'entraînement et évalué sur l'ensemble de test.
- Par exemple, pour un jeu de données de 1000 échantillons, vous pouvez utiliser 700 échantillons pour l'entraînement, 150 pour la validation et 150 pour les tests.
- **Stratified Sampling** : garantie que la distribution des classes dans les ensembles d'entraînement et de test est similaire à celle du jeu de données global. Cette approche est particulièrement importante pour les jeux de données déséquilibrés, dans lesquels certaines classes peuvent comporter beaucoup moins d'échantillons que d'autres.
- **Time Series Split** : pour les données de séries temporelles, division du jeu de données selon le temps, en veillant à ce que l'ensemble d'entraînement contienne les données des périodes antérieures et que l'ensemble de test contienne les données des périodes ultérieures. Cela permet d'évaluer les performances du modèle sur les données futures.
- **K-Fold Cross-Validation** : division du jeu de données en K sous-ensembles (folds) et entraînement du modèle K fois, en utilisant à chaque fois un fold différent comme ensemble de test et les folds restants comme ensemble d'entraînement. Cela permet de s'assurer que le modèle est évalué sur différents sous-ensembles de données, fournissant ainsi une estimation plus robuste de ses performances.

## Évaluation du modèle <sup>[[4]](#references)</sup>

L'évaluation d'un modèle est le processus qui consiste à mesurer les performances d'un modèle de machine learning sur des données inédites. Elle implique l'utilisation de différentes métriques pour quantifier la capacité du modèle à se généraliser à de nouvelles données. Les métriques d'évaluation courantes incluent :

### Exactitude

L'exactitude correspond à la proportion d'instances correctement prédites par rapport au nombre total d'instances. Elle est calculée comme suit :
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> L’exactitude est une métrique simple et intuitive, mais elle peut ne pas convenir aux jeux de données déséquilibrés où une classe domine les autres, car elle peut donner une impression trompeuse des performances du modèle. Par exemple, si 90 % des données appartiennent à la classe A et que le modèle prédit toutes les instances comme appartenant à la classe A, il atteindra une exactitude de 90 %, mais il ne sera pas utile pour prédire la classe B.

### Précision

La précision est la proportion de prédictions positives correctes parmi toutes les prédictions positives effectuées par le modèle. Elle se calcule comme suit :
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> La précision est particulièrement importante dans les scénarios où les faux positifs sont coûteux ou indésirables, comme dans les diagnostics médicaux ou la détection de fraudes. Par exemple, si un modèle prédit 100 instances comme positives, mais que seulement 80 d’entre elles le sont réellement, la précision serait de 0,8 (80 %).

### Rappel (sensibilité)

Le rappel, également appelé sensibilité ou taux de vrais positifs, est la proportion de prédictions positives correctes parmi toutes les instances réellement positives. Il est calculé comme suit :
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> Le rappel est crucial dans les scénarios où les faux négatifs sont coûteux ou indésirables, comme dans la détection des maladies ou le filtrage des spams. Par exemple, si un modèle identifie 80 instances positives réelles sur 100, le rappel serait de 0,8 (80 %).

### Score F1

Le score F1 est la moyenne harmonique de la précision et du rappel, offrant un équilibre entre ces deux métriques. Il se calcule comme suit :
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> Le score F1 est particulièrement utile lorsqu'il s'agit de jeux de données déséquilibrés, car il prend en compte les faux positifs et les faux négatifs. Il fournit une métrique unique qui synthétise le compromis entre la précision et le rappel. Par exemple, si un modèle a une précision de 0.8 et un rappel de 0.6, le score F1 serait d'environ 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

La métrique ROC-AUC évalue la capacité du modèle à distinguer les classes en traçant le taux de vrais positifs (sensibilité) par rapport au taux de faux positifs pour différents seuils. L'aire sous la courbe ROC (AUC) quantifie les performances du modèle : une valeur de 1 indique une classification parfaite, tandis qu'une valeur de 0.5 indique une prédiction aléatoire.

> [!TIP]
> Le ROC-AUC est particulièrement utile pour les problèmes de classification binaire et fournit une vue d'ensemble des performances du modèle avec différents seuils. Il est moins sensible au déséquilibre des classes que l'accuracy. Par exemple, un modèle avec un AUC de 0.9 indique une forte capacité à distinguer les instances positives des instances négatives.

### Specificity

La spécificité, également appelée taux de vrais négatifs, correspond à la proportion de prédictions négatives correctes parmi toutes les instances réellement négatives. Elle se calcule comme suit :
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> La spécificité est importante dans les situations où les faux positifs sont coûteux ou indésirables, comme dans les tests médicaux ou la détection de fraude. Elle aide à évaluer dans quelle mesure le modèle identifie les instances négatives. Par exemple, si un modèle identifie correctement 90 instances négatives réelles sur 100, la spécificité serait de 0,9 (90 %).

### Coefficient de corrélation de Matthews (MCC)
Le coefficient de corrélation de Matthews (MCC) est une mesure de la qualité des classifications binaires. Il prend en compte les vrais et faux positifs ainsi que les vrais et faux négatifs, offrant une évaluation équilibrée des performances du modèle. Le MCC est calculé comme suit :
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
où :
- **TP** : Vrais positifs
- **TN** : Vrais négatifs
- **FP** : Faux positifs
- **FN** : Faux négatifs

> [!TIP]
> Le MCC varie de -1 à 1, où 1 indique une classification parfaite, 0 indique une prédiction aléatoire et -1 indique un désaccord total entre la prédiction et l’observation. Il est particulièrement utile pour les jeux de données déséquilibrés, car il prend en compte les quatre composantes de la matrice de confusion.

### Erreur absolue moyenne (MAE)
L’erreur absolue moyenne (MAE) est une métrique de régression qui mesure la différence absolue moyenne entre les valeurs prédites et les valeurs réelles. Elle est calculée comme suit :
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
où :
- **n** : Nombre d’instances
- **y_i** : Valeur réelle pour l’instance i
- **ŷ_i** : Valeur prédite pour l’instance i

> [!TIP]
> La MAE fournit une interprétation directe de l’erreur moyenne des prédictions, ce qui la rend facile à comprendre. Elle est moins sensible aux valeurs aberrantes que d’autres métriques comme la Mean Squared Error (MSE). Par exemple, si un modèle a une MAE de 5, cela signifie qu’en moyenne, les prédictions du modèle s’écartent des valeurs réelles de 5 unités.

### Matrice de confusion

La matrice de confusion est un tableau qui résume les performances d’un modèle de classification en affichant le nombre de prédictions true positive, true negative, false positive et false negative. Elle fournit une vue détaillée des performances du modèle pour chaque classe.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)** : Le modèle a correctement prédit la classe positive.
- **True Negative (TN)** : Le modèle a correctement prédit la classe négative.
- **False Positive (FP)** : Le modèle a incorrectement prédit la classe positive (erreur de type I).
- **False Negative (FN)** : Le modèle a incorrectement prédit la classe négative (erreur de type II).

La matrice de confusion peut être utilisée pour calculer des métriques d’évaluation telles que l’accuracy, la precision, le recall et le F1 score.

## References

- [1] [scikit-learn - Prétraitement des données](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputation des valeurs manquantes](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Validation croisée : évaluation des performances de l’estimateur](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Métriques et scoring](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
