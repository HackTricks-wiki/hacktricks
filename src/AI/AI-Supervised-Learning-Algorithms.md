# Algorithmes d'apprentissage supervisé

{{#include ../banners/hacktricks-training.md}}

## Informations de base

L'apprentissage supervisé utilise des données étiquetées pour entraîner des modèles capables de faire des prédictions sur de nouvelles entrées non vues. En cybersécurité, l'apprentissage automatique supervisé est largement appliqué à des tâches telles que la détection d'intrusions (classifiant le trafic réseau comme *normal* ou *attaque*), la détection de logiciels malveillants (distinguant les logiciels malveillants des logiciels bénins), la détection de phishing (identifiant des sites Web ou des e-mails frauduleux) et le filtrage de spam, entre autres. Chaque algorithme a ses forces et est adapté à différents types de problèmes (classification ou régression). Ci-dessous, nous examinons les principaux algorithmes d'apprentissage supervisé, expliquons comment ils fonctionnent et démontrons leur utilisation sur de véritables ensembles de données en cybersécurité. Nous discutons également de la manière dont la combinaison de modèles (apprentissage par ensemble) peut souvent améliorer les performances prédictives.

## Algorithmes

-   **Régression linéaire :** Un algorithme de régression fondamental pour prédire des résultats numériques en ajustant une équation linéaire aux données.

-   **Régression logistique :** Un algorithme de classification (malgré son nom) qui utilise une fonction logistique pour modéliser la probabilité d'un résultat binaire.

-   **Arbres de décision :** Modèles structurés en arbre qui divisent les données par caractéristiques pour faire des prédictions ; souvent utilisés pour leur interprétabilité.

-   **Forêts aléatoires :** Un ensemble d'arbres de décision (via le bagging) qui améliore la précision et réduit le surapprentissage.

-   **Machines à vecteurs de support (SVM) :** Classificateurs à marge maximale qui trouvent l'hyperplan séparateur optimal ; peuvent utiliser des noyaux pour des données non linéaires.

-   **Naive Bayes :** Un classificateur probabiliste basé sur le théorème de Bayes avec une hypothèse d'indépendance des caractéristiques, utilisé de manière célèbre dans le filtrage de spam.

-   **k-Plus proches voisins (k-NN) :** Un classificateur simple "basé sur les instances" qui étiquette un échantillon en fonction de la classe majoritaire de ses voisins les plus proches.

-   **Machines de gradient boosting :** Modèles d'ensemble (par exemple, XGBoost, LightGBM) qui construisent un prédicteur fort en ajoutant séquentiellement des apprenants plus faibles (typiquement des arbres de décision).

Chaque section ci-dessous fournit une description améliorée de l'algorithme et un **exemple de code Python** utilisant des bibliothèques comme `pandas` et `scikit-learn` (et `PyTorch` pour l'exemple de réseau de neurones). Les exemples utilisent des ensembles de données en cybersécurité disponibles publiquement (tels que NSL-KDD pour la détection d'intrusions et un ensemble de données de sites Web de phishing) et suivent une structure cohérente :

1.  **Charger l'ensemble de données** (télécharger via URL si disponible).

2.  **Prétraiter les données** (par exemple, encoder les caractéristiques catégorielles, mettre à l'échelle les valeurs, diviser en ensembles d'entraînement/test).

3.  **Entraîner le modèle** sur les données d'entraînement.

4.  **Évaluer** sur un ensemble de test en utilisant des métriques : précision, rappel, F1-score et ROC AUC pour la classification (et erreur quadratique moyenne pour la régression).

Plongeons dans chaque algorithme :

### Régression linéaire

La régression linéaire est un **algorithme de régression** utilisé pour prédire des valeurs numériques continues. Elle suppose une relation linéaire entre les caractéristiques d'entrée (variables indépendantes) et la sortie (variable dépendante). Le modèle tente d'ajuster une ligne droite (ou un hyperplan dans des dimensions supérieures) qui décrit le mieux la relation entre les caractéristiques et la cible. Cela se fait généralement en minimisant la somme des erreurs au carré entre les valeurs prédites et réelles (méthode des moindres carrés ordinaires).

La forme la plus simple de représenter la régression linéaire est avec une ligne :
```plaintext
y = mx + b
```
Où :

- `y` est la valeur prédite (sortie)
- `m` est la pente de la ligne (coefficient)
- `x` est la caractéristique d'entrée
- `b` est l'ordonnée à l'origine

L'objectif de la régression linéaire est de trouver la ligne de meilleur ajustement qui minimise la différence entre les valeurs prédites et les valeurs réelles dans l'ensemble de données. Bien sûr, c'est très simple, ce serait une ligne droite séparant 2 catégories, mais si plus de dimensions sont ajoutées, la ligne devient plus complexe :
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Cas d'utilisation en cybersécurité :* La régression linéaire elle-même est moins courante pour les tâches de sécurité de base (qui sont souvent des classifications), mais elle peut être appliquée pour prédire des résultats numériques. Par exemple, on pourrait utiliser la régression linéaire pour **prédire le volume de trafic réseau** ou **estimer le nombre d'attaques sur une période donnée** en se basant sur des données historiques. Elle pourrait également prédire un score de risque ou le temps attendu jusqu'à la détection d'une attaque, étant donné certains indicateurs système. En pratique, les algorithmes de classification (comme la régression logistique ou les arbres) sont plus fréquemment utilisés pour détecter des intrusions ou des malwares, mais la régression linéaire sert de fondation et est utile pour des analyses orientées régression.

#### **Caractéristiques clés de la régression linéaire :**

-   **Type de problème :** Régression (prédiction de valeurs continues). Pas adapté pour une classification directe à moins qu'un seuil ne soit appliqué à la sortie.

-   **Interprétabilité :** Élevée -- les coefficients sont simples à interpréter, montrant l'effet linéaire de chaque caractéristique.

-   **Avantages :** Simple et rapide ; une bonne référence pour les tâches de régression ; fonctionne bien lorsque la relation réelle est approximativement linéaire.

-   **Limitations :** Ne peut pas capturer des relations complexes ou non linéaires (sans ingénierie des caractéristiques manuelle) ; sujet à un sous-ajustement si les relations sont non linéaires ; sensible aux valeurs aberrantes qui peuvent fausser les résultats.

-   **Trouver le meilleur ajustement :** Pour trouver la ligne de meilleur ajustement qui sépare les catégories possibles, nous utilisons une méthode appelée **Moindres Carrés Ordinaires (OLS)**. Cette méthode minimise la somme des différences au carré entre les valeurs observées et les valeurs prédites par le modèle linéaire.

<details>
<summary>Exemple -- Prédiction de la durée de connexion (régression) dans un ensemble de données d'intrusion
</summary>
Ci-dessous, nous démontrons la régression linéaire en utilisant l'ensemble de données de cybersécurité NSL-KDD. Nous traiterons cela comme un problème de régression en prédisant la `durée` des connexions réseau en fonction d'autres caractéristiques. (En réalité, `durée` est une caractéristique de NSL-KDD ; nous l'utilisons ici juste pour illustrer la régression.) Nous chargeons l'ensemble de données, le prétraitons (encodons les caractéristiques catégorielles), entraînons un modèle de régression linéaire et évaluons l'erreur quadratique moyenne (MSE) et le score R² sur un ensemble de test.
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
Dans cet exemple, le modèle de régression linéaire essaie de prédire la `duration` de connexion à partir d'autres caractéristiques du réseau. Nous mesurons la performance avec l'erreur quadratique moyenne (MSE) et R². Un R² proche de 1,0 indiquerait que le modèle explique la plupart de la variance dans la `duration`, tandis qu'un R² faible ou négatif indique un mauvais ajustement. (Ne soyez pas surpris si le R² est faible ici -- prédire la `duration` peut être difficile à partir des caractéristiques données, et la régression linéaire peut ne pas capturer les motifs s'ils sont complexes.)
</details>

### Régression Logistique

La régression logistique est un algorithme de **classification** qui modélise la probabilité qu'une instance appartienne à une classe particulière (typiquement la classe "positive"). Malgré son nom, la régression *logistique* est utilisée pour des résultats discrets (contrairement à la régression linéaire qui est pour des résultats continus). Elle est particulièrement utilisée pour la **classification binaire** (deux classes, par exemple, malveillant vs. bénin), mais elle peut être étendue à des problèmes multi-classes (en utilisant des approches softmax ou un contre tous).

La régression logistique utilise la fonction logistique (également connue sous le nom de fonction sigmoïde) pour mapper les valeurs prédites à des probabilités. Notez que la fonction sigmoïde est une fonction avec des valeurs comprises entre 0 et 1 qui croît en courbe en S selon les besoins de la classification, ce qui est utile pour les tâches de classification binaire. Par conséquent, chaque caractéristique de chaque entrée est multipliée par son poids assigné, et le résultat est passé à travers la fonction sigmoïde pour produire une probabilité :
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Où :

- `p(y=1|x)` est la probabilité que la sortie `y` soit 1 étant donné l'entrée `x`
- `e` est la base du logarithme naturel
- `z` est une combinaison linéaire des caractéristiques d'entrée, généralement représentée comme `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Notez comment, encore une fois, dans sa forme la plus simple, c'est une ligne droite, mais dans des cas plus complexes, cela devient un hyperplan avec plusieurs dimensions (une par caractéristique).

> [!TIP]
> *Cas d'utilisation en cybersécurité :* Parce que de nombreux problèmes de sécurité sont essentiellement des décisions oui/non, la régression logistique est largement utilisée. Par exemple, un système de détection d'intrusion pourrait utiliser la régression logistique pour décider si une connexion réseau est une attaque en fonction des caractéristiques de cette connexion. Dans la détection de phishing, la régression logistique peut combiner des caractéristiques d'un site web (longueur de l'URL, présence du symbole "@", etc.) en une probabilité d'être un phishing. Elle a été utilisée dans les filtres anti-spam de première génération et reste une base solide pour de nombreuses tâches de classification.

#### Régression Logistique pour la classification non binaire

La régression logistique est conçue pour la classification binaire, mais elle peut être étendue pour gérer des problèmes multi-classes en utilisant des techniques comme **one-vs-rest** (OvR) ou **régression softmax**. Dans OvR, un modèle de régression logistique séparé est entraîné pour chaque classe, la traitant comme la classe positive contre toutes les autres. La classe avec la probabilité prédite la plus élevée est choisie comme prédiction finale. La régression softmax généralise la régression logistique à plusieurs classes en appliquant la fonction softmax à la couche de sortie, produisant une distribution de probabilité sur toutes les classes.

#### **Caractéristiques clés de la régression logistique :**

-   **Type de problème :** Classification (généralement binaire). Elle prédit la probabilité de la classe positive.

-   **Interprétabilité :** Élevée -- comme la régression linéaire, les coefficients des caractéristiques peuvent indiquer comment chaque caractéristique influence les log-odds du résultat. Cette transparence est souvent appréciée en sécurité pour comprendre quels facteurs contribuent à une alerte.

-   **Avantages :** Simple et rapide à entraîner ; fonctionne bien lorsque la relation entre les caractéristiques et les log-odds du résultat est linéaire. Produit des probabilités, permettant une évaluation des risques. Avec une régularisation appropriée, elle se généralise bien et peut mieux gérer la multicolinéarité que la régression linéaire simple.

-   **Limitations :** Suppose une frontière de décision linéaire dans l'espace des caractéristiques (échoue si la véritable frontière est complexe/non linéaire). Elle peut sous-performer sur des problèmes où les interactions ou les effets non linéaires sont critiques, à moins que vous n'ajoutiez manuellement des caractéristiques polynomiales ou d'interaction. De plus, la régression logistique est moins efficace si les classes ne sont pas facilement séparables par une combinaison linéaire de caractéristiques.


<details>
<summary>Exemple -- Détection de sites Web de phishing avec régression logistique :</summary>

Nous utiliserons un **jeu de données de sites Web de phishing** (provenant du dépôt UCI) qui contient des caractéristiques extraites de sites Web (comme si l'URL a une adresse IP, l'âge du domaine, la présence d'éléments suspects dans le HTML, etc.) et une étiquette indiquant si le site est un phishing ou légitime. Nous entraînons un modèle de régression logistique pour classer les sites Web, puis évaluons sa précision, son rappel, son score F1 et son ROC AUC sur un échantillon de test.
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
Dans cet exemple de détection de phishing, la régression logistique produit une probabilité pour chaque site web d'être un phishing. En évaluant la précision, le rappel et le F1, nous avons une idée de la performance du modèle. Par exemple, un rappel élevé signifierait qu'il attrape la plupart des sites de phishing (important pour la sécurité afin de minimiser les attaques manquées), tandis qu'une haute précision signifie qu'il a peu de fausses alertes (important pour éviter la fatigue des analystes). L'AUC ROC (Area Under the ROC Curve) donne une mesure de performance indépendante du seuil (1.0 est idéal, 0.5 n'est pas mieux que le hasard). La régression logistique fonctionne souvent bien sur de telles tâches, mais si la frontière de décision entre les sites de phishing et légitimes est complexe, des modèles non linéaires plus puissants pourraient être nécessaires.

</details>

### Arbres de Décision

Un arbre de décision est un **algorithme d'apprentissage supervisé** polyvalent qui peut être utilisé pour des tâches de classification et de régression. Il apprend un modèle hiérarchique en forme d'arbre de décisions basé sur les caractéristiques des données. Chaque nœud interne de l'arbre représente un test sur une caractéristique particulière, chaque branche représente un résultat de ce test, et chaque nœud feuille représente une classe prédite (pour la classification) ou une valeur (pour la régression).

Pour construire un arbre, des algorithmes comme CART (Classification and Regression Tree) utilisent des mesures telles que **l'impureté de Gini** ou **le gain d'information (entropie)** pour choisir la meilleure caractéristique et le seuil pour diviser les données à chaque étape. L'objectif à chaque division est de partitionner les données pour augmenter l'homogénéité de la variable cible dans les sous-ensembles résultants (pour la classification, chaque nœud vise à être aussi pur que possible, contenant principalement une seule classe).

Les arbres de décision sont **hautement interprétables** -- on peut suivre le chemin de la racine à la feuille pour comprendre la logique derrière une prédiction (par exemple, *"SI `service = telnet` ET `src_bytes > 1000` ET `failed_logins > 3` ALORS classer comme attaque"*). Cela est précieux en cybersécurité pour expliquer pourquoi une certaine alerte a été déclenchée. Les arbres peuvent naturellement gérer à la fois des données numériques et catégorielles et nécessitent peu de prétraitement (par exemple, la mise à l'échelle des caractéristiques n'est pas nécessaire).

Cependant, un seul arbre de décision peut facilement surajuster les données d'entraînement, surtout s'il est développé en profondeur (beaucoup de divisions). Des techniques comme l'élagage (limiter la profondeur de l'arbre ou exiger un nombre minimum d'échantillons par feuille) sont souvent utilisées pour prévenir le surajustement.

Il y a 3 composants principaux d'un arbre de décision :
- **Nœud Racine** : Le nœud supérieur de l'arbre, représentant l'ensemble du jeu de données.
- **Nœuds Internes** : Nœuds qui représentent des caractéristiques et des décisions basées sur ces caractéristiques.
- **Nœuds Feuilles** : Nœuds qui représentent le résultat final ou la prédiction.

Un arbre pourrait finir par ressembler à ceci :
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Cas d'utilisation en cybersécurité :* Les arbres de décision ont été utilisés dans les systèmes de détection d'intrusions pour dériver des **règles** permettant d'identifier les attaques. Par exemple, les premiers IDS comme les systèmes basés sur ID3/C4.5 généraient des règles lisibles par l'homme pour distinguer le trafic normal du trafic malveillant. Ils sont également utilisés dans l'analyse des logiciels malveillants pour décider si un fichier est malveillant en fonction de ses attributs (taille du fichier, entropie de section, appels API, etc.). La clarté des arbres de décision les rend utiles lorsque la transparence est nécessaire -- un analyste peut inspecter l'arbre pour valider la logique de détection.

#### **Caractéristiques clés des arbres de décision :**

-   **Type de problème :** Classification et régression. Couramment utilisés pour la classification des attaques par rapport au trafic normal, etc.

-   **Interprétabilité :** Très élevée -- les décisions du modèle peuvent être visualisées et comprises comme un ensemble de règles si-alors. C'est un avantage majeur en matière de sécurité pour la confiance et la vérification du comportement du modèle.

-   **Avantages :** Peut capturer des relations non linéaires et des interactions entre les caractéristiques (chaque division peut être considérée comme une interaction). Pas besoin de mettre à l'échelle les caractéristiques ou d'encoder en one-hot les variables catégorielles -- les arbres gèrent cela nativement. Inférence rapide (la prédiction consiste simplement à suivre un chemin dans l'arbre).

-   **Limitations :** Susceptibles au surapprentissage s'ils ne sont pas contrôlés (un arbre profond peut mémoriser l'ensemble d'entraînement). Ils peuvent être instables -- de petits changements dans les données peuvent conduire à une structure d'arbre différente. En tant que modèles uniques, leur précision peut ne pas correspondre à des méthodes plus avancées (les ensembles comme les forêts aléatoires ont généralement de meilleures performances en réduisant la variance).

-   **Trouver la meilleure division :**
- **Impureté de Gini :** Mesure l'impureté d'un nœud. Une impureté de Gini plus faible indique une meilleure division. La formule est :

```plaintext
Gini = 1 - Σ(p_i^2)
```

Où `p_i` est la proportion d'instances dans la classe `i`.

- **Entropie :** Mesure l'incertitude dans l'ensemble de données. Une entropie plus faible indique une meilleure division. La formule est :

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Où `p_i` est la proportion d'instances dans la classe `i`.

- **Gain d'information :** La réduction de l'entropie ou de l'impureté de Gini après une division. Plus le gain d'information est élevé, meilleure est la division. Il est calculé comme suit :

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

De plus, un arbre se termine lorsque :
- Toutes les instances dans un nœud appartiennent à la même classe. Cela peut conduire à un surapprentissage.
- La profondeur maximale (codée en dur) de l'arbre est atteinte. C'est un moyen de prévenir le surapprentissage.
- Le nombre d'instances dans un nœud est inférieur à un certain seuil. C'est aussi un moyen de prévenir le surapprentissage.
- Le gain d'information des divisions supplémentaires est inférieur à un certain seuil. C'est aussi un moyen de prévenir le surapprentissage.

<details>
<summary>Exemple -- Arbre de décision pour la détection d'intrusions :</summary>
Nous allons entraîner un arbre de décision sur l'ensemble de données NSL-KDD pour classer les connexions réseau comme étant soit *normales* soit *attaque*. NSL-KDD est une version améliorée de l'ensemble de données classique KDD Cup 1999, avec des caractéristiques telles que le type de protocole, le service, la durée, le nombre de connexions échouées, etc., et une étiquette indiquant le type d'attaque ou "normal". Nous mapperons tous les types d'attaques à une classe "anomalie" (classification binaire : normal vs anomalie). Après l'entraînement, nous évaluerons la performance de l'arbre sur l'ensemble de test.
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
Dans cet exemple d'arbre de décision, nous avons limité la profondeur de l'arbre à 10 pour éviter un surajustement extrême (le paramètre `max_depth=10`). Les métriques montrent à quel point l'arbre distingue le trafic normal du trafic d'attaque. Un rappel élevé signifierait qu'il attrape la plupart des attaques (important pour un IDS), tandis qu'une haute précision signifie peu de fausses alertes. Les arbres de décision atteignent souvent une précision décente sur des données structurées, mais un seul arbre pourrait ne pas atteindre la meilleure performance possible. Néanmoins, l'*interprétabilité* du modèle est un grand avantage -- nous pourrions examiner les divisions de l'arbre pour voir, par exemple, quelles caractéristiques (par ex., `service`, `src_bytes`, etc.) sont les plus influentes pour signaler une connexion comme malveillante.

</details>

### Forêts Aléatoires

La Forêt Aléatoire est une méthode d'**apprentissage par ensemble** qui s'appuie sur des arbres de décision pour améliorer la performance. Une forêt aléatoire entraîne plusieurs arbres de décision (d'où "forêt") et combine leurs résultats pour faire une prédiction finale (pour la classification, généralement par vote majoritaire). Les deux idées principales dans une forêt aléatoire sont le **bagging** (agrégation par bootstrap) et la **randomisation des caractéristiques** :

-   **Bagging :** Chaque arbre est entraîné sur un échantillon bootstrap aléatoire des données d'entraînement (échantillonné avec remplacement). Cela introduit de la diversité parmi les arbres.

-   **Randomisation des Caractéristiques :** À chaque division dans un arbre, un sous-ensemble aléatoire de caractéristiques est considéré pour la division (au lieu de toutes les caractéristiques). Cela décorelle davantage les arbres.

En moyennant les résultats de nombreux arbres, la forêt aléatoire réduit la variance qu'un seul arbre de décision pourrait avoir. En termes simples, les arbres individuels peuvent surajuster ou être bruyants, mais un grand nombre d'arbres divers votant ensemble atténue ces erreurs. Le résultat est souvent un modèle avec une **précision plus élevée** et une meilleure généralisation qu'un seul arbre de décision. De plus, les forêts aléatoires peuvent fournir une estimation de l'importance des caractéristiques (en regardant combien chaque caractéristique réduit l'impureté en moyenne).

Les forêts aléatoires sont devenues un **outil essentiel en cybersécurité** pour des tâches telles que la détection d'intrusions, la classification de logiciels malveillants et la détection de spam. Elles fonctionnent souvent bien dès le départ avec un minimum de réglages et peuvent gérer de grands ensembles de caractéristiques. Par exemple, dans la détection d'intrusions, une forêt aléatoire peut surpasser un arbre de décision individuel en capturant des motifs d'attaques plus subtils avec moins de faux positifs. Des recherches ont montré que les forêts aléatoires se comportent favorablement par rapport à d'autres algorithmes dans la classification des attaques dans des ensembles de données comme NSL-KDD et UNSW-NB15.

#### **Caractéristiques clés des Forêts Aléatoires :**

-   **Type de Problème :** Principalement classification (également utilisé pour la régression). Très bien adapté aux données structurées de haute dimension courantes dans les journaux de sécurité.

-   **Interprétabilité :** Inférieure à celle d'un seul arbre de décision -- vous ne pouvez pas facilement visualiser ou expliquer des centaines d'arbres à la fois. Cependant, les scores d'importance des caractéristiques fournissent un aperçu de quelles attributs sont les plus influents.

-   **Avantages :** Précision généralement plus élevée que les modèles à arbre unique en raison de l'effet d'ensemble. Robuste au surajustement -- même si les arbres individuels surajustent, l'ensemble généralise mieux. Gère à la fois des caractéristiques numériques et catégorielles et peut gérer les données manquantes dans une certaine mesure. Il est également relativement robuste aux valeurs aberrantes.

-   **Limitations :** La taille du modèle peut être grande (beaucoup d'arbres, chacun potentiellement profond). Les prédictions sont plus lentes qu'un arbre unique (car vous devez agréger sur de nombreux arbres). Moins interprétable -- bien que vous connaissiez les caractéristiques importantes, la logique exacte n'est pas facilement traçable comme une règle simple. Si l'ensemble de données est extrêmement haute dimension et sparse, entraîner une très grande forêt peut être lourd en calcul.

-   **Processus d'Entraînement :**
1. **Échantillonnage Bootstrap :** Échantillonner aléatoirement les données d'entraînement avec remplacement pour créer plusieurs sous-ensembles (échantillons bootstrap).
2. **Construction d'Arbre :** Pour chaque échantillon bootstrap, construire un arbre de décision en utilisant un sous-ensemble aléatoire de caractéristiques à chaque division. Cela introduit de la diversité parmi les arbres.
3. **Agrégation :** Pour les tâches de classification, la prédiction finale est faite en prenant un vote majoritaire parmi les prédictions de tous les arbres. Pour les tâches de régression, la prédiction finale est la moyenne des prédictions de tous les arbres.

<details>
<summary>Exemple -- Forêt Aléatoire pour la Détection d'Intrusions (NSL-KDD) :</summary>
Nous utiliserons le même ensemble de données NSL-KDD (étiqueté binaire comme normal vs anomalie) et entraînerons un classificateur de Forêt Aléatoire. Nous nous attendons à ce que la forêt aléatoire fonctionne aussi bien ou mieux que l'arbre de décision unique, grâce à l'agrégation d'ensemble réduisant la variance. Nous l'évaluerons avec les mêmes métriques.
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
Le random forest atteint généralement de bons résultats sur cette tâche de détection d'intrusion. Nous pourrions observer une amélioration des métriques comme F1 ou AUC par rapport à l'arbre de décision unique, en particulier en ce qui concerne le rappel ou la précision, selon les données. Cela s'aligne avec la compréhension que *"Random Forest (RF) est un classificateur d'ensemble et fonctionne bien par rapport à d'autres classificateurs traditionnels pour une classification efficace des attaques."*. Dans un contexte d'opérations de sécurité, un modèle de random forest pourrait signaler les attaques de manière plus fiable tout en réduisant les fausses alertes, grâce à l'averaging de nombreuses règles de décision. L'importance des caractéristiques du forest pourrait nous indiquer quelles caractéristiques réseau sont les plus indicatives des attaques (par exemple, certains services réseau ou des comptes inhabituels de paquets).

</details>

### Support Vector Machines (SVM)

Les Support Vector Machines sont des modèles d'apprentissage supervisé puissants utilisés principalement pour la classification (et aussi la régression en tant que SVR). Un SVM essaie de trouver le **hyperplan de séparation optimal** qui maximise la marge entre deux classes. Seul un sous-ensemble de points d'entraînement (les "vecteurs de support" les plus proches de la frontière) détermine la position de cet hyperplan. En maximisant la marge (distance entre les vecteurs de support et l'hyperplan), les SVM ont tendance à obtenir une bonne généralisation.

La clé de la puissance des SVM est la capacité d'utiliser des **fonctions de noyau** pour gérer les relations non linéaires. Les données peuvent être implicitement transformées en un espace de caractéristiques de dimension supérieure où un séparateur linéaire pourrait exister. Les noyaux courants incluent polynomial, fonction de base radiale (RBF) et sigmoïde. Par exemple, si les classes de trafic réseau ne sont pas séparables linéairement dans l'espace de caractéristiques brut, un noyau RBF peut les mapper dans une dimension supérieure où le SVM trouve une séparation linéaire (ce qui correspond à une frontière non linéaire dans l'espace original). La flexibilité de choisir des noyaux permet aux SVM de s'attaquer à une variété de problèmes.

Les SVM sont connus pour bien fonctionner dans des situations avec des espaces de caractéristiques de haute dimension (comme les données textuelles ou les séquences d'opcodes de logiciels malveillants) et dans les cas où le nombre de caractéristiques est important par rapport au nombre d'échantillons. Ils étaient populaires dans de nombreuses applications de cybersécurité précoces telles que la classification de logiciels malveillants et la détection d'intrusions basée sur des anomalies dans les années 2000, montrant souvent une grande précision.

Cependant, les SVM ne s'adaptent pas facilement à des ensembles de données très volumineux (la complexité d'entraînement est super-linéaire par rapport au nombre d'échantillons, et l'utilisation de la mémoire peut être élevée car il peut être nécessaire de stocker de nombreux vecteurs de support). En pratique, pour des tâches comme la détection d'intrusions réseau avec des millions d'enregistrements, le SVM pourrait être trop lent sans un sous-échantillonnage soigneux ou l'utilisation de méthodes approximatives.

#### **Caractéristiques clés des SVM :**

-   **Type de problème :** Classification (binaire ou multiclass via un contre un/un contre le reste) et variantes de régression. Souvent utilisé dans la classification binaire avec une séparation de marge claire.

-   **Interprétabilité :** Moyenne -- Les SVM ne sont pas aussi interprétables que les arbres de décision ou la régression logistique. Bien que vous puissiez identifier quels points de données sont des vecteurs de support et avoir une idée de quelles caractéristiques pourraient être influentes (à travers les poids dans le cas du noyau linéaire), en pratique, les SVM (surtout avec des noyaux non linéaires) sont traités comme des classificateurs en boîte noire.

-   **Avantages :** Efficace dans des espaces de haute dimension ; peut modéliser des frontières de décision complexes avec le truc du noyau ; robuste au surapprentissage si la marge est maximisée (surtout avec un paramètre de régularisation approprié C) ; fonctionne bien même lorsque les classes ne sont pas séparées par une grande distance (trouve la meilleure frontière de compromis).

-   **Limitations :** **Intensif en calcul** pour de grands ensembles de données (tant l'entraînement que la prédiction se dégradent mal à mesure que les données augmentent). Nécessite un réglage minutieux des paramètres de noyau et de régularisation (C, type de noyau, gamma pour RBF, etc.). Ne fournit pas directement des sorties probabilistes (bien qu'on puisse utiliser le redimensionnement de Platt pour obtenir des probabilités). De plus, les SVM peuvent être sensibles au choix des paramètres de noyau --- un mauvais choix peut conduire à un sous-ajustement ou un surajustement.

*Cas d'utilisation en cybersécurité :* Les SVM ont été utilisés dans la **détection de logiciels malveillants** (par exemple, classer des fichiers en fonction des caractéristiques extraites ou des séquences d'opcodes), la **détection d'anomalies réseau** (classer le trafic comme normal ou malveillant), et la **détection de phishing** (en utilisant des caractéristiques des URL). Par exemple, un SVM pourrait prendre des caractéristiques d'un e-mail (comptes de certains mots-clés, scores de réputation de l'expéditeur, etc.) et le classer comme phishing ou légitime. Ils ont également été appliqués à la **détection d'intrusions** sur des ensembles de caractéristiques comme KDD, atteignant souvent une grande précision au prix du calcul.

<details>
<summary>Exemple -- SVM pour la classification de logiciels malveillants :</summary>
Nous allons utiliser à nouveau l'ensemble de données des sites Web de phishing, cette fois avec un SVM. Parce que les SVM peuvent être lents, nous utiliserons un sous-ensemble des données pour l'entraînement si nécessaire (l'ensemble de données contient environ 11k instances, que le SVM peut gérer raisonnablement). Nous utiliserons un noyau RBF qui est un choix courant pour les données non linéaires, et nous activerons les estimations de probabilité pour calculer le ROC AUC.
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
Le modèle SVM produira des métriques que nous pouvons comparer à la régression logistique sur la même tâche. Nous pourrions constater que SVM atteint une haute précision et AUC si les données sont bien séparées par les caractéristiques. En revanche, si l'ensemble de données contenait beaucoup de bruit ou des classes qui se chevauchent, SVM pourrait ne pas surpasser significativement la régression logistique. En pratique, les SVM peuvent donner un coup de pouce lorsqu'il existe des relations complexes et non linéaires entre les caractéristiques et la classe -- le noyau RBF peut capturer des frontières de décision courbées que la régression logistique manquerait. Comme pour tous les modèles, un réglage minutieux des paramètres `C` (régularisation) et du noyau (comme `gamma` pour RBF) est nécessaire pour équilibrer biais et variance.

</details>

#### Différence entre Régressions Logistiques & SVM

| Aspect | **Régression Logistique** | **Machines à Vecteurs de Support** |
|---|---|---|
| **Fonction objective** | Minimise **log‑loss** (entropie croisée). | Maximise la **marge** tout en minimisant **hinge‑loss**. |
| **Frontière de décision** | Trouve le **hyperplan de meilleur ajustement** qui modélise _P(y\|x)_. | Trouve le **hyperplan à marge maximale** (écart le plus grand aux points les plus proches). |
| **Sortie** | **Probabiliste** – donne des probabilités de classe calibrées via σ(w·x + b). | **Déterministe** – retourne des étiquettes de classe ; les probabilités nécessitent un travail supplémentaire (par exemple, mise à l'échelle de Platt). |
| **Régularisation** | L2 (par défaut) ou L1, équilibre directement sous/sur‑ajustement. | Le paramètre C équilibre la largeur de la marge par rapport aux erreurs de classification ; les paramètres du noyau ajoutent de la complexité. |
| **Noyaux / Non‑linéaire** | La forme native est **linéaire** ; la non-linéarité est ajoutée par l'ingénierie des caractéristiques. | Le **truc du noyau** intégré (RBF, poly, etc.) lui permet de modéliser des frontières complexes dans un espace de haute dimension. |
| **Scalabilité** | Résout une optimisation convexe en **O(nd)** ; gère très bien de grands n. | L'entraînement peut être **O(n²–n³)** en mémoire/temps sans solveurs spécialisés ; moins adapté aux très grands n. |
| **Interprétabilité** | **Élevée** – les poids montrent l'influence des caractéristiques ; le rapport de cotes est intuitif. | **Faible** pour les noyaux non linéaires ; les vecteurs de support sont rares mais pas faciles à expliquer. |
| **Sensibilité aux valeurs aberrantes** | Utilise une log‑loss lisse → moins sensible. | Hinge‑loss avec marge stricte peut être **sensible** ; la marge douce (C) atténue cela. |
| **Cas d'utilisation typiques** | Évaluation de crédit, risque médical, tests A/B – où **probabilités & explicabilité** comptent. | Classification d'images/textes, bio-informatique – où **frontières complexes** et **données de haute dimension** comptent. |

* **Si vous avez besoin de probabilités calibrées, d'interprétabilité, ou si vous travaillez sur de grands ensembles de données — choisissez la Régression Logistique.**
* **Si vous avez besoin d'un modèle flexible qui peut capturer des relations non linéaires sans ingénierie manuelle des caractéristiques — choisissez SVM (avec noyaux).**
* Les deux optimisent des objectifs convexes, donc **les minima globaux sont garantis**, mais les noyaux de SVM ajoutent des hyper-paramètres et un coût computationnel.

### Naive Bayes

Naive Bayes est une famille de **classificateurs probabilistes** basée sur l'application du théorème de Bayes avec une forte hypothèse d'indépendance entre les caractéristiques. Malgré cette hypothèse "naïve", Naive Bayes fonctionne souvent étonnamment bien pour certaines applications, en particulier celles impliquant des données textuelles ou catégorielles, telles que la détection de spam.

#### Théorème de Bayes

Le théorème de Bayes est la base des classificateurs Naive Bayes. Il relie les probabilités conditionnelles et marginales des événements aléatoires. La formule est :
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Où :
- `P(A|B)` est la probabilité a posteriori de la classe `A` étant donné la caractéristique `B`.
- `P(B|A)` est la vraisemblance de la caractéristique `B` étant donné la classe `A`.
- `P(A)` est la probabilité a priori de la classe `A`.
- `P(B)` est la probabilité a priori de la caractéristique `B`.

Par exemple, si nous voulons classer si un texte est écrit par un enfant ou un adulte, nous pouvons utiliser les mots dans le texte comme caractéristiques. Sur la base de certaines données initiales, le classificateur Naive Bayes calculera au préalable les probabilités de chaque mot d'appartenir à chaque classe potentielle (enfant ou adulte). Lorsqu'un nouveau texte est donné, il calculera la probabilité de chaque classe potentielle étant donné les mots dans le texte et choisira la classe avec la probabilité la plus élevée.

Comme vous pouvez le voir dans cet exemple, le classificateur Naive Bayes est très simple et rapide, mais il suppose que les caractéristiques sont indépendantes, ce qui n'est pas toujours le cas dans les données du monde réel.

#### Types de classificateurs Naive Bayes

Il existe plusieurs types de classificateurs Naive Bayes, en fonction du type de données et de la distribution des caractéristiques :
- **Gaussian Naive Bayes** : Suppose que les caractéristiques suivent une distribution gaussienne (normale). Il est adapté aux données continues.
- **Multinomial Naive Bayes** : Suppose que les caractéristiques suivent une distribution multinomiale. Il est adapté aux données discrètes, telles que les comptes de mots dans la classification de texte.
- **Bernoulli Naive Bayes** : Suppose que les caractéristiques sont binaires (0 ou 1). Il est adapté aux données binaires, telles que la présence ou l'absence de mots dans la classification de texte.
- **Categorical Naive Bayes** : Suppose que les caractéristiques sont des variables catégorielles. Il est adapté aux données catégorielles, telles que la classification des fruits en fonction de leur couleur et de leur forme.

#### **Caractéristiques clés de Naive Bayes :**

-   **Type de problème :** Classification (binaire ou multi-classe). Couramment utilisé pour des tâches de classification de texte en cybersécurité (spam, phishing, etc.).

-   **Interprétabilité :** Moyenne -- ce n'est pas aussi directement interprétable qu'un arbre de décision, mais on peut inspecter les probabilités apprises (par exemple, quels mots sont les plus susceptibles d'être dans des emails spam vs ham). La forme du modèle (probabilités pour chaque caractéristique donnée la classe) peut être comprise si nécessaire.

-   **Avantages :** **Entraînement et prédiction très rapides**, même sur de grands ensembles de données (linéaire par rapport au nombre d'instances * nombre de caractéristiques). Nécessite une quantité relativement petite de données pour estimer les probabilités de manière fiable, surtout avec un lissage approprié. Il est souvent étonnamment précis en tant que référence, surtout lorsque les caractéristiques contribuent indépendamment à la preuve de la classe. Fonctionne bien avec des données de haute dimension (par exemple, des milliers de caractéristiques provenant de texte). Aucun réglage complexe n'est requis au-delà de la définition d'un paramètre de lissage.

-   **Limitations :** L'hypothèse d'indépendance peut limiter la précision si les caractéristiques sont fortement corrélées. Par exemple, dans les données réseau, des caractéristiques comme `src_bytes` et `dst_bytes` pourraient être corrélées ; Naive Bayes ne capturera pas cette interaction. À mesure que la taille des données devient très grande, des modèles plus expressifs (comme les ensembles ou les réseaux neuronaux) peuvent surpasser NB en apprenant les dépendances entre les caractéristiques. De plus, si une certaine combinaison de caractéristiques est nécessaire pour identifier une attaque (et non pas seulement des caractéristiques individuelles indépendamment), NB aura des difficultés.

> [!TIP]
> *Cas d'utilisation en cybersécurité :* L'utilisation classique est la **détection de spam** -- Naive Bayes était au cœur des premiers filtres anti-spam, utilisant les fréquences de certains tokens (mots, phrases, adresses IP) pour calculer la probabilité qu'un email soit du spam. Il est également utilisé dans la **détection d'emails de phishing** et la **classification d'URL**, où la présence de certains mots-clés ou caractéristiques (comme "login.php" dans une URL, ou `@` dans un chemin d'URL) contribue à la probabilité de phishing. Dans l'analyse de logiciels malveillants, on pourrait imaginer un classificateur Naive Bayes qui utilise la présence de certains appels d'API ou permissions dans un logiciel pour prédire s'il s'agit de logiciels malveillants. Bien que des algorithmes plus avancés soient souvent plus performants, Naive Bayes reste une bonne référence en raison de sa rapidité et de sa simplicité.

<details>
<summary>Exemple -- Naive Bayes pour la détection de phishing :</summary>
Pour démontrer Naive Bayes, nous utiliserons Gaussian Naive Bayes sur le jeu de données d'intrusion NSL-KDD (avec des étiquettes binaires). Gaussian NB traitera chaque caractéristique comme suivant une distribution normale par classe. C'est un choix approximatif puisque de nombreuses caractéristiques réseau sont discrètes ou très biaisées, mais cela montre comment on appliquerait NB à des données de caractéristiques continues. Nous pourrions également choisir Bernoulli NB sur un ensemble de données de caractéristiques binaires (comme un ensemble d'alertes déclenchées), mais nous resterons avec NSL-KDD ici pour la continuité.
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
Ce code entraîne un classificateur Naive Bayes pour détecter des attaques. Naive Bayes va calculer des choses comme `P(service=http | Attack)` et `P(Service=http | Normal)` en fonction des données d'entraînement, en supposant l'indépendance entre les caractéristiques. Il utilisera ensuite ces probabilités pour classer de nouvelles connexions comme normales ou attaques en fonction des caractéristiques observées. La performance de NB sur NSL-KDD peut ne pas être aussi élevée que celle de modèles plus avancés (puisque l'indépendance des caractéristiques est violée), mais elle est souvent décente et présente l'avantage d'une vitesse extrême. Dans des scénarios comme le filtrage d'e-mails en temps réel ou le tri initial des URL, un modèle Naive Bayes peut rapidement signaler des cas manifestement malveillants avec une faible utilisation des ressources.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors est l'un des algorithmes d'apprentissage automatique les plus simples. C'est une méthode **non paramétrique, basée sur les instances** qui fait des prédictions en fonction de la similarité avec des exemples dans l'ensemble d'entraînement. L'idée pour la classification est : pour classer un nouveau point de données, trouver les **k** points les plus proches dans les données d'entraînement (ses "voisins les plus proches"), et attribuer la classe majoritaire parmi ces voisins. La "proximité" est définie par une métrique de distance, généralement la distance euclidienne pour les données numériques (d'autres distances peuvent être utilisées pour différents types de caractéristiques ou de problèmes).

K-NN nécessite *aucun entraînement explicite* -- la phase "d'entraînement" consiste simplement à stocker l'ensemble de données. Tout le travail se fait lors de la requête (prédiction) : l'algorithme doit calculer les distances du point de requête à tous les points d'entraînement pour trouver les plus proches. Cela rend le temps de prédiction **linéaire par rapport au nombre d'échantillons d'entraînement**, ce qui peut être coûteux pour de grands ensembles de données. En raison de cela, k-NN est mieux adapté aux petits ensembles de données ou aux scénarios où vous pouvez échanger mémoire et vitesse pour la simplicité.

Malgré sa simplicité, k-NN peut modéliser des frontières de décision très complexes (puisque, en effet, la frontière de décision peut avoir n'importe quelle forme dictée par la distribution des exemples). Il a tendance à bien fonctionner lorsque la frontière de décision est très irrégulière et que vous avez beaucoup de données -- laissant essentiellement les données "parler d'elles-mêmes". Cependant, dans des dimensions élevées, les métriques de distance peuvent devenir moins significatives (malédiction de la dimensionnalité), et la méthode peut avoir des difficultés à moins que vous n'ayez un grand nombre d'échantillons.

*Cas d'utilisation en cybersécurité :* k-NN a été appliqué à la détection d'anomalies -- par exemple, un système de détection d'intrusions pourrait étiqueter un événement réseau comme malveillant si la plupart de ses voisins les plus proches (événements précédents) étaient malveillants. Si le trafic normal forme des clusters et que les attaques sont des valeurs aberrantes, une approche K-NN (avec k=1 ou un petit k) effectue essentiellement une **détection d'anomalies par voisin le plus proche**. K-NN a également été utilisé pour classer des familles de logiciels malveillants par vecteurs de caractéristiques binaires : un nouveau fichier pourrait être classé comme appartenant à une certaine famille de logiciels malveillants s'il est très proche (dans l'espace des caractéristiques) d'instances connues de cette famille. En pratique, k-NN n'est pas aussi courant que des algorithmes plus évolutifs, mais il est conceptuellement simple et parfois utilisé comme référence ou pour des problèmes à petite échelle.

#### **Caractéristiques clés de k-NN :**

-   **Type de problème :** Classification (et des variantes de régression existent). C'est une méthode d'*apprentissage paresseux* -- pas d'ajustement explicite du modèle.

-   **Interprétabilité :** Faible à moyenne -- il n'y a pas de modèle global ou d'explication concise, mais on peut interpréter les résultats en regardant les voisins les plus proches qui ont influencé une décision (par exemple, "ce flux réseau a été classé comme malveillant parce qu'il est similaire à ces 3 flux malveillants connus"). Ainsi, les explications peuvent être basées sur des exemples.

-   **Avantages :** Très simple à mettre en œuvre et à comprendre. Ne fait aucune hypothèse sur la distribution des données (non paramétrique). Peut gérer naturellement des problèmes multi-classes. C'est **adaptatif** dans le sens où les frontières de décision peuvent être très complexes, façonnées par la distribution des données.

-   **Limitations :** La prédiction peut être lente pour de grands ensembles de données (doit calculer de nombreuses distances). Intensif en mémoire -- il stocke toutes les données d'entraînement. La performance se dégrade dans des espaces de caractéristiques de haute dimension car tous les points tendent à devenir presque équidistants (rendant le concept de "plus proche" moins significatif). Il faut choisir *k* (nombre de voisins) de manière appropriée -- un k trop petit peut être bruyant, un k trop grand peut inclure des points non pertinents d'autres classes. De plus, les caractéristiques doivent être mises à l'échelle de manière appropriée car les calculs de distance sont sensibles à l'échelle.

<details>
<summary>Exemple -- k-NN pour la détection de phishing :</summary>

Nous allons à nouveau utiliser NSL-KDD (classification binaire). Comme k-NN est lourd en calcul, nous utiliserons un sous-ensemble des données d'entraînement pour le rendre gérable dans cette démonstration. Nous allons choisir, disons, 20 000 échantillons d'entraînement sur les 125k complets, et utiliser k=5 voisins. Après l'entraînement (qui consiste vraiment juste à stocker les données), nous évaluerons sur l'ensemble de test. Nous allons également mettre à l'échelle les caractéristiques pour le calcul des distances afin de garantir qu'aucune caractéristique unique ne domine en raison de l'échelle.
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
Le modèle k-NN classera une connexion en examinant les 5 connexions les plus proches dans le sous-ensemble de l'ensemble d'entraînement. Si, par exemple, 4 de ces voisins sont des attaques (anomalies) et 1 est normal, la nouvelle connexion sera classée comme une attaque. La performance peut être raisonnable, bien que souvent pas aussi élevée qu'un Random Forest ou SVM bien réglé sur les mêmes données. Cependant, k-NN peut parfois briller lorsque les distributions de classes sont très irrégulières et complexes -- utilisant effectivement une recherche basée sur la mémoire. En cybersécurité, k-NN (avec k=1 ou un petit k) pourrait être utilisé pour la détection de modèles d'attaque connus par exemple, ou comme un composant dans des systèmes plus complexes (par exemple, pour le clustering et ensuite la classification en fonction de l'appartenance au cluster).

### Machines à Gradient Boosting (par exemple, XGBoost)

Les machines à gradient boosting sont parmi les algorithmes les plus puissants pour les données structurées. **Le gradient boosting** fait référence à la technique de construction d'un ensemble de faibles apprenants (souvent des arbres de décision) de manière séquentielle, où chaque nouveau modèle corrige les erreurs de l'ensemble précédent. Contrairement au bagging (Random Forests) qui construit des arbres en parallèle et les moyenne, le boosting construit des arbres *un par un*, chacun se concentrant davantage sur les instances que les arbres précédents ont mal prédites.

Les implémentations les plus populaires ces dernières années sont **XGBoost**, **LightGBM** et **CatBoost**, qui sont toutes des bibliothèques d'arbres de décision à gradient boosting (GBDT). Elles ont été extrêmement réussies dans les compétitions et applications d'apprentissage automatique, atteignant souvent **des performances de pointe sur des ensembles de données tabulaires**. En cybersécurité, les chercheurs et praticiens ont utilisé des arbres à gradient boosting pour des tâches telles que **la détection de logiciels malveillants** (en utilisant des caractéristiques extraites de fichiers ou du comportement d'exécution) et **la détection d'intrusions réseau**. Par exemple, un modèle de gradient boosting peut combiner de nombreuses règles faibles (arbres) telles que "si de nombreux paquets SYN et un port inhabituel -> probablement un scan" en un détecteur composite fort qui prend en compte de nombreux motifs subtils.

Pourquoi les arbres boostés sont-ils si efficaces ? Chaque arbre de la séquence est entraîné sur les *erreurs résiduelles* (gradients) des prédictions de l'ensemble actuel. De cette manière, le modèle **"booste"** progressivement les zones où il est faible. L'utilisation d'arbres de décision comme apprenants de base signifie que le modèle final peut capturer des interactions complexes et des relations non linéaires. De plus, le boosting a intrinsèquement une forme de régularisation intégrée : en ajoutant de nombreux petits arbres (et en utilisant un taux d'apprentissage pour ajuster leurs contributions), il généralise souvent bien sans surajustement important, à condition que des paramètres appropriés soient choisis.

#### **Caractéristiques clés du Gradient Boosting :**

-   **Type de problème :** Principalement classification et régression. En sécurité, généralement classification (par exemple, classifier une connexion ou un fichier de manière binaire). Il gère les problèmes binaires, multi-classes (avec perte appropriée), et même les problèmes de classement.

-   **Interprétabilité :** Faible à moyenne. Bien qu'un seul arbre boosté soit petit, un modèle complet peut avoir des centaines d'arbres, ce qui n'est pas interprétable par l'homme dans son ensemble. Cependant, comme Random Forest, il peut fournir des scores d'importance des caractéristiques, et des outils comme SHAP (SHapley Additive exPlanations) peuvent être utilisés pour interpréter les prédictions individuelles dans une certaine mesure.

-   **Avantages :** Souvent l'algorithme **le plus performant** pour les données structurées/tabulaires. Peut détecter des motifs et des interactions complexes. Dispose de nombreux réglages (nombre d'arbres, profondeur des arbres, taux d'apprentissage, termes de régularisation) pour adapter la complexité du modèle et prévenir le surajustement. Les implémentations modernes sont optimisées pour la vitesse (par exemple, XGBoost utilise des informations de gradient d'ordre supérieur et des structures de données efficaces). Tends à mieux gérer les données déséquilibrées lorsqu'il est combiné avec des fonctions de perte appropriées ou en ajustant les poids d'échantillon.

-   **Limitations :** Plus complexe à régler que des modèles plus simples ; l'entraînement peut être lent si les arbres sont profonds ou si le nombre d'arbres est important (bien que généralement plus rapide que l'entraînement d'un réseau de neurones profond comparable sur les mêmes données). Le modèle peut surajuster s'il n'est pas réglé (par exemple, trop d'arbres profonds avec une régularisation insuffisante). En raison de nombreux hyperparamètres, utiliser le gradient boosting efficacement peut nécessiter plus d'expertise ou d'expérimentation. De plus, comme les méthodes basées sur les arbres, il ne gère pas intrinsèquement les données très éparses et de haute dimension aussi efficacement que les modèles linéaires ou Naive Bayes (bien qu'il puisse encore être appliqué, par exemple, dans la classification de texte, mais pourrait ne pas être le premier choix sans ingénierie des caractéristiques).

> [!TIP]
> *Cas d'utilisation en cybersécurité :* Presque partout où un arbre de décision ou une forêt aléatoire pourrait être utilisé, un modèle de gradient boosting pourrait atteindre une meilleure précision. Par exemple, les compétitions de **détection de logiciels malveillants de Microsoft** ont vu une forte utilisation de XGBoost sur des caractéristiques conçues à partir de fichiers binaires. La recherche en **détection d'intrusions réseau** rapporte souvent des résultats de pointe avec des GBDTs (par exemple, XGBoost sur les ensembles de données CIC-IDS2017 ou UNSW-NB15). Ces modèles peuvent prendre une large gamme de caractéristiques (types de protocoles, fréquence de certains événements, caractéristiques statistiques du trafic, etc.) et les combiner pour détecter des menaces. Dans la détection de phishing, le gradient boosting peut combiner des caractéristiques lexicales des URL, des caractéristiques de réputation de domaine et des caractéristiques de contenu de page pour atteindre une très haute précision. L'approche d'ensemble aide à couvrir de nombreux cas particuliers et subtilités dans les données.

<details>
<summary>Exemple -- XGBoost pour la détection de phishing :</summary>
Nous allons utiliser un classificateur à gradient boosting sur l'ensemble de données de phishing. Pour garder les choses simples et autonomes, nous allons utiliser `sklearn.ensemble.GradientBoostingClassifier` (qui est une implémentation plus lente mais directe). Normalement, on pourrait utiliser les bibliothèques `xgboost` ou `lightgbm` pour de meilleures performances et des fonctionnalités supplémentaires. Nous allons entraîner le modèle et l'évaluer de manière similaire à avant.
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
Le modèle de gradient boosting atteindra probablement une très haute précision et AUC sur ce jeu de données de phishing (souvent, ces modèles peuvent dépasser 95 % de précision avec un réglage approprié sur de telles données, comme le montre la littérature. Cela démontre pourquoi les GBDT sont considérés comme *"le modèle de pointe pour les jeux de données tabulaires"* -- ils surpassent souvent des algorithmes plus simples en capturant des motifs complexes. Dans un contexte de cybersécurité, cela pourrait signifier attraper plus de sites de phishing ou d'attaques avec moins de faux négatifs. Bien sûr, il faut être prudent concernant le surajustement -- nous utiliserions généralement des techniques comme la validation croisée et surveillerions les performances sur un ensemble de validation lors du développement d'un tel modèle pour le déploiement.

</details>

### Combinaison de Modèles : Apprentissage par Ensemble et Stacking

L'apprentissage par ensemble est une stratégie de **combinaison de plusieurs modèles** pour améliorer la performance globale. Nous avons déjà vu des méthodes d'ensemble spécifiques : Random Forest (un ensemble d'arbres via le bagging) et Gradient Boosting (un ensemble d'arbres via le boosting séquentiel). Mais des ensembles peuvent également être créés de d'autres manières, comme les **ensembles de vote** ou la **généralisation empilée (stacking)**. L'idée principale est que différents modèles peuvent capturer différents motifs ou avoir différentes faiblesses ; en les combinant, nous pouvons **compenser les erreurs de chaque modèle par les forces des autres**.

-   **Ensemble de Vote :** Dans un classificateur de vote simple, nous entraînons plusieurs modèles divers (par exemple, une régression logistique, un arbre de décision et un SVM) et les faisons voter sur la prédiction finale (vote majoritaire pour la classification). Si nous pondérons les votes (par exemple, un poids plus élevé pour les modèles plus précis), c'est un schéma de vote pondéré. Cela améliore généralement la performance lorsque les modèles individuels sont raisonnablement bons et indépendants -- l'ensemble réduit le risque d'erreur d'un modèle individuel puisque d'autres peuvent la corriger. C'est comme avoir un panel d'experts plutôt qu'une seule opinion.

-   **Stacking (Ensemble Empilé) :** Le stacking va un peu plus loin. Au lieu d'un simple vote, il entraîne un **méta-modèle** pour **apprendre comment combiner au mieux les prédictions** des modèles de base. Par exemple, vous entraînez 3 classificateurs différents (apprenants de base), puis vous alimentez leurs sorties (ou probabilités) comme caractéristiques dans un méta-classificateur (souvent un modèle simple comme la régression logistique) qui apprend la manière optimale de les mélanger. Le méta-modèle est entraîné sur un ensemble de validation ou via validation croisée pour éviter le surajustement. Le stacking peut souvent surpasser le vote simple en apprenant *quels modèles faire confiance dans quelles circonstances*. En cybersécurité, un modèle pourrait être meilleur pour attraper les analyses de réseau tandis qu'un autre est meilleur pour attraper les signaux de malware ; un modèle de stacking pourrait apprendre à s'appuyer sur chacun de manière appropriée.

Les ensembles, que ce soit par vote ou stacking, tendent à **augmenter la précision** et la robustesse. L'inconvénient est une complexité accrue et parfois une interprétabilité réduite (bien que certaines approches d'ensemble comme la moyenne des arbres de décision puissent encore fournir un certain aperçu, par exemple, l'importance des caractéristiques). En pratique, si les contraintes opérationnelles le permettent, utiliser un ensemble peut conduire à des taux de détection plus élevés. De nombreuses solutions gagnantes dans les défis de cybersécurité (et les compétitions Kaggle en général) utilisent des techniques d'ensemble pour tirer le dernier bit de performance.

<details>
<summary>Exemple -- Ensemble de Vote pour la Détection de Phishing :</summary>
Pour illustrer le stacking de modèles, combinons quelques-uns des modèles que nous avons discutés sur le jeu de données de phishing. Nous utiliserons une régression logistique, un arbre de décision et un k-NN comme apprenants de base, et utiliserons un Random Forest comme méta-apprenant pour agréger leurs prédictions. Le méta-apprenant sera entraîné sur les sorties des apprenants de base (en utilisant la validation croisée sur l'ensemble d'entraînement). Nous nous attendons à ce que le modèle empilé fonctionne aussi bien ou légèrement mieux que les modèles individuels.
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
L'ensemble empilé tire parti des forces complémentaires des modèles de base. Par exemple, la régression logistique pourrait gérer les aspects linéaires des données, l'arbre de décision pourrait capturer des interactions spécifiques de type règle, et k-NN pourrait exceller dans les quartiers locaux de l'espace des caractéristiques. Le méta-modèle (un forêt aléatoire ici) peut apprendre à pondérer ces entrées. Les métriques résultantes montrent souvent une amélioration (même si légère) par rapport aux métriques de n'importe quel modèle unique. Dans notre exemple de phishing, si la régression logistique seule avait un F1 de disons 0.95 et l'arbre 0.94, l'ensemble pourrait atteindre 0.96 en récupérant là où chaque modèle se trompe.

Les méthodes d'ensemble comme celle-ci démontrent le principe que *"combiner plusieurs modèles conduit généralement à une meilleure généralisation"*. En cybersécurité, cela peut être mis en œuvre en ayant plusieurs moteurs de détection (l'un pourrait être basé sur des règles, un autre sur l'apprentissage automatique, un autre basé sur des anomalies) et ensuite une couche qui agrège leurs alertes -- effectivement une forme d'ensemble -- pour prendre une décision finale avec une confiance accrue. Lors du déploiement de tels systèmes, il faut considérer la complexité ajoutée et s'assurer que l'ensemble ne devienne pas trop difficile à gérer ou à expliquer. Mais d'un point de vue de précision, les ensembles et l'empilement sont des outils puissants pour améliorer la performance des modèles.

</details>


## Références

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
