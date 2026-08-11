# Algorithmes d’apprentissage supervisé

{{#include ../banners/hacktricks-training.md}}

## Informations de base

L’apprentissage supervisé utilise des données étiquetées pour entraîner des modèles capables d’effectuer des prédictions sur de nouvelles données d’entrée, encore jamais vues. En cybersécurité, le machine learning supervisé est largement utilisé pour des tâches telles que la détection d’intrusions (classification du trafic réseau comme *normal* ou *attaque*), la détection de malware (distinction entre les logiciels malveillants et les logiciels bénins), la détection du phishing (identification des sites web ou des e-mails frauduleux) et le filtrage du spam, entre autres.<sup>[[1]](#references)</sup> Chaque algorithme possède ses propres points forts et convient à différents types de problèmes (classification ou régression). Nous passons ci-dessous en revue les principaux algorithmes d’apprentissage supervisé, expliquons leur fonctionnement et montrons leur utilisation sur de véritables datasets de cybersécurité. Nous abordons également la manière dont la combinaison de modèles (ensemble learning) peut souvent améliorer les performances prédictives.

## Algorithmes

-   **Régression linéaire :** Un algorithme de régression fondamental permettant de prédire des valeurs numériques en ajustant une équation linéaire aux données.

-   **Régression logistique :** Un algorithme de classification (malgré son nom) qui utilise une fonction logistique pour modéliser la probabilité d’un résultat binaire.

-   **Arbres de décision :** Des modèles structurés en arbre qui divisent les données selon leurs caractéristiques pour effectuer des prédictions ; ils sont souvent utilisés pour leur interprétabilité.

-   **Random Forests :** Un ensemble d’arbres de décision (via le bagging) qui améliore la précision et réduit le surapprentissage.

-   **Support Vector Machines (SVM) :** Des classifieurs à marge maximale qui trouvent l’hyperplan séparateur optimal ; ils peuvent utiliser des kernels pour les données non linéaires.

-   **Naive Bayes :** Un classifieur probabiliste fondé sur le théorème de Bayes et reposant sur une hypothèse d’indépendance des caractéristiques, notamment utilisé pour le filtrage du spam.

-   **k-Nearest Neighbors (k-NN) :** Un classifieur simple « basé sur les instances » qui attribue une classe à un échantillon selon la classe majoritaire de ses voisins les plus proches.

-   **Gradient Boosting Machines :** Des modèles d’ensemble (par ex. XGBoost, LightGBM) qui construisent un prédicteur performant en ajoutant séquentiellement des learners plus faibles (généralement des arbres de décision).

Chaque section ci-dessous fournit une description améliorée de l’algorithme ainsi qu’un **exemple de code Python** utilisant des bibliothèques telles que `pandas` et `scikit-learn` (et `PyTorch` pour l’exemple de réseau neuronal). Les exemples utilisent des datasets de cybersécurité accessibles au public (tels que NSL-KDD pour la détection d’intrusions et un dataset de sites web de phishing) et suivent une structure cohérente :

1.  **Charger le dataset** (téléchargement via une URL si elle est disponible).

2.  **Prétraiter les données** (par ex. encoder les caractéristiques catégorielles, mettre les valeurs à l’échelle et diviser les données en ensembles d’entraînement et de test).

3.  **Entraîner le modèle** sur les données d’entraînement.

4.  **Évaluer** le modèle sur un ensemble de test à l’aide des métriques suivantes : accuracy, precision, recall, F1-score et ROC AUC pour la classification (ainsi que l’erreur quadratique moyenne pour la régression).

Examinons maintenant chaque algorithme :

### Régression linéaire

La régression linéaire est un algorithme de **régression** utilisé pour prédire des valeurs numériques continues. Il suppose l’existence d’une relation linéaire entre les caractéristiques d’entrée (variables indépendantes) et la sortie (variable dépendante). Le modèle tente d’ajuster une ligne droite (ou un hyperplan dans les dimensions supérieures) qui décrit au mieux la relation entre les caractéristiques et la cible. Cela s’effectue généralement en minimisant la somme des erreurs quadratiques entre les valeurs prédites et les valeurs réelles (méthode des moindres carrés ordinaires).<sup>[[2]](#references)</sup>

La manière la plus simple de représenter la régression linéaire est une ligne :
```plaintext
y = mx + b
```
Où :

- `y` est la valeur prédite (sortie)
- `m` est la pente de la ligne (coefficient)
- `x` est la caractéristique d'entrée
- `b` est l'ordonnée à l'origine

L'objectif de la régression linéaire est de trouver la ligne qui s'ajuste le mieux aux données et qui minimise la différence entre les valeurs prédites et les valeurs réelles de l'ensemble de données. Bien sûr, c'est très simple : il s'agirait d'une ligne droite séparant 2 catégories, mais si davantage de dimensions sont ajoutées, la ligne devient plus complexe :
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Cas d'utilisation en cybersécurité :* La régression linéaire est elle-même moins courante pour les tâches de sécurité fondamentales (qui sont souvent de la classification), mais elle peut être utilisée pour prédire des résultats numériques. Par exemple, on peut utiliser la régression linéaire pour **prédire le volume du trafic réseau** ou **estimer le nombre d'attaques sur une période** à partir de données historiques. Elle peut également prédire un score de risque ou le délai prévu avant la détection d'une attaque, à partir de certaines métriques du système. En pratique, les algorithmes de classification (comme la régression logistique ou les arbres) sont plus fréquemment utilisés pour détecter les intrusions ou les malwares, mais la régression linéaire sert de base et est utile pour les analyses axées sur la régression.

#### **Caractéristiques clés de la régression linéaire :**

-   **Type de problème :** Régression (prédiction de valeurs continues). Ne convient pas à la classification directe, sauf si un seuil est appliqué à la sortie.

-   **Interprétabilité :** Élevée -- les coefficients sont faciles à interpréter et montrent l'effet linéaire de chaque caractéristique.

-   **Avantages :** Simple et rapide ; constitue une bonne référence pour les tâches de régression ; fonctionne bien lorsque la relation réelle est approximativement linéaire.

-   **Limitations :** Ne peut pas représenter des relations complexes ou non linéaires (sans ingénierie manuelle des caractéristiques) ; risque de sous-ajustement si les relations sont non linéaires ; sensible aux valeurs aberrantes, qui peuvent fausser les résultats.

-   **Recherche du meilleur ajustement :** Pour trouver la droite de meilleur ajustement qui sépare les catégories possibles, nous utilisons une méthode appelée **Ordinary Least Squares (OLS)**. Cette méthode minimise la somme des différences au carré entre les valeurs observées et les valeurs prédites par le modèle linéaire.

<details>
<summary>Exemple -- Prédiction de la durée des connexions (régression) dans un jeu de données d'intrusion
</summary>
Ci-dessous, nous montrons une régression linéaire à l'aide du jeu de données de cybersécurité NSL-KDD. Nous traiterons cela comme un problème de régression en prédisant la `duration` des connexions réseau à partir d'autres caractéristiques. (En réalité, `duration` est l'une des caractéristiques de NSL-KDD ; nous l'utilisons ici uniquement pour illustrer la régression.) Nous chargeons le jeu de données, le prétraitons (encodage des caractéristiques catégorielles), entraînons un modèle de régression linéaire et évaluons l'erreur quadratique moyenne (MSE) ainsi que le score R² sur un jeu de test.
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
Dans cet exemple, le modèle de régression linéaire tente de prédire la `duration` d'une connexion à partir d'autres caractéristiques réseau. Nous mesurons les performances avec l'erreur quadratique moyenne (MSE) et le R². Un R² proche de 1,0 indiquerait que le modèle explique la majeure partie de la variance de `duration`, tandis qu'un R² faible ou négatif indique un mauvais ajustement. (Ne soyez pas surpris si le R² est faible ici : prédire la `duration` peut être difficile à partir des caractéristiques fournies, et la régression linéaire peut ne pas capturer les tendances si elles sont complexes.)
</details>

### Régression logistique

La régression logistique est un algorithme de **classification** qui modélise la probabilité qu'une instance appartienne à une classe particulière (généralement la classe « positive »). Malgré son nom, la régression *logistique* est utilisée pour des résultats discrets (contrairement à la régression linéaire, qui est destinée aux résultats continus). Elle est particulièrement utilisée pour la **classification binaire** (deux classes, par exemple malveillante ou bénigne), mais peut être étendue aux problèmes multiclasse (à l'aide d'approches softmax ou one-vs-rest).<sup>[[3]](#references)</sup>

La régression logistique utilise la fonction logistique (également appelée fonction sigmoïde) pour convertir les valeurs prédites en probabilités. Notez que la fonction sigmoïde est une fonction dont les valeurs sont comprises entre 0 et 1 et qui croît selon une courbe en forme de S en fonction des besoins de la classification, ce qui est utile pour les tâches de classification binaire. Par conséquent, chaque caractéristique de chaque entrée est multipliée par le poids qui lui est attribué, puis le résultat est transmis à la fonction sigmoïde afin de produire une probabilité :
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where :

- `p(y=1|x)` est la probabilité que la sortie `y` soit égale à 1 étant donné l'entrée `x`
- `e` est la base du logarithme naturel
- `z` est une combinaison linéaire des caractéristiques d'entrée, généralement représentée par `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Notez que, là encore, dans sa forme la plus simple, il s'agit d'une droite, mais que dans les cas plus complexes, elle devient un hyperplan avec plusieurs dimensions (une par caractéristique).

> [!TIP]
> *Cas d'utilisation en cybersécurité :* Comme de nombreux problèmes de sécurité sont essentiellement des décisions oui/non, la régression logistique est largement utilisée. Par exemple, un système de détection d'intrusion peut utiliser la régression logistique pour déterminer si une connexion réseau constitue une attaque, en se basant sur les caractéristiques de cette connexion. Pour la détection de phishing, la régression logistique peut combiner les caractéristiques d'un site web (longueur de l'URL, présence du symbole « @ », etc.) afin de calculer la probabilité qu'il s'agisse d'un site de phishing. Elle a été utilisée dans les premiers filtres anti-spam et reste une solide référence pour de nombreuses tâches de classification.

#### Régression logistique pour la classification non binaire

La régression logistique est conçue pour la classification binaire, mais elle peut être étendue afin de gérer les problèmes multi-classes à l'aide de techniques telles que **one-vs-rest** (OvR) ou la **softmax regression**. Avec OvR, un modèle de régression logistique distinct est entraîné pour chaque classe, en la considérant comme la classe positive face à toutes les autres. La classe ayant la probabilité prédite la plus élevée est choisie comme prédiction finale. La softmax regression généralise la régression logistique à plusieurs classes en appliquant la fonction softmax à la couche de sortie, ce qui produit une distribution de probabilité sur l'ensemble des classes.

#### **Caractéristiques clés de la régression logistique :**

-   **Type de problème :** Classification (généralement binaire). Elle prédit la probabilité de la classe positive.

-   **Interprétabilité :** Élevée -- comme pour la régression linéaire, les coefficients des caractéristiques peuvent indiquer comment chaque caractéristique influence le log-odds du résultat. Cette transparence est souvent appréciée en sécurité pour comprendre quels facteurs contribuent à une alerte.

-   **Avantages :** Simple et rapide à entraîner ; fonctionne bien lorsque la relation entre les caractéristiques et le log-odds du résultat est linéaire. Elle produit des probabilités, ce qui permet d'établir un score de risque. Avec une régularisation appropriée, elle se généralise bien et peut mieux gérer la multicolinéarité qu'une simple régression linéaire.

-   **Limitations :** Suppose une frontière de décision linéaire dans l'espace des caractéristiques (elle échoue si la véritable frontière est complexe/non linéaire). Elle peut être moins performante lorsque les interactions ou les effets non linéaires sont essentiels, à moins d'ajouter manuellement des caractéristiques polynomiales ou d'interaction. De plus, la régression logistique est moins efficace lorsque les classes ne sont pas facilement séparables par une combinaison linéaire des caractéristiques.


<details>
<summary>Exemple -- Détection de sites web de phishing avec la régression logistique :</summary>

Nous utiliserons un **Phishing Websites Dataset** (provenant du dépôt UCI), qui contient des caractéristiques extraites de sites web (par exemple, si l'URL contient une adresse IP, l'âge du domaine, la présence d'éléments suspects dans le HTML, etc.) ainsi qu'une étiquette indiquant si le site est un site de phishing ou un site légitime.<sup>[[4]](#references)</sup> Nous entraînons un modèle de régression logistique afin de classer les sites web, puis évaluons sa précision, sa précision positive, son rappel, son score F1 et son ROC AUC sur un sous-ensemble de test.
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
Dans cet exemple de détection de phishing, la régression logistique produit une probabilité indiquant si chaque site web est un site de phishing. En évaluant l’accuracy, la précision, le rappel et le score F1, nous obtenons une idée des performances du modèle. Par exemple, un rappel élevé signifie qu’il détecte la plupart des sites de phishing (ce qui est important en matière de sécurité pour réduire au minimum les attaques manquées), tandis qu’une précision élevée signifie qu’il génère peu de fausses alertes (ce qui est important pour éviter la fatigue des analystes). La ROC AUC (Area Under the ROC Curve) fournit une mesure des performances indépendante du seuil (1,0 est idéal, 0,5 n’est pas meilleur que le hasard). La régression logistique donne souvent de bons résultats pour ce type de tâches, mais si la frontière de décision entre les sites de phishing et les sites légitimes est complexe, des modèles non linéaires plus puissants peuvent être nécessaires.

</details>

### Arbres de décision

Un arbre de décision est un **algorithme d’apprentissage supervisé** polyvalent qui peut être utilisé pour les tâches de classification et de régression. Il apprend un modèle hiérarchique en forme d’arbre, fondé sur les caractéristiques des données. Chaque nœud interne de l’arbre représente un test portant sur une caractéristique particulière, chaque branche représente un résultat de ce test et chaque feuille représente une classe prédite (pour la classification) ou une valeur (pour la régression).<sup>[[5]](#references)</sup>

Pour construire un arbre, des algorithmes comme CART (Classification and Regression Tree) utilisent des mesures telles que l’**impureté de Gini** ou le **gain d’information (entropie)** afin de choisir la meilleure caractéristique et le meilleur seuil pour diviser les données à chaque étape. L’objectif de chaque division est de partitionner les données afin d’augmenter l’homogénéité de la variable cible dans les sous-ensembles obtenus (pour la classification, chaque nœud doit être aussi pur que possible et contenir principalement une seule classe).

Les arbres de décision sont **très interprétables** -- il est possible de suivre le chemin de la racine à la feuille pour comprendre la logique qui sous-tend une prédiction (par exemple, *« IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack »*). Cela est utile en cybersécurité pour expliquer pourquoi une alerte donnée a été déclenchée. Les arbres peuvent naturellement gérer les données numériques et catégorielles et nécessitent peu de prétraitement (par exemple, la mise à l’échelle des caractéristiques n’est pas nécessaire).

Cependant, un arbre de décision unique peut facilement surajuster les données d’entraînement, en particulier s’il est très profond (avec de nombreuses divisions). Des techniques comme l’élagage (limiter la profondeur de l’arbre ou exiger un nombre minimal d’échantillons par feuille) sont souvent utilisées pour éviter le surajustement.

Un arbre de décision comporte 3 composants principaux :
- **Nœud racine** : le nœud supérieur de l’arbre, représentant l’ensemble des données.
- **Nœuds internes** : les nœuds qui représentent les caractéristiques et les décisions fondées sur ces caractéristiques.
- **Nœuds feuilles** : les nœuds qui représentent le résultat final ou la prédiction.

Un arbre peut finalement ressembler à ceci :
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Cas d’utilisation en cybersécurité :* Les arbres de décision ont été utilisés dans les systèmes de détection d’intrusion pour déduire des **règles** permettant d’identifier les attaques. Par exemple, les premiers IDS basés sur ID3/C4.5 généraient des règles lisibles par l’humain pour distinguer le trafic normal du trafic malveillant. Ils sont également utilisés dans l’analyse des malwares pour déterminer si un fichier est malveillant en fonction de ses attributs (taille du fichier, entropie des sections, appels API, etc.). La clarté des arbres de décision les rend utiles lorsqu’une certaine transparence est nécessaire -- un analyste peut examiner l’arbre afin de valider la logique de détection.

#### **Caractéristiques principales des arbres de décision :**

-   **Type de problème :** Classification et régression. Couramment utilisés pour classifier les attaques par rapport au trafic normal, etc.

-   **Interprétabilité :** Très élevée -- les décisions du modèle peuvent être visualisées et comprises comme un ensemble de règles if-then. Il s’agit d’un avantage majeur en sécurité pour la confiance et la vérification du comportement du modèle.

-   **Avantages :** Peuvent capturer les relations non linéaires et les interactions entre les caractéristiques (chaque séparation peut être considérée comme une interaction). Il n’est pas nécessaire de mettre les caractéristiques à l’échelle ou d’effectuer un encodage one-hot des variables catégorielles -- les arbres les gèrent nativement. Inférence rapide (la prédiction consiste simplement à suivre un chemin dans l’arbre).

-   **Limitations :** Sujets au surapprentissage s’ils ne sont pas contrôlés (un arbre profond peut mémoriser l’ensemble d’entraînement). Ils peuvent être instables -- de petites modifications des données peuvent entraîner une structure d’arbre différente. En tant que modèles individuels, leur précision peut ne pas égaler celle de méthodes plus avancées (les ensembles comme Random Forests offrent généralement de meilleures performances en réduisant la variance).

-   **Recherche de la meilleure séparation :**
- **Impureté de Gini** : Mesure l’impureté d’un nœud. Une impureté de Gini plus faible indique une meilleure séparation. La formule est :

```plaintext
Gini = 1 - Σ(p_i^2)
```

Où `p_i` est la proportion d’instances appartenant à la classe `i`.

- **Entropie** : Mesure l’incertitude dans le jeu de données. Une entropie plus faible indique une meilleure séparation. La formule est :

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Où `p_i` est la proportion d’instances appartenant à la classe `i`.

- **Gain d’information** : Réduction de l’entropie ou de l’impureté de Gini après une séparation. Plus le gain d’information est élevé, meilleure est la séparation. Il est calculé comme suit :

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

De plus, un arbre s’arrête lorsque :
- Toutes les instances d’un nœud appartiennent à la même classe. Cela peut entraîner un surapprentissage.
- La profondeur maximale (définie en dur) de l’arbre est atteinte. Il s’agit d’une manière d’éviter le surapprentissage.
- Le nombre d’instances dans un nœud est inférieur à un certain seuil. Il s’agit également d’une manière d’éviter le surapprentissage.
- Le gain d’information obtenu lors de séparations supplémentaires est inférieur à un certain seuil. Il s’agit également d’une manière d’éviter le surapprentissage.

<details>
<summary>Exemple -- Arbre de décision pour la détection d’intrusion :</summary>
Nous allons entraîner un arbre de décision sur le dataset NSL-KDD afin de classifier les connexions réseau comme étant soit *normales*, soit des *attaques*. NSL-KDD est une version améliorée du dataset classique KDD Cup 1999, avec des caractéristiques telles que le type de protocole, le service, la durée, le nombre de connexions échouées, etc., ainsi qu’une étiquette indiquant le type d’attaque ou « normal ». Nous mapperons tous les types d’attaque vers une classe « anomalie » (classification binaire : normal contre anomalie). Après l’entraînement, nous évaluerons les performances de l’arbre sur le jeu de test.
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
Dans cet exemple d’arbre de décision, nous avons limité la profondeur de l’arbre à 10 afin d’éviter un surapprentissage extrême (le paramètre `max_depth=10`). Les métriques montrent dans quelle mesure l’arbre distingue le trafic normal du trafic d’attaque. Un rappel élevé signifie qu’il détecte la plupart des attaques (ce qui est important pour un IDS), tandis qu’une précision élevée signifie qu’il génère peu de fausses alertes. Les arbres de décision atteignent souvent une précision correcte sur les données structurées, mais un arbre unique peut ne pas atteindre les meilleures performances possibles. Néanmoins, l’*interprétabilité* du modèle constitue un avantage important -- nous pourrions examiner les divisions de l’arbre pour voir, par exemple, quelles fonctionnalités (p. ex. `service`, `src_bytes`, etc.) ont le plus d’influence lorsqu’il s’agit de signaler une connexion comme malveillante.

</details>

### Random Forests

Random Forest est une méthode d’**apprentissage en ensemble** qui s’appuie sur des arbres de décision pour améliorer les performances. Un random forest entraîne plusieurs arbres de décision (d’où le terme « forest ») et combine leurs résultats pour produire une prédiction finale (pour la classification, généralement par vote majoritaire). Les deux idées principales d’un random forest sont le **bagging** (agrégation bootstrap) et l’**aléatoire des fonctionnalités** :

-   **Bagging :** chaque arbre est entraîné sur un échantillon bootstrap aléatoire des données d’entraînement (échantillonné avec remise). Cela introduit de la diversité entre les arbres.

-   **Aléatoire des fonctionnalités :** à chaque division d’un arbre, un sous-ensemble aléatoire de fonctionnalités est pris en compte pour la division (au lieu de toutes les fonctionnalités). Cela réduit davantage la corrélation entre les arbres.

En faisant la moyenne des résultats de nombreux arbres, le random forest réduit la variance qu’un arbre de décision unique peut présenter. En termes simples, les arbres individuels peuvent surapprendre ou être bruités, mais un grand nombre d’arbres divers qui votent ensemble atténue ces erreurs. Le résultat est souvent un modèle avec une **précision supérieure** et une meilleure capacité de généralisation qu’un arbre de décision unique. De plus, les random forests peuvent fournir une estimation de l’importance des fonctionnalités (en examinant dans quelle mesure chaque division basée sur une fonctionnalité réduit l’impureté en moyenne).

Les random forests sont devenus un **outil de référence en cybersécurité** pour des tâches telles que la détection d’intrusion, la classification des malwares et la détection du spam. Ils offrent souvent de bonnes performances immédiatement, avec un réglage minimal, et peuvent gérer de grands ensembles de fonctionnalités. Par exemple, dans la détection d’intrusion, un random forest peut être plus performant qu’un arbre de décision individuel en détectant des schémas d’attaque plus subtils avec moins de faux positifs. Des recherches ont montré que les random forests étaient performants par rapport à d’autres algorithmes pour la classification d’attaques dans des jeux de données tels que NSL-KDD et UNSW-NB15.<sup>[[6]](#references)</sup><sup>[[7]](#references)</sup>

#### **Caractéristiques principales des Random Forests :**

-   **Type de problème :** principalement la classification (également utilisé pour la régression). Très bien adapté aux données structurées de grande dimension courantes dans les logs de sécurité.

-   **Interprétabilité :** inférieure à celle d’un arbre de décision unique -- il n’est pas facile de visualiser ou d’expliquer des centaines d’arbres à la fois. Cependant, les scores d’importance des fonctionnalités donnent une indication des attributs les plus influents.

-   **Avantages :** précision généralement supérieure à celle des modèles basés sur un seul arbre grâce à l’effet d’ensemble. Résistance au surapprentissage -- même si les arbres individuels surapprennent, l’ensemble généralise mieux. Gère les fonctionnalités numériques et catégorielles et peut prendre en charge les données manquantes dans une certaine mesure. Il est également relativement robuste aux valeurs aberrantes.

-   **Limitations :** la taille du modèle peut être importante (de nombreux arbres, chacun pouvant être profond). Les prédictions sont plus lentes que celles d’un arbre unique (car il faut agréger les résultats de nombreux arbres). Interprétabilité moindre -- même si vous connaissez les fonctionnalités importantes, la logique exacte n’est pas facilement traçable sous la forme d’une règle simple. Si le jeu de données est extrêmement dimensionnel et creux, l’entraînement d’un très grand forest peut être coûteux en ressources de calcul.

-   **Processus d’entraînement :**
1. **Échantillonnage bootstrap** : échantillonner aléatoirement les données d’entraînement avec remise afin de créer plusieurs sous-ensembles (échantillons bootstrap).
2. **Construction des arbres** : pour chaque échantillon bootstrap, construire un arbre de décision en utilisant un sous-ensemble aléatoire de fonctionnalités à chaque division. Cela introduit de la diversité entre les arbres.
3. **Agrégation** : pour les tâches de classification, la prédiction finale est obtenue en prenant le vote majoritaire parmi les prédictions de tous les arbres. Pour les tâches de régression, la prédiction finale est la moyenne des prédictions de tous les arbres.

<details>
<summary>Exemple -- Random Forest pour la détection d’intrusion (NSL-KDD) :</summary>
Nous utiliserons le même jeu de données NSL-KDD (étiqueté en deux classes : normal ou anomalie) et entraînerons un classifieur Random Forest. Nous nous attendons à ce que le random forest soit aussi performant, voire plus performant, que l’arbre de décision unique, grâce à la réduction de la variance obtenue par la moyenne des résultats de l’ensemble. Nous l’évaluerons avec les mêmes métriques.
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
La forêt aléatoire obtient généralement de bons résultats pour cette tâche de détection d'intrusion. Nous pourrions observer une amélioration des métriques telles que le F1 ou l'AUC par rapport à un arbre de décision unique, notamment en matière de rappel ou de précision, selon les données. Cela correspond à l'idée selon laquelle *« Random Forest (RF) est un classifieur d'ensemble et donne de bons résultats par rapport aux autres classifieurs traditionnels pour une classification efficace des attaques. »*.<sup>[[6]](#references)</sup> Dans un contexte d'opérations de sécurité, un modèle de forêt aléatoire pourrait signaler les attaques de manière plus fiable tout en réduisant les fausses alertes, grâce à la moyenne de nombreuses règles de décision. L'importance des features calculée par la forêt pourrait nous indiquer quelles features réseau sont les plus révélatrices d'attaques (par exemple, certains services réseau ou des nombres inhabituels de paquets).

</details>

### Support Vector Machines (SVM)

Les Support Vector Machines sont de puissants modèles d'apprentissage supervisé principalement utilisés pour la classification (ainsi que pour la régression avec SVR). Un SVM tente de trouver l'**hyperplan séparateur optimal** qui maximise la marge entre deux classes. Seul un sous-ensemble des points d'entraînement (les « vecteurs de support » les plus proches de la frontière) détermine la position de cet hyperplan. En maximisant la marge (la distance entre les vecteurs de support et l'hyperplan), les SVM tendent à obtenir une bonne capacité de généralisation.<sup>[[8]](#references)</sup>

La puissance des SVM repose notamment sur leur capacité à utiliser des **fonctions kernel** pour gérer les relations non linéaires. Les données peuvent être transformées implicitement dans un espace de features de dimension supérieure où un séparateur linéaire peut exister. Les kernels courants incluent les kernels polynomial, à fonction de base radiale (RBF) et sigmoïde. Par exemple, si les classes de trafic réseau ne sont pas séparables linéairement dans l'espace de features brutes, un kernel RBF peut les projeter dans une dimension supérieure où le SVM trouve une séparation linéaire (ce qui correspond à une frontière non linéaire dans l'espace d'origine). La flexibilité offerte par le choix des kernels permet aux SVM de traiter une grande variété de problèmes.

Les SVM sont réputés efficaces dans les situations impliquant des espaces de features de grande dimension (comme les données textuelles ou les séquences d'opcodes de malware) et lorsque le nombre de features est élevé par rapport au nombre d'échantillons. Ils étaient populaires dans de nombreuses premières applications de cybersécurité, telles que la classification de malware et la détection d'intrusion fondée sur les anomalies dans les années 2000, et affichaient souvent une grande précision.

Cependant, les SVM ne passent pas facilement à l'échelle de jeux de données très volumineux (la complexité de l'entraînement est superlinéaire par rapport au nombre d'échantillons et l'utilisation mémoire peut être élevée, car le modèle peut devoir stocker de nombreux vecteurs de support). En pratique, pour des tâches telles que la détection d'intrusion réseau avec des millions d'enregistrements, un SVM peut être trop lent sans sous-échantillonnage soigneux ou sans recours à des méthodes approximatives.

#### **Caractéristiques principales des SVM :**

-   **Type de problème :** Classification (binaire ou multiclasse via one-vs-one/one-vs-rest) et variantes de régression. Souvent utilisés pour la classification binaire avec une séparation nette par la marge.

-   **Interprétabilité :** Moyenne -- les SVM sont moins interprétables que les arbres de décision ou la régression logistique. Bien qu'il soit possible d'identifier les points de données qui sont des vecteurs de support et d'avoir une idée des features potentiellement influentes (grâce aux poids dans le cas d'un kernel linéaire), les SVM (en particulier avec des kernels non linéaires) sont en pratique considérés comme des classifieurs boîtes noires.

-   **Avantages :** Efficaces dans les espaces de grande dimension ; capables de modéliser des frontières de décision complexes grâce au kernel trick ; robustes au surapprentissage lorsque la marge est maximisée (notamment avec un paramètre de régularisation C approprié) ; fonctionnent bien même lorsque les classes ne sont pas séparées par une grande distance (ils trouvent la meilleure frontière de compromis).

-   **Limitations :** **Exigeants en ressources de calcul** pour les grands jeux de données (l'entraînement et la prédiction passent mal à l'échelle lorsque les données augmentent). Nécessitent un réglage soigneux des paramètres du kernel et de régularisation (C, type de kernel, gamma pour RBF, etc.). Ne fournissent pas directement de sorties probabilistes (bien qu'il soit possible d'utiliser le calibrage de Platt pour obtenir des probabilités). De plus, les SVM peuvent être sensibles au choix des paramètres du kernel --- un mauvais choix peut entraîner un sous-apprentissage ou un surapprentissage.

*Cas d'utilisation en cybersécurité :* les SVM ont été utilisés pour la **détection de malware** (par exemple, la classification de fichiers à partir de features extraites ou de séquences d'opcodes), la **détection d'anomalies réseau** (classification du trafic comme normal ou malveillant) et la **détection de phishing** (à l'aide de features d'URL). Par exemple, un SVM pourrait utiliser les features d'un e-mail (nombre de mots-clés spécifiques, scores de réputation de l'expéditeur, etc.) et le classer comme phishing ou légitime. Ils ont également été appliqués à la **détection d'intrusion** sur des jeux de features tels que KDD, en obtenant souvent une grande précision au prix d'un coût de calcul élevé.

<details>
<summary>Exemple -- SVM pour la classification de malware :</summary>
Nous utiliserons à nouveau le jeu de données de sites web de phishing, cette fois avec un SVM. Comme les SVM peuvent être lents, nous utiliserons si nécessaire un sous-ensemble des données pour l'entraînement (le jeu de données contient environ 11 000 instances, ce que le SVM peut gérer raisonnablement). Nous utiliserons un kernel RBF, un choix courant pour les données non linéaires, et activerons les estimations de probabilité afin de calculer la ROC AUC.
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
Le modèle SVM produira des métriques que nous pourrons comparer à celles de la régression logistique sur la même tâche. Nous pourrions constater que le SVM atteint une précision et une AUC élevées si les données sont bien séparées par les features. À l'inverse, si le dataset contient beaucoup de bruit ou des classes qui se chevauchent, le SVM pourrait ne pas surpasser significativement la régression logistique. En pratique, les SVM peuvent offrir de meilleures performances lorsqu'il existe des relations complexes et non linéaires entre les features et la classe — le kernel RBF peut capturer des frontières de décision courbes que la régression logistique ne pourrait pas modéliser. Comme pour tous les modèles, un réglage minutieux de `C` (régularisation) et des paramètres du kernel (comme `gamma` pour RBF) est nécessaire pour équilibrer le biais et la variance.

</details>

#### Différences entre la régression logistique et le SVM

| Aspect | **Régression logistique** | **Machines à vecteurs de support** |
|---|---|---|
| **Fonction objectif** | Minimise la **log-loss** (entropie croisée). | Maximise la **marge** tout en minimisant la **hinge-loss**. |
| **Frontière de décision** | Trouve l'**hyperplan le mieux ajusté** qui modélise _P(y\|x)_. | Trouve l'**hyperplan à marge maximale** (plus grand écart avec les points les plus proches). |
| **Sortie** | **Probabiliste** — fournit des probabilités de classe calibrées via σ(w·x + b). | **Déterministe** — renvoie des labels de classe ; les probabilités nécessitent un traitement supplémentaire (par exemple, le scaling de Platt). |
| **Régularisation** | L2 (par défaut) ou L1, équilibre directement le sous-ajustement et le surajustement. | Le paramètre C établit un compromis entre la largeur de la marge et les mauvaises classifications ; les paramètres du kernel ajoutent de la complexité. |
| **Kernels / Non-linéaire** | La forme native est **linéaire** ; la non-linéarité est ajoutée par feature engineering. | Le **kernel trick** intégré (RBF, poly, etc.) permet de modéliser des frontières complexes dans un espace de grande dimension. |
| **Scalabilité** | Résout une optimisation convexe en **O(nd)** ; gère efficacement les valeurs de n très élevées. | L'entraînement peut nécessiter **O(n²–n³)** en mémoire/temps sans solveurs spécialisés ; moins adapté aux valeurs de n très élevées. |
| **Interprétabilité** | **Élevée** — les poids indiquent l'influence des features ; l'odds ratio est intuitif. | **Faible** pour les kernels non linéaires ; les support vectors sont épars, mais difficiles à expliquer. |
| **Sensibilité aux outliers** | Utilise une log-loss lisse → moins sensible. | La hinge-loss avec une marge dure peut être **sensible** ; la marge souple (C) atténue ce problème. |
| **Cas d'utilisation courants** | Évaluation du risque de crédit, risque médical, tests A/B — lorsque les **probabilités et l'explicabilité** sont importantes. | Classification d'images/de texte, bio-informatique — lorsque les **frontières complexes** et les **données de grande dimension** sont importantes. |

* **Si vous avez besoin de probabilités calibrées, d'interprétabilité ou si vous travaillez sur d'énormes datasets — choisissez la régression logistique.**
* **Si vous avez besoin d'un modèle flexible capable de capturer des relations non linéaires sans feature engineering manuel — choisissez le SVM (avec des kernels).**
* Les deux optimisent des objectifs convexes, donc les **minimums globaux sont garantis**, mais les kernels du SVM ajoutent des hyperparamètres et un coût de calcul.

### Naive Bayes

Naive Bayes est une famille de **classifieurs probabilistes** fondée sur l'application du théorème de Bayes avec une forte hypothèse d'indépendance entre les features. Malgré cette hypothèse « naïve », Naive Bayes fonctionne souvent étonnamment bien pour certaines applications, notamment celles impliquant des données textuelles ou catégorielles, comme la détection de spam.<sup>[[9]](#references)</sup>


#### Théorème de Bayes

Le théorème de Bayes constitue le fondement des classifieurs Naive Bayes. Il établit une relation entre les probabilités conditionnelles et marginales d'événements aléatoires. La formule est la suivante :
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Where:
- `P(A|B)` est la probabilité a posteriori de la classe `A` étant donné la feature `B`.
- `P(B|A)` est la vraisemblance de la feature `B` étant donné la classe `A`.
- `P(A)` est la probabilité a priori de la classe `A`.
- `P(B)` est la probabilité a priori de la feature `B`.

Par exemple, si nous voulons déterminer si un texte a été écrit par un enfant ou un adulte, nous pouvons utiliser les mots du texte comme features. À partir de données initiales, le classifieur Naive Bayes calculera au préalable les probabilités que chaque mot appartienne à chacune des classes possibles (enfant ou adulte). Lorsqu'un nouveau texte est fourni, il calculera la probabilité de chaque classe possible étant donné les mots du texte, puis choisira la classe ayant la probabilité la plus élevée.

Comme vous pouvez le constater dans cet exemple, le classifieur Naive Bayes est très simple et rapide, mais il suppose que les features sont indépendantes, ce qui n'est pas toujours le cas dans les données du monde réel.


#### Types de classifieurs Naive Bayes

Il existe plusieurs types de classifieurs Naive Bayes, selon le type de données et la distribution des features :
- **Gaussian Naive Bayes** : suppose que les features suivent une distribution gaussienne (normale). Il convient aux données continues.
- **Multinomial Naive Bayes** : suppose que les features suivent une distribution multinomiale. Il convient aux données discrètes, comme le nombre de mots dans la classification de texte.
- **Bernoulli Naive Bayes** : suppose que les features sont binaires (0 ou 1). Il convient aux données binaires, comme la présence ou l'absence de mots dans la classification de texte.
- **Categorical Naive Bayes** : suppose que les features sont des variables catégorielles. Il convient aux données catégorielles, comme la classification de fruits selon leur couleur et leur forme.


#### **Caractéristiques clés de Naive Bayes :**

-   **Type de problème :** Classification (binaire ou multi-classe). Couramment utilisé pour les tâches de classification de texte en cybersécurité (spam, phishing, etc.).

-   **Interprétabilité :** Moyenne -- il n'est pas aussi directement interprétable qu'un arbre de décision, mais il est possible d'examiner les probabilités apprises (par exemple, les mots les plus susceptibles d'apparaître dans les emails spam par rapport aux emails légitimes). La forme du modèle (les probabilités de chaque feature étant donnée la classe) peut être comprise si nécessaire.

-   **Avantages :** Entraînement et prédiction **très rapides**, même sur de grands datasets (linéaires par rapport au nombre d'instances * au nombre de features). Nécessite une quantité relativement faible de données pour estimer les probabilités de manière fiable, notamment avec un lissage approprié. Il est souvent étonnamment précis comme baseline, en particulier lorsque les features contribuent indépendamment aux informations permettant de déterminer la classe. Fonctionne bien avec les données à haute dimension (par exemple, des milliers de features issues de texte). Aucun réglage complexe n'est nécessaire au-delà de la définition d'un paramètre de lissage.

-   **Limitations :** L'hypothèse d'indépendance peut limiter la précision si les features sont fortement corrélées. Par exemple, dans les données réseau, des features comme `src_bytes` et `dst_bytes` peuvent être corrélées ; Naive Bayes ne capturera pas cette interaction. Lorsque la taille des données devient très importante, des modèles plus expressifs (comme les ensembles ou les réseaux neuronaux) peuvent dépasser NB en apprenant les dépendances entre les features. De plus, si une combinaison particulière de features est nécessaire pour identifier une attaque (et pas seulement des features individuelles contribuant indépendamment), NB rencontrera des difficultés.

> [!TIP]
> *Cas d'utilisation en cybersécurité :* L'utilisation classique est la **détection du spam** -- Naive Bayes était au cœur des premiers filtres anti-spam, qui utilisaient les fréquences de certains tokens (mots, expressions, adresses IP) pour calculer la probabilité qu'un email soit un spam. Il est également utilisé pour la **détection des emails de phishing** et la **classification d'URL**, où la présence de certains mots-clés ou caractéristiques (comme "login.php" dans une URL ou `@` dans un chemin d'URL) contribue à la probabilité de phishing. Dans l'analyse de malware, on pourrait imaginer un classifieur Naive Bayes qui utiliserait la présence de certains appels API ou permissions dans un logiciel pour prédire s'il s'agit d'un malware. Même si des algorithmes plus avancés offrent souvent de meilleures performances, Naive Bayes reste une bonne baseline grâce à sa rapidité et sa simplicité.

<details>
<summary>Exemple -- Naive Bayes pour la détection de phishing :</summary>
Pour démontrer Naive Bayes, nous utiliserons Gaussian Naive Bayes sur le dataset d'intrusion NSL-KDD (avec des labels binaires). Gaussian NB traitera chaque feature comme suivant une distribution normale pour chaque classe. Il s'agit d'un choix approximatif, car de nombreuses features réseau sont discrètes ou fortement asymétriques, mais cela montre comment appliquer NB à des données de features continues. Nous pourrions également choisir Bernoulli NB sur un dataset de features binaires (comme un ensemble d'alertes déclenchées), mais nous resterons ici sur NSL-KDD pour assurer la continuité.
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
Ce code entraîne un classifieur Naive Bayes pour détecter les attaques. Naive Bayes calculera des éléments tels que `P(service=http | Attack)` et `P(Service=http | Normal)` à partir des données d'entraînement, en supposant l'indépendance entre les caractéristiques. Il utilisera ensuite ces probabilités pour classer les nouvelles connexions comme normales ou comme des attaques, en fonction des caractéristiques observées. Les performances de NB sur NSL-KDD peuvent ne pas être aussi élevées que celles de modèles plus avancés (car l'indépendance entre les caractéristiques n'est pas respectée), mais elles sont souvent correctes et s'accompagnent d'un avantage en termes de rapidité extrême. Dans des scénarios tels que le filtrage d'e-mails en temps réel ou le triage initial d'URLs, un modèle Naive Bayes peut rapidement signaler les cas manifestement malveillants avec une faible utilisation des ressources.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors est l'un des algorithmes de machine learning les plus simples. Il s'agit d'une méthode **non paramétrique, basée sur les instances** qui effectue des prédictions en fonction de la similarité avec les exemples de l'ensemble d'entraînement. Pour la classification, l'idée est la suivante : pour classer un nouveau point de données, trouver les **k** points les plus proches dans les données d'entraînement (ses « voisins les plus proches »), puis lui attribuer la classe majoritaire parmi ces voisins. La « proximité » est définie par une métrique de distance, généralement la distance euclidienne pour les données numériques (d'autres distances peuvent être utilisées selon le type de caractéristiques ou le problème).<sup>[[10]](#references)</sup>

K-NN ne nécessite *aucun entraînement explicite* -- la phase d'« entraînement » consiste simplement à stocker l'ensemble de données. Tout le travail est effectué lors de la requête (prédiction) : l'algorithme doit calculer les distances entre le point interrogé et tous les points d'entraînement afin de trouver les plus proches. Le temps de prédiction est donc **linéaire par rapport au nombre d'échantillons d'entraînement**, ce qui peut être coûteux pour les grands ensembles de données. Pour cette raison, k-NN convient surtout aux ensembles de données plus petits ou aux scénarios où l'on peut accepter un compromis entre mémoire et rapidité au profit de la simplicité.

Malgré sa simplicité, k-NN peut modéliser des frontières de décision très complexes (puisque, dans les faits, la frontière de décision peut prendre n'importe quelle forme dictée par la répartition des exemples). Il tend à être performant lorsque la frontière de décision est très irrégulière et que l'on dispose de nombreuses données -- il permet essentiellement aux données de « parler d'elles-mêmes ». Cependant, dans les espaces de grande dimension, les métriques de distance peuvent devenir moins pertinentes (fléau de la dimension), et la méthode peut rencontrer des difficultés à moins de disposer d'un très grand nombre d'échantillons.

*Cas d'utilisation en cybersécurité :* k-NN a été appliqué à la détection d'anomalies -- par exemple, un système de détection d'intrusion peut étiqueter un événement réseau comme malveillant si la majorité de ses voisins les plus proches (événements précédents) étaient malveillants. Si le trafic normal forme des clusters et que les attaques sont des valeurs aberrantes, une approche K-NN (avec k=1 ou une petite valeur de k) constitue essentiellement une **détection d'anomalies par le plus proche voisin**. K-NN a également été utilisé pour classer les familles de malware à l'aide de vecteurs de caractéristiques binaires : un nouveau fichier peut être classé dans une famille de malware donnée s'il est très proche (dans l'espace des caractéristiques) d'instances connues de cette famille. En pratique, k-NN est moins courant que les algorithmes plus évolutifs, mais il est conceptuellement simple et parfois utilisé comme référence ou pour des problèmes de petite échelle.

#### **Caractéristiques principales de k-NN :**

-   **Type de problème :** Classification (des variantes pour la régression existent). Il s'agit d'une méthode d'*apprentissage paresseux* -- aucun ajustement explicite de modèle n'est effectué.

-   **Interprétabilité :** Faible à moyenne -- il n'existe ni modèle global ni explication concise, mais les résultats peuvent être interprétés en examinant les voisins les plus proches qui ont influencé une décision (par exemple : « ce flux réseau a été classé comme malveillant parce qu'il est similaire à ces 3 flux malveillants connus »). Les explications peuvent donc être fondées sur des exemples.

-   **Avantages :** Très simple à implémenter et à comprendre. Ne fait aucune hypothèse sur la distribution des données (non paramétrique). Peut naturellement gérer les problèmes à classes multiples. Il est **adaptatif**, dans le sens où les frontières de décision peuvent être très complexes et façonnées par la distribution des données.

-   **Limitations :** La prédiction peut être lente pour les grands ensembles de données (de nombreuses distances doivent être calculées). Nécessite beaucoup de mémoire -- toutes les données d'entraînement sont stockées. Les performances se dégradent dans les espaces de caractéristiques de grande dimension, car tous les points tendent à devenir presque équidistants (ce qui rend le concept de « plus proche » moins pertinent). Il faut choisir *k* (le nombre de voisins) de manière appropriée -- une valeur de k trop petite peut produire du bruit, tandis qu'une valeur trop grande peut inclure des points non pertinents appartenant à d'autres classes. Les caractéristiques doivent également être mises à l'échelle correctement, car les calculs de distance sont sensibles à l'échelle.

<details>
<summary>Example -- k-NN for Phishing Detection:</summary>

Nous utiliserons à nouveau NSL-KDD (classification binaire). Comme k-NN est coûteux en calcul, nous utiliserons un sous-ensemble des données d'entraînement afin de rendre cette démonstration exploitable. Nous choisirons, par exemple, 20 000 échantillons d'entraînement parmi les 125k au total, et utiliserons k=5 voisins. Après l'entraînement (qui consiste en réalité simplement à stocker les données), nous évaluerons le modèle sur l'ensemble de test. Nous mettrons également les caractéristiques à l'échelle pour le calcul des distances, afin qu'aucune caractéristique ne domine en raison de son échelle.
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
Le modèle k-NN classera une connexion en examinant les 5 connexions les plus proches dans le sous-ensemble de données d'entraînement. Si, par exemple, 4 de ces voisines sont des attaques (anomalies) et 1 est normale, la nouvelle connexion sera classée comme une attaque. Les performances peuvent être raisonnables, bien qu'elles soient souvent moins élevées que celles d'un Random Forest ou d'un SVM correctement optimisé sur les mêmes données. Cependant, k-NN peut parfois se montrer particulièrement efficace lorsque les distributions des classes sont très irrégulières et complexes -- en utilisant essentiellement une recherche fondée sur la mémoire. En cybersécurité, k-NN (avec k=1 ou une petite valeur de k) peut être utilisé pour détecter des attack patterns connues par l'exemple, ou comme composant de systèmes plus complexes (par exemple, pour effectuer un clustering, puis classifier selon l'appartenance à un cluster).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Les Gradient Boosting Machines font partie des algorithmes les plus puissants pour les données structurées. **Gradient boosting** désigne la technique consistant à construire un ensemble de weak learners (souvent des decision trees) de manière séquentielle, chaque nouveau modèle corrigeant les erreurs de l'ensemble précédent. Contrairement au bagging (Random Forests), qui construit les arbres en parallèle et en fait la moyenne, le boosting construit les arbres *un par un*, chacun se concentrant davantage sur les instances que les arbres précédents ont mal prédites.<sup>[[11]](#references)</sup>

Les implémentations les plus populaires de ces dernières années sont **XGBoost**, **LightGBM** et **CatBoost**, qui sont toutes des bibliothèques de gradient boosting decision tree (GBDT). Elles ont rencontré un immense succès dans les compétitions de machine learning et dans les applications concrètes, obtenant souvent des **performances de pointe sur les jeux de données tabulaires**. En cybersécurité, les chercheurs et les professionnels ont utilisé des arbres de gradient boosting pour des tâches telles que la **détection de malware** (à l'aide de features extraites des fichiers ou du comportement à l'exécution) et la **détection d'intrusion réseau**. Par exemple, un modèle de gradient boosting peut combiner de nombreuses règles faibles (arbres), telles que « si de nombreux paquets SYN et un port inhabituel -> scan probable », afin de créer un détecteur composite puissant qui tient compte de nombreux patterns subtils.

Pourquoi les boosted trees sont-ils si efficaces ? Chaque arbre de la séquence est entraîné sur les *erreurs résiduelles* (gradients) des prédictions de l'ensemble actuel. Ainsi, le modèle **« booste »** progressivement les zones dans lesquelles il est faible. L'utilisation de decision trees comme base learners permet au modèle final de capturer des interactions complexes et des relations non linéaires. De plus, le boosting intègre une forme de regularization : en ajoutant de nombreux petits arbres (et en utilisant un learning rate pour mettre à l'échelle leurs contributions), il se généralise souvent bien sans overfitting majeur, à condition de choisir les paramètres appropriés.

#### **Caractéristiques principales du Gradient Boosting :**

-   **Type de problème :** Principalement la classification et la régression. En sécurité, il s'agit généralement de classification (par exemple, classifier une connexion ou un fichier en deux catégories). Il gère les problèmes binaires, multi-classes (avec une loss appropriée) et même les problèmes de ranking.

-   **Interprétabilité :** Faible à moyenne. Bien qu'un boosted tree individuel soit petit, un modèle complet peut comporter des centaines d'arbres, ce qui le rend difficilement interprétable par l'humain dans son ensemble. Cependant, comme Random Forest, il peut fournir des scores d'importance des features, et des outils tels que SHAP (SHapley Additive exPlanations) peuvent être utilisés pour interpréter dans une certaine mesure les prédictions individuelles.

-   **Avantages :** Il s'agit souvent de l'algorithme **le plus performant** pour les données structurées/tabulaires. Il peut détecter des patterns et des interactions complexes. Il dispose de nombreux paramètres de réglage (nombre d'arbres, profondeur des arbres, learning rate, termes de regularization) permettant d'adapter la complexité du modèle et d'empêcher l'overfitting. Les implémentations modernes sont optimisées pour la vitesse (par exemple, XGBoost utilise des informations de gradient du second ordre et des structures de données efficaces). Il tend à mieux gérer les données déséquilibrées lorsqu'il est associé à des fonctions de perte appropriées ou lorsque les poids des échantillons sont ajustés.

-   **Limitations :** Plus complexe à régler que les modèles plus simples ; l'entraînement peut être lent si les arbres sont profonds ou si leur nombre est élevé (bien qu'il soit généralement toujours plus rapide que l'entraînement d'un deep neural network comparable sur les mêmes données). Le modèle peut faire de l'overfitting s'il n'est pas correctement réglé (par exemple, trop d'arbres profonds avec une regularization insuffisante). En raison du grand nombre d'hyperparamètres, une utilisation efficace du gradient boosting peut nécessiter davantage d'expertise ou d'expérimentation. De plus, comme les méthodes fondées sur les arbres, il ne gère pas intrinsèquement les données très éparses et de grande dimension aussi efficacement que les modèles linéaires ou Naive Bayes (bien qu'il puisse tout de même être appliqué, par exemple à la classification de textes, mais qu'il ne soit peut-être pas le premier choix sans feature engineering).

> [!TIP]
> *Cas d'utilisation en cybersécurité :* Presque partout où un decision tree ou un random forest pourrait être utilisé, un modèle de gradient boosting peut atteindre une meilleure précision. Par exemple, les compétitions de **détection de malware de Microsoft** ont largement utilisé XGBoost sur des features conçues à partir de fichiers binaires. Les travaux de recherche sur la **détection d'intrusion réseau** rapportent souvent les meilleurs résultats avec des GBDT (par exemple, XGBoost sur les datasets CIC-IDS2017 ou UNSW-NB15). Ces modèles peuvent utiliser un large éventail de features (types de protocoles, fréquence de certains événements, features statistiques du trafic, etc.) et les combiner pour détecter les threats. Dans la détection de phishing, le gradient boosting peut combiner les features lexicales des URLs, les features de réputation des domaines et les features du contenu des pages afin d'atteindre une très grande précision. L'approche par ensemble aide à couvrir de nombreux cas particuliers et subtilités des données.

<details>
<summary>Exemple -- XGBoost for Phishing Detection:</summary>
Nous utiliserons un classifieur de gradient boosting sur le dataset de phishing. Pour garder les choses simples et autonomes, nous utiliserons `sklearn.ensemble.GradientBoostingClassifier` (qui est une implémentation plus lente, mais simple à utiliser). Normalement, on pourrait utiliser les bibliothèques `xgboost` ou `lightgbm` pour obtenir de meilleures performances et des fonctionnalités supplémentaires. Nous entraînerons le modèle et l'évaluerons de manière similaire à précédemment.
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
Le modèle de Gradient Boosting atteindra probablement une très grande précision et un AUC élevé sur ce dataset de phishing (avec un réglage approprié, ces modèles peuvent souvent dépasser 95 % de précision sur ce type de données, comme l'indique la littérature. Cela démontre pourquoi les GBDTs sont considérés comme *« le modèle state of the art pour les datasets tabulaires »* : ils surpassent souvent les algorithmes plus simples en capturant des patterns complexes.<sup>[[11]](#references)</sup> Dans un contexte de cybersécurité, cela pourrait permettre de détecter davantage de sites de phishing ou d'attaques avec moins de faux négatifs. Bien sûr, il faut se méfier de l'overfitting : lors du développement d'un tel modèle pour son déploiement, on utiliserait généralement des techniques comme la cross-validation et on surveillerait les performances sur un validation set.

</details>

### Combinaison de modèles : Ensemble Learning et Stacking

L'Ensemble Learning est une stratégie qui consiste à **combiner plusieurs modèles** afin d'améliorer les performances globales. Nous avons déjà vu des méthodes d'ensemble spécifiques : Random Forest (un ensemble d'arbres utilisant le bagging) et Gradient Boosting (un ensemble d'arbres utilisant le boosting séquentiel). Mais les ensembles peuvent également être créés d'autres manières, comme les **voting ensembles** ou la **stacked generalization (stacking)**. L'idée principale est que différents modèles peuvent capturer différents patterns ou présenter des faiblesses différentes ; en les combinant, nous pouvons **compenser les erreurs de chaque modèle par les points forts d'un autre**.<sup>[[12]](#references)</sup>

-   **Voting Ensemble :** Dans un classifieur utilisant un vote simple, nous entraînons plusieurs modèles diversifiés (par exemple, une régression logistique, un arbre de décision et un SVM), puis nous les faisons voter pour la prédiction finale (vote majoritaire pour la classification). Si nous pondérons les votes (par exemple, en attribuant un poids plus élevé aux modèles les plus précis), il s'agit d'un weighted voting scheme. Cela améliore généralement les performances lorsque les modèles individuels sont raisonnablement bons et indépendants : l'ensemble réduit le risque d'erreur d'un modèle individuel, car les autres peuvent la corriger. C'est comme disposer d'un panel d'experts plutôt que d'un seul avis.

-   **Stacking (Stacked Ensemble) :** Le stacking va un peu plus loin. Au lieu d'un simple vote, il entraîne un **meta-model** pour **apprendre à combiner au mieux les prédictions** des modèles de base. Par exemple, vous entraînez 3 classifieurs différents (base learners), puis vous fournissez leurs sorties (ou probabilités) comme features à un meta-classifier (souvent un modèle simple comme la régression logistique), qui apprend la manière optimale de les combiner. Le meta-model est entraîné sur un validation set ou via la cross-validation afin d'éviter l'overfitting. Le stacking peut souvent surpasser le simple vote en apprenant *quels modèles privilégier selon les circonstances*. En cybersécurité, un modèle peut être plus efficace pour détecter les network scans, tandis qu'un autre peut mieux détecter le malware beaconing ; un modèle de stacking pourrait apprendre à s'appuyer correctement sur chacun d'eux.

Les ensembles, qu'ils utilisent le vote ou le stacking, ont tendance à **améliorer la précision** et la robustesse. Leur inconvénient réside dans une complexité accrue et parfois une interprétabilité réduite (bien que certaines approches d'ensemble, comme la moyenne de decision trees, puissent tout de même fournir des informations utiles, par exemple l'importance des features). En pratique, si les contraintes opérationnelles le permettent, l'utilisation d'un ensemble peut entraîner des taux de détection plus élevés. De nombreuses solutions gagnantes dans les challenges de cybersécurité (et dans les compétitions Kaggle en général) utilisent des techniques d'ensemble pour obtenir le dernier gain de performance possible.

<details>
<summary>Exemple -- Voting Ensemble pour la détection de phishing :</summary>
Pour illustrer le model stacking, combinons quelques-uns des modèles présentés sur le dataset de phishing. Nous utiliserons une régression logistique, un arbre de décision et un k-NN comme base learners, ainsi qu'un Random Forest comme meta-learner pour agréger leurs prédictions. Le meta-learner sera entraîné sur les sorties des base learners (en utilisant la cross-validation sur le training set). Nous nous attendons à ce que le modèle stacké soit aussi performant, voire légèrement plus performant, que les modèles individuels.
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
Le stacking ensemble tire parti des forces complémentaires des modèles de base. Par exemple, la régression logistique peut traiter les aspects linéaires des données, l'arbre de décision peut capturer certaines interactions spécifiques semblables à des règles, et k-NN peut être particulièrement performant dans les voisinages locaux de l'espace des caractéristiques. Le méta-modèle (ici, un random forest) peut apprendre à pondérer ces entrées. Les métriques obtenues montrent souvent une amélioration (même légère) par rapport aux métriques de n'importe quel modèle pris individuellement. Dans notre exemple de phishing, si la régression logistique seule obtenait un score F1 de, disons, 0,95 et l'arbre 0,94, le stacking pourrait atteindre 0,96 en compensant les erreurs de chaque modèle.

Les méthodes d'ensemble comme celle-ci illustrent le principe selon lequel *« combiner plusieurs modèles mène généralement à une meilleure généralisation »*.<sup>[[12]](#references)</sup> En cybersécurité, cela peut être mis en œuvre en utilisant plusieurs moteurs de détection (l'un peut être basé sur des règles, un autre sur le machine learning et un autre sur la détection d'anomalies), puis une couche qui agrège leurs alertes -- formant ainsi une sorte d'ensemble -- afin de prendre une décision finale avec un niveau de confiance supérieur. Lors du déploiement de tels systèmes, il faut tenir compte de la complexité supplémentaire et s'assurer que l'ensemble ne devienne pas trop difficile à gérer ou à expliquer. Cependant, du point de vue de la précision, les ensembles et le stacking sont des outils puissants pour améliorer les performances des modèles.

</details>

Les approches basées sur les réseaux neuronaux décrites dans la [page sur le deep learning](AI-Deep-Learning.md) peuvent compléter ces modèles classiques pour la détection d'intrusions lorsque le jeu de données et le budget de calcul justifient cette complexité supplémentaire.<sup>[[13]](#references)</sup>

## References

- [1] [IA et machine learning en cybersécurité - zvelo](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [2] [La régression linéaire expliquée - Medium](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [3] [Régression logistique - Medium](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [4] [Sohail Ahmed Khan, Wasiq Khan, Abir Hussain - « Classification des attaques de phishing et des sites web à l'aide du machine learning et de plusieurs jeux de données (une analyse comparative) »](https://arxiv.org/pdf/2101.02552)
- [5] [Arbre de décision - GeeksforGeeks](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [6] [Reena Singh Rajput, Sanjay Agrawal - « Détection des attaques par déni de service à l'aide d'un classificateur random forest avec gain d'information »](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [7] [Raisa Abedin Disha, Sajjad Waheed - « Analyse des performances des modèles de machine learning pour un système de détection d'intrusions à l'aide de la technique de sélection de caractéristiques Gini Impurity-based Weighted Random Forest (GIWRF) »](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [8] [Qu'est-ce qu'une Support Vector Machine ? - IBM](https://www.ibm.com/think/topics/support-vector-machine)
- [9] [Filtrage des spams avec Naive Bayes - Wikipedia](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [10] [Qu'est-ce que k-Nearest Neighbors (KNN) ? - IBM](https://www.ibm.com/think/topics/knn)
- [11] [GBDT démystifié : comment fonctionnent LightGBM, XGBoost et CatBoost - Medium](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [12] [Ensemble learning : améliorer les performances des modèles en combinant leurs forces - Medium](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)
- [13] [Comment le deep learning améliore les systèmes de détection d'intrusions](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
{{#include ../banners/hacktricks-training.md}}
