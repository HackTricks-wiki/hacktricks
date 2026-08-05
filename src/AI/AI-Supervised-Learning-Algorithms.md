# Algoritmos de aprendizaje supervisado

{{#include ../banners/hacktricks-training.md}}

## Información básica

El aprendizaje supervisado utiliza datos etiquetados para entrenar modelos capaces de realizar predicciones sobre entradas nuevas que no se han visto anteriormente. En ciberseguridad, el aprendizaje automático supervisado se aplica ampliamente a tareas como la detección de intrusiones (clasificar el tráfico de red como *normal* o *ataque*), la detección de malware (distinguir el software malicioso del benigno), la detección de phishing (identificar sitios web o correos electrónicos fraudulentos) y el filtrado de spam, entre otras. Cada algoritmo tiene sus puntos fuertes y es adecuado para distintos tipos de problemas (clasificación o regresión). A continuación, revisamos algoritmos clave de aprendizaje supervisado, explicamos cómo funcionan y demostramos su uso con datasets reales de ciberseguridad. También analizamos cómo combinar modelos (aprendizaje en conjunto) puede mejorar a menudo el rendimiento predictivo.

## Algoritmos

-   **Regresión lineal:** Un algoritmo de regresión fundamental para predecir resultados numéricos mediante el ajuste de una ecuación lineal a los datos.

-   **Regresión logística:** Un algoritmo de clasificación (a pesar de su nombre) que utiliza una función logística para modelar la probabilidad de un resultado binario.

-   **Árboles de decisión:** Modelos estructurados en forma de árbol que dividen los datos según sus características para realizar predicciones; se utilizan a menudo por su interpretabilidad.

-   **Random Forests:** Un conjunto de árboles de decisión (mediante bagging) que mejora la precisión y reduce el overfitting.

-   **Support Vector Machines (SVM):** Clasificadores de margen máximo que encuentran el hiperplano de separación óptimo; pueden utilizar kernels para datos no lineales.

-   **Naive Bayes:** Un clasificador probabilístico basado en el teorema de Bayes, con la suposición de independencia entre las características, utilizado especialmente en el filtrado de spam.

-   **k-Nearest Neighbors (k-NN):** Un clasificador simple "basado en instancias" que asigna una etiqueta a una muestra según la clase mayoritaria de sus vecinos más cercanos.

-   **Gradient Boosting Machines:** Modelos de conjunto (por ejemplo, XGBoost, LightGBM) que construyen un predictor sólido mediante la adición secuencial de learners más débiles (normalmente árboles de decisión).

Cada sección a continuación proporciona una descripción mejorada del algoritmo y un **ejemplo de código en Python** utilizando bibliotecas como `pandas` y `scikit-learn` (y `PyTorch` para el ejemplo de red neuronal). Los ejemplos utilizan datasets de ciberseguridad disponibles públicamente (como NSL-KDD para la detección de intrusiones y un dataset de Phishing Websites) y siguen una estructura coherente:

1.  **Cargar el dataset** (descargarlo mediante una URL si está disponible).

2.  **Preprocesar los datos** (por ejemplo, codificar las características categóricas, escalar los valores y dividir los datos en conjuntos de entrenamiento y prueba).

3.  **Entrenar el modelo** con los datos de entrenamiento.

4.  **Evaluarlo** en un conjunto de prueba utilizando métricas: accuracy, precision, recall, F1-score y ROC AUC para la clasificación (y el error cuadrático medio para la regresión).

Profundicemos en cada algoritmo:

### Regresión lineal

La regresión lineal es un algoritmo de **regresión** utilizado para predecir valores numéricos continuos. Asume una relación lineal entre las características de entrada (variables independientes) y la salida (variable dependiente). El modelo intenta ajustar una línea recta (o un hiperplano en dimensiones superiores) que describa de la mejor manera la relación entre las características y el objetivo. Normalmente, esto se realiza minimizando la suma de los errores cuadrados entre los valores predichos y los reales (método de Mínimos Cuadrados Ordinarios).<sup>[[8]](#references)</sup>

La forma más sencilla de representar la regresión lineal es mediante una línea:
```plaintext
y = mx + b
```
Donde:

- `y` es el valor predicho (salida)
- `m` es la pendiente de la línea (coeficiente)
- `x` es la característica de entrada
- `b` es la intersección con el eje y

El objetivo de la regresión lineal es encontrar la línea que mejor se ajuste y que minimice la diferencia entre los valores predichos y los valores reales del conjunto de datos. Por supuesto, esto es muy sencillo: sería una línea recta que separaría 2 categorías, pero si se añaden más dimensiones, la línea se vuelve más compleja:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Casos de uso en ciberseguridad:* Linear regression por sí misma es menos común para tareas de seguridad principales (que suelen ser de clasificación), pero puede utilizarse para predecir resultados numéricos. Por ejemplo, se podría usar linear regression para **predecir el volumen del tráfico de red** o **estimar el número de ataques en un periodo de tiempo** basándose en datos históricos. También podría predecir una puntuación de riesgo o el tiempo esperado hasta la detección de un ataque, dados ciertos parámetros del sistema. En la práctica, los algoritmos de clasificación (como logistic regression o los árboles) se utilizan con más frecuencia para detectar intrusiones o malware, pero linear regression sirve como base y es útil para análisis orientados a la regresión.

#### **Características clave de Linear Regression:**

-   **Tipo de problema:** Regresión (predicción de valores continuos). No es adecuada para la clasificación directa a menos que se aplique un umbral a la salida.

-   **Interpretabilidad:** Alta -- los coeficientes son fáciles de interpretar y muestran el efecto lineal de cada característica.

-   **Ventajas:** Simple y rápida; una buena línea base para tareas de regresión; funciona bien cuando la relación real es aproximadamente lineal.

-   **Limitaciones:** No puede capturar relaciones complejas o no lineales (sin ingeniería manual de características); puede sufrir underfitting si las relaciones no son lineales; es sensible a los outliers, que pueden sesgar los resultados.

-   **Encontrar el mejor ajuste:** Para encontrar la línea de mejor ajuste que separa las categorías posibles, utilizamos un método llamado **Ordinary Least Squares (OLS)**. Este método minimiza la suma de las diferencias al cuadrado entre los valores observados y los valores predichos por el modelo lineal.

<details>
<summary>Ejemplo -- Predicción de la duración de las conexiones (regresión) en un dataset de intrusiones
</summary>
A continuación, mostramos linear regression utilizando el dataset de ciberseguridad NSL-KDD. Trataremos esto como un problema de regresión, prediciendo `duration` de las conexiones de red basándonos en otras características. (En realidad, `duration` es una característica de NSL-KDD; aquí la utilizamos únicamente para ilustrar la regresión). Cargamos el dataset, lo preprocesamos (codificamos las características categóricas), entrenamos un modelo de linear regression y evaluamos el Mean Squared Error (MSE) y la puntuación R² en un conjunto de prueba.
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
En este ejemplo, el modelo de regresión lineal intenta predecir `duration` de la conexión a partir de otras características de red. Medimos el rendimiento con el Error cuadrático medio (MSE) y R². Un R² cercano a 1.0 indicaría que el modelo explica la mayor parte de la varianza en `duration`, mientras que un R² bajo o negativo indica un ajuste deficiente. (No te sorprendas si el R² es bajo aquí: predecir `duration` puede ser difícil a partir de las características proporcionadas, y la regresión lineal podría no capturar los patrones si son complejos.)
</details>

### Regresión logística

La regresión logística es un algoritmo de **clasificación** que modela la probabilidad de que una instancia pertenezca a una clase determinada (normalmente la clase "positiva"). A pesar de su nombre, la regresión *logística* se utiliza para resultados discretos (a diferencia de la regresión lineal, que se utiliza para resultados continuos). Se usa especialmente para la **clasificación binaria** (dos clases, por ejemplo, maliciosa frente a benigna), pero puede ampliarse a problemas multiclase (mediante enfoques softmax o one-vs-rest).<sup>[[1]](#references)</sup>

La regresión logística utiliza la función logística (también conocida como función sigmoide) para convertir los valores predichos en probabilidades. Ten en cuenta que la función sigmoide es una función con valores entre 0 y 1 que crece siguiendo una curva en forma de S según las necesidades de la clasificación, lo que resulta útil para tareas de clasificación binaria. Por lo tanto, cada característica de cada entrada se multiplica por su peso asignado, y el resultado se pasa por la función sigmoide para producir una probabilidad:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Where:

- `p(y=1|x)` es la probabilidad de que la salida `y` sea 1 dado el valor de entrada `x`
- `e` es la base del logaritmo natural
- `z` es una combinación lineal de las características de entrada, normalmente representada como `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Observa que, de nuevo, en su forma más simple es una línea recta, pero en casos más complejos se convierte en un hiperplano con varias dimensiones (una por característica).

> [!TIP]
> *Casos de uso en ciberseguridad:* Debido a que muchos problemas de seguridad son esencialmente decisiones de sí/no, la regresión logística se utiliza ampliamente. Por ejemplo, un sistema de detección de intrusiones podría usar regresión logística para decidir si una conexión de red es un ataque basándose en las características de esa conexión. En la detección de phishing, la regresión logística puede combinar características de un sitio web (longitud de la URL, presencia del símbolo "@", etc.) para calcular la probabilidad de que sea phishing. Se ha utilizado en los filtros de spam de primera generación y sigue siendo una sólida referencia para muchas tareas de clasificación.

#### Regresión logística para clasificación no binaria

La regresión logística está diseñada para la clasificación binaria, pero puede ampliarse para manejar problemas multiclase mediante técnicas como **one-vs-rest** (OvR) o **softmax regression**. En OvR, se entrena un modelo de regresión logística independiente para cada clase, tratándola como la clase positiva frente a todas las demás. La clase con la probabilidad predicha más alta se elige como predicción final. Softmax regression generaliza la regresión logística a varias clases aplicando la función softmax a la capa de salida, lo que produce una distribución de probabilidad sobre todas las clases.

#### **Características clave de la regresión logística:**

-   **Tipo de problema:** Clasificación (normalmente binaria). Predice la probabilidad de la clase positiva.

-   **Interpretabilidad:** Alta -- al igual que en la regresión lineal, los coeficientes de las características pueden indicar cómo influye cada característica en los log-odds del resultado. Esta transparencia suele valorarse en seguridad para comprender qué factores contribuyen a una alerta.

-   **Ventajas:** Es sencilla y rápida de entrenar; funciona bien cuando la relación entre las características y los log-odds del resultado es lineal. Produce probabilidades, lo que permite asignar puntuaciones de riesgo. Con una regularización adecuada, generaliza bien y puede manejar la multicolinealidad mejor que la regresión lineal simple.

-   **Limitaciones:** Supone un límite de decisión lineal en el espacio de características (falla si el límite real es complejo/no lineal). Puede tener un rendimiento inferior en problemas donde las interacciones o los efectos no lineales son críticos, a menos que se añadan manualmente características polinómicas o de interacción. Además, la regresión logística es menos eficaz si las clases no se pueden separar fácilmente mediante una combinación lineal de características.


<details>
<summary>Ejemplo -- Detección de sitios web de phishing con regresión logística:</summary>

Usaremos un **Phishing Websites Dataset** (del repositorio UCI), que contiene características extraídas de sitios web (como si la URL tiene una dirección IP, la antigüedad del dominio, la presencia de elementos sospechosos en HTML, etc.) y una etiqueta que indica si el sitio es phishing o legítimo. Entrenaremos un modelo de regresión logística para clasificar sitios web y, a continuación, evaluaremos su accuracy, precision, recall, F1-score y ROC AUC en una división de prueba.
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
En este ejemplo de detección de phishing, la regresión logística produce una probabilidad de que cada sitio web sea phishing. Al evaluar la exactitud, la precisión, la exhaustividad y F1, obtenemos una idea del rendimiento del modelo. Por ejemplo, una exhaustividad alta significaría que detecta la mayoría de los sitios de phishing (algo importante en seguridad para minimizar los ataques no detectados), mientras que una precisión alta significa que genera pocas falsas alarmas (algo importante para evitar la fatiga de los analistas). El ROC AUC (Área bajo la curva ROC) proporciona una medida del rendimiento independiente del umbral (1.0 es ideal; 0.5 no es mejor que el azar). La regresión logística suele funcionar bien en este tipo de tareas, pero si la frontera de decisión entre los sitios de phishing y los legítimos es compleja, podrían ser necesarios modelos no lineales más potentes.

</details>

### Árboles de decisión

Un árbol de decisión es un **algoritmo de aprendizaje supervisado** versátil que puede utilizarse tanto para tareas de clasificación como de regresión. Aprende un modelo jerárquico con forma de árbol de decisiones basado en las características de los datos. Cada nodo interno del árbol representa una prueba sobre una característica concreta, cada rama representa un resultado de esa prueba y cada nodo hoja representa una clase predicha (para clasificación) o un valor (para regresión).<sup>[[2]](#references)</sup>

Para construir un árbol, algoritmos como CART (Classification and Regression Tree) utilizan medidas como la **impureza de Gini** o la **ganancia de información (entropía)** para elegir la mejor característica y el umbral con los que dividir los datos en cada paso. El objetivo de cada división es particionar los datos para aumentar la homogeneidad de la variable objetivo en los subconjuntos resultantes (en clasificación, cada nodo pretende ser lo más puro posible y contener predominantemente una sola clase).

Los árboles de decisión son **altamente interpretables**: se puede seguir el camino desde la raíz hasta la hoja para comprender la lógica detrás de una predicción (por ejemplo, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Esto resulta valioso en ciberseguridad para explicar por qué se generó una determinada alerta. Los árboles pueden manejar de forma natural tanto datos numéricos como categóricos y requieren poco preprocesamiento (por ejemplo, no es necesario escalar las características).

Sin embargo, un único árbol de decisión puede sobreajustar fácilmente los datos de entrenamiento, especialmente si crece demasiado (muchas divisiones). Para evitar el sobreajuste, suelen utilizarse técnicas como la poda (limitar la profundidad del árbol o exigir un número mínimo de muestras por hoja).

Hay 3 componentes principales en un árbol de decisión:
- **Nodo raíz**: El nodo superior del árbol, que representa todo el conjunto de datos.
- **Nodos internos**: Nodos que representan características y decisiones basadas en esas características.
- **Nodos hoja**: Nodos que representan el resultado final o la predicción.

Un árbol podría terminar teniendo un aspecto como este:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Casos de uso en ciberseguridad:* Los árboles de decisión se han utilizado en sistemas de detección de intrusiones para derivar **reglas** que permitan identificar ataques. Por ejemplo, los primeros IDS basados en ID3/C4.5 generaban reglas legibles para distinguir entre tráfico normal y malicioso. También se utilizan en el análisis de malware para decidir si un archivo es malicioso basándose en sus atributos (tamaño del archivo, entropía de las secciones, llamadas a la API, etc.). La claridad de los árboles de decisión los hace útiles cuando se necesita transparencia: un analista puede inspeccionar el árbol para validar la lógica de detección.

#### **Características clave de los árboles de decisión:**

-   **Tipo de problema:** Tanto clasificación como regresión. Se utilizan habitualmente para clasificar ataques frente a tráfico normal, etc.

-   **Interpretabilidad:** Muy alta: las decisiones del modelo pueden visualizarse y entenderse como un conjunto de reglas if-then. Esta es una ventaja importante en seguridad para la confianza y la verificación del comportamiento del modelo.

-   **Ventajas:** Pueden capturar relaciones no lineales e interacciones entre características (cada división puede considerarse una interacción). No es necesario escalar las características ni aplicar one-hot encoding a las variables categóricas: los árboles las gestionan de forma nativa. Inferencia rápida (la predicción consiste simplemente en seguir un recorrido en el árbol).

-   **Limitaciones:** Son propensos al overfitting si no se controlan (un árbol profundo puede memorizar el conjunto de entrenamiento). Pueden ser inestables: pequeños cambios en los datos podrían producir una estructura de árbol diferente. Como modelos individuales, su precisión podría no igualar la de métodos más avanzados (los ensembles como Random Forests suelen ofrecer un mejor rendimiento al reducir la varianza).

-   **Búsqueda de la mejor división:**
- **Gini Impurity**: Mide la impureza de un nodo. Una menor impureza de Gini indica una mejor división. La fórmula es:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Donde `p_i` es la proporción de instancias de la clase `i`.

- **Entropy**: Mide la incertidumbre del conjunto de datos. Una menor entropía indica una mejor división. La fórmula es:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Donde `p_i` es la proporción de instancias de la clase `i`.

- **Information Gain**: La reducción de la entropía o de la impureza de Gini después de una división. Cuanto mayor sea la ganancia de información, mejor será la división. Se calcula de la siguiente manera:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Además, un árbol termina cuando:
- Todas las instancias de un nodo pertenecen a la misma clase. Esto podría provocar overfitting.
- Se alcanza la profundidad máxima (hardcoded) del árbol. Esta es una forma de evitar el overfitting.
- El número de instancias de un nodo está por debajo de un umbral determinado. Esta también es una forma de evitar el overfitting.
- La ganancia de información de las divisiones adicionales está por debajo de un umbral determinado. Esta también es una forma de evitar el overfitting.

<details>
<summary>Ejemplo -- Árbol de decisión para la detección de intrusiones:</summary>
Entrenaremos un árbol de decisión con el dataset NSL-KDD para clasificar las conexiones de red como *normales* o *ataques*. NSL-KDD es una versión mejorada del clásico dataset KDD Cup 1999, con características como el tipo de protocolo, el servicio, la duración, el número de inicios de sesión fallidos, etc., y una etiqueta que indica el tipo de ataque o "normal". Asignaremos todos los tipos de ataque a una clase "anomaly" (clasificación binaria: normal frente a anomaly). Después del entrenamiento, evaluaremos el rendimiento del árbol en el conjunto de prueba.
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
En este ejemplo de árbol de decisión, limitamos la profundidad del árbol a 10 para evitar un overfitting extremo (el parámetro `max_depth=10`). Las métricas muestran qué tan bien distingue el árbol entre tráfico normal y tráfico de ataque. Un recall alto significaría que detecta la mayoría de los ataques (algo importante para un IDS), mientras que una precision alta significa que hay pocas falsas alarmas. Los árboles de decisión suelen lograr una accuracy decente en datos estructurados, pero un solo árbol quizá no alcance el mejor rendimiento posible. No obstante, la *interpretabilidad* del modelo es una gran ventaja: podríamos examinar las divisiones del árbol para ver, por ejemplo, qué features (como `service`, `src_bytes`, etc.) influyen más al marcar una conexión como maliciosa.

</details>

### Random Forests

Random Forest es un método de **ensemble learning** que se basa en árboles de decisión para mejorar el rendimiento. Un random forest entrena múltiples árboles de decisión (de ahí "forest") y combina sus resultados para realizar una predicción final (en clasificación, normalmente mediante votación mayoritaria). Las dos ideas principales de un random forest son el **bagging** (bootstrap aggregating) y la **aleatoriedad de features**:

-   **Bagging:** Cada árbol se entrena con una muestra bootstrap aleatoria de los datos de entrenamiento (muestreada con reemplazo). Esto introduce diversidad entre los árboles.

-   **Aleatoriedad de features:** En cada división de un árbol, se considera un subconjunto aleatorio de features para realizar la división (en lugar de todas las features). Esto reduce aún más la correlación entre los árboles.

Al promediar los resultados de muchos árboles, el random forest reduce la varianza que podría tener un solo árbol de decisión. En términos simples, los árboles individuales pueden hacer overfitting o ser ruidosos, pero un gran número de árboles diversos votando juntos suaviza esos errores. El resultado suele ser un modelo con **mayor accuracy** y mejor generalización que un solo árbol de decisión. Además, los random forests pueden proporcionar una estimación de la importancia de las features (observando cuánto reduce cada división de feature la impureza en promedio).

Los random forests se han convertido en un **workhorse en ciberseguridad** para tareas como la detección de intrusiones, la clasificación de malware y la detección de spam. Suelen funcionar bien out-of-the-box con un ajuste mínimo y pueden manejar grandes conjuntos de features. Por ejemplo, en la detección de intrusiones, un random forest puede superar a un árbol de decisión individual al detectar patrones más sutiles de ataques con menos falsos positivos. Las investigaciones han demostrado que los random forests tienen un rendimiento favorable en comparación con otros algoritmos al clasificar ataques en datasets como NSL-KDD y UNSW-NB15.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Características principales de Random Forests:**

-   **Tipo de problema:** Principalmente clasificación (también se utiliza para regresión). Muy adecuado para datos estructurados de alta dimensionalidad, habituales en los security logs.

-   **Interpretabilidad:** Menor que la de un solo árbol de decisión: no es fácil visualizar o explicar cientos de árboles a la vez. Sin embargo, los scores de importancia de las features proporcionan cierta información sobre qué atributos son más influyentes.

-   **Ventajas:** Generalmente ofrece mayor accuracy que los modelos de un solo árbol debido al efecto del ensemble. Es robusto frente al overfitting: aunque los árboles individuales hagan overfitting, el ensemble generaliza mejor. Maneja tanto features numéricas como categóricas y puede gestionar datos faltantes hasta cierto punto. También es relativamente robusto frente a outliers.

-   **Limitaciones:** El tamaño del modelo puede ser grande (muchos árboles, cada uno potencialmente profundo). Las predicciones son más lentas que con un solo árbol (ya que es necesario agregar los resultados de muchos árboles). Es menos interpretable: aunque se conocen las features importantes, la lógica exacta no se puede seguir fácilmente como una regla simple. Si el dataset tiene una dimensionalidad extremadamente alta y es disperso, entrenar un forest muy grande puede ser costoso computacionalmente.

-   **Proceso de entrenamiento:**
1. **Bootstrap Sampling**: Muestrear aleatoriamente los datos de entrenamiento con reemplazo para crear múltiples subconjuntos (muestras bootstrap).
2. **Construcción de árboles**: Para cada muestra bootstrap, construir un árbol de decisión utilizando un subconjunto aleatorio de features en cada división. Esto introduce diversidad entre los árboles.
3. **Agregación**: Para tareas de clasificación, la predicción final se realiza mediante una votación mayoritaria entre las predicciones de todos los árboles. Para tareas de regresión, la predicción final es el promedio de las predicciones de todos los árboles.

<details>
<summary>Ejemplo -- Random Forest para la detección de intrusiones (NSL-KDD):</summary>
Usaremos el mismo dataset NSL-KDD (con etiquetas binarias: normal frente a anomalía) y entrenaremos un clasificador Random Forest. Esperamos que el random forest tenga un rendimiento igual o superior al del árbol de decisión individual, gracias a que el promediado del ensemble reduce la varianza. Lo evaluaremos con las mismas métricas.
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
El random forest normalmente obtiene buenos resultados en esta tarea de detección de intrusiones. Podríamos observar una mejora en métricas como F1 o AUC en comparación con el árbol de decisión individual, especialmente en recall o precision, dependiendo de los datos. Esto coincide con la idea de que *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*. En un contexto de operaciones de seguridad, un modelo de random forest podría detectar ataques de forma más fiable y reducir las falsas alarmas, gracias al promediado de muchas reglas de decisión. La importancia de las features del forest podría indicarnos qué features de red son más indicativas de ataques (por ejemplo, ciertos servicios de red o recuentos inusuales de paquetes).

</details>

### Support Vector Machines (SVM)

Support Vector Machines son modelos potentes de aprendizaje supervisado utilizados principalmente para clasificación (y también para regresión como SVR). Un SVM intenta encontrar el **hiperplano de separación óptimo** que maximiza el margen entre dos clases. Solo un subconjunto de los puntos de entrenamiento (los "support vectors" más cercanos al límite) determina la posición de este hiperplano. Al maximizar el margen (la distancia entre los support vectors y el hiperplano), los SVM tienden a lograr una buena generalización.<sup>[[4]](#references)</sup>

La clave de la potencia de SVM es la capacidad de utilizar **kernel functions** para gestionar relaciones no lineales. Los datos pueden transformarse implícitamente en un espacio de features de mayor dimensión donde podría existir un separador lineal. Entre los kernels comunes se incluyen el polinómico, la función de base radial (RBF) y el sigmoide. Por ejemplo, si las clases del tráfico de red no son linealmente separables en el espacio de features sin procesar, un kernel RBF puede asignarlas a una dimensión superior donde el SVM encuentra una separación lineal (que corresponde a un límite no lineal en el espacio original). La flexibilidad para elegir kernels permite a los SVM abordar una gran variedad de problemas.

Los SVM son conocidos por funcionar bien en situaciones con espacios de features de alta dimensionalidad (como datos de texto o secuencias de opcodes de malware) y en casos donde el número de features es grande en relación con el número de muestras. Fueron populares en muchas aplicaciones tempranas de ciberseguridad, como la clasificación de malware y la detección de intrusiones basada en anomalías en la década de 2000, y a menudo mostraban una alta precisión.

Sin embargo, los SVM no escalan fácilmente a datasets muy grandes (la complejidad del entrenamiento es superlineal respecto al número de muestras y el uso de memoria puede ser elevado, ya que puede ser necesario almacenar muchos support vectors). En la práctica, para tareas como la detección de intrusiones de red con millones de registros, un SVM podría ser demasiado lento sin un subsampling cuidadoso o el uso de métodos aproximados.

#### **Características principales de SVM:**

-   **Tipo de problema:** Clasificación (binaria o multiclase mediante one-vs-one/one-vs-rest) y variantes de regresión. Se utiliza a menudo en clasificación binaria con una separación clara del margen.

-   **Interpretabilidad:** Media -- los SVM no son tan interpretables como los árboles de decisión o la regresión logística. Aunque se puede identificar qué puntos de datos son support vectors y obtener una idea de qué features podrían ser influyentes (a través de los pesos en el caso del kernel lineal), en la práctica los SVM (especialmente con kernels no lineales) se tratan como clasificadores de caja negra.

-   **Ventajas:** Eficaces en espacios de alta dimensionalidad; pueden modelar límites de decisión complejos mediante el kernel trick; resistentes al overfitting si se maximiza el margen (especialmente con un parámetro de regularización C adecuado); funcionan bien incluso cuando las clases no están separadas por una gran distancia (encuentran el mejor límite de compromiso).

-   **Limitaciones:** **Computacionalmente intensivos** para datasets grandes (tanto el entrenamiento como la predicción escalan mal a medida que crecen los datos). Requieren un ajuste cuidadoso de los parámetros del kernel y de regularización (C, tipo de kernel, gamma para RBF, etc.). No proporcionan directamente resultados probabilísticos (aunque se puede utilizar Platt scaling para obtener probabilidades). Además, los SVM pueden ser sensibles a la elección de los parámetros del kernel --- una elección deficiente puede provocar underfitting u overfitting.

*Casos de uso en ciberseguridad:* Los SVM se han utilizado en **detección de malware** (por ejemplo, para clasificar archivos basándose en features extraídas o secuencias de opcodes), **detección de anomalías de red** (clasificando el tráfico como normal o malicioso) y **detección de phishing** (utilizando features de las URLs). Por ejemplo, un SVM podría tomar las features de un email (recuentos de determinadas palabras clave, puntuaciones de reputación del remitente, etc.) y clasificarlo como phishing o legítimo. También se han aplicado a la **detección de intrusiones** en conjuntos de features como KDD, logrando a menudo una alta precisión a costa del consumo computacional.

<details>
<summary>Ejemplo -- SVM para la clasificación de malware:</summary>
Volveremos a utilizar el dataset de sitios web de phishing, esta vez con un SVM. Como los SVM pueden ser lentos, utilizaremos un subconjunto de los datos para el entrenamiento si es necesario (el dataset contiene aproximadamente 11k instancias, una cantidad que un SVM puede gestionar razonablemente). Utilizaremos un kernel RBF, una opción común para datos no lineales, y habilitaremos las estimaciones de probabilidad para calcular el ROC AUC.
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
El modelo SVM generará métricas que podemos comparar con Logistic Regression en la misma tarea. Podríamos observar que SVM alcanza una alta precisión y AUC si los datos están bien separados por las características. Por otro lado, si el dataset tuviera mucho ruido o clases superpuestas, SVM podría no superar significativamente a Logistic Regression. En la práctica, los SVM pueden ofrecer una mejora cuando existen relaciones complejas y no lineales entre las características y la clase: el kernel RBF puede capturar límites de decisión curvos que Logistic Regression no detectaría. Como ocurre con todos los modelos, es necesario ajustar cuidadosamente `C` (regularización) y los parámetros del kernel (como `gamma` para RBF) para equilibrar el sesgo y la varianza.

</details>

#### Diferencia entre Logistic Regression y SVM

| Aspecto | **Logistic Regression** | **Support Vector Machines** |
|---|---|---|
| **Función objetivo** | Minimiza la **log-loss** (entropía cruzada). | Maximiza el **margen** mientras minimiza la **hinge-loss**. |
| **Límite de decisión** | Encuentra el **hiperplano de mejor ajuste** que modela _P(y\|x)_. | Encuentra el **hiperplano de máximo margen** (la mayor distancia respecto a los puntos más cercanos). |
| **Salida** | **Probabilística**: proporciona probabilidades de clase calibradas mediante σ(w·x + b). | **Determinista**: devuelve etiquetas de clase; las probabilidades requieren trabajo adicional (por ejemplo, Platt scaling). |
| **Regularización** | L2 (predeterminada) o L1, equilibrando directamente el underfitting y el overfitting. | El parámetro C equilibra el ancho del margen frente a las clasificaciones incorrectas; los parámetros del kernel añaden complejidad. |
| **Kernels / No linealidad** | La forma nativa es **lineal**; la no linealidad se añade mediante feature engineering. | El **kernel trick** integrado (RBF, poly, etc.) permite modelar límites complejos en espacios de alta dimensionalidad. |
| **Escalabilidad** | Resuelve una optimización convexa en **O(nd)**; funciona bien con valores de n muy grandes. | El entrenamiento puede requerir **O(n²–n³)** en memoria/tiempo sin solvers especializados; es menos adecuado para valores enormes de n. |
| **Interpretabilidad** | **Alta**: los pesos muestran la influencia de las características; el odds ratio es intuitivo. | **Baja** para kernels no lineales; los support vectors son dispersos, pero no son fáciles de explicar. |
| **Sensibilidad a outliers** | Usa log-loss suave, por lo que es menos sensible. | La hinge-loss con hard margin puede ser **sensible**; el soft-margin (C) lo mitiga. |
| **Casos de uso habituales** | Credit scoring, riesgo médico y pruebas A/B, donde importan las **probabilidades y la explicabilidad**. | Clasificación de imágenes/texto y bio-informatics, donde importan los **límites complejos** y los **datos de alta dimensionalidad**. |

* **Si necesitas probabilidades calibradas, interpretabilidad o trabajar con datasets enormes, elige Logistic Regression.**
* **Si necesitas un modelo flexible que pueda capturar relaciones no lineales sin realizar feature engineering manual, elige SVM (con kernels).**
* Ambos optimizan objetivos convexos, por lo que las **soluciones mínimas globales están garantizadas**, pero los kernels de SVM añaden hiperparámetros y coste computacional.

### Naive Bayes

Naive Bayes es una familia de **clasificadores probabilísticos** basada en la aplicación del teorema de Bayes con una fuerte suposición de independencia entre las características. A pesar de esta suposición "ingenua", Naive Bayes suele funcionar sorprendentemente bien en determinadas aplicaciones, especialmente aquellas que implican datos de texto o categóricos, como la detección de spam.<sup>[[5]](#references)</sup>


#### Teorema de Bayes

El teorema de Bayes es la base de los clasificadores Naive Bayes. Relaciona las probabilidades condicionales y marginales de eventos aleatorios. La fórmula es:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Dónde:
- `P(A|B)` es la probabilidad posterior de la clase `A` dadas las características `B`.
- `P(B|A)` es la verosimilitud de las características `B` dada la clase `A`.
- `P(A)` es la probabilidad previa de la clase `A`.
- `P(B)` es la probabilidad previa de las características `B`.

Por ejemplo, si queremos clasificar si un texto fue escrito por un niño o un adulto, podemos usar las palabras del texto como características. Basándose en algunos datos iniciales, el clasificador Naive Bayes calculará previamente las probabilidades de que cada palabra pertenezca a cada clase potencial (niño o adulto). Cuando se proporciona un texto nuevo, calculará la probabilidad de cada clase potencial dadas las palabras del texto y elegirá la clase con la probabilidad más alta.

Como se puede ver en este ejemplo, el clasificador Naive Bayes es muy simple y rápido, pero asume que las características son independientes, lo que no siempre ocurre en los datos del mundo real.


#### Tipos de clasificadores Naive Bayes

Existen varios tipos de clasificadores Naive Bayes, dependiendo del tipo de datos y de la distribución de las características:
- **Gaussian Naive Bayes**: Asume que las características siguen una distribución gaussiana (normal). Es adecuado para datos continuos.
- **Multinomial Naive Bayes**: Asume que las características siguen una distribución multinomial. Es adecuado para datos discretos, como el recuento de palabras en la clasificación de texto.
- **Bernoulli Naive Bayes**: Asume que las características son binarias (0 o 1). Es adecuado para datos binarios, como la presencia o ausencia de palabras en la clasificación de texto.
- **Categorical Naive Bayes**: Asume que las características son variables categóricas. Es adecuado para datos categóricos, como clasificar frutas según su color y forma.


#### **Características clave de Naive Bayes:**

-   **Tipo de problema:** Clasificación (binaria o multiclase). Se usa habitualmente para tareas de clasificación de texto en ciberseguridad (spam, phishing, etc.).

-   **Interpretabilidad:** Media -- no es tan directamente interpretable como un árbol de decisión, pero se pueden inspeccionar las probabilidades aprendidas (por ejemplo, qué palabras aparecen con mayor probabilidad en los correos de spam frente a los correos legítimos). La estructura del modelo (las probabilidades de cada característica dada la clase) puede entenderse cuando sea necesario.

-   **Ventajas:** Entrenamiento y predicción **muy rápidos**, incluso con conjuntos de datos grandes (lineales respecto al número de instancias * número de características). Requiere una cantidad relativamente pequeña de datos para estimar las probabilidades de forma fiable, especialmente con un suavizado adecuado. A menudo es sorprendentemente preciso como modelo de referencia, especialmente cuando las características contribuyen de forma independiente a la evidencia de la clase. Funciona bien con datos de alta dimensionalidad (por ejemplo, miles de características extraídas de texto). No requiere ajustes complejos más allá de establecer un parámetro de suavizado.

-   **Limitaciones:** La suposición de independencia puede limitar la precisión si las características están muy correlacionadas. Por ejemplo, en datos de red, características como `src_bytes` y `dst_bytes` podrían estar correlacionadas; Naive Bayes no capturará esa interacción. A medida que el tamaño de los datos crece mucho, modelos más expresivos (como ensembles o redes neuronales) pueden superar a NB al aprender las dependencias entre características. Además, si se necesita una combinación determinada de características para identificar un ataque (y no solo características individuales que contribuyan de forma independiente), NB tendrá dificultades.

> [!TIP]
> *Casos de uso en ciberseguridad:* El uso clásico es la **detección de spam** -- Naive Bayes fue la base de los primeros filtros de spam, utilizando las frecuencias de determinados tokens (palabras, frases, direcciones IP) para calcular la probabilidad de que un correo electrónico sea spam. También se utiliza en la **detección de correos de phishing** y la **clasificación de URL**, donde la presencia de determinadas palabras clave o características (como "login.php" en una URL o `@` en una ruta de URL) contribuye a la probabilidad de phishing. En el análisis de malware, se podría imaginar un clasificador Naive Bayes que utilizara la presencia de determinadas llamadas a API o permisos en el software para predecir si se trata de malware. Aunque los algoritmos más avanzados suelen ofrecer un mejor rendimiento, Naive Bayes sigue siendo un buen modelo de referencia debido a su velocidad y simplicidad.

<details>
<summary>Ejemplo -- Naive Bayes para la detección de phishing:</summary>
Para demostrar Naive Bayes, utilizaremos Gaussian Naive Bayes con el conjunto de datos de intrusiones NSL-KDD (con etiquetas binarias). Gaussian NB tratará cada característica como si siguiera una distribución normal por clase. Esta es una elección aproximada, ya que muchas características de red son discretas o presentan una distribución muy sesgada, pero muestra cómo se aplicaría NB a datos de características continuas. También podríamos elegir Bernoulli NB con un conjunto de datos de características binarias (como un conjunto de alertas activadas), pero aquí seguiremos utilizando NSL-KDD para mantener la continuidad.
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
Este código entrena un clasificador Naive Bayes para detectar ataques. Naive Bayes calculará valores como `P(service=http | Attack)` y `P(Service=http | Normal)` basándose en los datos de entrenamiento y asumiendo independencia entre las features. Después utilizará estas probabilidades para clasificar nuevas conexiones como normales o ataques según las features observadas. El rendimiento de NB en NSL-KDD puede no ser tan alto como el de modelos más avanzados (ya que se viola la independencia entre features), pero suele ser aceptable y ofrece la ventaja de una velocidad extrema. En escenarios como el filtrado de correo electrónico en tiempo real o el triage inicial de URLs, un modelo Naive Bayes puede marcar rápidamente los casos obviamente maliciosos con un bajo uso de recursos.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors es uno de los algoritmos de machine learning más sencillos. Es un método **no paramétrico y basado en instancias** que realiza predicciones basándose en la similitud con ejemplos del conjunto de entrenamiento. La idea para la clasificación es la siguiente: para clasificar un nuevo punto de datos, se encuentran los **k** puntos más cercanos de los datos de entrenamiento (sus "vecinos más cercanos") y se asigna la clase mayoritaria entre esos vecinos. La "cercanía" se define mediante una métrica de distancia, normalmente la distancia euclidiana para datos numéricos (se pueden usar otras distancias para distintos tipos de features o problemas).<sup>[[10]](#references)</sup>

K-NN no requiere *entrenamiento explícito*: la fase de "entrenamiento" consiste simplemente en almacenar el dataset. Todo el trabajo se realiza durante la consulta (predicción): el algoritmo debe calcular las distancias desde el punto consultado hasta todos los puntos de entrenamiento para encontrar los más cercanos. Esto hace que el tiempo de predicción sea **lineal respecto al número de muestras de entrenamiento**, lo que puede resultar costoso para datasets grandes. Por ello, k-NN es más adecuado para datasets pequeños o escenarios en los que se puede intercambiar memoria y velocidad por simplicidad.

A pesar de su simplicidad, k-NN puede modelar fronteras de decisión muy complejas (ya que, en la práctica, la frontera de decisión puede tener cualquier forma determinada por la distribución de los ejemplos). Tiende a funcionar bien cuando la frontera de decisión es muy irregular y se dispone de muchos datos, ya que esencialmente permite que los datos "hablen por sí mismos". Sin embargo, en dimensiones altas, las métricas de distancia pueden volverse menos significativas (la maldición de la dimensionalidad), y el método puede tener dificultades a menos que se disponga de un número enorme de muestras.

*Casos de uso en cybersecurity:* k-NN se ha aplicado a la detección de anomalías; por ejemplo, un sistema de detección de intrusiones podría etiquetar un evento de red como malicioso si la mayoría de sus vecinos más cercanos (eventos anteriores) fueron maliciosos. Si el tráfico normal forma clusters y los ataques son outliers, un enfoque K-NN (con k=1 o un valor pequeño de k) realiza esencialmente una **detección de anomalías mediante el vecino más cercano**. K-NN también se ha utilizado para clasificar familias de malware mediante vectores de features binarios: un archivo nuevo podría clasificarse como perteneciente a una determinada familia de malware si está muy cerca (en el espacio de features) de instancias conocidas de esa familia. En la práctica, k-NN no es tan común como los algoritmos más escalables, pero es conceptualmente sencillo y a veces se utiliza como baseline o para problemas de pequeña escala.

#### **Características principales de k-NN:**

-   **Tipo de problema:** clasificación (también existen variantes de regresión). Es un método de *lazy learning*: no realiza un ajuste explícito del modelo.

-   **Interpretabilidad:** baja a media: no existe un modelo global ni una explicación concisa, pero se pueden interpretar los resultados observando los vecinos más cercanos que influyeron en una decisión (por ejemplo, "este flujo de red se clasificó como malicioso porque es similar a estos 3 flujos maliciosos conocidos"). Por tanto, las explicaciones pueden basarse en ejemplos.

-   **Ventajas:** muy sencillo de implementar y comprender. No realiza suposiciones sobre la distribución de los datos (no paramétrico). Puede gestionar de forma natural problemas multiclase. Es **adaptable**, en el sentido de que las fronteras de decisión pueden ser muy complejas y estar determinadas por la distribución de los datos.

-   **Limitaciones:** la predicción puede ser lenta para datasets grandes (debe calcular muchas distancias). Requiere mucha memoria, ya que almacena todos los datos de entrenamiento. El rendimiento se degrada en espacios de features de alta dimensionalidad porque todos los puntos tienden a estar casi a la misma distancia (lo que hace menos significativo el concepto de "más cercano"). Es necesario elegir *k* (el número de vecinos) adecuadamente: un valor de k demasiado pequeño puede generar ruido, mientras que uno demasiado grande puede incluir puntos irrelevantes de otras clases. Además, las features deben escalarse adecuadamente, ya que los cálculos de distancia son sensibles a la escala.

<details>
<summary>Ejemplo -- k-NN para la detección de phishing:</summary>

Volveremos a utilizar NSL-KDD (clasificación binaria). Como k-NN requiere un uso intensivo de recursos computacionales, utilizaremos un subconjunto de los datos de entrenamiento para que sea manejable en esta demostración. Elegiremos, por ejemplo, 20.000 muestras de entrenamiento de las 125.000 completas y usaremos k=5 vecinos. Después del entrenamiento (que en realidad consiste simplemente en almacenar los datos), evaluaremos el modelo con el conjunto de test. También escalaremos las features para el cálculo de distancias, con el fin de garantizar que ninguna feature domine debido a su escala.
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
El modelo k-NN clasificará una conexión observando las 5 conexiones más cercanas del subconjunto del conjunto de entrenamiento. Si, por ejemplo, 4 de esos vecinos son ataques (anomalías) y 1 es normal, la nueva conexión se clasificará como un ataque. El rendimiento puede ser razonable, aunque a menudo no tan alto como el de un Random Forest o SVM bien ajustado sobre los mismos datos. Sin embargo, k-NN puede destacar cuando las distribuciones de las clases son muy irregulares y complejas, ya que utiliza eficazmente una búsqueda basada en memoria. En cybersecurity, k-NN (con k=1 o un valor pequeño de k) podría utilizarse para detectar patrones de ataques conocidos mediante ejemplos, o como componente de sistemas más complejos (por ejemplo, para realizar clustering y clasificar posteriormente según la pertenencia a un cluster).
</details>

### Gradient Boosting Machines (e.g., XGBoost)

Gradient Boosting Machines se encuentran entre los algoritmos más potentes para datos estructurados. **Gradient boosting** hace referencia a la técnica de construir un ensemble de weak learners (a menudo decision trees) de forma secuencial, donde cada nuevo modelo corrige los errores del ensemble anterior. A diferencia del bagging (Random Forests), que construye los árboles en paralelo y calcula su promedio, boosting construye los árboles *uno por uno*, haciendo que cada uno se concentre más en las instancias que los árboles anteriores clasificaron incorrectamente.

Las implementaciones más populares en los últimos años son **XGBoost**, **LightGBM** y **CatBoost**, todas ellas bibliotecas de gradient boosting decision tree (GBDT). Han tenido un éxito extraordinario en competiciones y aplicaciones de machine learning, y a menudo **logran un rendimiento de vanguardia en datasets tabulares**. En cybersecurity, investigadores y profesionales han utilizado árboles con gradient boosting para tareas como la **detección de malware** (usando features extraídas de archivos o del comportamiento durante la ejecución) y la **detección de intrusiones de red**. Por ejemplo, un modelo de gradient boosting puede combinar muchas reglas débiles (árboles), como "si hay muchos paquetes SYN y un puerto inusual -> probablemente sea un scan", en un detector compuesto potente que tiene en cuenta muchos patrones sutiles.<sup>[[6]](#references)</sup>

¿Por qué son tan eficaces los árboles boosted? Cada árbol de la secuencia se entrena con los *errores residuales* (gradientes) de las predicciones del ensemble actual. De este modo, el modelo va **reforzando** gradualmente las áreas en las que es débil. El uso de decision trees como base learners permite que el modelo final capture interacciones complejas y relaciones no lineales. Además, boosting incorpora de forma inherente cierto grado de regularización integrada: al añadir muchos árboles pequeños (y utilizar un learning rate para escalar sus contribuciones), suele generalizar bien sin sufrir un overfitting excesivo, siempre que se seleccionen los parámetros adecuados.

#### **Características principales de Gradient Boosting:**

-   **Tipo de problema:** Principalmente clasificación y regresión. En seguridad, normalmente clasificación (por ejemplo, clasificar de forma binaria una conexión o un archivo). Admite problemas binarios, multi-class (con la loss apropiada) e incluso problemas de ranking.

-   **Interpretabilidad:** Baja a media. Aunque un único árbol boosted es pequeño, un modelo completo puede tener cientos de árboles, por lo que no resulta interpretable por completo para una persona. Sin embargo, al igual que Random Forest, puede proporcionar puntuaciones de importancia de las features, y herramientas como SHAP (SHapley Additive exPlanations) pueden utilizarse para interpretar, hasta cierto punto, predicciones individuales.

-   **Ventajas:** A menudo es el algoritmo con **mejor rendimiento** para datos estructurados/tabulares. Puede detectar patrones e interacciones complejas. Tiene muchos parámetros de ajuste (número de árboles, profundidad de los árboles, learning rate, términos de regularización) para adaptar la complejidad del modelo y evitar el overfitting. Las implementaciones modernas están optimizadas para la velocidad (por ejemplo, XGBoost utiliza información de gradientes de segundo orden y estructuras de datos eficientes). Tiende a gestionar mejor los datos desbalanceados cuando se combina con funciones de pérdida apropiadas o ajustando los pesos de las muestras.

-   **Limitaciones:** Es más complejo de ajustar que los modelos sencillos; el entrenamiento puede ser lento si los árboles son profundos o si el número de árboles es elevado (aunque normalmente sigue siendo más rápido que entrenar una deep neural network comparable con los mismos datos). El modelo puede sufrir overfitting si no se ajusta correctamente (por ejemplo, demasiados árboles profundos con una regularización insuficiente). Debido a la gran cantidad de hyperparameters, utilizar gradient boosting de forma eficaz puede requerir más conocimientos o experimentación. Además, al igual que los métodos basados en árboles, no gestiona de forma inherente los datos muy dispersos y de alta dimensionalidad con tanta eficiencia como los modelos lineales o Naive Bayes (aunque aún puede aplicarse, por ejemplo, en clasificación de texto, pero quizá no sea la primera opción sin feature engineering).

> [!TIP]
> *Casos de uso en cybersecurity:* En casi cualquier situación en la que pudiera utilizarse un decision tree o random forest, un modelo de gradient boosting podría lograr una mayor precisión. Por ejemplo, en las competiciones de **detección de malware de Microsoft** se ha utilizado ampliamente XGBoost sobre features diseñadas a partir de archivos binarios. Las investigaciones sobre **detección de intrusiones de red** suelen informar de los mejores resultados con GBDTs (por ejemplo, XGBoost sobre los datasets CIC-IDS2017 o UNSW-NB15). Estos modelos pueden utilizar una amplia variedad de features (tipos de protocolo, frecuencia de ciertos eventos, features estadísticas del tráfico, etc.) y combinarlas para detectar amenazas. En la detección de phishing, gradient boosting puede combinar features léxicas de las URLs, features de reputación de dominios y features del contenido de las páginas para lograr una precisión muy alta. El enfoque de ensemble ayuda a cubrir muchos casos extremos y matices de los datos.

<details>
<summary>Ejemplo -- XGBoost para la detección de phishing:</summary>
Usaremos un clasificador de gradient boosting sobre el dataset de phishing. Para mantener las cosas sencillas y autocontenidas, utilizaremos `sklearn.ensemble.GradientBoostingClassifier` (que es una implementación más lenta, pero sencilla). Normalmente, se podrían utilizar las bibliotecas `xgboost` o `lightgbm` para obtener un mejor rendimiento y funciones adicionales. Entrenaremos el modelo y lo evaluaremos de forma similar a antes.
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
El modelo de gradient boosting probablemente alcanzará una precisión y un AUC muy altos en este dataset de phishing (a menudo, estos modelos pueden superar el 95 % de precisión con un ajuste adecuado en este tipo de datos, como se observa en la literatura). Esto demuestra por qué los GBDT se consideran *"the state of the art model for tabular dataset"*; suelen superar a los algoritmos más simples al capturar patrones complejos. En un contexto de ciberseguridad, esto podría significar detectar más sitios de phishing o ataques con menos omisiones. Por supuesto, hay que tener cuidado con el overfitting; normalmente usaríamos técnicas como la validación cruzada y supervisaríamos el rendimiento en un conjunto de validación al desarrollar un modelo de este tipo para su despliegue.

</details>

### Combinación de modelos: Ensemble Learning y Stacking

El ensemble learning es una estrategia de **combinar varios modelos** para mejorar el rendimiento general. Ya hemos visto métodos de ensemble específicos: Random Forest (un ensemble de árboles mediante bagging) y Gradient Boosting (un ensemble de árboles mediante boosting secuencial). Pero los ensembles también pueden crearse de otras formas, como los **voting ensembles** o la **generalización apilada (stacking)**. La idea principal es que distintos modelos pueden capturar patrones diferentes o tener debilidades diferentes; al combinarlos, podemos **compensar los errores de cada modelo con los puntos fuertes de otro**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** En un clasificador de votación simple, entrenamos varios modelos diversos (por ejemplo, una regresión logística, un árbol de decisión y un SVM) y hacemos que voten sobre la predicción final (votación mayoritaria para la clasificación). Si ponderamos los votos (por ejemplo, asignando un peso mayor a los modelos más precisos), se trata de un esquema de votación ponderada. Esto normalmente mejora el rendimiento cuando los modelos individuales son razonablemente buenos e independientes; el ensemble reduce el riesgo del error de un modelo individual, ya que los demás pueden corregirlo. Es como contar con un panel de expertos en lugar de una sola opinión.

-   **Stacking (Stacked Ensemble):** El stacking va un paso más allá. En lugar de una votación simple, entrena un **meta-modelo** para **aprender cómo combinar mejor las predicciones** de los modelos base. Por ejemplo, se entrenan 3 clasificadores diferentes (base learners) y luego sus resultados (o probabilidades) se introducen como características en un meta-clasificador (a menudo un modelo simple como la regresión logística), que aprende la forma óptima de combinarlos. El meta-modelo se entrena con un conjunto de validación o mediante validación cruzada para evitar el overfitting. El stacking a menudo puede superar a la votación simple al aprender *en qué modelos confiar más en cada circunstancia*. En ciberseguridad, un modelo podría ser mejor detectando network scans, mientras que otro podría ser mejor detectando malware beaconing; un modelo de stacking podría aprender a recurrir a cada uno de forma adecuada.

Los ensembles, ya sea mediante votación o stacking, tienden a **mejorar la precisión** y la robustez. La desventaja es una mayor complejidad y, en ocasiones, una menor interpretabilidad (aunque algunos enfoques de ensemble, como el promedio de árboles de decisión, aún pueden proporcionar cierta información, por ejemplo, sobre la importancia de las características). En la práctica, si las restricciones operativas lo permiten, usar un ensemble puede producir mayores tasas de detección. Muchas soluciones ganadoras en desafíos de ciberseguridad (y en las competiciones de Kaggle en general) utilizan técnicas de ensemble para extraer hasta el último punto de rendimiento.

<details>
<summary>Ejemplo -- Voting Ensemble para la detección de phishing:</summary>
Para ilustrar el model stacking, combinemos algunos de los modelos que hemos analizado en el dataset de phishing. Usaremos una regresión logística, un árbol de decisión y un k-NN como base learners, y un Random Forest como meta-learner para agregar sus predicciones. El meta-learner se entrenará con los resultados de los base learners (mediante validación cruzada sobre el conjunto de entrenamiento). Esperamos que el modelo apilado tenga un rendimiento igual o ligeramente superior al de los modelos individuales.
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
El ensemble apilado aprovecha las fortalezas complementarias de los modelos base. Por ejemplo, la regresión logística puede manejar los aspectos lineales de los datos, el árbol de decisión puede capturar interacciones específicas similares a reglas y k-NN puede destacar en vecindarios locales del espacio de características. El meta-modelo (un random forest en este caso) puede aprender a ponderar estas entradas. Las métricas resultantes suelen mostrar una mejora (aunque sea ligera) con respecto a las métricas de cualquier modelo individual. En nuestro ejemplo de phishing, si la regresión logística por sí sola tuviera un F1 de, digamos, 0.95 y el árbol 0.94, el stack podría alcanzar 0.96 al compensar los errores de cada modelo.

Los métodos de ensemble como este demuestran el principio de que *"combinar múltiples modelos normalmente conduce a una mejor generalización"*. En ciberseguridad, esto puede implementarse mediante varios motores de detección (uno basado en reglas, otro en machine learning y otro en anomalías) y una capa que agregue sus alertas --efectivamente, una forma de ensemble-- para tomar una decisión final con mayor confianza. Al implementar estos sistemas, se debe tener en cuenta la complejidad adicional y garantizar que el ensemble no resulte demasiado difícil de gestionar o explicar. Sin embargo, desde el punto de vista de la precisión, los ensembles y el stacking son herramientas potentes para mejorar el rendimiento de los modelos.

</details>


## Referencias

- [1] [Logistic Regression](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Decision Tree - Introduction with example](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Denial of Services Attack Detection using Random Forest Classifier with Information Gain](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [What are Support Vector Machines (SVMs)? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Naive Bayes spam filtering (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT Demystified: How LightGBM, XGBoost, and CatBoost Work](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI and Machine Learning in Cybersecurity (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Linear Regression Explained](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Performance analysis of machine learning models for intrusion detection system using Gini Impurity-based Weighted Random Forest (GIWRF) feature selection technique](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [What is the k-nearest neighbors (KNN) algorithm? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Phishing Attacks and Websites Classification Using Machine Learning and Multiple Datasets (A Comparative Analysis)](https://arxiv.org/pdf/2101.02552)
- [12] [How Deep Learning Enhances Intrusion Detection Systems](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning: Boosting Model Performance by Combining Strengths](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
