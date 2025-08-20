# Algoritmos de Aprendizaje Supervisado

{{#include ../banners/hacktricks-training.md}}

## Información Básica

El aprendizaje supervisado utiliza datos etiquetados para entrenar modelos que pueden hacer predicciones sobre nuevas entradas no vistas. En ciberseguridad, el aprendizaje automático supervisado se aplica ampliamente a tareas como la detección de intrusiones (clasificando el tráfico de red como *normal* o *ataque*), la detección de malware (distinguiendo software malicioso de benigno), la detección de phishing (identificando sitios web o correos electrónicos fraudulentos) y el filtrado de spam, entre otros. Cada algoritmo tiene sus fortalezas y es adecuado para diferentes tipos de problemas (clasificación o regresión). A continuación, revisamos los algoritmos clave de aprendizaje supervisado, explicamos cómo funcionan y demostramos su uso en conjuntos de datos reales de ciberseguridad. También discutimos cómo combinar modelos (aprendizaje en conjunto) puede mejorar a menudo el rendimiento predictivo.

## Algoritmos

-   **Regresión Lineal:** Un algoritmo de regresión fundamental para predecir resultados numéricos ajustando una ecuación lineal a los datos.

-   **Regresión Logística:** Un algoritmo de clasificación (a pesar de su nombre) que utiliza una función logística para modelar la probabilidad de un resultado binario.

-   **Árboles de Decisión:** Modelos estructurados en forma de árbol que dividen los datos por características para hacer predicciones; a menudo se utilizan por su interpretabilidad.

-   **Bosques Aleatorios:** Un conjunto de árboles de decisión (a través de bagging) que mejora la precisión y reduce el sobreajuste.

-   **Máquinas de Vectores de Soporte (SVM):** Clasificadores de margen máximo que encuentran el hiperplano separador óptimo; pueden usar núcleos para datos no lineales.

-   **Naive Bayes:** Un clasificador probabilístico basado en el teorema de Bayes con una suposición de independencia de características, utilizado famosamente en el filtrado de spam.

-   **k-Vecinos Más Cercanos (k-NN):** Un clasificador simple "basado en instancias" que etiqueta una muestra según la clase mayoritaria de sus vecinos más cercanos.

-   **Máquinas de Aumento de Gradiente:** Modelos en conjunto (por ejemplo, XGBoost, LightGBM) que construyen un predictor fuerte al agregar secuencialmente aprendices más débiles (típicamente árboles de decisión).

Cada sección a continuación proporciona una descripción mejorada del algoritmo y un **ejemplo de código en Python** utilizando bibliotecas como `pandas` y `scikit-learn` (y `PyTorch` para el ejemplo de red neuronal). Los ejemplos utilizan conjuntos de datos de ciberseguridad disponibles públicamente (como NSL-KDD para detección de intrusiones y un conjunto de datos de sitios web de phishing) y siguen una estructura consistente:

1.  **Cargar el conjunto de datos** (descargar a través de URL si está disponible).

2.  **Preprocesar los datos** (por ejemplo, codificar características categóricas, escalar valores, dividir en conjuntos de entrenamiento/prueba).

3.  **Entrenar el modelo** en los datos de entrenamiento.

4.  **Evaluar** en un conjunto de prueba utilizando métricas: precisión, precisión, recuperación, F1-score y ROC AUC para clasificación (y error cuadrático medio para regresión).

Vamos a profundizar en cada algoritmo:

### Regresión Lineal

La regresión lineal es un **algoritmo de regresión** utilizado para predecir valores numéricos continuos. Asume una relación lineal entre las características de entrada (variables independientes) y la salida (variable dependiente). El modelo intenta ajustar una línea recta (o hiperplano en dimensiones superiores) que mejor describe la relación entre las características y el objetivo. Esto se hace típicamente minimizando la suma de los errores cuadrados entre los valores predichos y los valores reales (método de Mínimos Cuadrados Ordinarios).

La forma más simple de representar la regresión lineal es con una línea:
```plaintext
y = mx + b
```
Donde:

- `y` es el valor predicho (salida)
- `m` es la pendiente de la línea (coeficiente)
- `x` es la característica de entrada
- `b` es la intersección en y

El objetivo de la regresión lineal es encontrar la línea que mejor se ajusta y que minimiza la diferencia entre los valores predichos y los valores reales en el conjunto de datos. Por supuesto, esto es muy simple, sería una línea recta separando 2 categorías, pero si se añaden más dimensiones, la línea se vuelve más compleja:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Casos de uso en ciberseguridad:* La regresión lineal en sí misma es menos común para tareas de seguridad centrales (que a menudo son de clasificación), pero se puede aplicar para predecir resultados numéricos. Por ejemplo, se podría usar la regresión lineal para **predecir el volumen de tráfico de red** o **estimar el número de ataques en un período de tiempo** basado en datos históricos. También podría predecir un puntaje de riesgo o el tiempo esperado hasta la detección de un ataque, dados ciertos métricas del sistema. En la práctica, los algoritmos de clasificación (como la regresión logística o los árboles) se utilizan con más frecuencia para detectar intrusiones o malware, pero la regresión lineal sirve como base y es útil para análisis orientados a la regresión.

#### **Características clave de la regresión lineal:**

-   **Tipo de problema:** Regresión (predicción de valores continuos). No es adecuada para clasificación directa a menos que se aplique un umbral a la salida.

-   **Interpretabilidad:** Alta -- los coeficientes son fáciles de interpretar, mostrando el efecto lineal de cada característica.

-   **Ventajas:** Simple y rápida; una buena línea base para tareas de regresión; funciona bien cuando la relación verdadera es aproximadamente lineal.

-   **Limitaciones:** No puede capturar relaciones complejas o no lineales (sin ingeniería de características manual); propensa a subajuste si las relaciones son no lineales; sensible a valores atípicos que pueden sesgar los resultados.

-   **Encontrar el mejor ajuste:** Para encontrar la línea de mejor ajuste que separa las posibles categorías, usamos un método llamado **Ordinary Least Squares (OLS)**. Este método minimiza la suma de las diferencias al cuadrado entre los valores observados y los valores predichos por el modelo lineal.

<details>
<summary>Ejemplo -- Predicción de la duración de la conexión (Regresión) en un conjunto de datos de intrusión
</summary>
A continuación, demostramos la regresión lineal utilizando el conjunto de datos de ciberseguridad NSL-KDD. Trataremos esto como un problema de regresión prediciendo la `duración` de las conexiones de red basándonos en otras características. (En realidad, `duración` es una característica de NSL-KDD; la usamos aquí solo para ilustrar la regresión.) Cargamos el conjunto de datos, lo preprocesamos (codificamos características categóricas), entrenamos un modelo de regresión lineal y evaluamos el error cuadrático medio (MSE) y la puntuación R² en un conjunto de prueba.
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
En este ejemplo, el modelo de regresión lineal intenta predecir la `duración` de la conexión a partir de otras características de la red. Medimos el rendimiento con el Error Cuadrático Medio (MSE) y R². Un R² cercano a 1.0 indicaría que el modelo explica la mayor parte de la varianza en `duración`, mientras que un R² bajo o negativo indica un mal ajuste. (No te sorprendas si el R² es bajo aquí; predecir la `duración` podría ser difícil a partir de las características dadas, y la regresión lineal puede no capturar los patrones si son complejos.)
</details>

### Regresión Logística

La regresión logística es un algoritmo de **clasificación** que modela la probabilidad de que una instancia pertenezca a una clase particular (típicamente la clase "positiva"). A pesar de su nombre, la regresión *logística* se utiliza para resultados discretos (a diferencia de la regresión lineal, que es para resultados continuos). Se utiliza especialmente para **clasificación binaria** (dos clases, por ejemplo, malicioso vs. benigno), pero se puede extender a problemas de múltiples clases (utilizando enfoques de softmax o uno contra el resto).

La regresión logística utiliza la función logística (también conocida como la función sigmoide) para mapear valores predichos a probabilidades. Ten en cuenta que la función sigmoide es una función con valores entre 0 y 1 que crece en una curva en forma de S de acuerdo con las necesidades de la clasificación, lo cual es útil para tareas de clasificación binaria. Por lo tanto, cada característica de cada entrada se multiplica por su peso asignado, y el resultado se pasa a través de la función sigmoide para producir una probabilidad:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Donde:

- `p(y=1|x)` es la probabilidad de que la salida `y` sea 1 dado la entrada `x`
- `e` es la base del logaritmo natural
- `z` es una combinación lineal de las características de entrada, típicamente representada como `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Nota cómo, de nuevo, en su forma más simple es una línea recta, pero en casos más complejos se convierte en un hiperplano con varias dimensiones (una por característica).

> [!TIP]
> *Casos de uso en ciberseguridad:* Debido a que muchos problemas de seguridad son esencialmente decisiones de sí/no, la regresión logística se utiliza ampliamente. Por ejemplo, un sistema de detección de intrusiones podría usar regresión logística para decidir si una conexión de red es un ataque basado en las características de esa conexión. En la detección de phishing, la regresión logística puede combinar características de un sitio web (longitud de la URL, presencia del símbolo "@", etc.) en una probabilidad de ser phishing. Se ha utilizado en filtros de spam de primera generación y sigue siendo una base sólida para muchas tareas de clasificación.

#### Regresión Logística para clasificación no binaria

La regresión logística está diseñada para clasificación binaria, pero se puede extender para manejar problemas de múltiples clases utilizando técnicas como **uno contra el resto** (OvR) o **regresión softmax**. En OvR, se entrena un modelo de regresión logística separado para cada clase, tratándola como la clase positiva contra todas las demás. La clase con la mayor probabilidad predicha se elige como la predicción final. La regresión softmax generaliza la regresión logística a múltiples clases aplicando la función softmax a la capa de salida, produciendo una distribución de probabilidad sobre todas las clases.

#### **Características clave de la Regresión Logística:**

-   **Tipo de Problema:** Clasificación (generalmente binaria). Predice la probabilidad de la clase positiva.

-   **Interpretabilidad:** Alta -- al igual que la regresión lineal, los coeficientes de las características pueden indicar cómo cada característica influye en los log-odds del resultado. Esta transparencia es a menudo apreciada en seguridad para entender qué factores contribuyen a una alerta.

-   **Ventajas:** Simple y rápido de entrenar; funciona bien cuando la relación entre las características y los log-odds del resultado es lineal. Produce probabilidades, lo que permite la puntuación de riesgo. Con la regularización adecuada, generaliza bien y puede manejar la multicolinealidad mejor que la regresión lineal simple.

-   **Limitaciones:** Asume un límite de decisión lineal en el espacio de características (falla si el límite verdadero es complejo/no lineal). Puede tener un rendimiento inferior en problemas donde las interacciones o efectos no lineales son críticos, a menos que agregues manualmente características polinómicas o de interacción. Además, la regresión logística es menos efectiva si las clases no son fácilmente separables por una combinación lineal de características.


<details>
<summary>Ejemplo -- Detección de Sitios Web de Phishing con Regresión Logística:</summary>

Usaremos un **Conjunto de Datos de Sitios Web de Phishing** (del repositorio UCI) que contiene características extraídas de sitios web (como si la URL tiene una dirección IP, la antigüedad del dominio, presencia de elementos sospechosos en HTML, etc.) y una etiqueta que indica si el sitio es phishing o legítimo. Entrenamos un modelo de regresión logística para clasificar sitios web y luego evaluamos su precisión, precisión, recuperación, F1-score y ROC AUC en una división de prueba.
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
En este ejemplo de detección de phishing, la regresión logística produce una probabilidad de que cada sitio web sea phishing. Al evaluar la precisión, la exactitud, el recall y el F1, obtenemos una idea del rendimiento del modelo. Por ejemplo, un alto recall significaría que captura la mayoría de los sitios de phishing (importante para la seguridad para minimizar ataques perdidos), mientras que una alta precisión significa que tiene pocas falsas alarmas (importante para evitar la fatiga del analista). El ROC AUC (Área Bajo la Curva ROC) proporciona una medida de rendimiento independiente del umbral (1.0 es ideal, 0.5 no es mejor que el azar). La regresión logística a menudo funciona bien en tales tareas, pero si el límite de decisión entre sitios de phishing y legítimos es complejo, podrían ser necesarios modelos no lineales más potentes.

</details>

### Árboles de Decisión

Un árbol de decisión es un **algoritmo de aprendizaje supervisado** versátil que se puede utilizar tanto para tareas de clasificación como de regresión. Aprende un modelo jerárquico en forma de árbol de decisiones basado en las características de los datos. Cada nodo interno del árbol representa una prueba sobre una característica particular, cada rama representa un resultado de esa prueba y cada nodo hoja representa una clase predicha (para clasificación) o un valor (para regresión).

Para construir un árbol, algoritmos como CART (Árbol de Clasificación y Regresión) utilizan medidas como **impureza de Gini** o **ganancia de información (entropía)** para elegir la mejor característica y umbral para dividir los datos en cada paso. El objetivo en cada división es particionar los datos para aumentar la homogeneidad de la variable objetivo en los subconjuntos resultantes (para clasificación, cada nodo busca ser lo más puro posible, conteniendo predominantemente una sola clase).

Los árboles de decisión son **altamente interpretables**: se puede seguir el camino desde la raíz hasta la hoja para entender la lógica detrás de una predicción (por ejemplo, *"SI `service = telnet` Y `src_bytes > 1000` Y `failed_logins > 3` ENTONCES clasificar como ataque"*). Esto es valioso en ciberseguridad para explicar por qué se generó una alerta determinada. Los árboles pueden manejar naturalmente tanto datos numéricos como categóricos y requieren poco preprocesamiento (por ejemplo, no se necesita escalado de características).

Sin embargo, un solo árbol de decisión puede sobreajustar fácilmente los datos de entrenamiento, especialmente si se crece en profundidad (muchas divisiones). Se utilizan técnicas como la poda (limitar la profundidad del árbol o requerir un número mínimo de muestras por hoja) para prevenir el sobreajuste.

Hay 3 componentes principales de un árbol de decisión:
- **Nodo Raíz**: El nodo superior del árbol, que representa todo el conjunto de datos.
- **Nodos Internos**: Nodos que representan características y decisiones basadas en esas características.
- **Nodos Hoja**: Nodos que representan el resultado final o la predicción.

Un árbol podría terminar viéndose así:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Casos de uso en ciberseguridad:* Los árboles de decisión se han utilizado en sistemas de detección de intrusiones para derivar **reglas** para identificar ataques. Por ejemplo, los IDS tempranos como los sistemas basados en ID3/C4.5 generarían reglas legibles por humanos para distinguir entre tráfico normal y malicioso. También se utilizan en el análisis de malware para decidir si un archivo es malicioso en función de sus atributos (tamaño del archivo, entropía de sección, llamadas a API, etc.). La claridad de los árboles de decisión los hace útiles cuando se necesita transparencia: un analista puede inspeccionar el árbol para validar la lógica de detección.

#### **Características clave de los Árboles de Decisión:**

-   **Tipo de Problema:** Tanto clasificación como regresión. Comúnmente utilizados para la clasificación de ataques frente a tráfico normal, etc.

-   **Interpretabilidad:** Muy alta: las decisiones del modelo pueden ser visualizadas y entendidas como un conjunto de reglas if-then. Esta es una gran ventaja en seguridad para la confianza y verificación del comportamiento del modelo.

-   **Ventajas:** Pueden capturar relaciones no lineales e interacciones entre características (cada división puede verse como una interacción). No es necesario escalar características o codificar variables categóricas en one-hot: los árboles manejan eso de forma nativa. Inferencia rápida (la predicción es solo seguir un camino en el árbol).

-   **Limitaciones:** Propensos al sobreajuste si no se controlan (un árbol profundo puede memorizar el conjunto de entrenamiento). Pueden ser inestables: pequeños cambios en los datos pueden llevar a una estructura de árbol diferente. Como modelos individuales, su precisión puede no coincidir con métodos más avanzados (los conjuntos como Random Forests suelen tener un mejor rendimiento al reducir la varianza).

-   **Encontrar la Mejor División:**
- **Impureza de Gini**: Mide la impureza de un nodo. Una menor impureza de Gini indica una mejor división. La fórmula es:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Donde `p_i` es la proporción de instancias en la clase `i`.

- **Entropía**: Mide la incertidumbre en el conjunto de datos. Una menor entropía indica una mejor división. La fórmula es:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Donde `p_i` es la proporción de instancias en la clase `i`.

- **Ganancia de Información**: La reducción en la entropía o impureza de Gini después de una división. Cuanto mayor sea la ganancia de información, mejor será la división. Se calcula como:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Además, un árbol se termina cuando:
- Todas las instancias en un nodo pertenecen a la misma clase. Esto puede llevar al sobreajuste.
- Se alcanza la profundidad máxima (codificada) del árbol. Esta es una forma de prevenir el sobreajuste.
- El número de instancias en un nodo está por debajo de un cierto umbral. Esta también es una forma de prevenir el sobreajuste.
- La ganancia de información de divisiones adicionales está por debajo de un cierto umbral. Esta también es una forma de prevenir el sobreajuste.

<details>
<summary>Ejemplo -- Árbol de Decisión para Detección de Intrusiones:</summary>
Entrenaremos un árbol de decisión en el conjunto de datos NSL-KDD para clasificar conexiones de red como *normal* o *ataque*. NSL-KDD es una versión mejorada del clásico conjunto de datos KDD Cup 1999, con características como tipo de protocolo, servicio, duración, número de inicios de sesión fallidos, etc., y una etiqueta que indica el tipo de ataque o "normal". Mapearemos todos los tipos de ataque a una clase de "anomalía" (clasificación binaria: normal vs anomalía). Después de entrenar, evaluaremos el rendimiento del árbol en el conjunto de prueba.
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
En este ejemplo de árbol de decisión, limitamos la profundidad del árbol a 10 para evitar un sobreajuste extremo (el parámetro `max_depth=10`). Las métricas muestran qué tan bien el árbol distingue entre tráfico normal y de ataque. Un alto recall significaría que captura la mayoría de los ataques (importante para un IDS), mientras que una alta precisión significa pocas falsas alarmas. Los árboles de decisión a menudo logran una precisión decente en datos estructurados, pero un solo árbol podría no alcanzar el mejor rendimiento posible. No obstante, la *interpretabilidad* del modelo es una gran ventaja: podríamos examinar las divisiones del árbol para ver, por ejemplo, qué características (por ejemplo, `service`, `src_bytes`, etc.) son más influyentes para marcar una conexión como maliciosa.

</details>

### Bosques Aleatorios

Random Forest es un método de **aprendizaje en conjunto** que se basa en árboles de decisión para mejorar el rendimiento. Un bosque aleatorio entrena múltiples árboles de decisión (de ahí "bosque") y combina sus salidas para hacer una predicción final (para clasificación, típicamente por votación mayoritaria). Las dos ideas principales en un bosque aleatorio son **bagging** (agregación bootstrap) y **aleatoriedad de características**:

-   **Bagging:** Cada árbol se entrena en una muestra bootstrap aleatoria de los datos de entrenamiento (muestreada con reemplazo). Esto introduce diversidad entre los árboles.

-   **Aleatoriedad de Características:** En cada división de un árbol, se considera un subconjunto aleatorio de características para la división (en lugar de todas las características). Esto decorrela aún más los árboles.

Al promediar los resultados de muchos árboles, el bosque aleatorio reduce la varianza que podría tener un solo árbol de decisión. En términos simples, los árboles individuales pueden sobreajustarse o ser ruidosos, pero un gran número de árboles diversos votando juntos suaviza esos errores. El resultado es a menudo un modelo con **mayor precisión** y mejor generalización que un solo árbol de decisión. Además, los bosques aleatorios pueden proporcionar una estimación de la importancia de las características (observando cuánto reduce cada división de características la impureza en promedio).

Los bosques aleatorios se han convertido en un **caballo de batalla en ciberseguridad** para tareas como detección de intrusiones, clasificación de malware y detección de spam. A menudo funcionan bien de manera inmediata con una mínima configuración y pueden manejar grandes conjuntos de características. Por ejemplo, en la detección de intrusiones, un bosque aleatorio puede superar a un árbol de decisión individual al capturar patrones de ataques más sutiles con menos falsos positivos. La investigación ha demostrado que los bosques aleatorios tienen un rendimiento favorable en comparación con otros algoritmos en la clasificación de ataques en conjuntos de datos como NSL-KDD y UNSW-NB15.

#### **Características clave de los Bosques Aleatorios:**

-   **Tipo de Problema:** Principalmente clasificación (también se utiliza para regresión). Muy bien adaptado para datos estructurados de alta dimensión comunes en registros de seguridad.

-   **Interpretabilidad:** Menor que un solo árbol de decisión: no puedes visualizar o explicar fácilmente cientos de árboles a la vez. Sin embargo, las puntuaciones de importancia de características proporcionan cierta información sobre qué atributos son más influyentes.

-   **Ventajas:** Generalmente mayor precisión que los modelos de un solo árbol debido al efecto de conjunto. Robusto al sobreajuste: incluso si los árboles individuales sobreajustan, el conjunto generaliza mejor. Maneja tanto características numéricas como categóricas y puede gestionar datos faltantes hasta cierto punto. También es relativamente robusto a los valores atípicos.

-   **Limitaciones:** El tamaño del modelo puede ser grande (muchos árboles, cada uno potencialmente profundo). Las predicciones son más lentas que un solo árbol (ya que debes agregar sobre muchos árboles). Menos interpretable: aunque conoces las características importantes, la lógica exacta no es fácilmente rastreable como una regla simple. Si el conjunto de datos es extremadamente de alta dimensión y disperso, entrenar un bosque muy grande puede ser computacionalmente pesado.

-   **Proceso de Entrenamiento:**
1. **Muestreo Bootstrap:** Muestrear aleatoriamente los datos de entrenamiento con reemplazo para crear múltiples subconjuntos (muestras bootstrap).
2. **Construcción del Árbol:** Para cada muestra bootstrap, construir un árbol de decisión utilizando un subconjunto aleatorio de características en cada división. Esto introduce diversidad entre los árboles.
3. **Agregación:** Para tareas de clasificación, la predicción final se realiza tomando una votación mayoritaria entre las predicciones de todos los árboles. Para tareas de regresión, la predicción final es el promedio de las predicciones de todos los árboles.

<details>
<summary>Ejemplo -- Bosque Aleatorio para Detección de Intrusiones (NSL-KDD):</summary>
Usaremos el mismo conjunto de datos NSL-KDD (etiquetado binariamente como normal vs anómalo) y entrenaremos un clasificador de Bosque Aleatorio. Esperamos que el bosque aleatorio funcione tan bien o mejor que el árbol de decisión individual, gracias a que el promedio del conjunto reduce la varianza. Lo evaluaremos con las mismas métricas.
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
El random forest generalmente logra resultados sólidos en esta tarea de detección de intrusiones. Podríamos observar una mejora en métricas como F1 o AUC en comparación con el árbol de decisión único, especialmente en recall o precisión, dependiendo de los datos. Esto se alinea con la comprensión de que *"Random Forest (RF) es un clasificador de conjunto y funciona bien en comparación con otros clasificadores tradicionales para la clasificación efectiva de ataques."*. En un contexto de operaciones de seguridad, un modelo de random forest podría señalar ataques de manera más confiable mientras reduce las falsas alarmas, gracias al promedio de muchas reglas de decisión. La importancia de las características del bosque podría indicarnos qué características de la red son más indicativas de ataques (por ejemplo, ciertos servicios de red o conteos inusuales de paquetes).

</details>

### Support Vector Machines (SVM)

Las Support Vector Machines son modelos de aprendizaje supervisado poderosos utilizados principalmente para clasificación (y también regresión como SVR). Un SVM intenta encontrar el **hiperplano separador óptimo** que maximiza el margen entre dos clases. Solo un subconjunto de puntos de entrenamiento (los "vectores de soporte" más cercanos al límite) determina la posición de este hiperplano. Al maximizar el margen (distancia entre los vectores de soporte y el hiperplano), los SVM tienden a lograr una buena generalización.

La clave del poder de SVM es la capacidad de usar **funciones de kernel** para manejar relaciones no lineales. Los datos pueden transformarse implícitamente en un espacio de características de mayor dimensión donde podría existir un separador lineal. Los kernels comunes incluyen polinómico, función de base radial (RBF) y sigmoide. Por ejemplo, si las clases de tráfico de red no son separables linealmente en el espacio de características en bruto, un kernel RBF puede mapearlas a una dimensión superior donde el SVM encuentra una división lineal (que corresponde a un límite no lineal en el espacio original). La flexibilidad de elegir kernels permite a los SVM abordar una variedad de problemas.

Se sabe que los SVM funcionan bien en situaciones con espacios de características de alta dimensión (como datos de texto o secuencias de opcodes de malware) y en casos donde el número de características es grande en relación con el número de muestras. Fueron populares en muchas aplicaciones tempranas de ciberseguridad, como la clasificación de malware y la detección de intrusiones basada en anomalías en los años 2000, mostrando a menudo alta precisión.

Sin embargo, los SVM no escalan fácilmente a conjuntos de datos muy grandes (la complejidad de entrenamiento es superlineal en el número de muestras, y el uso de memoria puede ser alto ya que puede necesitar almacenar muchos vectores de soporte). En la práctica, para tareas como la detección de intrusiones en red con millones de registros, el SVM podría ser demasiado lento sin un muestreo cuidadoso o el uso de métodos aproximados.

#### **Características clave de SVM:**

-   **Tipo de Problema:** Clasificación (binaria o multicategoría a través de uno contra uno/uno contra el resto) y variantes de regresión. A menudo se utiliza en clasificación binaria con separación de márgenes clara.

-   **Interpretabilidad:** Media -- Los SVM no son tan interpretables como los árboles de decisión o la regresión logística. Si bien puedes identificar qué puntos de datos son vectores de soporte y tener una idea de qué características podrían ser influyentes (a través de los pesos en el caso del kernel lineal), en la práctica, los SVM (especialmente con kernels no lineales) se tratan como clasificadores de caja negra.

-   **Ventajas:** Efectivos en espacios de alta dimensión; pueden modelar límites de decisión complejos con el truco del kernel; robustos al sobreajuste si se maximiza el margen (especialmente con un parámetro de regularización C adecuado); funcionan bien incluso cuando las clases no están separadas por una gran distancia (encuentran el mejor límite de compromiso).

-   **Limitaciones:** **Intensivo computacionalmente** para conjuntos de datos grandes (tanto el entrenamiento como la predicción escalan mal a medida que los datos crecen). Requiere un ajuste cuidadoso de los parámetros del kernel y de regularización (C, tipo de kernel, gamma para RBF, etc.). No proporciona directamente salidas probabilísticas (aunque se puede usar el escalado de Platt para obtener probabilidades). Además, los SVM pueden ser sensibles a la elección de los parámetros del kernel --- una mala elección puede llevar a un subajuste o sobreajuste.

*Casos de uso en ciberseguridad:* Los SVM se han utilizado en **detección de malware** (por ejemplo, clasificando archivos en función de características extraídas o secuencias de opcodes), **detección de anomalías en la red** (clasificando el tráfico como normal o malicioso) y **detección de phishing** (utilizando características de URLs). Por ejemplo, un SVM podría tomar características de un correo electrónico (conteos de ciertas palabras clave, puntajes de reputación del remitente, etc.) y clasificarlo como phishing o legítimo. También se han aplicado a **detección de intrusiones** en conjuntos de características como KDD, logrando a menudo alta precisión a costa de computación.

<details>
<summary>Ejemplo -- SVM para Clasificación de Malware:</summary>
Usaremos el conjunto de datos de sitios web de phishing nuevamente, esta vez con un SVM. Debido a que los SVM pueden ser lentos, utilizaremos un subconjunto de los datos para el entrenamiento si es necesario (el conjunto de datos tiene alrededor de 11k instancias, que SVM puede manejar razonablemente). Usaremos un kernel RBF que es una elección común para datos no lineales, y habilitaremos estimaciones de probabilidad para calcular ROC AUC.
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
El modelo SVM generará métricas que podemos comparar con la regresión logística en la misma tarea. Podríamos encontrar que SVM logra una alta precisión y AUC si los datos están bien separados por las características. Por otro lado, si el conjunto de datos tiene mucho ruido o clases superpuestas, SVM podría no superar significativamente a la regresión logística. En la práctica, los SVM pueden ofrecer un impulso cuando hay relaciones complejas y no lineales entre características y clase; el núcleo RBF puede capturar límites de decisión curvados que la regresión logística pasaría por alto. Al igual que con todos los modelos, se necesita un ajuste cuidadoso de los parámetros `C` (regularización) y del núcleo (como `gamma` para RBF) para equilibrar el sesgo y la varianza.

</details>

#### Diferencia entre Regresiones Logísticas y SVM

| Aspecto | **Regresión Logística** | **Máquinas de Vectores de Soporte** |
|---|---|---|
| **Función objetivo** | Minimiza **log‑loss** (entropía cruzada). | Maximiza el **margen** mientras minimiza **hinge‑loss**. |
| **Límite de decisión** | Encuentra el **hiperplano de mejor ajuste** que modela _P(y\|x)_. | Encuentra el **hiperplano de margen máximo** (el mayor espacio a los puntos más cercanos). |
| **Salida** | **Probabilística** – da probabilidades de clase calibradas a través de σ(w·x + b). | **Determinista** – devuelve etiquetas de clase; las probabilidades requieren trabajo adicional (por ejemplo, escalado de Platt). |
| **Regularización** | L2 (predeterminado) o L1, equilibra directamente el sobreajuste/subajuste. | El parámetro C intercambia el ancho del margen frente a las clasificaciones erróneas; los parámetros del núcleo añaden complejidad. |
| **Núcleos / No lineales** | La forma nativa es **lineal**; la no linealidad se añade mediante ingeniería de características. | El **truco del núcleo** incorporado (RBF, polinómico, etc.) permite modelar límites complejos en un espacio de alta dimensión. |
| **Escalabilidad** | Resuelve una optimización convexa en **O(nd)**; maneja bien n muy grande. | El entrenamiento puede ser **O(n²–n³)** en memoria/tiempo sin solucionadores especializados; menos amigable para n enorme. |
| **Interpretabilidad** | **Alta** – los pesos muestran la influencia de las características; la razón de probabilidades es intuitiva. | **Baja** para núcleos no lineales; los vectores de soporte son escasos pero no fáciles de explicar. |
| **Sensibilidad a valores atípicos** | Usa log‑loss suave → menos sensible. | Hinge‑loss con margen duro puede ser **sensible**; el margen suave (C) mitiga. |
| **Casos de uso típicos** | Evaluación de crédito, riesgo médico, pruebas A/B – donde importan **probabilidades y explicabilidad**. | Clasificación de imágenes/texto, bioinformática – donde importan **límites complejos** y **datos de alta dimensión**. |

* **Si necesitas probabilidades calibradas, interpretabilidad, o trabajas con conjuntos de datos enormes — elige Regresión Logística.**
* **Si necesitas un modelo flexible que pueda capturar relaciones no lineales sin ingeniería manual de características — elige SVM (con núcleos).**
* Ambos optimizan objetivos convexos, por lo que **se garantizan mínimos globales**, pero los núcleos de SVM añaden hiperparámetros y costo computacional.

### Naive Bayes

Naive Bayes es una familia de **clasificadores probabilísticos** basados en la aplicación del Teorema de Bayes con una fuerte suposición de independencia entre características. A pesar de esta suposición "ingenua", Naive Bayes a menudo funciona sorprendentemente bien para ciertas aplicaciones, especialmente aquellas que involucran texto o datos categóricos, como la detección de spam.

#### Teorema de Bayes

El teorema de Bayes es la base de los clasificadores Naive Bayes. Relaciona las probabilidades condicionales y marginales de eventos aleatorios. La fórmula es:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Donde:
- `P(A|B)` es la probabilidad posterior de la clase `A` dado el atributo `B`.
- `P(B|A)` es la verosimilitud del atributo `B` dado la clase `A`.
- `P(A)` es la probabilidad previa de la clase `A`.
- `P(B)` es la probabilidad previa del atributo `B`.

Por ejemplo, si queremos clasificar si un texto fue escrito por un niño o un adulto, podemos usar las palabras en el texto como atributos. Basado en algunos datos iniciales, el clasificador Naive Bayes calculará previamente las probabilidades de que cada palabra esté en cada clase potencial (niño o adulto). Cuando se proporciona un nuevo texto, calculará la probabilidad de cada clase potencial dado las palabras en el texto y elegirá la clase con la probabilidad más alta.

Como puedes ver en este ejemplo, el clasificador Naive Bayes es muy simple y rápido, pero asume que los atributos son independientes, lo cual no siempre es el caso en datos del mundo real.

#### Tipos de clasificadores Naive Bayes

Hay varios tipos de clasificadores Naive Bayes, dependiendo del tipo de datos y la distribución de los atributos:
- **Gaussian Naive Bayes**: Asume que los atributos siguen una distribución gaussiana (normal). Es adecuado para datos continuos.
- **Multinomial Naive Bayes**: Asume que los atributos siguen una distribución multinomial. Es adecuado para datos discretos, como conteos de palabras en clasificación de texto.
- **Bernoulli Naive Bayes**: Asume que los atributos son binarios (0 o 1). Es adecuado para datos binarios, como la presencia o ausencia de palabras en clasificación de texto.
- **Categorical Naive Bayes**: Asume que los atributos son variables categóricas. Es adecuado para datos categóricos, como clasificar frutas según su color y forma.

#### **Características clave de Naive Bayes:**

-   **Tipo de problema:** Clasificación (binaria o multicategoría). Comúnmente utilizado para tareas de clasificación de texto en ciberseguridad (spam, phishing, etc.).

-   **Interpretabilidad:** Media -- no es tan directamente interpretable como un árbol de decisión, pero se pueden inspeccionar las probabilidades aprendidas (por ejemplo, qué palabras son más probables en correos spam frente a ham). La forma del modelo (probabilidades para cada atributo dado la clase) puede ser entendida si es necesario.

-   **Ventajas:** **Entrenamiento y predicción muy rápidos**, incluso en grandes conjuntos de datos (lineales en el número de instancias * número de atributos). Requiere una cantidad relativamente pequeña de datos para estimar probabilidades de manera confiable, especialmente con un suavizado adecuado. A menudo es sorprendentemente preciso como línea base, especialmente cuando los atributos contribuyen independientemente a la evidencia de la clase. Funciona bien con datos de alta dimensión (por ejemplo, miles de atributos de texto). No se requiere ajuste complejo más allá de establecer un parámetro de suavizado.

-   **Limitaciones:** La suposición de independencia puede limitar la precisión si los atributos están altamente correlacionados. Por ejemplo, en datos de red, atributos como `src_bytes` y `dst_bytes` podrían estar correlacionados; Naive Bayes no capturará esa interacción. A medida que el tamaño de los datos crece mucho, modelos más expresivos (como ensamblajes o redes neuronales) pueden superar a NB al aprender dependencias entre atributos. Además, si se necesita una cierta combinación de atributos para identificar un ataque (no solo atributos individuales de manera independiente), NB tendrá dificultades.

> [!TIP]
> *Casos de uso en ciberseguridad:* El uso clásico es **detección de spam** -- Naive Bayes fue el núcleo de los primeros filtros de spam, utilizando las frecuencias de ciertos tokens (palabras, frases, direcciones IP) para calcular la probabilidad de que un correo electrónico sea spam. También se utiliza en **detección de correos de phishing** y **clasificación de URL**, donde la presencia de ciertas palabras clave o características (como "login.php" en una URL, o `@` en una ruta de URL) contribuyen a la probabilidad de phishing. En el análisis de malware, se podría imaginar un clasificador Naive Bayes que utiliza la presencia de ciertas llamadas a API o permisos en software para predecir si es malware. Aunque algoritmos más avanzados a menudo tienen un mejor rendimiento, Naive Bayes sigue siendo una buena línea base debido a su velocidad y simplicidad.

<details>
<summary>Ejemplo -- Naive Bayes para Detección de Phishing:</summary>
Para demostrar Naive Bayes, utilizaremos Gaussian Naive Bayes en el conjunto de datos de intrusión NSL-KDD (con etiquetas binarias). Gaussian NB tratará cada atributo como si siguiera una distribución normal por clase. Esta es una elección aproximada ya que muchos atributos de red son discretos o están altamente sesgados, pero muestra cómo se aplicaría NB a datos de atributos continuos. También podríamos elegir Bernoulli NB en un conjunto de datos de atributos binarios (como un conjunto de alertas activadas), pero nos quedaremos con NSL-KDD aquí para mantener la continuidad.
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
Este código entrena un clasificador Naive Bayes para detectar ataques. Naive Bayes calculará cosas como `P(service=http | Attack)` y `P(Service=http | Normal)` basándose en los datos de entrenamiento, asumiendo independencia entre las características. Luego utilizará estas probabilidades para clasificar nuevas conexiones como normales o ataques según las características observadas. El rendimiento de NB en NSL-KDD puede no ser tan alto como el de modelos más avanzados (ya que se viola la independencia de características), pero a menudo es decente y tiene la ventaja de una velocidad extrema. En escenarios como el filtrado de correos electrónicos en tiempo real o el triaje inicial de URLs, un modelo de Naive Bayes puede marcar rápidamente casos claramente maliciosos con bajo uso de recursos.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors es uno de los algoritmos de aprendizaje automático más simples. Es un método **no paramétrico, basado en instancias** que hace predicciones basadas en la similitud con ejemplos en el conjunto de entrenamiento. La idea para la clasificación es: para clasificar un nuevo punto de datos, encontrar los **k** puntos más cercanos en los datos de entrenamiento (sus "vecinos más cercanos") y asignar la clase mayoritaria entre esos vecinos. La "cercanía" se define mediante una métrica de distancia, típicamente la distancia euclidiana para datos numéricos (se pueden usar otras distancias para diferentes tipos de características o problemas).

K-NN requiere *ningún entrenamiento explícito* -- la fase de "entrenamiento" es solo almacenar el conjunto de datos. Todo el trabajo ocurre durante la consulta (predicción): el algoritmo debe calcular distancias desde el punto de consulta a todos los puntos de entrenamiento para encontrar los más cercanos. Esto hace que el tiempo de predicción sea **lineal en el número de muestras de entrenamiento**, lo que puede ser costoso para conjuntos de datos grandes. Debido a esto, k-NN es más adecuado para conjuntos de datos más pequeños o escenarios donde se puede intercambiar memoria y velocidad por simplicidad.

A pesar de su simplicidad, k-NN puede modelar límites de decisión muy complejos (ya que efectivamente el límite de decisión puede tener cualquier forma dictada por la distribución de ejemplos). Tiende a funcionar bien cuando el límite de decisión es muy irregular y se tiene mucha data -- esencialmente dejando que los datos "hablen por sí mismos". Sin embargo, en dimensiones altas, las métricas de distancia pueden volverse menos significativas (maldición de la dimensionalidad), y el método puede tener dificultades a menos que se tenga un gran número de muestras.

*Casos de uso en ciberseguridad:* k-NN se ha aplicado a la detección de anomalías -- por ejemplo, un sistema de detección de intrusiones podría etiquetar un evento de red como malicioso si la mayoría de sus vecinos más cercanos (eventos anteriores) eran maliciosos. Si el tráfico normal forma clústeres y los ataques son atípicos, un enfoque K-NN (con k=1 o k pequeño) esencialmente realiza una **detección de anomalías por vecino más cercano**. K-NN también se ha utilizado para clasificar familias de malware mediante vectores de características binarias: un nuevo archivo podría clasificarse como una cierta familia de malware si está muy cerca (en el espacio de características) de instancias conocidas de esa familia. En la práctica, k-NN no es tan común como algoritmos más escalables, pero es conceptualmente sencillo y a veces se utiliza como una línea base o para problemas a pequeña escala.

#### **Características clave de k-NN:**

-   **Tipo de Problema:** Clasificación (y existen variantes de regresión). Es un método de *aprendizaje perezoso* -- sin ajuste de modelo explícito.

-   **Interpretabilidad:** Baja a media -- no hay un modelo global o explicación concisa, pero se pueden interpretar los resultados observando los vecinos más cercanos que influyeron en una decisión (por ejemplo, "este flujo de red fue clasificado como malicioso porque es similar a estos 3 flujos maliciosos conocidos"). Así, las explicaciones pueden basarse en ejemplos.

-   **Ventajas:** Muy simple de implementar y entender. No hace suposiciones sobre la distribución de datos (no paramétrico). Puede manejar naturalmente problemas de múltiples clases. Es **adaptativo** en el sentido de que los límites de decisión pueden ser muy complejos, moldeados por la distribución de datos.

-   **Limitaciones:** La predicción puede ser lenta para conjuntos de datos grandes (debe calcular muchas distancias). Intensivo en memoria -- almacena todos los datos de entrenamiento. El rendimiento se degrada en espacios de características de alta dimensión porque todos los puntos tienden a volverse casi equidistantes (haciendo que el concepto de "más cercano" sea menos significativo). Necesita elegir *k* (número de vecinos) adecuadamente -- un k demasiado pequeño puede ser ruidoso, un k demasiado grande puede incluir puntos irrelevantes de otras clases. Además, las características deben escalarse adecuadamente porque los cálculos de distancia son sensibles a la escala.

<details>
<summary>Ejemplo -- k-NN para Detección de Phishing:</summary>

Usaremos nuevamente NSL-KDD (clasificación binaria). Debido a que k-NN es computacionalmente pesado, utilizaremos un subconjunto de los datos de entrenamiento para mantenerlo manejable en esta demostración. Elegiremos, digamos, 20,000 muestras de entrenamiento de las 125k completas, y usaremos k=5 vecinos. Después de entrenar (realmente solo almacenando los datos), evaluaremos en el conjunto de prueba. También escalaremos las características para el cálculo de distancias para asegurar que ninguna característica única domine debido a la escala.
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
El modelo k-NN clasificará una conexión observando las 5 conexiones más cercanas en el subconjunto del conjunto de entrenamiento. Si, por ejemplo, 4 de esos vecinos son ataques (anomalías) y 1 es normal, la nueva conexión se clasificará como un ataque. El rendimiento puede ser razonable, aunque a menudo no tan alto como un Random Forest o SVM bien ajustado en los mismos datos. Sin embargo, k-NN a veces puede destacar cuando las distribuciones de clases son muy irregulares y complejas, utilizando efectivamente una búsqueda basada en memoria. En ciberseguridad, k-NN (con k=1 o k pequeño) podría usarse para la detección de patrones de ataque conocidos por ejemplo, o como un componente en sistemas más complejos (por ejemplo, para agrupamiento y luego clasificación basada en la pertenencia al grupo).

### Gradient Boosting Machines (por ejemplo, XGBoost)

Las Gradient Boosting Machines están entre los algoritmos más poderosos para datos estructurados. **Gradient boosting** se refiere a la técnica de construir un conjunto de aprendices débiles (a menudo árboles de decisión) de manera secuencial, donde cada nuevo modelo corrige los errores del conjunto anterior. A diferencia del bagging (Random Forests) que construye árboles en paralelo y los promedia, el boosting construye árboles *uno por uno*, cada uno enfocándose más en las instancias que los árboles anteriores predijeron incorrectamente.

Las implementaciones más populares en los últimos años son **XGBoost**, **LightGBM** y **CatBoost**, todas las cuales son bibliotecas de árboles de decisión de gradient boosting (GBDT). Han tenido un éxito extremo en competiciones y aplicaciones de aprendizaje automático, logrando a menudo **un rendimiento de vanguardia en conjuntos de datos tabulares**. En ciberseguridad, investigadores y profesionales han utilizado árboles de gradient boosting para tareas como **detección de malware** (usando características extraídas de archivos o comportamiento en tiempo de ejecución) y **detección de intrusiones en redes**. Por ejemplo, un modelo de gradient boosting puede combinar muchas reglas débiles (árboles) como "si muchos paquetes SYN y puerto inusual -> probablemente escaneo" en un detector compuesto fuerte que tiene en cuenta muchos patrones sutiles.

¿Por qué son tan efectivos los árboles potenciados? Cada árbol en la secuencia se entrena en los *errores residuales* (gradientes) de las predicciones del conjunto actual. De esta manera, el modelo gradualmente **"potencia"** las áreas donde es débil. El uso de árboles de decisión como aprendices base significa que el modelo final puede capturar interacciones complejas y relaciones no lineales. Además, el boosting tiene inherentemente una forma de regularización incorporada: al agregar muchos árboles pequeños (y usar una tasa de aprendizaje para escalar sus contribuciones), a menudo generaliza bien sin un gran sobreajuste, siempre que se elijan parámetros adecuados.

#### **Características clave del Gradient Boosting:**

-   **Tipo de Problema:** Principalmente clasificación y regresión. En seguridad, generalmente clasificación (por ejemplo, clasificar binariamente una conexión o archivo). Maneja problemas binarios, multicategoría (con pérdida apropiada) e incluso problemas de clasificación.

-   **Interpretabilidad:** Baja a media. Mientras que un solo árbol potenciado es pequeño, un modelo completo puede tener cientos de árboles, lo que no es interpretable para los humanos en su totalidad. Sin embargo, al igual que Random Forest, puede proporcionar puntuaciones de importancia de características, y herramientas como SHAP (SHapley Additive exPlanations) pueden usarse para interpretar predicciones individuales hasta cierto punto.

-   **Ventajas:** A menudo el algoritmo **mejor rendimiento** para datos estructurados/tabulares. Puede detectar patrones e interacciones complejas. Tiene muchos parámetros de ajuste (número de árboles, profundidad de los árboles, tasa de aprendizaje, términos de regularización) para adaptar la complejidad del modelo y prevenir el sobreajuste. Las implementaciones modernas están optimizadas para velocidad (por ejemplo, XGBoost utiliza información de gradiente de segundo orden y estructuras de datos eficientes). Tiende a manejar mejor los datos desbalanceados cuando se combina con funciones de pérdida apropiadas o ajustando los pesos de las muestras.

-   **Limitaciones:** Más complejo de ajustar que modelos más simples; el entrenamiento puede ser lento si los árboles son profundos o el número de árboles es grande (aunque aún suele ser más rápido que entrenar una red neuronal profunda comparable en los mismos datos). El modelo puede sobreajustarse si no se ajusta (por ejemplo, demasiados árboles profundos con insuficiente regularización). Debido a muchos hiperparámetros, usar gradient boosting de manera efectiva puede requerir más experiencia o experimentación. Además, al igual que los métodos basados en árboles, no maneja inherentemente datos muy dispersos y de alta dimensión tan eficientemente como los modelos lineales o Naive Bayes (aunque aún se puede aplicar, por ejemplo, en clasificación de texto, pero podría no ser la primera opción sin ingeniería de características).

> [!TIP]
> *Casos de uso en ciberseguridad:* Casi en cualquier lugar donde se podría usar un árbol de decisión o un random forest, un modelo de gradient boosting podría lograr mejor precisión. Por ejemplo, las competiciones de **detección de malware de Microsoft** han visto un uso intensivo de XGBoost en características diseñadas a partir de archivos binarios. La investigación en **detección de intrusiones en redes** a menudo informa los mejores resultados con GBDTs (por ejemplo, XGBoost en los conjuntos de datos CIC-IDS2017 o UNSW-NB15). Estos modelos pueden tomar una amplia gama de características (tipos de protocolo, frecuencia de ciertos eventos, características estadísticas del tráfico, etc.) y combinarlas para detectar amenazas. En la detección de phishing, el gradient boosting puede combinar características léxicas de URLs, características de reputación de dominios y características de contenido de páginas para lograr una precisión muy alta. El enfoque de conjunto ayuda a cubrir muchos casos extremos y sutilezas en los datos.

<details>
<summary>Ejemplo -- XGBoost para Detección de Phishing:</summary>
Usaremos un clasificador de gradient boosting en el conjunto de datos de phishing. Para mantener las cosas simples y autoconclusivas, usaremos `sklearn.ensemble.GradientBoostingClassifier` (que es una implementación más lenta pero directa). Normalmente, uno podría usar las bibliotecas `xgboost` o `lightgbm` para un mejor rendimiento y características adicionales. Entrenaremos el modelo y lo evaluaremos de manera similar a antes.
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
El modelo de gradient boosting probablemente logrará una precisión y AUC muy altas en este conjunto de datos de phishing (a menudo, estos modelos pueden superar el 95% de precisión con un ajuste adecuado en tales datos, como se ha visto en la literatura. Esto demuestra por qué los GBDTs son considerados *"el modelo de vanguardia para conjuntos de datos tabulares"* -- a menudo superan a algoritmos más simples al capturar patrones complejos. En un contexto de ciberseguridad, esto podría significar detectar más sitios de phishing o ataques con menos fallos. Por supuesto, uno debe tener cuidado con el sobreajuste -- normalmente usaríamos técnicas como la validación cruzada y monitorear el rendimiento en un conjunto de validación al desarrollar un modelo así para su implementación.

</details>

### Combinando Modelos: Aprendizaje por Conjuntos y Stacking

El aprendizaje por conjuntos es una estrategia de **combinar múltiples modelos** para mejorar el rendimiento general. Ya vimos métodos de conjunto específicos: Random Forest (un conjunto de árboles a través de bagging) y Gradient Boosting (un conjunto de árboles a través de boosting secuencial). Pero los conjuntos también se pueden crear de otras maneras, como **conjuntos de votación** o **generalización apilada (stacking)**. La idea principal es que diferentes modelos pueden capturar diferentes patrones o tener diferentes debilidades; al combinarlos, podemos **compensar los errores de cada modelo con las fortalezas de otro**.

-   **Conjunto de Votación:** En un clasificador de votación simple, entrenamos múltiples modelos diversos (digamos, una regresión logística, un árbol de decisión y un SVM) y les hacemos votar sobre la predicción final (voto mayoritario para la clasificación). Si ponderamos los votos (por ejemplo, mayor peso a los modelos más precisos), es un esquema de votación ponderada. Esto típicamente mejora el rendimiento cuando los modelos individuales son razonablemente buenos e independientes -- el conjunto reduce el riesgo del error de un modelo individual ya que otros pueden corregirlo. Es como tener un panel de expertos en lugar de una sola opinión.

-   **Stacking (Conjunto Apilado):** Stacking va un paso más allá. En lugar de un simple voto, entrena un **meta-modelo** para **aprender cómo combinar mejor las predicciones** de los modelos base. Por ejemplo, entrenas 3 clasificadores diferentes (aprendices base), luego alimentas sus salidas (o probabilidades) como características en un meta-clasificador (a menudo un modelo simple como la regresión logística) que aprende la forma óptima de mezclarlos. El meta-modelo se entrena en un conjunto de validación o mediante validación cruzada para evitar el sobreajuste. Stacking a menudo puede superar el voto simple al aprender *en qué modelos confiar más en qué circunstancias*. En ciberseguridad, un modelo podría ser mejor para detectar escaneos de red mientras que otro es mejor para detectar el beaconing de malware; un modelo de stacking podría aprender a confiar en cada uno de manera apropiada.

Los conjuntos, ya sea por votación o stacking, tienden a **aumentar la precisión** y la robustez. La desventaja es la complejidad aumentada y, a veces, la reducción de la interpretabilidad (aunque algunos enfoques de conjunto, como un promedio de árboles de decisión, aún pueden proporcionar cierta información, por ejemplo, la importancia de las características). En la práctica, si las restricciones operativas lo permiten, usar un conjunto puede llevar a tasas de detección más altas. Muchas soluciones ganadoras en desafíos de ciberseguridad (y competiciones de Kaggle en general) utilizan técnicas de conjunto para exprimir el último bit de rendimiento.

<details>
<summary>Ejemplo -- Conjunto de Votación para Detección de Phishing:</summary>
Para ilustrar el stacking de modelos, combinemos algunos de los modelos que discutimos en el conjunto de datos de phishing. Usaremos una regresión logística, un árbol de decisión y un k-NN como aprendices base, y utilizaremos un Random Forest como meta-aprendiz para agregar sus predicciones. El meta-aprendiz se entrenará con las salidas de los aprendices base (usando validación cruzada en el conjunto de entrenamiento). Esperamos que el modelo apilado funcione tan bien o ligeramente mejor que los modelos individuales.
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
El ensamblaje apilado aprovecha las fortalezas complementarias de los modelos base. Por ejemplo, la regresión logística podría manejar aspectos lineales de los datos, el árbol de decisión podría capturar interacciones específicas similares a reglas, y k-NN podría sobresalir en vecindarios locales del espacio de características. El meta-modelo (aquí un bosque aleatorio) puede aprender a ponderar estas entradas. Las métricas resultantes a menudo muestran una mejora (incluso si es leve) sobre las métricas de cualquier modelo individual. En nuestro ejemplo de phishing, si la regresión logística sola tenía un F1 de, digamos, 0.95 y el árbol 0.94, el apilamiento podría alcanzar 0.96 al recoger donde cada modelo comete errores.

Los métodos de ensamblaje como este demuestran el principio de que *"combinar múltiples modelos generalmente conduce a una mejor generalización"*. En ciberseguridad, esto se puede implementar teniendo múltiples motores de detección (uno podría ser basado en reglas, uno de aprendizaje automático, uno basado en anomalías) y luego una capa que agrega sus alertas -- efectivamente una forma de ensamblaje -- para tomar una decisión final con mayor confianza. Al implementar tales sistemas, se debe considerar la complejidad añadida y asegurarse de que el ensamblaje no se vuelva demasiado difícil de gestionar o explicar. Pero desde el punto de vista de la precisión, los ensamblajes y el apilamiento son herramientas poderosas para mejorar el rendimiento del modelo.

</details>


## Referencias

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
