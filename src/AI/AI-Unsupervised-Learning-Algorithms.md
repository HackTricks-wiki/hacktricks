# Algoritmos de Aprendizaje No Supervisado

{{#include ../banners/hacktricks-training.md}}

## Aprendizaje No Supervisado

El aprendizaje no supervisado es un tipo de aprendizaje automático donde el modelo se entrena con datos sin respuestas etiquetadas. El objetivo es encontrar patrones, estructuras o relaciones dentro de los datos. A diferencia del aprendizaje supervisado, donde el modelo aprende de ejemplos etiquetados, los algoritmos de aprendizaje no supervisado trabajan con datos no etiquetados. 
El aprendizaje no supervisado se utiliza a menudo para tareas como agrupamiento, reducción de dimensionalidad y detección de anomalías. Puede ayudar a descubrir patrones ocultos en los datos, agrupar elementos similares o reducir la complejidad de los datos mientras se preservan sus características esenciales.

### Agrupamiento K-Means

K-Means es un algoritmo de agrupamiento basado en centroides que particiona los datos en K grupos asignando cada punto al centroide del grupo más cercano. El algoritmo funciona de la siguiente manera:
1. **Inicialización**: Elegir K centros de grupo iniciales (centroides), a menudo aleatoriamente o mediante métodos más inteligentes como k-means++.
2. **Asignación**: Asignar cada punto de datos al centroide más cercano basado en una métrica de distancia (por ejemplo, distancia euclidiana).
3. **Actualización**: Recalcular los centroides tomando la media de todos los puntos de datos asignados a cada grupo.
4. **Repetir**: Los pasos 2–3 se repiten hasta que las asignaciones de grupos se estabilizan (los centroides ya no se mueven significativamente).

> [!TIP]
> *Casos de uso en ciberseguridad:* K-Means se utiliza para la detección de intrusiones agrupando eventos de red. Por ejemplo, los investigadores aplicaron K-Means al conjunto de datos de intrusión KDD Cup 99 y encontraron que particionaba efectivamente el tráfico en grupos de normalidad vs. ataque. En la práctica, los analistas de seguridad podrían agrupar entradas de registro o datos de comportamiento de usuarios para encontrar grupos de actividad similar; cualquier punto que no pertenezca a un grupo bien formado podría indicar anomalías (por ejemplo, una nueva variante de malware formando su propio pequeño grupo). K-Means también puede ayudar en la clasificación de familias de malware agrupando binarios según perfiles de comportamiento o vectores de características.

#### Selección de K
El número de grupos (K) es un hiperparámetro que debe definirse antes de ejecutar el algoritmo. Técnicas como el Método del Codo o la Puntuación de Silueta pueden ayudar a determinar un valor apropiado para K evaluando el rendimiento del agrupamiento:

- **Método del Codo**: Graficar la suma de las distancias al cuadrado desde cada punto hasta su centroide de grupo asignado como una función de K. Buscar un punto de "codo" donde la tasa de disminución cambia drásticamente, indicando un número adecuado de grupos.
- **Puntuación de Silueta**: Calcular la puntuación de silueta para diferentes valores de K. Una puntuación de silueta más alta indica grupos mejor definidos.

#### Suposiciones y Limitaciones

K-Means asume que **los grupos son esféricos y de tamaño igual**, lo cual puede no ser cierto para todos los conjuntos de datos. Es sensible a la colocación inicial de los centroides y puede converger a mínimos locales. Además, K-Means no es adecuado para conjuntos de datos con densidades variables o formas no globulares y características con diferentes escalas. Los pasos de preprocesamiento como la normalización o estandarización pueden ser necesarios para asegurar que todas las características contribuyan de manera equitativa a los cálculos de distancia.

<details>
<summary>Ejemplo -- Agrupamiento de Eventos de Red
</summary>
A continuación, simulamos datos de tráfico de red y usamos K-Means para agruparlos. Supongamos que tenemos eventos con características como duración de conexión y conteo de bytes. Creamos 3 grupos de tráfico "normal" y 1 pequeño grupo que representa un patrón de ataque. Luego ejecutamos K-Means para ver si los separa.
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
En este ejemplo, K-Means debería encontrar 4 clústeres. El pequeño clúster de ataque (con una duración inusualmente alta de ~200) idealmente formará su propio clúster dado su distancia de los clústeres normales. Imprimimos los tamaños y centros de los clústeres para interpretar los resultados. En un escenario real, uno podría etiquetar el clúster con pocos puntos como posibles anomalías o inspeccionar sus miembros en busca de actividad maliciosa.
</details>

### Agrupamiento Jerárquico

El agrupamiento jerárquico construye una jerarquía de clústeres utilizando un enfoque de abajo hacia arriba (aglomerativo) o un enfoque de arriba hacia abajo (divisivo):

1. **Aglomerativo (De Abajo Hacia Arriba)**: Comienza con cada punto de datos como un clúster separado y fusiona iterativamente los clústeres más cercanos hasta que quede un solo clúster o se cumpla un criterio de detención.
2. **Divisivo (De Arriba Hacia Abajo)**: Comienza con todos los puntos de datos en un solo clúster y divide iterativamente los clústeres hasta que cada punto de datos sea su propio clúster o se cumpla un criterio de detención.

El agrupamiento aglomerativo requiere una definición de distancia entre clústeres y un criterio de enlace para decidir qué clústeres fusionar. Los métodos de enlace comunes incluyen enlace simple (distancia de los puntos más cercanos entre dos clústeres), enlace completo (distancia de los puntos más lejanos), enlace promedio, etc., y la métrica de distancia suele ser euclidiana. La elección del enlace afecta la forma de los clústeres producidos. No es necesario especificar de antemano el número de clústeres K; se puede "cortar" el dendrograma en un nivel elegido para obtener el número deseado de clústeres.

El agrupamiento jerárquico produce un dendrograma, una estructura en forma de árbol que muestra las relaciones entre clústeres en diferentes niveles de granularidad. El dendrograma se puede cortar en un nivel deseado para obtener un número específico de clústeres.

> [!TIP]
> *Casos de uso en ciberseguridad:* El agrupamiento jerárquico puede organizar eventos o entidades en un árbol para detectar relaciones. Por ejemplo, en el análisis de malware, el agrupamiento aglomerativo podría agrupar muestras por similitud de comportamiento, revelando una jerarquía de familias y variantes de malware. En seguridad de red, uno podría agrupar flujos de tráfico IP y usar el dendrograma para ver subagrupaciones de tráfico (por ejemplo, por protocolo, luego por comportamiento). Dado que no es necesario elegir K de antemano, es útil al explorar nuevos datos para los cuales se desconoce el número de categorías de ataque.

#### Suposiciones y Limitaciones

El agrupamiento jerárquico no asume una forma particular de clúster y puede capturar clústeres anidados. Es útil para descubrir taxonomía o relaciones entre grupos (por ejemplo, agrupar malware por subgrupos familiares). Es determinista (sin problemas de inicialización aleatoria). Una ventaja clave es el dendrograma, que proporciona información sobre la estructura de agrupamiento de los datos en todas las escalas: los analistas de seguridad pueden decidir un corte apropiado para identificar clústeres significativos. Sin embargo, es computacionalmente costoso (típicamente $O(n^2)$ o peor para implementaciones ingenuas) y no es factible para conjuntos de datos muy grandes. También es un procedimiento codicioso: una vez que se realiza una fusión o división, no se puede deshacer, lo que puede llevar a clústeres subóptimos si ocurre un error temprano. Los valores atípicos también pueden afectar algunas estrategias de enlace (el enlace simple puede causar el efecto de "encadenamiento" donde los clústeres se vinculan a través de valores atípicos).

<details>
<summary>Ejemplo -- Agrupamiento Aglomerativo de Eventos
</summary>

Reutilizaremos los datos sintéticos del ejemplo de K-Means (3 clústeres normales + 1 clúster de ataque) y aplicaremos el agrupamiento aglomerativo. Luego ilustramos cómo obtener un dendrograma y etiquetas de clúster.
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

### DBSCAN (Clustering Espacial Basado en Densidad de Aplicaciones con Ruido)

DBSCAN es un algoritmo de clustering basado en densidad que agrupa puntos que están estrechamente empaquetados, mientras marca puntos en regiones de baja densidad como atípicos. Es particularmente útil para conjuntos de datos con densidades variables y formas no esféricas.

DBSCAN funciona definiendo dos parámetros:
- **Epsilon (ε)**: La distancia máxima entre dos puntos para ser considerados parte del mismo clúster.
- **MinPts**: El número mínimo de puntos requeridos para formar una región densa (punto central).

DBSCAN identifica puntos centrales, puntos de frontera y puntos de ruido:
- **Punto Central**: Un punto con al menos MinPts vecinos dentro de la distancia ε.
- **Punto de Frontera**: Un punto que está dentro de la distancia ε de un punto central pero tiene menos de MinPts vecinos.
- **Punto de Ruido**: Un punto que no es ni un punto central ni un punto de frontera.

El clustering procede eligiendo un punto central no visitado, marcándolo como un nuevo clúster, y luego agregando recursivamente todos los puntos alcanzables por densidad desde él (puntos centrales y sus vecinos, etc.). Los puntos de frontera se agregan al clúster de un núcleo cercano. Después de expandir todos los puntos alcanzables, DBSCAN se mueve a otro núcleo no visitado para comenzar un nuevo clúster. Los puntos no alcanzados por ningún núcleo permanecen etiquetados como ruido.

> [!TIP]
> *Casos de uso en ciberseguridad:* DBSCAN es útil para la detección de anomalías en el tráfico de red. Por ejemplo, la actividad normal de los usuarios podría formar uno o más clústeres densos en el espacio de características, mientras que los comportamientos de ataque novedosos aparecen como puntos dispersos que DBSCAN etiquetará como ruido (atípicos). Se ha utilizado para agrupar registros de flujo de red, donde puede detectar escaneos de puertos o tráfico de denegación de servicio como regiones escasas de puntos. Otra aplicación es agrupar variantes de malware: si la mayoría de las muestras se agrupan por familias pero unas pocas no encajan en ningún lugar, esas pocas podrían ser malware de día cero. La capacidad de marcar ruido significa que los equipos de seguridad pueden centrarse en investigar esos atípicos.

#### Suposiciones y Limitaciones

**Suposiciones y Fortalezas:**: DBSCAN no asume clústeres esféricos; puede encontrar clústeres de forma arbitraria (incluso clústeres en cadena o adyacentes). Determina automáticamente el número de clústeres basado en la densidad de datos y puede identificar efectivamente atípicos como ruido. Esto lo hace poderoso para datos del mundo real con formas irregulares y ruido. Es robusto ante atípicos (a diferencia de K-Means, que los fuerza a entrar en clústeres). Funciona bien cuando los clústeres tienen densidad aproximadamente uniforme.

**Limitaciones**: El rendimiento de DBSCAN depende de elegir valores apropiados de ε y MinPts. Puede tener dificultades con datos que tienen densidades variables; un solo ε no puede acomodar clústeres densos y escasos. Si ε es demasiado pequeño, etiqueta la mayoría de los puntos como ruido; si es demasiado grande, los clústeres pueden fusionarse incorrectamente. Además, DBSCAN puede ser ineficiente en conjuntos de datos muy grandes (naivamente $O(n^2)$, aunque la indexación espacial puede ayudar). En espacios de características de alta dimensión, el concepto de "distancia dentro de ε" puede volverse menos significativo (la maldición de la dimensionalidad), y DBSCAN puede necesitar un ajuste cuidadoso de parámetros o puede no encontrar clústeres intuitivos. A pesar de esto, extensiones como HDBSCAN abordan algunos problemas (como la densidad variable).

<details>
<summary>Ejemplo -- Clustering con Ruido
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
En este fragmento, ajustamos `eps` y `min_samples` para adaptarlos a la escala de nuestros datos (15.0 en unidades de características, y requiriendo 5 puntos para formar un clúster). DBSCAN debería encontrar 2 clústeres (los clústeres de tráfico normal) y marcar los 5 valores atípicos inyectados como ruido. Salimos el número de clústeres frente a puntos de ruido para verificar esto. En un entorno real, uno podría iterar sobre ε (usando una heurística de gráfico de distancia k para elegir ε) y MinPts (a menudo establecido alrededor de la dimensionalidad de los datos + 1 como regla general) para encontrar resultados de agrupamiento estables. La capacidad de etiquetar explícitamente el ruido ayuda a separar los datos de ataque potencial para un análisis posterior.

</details>

### Análisis de Componentes Principales (PCA)

PCA es una técnica para **reducción de dimensionalidad** que encuentra un nuevo conjunto de ejes ortogonales (componentes principales) que capturan la máxima varianza en los datos. En términos simples, PCA rota y proyecta los datos en un nuevo sistema de coordenadas de tal manera que el primer componente principal (PC1) explica la mayor varianza posible, el segundo PC (PC2) explica la mayor varianza ortogonal a PC1, y así sucesivamente. Matemáticamente, PCA calcula los eigenvectores de la matriz de covarianza de los datos; estos eigenvectores son las direcciones de los componentes principales, y los eigenvalores correspondientes indican la cantidad de varianza explicada por cada uno. Se utiliza a menudo para extracción de características, visualización y reducción de ruido.

Tenga en cuenta que esto es útil si las dimensiones del conjunto de datos contienen **dependencias o correlaciones lineales significativas**.

PCA funciona identificando los componentes principales de los datos, que son las direcciones de máxima varianza. Los pasos involucrados en PCA son:
1. **Estandarización**: Centrar los datos restando la media y escalándolos a varianza unitaria.
2. **Matriz de Covarianza**: Calcular la matriz de covarianza de los datos estandarizados para entender las relaciones entre características.
3. **Descomposición de Eigenvalores**: Realizar la descomposición de eigenvalores en la matriz de covarianza para obtener los eigenvalores y eigenvectores.
4. **Seleccionar Componentes Principales**: Ordenar los eigenvalores en orden descendente y seleccionar los K eigenvectores superiores correspondientes a los eigenvalores más grandes. Estos eigenvectores forman el nuevo espacio de características.
5. **Transformar Datos**: Proyectar los datos originales en el nuevo espacio de características utilizando los componentes principales seleccionados.
PCA se utiliza ampliamente para visualización de datos, reducción de ruido y como un paso de preprocesamiento para otros algoritmos de aprendizaje automático. Ayuda a reducir la dimensionalidad de los datos mientras se retiene su estructura esencial.

#### Eigenvalores y Eigenvectores

Un eigenvalor es un escalar que indica la cantidad de varianza capturada por su correspondiente eigenvector. Un eigenvector representa una dirección en el espacio de características a lo largo de la cual los datos varían más.

Imagina que A es una matriz cuadrada, y v es un vector no nulo tal que: `A * v = λ * v`
donde:
- A es una matriz cuadrada como [ [1, 2], [2, 1]] (por ejemplo, matriz de covarianza)
- v es un eigenvector (por ejemplo, [1, 1])

Entonces, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]` que será el eigenvalor λ multiplicado por el eigenvector v, haciendo que el eigenvalor λ = 3.

#### Eigenvalores y Eigenvectores en PCA

Vamos a explicar esto con un ejemplo. Imagina que tienes un conjunto de datos con muchas imágenes en escala de grises de rostros de 100x100 píxeles. Cada píxel puede considerarse una característica, por lo que tienes 10,000 características por imagen (o un vector de 10000 componentes por imagen). Si deseas reducir la dimensionalidad de este conjunto de datos utilizando PCA, seguirías estos pasos:

1. **Estandarización**: Centrar los datos restando la media de cada característica (píxel) del conjunto de datos.
2. **Matriz de Covarianza**: Calcular la matriz de covarianza de los datos estandarizados, que captura cómo varían juntas las características (píxeles).
- Tenga en cuenta que la covarianza entre dos variables (píxeles en este caso) indica cuánto cambian juntas, por lo que la idea aquí es averiguar qué píxeles tienden a aumentar o disminuir juntos con una relación lineal.
- Por ejemplo, si el píxel 1 y el píxel 2 tienden a aumentar juntos, la covarianza entre ellos será positiva.
- La matriz de covarianza será una matriz de 10,000x10,000 donde cada entrada representa la covarianza entre dos píxeles.
3. **Resolver la ecuación de eigenvalores**: La ecuación de eigenvalores a resolver es `C * v = λ * v` donde C es la matriz de covarianza, v es el eigenvector y λ es el eigenvalor. Se puede resolver utilizando métodos como:
- **Descomposición de Eigenvalores**: Realizar la descomposición de eigenvalores en la matriz de covarianza para obtener los eigenvalores y eigenvectores.
- **Descomposición en Valores Singulares (SVD)**: Alternativamente, puedes usar SVD para descomponer la matriz de datos en valores y vectores singulares, lo que también puede dar lugar a los componentes principales.
4. **Seleccionar Componentes Principales**: Ordenar los eigenvalores en orden descendente y seleccionar los K eigenvectores superiores correspondientes a los eigenvalores más grandes. Estos eigenvectores representan las direcciones de máxima varianza en los datos.

> [!TIP]
> *Casos de uso en ciberseguridad:* Un uso común de PCA en seguridad es la reducción de características para la detección de anomalías. Por ejemplo, un sistema de detección de intrusiones con más de 40 métricas de red (como características de NSL-KDD) puede usar PCA para reducir a un puñado de componentes, resumiendo los datos para visualización o alimentando algoritmos de agrupamiento. Los analistas podrían trazar el tráfico de red en el espacio de los dos primeros componentes principales para ver si los ataques se separan del tráfico normal. PCA también puede ayudar a eliminar características redundantes (como bytes enviados frente a bytes recibidos si están correlacionados) para hacer que los algoritmos de detección sean más robustos y rápidos.

#### Suposiciones y Limitaciones

PCA asume que **los ejes principales de varianza son significativos**; es un método lineal, por lo que captura correlaciones lineales en los datos. Es no supervisado ya que utiliza solo la covarianza de las características. Las ventajas de PCA incluyen la reducción de ruido (los componentes de pequeña varianza a menudo corresponden a ruido) y la decorrelación de características. Es computacionalmente eficiente para dimensiones moderadamente altas y a menudo es un paso de preprocesamiento útil para otros algoritmos (para mitigar la maldición de la dimensionalidad). Una limitación es que PCA está limitado a relaciones lineales; no capturará estructuras no lineales complejas (mientras que los autoencoders o t-SNE podrían). Además, los componentes de PCA pueden ser difíciles de interpretar en términos de características originales (son combinaciones de características originales). En ciberseguridad, uno debe ser cauteloso: un ataque que solo causa un cambio sutil en una característica de baja varianza podría no aparecer en los principales PCs (ya que PCA prioriza la varianza, no necesariamente la "interesanteza").

<details>
<summary>Ejemplo -- Reducción de Dimensiones de Datos de Red
</summary>

Supongamos que tenemos registros de conexiones de red con múltiples características (por ejemplo, duraciones, bytes, conteos). Generaremos un conjunto de datos sintético de 4 dimensiones (con alguna correlación entre características) y utilizaremos PCA para reducirlo a 2 dimensiones para visualización o análisis posterior.
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
Aquí tomamos los clústeres de tráfico normal anteriores y extendimos cada punto de datos con dos características adicionales (paquetes y errores) que se correlacionan con bytes y duración. Luego se utiliza PCA para comprimir las 4 características en 2 componentes principales. Imprimimos la razón de varianza explicada, que podría mostrar que, digamos, >95% de la varianza es capturada por 2 componentes (lo que significa poca pérdida de información). La salida también muestra que la forma de los datos se reduce de (1500, 4) a (1500, 2). Los primeros puntos en el espacio PCA se dan como un ejemplo. En la práctica, uno podría trazar data_2d para verificar visualmente si los clústeres son distinguibles. Si hubiera una anomalía presente, uno podría verla como un punto alejado del clúster principal en el espacio PCA. Por lo tanto, PCA ayuda a destilar datos complejos en una forma manejable para la interpretación humana o como entrada para otros algoritmos.

</details>


### Modelos de Mezcla Gaussiana (GMM)

Un Modelo de Mezcla Gaussiana asume que los datos se generan a partir de una mezcla de **varias distribuciones Gaussianas (normales) con parámetros desconocidos**. En esencia, es un modelo de agrupamiento probabilístico: intenta asignar suavemente cada punto a uno de K componentes Gaussianos. Cada componente Gaussiano k tiene un vector medio (μ_k), una matriz de covarianza (Σ_k) y un peso de mezcla (π_k) que representa cuán prevalente es ese clúster. A diferencia de K-Means, que hace asignaciones "duras", GMM le da a cada punto una probabilidad de pertenecer a cada clúster.

El ajuste de GMM se realiza típicamente a través del algoritmo de Expectativa-Maximización (EM):

- **Inicialización**: Comenzar con conjeturas iniciales para las medias, covarianzas y coeficientes de mezcla (o usar los resultados de K-Means como punto de partida).

- **Paso E (Expectativa)**: Dado los parámetros actuales, calcular la responsabilidad de cada clúster para cada punto: esencialmente `r_nk = P(z_k | x_n)` donde z_k es la variable latente que indica la pertenencia al clúster para el punto x_n. Esto se hace utilizando el teorema de Bayes, donde calculamos la probabilidad posterior de que cada punto pertenezca a cada clúster basado en los parámetros actuales. Las responsabilidades se calculan como:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
donde:
- \( \pi_k \) es el coeficiente de mezcla para el clúster k (probabilidad a priori del clúster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) es la función de densidad de probabilidad Gaussiana para el punto \( x_n \) dado la media \( \mu_k \) y la covarianza \( \Sigma_k \).

- **Paso M (Maximización)**: Actualizar los parámetros utilizando las responsabilidades calculadas en el paso E:
- Actualizar cada media μ_k como el promedio ponderado de los puntos, donde los pesos son las responsabilidades.
- Actualizar cada covarianza Σ_k como la covarianza ponderada de los puntos asignados al clúster k.
- Actualizar los coeficientes de mezcla π_k como la responsabilidad promedio para el clúster k.

- **Iterar** los pasos E y M hasta la convergencia (los parámetros se estabilizan o la mejora de la verosimilitud está por debajo de un umbral).

El resultado es un conjunto de distribuciones Gaussianas que modelan colectivamente la distribución general de los datos. Podemos usar el GMM ajustado para agrupar asignando cada punto a la Gaussiana con mayor probabilidad, o mantener las probabilidades para la incertidumbre. También se puede evaluar la verosimilitud de nuevos puntos para ver si se ajustan al modelo (útil para la detección de anomalías).

> [!TIP]
> *Casos de uso en ciberseguridad:* GMM se puede utilizar para la detección de anomalías modelando la distribución de datos normales: cualquier punto con una probabilidad muy baja bajo la mezcla aprendida se marca como anomalía. Por ejemplo, podrías entrenar un GMM en características de tráfico de red legítimo; una conexión de ataque que no se asemeje a ningún clúster aprendido tendría una baja probabilidad. Los GMM también se utilizan para agrupar actividades donde los clústeres pueden tener diferentes formas – por ejemplo, agrupar usuarios por perfiles de comportamiento, donde las características de cada perfil pueden ser similares a Gaussianas pero con su propia estructura de varianza. Otro escenario: en la detección de phishing, las características de correos electrónicos legítimos podrían formar un clúster Gaussiano, el phishing conocido otro, y nuevas campañas de phishing podrían aparecer como una Gaussiana separada o como puntos de baja probabilidad en relación con la mezcla existente.

#### Suposiciones y Limitaciones

GMM es una generalización de K-Means que incorpora covarianza, por lo que los clústeres pueden ser elipsoidales (no solo esféricos). Maneja clústeres de diferentes tamaños y formas si la covarianza es completa. El agrupamiento suave es una ventaja cuando los límites de los clústeres son difusos – por ejemplo, en ciberseguridad, un evento podría tener rasgos de múltiples tipos de ataque; GMM puede reflejar esa incertidumbre con probabilidades. GMM también proporciona una estimación de densidad probabilística de los datos, útil para detectar valores atípicos (puntos con baja probabilidad bajo todos los componentes de la mezcla).

Por otro lado, GMM requiere especificar el número de componentes K (aunque se pueden usar criterios como BIC/AIC para seleccionarlo). EM a veces puede converger lentamente o a un óptimo local, por lo que la inicialización es importante (a menudo se ejecuta EM múltiples veces). Si los datos no siguen realmente una mezcla de Gaussianas, el modelo puede ser un mal ajuste. También existe el riesgo de que una Gaussiana se reduzca para cubrir solo un valor atípico (aunque la regularización o los límites de covarianza mínima pueden mitigar eso).


<details>
<summary>Ejemplo --  Agrupamiento Suave & Puntuaciones de Anomalía
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
En este código, entrenamos un GMM con 3 Gaussianos sobre el tráfico normal (suponiendo que conocemos 3 perfiles de tráfico legítimo). Las medias y covarianzas impresas describen estos clústeres (por ejemplo, una media podría estar alrededor de [50,500] correspondiente al centro de un clúster, etc.). Luego probamos una conexión sospechosa [duration=200, bytes=800]. El predict_proba da la probabilidad de que este punto pertenezca a cada uno de los 3 clústeres; esperaríamos que estas probabilidades sean muy bajas o altamente sesgadas ya que [200,800] está lejos de los clústeres normales. Se imprime la puntuación general de score_samples (log-verosimilitud); un valor muy bajo indica que el punto no se ajusta bien al modelo, marcándolo como una anomalía. En la práctica, se podría establecer un umbral en la log-verosimilitud (o en la probabilidad máxima) para decidir si un punto es lo suficientemente improbable como para considerarse malicioso. GMM, por lo tanto, proporciona una forma fundamentada de hacer detección de anomalías y también genera clústeres suaves que reconocen la incertidumbre.

### Isolation Forest

**Isolation Forest** es un algoritmo de detección de anomalías en conjunto basado en la idea de aislar puntos aleatoriamente. El principio es que las anomalías son pocas y diferentes, por lo que son más fáciles de aislar que los puntos normales. Un Isolation Forest construye muchos árboles de aislamiento binarios (árboles de decisión aleatorios) que particionan los datos aleatoriamente. En cada nodo de un árbol, se selecciona una característica aleatoria y se elige un valor de división aleatorio entre el mínimo y el máximo de esa característica para los datos en ese nodo. Esta división divide los datos en dos ramas. El árbol crece hasta que cada punto está aislado en su propia hoja o se alcanza una altura máxima del árbol.

La detección de anomalías se realiza observando la longitud del camino de cada punto en estos árboles aleatorios: el número de divisiones requeridas para aislar el punto. Intuitivamente, las anomalías (valores atípicos) tienden a ser aisladas más rápido porque una división aleatoria es más probable que separe un valor atípico (que se encuentra en una región escasa) que un punto normal en un clúster denso. El Isolation Forest calcula una puntuación de anomalía a partir de la longitud promedio del camino en todos los árboles: camino promedio más corto → más anómalo. Las puntuaciones suelen estar normalizadas a [0,1] donde 1 significa muy probable que sea una anomalía.

> [!TIP]
> *Casos de uso en ciberseguridad:* Los Isolation Forests se han utilizado con éxito en detección de intrusiones y detección de fraudes. Por ejemplo, entrenar un Isolation Forest en registros de tráfico de red que contienen principalmente comportamiento normal; el bosque producirá caminos cortos para tráfico extraño (como una IP que utiliza un puerto desconocido o un patrón de tamaño de paquete inusual), marcándolo para inspección. Debido a que no requiere ataques etiquetados, es adecuado para detectar tipos de ataques desconocidos. También se puede implementar en datos de inicio de sesión de usuarios para detectar tomas de control de cuentas (los tiempos o ubicaciones de inicio de sesión anómalos se aíslan rápidamente). En un caso de uso, un Isolation Forest podría proteger a una empresa monitoreando métricas del sistema y generando una alerta cuando una combinación de métricas (CPU, red, cambios de archivos) se ve muy diferente (caminos de aislamiento cortos) de los patrones históricos.

#### Suposiciones y Limitaciones

**Ventajas**: Isolation Forest no requiere una suposición de distribución; se dirige directamente al aislamiento. Es eficiente en datos de alta dimensión y grandes conjuntos de datos (complejidad lineal $O(n\log n)$ para construir el bosque) ya que cada árbol aísla puntos con solo un subconjunto de características y divisiones. Tiende a manejar bien las características numéricas y puede ser más rápido que los métodos basados en distancia que podrían ser $O(n^2)$. También proporciona automáticamente una puntuación de anomalía, por lo que puedes establecer un umbral para alertas (o usar un parámetro de contaminación para decidir automáticamente un corte basado en una fracción de anomalía esperada).

**Limitaciones**: Debido a su naturaleza aleatoria, los resultados pueden variar ligeramente entre ejecuciones (aunque con suficientes árboles esto es menor). Si los datos tienen muchas características irrelevantes o si las anomalías no se diferencian fuertemente en ninguna característica, el aislamiento podría no ser efectivo (divisiones aleatorias podrían aislar puntos normales por casualidad; sin embargo, promediar muchos árboles mitiga esto). Además, el Isolation Forest generalmente asume que las anomalías son una pequeña minoría (lo cual es generalmente cierto en escenarios de ciberseguridad).

<details>
<summary>Ejemplo -- Detección de Valores Atípicos en Registros de Red
</summary>

Usaremos el conjunto de datos de prueba anterior (que contiene puntos normales y algunos puntos de ataque) y ejecutaremos un Isolation Forest para ver si puede separar los ataques. Supondremos que esperamos que ~15% de los datos sean anómalos (para demostración).
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
En este código, instanciamos `IsolationForest` con 100 árboles y establecemos `contamination=0.15` (lo que significa que esperamos alrededor del 15% de anomalías; el modelo establecerá su umbral de puntuación para que ~15% de los puntos sean marcados). Lo ajustamos en `X_test_if`, que contiene una mezcla de puntos normales y de ataque (nota: normalmente ajustarías en datos de entrenamiento y luego usarías predecir en nuevos datos, pero aquí, para ilustrar, ajustamos y predecimos en el mismo conjunto para observar directamente los resultados).

La salida muestra las etiquetas predichas para los primeros 20 puntos (donde -1 indica anomalía). También imprimimos cuántas anomalías se detectaron en total y algunos ejemplos de puntuaciones de anomalía. Esperaríamos que aproximadamente 18 de 120 puntos sean etiquetados como -1 (ya que la contaminación fue del 15%). Si nuestras 20 muestras de ataque son realmente las más atípicas, la mayoría de ellas deberían aparecer en esas predicciones de -1. La puntuación de anomalía (la función de decisión de Isolation Forest) es más alta para los puntos normales y más baja (más negativa) para las anomalías; imprimimos algunos valores para ver la separación. En la práctica, uno podría ordenar los datos por puntuación para ver los principales atípicos e investigarlos. Isolation Forest, por lo tanto, proporciona una forma eficiente de filtrar grandes datos de seguridad no etiquetados y seleccionar las instancias más irregulares para análisis humano o un escrutinio automatizado adicional.

### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** es una técnica de reducción de dimensionalidad no lineal diseñada específicamente para visualizar datos de alta dimensión en 2 o 3 dimensiones. Convierte similitudes entre puntos de datos en distribuciones de probabilidad conjunta y trata de preservar la estructura de los vecindarios locales en la proyección de menor dimensión. En términos más simples, t-SNE coloca puntos en (digamos) 2D de tal manera que puntos similares (en el espacio original) terminen cerca unos de otros y puntos disímiles terminen lejos con alta probabilidad.

El algoritmo tiene dos etapas principales:

1. **Calcular afinidades por pares en el espacio de alta dimensión:** Para cada par de puntos, t-SNE calcula una probabilidad de que uno elegiría ese par como vecinos (esto se hace centrando una distribución gaussiana en cada punto y midiendo distancias; el parámetro de perplejidad influye en el número efectivo de vecinos considerados).
2. **Calcular afinidades por pares en el espacio de baja dimensión (por ejemplo, 2D):** Inicialmente, los puntos se colocan aleatoriamente en 2D. t-SNE define una probabilidad similar para las distancias en este mapa (utilizando un núcleo de distribución t de Student, que tiene colas más pesadas que la gaussiana para permitir que los puntos distantes tengan más libertad).
3. **Descenso de Gradiente:** t-SNE luego mueve iterativamente los puntos en 2D para minimizar la divergencia de Kullback–Leibler (KL) entre la distribución de afinidad de alta dimensión y la de baja dimensión. Esto hace que la disposición en 2D refleje la estructura de alta dimensión tanto como sea posible; los puntos que estaban cerca en el espacio original se atraerán entre sí, y aquellos que están lejos se repelerán, hasta que se encuentre un equilibrio.

El resultado es a menudo un gráfico de dispersión visualmente significativo donde los clústeres en los datos se vuelven evidentes.

> [!TIP]
> *Casos de uso en ciberseguridad:* t-SNE se utiliza a menudo para **visualizar datos de seguridad de alta dimensión para análisis humano**. Por ejemplo, en un centro de operaciones de seguridad, los analistas podrían tomar un conjunto de datos de eventos con docenas de características (números de puerto, frecuencias, conteos de bytes, etc.) y usar t-SNE para producir un gráfico en 2D. Los ataques podrían formar sus propios clústeres o separarse de los datos normales en este gráfico, facilitando su identificación. Se ha aplicado a conjuntos de datos de malware para ver agrupaciones de familias de malware o a datos de intrusión en redes donde diferentes tipos de ataque se agrupan de manera distintiva, guiando una investigación adicional. Esencialmente, t-SNE proporciona una forma de ver la estructura en datos cibernéticos que de otro modo serían inescrutables.

#### Suposiciones y Limitaciones

t-SNE es excelente para el descubrimiento visual de patrones. Puede revelar clústeres, subclústeres y atípicos que otros métodos lineales (como PCA) podrían no detectar. Se ha utilizado en investigaciones de ciberseguridad para visualizar datos complejos como perfiles de comportamiento de malware o patrones de tráfico de red. Debido a que preserva la estructura local, es bueno para mostrar agrupaciones naturales.

Sin embargo, t-SNE es computacionalmente más pesado (aproximadamente $O(n^2)$), por lo que puede requerir muestreo para conjuntos de datos muy grandes. También tiene hiperparámetros (perplejidad, tasa de aprendizaje, iteraciones) que pueden afectar la salida; por ejemplo, diferentes valores de perplejidad podrían revelar clústeres a diferentes escalas. Los gráficos de t-SNE a veces pueden ser malinterpretados; las distancias en el mapa no son directamente significativas a nivel global (se enfoca en el vecindario local, a veces los clústeres pueden aparecer artificialmente bien separados). Además, t-SNE es principalmente para visualización; no proporciona una forma directa de proyectar nuevos puntos de datos sin recomputar, y no está destinado a ser utilizado como un preprocesamiento para modelado predictivo (UMAP es una alternativa que aborda algunos de estos problemas con mayor velocidad).

<details>
<summary>Ejemplo -- Visualizando Conexiones de Red
</summary>

Usaremos t-SNE para reducir un conjunto de datos de múltiples características a 2D. Para ilustrar, tomemos los datos de 4D anteriores (que tenían 3 clústeres naturales de tráfico normal) y agreguemos algunos puntos de anomalía. Luego ejecutamos t-SNE y (conceptualmente) visualizamos los resultados.
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
Aquí combinamos nuestro conjunto de datos normal 4D anterior con un puñado de valores atípicos extremos (los valores atípicos tienen una característica (“duración”) establecida muy alta, etc., para simular un patrón extraño). Ejecutamos t-SNE con una perplexidad típica de 30. Los datos de salida _data_2d_ tienen forma (1505, 2). En realidad, no vamos a graficar en este texto, pero si lo hiciéramos, esperaríamos ver quizás tres grupos compactos correspondientes a los 3 grupos normales, y los 5 valores atípicos apareciendo como puntos aislados lejos de esos grupos. En un flujo de trabajo interactivo, podríamos colorear los puntos por su etiqueta (normal o qué grupo, frente a anomalía) para verificar esta estructura. Incluso sin etiquetas, un analista podría notar esos 5 puntos sentados en un espacio vacío en el gráfico 2D y marcarlos. Esto muestra cómo t-SNE puede ser una herramienta poderosa para la detección visual de anomalías y la inspección de grupos en datos de ciberseguridad, complementando los algoritmos automatizados anteriores.

</details>

### HDBSCAN (Clustering Espacial Basado en Densidad Jerárquico de Aplicaciones con Ruido)

**HDBSCAN** es una extensión de DBSCAN que elimina la necesidad de elegir un único valor global `eps` y es capaz de recuperar grupos de **diferente densidad** construyendo una jerarquía de componentes conectados por densidad y luego condensándola. En comparación con DBSCAN estándar, generalmente

* extrae grupos más intuitivos cuando algunos grupos son densos y otros son escasos,
* tiene solo un verdadero hiperparámetro (`min_cluster_size`) y un valor predeterminado sensato,
* le da a cada punto una *probabilidad* de pertenencia a un grupo y un **puntaje de valor atípico** (`outlier_scores_`), lo cual es extremadamente útil para paneles de búsqueda de amenazas.

> [!TIP]
> *Casos de uso en ciberseguridad:* HDBSCAN es muy popular en los pipelines modernos de búsqueda de amenazas; a menudo lo verás dentro de libros de jugadas de caza basados en notebooks que se envían con suites comerciales de XDR. Una receta práctica es agrupar el tráfico de beaconing HTTP durante IR: el agente de usuario, el intervalo y la longitud de la URI a menudo forman varios grupos compactos de actualizadores de software legítimos, mientras que los beacons de C2 permanecen como pequeños grupos de baja densidad o como puro ruido.

<details>
<summary>Ejemplo – Encontrar canales C2 de beaconing</summary>
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

### Consideraciones de Robustez y Seguridad – Envenenamiento y Ataques Adversariales (2023-2025)

Trabajos recientes han demostrado que **los aprendices no supervisados *no* son inmunes a atacantes activos**:

* **Envenenamiento de datos contra detectores de anomalías.** Chen *et al.* (IEEE S&P 2024) demostraron que agregar tan solo un 3 % de tráfico elaborado puede desplazar el límite de decisión de Isolation Forest y ECOD de modo que los ataques reales parezcan normales. Los autores lanzaron un PoC de código abierto (`udo-poison`) que sintetiza automáticamente puntos de veneno.
* **Inyección de puertas traseras en modelos de agrupamiento.** La técnica *BadCME* (BlackHat EU 2023) implanta un pequeño patrón de activación; cada vez que aparece ese activador, un detector basado en K-Means coloca silenciosamente el evento dentro de un clúster “benigno”.
* **Evasión de DBSCAN/HDBSCAN.** Un preprint académico de 2025 de KU Leuven mostró que un atacante puede elaborar patrones de balizamiento que caen intencionadamente en huecos de densidad, ocultándose efectivamente dentro de etiquetas de *ruido*.

Mitigaciones que están ganando tracción:

1. **Desinfección del modelo / TRIM.** Antes de cada época de reentrenamiento, descartar el 1–2 % de los puntos con mayor pérdida (máxima verosimilitud recortada) para hacer que el envenenamiento sea drásticamente más difícil.
2. **Ensamblaje de consenso.** Combinar varios detectores heterogéneos (por ejemplo, Isolation Forest + GMM + ECOD) y generar una alerta si *cualquiera* de los modelos señala un punto. La investigación indica que esto aumenta el costo para el atacante en más de 10×.
3. **Defensa basada en distancia para agrupamiento.** Recalcular clústeres con `k` semillas aleatorias diferentes e ignorar puntos que constantemente cambian de clúster.

---

### Herramientas Modernas de Código Abierto (2024-2025)

* **PyOD 2.x** (lanzado en mayo de 2024) agregó detectores *ECOD*, *COPOD* y *AutoFormer* acelerados por GPU. Ahora incluye un subcomando `benchmark` que te permite comparar más de 30 algoritmos en tu conjunto de datos con **una línea de código**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (febrero de 2025) se centra en visión pero también contiene una implementación genérica de **PatchCore** – útil para la detección de páginas de phishing basadas en capturas de pantalla.
* **scikit-learn 1.5** (noviembre de 2024) finalmente expone `score_samples` para *HDBSCAN* a través del nuevo envoltorio `cluster.HDBSCAN`, por lo que no necesitas el paquete contrib externo cuando estás en Python 3.12.

<details>
<summary>Ejemplo rápido de PyOD – Ensamble ECOD + Isolation Forest</summary>
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

## Referencias

- [HDBSCAN – Agrupamiento jerárquico basado en densidad](https://github.com/scikit-learn-contrib/hdbscan)
- Chen, X. *et al.* “Sobre la vulnerabilidad de la detección de anomalías no supervisada a la contaminación de datos.” *Simposio de IEEE sobre Seguridad y Privacidad*, 2024.



{{#include ../banners/hacktricks-training.md}}
