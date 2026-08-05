# Algoritmos de aprendizaje no supervisado

{{#include ../banners/hacktricks-training.md}}

## Aprendizaje no supervisado

El aprendizaje no supervisado es un tipo de machine learning en el que el modelo se entrena con datos sin respuestas etiquetadas. El objetivo es encontrar patrones, estructuras o relaciones dentro de los datos. A diferencia del aprendizaje supervisado, en el que el modelo aprende a partir de ejemplos etiquetados, los algoritmos de aprendizaje no supervisado trabajan con datos sin etiquetar.
El aprendizaje no supervisado se utiliza a menudo para tareas como clustering, reducción de dimensionalidad y detección de anomalías. Puede ayudar a descubrir patrones ocultos en los datos, agrupar elementos similares o reducir la complejidad de los datos conservando sus características esenciales.


### K-Means Clustering

K-Means es un algoritmo de clustering basado en centroides que divide los datos en K clusters asignando cada punto a la media del cluster más cercano. El algoritmo funciona de la siguiente manera:
1. **Inicialización**: Elige K centros de cluster iniciales (centroides), a menudo de forma aleatoria o mediante métodos más avanzados como k-means++
2. **Asignación**: Asigna cada punto de datos al centroide más cercano según una métrica de distancia (por ejemplo, la distancia euclidiana).
3. **Actualización**: Recalcula los centroides obteniendo la media de todos los puntos de datos asignados a cada cluster.
4. **Repetición**: Los pasos 2–3 se repiten hasta que las asignaciones de los clusters se estabilizan (los centroides dejan de moverse significativamente).

> [!TIP]
> *Casos de uso en ciberseguridad:* K-Means se utiliza para la detección de intrusiones mediante el clustering de eventos de red. Por ejemplo, unos investigadores aplicaron K-Means al dataset de intrusiones KDD Cup 99 y descubrieron que dividía eficazmente el tráfico en clusters normales y de ataques. En la práctica, los analistas de seguridad pueden agrupar entradas de logs o datos de comportamiento de usuarios para encontrar grupos de actividad similar; cualquier punto que no pertenezca a un cluster bien definido podría indicar anomalías (por ejemplo, una nueva variante de malware que forme su propio cluster pequeño). K-Means también puede ayudar a clasificar familias de malware agrupando binarios según perfiles de comportamiento o vectores de características.

#### Selección de K
El número de clusters (K) es un hiperparámetro que debe definirse antes de ejecutar el algoritmo. Técnicas como el Método del Codo o el Silhouette Score pueden ayudar a determinar un valor adecuado para K mediante la evaluación del rendimiento del clustering:

- **Método del Codo**: Representa gráficamente la suma de las distancias al cuadrado desde cada punto hasta el centroide del cluster asignado en función de K. Busca un punto de "codo" donde la tasa de disminución cambie bruscamente, lo que indica un número adecuado de clusters.
- **Silhouette Score**: Calcula el silhouette score para diferentes valores de K. Un silhouette score más alto indica clusters mejor definidos.

#### Supuestos y limitaciones

K-Means asume que los **clusters son esféricos y tienen el mismo tamaño**, lo que puede no cumplirse en todos los datasets. Es sensible a la posición inicial de los centroides y puede converger a mínimos locales. Además, K-Means no es adecuado para datasets con densidades variables, formas no globulares o características con escalas diferentes. Pueden ser necesarios pasos de preprocesamiento como la normalización o la estandarización para garantizar que todas las características contribuyan por igual a los cálculos de distancia.

<details>
<summary>Ejemplo -- Clustering de eventos de red
</summary>
A continuación simulamos datos de tráfico de red y utilizamos K-Means para agruparlos. Supongamos que tenemos eventos con características como la duración de la conexión y el número de bytes. Creamos 3 clusters de tráfico “normal” y 1 cluster pequeño que representa un patrón de ataque. Después ejecutamos K-Means para comprobar si los separa.
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
En este ejemplo, K-Means debería encontrar 4 clusters. El pequeño cluster de ataques (con una duración inusualmente alta, ~200) idealmente formará su propio cluster dada su distancia de los clusters normales. Imprimimos los tamaños y centros de los clusters para interpretar los resultados. En un escenario real, se podría etiquetar el cluster con pocos puntos como posibles anomalías o inspeccionar sus miembros en busca de actividad maliciosa.
</details>

### Clustering jerárquico

El clustering jerárquico construye una jerarquía de clusters utilizando un enfoque ascendente (aglomerativo) o descendente (divisivo):

1. **Aglomerativo (ascendente)**: Comienza con cada punto de datos como un cluster separado y fusiona iterativamente los clusters más cercanos hasta que queda un solo cluster o se cumple un criterio de detención.
2. **Divisivo (descendente)**: Comienza con todos los puntos de datos en un solo cluster y divide iterativamente los clusters hasta que cada punto de datos es su propio cluster o se cumple un criterio de detención.

El clustering aglomerativo requiere una definición de la distancia entre clusters y un criterio de enlace para decidir qué clusters fusionar. Los métodos de enlace comunes incluyen el enlace simple (distancia entre los puntos más cercanos de dos clusters), el enlace completo (distancia entre los puntos más lejanos), el enlace promedio, etc., y la métrica de distancia suele ser euclidiana. La elección del enlace afecta a la forma de los clusters producidos. No es necesario especificar previamente el número de clusters K; se puede “cortar” el dendrograma en un nivel elegido para obtener el número de clusters deseado.

El clustering jerárquico produce un dendrograma, una estructura similar a un árbol que muestra las relaciones entre clusters en distintos niveles de granularidad. El dendrograma se puede cortar en el nivel deseado para obtener un número específico de clusters.

> [!TIP]
> *Casos de uso en ciberseguridad:* El clustering jerárquico puede organizar eventos o entidades en un árbol para detectar relaciones. Por ejemplo, en el análisis de malware, el clustering aglomerativo podría agrupar muestras según su similitud de comportamiento, revelando una jerarquía de familias y variantes de malware. En seguridad de redes, se podrían agrupar flujos de tráfico IP y utilizar el dendrograma para observar subgrupos de tráfico (por ejemplo, primero por protocolo y luego por comportamiento). Como no es necesario elegir K de antemano, resulta útil al explorar datos nuevos cuyo número de categorías de ataque se desconoce.

#### Supuestos y limitaciones

El clustering jerárquico no presupone una forma de cluster específica y puede capturar clusters anidados. Es útil para descubrir taxonomías o relaciones entre grupos (por ejemplo, agrupar malware por subgrupos de familias). Es determinista (no presenta problemas de inicialización aleatoria). Una ventaja clave es el dendrograma, que proporciona información sobre la estructura de clustering de los datos en todas las escalas; los analistas de seguridad pueden decidir un punto de corte adecuado para identificar clusters significativos. Sin embargo, es computacionalmente costoso (normalmente $O(n^2)$ o peor en implementaciones ingenuas) y no resulta viable para datasets muy grandes. También es un procedimiento codicioso: una vez realizada una fusión o división, no se puede deshacer, lo que puede producir clusters subóptimos si se comete un error al principio. Los valores atípicos también pueden afectar a algunas estrategias de enlace (el enlace simple puede provocar el efecto de “encadenamiento”, en el que los clusters se conectan mediante valores atípicos).

<details>
<summary>Ejemplo -- Clustering aglomerativo de eventos
</summary>

Reutilizaremos los datos sintéticos del ejemplo de K-Means (3 clusters normales + 1 cluster de ataques) y aplicaremos clustering aglomerativo. A continuación, mostraremos cómo obtener un dendrograma y las etiquetas de los clusters.
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

### DBSCAN (Clustering espacial basado en densidad de aplicaciones con ruido)

DBSCAN es un algoritmo de clustering basado en densidad que agrupa los puntos que están muy próximos entre sí, mientras marca como valores atípicos los puntos de regiones con baja densidad. Es especialmente útil para datasets con densidades variables y formas no esféricas.

DBSCAN funciona definiendo dos parámetros:
- **Epsilon (ε)**: La distancia máxima entre dos puntos para que se consideren parte del mismo cluster.
- **MinPts**: El número mínimo de puntos necesarios para formar una región densa (punto central).

DBSCAN identifica puntos centrales, puntos frontera y puntos de ruido:
- **Punto central**: Un punto con al menos MinPts vecinos dentro de una distancia ε.
- **Punto frontera**: Un punto que está dentro de una distancia ε de un punto central, pero tiene menos de MinPts vecinos.
- **Punto de ruido**: Un punto que no es ni un punto central ni un punto frontera.

El clustering comienza seleccionando un punto central no visitado, marcándolo como un nuevo cluster y añadiendo recursivamente todos los puntos alcanzables por densidad desde él (puntos centrales y sus vecinos, etc.). Los puntos frontera se añaden al cluster de un punto central cercano. Después de expandir todos los puntos alcanzables, DBSCAN pasa a otro punto central no visitado para iniciar un nuevo cluster. Los puntos a los que no llega ningún punto central permanecen etiquetados como ruido.

> [!TIP]
> *Casos de uso en ciberseguridad:* DBSCAN es útil para la detección de anomalías en el tráfico de red. Por ejemplo, la actividad normal de los usuarios podría formar uno o más clusters densos en el espacio de características, mientras que los comportamientos de ataque nuevos aparecen como puntos dispersos que DBSCAN etiquetará como ruido (valores atípicos). Se ha utilizado para agrupar registros de flujo de red, donde puede detectar port scans o tráfico de denial-of-service como regiones dispersas de puntos. Otra aplicación es agrupar variantes de malware: si la mayoría de las muestras se agrupan por familias, pero algunas no encajan en ningún grupo, esas pocas podrían ser malware zero-day. La capacidad de marcar el ruido permite a los equipos de seguridad centrarse en investigar esos valores atípicos.

#### Supuestos y limitaciones

**Supuestos y ventajas:**: DBSCAN no presupone que los clusters sean esféricos; puede encontrar clusters con formas arbitrarias (incluso clusters alargados o adyacentes). Determina automáticamente el número de clusters basándose en la densidad de los datos y puede identificar eficazmente los valores atípicos como ruido. Esto lo hace potente para datos del mundo real con formas irregulares y ruido. Es resistente a los valores atípicos (a diferencia de K-Means, que los fuerza a formar parte de clusters). Funciona bien cuando los clusters tienen una densidad aproximadamente uniforme.

**Limitaciones**: El rendimiento de DBSCAN depende de elegir valores adecuados para ε y MinPts. Puede tener dificultades con datos que presentan densidades variables; un único valor de ε no puede adaptarse simultáneamente a clusters densos y dispersos. Si ε es demasiado pequeño, etiqueta la mayoría de los puntos como ruido; si es demasiado grande, los clusters pueden fusionarse incorrectamente. Además, DBSCAN puede ser ineficiente con datasets muy grandes (ingenuamente $O(n^2)$, aunque la indexación espacial puede ayudar). En espacios de características de alta dimensionalidad, el concepto de “distancia dentro de ε” puede perder significado (la maldición de la dimensionalidad), y DBSCAN puede requerir un ajuste cuidadoso de los parámetros o no encontrar clusters intuitivos. A pesar de esto, extensiones como HDBSCAN abordan algunos problemas, como la densidad variable.

<details>
<summary>Ejemplo -- Clustering con ruido
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
En este fragmento, ajustamos `eps` y `min_samples` para adaptarlos a la escala de nuestros datos (15.0 en unidades de las características y requiriendo 5 puntos para formar un clúster). DBSCAN debería encontrar 2 clústeres (los clústeres de tráfico normal) y marcar los 5 valores atípicos inyectados como ruido. Mostramos el número de clústeres frente a los puntos de ruido para verificarlo. En un entorno real, se podría iterar sobre ε (usando una heurística basada en un gráfico de distancias a los k vecinos para elegir ε) y MinPts (a menudo establecido aproximadamente en la dimensionalidad de los datos + 1 como regla general) para encontrar resultados de clustering estables. La capacidad de etiquetar explícitamente el ruido ayuda a separar los datos de posibles ataques para analizarlos posteriormente.

</details>

### Principal Component Analysis (PCA)

PCA es una técnica de **reducción de dimensionalidad** que encuentra un nuevo conjunto de ejes ortogonales (componentes principales) que capturan la máxima varianza de los datos. En términos sencillos, PCA rota y proyecta los datos sobre un nuevo sistema de coordenadas, de modo que el primer componente principal (PC1) explica la mayor varianza posible, el segundo componente (PC2) explica la mayor varianza ortogonal a PC1, y así sucesivamente. Matemáticamente, PCA calcula los eigenvectores de la matriz de covarianza de los datos; estos eigenvectores son las direcciones de los componentes principales, y los eigenvalores correspondientes indican la cantidad de varianza explicada por cada uno. A menudo se utiliza para la extracción de características, la visualización y la reducción del ruido.

Ten en cuenta que esto resulta útil si las dimensiones del dataset contienen **dependencias lineales o correlaciones significativas**.

PCA funciona identificando los componentes principales de los datos, que son las direcciones de máxima varianza. Los pasos que intervienen en PCA son:
1. **Estandarización**: Centrar los datos restando la media y escalarlos a una varianza unitaria.
2. **Matriz de covarianza**: Calcular la matriz de covarianza de los datos estandarizados para comprender las relaciones entre las características.
3. **Descomposición de eigenvalores**: Realizar la descomposición de eigenvalores sobre la matriz de covarianza para obtener los eigenvalores y eigenvectores.
4. **Seleccionar los componentes principales**: Ordenar los eigenvalores de forma descendente y seleccionar los K eigenvectores superiores correspondientes a los eigenvalores más grandes. Estos eigenvectores forman el nuevo espacio de características.
5. **Transformar los datos**: Proyectar los datos originales sobre el nuevo espacio de características usando los componentes principales seleccionados.
PCA se utiliza ampliamente para la visualización de datos, la reducción del ruido y como paso de preprocesamiento para otros algoritmos de machine learning. Ayuda a reducir la dimensionalidad de los datos conservando al mismo tiempo su estructura esencial.

#### Eigenvalores y eigenvectores

Un eigenvalor es un escalar que indica la cantidad de varianza capturada por su eigenvector correspondiente. Un eigenvector representa una dirección en el espacio de características a lo largo de la cual los datos varían más.

Imagina que A es una matriz cuadrada y que v es un vector distinto de cero tal que: `A * v = λ * v`
donde:
- A es una matriz cuadrada como [ [1, 2], [2, 1]] (por ejemplo, una matriz de covarianza)
- v es un eigenvector (por ejemplo, [1, 1])

Entonces, `A * v = [ [1, 2], [2, 1]] * [1, 1] = [3, 3]`, que será el eigenvalor λ multiplicado por el eigenvector v, haciendo que el eigenvalor λ = 3.

#### Eigenvalores y eigenvectores en PCA

Expliquémoslo con un ejemplo. Imagina que tienes un dataset con muchas imágenes en escala de grises de rostros de 100x100 píxeles. Cada píxel puede considerarse una característica, por lo que tienes 10.000 características por imagen (o un vector de 10000 componentes por imagen). Si quieres reducir la dimensionalidad de este dataset usando PCA, seguirías estos pasos:

1. **Estandarización**: Centrar los datos restando del dataset la media de cada característica (píxel).
2. **Matriz de covarianza**: Calcular la matriz de covarianza de los datos estandarizados, que captura cómo varían conjuntamente las características (píxeles).
- Ten en cuenta que la covarianza entre dos variables (píxeles en este caso) indica cuánto cambian conjuntamente, por lo que la idea aquí es averiguar qué píxeles tienden a aumentar o disminuir conjuntamente con una relación lineal.
- Por ejemplo, si el píxel 1 y el píxel 2 tienden a aumentar conjuntamente, la covarianza entre ellos será positiva.
- La matriz de covarianza será una matriz de 10,000x10,000 en la que cada entrada representa la covarianza entre dos píxeles.
3. **Resolver la ecuación de eigenvalores**: La ecuación de eigenvalores que se debe resolver es `C * v = λ * v`, donde C es la matriz de covarianza, v es el eigenvector y λ es el eigenvalor. Puede resolverse usando métodos como:
- **Descomposición de eigenvalores**: Realizar la descomposición de eigenvalores sobre la matriz de covarianza para obtener los eigenvalores y eigenvectores.
- **Descomposición en valores singulares (SVD)**: Como alternativa, puedes usar SVD para descomponer la matriz de datos en valores y vectores singulares, lo que también puede producir los componentes principales.
4. **Seleccionar los componentes principales**: Ordenar los eigenvalores de forma descendente y seleccionar los K eigenvectores superiores correspondientes a los eigenvalores más grandes. Estos eigenvectores representan las direcciones de máxima varianza de los datos.

> [!TIP]
> *Casos de uso en ciberseguridad:* Un uso habitual de PCA en security es la reducción de características para la detección de anomalías. Por ejemplo, un sistema de detección de intrusiones con más de 40 métricas de red (como las características de NSL-KDD) puede usar PCA para reducirlas a un pequeño número de componentes, resumir los datos para su visualización o introducirlos en algoritmos de clustering. Los analistas podrían representar el tráfico de red en el espacio de los dos primeros componentes principales para comprobar si los ataques se separan del tráfico normal. PCA también puede ayudar a eliminar características redundantes (como bytes enviados frente a bytes recibidos si están correlacionados) para hacer que los algoritmos de detección sean más robustos y rápidos.

#### Supuestos y limitaciones

PCA asume que los **ejes principales de varianza son significativos**; es un método lineal, por lo que captura las correlaciones lineales de los datos. Es no supervisado, ya que utiliza únicamente la covarianza de las características. Entre las ventajas de PCA se incluyen la reducción del ruido (los componentes de varianza pequeña suelen corresponder al ruido) y la descorrelación de las características. Es computacionalmente eficiente para dimensiones moderadamente altas y suele ser un paso de preprocesamiento útil para otros algoritmos (para mitigar la maldición de la dimensionalidad). Una limitación es que PCA está restringido a relaciones lineales: no captura estructuras no lineales complejas (mientras que los autoencoders o t-SNE sí podrían hacerlo). Además, los componentes de PCA pueden ser difíciles de interpretar en términos de las características originales (son combinaciones de características originales). En ciberseguridad, se debe tener precaución: un ataque que solo provoque un cambio sutil en una característica de baja varianza podría no aparecer en los PC principales (ya que PCA prioriza la varianza y no necesariamente lo “interesante”).

<details>
<summary>Ejemplo -- Reducción de las dimensiones de datos de red
</summary>

Supongamos que tenemos logs de conexiones de red con varias características (por ejemplo, duraciones, bytes y recuentos). Generaremos un dataset sintético de 4 dimensiones (con cierta correlación entre características) y usaremos PCA para reducirlo a 2 dimensiones con fines de visualización o análisis posterior.
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
Aquí tomamos los clusters de tráfico normal anteriores y ampliamos cada punto de datos con dos features adicionales (packets y errors) que se correlacionan con bytes y duration. Después, PCA se utiliza para comprimir las 4 features en 2 componentes principales. Imprimimos el ratio de varianza explicada, que podría mostrar que, por ejemplo, >95% de la varianza queda capturada por 2 componentes (lo que significa una pequeña pérdida de información). La salida también muestra cómo la forma de los datos se reduce de (1500, 4) a (1500, 2). Los primeros puntos en el espacio PCA se proporcionan como ejemplo. En la práctica, se podría representar data_2d para comprobar visualmente si los clusters son distinguibles. Si hubiera una anomalía, podría observarse como un punto alejado del cluster principal en el espacio PCA. Por tanto, PCA ayuda a destilar datos complejos en un formato manejable para la interpretación humana o para utilizarlos como entrada de otros algoritmos.

</details>


### Gaussian Mixture Models (GMM)

Un Gaussian Mixture Model asume que los datos se generan a partir de una mezcla de **varias distribuciones Gaussianas (normales) con parámetros desconocidos**. En esencia, es un modelo probabilístico de clustering: intenta asignar de forma flexible cada punto a uno de K componentes Gaussianos. Cada componente Gaussiano k tiene un vector de media (μ_k), una matriz de covarianza (Σ_k) y un peso de mezcla (π_k) que representa la prevalencia de ese cluster. A diferencia de K-Means, que realiza asignaciones “hard”, GMM proporciona a cada punto una probabilidad de pertenecer a cada cluster.

El ajuste de GMM normalmente se realiza mediante el algoritmo Expectation-Maximization (EM):

- **Initialization**: Se comienza con estimaciones iniciales para las medias, covarianzas y coeficientes de mezcla (o se utilizan los resultados de K-Means como punto de partida).

- **E-step (Expectation)**: Dados los parámetros actuales, se calcula la responsabilidad de cada cluster para cada punto: esencialmente `r_nk = P(z_k | x_n)`, donde z_k es la variable latente que indica la pertenencia al cluster del punto x_n. Esto se realiza mediante el teorema de Bayes, calculando la probabilidad posterior de que cada punto pertenezca a cada cluster según los parámetros actuales. Las responsabilidades se calculan de la siguiente manera:
```math
r_{nk} = \frac{\pi_k \mathcal{N}(x_n | \mu_k, \Sigma_k)}{\sum_{j=1}^{K} \pi_j \mathcal{N}(x_n | \mu_j, \Sigma_j)}
```
donde:
- \( \pi_k \) es el coeficiente de mezcla del cluster k (probabilidad previa del cluster k),
- \( \mathcal{N}(x_n | \mu_k, \Sigma_k) \) es la función de densidad de probabilidad Gaussiana para el punto \( x_n \), dada la media \( \mu_k \) y la covarianza \( \Sigma_k \).

- **M-step (Maximization)**: Se actualizan los parámetros utilizando las responsabilidades calculadas en el E-step:
- Se actualiza cada media μ_k como la media ponderada de los puntos, donde los pesos son las responsabilidades.
- Se actualiza cada covarianza Σ_k como la covarianza ponderada de los puntos asignados al cluster k.
- Se actualizan los coeficientes de mezcla π_k como la responsabilidad media del cluster k.

- Se **Iterate** entre los pasos E y M hasta alcanzar la convergencia (cuando los parámetros se estabilizan o la mejora de la likelihood queda por debajo de un umbral).

El resultado es un conjunto de distribuciones Gaussianas que modelan colectivamente la distribución general de los datos. Podemos utilizar el GMM ajustado para realizar clustering asignando cada punto a la Gaussiana con mayor probabilidad, o conservar las probabilidades para representar la incertidumbre. También se puede evaluar la likelihood de nuevos puntos para comprobar si encajan en el modelo (lo que resulta útil para la detección de anomalías).

> [!TIP]
> *Use cases in cybersecurity:* GMM puede utilizarse para la detección de anomalías mediante el modelado de la distribución de los datos normales: cualquier punto con una probabilidad muy baja bajo la mezcla aprendida se marca como anomalía. Por ejemplo, se podría entrenar un GMM con features de tráfico de red legítimo; una conexión de ataque que no se parezca a ningún cluster aprendido tendría una likelihood baja. Los GMM también se utilizan para agrupar actividades cuyos clusters podrían tener formas diferentes; por ejemplo, para agrupar usuarios según sus perfiles de comportamiento, donde las features de cada perfil podrían seguir una distribución similar a la Gaussiana, pero con su propia estructura de varianza. Otro escenario sería la detección de phishing: las features de los emails legítimos podrían formar un cluster Gaussiano, los emails de phishing conocidos otro, y las nuevas campañas de phishing podrían aparecer como una Gaussiana independiente o como puntos con una likelihood baja respecto a la mezcla existente.

#### Assumptions and Limitations

GMM es una generalización de K-Means que incorpora la covarianza, por lo que los clusters pueden ser elipsoidales (no solo esféricos). Puede gestionar clusters de diferentes tamaños y formas si la covarianza es full. El soft clustering es una ventaja cuando los límites entre clusters son difusos; por ejemplo, en ciberseguridad, un evento podría tener características de varios tipos de ataque, y GMM puede reflejar esa incertidumbre mediante probabilidades. GMM también proporciona una estimación probabilística de la densidad de los datos, útil para detectar outliers (puntos con una likelihood baja bajo todos los componentes de la mezcla).

Como desventaja, GMM requiere especificar el número de componentes K (aunque se pueden utilizar criterios como BIC/AIC para seleccionarlo). En ocasiones, EM puede converger lentamente o alcanzar un óptimo local, por lo que la inicialización es importante (a menudo se ejecuta EM varias veces). Si los datos no siguen realmente una mezcla de Gaussianas, el modelo podría ajustarse mal. También existe el riesgo de que una Gaussiana se reduzca hasta cubrir únicamente un outlier (aunque la regularización o los límites mínimos de covarianza pueden mitigar este problema).


<details>
<summary>Example --  Soft Clustering & Anomaly Scores
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
En este código, entrenamos un GMM con 3 Gaussianas sobre el tráfico normal (asumiendo que conocemos 3 perfiles de tráfico legítimo). Las medias y covarianzas impresas describen estos clusters (por ejemplo, una media podría estar alrededor de [50,500], correspondiente al centro de uno de los clusters, etc.). Luego probamos una conexión sospechosa [duration=200, bytes=800]. `predict_proba` proporciona la probabilidad de que este punto pertenezca a cada uno de los 3 clusters; esperaríamos que estas probabilidades fueran muy bajas o estuvieran muy sesgadas, ya que [200,800] se encuentra lejos de los clusters normales. Se imprime el `score_samples` general (log-likelihood); un valor muy bajo indica que el punto no encaja bien con el modelo, marcándolo como una anomalía. En la práctica, se podría establecer un umbral sobre el log-likelihood (o sobre la probabilidad máxima) para decidir si un punto es suficientemente improbable como para considerarlo malicioso. Por tanto, GMM proporciona una forma fundamentada de realizar anomaly detection y también produce clusters flexibles que reconocen la incertidumbre.
</details>

### Isolation Forest

**Isolation Forest** es un algoritmo de anomaly detection basado en la idea de aislar puntos aleatoriamente. El principio es que las anomalías son escasas y diferentes, por lo que resulta más fácil aislarlas que aislar los puntos normales. Un Isolation Forest construye muchos árboles binarios de aislamiento (random decision trees) que particionan los datos aleatoriamente. En cada nodo de un árbol, se selecciona una feature aleatoria y se elige un valor de división aleatorio entre el mínimo y el máximo de esa feature para los datos de dicho nodo. Esta división separa los datos en dos ramas. El árbol crece hasta que cada punto queda aislado en su propia hoja o se alcanza una altura máxima del árbol.

La detección de anomalías se realiza observando la longitud del recorrido de cada punto en estos árboles aleatorios: el número de divisiones necesarias para aislarlo. Intuitivamente, las anomalías (outliers) tienden a aislarse más rápido porque una división aleatoria tiene más probabilidades de separar un outlier (que se encuentra en una región dispersa) que un punto normal en un cluster denso. Isolation Forest calcula un anomaly score a partir de la longitud media del recorrido en todos los árboles: recorrido medio más corto → mayor anomalía. Los scores suelen normalizarse al intervalo [0,1], donde 1 significa que probablemente se trata de una anomalía.

> [!TIP]
> *Casos de uso en ciberseguridad:* Isolation Forests se han utilizado con éxito en intrusion detection y fraud detection. Por ejemplo, se puede entrenar un Isolation Forest con logs de tráfico de red que contengan principalmente comportamiento normal; el forest producirá recorridos cortos para el tráfico anómalo (como una IP que utiliza un puerto desconocido o un patrón inusual de tamaños de paquetes), marcándolo para su inspección. Como no requiere ataques etiquetados, es adecuado para detectar tipos de ataque desconocidos. También puede implementarse sobre datos de inicio de sesión de usuarios para detectar account takeovers (las horas o ubicaciones de inicio de sesión anómalas se aíslan rápidamente). En un caso de uso, un Isolation Forest podría proteger una empresa monitorizando las métricas del sistema y generando una alerta cuando una combinación de métricas (CPU, red, cambios de archivos) sea muy diferente (recorridos de aislamiento cortos) de los patrones históricos.

#### Assumptions and Limitations

**Ventajas**: Isolation Forest no requiere asumir una distribución; se centra directamente en el aislamiento. Es eficiente con datos de alta dimensionalidad y grandes datasets (complejidad lineal $O(n\log n)$ para construir el forest), ya que cada árbol aísla los puntos utilizando solo un subconjunto de features y divisiones. Tiende a gestionar bien las features numéricas y puede ser más rápido que los métodos basados en distancia, que podrían tener una complejidad de $O(n^2)$. También proporciona automáticamente un anomaly score, por lo que se puede establecer un umbral para las alertas (o utilizar un parámetro de contaminación para decidir automáticamente un cutoff basado en una fracción de anomalías esperada).

**Limitaciones**: Debido a su naturaleza aleatoria, los resultados pueden variar ligeramente entre ejecuciones (aunque esta variación es mínima con un número suficiente de árboles). Si los datos contienen muchas features irrelevantes o si las anomalías no se diferencian claramente en ninguna feature, el aislamiento podría no ser eficaz (las divisiones aleatorias podrían aislar puntos normales por casualidad; sin embargo, el promedio de muchos árboles mitiga este efecto). Además, Isolation Forest generalmente asume que las anomalías son una minoría pequeña (lo que suele ser cierto en escenarios de ciberseguridad).

<details>
<summary>Example --  Detecting Outliers in Network Logs
</summary>

Utilizaremos el dataset de prueba anterior (que contiene puntos normales y algunos puntos de ataque) y ejecutaremos un Isolation Forest para comprobar si puede separar los ataques. Asumiremos que esperamos que aproximadamente el 15 % de los datos sean anómalos (a modo de demostración).
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
En este código, instanciamos `IsolationForest` con 100 árboles y establecemos `contamination=0.15` (lo que significa que esperamos aproximadamente un 15 % de anomalías; el modelo establecerá su umbral de puntuación para que se marquen aproximadamente el 15 % de los puntos). Lo ajustamos sobre `X_test_if`, que contiene una combinación de puntos normales y de ataque (nota: normalmente se ajustaría sobre los datos de entrenamiento y después se usaría predict sobre datos nuevos, pero aquí, con fines ilustrativos, ajustamos y predecimos sobre el mismo conjunto para observar directamente los resultados).

La salida muestra las etiquetas predichas para los primeros 20 puntos (donde -1 indica una anomalía). También mostramos cuántas anomalías se detectaron en total y algunos ejemplos de puntuaciones de anomalía. Esperaríamos que aproximadamente 18 de los 120 puntos fueran etiquetados como -1 (ya que contamination era del 15 %). Si nuestras 20 muestras de ataque son realmente las más atípicas, la mayoría debería aparecer en esas predicciones -1. La puntuación de anomalía (la función de decisión de Isolation Forest) es mayor para los puntos normales y menor (más negativa) para las anomalías; mostramos algunos valores para observar la separación. En la práctica, se podrían ordenar los datos por puntuación para ver los valores más atípicos e investigarlos. Por tanto, Isolation Forest proporciona una forma eficiente de filtrar grandes volúmenes de datos de seguridad sin etiquetar y seleccionar las instancias más irregulares para el análisis humano o para un escrutinio automatizado adicional.
</details>


### t-SNE (t-Distributed Stochastic Neighbor Embedding)

**t-SNE** es una técnica no lineal de reducción de dimensionalidad diseñada específicamente para visualizar datos de alta dimensionalidad en 2 o 3 dimensiones. Convierte las similitudes entre los puntos de datos en distribuciones de probabilidad conjuntas e intenta preservar la estructura de los vecindarios locales en la proyección de menor dimensionalidad. En términos más sencillos, t-SNE coloca los puntos en, por ejemplo, 2D, de modo que los puntos similares (en el espacio original) terminen cerca unos de otros y los puntos diferentes terminen alejados con una alta probabilidad.

El algoritmo tiene tres etapas principales:

1. **Compute pairwise affinities in high-dimensional space:** Para cada par de puntos, t-SNE calcula la probabilidad de que ese par se elija como vecinos (esto se hace centrando una distribución gaussiana en cada punto y midiendo las distancias; el parámetro de perplexity influye en el número efectivo de vecinos considerados).
2. **Compute pairwise affinities in low-dimensional (e.g. 2D) space:** Inicialmente, los puntos se colocan aleatoriamente en 2D. t-SNE define una probabilidad similar para las distancias en este mapa (usando un kernel de distribución t de Student, que tiene colas más pesadas que la distribución gaussiana para permitir una mayor libertad a los puntos distantes).
3. **Gradient Descent:** A continuación, t-SNE mueve iterativamente los puntos en 2D para minimizar la divergencia de Kullback–Leibler (KL) entre la distribución de afinidad de alta dimensionalidad y la de baja dimensionalidad. Esto hace que la disposición en 2D refleje la estructura de alta dimensionalidad tanto como sea posible: los puntos que estaban cerca en el espacio original se atraen entre sí y los que estaban alejados se repelen, hasta encontrar un equilibrio.

El resultado suele ser un gráfico de dispersión visualmente significativo en el que los clusters de los datos se vuelven evidentes.

> [!TIP]
> *Use cases in cybersecurity:* t-SNE se utiliza a menudo para **visualizar datos de seguridad de alta dimensionalidad para el análisis humano**. Por ejemplo, en un centro de operaciones de seguridad, los analistas podrían tomar un dataset de eventos con docenas de características (números de puerto, frecuencias, cantidades de bytes, etc.) y usar t-SNE para generar un gráfico 2D. Los ataques podrían formar sus propios clusters o separarse de los datos normales en este gráfico, lo que facilitaría su identificación. Se ha aplicado a datasets de malware para observar agrupaciones de familias de malware, o a datos de intrusiones de red, donde distintos tipos de ataque forman clusters diferenciados, lo que orienta investigaciones posteriores. En esencia, t-SNE ofrece una forma de observar estructuras en datos cibernéticos que, de otro modo, serían difíciles de interpretar.

#### Assumptions and Limitations

t-SNE es excelente para descubrir visualmente patrones. Puede revelar clusters, subclusters y valores atípicos que otros métodos lineales (como PCA) quizá no detecten. Se ha utilizado en investigaciones de ciberseguridad para visualizar datos complejos, como perfiles de comportamiento de malware o patrones de tráfico de red. Como preserva la estructura local, es eficaz para mostrar agrupaciones naturales.

Sin embargo, t-SNE tiene un coste computacional mayor (aproximadamente $O(n^2)$), por lo que puede requerir muestreo en datasets muy grandes. También tiene hiperparámetros (perplexity, learning rate, iterations) que pueden afectar a la salida; por ejemplo, distintos valores de perplexity podrían revelar clusters a diferentes escalas. Los gráficos de t-SNE pueden interpretarse erróneamente: las distancias en el mapa no son directamente significativas a nivel global (se centra en los vecindarios locales y, en ocasiones, los clusters pueden parecer artificialmente bien separados). Además, t-SNE se utiliza principalmente para visualización; no proporciona una forma sencilla de proyectar nuevos puntos de datos sin volver a realizar el cálculo y no está pensado para usarse como preprocesamiento en modelos predictivos (UMAP es una alternativa que resuelve algunos de estos problemas con una mayor velocidad).

<details>
<summary>Example -- Visualizing Network Connections
</summary>

Usaremos t-SNE para reducir un dataset con múltiples características a 2D. Como ilustración, tomemos los datos 4D anteriores (que tenían 3 clusters naturales de tráfico normal) y añadamos algunos puntos de anomalía. A continuación, ejecutaremos t-SNE y visualizaremos los resultados de forma conceptual.
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
Aquí combinamos nuestro dataset normal 4D anterior con un pequeño conjunto de valores atípicos extremos (los valores atípicos tienen una característica (“duration”) configurada con un valor muy alto, etc., para simular un patrón inusual). Ejecutamos t-SNE con una perplexity típica de 30. Los datos de salida `data_2d` tienen una forma de (1505, 2). No realizaremos el gráfico en este texto, pero, si lo hiciéramos, esperaríamos ver quizá tres clusters compactos correspondientes a los 3 clusters normales, y los 5 valores atípicos aparecerían como puntos aislados alejados de esos clusters. En un flujo de trabajo interactivo, podríamos colorear los puntos según su etiqueta (normal o perteneciente a un cluster, frente a anomaly) para verificar esta estructura. Incluso sin etiquetas, un analista podría notar esos 5 puntos situados en un espacio vacío del gráfico 2D y marcarlos. Esto demuestra cómo t-SNE puede ser una ayuda muy eficaz para la detección visual de anomalías y la inspección de clusters en datos de cybersecurity, complementando los algoritmos automatizados anteriores.

</details>


### HDBSCAN (Agrupamiento espacial jerárquico basado en densidad de aplicaciones con ruido)

**HDBSCAN** es una extensión de DBSCAN que elimina la necesidad de elegir un único valor global de `eps` y puede recuperar clusters de **diferente densidad** mediante la construcción de una jerarquía de componentes conectados por densidad y su posterior condensación. En comparación con el DBSCAN vanilla, normalmente

* extrae clusters más intuitivos cuando algunos clusters son densos y otros dispersos,
* solo tiene un hiperparámetro real (`min_cluster_size`) y un valor predeterminado razonable,
* asigna a cada punto una *probabilidad* de pertenencia a un cluster y un **outlier score** (`outlier_scores_`), lo que resulta extremadamente práctico para dashboards de threat-hunting.<sup>[[1]](#references)</sup>

> [!TIP]
> *Casos de uso en cybersecurity:* HDBSCAN es muy popular en los pipelines modernos de threat-hunting; a menudo aparece en playbooks de hunting basados en notebooks distribuidos con suites XDR comerciales. Una receta práctica consiste en agrupar el tráfico de beaconing HTTP durante una respuesta a incidentes (IR): el user-agent, el intervalo y la longitud de la URI suelen formar varios grupos compactos de actualizadores de software legítimos, mientras que los beacons de C2 permanecen como pequeños clusters de baja densidad o como puro ruido.

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

### Consideraciones de Robustez y Seguridad – Poisoning y Adversarial Attacks (2023-2025)

Trabajos recientes han demostrado que los **unsupervised learners *no* son inmunes a los atacantes activos**:

* **Data-poisoning contra detectores de anomalías.** Chen *et al.* (IEEE S&P 2024) demostraron que añadir tan solo un 3 % de tráfico manipulado puede desplazar el límite de decisión de Isolation Forest y ECOD, haciendo que los ataques reales parezcan normales. Los autores publicaron un PoC de código abierto (`udo-poison`) que sintetiza automáticamente puntos de poisoning.<sup>[[2]](#references)</sup>
* **Backdooring de modelos de clustering.** La técnica *BadCME* (BlackHat EU 2023) implanta un pequeño patrón trigger; siempre que aparece ese trigger, un detector basado en K-Means coloca silenciosamente el evento dentro de un cluster “benigno”.
* **Evasión de DBSCAN/HDBSCAN.** Un pre-print académico de 2025 de KU Leuven mostró que un atacante puede crear patrones de beaconing que caen deliberadamente en huecos de densidad, ocultándose efectivamente dentro de las etiquetas *noise*.

Mitigaciones que están ganando aceptación:

1. **Model sanitisation / TRIM.** Antes de cada epoch de retraining, descartar el 1–2 % de los puntos con mayor loss (trimmed maximum likelihood) para dificultar considerablemente el poisoning.
2. **Consensus ensembling.** Combinar varios detectores heterogéneos (por ejemplo, Isolation Forest + GMM + ECOD) y generar una alerta si *cualquier* modelo marca un punto. Las investigaciones indican que esto aumenta el coste del atacante en más de 10×.
3. **Defensa basada en distancia para clustering.** Recalcular los clusters con `k` seeds aleatorias diferentes e ignorar los puntos que cambien constantemente de cluster.

---

### Herramientas Open-Source Modernas (2024-2025)

* **PyOD 2.x** (publicado en mayo de 2024) añadió detectores *ECOD*, *COPOD* y *AutoFormer* acelerados por GPU. Ahora incluye un subcomando `benchmark` que permite comparar más de 30 algoritmos en tu dataset con **una sola línea de código**:
```bash
pyod benchmark --input logs.csv --label attack --n_jobs 8
```
* **Anomalib v1.5** (febrero de 2025) se centra en vision, pero también contiene una implementación genérica de **PatchCore**, útil para detectar páginas de phishing basándose en capturas de pantalla.
* **scikit-learn 1.5** (noviembre de 2024) finalmente expone `score_samples` para *HDBSCAN* mediante el nuevo wrapper `cluster.HDBSCAN`, por lo que no necesitas el paquete contrib externo cuando utilizas Python 3.12.

<details>
<summary>Ejemplo rápido de PyOD – ensemble de ECOD + Isolation Forest</summary>
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

- [1] [HDBSCAN – clustering jerárquico basado en densidad](https://github.com/scikit-learn-contrib/hdbscan)
- [2] Chen, X. *et al.* “Sobre la vulnerabilidad de la detección de anomalías no supervisada frente al envenenamiento de datos.” *Simposio IEEE sobre Seguridad y Privacidad*, 2024.



{{#include ../banners/hacktricks-training.md}}
