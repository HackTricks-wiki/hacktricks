# Preparación y Evaluación de Datos del Modelo

{{#include ../banners/hacktricks-training.md}}

La preparación de datos del modelo es un paso crucial en la pipeline de aprendizaje automático, ya que implica transformar datos en bruto en un formato adecuado para entrenar modelos de aprendizaje automático. Este proceso incluye varios pasos clave:

1. **Recolección de Datos**: Reunir datos de diversas fuentes, como bases de datos, APIs o archivos. Los datos pueden ser estructurados (por ejemplo, tablas) o no estructurados (por ejemplo, texto, imágenes).
2. **Limpieza de Datos**: Eliminar o corregir puntos de datos erróneos, incompletos o irrelevantes. Este paso puede implicar manejar valores faltantes, eliminar duplicados y filtrar valores atípicos.
3. **Transformación de Datos**: Convertir los datos en un formato adecuado para el modelado. Esto puede incluir normalización, escalado, codificación de variables categóricas y creación de nuevas características a través de técnicas como la ingeniería de características.
4. **División de Datos**: Dividir el conjunto de datos en conjuntos de entrenamiento, validación y prueba para asegurar que el modelo pueda generalizar bien a datos no vistos.

## Recolección de Datos

La recolección de datos implica reunir datos de diversas fuentes, que pueden incluir:
- **Bases de Datos**: Extraer datos de bases de datos relacionales (por ejemplo, bases de datos SQL) o bases de datos NoSQL (por ejemplo, MongoDB).
- **APIs**: Obtener datos de APIs web, que pueden proporcionar datos en tiempo real o históricos.
- **Archivos**: Leer datos de archivos en formatos como CSV, JSON o XML.
- **Web Scraping**: Recopilar datos de sitios web utilizando técnicas de web scraping.

Dependiendo del objetivo del proyecto de aprendizaje automático, los datos se extraerán y recopilarán de fuentes relevantes para asegurar que sean representativos del dominio del problema.

## Limpieza de Datos

La limpieza de datos es el proceso de identificar y corregir errores o inconsistencias en el conjunto de datos. Este paso es esencial para asegurar la calidad de los datos utilizados para entrenar modelos de aprendizaje automático. Las tareas clave en la limpieza de datos incluyen:
- **Manejo de Valores Faltantes**: Identificar y abordar puntos de datos faltantes. Las estrategias comunes incluyen:
- Eliminar filas o columnas con valores faltantes.
- Imputar valores faltantes utilizando técnicas como la imputación de media, mediana o moda.
- Usar métodos avanzados como la imputación de K-vecinos más cercanos (KNN) o la imputación por regresión.
- **Eliminación de Duplicados**: Identificar y eliminar registros duplicados para asegurar que cada punto de datos sea único.
- **Filtrado de Valores Atípicos**: Detectar y eliminar valores atípicos que pueden sesgar el rendimiento del modelo. Se pueden usar técnicas como Z-score, IQR (Rango Intercuartílico) o visualizaciones (por ejemplo, diagramas de caja) para identificar valores atípicos.

### Ejemplo de limpieza de datos
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
## Transformación de Datos

La transformación de datos implica convertir los datos en un formato adecuado para el modelado. Este paso puede incluir:
- **Normalización y Estandarización**: Escalar características numéricas a un rango común, típicamente [0, 1] o [-1, 1]. Esto ayuda a mejorar la convergencia de los algoritmos de optimización.
- **Escalado Min-Max**: Reescalar características a un rango fijo, generalmente [0, 1]. Esto se hace utilizando la fórmula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalización Z-Score**: Estandarizar características restando la media y dividiendo por la desviación estándar, resultando en una distribución con una media de 0 y una desviación estándar de 1. Esto se hace utilizando la fórmula: `X' = (X - μ) / σ`, donde μ es la media y σ es la desviación estándar.
- **Asimetría y Curtosis**: Ajustar la distribución de características para reducir la asimetría (asimetría) y la curtosis (pico). Esto se puede hacer utilizando transformaciones como logarítmica, raíz cuadrada o transformaciones de Box-Cox. Por ejemplo, si una característica tiene una distribución sesgada, aplicar una transformación logarítmica puede ayudar a normalizarla.
- **Normalización de Cadenas**: Convertir cadenas a un formato consistente, como:
- Minúsculas
- Eliminación de caracteres especiales (manteniendo los relevantes)
- Eliminación de palabras vacías (palabras comunes que no contribuyen al significado, como "el", "es", "y")
- Eliminación de palabras demasiado frecuentes y demasiado raras (por ejemplo, palabras que aparecen en más del 90% de los documentos o menos de 5 veces en el corpus)
- Recorte de espacios en blanco
- **Stemming/Lematización**: Reducir palabras a su forma base o raíz (por ejemplo, "corriendo" a "correr").

- **Codificación de Variables Categóricas**: Convertir variables categóricas en representaciones numéricas. Las técnicas comunes incluyen:
- **Codificación One-Hot**: Crear columnas binarias para cada categoría.
- Por ejemplo, si una característica tiene categorías "rojo", "verde" y "azul", se transformará en tres columnas binarias: `is_red`(100), `is_green`(010) y `is_blue`(001).
- **Codificación de Etiquetas**: Asignar un entero único a cada categoría.
- Por ejemplo, "rojo" = 0, "verde" = 1, "azul" = 2.
- **Codificación Ordinal**: Asignar enteros basados en el orden de las categorías.
- Por ejemplo, si las categorías son "bajo", "medio" y "alto", se pueden codificar como 0, 1 y 2, respectivamente.
- **Codificación Hashing**: Utilizar una función hash para convertir categorías en vectores de tamaño fijo, lo que puede ser útil para variables categóricas de alta cardinalidad.
- Por ejemplo, si una característica tiene muchas categorías únicas, el hashing puede reducir la dimensionalidad mientras preserva algo de información sobre las categorías.
- **Bolsa de Palabras (BoW)**: Representar datos de texto como una matriz de conteos o frecuencias de palabras, donde cada fila corresponde a un documento y cada columna corresponde a una palabra única en el corpus.
- Por ejemplo, si el corpus contiene las palabras "gato", "perro" y "pez", un documento que contiene "gato" y "perro" se representaría como [1, 1, 0]. Esta representación específica se llama "unigram" y no captura el orden de las palabras, por lo que pierde información semántica.
- **Bigram/Trigram**: Ampliar BoW para capturar secuencias de palabras (bigrams o trigrams) para retener algo de contexto. Por ejemplo, "gato y perro" se representaría como un bigram [1, 1] para "gato y" y [1, 1] para "y perro". En estos casos se recopila más información semántica (aumentando la dimensionalidad de la representación) pero solo para 2 o 3 palabras a la vez.
- **TF-IDF (Frecuencia de Término-Frecuencia Inversa de Documento)**: Una medida estadística que evalúa la importancia de una palabra en un documento en relación con una colección de documentos (corpus). Combina la frecuencia de término (con qué frecuencia aparece una palabra en un documento) y la frecuencia inversa de documento (qué tan rara es una palabra en todos los documentos).
- Por ejemplo, si la palabra "gato" aparece frecuentemente en un documento pero es rara en todo el corpus, tendrá un alto puntaje TF-IDF, indicando su importancia en ese documento.

- **Ingeniería de Características**: Crear nuevas características a partir de las existentes para mejorar el poder predictivo del modelo. Esto puede implicar combinar características, extraer componentes de fecha/hora o aplicar transformaciones específicas del dominio.

## División de Datos

La división de datos implica dividir el conjunto de datos en subconjuntos separados para entrenamiento, validación y prueba. Esto es esencial para evaluar el rendimiento del modelo en datos no vistos y prevenir el sobreajuste. Las estrategias comunes incluyen:
- **División Entrenamiento-Prueba**: Dividir el conjunto de datos en un conjunto de entrenamiento (típicamente 60-80% de los datos), un conjunto de validación (10-15% de los datos) para ajustar hiperparámetros, y un conjunto de prueba (10-15% de los datos). El modelo se entrena en el conjunto de entrenamiento y se evalúa en el conjunto de prueba.
- Por ejemplo, si tienes un conjunto de datos de 1000 muestras, podrías usar 700 muestras para entrenamiento, 150 para validación y 150 para prueba.
- **Muestreo Estratificado**: Asegurar que la distribución de clases en los conjuntos de entrenamiento y prueba sea similar a la del conjunto de datos general. Esto es particularmente importante para conjuntos de datos desbalanceados, donde algunas clases pueden tener significativamente menos muestras que otras.
- **División de Series Temporales**: Para datos de series temporales, el conjunto de datos se divide en función del tiempo, asegurando que el conjunto de entrenamiento contenga datos de períodos anteriores y el conjunto de prueba contenga datos de períodos posteriores. Esto ayuda a evaluar el rendimiento del modelo en datos futuros.
- **Validación Cruzada K-Fold**: Dividir el conjunto de datos en K subconjuntos (folds) y entrenar el modelo K veces, cada vez utilizando un fold diferente como conjunto de prueba y los folds restantes como conjunto de entrenamiento. Esto ayuda a asegurar que el modelo se evalúe en diferentes subconjuntos de datos, proporcionando una estimación más robusta de su rendimiento.

## Evaluación del Modelo

La evaluación del modelo es el proceso de evaluar el rendimiento de un modelo de aprendizaje automático en datos no vistos. Implica utilizar varias métricas para cuantificar qué tan bien generaliza el modelo a nuevos datos. Las métricas de evaluación comunes incluyen:

### Precisión

La precisión es la proporción de instancias correctamente predichas sobre el total de instancias. Se calcula como:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> La precisión es una métrica simple e intuitiva, pero puede no ser adecuada para conjuntos de datos desbalanceados donde una clase domina a las otras, ya que puede dar una impresión engañosa del rendimiento del modelo. Por ejemplo, si el 90% de los datos pertenece a la clase A y el modelo predice todas las instancias como clase A, alcanzará un 90% de precisión, pero no será útil para predecir la clase B.

### Precisión

La precisión es la proporción de predicciones verdaderas positivas de todas las predicciones positivas realizadas por el modelo. Se calcula como:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> La precisión es particularmente importante en escenarios donde los falsos positivos son costosos o indeseables, como en diagnósticos médicos o detección de fraudes. Por ejemplo, si un modelo predice 100 instancias como positivas, pero solo 80 de ellas son realmente positivas, la precisión sería 0.8 (80%).

### Recall (Sensibilidad)

El recall, también conocido como sensibilidad o tasa de verdaderos positivos, es la proporción de predicciones verdaderas positivas sobre todas las instancias positivas reales. Se calcula como:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> El recall es crucial en escenarios donde los falsos negativos son costosos o indeseables, como en la detección de enfermedades o el filtrado de spam. Por ejemplo, si un modelo identifica 80 de 100 instancias positivas reales, el recall sería 0.8 (80%).

### F1 Score

El F1 score es la media armónica de la precisión y el recall, proporcionando un equilibrio entre las dos métricas. Se calcula como:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> La puntuación F1 es particularmente útil cuando se trata de conjuntos de datos desbalanceados, ya que considera tanto los falsos positivos como los falsos negativos. Proporciona una métrica única que captura el equilibrio entre precisión y recuperación. Por ejemplo, si un modelo tiene una precisión de 0.8 y una recuperación de 0.6, la puntuación F1 sería aproximadamente 0.69.

### ROC-AUC (Característica de Operación del Receptor - Área Bajo la Curva)

La métrica ROC-AUC evalúa la capacidad del modelo para distinguir entre clases al trazar la tasa de verdaderos positivos (sensibilidad) contra la tasa de falsos positivos en varios ajustes de umbral. El área bajo la curva ROC (AUC) cuantifica el rendimiento del modelo, con un valor de 1 que indica una clasificación perfecta y un valor de 0.5 que indica una adivinanza aleatoria.

> [!TIP]
> ROC-AUC es particularmente útil para problemas de clasificación binaria y proporciona una visión integral del rendimiento del modelo a través de diferentes umbrales. Es menos sensible al desbalance de clases en comparación con la precisión. Por ejemplo, un modelo con un AUC de 0.9 indica que tiene una alta capacidad para distinguir entre instancias positivas y negativas.

### Especificidad

La especificidad, también conocida como tasa de verdaderos negativos, es la proporción de predicciones verdaderas negativas de todas las instancias negativas reales. Se calcula como:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> La especificidad es importante en escenarios donde los falsos positivos son costosos o indeseables, como en pruebas médicas o detección de fraudes. Ayuda a evaluar qué tan bien el modelo identifica instancias negativas. Por ejemplo, si un modelo identifica correctamente 90 de 100 instancias negativas reales, la especificidad sería 0.9 (90%).

### Matthews Correlation Coefficient (MCC)
El Coeficiente de Correlación de Matthews (MCC) es una medida de la calidad de las clasificaciones binarias. Tiene en cuenta los verdaderos y falsos positivos y negativos, proporcionando una visión equilibrada del rendimiento del modelo. El MCC se calcula como:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
donde:
- **TP**: Verdaderos Positivos
- **TN**: Verdaderos Negativos
- **FP**: Falsos Positivos
- **FN**: Falsos Negativos

> [!TIP]
> El MCC varía de -1 a 1, donde 1 indica una clasificación perfecta, 0 indica una suposición aleatoria y -1 indica un desacuerdo total entre la predicción y la observación. Es particularmente útil para conjuntos de datos desbalanceados, ya que considera los cuatro componentes de la matriz de confusión.

### Error Absoluto Medio (MAE)
El Error Absoluto Medio (MAE) es una métrica de regresión que mide la diferencia absoluta promedio entre los valores predichos y los valores reales. Se calcula como:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
donde:
- **n**: Número de instancias
- **y_i**: Valor real para la instancia i
- **ŷ_i**: Valor predicho para la instancia i

> [!TIP]
> MAE proporciona una interpretación sencilla del error promedio en las predicciones, lo que facilita su comprensión. Es menos sensible a los valores atípicos en comparación con otras métricas como el Error Cuadrático Medio (MSE). Por ejemplo, si un modelo tiene un MAE de 5, significa que, en promedio, las predicciones del modelo se desvían de los valores reales en 5 unidades.

### Matriz de Confusión

La matriz de confusión es una tabla que resume el rendimiento de un modelo de clasificación mostrando los conteos de verdaderos positivos, verdaderos negativos, falsos positivos y falsos negativos. Proporciona una vista detallada de qué tan bien se desempeña el modelo en cada clase.

|               | Predicho Positivo | Predicho Negativo |
|---------------|---------------------|---------------------|
| Real Positivo | Verdadero Positivo (TP)  | Falso Negativo (FN)  |
| Real Negativo | Falso Positivo (FP) | Verdadero Negativo (TN)   |

- **Verdadero Positivo (TP)**: El modelo predijo correctamente la clase positiva.
- **Verdadero Negativo (TN)**: El modelo predijo correctamente la clase negativa.
- **Falso Positivo (FP)**: El modelo predijo incorrectamente la clase positiva (error de Tipo I).
- **Falso Negativo (FN)**: El modelo predijo incorrectamente la clase negativa (error de Tipo II).

La matriz de confusión se puede utilizar para calcular varias métricas de evaluación, como precisión, exactitud, recuperación y puntuación F1.

{{#include ../banners/hacktricks-training.md}}
