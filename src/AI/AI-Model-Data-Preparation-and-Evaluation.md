# Preparación y evaluación de datos del modelo

{{#include ../banners/hacktricks-training.md}}

La preparación de los datos del modelo es un paso crucial en el pipeline de machine learning, ya que implica transformar datos sin procesar a un formato adecuado para entrenar modelos de machine learning. Este proceso incluye varios pasos clave:

1. **Recopilación de datos**: Recopilar datos de diversas fuentes, como bases de datos, APIs o archivos. Los datos pueden estar estructurados (p. ej., tablas) o no estructurados (p. ej., texto, imágenes).
2. **Limpieza de datos**: Eliminar o corregir puntos de datos erróneos, incompletos o irrelevantes. Este paso puede implicar gestionar valores ausentes, eliminar duplicados y filtrar outliers.
3. **Transformación de datos**: Convertir los datos a un formato adecuado para el modelado. Esto puede incluir normalización, escalado, codificación de variables categóricas y creación de nuevas características mediante técnicas como feature engineering.
4. **División de datos**: Dividir el dataset en conjuntos de entrenamiento, validación y prueba para garantizar que el modelo pueda generalizar correctamente a datos no vistos.

## Recopilación de datos

La recopilación de datos implica obtener datos de diversas fuentes, que pueden incluir:
- **Bases de datos**: Extraer datos de bases de datos relacionales (p. ej., bases de datos SQL) o bases de datos NoSQL (p. ej., MongoDB).
- **APIs**: Obtener datos de APIs web, que pueden proporcionar datos en tiempo real o históricos.
- **Archivos**: Leer datos de archivos en formatos como CSV, JSON o XML.
- **Web Scraping**: Recopilar datos de sitios web mediante técnicas de Web Scraping.

Según el objetivo del proyecto de machine learning, los datos se extraerán y recopilarán de fuentes relevantes para garantizar que sean representativos del dominio del problema.

## Limpieza de datos <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

La limpieza de datos es el proceso de identificar y corregir errores o inconsistencias en el dataset. Este paso es esencial para garantizar la calidad de los datos utilizados para entrenar modelos de machine learning. Las tareas clave de la limpieza de datos incluyen:
- **Gestión de valores ausentes**: Identificar y abordar los puntos de datos ausentes. Entre las estrategias habituales se incluyen:
- Eliminar filas o columnas con valores ausentes.
- Imputar valores ausentes mediante técnicas como la imputación de la media, la mediana o la moda.
- Utilizar métodos avanzados como la imputación mediante K-nearest neighbors (KNN) o la imputación por regresión.
- **Eliminación de duplicados**: Identificar y eliminar registros duplicados para garantizar que cada punto de datos sea único.
- **Filtrado de outliers**: Detectar y eliminar outliers que puedan distorsionar el rendimiento del modelo. Para identificar outliers pueden utilizarse técnicas como Z-score, IQR (Interquartile Range) o visualizaciones (p. ej., box plots).

### Ejemplo de limpieza de datos
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
## Transformación de datos <sup>[[1]](#references)</sup>

La transformación de datos implica convertir los datos a un formato adecuado para el modelado. Este paso puede incluir:
- **Normalización y estandarización**: Escalar las características numéricas a un rango común, normalmente [0, 1] o [-1, 1]. Esto puede mejorar la convergencia de los algoritmos de optimización.
- **Escalado Min-Max**: Reescalar las características a un rango fijo, normalmente [0, 1]. Esto se realiza mediante la fórmula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalización Z-Score**: Estandarizar las características restando la media y dividiendo por la desviación estándar, lo que da como resultado una distribución con una media de 0 y una desviación estándar de 1. Esto se realiza mediante la fórmula: `X' = (X - μ) / σ`, donde μ es la media y σ es la desviación estándar.
- **Asimetría y curtosis**: Ajustar las distribuciones de las características con transformaciones como el logaritmo, la raíz cuadrada o Box-Cox. Por ejemplo, una transformación logarítmica puede reducir la asimetría positiva.
- **Normalización de cadenas**: Convertir las cadenas a un formato coherente, como:
- Convertir a minúsculas
- Eliminar caracteres especiales (conservando los relevantes)
- Eliminar stop words (palabras comunes que no contribuyen al significado, como "the", "is" y "and")
- Eliminar palabras demasiado frecuentes y demasiado poco frecuentes (por ejemplo, palabras que aparecen en más del 90% de los documentos o menos de 5 veces en el corpus)
- Eliminar espacios en blanco
- Stemming/Lemmatization: Reducir las palabras a su forma base o raíz (por ejemplo, "running" a "run").

- **Codificación de variables categóricas**: Convertir las variables categóricas en representaciones numéricas. Entre las técnicas comunes se incluyen:
- **One-Hot Encoding**: Crear columnas binarias para cada categoría.
- Por ejemplo, si una característica tiene las categorías "red", "green" y "blue", se transformará en tres columnas binarias: `is_red`(100), `is_green`(010) y `is_blue`(001).
- **Label Encoding**: Asignar un entero único a cada categoría.
- Por ejemplo, "red" = 0, "green" = 1 y "blue" = 2.
- **Ordinal Encoding**: Asignar enteros según el orden de las categorías.
- Por ejemplo, si las categorías son "low", "medium" y "high", se pueden codificar como 0, 1 y 2, respectivamente.
- **Hashing Encoding**: Usar una función hash para convertir las categorías en vectores de tamaño fijo, lo que puede ser útil para variables categóricas de alta cardinalidad.
- Por ejemplo, si una característica tiene muchas categorías únicas, el hashing puede reducir la dimensionalidad y conservar parte de la información sobre las categorías.
- **Bag of Words (BoW)**: Representar los datos de texto como una matriz de recuentos o frecuencias de palabras, donde cada fila corresponde a un documento y cada columna corresponde a una palabra única del corpus.
- Por ejemplo, si el corpus contiene las palabras "cat", "dog" y "fish", un documento que contiene "cat" y "dog" se representaría como [1, 1, 0]. Esta representación específica se denomina "unigram" y no captura el orden de las palabras, por lo que pierde información semántica.
- **Bigram/Trigram**: Extender BoW para capturar secuencias de palabras (bigramas o trigramas) y conservar parte del contexto. Por ejemplo, "cat and dog" se representaría como un bigrama [1, 1] para "cat and" y [1, 1] para "and dog". En este caso se obtiene más información semántica (aumentando la dimensionalidad de la representación), pero solo para 2 o 3 palabras a la vez.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Medida estadística que evalúa la importancia de una palabra en un documento en relación con una colección de documentos (corpus). Combina la frecuencia del término (la frecuencia con la que aparece una palabra en un documento) y la frecuencia inversa del documento (la rareza de una palabra en todos los documentos).
- Por ejemplo, si la palabra "cat" aparece con frecuencia en un documento, pero es poco frecuente en todo el corpus, tendrá una puntuación TF-IDF alta, lo que indica su importancia en ese documento.

- **Ingeniería de características**: Crear nuevas características a partir de las existentes para mejorar la capacidad predictiva del modelo. Esto puede implicar combinar características, extraer componentes de fecha y hora o aplicar transformaciones específicas del dominio.

## División de datos <sup>[[3]](#references)</sup>

La división de datos implica separar el conjunto de datos en subconjuntos independientes para entrenamiento, validación y pruebas. Esto es esencial para evaluar el rendimiento del modelo con datos no vistos y evitar el sobreajuste. Entre las estrategias comunes se incluyen:
- **División Train-Test**: Dividir el conjunto de datos en un conjunto de entrenamiento (normalmente entre el 60% y el 80% de los datos), un conjunto de validación (entre el 10% y el 15% de los datos) para ajustar los hiperparámetros y un conjunto de pruebas (entre el 10% y el 15% de los datos). El modelo se entrena con el conjunto de entrenamiento y se evalúa con el conjunto de pruebas.
- Por ejemplo, si tienes un conjunto de datos de 1000 muestras, podrías usar 700 muestras para el entrenamiento, 150 para la validación y 150 para las pruebas.
- **Muestreo estratificado**: Garantizar que la distribución de las clases en los conjuntos de entrenamiento y pruebas sea similar a la del conjunto de datos general. Esto es especialmente importante para conjuntos de datos desequilibrados, en los que algunas clases pueden tener muchas menos muestras que otras.
- **División de series temporales**: Para datos de series temporales, el conjunto de datos se divide según el tiempo, garantizando que el conjunto de entrenamiento contenga datos de periodos anteriores y que el conjunto de pruebas contenga datos de periodos posteriores. Esto ayuda a evaluar el rendimiento del modelo con datos futuros.
- **Validación cruzada K-Fold**: Dividir el conjunto de datos en K subconjuntos (folds) y entrenar el modelo K veces, utilizando cada vez un fold diferente como conjunto de pruebas y los folds restantes como conjunto de entrenamiento. Esto ayuda a garantizar que el modelo se evalúe con diferentes subconjuntos de datos, proporcionando una estimación más sólida de su rendimiento.

## Evaluación del modelo <sup>[[4]](#references)</sup>

La evaluación del modelo es el proceso de valorar el rendimiento de un modelo de machine learning con datos no vistos. Implica usar diversas métricas para cuantificar en qué medida el modelo generaliza a nuevos datos. Entre las métricas de evaluación comunes se incluyen:

### Exactitud

La exactitud es la proporción de instancias predichas correctamente respecto al total de instancias. Se calcula de la siguiente manera:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> La exactitud es una métrica sencilla e intuitiva, pero puede no ser adecuada para datasets desequilibrados en los que una clase domina a las demás, ya que puede dar una impresión engañosa del rendimiento del modelo. Por ejemplo, si el 90 % de los datos pertenece a la clase A y el modelo predice todas las instancias como clase A, alcanzará una exactitud del 90 %, pero no será útil para predecir la clase B.

### Precisión

La precisión es la proporción de predicciones positivas verdaderas respecto a todas las predicciones positivas realizadas por el modelo. Se calcula de la siguiente manera:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> La precisión es especialmente importante en escenarios donde los falsos positivos son costosos o indeseables, como en los diagnósticos médicos o la detección de fraude. Por ejemplo, si un modelo predice 100 instancias como positivas, pero solo 80 de ellas son realmente positivas, la precisión sería de 0,8 (80%).

### Recall (Sensibilidad)

Recall, también conocido como sensibilidad o tasa de verdaderos positivos, es la proporción de predicciones positivas verdaderas respecto a todas las instancias positivas reales. Se calcula de la siguiente manera:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> El recall es crucial en escenarios donde los falsos negativos son costosos o indeseables, como en la detección de enfermedades o el filtrado de spam. Por ejemplo, si un modelo identifica 80 de 100 instancias positivas reales, el recall sería 0.8 (80%).

### F1 Score

El F1 score es la media armónica de la precisión y el recall, proporcionando un equilibrio entre ambas métricas. Se calcula así:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> La puntuación F1 es particularmente útil al trabajar con datasets desequilibrados, ya que considera tanto los falsos positivos como los falsos negativos. Proporciona una única métrica que captura el equilibrio entre precisión y recall. Por ejemplo, si un modelo tiene una precisión de 0.8 y un recall de 0.6, la puntuación F1 sería aproximadamente 0.69.

### ROC-AUC (Receiver Operating Characteristic - Area Under the Curve)

La métrica ROC-AUC evalúa la capacidad del modelo para distinguir entre clases mediante la representación de la tasa de verdaderos positivos (sensibilidad) frente a la tasa de falsos positivos en varios valores umbral. El área bajo la curva ROC (AUC) cuantifica el rendimiento del modelo: un valor de 1 indica una clasificación perfecta y un valor de 0.5 indica una predicción aleatoria.

> [!TIP]
> ROC-AUC es particularmente útil para problemas de clasificación binaria y proporciona una visión completa del rendimiento del modelo con diferentes umbrales. Es menos sensible al desequilibrio entre clases que la accuracy. Por ejemplo, un modelo con un AUC de 0.9 indica que tiene una gran capacidad para distinguir entre instancias positivas y negativas.

### Especificidad

La especificidad, también conocida como tasa de verdaderos negativos, es la proporción de predicciones verdaderamente negativas respecto a todas las instancias negativas reales. Se calcula de la siguiente manera:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> La especificidad es importante en escenarios en los que los falsos positivos son costosos o indeseables, como en las pruebas médicas o la detección de fraude. Ayuda a evaluar qué tan bien identifica el modelo las instancias negativas. Por ejemplo, si un modelo identifica correctamente 90 de 100 instancias negativas reales, la especificidad sería 0,9 (90%).

### Matthews Correlation Coefficient (MCC)
El Matthews Correlation Coefficient (MCC) es una medida de la calidad de las clasificaciones binarias. Tiene en cuenta los verdaderos y falsos positivos y negativos, proporcionando una visión equilibrada del rendimiento del modelo. El MCC se calcula de la siguiente manera:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
donde:
- **TP**: Verdaderos positivos
- **TN**: Verdaderos negativos
- **FP**: Falsos positivos
- **FN**: Falsos negativos

> [!TIP]
> El MCC varía de -1 a 1, donde 1 indica una clasificación perfecta, 0 indica predicciones aleatorias y -1 indica un desacuerdo total entre la predicción y la observación. Es especialmente útil para conjuntos de datos desequilibrados, ya que considera los cuatro componentes de la matriz de confusión.

### Error absoluto medio (MAE)
El error absoluto medio (MAE) es una métrica de regresión que mide la diferencia absoluta promedio entre los valores predichos y los reales. Se calcula de la siguiente manera:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
donde:
- **n**: Número de instancias
- **y_i**: Valor real de la instancia i
- **ŷ_i**: Valor predicho para la instancia i

> [!TIP]
> MAE proporciona una interpretación directa del error promedio en las predicciones, lo que facilita su comprensión. Es menos sensible a los valores atípicos en comparación con otras métricas, como el Error Cuadrático Medio (MSE). Por ejemplo, si un modelo tiene un MAE de 5, significa que, en promedio, las predicciones del modelo se desvían de los valores reales en 5 unidades.

### Matriz de confusión

La matriz de confusión es una tabla que resume el rendimiento de un modelo de clasificación mostrando el número de predicciones verdaderas positivas, verdaderas negativas, falsas positivas y falsas negativas. Proporciona una visión detallada de qué tan bien funciona el modelo en cada clase.

|               | Positivo predicho | Negativo predicho |
|---------------|---------------------|---------------------|
| Positivo real| Verdadero positivo (TP)  | Falso negativo (FN)  |
| Negativo real| Falso positivo (FP) | Verdadero negativo (TN)   |

- **Verdadero positivo (TP)**: El modelo predijo correctamente la clase positiva.
- **Verdadero negativo (TN)**: El modelo predijo correctamente la clase negativa.
- **Falso positivo (FP)**: El modelo predijo incorrectamente la clase positiva (error de tipo I).
- **Falso negativo (FN)**: El modelo predijo incorrectamente la clase negativa (error de tipo II).

La matriz de confusión se puede utilizar para calcular métricas de evaluación, como exactitud, precisión, exhaustividad y puntuación F1.

## References

- [1] [scikit-learn - Preprocesamiento de datos](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputación de valores faltantes](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Validación cruzada: evaluación del rendimiento del estimador](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Métricas y puntuación](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
