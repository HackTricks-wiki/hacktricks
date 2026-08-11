# Preparação e Avaliação de Dados do Modelo

{{#include ../banners/hacktricks-training.md}}

A preparação dos dados do modelo é uma etapa crucial no pipeline de machine learning, pois envolve transformar dados brutos em um formato adequado para o treinamento de modelos de machine learning. Esse processo inclui várias etapas importantes:

1. **Coleta de Dados**: Coletar dados de várias fontes, como bancos de dados, APIs ou arquivos. Os dados podem ser estruturados (por exemplo, tabelas) ou não estruturados (por exemplo, texto, imagens).
2. **Limpeza de Dados**: Remover ou corrigir pontos de dados errôneos, incompletos ou irrelevantes. Essa etapa pode envolver o tratamento de valores ausentes, a remoção de duplicatas e a filtragem de outliers.
3. **Transformação de Dados**: Converter os dados para um formato adequado à modelagem. Isso pode incluir normalização, escalonamento, codificação de variáveis categóricas e criação de novos recursos por meio de técnicas como feature engineering.
4. **Divisão dos Dados**: Dividir o dataset em conjuntos de treinamento, validação e teste para garantir que o modelo consiga generalizar bem para dados não vistos.

## Coleta de Dados

A coleta de dados envolve reunir dados de várias fontes, que podem incluir:
- **Bancos de Dados**: Extrair dados de bancos de dados relacionais (por exemplo, bancos de dados SQL) ou bancos de dados NoSQL (por exemplo, MongoDB).
- **APIs**: Obter dados de APIs web, que podem fornecer dados em tempo real ou históricos.
- **Arquivos**: Ler dados de arquivos em formatos como CSV, JSON ou XML.
- **Web Scraping**: Coletar dados de sites usando técnicas de web scraping.

Dependendo do objetivo do projeto de machine learning, os dados serão extraídos e coletados de fontes relevantes para garantir que sejam representativos do domínio do problema.

## Limpeza de Dados <sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

A limpeza de dados é o processo de identificar e corrigir erros ou inconsistências no dataset. Essa etapa é essencial para garantir a qualidade dos dados usados no treinamento de modelos de machine learning. As principais tarefas de limpeza de dados incluem:
- **Tratamento de Valores Ausentes**: Identificar e lidar com pontos de dados ausentes. As estratégias comuns incluem:
- Remover linhas ou colunas com valores ausentes.
- Imputar valores ausentes usando técnicas como imputação pela média, mediana ou moda.
- Usar métodos avançados, como imputação por K-nearest neighbors (KNN) ou imputação por regressão.
- **Remoção de Duplicatas**: Identificar e remover registros duplicados para garantir que cada ponto de dados seja único.
- **Filtragem de Outliers**: Detectar e remover outliers que possam distorcer o desempenho do modelo. Técnicas como Z-score, IQR (Intervalo Interquartil) ou visualizações (por exemplo, box plots) podem ser usadas para identificar outliers.

### Exemplo de limpeza de dados
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
## Transformação de Dados <sup>[[1]](#references)</sup>

A transformação de dados envolve converter os dados para um formato adequado à modelagem. Esta etapa pode incluir:
- **Normalização e padronização**: Redimensionar features numéricas para um intervalo comum, normalmente [0, 1] ou [-1, 1]. Isso pode melhorar a convergência dos algoritmos de otimização.
- **Min-Max Scaling**: Redimensionar features para um intervalo fixo, geralmente [0, 1]. Isso é feito usando a fórmula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalização por Z-Score**: Padronizar features subtraindo a média e dividindo pelo desvio padrão, resultando em uma distribuição com média 0 e desvio padrão 1. Isso é feito usando a fórmula: `X' = (X - μ) / σ`, em que μ é a média e σ é o desvio padrão.
- **Assimetria e curtose**: Ajustar distribuições de features com transformações como logaritmo, raiz quadrada ou Box-Cox. Por exemplo, uma transformação logarítmica pode reduzir a assimetria positiva.
- **Normalização de Strings**: Converter strings para um formato consistente, como:
- Converter para minúsculas
- Remover caracteres especiais (mantendo os relevantes)
- Remover stop words (palavras comuns que não contribuem para o significado, como "the", "is" e "and")
- Remover palavras muito frequentes e palavras muito raras (por exemplo, palavras que aparecem em mais de 90% dos documentos ou menos de 5 vezes no corpus)
- Remover espaços em branco excedentes
- Stemming/Lemmatization: Reduzir palavras à sua forma básica ou raiz (por exemplo, "running" para "run").

- **Codificação de Variáveis Categóricas**: Converter variáveis categóricas em representações numéricas. As técnicas comuns incluem:
- **One-Hot Encoding**: Criar colunas binárias para cada categoria.
- Por exemplo, se uma feature tiver as categorias "red", "green" e "blue", ela será transformada em três colunas binárias: `is_red`(100), `is_green`(010) e `is_blue`(001).
- **Label Encoding**: Atribuir um inteiro exclusivo a cada categoria.
- Por exemplo, "red" = 0, "green" = 1, "blue" = 2.
- **Ordinal Encoding**: Atribuir inteiros com base na ordem das categorias.
- Por exemplo, se as categorias forem "low", "medium" e "high", elas poderão ser codificadas como 0, 1 e 2, respectivamente.
- **Hashing Encoding**: Usar uma função hash para converter categorias em vetores de tamanho fixo, o que pode ser útil para variáveis categóricas de alta cardinalidade.
- Por exemplo, se uma feature tiver muitas categorias exclusivas, o hashing poderá reduzir a dimensionalidade preservando algumas informações sobre as categorias.
- **Bag of Words (BoW)**: Representar dados de texto como uma matriz de contagens ou frequências de palavras, em que cada linha corresponde a um documento e cada coluna corresponde a uma palavra exclusiva no corpus.
- Por exemplo, se o corpus contiver as palavras "cat", "dog" e "fish", um documento contendo "cat" e "dog" seria representado como [1, 1, 0]. Essa representação específica é chamada de "unigram" e não captura a ordem das palavras, portanto perde informações semânticas.
- **Bigram/Trigram**: Estender o BoW para capturar sequências de palavras (bigrams ou trigrams) e manter algum contexto. Por exemplo, "cat and dog" seria representado como um bigram [1, 1] para "cat and" e [1, 1] para "and dog". Nesse caso, mais informações semânticas são obtidas (aumentando a dimensionalidade da representação), mas apenas para 2 ou 3 palavras por vez.
- **TF-IDF (Term Frequency-Inverse Document Frequency)**: Uma medida estatística que avalia a importância de uma palavra em um documento em relação a uma coleção de documentos (corpus). Ela combina a frequência do termo (com que frequência uma palavra aparece em um documento) e a frequência inversa do documento (quão rara é uma palavra em todos os documentos).
- Por exemplo, se a palavra "cat" aparecer com frequência em um documento, mas for rara em todo o corpus, ela terá uma pontuação TF-IDF alta, indicando sua importância nesse documento.

- **Engenharia de Features**: Criar novas features a partir das existentes para aumentar o poder preditivo do modelo. Isso pode envolver combinar features, extrair componentes de data/hora ou aplicar transformações específicas do domínio.

## Divisão de Dados <sup>[[3]](#references)</sup>

A divisão de dados envolve separar o dataset em subconjuntos distintos para treinamento, validação e teste. Isso é essencial para avaliar o desempenho do modelo em dados não vistos e evitar overfitting. As estratégias comuns incluem:
- **Train-Test Split**: Dividir o dataset em um conjunto de treinamento (normalmente 60-80% dos dados), um conjunto de validação (10-15% dos dados) para ajustar hyperparameters e um conjunto de teste (10-15% dos dados). O modelo é treinado no conjunto de treinamento e avaliado no conjunto de teste.
- Por exemplo, se você tiver um dataset com 1000 amostras, poderá usar 700 amostras para treinamento, 150 para validação e 150 para teste.
- **Stratified Sampling**: Garantir que a distribuição das classes nos conjuntos de treinamento e teste seja semelhante à do dataset geral. Isso é particularmente importante para datasets desbalanceados, nos quais algumas classes podem ter significativamente menos amostras que outras.
- **Time Series Split**: Para dados de séries temporais, o dataset é dividido com base no tempo, garantindo que o conjunto de treinamento contenha dados de períodos anteriores e o conjunto de teste contenha dados de períodos posteriores. Isso ajuda a avaliar o desempenho do modelo em dados futuros.
- **K-Fold Cross-Validation**: Dividir o dataset em K subconjuntos (folds) e treinar o modelo K vezes, usando a cada vez um fold diferente como conjunto de teste e os folds restantes como conjunto de treinamento. Isso ajuda a garantir que o modelo seja avaliado em diferentes subconjuntos de dados, fornecendo uma estimativa mais robusta de seu desempenho.

## Avaliação do Modelo <sup>[[4]](#references)</sup>

A avaliação do modelo é o processo de verificar o desempenho de um modelo de machine learning em dados não vistos. Ela envolve o uso de várias métricas para quantificar o quanto o modelo generaliza para novos dados. As métricas comuns de avaliação incluem:

### Accuracy

Accuracy é a proporção de instâncias previstas corretamente em relação ao total de instâncias. Ela é calculada como:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> A acurácia é uma métrica simples e intuitiva, mas pode não ser adequada para datasets desbalanceados, nos quais uma classe domina as demais, pois pode causar uma impressão enganosa sobre o desempenho do modelo. Por exemplo, se 90% dos dados pertencerem à classe A e o modelo prever todas as instâncias como classe A, ele alcançará 90% de acurácia, mas não será útil para prever a classe B.

### Precisão

Precisão é a proporção de previsões verdadeiramente positivas entre todas as previsões positivas feitas pelo modelo. Ela é calculada da seguinte forma:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> A precisão é particularmente importante em cenários nos quais falsos positivos são dispendiosos ou indesejáveis, como em diagnósticos médicos ou detecção de fraudes. Por exemplo, se um modelo prevê 100 instâncias como positivas, mas apenas 80 delas são realmente positivas, a precisão seria 0,8 (80%).

### Recall (Sensibilidade)

Recall, também conhecido como sensibilidade ou taxa de verdadeiros positivos, é a proporção de previsões verdadeiramente positivas em relação a todas as instâncias positivas reais. Ele é calculado como:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> O recall é crucial em cenários nos quais falsos negativos são custosos ou indesejáveis, como na detecção de doenças ou na filtragem de spam. Por exemplo, se um modelo identificar 80 de 100 instâncias positivas reais, o recall será 0,8 (80%).

### Pontuação F1

A pontuação F1 é a média harmônica entre precision e recall, fornecendo um equilíbrio entre as duas métricas. Ela é calculada como:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> A pontuação F1 é particularmente útil ao lidar com conjuntos de dados desbalanceados, pois considera tanto os falsos positivos quanto os falsos negativos. Ela fornece uma única métrica que captura o equilíbrio entre precisão e recall. Por exemplo, se um modelo tiver uma precisão de 0.8 e um recall de 0.6, a pontuação F1 será aproximadamente 0.69.

### ROC-AUC (Característica de Operação do Receptor - Área Sob a Curva)

A métrica ROC-AUC avalia a capacidade do modelo de distinguir entre classes, plotando a taxa de verdadeiros positivos (sensibilidade) em relação à taxa de falsos positivos em várias configurações de limiar. A área sob a curva ROC (AUC) quantifica o desempenho do modelo, com um valor de 1 indicando uma classificação perfeita e um valor de 0.5 indicando uma estimativa aleatória.

> [!TIP]
> ROC-AUC é particularmente útil para problemas de classificação binária e fornece uma visão abrangente do desempenho do modelo em diferentes limiares. Ela é menos sensível ao desbalanceamento de classes em comparação com a acurácia. Por exemplo, um modelo com uma AUC de 0.9 indica que ele tem uma alta capacidade de distinguir entre instâncias positivas e negativas.

### Especificidade

A especificidade, também conhecida como taxa de verdadeiros negativos, é a proporção de previsões de verdadeiros negativos em relação a todas as instâncias negativas reais. Ela é calculada como:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> A especificidade é importante em cenários nos quais falsos positivos são dispendiosos ou indesejáveis, como em testes médicos ou detecção de fraudes. Ela ajuda a avaliar quão bem o modelo identifica instâncias negativas. Por exemplo, se um modelo identifica corretamente 90 de 100 instâncias negativas reais, a especificidade seria 0,9 (90%).

### Coeficiente de Correlação de Matthews (MCC)
O Coeficiente de Correlação de Matthews (MCC) é uma medida da qualidade de classificações binárias. Ele considera os verdadeiros e falsos positivos e negativos, fornecendo uma visão equilibrada do desempenho do modelo. O MCC é calculado como:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
onde:
- **TP**: Verdadeiros Positivos
- **TN**: Verdadeiros Negativos
- **FP**: Falsos Positivos
- **FN**: Falsos Negativos

> [!TIP]
> O MCC varia de -1 a 1, onde 1 indica classificação perfeita, 0 indica uma previsão aleatória e -1 indica discordância total entre a previsão e a observação. Ele é particularmente útil para conjuntos de dados desbalanceados, pois considera todos os quatro componentes da matriz de confusão.

### Erro Absoluto Médio (MAE)
O Erro Absoluto Médio (MAE) é uma métrica de regressão que mede a diferença absoluta média entre os valores previstos e os valores reais. Ele é calculado como:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
onde:
- **n**: Número de instâncias
- **y_i**: Valor real da instância i
- **ŷ_i**: Valor previsto para a instância i

> [!TIP]
> O MAE fornece uma interpretação direta do erro médio nas previsões, facilitando sua compreensão. Ele é menos sensível a outliers em comparação com outras métricas, como o Erro Quadrático Médio (MSE). Por exemplo, se um modelo tiver um MAE de 5, isso significa que, em média, as previsões do modelo desviam-se dos valores reais em 5 unidades.

### Matriz de Confusão

A matriz de confusão é uma tabela que resume o desempenho de um modelo de classificação, mostrando as contagens de previsões verdadeiras positivas, verdadeiras negativas, falsas positivas e falsas negativas. Ela fornece uma visão detalhada de como o modelo se comporta em cada classe.

|               | Predicted Positive | Predicted Negative |
|---------------|---------------------|---------------------|
| Actual Positive| True Positive (TP)  | False Negative (FN)  |
| Actual Negative| False Positive (FP) | True Negative (TN)   |

- **True Positive (TP)**: O modelo previu corretamente a classe positiva.
- **True Negative (TN)**: O modelo previu corretamente a classe negativa.
- **False Positive (FP)**: O modelo previu incorretamente a classe positiva (erro do Tipo I).
- **False Negative (FN)**: O modelo previu incorretamente a classe negativa (erro do Tipo II).

A matriz de confusão pode ser usada para calcular métricas de avaliação, como acurácia, precisão, recall e pontuação F1.

## References

- [1] [scikit-learn - Pré-processamento de dados](https://scikit-learn.org/stable/modules/preprocessing.html)
- [2] [scikit-learn - Imputação de valores ausentes](https://scikit-learn.org/stable/modules/impute.html)
- [3] [scikit-learn - Validação cruzada: avaliação do desempenho do estimador](https://scikit-learn.org/stable/modules/cross_validation.html)
- [4] [scikit-learn - Métricas e pontuação](https://scikit-learn.org/stable/modules/model_evaluation.html)
{{#include ../banners/hacktricks-training.md}}
