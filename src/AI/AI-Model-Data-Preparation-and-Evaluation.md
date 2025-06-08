# Preparação e Avaliação de Dados do Modelo

{{#include ../banners/hacktricks-training.md}}

A preparação de dados do modelo é uma etapa crucial no pipeline de aprendizado de máquina, pois envolve a transformação de dados brutos em um formato adequado para o treinamento de modelos de aprendizado de máquina. Este processo inclui várias etapas-chave:

1. **Coleta de Dados**: Coletar dados de várias fontes, como bancos de dados, APIs ou arquivos. Os dados podem ser estruturados (por exemplo, tabelas) ou não estruturados (por exemplo, texto, imagens).
2. **Limpeza de Dados**: Remover ou corrigir pontos de dados errôneos, incompletos ou irrelevantes. Esta etapa pode envolver o tratamento de valores ausentes, remoção de duplicatas e filtragem de outliers.
3. **Transformação de Dados**: Converter os dados em um formato adequado para modelagem. Isso pode incluir normalização, escalonamento, codificação de variáveis categóricas e criação de novos recursos por meio de técnicas como engenharia de recursos.
4. **Divisão de Dados**: Dividir o conjunto de dados em conjuntos de treinamento, validação e teste para garantir que o modelo possa generalizar bem para dados não vistos.

## Coleta de Dados

A coleta de dados envolve reunir dados de várias fontes, que podem incluir:
- **Bancos de Dados**: Extraindo dados de bancos de dados relacionais (por exemplo, bancos de dados SQL) ou bancos de dados NoSQL (por exemplo, MongoDB).
- **APIs**: Buscando dados de APIs da web, que podem fornecer dados em tempo real ou históricos.
- **Arquivos**: Lendo dados de arquivos em formatos como CSV, JSON ou XML.
- **Web Scraping**: Coletando dados de sites usando técnicas de web scraping.

Dependendo do objetivo do projeto de aprendizado de máquina, os dados serão extraídos e coletados de fontes relevantes para garantir que sejam representativos do domínio do problema.

## Limpeza de Dados

A limpeza de dados é o processo de identificar e corrigir erros ou inconsistências no conjunto de dados. Esta etapa é essencial para garantir a qualidade dos dados usados para treinar modelos de aprendizado de máquina. As principais tarefas na limpeza de dados incluem:
- **Tratamento de Valores Ausentes**: Identificar e abordar pontos de dados ausentes. As estratégias comuns incluem:
- Remover linhas ou colunas com valores ausentes.
- Imputar valores ausentes usando técnicas como imputação pela média, mediana ou moda.
- Usar métodos avançados como imputação por K-vizinhos mais próximos (KNN) ou imputação por regressão.
- **Remoção de Duplicatas**: Identificar e remover registros duplicados para garantir que cada ponto de dado seja único.
- **Filtragem de Outliers**: Detectar e remover outliers que podem distorcer o desempenho do modelo. Técnicas como Z-score, IQR (Intervalo Interquartil) ou visualizações (por exemplo, box plots) podem ser usadas para identificar outliers.

### Exemplo de limpeza de dados
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
## Transformação de Dados

A transformação de dados envolve converter os dados em um formato adequado para modelagem. Esta etapa pode incluir:
- **Normalização e Padronização**: Escalonamento de características numéricas para uma faixa comum, tipicamente [0, 1] ou [-1, 1]. Isso ajuda a melhorar a convergência dos algoritmos de otimização.
- **Escalonamento Min-Max**: Redimensionamento de características para uma faixa fixa, geralmente [0, 1]. Isso é feito usando a fórmula: `X' = (X - X_{min}) / (X_{max} - X_{min})`
- **Normalização Z-Score**: Padronização de características subtraindo a média e dividindo pelo desvio padrão, resultando em uma distribuição com média 0 e desvio padrão 1. Isso é feito usando a fórmula: `X' = (X - μ) / σ`, onde μ é a média e σ é o desvio padrão.
- **Assimetria e Curtose**: Ajustando a distribuição das características para reduzir a assimetria (assimetria) e a curtose (apinhamento). Isso pode ser feito usando transformações como logarítmica, raiz quadrada ou transformações de Box-Cox. Por exemplo, se uma característica tem uma distribuição assimétrica, aplicar uma transformação logarítmica pode ajudar a normalizá-la.
- **Normalização de Strings**: Convertendo strings para um formato consistente, como:
- Minúsculas
- Removendo caracteres especiais (mantendo os relevantes)
- Removendo palavras de parada (palavras comuns que não contribuem para o significado, como "o", "é", "e")
- Removendo palavras muito frequentes e palavras muito raras (por exemplo, palavras que aparecem em mais de 90% dos documentos ou menos de 5 vezes no corpus)
- Cortando espaços em branco
- Stemming/Lematização: Reduzindo palavras à sua forma base ou raiz (por exemplo, "correndo" para "correr").

- **Codificação de Variáveis Categóricas**: Convertendo variáveis categóricas em representações numéricas. As técnicas comuns incluem:
- **Codificação One-Hot**: Criando colunas binárias para cada categoria.
- Por exemplo, se uma característica tem categorias "vermelho", "verde" e "azul", ela será transformada em três colunas binárias: `is_red`(100), `is_green`(010) e `is_blue`(001).
- **Codificação de Rótulos**: Atribuindo um inteiro único a cada categoria.
- Por exemplo, "vermelho" = 0, "verde" = 1, "azul" = 2.
- **Codificação Ordinal**: Atribuindo inteiros com base na ordem das categorias.
- Por exemplo, se as categorias são "baixo", "médio" e "alto", elas podem ser codificadas como 0, 1 e 2, respectivamente.
- **Codificação por Hashing**: Usando uma função hash para converter categorias em vetores de tamanho fixo, o que pode ser útil para variáveis categóricas de alta cardinalidade.
- Por exemplo, se uma característica tem muitas categorias únicas, o hashing pode reduzir a dimensionalidade enquanto preserva algumas informações sobre as categorias.
- **Bag of Words (BoW)**: Representando dados de texto como uma matriz de contagens ou frequências de palavras, onde cada linha corresponde a um documento e cada coluna corresponde a uma palavra única no corpus.
- Por exemplo, se o corpus contém as palavras "gato", "cachorro" e "peixe", um documento contendo "gato" e "cachorro" seria representado como [1, 1, 0]. Esta representação específica é chamada de "unigram" e não captura a ordem das palavras, portanto, perde informações semânticas.
- **Bigram/Trigram**: Estendendo BoW para capturar sequências de palavras (bigrams ou trigrams) para reter algum contexto. Por exemplo, "gato e cachorro" seria representado como um bigram [1, 1] para "gato e" e [1, 1] para "e cachorro". Nesses casos, mais informações semânticas são coletadas (aumentando a dimensionalidade da representação), mas apenas para 2 ou 3 palavras de cada vez.
- **TF-IDF (Frequência de Termo-Frequência Inversa de Documento)**: Uma medida estatística que avalia a importância de uma palavra em um documento em relação a uma coleção de documentos (corpus). Combina a frequência do termo (com que frequência uma palavra aparece em um documento) e a frequência inversa do documento (quão rara uma palavra é em todos os documentos).
- Por exemplo, se a palavra "gato" aparece frequentemente em um documento, mas é rara em todo o corpus, ela terá uma alta pontuação TF-IDF, indicando sua importância naquele documento.

- **Engenharia de Recursos**: Criando novos recursos a partir dos existentes para aumentar o poder preditivo do modelo. Isso pode envolver a combinação de recursos, extração de componentes de data/hora ou aplicação de transformações específicas do domínio.

## Divisão de Dados

A divisão de dados envolve dividir o conjunto de dados em subconjuntos separados para treinamento, validação e teste. Isso é essencial para avaliar o desempenho do modelo em dados não vistos e prevenir overfitting. As estratégias comuns incluem:
- **Divisão Treinamento-Teste**: Dividindo o conjunto de dados em um conjunto de treinamento (tipicamente 60-80% dos dados), um conjunto de validação (10-15% dos dados) para ajustar hiperparâmetros, e um conjunto de teste (10-15% dos dados). O modelo é treinado no conjunto de treinamento e avaliado no conjunto de teste.
- Por exemplo, se você tem um conjunto de dados de 1000 amostras, pode usar 700 amostras para treinamento, 150 para validação e 150 para teste.
- **Amostragem Estratificada**: Garantindo que a distribuição de classes nos conjuntos de treinamento e teste seja semelhante ao conjunto de dados geral. Isso é particularmente importante para conjuntos de dados desbalanceados, onde algumas classes podem ter significativamente menos amostras do que outras.
- **Divisão de Séries Temporais**: Para dados de séries temporais, o conjunto de dados é dividido com base no tempo, garantindo que o conjunto de treinamento contenha dados de períodos anteriores e o conjunto de teste contenha dados de períodos posteriores. Isso ajuda a avaliar o desempenho do modelo em dados futuros.
- **Validação Cruzada K-Fold**: Dividindo o conjunto de dados em K subconjuntos (folds) e treinando o modelo K vezes, cada vez usando um fold diferente como conjunto de teste e os folds restantes como conjunto de treinamento. Isso ajuda a garantir que o modelo seja avaliado em diferentes subconjuntos de dados, fornecendo uma estimativa mais robusta de seu desempenho.

## Avaliação do Modelo

A avaliação do modelo é o processo de avaliar o desempenho de um modelo de aprendizado de máquina em dados não vistos. Envolve o uso de várias métricas para quantificar quão bem o modelo generaliza para novos dados. As métricas de avaliação comuns incluem:

### Acurácia

A acurácia é a proporção de instâncias corretamente previstas em relação ao total de instâncias. É calculada como:
```plaintext
Accuracy = (Number of Correct Predictions) / (Total Number of Predictions)
```
> [!TIP]
> A acurácia é uma métrica simples e intuitiva, mas pode não ser adequada para conjuntos de dados desbalanceados onde uma classe domina as outras, pois pode dar uma impressão enganosa do desempenho do modelo. Por exemplo, se 90% dos dados pertencem à classe A e o modelo prevê todas as instâncias como classe A, ele alcançará 90% de acurácia, mas não será útil para prever a classe B.

### Precisão

A precisão é a proporção de previsões verdadeiramente positivas em relação a todas as previsões positivas feitas pelo modelo. É calculada como:
```plaintext
Precision = (True Positives) / (True Positives + False Positives)
```
> [!TIP]
> A precisão é particularmente importante em cenários onde falsos positivos são custosos ou indesejáveis, como em diagnósticos médicos ou detecção de fraudes. Por exemplo, se um modelo prevê 100 instâncias como positivas, mas apenas 80 delas são realmente positivas, a precisão seria 0,8 (80%).

### Recall (Sensibilidade)

Recall, também conhecido como sensibilidade ou taxa de verdadeiros positivos, é a proporção de previsões verdadeiras positivas em relação a todas as instâncias positivas reais. É calculado como:
```plaintext
Recall = (True Positives) / (True Positives + False Negatives)
```
> [!TIP]
> A recuperação é crucial em cenários onde falsos negativos são custosos ou indesejáveis, como na detecção de doenças ou filtragem de spam. Por exemplo, se um modelo identifica 80 de 100 instâncias positivas reais, a recuperação seria 0,8 (80%).

### F1 Score

O F1 score é a média harmônica de precisão e recuperação, fornecendo um equilíbrio entre as duas métricas. É calculado como:
```plaintext
F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
```
> [!TIP]
> A pontuação F1 é particularmente útil ao lidar com conjuntos de dados desbalanceados, pois considera tanto os falsos positivos quanto os falsos negativos. Ela fornece uma métrica única que captura a troca entre precisão e revocação. Por exemplo, se um modelo tem uma precisão de 0,8 e uma revocação de 0,6, a pontuação F1 seria aproximadamente 0,69.

### ROC-AUC (Receiver Operating Characteristic - Área Sob a Curva)

A métrica ROC-AUC avalia a capacidade do modelo de distinguir entre classes, plotando a taxa de verdadeiros positivos (sensibilidade) contra a taxa de falsos positivos em várias configurações de limiar. A área sob a curva ROC (AUC) quantifica o desempenho do modelo, com um valor de 1 indicando classificação perfeita e um valor de 0,5 indicando adivinhação aleatória.

> [!TIP]
> ROC-AUC é particularmente útil para problemas de classificação binária e fornece uma visão abrangente do desempenho do modelo em diferentes limiares. É menos sensível ao desbalanceamento de classes em comparação com a precisão. Por exemplo, um modelo com um AUC de 0,9 indica que ele tem uma alta capacidade de distinguir entre instâncias positivas e negativas.

### Especificidade

A especificidade, também conhecida como taxa de verdadeiros negativos, é a proporção de previsões verdadeiras negativas em relação a todas as instâncias negativas reais. Ela é calculada como:
```plaintext
Specificity = (True Negatives) / (True Negatives + False Positives)
```
> [!TIP]
> A especificidade é importante em cenários onde falsos positivos são custosos ou indesejáveis, como em testes médicos ou detecção de fraudes. Ela ajuda a avaliar quão bem o modelo identifica instâncias negativas. Por exemplo, se um modelo identifica corretamente 90 de 100 instâncias negativas reais, a especificidade seria 0,9 (90%).

### Coeficiente de Correlação de Matthews (MCC)
O Coeficiente de Correlação de Matthews (MCC) é uma medida da qualidade das classificações binárias. Ele leva em conta verdadeiros e falsos positivos e negativos, fornecendo uma visão equilibrada do desempenho do modelo. O MCC é calculado como:
```plaintext
MCC = (TP * TN - FP * FN) / sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN))
```
onde:
- **TP**: Verdadeiros Positivos
- **TN**: Verdadeiros Negativos
- **FP**: Falsos Positivos
- **FN**: Falsos Negativos

> [!TIP]
> O MCC varia de -1 a 1, onde 1 indica classificação perfeita, 0 indica adivinhação aleatória e -1 indica total desacordo entre previsão e observação. É particularmente útil para conjuntos de dados desbalanceados, pois considera todos os quatro componentes da matriz de confusão.

### Erro Absoluto Médio (MAE)
Erro Absoluto Médio (MAE) é uma métrica de regressão que mede a diferença absoluta média entre os valores previstos e os valores reais. É calculado como:
```plaintext
MAE = (1/n) * Σ|y_i - ŷ_i|
```
onde:
- **n**: Número de instâncias
- **y_i**: Valor real para a instância i
- **ŷ_i**: Valor previsto para a instância i

> [!TIP]
> MAE fornece uma interpretação direta do erro médio nas previsões, tornando fácil de entender. É menos sensível a outliers em comparação com outras métricas, como o Erro Quadrático Médio (MSE). Por exemplo, se um modelo tem um MAE de 5, isso significa que, em média, as previsões do modelo se desviam dos valores reais em 5 unidades.

### Matriz de Confusão

A matriz de confusão é uma tabela que resume o desempenho de um modelo de classificação, mostrando as contagens de previsões verdadeiras positivas, verdadeiras negativas, falsas positivas e falsas negativas. Ela fornece uma visão detalhada de quão bem o modelo se desempenha em cada classe.

|               | Previsto Positivo   | Previsto Negativo   |
|---------------|---------------------|---------------------|
| Real Positivo | Verdadeira Positiva (TP)  | Falsa Negativa (FN)  |
| Real Negativo | Falsa Positiva (FP) | Verdadeira Negativa (TN)   |

- **Verdadeira Positiva (TP)**: O modelo previu corretamente a classe positiva.
- **Verdadeira Negativa (TN)**: O modelo previu corretamente a classe negativa.
- **Falsa Positiva (FP)**: O modelo previu incorretamente a classe positiva (Erro Tipo I).
- **Falsa Negativa (FN)**: O modelo previu incorretamente a classe negativa (Erro Tipo II).

A matriz de confusão pode ser usada para calcular várias métricas de avaliação, como precisão, recall e F1 score.

{{#include ../banners/hacktricks-training.md}}
