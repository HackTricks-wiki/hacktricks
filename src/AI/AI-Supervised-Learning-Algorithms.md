# Supervised Learning Algorithms

{{#include ../banners/hacktricks-training.md}}

## Informações básicas

O aprendizado supervisionado usa dados rotulados para treinar modelos capazes de fazer previsões sobre entradas novas e não vistas. Na cybersecurity, o machine learning supervisionado é amplamente aplicado a tarefas como detecção de intrusões (classificar o tráfego de rede como *normal* ou *attack*), detecção de malware (distinguir software malicioso de software benigno), detecção de phishing (identificar sites ou emails fraudulentos) e filtragem de spam, entre outras. Cada algoritmo tem seus pontos fortes e é adequado para diferentes tipos de problemas (classificação ou regressão). A seguir, revisamos os principais algoritmos de aprendizado supervisionado, explicamos como funcionam e demonstramos seu uso em datasets reais de cybersecurity. Também discutimos como combinar modelos (ensemble learning) pode frequentemente melhorar o desempenho preditivo.

## Algoritmos

-   **Linear Regression:** Um algoritmo fundamental de regressão para prever resultados numéricos ajustando uma equação linear aos dados.

-   **Logistic Regression:** Um algoritmo de classificação (apesar do nome) que usa uma função logística para modelar a probabilidade de um resultado binário.

-   **Decision Trees:** Modelos estruturados em árvore que dividem os dados por características para fazer previsões; frequentemente usados por sua interpretabilidade.

-   **Random Forests:** Um ensemble de árvores de decisão (por meio de bagging) que melhora a precisão e reduz o overfitting.

-   **Support Vector Machines (SVM):** Classificadores de margem máxima que encontram o hiperplano de separação ideal; podem usar kernels para dados não lineares.

-   **Naive Bayes:** Um classificador probabilístico baseado no teorema de Bayes, com uma suposição de independência entre as características, usado principalmente na filtragem de spam.

-   **k-Nearest Neighbors (k-NN):** Um classificador simples "baseado em instâncias" que rotula uma amostra com base na classe majoritária de seus vizinhos mais próximos.

-   **Gradient Boosting Machines:** Modelos ensemble (por exemplo, XGBoost, LightGBM) que constroem um preditor forte adicionando sequencialmente learners mais fracos (normalmente árvores de decisão).

Cada seção abaixo fornece uma descrição aprimorada do algoritmo e um **exemplo de código Python** usando bibliotecas como `pandas` e `scikit-learn` (e `PyTorch` no exemplo de rede neural). Os exemplos usam datasets de cybersecurity disponíveis publicamente (como NSL-KDD para detecção de intrusões e um dataset de Phishing Websites) e seguem uma estrutura consistente:

1.  **Carregar o dataset** (baixar via URL, se disponível).

2.  **Pré-processar os dados** (por exemplo, codificar características categóricas, dimensionar valores e dividir os conjuntos de treino/teste).

3.  **Treinar o modelo** usando os dados de treinamento.

4.  **Avaliar** em um conjunto de teste usando métricas: accuracy, precision, recall, F1-score e ROC AUC para classificação (e mean squared error para regressão).

Vamos analisar cada algoritmo:

### Linear Regression

A regressão linear é um algoritmo de **regressão** usado para prever valores numéricos contínuos. Ele assume uma relação linear entre as características de entrada (variáveis independentes) e a saída (variável dependente). O modelo tenta ajustar uma linha reta (ou um hiperplano em dimensões superiores) que descreva melhor a relação entre as características e o target. Isso normalmente é feito minimizando a soma dos erros quadráticos entre os valores previstos e os reais (método Ordinary Least Squares).<sup>[[8]](#references)</sup>

A forma mais simples de representar a regressão linear é com uma linha:
```plaintext
y = mx + b
```
Onde:

- `y` é o valor previsto (saída)
- `m` é a inclinação da linha (coeficiente)
- `x` é a característica de entrada
- `b` é o intercepto em y

O objetivo da regressão linear é encontrar a linha que melhor se ajusta e minimiza a diferença entre os valores previstos e os valores reais no conjunto de dados. Naturalmente, isso é muito simples: seria uma linha reta separando 2 categorias. Porém, se mais dimensões forem adicionadas, a linha se torna mais complexa:
```plaintext
y = w1*x1 + w2*x2 + ... + wn*xn + b
```
> [!TIP]
> *Casos de uso em cybersecurity:* A própria regressão linear é menos comum em tarefas centrais de segurança (que geralmente são de classificação), mas pode ser aplicada para prever resultados numéricos. Por exemplo, a regressão linear pode ser usada para **prever o volume de tráfego de rede** ou **estimar o número de ataques em um período** com base em dados históricos. Ela também pode prever uma pontuação de risco ou o tempo esperado até a detecção de um ataque, considerando determinadas métricas do sistema. Na prática, algoritmos de classificação (como regressão logística ou árvores) são usados com mais frequência para detectar intrusões ou malware, mas a regressão linear serve como base e é útil para análises orientadas à regressão.

#### **Principais características da regressão linear:**

-   **Tipo de problema:** Regressão (previsão de valores contínuos). Não é adequada para classificação direta, a menos que um limite seja aplicado à saída.

-   **Interpretabilidade:** Alta -- os coeficientes são fáceis de interpretar, mostrando o efeito linear de cada feature.

-   **Vantagens:** Simples e rápida; uma boa referência para tarefas de regressão; funciona bem quando a relação verdadeira é aproximadamente linear.

-   **Limitações:** Não consegue capturar relações complexas ou não lineares (sem engenharia manual de features); tende a sofrer underfitting quando as relações não são lineares; é sensível a outliers, que podem distorcer os resultados.

-   **Encontrando o melhor ajuste:** Para encontrar a linha de melhor ajuste que separa as possíveis categorias, usamos um método chamado **Ordinary Least Squares (OLS)**. Esse método minimiza a soma das diferenças ao quadrado entre os valores observados e os valores previstos pelo modelo linear.

<details>
<summary>Exemplo -- Prevendo a Duração das Conexões (Regressão) em um Dataset de Intrusão
</summary>
A seguir, demonstramos a regressão linear usando o dataset de cybersecurity NSL-KDD. Trataremos isso como um problema de regressão, prevendo a `duration` das conexões de rede com base em outras features. (Na realidade, `duration` é uma das features do NSL-KDD; nós a usamos aqui apenas para ilustrar a regressão.) Carregamos o dataset, fazemos o pré-processamento (codificando as features categóricas), treinamos um modelo de regressão linear e avaliamos o Mean Squared Error (MSE) e o score R² em um conjunto de teste.
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
Neste exemplo, o modelo de regressão linear tenta prever a `duration` da conexão a partir de outros recursos de rede. Medimos o desempenho com o Erro Quadrático Médio (MSE) e R². Um R² próximo de 1.0 indicaria que o modelo explica a maior parte da variância em `duration`, enquanto um R² baixo ou negativo indica um ajuste ruim. (Não se surpreenda se o R² for baixo aqui -- prever `duration` pode ser difícil a partir dos recursos fornecidos, e a regressão linear pode não capturar os padrões se eles forem complexos.)
</details>

### Regressão Logística

A regressão logística é um algoritmo de **classificação** que modela a probabilidade de uma instância pertencer a uma determinada classe (normalmente a classe "positiva"). Apesar do nome, a regressão *logística* é usada para resultados discretos (ao contrário da regressão linear, que é usada para resultados contínuos). Ela é especialmente usada para **classificação binária** (duas classes, por exemplo, maliciosa vs. benigna), mas pode ser estendida para problemas multiclasse (usando abordagens softmax ou one-vs-rest).<sup>[[1]](#references)</sup>

A regressão logística usa a função logística (também conhecida como função sigmoide) para mapear valores previstos para probabilidades. Observe que a função sigmoide é uma função com valores entre 0 e 1 que cresce em uma curva em forma de S, de acordo com as necessidades da classificação, o que é útil para tarefas de classificação binária. Portanto, cada recurso de cada entrada é multiplicado pelo peso atribuído a ele, e o resultado é passado pela função sigmoide para produzir uma probabilidade:
```plaintext
p(y=1|x) = 1 / (1 + e^(-z))
```
Onde:

- `p(y=1|x)` é a probabilidade de que a saída `y` seja 1 dado o valor de entrada `x`
- `e` é a base do logaritmo natural
- `z` é uma combinação linear das características de entrada, normalmente representada como `z = w1*x1 + w2*x2 + ... + wn*xn + b`. Observe que, novamente, em sua forma mais simples, ela é uma linha reta, mas em casos mais complexos torna-se um hiperplano com várias dimensões (uma por característica).

> [!TIP]
> *Casos de uso em cibersegurança:* Como muitos problemas de segurança são essencialmente decisões de sim/não, Logistic Regression é amplamente usada. Por exemplo, um sistema de detecção de intrusões pode usar Logistic Regression para decidir se uma conexão de rede é um ataque com base nas características dessa conexão. Na detecção de phishing, Logistic Regression pode combinar características de um site (comprimento da URL, presença do símbolo "@", etc.) em uma probabilidade de ser phishing. Ela foi usada em filtros de spam de primeira geração e continua sendo uma forte referência para muitas tarefas de classificação.

#### Logistic Regression para classificação não binária

Logistic Regression foi projetada para classificação binária, mas pode ser estendida para lidar com problemas multiclasses usando técnicas como **one-vs-rest** (OvR) ou **softmax regression**. No OvR, um modelo separado de Logistic Regression é treinado para cada classe, tratando-a como a classe positiva contra todas as outras. A classe com a maior probabilidade prevista é escolhida como a previsão final. Softmax regression generaliza Logistic Regression para múltiplas classes aplicando a função softmax à camada de saída, produzindo uma distribuição de probabilidade sobre todas as classes.

#### **Principais características de Logistic Regression:**

-   **Tipo de problema:** Classificação (geralmente binária). Prevê a probabilidade da classe positiva.

-   **Interpretabilidade:** Alta -- assim como na regressão linear, os coeficientes das características podem indicar como cada característica influencia o logaritmo das chances do resultado. Essa transparência costuma ser valorizada em segurança para entender quais fatores contribuem para um alerta.

-   **Vantagens:** Simples e rápida de treinar; funciona bem quando a relação entre as características e o logaritmo das chances do resultado é linear. Produz probabilidades, permitindo a pontuação de risco. Com uma regularização adequada, generaliza bem e consegue lidar melhor com multicolinearidade do que a regressão linear comum.

-   **Limitações:** Assume uma fronteira de decisão linear no espaço das características (falha se a verdadeira fronteira for complexa/não linear). Pode ter desempenho inferior em problemas nos quais interações ou efeitos não lineares são críticos, a menos que você adicione manualmente características polinomiais ou de interação. Além disso, Logistic Regression é menos eficaz quando as classes não são facilmente separáveis por uma combinação linear de características.


<details>
<summary>Exemplo -- Detecção de sites de phishing com Logistic Regression:</summary>

Usaremos um **Phishing Websites Dataset** (do repositório da UCI), que contém características extraídas de sites (como se a URL possui um endereço IP, a idade do domínio, a presença de elementos suspeitos no HTML etc.) e um rótulo indicando se o site é phishing ou legítimo. Treinamos um modelo de Logistic Regression para classificar sites e, em seguida, avaliamos sua accuracy, precision, recall, F1-score e ROC AUC em uma divisão de teste.
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
Neste exemplo de detecção de phishing, a regressão logística produz uma probabilidade de cada website ser phishing. Ao avaliar accuracy, precision, recall e F1, obtemos uma noção do desempenho do modelo. Por exemplo, um recall alto significaria que ele detecta a maioria dos sites de phishing (importante para a segurança, a fim de minimizar ataques não detectados), enquanto uma precision alta significa que há poucos falsos alarmes (importante para evitar a fadiga dos analistas). A ROC AUC (Área Sob a Curva ROC) fornece uma medida de desempenho independente do threshold (1.0 é o ideal; 0.5 não é melhor que o acaso). A regressão logística geralmente apresenta bom desempenho nessas tarefas, mas, se a fronteira de decisão entre sites de phishing e legítimos for complexa, talvez sejam necessários modelos não lineares mais poderosos.

</details>

### Árvores de Decisão

Uma árvore de decisão é um **algoritmo de aprendizado supervisionado** versátil, que pode ser usado tanto para tarefas de classificação quanto de regressão. Ela aprende um modelo hierárquico, semelhante a uma árvore, de decisões baseadas nas features dos dados. Cada nó interno da árvore representa um teste em uma determinada feature, cada ramo representa um resultado desse teste e cada nó folha representa uma classe prevista (para classificação) ou um valor (para regressão).<sup>[[2]](#references)</sup>

Para construir uma árvore, algoritmos como CART (Classification and Regression Tree) usam medidas como **impureza de Gini** ou **ganho de informação (entropia)** para escolher a melhor feature e o threshold para dividir os dados em cada etapa. O objetivo de cada divisão é particionar os dados para aumentar a homogeneidade da variável-alvo nos subconjuntos resultantes (na classificação, cada nó busca ser o mais puro possível, contendo predominantemente uma única classe).

As árvores de decisão são **altamente interpretáveis** -- é possível seguir o caminho da raiz até a folha para entender a lógica por trás de uma previsão (por exemplo, *"IF `service = telnet` AND `src_bytes > 1000` AND `failed_logins > 3` THEN classify as attack"*). Isso é valioso em cybersecurity para explicar por que determinado alerta foi gerado. As árvores conseguem lidar naturalmente tanto com dados numéricos quanto categóricos e exigem pouco pré-processamento (por exemplo, não é necessário fazer feature scaling).

No entanto, uma única árvore de decisão pode facilmente sofrer overfitting nos dados de treinamento, especialmente se crescer muito (com muitas divisões). Técnicas como pruning (limitar a profundidade da árvore ou exigir um número mínimo de amostras por folha) são frequentemente usadas para evitar overfitting.

Há 3 componentes principais em uma árvore de decisão:
- **Nó Raiz**: o nó superior da árvore, que representa todo o dataset.
- **Nós Internos**: nós que representam features e decisões baseadas nessas features.
- **Nós Folha**: nós que representam o resultado ou a previsão final.

Uma árvore pode acabar apresentando esta aparência:
```plaintext
[Root Node]
/   \
[Node A]  [Node B]
/   \      /   \
[Leaf 1] [Leaf 2] [Leaf 3] [Leaf 4]
```
> [!TIP]
> *Casos de uso em cybersecurity:* As árvores de decisão têm sido usadas em sistemas de detecção de intrusão para derivar **regras** de identificação de ataques. Por exemplo, os primeiros IDS baseados em ID3/C4.5 geravam regras legíveis por humanos para distinguir tráfego normal de tráfego malicioso. Elas também são usadas na análise de malware para decidir se um arquivo é malicioso com base em seus atributos (tamanho do arquivo, entropia das seções, chamadas de API etc.). A clareza das árvores de decisão as torna úteis quando a transparência é necessária -- um analista pode inspecionar a árvore para validar a lógica de detecção.

#### **Principais características das Árvores de Decisão:**

-   **Tipo de problema:** Classificação e regressão. Comumente usadas para classificar ataques e tráfego normal etc.

-   **Interpretabilidade:** Muito alta -- as decisões do modelo podem ser visualizadas e compreendidas como um conjunto de regras if-then. Essa é uma grande vantagem em segurança para a confiança e a verificação do comportamento do modelo.

-   **Vantagens:** Podem capturar relações não lineares e interações entre atributos (cada divisão pode ser vista como uma interação). Não é necessário dimensionar os atributos nem aplicar one-hot encoding a variáveis categóricas -- as árvores lidam com isso nativamente. Inferência rápida (a previsão consiste apenas em seguir um caminho na árvore).

-   **Limitações:** Tendem a sofrer overfitting se não forem controladas (uma árvore profunda pode memorizar o conjunto de treinamento). Podem ser instáveis -- pequenas alterações nos dados podem resultar em uma estrutura de árvore diferente. Como modelos individuais, sua precisão pode não corresponder à de métodos mais avançados (ensembles como Random Forests normalmente apresentam melhor desempenho ao reduzir a variância).

-   **Encontrando a melhor divisão:**
- **Gini Impurity**: Mede a impureza de um nó. Uma Gini impurity menor indica uma divisão melhor. A fórmula é:

```plaintext
Gini = 1 - Σ(p_i^2)
```

Onde `p_i` é a proporção de instâncias na classe `i`.

- **Entropy**: Mede a incerteza no dataset. Uma entropy menor indica uma divisão melhor. A fórmula é:

```plaintext
Entropy = -Σ(p_i * log2(p_i))
```

Onde `p_i` é a proporção de instâncias na classe `i`.

- **Information Gain**: A redução na entropy ou na Gini impurity após uma divisão. Quanto maior o information gain, melhor a divisão. Ele é calculado da seguinte forma:

```plaintext
Information Gain = Entropy(parent) - (Weighted Average of Entropy(children))
```

Além disso, uma árvore é encerrada quando:
- Todas as instâncias em um nó pertencem à mesma classe. Isso pode levar a overfitting.
- A profundidade máxima (hardcoded) da árvore é atingida. Essa é uma forma de evitar overfitting.
- O número de instâncias em um nó fica abaixo de um determinado limite. Essa também é uma forma de evitar overfitting.
- O information gain de divisões adicionais fica abaixo de um determinado limite. Essa também é uma forma de evitar overfitting.

<details>
<summary>Exemplo -- Árvore de Decisão para Detecção de Intrusão:</summary>
Treinaremos uma árvore de decisão no dataset NSL-KDD para classificar conexões de rede como *normal* ou *attack*. NSL-KDD é uma versão aprimorada do dataset clássico KDD Cup 1999, com atributos como tipo de protocolo, serviço, duração, número de logins com falha etc., e um rótulo que indica o tipo de ataque ou "normal". Mapearemos todos os tipos de ataque para uma classe "anomaly" (classificação binária: normal vs anomaly). Após o treinamento, avaliaremos o desempenho da árvore no conjunto de teste.
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
Neste exemplo de árvore de decisão, limitamos a profundidade da árvore a 10 para evitar overfitting extremo (o parâmetro `max_depth=10`). As métricas mostram quão bem a árvore distingue o tráfego normal do tráfego de ataque. Um recall alto significaria que ela detecta a maioria dos ataques (algo importante para um IDS), enquanto uma precision alta significa poucos falsos alarmes. Árvores de decisão geralmente alcançam uma accuracy razoável em dados estruturados, mas uma única árvore pode não atingir o melhor desempenho possível. Ainda assim, a *interpretabilidade* do modelo é uma grande vantagem -- poderíamos examinar as divisões da árvore para verificar, por exemplo, quais features (como `service`, `src_bytes`, etc.) são mais influentes para sinalizar uma conexão como maliciosa.

</details>

### Random Forests

Random Forest é um método de **ensemble learning** que se baseia em árvores de decisão para melhorar o desempenho. Um random forest treina várias árvores de decisão (daí o termo "forest") e combina suas saídas para fazer uma previsão final (para classificação, normalmente por votação majoritária). As duas ideias principais em um random forest são **bagging** (bootstrap aggregating) e **feature randomness**:

-   **Bagging:** Cada árvore é treinada em uma amostra bootstrap aleatória dos dados de treinamento (amostrada com reposição). Isso introduz diversidade entre as árvores.

-   **Feature Randomness:** Em cada divisão de uma árvore, um subconjunto aleatório de features é considerado para a divisão (em vez de todas as features). Isso reduz ainda mais a correlação entre as árvores.

Ao calcular a média dos resultados de muitas árvores, o random forest reduz a variância que uma única árvore de decisão poderia apresentar. Em termos simples, árvores individuais podem sofrer overfitting ou ser ruidosas, mas um grande número de árvores diversificadas votando em conjunto suaviza esses erros. O resultado geralmente é um modelo com **accuracy mais alta** e melhor generalização do que uma única árvore de decisão. Além disso, random forests podem fornecer uma estimativa da importância das features (observando quanto cada divisão de feature reduz a impureza, em média).

Random forests tornaram-se uma **ferramenta fundamental em cybersecurity** para tarefas como intrusion detection, classificação de malware e detecção de spam. Elas geralmente apresentam bom desempenho imediatamente, com pouco tuning, e conseguem lidar com grandes conjuntos de features. Por exemplo, em intrusion detection, um random forest pode superar uma árvore de decisão individual ao detectar padrões mais sutis de ataques com menos falsos positivos. Pesquisas demonstraram que random forests apresentam resultados favoráveis em comparação com outros algoritmos na classificação de ataques em datasets como NSL-KDD e UNSW-NB15.<sup>[[3]](#references)[[9]](#references)</sup>

#### **Principais características de Random Forests:**

-   **Tipo de problema:** Principalmente classificação (também usado para regressão). Muito adequado para dados estruturados de alta dimensionalidade, comuns em security logs.

-   **Interpretabilidade:** Inferior à de uma única árvore de decisão -- não é fácil visualizar ou explicar centenas de árvores de uma só vez. No entanto, as pontuações de importância das features fornecem alguma indicação sobre quais atributos são mais influentes.

-   **Vantagens:** Geralmente apresenta accuracy mais alta do que modelos de árvore única devido ao efeito de ensemble. É robusto contra overfitting -- mesmo que árvores individuais sofram overfitting, o ensemble generaliza melhor. Lida com features numéricas e categóricas e consegue gerenciar dados ausentes até certo ponto. Também é relativamente robusto contra outliers.

-   **Limitações:** O tamanho do modelo pode ser grande (muitas árvores, cada uma potencialmente profunda). As previsões são mais lentas do que as de uma única árvore (é necessário agregar os resultados de muitas árvores). É menos interpretável -- embora você saiba quais features são importantes, a lógica exata não é facilmente rastreável como uma regra simples. Se o dataset for extremamente esparso e de alta dimensionalidade, treinar um forest muito grande pode exigir muitos recursos computacionais.

-   **Processo de treinamento:**
1. **Bootstrap Sampling**: Amostrar aleatoriamente os dados de treinamento com reposição para criar vários subconjuntos (amostras bootstrap).
2. **Tree Construction**: Para cada amostra bootstrap, construir uma árvore de decisão usando um subconjunto aleatório de features em cada divisão. Isso introduz diversidade entre as árvores.
3. **Aggregation**: Para tarefas de classificação, a previsão final é feita por meio de uma votação majoritária entre as previsões de todas as árvores. Para tarefas de regressão, a previsão final é a média das previsões de todas as árvores.

<details>
<summary>Exemplo -- Random Forest para Intrusion Detection (NSL-KDD):</summary>
Usaremos o mesmo dataset NSL-KDD (rotulado de forma binária como normal ou anomalia) e treinaremos um classificador Random Forest. Esperamos que o random forest tenha um desempenho igual ou superior ao da árvore de decisão individual, graças à redução da variância proporcionada pela média do ensemble. Nós o avaliaremos com as mesmas métricas.
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
A random forest normalmente obtém bons resultados nessa tarefa de detecção de intrusão. Podemos observar uma melhoria em métricas como F1 ou AUC em comparação com uma única árvore de decisão, especialmente em recall ou precision, dependendo dos dados. Isso está de acordo com o entendimento de que *"Random Forest (RF) is an ensemble classifier and performs well compared to other traditional classifiers for effective classification of attacks."*. Em um contexto de security operations, um modelo de random forest pode identificar ataques com mais confiabilidade e reduzir falsos alarmes, graças à média de muitas regras de decisão. A feature importance da forest pode indicar quais network features são mais associadas a ataques (por exemplo, determinados network services ou contagens incomuns de pacotes).

</details>

### Support Vector Machines (SVM)

Support Vector Machines são modelos poderosos de supervised learning usados principalmente para classification (e também para regression como SVR). Um SVM tenta encontrar o **optimal separating hyperplane** que maximiza a margem entre duas classes. Apenas um subconjunto dos pontos de treinamento (os "support vectors" mais próximos do limite) determina a posição desse hyperplane. Ao maximizar a margem (distância entre os support vectors e o hyperplane), os SVMs tendem a alcançar uma boa generalização.<sup>[[4]](#references)</sup>

Um dos pontos fundamentais do poder dos SVMs é a capacidade de usar **kernel functions** para lidar com relações não lineares. Os dados podem ser transformados implicitamente em um feature space de dimensão mais alta, onde pode existir um separador linear. Kernels comuns incluem polynomial, radial basis function (RBF) e sigmoid. Por exemplo, se as classes de network traffic não forem linearmente separáveis no feature space bruto, um RBF kernel pode mapeá-las para uma dimensão maior, onde o SVM encontra uma divisão linear (que corresponde a um limite não linear no espaço original). A flexibilidade na escolha dos kernels permite que os SVMs lidem com diversos problemas.

Os SVMs são conhecidos por terem bom desempenho em situações com feature spaces de alta dimensionalidade (como dados de texto ou sequências de malware opcodes) e em casos nos quais o número de features é grande em relação ao número de amostras. Eles foram populares em muitas aplicações iniciais de cybersecurity, como classificação de malware e detecção de intrusão baseada em anomalias nos anos 2000, frequentemente apresentando alta accuracy.

No entanto, os SVMs não escalam facilmente para datasets muito grandes (a complexidade do treinamento é superlinear em relação ao número de amostras, e o uso de memória pode ser alto, pois pode ser necessário armazenar muitos support vectors). Na prática, para tarefas como network intrusion detection com milhões de registros, o SVM pode ser lento demais sem um subsampling cuidadoso ou o uso de métodos aproximados.

#### **Key characteristics of SVM:**

-   **Type of Problem:** Classification (binary ou multiclass via one-vs-one/one-vs-rest) e variantes de regression. Frequentemente usado em binary classification com separação clara de margem.

-   **Interpretability:** Média -- os SVMs não são tão interpretáveis quanto decision trees ou logistic regression. Embora seja possível identificar quais pontos de dados são support vectors e obter alguma noção de quais features podem ser influentes (por meio dos pesos no caso de um linear kernel), na prática os SVMs (especialmente com non-linear kernels) são tratados como classificadores black-box.

-   **Advantages:** Eficaz em espaços de alta dimensionalidade; pode modelar decision boundaries complexos com o kernel trick; resistente a overfitting quando a margem é maximizada (especialmente com um parâmetro de regularização C adequado); funciona bem mesmo quando as classes não estão separadas por uma grande distância (encontra o melhor limite de compromisso).

-   **Limitations:** **Computationally intensive** para datasets grandes (tanto o treinamento quanto a prediction escalam mal à medida que os dados crescem). Requer um ajuste cuidadoso dos parâmetros do kernel e da regularização (C, tipo de kernel, gamma para RBF, etc.). Não fornece diretamente probabilistic outputs (embora seja possível usar Platt scaling para obter probabilidades). Além disso, os SVMs podem ser sensíveis à escolha dos parâmetros do kernel --- uma escolha inadequada pode causar underfit ou overfit.

*Use cases in cybersecurity:* Os SVMs têm sido usados em **malware detection** (por exemplo, classificando arquivos com base em features extraídas ou sequências de opcodes), **network anomaly detection** (classificando o traffic como normal ou malicioso) e **phishing detection** (usando features de URLs). Por exemplo, um SVM poderia receber features de um e-mail (contagens de determinadas palavras-chave, scores de reputação do remetente etc.) e classificá-lo como phishing ou legítimo. Eles também foram aplicados à **intrusion detection** em feature sets como KDD, frequentemente alcançando alta accuracy ao custo de computação.

<details>
<summary>Example -- SVM for Malware Classification:</summary>
Usaremos novamente o phishing website dataset, desta vez com um SVM. Como os SVMs podem ser lentos, usaremos um subconjunto dos dados para o treinamento, se necessário (o dataset possui cerca de 11 mil instâncias, quantidade que um SVM consegue processar razoavelmente). Usaremos um RBF kernel, que é uma escolha comum para dados não lineares, e habilitaremos probability estimates para calcular o ROC AUC.
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
O modelo SVM produzirá métricas que podemos comparar com a regressão logística na mesma tarefa. Podemos descobrir que o SVM alcança alta accuracy e AUC se os dados forem bem separados pelas features. Por outro lado, se o dataset tiver muito ruído ou classes sobrepostas, o SVM talvez não supere significativamente a regressão logística. Na prática, os SVMs podem oferecer um ganho quando existem relações complexas e não lineares entre as features e a classe — o kernel RBF consegue capturar limites de decisão curvos que a regressão logística não identificaria. Como ocorre com todos os modelos, é necessário ajustar cuidadosamente `C` (regularização) e os parâmetros do kernel (como `gamma` para RBF) para equilibrar bias e variância.

</details>

#### Diferença entre Regressão Logística e SVM

| Aspecto | **Regressão Logística** | **Support Vector Machines** |
|---|---|---|
| **Função objetivo** | Minimiza a **log-loss** (entropia cruzada). | Maximiza a **margem** enquanto minimiza a **hinge-loss**. |
| **Limite de decisão** | Encontra o **hiperplano de melhor ajuste** que modela _P(y\|x)_. | Encontra o **hiperplano de margem máxima** (maior distância até os pontos mais próximos). |
| **Saída** | **Probabilística** – fornece probabilidades de classe calibradas por meio de σ(w·x + b). | **Determinística** – retorna rótulos de classe; probabilidades exigem trabalho adicional (por exemplo, Platt scaling). |
| **Regularização** | L2 (padrão) ou L1, equilibrando diretamente underfitting e overfitting. | O parâmetro C equilibra a largura da margem e as classificações incorretas; os parâmetros do kernel adicionam complexidade. |
| **Kernels / Não linearidade** | A forma nativa é **linear**; a não linearidade é adicionada por meio de feature engineering. | O **kernel trick** integrado (RBF, poly etc.) permite modelar limites complexos em espaços de alta dimensionalidade. |
| **Escalabilidade** | Resolve uma otimização convexa em **O(nd)**; lida bem com valores muito grandes de n. | O treinamento pode exigir **O(n²–n³)** de memória/tempo sem solvers especializados; é menos adequado para valores enormes de n. |
| **Interpretabilidade** | **Alta** – os pesos mostram a influência das features; o odds ratio é intuitivo. | **Baixa** para kernels não lineares; os support vectors são esparsos, mas não são fáceis de explicar. |
| **Sensibilidade a outliers** | Usa log-loss suave → menos sensível. | A hinge-loss com margem rígida pode ser **sensível**; a margem suave (C) reduz esse efeito. |
| **Casos de uso típicos** | Credit scoring, risco médico, testes A/B — quando **probabilidades e explicabilidade** são importantes. | Classificação de imagens/textos, bio-informática — quando **limites complexos** e **dados de alta dimensionalidade** são importantes. |

* **Se você precisa de probabilidades calibradas, interpretabilidade ou trabalha com datasets enormes — escolha a Regressão Logística.**
* **Se você precisa de um modelo flexível que capture relações não lineares sem feature engineering manual — escolha SVM (com kernels).**
* Ambos otimizam objetivos convexos, portanto **mínimos globais são garantidos**, mas os kernels do SVM adicionam hiperparâmetros e custo computacional.

### Naive Bayes

Naive Bayes é uma família de **classificadores probabilísticos** baseada na aplicação do Teorema de Bayes com uma forte suposição de independência entre as features. Apesar dessa suposição "ingênua", Naive Bayes frequentemente funciona surpreendentemente bem em determinadas aplicações, especialmente aquelas que envolvem dados textuais ou categóricos, como detecção de spam.<sup>[[5]](#references)</sup>


#### Teorema de Bayes

O teorema de Bayes é a base dos classificadores Naive Bayes. Ele relaciona as probabilidades condicionais e marginais de eventos aleatórios. A fórmula é:
```plaintext
P(A|B) = (P(B|A) * P(A)) / P(B)
```
Onde:
- `P(A|B)` é a probabilidade posterior da classe `A` dado o recurso `B`.
- `P(B|A)` é a verossimilhança do recurso `B` dada a classe `A`.
- `P(A)` é a probabilidade a priori da classe `A`.
- `P(B)` é a probabilidade a priori do recurso `B`.

Por exemplo, se quisermos classificar se um texto foi escrito por uma criança ou por um adulto, podemos usar as palavras no texto como recursos. Com base em alguns dados iniciais, o classificador Naive Bayes calculará previamente as probabilidades de cada palavra pertencer a cada classe potencial (criança ou adulto). Quando um novo texto for fornecido, ele calculará a probabilidade de cada classe potencial dadas as palavras no texto e escolherá a classe com a maior probabilidade.

Como você pode ver neste exemplo, o classificador Naive Bayes é muito simples e rápido, mas presume que os recursos são independentes, o que nem sempre ocorre em dados do mundo real.


#### Tipos de classificadores Naive Bayes

Existem vários tipos de classificadores Naive Bayes, dependendo do tipo de dados e da distribuição dos recursos:
- **Gaussian Naive Bayes**: presume que os recursos seguem uma distribuição Gaussiana (normal). É adequado para dados contínuos.
- **Multinomial Naive Bayes**: presume que os recursos seguem uma distribuição multinomial. É adequado para dados discretos, como contagens de palavras em classificação de textos.
- **Bernoulli Naive Bayes**: presume que os recursos são binários (0 ou 1). É adequado para dados binários, como a presença ou ausência de palavras em classificação de textos.
- **Categorical Naive Bayes**: presume que os recursos são variáveis categóricas. É adequado para dados categóricos, como classificar frutas com base em sua cor e formato.


#### **Principais características do Naive Bayes:**

-   **Tipo de problema:** Classificação (binária ou multiclasse). É comumente usado para tarefas de classificação de textos em cybersecurity (spam, phishing etc.).

-   **Interpretabilidade:** Média -- não é tão diretamente interpretável quanto uma árvore de decisão, mas é possível inspecionar as probabilidades aprendidas (por exemplo, quais palavras têm maior probabilidade de aparecer em emails de spam em comparação com emails ham). A estrutura do modelo (probabilidades de cada recurso dada a classe) pode ser compreendida quando necessário.

-   **Vantagens:** Treinamento e predição **muito rápidos**, mesmo em grandes conjuntos de dados (lineares em relação ao número de instâncias * número de recursos). Requer uma quantidade relativamente pequena de dados para estimar probabilidades de forma confiável, especialmente com um smoothing adequado. Muitas vezes é surpreendentemente preciso como baseline, especialmente quando os recursos contribuem de forma independente para evidenciar a classe. Funciona bem com dados de alta dimensionalidade (por exemplo, milhares de recursos extraídos de textos). Não exige tuning complexo além da configuração de um parâmetro de smoothing.

-   **Limitações:** A hipótese de independência pode limitar a precisão se os recursos forem altamente correlacionados. Por exemplo, em dados de rede, recursos como `src_bytes` e `dst_bytes` podem ser correlacionados; o Naive Bayes não capturará essa interação. À medida que o volume de dados cresce muito, modelos mais expressivos (como ensembles ou redes neurais) podem superar o NB ao aprender as dependências entre os recursos. Além disso, se uma determinada combinação de recursos for necessária para identificar um ataque (e não apenas recursos individuais contribuindo de forma independente), o NB terá dificuldades.

> [!TIP]
> *Casos de uso em cybersecurity:* O uso clássico é a **detecção de spam** -- o Naive Bayes foi a base dos primeiros filtros de spam, usando as frequências de determinados tokens (palavras, frases, endereços IP) para calcular a probabilidade de um email ser spam. Ele também é usado na **detecção de phishing em emails** e na **classificação de URLs**, em que a presença de determinadas palavras-chave ou características (como "login.php" em uma URL ou `@` no caminho de uma URL) contribui para a probabilidade de phishing. Na análise de malware, pode-se imaginar um classificador Naive Bayes que use a presença de determinadas chamadas de API ou permissões no software para prever se ele é malware. Embora algoritmos mais avançados geralmente tenham um desempenho melhor, o Naive Bayes continua sendo um bom baseline devido à sua velocidade e simplicidade.

<details>
<summary>Exemplo -- Naive Bayes para detecção de phishing:</summary>
Para demonstrar o Naive Bayes, usaremos o Gaussian Naive Bayes no conjunto de dados de intrusão NSL-KDD (com rótulos binários). O Gaussian NB tratará cada recurso como seguindo uma distribuição normal por classe. Essa é uma escolha aproximada, pois muitos recursos de rede são discretos ou apresentam forte assimetria, mas ela mostra como o NB seria aplicado a dados de recursos contínuos. Também poderíamos escolher o Bernoulli NB em um conjunto de dados com recursos binários (como um conjunto de alertas acionados), mas continuaremos com o NSL-KDD aqui para manter a continuidade.
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
Este código treina um classificador Naive Bayes para detectar ataques. O Naive Bayes calculará coisas como `P(service=http | Attack)` e `P(Service=http | Normal)` com base nos dados de treinamento, assumindo independência entre as features. Em seguida, usará essas probabilidades para classificar novas conexões como normais ou ataques, com base nas features observadas. O desempenho do NB no NSL-KDD pode não ser tão alto quanto o de modelos mais avançados (já que a independência entre as features é violada), mas geralmente é razoável e oferece o benefício de uma velocidade extrema. Em cenários como filtragem de e-mails em tempo real ou triagem inicial de URLs, um modelo Naive Bayes pode sinalizar rapidamente casos obviamente maliciosos usando poucos recursos.

</details>

### k-Nearest Neighbors (k-NN)

k-Nearest Neighbors é um dos algoritmos de machine learning mais simples. É um método **não paramétrico e baseado em instâncias** que faz previsões com base na similaridade com exemplos do conjunto de treinamento. A ideia para classificação é: para classificar um novo ponto de dados, encontrar os **k** pontos mais próximos nos dados de treinamento (seus "vizinhos mais próximos") e atribuir a classe majoritária entre esses vizinhos. A "proximidade" é definida por uma métrica de distância, normalmente a distância euclidiana para dados numéricos (outras distâncias podem ser usadas para diferentes tipos de features ou problemas).<sup>[[10]](#references)</sup>

K-NN não exige *treinamento explícito* -- a fase de "treinamento" consiste apenas em armazenar o dataset. Todo o trabalho acontece durante a consulta (previsão): o algoritmo deve calcular as distâncias do ponto consultado até todos os pontos de treinamento para encontrar os mais próximos. Isso torna o tempo de previsão **linear em relação ao número de amostras de treinamento**, o que pode ser custoso para datasets grandes. Por isso, k-NN é mais adequado para datasets menores ou cenários em que seja possível trocar memória e velocidade por simplicidade.

Apesar de sua simplicidade, k-NN pode modelar fronteiras de decisão muito complexas (pois, na prática, a fronteira de decisão pode ter qualquer formato determinado pela distribuição dos exemplos). Ele tende a funcionar bem quando a fronteira de decisão é muito irregular e há muitos dados -- essencialmente permitindo que os dados "falem por si mesmos". No entanto, em dimensões elevadas, as métricas de distância podem se tornar menos significativas (maldição da dimensionalidade), e o método pode ter dificuldades, a menos que haja um número enorme de amostras.

*Casos de uso em cybersecurity:* k-NN tem sido aplicado à detecção de anomalias -- por exemplo, um sistema de detecção de intrusão pode classificar um evento de rede como malicioso se a maioria dos seus vizinhos mais próximos (eventos anteriores) tiver sido maliciosa. Se o tráfego normal formar clusters e os ataques forem outliers, uma abordagem K-NN (com k=1 ou um k pequeno) será essencialmente uma **detecção de anomalias baseada no vizinho mais próximo**. K-NN também tem sido usado para classificar famílias de malware por meio de vetores de features binárias: um novo arquivo pode ser classificado como pertencente a uma determinada família de malware se estiver muito próximo (no espaço de features) de instâncias conhecidas dessa família. Na prática, k-NN não é tão comum quanto algoritmos mais escaláveis, mas é conceitualmente simples e às vezes usado como baseline ou para problemas de pequena escala.

#### **Principais características do k-NN:**

-   **Tipo de problema:** Classificação (e existem variantes para regressão). É um método de *lazy learning* -- não há ajuste explícito de um modelo.

-   **Interpretabilidade:** Baixa a média -- não existe um modelo global ou uma explicação concisa, mas é possível interpretar os resultados observando os vizinhos mais próximos que influenciaram uma decisão (por exemplo, "este fluxo de rede foi classificado como malicioso porque é semelhante a estes 3 fluxos maliciosos conhecidos"). Portanto, as explicações podem ser baseadas em exemplos.

-   **Vantagens:** Muito simples de implementar e entender. Não faz suposições sobre a distribuição dos dados (não paramétrico). Pode lidar naturalmente com problemas multiclasse. É **adaptável**, no sentido de que as fronteiras de decisão podem ser muito complexas, moldadas pela distribuição dos dados.

-   **Limitações:** A previsão pode ser lenta para datasets grandes (é necessário calcular muitas distâncias). Consome muita memória -- armazena todos os dados de treinamento. O desempenho piora em espaços de features de alta dimensionalidade, pois todos os pontos tendem a se tornar quase equidistantes (fazendo com que o conceito de "mais próximo" seja menos significativo). É necessário escolher *k* (número de vizinhos) adequadamente -- um k muito pequeno pode gerar ruído, enquanto um k muito grande pode incluir pontos irrelevantes de outras classes. Além disso, as features devem ser dimensionadas adequadamente, pois os cálculos de distância são sensíveis à escala.

<details>
<summary>Exemplo -- k-NN para detecção de Phishing:</summary>

Usaremos novamente o NSL-KDD (classificação binária). Como k-NN é computacionalmente pesado, usaremos um subconjunto dos dados de treinamento para manter esta demonstração viável. Escolheremos, por exemplo, 20.000 amostras de treinamento dentre as 125 mil completas e usaremos k=5 vizinhos. Após o treinamento (na prática, apenas armazenando os dados), avaliaremos o modelo no conjunto de teste. Também dimensionaremos as features para o cálculo das distâncias, garantindo que nenhuma feature individual domine devido à sua escala.
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
O modelo k-NN classificará uma conexão analisando as 5 conexões mais próximas no subconjunto do conjunto de treinamento. Se, por exemplo, 4 desses vizinhos forem attacks (anomalies) e 1 for normal, a nova conexão será classificada como um attack. O desempenho pode ser razoável, embora frequentemente não seja tão alto quanto o de um Random Forest ou SVM bem ajustado nos mesmos dados. No entanto, o k-NN às vezes pode se destacar quando as distribuições das classes são muito irregulares e complexas -- usando efetivamente uma consulta baseada em memória. Em cybersecurity, o k-NN (com k=1 ou um k pequeno) pode ser usado para detectar padrões de attacks conhecidos por meio de exemplos ou como um componente de sistemas mais complexos (por exemplo, para clustering e posterior classificação com base na associação a clusters).
</details>

### Gradient Boosting Machines (por exemplo, XGBoost)

Gradient Boosting Machines estão entre os algorithms mais poderosos para dados estruturados. **Gradient boosting** refere-se à técnica de construir um ensemble de weak learners (geralmente decision trees) de maneira sequencial, na qual cada novo modelo corrige os erros do ensemble anterior. Diferentemente do bagging (Random Forests), que constrói árvores em paralelo e calcula a média entre elas, o boosting constrói árvores *uma por uma*, cada uma se concentrando mais nas instâncias que as árvores anteriores classificaram incorretamente.

As implementações mais populares nos últimos anos são **XGBoost**, **LightGBM** e **CatBoost**, todas bibliotecas de gradient boosting decision tree (GBDT). Elas têm obtido enorme sucesso em competições e aplicações de machine learning, frequentemente **alcançando desempenho de state-of-the-art em datasets tabulares**. Em cybersecurity, pesquisadores e profissionais usam gradient boosted trees em tarefas como **malware detection** (usando features extraídas de arquivos ou do comportamento em runtime) e **network intrusion detection**. Por exemplo, um modelo de gradient boosting pode combinar muitas regras fracas (árvores), como "se houver muitos pacotes SYN e uma porta incomum -> provavelmente é um scan", em um detector composto forte que considera muitos padrões sutis.<sup>[[6]](#references)</sup>

Por que as boosted trees são tão eficazes? Cada árvore da sequência é treinada com base nos *erros residuais* (gradients) das predições do ensemble atual. Dessa forma, o modelo gradualmente **"boosts"** as áreas em que é fraco. O uso de decision trees como base learners permite que o modelo final capture interações complexas e relações não lineares. Além disso, o boosting possui inerentemente uma forma de regularização integrada: ao adicionar muitas árvores pequenas (e usar uma learning rate para dimensionar suas contribuições), ele geralmente generaliza bem sem overfitting excessivo, desde que os parâmetros adequados sejam escolhidos.

#### **Principais características do Gradient Boosting:**

-   **Tipo de problema:** Principalmente classification e regression. Em security, geralmente classification (por exemplo, classificar uma conexão ou arquivo como binário). Ele lida com problemas binários, multi-class (com a loss apropriada) e até mesmo problemas de ranking.

-   **Interpretabilidade:** Baixa a média. Embora uma única boosted tree seja pequena, um modelo completo pode ter centenas de árvores, o que não é interpretável por humanos como um todo. No entanto, assim como o Random Forest, ele pode fornecer scores de feature importance, e ferramentas como SHAP (SHapley Additive exPlanations) podem ser usadas para interpretar individual predictions até certo ponto.

-   **Vantagens:** Frequentemente é o algorithm de **melhor desempenho** para dados estruturados/tabulares. Pode detectar padrões e interações complexos. Possui muitos parâmetros de ajuste (número de árvores, profundidade das árvores, learning rate, termos de regularization) para adaptar a complexidade do modelo e evitar overfitting. As implementações modernas são otimizadas para velocidade (por exemplo, o XGBoost usa informações de gradient de segunda ordem e estruturas de dados eficientes). Tende a lidar melhor com dados desbalanceados quando combinado com loss functions apropriadas ou pelo ajuste dos sample weights.

-   **Limitações:** É mais complexo de ajustar do que modelos mais simples; o treinamento pode ser lento se as árvores forem profundas ou se o número de árvores for grande (embora normalmente ainda seja mais rápido do que treinar uma deep neural network comparável nos mesmos dados). O modelo pode sofrer overfitting se não for ajustado (por exemplo, muitas árvores profundas com regularization insuficiente). Devido ao grande número de hyperparameters, usar gradient boosting de forma eficaz pode exigir mais experiência ou experimentação. Além disso, assim como os métodos baseados em árvores, ele não lida inerentemente com dados muito esparsos e de alta dimensionalidade de forma tão eficiente quanto modelos lineares ou Naive Bayes (embora ainda possa ser aplicado, por exemplo, em text classification, mas talvez não seja a primeira escolha sem feature engineering).

> [!TIP]
> *Casos de uso em cybersecurity:* Em praticamente qualquer situação em que uma decision tree ou random forest poderia ser usada, um modelo de gradient boosting pode alcançar melhor accuracy. Por exemplo, competições de **Microsoft's malware detection** têm usado intensivamente XGBoost em features elaboradas a partir de binary files. Pesquisas sobre **network intrusion detection** frequentemente relatam os melhores resultados com GBDTs (por exemplo, XGBoost nos datasets CIC-IDS2017 ou UNSW-NB15). Esses modelos podem receber uma ampla variedade de features (tipos de protocolo, frequência de determinados eventos, features estatísticas do tráfego etc.) e combiná-las para detectar threats. Em phishing detection, o gradient boosting pode combinar features lexicais de URLs, features de reputação de domínios e features de conteúdo de páginas para alcançar uma accuracy muito alta. A abordagem de ensemble ajuda a cobrir muitos corner cases e sutilezas nos dados.

<details>
<summary>Exemplo -- XGBoost para Phishing Detection:</summary>
Usaremos um gradient boosting classifier no dataset de phishing. Para manter as coisas simples e autocontidas, usaremos `sklearn.ensemble.GradientBoostingClassifier` (que é uma implementação mais lenta, porém direta). Normalmente, seria possível usar as bibliotecas `xgboost` ou `lightgbm` para obter melhor desempenho e recursos adicionais. Treinaremos o modelo e o avaliaremos de forma semelhante ao exemplo anterior.
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
O modelo de gradient boosting provavelmente alcançará uma precisão e uma AUC muito altas neste dataset de phishing (com frequência, esses modelos podem exceder 95% de precisão com o ajuste adequado nesse tipo de dado, como observado na literatura. Isso demonstra por que os GBDTs são considerados *"o state of the art model para datasets tabulares"* -- eles geralmente superam algoritmos mais simples ao capturar padrões complexos. Em um contexto de cibersegurança, isso pode significar detectar mais sites de phishing ou ataques com menos falhas. É claro que devemos ter cuidado com overfitting -- normalmente usaríamos técnicas como validação cruzada e monitoraríamos o desempenho em um conjunto de validação ao desenvolver um modelo desse tipo para deployment.

</details>

### Combinação de Modelos: Ensemble Learning e Stacking

Ensemble learning é uma estratégia de **combinar vários modelos** para melhorar o desempenho geral. Já vimos métodos específicos de ensemble: Random Forest (um ensemble de árvores via bagging) e Gradient Boosting (um ensemble de árvores via boosting sequencial). Mas ensembles também podem ser criados de outras formas, como **voting ensembles** ou **stacked generalization (stacking)**. A ideia principal é que diferentes modelos podem capturar padrões diferentes ou ter fraquezas distintas; ao combiná-los, podemos **compensar os erros de cada modelo com os pontos fortes de outro**.<sup>[[13]](#references)</sup>

-   **Voting Ensemble:** Em um classificador de votação simples, treinamos vários modelos diversos (por exemplo, uma regressão logística, uma árvore de decisão e um SVM) e fazemos com que votem na previsão final (voto majoritário para classificação). Se ponderarmos os votos (por exemplo, atribuindo um peso maior aos modelos mais precisos), teremos um esquema de votação ponderada. Isso normalmente melhora o desempenho quando os modelos individuais são razoavelmente bons e independentes -- o ensemble reduz o risco de um erro de um modelo individual, pois os outros podem corrigi-lo. É como ter um painel de especialistas em vez de uma única opinião.

-   **Stacking (Stacked Ensemble):** O stacking vai um passo além. Em vez de uma votação simples, ele treina um **meta-modelo** para **aprender como combinar melhor as previsões** dos modelos base. Por exemplo, você treina 3 classificadores diferentes (learners base) e, em seguida, fornece suas saídas (ou probabilidades) como features para um meta-classificador (geralmente um modelo simples, como a regressão logística), que aprende a melhor maneira de combiná-las. O meta-modelo é treinado em um conjunto de validação ou por meio de validação cruzada para evitar overfitting. O stacking muitas vezes supera a votação simples ao aprender *em quais modelos confiar mais em cada situação*. Em cibersegurança, um modelo pode ser melhor para detectar network scans, enquanto outro pode ser melhor para detectar malware beaconing; um modelo de stacking poderia aprender a confiar adequadamente em cada um deles.

Ensembles, sejam por votação ou stacking, tendem a **aumentar a precisão** e a robustez. A desvantagem é o aumento da complexidade e, às vezes, a redução da interpretabilidade (embora algumas abordagens de ensemble, como uma média de árvores de decisão, ainda possam fornecer alguns insights, por exemplo, a importância das features). Na prática, se as restrições operacionais permitirem, usar um ensemble pode resultar em taxas de detecção mais altas. Muitas soluções vencedoras em desafios de cibersegurança (e em competições do Kaggle em geral) usam técnicas de ensemble para extrair o último pouco de desempenho.

<details>
<summary>Exemplo -- Voting Ensemble para Detecção de Phishing:</summary>
Para ilustrar o model stacking, vamos combinar alguns dos modelos que discutimos no dataset de phishing. Usaremos uma regressão logística, uma árvore de decisão e um k-NN como learners base, e usaremos um Random Forest como meta-learner para agregar suas previsões. O meta-learner será treinado com as saídas dos learners base (usando validação cruzada no conjunto de treinamento). Esperamos que o modelo stacked tenha um desempenho tão bom quanto ou ligeiramente melhor que os modelos individuais.
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
O ensemble empilhado aproveita os pontos fortes complementares dos modelos base. Por exemplo, a regressão logística pode lidar com os aspectos lineares dos dados, a árvore de decisão pode capturar interações específicas semelhantes a regras, e o k-NN pode se destacar em vizinhanças locais do espaço de atributos. O meta-modelo (uma random forest, neste caso) pode aprender como ponderar essas entradas. As métricas resultantes frequentemente mostram uma melhoria (mesmo que pequena) em relação às métricas de qualquer modelo individual. Em nosso exemplo de phishing, se a regressão logística sozinha tivesse um F1 de, digamos, 0.95 e a árvore 0.94, o stack poderia alcançar 0.96 ao compensar os pontos em que cada modelo comete erros.

Métodos de ensemble como este demonstram o princípio de que *"combinar vários modelos normalmente leva a uma melhor generalização"*. Em cybersecurity, isso pode ser implementado com vários mecanismos de detecção (um pode ser baseado em regras, outro em machine learning e outro em anomalias) e, em seguida, uma camada que agrega seus alertas -- efetivamente uma forma de ensemble -- para tomar uma decisão final com maior confiança. Ao implantar esses sistemas, é necessário considerar a complexidade adicional e garantir que o ensemble não se torne difícil demais de gerenciar ou explicar. Porém, do ponto de vista da precisão, ensembles e stacking são ferramentas poderosas para melhorar o desempenho dos modelos.

</details>


## Referências

- [1] [Regressão logística](https://madhuramiah.medium.com/logistic-regression-6e55553cc003)
- [2] [Árvore de decisão - Introdução com exemplo](https://www.geeksforgeeks.org/decision-tree-introduction-example/)
- [3] [Detecção de ataques de Denial of Services usando Random Forest Classifier com Information Gain](https://rjwave.org/ijedr/viewpaperforall.php?paper=IJEDR1703132)
- [4] [O que são Support Vector Machines (SVMs)? (IBM)](https://www.ibm.com/think/topics/support-vector-machine)
- [5] [Filtragem de spam com Naive Bayes (Wikipedia)](https://en.m.wikipedia.org/wiki/Naive_Bayes_spam_filtering)
- [6] [GBDT desmistificado: como LightGBM, XGBoost e CatBoost funcionam](https://medium.com/@rupalipatelkvc/gbdt-demystified-how-lightgbm-xgboost-and-catboost-work-9479b7262644)
- [7] [AI e Machine Learning em Cybersecurity (zvelo)](https://zvelo.com/ai-and-machine-learning-in-cybersecurity/)
- [8] [Regressão linear explicada](https://medium.com/@chaandram/linear-regression-explained-28d5bf1934ae)
- [9] [Análise de desempenho de modelos de machine learning para sistema de detecção de intrusões usando a técnica de seleção de atributos Gini Impurity-based Weighted Random Forest (GIWRF)](https://cybersecurity.springeropen.com/articles/10.1186/s42400-021-00103-8)
- [10] [O que é o algoritmo k-nearest neighbors (KNN)? (IBM)](https://www.ibm.com/think/topics/knn)
- [11] [Classificação de ataques e websites de phishing usando machine learning e múltiplos conjuntos de dados (uma análise comparativa)](https://arxiv.org/pdf/2101.02552)
- [12] [Como o Deep Learning aprimora sistemas de detecção de intrusões](https://cybersecurity-magazine.com/how-deep-learning-enhances-intrusion-detection-systems/)
- [13] [Ensemble Learning: melhorando o desempenho dos modelos ao combinar pontos fortes](https://medium.com/@sarahzouinina/ensemble-learning-boosting-model-performance-by-combining-strengths-02e56165b901)

{{#include ../banners/hacktricks-training.md}}
